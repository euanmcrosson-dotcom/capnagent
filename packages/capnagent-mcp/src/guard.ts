import { popChallengeFor } from "@capnagent/core";
import type { Auditor, Capability, Context, Receipt, Verifier } from "@capnagent/core";

/**
 * A Context-builder callback. Called once per tool invocation; receives the
 * tool name and arguments and returns the {@link Context} the verifier should
 * evaluate caveats against.
 *
 * The callback may be synchronous or async. Errors it throws propagate
 * through `guardCall` / a wrapped client unchanged.
 */
export type ContextProvider = (toolName: string, args: unknown) => Context | Promise<Context>;

/**
 * Result of a guarded tool call.
 *
 * On allow, the underlying tool's result is returned alongside the
 * {@link Receipt}. On deny, the underlying tool was NEVER invoked and the
 * receipt explains why.
 */
export type GuardedResult<T> =
  | { allowed: true; result: T; receipt: Receipt }
  | { allowed: false; reason: string; receipt: Receipt };

/**
 * Minimal MCP-client surface — just the tools/call shape we mediate. Any
 * concrete MCP client (or any object) that structurally implements this
 * method can be passed to {@link wrapMCPClient}.
 */
export interface MCPClientLike {
  callTool(name: string, args: unknown): Promise<unknown>;
}

/** Options shared by `wrapMCPClient` and `guardCall`. */
export interface WrapOptions {
  /** The capability whose caveats authorise (or refuse) the call. */
  capability: Capability;
  /** Auditor that signs the receipt of every decision. */
  auditor: Auditor;
  /** Verifier — the cryptographic + caveat-evaluation engine. */
  verifier: Verifier;
  /** Builds the per-call {@link Context} the verifier evaluates against. */
  context: ContextProvider;
  /**
   * Called once per produced receipt — both allowed and denied. Caller may
   * persist to disk, post to a pipeline, etc. Errors thrown here are logged
   * via `console.error` and SWALLOWED: they never block the underlying tool
   * call on the allow path, and never replace the `CapabilityDeniedError`
   * on the deny path.
   *
   * Errors that occur *before* a receipt exists (e.g. CapabilityChainError
   * from the verifier) do not fire `onReceipt`.
   */
  onReceipt?: (r: Receipt) => void | Promise<void>;

  /**
   * REQUIRED if `capability.holderOfKey` is set; otherwise ignored.
   *
   * The wrapper will:
   *   1. Compute `challenge = popChallengeFor(capability, ctx)`.
   *   2. Call `signer(challenge)` to get a 64-byte ed25519 signature.
   *   3. Call `verifier.verifyWithProof(...)` with `(challenge, proof)`.
   *
   * If `capability.holderOfKey` is set and `signer` is undefined, the
   * wrapper throws an `Error("capability is bound to a holder key but
   * no signer was provided in WrapOptions")` synchronously BEFORE any
   * tool call — same fail-closed semantics as the Rust core's
   * `Verifier::verify_with_context` denying hok-bound tokens.
   *
   * The signer may run in-memory (e.g. `@noble/ed25519`), in a Web
   * Crypto context, or out-of-process (KMS, HSM, signing service);
   * capnagent does not take a position. Async signers are awaited.
   */
  signer?: (challenge: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}

/**
 * The exact error message thrown when a hok-bound capability is wrapped
 * (or guarded) without a `signer`. Constant so adapters and tests can
 * assert against it without coupling to the surrounding wording.
 */
export const MISSING_SIGNER_MESSAGE =
  "capability is bound to a holder key but no signer was provided in WrapOptions";

/**
 * Throws synchronously if `options.capability` is hok-bound but no
 * `signer` was supplied. Public so `wrapMCPClient` and `guardCall`
 * share the same fail-closed gate; the message is locked by
 * {@link MISSING_SIGNER_MESSAGE}.
 *
 * @internal — re-export point for wrap.ts; not part of the public API.
 */
export function __assertSignerIfHok(options: WrapOptions): void {
  if (options.capability.holderOfKey !== undefined && options.signer === undefined) {
    throw new Error(MISSING_SIGNER_MESSAGE);
  }
}

/**
 * Internal: run one verification decision. Used by both `guardCall` and the
 * proxied `callTool` inside `wrapMCPClient`.
 *
 * The verifier's `verifyWithContext` may throw `CapabilityChainError` or
 * `CapabilityAuditError` — those are produced *before* a receipt exists, so
 * we let them propagate unchanged and do NOT fire `onReceipt`. If the call
 * succeeds we have a receipt regardless of allow/deny, and `onReceipt` fires
 * with errors swallowed.
 *
 * @internal — not part of the public API.
 */
export async function __decide(
  options: WrapOptions,
  toolName: string,
  args: unknown,
): Promise<{ receipt: Receipt }> {
  const ctx = await Promise.resolve(options.context(toolName, args));
  const receipt = await runVerification(options, ctx);
  await fireOnReceipt(options.onReceipt, receipt);
  return { receipt };
}

/**
 * Pick the right verification entry point based on whether the
 * capability is hok-bound. For non-hok caps we go through
 * `verifyWithContext` (the v0 path); for hok-bound caps we derive the
 * default proof-of-possession challenge, ask the configured signer to
 * sign it, and route through `verifyWithProof`.
 *
 * The signer is awaited in case it goes out-of-process (KMS / HSM).
 * Bad proofs come back inside the receipt as `outcome.kind === "denied"`
 * with a reason string — they are NOT thrown from this function.
 */
async function runVerification(options: WrapOptions, ctx: Context): Promise<Receipt> {
  if (options.capability.holderOfKey !== undefined) {
    if (!options.signer) {
      // Caught at config time by `__assertSignerIfHok`; defence-in-depth
      // here in case a caller invokes `__decide` without going through
      // `wrapMCPClient` / `guardCall`.
      throw new Error(MISSING_SIGNER_MESSAGE);
    }
    const challenge = popChallengeFor(options.capability, ctx);
    const proof = await Promise.resolve(options.signer(challenge));
    return options.verifier.verifyWithProof(
      options.capability,
      ctx,
      options.auditor,
      challenge,
      proof,
    );
  }
  return options.verifier.verifyWithContext(options.capability, ctx, options.auditor);
}

async function fireOnReceipt(
  cb: ((r: Receipt) => void | Promise<void>) | undefined,
  receipt: Receipt,
): Promise<void> {
  if (!cb) return;
  try {
    await cb(receipt);
  } catch (err) {
    // Spec §3.3: onReceipt errors MUST NOT block the underlying call. We
    // log to make them debuggable; we never let them change the outcome.
    console.error("[@capnagent/mcp] onReceipt threw:", err);
  }
}

/**
 * Lower-level guard: run one verification + audit and return a typed
 * {@link GuardedResult}. Useful for non-MCP frameworks where you want to
 * branch on `allowed` rather than catch a thrown error.
 *
 * `inner` is invoked exactly once on the allow path, never on the deny
 * path. Verifier errors (chain / audit) propagate; the caller decides how
 * to handle them.
 */
export async function guardCall<T>(
  options: WrapOptions,
  toolName: string,
  args: unknown,
  inner: () => Promise<T>,
): Promise<GuardedResult<T>> {
  // Sync config check — fail-closed BEFORE we evaluate the
  // ContextProvider, build a challenge, or invoke `inner`.
  __assertSignerIfHok(options);
  const { receipt } = await __decide(options, toolName, args);
  if (receipt.outcome.kind === "denied") {
    return { allowed: false, reason: receipt.outcome.reason, receipt };
  }
  const result = await inner();
  return { allowed: true, result, receipt };
}
