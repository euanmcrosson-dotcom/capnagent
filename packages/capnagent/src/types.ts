/**
 * Public, camelCase types exposed by `@capnagent/core`. The wire-format
 * counterparts (snake_case `RawReceipt`, etc.) live in `wasm.ts` and
 * never leak past the wrapper.
 */

/**
 * Verifier-controlled facts at the moment of a tool call. Passed to
 * `Verifier.verifyWithContext`. All fields camelCase.
 *
 * Mirrors `crates/capnagent-core/src/context.rs` but uses millis-since-epoch
 * for `now` so JS callers don't need a `SystemTime` shim.
 */
export interface Context {
  /** Defaults to `Date.now()` on the WASM side if omitted. */
  nowMs?: number;
  caller: string;
  tool: string;
  args: unknown;
  env?: Record<string, string>;
}

/**
 * Public, camelCase audit receipt returned by `Verifier.verifyWithContext`
 * and consumed by `Auditor.verify`.
 *
 * `caveats` is a `ReadonlyArray` and is frozen at translation time — the
 * wrapper defensively copies the array out of the WASM boundary so callers
 * can't mutate the receipt in flight before audit verification.
 */
export interface Receipt {
  /**
   * Receipt schema version. Currently always `1`. The Rust verifier
   * rejects unknown versions fail-closed (forward-compat gate, see
   * Rust-side `docs/DESIGN.md` §14). Bumping this is a wire-format
   * break, not a hot upgrade.
   */
  version: number;
  capabilityIdentifier: string;
  caveats: ReadonlyArray<{ predicate: string }>;
  contextSummary: {
    caller: string;
    tool: string;
    argsHash: string;
  };
  outcome: { kind: "allowed" } | { kind: "denied"; reason: string };
  timestampMs: number;
  /** Lower-case hex, no prefix. */
  signature: string;
}
