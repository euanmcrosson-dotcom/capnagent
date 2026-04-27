/**
 * Public API for the `@capnagent` package.
 *
 * Wraps the wasm-bindgen-generated classes in `./wasm` (which currently
 * re-exports `./__wasm-stub`) and presents an idiomatic TypeScript surface:
 *
 *   - All field names are camelCase. snake_case from the WASM boundary is
 *     translated in `./translate` and never leaks past these wrappers.
 *   - Errors thrown by the WASM layer are mapped into the typed
 *     `CapabilityError` hierarchy. The mapping table lives in
 *     `mapWasmError` below; see the comment there for the rules.
 *   - `init()` is idempotent and required. Every other API throws a
 *     descriptive `CapabilityError` if used before `init()` has resolved.
 *   - WASM `free()` is intentionally not exposed. v0 leans on JS GC; v0.1
 *     will adopt explicit-resource-management once `using` is stable.
 *
 * See `docs/WEEK3_SPEC.md` §3.2 for the locked contract.
 */

import { CapabilityAuditError, CapabilityChainError, CapabilityError } from "./errors.js";
import { rawReceiptToReceipt, receiptToRaw } from "./translate.js";
import type { Context, Receipt } from "./types.js";
import * as wasm from "./wasm.js";

export { CapabilityAuditError, CapabilityChainError, CapabilityError };
export type { Context, Receipt };

// ---------------------------------------------------------------------------
// init() — idempotent, required-before-use
// ---------------------------------------------------------------------------

let initPromise: Promise<void> | null = null;
let ready = false;

/**
 * Initialize the underlying WASM module. Idempotent: calling more than
 * once returns the same in-flight promise on parallel calls and a resolved
 * promise once initialization has succeeded.
 *
 * Must be called and awaited before any other API in this package is used.
 */
export function init(): Promise<void> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    // The wasm-bindgen `init()` is synchronous in the §3.1 contract; wrapping
    // in an async IIFE keeps the public signature `Promise<void>` for
    // forward-compat with bundler-target builds where init becomes async.
    wasm.init();
    ready = true;
  })();
  return initPromise;
}

function ensureReady(): void {
  if (!ready) {
    throw new CapabilityError(
      "capnagent: init() must be called and awaited before using any other API",
    );
  }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/**
 * Map a wasm-bindgen-thrown `Error` into the typed `CapabilityError`
 * hierarchy.
 *
 * v0 uses a two-stage decision:
 *
 *   1. **Operation context** — the wrapper method already knows what kind
 *      of failure is expected. `Auditor.verify` always maps to
 *      `CapabilityAuditError`; `Verifier.verify` (no context) always maps
 *      to `CapabilityChainError`.
 *   2. **Message inspection** — `Verifier.verifyWithContext` can throw
 *      either, so it sniffs the message for "audit"/"signature" keywords
 *      to pick `CapabilityAuditError`, falling back to
 *      `CapabilityChainError`.
 *
 * The wasm-bindgen errors come back as plain `Error` instances. When v0.1
 * adds typed error variants on the WASM side, replace the message sniff
 * with `instanceof` checks; the public hierarchy stays the same.
 */
type ErrorKind = "chain" | "audit" | "either" | "generic";

function mapWasmError(e: unknown, kind: ErrorKind): never {
  const message = e instanceof Error ? e.message : String(e);

  if (kind === "audit") {
    throw new CapabilityAuditError(message);
  }
  if (kind === "chain") {
    throw new CapabilityChainError(message);
  }
  if (kind === "either") {
    const lower = message.toLowerCase();
    if (lower.includes("audit") || lower.includes("signature") || lower.includes("tamper")) {
      throw new CapabilityAuditError(message);
    }
    throw new CapabilityChainError(message);
  }
  throw new CapabilityError(message);
}

// ---------------------------------------------------------------------------
// Public class wrappers
// ---------------------------------------------------------------------------

/**
 * A capability token: identifier, caveats, and an HMAC-chained signature.
 * Construct one via `Issuer.fromKey(...).issue(...)` or recover one from
 * its serialized form via `Capability.parse`.
 */
export class Capability {
  /** @internal — wrapper's handle on the wasm-bindgen instance. */
  readonly _inner: wasm.Capability;

  /** @internal */
  constructor(inner: wasm.Capability) {
    this._inner = inner;
  }

  /** Decode a previously-serialized capability token. */
  static parse(token: string): Capability {
    ensureReady();
    try {
      return new Capability(wasm.Capability.parse(token));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /** Encode this capability as a URL-safe, unpadded base64 token. */
  serialize(): string {
    ensureReady();
    try {
      return this._inner.serialize();
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /**
   * Append a caveat, producing a strictly narrower capability. Anyone
   * holding the parent can do this; nobody can broaden it.
   */
  attenuate(predicate: string): Capability {
    ensureReady();
    try {
      return new Capability(this._inner.attenuate(predicate));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /** Public identifier of the capability (what authority it grants). */
  get identifier(): string {
    ensureReady();
    return this._inner.identifier;
  }

  /**
   * The 32-byte ed25519 public key this capability is bound to, or
   * `undefined` for non-hok tokens. The binding is folded into the HMAC
   * chain at issuance so it cannot be added, removed, or changed after
   * the fact — see `docs/DESIGN.md` §11.
   */
  get holderOfKey(): Uint8Array | undefined {
    ensureReady();
    return this._inner.holderOfKey;
  }
}

/** Builder returned from `Issuer.issue`. Append caveats, then `build`. */
export class CapabilityBuilder {
  /** @internal */
  readonly _inner: wasm.CapabilityBuilder;

  /** @internal */
  constructor(inner: wasm.CapabilityBuilder) {
    this._inner = inner;
  }

  /** Append a caveat predicate to the in-progress capability. */
  caveat(predicate: string): CapabilityBuilder {
    ensureReady();
    try {
      // wasm-bindgen returns the same builder; re-wrap for type cleanliness.
      return new CapabilityBuilder(this._inner.caveat(predicate));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /**
   * Bind the in-progress capability to a 32-byte ed25519 public key
   * (DPoP-style holder-of-key). Must be called BEFORE any `.caveat()`
   * call — the Rust core asserts hok-first ordering and will throw
   * otherwise. The binding is folded into the HMAC chain so it cannot
   * be added, removed, or changed by any holder downstream.
   *
   * See `docs/DESIGN.md` §11 for the threat model and trade-offs.
   */
  holderOfKey(pubkey: Uint8Array): CapabilityBuilder {
    ensureReady();
    try {
      return new CapabilityBuilder(this._inner.holderOfKey(pubkey));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /** Finalize the builder into a `Capability`. */
  build(): Capability {
    ensureReady();
    try {
      return new Capability(this._inner.build());
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }
}

/** Mints fresh capabilities from a root key. Construct via `fromKey`. */
export class Issuer {
  /** @internal */
  readonly _inner: wasm.Issuer;

  /** @internal */
  constructor(inner: wasm.Issuer) {
    this._inner = inner;
  }

  /** Build an issuer from a raw key. The key is held only inside WASM. */
  static fromKey(key: Uint8Array): Issuer {
    ensureReady();
    try {
      return new Issuer(wasm.Issuer.fromKey(key));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /** Begin issuing a capability with the given identifier. */
  issue(identifier: string): CapabilityBuilder {
    ensureReady();
    try {
      return new CapabilityBuilder(this._inner.issue(identifier));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }
}

/** Signs and verifies audit receipts. */
export class Auditor {
  /** @internal */
  readonly _inner: wasm.Auditor;

  /** Construct an auditor from its HMAC key. */
  constructor(key: Uint8Array) {
    ensureReady();
    try {
      this._inner = new wasm.Auditor(key);
    } catch (e) {
      // Constructor throws -> the partially-constructed `this` is never
      // returned to the caller, so `_inner` being unassigned is sound.
      mapWasmError(e, "audit");
    }
  }

  /**
   * Verify a receipt's HMAC signature. Throws `CapabilityAuditError` on
   * any tampering or wrong-key condition.
   */
  verify(receipt: Receipt): void {
    ensureReady();
    try {
      this._inner.verify(receiptToRaw(receipt));
    } catch (e) {
      mapWasmError(e, "audit");
    }
  }
}

/**
 * A point-in-time, HMAC-signed list of revoked capability identifiers.
 * Issued by `Revoker.publish(...)`; installed on a `Verifier` via
 * `withRevocationList(...)`. Wire-portable: `serialize()` returns a
 * URL-safe base64 string the issuer can ship to verifiers; the
 * verifier re-checks the signature at install time.
 *
 * See `docs/DESIGN.md` §10 for the design rationale.
 */
export class RevocationList {
  /** @internal */
  readonly _inner: wasm.RevocationList;

  /** @internal */
  constructor(inner: wasm.RevocationList) {
    this._inner = inner;
  }

  /** Decode a previously-serialized revocation list from base64. */
  static parse(token: string): RevocationList {
    ensureReady();
    try {
      return new RevocationList(wasm.RevocationList.parse(token));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /** Encode this list as a URL-safe, unpadded base64 string. */
  serialize(): string {
    ensureReady();
    try {
      return this._inner.serialize();
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /**
   * Whether `identifier` appears in the revocation list. O(log n) —
   * the underlying revoked vec is sorted.
   */
  contains(identifier: string): boolean {
    ensureReady();
    return this._inner.contains(identifier);
  }

  /** Number of revoked identifiers. */
  get size(): number {
    ensureReady();
    return this._inner.size;
  }

  /** Whether the list has zero revocations. */
  get isEmpty(): boolean {
    ensureReady();
    return this._inner.isEmpty;
  }

  /**
   * Wall-clock the list was published, in milliseconds since the
   * UNIX epoch. Verifiers may reject lists older than a configured
   * staleness window; that policy lives at the caller.
   */
  get issuedAtMs(): number {
    ensureReady();
    return Number(this._inner.issuedAtMs);
  }
}

/**
 * Issuer-side helper for building and signing revocation lists.
 * Holds the root key plus an in-memory set of revoked identifiers.
 * Call `publish(issuedAtMs)` to mint a fresh signed snapshot.
 *
 * Usage:
 *
 *     const revoker = new Revoker(rootKey);
 *     revoker.revoke("cap-id-of-stolen-token");
 *     const list = revoker.publish(Date.now());
 *     // ship `list.serialize()` to verifiers; they install via
 *     // `verifier.withRevocationList(list)`.
 */
export class Revoker {
  /** @internal */
  readonly _inner: wasm.Revoker;

  /** Construct a Revoker from the same root key the Issuer uses. */
  constructor(rootKey: Uint8Array) {
    ensureReady();
    try {
      this._inner = new wasm.Revoker(rootKey);
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /** Mark a capability identifier as revoked. Idempotent. */
  revoke(identifier: string): void {
    ensureReady();
    this._inner.revoke(identifier);
  }

  /**
   * Remove an identifier from the revoked set. Returns true if the
   * entry was present and removed. Use sparingly — "unrevoke" makes
   * auditors nervous.
   */
  unrevoke(identifier: string): boolean {
    ensureReady();
    return this._inner.unrevoke(identifier);
  }

  /** Number of revoked identifiers currently held. */
  get size(): number {
    ensureReady();
    return this._inner.size;
  }

  /** Whether the Revoker has any entries. */
  get isEmpty(): boolean {
    ensureReady();
    return this._inner.isEmpty;
  }

  /**
   * Snapshot the current revoked set into a signed RevocationList.
   * Pass `issuedAtMs` from a clock authority you trust (NOT
   * `Date.now()` from inside the verifier — the issuer's clock is
   * the right authority for "when was this list published").
   */
  publish(issuedAtMs: number): RevocationList {
    ensureReady();
    if (!Number.isInteger(issuedAtMs) || issuedAtMs < 0) {
      throw new CapabilityError(
        `Revoker.publish: issuedAtMs must be a non-negative integer (got ${issuedAtMs})`,
      );
    }
    try {
      return new RevocationList(this._inner.publish(BigInt(issuedAtMs)));
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }
}

/**
 * In-memory nonce store for replay protection on `verifyWithProof`.
 *
 * Construct once and pass to `Verifier.withNonceStore(...)`. The
 * handle stays inspectable from JS even after install — both this
 * wrapper and the verifier hold a shared reference to the same store.
 *
 * Has no effect on `verifyWithContext` — non-hok bearer tokens are
 * explicitly designed to be reusable.
 *
 * Production deployments that need cross-process / cross-restart
 * replay resistance should provide a custom `NonceStore` impl in Rust
 * and depend on `capnagent-core` directly. The TS surface only ships
 * the in-memory backing.
 */
export class NonceStore {
  /** @internal — wrapper's handle on the wasm-bindgen instance. */
  readonly _inner: wasm.NonceStore;

  /** Construct a fresh, empty in-memory nonce store. */
  constructor() {
    ensureReady();
    try {
      this._inner = new wasm.NonceStore();
    } catch (e) {
      mapWasmError(e, "generic");
    }
  }

  /**
   * Number of entries currently held (including expired ones that have
   * not yet been overwritten). Useful for tests and metrics.
   */
  get size(): number {
    ensureReady();
    return this._inner.size;
  }

  /** Whether the store has zero entries. */
  get isEmpty(): boolean {
    ensureReady();
    return this._inner.isEmpty;
  }

  /**
   * Drop all recorded nonces. Useful for tests; production callers
   * rarely want this — replay protection depends on entries persisting
   * for the full TTL.
   */
  clear(): void {
    ensureReady();
    this._inner.clear();
  }
}

/** Verifies capabilities against the root key (and a context, for caveats). */
export class Verifier {
  /** @internal */
  _inner: wasm.Verifier;

  /** Construct a verifier from the root key. */
  constructor(key: Uint8Array) {
    ensureReady();
    try {
      this._inner = new wasm.Verifier(key);
    } catch (e) {
      mapWasmError(e, "chain");
    }
  }

  /**
   * Install a {@link NonceStore} for replay protection on
   * `verifyWithProof`. Each accepted proof's `sha256(proof)` is
   * recorded with the configured TTL (default 5 minutes); subsequent
   * calls within the TTL produce a denial receipt with reason
   * `"proof replay detected"`.
   *
   * Has no effect on `verifyWithContext` — non-hok bearer tokens are
   * explicitly designed to be reusable.
   *
   * Returns `this` so calls can be chained. The underlying WASM handle
   * is consumed and replaced; do not retain references to the
   * pre-call instance.
   */
  withNonceStore(store: NonceStore): this {
    ensureReady();
    try {
      this._inner = this._inner.withNonceStore(store._inner);
      return this;
    } catch (e) {
      mapWasmError(e, "chain");
    }
  }

  /**
   * Install a signed {@link RevocationList}. The list's HMAC
   * signature is verified against the verifier's root key BEFORE
   * the list is installed; mismatch throws `CapabilityChainError`
   * with message `"invalid revocation-list signature"` and the
   * list is NOT attached. This fail-closed behavior is deliberate:
   * a tampered or wrong-key list fails LOUDLY at install time
   * instead of silently producing a verifier that has no protection.
   *
   * Once installed, every subsequent `verifyWithContext` /
   * `verifyWithProof` call denies any capability whose identifier
   * is in the list — denial reason
   * `"capability revoked: <identifier>"`, audit-loggable like every
   * other denial.
   *
   * Returns `this` so calls can be chained.
   */
  withRevocationList(list: RevocationList): this {
    ensureReady();
    try {
      // WASM signature is `&mut self -> Result<(), JsError>` (not
      // consuming) so a signature-mismatch throw leaves the handle
      // valid for retry — different from withNonceStore / withNonceTtlMs
      // which can never fail and use the consuming pattern. We layer
      // `return this` here to keep the JS API uniformly chainable.
      this._inner.withRevocationList(list._inner);
      return this;
    } catch (e) {
      mapWasmError(e, "chain");
    }
  }

  /**
   * Override the per-nonce TTL in milliseconds. Default is 5 minutes.
   * Only meaningful in combination with {@link withNonceStore}.
   *
   * Returns `this` so calls can be chained.
   */
  withNonceTtlMs(ttlMs: number): this {
    ensureReady();
    if (!Number.isInteger(ttlMs) || ttlMs < 0) {
      throw new CapabilityError(
        `Verifier.withNonceTtlMs: ttlMs must be a non-negative integer (got ${ttlMs})`,
      );
    }
    try {
      this._inner = this._inner.withNonceTtlMs(BigInt(ttlMs));
      return this;
    } catch (e) {
      mapWasmError(e, "chain");
    }
  }

  /**
   * Cheap chain-only check: confirm the HMAC chain holds under the root
   * key. Throws `CapabilityChainError` if the chain has been tampered
   * with or the wrong key was used.
   */
  verify(cap: Capability): void {
    ensureReady();
    try {
      this._inner.verify(cap._inner);
    } catch (e) {
      mapWasmError(e, "chain");
    }
  }

  /**
   * Full verification: chain check, evaluate every caveat against `ctx`,
   * sign a receipt, and return it. The receipt is logged regardless of
   * outcome — the `outcome.kind === "denied"` path is the load-bearing
   * audit trail for refused calls.
   */
  verifyWithContext(cap: Capability, ctx: Context, auditor: Auditor): Receipt {
    ensureReady();
    try {
      const raw = this._inner.verifyWithContext(cap._inner, ctx, auditor._inner);
      return rawReceiptToReceipt(raw);
    } catch (e) {
      mapWasmError(e, "either");
    }
  }

  /**
   * Holder-of-key verification: chain → proof → revocation → caveats.
   *
   * Required entry point for capabilities that were bound with
   * `CapabilityBuilder.holderOfKey(pubkey)` at issuance time.
   * `challenge` is the bytes the holder signed (use {@link popChallengeFor}
   * for the standard derivation, or supply a deployment-specific value
   * that layers in nonces / antireplay state). `proof` is the 64-byte
   * ed25519 signature.
   *
   * Bad proofs become a `Receipt` with `outcome.kind === "denied"` and
   * a reason string — same audit-loggable shape as a caveat denial. A
   * bad chain still throws `CapabilityChainError`; a tampered receipt
   * becomes `CapabilityAuditError`. See `docs/DESIGN.md` §11 for the
   * deny-vs-throw rationale.
   */
  verifyWithProof(
    cap: Capability,
    ctx: Context,
    auditor: Auditor,
    challenge: Uint8Array,
    proof: Uint8Array,
  ): Receipt {
    ensureReady();
    try {
      const raw = this._inner.verifyWithProof(cap._inner, ctx, auditor._inner, challenge, proof);
      return rawReceiptToReceipt(raw);
    } catch (e) {
      mapWasmError(e, "either");
    }
  }
}

/**
 * Standard proof-of-possession challenge derivation for a `(cap, ctx)`
 * pair: `SHA-256(canonical-JSON({ id, tool, args_hash, now_ms }))`.
 *
 * Holders use this on their side to compute what to sign; verifiers
 * use the same function on the other side to compute what to compare
 * against. Both sides must agree bytewise — that is the whole point.
 *
 * Returns the 32-byte hash. Deployments that need to layer in extra
 * state (nonces, antireplay, request-shape binding) can compute their
 * own challenge bytes and pass them to {@link Verifier.verifyWithProof}
 * directly; this function is the documented default.
 */
export function popChallengeFor(cap: Capability, ctx: Context): Uint8Array {
  ensureReady();
  try {
    return wasm.popChallengeFor(cap._inner, ctx);
  } catch (e) {
    mapWasmError(e, "generic");
  }
}
