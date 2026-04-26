/**
 * Public error hierarchy for the `@capnagent` package. All errors thrown
 * by the wrapper extend `CapabilityError`, so callers can catch the family
 * with one `instanceof` and the specific subtype with another.
 *
 * The wrapper maps WASM-thrown errors into these subclasses at the
 * boundary; consumers never see raw wasm-bindgen errors. See `index.ts`
 * for the mapping table.
 */

/** Root of the capnagent error hierarchy. */
export class CapabilityError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "CapabilityError";
  }
}

/**
 * The HMAC chain failed to verify (forged signature, tampered caveats,
 * wrong root key, etc.) — the capability itself is invalid.
 */
export class CapabilityChainError extends CapabilityError {
  constructor(message?: string) {
    super(message);
    this.name = "CapabilityChainError";
  }
}

/**
 * The audit signature on a receipt failed to verify (tampered receipt,
 * wrong auditor key). Distinguishes audit-trail integrity failures from
 * capability-chain failures so callers can react appropriately.
 */
export class CapabilityAuditError extends CapabilityError {
  constructor(message?: string) {
    super(message);
    this.name = "CapabilityAuditError";
  }
}
