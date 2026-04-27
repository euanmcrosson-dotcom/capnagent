/**
 * Boundary translation between the WASM wire format (`RawReceipt`,
 * snake_case) and the public API (`Receipt`, camelCase).
 *
 * Translation is centralized here so there is exactly one place to audit
 * field-name mapping. The rule is:
 *
 *   - On every receiver from WASM (e.g. `Verifier.verifyWithContext`):
 *     `RawReceipt` -> `Receipt`. Arrays are defensively copied and frozen.
 *   - On every sender into WASM (e.g. `Auditor.verify(receipt)`):
 *     `Receipt` -> `RawReceipt`. The shape round-trips byte-identically.
 *
 * snake_case never leaks into the public API.
 */

import type { Receipt } from "./types.js";
import type { RawReceipt } from "./wasm.js";

/** Convert a WASM-side `RawReceipt` to the public `Receipt`. */
export function rawReceiptToReceipt(raw: RawReceipt): Receipt {
  // Defensively copy each caveat object and freeze the wrapper. A receipt
  // is supposed to be a *record* of a past decision; mutating it after the
  // fact would break the audit signature contract.
  const frozenCaveats = Object.freeze(
    raw.caveats.map((c) => Object.freeze({ predicate: c.predicate })),
  );

  return {
    capabilityIdentifier: raw.capability_identifier,
    caveats: frozenCaveats,
    contextSummary: {
      caller: raw.context_summary.caller,
      tool: raw.context_summary.tool,
      argsHash: raw.context_summary.args_hash,
    },
    // The outcome variant already uses camelCase keys (`kind`, `reason`).
    // Copy through a fresh object so callers can't tamper with the receipt
    // and have it round-trip through Auditor.verify successfully later.
    outcome:
      raw.outcome.kind === "allowed"
        ? { kind: "allowed" }
        : { kind: "denied", reason: raw.outcome.reason },
    timestampMs: raw.timestamp_ms,
    signature: raw.signature,
  };
}

/**
 * Convert a public `Receipt` back into the WASM-side `RawReceipt`.
 * Required by `Auditor.verify`, which needs the wire-format object to
 * recompute and constant-time-compare the HMAC signature.
 */
export function receiptToRaw(r: Receipt): RawReceipt {
  return {
    capability_identifier: r.capabilityIdentifier,
    // Copy caveats out of the (potentially frozen) wrapper so the WASM
    // side can hand them through whatever transport it uses.
    caveats: r.caveats.map((c) => ({ predicate: c.predicate })),
    context_summary: {
      caller: r.contextSummary.caller,
      tool: r.contextSummary.tool,
      args_hash: r.contextSummary.argsHash,
    },
    outcome:
      r.outcome.kind === "allowed"
        ? { kind: "allowed" }
        : { kind: "denied", reason: r.outcome.reason },
    timestamp_ms: r.timestampMs,
    signature: r.signature,
  };
}
