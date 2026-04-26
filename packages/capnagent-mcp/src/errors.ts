// AT MERGE TIME: rewrite `from "./__capnagent-stub"` to `from "@capnagent"`.
import type { Receipt } from "./__capnagent-stub";

/**
 * Thrown by a wrapped MCP client's `callTool` when the verifier denies the
 * capability for a given context. Carries the full {@link Receipt} so the
 * caller can route the decision into observability / debugging.
 *
 * IMPORTANT: this is *not* used for chain-integrity failures or audit-tamper
 * failures — those propagate as `CapabilityChainError` and
 * `CapabilityAuditError` from `@capnagent` directly. A
 * `CapabilityDeniedError` always means: the capability was cryptographically
 * valid, but at least one caveat refused this specific call.
 */
export class CapabilityDeniedError extends Error {
  readonly receipt: Receipt;

  constructor(receipt: Receipt) {
    super(receipt.outcome.kind === "denied" ? receipt.outcome.reason : "denied (no reason)");
    this.name = "CapabilityDeniedError";
    this.receipt = receipt;
  }
}
