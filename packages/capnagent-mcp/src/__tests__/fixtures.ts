import { vi } from "vitest";
import type { Auditor, Capability, Context, Receipt, Verifier } from "../__capnagent-stub";

/**
 * The base receipt shape — fields shaped exactly per WEEK3_SPEC §3.2's
 * `Receipt`. Tests override one field at a time to flip allow/deny etc.
 */
export function makeReceipt(overrides: Partial<Receipt> = {}): Receipt {
  return {
    capabilityIdentifier: "buy",
    caveats: [{ predicate: 'merchant == "amazon.com"' }],
    contextSummary: {
      caller: "agent:planner",
      tool: "http.post",
      argsHash: "ab".repeat(32),
    },
    outcome: { kind: "allowed" },
    timestampMs: 1_745_792_000_000,
    signature: "00".repeat(32),
    ...overrides,
  };
}

export function allowReceipt(): Receipt {
  return makeReceipt({ outcome: { kind: "allowed" } });
}

export function denyReceipt(reason = "caveat amount<=50_usd failed: 60_usd"): Receipt {
  return makeReceipt({ outcome: { kind: "denied", reason } });
}

/**
 * Build a Verifier-shaped object whose `verifyWithContext` is a vitest mock
 * delegating to `impl`. The `verify` method is a no-op mock; we don't call
 * it from the adapter.
 */
export function fakeVerifier(
  impl: (cap: Capability, ctx: Context, auditor: Auditor) => Receipt,
): Verifier {
  // The Verifier class from the stub throws in its constructor, so we can't
  // use `new`. Build a plain object that satisfies the structural shape.
  const v = {
    verify: vi.fn(),
    verifyWithContext: vi.fn(impl),
  };
  return v as unknown as Verifier;
}

export const fakeCap = {} as Capability;
export const fakeAuditor = {} as Auditor;

export function sampleContext(): Context {
  return {
    caller: "agent:planner",
    tool: "http.post",
    args: { url: "https://amazon.com/cart", qty: 1 },
  };
}
