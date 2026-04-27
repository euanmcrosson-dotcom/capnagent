import type { Auditor, Capability, Context, Receipt, Verifier } from "@capnagent/core";
import { vi } from "vitest";

// Pretend-key bytes (test-only): 32-byte ed25519 public key, 64-byte
// signature. Filled with a recognizable constant so failure messages
// are easy to read.
export const TEST_PUBKEY = new Uint8Array(32).fill(0x77);
export const TEST_SIGNATURE = new Uint8Array(64).fill(0x55);

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
 * it from the adapter. `verifyWithProof` defaults to a no-op mock; tests
 * that exercise the hok path supply their own implementation.
 */
export function fakeVerifier(
  impl: (cap: Capability, ctx: Context, auditor: Auditor) => Receipt,
  proofImpl?: (
    cap: Capability,
    ctx: Context,
    auditor: Auditor,
    challenge: Uint8Array,
    proof: Uint8Array,
  ) => Receipt,
): Verifier {
  const v = {
    verify: vi.fn(),
    verifyWithContext: vi.fn(impl),
    verifyWithProof: vi.fn(proofImpl ?? (() => allowReceipt())),
  };
  return v as unknown as Verifier;
}

/**
 * Plain-object capability shaped for the structural use in
 * `WrapOptions`. By default `holderOfKey` is undefined (the v0 path).
 * Tests that exercise hok pass a `pubkey` so the gate fires.
 */
export function fakeCapability(pubkey?: Uint8Array): Capability {
  return { holderOfKey: pubkey } as unknown as Capability;
}

export const fakeCap = fakeCapability();
export const fakeAuditor = {} as Auditor;

export function sampleContext(): Context {
  return {
    caller: "agent:planner",
    tool: "http.post",
    args: { url: "https://amazon.com/cart", qty: 1 },
  };
}
