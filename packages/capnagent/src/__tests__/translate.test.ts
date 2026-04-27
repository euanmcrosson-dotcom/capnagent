/**
 * Tests for boundary translation between `RawReceipt` (wire) and `Receipt`
 * (public). These exercise translate.ts in isolation — no WASM, no wrapper
 * classes, no init. See WEEK3_SPEC.md §5 ("camelCase translation" focus).
 */

import { describe, expect, it } from "vitest";
import { rawReceiptToReceipt, receiptToRaw } from "../translate.js";
import type { Receipt } from "../types.js";
import type { RawReceipt } from "../wasm.js";

const sampleAllowed: RawReceipt = {
  version: 1,
  capability_identifier: "buy",
  caveats: [{ predicate: 'merchant == "amazon.com"' }, { predicate: "amount <= 50_usd" }],
  context_summary: {
    caller: "agent:planner",
    tool: "http.post",
    args_hash: "abc123",
  },
  outcome: { kind: "allowed" },
  timestamp_ms: 1_700_000_000_000,
  signature: "deadbeef",
};

const sampleDenied: RawReceipt = {
  version: 1,
  capability_identifier: "buy",
  caveats: [],
  context_summary: { caller: "agent:rogue", tool: "bank.wire", args_hash: "00" },
  outcome: { kind: "denied", reason: "tool != http.post" },
  timestamp_ms: 0,
  signature: "",
};

describe("rawReceiptToReceipt", () => {
  it("renames every snake_case field to camelCase", () => {
    const r = rawReceiptToReceipt(sampleAllowed);
    expect(r.capabilityIdentifier).toBe("buy");
    expect(r.contextSummary.argsHash).toBe("abc123");
    expect(r.timestampMs).toBe(1_700_000_000_000);
    expect(r.signature).toBe("deadbeef");

    // Make sure no snake_case keys leaked through. The static type already
    // forbids this, but runtime-checking guards against accidental
    // `Object.assign`-style implementations later.
    const keys = Object.keys(r);
    expect(keys).not.toContain("capability_identifier");
    expect(keys).not.toContain("timestamp_ms");
    const summaryKeys = Object.keys(r.contextSummary);
    expect(summaryKeys).not.toContain("args_hash");
  });

  it("preserves the allowed outcome variant verbatim", () => {
    const r = rawReceiptToReceipt(sampleAllowed);
    expect(r.outcome).toEqual({ kind: "allowed" });
  });

  it("preserves the denied outcome reason", () => {
    const r = rawReceiptToReceipt(sampleDenied);
    expect(r.outcome).toEqual({ kind: "denied", reason: "tool != http.post" });
  });

  it("freezes the caveats array (push fails)", () => {
    const r = rawReceiptToReceipt(sampleAllowed);
    expect(Object.isFrozen(r.caveats)).toBe(true);
    expect(() => {
      // Cast to any to bypass the ReadonlyArray type and exercise runtime
      // immutability — this is exactly the foot-gun the freeze prevents.
      (r.caveats as Array<{ predicate: string }>).push({ predicate: "evil" });
    }).toThrow();
  });

  it("freezes each caveat object (predicate cannot be reassigned)", () => {
    const r = rawReceiptToReceipt(sampleAllowed);
    const first = r.caveats[0];
    expect(first).toBeDefined();
    expect(Object.isFrozen(first)).toBe(true);
  });

  it("does not alias the WASM input array (defensive copy)", () => {
    const raw: RawReceipt = {
      ...sampleAllowed,
      caveats: [{ predicate: "x == y" }],
    };
    const r = rawReceiptToReceipt(raw);
    // Mutate the WASM-side array; the receipt should be unaffected.
    raw.caveats.push({ predicate: "injected" });
    expect(r.caveats.length).toBe(1);
  });
});

describe("receiptToRaw", () => {
  it("renames every camelCase field back to snake_case", () => {
    const receipt: Receipt = rawReceiptToReceipt(sampleAllowed);
    const raw = receiptToRaw(receipt);
    expect(raw.capability_identifier).toBe("buy");
    expect(raw.context_summary.args_hash).toBe("abc123");
    expect(raw.timestamp_ms).toBe(1_700_000_000_000);
    const keys = Object.keys(raw);
    expect(keys).not.toContain("capabilityIdentifier");
    expect(keys).not.toContain("timestampMs");
  });

  it("round-trips RawReceipt -> Receipt -> RawReceipt byte-identical (allowed)", () => {
    expect(receiptToRaw(rawReceiptToReceipt(sampleAllowed))).toEqual(sampleAllowed);
  });

  it("round-trips RawReceipt -> Receipt -> RawReceipt byte-identical (denied)", () => {
    expect(receiptToRaw(rawReceiptToReceipt(sampleDenied))).toEqual(sampleDenied);
  });
});
