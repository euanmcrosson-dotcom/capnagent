/**
 * The demo IS the test. If this file ever fails, capnagent's
 * confused-deputy defense has regressed and the project's central claim
 * is broken — fix the implementation, not the assertions.
 */

import { describe, expect, it } from "vitest";
import { runDemo } from "../runner.js";

describe("shopping-agent demo", () => {
  it("end-to-end: legitimate purchase allowed; hostile wire denied", async () => {
    const run = await runDemo();

    // ── allow leg ────────────────────────────────────────────────────
    expect(run.legitimatePurchaseSucceeded).toBe(true);

    // ── deny leg ─────────────────────────────────────────────────────
    expect(run.hostileWireDenied).toBe(true);
    expect(run.hostileWireDenialReason).not.toBeNull();
    // Reason should mention the failing caveat (the tool != check).
    expect(run.hostileWireDenialReason).toMatch(/tool/i);

    // ── the load-bearing assertion ───────────────────────────────────
    // bank.wire MUST NOT have reached the underlying mock shop. If it
    // did, the capability boundary failed and the demo is broken.
    const wireCalls = run.underlyingCalls.filter((c) => c.tool === "bank.wire");
    expect(wireCalls).toEqual([]);

    // ── audit trail ──────────────────────────────────────────────────
    // Every guarded call should produce a receipt — search, purchase,
    // and the denied wire attempt = 3 receipts.
    expect(run.receipts.length).toBeGreaterThanOrEqual(3);
  });

  it("legitimate calls reached the shop (catalog.search + checkout.purchase)", async () => {
    const run = await runDemo();
    const tools = run.underlyingCalls.map((c) => c.tool);
    expect(tools).toContain("catalog.search");
    expect(tools).toContain("checkout.purchase");
  });

  it("the demo runs deterministically — running it twice gives the same shape", async () => {
    const a = await runDemo();
    const b = await runDemo();
    expect(a.legitimatePurchaseSucceeded).toBe(b.legitimatePurchaseSucceeded);
    expect(a.hostileWireDenied).toBe(b.hostileWireDenied);
    expect(a.underlyingCalls.length).toBe(b.underlyingCalls.length);
  });
});
