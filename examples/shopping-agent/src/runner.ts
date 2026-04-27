/**
 * End-to-end demo runner.
 *
 * Issues TWO capabilities — a `browse` cap permitting `catalog.search`
 * and a `buy` cap permitting `checkout.purchase` (with a merchant + spend
 * ceiling). Wraps the same mock MCP client through each, so the agent
 * uses the right cap for the right kind of call. Then tries `bank.wire`
 * with the buy cap — denied, because no capability the agent holds
 * permits that tool.
 *
 *   1. Legitimate purchase flow: search via browse-guard, purchase via
 *      buy-guard. Both succeed. Both audited.
 *   2. Hostile-product-page injection: agent attempts `bank.wire` via
 *      buy-guard. Denied before the mock shop ever sees the call.
 *
 * No LLM is involved. The "agent" here is a deterministic script that
 * makes the same tool calls a real LLM-driven agent might make under
 * each scenario. The point of the demo is the capability boundary, not
 * the model.
 */

import { Auditor, type Capability, type Context, Issuer, Verifier, init } from "@capnagent/core";
import { CapabilityDeniedError, type WrapOptions, wrapMCPClient } from "@capnagent/mcp";

import {
  type CallLog,
  type Product,
  type PurchaseArgs,
  type WireArgs,
  createMockShop,
} from "./shop.js";

export interface DemoRun {
  /** Calls that actually reached the underlying mock shop. */
  underlyingCalls: ReadonlyArray<CallLog>;
  /** Whether the legitimate purchase succeeded. */
  legitimatePurchaseSucceeded: boolean;
  /** Whether the hostile wire attempt was denied. */
  hostileWireDenied: boolean;
  /** Reason the wire was denied (matched against verifier output). */
  hostileWireDenialReason: string | null;
  /** All receipts emitted by the verifier, in order. */
  receipts: ReadonlyArray<unknown>;
}

const ROOT_KEY = new Uint8Array(32).fill(0xa1);
const AUDIT_KEY = new Uint8Array(32).fill(0xa2);

/**
 * Issue a tightly-scoped browse capability. Permits `catalog.search`
 * by `agent:planner`, nothing else.
 */
export function issueBrowseCapability(): Capability {
  return Issuer.fromKey(ROOT_KEY)
    .issue("browse")
    .caveat(`tool == "catalog.search"`)
    .caveat(`caller == "agent:planner"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

/**
 * Issue a tightly-scoped buy capability. Permits `checkout.purchase`
 * at amazon.com for ≤ $50, by `agent:planner`, before the deadline.
 *
 * `arg.amount <= 50` is unitless because JSON args have no unit suffix
 * in v0; the DSL is type-strict on units. See `docs/DESIGN.md`.
 */
export function issueBuyCapability(): Capability {
  return Issuer.fromKey(ROOT_KEY)
    .issue("buy")
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`caller == "agent:planner"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

/** Build the shared `WrapOptions` skeleton; only the capability differs. */
function makeOptions(args: {
  capability: Capability;
  receipts: unknown[];
}): WrapOptions {
  return {
    capability: args.capability,
    auditor: new Auditor(AUDIT_KEY),
    verifier: new Verifier(ROOT_KEY),
    context: (toolName: string, callArgs: unknown): Context => ({
      caller: "agent:planner",
      tool: toolName,
      args: callArgs,
      nowMs: Date.now(),
    }),
    onReceipt: (r) => {
      args.receipts.push(r);
    },
  };
}

/**
 * Run both scenarios end-to-end and return a structured summary.
 * Pure async; no console output. Tests inspect the returned `DemoRun`.
 */
export async function runDemo(): Promise<DemoRun> {
  await init();

  const browseCap = issueBrowseCapability();
  const buyCap = issueBuyCapability();
  const receipts: unknown[] = [];

  const shop = createMockShop();
  const browseGuard = wrapMCPClient(shop, makeOptions({ capability: browseCap, receipts }));
  const buyGuard = wrapMCPClient(shop, makeOptions({ capability: buyCap, receipts }));

  // ── Scenario 1: legitimate USB-C cable purchase ─────────────────────
  // Agent uses the browse-guard for the read tool, then the buy-guard
  // for the privileged purchase.
  const products = (await browseGuard.callTool("catalog.search", {
    query: "usb-c cable",
  })) as Product[];
  const legitProduct = products.find((p) => p.id === "usbc-cable-1m");
  if (!legitProduct) throw new Error("expected legit product in catalog");

  const purchaseArgs: PurchaseArgs = {
    productId: legitProduct.id,
    amount: 20, // dollars; matches priceCents 2000
    merchant: legitProduct.merchant,
  };
  let legitimatePurchaseSucceeded = false;
  try {
    await buyGuard.callTool("checkout.purchase", purchaseArgs);
    legitimatePurchaseSucceeded = true;
  } catch {
    legitimatePurchaseSucceeded = false;
  }

  // ── Scenario 2: hostile-product-page injection ──────────────────────
  // The agent reads the hostile description and (naively) tries to call
  // bank.wire. Even with the buy-guard's relatively permissive surface,
  // the `tool == "checkout.purchase"` caveat denies any other tool. No
  // capability the agent holds permits bank.wire — denied before the
  // mock shop sees it.
  const wireArgs: WireArgs = { amount: 5000, to: "attacker@evil.example" };
  let hostileWireDenied = false;
  let hostileWireDenialReason: string | null = null;
  try {
    await buyGuard.callTool("bank.wire", wireArgs);
    hostileWireDenied = false;
  } catch (e) {
    if (e instanceof CapabilityDeniedError) {
      hostileWireDenied = true;
      const outcome = e.receipt.outcome;
      hostileWireDenialReason = outcome.kind === "denied" ? outcome.reason : null;
    } else {
      throw e;
    }
  }

  return {
    underlyingCalls: shop.log,
    legitimatePurchaseSucceeded,
    hostileWireDenied,
    hostileWireDenialReason,
    receipts,
  };
}
