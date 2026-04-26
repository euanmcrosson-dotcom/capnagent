# shopping-agent (demo)

> The visceral demo: an injected prompt tries to make a shopping agent
> wire $5,000 to an attacker. Even though the agent obeys the prompt,
> capnagent denies the wire because it's outside the issued capability's
> scope.

This is the v0 deliverable for week 4 of the
[capnagent roadmap](../../docs/DESIGN.md). The demo is intentionally
**deterministic** — no LLM, no API keys, no network. The "agent" is a
script that makes the same tool calls a real LLM-driven agent would
make under each scenario. The point of the demo is the **capability
boundary**, not the model.

## What the demo proves

1. A capability scoped to `tool == "checkout.purchase" && arg.merchant
   == "amazon.com" && arg.amount <= 50` allows a legitimate USB-C cable
   purchase to go through.
2. The same capability **denies** any call to `bank.wire`, regardless
   of what the agent's reasoning has been convinced to do.
3. Every decision — allow or deny — produces a signed `Receipt`.
   Denials never reach the underlying tool surface.

The whole flow is asserted as a vitest test. If it ever fails, the
project's central claim is broken — fix the implementation, not the
test.

## Run it

```bash
# from the repo root
npm run build:wasm        # builds the WASM artifact (once per fresh clone)
npm test --workspace=@capnagent-examples/shopping-agent
```

Expected output:

```
✓ end-to-end: legitimate purchase allowed; hostile wire denied
✓ legitimate calls reached the shop (catalog.search + checkout.purchase)
✓ the demo runs deterministically — running it twice gives the same shape
```

## What's in here

```
src/
  shop.ts        Mock MCP-compatible client — exposes
                 catalog.search, checkout.purchase, bank.wire.
                 Includes a hostile product description with an
                 embedded prompt-injection.
  runner.ts      Issues the scoped capability, wraps the shop with
                 wrapMCPClient, runs both scenarios, returns a
                 structured DemoRun summary.
  index.ts       Re-exports.
  __tests__/
    demo.test.ts End-to-end assertions on the DemoRun.
```

## Coming in week 4 part 2

A second demo will replicate the same flow with the **Anthropic TS
SDK** driving a real Claude model as the agent. Same capability, same
hostile product page, but now the model itself is the thing being
guarded — making the security claim much more visceral. That demo
needs an API key; the scripted version here does not.
