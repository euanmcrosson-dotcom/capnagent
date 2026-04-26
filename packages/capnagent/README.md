# @capnagent/core

> Idiomatic TypeScript wrapper around the
> [capnagent](https://github.com/euanmcrosson-dotcom/capnagent) WASM core.
> Capability-based authority tokens for AI agent tool calls.

Status: **v0 — pre-release.** API may change. See the repo's
[`docs/DESIGN.md`](https://github.com/euanmcrosson-dotcom/capnagent/blob/master/docs/DESIGN.md)
for the threat model and the
[`docs/WEEK3_SPEC.md`](https://github.com/euanmcrosson-dotcom/capnagent/blob/master/docs/WEEK3_SPEC.md)
for the locked TS contract.

## Install

```bash
npm install @capnagent/core
```

## Quick start

```ts
import { Issuer, Verifier, Auditor, init } from "@capnagent/core";

await init();

const rootKey = new Uint8Array(32);
crypto.getRandomValues(rootKey);

const cap = Issuer.fromKey(rootKey)
  .issue("buy")
  .caveat(`arg.merchant == "amazon.com"`)
  .caveat("arg.amount <= 50")
  .caveat("now <= @2099-01-01T00:00:00Z")
  .build();

const verifier = new Verifier(rootKey);
const auditor  = new Auditor(crypto.getRandomValues(new Uint8Array(32)));

const receipt = verifier.verifyWithContext(
  cap,
  {
    caller: "agent:planner",
    tool:   "http.post",
    args:   { merchant: "amazon.com", amount: 49 },
  },
  auditor,
);

if (receipt.outcome.kind === "allowed") {
  // proceed with the tool call
} else {
  console.log("denied:", receipt.outcome.reason);
}
```

## Bundler / test-runner setup

`@capnagent/core` ships a real WebAssembly module under the hood
(`crates/capnagent-wasm/pkg/capnagent_wasm_bg.wasm`). Most modern
bundlers and runtimes load this directly, but **vite, vitest, and a few
others need two small plugins** to handle the
[ESM-Wasm integration proposal](https://github.com/WebAssembly/esm-integration):

```bash
npm install --save-dev vite-plugin-wasm vite-plugin-top-level-await
```

```ts
// vite.config.ts  /  vitest.config.ts
import { defineConfig } from "vitest/config";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
  // ...
});
```

Without these, you'll see a build-time error like:

> "ESM integration proposal for Wasm" is not supported currently. Use
> vite-plugin-wasm or other community plugins to handle this.

Webpack ≥ 5, esbuild, Rollup with `@rollup/plugin-wasm`, and Node 20+
(with `--experimental-wasm-modules`) all load the module without
additional configuration.

## API

The full surface is locked in [`docs/WEEK3_SPEC.md`
§3.2](https://github.com/euanmcrosson-dotcom/capnagent/blob/master/docs/WEEK3_SPEC.md)
of the upstream repo. Highlights:

- `init()` — must be awaited once at process startup.
- `Issuer.fromKey(key)` / `.issue(id).caveat(...).build()` — mint
  capabilities.
- `Capability.parse(token)` / `.serialize()` — wire-format encode and
  decode.
- `new Verifier(key).verify(cap)` — chain-only check; throws
  `CapabilityChainError` on tamper.
- `new Verifier(key).verifyWithContext(cap, ctx, auditor)` — full
  pipeline; returns a signed `Receipt` carrying
  `outcome: { kind: "allowed" } | { kind: "denied"; reason }`.
- `new Auditor(key).verify(receipt)` — recompute the receipt's HMAC and
  reject on tamper.
- Errors: `CapabilityError` → `CapabilityChainError`,
  `CapabilityAuditError`. Denial is **not** an error — it is an
  `Outcome` on the returned `Receipt`.

## Caveat DSL

The grammar is tiny by design:

```
predicate   ::= ident op value
ident       ::= now | caller | tool | arg.<key>… | env.<key>
op          ::= == | != | <= | >= | < | > | matches
value       ::= "string" | number | @rfc3339-timestamp
```

Full BNF and reserved-ident table in
[`docs/WEEK2_SPEC.md`
§2.2](https://github.com/euanmcrosson-dotcom/capnagent/blob/master/docs/WEEK2_SPEC.md).

## Building from source

The WASM artifact is gitignored. Run once after a fresh clone:

```bash
npm install
npm run build:wasm   # → crates/capnagent-wasm/pkg/
npm test --workspaces
```

## License

Apache-2.0.
