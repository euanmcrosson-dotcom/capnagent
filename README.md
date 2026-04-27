# capnagent

> Capability-based authority tokens for AI agent tool calls. Prompt
> injection is a confused-deputy attack — capnagent removes the deputy's
> ambient authority. Every tool call carries a macaroon-style capability
> that is attenuable, revocable, and audit-logged. An agent under
> attack — or simply asked to do something it wasn't authorized for —
> still cannot exceed its scope.

![capnagent denies a wire transfer that exceeds the issued capability's scope, while allowing the in-scope cable purchase](docs/demo-direct.gif)

The clip above is the `demo:llm-direct` scenario: a real Claude Opus 4.7
agent driven by the Anthropic SDK is asked to send a $30 wire **and**
buy a USB-C cable. The issued capability scopes the agent to
`tool == "checkout.purchase"`. The wire fires; capnagent denies it
before the underlying tool surface is touched; the cable purchase
proceeds normally. Every decision is signed into an audit receipt.

```
→ bank.wire {"to":"bob@example.com","amount":30}
  ✗ DENIED  caveat failed: tool == "checkout.purchase"

bank.wire reached underlying shop: no
capnagent denied the wire on capability-scope grounds —
the user's direct request exceeded what the issued capability permits.
```

## Status: v0 shipped, v0.1 in progress

| Phase | Deliverable | Status |
|---:|---|:---:|
| v0 wk 1 | Macaroon core in Rust: issue, attenuate, verify. 9 proptest cases proving the cannot-broaden invariant. | ✅ |
| v0 wk 2 | Caveat DSL parser + evaluator. Verifier-controlled `Context`. Audit-log signer. 99 tests across 4 targets. | ✅ |
| v0 wk 3 | WASM bindings + `@capnagent/core` (TS) + `@capnagent/mcp` adapter. 55 vitest cases. | ✅ |
| v0 wk 4 | Shopping-agent demo (scripted + LLM-driven via Anthropic SDK). Scenarios: `honest`, `naive`, `direct`, `hok`. | ✅ |
| v0 wk 5 | Signed revocation list + integrated 3-gate verify pipeline. 18 tests. | ✅ |
| v0 wk 6 | Public release: README, threat model, demo video, blog post. | ✅ |
| v0.1 | DPoP holder-of-key — Rust core (ed25519, `verify_with_proof`, 4-gate pipeline) + WASM bindings + `@capnagent/core` TS surface + `@capnagent/mcp` `signer` field + demo `hok` scenario. 17 Rust tests + cross-package TS tests. | ✅ |
| v0.1 | Decimal numbers in the caveat DSL — BNF widened to `\d+(\.\d+)?`, exact-binary equality. 22 new tests. | ✅ |
| v0.1 | DSL boolean composition — `OR` / `AND` / parens with standard precedence and short-circuit eval. 24 new tests. | ✅ |
| v0.1 | Replay protection — `NonceStore` trait + `InMemoryNonceStore` impl, opt-in via `Verifier::with_nonce_store`. Integrated into `verify_with_proof` as a 5th gate. 14 tests. | ✅ |
| v0.1 | Receipt schema versioning. | next |

CI runs **293 tests** on every push (8 Rust integration targets, WASM
smoke, TS unit, scripted demo, hok deterministic); 3 additional opt-in
live-API tests run locally with `ANTHROPIC_API_KEY` set.

## What's in the repo

```
crates/
  capnagent-core/        Rust crypto core (Issuer, Verifier, Auditor,
                         Capability, Caveat, Context, caveat DSL).
  capnagent-wasm/        wasm-bindgen wrapper around capnagent-core.

packages/
  capnagent/             @capnagent/core — idiomatic TS wrapper around
                         the WASM artifact. Snake↔camel translation,
                         frozen receipts, typed error hierarchy.
  capnagent-mcp/         @capnagent/mcp — drop-in wrapper around any
                         structurally-typed MCP client (wrapMCPClient,
                         guardCall, CapabilityDeniedError).

examples/
  shopping-agent/        End-to-end demo. Four LLM scenarios + one
                         deterministic vitest spec. The clip above is
                         from this package.
  mcp-fs-agent/          First real-world consumer of @capnagent/mcp:
                         a sandbox-scoped filesystem agent. Reads
                         inside a configured prefix are allowed; reads
                         outside, plus all writes, are denied before
                         the underlying client sees them.

docs/
  DESIGN.md              Threat model, security argument, error model,
                         v0 milestones, v0.1 backlog.
  WEEK2_SPEC.md          Type contracts that drove the parallel
                         3-terminal week-2 implementation.
  WEEK3_SPEC.md          Same, for the WASM/TS surface.
  demo-direct.gif        The recording above.
```

## Quick taste — Rust

```rust
use capnagent_core::{Issuer, Verifier};

let secret = b"32-bytes-from-a-csprng-please-thanks";

let cap = Issuer::from_key(secret)
    .issue("buy")
    .caveat(r#"tool == "checkout.purchase""#)
    .caveat(r#"arg.merchant == "amazon.com""#)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();

let token = cap.serialize();             // base64url, ~250 bytes
let parsed = capnagent_core::Capability::parse(&token).unwrap();
Verifier::new(secret).verify(&parsed).unwrap();
```

## Quick taste — TypeScript / MCP

```ts
import { Issuer, Verifier, Auditor, init } from "@capnagent/core";
import { wrapMCPClient } from "@capnagent/mcp";

await init();

const buyCap = Issuer.fromKey(rootKey)
  .issue("buy")
  .caveat(`tool == "checkout.purchase"`)
  .caveat(`arg.merchant == "amazon.com"`)
  .caveat("arg.amount <= 50")
  .build();

const guarded = wrapMCPClient(mcpClient, {
  capability: buyCap,
  verifier: new Verifier(rootKey),
  auditor:  new Auditor(auditKey),
  context: (toolName, args) => ({ caller: "agent:planner", tool: toolName, args }),
  onReceipt: (r) => auditSink.append(r),
});

// All callTool() routes through the verifier first. Out-of-scope
// calls throw CapabilityDeniedError before the underlying tool runs.
await guarded.callTool("checkout.purchase", { ... });
```

## Build & run the demo locally

```bash
# Rust core, WASM artifact, TS packages, demo runner — all from npm scripts at root
npm install
npm run build:wasm                       # produces crates/capnagent-wasm/pkg/
npm run -w @capnagent/core build         # produces packages/capnagent/dist/

# Tests (no API key required)
cargo test
npm test --workspaces --if-present       # 55 TS + 22 WASM-smoke + 3 scripted demo

# Live LLM demo (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
npm run -w @capnagent-examples/shopping-agent demo:llm-direct

# Sandbox-scoped filesystem agent (no API key)
npm run -w @capnagent-examples/mcp-fs-agent demo
```

The shopping-agent's four scenarios are documented in
[`examples/shopping-agent/README.md`](examples/shopping-agent/README.md).
The filesystem agent — the first real-world consumer of `@capnagent/mcp` —
is in [`examples/mcp-fs-agent/README.md`](examples/mcp-fs-agent/README.md).

## Security model

The full threat model is in [`docs/DESIGN.md`](docs/DESIGN.md) §2. The
three load-bearing legs of the security argument are §5; any
vulnerability that breaks one of them is in scope per
[`SECURITY.md`](SECURITY.md):

1. **Cryptographic integrity.** A holder cannot broaden a capability
   without the root key (HMAC-SHA256 macaroon chain).
2. **Verifier-controlled context.** Caveats evaluate against facts the
   *verifier* knows, not facts the agent claims.
3. **Trivially-auditable caveats.** A human can read every caveat on a
   token and predict exactly what it permits in under 30 seconds.

The property tests in
`crates/capnagent-core/tests/property_tests.rs` encode invariant 1 in
code. Any reported violation must be reproducible there or in an
equivalent harness.

## License

[Apache-2.0](LICENSE).
