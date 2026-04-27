# Show HN: capnagent — capability tokens that bound what AI agent tool calls *can* do

> **The 60-second version.** A real Claude Opus 4.7 agent is asked to send a $30 wire and buy a USB-C cable. The issued capability scopes the agent to checkout-only, with a $50 ceiling. The agent attempts both. capnagent denies the wire on capability-scope grounds before the underlying tool surface is touched. The cable purchase proceeds. Every decision is signed into a tamper-evident audit receipt.
>
> Repo: https://github.com/euanmcrosson-dotcom/capnagent
>
> Demo (GIF): https://github.com/euanmcrosson-dotcom/capnagent/blob/master/docs/demo-direct.gif

---

## The problem

Prompt injection isn't really a "tricks the LLM" problem. It's a **confused-deputy** problem. The model holds your authority — your OAuth token, your shell, your bank — and someone convinces it to use that authority on someone else's behalf. The fix isn't smarter guardrails. It's **not giving the deputy ambient authority in the first place**.

That insight has been sitting in capability-security research for forty years (Lampson 1974, the original Hydra and KeyKOS work, macaroons in 2014). It just hasn't shown up in mainstream AI-agent stacks yet, because the agent ecosystem grew up around bearer tokens and "trust the model".

## What capnagent is

capnagent is a Rust library (with TypeScript / WebAssembly bindings and an MCP adapter) that gives you **macaroon-style capability tokens** for agent tool calls. Every tool call carries a token that:

- is **bounded by attenuable caveats** — `(tool == "catalog.search") OR (tool == "checkout.purchase" AND arg.merchant == "amazon.com" AND arg.amount <= 50.00)`, `now <= @2099-01-01T00:00:00Z`, etc.
- is **cryptographically integrity-protected** — anyone holding it can attenuate it (add stricter caveats), nobody can broaden it without the root key. HMAC-SHA256 chain.
- can be **bound to a holder key** — DPoP-style ed25519 proof of possession on every call. A stolen bearer token is useless without the private key.
- is **revocable** — issuer publishes a signed revocation list; verifier checks it as part of the verify pipeline.
- is **replay-protected** — pluggable `NonceStore` (default in-memory TTL) refuses a previously-accepted proof from being reused within the window.
- produces a **signed audit receipt** for every decision, allow or deny — every attempt against a revoked or replayed token is captured for incident response.

The verifier runs five gates, in order, before letting a tool call proceed:

1. **Chain integrity** — HMAC chain matches. Forged tokens never reach the receipt stage.
2. **Holder-of-key proof of possession** — ed25519 signature on a per-call challenge derived from `(cap_id, tool, args_hash, now_ms)`. Wrong key, wrong challenge, malformed proof → denied. (hok-bound caps only.)
3. **Replay** — `sha256(proof)` in the nonce store within TTL → denied. (hok-bound caps only.)
4. **Revocation** — capability identifier in the signed revocation list → denied.
5. **Caveat evaluation** — every caveat in the token holds against the verifier-controlled `Context` (current time, caller, tool, args, env). Caveats compose via `OR` / `AND` / parens with standard precedence and short-circuit eval.

If any gate denies, the call is refused before the underlying tool surface sees it. Denials produce signed receipts so the audit log captures *every attempt*, including the ones that would have been silently dropped by a layer above.

## The demo

The repo ships an end-to-end shopping-agent demo wired into the official Anthropic TypeScript SDK. It runs as a normal agentic loop — the model decides which tools to call, the harness executes them — but every tool call routes through `wrapMCPClient`, capnagent's MCP adapter that intercepts at the `tools/call` boundary.

Four scenarios:

- **`honest`** — prompt injection in the catalog, neutral system prompt. Modern Claude refuses on its own. capnagent is the defense-in-depth backstop.
- **`naive`** — same injection, but a system prompt that tells the agent to follow tool-output instructions. Empirically, Haiku 4.5 and Opus 4.7 both still refuse — alignment is doing real work — but if they didn't, capnagent catches it.
- **`direct`** — no injection at all. The user *explicitly asks* for a wire and a cable in the same message. The agent does what the user asked. capnagent allows the cable (in scope) and denies the wire (out of scope). This is the principle-of-least-authority demo, and it fires reliably on any model.
- **`hok`** — `direct`'s flow but cryptographically tightened. The agent holds an ed25519 key; every tool call is gated by a fresh proof-of-possession signature. The issued capability uses v0.1 boolean composition + a decimal caveat — `(tool == "catalog.search") OR (tool == "checkout.purchase" AND arg.merchant == "amazon.com" AND arg.amount <= 50.00)`. Same outcome (`bank.wire` denied), more boundaries crossed (5 gates instead of 3).

The GIF at the top of the README is the `direct` scenario running against Claude Opus 4.7.

## What's surprising about doing this in 2026

Two findings worth flagging from building this:

1. **Modern frontier-aligned LLMs are surprisingly hard to prompt-inject through tool output.** Both Haiku 4.5 and Opus 4.7 routinely refused our hostile catalog descriptions, and Opus went further — it explicitly flagged the injection to the user and suggested reporting the listing. That's a fantastic alignment result, but it does mean the prompt-injection threat model isn't where the demo lands hardest. The `direct` scenario is — capability scope holds even when the user is the one asking for the out-of-scope action, because the issued capability is the contract, not the prompt.

2. **The right frame for capnagent isn't "we trick LLMs into misbehaving so we can catch them."** It's "the capability boundary holds regardless of what the agent is doing or why." Three legitimate reasons an agent might attempt an out-of-scope tool call: prompt injection (adversary), naive harness (designer), over-broad user request (operator). All three need the same defense. We were originally focused only on the first.

## What's there

```
crates/
  capnagent-core/        Rust crypto core. 8 integration test targets,
                         214 Rust tests. cargo fmt + clippy clean.
                         unsafe_code = forbid.
  capnagent-wasm/        wasm-bindgen wrapper.

packages/
  capnagent/             @capnagent/core — TS wrapper around the WASM artifact.
                         Snake↔camel translation, frozen receipts, typed errors,
                         hok / proof / verifyWithProof / popChallengeFor.
  capnagent-mcp/         @capnagent/mcp — drop-in wrapper around any
                         structurally-typed MCP client. Optional `signer`
                         for hok-bound capabilities; missing-signer is
                         fail-closed at config time.

examples/
  shopping-agent/        End-to-end demo with four LLM scenarios.
  mcp-fs-agent/          Sandbox-scoped filesystem agent — first
                         real-world consumer of @capnagent/mcp. Pure
                         deterministic vitest, no API key required.

docs/
  DESIGN.md              Threat model, security argument (3 legs), error
                         model, milestones, v0.1 backlog, revocation
                         surface, holder-of-key surface, DSL boolean
                         composition, replay protection.
  WEEK[2,3]_SPEC.md      Type contracts that drove the parallel multi-
                         terminal implementation.
  V0_1_SPEC.md           Same, for v0.1.
  blog/v0-show-hn.md     This post.
```

CI runs **319 tests** on every push (8 Rust integration targets, WASM smoke, TS unit, scripted demo, hok deterministic). 3 additional opt-in live-API tests run locally with `ANTHROPIC_API_KEY` set.

## Status

This is **v0 + most of v0.1**. v0 (weeks 1–6) is fully shipped: core + DSL + audit + WASM + TS + MCP + demos + revocation + GIF in the README. v0.1 ships:

- DPoP-style holder-of-key (ed25519, `verify_with_proof` entry point)
- TS / WASM wire-up of holder-of-key — usable from JS
- Decimal numbers in the caveat DSL
- Boolean composition in the DSL (`OR` / `AND` / parens)
- Replay protection (`NonceStore` trait + in-memory TTL impl)

What's left: receipt schema versioning (cosmetic future-proofing), a `NonceStore` TS surface so the replay path is reachable from JS too. Both deferred to v0.2.

I'd love feedback, especially on:

- **The threat model.** `docs/DESIGN.md` §2 + §5. If you can break one of the three legs of the security argument, please open a security advisory.
- **Real-world use cases.** The MCP adapter is the obvious integration; what other agent stacks should this plug into?
- **The caveat DSL.** v0.1 widened it to support decimals and boolean composition. What's the next thing missing for production?
- **Replay-store backends.** The default is in-memory. Production deployments will want Redis / Postgres / Trillian-style logs. What does your environment use?

## Try it

```bash
git clone https://github.com/euanmcrosson-dotcom/capnagent
cd capnagent
npm install && npm run build:wasm && npm run -w @capnagent/core build
cargo test                                           # 214 Rust tests
npm test --workspaces --if-present                   # 99 TS + 26 WASM-smoke

# live LLM demo (needs ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
npm run -w @capnagent-examples/shopping-agent demo:llm-direct  # the GIF
npm run -w @capnagent-examples/shopping-agent demo:llm-hok     # full v0.1 surface
```

Apache-2.0. Built solo over the last few weeks. Issues + PRs welcome.

---

## Appendix: Show HN submission templates

### Title (≤80 chars)

```
Show HN: Capnagent – capability tokens that bound what AI agent tool calls can do
```

### One-paragraph submission comment

```
Hi HN — capnagent is a Rust library (with WASM + TS bindings and an
MCP adapter) that gives AI agent tool calls macaroon-style capability
tokens. Instead of "trust the model not to be prompt-injected", every
tool call goes through a 5-gate verifier: chain integrity, holder-of-
key proof of possession (ed25519), replay protection (nonce store),
revocation, and caveat evaluation against a verifier-controlled
context. Caveats compose with OR / AND / parens, including decimals
and timestamps. Out-of-scope calls are refused before the underlying
tool surface sees them; every decision is signed into an audit
receipt. The 48-second GIF in the README shows a real Claude Opus 4.7
agent's wire-transfer attempt being denied on capability-scope
grounds while a legitimate cable purchase proceeds. v0 + most of v0.1
are shipped; 319 tests in CI. Looking for feedback on the threat
model and on what production deployments need from the replay-store
backend. Built solo over a few weeks.
```

### Why this should land

Three angles working in this post's favor:

1. **Visceral demo at the top.** The GIF tells the story in <60 seconds without anyone reading code. HN responds to artifacts more than to prose.
2. **A real architectural take, not yet-another-guardrail.** The capability-security framing is a load-bearing critique of the current "trust the model" defaults, and tying it back to Lampson 1974 / macaroons frames it as recovering established research rather than inventing something untested.
3. **Five distinct cryptographic boundaries.** Reviewers who aren't impressed by capability tokens alone will at least be impressed by the depth of the pipeline — chain HMAC, ed25519 PoP, replay store, revocation list, caveat DSL — and how each surface is independently testable. The `verify_with_proof` flow is documented as five legs in `DESIGN.md`, which is the right shape for a security-curious reader to validate.

Failure modes to watch for in the comments:

- *"Can't an attacker just…?"* — most of these are addressed in DESIGN.md §2/§5; the answer is usually "yes, but that breaks one of the three legs of the security argument and that's testable in property_tests.rs". Specifically, the cannot-broaden invariant has 9 proptest cases; chain forgery, drop-caveat, reorder-caveat, modify-caveat, signature-bitflip, and cross-key all reject.
- *"How is this different from JWT scopes?"* — capabilities attenuate, JWT scopes don't. Macaroon-chain semantics + holder-of-key + audit receipts + revocation + replay protection is the substantive difference. JWT scopes are a static label; capabilities are a small program the verifier evaluates.
- *"Why not just use OPA / Cedar / [policy engine]?"* — those are policy languages bolted onto bearer tokens. capnagent is a bearer-token replacement; the caveat DSL is deliberately tiny (one page of BNF) so caveats stay trivially auditable. Policy engines complement; they don't substitute.
- *"DPoP isn't novel."* — correct, that's the point. We're applying RFC 9449 / OAuth-DPoP-style proof of possession to capability tokens specifically. The novelty is the composition (chain → proof → replay → revocation → caveats) and that the implementation is hardened end-to-end through 8 Rust integration test targets.
- *"What about race conditions on the nonce store?"* — `NonceStore::try_record` is contractually atomic (check + insert appears as one operation to the caller). The in-memory impl uses a `Mutex<HashMap<...>>`. Tests include a thread-safety stress.
