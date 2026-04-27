# Show HN: capnagent — capability tokens that bound what AI agent tool calls *can* do

> **The 60-second version.** A real Claude Opus 4.7 agent is asked to send a $30 wire and buy a USB-C cable. The issued capability scopes the agent to `tool == "checkout.purchase"`. The agent attempts both. capnagent denies the wire on capability-scope grounds before the underlying tool surface is touched. The cable purchase proceeds. Every decision is signed into a tamper-evident audit receipt.
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

- is **bounded by attenuable caveats** — `tool == "checkout.purchase"`, `arg.merchant == "amazon.com"`, `arg.amount <= 50`, `now <= @2099-01-01T00:00:00Z`
- is **cryptographically integrity-protected** — anyone holding it can attenuate it (add stricter caveats), nobody can broaden it without the root key. HMAC-SHA256 chain.
- is **revocable** — issuer publishes a signed revocation list; verifier checks it as part of the verify pipeline
- produces a **signed audit receipt** for every decision, allow or deny — every attempt against a revoked token is captured for incident response

The verifier checks three things, in order, before letting a tool call proceed:

1. **Chain integrity** — HMAC chain matches. Forged tokens never reach the receipt stage.
2. **Revocation** — capability identifier not in the signed revocation list.
3. **Caveat evaluation** — every caveat in the token holds against the verifier-controlled `Context` (current time, caller, tool, args, env).

If any of those fail, the call is refused before the underlying tool surface sees it.

## The demo

The repo ships an end-to-end shopping-agent demo wired into the official Anthropic TypeScript SDK. It runs as a normal agentic loop — the model decides which tools to call, the harness executes them — but every tool call routes through `wrapMCPClient`, capnagent's MCP-adapter that intercepts at the `tools/call` boundary.

Three scenarios:

- **`honest`** — prompt injection in the catalog, neutral system prompt. Modern Claude refuses on its own. capnagent is the defense-in-depth backstop.
- **`naive`** — same injection, but a system prompt that tells the agent to follow tool-output instructions. Empirically, Haiku 4.5 and Opus 4.7 both still refuse — alignment is doing real work — but if they didn't, capnagent catches it.
- **`direct`** — no injection at all. The user *explicitly asks* for a wire and a cable in the same message. The agent does what the user asked. capnagent allows the cable (in scope) and denies the wire (out of scope). This is the principle-of-least-authority demo, and it fires reliably on any model.

The GIF at the top of the README is the `direct` scenario running against Claude Opus 4.7.

## What's surprising about doing this in 2026

Two findings worth flagging from building this:

1. **Modern frontier-aligned LLMs are surprisingly hard to prompt-inject through tool output.** Both Haiku 4.5 and Opus 4.7 routinely refused our hostile catalog descriptions, and Opus went further — it explicitly flagged the injection to the user and suggested reporting the listing. That's a fantastic alignment result, but it does mean the prompt-injection threat model isn't where the demo lands hardest. The `direct` scenario is — capability scope holds even when the user is the one asking for the out-of-scope action, because the issued capability is the contract, not the prompt.

2. **The right frame for capnagent isn't "we trick LLMs into misbehaving so we can catch them."** It's "the capability boundary holds regardless of what the agent is doing or why." Three legitimate reasons an agent might attempt an out-of-scope tool call: prompt injection (adversary), naive harness (designer), over-broad user request (operator). All three need the same defense. We were originally focused only on the first.

## What's there

```
crates/
  capnagent-core/        Rust crypto core. 137 tests across 6 integration
                         targets. cargo fmt + clippy clean. unsafe_code = forbid.
  capnagent-wasm/        wasm-bindgen wrapper.

packages/
  capnagent/             @capnagent/core — TS wrapper around the WASM artifact.
                         Snake↔camel translation, frozen receipts, typed errors.
  capnagent-mcp/         @capnagent/mcp — drop-in wrapper around any
                         structurally-typed MCP client.

examples/
  shopping-agent/        End-to-end demo with three LLM scenarios.

docs/
  DESIGN.md              Threat model, security argument, error model,
                         milestones, v0.1 backlog, revocation surface.
  WEEK[2,3]_SPEC.md      Type contracts that drove the parallel multi-terminal
                         implementation.
  blog/v0-show-hn.md     This post.
```

CI runs **196 tests** on every push (Rust property + integration + revocation, WASM smoke, TS unit, scripted demo). 3 additional opt-in live-API tests run locally with `ANTHROPIC_API_KEY` set.

## Status

This is **v0**. Weeks 1–5 of the roadmap are shipped (core + DSL + audit + WASM + TS adapter + MCP wrapper + demos + revocation). Week 6 is the public release — README polish, this post, threat model writeup. v0.1 backlog is documented in `docs/DESIGN.md` §9: DPoP-style holder-of-key, decimal numbers in the caveat DSL, disjunctions, replay protection, receipt schema versioning.

I'd love feedback, especially on:

- **The threat model.** `docs/DESIGN.md` §2 + §5. If you can break one of the three legs of the security argument, please open a security advisory.
- **Real-world use cases.** The MCP adapter is the obvious integration; what other agent stacks should this plug into?
- **The caveat DSL.** Currently 7 reserved identifiers + 7 operators. What's missing for production?

## Try it

```bash
git clone https://github.com/euanmcrosson-dotcom/capnagent
cd capnagent
npm install && npm run build:wasm && npm run -w @capnagent/core build
cargo test                                           # 137 Rust tests
npm test --workspaces --if-present                   # 55 TS + 22 WASM-smoke + 3 scripted demo

# live LLM demo (needs ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY=sk-ant-...
npm run -w @capnagent-examples/shopping-agent demo:llm-direct
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
Hi HN — capnagent is a Rust library (with WASM + TS bindings and an MCP
adapter) that gives AI agent tool calls macaroon-style capability tokens.
Instead of "trust the model not to be prompt-injected", every tool call
carries a token with attenuable caveats (`tool == "x"`, `arg.amount <= 50`,
`expires <= ...`); the verifier refuses anything outside scope before the
underlying tool surface sees the call. The 48-second GIF in the README
shows a real Claude Opus 4.7 agent's wire-transfer attempt being denied
on capability-scope grounds while a legitimate cable purchase proceeds.
v0 ships the core + audit log + revocation list + Anthropic-SDK demo;
v0.1 adds DPoP holder-of-key. Looking for feedback on the threat model
and the caveat DSL. Built solo over a few weeks.
```

### Why this should land

Two angles working in this post's favor:

1. **Visceral demo at the top.** The GIF tells the story in <60 seconds without anyone reading code. HN responds to artifacts more than to prose.
2. **A real architectural take, not yet-another-guardrail.** The capability-security framing is a load-bearing critique of the current "trust the model" defaults, and tying it back to Lampson 1974 / macaroons frames it as recovering established research rather than inventing something untested.

Failure modes to watch for in the comments:
- "Can't an attacker just...?" — most of these are addressed in DESIGN.md §2/§5; the answer is usually "yes, but that breaks one of the three legs of the security argument and that's testable in property_tests.rs".
- "How is this different from JWT scopes?" — capabilities attenuate, JWT scopes don't. Macaroon-chain semantics + audit receipts + revocation is the substantive difference. Worth having a one-liner ready.
- "Why not just use OPA / Cedar / [policy engine]?" — those are policy languages bolted onto bearer tokens. capnagent is a bearer-token replacement; the caveat DSL is deliberately tiny so caveats stay trivially auditable.
