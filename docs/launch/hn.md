# Show HN submission

**Where:** https://news.ycombinator.com/submit
**When:** Tuesday–Thursday, 8–10am Eastern (peak window).
**Account requirements:** any account in good standing. Posts from accounts with karma <5 sometimes go straight to the new-but-buried queue; if that happens, post once and don't re-submit — flagging happens fast.

## Title (≤80 chars)

```
Show HN: Capnagent – capability tokens that bound what AI agent tool calls can do
```

## Body (paste as the first comment on the post)

```
Hi HN — capnagent is a Rust library (with WASM + TS bindings and an
MCP adapter) that gives AI agent tool calls macaroon-style capability
tokens. Instead of "trust the model not to be prompt-injected", every
tool call goes through a 5-gate verifier: chain integrity, holder-of-
key proof of possession (ed25519), replay protection (nonce store),
revocation, and caveat evaluation against a verifier-controlled
context. Caveats compose with OR / AND / parens, including decimals
and timestamps. Out-of-scope calls are refused before the underlying
tool surface sees them; every decision is signed into a versioned
audit receipt. The GIF in the README shows a real Claude Opus 4.7
agent's wire-transfer attempt denied on capability-scope grounds
while a legitimate cable purchase proceeds. Three real-world
consumers ship in the repo (filesystem, HTTP, shell — all
deterministic, no LLM required), plus a verified integration test
against the official @modelcontextprotocol/server-filesystem.
v0/v0.1/v0.2 all shipped, backlog empty. ~17 kHz 5-gate
verifications/core (criterion bench in repo). 220+ Rust tests, 111
TS tests in CI. Looking for feedback on the threat model and on what
production deployments need from the replay-store backend.
```

## URL

```
https://github.com/euanmcrosson-dotcom/capnagent
```

## After posting

- DON'T touch the post for the first 30 min — early flag-clusters from your own friends/circle can hurt.
- DO answer comments in the first hour. Top-of-thread responses beat reply-thread depth.
- Common comment patterns to be ready for:
  - **"Can't an attacker just…?"** Most are addressed in DESIGN.md §2/§5. Specifically: the cannot-broaden invariant has 9 proptest cases. Boolean DSL composition has 8 more. Reply with the file path and the property name.
  - **"How is this different from JWT scopes?"** Capabilities attenuate, JWT scopes don't. Macaroon-chain + holder-of-key + audit receipts + revocation + replay protection is the substantive difference. JWT scopes are a static label; capabilities are a small program the verifier evaluates.
  - **"Why not OPA / Cedar / [policy engine]?"** Those are policy languages bolted onto bearer tokens. capnagent is a bearer-token replacement; the caveat DSL is one page of BNF so caveats stay trivially auditable. Policy engines complement; they don't substitute.
  - **"DPoP isn't novel."** Correct, that's the point. capnagent applies RFC 9449 / OAuth-DPoP-style proof of possession to capability tokens specifically. The novelty is the composition (chain → proof → replay → revocation → caveats).
- If someone reports a bug or possible vuln, ask them to file a security advisory; don't debug in-thread.

## Failure-mode plan

- If the post sits at <5 points after 90 min: don't repost — that gets flagged. Pivot to lobste.rs / r/rust the same week.
- If it gets flagged: don't argue. Note any feedback, fix what's substantive, try a different platform in 2–3 weeks.
