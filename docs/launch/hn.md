# Show HN submission

**Where:** https://news.ycombinator.com/submit
**When:** Tuesday–Thursday, 8–10am Eastern (peak window).
**Account requirements:** any account in good standing. Posts from accounts with karma <5 sometimes go straight to the new-but-buried queue; if that happens, post once and don't re-submit — flagging happens fast.

## Title (≤80 chars)

```
Show HN: Capnagent – a public purple-team harness for MCP and AI agent tools
```

## Body (paste as the first comment on the post)

```
Hi HN — capnagent is a public purple-team harness for MCP servers
and AI-agent tool surfaces. It treats prompt injection as a
confused-deputy attack and proves it: each round in the corpus is an
adversarial scenario (e.g. tool-description injection / cross-server
confused deputy), a falsifiable security claim, a runnable PoC that
simulates the worst case (model fully cooperates with the
injection), and a signed denial receipt as evidence. Reviewers can
clone the repo and verify every claim by running the test suite —
no prose-trust required.

Round 01 is in: tool-description injection against an MCP filesystem
server. 8/8 PoC tests pass; the structural defense holds when the
issued capability is tightly path-bounded (and the round explicitly
documents the residual risk: loose capabilities still lose;
in-sandbox secrets are operator responsibility). Rounds 02-05
queued: replay attack on hok-bound caps, capability broadening,
cross-origin exfil via http-agent, shell-allowlist bypass.

The engine underneath is a Rust capability-token library
(macaroon-style chain, ed25519 holder-of-key, replay protection via
NonceStore, signed revocation list, caveat DSL with OR/AND/parens
and decimals) with WASM/TS bindings and an MCP adapter that drops
in front of any structurally-typed MCP client. Verified live
integration against the official @modelcontextprotocol/server-
filesystem. Per-call latency: 1.4 µs chain-only, 56 µs full hok,
170 µs hok+replay. ~17 kHz 5-gate verifications per core.

220+ Rust tests, 136 TS tests in CI. Looking for adversarial review
of the threat model and suggestions for the next purple-team round.
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
