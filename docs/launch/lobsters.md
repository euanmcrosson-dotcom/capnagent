# Lobste.rs submission

**Where:** https://lobste.rs/stories/new
**Tags:** `rust`, `security`, `cryptography`, `release`
**When:** any weekday morning Eastern; lobste.rs has lower posting volume than HN, so timing matters less.
**Account requirements:** lobste.rs is invite-only. If you don't have an account, find a Rust contributor who does and ask politely; this is normal.

## Why lobste.rs

Different audience from HN: smaller, more technical, more patient with crypto and Rust specifics. Comment quality is high. A well-received lobste.rs post tends to surface 2–5 thoughtful technical reviewers — exactly the eyes capnagent needs.

## Title

```
Capnagent: macaroon-style capability tokens for AI agent tool calls
```

## URL

```
https://github.com/euanmcrosson-dotcom/capnagent
```

## Description (the box under the URL)

```
A Rust library (with WASM + TS bindings and an MCP adapter)
implementing macaroon-style capability tokens for AI agent tool
calls. Treats prompt injection as a confused-deputy problem, not a
"trick the model" problem — the agent simply doesn't hold ambient
authority. Every tool call routes through a 5-gate verifier (chain
integrity, ed25519 holder-of-key proof, replay protection,
revocation, caveat evaluation against a verifier-controlled
context). Caveats compose via OR/AND/parens with decimals and
timestamps. Three real-world consumers ship in the repo (filesystem,
HTTP, shell), plus a verified live-integration test against the
official @modelcontextprotocol/server-filesystem. Pure Rust core,
no_std-friendly except for std::sync; WASM build via wasm-pack;
~17 kHz 5-gate verifications/core (criterion bench in repo).
unsafe_code = forbid. 220+ Rust tests including proptests for the
no-broaden chain invariant and the boolean DSL composition laws.
Looking for adversarial review of the threat model.
```

## After posting

- lobste.rs threads stay readable for days — the slow-burn engagement is the point.
- Top comments often ask for design decisions, not "what does this do." Be ready with:
  - Why HMAC-SHA256 chain rather than RSA-PSS or ed25519 for the macaroon? (HMAC is symmetric — issuer/verifier share a key. The hok layer adds the asymmetric-key proof on top, where the asymmetry is needed.)
  - Why the explicit caveat DSL rather than embedding Rego/CEL? (Trivial-auditability invariant — see DESIGN.md §5 leg 3.)
  - Why bind hok via the HMAC chain (`b"__hok:" || pubkey`) rather than as a separate field? (So a holder can't "downgrade" a hok-bound cap to a bearer-token cap by stripping the field — the chain catches it.)
- A "off-topic" tag-flag from a moderator usually means the wrong tags. `crypto` and `security` are fine; avoid `programming` (too broad).
