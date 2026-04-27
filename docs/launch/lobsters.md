# Lobste.rs submission

**Where:** https://lobste.rs/stories/new
**Tags:** `rust`, `security`, `cryptography`, `release`
**When:** any weekday morning Eastern; lobste.rs has lower posting volume than HN, so timing matters less.
**Account requirements:** lobste.rs is invite-only. If you don't have an account, find a Rust contributor who does and ask politely; this is normal.

## Why lobste.rs

Different audience from HN: smaller, more technical, more patient with crypto and Rust specifics. Comment quality is high. A well-received lobste.rs post tends to surface 2–5 thoughtful technical reviewers — exactly the eyes capnagent needs.

## Title

```
Capnagent: a public purple-team harness for MCP and AI-agent tool surfaces
```

## URL

```
https://github.com/euanmcrosson-dotcom/capnagent
```

## Description (the box under the URL)

```
A public adversarial-test corpus for MCP servers and AI-agent tool
surfaces, plus the Rust capability-token engine that powers the
defense. Methodology is blue-first: each round writes a falsifiable
security claim, then the red side constructs an attack designed to
falsify it. The PoC simulates the worst case — the agent has been
fully compromised by the injection and emits the calls the attacker
described — and asserts the structural defense holds regardless of
model behavior. Every denial produces a signed receipt committed as
evidence; reviewers can verify the full corpus by running the test
suite. Round 01 (tool-description injection / cross-server confused
deputy) is in; 8/8 PoC tests pass. Engine: macaroon-style HMAC
chain, ed25519 holder-of-key, NonceStore replay protection, signed
revocation list, caveat DSL with OR/AND/parens. WASM/TS bindings.
Verified live-integration against the official
@modelcontextprotocol/server-filesystem. Pure Rust, unsafe_code =
forbid, ~17 kHz 5-gate verifications/core. Looking for adversarial
review and suggestions for the next round.
```

## After posting

- lobste.rs threads stay readable for days — the slow-burn engagement is the point.
- Top comments often ask for design decisions, not "what does this do." Be ready with:
  - Why HMAC-SHA256 chain rather than RSA-PSS or ed25519 for the macaroon? (HMAC is symmetric — issuer/verifier share a key. The hok layer adds the asymmetric-key proof on top, where the asymmetry is needed.)
  - Why the explicit caveat DSL rather than embedding Rego/CEL? (Trivial-auditability invariant — see DESIGN.md §5 leg 3.)
  - Why bind hok via the HMAC chain (`b"__hok:" || pubkey`) rather than as a separate field? (So a holder can't "downgrade" a hok-bound cap to a bearer-token cap by stripping the field — the chain catches it.)
- A "off-topic" tag-flag from a moderator usually means the wrong tags. `crypto` and `security` are fine; avoid `programming` (too broad).
