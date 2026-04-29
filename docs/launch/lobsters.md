# Lobste.rs submission

**Where:** https://lobste.rs/stories/new
**Tags:** `rust`, `security`, `cryptography`, `release`
**When:** any weekday morning Eastern; lobste.rs has lower posting volume than HN, so timing matters less.
**Account requirements:** lobste.rs is invite-only. If you don't have an account, find a Rust contributor who does and ask politely; this is normal.

## Why lobste.rs

Different audience from HN: smaller, more technical, more patient with crypto and Rust specifics. Comment quality is high. A well-received lobste.rs post tends to surface 2–5 thoughtful technical reviewers — exactly the eyes capnagent needs.

## Title

```
Capnagent + mcp-recon: defensive engine and offensive companion for MCP agents
```

## URL

```
https://github.com/euanmcrosson-dotcom/capnagent
```

## Description (the box under the URL)

```
Two related projects shipping together:

  capnagent  — capability-bounded authorization for AI agent tool calls.
  mcp-recon  — reverse-engineer any MCP server's tool surface in 30s
               (github.com/euanmcrosson-dotcom/mcp-recon).

The recon-then-bound workflow: mcp-recon scans an MCP server,
emits a Markdown threat profile + recommended capnagent caveat
per tool; capnagent enforces those caveats at the gate.

capnagent (the deeper of the two): a public adversarial-test
corpus for MCP servers and AI-agent tool surfaces, plus the Rust
capability-token engine that powers the defense. Methodology is
blue-first: each round writes a falsifiable security claim, then
the red side constructs an attack designed to falsify it. The
PoC simulates the worst case — agent fully compromised, emits
exactly the calls the attacker described — and asserts the
structural defense holds regardless of model behavior. Every
denial produces a signed receipt committed as evidence;
reviewers verify by running the suite.

10 rounds closed (cross-server confused deputy, hok-replay,
capability broadening, revocation race, cross-origin exfil, IDN
homograph, fs-sandbox path-traversal, etc). On top: an "angles"
run — 4 parallel agents adversarially testing the engine itself —
surfaced 17 findings including 4 HIGH severity defects in our own
code:

  A.1  Sub-ulp f64 collapse: `arg.amount <= 50` admits 50.000000000000001
  B.2  cap.attenuate("") produces a silent permanent-deny token
  B.3  Auditor accepts a zero-byte HMAC key
  C.5  Empty-caveat capability = god-mode authorization

v0.5 SHIPPED and closes 3 of 4 (A.1 sub-ulp f64 is parked under
design discussion — integer-only mode for monetary caveats is the
likely fix). The point of the corpus is that defects this severe
are findable and fixable in a public loop — not after a CVE.

Engine: macaroon-style HMAC chain, ed25519 holder-of-key (DPoP),
NonceStore replay protection, signed revocation list, caveat DSL
with OR/AND/parens. WASM/TS bindings; MCP adapter verified
live against @modelcontextprotocol/server-filesystem. unsafe_code =
forbid, ~17 kHz 5-gate verifications/core. 242 Rust tests, 322 TS
tests, criterion benches. Looking for adversarial review of the
methodology and the angles findings.
```

## After posting

- lobste.rs threads stay readable for days — the slow-burn engagement is the point.
- Top comments often ask for design decisions, not "what does this do." Be ready with:
  - Why HMAC-SHA256 chain rather than RSA-PSS or ed25519 for the macaroon? (HMAC is symmetric — issuer/verifier share a key. The hok layer adds the asymmetric-key proof on top, where the asymmetry is needed.)
  - Why the explicit caveat DSL rather than embedding Rego/CEL? (Trivial-auditability invariant — see DESIGN.md §5 leg 3.)
  - Why bind hok via the HMAC chain (`b"__hok:" || pubkey`) rather than as a separate field? (So a holder can't "downgrade" a hok-bound cap to a bearer-token cap by stripping the field — the chain catches it.)
  - "How did you find A.1 (the sub-ulp f64 collapse)?" Parallel angles run — one of four agents was specifically tasked with edge-cases on numeric coercions in the DSL. Tested literal `50.000000000000001` in the holder-supplied JSON and watched the verifier admit. Fix: integer-only mode for monetary caveats (under design discussion in the v0.5 queue).
  - "Why ship the angles findings publicly before fixing them?" Because the methodology *is* the artifact. A corpus that hides its own defects is not a purple-team corpus; it's marketing.
- A "off-topic" tag-flag from a moderator usually means the wrong tags. `crypto` and `security` are fine; avoid `programming` (too broad).
