# Show HN submission

**Where:** https://news.ycombinator.com/submit
**When:** Tuesday–Thursday, 8–10am Eastern (peak window).
**Account requirements:** any account in good standing. Posts from accounts with karma <5 sometimes go straight to the new-but-buried queue; if that happens, post once and don't re-submit — flagging happens fast.

## Title (≤80 chars)

```
Show HN: Capnagent — capability tokens for AI agent tool calls, 4/4 HIGH closed
```

Alternates:

- `Show HN: I red-teamed my own capability-token engine — 17 findings, 4/4 HIGH closed`
- `Show HN: Three-layer agent security stack — recon, capability tokens, runtime policy`

## Body (paste as the first comment on the post)

```
Hi HN — capnagent is a public purple-team harness for MCP servers
and AI-agent tool surfaces, plus the Rust capability-token engine
underneath. Macaroon-style chains, ed25519 holder-of-key (DPoP
shape), NonceStore replay protection, signed revocation list,
caveat DSL with boolean composition. ~1.4 µs chain-only verify,
~17 kHz 5-gate verifications/core. unsafe_code = forbid.

Repo: github.com/euanmcrosson-dotcom/capnagent

Two related repos in the same agent-security stack:

  [ mcp-recon ]  →  [ capnagent ]  →  [ mcp-guard ]
   recon layer      authority layer    runtime-policy layer
   what's            what authority      what action is denied
   exposed?          can the agent       at runtime even if
                     hold?               authority slips?

  mcp-recon: github.com/euanmcrosson-dotcom/mcp-recon
  mcp-guard: github.com/euanmcrosson-dotcom/mcp-guard

The interesting thing isn't that I built defenses — it's that I
red-teamed them. Methodology is blue-first: every round writes a
falsifiable security claim, then constructs an attack designed to
falsify it. The PoC simulates the worst case (the model is fully
compromised by the injection and emits exactly the calls the
attacker described), and the verifier's denial — or admission — is
recorded as a signed audit receipt. Reviewers verify by running
the suite; no prose-trust required.

10 rounds closed. Then I ran an "angles" pass: 4 parallel agents
writing adversarial test files against my own engine. 36 angles,
17 findings, FOUR HIGH severity defects:

  A.1  Sub-ulp f64 collapse — `arg.amount <= 50` admits a holder
       whose `amount` is `50.000000000000001`. Authorization bypass.
  B.2  `cap.attenuate("")` produces a silent permanent-deny token.
       Any holder in a chain can brick a delegated cap.
  B.3  Auditor accepts a zero-byte HMAC key. Realistic deployment
       trap (audit key derived from an unset env var).
  C.5  Empty-caveat capability = god-mode. `Issuer.issue("x").build()`
       with no caveats authorizes every context.

These are real engineering defects, found and triaged in a public
loop rather than after a CVE. As of v0.6.1 (shipped today):
**all 4 HIGH are closed end-to-end.** B.2, B.3, C.5 closed in v0.5;
A.1 closed in v0.6 (Rust DSL evaluator now tracks integer-syntactic
vs float-syntactic source text and refuses to compare an integer
caveat literal against a float-syntactic arg); v0.6.1 added
`verifyWithContextJson` so JS callers who have the original JSON
get the same protection across the WASM boundary.

The point isn't that the engine is perfect — it's that the
methodology lets you find defects this severe BEFORE deployment,
in public, with each finding becoming a reproducible test. The
corpus is the artifact; the library is the engine; the
methodology — falsifiable claim → adversarial PoC → signed
receipt → fix or document — is what makes the corpus auditable.

Engine: ~1.4 µs chain-only verify, 56 µs hok, 170 µs hok+replay,
~17 kHz 5-gate verifications/core. Apache-2.0, unsafe_code = forbid.
246 Rust tests + 346 TS tests + criterion benches in CI. WASM/TS
bindings + MCP adapter verified live against the official
@modelcontextprotocol/server-filesystem.

Looking for adversarial review of the threat model + the angles
methodology, OR for one partner team running an agent in production
who'd let me write Round 11 against their stack (free, ~3 weeks
elapsed, both names on the writeup). Partner brief:
docs/launch/partner-brief-v0.7.md.

If you can break round NN or design round 11 — that's the
conversation I'm here for.
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
