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
and AI-agent tool surfaces, plus the Rust capability-token engine
underneath. Methodology is blue-first: every round writes a
falsifiable security claim, then constructs an attack designed to
falsify it. The PoC simulates the worst case (the model has been
fully compromised by the injection and emits exactly the calls the
attacker described), and the verifier's denial — or admission — is
recorded as a signed audit receipt. Reviewers verify by running the
suite; no prose-trust required.

The interesting thing isn't that we built defenses — it's that we
red-teamed them. 10 rounds are closed (cross-server confused deputy,
hok-replay, capability broadening, revocation race, cross-origin
exfil, IDN homograph, path-traversal, etc). Then we ran an "angles"
pass: 4 parallel agents writing adversarial test files against our
own engine. 36 angles, 17 findings, including FOUR HIGH severity
defects:

  A.1  Sub-ulp f64 collapse — `arg.amount <= 50` admits a holder
       whose `amount` is `50.000000000000001`. Authorization bypass.
  B.2  `cap.attenuate("")` produces a silent permanent-deny token.
       Any holder in a chain can brick a delegated cap.
  B.3  Auditor accepts a zero-byte HMAC key. Realistic deployment
       trap (audit key derived from an unset env var).
  C.5  Empty-caveat capability = god-mode. `Issuer.issue("x").build()`
       with no caveats authorizes every context.

These are real engineering defects, found and triaged before launch
rather than after. v0.5 closes all four in one batch (fixes are
queued; ETA this week). The corpus is the artifact; the library is
the engine; the methodology — falsifiable claim → adversarial PoC →
signed receipt — is what makes the corpus auditable.

Engine: macaroon-style HMAC chain, ed25519 holder-of-key (DPoP-
shape), NonceStore replay protection, signed revocation list, caveat
DSL with boolean composition. WASM/TS bindings + MCP adapter,
verified against @modelcontextprotocol/server-filesystem live. 1.4 µs
chain-only verify, 56 µs hok, 170 µs hok+replay. ~17 kHz 5-gate
verifications/core. unsafe_code = forbid.

230+ Rust tests, ~318 TS tests, criterion benches in CI. Looking
for adversarial review of the threat model + the angles
methodology. If you can break round NN or design round 11, that's
the conversation I'm here for.
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
