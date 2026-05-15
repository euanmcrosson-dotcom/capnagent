# Show HN submission

**Where:** https://news.ycombinator.com/submit
**When:** Tuesday–Thursday, 8–10am Eastern (peak window).
**Account requirements:** any account in good standing. Posts from accounts with karma <5 sometimes go straight to the new-but-buried queue; if that happens, post once and don't re-submit — flagging happens fast.

## Title (80-char limit)

```
Show HN: Three-layer agent-security stack: capnagent, mcp-guardrails, mcp-recon
```
(80 chars — at the limit. Strongest framing, leads with the architecture and gives the reader three concrete things to click.)

Alternates:

```
Show HN: I red-teamed my own capability-token engine — 4/4 HIGH closed in public
```
(80 chars — leads with capnagent's strongest single claim.)

```
Show HN: Capnagent — capability tokens for AI agent tool calls
```
(63 chars — minimalist, lets the body do the work.)

**My pick: option 1.** Says what it is, gives three concrete artefacts, sets up the verify-in-90-seconds payoff in the body.

## Body (paste as the first comment on the post)

```
Hi HN — three related repos, one install each, all live as of today:

  pip install capnagent              # capability tokens + audit receipts
  pip install mcp-guardrails         # deterministic policy library
  npx mcp-recon --help               # MCP server tool-surface auditor

Repos:
  github.com/euanmcrosson-dotcom/capnagent
  github.com/euanmcrosson-dotcom/mcp-guard       (PyPI: mcp-guardrails)
  github.com/euanmcrosson-dotcom/mcp-recon

# How the three compose

  [ mcp-recon ]  →  [ capnagent ]  →  [ mcp-guardrails ]
   recon            authority           runtime policy
   what's exposed?  what authority      what action is denied
                    can the agent       at runtime even if
                    hold?               the authority slips?

It's not a framework, it's a factoring. Different problems,
different abstractions, separate libraries you can adopt
independently. Use one and get value; use all three and get
defense in depth.

# 90-second verify (literally — run this in a fresh shell)

  pip install capnagent
  python -c "from capnagent import Issuer, Verifier, Auditor; print('ok')"
  pip install mcp-guardrails
  python -c "from mcp_guard import synthesize_default_policy as p; print(len(p().rules), 'rules')"
  npx -y mcp-recon --help

(Expected last command: a `mcp-recon scan / enumerate / fuzz / ...`
help screen.)

# Capnagent (the deepest of the three — full red-team story)

A public purple-team harness for MCP servers and AI-agent tool
surfaces, plus the Rust capability-token engine underneath.
Macaroon-style chains, ed25519 holder-of-key (DPoP shape),
NonceStore replay protection, signed revocation list, caveat DSL
with boolean composition. ~1.4 µs chain-only verify, ~17 kHz 5-gate
verifications/core. Apache-2.0, unsafe_code = forbid.

Methodology is blue-first: every round writes a falsifiable
security claim, then constructs an attack designed to falsify it.
The PoC simulates the worst case (the model is fully compromised by
the injection and emits exactly the calls the attacker described),
and the verifier's denial — or admission — is recorded as a signed
audit receipt. Reviewers verify by running the suite; no
prose-trust required.

10 rounds closed against the engine. Then I ran an "angles" pass:
4 parallel agents writing adversarial test files against my own
code. 36 angles, 17 findings, FOUR HIGH-severity defects in my
own engine:

  A.1  Sub-ulp f64 collapse. `arg.amount <= 50` admits a holder
       whose `amount` is `50.000000000000001`. Authorization bypass.
  B.2  `cap.attenuate("")` produces a silent permanent-deny token.
       Any holder in a chain can brick a delegated cap.
  B.3  Auditor accepts a zero-byte HMAC key. Realistic deployment
       trap (audit key derived from an unset env var).
  C.5  Empty-caveat capability = god-mode. `Issuer.issue("x").build()`
       with no caveats authorizes every context.

All four are closed end-to-end as of today: B.2 / B.3 / C.5 in v0.5;
A.1 in v0.6 (Rust DSL evaluator now tracks the source-text shape
of every numeric value and refuses to compare an integer-syntactic
caveat literal against a float-syntactic arg); v0.6.1 added a JSON-
string entry point so JS callers get the same protection across
the WASM boundary; the Python binding gets A.1 closure end-to-end
for free (Python's `json.dumps` doesn't have JS's f64 collapse).

The point isn't that the engine is perfect — it's that the
methodology lets you find defects this severe BEFORE deployment,
in public, with each finding becoming a reproducible test.

# Mcp-guardrails (the runtime-policy layer)

Drop-in deterministic policy library. 9 attack-class patterns
across 122 rules: indirect injection, SSRF, SQL injection, shell
injection, path traversal, PII / secret exfil, etc. Tracks the
JSON source text of every numeric value so sub-ulp collapse
doesn't slip past integer-domain caveats. 304-case backtest corpus,
TPR 1.00, FPR 0.01. Four framework adapters (Anthropic MCP SDK,
LangChain, LlamaIndex, CrewAI). Six reproducible case studies in
`case_studies/` including EchoLeak (GPT-4o 66.7% silent compliance
vs Claude 0%), MCP tool-description poisoning, RAG context
poisoning, agent self-prompting loops.

# Mcp-recon (the recon layer)

Reverse-engineer any MCP server's tool surface in 30 seconds.
Enumerate tools, fuzz schemas along six adversarial axes, classify
authority against OWASP LLM Top 10 + MITRE ATLAS, emit a Markdown
threat profile with copy-pasteable capnagent caveats per tool.
Stand-alone offensive tool; pairs cleanly with capnagent for the
defensive side.

# Why publish this as a stack vs three separate posts

The factoring IS the contribution. There's a lot of "AI agent
security" content right now framed around input filtering — what
the model sees, what the classifier says. I think the more durable
defense is at the action layer: capability tokens that bound what
the agent CAN do, deterministic policy that fires on the actual
tool call, signed receipts for the auditor. Input filtering
complements that, doesn't replace it.

If only one layer ends up being load-bearing for your stack,
that's fine — adopt that one. The stack-as-stack is a way to
think, not a thing you have to install in full.

# What I'm asking for

  - Adversarial review of the threat model, the caveat DSL, or
    the angles methodology. If you can break a closed purple-team
    round or design round 11, that's the conversation I want.
  - If you're running an agent platform in production and would
    let me wire capnagent in front of one of your tool surfaces
    for a Round 11 writeup — partner brief is in
    capnagent/docs/launch/partner-brief-v0.7.md. Free, ~3 weeks
    elapsed, both names on the writeup.
  - If you're solving the same problem differently — say so. I'm
    already in one conversation with another builder who's coming
    at this from the SOC-2-evidence angle; happy to compare notes
    with more people.

# Numbers for the people who like numbers

  - capnagent: 246 Rust + 195 TS + 8 Python = 449 tests, all green.
    1.4 µs chain verify, 56 µs hok, 170 µs hok+replay, ~17 kHz
    5-gate verifications/core. CI: cargo deny, cargo audit,
    wasm-pack node smoke, build+test on every push.
  - mcp-guardrails: 99 tests, TPR 1.00 / FPR 0.01 on a 304-case
    backtest corpus, 4 HIGH-severity findings all closed.
  - mcp-recon: 68 tests + 5 public-MCP-server scans in the
    dataset, 6 documented findings from the dataset.
  - All three: zero runtime deps in the core, Apache-2.0 (capnagent
    + mcp-recon) / MIT (mcp-guardrails), criterion benches for the
    Rust hot paths.

The most interesting thing about doing all three at once was how
much each one taught the others — A.1 was found by an angle agent
working on capnagent, but it shaped the source-text tracking that
ended up in mcp-guardrails too. The real "stack" is the methodology
loop, not the libraries.
```

## URL

```
https://github.com/euanmcrosson-dotcom/capnagent
```

(Reason: capnagent is the single deepest project of the three, and the URL the post links to is the one that gets the bulk of the stars / PRs / follow-up. Body links to the other two repos in plain text.)

## After posting

- DON'T touch the post for the first 30 min — early flag-clusters from your own friends/circle can hurt.
- DO answer comments in the first hour. Top-of-thread responses beat reply-thread depth.
- Common comment patterns to be ready for:
  - **"Can't an attacker just…?"** Most are addressed in `DESIGN.md` §2/§5 and the purple-team rounds. Specifically: the cannot-broaden invariant has 9 proptest cases. Boolean DSL composition has 8 more. Reply with the file path and the property name; reviewers respect file-path responses.
  - **"How is this different from JWT scopes?"** Capabilities attenuate, JWT scopes don't. Macaroon-chain + holder-of-key + audit receipts + revocation + replay protection is the substantive difference. JWT scopes are a static label; capabilities are a small program the verifier evaluates.
  - **"Why not OPA / Cedar / [policy engine]?"** Those are policy languages bolted onto bearer tokens. capnagent is a bearer-token replacement; the caveat DSL is one page of BNF so caveats stay trivially auditable. Policy engines complement; they don't substitute.
  - **"DPoP isn't novel."** Correct, that's the point. capnagent applies RFC 9449 / OAuth-DPoP-style proof of possession to capability tokens specifically. The novelty is the composition (chain → proof → replay → revocation → caveats).
  - **"Just use Guardrails AI / Nemo Guardrails / Llama Guard."** Those are classifier-based — the model decides whether the call is safe. mcp-guardrails is the deterministic complement. Best deployment uses both: classifier as early warning, deterministic policy as the unconditional gate.
  - **"Three projects is too many."** Fair, but each one stands alone. Adopt the layer that matches your problem; the stack-as-stack is a way to think, not a thing you have to install in full.
- If someone reports a bug or possible vuln, ask them to file a security advisory; don't debug in-thread.
- DO post a follow-up comment of your own ~30 min in with one specific technical detail not in the body — surfaces the post in the comment-activity ranking.

## Cross-promotion (within 24h)

- **Email Simon Willison the same day you post.** Subject: "Show HN today: three-layer agent-security stack — capnagent, mcp-guardrails, mcp-recon." 2-line body + the HN URL. He links to stuff like this on his weblog; one mention triples the traffic.
- **Lobste.rs** the next day (separate post, similar body). Tag: `security`, `ai`.
- **r/MachineLearning** + **r/programming** the next day. Re-frame slightly: lead with the methodology (red-team-your-own-engine) rather than the install commands.

## Failure-mode plan

- If the post sits at <5 points after 90 min: don't repost — that gets flagged. Pivot to lobste.rs / r/rust the same week.
- If it gets flagged outright: don't argue. Note any feedback, fix what's substantive, try a different platform in 2–3 weeks.
- If someone calls out a real bug in the body: thank them, fix it in the repo, edit the post or post a follow-up comment with the correction. HN respects "you were right, I fixed it" responses far more than "actually you're wrong."

## What to verify the morning of posting

15-minute pre-flight, do these:

  1. `pip install --upgrade capnagent` from a clean venv — does the install + import work?
  2. Same for `pip install --upgrade mcp-guardrails`.
  3. `npx -y mcp-recon --help` in a clean directory — does it run?
  4. Open all three GitHub repos in incognito — do the READMEs render and link correctly?
  5. Double-check the 4-HIGH-closed claim — read `capnagent/docs/EVALUATION.md` and confirm A.1's "CLOSED v0.6" marker is in place.
  6. The 90-second verify block in the body — copy-paste it into a fresh terminal and confirm every line works.

If any of those fail, fix before posting.
