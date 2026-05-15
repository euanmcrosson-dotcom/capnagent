# Roadmap

What's coming, in honest priority order. The project is alive
(commits this week) but it's run by one developer; promises are
realistic, not aspirational.

> **Versioning intent.** Pre-1.0 means the public API may change.
> Each minor version is a contracted batch of fixes / features
> with a CHANGELOG entry. v1.0 means the API has been stable for
> at least 60 days and at least one external integration is in
> production.

---

## v0.6 — A.1 closure (Rust engine + v0.6.1 JS-layer follow-on)

**Status: SHIPPED 2026-05-15 (v0.6.0 + v0.6.1).** Closes A.1 end-to-end:
- v0.6.0 closed the engine-side path (Rust DSL evaluator).
- v0.6.1 closed the JS-layer path (`Verifier.verifyWithContextJson`
  API; callers who hand us the raw JSON get full protection).

**Design call locked:** integer-domain mode, source-text tracking.
The DSL now distinguishes integer-syntactic numeric values (literals
without a fractional part; JSON numbers whose source text contains
no `.`/`e`/`E`) from float-syntactic ones. When an ordering or
equality comparison sees an integer-syntactic caveat literal vs a
float-syntactic arg, it errors out with an actionable message
rather than silently coercing.

Alternative considered (unit-typed numerics: `_usd` carries decimal
precision, `_cents` carries integer precision): rejected for v0.6
on the principle that simpler DSL surface = smaller attack surface
in a security-critical path. The integer-domain approach reuses
existing `Unit` machinery and adds one structural field (`NumKind`)
instead of a new parser-level type lattice.

**What shipped in the engine (Rust):**

- `serde_json` `arbitrary_precision` feature enabled — JSON number
  source text is preserved past parse time.
- `Value::Number` widened to `(f64, Option<Unit>, NumKind)` — third
  field tracks Integer vs Float syntactic shape.
- `parse_number` marks literals based on whether `.` was parsed.
- `json_to_value` marks args based on whether the JSON source
  contains `.`/`e`/`E`.
- `apply_op` rejects (Integer literal × Float arg) for ordering
  and equality ops with a clear error explaining the two mitigations:
  (a) use a fractional literal (`<= 50.0`) if you actually want
  approximate semantics; (b) use the `_cents` form
  (`arg.amount_cents <= 5000`) for exact integer semantics.

**What ships in tests:**

- 6 new Rust integration tests in `caveat_dsl_tests.rs`:
  - `v0_6_integer_caveat_rejects_decimal_arg_under_threshold`
  - `v0_6_integer_caveat_rejects_decimal_arg_over_threshold`
  - `v0_6_integer_caveat_with_integer_arg_still_works`
  - `v0_6_integer_caveat_escape_hatch_via_fractional_literal`
  - `v0_6_integer_caveat_escape_hatch_via_cents_form`
  - `v0_6_sub_ulp_collapse_a1_closed`
- TS angle test `angles-dsl-edges.angles.test.ts`: A.1 entry
  renamed `[CLOSED-PARTIAL v0.6]` with detailed comment explaining
  the JS-layer collapse. New companion test demonstrates the
  `_cents` mitigation end-to-end through the JS layer.

**What's deliberately deferred (v0.6.1 / v0.7):**

The JS-layer collapse — `JSON.parse("50.000000000000001")` in
JavaScript yields f64 `50.0` before any of capnagent's code runs —
is environmental, not engine-side. To get full A.1 protection for
JS callers, the WASM API needs to accept ctx args as a JSON string
(so the original source text survives across the boundary). That's
a meaningful API addition tracked as a follow-on. Mitigation today
for JS callers: use the `_cents` form, which sidesteps the issue
because both sides are integer-syntactic.

**Corpus status:** 4 HIGH found, **4 HIGH closed in the engine.**
The angle finding remains documented for transparency about the
JS-layer artefact, with the closure clearly attributed to the Rust
DSL evaluator.

---

## v0.7 — Round 11 against a real production stack

**Goal: replace the strongest single PR claim ("we red-teamed our
own engine") with the next-strongest one ("we red-teamed [partner
X]'s production stack").**

The target is a partner team that ships an agentic product with
real tool calls — coding agent, AI customer-support, browser-
automation, AI-trading. Outreach is structured in
[`docs/launch/outreach.md`](launch/outreach.md).

The deliverable:

1. capnagent wrapping the partner's agent in their staging or
   production environment.
2. A round documented in `docs/purple-team/11-<partner-name>.md`
   with the standard shape: blue-first claim, attack PoC, signed
   receipt, gap-class, residual-risk.
3. Both names on the writeup. Partner keeps the receipts; we keep
   the writeup; both can publish.

**Hard requirement:** real partner, not a synthetic stack. If
outreach produces no partner after wave-1 + wave-2 DMs, the right
move is **stop** rather than write a synthetic round 11. Synthetic
rounds dilute the corpus.

**Estimated time-to-ship:** depends on partner availability.
Targeting one Saturday-afternoon project with a willing
collaborator.

---

## v0.8 — Coverage + observability

**Goal: turn capnagent from "tool you can adopt" into "tool a
production team can audit."**

Concrete deliverables:

- **Coverage badge** in the README. Adding `cargo-tarpaulin` (or
  similar) to CI; surfacing line + branch coverage percentages.
  Open question: is high coverage actually meaningful for a crypto
  layer with proptest properties? Likely yes for the non-property
  paths.
- **Per-round receipt schemas** committed under
  `docs/purple-team/evidence/schema/` so a downstream consumer can
  validate their own audit-log shape against what capnagent
  emits.
- **Receipt-stream demo:** a small dashboard (web page or CLI
  tool) that consumes a receipt stream from a running agent and
  reports denial-rate by tool / by caller / by caveat. Useful for
  ops teams trying to detect "is the agent trying things we should
  worry about?"

**Estimated time-to-ship:** 1 month, modular — items can ship
independently.

---

## v0.9 — Hardening pass before v1.0

**Goal: surface every API shape and lock it.**

- **Deprecate** any pre-1.0 surface that has felt awkward in
  practice. Likely candidates: the consume-after-attenuate
  pattern in WASM (the angles run flagged this); WASM-side
  `holderOfKey` ordering constraints.
- **Add** what's missing for production deployment: documented
  Redis / Postgres `NonceStore` adapters; documented
  `RevocationList` distribution patterns; clear guidance on
  rotating root keys.
- **Audit** dependency tree against `cargo-deny` + `cargo-audit`;
  pin minimum acceptable versions; document supply-chain posture
  in `SECURITY.md`.

After v0.9 the API is a candidate for stability.

**Estimated time-to-ship:** depends on v0.7 / v0.8 feedback.

---

## v1.0 — stable API, production-ready signal

**Goal: drop the pre-1.0 caveat on the README. Document migration
paths from any breaking changes since v0.5.**

Acceptance criteria for v1.0:

- [ ] At least one external integration in production (round 11
      partner counts).
- [ ] No breaking API changes in the trailing 60 days.
- [ ] All 4 HIGH angle findings closed (i.e., v0.6 has shipped).
- [ ] Coverage badge ≥ 80% on the Rust core.
- [ ] An external security review (paid or volunteer) has read
      `SECURITY-POSTURE.md` and `RELATED-WORK.md` and signed off
      on the framework mappings.
- [ ] At least one workshop submission (SaTML / SCRAP / AI Village)
      attempted, regardless of acceptance.

We are NOT rushing to v1.0. Pre-1.0 is honest about the surface
churn that's still likely; falsely promising stability would be
worse than acknowledging it.

---

## What's explicitly NOT on the roadmap

These are out of scope for at least the next 6 months. Listed
honestly so a reviewer can see the boundary:

- **A graphical UI / dashboard product.** capnagent is a library.
  The dashboard mentioned in v0.8 is a *demo* of consuming the
  receipt stream, not a product.
- **Hosted SaaS.** Some other team's job. capnagent runs in
  whatever runtime the agent runs in.
- **Detection-based features.** capnagent is structural; we do not
  classify input/output for prompt-injection signals. That's a
  different layer (Lakera, Rebuff, NeMo Guardrails — see
  [`COMPARISON.md`](COMPARISON.md)).
- **Model-behavior-based features.** No fine-tuning, no RLHF, no
  alignment work happens here. Capabilities, not behavior.
- **General-purpose policy engine.** OPA / Cedar are good. We are
  not trying to be them. capnagent's caveat DSL is intentionally
  one page of BNF.

---

## How this roadmap stays honest

- A version is "shipped" only after the CHANGELOG.md has the
  entry, the tests are green, and the commit is on master.
- A version is "designed" only after a written design note is
  committed (e.g., `docs/V0_6_SPEC.md`).
- A version stays at "planned" until designed.
- Anything not in this document doesn't exist as a project
  commitment — it's an idea.

If a senior reviewer asks "what's coming in v0.6?", the answer
is in this file. If they ask "what's coming in 2027?", the
honest answer is "I don't know yet, and any commitment here would
be theatre."

---

## Last updated

The git log is the canonical source of truth for what's actually
been done. This file is a forward-looking *intent*, re-checked at
each minor release.
