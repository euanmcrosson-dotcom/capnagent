# Purple-team corpus

Adversarial test data for capnagent. Each round is one cycle of a
blue → red → iterate loop, recorded in a structured plain-text
format so the corpus is grep-friendly, reviewable by external
security researchers, and re-validatable by anyone who can clone
the repo and run `npm test`.

## Format

The format is adapted from a detection-engineering convention with
seven additions for authorization-engineering specifics. See
[`_template.md`](./_template.md) for the canonical shape; new
rounds copy that file as `NN-<short-name>.md`.

The metadata header captures the falsifiable claim, the runnable
PoC, the tested + not-yet-tested variants, the known bypasses, the
re-validate cadence, and the round status. The run history is the
load-bearing part — each retry of the test under different
conditions is one row, with the gap-class and action that drove
the next iteration. CLOSED means the structural defense held with
both positive and negative hypotheses met; CLOSED does NOT mean
"forever" — every round has a `Re-validate-by:` date.

## Methodology

Blue-first. Each round:

1. **Blue writes the security claim** in falsifiable form, with
   BOTH halves explicit:
   - **Positive (true-positive):** given capability C, attack
     call A SHOULD be denied with reason matching pattern P.
   - **Negative (true-negative):** given the same capability C,
     legitimate call L SHOULD be allowed and return result R.
   A defense that denies everything is not the win condition.
   Both halves must hold for CLOSED.

2. **Red constructs an attack** designed to falsify the positive
   half. The attack is concrete (a malicious tool description, an
   injected prompt, a captured-and-replayed token, etc.) and
   reproducible (someone else can clone, run, watch).

3. **Run the attack against capnagent** under the stated
   environment. Two outcomes:
   - **Defense holds:** PASS. Receipt captured, run status logged
     with `Gap-class: NONE`. If this is the first run and
     coverage is good, the round CLOSES.
   - **Defense breaks:** FAIL or PARTIAL. Gap is classified,
     action recorded, the round stays OPEN, next run inherits the
     fix.

4. **Re-validate-by date set.** Defaults to 6 months from CLOSED.
   Defenses rot — capnagent versions advance, MCP SDK changes,
   threat-class atomics evolve. CLOSED-forever is a lie; this
   field is the lie-detector.

## Why blue-first

For research-quality output:

- It forces *us* to write the security claim before the attack
  is constructed. Otherwise the claim quietly drifts to match the
  result. Falsifiable claims first; attacks second.
- It prevents the "we already know the answer" bias when both
  red and blue are the same person.
- It gives red a concrete target — not a vague "find anything bad."

Red-first is the right pattern for mature deployed systems
measuring residual risk in the wild. capnagent is still proving
the structural claim; blue-first dominates here.

## What every entry must include

- A **falsifiable security claim** with both true-positive and
  true-negative halves.
- A **runnable PoC** — vitest spec at
  `examples/*/src/__tests__/*.purple.test.ts`. Prose can lie;
  the script can't.
- The **denial receipt** committed under `evidence/`. Reviewers
  can verify the receipt's HMAC signature against the test's root
  key independently.
- A **`Coverage:`** field listing tested + not-yet-tested
  variants, so one atomic doesn't claim the whole technique.
- An honest **`Known-bypasses:`** list. Every defense has limits;
  pretending otherwise is how security writeups get destroyed in
  comments.
- An **`Env:`** field per run so PASSes don't lie across
  platforms.
- An **`FP-7d:`** measurement (or `pending baseline`). CLOSED
  without an FP measurement means useful-when-tight, not
  useful-in-production.
- A **`Gap-class:`** per run, so the corpus is aggregable —
  grep across rounds and discover "60% of our gaps are
  CAPABILITY-CONFIG, we should ship better issuance defaults."

## How to add a new round

1. Copy `_template.md` to `NN-<short-name>.md` (next number).
2. Fill the header blue-first: claim, coverage, known-bypasses.
3. Write the runnable PoC at
   `examples/<package>/src/__tests__/<short-name>.purple.test.ts`.
4. Run it. Capture the receipt JSON via the package's
   `regen-purple-evidence` bin script (or write one if the
   package doesn't have it yet — see the mcp-fs-agent example).
5. Fill in Run 1's metadata. If PASS, set Status: CLOSED with
   today's date and Re-validate-by: today + 6 months. If
   FAIL/PARTIAL, classify the gap, take the action, run again as
   Run 2.
6. Commit the entry, the PoC, and the receipt evidence as one
   unit.

## Index

| #  | Name                                             | Class                  | Status                | Re-validate-by | Gates fired (last run)        |
|----|--------------------------------------------------|------------------------|-----------------------|----------------|-------------------------------|
| 01 | Tool-description injection (cross-server CD)     | OWASP LLM01, CWE-441   | CLOSED 2026-05-04     | 2026-11-04     | chain ✓ caveat ✗              |
| 02 | Replay attack on hok-bound capability            | OWASP A07, CWE-294     | CLOSED 2026-05-04     | 2026-11-04     | chain ✓ proof ✓ replay ✗      |
| 03 | Capability broadening (hostile-holder tampering) | CWE-345                | CLOSED 2026-04-27     | 2026-10-27     | chain ✗ (pre-receipt throw)   |
| 04 | Revocation race (revoked-capability replay)      | OWASP A01, CWE-672     | CLOSED 2026-04-27     | 2026-10-27     | chain ✓ revoke ✗              |
| 05 | Cross-origin exfil via http-agent                | OWASP LLM01, CWE-441   | CLOSED 2026-04-27     | 2026-10-27     | chain ✓ caveat ✗ (origin)     |
| 06 | Silent-bypass on revocation-list install (operator trap) | OWASP A04, CWE-693, CWE-754 | CLOSED 2026-04-28 (Run 1 BREAKS, Run 2 CLOSED post-v0.4) | 2026-10-28 | chain ✓ revoke (DETECTABLE) caveat ✓ |
| 07 | fs-sandbox prefix foot-gun (operator misconfig)  | OWASP A04, CWE-22      | **BREAKS** 2026-04-27 (substring `matches` is not path-aware; fix queued) | 2026-10-27 | chain ✓ caveat ✓ (incorrectly allows lateral path) |
| 08 | Forgot NonceStore on hok-bound caps (operator trap) | OWASP A04, A07         | CLOSED 2026-04-27 (Run 1; v0.4 `hasNonceStore()` enables detection) | 2026-10-27 | dual: without store: replay (NOT INSTALLED) allowing replay; with store: replay ✗ |
| 09 | IDN homograph in origin allowlist (operator trap) | CWE-1007, OWASP A04    | **BREAKS** 2026-04-27 (`isExactOrigin` accepts punycode silently; TR39 fix queued) | 2026-10-27 | chain ✓ caveat ✓ (allows attacker-host punycode) |

(Status enum: `OPEN`, `PARTIAL`, `CLOSED — date`. Gates symbols:
`✓` gate checked + passed; `✗` gate checked + denied (this is
the gate that caught the attack); `-` not applicable to the
attack class.)
