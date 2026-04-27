# Round NN — <Attack Name>

> One-line summary: what attack, what's at stake, what's the
> punchline. Replace this blockquote.

```text
Attack class:     <class + refs (e.g. OWASP LLM01, CWE-441)>
Hypothesis:       Positive (true-positive): given <capability>,
                  <attack call> SHOULD be DENIED at the capnagent
                  gate with denial reason matching <pattern>.

                  Negative (true-negative): given the same
                  capability, <legitimate in-scope call> SHOULD be
                  ALLOWED and return <expected result>.

                  Both halves are testable; both must hold for the
                  round to CLOSE. A defense that denies everything
                  is not the win condition.
Test (PoC):       <relative/path/to/file.purple.test.ts>
Coverage:         Tested variants:
                    - <variant 1>
                    - <variant 2>
                    - <variant N>
                  Not yet tested:
                    - <variant M>
                    - <variant K>
Known-bypasses:   - <condition under which the defense breaks>
                  - <condition under which the defense breaks>
                  - <condition that's out-of-scope by design>
Re-validate-by:   YYYY-MM-DD   (default: 6 months from CLOSED date)
Owner:            <owner>
Status:           OPEN | PARTIAL | CLOSED — <date if CLOSED>

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — YYYY-MM-DD HH:MM UTC                              [FAIL|PARTIAL|PASS]
  Env:          <OS> + Node <ver> + capnagent <commit-or-tag>
                + <client variant: in-process | live-MCP | other>
  Gates:        chain ?  | proof ?  | replay ?  | revoke ?  | caveat ?
                  ✓ = gate checked, passed (call permitted by it)
                  ✗ = gate checked, denied (this is the gate that
                       caught the attack; should be ✗ on at least
                       one gate for FAIL/PARTIAL/PASS denial paths)
                  - = gate not applicable to this attack class
  Decision:     DENIED — reason: "<verbatim from receipt>"
                  or
                ALLOWED — and the negative-hypothesis check returned
                <expected legit result>.
  Latency:      <µs> verifier mean over <N> calls (criterion bench
                if measured; "n/a" otherwise).
  FP-7d:        <count> | pending baseline | N/A
                  False denials of legitimate calls in a 7-day
                  observation window. CLOSED without an FP-7d
                  measurement means useful-when-tight, not
                  useful-in-production.
  Gap-class:    CAPABILITY-CONFIG | DEFENSE-LOGIC | OPERATOR-MISCONFIG |
                OUT-OF-SCOPE | HYPOTHESIS | NONE
                  CAPABILITY-CONFIG  the issued cap was too broad/narrow
                  DEFENSE-LOGIC      capnagent itself misbehaved (bug)
                  OPERATOR-MISCONFIG Context provider / wiring fault
                  OUT-OF-SCOPE       defense correctly didn't cover it
                  HYPOTHESIS         the claim was wrong, revise it
                  NONE               PASS — no gap
  Gap:          <one-line description, or "None" if PASS>
  Action:       <what changed before the next run, or "Closed" if PASS>

Run 2 — YYYY-MM-DD HH:MM UTC                              [...]
  Env:          ...
  Gates:        ...
  Decision:     ...
  Latency:      ...
  FP-7d:        ...
  Gap-class:    ...
  Gap:          ...
  Action:       ...
```

## Evidence

- **Runnable PoC:** [`<relative/path>`](../../<relative/path>)
- **Receipt JSON:** [`evidence/NN-<name>.receipt.json`](evidence/NN-<name>.receipt.json)
- **Regen script:** `npm run -w <package> <script-name>`

## Notes

Free-form context that doesn't fit the structured fields:

- **Threat model elaboration** — the attacker's wider capability,
  their goal, why this attack class matters now.
- **Defender-assumption rationale** — why the capability was scoped
  the way it was, what realistic operator config would look like.
- **Source research** — papers, blog posts, prior CVEs that motivated
  the round.
- **Defender-actionable** — concrete operator-config changes implied
  by the round's outcome (bullet list).
