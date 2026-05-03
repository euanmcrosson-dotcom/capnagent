# Round 12 — Capability re-issuance after denial (operator-side runbook)

> A prompt-injected agent has its tool calls denied by the gate.
> Standard ergonomics: the agent reports the denial in its reply
> and the next turn's planner asks for a broader capability. If
> the issuer naively re-issues whatever the agent asks for, the
> defense degrades to nothing — the agent eventually gets a
> capability that permits the malicious action. The defense
> against this is **operator-side**: count denials per (caller,
> tool) within a window, apply back-off when a spike is observed,
> require human approval before re-issuing a strictly broader cap.
> capnagent's job is to make the signal cryptographically
> authoritative; the issuer's job is to read it. This round
> documents the contract and the runbook; it is intentionally
> NOT a structural-defense round.

```text
Attack class:     Operator-side denial-of-defense via re-issuance
                  churn. No CWE/OWASP analogue at this level of
                  granularity. Closest precedent is the abstract
                  "operator-side rate-limiting" pattern called
                  out in the operator-responsibility section of
                  THREAT_MODEL.md.
Hypothesis:       This round's hypothesis is different from rounds
                  01–11: it asserts the **shape of the contract**
                  between capnagent and the issuer, not a structural
                  defense. The four claims:

                  1. Every denied call produces a signed receipt
                     distinguishable from an allowed call by
                     `outcome.kind`.
                  2. The receipt's signature is verifiable
                     independently of capnagent's runtime state —
                     the issuer can ingest signed receipts from a
                     different process / a logfile / a stream and
                     trust them.
                  3. Re-issuance is a pure cryptographic operation
                     independent of any prior denial — capnagent
                     does NOT remember that this caller had calls
                     denied. The issuer must remember.
                  4. There is no in-band path from the agent to the
                     issuer; the agent observing a denial cannot
                     influence what the issuer decides next (the
                     receipt is consumed by the issuer's logging
                     pipeline, not by the agent).

                  All four are tested in the PoC.
Test (PoC):       packages/capnagent/src/__tests__/cap-reissuance-after-denial.purple.test.ts
Coverage:         Tested variants:
                    - denial → outcome.kind === "denied", reason
                      string non-empty (operator can grep)
                    - allowed → outcome.kind === "allowed"
                      (denials are distinguishable from allows)
                    - 5 denials in a row → 5 independent receipts;
                      verifier exposes no `denialCount` accessor
                    - re-issuing a broader cap after a 10-denial
                      spike succeeds — capnagent does NOT enforce
                      back-off
                    - two issuer processes under same root key
                      → independent state (back-off counter must
                      live outside the issuer-process boundary)
                    - receipt is the verify call's RETURN value, NOT
                      a Promise the agent could await; receipt
                      audience is the operator, not the agent
                    - bypass: naive issuer re-mints the same narrow
                      cap → 5/5 denied (no improvement, but no
                      escalation either)
                    - bypass: naive issuer broadens after each
                      denial → eventually permits the action
                      (CAPABILITY-CONFIG outcome — what the round
                      defends against, and the operator's runbook
                      stops)
                  Not yet tested:
                    - Specific back-off algorithms (token bucket,
                      exponential, fixed-window). Operator-policy
                      choices.
                    - Library-side `BackoffController` helper.
                      v0.7 backlog candidate. Deliberately excluded
                      from v0.6 to keep library surface narrow.
                    - Cross-process denial counting under a shared
                      backing store (Redis/Postgres). Same shape
                      as round 02's distributed-NonceStore problem.
                    - Insider-issuer adversaries. If the issuer
                      ITSELF is hostile, capnagent has no defense.
                      Out of scope per THREAT_MODEL.md.
Known-bypasses:   - Naive issuer policy: re-issue strictly broader
                    cap after each observed denial. The agent
                    eventually gets the action through. PoC pins
                    this. The mitigation is the operator's
                    runbook, not a capnagent change.
                  - Insider-issuer: hostile issuer re-issues
                    unrestricted caps regardless of denial signals.
                    Out of scope.
                  - Cross-process state desync: issuer A has the
                    back-off counter; issuer B under the same root
                    key doesn't. Same answer as round 02 — shared
                    backing store for the counter.
                  - Time-based bypass: agent waits past back-off
                    window and tries again. The window length is
                    the operator's choice; the round notes the
                    trade-off but does not prescribe a value.
Re-validate-by:   2026-11-03   (default: 6 months from CLOSED date)
Owner:            v0.6 maintainers
Status:           CLOSED — 2026-05-03

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-05-03 02:14 UTC                              [PASS]
  Env:          Windows 11 + Node 22 + capnagent v0.6-pre
                + in-process verifier (no MCP client)
  Gates:        chain ✓ | proof - | replay - | revoke - | caveat ✗
                  caveat ✗ on the over-budget call (denial path)
                  caveat ✓ on the in-budget call (allow path)
                  Both paths produce signed receipts the operator's
                  back-off counter consumes externally.
  Decision:     Receipt-stream contract verified. Re-issuance is a
                pure cryptographic operation; capnagent imposes no
                runtime back-off. Operator-side responsibility
                explicitly pinned by the no-`denialCount`-accessor
                assertion.
  Latency:      n/a — pure verifier path.
  FP-7d:        N/A — this is a runbook round, not a detection.
  Gap-class:    NONE
  Gap:          None.
  Action:       Closed.
```

## Evidence

- **Runnable PoC:** [`cap-reissuance-after-denial.purple.test.ts`](../../packages/capnagent/src/__tests__/cap-reissuance-after-denial.purple.test.ts)
- **Round file:** [this document](12-cap-reissuance-after-denial.md)

## Notes

### Why this round has no structural-defense PoC

The corpus contract for closed rounds (01–11) is *"the structural
defense holds; the PoC asserts both positive and negative
hypotheses."* Round 12's hypothesis is different: it asserts the
**shape of the contract** between capnagent and the issuer.

This is intentional. Some classes of defense are not the
verifier's responsibility — they are the *issuer's*. capnagent's
contribution is the cryptographic primitive that lets the issuer
build a defense; the issuer's contribution is the back-off logic.
A round that documented an operator-policy detail as a structural
defense would mislead reviewers about where the trust boundary is.

The four claims in the Hypothesis section together describe the
"surface the operator must integrate against." The PoC verifies
that surface.

### Operator runbook (defender-actionable)

If you operate an issuer that mints capabilities for AI agents,
implement these in the issuer process (or in an issuer-side
service that all issuer processes consult):

1. **Count denials per `(caller, tool)`.** Sliding window — 5 min
   to 1 hour, depending on agent traffic shape. The receipt's
   `outcome.kind === "denied"` is the signal.

2. **Hash the denial reason.** Use it as a sub-key. A spike of
   "caveat failed: tool == ..." denials is a different signal
   from a spike of "caveat failed: arg.amount <= ..." denials,
   and the back-off policy may differ.

3. **Apply back-off when the count exceeds a threshold.** The
   simplest correct policy: refuse to re-issue a strictly broader
   cap from the agent's request after N denials in the window.
   Refer to a human approval queue instead. Threshold values are
   per-deployment.

4. **Reset the counter only on positive operator action.** Time
   alone should not reset the counter — that turns the back-off
   into a "wait it out" attack. A human approval, a fresh agent
   session under a new caller identifier, or a documented
   operational reset are the right reset triggers.

5. **Surface the spike to the audit dashboard.** A denial-spike
   pattern is a security-relevant signal even if back-off
   correctly contains it; the operator should know when an agent
   is exhibiting injection-shaped behavior.

6. **Test that your back-off works.** A regression where the
   issuer silently disables back-off (config drift, deployment
   bug) is exactly the silent-bypass class round 06 documents
   for the revocation list. Treat the back-off counter the same
   way: a deployment-readiness probe should assert it is active.

### Why no library-side `BackoffController` in v0.6

Three reasons capnagent does not ship a `BackoffController` in
v0.6:

1. **Library surface discipline.** capnagent's contract is "the
   verifier and the gate." Adding back-off would expand the
   surface to include issuer-side policy, which is the issuer's
   job to choose, not the library's. Once we ship a default,
   operators converge on it whether or not it fits — see also
   the v0.5 `NonceStore.clear()` discussion.

2. **Policy choices are deployment-specific.** The right window,
   threshold, and reset policy depend on how many agents you
   run, how often they make decisions, what their traffic
   distribution looks like, and how forgiving your operations
   tolerance is. None of that is library territory.

3. **A bad default is worse than no default.** If we shipped a
   token-bucket with a 5-minute window and a threshold of 10,
   operators would pin to those defaults and not consider whether
   they fit. The PoC documents the surface and the runbook;
   operators implement.

A `BackoffController` is a v0.7 backlog candidate **only if** real
operators ask. Until then, the runbook is the v0.6 answer.

### Source research

- Round 02 (this corpus): replay protection — same operator-vs-
  library trust-boundary discussion. NonceStore is opt-in; replay
  protection is operator-installed; capnagent enforces nothing if
  the operator forgot to call `withNonceStore()`.
- Round 06 (this corpus): silent-bypass on revocation-list install
  — the same lesson re-stated for the revocation channel.
- Round 11 (this corpus): indirect injection cascade — the
  *call-time* defense that produces the denials this round
  documents the response to.

### What this round explicitly does NOT claim

- It does NOT claim capnagent prevents the agent from getting a
  broader capability after a denial spike. The agent can always
  ask, the issuer can always re-mint. The defense is the
  *operator's* discipline, not the verifier's.
- It does NOT claim a specific back-off policy is "right" — the
  runbook lists patterns and trade-offs; deployment chooses.
- It does NOT claim the receipt stream is the only signal. Most
  operators will also feed in other signals (per-caller request
  rate, semantic similarity of denied calls, etc.). The receipt
  is the *cryptographically authoritative* one — anything else
  is operator policy on top.
