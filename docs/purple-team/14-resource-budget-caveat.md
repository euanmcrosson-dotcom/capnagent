# Round 14 — Resource-budget caveat (`verifier.<field>` DSL extension)

> Rounds 11-13 surfaced cumulative-effect attacks the structural
> defense couldn't address: an agent making 10,000 in-scope tool
> calls, a sub-agent recursing 50 levels deep, an LLM-completion cap
> burning down a customer's monthly budget. Each individual call is
> in-scope; the cumulative behavior is the attack. capnagent had no
> language to express "and the running total is too high." This
> round introduces that language. **Status: CLOSED 2026-04-30 (Run 1).**
> The headline v0.6 feature: a new top-level DSL identifier
> (`verifier.<field>`) that reads facts the operator's harness
> populates BEFORE calling `verifyWithContext`, never the agent.

```text
Attack class:     OWASP A04:2021 (Insecure Design); CWE-400 (Uncontrolled
                  Resource Consumption); CWE-799 (Improper Control of
                  Interaction Frequency). Adjacent to OWASP LLM10
                  (Unbounded Consumption) but framed for tool-call
                  authorization specifically.
Hypothesis:       Positive (true-positive): given a capability with a
                  caveat predicate `verifier.tokens_used <= N`, after
                  the harness's tracked counter has crossed N, the
                  next verifyWithContext call MUST be denied with
                  reason matching `caveat failed: verifier\.tokens_used`.

                  Negative (true-negative): the same capability with
                  the harness's counter still under N MUST be allowed,
                  and the unrelated existing defenses (chain integrity,
                  proof-of-possession, revocation, other caveats) MUST
                  continue to behave the way prior rounds proved.

                  Positive expected to HOLD. Negative expected to HOLD.
                  Round status reflects whether both halves did.
Test (PoC):       packages/capnagent/src/__tests__/resource-budget-caveat.purple.test.ts
Coverage:         Tested variants:
                    - basic threshold: 5 calls under budget allowed,
                      6th (boundary-crossing) call denied
                    - structural binding: dropping the budget caveat
                      from the wire form breaks the chain (round-03
                      shape, applied to the new caveat class)
                    - missing verifierFacts is fail-closed (UnknownIdent
                      surfaces as a denial reason, never a silent pass)
                    - the agent CANNOT spoof verifier.<field> by putting
                      the same key in arg.<field>; the DSL distinguishes
                      the two name-spaces
                    - composition: AND of two verifier-fact thresholds
                      (tokens AND depth) denies if either crosses
                    - denial receipts are signed and verify under the
                      audit key — operators alert on the
                      outcome.kind === "denied" stream
                    - nested verifier paths (verifier.budget.tokens_used)
                      resolve like nested arg paths
                    - operator-foot-gun calibration: the verifier does
                      NOT enforce monotonicity — a buggy/hostile harness
                      that resets the counter to 0 lets an over-budget
                      cap pass. Pinned in test, documented as
                      operator-side responsibility.
                  Not yet tested:
                    - distributed-counter coherence across multiple
                      verifier processes sharing a root key (same shape
                      as the NonceStore distribution problem; out-of-
                      scope per THREAT_MODEL.md, but worth a sibling
                      "operator-forgot-to-share-the-counter" round
                      modeled on round 06's introspection-gap finding)
                    - read-evaluate-update atomicity: a burst of N
                      concurrent calls can each read the same below-
                      threshold counter and all pass, collectively
                      exceeding the budget by up to N-1 calls.
                      Mitigation is harness-side (serialize budget-
                      bearing calls, or hardstop reserve); worth a
                      future round measuring real-world burst sizes
                      and recommending a sane reserve.
                    - cap-config foot-guns: a too-loose threshold
                      (`verifier.tokens_used <= 999999999`) defeats
                      this defense the same way a too-loose
                      `arg.path matches "~"` defeats round 01.
                      Operator responsibility, like every other
                      cap-config angle. Future round can demonstrate
                      via tooling (`mcp-recon` or a capnagent-side
                      cap linter) rather than runtime defense.
                    - unit-mismatched verifier facts: the DSL's unit
                      system applies to numeric literals (e.g. `50_usd`)
                      but JSON-derived values come back unitless. The
                      PoC pins this contract; a future round could
                      explore extending the JSON-to-Value bridge so
                      harnesses can stamp units onto verifier facts.
Known-bypasses:   - The harness lying about facts. If the harness sets
                    verifierFacts: { tokens_used: 0 } on every call,
                    the cap is useless. The structural argument
                    REQUIRES that the harness actually computes the
                    counter. This is operator-config domain, the same
                    shape as choosing realistic TTLs (THREAT_MODEL.md
                    operator-responsibility 3).
                  - The harness reading a stale counter. If the
                    counter store (Redis, Postgres) is eventually
                    consistent and the harness reads from a replica
                    behind the writer, the verifier sees a value
                    older than reality. The defense degrades by the
                    replication lag. Mitigation is an operator
                    deployment choice (read-from-primary on the
                    budget-bearing path) and is documented as a
                    known operator-side trade-off.
                  - Privilege escalation within the underlying tool.
                    A budget caveat bounds tool-call AUTHORIZATION;
                    it does not bound what the tool does once invoked.
                    A tool that, on a single in-scope call, runs a
                    1-million-token internal loop is the tool's
                    authority, not capnagent's. Same shape as
                    THREAT_MODEL.md row "privilege escalation within
                    the underlying tool surface."
                  - Out of scope: race-condition attacks on the
                    counter's underlying store. Cryptographic-
                    storage domain, not authorization-engineering.
Re-validate-by:   2026-10-30   (next routine re-validation; this
                                round's defense is structural, so the
                                primary regression risk is the DSL
                                resolver getting silently broken by a
                                future widening of `arg.<field>` that
                                reaches into `verifier.<field>`.
                                Re-validation watches that the
                                resolver still distinguishes the two
                                name-spaces.)
Owner:            blue-lead
Status:           CLOSED — 2026-04-30 (Run 1)
                  The first capnagent round whose CLOSED requires a
                  net-new feature (the `verifier.<field>` DSL
                  identifier shipped in v0.6 simultaneously with this
                  round's PoC). All prior rounds were either
                  defended-by-shape (01-05), defended-by-engine-fix
                  on top of an existing surface (06-10), or
                  contract-shape rounds (11-13). Round 14 is the
                  first "we need a new authority surface to defend
                  this" round.

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-30 02:30 UTC                              [PASS]
  Env:          Windows 11 + Node 20.x + capnagent @ feat/round-14
                + capnagent-core v0.6 (Rust DSL extension built fresh
                via `npm run build:wasm`)
  Gates:        chain ✓ | proof - | replay - | revoke - |
                caveat ✓ for in-budget calls; caveat ✗ for
                threshold-crossing calls. The new resolver branch
                (`"verifier" => ...` in caveat_dsl.rs::resolve_ident)
                fired on every iteration of the 5-allowed/1-denied
                cycle. Receipts on the denied call carried reason
                `"caveat failed: verifier.tokens_used < 1000"` —
                deterministic, locked to the predicate text.
  Decision:     ALLOWED for the first 5; DENIED for the 6th.
                Both hypotheses HELD on first run.
  Latency:      Bench measurement deferred — the resolver branch is
                a JSON-walk identical in shape to `arg.<field>`, so
                first-order it adds the same cost (a few hundred ns
                per nested key). Future bench cycle to measure the
                end-to-end verify_with_context overhead with a
                multi-key verifier_facts payload. The expected
                regression vs. v0.5 is on the order of "indistinguishable
                from noise" for shallow facts.
  Hash-witness: TBD on commit. Will be filled in once this branch
                merges and a deterministic Run-1 receipt is captured.
  Decision:     CLOSED. The new authority surface works as designed.
                The agent has no path to influence verifier_facts —
                that's the entire structural claim — and the harness
                is the operator's choice of code, which is the
                operator-side of the defense.

──────────────────────────────────────────────────────────────────
Defender-actionable notes
──────────────────────────────────────────────────────────────────

The structural defense holds, but its usefulness depends on
operator-side discipline. Concrete things the operator OWES the
deployment:

1. **The harness — not the agent — populates `verifierFacts`.** This
   is the entire security claim. If the harness reads any agent-
   produced field and copies it into verifierFacts, the defense
   collapses. Code review for verifierFacts populations should treat
   it the same way credit-card-number handling is treated: every
   caller must be inspectable end-to-end.

2. **Counter consistency under bursts.** A naive harness reads the
   counter at request time, hands it to the verifier, and updates
   after the tool call returns. A burst of N concurrent calls all
   read the same counter and all pass. Mitigations:
   - Serialize budget-bearing calls (a per-session lock).
   - Use approximate accounting with a hardstop reserve (e.g. cap
     at 90% of budget; over-budget calls in flight are bounded by
     that 10%).
   - Pre-decrement the counter at the request gate, refund on
     denial. Trades over-counting for under-counting.

3. **Counter persistence across restarts.** The default in-memory
   tracker resets on process restart. For production, back the
   counter with Redis / Postgres / your durable store of choice.
   THREAT_MODEL.md row "Distributed replay across multiple verifier
   processes" applies analogously here.

4. **Caveat-DSL semantic foot-guns: tight thresholds.** A loose
   `verifier.tokens_used <= 999999999` defeats this defense the same
   way a loose `arg.path matches "~"` defeats round 01. Cap issuers
   should justify the threshold and audit it on issuance. A future
   capnagent-side cap linter is queued (see "not yet tested" above).

5. **Monitor `outcome.kind === "denied"` with reason matching
   `verifier\.`.** A spike in budget-caveat denials is the highest-
   signal anomaly indicator capnagent produces for this class —
   either a real cost-amplification attack in flight, or a
   miscalibrated cap. Either way, alert.

──────────────────────────────────────────────────────────────────
Adjacent rounds
──────────────────────────────────────────────────────────────────

- **Round 11 (indirect injection cascade via tool response).** The
  follow-on call shape that R11 covers is structurally denied by
  the cap's tool-name + arg-shape caveats. R14 adds defense for the
  case where the agent stays in-scope but burns capacity. Composes
  cleanly: a cap with both a tool-name caveat AND a budget caveat
  resists both attack shapes.
- **Round 12 (cap re-issuance after denial).** R12 surfaces that
  re-issuing a cap to bump the budget is pure crypto with no in-
  band agent → issuer path. R14 makes "re-issue with a wider
  budget" an explicit operator decision rather than a side-effect
  of caveat-shape. Operators raising a budget cap should leave the
  audit trail an issuer-side runbook entry, not a quietly-broader
  reissuance.
- **Round 13 (sub-agent scope drift).** R13 shows that sub-agent
  attenuation is consuming and that the executor's identifier is
  inherited from the planner. R14 lets a planner attenuate with
  `verifier.subagent_depth <= 3` so the executor cannot recurse
  beyond a budget-per-session limit even if the planner-cap caveats
  would otherwise admit deep delegation chains.
```
