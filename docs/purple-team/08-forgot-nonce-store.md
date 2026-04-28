# Round 08 — Operator forgets NonceStore on hok-bound caps

> Round 02 closed `holds-with-caveat` for hok-bound replay protection.
> v0.1's NonceStore is **opt-in** — a verifier without
> `withNonceStore(...)` accepts replays even on hok-bound caps.
> Round 02's residual-risk section flagged this as a known hazard; this
> round tests the operator-trap directly. With v0.4's `hasNonceStore()`
> introspection method shipped, the configuration gap is now
> detectable. **Status: CLOSED on Run 1.**

```text
Attack class:     OWASP A04:2021 (Insecure Design); OWASP A07:2021
                  (Identification and Authentication Failures);
                  CWE-294 (Authentication Bypass by Capture-Replay);
                  CWE-693 (Protection Mechanism Failure); CWE-665
                  (Improper Initialization).
Hypothesis:       Positive (true-positive): given a hok-bound
                  capability and a Verifier with NO `NonceStore`
                  installed, the operator can DETECT this configuration
                  error via `verifier.hasNonceStore() === false` BEFORE
                  relying on the (non-existent) replay defense. The
                  detection mechanism is present and correct.

                  Negative (true-negative): a Verifier WITH a
                  NonceStore installed reports `hasNonceStore() ===
                  true` AND correctly denies replays with reason
                  exactly `"proof replay detected"`. (Round 02
                  regression coverage.)

                  Plus the demonstration-of-need: confirm the actual
                  gap — without a NonceStore installed, hok-bound
                  replays succeed silently. That visceral proof is
                  what makes the introspection method load-bearing.

                  Both halves are tested in the PoC; both must hold.
Test (PoC):       packages/capnagent/src/__tests__/forgot-nonce-store.purple.test.ts
Coverage:         Tested variants:
                    - fresh Verifier: `hasNonceStore()` returns false
                      (positive hypothesis: detection mechanism works)
                    - WITHOUT a NonceStore installed, hok-bound replay
                      is silently ALLOWED (the gap; demonstration-of-
                      need for the introspection method)
                    - the deployment-readiness pattern works:
                      `assert(verifier.hasNonceStore())` after wiring
                      catches the operator forgetting the install
                    - WITH a NonceStore installed, `hasNonceStore()`
                      returns true AND replay is correctly denied with
                      reason "proof replay detected" (round 02
                      regression coverage)
                    - Verifier with both `withRevocationList` AND
                      `withNonceStore` reports both true; the
                      introspection methods compose
                    - negative-tightening: Verifier with only
                      `withRevocationList` reports
                      `hasRevocationList() === true` and
                      `hasNonceStore() === false` — defenses are
                      independently introspectable, not a generic
                      "any defense installed?" boolean
                  Not yet tested:
                    - Operator who installs the NonceStore but
                      FORGETS to call the deploy-readiness
                      postcondition. There is no API design that
                      defeats determined operator apathy. Out of
                      scope by the same reasoning as round 06.
                    - Bearer-token (non-hok) caps with NonceStore.
                      `NonceStore` has no effect on
                      `verifyWithContext` by design — bearer tokens
                      are explicitly designed to be reusable.
                      Documented in the class doc; not a gap.
                    - Distributed deployment: two verifier processes
                      each report `hasNonceStore() === true` while
                      holding independent in-memory stores. An
                      attacker can replay the same proof against
                      each. Out of scope until a shared `NonceStore`
                      backend ships (sibling residual risk to round
                      02's "DISTRIBUTED RACE").
                    - The operator who silently catches an error
                      from `withNonceStore` — `withNonceStore`
                      cannot fail at install (no signature check; no
                      Result return), so the round-06-shape
                      silent-bypass doesn't apply here. The gap is
                      simpler: forgetting the call entirely.
Known-bypasses:   - The introspection method makes the failure mode
                    detectable, NOT prevented. The operator still has
                    to write the postcondition assertion. Same
                    ergonomics-vs-semantics framing as round 06.
                  - The fix doesn't help operators who write the
                    postcondition but silently swallow its failure
                    too. There is no API design that defeats
                    determined operator apathy. The bar is "make the
                    failure mode visible at the deploy-readiness
                    layer," not "make the failure mode impossible."
                  - Out of scope: malicious operators. The threat
                    model is operator-error / operator-inertia, not
                    adversarial operators.
                  - InMemoryNonceStore loses entries on process
                    restart. `hasNonceStore()` returning true after
                    restart says "a store is wired up" — it does not
                    say "the store remembers entries from before the
                    restart." That's a sibling residual risk
                    (round 02's "PROCESS RESTART" bullet), not
                    something this introspection method addresses.
Re-validate-by:   2026-10-27   (default: 6 months from CLOSED date)
Owner:            blue-lead
Status:           CLOSED — 2026-04-27 (Run 1)
                  v0.4's introspection methods (`hasNonceStore()`,
                  `hasRevocationList()`, `revocationListIssuedAtMs()`)
                  shipped at commit `a1e98ac` BEFORE this round was
                  authored, so the operator-config gap is detectable
                  from day one. Round 08 closes on first run because
                  the defense (introspection-based detection) is
                  present and correct from the start. The round still
                  carries a real finding: the visceral evidence that
                  WITHOUT a NonceStore installed, hok-bound replays
                  succeed — exactly what round 02's residual-risk
                  bullet warned about, now captured in an annotated
                  receipt.

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-27 (UTC)                                  [PASS]
  Env:          Windows 11 + Node 20.x + capnagent @ a1e98ac+v0.4
                + @capnagent/core (real WASM via wasm-pack pkg with
                v0.4 introspection methods)
                + real @noble/ed25519 (async path, no sha512Sync
                config required)
  Gates:        Dual-run note — this round captures TWO scenarios in
                one PoC because the finding is the contrast between
                them.

                Scenario A (operator forgot the install — the gap):
                  chain ✓ | proof ✓ | replay (NOT INSTALLED) | revoke - | caveat ✓
                    Chain integrity passed. Proof verified. Replay
                    leg shows "NOT INSTALLED" — the verifier has no
                    NonceStore, so the gate doesn't fire even on
                    byte-identical replay. Caveats trivially pass.
                    Replay is ALLOWED.

                Scenario B (operator installed correctly — round 02
                regression):
                  chain ✓ | proof ✓ | replay ✗ | revoke - | caveat -
                    Same proof, NonceStore installed. Replay leg
                    fires and DENIES with reason "proof replay
                    detected". Caveats not reached (replay short-
                    circuits before them, as designed).

                The introspection method (`hasNonceStore()`)
                distinguishes these two scenarios from the API
                surface — the round's central deliverable.
  Decision:     POSITIVE HYPOTHESIS: the operator CAN detect the
                missing-NonceStore configuration via
                `verifier.hasNonceStore() === false` BEFORE relying
                on the (non-existent) replay defense. The
                deployment-readiness pattern (`assert(verifier
                .hasNonceStore())`) catches the forgotten install
                at deploy time instead of silently accepting
                replays in production.

                NEGATIVE HYPOTHESIS held — Verifier with NonceStore
                installed reports `hasNonceStore() === true` and
                correctly denies replays. Round 02's central
                guarantee re-confirmed.

                DEMONSTRATION-OF-NEED captured — gap_receipt shows
                ALLOWED for what should have been denied. Verbatim
                evidence of why the introspection method is
                load-bearing.
  Latency:      ~170 µs verifier mean for verifyWithProof (unchanged
                from round 02 measurement).
                hasNonceStore(): O(1), single Option-is-some check
                across the WASM boundary (same shape as
                hasRevocationList from round 06's Run 2).
  FP-7d:        N/A — this round measures introspection-method
                correctness, not ongoing operational behavior.
                Round 02's FP-7d (still pending baseline) covers the
                replay-denial leg.
  Gap-class:    NONE — v0.4's introspection methods landed before
                this round was authored. The gap from round 02's
                residual-risk bullet ("WITHOUT a NonceStore
                installed, the verifier accepts replays") is now
                detectable at the API layer; the OPERATOR-MISCONFIG
                half still requires the operator to write the
                postcondition assertion, but they CAN now write it.
  Gap:          None at the engine layer. Operators must still add
                the `assert(verifier.hasNonceStore())` postcondition
                to their deployment-readiness code; the engine
                cannot force this.
  Action:       Closed on Run 1. Folded into the regression suite
                (the PoC runs in default `npm test --workspaces`).
                Two captured receipts (gap and fixed) folded into the
                evidence corpus. Re-validate at 2026-10-27 to confirm
                no regression of the introspection methods.
```

## Evidence

- **Runnable PoC:** [`packages/capnagent/src/__tests__/forgot-nonce-store.purple.test.ts`](../../packages/capnagent/src/__tests__/forgot-nonce-store.purple.test.ts) — deterministic tests, all passing. Both halves of the hypothesis are encoded; the gap demonstration is encoded as a positive assertion (`outcome.kind === "allowed"`) so a future regression that accidentally enabled NonceStore-by-default would be caught.
- **Receipt JSON:** [`evidence/08-forgot-nonce-store.receipt.json`](evidence/08-forgot-nonce-store.receipt.json) — single annotated object with two halves. `gap_receipt`: ALLOWED outcome for a replay against a verifier without NonceStore (the demonstration-of-need). `fixed_receipt`: DENIED outcome with reason `"proof replay detected"` against a verifier WITH NonceStore (round 02's locked reason string).
- **Regen script:** `npm run -w @capnagent-examples/shopping-agent regen-purple-evidence-08`
- **Linked rounds:** Round 02 (the defense whose ergonomics gap this tests) and round 06 (the sister round that introduced the introspection-method pattern). v0.4 commit reference: `a1e98ac`.

## Notes

### Why this round closes on first run

Rounds 01-05 each took at least one run to close, and round 06 was the first to BREAK on Run 1 then close on Run 2 after the engine fix shipped. Round 08 is different: the engine fix (the `hasNonceStore()` introspection method, v0.4) shipped BEFORE this round was authored, prompted by round 06's finding. Round 08 documents a failure mode that was already mitigated at the API layer. Closing on Run 1 is the right outcome — the round captures both the underlying gap (replay-without-NonceStore is silently allowed) and the now-shipped fix (introspection makes the gap detectable).

This is a structurally important round for the corpus: it shows that round 06's finding generalized — the introspection-method pattern correctly extends from `hasRevocationList()` to `hasNonceStore()`, and the same operator-readiness postcondition shape works for both opt-in defenses.

### Why the dual-run narrative is in ONE PoC, not two

Round 06's Run 1/Run 2 split was about TIME — the engine fix shipped between runs. Round 08 has no time gap; the fix landed before the round was even opened. The "dual run" lives entirely INSIDE Run 1 because both scenarios (gap, fixed) are testable simultaneously with the v0.4 binary. The receipt evidence captures both as `gap_receipt` and `fixed_receipt` keyed under one annotated JSON object, so a reviewer can compare them side by side.

The Gates row in Run 1 has the dual-run treatment: Scenario A and Scenario B inline, distinguishing the "NOT INSTALLED" replay column (for the gap) from the "✗" replay column (for the fix). This stretches the template's gate-row format slightly — the canonical row is one set of `chain | proof | replay | revoke | caveat` checkmarks, not two — but the contrast is the round's whole point and merging the two scenarios into one row would obscure the finding.

### Severity framing

Same calibration as round 02 (and round 06): no malicious actor required. The "attacker" is operator inertia. The trigger is omitting `withNonceStore(...)` — not an empty catch like round 06, just a missing call. That makes severity HIGH:
- the bar to trigger is even lower than round 06 (a forgotten line, not a swallowed error)
- the consequence is exactly what hok-bound caps are supposed to prevent (replay)
- v0.1's API gave operators no signal that the defense was missing

v0.4's introspection method doesn't reduce severity of the underlying configuration mistake. It reduces the chance of the mistake reaching production by making it detectable at deploy-readiness time — which is the right layer for a configuration-error class fault.

### Defender-actionable

For an operator using capnagent with hok-bound capabilities:

1. **Always install a `NonceStore` on the verifier** when issuing hok-bound caps. The default verifier does NOT protect against replay; it's opt-in. Round 02's defender-actionable bullet 1 is the canonical statement of this.
2. **Add a deploy-readiness postcondition** on every verifier configured for hok-bound caps:
   ```ts
   const verifier = new Verifier(rootKey).withNonceStore(new NonceStore());
   if (!verifier.hasNonceStore()) {
     throw new Error("CRITICAL: hok-bound caps in use but no NonceStore installed");
   }
   ```
   Combine with `verifier.hasRevocationList()` for a single readiness probe that asserts every opt-in defense the deployment expects.
3. **Add a startup-probe metric** that records `verifier.hasNonceStore()` at deploy time. Alert on transitions from `true` to `false` (replay defense lost) — this would catch a follow-on rotation or hot-reload that silently re-instantiated the verifier without re-wiring the store.
4. **For deployments with hok-bound caps in production**: treat a verifier reporting `hasNonceStore() === false` as an out-of-rotation condition. Drain traffic to verifiers reporting `true`; page on persistent `false`.
5. **Plan for the durable-backend migration** (Redis, Postgres) before turning on hok in production. `hasNonceStore() === true` says a store is installed; it does NOT say the store survives process restart. Round 02's defender-actionable bullets 3 and 6 cover this.

### Source research

- Round 02 (`docs/purple-team/02-replay-attack-on-hok-bound-cap.md`) — the residual-risk section that flagged this exact failure mode.
- Round 06 (`docs/purple-team/06-silent-bypass-revocation-install.md`) — the round that surfaced the introspection-method pattern and triggered the v0.4 work.
- RFC 9449 (DPoP) — the holder-of-key replay-protection model capnagent's `verify_with_proof` is shaped after.
- CWE-294 (Authentication Bypass by Capture-Replay) — the attack class the missing-NonceStore enables.
- CWE-665 (Improper Initialization) — the operator-error class this round documents.
- CWE-693 (Protection Mechanism Failure) — the broader category.
- OWASP A04:2021 (Insecure Design) — covers the API-design half (opt-in default with no detection mechanism would be a design fault; v0.4 closes that half).
