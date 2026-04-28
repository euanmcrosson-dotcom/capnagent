# Round 06 — Silent-bypass on revocation-list install (operator trap)

> Round 04 established that the revocation-list defense holds when
> installed correctly. This round tests what happens when the OPERATOR
> misuses the install API in a realistic way — catches the throw,
> logs it, continues. The defense breaks. A capability the operator
> believed they revoked is silently authorized. **Status: BREAKS.**
> Recommended fix is engine-side: expose `hasRevocationList()` /
> `hasNonceStore()` introspection so operators can write postcondition
> assertions on install-state.

```text
Attack class:     OWASP A04:2021 (Insecure Design); CWE-693 (Protection
                  Mechanism Failure); CWE-754 (Improper Check for
                  Unusual or Exceptional Conditions).
Hypothesis:       Positive (true-positive): given a Verifier where the
                  operator BELIEVES a RevocationList was installed but
                  the install actually threw and was silently ignored,
                  verifyWithContext on a capability whose identifier
                  IS in the (un-installed) list MUST be denied with
                  reason "capability revoked: <id>".

                  Negative (true-negative): a Verifier with a
                  successfully-installed list correctly denies revoked
                  caps AND allows non-revoked caps (the existing
                  round 04 behavior).

                  The positive hypothesis is EXPECTED TO FAIL — that
                  is the round's central finding. The PoC programmatically
                  proves the failure.
Test (PoC):       packages/capnagent/src/__tests__/silent-bypass-revocation.purple.test.ts
Coverage:         Tested variants:
                    - operator catches install error in try/catch and
                      ignores → revoked cap goes through allowed
                    - the broken state is invisible from the public
                      Verifier API surface (no introspection method)
                    - negative: install-succeeds path still denies
                      revoked, allows non-revoked (round 04 regression
                      coverage)
                    - severity calibration: the trigger is a routine
                      try/catch + logger.warn pattern, NOT adversarial
                      code
                  Not yet tested:
                    - same-shape silent-bypass on NonceStore install
                      (no install error in NonceStore — the gap there
                      is "operator forgot to install at all" rather
                      than "install errored and was swallowed").
                      Worth a sibling test focused on detection of
                      "no NonceStore installed but hok-bound caps in
                      use" — a different class of gap.
                    - Rust-side equivalent: `let _ = verifier.with_revocation_list(list)`
                      silently swallows the Result<Self, RevocationError>.
                      Same finding, Rust path.
                    - Promise-based silent-bypass: `await
                      somethingAsync().catch(() => {})` patterns that
                      flatten install failures into success.
                    - Silent-bypass after a successful FIRST install
                      followed by a failed SECOND install (e.g. list
                      rotation): does the second install's failure
                      leave the verifier in a half-installed state?
Known-bypasses:   - Once the engine fix lands (`hasRevocationList()`
                    introspection), this round's failure becomes
                    detectable but NOT prevented — the operator still
                    has to write the postcondition check. So the
                    underlying threat (silent ignore of install
                    error) is mitigated by API ergonomics, not
                    capability semantics.
                  - The fix doesn't help operators who silently
                    ignore the postcondition's failure too. There is
                    no API design that defeats determined operator
                    apathy. The bar is "make the failure mode
                    visible at the deploy-readiness layer," not
                    "make the failure mode impossible."
                  - Out of scope: malicious operators. The threat
                    model here is operator-error / operator-inertia,
                    not adversarial operators.
Re-validate-by:   2026-10-28   (next routine re-validation; engine
                                fix has shipped — re-validation now
                                checks for regression of the
                                introspection methods.)
Owner:            blue-lead
Status:           CLOSED — 2026-04-28 (Run 2 with v0.4 fix)
                  Run 1 BROKE; Run 2 CLOSED after the engine fix
                  shipped (`hasRevocationList()` /
                  `revocationListIssuedAtMs()` / `hasNonceStore()`
                  introspection methods on `Verifier`). The
                  silent-bypass operator pattern is no longer
                  invisible from the API surface — operators can
                  write a postcondition assertion that catches the
                  silent-failed install. The first round in the
                  corpus to BREAK then CLOSE within a single
                  development cycle, demonstrating the angles
                  methodology end-to-end: surface a real defect,
                  ship a real fix, prove the fix with a re-run.

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-28 02:08 UTC                              [FAIL]
  Env:          Windows 11 + Node 20.x + capnagent @ a1e5829
                + @capnagent/core (real WASM via wasm-pack pkg)
  Gates:        chain ✓ | proof - | replay - | revoke (NOT INSTALLED) | caveat ✓
                  Chain integrity passed. Bearer-token cap, no hok.
                  Revocation gate is the failure point — but it
                  fires its own absence (the cap IS in what the
                  operator believed was the list, but no list is
                  actually installed because the install threw and
                  was ignored). Caveat gate then trivially passes
                  since all the cap's caveats are well-formed and
                  satisfy the test context.
  Decision:     ALLOWED — outcome.kind = "allowed".
                Expected: DENIED with reason
                          "capability revoked: buy-stolen-token".
                Observed: ALLOWED. The cap that the operator believed
                          they revoked goes through unimpeded.
                Negative hypothesis (install-succeeds path) HELD as
                expected — this is regression coverage for round 04.
  Latency:      ~11 µs (verify_with_context bench mean — same as
                round 01's measurement; no list installed means no
                revocation-leg work).
  FP-7d:        N/A — this round measures a defense BREAK, not
                ongoing operational behavior.
  Gap-class:    DEFENSE-LOGIC + OPERATOR-MISCONFIG (joint)
                  The DEFENSE-LOGIC half: the engine API doesn't
                  expose introspection so the operator can't detect
                  the silent-failed install.
                  The OPERATOR-MISCONFIG half: the operator wrote
                  the routine try/catch+log+continue pattern that
                  defensive Node.js codebases use everywhere.
                  Joint classification because either half alone
                  would be fine. The intersection is the failure
                  mode.
  Gap:          Verifier has no public method to ask "do I have a
                revocation list installed?" An operator who installed
                successfully and an operator who silently swallowed
                the install error are indistinguishable from the API
                surface. Compounded by: the install method's failure
                pattern (throws CapabilityChainError) maps directly
                onto the most common JavaScript error-handling
                idiom (try/catch with log-and-continue), which means
                the wrong thing happens by default.
  Action:       Round 06 OPENS the engine v0.4 work. The fix is API
                additions on `Verifier`:
                  - hasRevocationList(): boolean
                  - hasNonceStore(): boolean
                  - revocationListIssuedAtMs(): number | null
                These let operators write postcondition assertions
                in deployment-readiness code:
                  verifier.withRevocationList(list);  // may throw
                  if (!verifier.hasRevocationList()) {
                    throw new Error("CRITICAL: silent-failed install");
                  }
                When the fix lands, this PoC's first test gets a
                NEW assertion (`verifier.hasRevocationList() === false`
                after the silent-failed install) and the round
                re-runs with status flipping BREAKS → CLOSED.

Run 2 — 2026-04-28 02:19 UTC                              [PASS]
  Env:          Windows 11 + Node 20.x + capnagent @ 2939ee0+v0.4
                + @capnagent/core (real WASM via wasm-pack pkg
                rebuilt with the v0.4 introspection methods)
  Gates:        chain ✓ | proof - | replay - | revoke (DETECTABLE) | caveat ✓
                  Same scenario as Run 1 — operator silently catches
                  install error. Run-1 verdict (the cap is allowed
                  when the operator believed it revoked) is
                  STRUCTURALLY UNCHANGED — no semantic change to
                  what verify_with_context does in that case. The
                  fix is at the introspection layer.
  Decision:     The verifier still ALLOWS the supposedly-revoked
                cap (no list installed, capability passes caveats
                and chain). What CHANGED is that the operator can
                NOW detect the silent-failed install via
                `verifier.hasRevocationList() === false` BEFORE
                trusting the verifier in production. Postcondition
                assertion now possible:
                  verifier.withRevocationList(badList);
                  // throw caught and ignored above
                  assert(verifier.hasRevocationList(),
                         "CRITICAL: install silently failed");
                Two new positive-hypothesis tests verify:
                  (a) silent-failed install → hasRevocationList()
                      returns false, revocationListIssuedAtMs()
                      returns undefined
                  (b) successful install → hasRevocationList()
                      returns true, revocationListIssuedAtMs()
                      returns the published-at timestamp
  Latency:      ~11 µs (verify_with_context unchanged)
                hasRevocationList() / hasNonceStore(): O(1), single
                Option-is-some check across the WASM boundary.
                revocationListIssuedAtMs(): O(1).
  FP-7d:        N/A
  Gap-class:    NONE — the gap from Run 1 (DEFENSE-LOGIC + OPERATOR-
                MISCONFIG joint) is closed at the engine layer for
                the DEFENSE-LOGIC half. The OPERATOR-MISCONFIG half
                still requires the operator to write the
                postcondition assertion, but they CAN now write it.
  Gap:          None at the engine layer. Operators must still
                add the postcondition assertion to their
                deployment-readiness code; the engine cannot force
                this.
  Action:       Round CLOSED. Engine v0.4 introspection methods
                shipped. Defender-actionable updated below to
                document the postcondition pattern. The PoC tests
                serve as regression coverage — if a future change
                breaks `hasRevocationList()` returning false on a
                silent-failed install, this PoC's Run-2 tests will
                fail.
```

## Evidence

- **Runnable PoC:** [`packages/capnagent/src/__tests__/silent-bypass-revocation.purple.test.ts`](../../packages/capnagent/src/__tests__/silent-bypass-revocation.purple.test.ts) — 5 deterministic tests, all passing (the "FAIL" is the SCENARIO outcome, not the test outcome — the test successfully demonstrates the defense break).
- **Receipt JSON:** [`evidence/06-silent-bypass-revocation-install.receipt.json`](evidence/06-silent-bypass-revocation-install.receipt.json) — the `allowed` receipt produced for a cap that should have been `denied`. The visceral evidence of the gap.
- **Linked round:** Round 04 documented this as a known hazard ("paged-alert in production"); round 06 programmatically proves it AND surfaces the deeper API-design gap.

## Notes

### Why this is the most impactful round in the corpus so far

Rounds 01-05 each tested the structural defense against a specific attack class. They all closed `holds-with-caveat`, which is the right outcome for those attack shapes — the structural defense really does hold under the stated assumptions. But "stated assumptions" included "the operator configured this correctly," which is exactly what round 06 stops assuming.

The angles methodology (from purple-scaffold) is built around a different question: what happens when the assumptions break? Round 06 tests **operator-ergonomics** as the failure mode. It is the first round where the answer is "the defense does not hold."

This is a more impactful finding than "we passed another structural test" because it targets the integration boundary between the engine and a real production deployment — the place where defenses actually fail in the field.

### Severity framing

Triggering this requires no malicious actor. The operator pattern is the standard defensive Node.js codebase pattern:

```ts
try {
  verifier.withRevocationList(list);
} catch (err) {
  logger.warn("revocation install failed:", err);
  // execution continues — the verifier silently has no list
}
```

That's not adversarial code. That's the same pattern every team writes for "log and continue" semantics. Severity is HIGH because the bar to trigger is low and the consequence (revoked caps go through) is exactly what revocation is supposed to prevent.

### What changes in the engine

Engine v0.4 will add `Verifier` introspection methods. Two specific additions:

```ts
class Verifier {
  // ... existing methods ...

  /** True iff a RevocationList is currently installed. */
  hasRevocationList(): boolean;

  /** Issued-at timestamp of the installed list, or null if none. */
  revocationListIssuedAtMs(): number | null;

  /** True iff a NonceStore is currently installed. */
  hasNonceStore(): boolean;
}
```

The same shape generalizes to any future opt-in defense: every install-time-fallible builder method must be paired with a state-query method.

### Defender-actionable

For an operator using capnagent in production:

1. **Until v0.4 lands**, treat any thrown `CapabilityChainError` from `withRevocationList` as a deploy-time hard failure. Do NOT log-and-continue. Do NOT use a generic exception swallower around the install call.
2. **Wrap install in a function that re-throws**, not a try/catch that logs:
   ```ts
   function installRevocationList(verifier, list) {
     verifier.withRevocationList(list); // let any throw propagate
   }
   ```
   The function exists to mark the call site as "must not be silently caught."
3. **When v0.4 lands**, add a deploy-readiness check:
   ```ts
   verifier.withRevocationList(list);
   assert(verifier.hasRevocationList(), "revocation-list install silently failed");
   ```
4. **Add a startup-probe metric** that records `verifier.hasRevocationList()` at deployment time. Alert on transitions from `true` to `false` (revocation defense lost) — this would catch a follow-on rotation that silently failed too.
5. **Track and review every uninstall** of the revocation list. There is no business reason to remove a revocation list mid-flight; any such transition should be paged.

### Source research

- OWASP A04:2021 — Insecure Design (the broader category covering API designs that pair install-failure modes with common error-handling idioms in failure-coupled ways).
- CWE-693 — Protection Mechanism Failure.
- CWE-754 — Improper Check for Unusual or Exceptional Conditions (the operator-side half: failing to check / propagate the install error).
- The purple-scaffold angles methodology — round 06 is the first capnagent application of that methodology (testing FAILURE MODES of existing defenses, not new attack classes).
