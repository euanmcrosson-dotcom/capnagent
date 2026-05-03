# Round 13 — Sub-agent / delegated-capability scope drift

> A planner agent holds a broad shopping capability and delegates the
> purchase step to an executor sub-agent by issuing the executor a
> strictly-attenuated cap. The threat: the executor (or an attacker
> who has compromised it via prompt injection) tries to use more
> authority than it was delegated — by presenting the narrow cap for
> a broader action, or by hand-mutating the cap bytes to broaden it.
> capnagent's HMAC-chain macaroon construction guarantees both halves
> denying: caveat eval rejects the over-broad call under the narrow
> cap, and chain integrity rejects every forge-broader attempt that
> doesn't possess the root key. The property test in
> `crates/capnagent-core/tests/property_tests.rs` proves the math
> holds for arbitrary inputs; this round demonstrates it end-to-end
> across a realistic planner→executor workflow.

```text
Attack class:     OWASP A01 (Broken Access Control); CWE-269
                  (Improper Privilege Management); CWE-285 (Improper
                  Authorization). Macaroon-style delegation is the
                  reference defense; the no-broaden invariant is the
                  load-bearing property.
Hypothesis:       Three falsifiable claims, all positive (each must
                  hold for the round to CLOSE):

                  CLAIM 1 (in-scope-permits, defense doesn't
                  over-tighten): given an executor cap attenuated
                  from a planner cap with `arg.amount <= 50`, an
                  in-scope call (amount = 30) MUST be ALLOWED.

                  CLAIM 2 (no-broaden, end-to-end): given the same
                  executor cap, a call that would be in-scope under
                  the BROADER planner cap (amount = 150) MUST be
                  DENIED, with the denial reason naming the
                  attenuation caveat (matches /amount/).

                  CLAIM 3 (cryptographic invariant, chain integrity):
                  any attempt to fabricate a broader cap from the
                  executor cap WITHOUT the root key — by dropping
                  the attenuation caveat, mutating its predicate, or
                  splicing in the planner cap's signature — MUST
                  throw `CapabilityChainError` at the first gate
                  before any caveat eval runs.

                  All three are tested in the PoC; all three must
                  hold.
Test (PoC):       packages/capnagent/src/__tests__/subagent-scope-drift.purple.test.ts
Coverage:         Tested variants:
                    - in-scope executor call ($30, ≤50): ALLOWED
                    - executor scope-drift to planner-broad amount
                      ($150): DENIED with reason matching /amount/
                    - sanity: same $150 ctx under PLANNER cap is
                      ALLOWED (proves CLAIM 2's denial is genuinely
                      about the attenuation, not malformed input)
                    - fabricate-broader (a): drop attenuation
                      caveat → CapabilityChainError
                    - fabricate-broader (b): mutate attenuation
                      caveat predicate (50 → 500) → CapabilityChainError
                    - fabricate-broader (c): splice planner sig onto
                      executor structure → CapabilityChainError
                    - nested attenuation: planner → executor (≤50)
                      → sub-executor (≤20). At $15 all three layers
                      ALLOW; at $30 sub-executor DENIES; at $100
                      both attenuated layers DENY; planner ALLOWS
                      throughout
                    - sub-executor broaden-back attempt (drop
                      deepest attenuation) → CapabilityChainError
                    - audit-loggability: caveat denial produces
                      signed receipt that round-trips through
                      Auditor.verify
                    - chain-failure asymmetry: fabrication attempts
                      throw with NO receipt produced (deliberate; see
                      DESIGN.md §11)
                  Not yet tested:
                    - Distributed delegation across processes / hosts.
                      The verifier is a pure function of (cap, ctx,
                      root_key) so the in-process model is sound; a
                      cross-process executor holding only the
                      serialized executor cap produces structurally
                      identical denial paths. Cross-process is a
                      wiring exercise, deferred until a real
                      multi-process example exists.
                    - Revocation propagation from planner to executor.
                      capnagent's revocation is by-identifier, and
                      attenuation does NOT change the identifier — so
                      revoking the planner identifier also revokes
                      every attenuated descendant. There is no API
                      today to revoke selectively by chain depth.
                      Documented as a residual-risk test below; a
                      future round can address selective-descendant
                      revocation if and when an API is introduced.
                    - Holder-of-key attenuation. The hok binding is
                      established at issuance and folded into the
                      chain; attenuating a hok-bound cap should
                      preserve the binding. Untested at this round
                      because it adds an orthogonal axis (hok proof
                      handling on the executor side); covered by
                      Round 02 separately for hok mechanics.
                    - Attenuation across DSL primitives other than
                      `arg.amount`. The attack pattern is identical
                      across predicate types; the round picks one
                      representative numeric predicate. Coverage of
                      `tool ==`, `arg.merchant ==`, and `now <=`
                      attenuations is implicit in CLAIM 3 (any
                      caveat tampering is rejected) but not
                      individually exercised.
Known-bypasses:   - OPERATOR PASSES THE SAME CAP TO EXECUTOR INSTEAD
                    OF ATTENUATING. CAPABILITY-CONFIG class — the
                    executor holds the broad planner cap and there
                    is no attenuation caveat to enforce. capnagent's
                    structural defense is conditional on the operator
                    actually calling `.attenuate()` before handing
                    the cap to a less-trusted holder. Documented as
                    a defender-actionable below.
                  - OPERATOR GIVES THE EXECUTOR THE ROOT KEY. OUT-OF-
                    SCOPE: any defense that depends on a secret key
                    fails when the key is given to the attacker. The
                    structural property "nobody but a root-key holder
                    can broaden a cap" remains true; the assumption
                    that the executor isn't a root-key holder is what
                    broke. Same residual-risk class as round 03's
                    "stolen key" disclaimer.
                  - REVOKING THE PLANNER CAP REVOKES THE EXECUTOR.
                    Attenuation does not generate a new identifier,
                    so all derived caps share the planner's
                    identifier and a single revocation kills the
                    whole chain. This is desirable in some threat
                    models (panic-button revocation of an entire
                    delegation tree) and surprising in others
                    (operator wanted to revoke just the planner and
                    leave executors running). Documented; no API
                    fix queued.
                  - PROMPT-INJECTION-INDUCED EXECUTOR REASONING.
                    capnagent denies the out-of-scope CALL the
                    executor produces; it does NOT prevent the
                    executor's reasoning from going haywire and
                    asking for the out-of-scope call in the first
                    place. The denial is the structural defense;
                    upstream model alignment is the model-vendor's
                    job. Cross-reference: round 11 (indirect
                    injection cascade).
Re-validate-by:   2026-11-03   (6 months from initial CLOSED date)
Owner:            blue-lead
Status:           CLOSED — 2026-05-03

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-05-03 02:09 UTC                              [PASS]
  Env:          Windows 11 + Node 20.x + capnagent @
                purple/round-13-subagent-scope-drift HEAD
                + @capnagent/core (real WASM via wasm-pack pkg)
                + in-process planner+executor (single test file
                  plays both roles)
  Gates:        chain ✓ (CLAIM 1, CLAIM 2 path) | chain ✗ (CLAIM 3
                fabrication variants — caught at chain) |
                proof - | replay - | revoke - | caveat ✓ (CLAIM 1
                in-scope) | caveat ✗ (CLAIM 2 over-broad call —
                caught at caveat eval after chain passed)
                  All three claims verified; the round fires both
                  the chain ✗ and caveat ✗ columns. CLAIM 3's
                  three sub-variants (drop / mutate / splice) all
                  throw CapabilityChainError before any audit
                  signing.
  Decision:     CLAIM 1 — ALLOWED for in-scope executor call (≤50,
                amount=30). CLAIM 2 — DENIED with reason matching
                /amount/ for executor over-broad call (amount=150);
                same context under planner cap ALLOWED, confirming
                the denial is about the attenuation specifically.
                CLAIM 3 — three variants all throw
                CapabilityChainError; no receipt produced (chain
                failures throw before audit signing per DESIGN.md
                §11).
  Latency:      n/a — round 13 doesn't measure pipeline latency.
                Verifier-leg latency is measured in
                `crates/capnagent-core/benches/verify_pipeline.rs`
                (~11 µs bearer-token mean). Attenuation appends one
                HMAC-SHA256 on top of issuance; the chain-walk on
                verify is O(n_caveats), which for a 7-caveat
                sub-executor cap is well under 20 µs.
  FP-7d:        pending baseline. The PoC has 12/12 passing tests
                with zero false denials of in-scope calls. CLOSED
                here means the structural defense holds; useful-in-
                production is gated on a real-deployment FP-7d
                measurement which can only come from a deployment.
  Gap-class:    NONE
  Gap:          None — defense held in 12/12 tests on first run.
                All three claims verified. One operational finding
                surfaced (see Notes): `Capability.attenuate(self)`
                is consuming, so callers that want both the planner
                cap and the executor cap must mint a fresh planner
                cap for the attenuation. Macaroon issuance is
                deterministic so the second instance has identical
                wire bytes to the first — operationally safe, but
                callers must know about the consume semantics.
  Action:       Closed. Round folded into the regression suite;
                executor-pattern documentation in DESIGN.md §11.5
                points operators at this round for the canonical
                planner→executor delegation pattern. Re-validate
                at 2026-11-03 to confirm no library regression and
                to record the FP-7d once a real deployment exists.
```

## Evidence

- **Runnable PoC:** [`packages/capnagent/src/__tests__/subagent-scope-drift.purple.test.ts`](../../packages/capnagent/src/__tests__/subagent-scope-drift.purple.test.ts) — 12 deterministic tests, all passing.
- **Property-test backing:** [`crates/capnagent-core/tests/property_tests.rs`](../../crates/capnagent-core/tests/property_tests.rs) — `attenuation_preserves_validity` (positive), `dropping_a_caveat_breaks_verification`, `modifying_a_caveat_breaks_verification`, `signature_bitflip_breaks_verification` (the no-broaden math).
- **Regen script:** none required — round 13 fires both `chain ✗` and `caveat ✗` gates; the chain failures throw with no receipt to capture (consistent with round 03), and the caveat failures' receipt content is fully reconstructible from the test inputs (deterministic).

## Notes

### Threat model elaboration

The realistic deployment shape this round models:

```
┌──────────────────────────────────────────────┐
│ Operator KMS                                 │
│   issues planner cap (amount <= 200)         │
└─────────────────┬────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────┐
│ Planner agent (system prompt: "shop wisely") │
│   - holds planner cap                        │
│   - decides on $30 amazon purchase           │
│   - calls .attenuate("amount <= 50") to      │
│     mint executor cap                        │
└─────────────────┬────────────────────────────┘
                  │ (executor cap, no root key)
                  ▼
┌──────────────────────────────────────────────┐
│ Executor sub-agent (purchase tool worker)    │
│   - holds ONLY executor cap                  │
│   - submits checkout.purchase(amount=30)     │
│     → ALLOWED at gate                        │
│                                              │
│   Adversary scenarios:                       │
│   (a) executor reasons toward $150 purchase  │
│       → DENIED at caveat (CLAIM 2)           │
│   (b) executor's process is compromised by   │
│       prompt injection in tool output;       │
│       attacker mutates serialized cap to     │
│       broaden → CapabilityChainError         │
│       (CLAIM 3)                              │
│   (c) attacker steals executor cap from log  │
│       file and tries to use it for $150     │
│       → DENIED at caveat (CLAIM 2)           │
└──────────────────────────────────────────────┘
```

The defense is structural at every node. The planner's broad cap is
NEVER seen by the executor; only the attenuated cap crosses the
trust boundary. Even total compromise of the executor doesn't yield
broader authority than what was attenuated to.

### Defender-assumption rationale

Why $200 → $50 specifically:

- The planner cap reflects the operator's policy ceiling for the
  agent session: "this user has authorized up to $200 of shopping
  this hour." That's the trust the operator extends to the planner.
- The executor cap reflects the planner's own intent for THIS tool
  call: "I want this purchase to be at most $50 in case my reasoning
  is off." That's the trust the planner extends to the executor for
  one delegated step.
- The split is realistic. Operators don't want to re-issue caps for
  every delegation step (it would require a round-trip to the KMS
  per call), and planners don't want to give executors the full
  hourly budget (least-privilege at the delegation boundary).

The macaroon contract makes this split free: the planner can
attenuate without root-key access (HMAC(prev_sig, new_caveat) is a
local computation). The verifier walks the full chain at gate time;
the executor's narrower bound binds even though the planner's
broader bound is also in the chain.

### API note: `Capability.attenuate(self)` is consuming

The WASM-bound signature is `attenuate(self, predicate)`, following
Rust ownership semantics. After calling `cap.attenuate(...)`, the
ORIGINAL `Capability` instance has a dangling `_inner` handle and any
subsequent use throws "null pointer passed to rust" from the WASM
boundary.

Implications:

1. **Test discipline.** Tests that need both layers (planner + its
   attenuated executor) must mint a SECOND planner cap to attenuate
   into the executor. Macaroon issuance is deterministic over (root
   key, identifier, caveat list), so the two instances have
   identical wire bytes — they're indistinguishable except for being
   separate WASM handles. The test in this round uses
   `issuePlannerPair()` for this case.
2. **Operator pattern.** Operators delegating to executors should
   issue a fresh cap from the issuer for the planner role, then
   attenuate it for the executor role, in a single function. Holding
   the planner cap as an instance variable AND attenuating from it
   is a foot-gun.
3. **Future API.** A `clone()` method on `Capability` (which would
   round-trip through serialize/parse internally) would eliminate
   the foot-gun; not worth it for v0 because the workaround is
   trivial and the consume semantics actively prevent some classes
   of accidental misuse (operator believes they're holding the
   broader cap but their handle is dead).

This is not a security bug — chain integrity is unaffected, and the
"null pointer passed to rust" is loud enough that it can't lurk
silently. It's an ergonomic foot-gun the round documents.

### Defender-actionable (operator config implied by this round)

For an operator using capnagent with planner→executor delegation:

1. **Always `.attenuate()` before handing a cap to a less-trusted
   holder.** The structural defense is conditional on the executor
   holding a strictly-narrower cap. If the operator hands the
   executor the planner cap directly, capnagent has nothing to
   gate against. See "OPERATOR PASSES THE SAME CAP" in the test's
   residual-risk section.
2. **Issue the planner cap fresh per session, attenuate per
   delegation step.** Don't reuse a long-lived planner cap as the
   parent for many short-lived executor caps without rotating the
   parent — a captured executor cap stays valid for the parent's
   full lifetime.
3. **Keep planner and executor caps in separate handles.**
   `Capability.attenuate(self)` is consuming; mint a fresh cap from
   the issuer each time you need both layers. See API-note above.
4. **Choose attenuation that bounds the SPECIFIC over-step you're
   worried about.** The round attenuates `arg.amount` because the
   threat model is "executor spends too much." If the threat is
   "executor calls the wrong tool," attenuate `tool ==`. If it's
   "executor ships to the wrong address," attenuate `arg.shipping`.
   The macaroon contract supports any caveat predicate.
5. **Treat each attenuation layer as a trust-boundary marker.** A
   3-layer chain (planner→executor→sub-executor) has THREE distinct
   trust contexts. The audit log's `capability_identifier` can't
   distinguish them (all three share the planner's id), so the
   operator must keep their own mapping if per-layer attribution
   matters.
6. **Plan revocation as a chain-wide operation.** Today, revoking
   the planner identifier revokes every descendant. Don't issue
   long-lived caps you might want to revoke selectively-by-layer;
   re-issue when scope changes.

### Source research

- Birgisson et al., "Macaroons: Cookies with Contextual Caveats
  for Decentralized Authorization in the Cloud" (NDSS 2014). The
  no-broaden / append-only-attenuation property is the headline
  result; capnagent's chain construction is a direct descendant.
- OWASP Top 10 2021, A01 (Broken Access Control). Sub-agent /
  delegated-capability scope drift is the AI-agent-specific
  instantiation; the structural defense is the same as in
  traditional access-control systems.
- CWE-269 (Improper Privilege Management) — the canonical weakness
  this round mitigates at the delegation boundary.
- Anthropic's "Claude's constitution" and similar agent-design
  guidance recommend least-privilege delegation but don't typically
  specify the cryptographic enforcement mechanism. capnagent is one
  such mechanism.
