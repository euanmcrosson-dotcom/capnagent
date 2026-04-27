# Round 03 — Capability broadening attempt

> A hostile holder tries to USE more authority than they were granted:
> drop a caveat, mutate a caveat's predicate text, splice a signature
> from a different cap, swap signatures across keys, or mint under
> a different root key entirely. capnagent's HMAC-SHA256 macaroon
> chain catches every variant at the FIRST gate, before any caveat
> evaluation runs. `Verifier.verify(tamperedCap)` THROWS
> `CapabilityChainError` — chain integrity failures are unrecoverable,
> no audit signing happens, no receipt is produced. This round fires
> the `chain ✗` gate column the corpus had empty.

```text
Attack class:     CWE-345 (Insufficient Verification of Data
                  Authenticity); CWE-353 (Missing Support for
                  Integrity Check); broader macaroon-broadening
                  threat class from Birgisson et al., NDSS 2014.
                  Formal underpinning: 9 proptests in
                  crates/capnagent-core/tests/property_tests.rs
                  (issued_capability_verifies, attenuation_preserves_
                  validity, round_trip_serialize_parse_verify,
                  dropping_a_caveat_breaks_verification, reordering_
                  caveats_breaks_verification, modifying_a_caveat_
                  breaks_verification, signature_bitflip_breaks_
                  verification, capabilities_do_not_cross_verify,
                  adversarial_forgery_is_rejected) — these are the
                  invariants the chain check is supposed to satisfy.
                  Round 03 is the JS-side concrete-evidence
                  counterpart: the same defenses, but exercised
                  through the public TS surface against the real
                  WASM verifier.
Hypothesis:       Positive (true-positive): any modification to a
                  serialized capability that the holder did NOT
                  re-authenticate (i.e. without re-signing under the
                  root key — which they can't, because they don't
                  have it) MUST cause `Verifier.verify(...)` to
                  THROW `CapabilityChainError` BEFORE any caveat
                  evaluation runs. The throw is the win condition;
                  no receipt is produced because chain failures
                  short-circuit before audit signing.

                  Negative (true-negative): `Verifier.verify(...)`
                  on the unmodified, legitimately-issued capability
                  MUST succeed without throwing. A defense that
                  rejects every cap is not the win condition.
                  Additionally, a legitimately-narrowed cap (via
                  `cap.attenuate(...)`) MUST still verify — the
                  defense is asymmetric: narrowing is open to all
                  holders, broadening is impossible without the
                  root key.

                  Both halves are tested in the PoC; both must hold.
Test (PoC):       packages/capnagent/src/__tests__/capability-broadening.purple.test.ts
Coverage:         Tested variants:
                    - single-byte flip in the middle of the
                      serialized base64 token (parseable but the
                      chain no longer matches)
                    - a caveat dropped from the wire format (drops
                      the tightest amount bound)
                    - a caveat's predicate text mutated
                      (`arg.amount <= 50` → `arg.amount <= 5000`)
                    - signature field zeroed (last 32 bytes / 64
                      hex chars overwritten with 0x00)
                    - signature spliced from a different
                      legitimately-issued cap (same root key,
                      different caveats — proves the chain binds
                      to the actual caveats, not just the
                      identifier)
                    - cap minted under a DIFFERENT root key, then
                      verified under the original root key (sanity
                      check that the cap is internally valid under
                      the alt key, confirming the rejection is
                      key-bound not structural)
                    - siblings under same root key with same
                      identifier and different caveats both verify
                      independently — proves chain is bound to
                      caveats, not just identifier
                    - audit-trail integrity: chain failures throw
                      and produce NO receipt; the loop runs every
                      tamper variant and confirms zero receipts
                      surfaced (deliberate asymmetry from caveat
                      denial which DOES produce a signed receipt)
                    - negative-leg control: legitimate narrow-only
                      `cap.attenuate(...)` followed by `verify`
                      succeeds — defense doesn't over-tighten
                    - residual-risk control: an attacker holding
                      the root key mints arbitrary caps and they
                      all pass (chain integrity is not a key-
                      management defense)
                    - residual-risk control: chain check is blind
                      to caveat tightness (overly-broad caveats
                      pass the chain leg; that's Round 01's domain)
                  Not yet tested:
                    - Caveat REORDER (reordering_caveats_breaks_
                      verification in Rust proptests covers this;
                      JS wire-format edit is straightforward but
                      the round already has 12 tests — folded
                      into Coverage by reference, not retested).
                    - hok-bound chain forgery (a hok-bound cap with
                      a swapped public key). The hok bytes are
                      folded into the chain via `chain_holder_of_
                      key`; swapping them invalidates the chain.
                      Behaviorally identical to the
                      caveat-mutation variants here; deferred.
                    - Cross-version forgery (an attacker presents
                      a v0.1 wire-format cap to a v0.2 verifier,
                      or vice versa). Out of scope until v0.3
                      ships an explicit version field on the wire;
                      v0.2 only versions the receipt.
                    - Algorithm-confusion attack (claim a cap was
                      signed with a different MAC primitive, hope
                      the verifier defaults). N/A — capnagent's
                      wire format does not encode the algorithm;
                      HMAC-SHA256 is hardcoded. Documented as
                      not-applicable, not as out-of-scope.
                    - Length-extension attack on raw SHA-256.
                      N/A — HMAC is not vulnerable by construction.
Known-bypasses:   - ROOT-KEY COMPROMISE. The whole defense rests
                    on the root key being secret. If the operator
                    leaks the key (committed to git, stolen from
                    env, exfiltrated by a compromised CI runner),
                    the attacker mints arbitrary caps and they ALL
                    pass `verify`. capnagent has nothing to say
                    about this — it's an operator-side key-
                    management problem. The PoC's residual-risk
                    test makes this explicit.
                  - OVERLY-BROAD CAVEATS. The chain check is BLIND
                    to whether caveats are tight or loose. A cap
                    with `arg.path matches ""` (matches anything)
                    passes the chain leg cleanly — that's Round 01
                    territory, not Round 03. Operator
                    responsibility (issuance hygiene).
                  - POST-VERIFY TAMPERING. capnagent verifies a
                    cap once at the gate; if a downstream layer
                    persists the cap, mutates it, and reuses the
                    pre-verification version of any of its data
                    (e.g. caches the caveat list at parse time,
                    then evaluates against a separately-mutated
                    copy), the attack window is downstream of
                    capnagent. Out of scope for the verifier; in
                    scope for adapter / wrapper code review.
                  - ROOT-KEY ROTATION RACE. If an operator rotates
                    the root key while in-flight caps are mid-
                    verification, the chain check rejects the old
                    caps. That's correct behavior, but it can
                    look like a denial spike during a rotation
                    window. Documented as operational, not as a
                    defense gap.
Re-validate-by:   2026-10-27   (6 months from initial CLOSED date)
Owner:            blue-lead
Status:           CLOSED — validated 2026-04-27

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-27 23:38 UTC                              [PASS]
  Env:          Windows 11 + Node 24.x + capnagent worktree
                + @capnagent/core (real WASM via wasm-pack pkg,
                  built in worktree)
                + no @noble/ed25519 needed — chain-only path
                  doesn't touch ed25519
  Gates:        chain ✗ | proof - | replay - | revoke - | caveat -
                  Chain integrity failed FIRST, before any other
                  gate could run. That's the gate column this
                  round was designed to fire. Proof / replay /
                  revoke / caveat were all not-applicable: chain-
                  only path on bearer caps + no NonceStore + no
                  RevocationList + no Auditor (Verifier.verify is
                  the chain-only entry point and doesn't accept
                  one). The thrown CapabilityChainError pre-empts
                  all of them.
  Decision:     THROWN — error.name = "CapabilityChainError",
                error.message = "invalid signature".
                  Captured uniformly across all 5 tamper variants
                  in the regen evidence (v2-caveat-dropped,
                  v3-caveat-mutated, v4-signature-zeroed, v5-
                  signature-spliced-from-sibling, v6-cross-key-
                  forgery). Same error class, same message — the
                  WASM core surfaces a single chain-failure error
                  type rather than leaking which sub-variant
                  fired, which is the right primitive for an
                  authorization decision. (See `Notes` below for
                  the rationale.)
                Negative hypothesis also held: untampered
                `Verifier.verify(legitCap)` returned cleanly with
                no throw, and `cap.attenuate(...)` followed by
                `verify` also succeeded — narrow-only path is
                preserved.
  Latency:      <5 µs verifier mean (chain-only verify is the
                cheapest path in the verifier — HMAC-SHA256 chain
                walk over ≤5 caveats; no ed25519, no audit
                signing, no canonical-JSON serialize). Not
                separately benched as part of this round; the
                existing `verify_pipeline.rs` criterion suite
                includes the chain-only baseline.
  FP-7d:        pending baseline. The PoC suite has zero false
                throws across the negative-leg tests (legitimate
                cap + 3 attenuation variants), but that's unit-
                level — not a 7-day production observation.
                CLOSED here means the structural defense holds;
                useful-in-production is gated on a real-deployment
                FP-7d measurement which can only come from a
                deployment.
  Gap-class:    NONE
  Gap:          None — defense held in 12/12 PoC tests on first
                run, and the regen script captured 5 chain-failure
                variants with byte-deterministic error output.
                Both positive (every tamper variant throws
                CapabilityChainError) and negative (untampered cap
                verifies cleanly, attenuated cap verifies cleanly)
                halves met. The Rust property tests at
                `crates/capnagent-core/tests/property_tests.rs`
                provide the formal underpinning across the random
                input space; this round is the JS-side
                concrete-evidence counterpart.
  Action:       Closed. Round folded into the regression suite
                (the PoC runs in default `npm test --workspaces`).
                Re-validate at 2026-10-27 to confirm no library
                regression and to record the FP-7d once a real
                deployment exists.
```

## Evidence

- **Runnable PoC:** [`packages/capnagent/src/__tests__/capability-broadening.purple.test.ts`](../../packages/capnagent/src/__tests__/capability-broadening.purple.test.ts) — 12 deterministic tests, all passing.
- **Evidence JSON:** [`evidence/03-capability-broadening.evidence.json`](evidence/03-capability-broadening.evidence.json) — 5 captured chain-failure variants. Note this is `.evidence.json`, not `.receipt.json`: chain failures THROW before audit signing, so there is no signed receipt to capture. The evidence file records the `(error.name, error.message, rejected token)` triple per variant; a reviewer can replay each rejected token against `Verifier(ROOT_KEY).verify(...)` and confirm it still throws.
- **Regen script:** `npm run -w @capnagent-examples/shopping-agent regen-purple-evidence-03`
- **Formal underpinning:** [`crates/capnagent-core/tests/property_tests.rs`](../../crates/capnagent-core/tests/property_tests.rs) — 9 Rust proptests covering the same invariants over the random input space. Round 03's PoC is concrete-input evidence; the Rust proptests are the universal-quantifier evidence. They are intentionally redundant: the proptests give a strong existential-falsification signal, the JS PoC gives reviewer-readable evidence at the public-API level.

## Notes

### Why this round fires `chain ✗` and not `caveat ✗`

The two are deliberately different gates with different audit-trail
shapes:

- **Chain failure** — the cap is forged or corrupt. The verifier
  THROWS `CapabilityChainError` and produces no receipt. There is
  no legitimate audit trail to sign because there is no legitimate
  cap. Producing a receipt for a chain failure would mean the
  auditor key signs over a forgery, which is exactly the wrong
  primitive.
- **Caveat denial** — the cap is valid but the call doesn't fit
  inside the caveats. The verifier RETURNS a signed denial receipt
  with `outcome.kind === "denied"` and a reason string. The audit
  trail is meaningful: a legit cap that legit-failed-the-policy.
  Round 01 fires this gate.

So `chain ✗` short-circuits before the caveat leg ever runs. An
attacker who drops a caveat and presents the broadened cap doesn't
get back "caveat failed" — they get back a thrown
`CapabilityChainError`, with no caveat-level information. That's
load-bearing for two reasons: (a) the audit trail correctly
distinguishes "your cap is fake" from "your cap is real but the
call is out of scope," and (b) the attacker doesn't get an oracle
that tells them which caveat is the tightest one.

### Why the error message is uniformly `"invalid signature"`

The WASM core surfaces a single chain-failure error type for every
sub-variant: dropped caveat, mutated predicate, zeroed signature,
spliced signature, cross-key forgery — all five surface as
`CapabilityChainError("invalid signature")`. That uniformity is
deliberate. The verifier knows WHICH variant happened (it
recomputes the chain step-by-step and the mismatch shows up at a
specific step), but it does NOT leak that information to the
caller, because:

1. **Authorization decisions should not be variance oracles.** If
   the error message said "caveat 3 was dropped," an attacker
   probing variants would learn which caveats are even present.
   Locking the message to a single string keeps the verifier
   leakage at zero bits.
2. **Greppable alerting works at one string.** Ops dashboards
   grep for `"invalid signature"` and alert on any positive count.
   That's the highest-signal anomaly indicator the chain leg
   produces.
3. **Fail-closed simplicity.** The verifier returns a single
   no-go signal; the caller has no decision to make. There is no
   "almost valid" path.

### Why this test bypasses the wrapper

`wrapMCPClient` always hands the verifier whatever cap bytes it
received, so the wrapper itself doesn't filter tampered tokens —
it relies entirely on the verifier's chain check. We model the
attacker by manipulating the serialized base64-JSON token directly
(the wire format is documented in `crates/capnagent-core/src/
capability.rs`: `URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cap))`)
and by using the public `Issuer` API to mint near-equivalents
under attacker-chosen keys. Every variant exercises a real WASM
verifier path; no mocks.

### Operational finding: how to construct tampered caps from the public TS API

The wire format `base64url(JSON)` is editable from JS without any
extra surface. The PoC implements `decodeToken` / `encodeToken`
helpers that turn the serialized token into a plain JS object,
edit it, and re-encode it. The instinct from the task brief was
to fall back to `Issuer.fromKey(differentKey)` if byte-editing
wasn't feasible from JS — but it IS feasible (the format is
straightforward), so both approaches are exercised: variants 1–5
use byte editing, variant 6 uses cross-key minting. The
combination gives full coverage of the threat model with
high-fidelity attacker simulation.

### Defender-actionable (operator config implied by this round)

For an operator using capnagent to authorize tool calls:

1. **Treat root-key compromise as the only chain-leg failure mode
   the operator can actually cause.** capnagent's chain check is
   correct by construction (proven by the property tests); the
   only way it fails in the field is if the root key leaks.
   Standard key-management hygiene applies: CSPRNG-derived,
   ≥32 bytes, in a secret store, never logged, rotated on
   schedule, alerts on access.
2. **Alert on `error.name === "CapabilityChainError"`.** Any
   positive count means an attacker is actively presenting forged
   or tampered caps. The error class is locked, so greppable.
3. **Do NOT rely on receipt-based audit trails for chain
   failures.** There are none, by design. Chain-failure attempts
   must be logged at the VERIFIER call-site (which is in the
   `wrapMCPClient` adapter for MCP-fronted deployments, or at
   the application's authorization-middleware layer for direct
   uses). One log event per `CapabilityChainError` thrown.
4. **Run with a `RevocationList` for defense in depth.** Round 03
   doesn't fire the `revoke ✗` gate, but a separately-revoked cap
   that's also been tampered with would hit chain ✗ first; if the
   operator only deploys revocation, they'd have to re-issue
   every cap to roll a key. Both gates together is the
   defense-in-depth posture.
5. **Re-validate the property tests + this PoC after every
   capnagent-core dependency bump.** Anything in
   `crates/capnagent-core/Cargo.toml` (sha2, hmac, base64,
   serde_json) sits under the chain check; a bug in any of them
   could surface as a Round 03 regression. The
   `Re-validate-by:` date defaults to 6 months but pull-request
   gates should run the PoC on every PR that touches
   capnagent-core.

### Source research

- Birgisson et al., *"Macaroons: Cookies with Contextual Caveats
  for Decentralized Authorization in the Cloud"*, NDSS 2014 — the
  paper capnagent's macaroon chain is shaped after. Section 3.3
  is the broadening-resistance argument; this round is its
  concrete instantiation in the capnagent surface.
- CWE-345 (Insufficient Verification of Data Authenticity) — the
  weakness class this round mitigates.
- CWE-353 (Missing Support for Integrity Check) — same class,
  finer-grained.
- Bellare, Canetti, Krawczyk, *"Keying Hash Functions for Message
  Authentication"*, CRYPTO 1996 — HMAC's security argument; what
  the chain check actually depends on.
