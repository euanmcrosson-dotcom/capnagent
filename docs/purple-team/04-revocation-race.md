# Round 04 — Revocation race / revoked-capability replay

> A holder of a once-legitimate capability continues to use it after
> the issuer has published a signed revocation list adding the cap's
> identifier. The chain is intact, the caveats still hold, any hok
> proof would still verify — without revocation, the verifier has no
> reason to refuse. capnagent's `Verifier::with_revocation_list(...)`
> consults the list at every verify call; capabilities whose
> identifiers are in the list are denied with reason
> `"capability revoked: <identifier>"`. Defense holds; this round
> fires the `revoke ✗` gate column the corpus had empty.

```text
Attack class:     OWASP A01:2021 (Broken Access Control); CWE-672
                  (Operation on a Resource after Expiration or
                  Release). Adjacent: macaroon "third-party caveat"
                  / discharge-token revocation in Birgisson et al.
                  NDSS 2014.
Hypothesis:       Positive (true-positive): given a Verifier with a
                  signed RevocationList installed where the list
                  contains capability identifier `<id>`, any verify
                  call for a cap whose identifier is `<id>` MUST be
                  denied with reason exactly equal to
                  "capability revoked: <id>". The prefix
                  "capability revoked: " is locked because audit-log
                  greppability depends on it; the trailing identifier
                  is included so incident response can pivot from
                  receipt → exact stolen token.

                  Negative (true-negative): with the same Verifier +
                  RevocationList, a cap whose identifier is NOT in
                  the list MUST be allowed (assuming chain + caveats
                  also pass). A defense that denies legitimate non-
                  revoked caps is not the win condition.

                  Both halves are tested in the PoC; both must hold.
Test (PoC):       crates/capnagent-core/tests/round_04_revocation_race.purple.rs
Coverage:         Tested variants:
                    - revoked-id cap → DENIED, exact reason match
                    - non-revoked cap, same Verifier+list → ALLOWED
                      (negative hypothesis — no over-tightening)
                    - list signed under WRONG root key → install
                      returns RevocationError::InvalidSignature; no
                      list attached
                    - list TAMPERED after correct signing (attacker
                      adds an identifier to the in-memory vec) →
                      install returns InvalidSignature
                    - Verifier WITHOUT a list → revoked cap still
                      ALLOWED (gate is opt-in, not default)
                    - multi-id list: each of three revoked ids
                      denied, an unrelated fourth id allowed
                    - without_revocation_list() removes the gate
                      mid-process: same cap that was denied is now
                      allowed (cleanly removable)
                    - race scenario: t=0 verifier_v0 (no list) allows
                      → t=1 issuer publishes revocation → t=2 fresh
                      verifier_v1 with new list installed denies the
                      same cap. capnagent has NO automatic mid-flight
                      revocation push; freshness is operator's
                      responsibility (publish + reload cadence).
                    - revocation precedes caveat evaluation: a cap
                      that's BOTH revoked AND has a malformed caveat
                      yields the "capability revoked: ..." reason,
                      not the caveat-parse reason — confirms gate
                      ordering and prevents leaking a caveat
                      diagnostic when revocation alone would suffice
                    - audit-loggability: 10 attempts against a
                      revoked cap → 10 signed denial receipts; under
                      identical inputs the receipts are byte-
                      identical (operational note, see Notes — same
                      HMAC-determinism finding as round 02)
                  Not yet tested:
                    - Cross-process / distributed revocation
                      propagation. capnagent has no built-in fanout;
                      operators must distribute the published list
                      to every verifier. A verifier that hasn't
                      reloaded since the publish accepts the cap.
                      Out of scope until a "RevocationList feed"
                      protocol is specified.
                    - Stale-list rejection by `issued_at_ms`. The
                      verifier accepts any signed list regardless of
                      freshness; staleness is a deployment policy
                      that lives at the caller, not at the gate.
                    - Hok-bound + revoked cap via `verify_with_proof`.
                      The revocation leg fires identically there
                      (verifier.rs §"Leg 4 — revocation" inside
                      verify_with_proof), but this PoC only exercises
                      the bearer-token path. The hok-path coverage
                      lives in the existing
                      `crates/capnagent-core/tests/revocation_tests.rs`.
                    - Negative-cache poisoning: an attacker replaces
                      a published list on disk with an empty signed
                      list. Out of scope; capnagent has no list-
                      monotonicity check, and signed-empty is a valid
                      operator action ("we revoked nothing today").
                    - Race: revocation publishes WHILE a verify call
                      is mid-flight (true concurrency hazard). The
                      Verifier holds the list by Option<RevocationList>
                      and is not currently swappable atomically; the
                      operator pattern is "construct fresh verifier
                      per epoch". Documented; not exercised.
                    - Wasm/JS surface coverage. As of v0.2 the WASM
                      bindings (`crates/capnagent-wasm/src/lib.rs`)
                      do NOT expose `RevocationList` / `Revoker` /
                      `Verifier::withRevocationList`. The TS package
                      only references revocation in a doc-comment on
                      `verifyWithProof`. Operators using the JS
                      surface CANNOT install a revocation list today.
                      Tracked as a follow-up.
Known-bypasses:   - NO LIST INSTALLED. The default Verifier has no
                    revocation list. Operators must explicitly call
                    `with_revocation_list(...)`. A revoked cap
                    presented to a Verifier without a list is
                    indistinguishable from a legitimate cap — chain
                    holds, caveats hold, accepted. Documented.
                  - STALE LIST. A long-lived Verifier instance that
                    was constructed with last-Tuesday's list will
                    accept any cap revoked after that publish. There
                    is no automatic refresh; freshness is operator's
                    responsibility. Production deployments need a
                    publish/reload protocol with an SLA on the
                    propagation window.
                  - JS / WASM SURFACE. The WASM bindings do not
                    expose revocation. Any operator using the
                    @capnagent/core npm package today CANNOT install
                    a list. Workaround: depend on the Rust crate
                    directly. Properly fixed by exposing
                    `RevocationList` + `withRevocationList` through
                    `capnagent-wasm` (follow-up).
                  - ROOT-KEY COMPROMISE. An attacker who holds the
                    issuer's root key can forge a list with
                    `revoked: []` and pass `verify_signature`.
                    Revocation defense assumes an uncompromised root
                    — same trust assumption as Issuer minting.
                  - DISTRIBUTED RACE. With multiple verifiers, the
                    one that reloaded last accepts the longest. Out
                    of scope until a shared / pushed `RevocationList`
                    feed ships.
                  - LIST TRUNCATION ON DISK. If the operator stores
                    the list as a file and a partial write truncates
                    it, the truncated bytes will fail signature
                    verification and `with_revocation_list` will
                    refuse to install — fail-closed. But the
                    Verifier ends up with NO list, which is the
                    silent-bypass mode. Operators must alarm on
                    "tried to install, refused" events.
Re-validate-by:   2026-10-27   (6 months from initial CLOSED date)
Owner:            blue-lead
Status:           CLOSED — validated 2026-04-27

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-27 UTC                                    [PASS]
  Env:          Windows 11 + cargo (stable) + capnagent-core in
                tree (worktree agent-a0335090b2ad8889c). PoC is a
                Rust integration test against the in-process
                `capnagent_core` crate; no WASM / JS in this round
                because the JS surface does not yet expose
                RevocationList (see Notes).
  Gates:        chain ✓ | proof - | replay - | revoke ✗ | caveat -
                  Chain integrity passed (cap is well-formed, signed
                  by the same root key the verifier holds). Proof
                  leg is N/A (bearer token, no hok). Replay leg is
                  N/A (no NonceStore installed for this round).
                  Revocation leg fired and DENIED — that's the win
                  path. Caveat leg never reached: revocation short-
                  circuits before caveats, by design.
  Decision:     DENIED — reason: "capability revoked: buy-stolen-token"
                Negative hypothesis also held: a cap with a different
                identifier verified against the SAME (Verifier, list)
                pair was Allowed. The defense doesn't degenerate into
                "deny everything once a list is set".
  Latency:      n/a — no criterion bench for the revocation leg in
                v0.2. The check is `BTreeSet::contains` on a sorted
                Vec<String> (binary-search, O(log n)) plus a string
                clone on the deny path. Bench coverage is a follow-
                up.
  FP-7d:        pending baseline. The PoC has zero false denials of
                non-revoked caps across 11 tests, but that is unit-
                level — not a 7-day production observation. CLOSED
                here means the structural defense holds; useful-in-
                production is gated on a real-deployment FP-7d
                measurement which can only come from a deployment.
  Gap-class:    NONE
  Gap:          None — defense held in 11/11 PoC tests on first run.
                Both positive (revoked cap denied with locked reason
                including identifier) and negative (non-revoked cap
                allowed) halves met. One operational finding
                surfaced and recorded in the PoC: under identical
                inputs the denial receipt is byte-identical (same
                HMAC-determinism property as round 02), so ops
                monitoring must count attempts at the call-site
                layer, not by unique receipt-hash dedup. One
                surface-coverage gap surfaced and recorded as a
                follow-up: the WASM/JS bindings do not expose
                RevocationList, so JS-side operators currently have
                no path to install a list.
  Action:       Closed. Round folded into the regression suite
                (`cargo test -p capnagent-core` runs the PoC by
                default). Re-validate at 2026-10-27 to confirm no
                library regression and to record the FP-7d once a
                real deployment exists. Follow-up: expose
                RevocationList via capnagent-wasm so the JS surface
                can install a list — tracked outside this round
                because it's a v0.3 API addition, not a defense
                regression.
```

## Evidence

- **Runnable PoC:** [`crates/capnagent-core/tests/round_04_revocation_race.purple.rs`](../../crates/capnagent-core/tests/round_04_revocation_race.purple.rs) — 11 deterministic tests, all passing.
- **Receipt JSON:** [`evidence/04-revocation-race.receipt.json`](evidence/04-revocation-race.receipt.json) — captured revocation-denial receipt (deterministic; same bytes on every regen run thanks to frozen `now_ms`).
- **Regen command:** `RUST_REGEN=1 cargo test -p capnagent-core --test round_04_revocation_race_purple regen_evidence_when_env_set -- --nocapture` (writes the receipt file using the same fixture as Variant 1).

## Notes

### Why this round is a Rust PoC, not TypeScript

As of v0.2 the WASM bindings at `crates/capnagent-wasm/src/lib.rs`
do not expose `RevocationList`, `Revoker`, or
`Verifier::with_revocation_list`. The TS surface
(`packages/capnagent/src/index.ts`) only mentions revocation in a
doc comment on `verifyWithProof`. Writing the PoC in TypeScript
would require either re-implementing the surface in TS (defeats the
"defense holds at the gate" purpose) or skipping the test entirely.
The corpus's PoC files are language-agnostic; round 02's choice of
TS was incidental, not contractual. The Rust integration-test path
exercises the exact same defense the WASM bindings would forward
to, so the structural-evidence claim is unweakened.

### The exact denial reason string is locked

`crates/capnagent-core/src/verifier.rs::check_revocation` emits:

```text
format!("capability revoked: {}", cap.identifier)
```

The PoC asserts both halves: a `starts_with("capability revoked: ")`
prefix check (greppability) AND an exact `==` against the full
string (full-fidelity). If either drifts — e.g. revocation.rs is
ever refactored to drop the identifier from the reason for privacy,
or to switch from a colon-space to a different separator — the
corpus assertion is the canary. The TS surface, when it exists,
must mint the same string bytewise; that is the wire contract for
audit-log monitoring.

### Threat model elaboration

The threat surface is wider than "stolen token re-used by the
attacker who stole it":

- **Lost device.** A user's laptop is stolen with a long-lived
  capability cached. The user reports it; the issuer publishes a
  revocation. The verifier needs to refuse the cap before the
  natural expiry caveat fires.
- **Employee offboarding.** A departing employee's role-bound caps
  must be revoked at termination, not at next-natural-expiry.
- **Compromised proxy.** A TLS-terminating proxy logged caps in
  cleartext; rotation is in progress; affected identifiers are
  revoked en-masse.
- **Abuse signal.** Anomaly detection flags a cap as exfiltration-
  pattern. Revocation is the immediate action while investigation
  proceeds.

In every case the verifier's job is the same: refuse a cap whose
identifier appears on a list, regardless of how cryptographically
intact the underlying token still is. capnagent's design folds that
into a single per-call check.

### Operational finding: HMAC determinism on revocation denials

Under identical inputs (same cap + same ctx + same revoked outcome),
the canonical-JSON serialized receipt is byte-identical, so the
HMAC signature is byte-identical. That's correct HMAC behavior —
not a bug — but it has the same operational implication as round
02:

- **DO** count revocation-denial attempts at the call-site / wrapper
  layer (one event per `verify_with_context` invocation against a
  revoked cap).
- **DO NOT** count at the audit-log dedup layer — unique receipt
  hashes will collapse to 1 under a burst, hiding the attack.
- Idempotency / cache layers downstream can safely dedup by receipt
  hash without losing security signal — but **SHOULD** record the
  dedup count alongside the kept hash, otherwise a 1000-attempt
  burst becomes "1 receipt seen" in the audit trail.

Encoded in the `ten_revoked_attempts_each_produce_a_signed_denial_receipt`
test in the PoC.

### What this round explicitly does NOT promise

- **Mid-flight revocation push.** capnagent does not run a control
  plane that pushes new lists to long-lived `Verifier` instances. A
  verifier consults the list it was constructed with; a fresh list
  requires a fresh `Verifier::new(root).with_revocation_list(list)`
  call. Operators control the cadence. The "race" variant in the
  PoC documents this explicitly: at t=2 a *new* verifier sees the
  revocation; the t=0 verifier still holds its empty list.
- **List monotonicity.** A signed list with `revoked: []` and a
  later `issued_at_ms` will pass `verify_signature` and unrevoke
  every prior identifier, if the operator installs it. capnagent
  has no "lists must be append-only" enforcement; if an attacker
  with the root key produces a published "revoked: []" snapshot,
  the verifier accepts it. Defense degrades to "trust the root
  key", same as everything else issuer-side.
- **Distributed agreement.** Two verifiers in two processes with
  different installed lists will disagree about the revocation
  status of the same cap. There's no consensus layer in v0.2;
  operators run per-epoch verifiers and accept the propagation
  window.

### Defender-actionable (operator config implied by this round)

For an operator using capnagent in a deployment that needs
revocation:

1. **Always install a `RevocationList` on the verifier** when the
   threat model includes stolen / lost / compromised caps. The
   default Verifier does NOT consult any list; revocation is
   opt-in. `Verifier::new(root).with_revocation_list(list)?` is the
   minimum.
2. **Sign the list with the same root key as the Issuer**, NOT a
   different "revocation key". The trust root is the Issuer's; an
   independent revocation key is extra surface for no extra defense
   (and more keys to lose).
3. **Reload the list on every verifier-construction event**, and
   construct fresh verifiers on a cadence appropriate to your
   propagation SLA. capnagent has no automatic refresh; the cadence
   is operator policy. A common pattern is per-request reload from
   a memoized in-memory copy backed by a `RevocationList` URL
   poller.
4. **Monitor denial receipts with reason prefix
   `"capability revoked: "`.** This is a high-signal anomaly
   indicator — every hit is either an attacker attempting a known-
   stolen cap, OR a legitimate user whose cap was revoked
   prematurely (which is its own ops bug). The prefix is locked, so
   greppable. Alert on any positive count.
5. **Count revocation attempts at the call-site, not by unique
   receipt hash.** Same finding as round 02. Under a replay burst
   the receipts are byte-identical; dedup-by-hash hides the burst.
6. **Alarm on `with_revocation_list` returning
   `InvalidSignature`.** That means either a tampered list was
   served, or the publishing key is out-of-sync. Either way the
   verifier ends up with NO list, which is the silent-bypass mode.
   This MUST be a paged alert in production.
7. **Plan for the WASM-binding follow-up**, if you're using the JS
   surface. v0.2's `@capnagent/core` package does not expose
   `RevocationList`. JS-side operators have no revocation gate
   available today; the workaround is to run verification through
   a Rust-side service. The v0.3 API addition is tracked outside
   this round.
8. **Treat list staleness as part of the threat model.** If your
   propagation SLA is 60 seconds, an attacker with a valid stolen
   cap has a 60-second window. Document the window; don't pretend
   it's zero.

### Source research

- Birgisson et al., *"Macaroons: Cookies with Contextual Caveats
  for Decentralized Authorization in the Cloud"*, NDSS 2014 — the
  capability-with-caveats model capnagent inherits from. Macaroons'
  third-party caveat / discharge-token design is the classic
  alternative to first-party revocation lists.
- OWASP Top 10 2021, A01 (Broken Access Control) — broader category
  in which "revoked credential still accepted" sits.
- CWE-672 (Operation on a Resource after Expiration or Release) —
  the canonical weakness this round mitigates.
