# Round 02 — Replay attack on a hok-bound capability

> An attacker captures a hok-bound capability + ed25519 proof
> mid-flight and replays both bytes-for-bytes to perform the same
> authorized action a second time. The chain holds, the proof is
> valid, the caveats still pass — without replay protection, the
> verifier accepts. capnagent's `NonceStore` records `sha256(proof)`
> of every accepted proof and refuses byte-identical re-presentations
> within `nonce_ttl_ms`. Defense holds; this round fires the
> `replay ✗` gate column the corpus had empty.

```text
Attack class:     OWASP A07:2021 (Identification and Authentication
                  Failures); CWE-294 (Authentication Bypass by
                  Capture-Replay).
Hypothesis:       Positive (true-positive): given a hok-bound
                  capability and an installed NonceStore, presenting
                  a previously-accepted (proof, challenge) pair a
                  second time within `nonce_ttl_ms` MUST be denied
                  with reason exactly equal to "proof replay
                  detected". Reason string is locked because audit-
                  log greppability depends on it.

                  Negative (true-negative): given the same cap and
                  store, a FRESH (proof, challenge) pair (different
                  ctx.now_ms → different challenge → different
                  signature → different sha256(proof)) MUST be
                  allowed. A defense that denies legitimate fresh
                  proofs is not the win condition.

                  Both halves are tested in the PoC; both must hold.
Test (PoC):       packages/capnagent/src/__tests__/replay-attack.purple.test.ts
Coverage:         Tested variants:
                    - first presentation of a captured proof: ALLOWED
                    - second presentation (same bytes, within TTL):
                      DENIED with exact reason match
                    - fresh proof (different now_ms, same cap):
                      ALLOWED — defense doesn't over-tighten
                    - gate ordering: replay denial does NOT cascade
                      into caveat evaluation; reason is "proof replay
                      detected", not a leaked caveat-failure message
                    - audit-loggability: 10 replays produce 10
                      signed receipts; under identical inputs the
                      receipts are byte-identical (operational note,
                      see Notes)
                    - TTL=0 boundary: every entry already-expired,
                      replay goes through (operator's choice of TTL
                      is load-bearing)
                    - clear() bypass: store.clear() lets the same
                      proof through; production must NOT auto-clear
                    - opt-in property: WITHOUT a NonceStore installed,
                      the verifier accepts replays — replay protection
                      is opt-in, not default
                  Not yet tested:
                    - Cross-process / distributed replay (two verifier
                      processes with separate in-memory stores both
                      accept the same bytes). Requires Redis-backed
                      `NonceStore`; out of scope until a durable
                      backend ships.
                    - TTL-edge replay (caller waits TTL+1ms, then
                      replays — should succeed because nonce
                      expired). Time-based test, deferred.
                    - Adversarial clock control (verifier reads
                      system time and attacker influences it). Out
                      of scope; assumes monotonic, non-adversarial
                      clock.
                    - High-concurrency race: two parallel verifier
                      threads in the same process see the same proof
                      simultaneously. Mutex-protected by design;
                      Rust-side `replay_protection_tests.rs` has a
                      thread-safety stress, JS-side does not.
                    - Memory exhaustion via attacker-driven nonce
                      flood (millions of unique proofs). InMemory-
                      NonceStore grows unbounded between sweeps;
                      production needs a bounded backing store.
Known-bypasses:   - NO NONCESTORE INSTALLED. The verifier defaults to
                    no replay protection — bearer tokens are designed
                    to be reusable. If the operator forgets
                    `Verifier.withNonceStore(...)` even on a hok-
                    bound cap, replays are accepted. Documented
                    explicitly; defense is opt-in.
                  - PROCESS RESTART. InMemoryNonceStore loses every
                    entry on restart. Captured proofs presented
                    immediately after a restart are accepted.
                    Production deployments need a durable backing
                    store (Redis, Postgres) with operator-defined
                    retention.
                  - TTL EXPIRY. Replays presented after `nonce_ttl_ms`
                    are accepted. The default TTL is 5 minutes; an
                    attacker who captures bytes and waits 6 minutes
                    succeeds. Operator's TTL choice is load-bearing
                    and must reflect the realistic capture-to-replay
                    window for their threat model.
                  - LOG-LEVEL DOWNGRADE. If the operator turns off
                    receipt persistence under load (an "ops shortcut"
                    that gets normalized in some prod environments),
                    the audit trail of denied replays disappears,
                    even though the gate still fires. The defense
                    holds; the EVIDENCE doesn't.
                  - DISTRIBUTED RACE. Two verifier processes serving
                    the same root key with separate in-memory stores
                    each accept the same proof once. Out of scope
                    until a shared `NonceStore` backend ships.
Re-validate-by:   2026-11-04   (6 months from initial CLOSED date)
Owner:            blue-lead
Status:           CLOSED — validated 2026-05-04

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-05-04 23:23 UTC                              [PASS]
  Env:          Windows 11 + Node 20.x + capnagent @ af2310c
                + @capnagent/core (real WASM via wasm-pack pkg)
                + real @noble/ed25519 (async path, no sha512Sync
                config required)
  Gates:        chain ✓ | proof ✓ | replay ✗ | revoke - | caveat -
                  Chain integrity passed (cap is valid, hok bound).
                  Proof verified (ed25519 sig over challenge).
                  Replay leg fired and DENIED — this is the gate
                  that caught the attack. Revocation + caveat legs
                  were not reached (replay short-circuits before
                  them, as designed).
  Decision:     DENIED — reason: "proof replay detected"
                Negative hypothesis also held: a fresh proof for the
                same cap with a different now_ms produces a different
                challenge → different signature → different
                sha256(proof) → no replay match → ALLOWED.
  Latency:      ~170 µs verifier mean (criterion bench
                `verify_with_proof_and_replay`, see
                crates/capnagent-core/benches/verify_pipeline.rs).
                Includes ed25519 verify (~45 µs), replay-store hash
                + lookup, audit signing.
  FP-7d:        pending baseline. The PoC has zero false denials of
                fresh proofs across 8 tests (tested at unit level,
                not 7-day production observation). CLOSED here means
                the structural defense holds; useful-in-production
                is gated on a real-deployment FP-7d measurement
                which can only come from a deployment.
  Gap-class:    NONE
  Gap:          None — defense held in 8/8 PoC tests on first run.
                Both positive (replay denied with exact reason
                match) and negative (fresh proof allowed) halves
                met. Operational finding surfaced and captured in
                the PoC: under identical inputs the receipt is
                byte-identical (HMAC determinism), so ops monitoring
                must count replay attempts at the call-site layer,
                not by unique-receipt-hash dedup.
  Action:       Closed. Round folded into the regression suite (the
                PoC runs in default `npm test --workspaces`). Re-
                validate at 2026-11-04 to confirm no library
                regression and to record the FP-7d once a real
                deployment exists.
```

## Evidence

- **Runnable PoC:** [`packages/capnagent/src/__tests__/replay-attack.purple.test.ts`](../../packages/capnagent/src/__tests__/replay-attack.purple.test.ts) — 8 deterministic tests, all passing.
- **Receipt JSON:** [`evidence/02-replay-attack-on-hok-bound-cap.receipt.json`](evidence/02-replay-attack-on-hok-bound-cap.receipt.json) — captured replay-denial receipt (deterministic; same bytes on every regen run).
- **Regen script:** `npm run -w @capnagent-examples/shopping-agent regen-purple-evidence-02`

## Notes

### Why this test bypasses the wrapper

`wrapMCPClient`'s default flow signs a fresh proof per call via the
`signer` callback, so identical proof bytes never cross the wire in
practice. The threat model assumes the attacker has the bytes
already — captured from a previous legitimate call. We model that
by holding `now_ms` constant across the two presentations, which
makes the derived challenge identical and lets us reuse the same
pre-computed signature. That's the closest in-process analogue to
"captured-and-replayed."

A real attacker capture point would be: a compromised TLS-
terminating proxy, a malicious downstream adapter that logs
requests, debug middleware that persists to disk, or a sidecar
process that observes raw IPC. capnagent's defense is at the
verifier layer and doesn't depend on which capture vector the
attacker used — what matters is whether the verifier sees
sha256(proof) twice.

### Operational finding: HMAC determinism on replay denials

Under identical inputs (same cap + same ctx + same denial outcome),
the canonical-JSON serialized receipt is byte-identical, so the
HMAC signature is byte-identical. That's correct HMAC behavior —
not a bug — but it has operational implications:

- **DO** count replay attempts at the wrapper / call-site layer
  (one event per `callTool` invocation).
- **DO NOT** count attempts at the audit-log dedup layer (unique
  receipt hashes will collapse to 1 across a burst, hiding the
  attack).
- Idempotency / cache layers downstream can safely dedup by receipt
  hash without losing security signal — but **SHOULD** record the
  dedup count alongside the kept hash, otherwise a 1000-replay
  burst becomes "1 receipt seen" in the audit trail.

This finding is encoded in the `audit_trail` test in the PoC.

### Defender-actionable (operator config implied by this round)

For an operator using capnagent with hok-bound capabilities:

1. **Always install a `NonceStore` on the verifier** when issuing
   hok-bound caps. The default verifier does NOT protect against
   replay; it's opt-in. `Verifier.withNonceStore(new NonceStore())`
   is the minimum.
2. **Choose `nonce_ttl_ms` to match your realistic capture-to-replay
   window**, not the default. The default 5 minutes is a generic
   compromise; a system where proofs cross multiple network hops
   should use a longer TTL; a system where proofs are signed and
   immediately verified in-process can use seconds.
3. **Move to a durable `NonceStore` backend** (Redis, Postgres,
   Trillian-style log) before going to production. The
   `InMemoryNonceStore` is for development and tests — it loses
   state on restart. The custom-backend integration point is
   already a Rust trait (`NonceStore`); the JS surface only ships
   the in-memory impl in v0.2.
4. **Monitor denial receipts** with reason `"proof replay detected"`
   — this is the highest-signal anomaly indicator capnagent
   produces under hok-bound caps. The string is locked, so
   greppable. Alert on any positive count.
5. **Count replay attempts at the call-site layer**, not by unique
   receipt hash. Under attack, multiple replays produce identical
   receipts; dedup-by-hash hides the burst. See "Operational
   finding" above.
6. **Plan for the durable-backend migration before turning on hok**
   in production, not after. The transition from in-memory to
   Redis-backed is straightforward at the trait level but requires
   careful retention and HA configuration that's better designed
   up-front.

### Source research

- RFC 9449 (DPoP — Demonstrating Proof-of-Possession at the
  Application Layer) — the holder-of-key replay-protection model
  capnagent's `verify_with_proof` is shaped after.
- CWE-294 (Authentication Bypass by Capture-Replay) — the canonical
  weakness this round mitigates.
- OWASP Top 10 2021, A07 (Identification and Authentication
  Failures) — broader category.
