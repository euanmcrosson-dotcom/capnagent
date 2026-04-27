//! Tests for the [`NonceStore`] surface and its integration with
//! [`Verifier::verify_with_proof`] for DPoP-style replay protection.
//!
//! Threat model: an attacker who captures a (cap, proof) pair tries to
//! reuse it within the proof's TTL window. With a NonceStore installed,
//! the second use is denied. The first use is unaffected.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

use capnagent_core::{
    pop_challenge_for, Auditor, Capability, Context, InMemoryNonceStore, Issuer, NonceStore,
    Outcome, Verifier,
};

const ROOT_KEY: &[u8] = b"replay-test-root-key-32-bytes!!";
const AUDIT_KEY: &[u8] = b"replay-test-audit-key-32-bytes!";

fn ctx_at(t: SystemTime) -> Context {
    Context {
        now: t,
        caller: "agent:test".into(),
        tool: "tool".into(),
        args: serde_json::json!({"x": 1}),
        env: HashMap::new(),
    }
}

fn fresh_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn issue_with_hok(signing_key: &SigningKey) -> Capability {
    Issuer::from_key(ROOT_KEY)
        .issue("buy")
        .holder_of_key(signing_key.verifying_key().as_bytes())
        .build()
}

/// Build a [`InMemoryNonceStore`] and return parallel `Arc` handles —
/// a concrete one (for `.len()` / `.clear()` inspection) and a
/// `dyn NonceStore` one (for `Verifier::with_nonce_store`).
/// The `let dyn: Arc<dyn NonceStore> = ...` assignment is the
/// load-bearing line that triggers the unsized-coercion.
fn fresh_store() -> (Arc<InMemoryNonceStore>, Arc<dyn NonceStore>) {
    let concrete = Arc::new(InMemoryNonceStore::new());
    let dynamic: Arc<dyn NonceStore> = Arc::clone(&concrete) as _;
    (concrete, dynamic)
}

// ───────────────────────── InMemoryNonceStore unit tests ─────────────────────────

#[test]
fn fresh_nonce_records_successfully() {
    let store = InMemoryNonceStore::new();
    assert!(store.try_record(b"nonce-1", 0, 1_000));
}

#[test]
fn same_nonce_within_ttl_is_rejected() {
    let store = InMemoryNonceStore::new();
    assert!(store.try_record(b"nonce-1", 0, 1_000));
    // 500ms later — still within the 1000ms TTL window.
    assert!(!store.try_record(b"nonce-1", 500, 1_000));
}

#[test]
fn same_nonce_after_ttl_expiry_is_accepted() {
    let store = InMemoryNonceStore::new();
    assert!(store.try_record(b"nonce-1", 0, 1_000));
    // 1500ms later — past the TTL. The entry expired, so the same
    // nonce can be recorded again. (In practice this is rare for
    // hok-bound capabilities since the proof challenge includes
    // now_ms, so the same proof bytes won't recur — but the contract
    // says expired entries are absent, and we test that.)
    assert!(store.try_record(b"nonce-1", 1_500, 1_000));
}

#[test]
fn different_nonces_dont_collide() {
    let store = InMemoryNonceStore::new();
    assert!(store.try_record(b"nonce-1", 0, 1_000));
    assert!(store.try_record(b"nonce-2", 0, 1_000));
    assert!(store.try_record(b"nonce-3", 0, 1_000));
    assert_eq!(store.len(), 3);
}

#[test]
fn replay_does_not_refresh_the_existing_expiry() {
    let store = InMemoryNonceStore::new();
    // Record at t=0 with TTL 1000 → expires at t=1000.
    assert!(store.try_record(b"nonce", 0, 1_000));
    // Replay attempt at t=500. Refused. The existing entry's expiry
    // must NOT be bumped to t=1500 (which would extend the attacker's
    // replay window through honest behavior).
    assert!(!store.try_record(b"nonce", 500, 1_000));
    // At t=1100 — past the ORIGINAL expiry. If the replay refreshed
    // to 1500, this would still be in the window; it isn't, so the
    // record succeeds.
    assert!(store.try_record(b"nonce", 1_100, 1_000));
}

#[test]
fn clear_resets_the_store() {
    let store = InMemoryNonceStore::new();
    store.try_record(b"a", 0, 1_000);
    store.try_record(b"b", 0, 1_000);
    assert_eq!(store.len(), 2);
    store.clear();
    assert!(store.is_empty());
}

#[test]
fn nonce_store_is_thread_safe() {
    use std::thread;
    let store = Arc::new(InMemoryNonceStore::new());
    let mut handles = Vec::new();
    for tid in 0..8 {
        let s = Arc::clone(&store);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let nonce = format!("t{tid}-n{i}");
                assert!(s.try_record(nonce.as_bytes(), 0, 60_000));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(store.len(), 8 * 100);
}

// ───────────────────────── Verifier integration ─────────────────────────

#[test]
fn first_proof_use_is_allowed_with_nonce_store_installed() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key);
    let auditor = Auditor::new(AUDIT_KEY);
    let (store, dyn_store) = fresh_store();

    let verifier = Verifier::new(ROOT_KEY).with_nonce_store(dyn_store);
    let ctx = ctx_at(SystemTime::now());
    let challenge = pop_challenge_for(&cap, &ctx);
    let proof = key.sign(&challenge).to_bytes();

    let receipt = verifier
        .verify_with_proof(&cap, &ctx, &auditor, &challenge, &proof)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
    assert_eq!(store.len(), 1, "first use must record the proof");
}

#[test]
fn replayed_proof_is_denied_with_replay_reason() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key);
    let auditor = Auditor::new(AUDIT_KEY);
    let (_store, dyn_store) = fresh_store();

    let verifier = Verifier::new(ROOT_KEY).with_nonce_store(dyn_store);
    let ctx = ctx_at(SystemTime::now());
    let challenge = pop_challenge_for(&cap, &ctx);
    let proof = key.sign(&challenge).to_bytes();

    // First use: allowed.
    let r1 = verifier
        .verify_with_proof(&cap, &ctx, &auditor, &challenge, &proof)
        .unwrap();
    assert_eq!(r1.outcome, Outcome::Allowed);

    // Second use of the SAME (proof, ctx): denied as a replay.
    let r2 = verifier
        .verify_with_proof(&cap, &ctx, &auditor, &challenge, &proof)
        .unwrap();
    match &r2.outcome {
        Outcome::Denied { reason } => assert!(
            reason.contains("replay"),
            "denial reason should call out replay: {reason}",
        ),
        other => panic!("expected Denied, got {other:?}"),
    }

    // The denial receipt is still HMAC-valid — replays must show up
    // in the audit log, exactly the signal incident response needs.
    auditor.verify(&r2).unwrap();
}

#[test]
fn no_nonce_store_means_no_replay_check() {
    // Without an installed NonceStore, the verifier accepts the same
    // proof bytes repeatedly. Backward-compat with the v0.1 DPoP
    // baseline that shipped before this commit.
    let key = fresh_keypair();
    let cap = issue_with_hok(&key);
    let auditor = Auditor::new(AUDIT_KEY);

    let verifier = Verifier::new(ROOT_KEY);
    let ctx = ctx_at(SystemTime::now());
    let challenge = pop_challenge_for(&cap, &ctx);
    let proof = key.sign(&challenge).to_bytes();

    let r1 = verifier
        .verify_with_proof(&cap, &ctx, &auditor, &challenge, &proof)
        .unwrap();
    let r2 = verifier
        .verify_with_proof(&cap, &ctx, &auditor, &challenge, &proof)
        .unwrap();
    assert_eq!(r1.outcome, Outcome::Allowed);
    assert_eq!(r2.outcome, Outcome::Allowed);
}

#[test]
fn different_proofs_dont_collide_in_the_store() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key);
    let auditor = Auditor::new(AUDIT_KEY);
    let (store, dyn_store) = fresh_store();

    let verifier = Verifier::new(ROOT_KEY).with_nonce_store(dyn_store);

    // Two distinct contexts (different ctx.now) → different challenges
    // → different proofs. Both should pass.
    let now_a = SystemTime::now();
    let now_b = now_a + Duration::from_millis(1);
    for ctx_now in [now_a, now_b] {
        let ctx = ctx_at(ctx_now);
        let challenge = pop_challenge_for(&cap, &ctx);
        let proof = key.sign(&challenge).to_bytes();
        let receipt = verifier
            .verify_with_proof(&cap, &ctx, &auditor, &challenge, &proof)
            .unwrap();
        assert_eq!(receipt.outcome, Outcome::Allowed);
    }
    assert_eq!(store.len(), 2);
}

#[test]
fn replay_outside_ttl_window_is_allowed() {
    // The TTL boundary: a proof that hasn't been seen in over
    // `nonce_ttl_ms` is treated as fresh. Manually advance ctx.now
    // by more than the TTL to simulate.
    let key = fresh_keypair();
    let cap = issue_with_hok(&key);
    let auditor = Auditor::new(AUDIT_KEY);
    let (_store, dyn_store) = fresh_store();

    let ttl_ms = 1_000_u64;
    let verifier = Verifier::new(ROOT_KEY)
        .with_nonce_store(dyn_store)
        .with_nonce_ttl_ms(ttl_ms);

    let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);
    let ctx_a = ctx_at(t0);
    let challenge = pop_challenge_for(&cap, &ctx_a);
    let proof = key.sign(&challenge).to_bytes();

    // First use at t0.
    let r1 = verifier
        .verify_with_proof(&cap, &ctx_a, &auditor, &challenge, &proof)
        .unwrap();
    assert_eq!(r1.outcome, Outcome::Allowed);

    // Second use at t0 + 2 seconds — past the 1000ms TTL. Replay
    // window is closed; the same proof bytes are accepted again.
    // (Realistic? In practice the proof challenge derivation includes
    // now_ms, so the *same* proof can't recur from a non-malicious
    // holder. But the store contract says expired entries are
    // absent, and that's what we test.)
    let ctx_b = ctx_at(t0 + Duration::from_secs(2));
    let r2 = verifier
        .verify_with_proof(&cap, &ctx_b, &auditor, &challenge, &proof)
        .unwrap();
    assert_eq!(r2.outcome, Outcome::Allowed);
}

#[test]
fn replay_does_not_record_via_outer_paths() {
    // Important: only the proof-PASSED path records the nonce.
    //   - Bad proof          -> denied, NOT recorded (so the holder
    //                            can re-attempt with a corrected proof).
    //   - Caveat-failed      -> recorded? YES — the proof was valid,
    //                            the caveats just denied. Replay
    //                            protection still applies.
    //   - Forged chain       -> never reaches the proof check, NOT
    //                            recorded.
    //   - Revoked            -> proof valid, recorded; revocation
    //                            denial follows. This is intentional.
    let key = fresh_keypair();
    let cap = issue_with_hok(&key);
    let auditor = Auditor::new(AUDIT_KEY);
    let (store, dyn_store) = fresh_store();

    let verifier = Verifier::new(ROOT_KEY).with_nonce_store(dyn_store);
    let ctx = ctx_at(SystemTime::now());
    let challenge = pop_challenge_for(&cap, &ctx);

    // Bad proof: random bytes. Proof check fails. Store stays empty.
    let bogus_proof = [0xAA_u8; 64];
    let r = verifier
        .verify_with_proof(&cap, &ctx, &auditor, &challenge, &bogus_proof)
        .unwrap();
    assert!(matches!(r.outcome, Outcome::Denied { .. }));
    assert_eq!(
        store.len(),
        0,
        "bad proofs must not be recorded (would lock out a legit retry)",
    );

    // Now a valid proof — recorded.
    let good_proof = key.sign(&challenge).to_bytes();
    let r = verifier
        .verify_with_proof(&cap, &ctx, &auditor, &challenge, &good_proof)
        .unwrap();
    assert_eq!(r.outcome, Outcome::Allowed);
    assert_eq!(store.len(), 1);
}

// ───────────────────────── verify_with_context unaffected ─────────────────────────

#[test]
fn verify_with_context_does_not_consult_the_nonce_store() {
    // Non-hok bearer tokens are explicitly designed to be reusable.
    // Replay protection there would break the model. Even if a
    // NonceStore is installed, the verify_with_context path must NOT
    // record or check anything in it.
    let cap = Issuer::from_key(ROOT_KEY).issue("buy").build();
    let auditor = Auditor::new(AUDIT_KEY);
    let (store, dyn_store) = fresh_store();

    let verifier = Verifier::new(ROOT_KEY).with_nonce_store(dyn_store);
    let ctx = ctx_at(SystemTime::now());

    for _ in 0..3 {
        let receipt = verifier.verify_with_context(&cap, &ctx, &auditor).unwrap();
        assert_eq!(receipt.outcome, Outcome::Allowed);
    }
    assert_eq!(
        store.len(),
        0,
        "verify_with_context must not touch the nonce store",
    );
}
