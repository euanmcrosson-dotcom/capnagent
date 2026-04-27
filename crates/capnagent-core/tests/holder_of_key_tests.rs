//! Tests for DPoP-style holder-of-key (`holder_of_key` field on
//! `Capability` + `Verifier::verify_with_proof`).
//!
//! Threat model addressed: capability theft mid-flight when the
//! attacker has the bearer token but not the holder's private key.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::time::SystemTime;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

use capnagent_core::{
    pop_challenge_for, Auditor, Capability, Context, Issuer, Outcome, Verifier, VerifyError,
};

const ROOT_KEY: &[u8] = b"hok-test-root-key-32-bytes-pls!";
const AUDIT_KEY: &[u8] = b"hok-test-audit-key-32-bytes-go!!";

fn ctx() -> Context {
    Context {
        now: SystemTime::now(),
        caller: "agent:test".into(),
        tool: "tool".into(),
        args: serde_json::json!({"x": 1}),
        env: HashMap::new(),
    }
}

fn fresh_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn issue_with_hok(signing_key: &SigningKey, identifier: &str) -> Capability {
    Issuer::from_key(ROOT_KEY)
        .issue(identifier)
        .holder_of_key(signing_key.verifying_key().as_bytes())
        .build()
}

// ───────────────────────── chain integrity (hok in chain) ─────────────────────────

#[test]
fn hok_bound_capability_verifies_under_correct_key() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key, "buy");
    Verifier::new(ROOT_KEY).verify(&cap).unwrap();
}

#[test]
fn dropping_holder_of_key_breaks_chain() {
    let key = fresh_keypair();
    let mut cap = issue_with_hok(&key, "buy");
    cap.holder_of_key = None;
    assert!(Verifier::new(ROOT_KEY).verify(&cap).is_err());
}

#[test]
fn swapping_holder_of_key_breaks_chain() {
    let key1 = fresh_keypair();
    let key2 = fresh_keypair();
    let mut cap = issue_with_hok(&key1, "buy");
    cap.holder_of_key = Some(key2.verifying_key().as_bytes().to_vec());
    assert!(Verifier::new(ROOT_KEY).verify(&cap).is_err());
}

#[test]
fn old_token_without_hok_still_verifies_unchanged() {
    // Backward-compat: a v0 token (no holder_of_key) must still verify
    // exactly as before with the v0.1 chain logic.
    let cap = Issuer::from_key(ROOT_KEY).issue("buy").build();
    assert!(cap.holder_of_key.is_none());
    Verifier::new(ROOT_KEY).verify(&cap).unwrap();
}

#[test]
fn caveats_attenuate_after_hok_is_set() {
    // Verifies that the chain order is hok-then-caveats: building a cap
    // with hok + caveats must still verify, and dropping a caveat must
    // still break the chain.
    let key = fresh_keypair();
    let cap = Issuer::from_key(ROOT_KEY)
        .issue("buy")
        .holder_of_key(key.verifying_key().as_bytes())
        .caveat("arg.x == 1")
        .caveat("arg.y == 2")
        .build();
    Verifier::new(ROOT_KEY).verify(&cap).unwrap();

    let mut tampered = cap.clone();
    tampered.caveats.pop();
    assert!(Verifier::new(ROOT_KEY).verify(&tampered).is_err());
}

#[test]
fn round_trip_serializes_holder_of_key_field() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key, "buy");
    let token = cap.serialize();
    let parsed = Capability::parse(&token).unwrap();
    assert_eq!(parsed.holder_of_key, cap.holder_of_key);
    Verifier::new(ROOT_KEY).verify(&parsed).unwrap();
}

#[test]
fn old_serialized_token_round_trips_with_hok_none() {
    // A token serialized BEFORE this code shipped won't have a
    // `holder_of_key` field. Forward-deserialization must default it
    // to None and the chain must still validate.
    let cap = Issuer::from_key(ROOT_KEY).issue("buy").build();
    let token = cap.serialize();
    // Sanity: the JSON should NOT contain the holder_of_key field
    // because of `skip_serializing_if = "Option::is_none"`.
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&token)
        .unwrap();
    let json = std::str::from_utf8(&bytes).unwrap();
    assert!(
        !json.contains("holder_of_key"),
        "v0 tokens must serialize without the field: {json}",
    );

    // And a manually-crafted "v0.1 token without hok" must round-trip.
    let parsed = Capability::parse(&token).unwrap();
    assert!(parsed.holder_of_key.is_none());
    Verifier::new(ROOT_KEY).verify(&parsed).unwrap();
}

// ───────────────────────── verify_with_context refuses hok-bound ─────────────────────────

#[test]
fn verify_with_context_denies_hok_bound_capability() {
    // Mixing the no-proof entry point with a hok-bound capability is
    // a configuration mistake. Fail-closed: produce a Denied receipt
    // so the audit log captures the attempt.
    let key = fresh_keypair();
    let cap = issue_with_hok(&key, "buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();

    match &receipt.outcome {
        Outcome::Denied { reason } => {
            assert!(reason.contains("verify_with_proof"));
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

// ───────────────────────── verify_with_proof happy paths ─────────────────────────

#[test]
fn correct_proof_yields_outcome_allowed() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key, "buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let context = ctx();
    let challenge = pop_challenge_for(&cap, &context);
    let proof = key.sign(&challenge).to_bytes();

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &context, &auditor, &challenge, &proof)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

#[test]
fn correct_proof_with_caveats_evaluates_caveats() {
    let key = fresh_keypair();
    let cap = Issuer::from_key(ROOT_KEY)
        .issue("buy")
        .holder_of_key(key.verifying_key().as_bytes())
        .caveat("arg.x == 1")
        .build();
    let auditor = Auditor::new(AUDIT_KEY);

    let context = ctx();
    let challenge = pop_challenge_for(&cap, &context);
    let proof = key.sign(&challenge).to_bytes();

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &context, &auditor, &challenge, &proof)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

#[test]
fn caveat_failure_after_valid_proof_yields_denied() {
    let key = fresh_keypair();
    let cap = Issuer::from_key(ROOT_KEY)
        .issue("buy")
        .holder_of_key(key.verifying_key().as_bytes())
        .caveat("arg.x == 999") // will fail; ctx has x=1
        .build();
    let auditor = Auditor::new(AUDIT_KEY);

    let context = ctx();
    let challenge = pop_challenge_for(&cap, &context);
    let proof = key.sign(&challenge).to_bytes();

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &context, &auditor, &challenge, &proof)
        .unwrap();
    match &receipt.outcome {
        Outcome::Denied { reason } => assert!(reason.contains("caveat failed")),
        other => panic!("expected caveat-failed Denied, got {other:?}"),
    }
}

// ───────────────────────── verify_with_proof failure modes ─────────────────────────

#[test]
fn proof_signed_by_wrong_key_is_denied() {
    let real_key = fresh_keypair();
    let attacker_key = fresh_keypair();
    let cap = issue_with_hok(&real_key, "buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let context = ctx();
    let challenge = pop_challenge_for(&cap, &context);
    // Attacker signs with their own key, claiming to be the holder.
    let bogus_proof = attacker_key.sign(&challenge).to_bytes();

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &context, &auditor, &challenge, &bogus_proof)
        .unwrap();
    match &receipt.outcome {
        Outcome::Denied { reason } => assert!(reason.contains("proof failed")),
        other => panic!("expected proof-failed Denied, got {other:?}"),
    }
}

#[test]
fn proof_over_wrong_challenge_is_denied() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key, "buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let context = ctx();
    let proof = key.sign(b"a totally different challenge").to_bytes();
    let challenge = pop_challenge_for(&cap, &context);

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &context, &auditor, &challenge, &proof)
        .unwrap();
    assert!(matches!(receipt.outcome, Outcome::Denied { .. }));
}

#[test]
fn malformed_proof_bytes_is_denied_not_panic() {
    let key = fresh_keypair();
    let cap = issue_with_hok(&key, "buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let context = ctx();
    let challenge = pop_challenge_for(&cap, &context);

    // Wrong length (not 64 bytes) — verify_with_proof must not panic.
    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &context, &auditor, &challenge, &[0u8; 10])
        .unwrap();
    match &receipt.outcome {
        Outcome::Denied { reason } => assert!(reason.contains("malformed proof")),
        other => panic!("expected malformed-proof Denied, got {other:?}"),
    }
}

#[test]
fn verify_with_proof_on_non_hok_capability_is_denied() {
    // Calling the proof entry point on a cap that wasn't issued with
    // holder_of_key must surface the configuration mistake as a
    // denial, not blindly allow.
    let cap = Issuer::from_key(ROOT_KEY).issue("buy").build();
    let auditor = Auditor::new(AUDIT_KEY);

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &ctx(), &auditor, b"challenge", &[0u8; 64])
        .unwrap();
    match &receipt.outcome {
        Outcome::Denied { reason } => {
            assert!(reason.contains("not hok-bound"));
        }
        other => panic!("expected not-hok-bound Denied, got {other:?}"),
    }
}

#[test]
fn forged_chain_yields_chain_error_not_proof_check() {
    let key = fresh_keypair();
    let mut cap = issue_with_hok(&key, "buy");
    cap.signature[0] ^= 0x01; // tamper

    let auditor = Auditor::new(AUDIT_KEY);
    let context = ctx();
    let challenge = pop_challenge_for(&cap, &context);
    let proof = key.sign(&challenge).to_bytes();

    let result =
        Verifier::new(ROOT_KEY).verify_with_proof(&cap, &context, &auditor, &challenge, &proof);
    assert!(matches!(result, Err(VerifyError::Chain(_))));
}

#[test]
fn auditor_verifies_denied_proof_receipts() {
    // The audit log must capture every attempt against a hok-bound
    // capability — including failed proofs — and the receipt must be
    // tamper-evident.
    let real_key = fresh_keypair();
    let attacker_key = fresh_keypair();
    let cap = issue_with_hok(&real_key, "buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let context = ctx();
    let challenge = pop_challenge_for(&cap, &context);
    let bogus_proof = attacker_key.sign(&challenge).to_bytes();

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_proof(&cap, &context, &auditor, &challenge, &bogus_proof)
        .unwrap();
    auditor
        .verify(&receipt)
        .expect("denied-proof receipts must be HMAC-valid");
}
