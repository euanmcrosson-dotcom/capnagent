//! Tests for the revocation list — its signing, its tamper-resistance,
//! and its integration with `Verifier::verify_with_context`.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::time::SystemTime;

use capnagent_core::{
    Auditor, Context, Issuer, Outcome, RevocationError, RevocationList, Revoker, Verifier,
};

const ROOT_KEY: &[u8] = b"revocation-test-root-key-32-bytes";
const AUDIT_KEY: &[u8] = b"revocation-test-audit-key-32-byte";

fn ctx() -> Context {
    Context {
        now: SystemTime::now(),
        caller: "agent:test".into(),
        tool: "tool".into(),
        args: serde_json::Value::Null,
        env: HashMap::new(),
    }
}

// ───────────────────────── RevocationList signature ─────────────────────────

#[test]
fn revoker_publishes_a_self_consistent_list() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    revoker.revoke("transfer");
    let list = revoker.publish(1_000);
    list.verify_signature(ROOT_KEY).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list.issued_at_ms, 1_000);
}

#[test]
fn empty_revoker_publishes_an_empty_signed_list() {
    let revoker = Revoker::new(ROOT_KEY);
    let list = revoker.publish(0);
    list.verify_signature(ROOT_KEY).unwrap();
    assert!(list.is_empty());
}

#[test]
fn publish_dedups_repeated_revoke_calls() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    revoker.revoke("buy");
    revoker.revoke("buy");
    let list = revoker.publish(0);
    assert_eq!(list.len(), 1);
}

#[test]
fn unrevoke_removes_from_published_list() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    revoker.revoke("transfer");
    assert!(revoker.unrevoke("buy"));
    assert!(!revoker.unrevoke("buy")); // already gone
    let list = revoker.publish(0);
    assert!(!list.contains("buy"));
    assert!(list.contains("transfer"));
}

#[test]
fn signature_validates_under_correct_key_only() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let list = revoker.publish(1_000);
    list.verify_signature(ROOT_KEY).unwrap();
    assert!(matches!(
        list.verify_signature(b"a-different-32-byte-key!!!!!!!!!"),
        Err(RevocationError::InvalidSignature)
    ));
}

#[test]
fn tampering_with_revoked_list_breaks_signature() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let mut list = revoker.publish(1_000);
    list.revoked.push("attacker_added".into());
    assert!(matches!(
        list.verify_signature(ROOT_KEY),
        Err(RevocationError::InvalidSignature)
    ));
}

#[test]
fn tampering_with_issued_at_breaks_signature() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let mut list = revoker.publish(1_000);
    list.issued_at_ms = 999_999;
    assert!(matches!(
        list.verify_signature(ROOT_KEY),
        Err(RevocationError::InvalidSignature)
    ));
}

#[test]
fn signature_bitflip_breaks_verification() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let mut list = revoker.publish(1_000);
    list.signature[0] ^= 0x01;
    assert!(matches!(
        list.verify_signature(ROOT_KEY),
        Err(RevocationError::InvalidSignature)
    ));
}

#[test]
fn list_is_replayable_via_serde_round_trip() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    revoker.revoke("transfer");
    let original = revoker.publish(42);
    let json = serde_json::to_string(&original).unwrap();
    let parsed: RevocationList = serde_json::from_str(&json).unwrap();
    assert_eq!(original, parsed);
    parsed.verify_signature(ROOT_KEY).unwrap();
}

// ───────────────────────── Verifier integration ─────────────────────────

fn issue(identifier: &str) -> capnagent_core::Capability {
    Issuer::from_key(ROOT_KEY).issue(identifier).build()
}

#[test]
fn verifier_without_revocation_list_allows_anything_chain_valid() {
    let cap = issue("buy");
    let auditor = Auditor::new(AUDIT_KEY);
    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

#[test]
fn verifier_with_empty_revocation_list_allows() {
    let cap = issue("buy");
    let auditor = Auditor::new(AUDIT_KEY);
    let list = Revoker::new(ROOT_KEY).publish(0);
    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();
    let receipt = verifier
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

#[test]
fn revoked_capability_yields_outcome_denied_not_error() {
    let cap = issue("buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let list = revoker.publish(1_000);

    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();
    let receipt = verifier
        .verify_with_context(&cap, &ctx(), &auditor)
        .expect("revocation must be a denial outcome, not an error");

    match &receipt.outcome {
        Outcome::Denied { reason } => {
            assert!(
                reason.contains("revoked"),
                "denial reason should call out revocation: {reason}",
            );
            assert!(reason.contains("buy"));
        }
        other => panic!("expected Denied, got {other:?}"),
    }

    // The denied receipt must still be HMAC-valid — the audit log should
    // be tamper-evident for revoked-token attempts as much as for any
    // other outcome.
    auditor.verify(&receipt).unwrap();
}

#[test]
fn non_revoked_capability_evaluates_caveats_normally() {
    let cap = issue("buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("transfer"); // a different identifier
    let list = revoker.publish(1_000);

    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();
    let receipt = verifier
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

#[test]
fn verifier_refuses_to_install_a_tampered_revocation_list() {
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let mut list = revoker.publish(1_000);
    list.revoked.push("attacker_inserted".into());

    let result = Verifier::new(ROOT_KEY).with_revocation_list(list);
    assert!(matches!(result, Err(RevocationError::InvalidSignature)));
}

#[test]
fn verifier_refuses_a_list_signed_by_a_different_key() {
    let mut revoker = Revoker::new(b"a-completely-different-32b-key!!!");
    revoker.revoke("buy");
    let list = revoker.publish(1_000);

    let result = Verifier::new(ROOT_KEY).with_revocation_list(list);
    assert!(matches!(result, Err(RevocationError::InvalidSignature)));
}

#[test]
fn revocation_short_circuits_caveat_evaluation() {
    // Even if caveats would *also* fail, the denial reason should
    // call out revocation — that is the more important signal.
    let cap = Issuer::from_key(ROOT_KEY)
        .issue("buy")
        .caveat("totally invalid syntax")
        .build();
    let auditor = Auditor::new(AUDIT_KEY);

    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let list = revoker.publish(1_000);

    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();
    let receipt = verifier
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();
    match &receipt.outcome {
        Outcome::Denied { reason } => {
            assert!(reason.contains("revoked"));
            assert!(!reason.contains("parse"));
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn revocation_list_can_be_swapped_at_runtime() {
    let cap = issue("buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");

    // First snapshot — buy is revoked, expect denial.
    let list_v1 = revoker.publish(1_000);
    let verifier_v1 = Verifier::new(ROOT_KEY)
        .with_revocation_list(list_v1)
        .unwrap();
    let receipt_v1 = verifier_v1
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();
    assert!(matches!(receipt_v1.outcome, Outcome::Denied { .. }));

    // Second snapshot — operator unrevoked, expect allow on a fresh
    // verifier with the new list.
    revoker.unrevoke("buy");
    let list_v2 = revoker.publish(2_000);
    let verifier_v2 = Verifier::new(ROOT_KEY)
        .with_revocation_list(list_v2)
        .unwrap();
    let receipt_v2 = verifier_v2
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt_v2.outcome, Outcome::Allowed);
}

#[test]
fn without_revocation_list_clears_an_installed_one() {
    let cap = issue("buy");
    let auditor = Auditor::new(AUDIT_KEY);

    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let list = revoker.publish(1_000);

    let verifier = Verifier::new(ROOT_KEY)
        .with_revocation_list(list)
        .unwrap()
        .without_revocation_list();
    let receipt = verifier
        .verify_with_context(&cap, &ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

#[test]
fn revocation_list_getter_reflects_install_state() {
    // The `revocation_list()` accessor lets deployment-readiness code inspect
    // the installed list (e.g. to surface a stale `issued_at_ms` to operators).
    // It must return `None` before install and the live list after.
    let mut revoker = Revoker::new(ROOT_KEY);
    revoker.revoke("buy");
    let list = revoker.publish(4_242);

    let verifier = Verifier::new(ROOT_KEY);
    assert!(verifier.revocation_list().is_none());
    assert!(!verifier.has_revocation_list());

    let verifier = verifier.with_revocation_list(list).unwrap();
    assert!(verifier.has_revocation_list());
    let installed = verifier
        .revocation_list()
        .expect("getter must return the installed list");
    assert_eq!(installed.issued_at_ms, 4_242);
    assert!(installed.contains("buy"));
}
