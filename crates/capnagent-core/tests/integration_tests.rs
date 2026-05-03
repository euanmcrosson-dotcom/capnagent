//! End-to-end tests for the integrated entry point
//! [`Verifier::verify_with_context`].
//!
//! These tests exercise the *combination* of chain verification + caveat
//! evaluation + audit signing as a single unit. The individual modules
//! already have their own tests under `property_tests.rs`,
//! `context_tests.rs`, `caveat_dsl_tests.rs`, and `audit_tests.rs`. This
//! file is the contract that wires them together.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use capnagent_core::{Auditor, Context, Issuer, Outcome, Receipt, Verifier, VerifyError};

const ROOT_KEY: &[u8] = b"capnagent-test-root-key-32-bytes!";
const AUDIT_KEY: &[u8] = b"capnagent-test-audit-key-32bytes!";

fn issuer() -> Issuer {
    Issuer::from_key(ROOT_KEY)
}

fn verifier() -> Verifier {
    Verifier::new(ROOT_KEY)
}

fn auditor() -> Auditor {
    Auditor::new(AUDIT_KEY)
}

fn ctx_with(caller: &str, tool: &str, args: serde_json::Value) -> Context {
    Context {
        now: SystemTime::now(),
        caller: caller.into(),
        tool: tool.into(),
        args,
        env: HashMap::new(),
        verifier_facts: serde_json::Value::Null,
    }
}

// ───────────────────────── allow path ─────────────────────────

#[test]
fn allow_path_produces_signed_receipt() {
    let cap = issuer()
        .issue("buy")
        .caveat(r#"arg.merchant == "amazon.com""#)
        .caveat("arg.amount <= 50")
        .build();

    let ctx = ctx_with(
        "agent:planner",
        "http.post",
        serde_json::json!({ "merchant": "amazon.com", "amount": 49 }),
    );

    let receipt = verifier()
        .verify_with_context(&cap, &ctx, &auditor())
        .expect("chain valid; should not error");

    assert_eq!(receipt.outcome, Outcome::Allowed);
    assert_eq!(receipt.capability_identifier, "buy");
    assert_eq!(receipt.context_summary.caller, "agent:planner");
    assert_eq!(receipt.context_summary.tool, "http.post");
    auditor()
        .verify(&receipt)
        .expect("auditor signs and re-verifies its own receipts");
}

#[test]
fn allow_path_with_zero_caveats_still_emits_a_receipt() {
    let cap = issuer().issue("ping").build();
    let ctx = ctx_with("agent:planner", "ping", serde_json::Value::Null);

    let receipt = verifier()
        .verify_with_context(&cap, &ctx, &auditor())
        .expect("zero-caveat allow path");
    assert_eq!(receipt.outcome, Outcome::Allowed);
    assert!(receipt.caveats.is_empty());
}

// ───────────────────────── deny path ─────────────────────────

#[test]
fn caveat_that_evaluates_false_is_denied() {
    let cap = issuer()
        .issue("buy")
        .caveat(r#"arg.merchant == "amazon.com""#)
        .build();

    // Wrong merchant — caveat fails.
    let ctx = ctx_with(
        "agent:planner",
        "http.post",
        serde_json::json!({ "merchant": "evil.example" }),
    );

    let receipt = verifier()
        .verify_with_context(&cap, &ctx, &auditor())
        .expect("chain still valid even when a caveat fails — denial is an outcome");

    match &receipt.outcome {
        Outcome::Denied { reason } => {
            assert!(
                reason.contains("caveat failed"),
                "denial reason should mention caveat: {reason}"
            );
        }
        other => panic!("expected Denied, got {other:?}"),
    }
    auditor()
        .verify(&receipt)
        .expect("denied receipts are still signed and verifiable");
}

#[test]
fn malformed_caveat_is_denied_not_errored() {
    // The DSL grammar requires `ident op value`. This caveat is gibberish
    // and won't parse — fail-closed semantics turn that into a denial,
    // never a silent allow.
    let cap = issuer()
        .issue("buy")
        .caveat("this is not a valid predicate")
        .build();

    let ctx = ctx_with("agent:planner", "http.post", serde_json::Value::Null);

    let receipt = verifier()
        .verify_with_context(&cap, &ctx, &auditor())
        .expect("malformed caveat must not error — must deny");

    match &receipt.outcome {
        Outcome::Denied { reason } => {
            assert!(
                reason.contains("parse error"),
                "denial reason should mention parse: {reason}"
            );
        }
        other => panic!("expected Denied for malformed caveat, got {other:?}"),
    }
}

#[test]
fn first_failing_caveat_short_circuits_with_a_clear_reason() {
    // Three caveats — the second fails. Reason should mention that one.
    let cap = issuer()
        .issue("buy")
        .caveat(r#"caller == "agent:planner""#)
        .caveat("arg.amount <= 10")
        .caveat(r#"arg.merchant == "amazon.com""#)
        .build();

    let ctx = ctx_with(
        "agent:planner",
        "http.post",
        serde_json::json!({ "amount": 999, "merchant": "amazon.com" }),
    );

    let receipt = verifier()
        .verify_with_context(&cap, &ctx, &auditor())
        .expect("denial");

    let reason = match receipt.outcome {
        Outcome::Denied { ref reason } => reason.clone(),
        ref other => panic!("expected Denied, got {other:?}"),
    };
    assert!(
        reason.contains("arg.amount <= 10"),
        "should call out the failing caveat: {reason}"
    );
}

// ───────────────────────── tamper path ─────────────────────────

#[test]
fn forged_signature_is_a_chain_error_not_a_denial() {
    let mut cap = issuer().issue("buy").caveat("arg.amount <= 50").build();
    // Flip a single bit in the signature. This is the canonical "forged
    // token" scenario — the chain integrity check must reject before
    // caveat evaluation gets a chance to run.
    cap.signature[0] ^= 0x01;

    let ctx = ctx_with(
        "agent:planner",
        "http.post",
        serde_json::json!({ "amount": 1 }),
    );

    let result = verifier().verify_with_context(&cap, &ctx, &auditor());
    match result {
        Err(VerifyError::Chain(_)) => {}
        Ok(receipt) => panic!(
            "forged token must not produce a receipt — got Ok({:?})",
            receipt.outcome
        ),
        Err(other) => panic!("expected VerifyError::Chain, got {other:?}"),
    }
}

#[test]
fn dropping_a_caveat_after_issuance_is_a_chain_error() {
    let mut cap = issuer()
        .issue("buy")
        .caveat("arg.amount <= 50")
        .caveat(r#"arg.merchant == "amazon.com""#)
        .build();

    cap.caveats.pop(); // attempt to "broaden" by dropping a caveat
    let ctx = ctx_with(
        "agent:planner",
        "http.post",
        serde_json::json!({ "amount": 1, "merchant": "evil.example" }),
    );

    assert!(matches!(
        verifier().verify_with_context(&cap, &ctx, &auditor()),
        Err(VerifyError::Chain(_))
    ));
}

#[test]
fn wrong_root_key_does_not_cross_verify() {
    let cap = issuer().issue("buy").build();
    let other_verifier = Verifier::new(b"a-completely-different-32b-key!!!");

    assert!(matches!(
        other_verifier.verify_with_context(
            &cap,
            &ctx_with("a", "b", serde_json::Value::Null),
            &auditor()
        ),
        Err(VerifyError::Chain(_))
    ));
}

// ───────────────────────── receipt-as-record ─────────────────────────

#[test]
fn allowed_and_denied_receipts_round_trip_through_json() {
    let cap = issuer().issue("buy").caveat("arg.amount <= 5").build();
    let ctx_allowed = ctx_with(
        "agent:planner",
        "http.post",
        serde_json::json!({ "amount": 3 }),
    );
    let ctx_denied = ctx_with(
        "agent:planner",
        "http.post",
        serde_json::json!({ "amount": 50 }),
    );

    for ctx in [&ctx_allowed, &ctx_denied] {
        let receipt = verifier()
            .verify_with_context(&cap, ctx, &auditor())
            .expect("chain valid");
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
        auditor()
            .verify(&parsed)
            .expect("round-tripped receipt verifies");
    }
}

#[test]
fn time_caveat_observes_verifier_supplied_now() {
    // `now <= @<future>` should hold; `now <= @<past>` should not.
    let cap = issuer()
        .issue("buy")
        .caveat("now <= @2099-01-01T00:00:00Z")
        .build();

    let ctx = Context {
        now: SystemTime::now(),
        caller: "agent:planner".into(),
        tool: "http.post".into(),
        args: serde_json::Value::Null,
        env: HashMap::new(),
        verifier_facts: serde_json::Value::Null,
    };

    let receipt = verifier()
        .verify_with_context(&cap, &ctx, &auditor())
        .expect("chain valid");
    assert_eq!(receipt.outcome, Outcome::Allowed);

    let cap_expired = issuer()
        .issue("buy")
        .caveat("now <= @1970-01-02T00:00:00Z")
        .build();
    let receipt_expired = verifier()
        .verify_with_context(&cap_expired, &ctx, &auditor())
        .expect("chain valid");
    assert!(matches!(receipt_expired.outcome, Outcome::Denied { .. }));
}

#[test]
fn timestamp_field_is_recent() {
    let cap = issuer().issue("buy").build();
    let ctx = ctx_with("a", "b", serde_json::Value::Null);

    let before = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let receipt = verifier()
        .verify_with_context(&cap, &ctx, &auditor())
        .unwrap();
    let after = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + Duration::from_secs(1).as_millis() as u64;

    assert!(
        receipt.timestamp_ms >= before && receipt.timestamp_ms <= after,
        "receipt timestamp {} not in [{before}, {after}]",
        receipt.timestamp_ms,
    );
}
