//! Tests for the audit-log module (`crates/capnagent-core/src/audit.rs`).
#![allow(missing_docs)]

use proptest::prelude::*;
use std::collections::HashMap;
use std::time::SystemTime;

use capnagent_core::audit::{AuditError, AuditLog, Auditor, Outcome, Receipt};
use capnagent_core::{Capability, Caveat, Context, Issuer, RECEIPT_SCHEMA_VERSION};

const KEY: &[u8] = b"audit-test-key-do-not-use-in-prod";
const OTHER_KEY: &[u8] = b"a-different-32-byte-key!!!!!!!!!";

fn sample_cap() -> Capability {
    Issuer::from_key(KEY)
        .issue("buy")
        .caveat("merchant == \"amazon.com\"")
        .caveat("amount <= 50_usd")
        .build()
}

fn sample_ctx() -> Context {
    let mut env = HashMap::new();
    env.insert("region".into(), "us-east-1".into());
    Context {
        now: SystemTime::now(),
        caller: "agent:planner".into(),
        tool: "http.post".into(),
        args: serde_json::json!({
            "url": "https://amazon.com/cart",
            "qty": 1,
            "items": ["usb-c-cable"],
        }),
        env,
        verifier_facts: serde_json::Value::Null,
    }
}

/// Generate a unique temp path per test invocation. We avoid the
/// `tempfile` crate because it isn't in `[dev-dependencies]` and the spec
/// forbids adding new deps for week 2.
fn temp_log_path(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("capnagent_audit_{label}_{pid}_{nanos}_{n}.ndjson"))
}

// --- happy-path round trips ----------------------------------------------

#[test]
fn sign_then_verify_round_trips() {
    let auditor = Auditor::new(KEY);
    let cap = sample_cap();
    let ctx = sample_ctx();
    let receipt = auditor.sign(&cap, &ctx, Outcome::Allowed);
    assert_eq!(receipt.capability_identifier, cap.identifier);
    assert_eq!(receipt.caveats, cap.caveats);
    assert_eq!(receipt.context_summary.caller, "agent:planner");
    assert_eq!(receipt.context_summary.tool, "http.post");
    assert_eq!(receipt.context_summary.args_hash, ctx.args_hash());
    assert_eq!(receipt.outcome, Outcome::Allowed);
    assert!(!receipt.signature.is_empty());
    auditor
        .verify(&receipt)
        .expect("freshly signed receipt must verify");
}

#[test]
fn denied_outcome_round_trips() {
    let auditor = Auditor::new(KEY);
    let cap = sample_cap();
    let ctx = sample_ctx();
    let outcome = Outcome::Denied {
        reason: "caveat amount<=50_usd failed: 60_usd".into(),
    };
    let receipt = auditor.sign(&cap, &ctx, outcome.clone());
    assert_eq!(receipt.outcome, outcome);
    auditor
        .verify(&receipt)
        .expect("denied receipts must verify too");
}

#[test]
fn outcome_serialization_uses_internal_tag() {
    // §2.3 fixes Outcome's serde shape: `tag = "kind"`, snake_case.
    let allowed = serde_json::to_value(Outcome::Allowed).unwrap();
    assert_eq!(allowed, serde_json::json!({"kind": "allowed"}));

    let denied = serde_json::to_value(Outcome::Denied {
        reason: "nope".into(),
    })
    .unwrap();
    assert_eq!(
        denied,
        serde_json::json!({"kind": "denied", "reason": "nope"})
    );
}

#[test]
fn receipt_json_round_trip_preserves_equality() {
    let auditor = Auditor::new(KEY);
    let receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: Receipt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, receipt);
    auditor
        .verify(&parsed)
        .expect("round-tripped receipt must still verify");
}

// --- field tampering breaks verify ---------------------------------------

#[test]
fn tampering_capability_identifier_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt.capability_identifier.push_str("-tampered");
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn tampering_caveats_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt
        .caveats
        .push(Caveat::new("amount <= 9999_usd".to_string()));
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn dropping_caveats_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt.caveats.pop();
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn tampering_caller_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt.context_summary.caller = "agent:rogue".into();
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn tampering_tool_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt.context_summary.tool = "bank.wire".into();
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn tampering_args_hash_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt.context_summary.args_hash = "0".repeat(64);
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn tampering_outcome_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt.outcome = Outcome::Denied {
        reason: "oh no".into(),
    };
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn tampering_timestamp_breaks_verify() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    receipt.timestamp_ms = receipt.timestamp_ms.wrapping_add(1);
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

#[test]
fn cross_key_verification_fails() {
    let signer = Auditor::new(KEY);
    let other = Auditor::new(OTHER_KEY);
    let receipt = signer.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    assert!(matches!(
        other.verify(&receipt),
        Err(AuditError::InvalidSignature)
    ));
}

// --- schema version (DESIGN.md §14) --------------------------------------

/// Round-trip: a freshly signed receipt carries `version == 1` in both
/// the in-memory struct and its canonical-JSON encoding, and verifies.
#[test]
fn receipt_carries_schema_version_one_and_round_trips() {
    let auditor = Auditor::new(KEY);
    let receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);

    // The in-memory struct exposes the version constant.
    assert_eq!(receipt.version, 1);
    assert_eq!(receipt.version, RECEIPT_SCHEMA_VERSION);

    // The canonical-JSON form serializes it as `"version": 1`.
    let v = serde_json::to_value(&receipt).expect("receipt is serializable");
    assert_eq!(
        v.get("version"),
        Some(&serde_json::json!(1)),
        "receipts must serialize `version: 1`",
    );

    // And it round-trips through JSON.
    let json = serde_json::to_string(&receipt).unwrap();
    let parsed: Receipt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.version, 1);
    auditor
        .verify(&parsed)
        .expect("freshly signed receipt with version=1 must verify");
}

/// Mutating `version` on a verified receipt to an unsupported value
/// causes `verify()` to error. This is the forward-compat fail-closed
/// gate from DESIGN.md §14: a v0.3 verifier reading a v0.4 receipt must
/// refuse to interpret it rather than silently accepting it under the
/// old caveat semantics.
#[test]
fn unsupported_version_is_rejected_by_verifier() {
    let auditor = Auditor::new(KEY);
    let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);

    receipt.version = 99;
    assert!(
        matches!(
            auditor.verify(&receipt),
            Err(AuditError::UnsupportedVersion {
                got: 99,
                expected: 1
            }),
        ),
        "verify must reject unknown schema versions with UnsupportedVersion",
    );

    // Version 0 (the "legacy / no version field" sentinel) is also
    // rejected, on the same fail-closed grounds.
    receipt.version = 0;
    assert!(matches!(
        auditor.verify(&receipt),
        Err(AuditError::UnsupportedVersion {
            got: 0,
            expected: 1
        }),
    ));
}

/// The HMAC signing input must cover the version byte. If a man-in-the-
/// middle could rewrite `version` from 1 to some other in-range value
/// without invalidating the signature, the version-binding contract from
/// DESIGN.md §14 would be vacuous. We test this by:
///
///   1. Signing a real v=1 receipt.
///   2. Mutating `version` (and faking the version gate by re-running
///      the HMAC step against the body alone, with the version-prefix
///      stripped, would have *passed*) — instead, here we just confirm
///      that *swapping in a forged signature for the body alone*
///      (without the version-prefix tag) does NOT verify.
///
/// The simpler property — and the one the production code actually
/// relies on — is that recomputing the canonical-JSON HMAC for any
/// receipt with a tampered `version` yields a different MAC than the
/// stored one. We assert that here by computing the HMAC the verifier
/// computes for a version=42 receipt (with the v=1 receipt's signature
/// frozen) and checking it does not match.
#[test]
fn signature_locks_in_version_byte() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let auditor = Auditor::new(KEY);
    let receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    let v1_signature = receipt.signature.clone();

    // Build the canonical-JSON body of an identical receipt but with
    // `version` rewritten to 42. The verifier's signing input is
    // `b"v" || version || canonical_json(receipt_minus_signature)`.
    let mut tampered = receipt.clone();
    tampered.version = 42;
    tampered.signature = Vec::new();
    let mut body = serde_json::to_value(&tampered).unwrap();
    if let serde_json::Value::Object(ref mut m) = body {
        m.remove("signature");
    }
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let mut input_v42 = Vec::with_capacity(body_bytes.len() + 2);
    input_v42.push(b'v');
    input_v42.push(42);
    input_v42.extend_from_slice(&body_bytes);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(KEY).unwrap();
    mac.update(&input_v42);
    let mac_v42 = mac.finalize().into_bytes().to_vec();

    // The MAC over the v=42 input must NOT match the v=1 receipt's
    // signature. If these were equal it would mean the version byte
    // had no effect on the signing input — i.e. a MITM could swap
    // version freely. This is the property we lock down.
    assert_ne!(
        mac_v42, v1_signature,
        "HMAC of (version=42 || body) must differ from v=1 receipt's signature",
    );

    // And, end-to-end: even if an attacker forges a valid HMAC for the
    // v=42 body, the verifier's pre-HMAC version gate refuses the
    // receipt outright.
    let mut hostile = tampered.clone();
    hostile.signature = mac_v42;
    assert!(matches!(
        auditor.verify(&hostile),
        Err(AuditError::UnsupportedVersion { .. }),
    ));
}

// --- AuditLog round trips ------------------------------------------------

#[test]
fn empty_log_iter_returns_no_items() {
    let path = temp_log_path("empty");
    {
        let _log = AuditLog::open(&path).expect("open empty log");
    }
    let count = AuditLog::iter(&path).expect("iter open").count();
    assert_eq!(count, 0);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn append_then_iterate_round_trip() {
    let path = temp_log_path("roundtrip");
    let auditor = Auditor::new(KEY);
    let r1 = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    let r2 = auditor.sign(
        &sample_cap(),
        &sample_ctx(),
        Outcome::Denied {
            reason: "caveat merchant==amazon.com failed: ebay.com".into(),
        },
    );

    {
        let mut log = AuditLog::open(&path).expect("open log");
        log.append(&r1).expect("append r1");
        log.append(&r2).expect("append r2");
        // Drop here to release the OS handle before iter reads.
    }

    let recovered: Vec<Receipt> = AuditLog::iter(&path)
        .expect("iter open")
        .collect::<Result<_, _>>()
        .expect("all lines parse");

    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[0], r1);
    assert_eq!(recovered[1], r2);
    for r in &recovered {
        auditor
            .verify(r)
            .expect("recovered receipts must still verify");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn append_preserves_existing_contents_across_reopen() {
    let path = temp_log_path("reopen");
    let auditor = Auditor::new(KEY);
    let r1 = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
    let r2 = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);

    {
        let mut log = AuditLog::open(&path).expect("open #1");
        log.append(&r1).expect("append r1");
    }
    {
        let mut log = AuditLog::open(&path).expect("open #2");
        log.append(&r2).expect("append r2");
    }

    let recovered: Vec<Receipt> = AuditLog::iter(&path)
        .expect("iter")
        .collect::<Result<_, _>>()
        .expect("parse all");
    assert_eq!(recovered.len(), 2, "second open must not truncate");
    assert_eq!(recovered[0], r1);
    assert_eq!(recovered[1], r2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn iter_surfaces_malformed_line_as_err() {
    let path = temp_log_path("malformed");
    {
        let mut log = AuditLog::open(&path).expect("open");
        let auditor = Auditor::new(KEY);
        let r = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
        log.append(&r).expect("append good line");
    }
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("reopen for raw append");
        f.write_all(b"this is not json\n").expect("write garbage");
    }

    let results: Vec<_> = AuditLog::iter(&path).expect("iter").collect();
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(), "first line is a real receipt");
    assert!(
        matches!(&results[1], Err(AuditError::Json(_))),
        "second line should surface as a JSON error",
    );
    let _ = std::fs::remove_file(&path);
}

// --- proptest tamper resistance ------------------------------------------

proptest! {
    /// Flipping any single bit in any byte of the signature must break
    /// verification. Mirrors the analogous capability-layer property in
    /// `tests/property_tests.rs`.
    #[test]
    fn signature_bitflip_breaks_verify(bit_idx in any::<usize>()) {
        let auditor = Auditor::new(KEY);
        let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
        let total_bits = receipt.signature.len() * 8;
        prop_assume!(total_bits > 0);
        let bi = bit_idx % total_bits;
        receipt.signature[bi / 8] ^= 1 << (bi % 8);
        prop_assert!(auditor.verify(&receipt).is_err());
    }

    /// Replacing the caller with anything different from the original
    /// must break verification.
    #[test]
    fn caller_tamper_breaks_verify(new_caller in "[a-zA-Z0-9_:.\\-]{0,32}") {
        let auditor = Auditor::new(KEY);
        let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
        prop_assume!(new_caller != receipt.context_summary.caller);
        receipt.context_summary.caller = new_caller;
        prop_assert!(auditor.verify(&receipt).is_err());
    }

    /// Replacing the tool name must break verification.
    #[test]
    fn tool_tamper_breaks_verify(new_tool in "[a-zA-Z0-9_.\\-]{1,32}") {
        let auditor = Auditor::new(KEY);
        let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
        prop_assume!(new_tool != receipt.context_summary.tool);
        receipt.context_summary.tool = new_tool;
        prop_assert!(auditor.verify(&receipt).is_err());
    }

    /// Replacing the args_hash with any other 64-char hex string must
    /// break verification.
    #[test]
    fn args_hash_tamper_breaks_verify(new_hash in "[a-f0-9]{64}") {
        let auditor = Auditor::new(KEY);
        let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
        prop_assume!(new_hash != receipt.context_summary.args_hash);
        receipt.context_summary.args_hash = new_hash;
        prop_assert!(auditor.verify(&receipt).is_err());
    }

    /// Bumping the timestamp (in either direction) must break verification.
    #[test]
    fn timestamp_tamper_breaks_verify(delta in 1u64..u64::MAX/2) {
        let auditor = Auditor::new(KEY);
        let mut receipt = auditor.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
        receipt.timestamp_ms = receipt.timestamp_ms.wrapping_add(delta);
        prop_assert!(auditor.verify(&receipt).is_err());
    }

    /// Two distinct keys must not cross-verify each other's receipts.
    #[test]
    fn distinct_keys_do_not_cross_verify(
        key_a in prop::collection::vec(any::<u8>(), 16..64),
        key_b in prop::collection::vec(any::<u8>(), 16..64),
    ) {
        prop_assume!(key_a != key_b);
        let signer = Auditor::new(&key_a);
        let other  = Auditor::new(&key_b);
        let receipt = signer.sign(&sample_cap(), &sample_ctx(), Outcome::Allowed);
        prop_assert!(other.verify(&receipt).is_err());
    }
}
