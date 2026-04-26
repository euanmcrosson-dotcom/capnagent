//! Tests for the audit-log module (`crates/capnagent-core/src/audit.rs`).
//!
//! The audit module imports `crate::capability::{Capability, Caveat}` and
//! `crate::context::Context`. The capability types already exist on master;
//! `Context` is being built in parallel on `feat/week2-context` and is not
//! yet on this branch. To keep `feat/week2-audit` green in isolation, this
//! test file:
//!
//! 1. Includes `audit.rs` directly via `#[path = "../src/audit.rs"]`.
//! 2. Provides a `mod capability` shim that re-exports the real
//!    `Capability` and `Caveat` from `capnagent_core`.
//! 3. Provides a `mod context` stub whose public shape exactly matches
//!    the contract locked in WEEK2_SPEC §2.1.
//!
//! At merge time, `audit.rs` will be wired into `lib.rs` and these stubs
//! will be unnecessary — `audit.rs` will pick up the real `Context` from
//! the merged `feat/week2-context` branch. The contract is what is being
//! tested, not the stub.
#![allow(missing_docs)]

use proptest::prelude::*;
use std::collections::HashMap;
use std::time::SystemTime;

/// Re-export shim: makes `crate::capability::{Capability, Caveat}` resolve
/// inside the `audit.rs` submodule.
mod capability {
    pub use capnagent_core::{Capability, Caveat};
}

/// Local stub for `Context`. Mirrors WEEK2_SPEC §2.1 exactly; the real
/// type lives on Terminal B's branch and replaces this one at merge time.
mod context {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::time::SystemTime;

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct Context {
        // `now` and `env` are part of the WEEK2_SPEC §2.1 contract even
        // though `audit::Auditor::sign` only reads `caller`, `tool`, and
        // `args` from `Context`. Keeping them here so the stub matches
        // the real type's shape exactly.
        pub now: SystemTime,
        pub caller: String,
        pub tool: String,
        pub args: serde_json::Value,
        pub env: HashMap<String, String>,
    }

    impl Context {
        /// SHA-256 hex of the canonical-JSON encoding of `args`. The route
        /// through `serde_json::Value` (which uses a sorted `BTreeMap` for
        /// objects by default) is what makes this deterministic.
        pub fn args_hash(&self) -> String {
            let canonical =
                serde_json::to_string(&self.args).expect("Value is always serializable");
            let mut h = Sha256::new();
            h.update(canonical.as_bytes());
            let bytes = h.finalize();
            let mut out = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                out.push_str(&format!("{b:02x}"));
            }
            out
        }
    }
}

#[path = "../src/audit.rs"]
mod audit;

use audit::{AuditError, AuditLog, Auditor, Outcome, Receipt};
use capability::{Capability, Caveat};
use capnagent_core::Issuer;
use context::Context;

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
