//! Purple-team PoC for `docs/purple-team/04-revocation-race.md`.
//!
//! Round 04 fires the `revoke ✗` gate column. The structural defense:
//! a `RevocationList`, signed under the same root key as the Issuer,
//! is attached to the `Verifier` via `with_revocation_list(...)`. On
//! every `verify_with_context` / `verify_with_proof` call the verifier
//! checks `cap.identifier` against the list and denies with reason
//! `"capability revoked: <identifier>"` if present. The denial is
//! recorded as an audit-loggable `Outcome::Denied`, not an error.
//!
//! # Threat model
//!
//! A holder of a once-legitimate capability continues to use it after
//! the issuer has decided the token is compromised (lost device, stale
//! session, employee offboarding, abuse signal). The cryptographic
//! chain is still intact, the caveats still hold, and any hok-bound
//! proof would still verify — without revocation, the verifier has no
//! reason to refuse. With a `RevocationList` whose published
//! identifier set contains `cap.identifier`, the verifier short-
//! circuits before caveat evaluation and denies.
//!
//! # Why this is a Rust PoC, not TypeScript
//!
//! As of v0.2 the WASM bindings (`crates/capnagent-wasm/src/lib.rs`)
//! do NOT expose `RevocationList`, `Revoker`, or
//! `Verifier::with_revocation_list`. The TS surface
//! (`packages/capnagent/src/index.ts`) only mentions revocation in
//! a doc comment on `verifyWithProof`. So the PoC lives in Rust where
//! the API is reachable. The corpus's choice of language for round 02
//! was incidental; the structural-evidence requirement is language-
//! agnostic.
//!
//! # What this PoC does NOT cover
//!
//!   - Cross-process / distributed revocation propagation (one verifier
//!     gets the new list, a parallel verifier still holds the old one).
//!     capnagent has no automatic mid-flight revocation push;
//!     verifiers consult their installed list per call, so freshness
//!     is operator's responsibility (publish + reload cadence).
//!   - Stale-list rejection by `issued_at_ms` (verifier policy decides
//!     whether a list older than N minutes is acceptable). Out of
//!     scope here — the verifier accepts any signed list regardless of
//!     freshness; staleness is a deployment concern.
//!   - Revocation-list compromise (attacker holds the root key and
//!     publishes `revoked: []`). At that point the attacker can also
//!     mint capabilities directly; revocation defense assumes an
//!     uncompromised root.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::time::UNIX_EPOCH;

use capnagent_core::{
    Auditor, Capability, Context, Issuer, Outcome, Receipt, RevocationError, Revoker, Verifier,
};

const ROOT_KEY: &[u8] = b"round04-revocation-root-key-32b!";
const AUDIT_KEY: &[u8] = b"round04-revocation-audit-key-32!";
const WRONG_ROOT_KEY: &[u8] = b"round04-WRONG-attacker-root-32b!";

/// Locked denial reason. The exact format string emitted by
/// `crates/capnagent-core/src/verifier.rs::check_revocation`:
/// `"capability revoked: {identifier}"`. Audit-log greppability
/// depends on the prefix being stable.
const DENIAL_REASON_PREFIX: &str = "capability revoked: ";

const FROZEN_NOW_MS: u64 = 1_700_000_000_000;

fn frozen_ctx() -> Context {
    Context {
        now: UNIX_EPOCH + std::time::Duration::from_millis(FROZEN_NOW_MS),
        caller: "agent:planner".into(),
        tool: "checkout.purchase".into(),
        args: serde_json::json!({ "merchant": "amazon.com", "amount": 20 }),
        env: HashMap::new(),
    }
}

fn issue(identifier: &str) -> Capability {
    Issuer::from_key(ROOT_KEY).issue(identifier).build()
}

fn revoker_with(ids: &[&str]) -> Revoker {
    let mut r = Revoker::new(ROOT_KEY);
    for id in ids {
        r.revoke(*id);
    }
    r
}

// ───────────────────────── Variant 1 — positive hypothesis ─────────────────────────

#[test]
fn variant_1_revoked_identifier_is_denied_with_locked_reason_string() {
    // Positive hypothesis: a Verifier with an installed signed
    // RevocationList containing `cap.identifier` MUST deny that cap
    // with reason exactly equal to "capability revoked: <id>".
    let cap = issue("buy-stolen-token");
    let auditor = Auditor::new(AUDIT_KEY);

    let list = revoker_with(&["buy-stolen-token"]).publish(FROZEN_NOW_MS);
    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();

    let receipt = verifier
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .expect("revocation must be a denial outcome, not an error");

    match &receipt.outcome {
        Outcome::Denied { reason } => {
            // EXACT string lock — both prefix and the identifier suffix.
            // If revocation.rs ever drifts (e.g. drops the identifier
            // from the reason for privacy), this assertion is the
            // canary. The corpus needs to be updated in lockstep.
            assert_eq!(reason, "capability revoked: buy-stolen-token");
            assert!(reason.starts_with(DENIAL_REASON_PREFIX));
        }
        other => panic!("expected Denied, got {other:?}"),
    }

    // The denial receipt itself must be HMAC-valid — incident response
    // greps the audit log; tampered denials would defeat that.
    auditor
        .verify(&receipt)
        .expect("denial receipt is HMAC-valid");
}

// ───────────────────────── Variant 2 — negative hypothesis ─────────────────────────

#[test]
fn variant_2_non_revoked_identifier_is_allowed_defense_does_not_overtighten() {
    // Negative hypothesis: with the same Verifier + RevocationList, a
    // cap whose identifier is NOT in the list MUST be allowed
    // (assuming chain + caveats also pass). A defense that denies
    // legitimate non-revoked caps is not the win condition.
    let cap = issue("buy-still-good");
    let auditor = Auditor::new(AUDIT_KEY);

    // Revoke a DIFFERENT identifier than the one we're issuing.
    let list = revoker_with(&["buy-stolen-token"]).publish(FROZEN_NOW_MS);
    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();

    let receipt = verifier
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

// ───────────────────────── Variant 3 — invalid signature ─────────────────────────

#[test]
fn variant_3_revocation_list_signed_under_wrong_root_is_not_attached() {
    // A list signed under a key that ISN'T the verifier's root key
    // must be refused at install-time. The verifier ends up with no
    // list installed, not silently with a bogus one.
    let mut wrong_revoker = Revoker::new(WRONG_ROOT_KEY);
    wrong_revoker.revoke("buy-stolen-token");
    let bogus_list = wrong_revoker.publish(FROZEN_NOW_MS);

    let result = Verifier::new(ROOT_KEY).with_revocation_list(bogus_list);
    assert!(matches!(result, Err(RevocationError::InvalidSignature)));
}

#[test]
fn variant_3b_tampered_revocation_list_is_not_attached() {
    // Even a list signed by the right key, then tampered after
    // signing (attacker adds an identifier to the in-memory vec
    // before passing to `with_revocation_list`), must be rejected.
    let mut list = revoker_with(&["buy-stolen-token"]).publish(FROZEN_NOW_MS);
    list.revoked.push("attacker_added_target".into());

    let result = Verifier::new(ROOT_KEY).with_revocation_list(list);
    assert!(matches!(result, Err(RevocationError::InvalidSignature)));
}

// ───────────────────────── Variant 4 — opt-in property ─────────────────────────

#[test]
fn variant_4_verifier_without_a_list_continues_to_allow() {
    // Same cap as variant 1, but no RevocationList installed. The
    // chain is intact and there are no caveats — the verifier
    // allows. Proves the gate is OPT-IN, not default. Operator must
    // remember to install a list; capnagent does not autonomously
    // refuse caps it has never been told are revoked.
    let cap = issue("buy-stolen-token");
    let auditor = Auditor::new(AUDIT_KEY);

    let receipt = Verifier::new(ROOT_KEY)
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

// ───────────────────────── Variant 5 — multi-id list ─────────────────────────

#[test]
fn variant_5_revocation_list_with_multiple_identifiers_recognizes_each() {
    let auditor = Auditor::new(AUDIT_KEY);
    let list = revoker_with(&["buy-A", "buy-B", "buy-C"]).publish(FROZEN_NOW_MS);
    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();

    for id in ["buy-A", "buy-B", "buy-C"] {
        let cap = issue(id);
        let receipt = verifier
            .verify_with_context(&cap, &frozen_ctx(), &auditor)
            .unwrap();
        match &receipt.outcome {
            Outcome::Denied { reason } => {
                assert_eq!(reason, &format!("capability revoked: {id}"));
            }
            other => panic!("expected Denied for {id}, got {other:?}"),
        }
    }

    // And a fourth, non-revoked id is still allowed — guards against
    // a defense that became "deny everything once a list is set".
    let unrelated = issue("buy-D");
    let receipt = verifier
        .verify_with_context(&unrelated, &frozen_ctx(), &auditor)
        .unwrap();
    assert_eq!(receipt.outcome, Outcome::Allowed);
}

// ───────────────────────── Variant 6 — gate is removable ─────────────────────────

#[test]
fn variant_6_without_revocation_list_clears_an_installed_gate() {
    // After `without_revocation_list()`, the cap allows again — the
    // gate is removable mid-process. Operationally this models a
    // verifier reconfigured to drop a stale list before a new one is
    // installed (or, in tests, swapping fixtures cleanly).
    let cap = issue("buy-stolen-token");
    let auditor = Auditor::new(AUDIT_KEY);

    let list = revoker_with(&["buy-stolen-token"]).publish(FROZEN_NOW_MS);
    let v_with_list = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();

    // First pass — list installed, denied.
    let r1 = v_with_list
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();
    assert!(matches!(r1.outcome, Outcome::Denied { .. }));

    // Drop the list — same cap now passes.
    let v_without_list = v_with_list.without_revocation_list();
    let r2 = v_without_list
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();
    assert_eq!(r2.outcome, Outcome::Allowed);
}

// ───────────────────────── Variant 7 — race scenario ─────────────────────────

#[test]
fn variant_7_race_pre_revocation_allow_then_post_revocation_deny() {
    // Race scenario, narrated:
    //
    //   t=0  Issuer mints `buy-race-target`, hands to holder. Holder
    //        verifies once via `verifier_v0` (no list yet) — ALLOWED.
    //   t=1  Incident-response decides the token is compromised.
    //        Issuer publishes a fresh signed list including
    //        `buy-race-target`.
    //   t=2  A NEW verifier (`verifier_v1`) is constructed with that
    //        published list installed. Subsequent verifies of the
    //        same cap — DENIED.
    //
    // capnagent has NO automatic mid-flight revocation push. A long-
    // lived `Verifier` instance does not poll for new lists; the
    // operator decides when to swap. Freshness is operator's
    // responsibility — see round doc § "Defender-actionable" for the
    // publish/reload cadence guidance.
    let cap = issue("buy-race-target");
    let auditor = Auditor::new(AUDIT_KEY);

    // t=0 — no list yet.
    let verifier_v0 = Verifier::new(ROOT_KEY);
    let r0 = verifier_v0
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();
    assert_eq!(
        r0.outcome,
        Outcome::Allowed,
        "pre-revocation use should be allowed"
    );

    // t=1 — issuer publishes revocation. Wall-clock advances; the
    // list's `issued_at_ms` is the publication time, not the
    // verifier's clock.
    let list = revoker_with(&["buy-race-target"]).publish(FROZEN_NOW_MS + 60_000);

    // t=2 — fresh verifier with the new list. Same cap, DENIED.
    let verifier_v1 = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();
    let r2 = verifier_v1
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();
    match &r2.outcome {
        Outcome::Denied { reason } => {
            assert_eq!(reason, "capability revoked: buy-race-target");
        }
        other => panic!("expected Denied at t=2, got {other:?}"),
    }
}

// ───────────────────────── Bonus — revocation precedes caveats ─────────────────────────

#[test]
fn revocation_short_circuits_before_caveat_evaluation() {
    // Even if the cap's caveats would ALSO fail, the verifier must
    // surface the revocation reason — that's the higher-signal denial.
    // Important because a captured-and-revoked cap whose caveat
    // expiry has also passed should not produce a confusing "caveat
    // failed: now <= ..." reason that leaks the cap's expiry policy.
    let cap = Issuer::from_key(ROOT_KEY)
        .issue("buy-double-failed")
        .caveat("totally invalid syntax !!!")
        .build();
    let auditor = Auditor::new(AUDIT_KEY);

    let list = revoker_with(&["buy-double-failed"]).publish(FROZEN_NOW_MS);
    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();

    let receipt = verifier
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();
    match &receipt.outcome {
        Outcome::Denied { reason } => {
            assert!(reason.starts_with(DENIAL_REASON_PREFIX));
            assert!(
                !reason.contains("parse"),
                "revocation must short-circuit before caveat parse: {reason}",
            );
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

// ───────────────────────── Audit-trail integrity on a revocation burst ─────────────────────────

#[test]
fn ten_revoked_attempts_each_produce_a_signed_denial_receipt() {
    // Operational property: every revoked-token attempt is itself
    // audit-logged. An attacker who hammers a known-revoked cap
    // produces a receipt per attempt. Under identical inputs the
    // receipts are byte-identical (HMAC determinism — same finding
    // as round 02), so monitoring should count attempts at the
    // call-site layer, not by unique receipt hash.
    let cap = issue("buy-burst-target");
    let auditor = Auditor::new(AUDIT_KEY);

    let list = revoker_with(&["buy-burst-target"]).publish(FROZEN_NOW_MS);
    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();

    let mut sigs: Vec<Vec<u8>> = Vec::new();
    for _ in 0..10 {
        let r = verifier
            .verify_with_context(&cap, &frozen_ctx(), &auditor)
            .unwrap();
        match &r.outcome {
            Outcome::Denied { reason } => {
                assert_eq!(reason, "capability revoked: buy-burst-target");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        // Each receipt is HMAC-valid in isolation.
        auditor.verify(&r).unwrap();
        sigs.push(r.signature.clone());
    }
    // Identical inputs → identical canonical-JSON → identical HMAC
    // signatures. Operators MUST count by call-site, not by unique
    // receipt-hash dedup.
    let unique = sigs.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), 1, "byte-identical receipts on a replay burst");
}

// ───────────────────────── Evidence regen ─────────────────────────

/// When `RUST_REGEN=1`, this test writes the canonical denial-receipt
/// evidence file. Otherwise it's a no-op so it doesn't slow down the
/// regular `cargo test` run. The evidence file is committed to the
/// repo at `docs/purple-team/evidence/04-revocation-race.receipt.json`.
///
/// The receipt captured here is the same shape produced by Variant 1.
/// We wrap it in a wrapper struct that adds the camelCase aliases the
/// rest of the corpus uses (round 01 / 02 evidence is camelCase from
/// the WASM bindings); rust-side serde gives us snake_case naturally,
/// so we serialize through a JSON Value to remap.
#[test]
fn regen_evidence_when_env_set() {
    if std::env::var("RUST_REGEN").as_deref() != Ok("1") {
        return;
    }

    // Produce a deterministic denial receipt — same shape as
    // Variant 1's. Frozen ctx makes the canonical JSON / HMAC
    // signature reproducible bytewise across regen runs.
    let cap = issue("buy-stolen-token");
    let auditor = Auditor::new(AUDIT_KEY);
    let list = revoker_with(&["buy-stolen-token"]).publish(FROZEN_NOW_MS);
    let verifier = Verifier::new(ROOT_KEY).with_revocation_list(list).unwrap();
    let receipt: Receipt = verifier
        .verify_with_context(&cap, &frozen_ctx(), &auditor)
        .unwrap();

    // Resolve `docs/purple-team/evidence/...` relative to the
    // workspace root. CARGO_MANIFEST_DIR points at this crate's
    // manifest dir, so we pop two levels.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = std::path::Path::new(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root should be two levels above crates/capnagent-core");
    let out = workspace_root
        .join("docs")
        .join("purple-team")
        .join("evidence")
        .join("04-revocation-race.receipt.json");

    // Pretty-printed snake_case JSON — matches Rust serde defaults
    // for the Receipt type.
    let json = serde_json::to_string_pretty(&receipt).expect("Receipt is serializable");
    std::fs::write(&out, json).expect("evidence file is writable");
    eprintln!("regen wrote {}", out.display());
}

// ───────────────────────── Hypothesis-coverage summary ─────────────────────────
//
//   #1  positive: revoked id → Denied("capability revoked: <id>")
//   #2  negative: non-revoked id → Allowed
//   #3  invalid-sig list → with_revocation_list errors (3a wrong key,
//       3b post-sign tamper)
//   #4  no list installed → cap still allowed (gate is opt-in)
//   #5  multi-id list: each id denied with locked reason; unrelated
//       id allowed (no over-tightening)
//   #6  without_revocation_list() removes the gate mid-process
//   #7  race: pre-publication allow, post-publication deny via fresh
//       verifier — capnagent has no automatic push, freshness is
//       operator's responsibility
//   bonus: revocation short-circuits before caveat evaluation
//   bonus: ten-burst replay against revoked id produces ten signed
//          denial receipts (byte-identical signatures under identical
//          inputs — same HMAC-determinism finding as round 02)
//   regen: opt-in via RUST_REGEN=1; writes the canonical evidence file
