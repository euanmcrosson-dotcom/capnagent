//! Audit log for capability-verification decisions.
//!
//! Every accept-or-reject of a capability produces a signed [`Receipt`]
//! that is appended to a newline-delimited JSON log on disk. Receipts are
//! signed with HMAC-SHA256 (Ed25519 is deferred to v0.1) and verified in
//! constant time. The canonical-JSON encoding used for the signature is
//! the same one used by [`Context::args_hash`]: keys sorted lexicographically
//! at every object level, no whitespace, UTF-8.
//!
//! Determinism of canonical-JSON is load-bearing — two implementations
//! that disagree about field order would produce receipts that fail to
//! verify across the boundary.
//!
//! # Threat model
//!
//! The audit log defends against a *post-facto* attacker editing receipts
//! to hide a denied call or to forge an "allowed" record. It does not
//! defend against an attacker who already holds the auditing key — at that
//! point the attacker can mint receipts directly. Confidentiality of the
//! log against the verifier itself is explicitly out of scope (see
//! `docs/DESIGN.md` §2).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::UNIX_EPOCH;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::capability::{Capability, Caveat};
use crate::context::Context;

type HmacSha256 = Hmac<Sha256>;

/// Current receipt schema version. Bumped only on a wire-format break.
///
/// See `docs/DESIGN.md` §14 ("Receipt schema versioning") for the
/// fail-closed forward-compat semantics. A verifier built against
/// version `N` rejects any receipt whose `version != N`.
pub const RECEIPT_SCHEMA_VERSION: u8 = 1;

/// Minimum byte length accepted for an `Auditor` HMAC key.
///
/// Lower bound from purple-team angle B.3: a deployment that derived its
/// audit key from an unset env var would silently produce forgeable
/// receipts (HMAC accepts any key length per RFC 2104, including zero).
/// 16 bytes is the floor below which the security argument breaks; 32+
/// from a CSPRNG is still the production recommendation. Enforced at
/// construction so the failure surfaces at startup, not at verify time.
pub const MIN_AUDIT_KEY_LEN: usize = 16;

/// A signed record of a single verification decision.
///
/// Receipts are append-only. Once written to an [`AuditLog`] they should
/// not be edited; the signature is the integrity check that detects
/// after-the-fact tampering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    /// Receipt schema version. Currently always [`RECEIPT_SCHEMA_VERSION`]
    /// (== 1). The verifier rejects unknown values fail-closed; bumping
    /// this is a wire-format break, not a hot upgrade. See DESIGN.md §14.
    pub version: u8,
    /// The [`Capability::identifier`] of the token that was being verified.
    pub capability_identifier: String,
    /// The full caveat list as it stood at verification time. Order matters.
    pub caveats: Vec<Caveat>,
    /// Verifier-controlled summary of the call context. Args themselves
    /// are not stored — only their hash — to keep receipts compact and to
    /// avoid leaking sensitive arguments into the audit trail.
    pub context_summary: ContextSummary,
    /// What the verifier decided: allowed, or denied with a reason.
    pub outcome: Outcome,
    /// Wall-clock time of the decision, milliseconds since the UNIX epoch.
    pub timestamp_ms: u64,
    /// HMAC-SHA256 over the canonical-JSON of the receipt with this field
    /// omitted. Hex-encoded for human-readable JSON.
    #[serde(with = "crate::hex::serde_with")]
    pub signature: Vec<u8>,
}

/// Non-secret summary of the call context at verification time.
///
/// `args_hash` is `Context::args_hash()` — a SHA-256 hex of the canonical
/// JSON of the arguments. Storing the hash, not the args, lets the audit
/// log be shared without leaking call payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextSummary {
    /// Identity of the agent or caller (`Context::caller`).
    pub caller: String,
    /// Tool that was about to be invoked (`Context::tool`).
    pub tool: String,
    /// SHA-256 hex of the canonical-JSON of `Context::args`.
    pub args_hash: String,
}

/// Verification outcome — either the call was allowed, or it was denied
/// with a short human-readable reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Outcome {
    /// The capability was accepted; the call may proceed.
    Allowed,
    /// The capability was rejected; the call must not proceed.
    Denied {
        /// Short human-readable explanation, e.g. `"caveat amount<=50_usd failed"`.
        /// Not machine-actionable; for diagnostics only.
        reason: String,
    },
}

/// HMAC-SHA256 signer / verifier for [`Receipt`]s.
///
/// Holds the signing key. Verifying a receipt requires the same key it was
/// signed with — that is the integrity guarantee we are buying.
pub struct Auditor {
    key: Vec<u8>,
}

impl Auditor {
    /// Construct an auditor from a raw key.
    ///
    /// # Panics
    ///
    /// Panics if `key.len() < MIN_AUDIT_KEY_LEN` (16). HMAC itself accepts
    /// keys of any length per RFC 2104 — including zero — but a sub-16-byte
    /// audit key is cryptographically catastrophic and the most common way
    /// to produce one is a misconfigured deployment (audit key derived from
    /// an unset env var). Failing fast at construction makes the
    /// misconfiguration loud at startup rather than silent at verify time.
    /// Production callers SHOULD use a 32-byte key from a CSPRNG.
    pub fn new(key: &[u8]) -> Self {
        assert!(
            key.len() >= MIN_AUDIT_KEY_LEN,
            "Auditor: key length {} < MIN_AUDIT_KEY_LEN ({}); see audit.rs",
            key.len(),
            MIN_AUDIT_KEY_LEN,
        );
        Self { key: key.to_vec() }
    }

    /// Build and sign a receipt for a verification decision.
    ///
    /// The signature covers HMAC-SHA256 of a domain-separated input:
    /// `b"v" || [version_byte] || canonical_json(receipt_without_signature)`.
    /// The leading `b"v" || version` tag binds the schema version into
    /// the MAC so a man-in-the-middle cannot rewrite `version` without
    /// invalidating the signature — even though `version` is also
    /// included inside the canonical-JSON body. The redundancy is
    /// deliberate: the body covers it for free, and the prefix tag
    /// makes the version-binding contract explicit and self-documenting
    /// in the signing input.
    pub fn sign(&self, cap: &Capability, ctx: &Context, outcome: Outcome) -> Receipt {
        // Use the verifier-supplied `now` from the Context rather than
        // calling `SystemTime::now()` here. Two reasons:
        //
        // 1. Semantic — the receipt's timestamp should match the wall-clock
        //    the verifier evaluated caveats against, not "whenever audit
        //    got around to signing". Using ctx.now keeps the receipt
        //    self-consistent.
        // 2. Portability — `SystemTime::now()` panics with `unreachable!`
        //    on `wasm32-unknown-unknown` (no system clock). Pulling the
        //    timestamp from the Context (which the WASM binding seeds from
        //    JS-side `Date.now()`) avoids a build-target-specific shim.
        let timestamp_ms = ctx
            .now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut receipt = Receipt {
            version: RECEIPT_SCHEMA_VERSION,
            capability_identifier: cap.identifier.clone(),
            caveats: cap.caveats.clone(),
            context_summary: ContextSummary {
                caller: ctx.caller.clone(),
                tool: ctx.tool.clone(),
                args_hash: ctx.args_hash(),
            },
            outcome,
            timestamp_ms,
            signature: Vec::new(),
        };
        let bytes = signing_input(&receipt).expect("Receipt is always serializable");
        receipt.signature = hmac_sign(&self.key, &bytes);
        receipt
    }

    /// Recompute the receipt's signature and constant-time-compare it
    /// against the stored signature.
    ///
    /// Returns `Ok(())` on a match. Behavior summary:
    ///
    /// - `receipt.version != RECEIPT_SCHEMA_VERSION` →
    ///   [`AuditError::UnsupportedVersion`]. Fail-closed forward-compat:
    ///   a verifier built against version `N` refuses to interpret a
    ///   receipt that claims any other schema version. See DESIGN.md §14.
    /// - Any tampering with any non-`signature` field (including
    ///   `version`), or any change to the signature bytes →
    ///   [`AuditError::InvalidSignature`].
    pub fn verify(&self, receipt: &Receipt) -> Result<(), AuditError> {
        // Version gate runs BEFORE the HMAC check. The signature also
        // covers `version` (via both the domain-separated prefix tag
        // and the canonical-JSON body), so a tampered version would be
        // caught at the HMAC stage too. Checking explicitly first gives
        // a clearer error and matches the fail-closed policy.
        if receipt.version != RECEIPT_SCHEMA_VERSION {
            return Err(AuditError::UnsupportedVersion {
                got: receipt.version,
                expected: RECEIPT_SCHEMA_VERSION,
            });
        }
        let bytes = signing_input(receipt)?;
        let expected = hmac_sign(&self.key, &bytes);
        if expected.ct_eq(&receipt.signature).into() {
            Ok(())
        } else {
            Err(AuditError::InvalidSignature)
        }
    }
}

fn hmac_sign(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Errors surfaced by the audit module.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The recomputed signature did not match the stored one.
    #[error("invalid signature")]
    InvalidSignature,
    /// The receipt declares a schema version this verifier does not
    /// understand. Surfaced as a dedicated variant (rather than folded
    /// into [`AuditError::InvalidSignature`]) so callers — and incident
    /// responders reading the error — can tell a version-skew miss from
    /// a tampering attempt at a glance. See DESIGN.md §14.
    #[error("unsupported receipt schema version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// Schema version declared on the receipt.
        got: u8,
        /// Schema version this build of the verifier accepts.
        expected: u8,
    },
    /// I/O error reading or writing the log file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON encode or decode failure on a receipt.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Append-only newline-delimited JSON log of [`Receipt`]s.
///
/// Each call to [`AuditLog::append`] writes one JSON-encoded receipt
/// followed by a single `\n`. The on-disk format is plain NDJSON so the
/// log can be inspected with `jq`, tailed with `tail -f`, or shipped to
/// any standard log pipeline.
pub struct AuditLog {
    file: File,
}

impl AuditLog {
    /// Open the log at `path` for appending, creating the file if it does
    /// not exist. Existing contents are preserved; new writes go to the
    /// end of the file.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;
        Ok(Self { file })
    }

    /// Append one receipt as a single JSON line.
    ///
    /// I/O is unbuffered: each `append` is one `write_all` of the JSON
    /// followed by one `write_all` of `\n`. This keeps the cost of a
    /// crash-bounded flush model simple — a partially-written line is the
    /// only corruption mode.
    pub fn append(&mut self, receipt: &Receipt) -> std::io::Result<()> {
        let line = serde_json::to_string(receipt)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        Ok(())
    }

    /// Iterate receipts from disk in append order.
    ///
    /// Opens a fresh read-only handle on `path` so iteration is decoupled
    /// from any writer that may still be appending. Blank or whitespace-only
    /// lines are silently skipped (a trailing `\n` is the most common
    /// source). Each non-blank line is parsed as a [`Receipt`]; a malformed
    /// line yields an `Err` from the iterator without aborting the rest.
    pub fn iter(
        path: impl AsRef<Path>,
    ) -> std::io::Result<Box<dyn Iterator<Item = Result<Receipt, AuditError>>>> {
        let file = File::open(path.as_ref())?;
        let reader = BufReader::new(file);
        Ok(Box::new(reader.lines().filter_map(
            |line_res| match line_res {
                Ok(s) if s.trim().is_empty() => None,
                Ok(s) => Some(serde_json::from_str::<Receipt>(&s).map_err(AuditError::Json)),
                Err(e) => Some(Err(AuditError::Io(e))),
            },
        )))
    }
}

/// HMAC input for a receipt:
///   `b"v" || [version_byte] || canonical_json(receipt_without_signature)`.
///
/// The `b"v" || version` prefix is a domain-separated tag binding the
/// receipt's schema version into the MAC. `version` is also part of the
/// canonical-JSON body (because it's a struct field), so the prefix is
/// redundant for integrity — but it makes the version-binding contract
/// explicit at the signing-input layer, so a future schema change that
/// (say) renames the field can never silently lose the version-binding
/// property: the prefix tag stays.
///
/// The route through `serde_json::Value` is intentional: the default
/// `serde_json::Map` is a sorted `BTreeMap`, so a `Value`-based round trip
/// canonicalises key order at every object level. `serde_json::to_vec`
/// (not `to_vec_pretty`) emits no whitespace. The combination matches the
/// `Context::args_hash` rules locked in WEEK2_SPEC §2.1.
fn signing_input(receipt: &Receipt) -> Result<Vec<u8>, serde_json::Error> {
    let mut v = serde_json::to_value(receipt)?;
    if let serde_json::Value::Object(ref mut m) = v {
        m.remove("signature");
    }
    let body = serde_json::to_vec(&v)?;
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(b'v');
    out.push(receipt.version);
    out.extend_from_slice(&body);
    Ok(out)
}
