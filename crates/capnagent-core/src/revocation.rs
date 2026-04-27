//! Capability revocation.
//!
//! A [`RevocationList`] is an HMAC-signed list of capability identifiers
//! that the verifier should refuse, regardless of how cryptographically
//! intact the underlying tokens are. It addresses the *capability theft
//! mid-flight* threat from `docs/DESIGN.md` §2: once an issuer learns
//! that a token has been compromised — or that a session is over — the
//! revocation list is how they shut it down before the token's natural
//! expiry.
//!
//! Design choices:
//!
//! - **Signed by the same root key as the issuer.** Same trust root,
//!   no extra key-management surface. The verifier rejects a list
//!   whose signature does not match.
//! - **Append-only logically; the on-disk format is a fresh snapshot
//!   each time.** A new list with `issued_at_ms = T` supersedes any
//!   list with an earlier timestamp. Verifiers that hold both should
//!   prefer the newer one.
//! - **Identifiers are sorted before signing** so the byte-level
//!   serialization is deterministic and replay-stable.
//! - **Revocation does not fail-stop the verifier — it is recorded
//!   as a denial outcome** in the audit log. The audit trail of "this
//!   revoked token was attempted at time T by caller C" is exactly
//!   the signal an incident-response team needs.

use std::collections::BTreeSet;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::hex::serde_with as hex_serde_with;

type HmacSha256 = Hmac<Sha256>;

/// A point-in-time list of revoked capability identifiers, signed by
/// the issuer's root key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RevocationList {
    /// Wall-clock the list was published (milliseconds since the UNIX
    /// epoch). Verifiers may reject lists older than a configured
    /// staleness window; that policy lives at the caller, not here.
    pub issued_at_ms: u64,

    /// Sorted, deduplicated list of revoked capability identifiers.
    /// Order is part of the signed payload — callers should not
    /// re-sort after deserializing.
    pub revoked: Vec<String>,

    /// HMAC-SHA256 over `canonical(self)` with the `signature` field
    /// emptied. Hex-encoded.
    #[serde(with = "hex_serde_with")]
    pub signature: Vec<u8>,
}

impl RevocationList {
    /// Recompute the signature using `key` and constant-time-compare it
    /// against the stored signature.
    pub fn verify_signature(&self, key: &[u8]) -> Result<(), RevocationError> {
        let bytes = canonical_bytes_for_signing(self);
        let expected = hmac_sign(key, &bytes);
        if expected.ct_eq(&self.signature).into() {
            Ok(())
        } else {
            Err(RevocationError::InvalidSignature)
        }
    }

    /// Whether `identifier` appears in this list. O(log n) since
    /// `revoked` is required to be sorted.
    #[must_use]
    pub fn contains(&self, identifier: &str) -> bool {
        self.revoked
            .binary_search_by(|s| s.as_str().cmp(identifier))
            .is_ok()
    }

    /// Number of revoked identifiers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Whether the list has zero revocations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

/// Issuer-side helper for building and signing revocation lists.
///
/// Holds the root key plus the in-memory set of revoked identifiers.
/// Call [`Revoker::publish`] to mint a fresh signed snapshot suitable
/// for handing to a [`crate::Verifier`].
pub struct Revoker {
    root_key: Vec<u8>,
    revoked: BTreeSet<String>,
}

impl Revoker {
    /// Construct a Revoker from the same root key the Issuer uses.
    pub fn new(root_key: &[u8]) -> Self {
        Self {
            root_key: root_key.to_vec(),
            revoked: BTreeSet::new(),
        }
    }

    /// Mark a capability identifier as revoked. Idempotent.
    pub fn revoke(&mut self, identifier: impl Into<String>) {
        self.revoked.insert(identifier.into());
    }

    /// Remove an identifier from the revoked set. Use sparingly —
    /// "unrevoke" makes auditors nervous and is not always supported
    /// by downstream policy. Returns whether the entry was present.
    pub fn unrevoke(&mut self, identifier: &str) -> bool {
        self.revoked.remove(identifier)
    }

    /// Snapshot the current revoked set into a signed [`RevocationList`].
    /// `issued_at_ms` is wall-clock in milliseconds since epoch — pass
    /// it from the verifier-side clock you trust (NOT `SystemTime::now()`
    /// inside this fn, which would panic on `wasm32-unknown-unknown`
    /// and also would tie the function to a specific clock authority).
    #[must_use]
    pub fn publish(&self, issued_at_ms: u64) -> RevocationList {
        let revoked: Vec<String> = self.revoked.iter().cloned().collect();
        let mut list = RevocationList {
            issued_at_ms,
            revoked,
            signature: Vec::new(),
        };
        let bytes = canonical_bytes_for_signing(&list);
        list.signature = hmac_sign(&self.root_key, &bytes);
        list
    }

    /// Number of currently-revoked identifiers held by the Revoker.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Whether the Revoker has any entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

/// Errors specific to the revocation surface. Distinct from
/// [`crate::Error`] (capability chain) and [`crate::AuditError`]
/// (audit log).
#[derive(Debug, Error)]
pub enum RevocationError {
    /// The list's signature did not validate against the supplied key.
    #[error("invalid revocation-list signature")]
    InvalidSignature,
}

// ───────────────────────── internals ─────────────────────────

fn canonical_bytes_for_signing(list: &RevocationList) -> Vec<u8> {
    // Strip the signature for the bytes we sign over.
    let stripped = RevocationList {
        issued_at_ms: list.issued_at_ms,
        revoked: list.revoked.clone(),
        signature: Vec::new(),
    };
    // serde_json with sorted-by-construction fields and a sorted
    // `revoked` vec gives us a deterministic byte sequence. The vec
    // is sorted by `Revoker::publish`; we re-sort here defensively in
    // case a caller hand-constructed the list.
    let mut sorted = stripped;
    sorted.revoked.sort();
    sorted.revoked.dedup();
    serde_json::to_vec(&sorted).expect("RevocationList is always serializable")
}

fn hmac_sign(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}
