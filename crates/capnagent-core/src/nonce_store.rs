//! Replay protection for proof-of-possession.
//!
//! Threat: a captured token + proof can be replayed by the same attacker
//! (in the hok case) within the proof's TTL window. The
//! [`pop_challenge_for`](crate::pop_challenge_for) derivation already
//! includes `ctx.now_ms`, so two legitimate calls at different
//! timestamps produce different challenges and signatures — but an
//! attacker who races the original within the same millisecond wins.
//!
//! A [`NonceStore`] gives the verifier somewhere to record proofs it
//! has accepted. Subsequent attempts to reuse the same proof bytes get
//! denied, with `Outcome::Denied { reason: "proof replay detected" }`,
//! which is audit-loggable just like every other denial.
//!
//! ## Scope
//!
//! Replay protection only applies to [`Verifier::verify_with_proof`].
//! Non-hok bearer tokens are explicitly designed to be reusable — a
//! capability that authorises "buy at amazon.com up to $50" should be
//! usable for many purchases. Adding replay protection there would
//! break the model.
//!
//! ## Persistence
//!
//! [`InMemoryNonceStore`] is the default implementation. It is, as the
//! name suggests, in-memory — restarts forget every recorded proof.
//! Production deployments that need cross-process or cross-restart
//! replay resistance should provide their own [`NonceStore`] backed by
//! Redis, Postgres, or whatever durable store fits.
//!
//! ## TTL
//!
//! Entries past their expiry are treated as absent on the next
//! `try_record` call. We do not actively sweep — old entries linger
//! until they're overwritten by the next attempt to record the same
//! nonce. For workloads that see very high churn of unique nonces,
//! provide a sweeper or use a backing store that handles expiration
//! natively.

use std::collections::HashMap;
use std::sync::Mutex;

/// Backing store that records accepted proofs so the verifier can
/// detect replays. Implementations must be `Send + Sync` because the
/// verifier holds a shared reference and may be called from multiple
/// threads.
pub trait NonceStore: Send + Sync {
    /// Try to record `nonce` with effective expiry of `now_ms +
    /// ttl_ms`. Returns:
    ///
    /// - `true` if `nonce` was not previously seen, or its previous
    ///   entry has already expired. The store records the new entry.
    /// - `false` if `nonce` is already in the store with a non-expired
    ///   entry. The store does NOT update the existing entry — the
    ///   original expiry stands.
    ///
    /// Implementations must be safe to call concurrently. The
    /// "check then insert" must appear atomic to the caller; otherwise
    /// two concurrent verifiers could each see the absence and both
    /// accept the replay.
    fn try_record(&self, nonce: &[u8], now_ms: u64, ttl_ms: u64) -> bool;
}

/// Default in-memory [`NonceStore`].
///
/// Backed by `Mutex<HashMap<Vec<u8>, u64>>`. The hashmap key is the
/// nonce (typically `sha256(proof)` — 32 bytes); the value is the
/// expiry timestamp in ms-since-UNIX-epoch.
///
/// Memory grows with the number of unique non-expired nonces. There
/// is no background sweeper; expired entries are reclaimed only when
/// the same nonce is re-recorded. For workloads that need bounded
/// memory, provide an alternate impl.
pub struct InMemoryNonceStore {
    seen: Mutex<HashMap<Vec<u8>, u64>>,
}

impl InMemoryNonceStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Number of entries currently held (including expired ones that
    /// have not yet been overwritten). Useful for tests and
    /// instrumentation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.lock().expect("nonce store poisoned").len()
    }

    /// Whether the store has zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop all recorded nonces. Useful for tests; production callers
    /// rarely want this.
    pub fn clear(&self) {
        self.seen.lock().expect("nonce store poisoned").clear();
    }
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn try_record(&self, nonce: &[u8], now_ms: u64, ttl_ms: u64) -> bool {
        let mut seen = self.seen.lock().expect("nonce store poisoned");
        if let Some(&existing_expiry) = seen.get(nonce) {
            if existing_expiry > now_ms {
                // Still valid — this is a replay. Do not refresh.
                return false;
            }
        }
        let expiry = now_ms.saturating_add(ttl_ms);
        seen.insert(nonce.to_vec(), expiry);
        true
    }
}
