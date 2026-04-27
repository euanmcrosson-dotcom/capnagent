//! Capability issuance — the only operation that requires the root key.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::capability::{chain_caveat, chain_holder_of_key, Capability, Caveat};

/// Holds the root secret key. Every capability descends from an Issuer.
///
/// The Issuer is the only object in the system that can mint a *new* root
/// capability. After issuance, anyone in possession of the token can attenuate
/// it without needing access to the Issuer.
pub struct Issuer {
    root_key: Vec<u8>,
}

impl Issuer {
    /// Construct an Issuer from a secret key. The key SHOULD be at least
    /// 32 bytes from a CSPRNG. capnagent does not enforce a minimum because
    /// short keys are still useful in tests, but production callers must.
    pub fn from_key(key: &[u8]) -> Self {
        Self {
            root_key: key.to_vec(),
        }
    }

    /// Begin issuing a capability with the given public identifier. Use the
    /// returned builder to attach caveats before calling `.build()`.
    pub fn issue(&self, identifier: impl Into<String>) -> CapabilityBuilder {
        let identifier = identifier.into();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.root_key)
            .expect("HMAC accepts keys of any length");
        mac.update(identifier.as_bytes());
        let sig = mac.finalize().into_bytes().to_vec();
        CapabilityBuilder {
            identifier,
            holder_of_key: None,
            caveats: Vec::new(),
            signature: sig,
        }
    }
}

/// Fluent builder produced by [`Issuer::issue`]. Callers chain
/// `.holder_of_key(pubkey)` (optional, before any caveat) then
/// `.caveat(..)` (zero or more) then `.build()`.
pub struct CapabilityBuilder {
    identifier: String,
    holder_of_key: Option<Vec<u8>>,
    caveats: Vec<Caveat>,
    signature: Vec<u8>,
}

impl CapabilityBuilder {
    /// Bind this capability to an ed25519 public key. The verifier will
    /// require every use of the resulting token to carry a signature
    /// over a per-call challenge made with the corresponding private
    /// key. See [`crate::Verifier::verify_with_proof`].
    ///
    /// `pubkey` MUST be exactly 32 bytes (ed25519 raw public key).
    /// Calling this twice replaces the previous binding **and** rebuilds
    /// the chain from the identifier — caveats added before
    /// `holder_of_key` would be invalidated, so the API requires
    /// `holder_of_key` before any `caveat` calls; if you call them out
    /// of order, the previously-applied caveats are dropped.
    ///
    /// # Panics
    ///
    /// Panics if `pubkey.len() != 32`.
    #[must_use]
    pub fn holder_of_key(mut self, pubkey: &[u8]) -> Self {
        assert_eq!(
            pubkey.len(),
            32,
            "ed25519 public keys are exactly 32 bytes; got {}",
            pubkey.len(),
        );

        // Recompute the chain from sig_0 = HMAC(root_key, identifier)
        // (which is what we have in `self.signature` if no caveats have
        // been added yet). If caveats have been added before this call,
        // we'd have to recompute them after the hok step too — for
        // simplicity, this builder requires hok-first ordering and
        // panics if caveats are already present.
        assert!(
            self.caveats.is_empty(),
            "holder_of_key must be set before any .caveat() calls",
        );
        self.signature = chain_holder_of_key(&self.signature, pubkey);
        self.holder_of_key = Some(pubkey.to_vec());
        self
    }

    /// Append a caveat at issuance time. Equivalent to building the capability
    /// and then calling `attenuate`, except the signature chain is built once.
    #[must_use]
    pub fn caveat(mut self, predicate: impl Into<String>) -> Self {
        let caveat = Caveat::new(predicate);
        self.signature = chain_caveat(&self.signature, &caveat);
        self.caveats.push(caveat);
        self
    }

    /// Finalize the capability.
    pub fn build(self) -> Capability {
        Capability {
            identifier: self.identifier,
            holder_of_key: self.holder_of_key,
            caveats: self.caveats,
            signature: self.signature,
        }
    }
}
