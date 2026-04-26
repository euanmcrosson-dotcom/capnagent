//! Capability issuance — the only operation that requires the root key.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::capability::{chain_caveat, Capability, Caveat};

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
            caveats: Vec::new(),
            signature: sig,
        }
    }
}

/// Fluent builder produced by [`Issuer::issue`]. Callers chain `.caveat(..)`
/// then `.build()`.
pub struct CapabilityBuilder {
    identifier: String,
    caveats: Vec<Caveat>,
    signature: Vec<u8>,
}

impl CapabilityBuilder {
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
            caveats: self.caveats,
            signature: self.signature,
        }
    }
}
