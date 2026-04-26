//! Capability verification — checks the HMAC chain against the root key.
//!
//! Caveat *evaluation* is intentionally not done here in v0. Verification only
//! confirms the chain integrity (i.e. that the holder has not added/dropped/
//! modified caveats out of band). Predicate evaluation against a verification
//! context is the week-2 deliverable; for now the caller receives the caveats
//! and decides.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::capability::{chain_caveat, Capability, Caveat};
use crate::{Error, Result};

/// Verifies capability tokens against the root key.
pub struct Verifier {
    root_key: Vec<u8>,
}

/// The result of a successful verification — borrows the verified capability.
#[derive(Debug)]
pub struct Verified<'a> {
    /// Public identifier carried by the capability.
    pub identifier: &'a str,
    /// Ordered caveats whose chain integrity has been confirmed.
    pub caveats: &'a [Caveat],
}

impl Verifier {
    /// Construct a Verifier from the same root key the Issuer used.
    pub fn new(key: &[u8]) -> Self {
        Self {
            root_key: key.to_vec(),
        }
    }

    /// Recompute the HMAC chain for `cap` and compare against its signature
    /// in constant time.
    pub fn verify<'a>(&self, cap: &'a Capability) -> Result<Verified<'a>> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.root_key)
            .expect("HMAC accepts keys of any length");
        mac.update(cap.identifier.as_bytes());
        let mut sig = mac.finalize().into_bytes().to_vec();
        for caveat in &cap.caveats {
            sig = chain_caveat(&sig, caveat);
        }

        if sig.len() != cap.signature.len() {
            return Err(Error::InvalidSignature);
        }
        if sig.ct_eq(&cap.signature).unwrap_u8() != 1 {
            return Err(Error::InvalidSignature);
        }

        Ok(Verified {
            identifier: &cap.identifier,
            caveats: &cap.caveats,
        })
    }
}
