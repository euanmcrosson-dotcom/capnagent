//! On-the-wire capability representation.
//!
//! A `Capability` is a tuple `(identifier, caveats[], signature)` where the
//! signature is an HMAC-SHA256 chain rooted at the issuer's secret key.
//!
//! Construction:
//! ```text
//! sig_0 = HMAC(root_key, identifier)
//! sig_i = HMAC(sig_{i-1}, caveat_i.predicate)   for i = 1..n
//! signature = sig_n
//! ```
//!
//! The chain has the load-bearing property that anyone holding `sig_i` can
//! produce `sig_{i+1}` by appending a caveat — but cannot reverse it. So
//! attenuation is open to all holders; broadening is impossible without the
//! root key.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{Error, Result};

/// A single caveat — a predicate string that must hold at verification time.
///
/// In v0 the predicate is opaque to the core: the verifier returns the list
/// of caveats and the caller decides how to evaluate them. The caveat DSL
/// (`amount <= ...`, `expires <= ...`, etc.) is the week-2 deliverable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Caveat {
    /// Free-form predicate text. Will be parsed by the caveat DSL in v0.1.
    pub predicate: String,
}

impl Caveat {
    /// Build a caveat from any string-like input.
    pub fn new(predicate: impl Into<String>) -> Self {
        Self {
            predicate: predicate.into(),
        }
    }
}

/// A capability token: identifier, caveats, and the HMAC chain signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// Public identifier for the capability — what authority it grants.
    pub identifier: String,
    /// Ordered list of caveats. Order is part of the signed payload.
    pub caveats: Vec<Caveat>,
    /// HMAC-SHA256 signature, hex-encoded for human-readable JSON.
    #[serde(with = "crate::hex::serde_with")]
    pub signature: Vec<u8>,
}

impl Capability {
    /// Append a caveat, producing a strictly narrower capability.
    ///
    /// This is the public attenuation API any holder can call. The new
    /// signature is computed by HMAC-chaining; the previous signature is the
    /// only secret needed.
    #[must_use]
    pub fn attenuate(mut self, predicate: impl Into<String>) -> Self {
        let caveat = Caveat::new(predicate);
        let new_sig = chain_caveat(&self.signature, &caveat);
        self.caveats.push(caveat);
        self.signature = new_sig;
        self
    }

    /// Encode the capability as a URL-safe, unpadded base64 string of its JSON.
    pub fn serialize(&self) -> String {
        let json = serde_json::to_vec(self).expect("Capability is always serializable");
        URL_SAFE_NO_PAD.encode(&json)
    }

    /// Decode a previously-serialized token. Performs no signature check —
    /// callers must hand the result to a `Verifier`.
    pub fn parse(token: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(token)?;
        let cap: Capability = serde_json::from_slice(&bytes)
            .map_err(|e| Error::InvalidFormat(format!("not a valid capnagent capability: {e}")))?;
        Ok(cap)
    }
}

/// HMAC-SHA256(prev_sig, caveat.predicate). Internal building block shared
/// by issuer, attenuator, and verifier so they stay in lock-step.
pub(crate) fn chain_caveat(prev_sig: &[u8], caveat: &Caveat) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(prev_sig).expect("HMAC accepts keys of any length");
    mac.update(caveat.predicate.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
