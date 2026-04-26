//! Capability verification.
//!
//! Two entry points:
//!
//! - [`Verifier::verify`] checks the HMAC chain only. It is the same surface
//!   that property-tested the cannot-broaden invariant in week 1. Caveat
//!   semantics are not its concern.
//! - [`Verifier::verify_with_context`] is the integrated entry point. It
//!   verifies the chain, evaluates every caveat against the supplied
//!   [`Context`], hands the outcome to an [`Auditor`] for signing, and
//!   returns the resulting [`Receipt`]. Per `docs/DESIGN.md` §6, denial is
//!   carried on `Receipt::outcome`, not in the error type — only events
//!   that "should not happen during normal operation" (chain forgery, audit
//!   I/O failure) flow through [`VerifyError`].

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::audit::{AuditError, Auditor, Outcome, Receipt};
use crate::capability::{chain_caveat, Capability, Caveat};
use crate::caveat_dsl;
use crate::context::Context;
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

    /// Full verification pipeline:
    ///
    /// 1. Confirm the HMAC chain integrity ([`Verifier::verify`]). On
    ///    failure, return [`VerifyError::Chain`] — no receipt is produced
    ///    because a forged token is not a normal authorization decision.
    /// 2. Parse and evaluate every caveat against `ctx` using the v0
    ///    [`caveat_dsl`]. A caveat that fails to parse, fails to evaluate,
    ///    or returns `false` becomes a [`Outcome::Denied`] with a short
    ///    reason. Fail-closed: an unrecognised caveat is a denial, never
    ///    a silent allow.
    /// 3. Hand the resulting [`Outcome`] to the supplied [`Auditor`] for
    ///    signing. The receipt is returned to the caller, who is
    ///    responsible for appending it to whatever [`crate::AuditLog`]
    ///    they have open.
    ///
    /// # Errors
    ///
    /// - [`VerifyError::Chain`] if the capability's HMAC chain is invalid.
    /// - [`VerifyError::Audit`] if the auditor fails to sign the receipt.
    pub fn verify_with_context(
        &self,
        cap: &Capability,
        ctx: &Context,
        auditor: &Auditor,
    ) -> std::result::Result<Receipt, VerifyError> {
        // Leg 1 — chain integrity. A failure here is an adversarial event,
        // not a normal denial. We refuse to mint a receipt for a forged
        // capability because the receipt format implies "I saw a real
        // capability and decided X".
        self.verify(cap)?;

        // Leg 2 — caveat evaluation. Any failure becomes a Denied outcome
        // with a short, reproducible reason.
        let outcome = match evaluate_all(&cap.caveats, ctx) {
            Ok(()) => Outcome::Allowed,
            Err(reason) => Outcome::Denied { reason },
        };

        // Leg 3 — sign. Audit signing is infallible at the type level
        // (HMAC over canonical JSON), but the canonical-JSON encoding can
        // surface a `serde_json::Error` if a Receipt field were ever
        // non-serializable. That can't happen with the current Receipt
        // shape, so this is defensive.
        Ok(auditor.sign(cap, ctx, outcome))
    }
}

/// Walks the caveats once, parsing and evaluating each. Returns `Ok(())` if
/// all hold, or `Err(reason)` describing the first failure.
///
/// Fail-closed semantics: a caveat that won't parse becomes a denial reason
/// rather than an allow path. The verifier never accepts a token whose
/// caveats it cannot understand.
fn evaluate_all(caveats: &[Caveat], ctx: &Context) -> std::result::Result<(), String> {
    for caveat in caveats {
        let predicate = caveat_dsl::parse(&caveat.predicate)
            .map_err(|e| format!("caveat parse error in {:?}: {e}", caveat.predicate))?;
        let holds = caveat_dsl::evaluate(&predicate, ctx)
            .map_err(|e| format!("caveat eval error in {:?}: {e}", caveat.predicate))?;
        if !holds {
            return Err(format!("caveat failed: {}", caveat.predicate));
        }
    }
    Ok(())
}

/// Failure modes of the integrated [`Verifier::verify_with_context`] entry
/// point. Per `docs/DESIGN.md` §6, denial is **not** an error — it is an
/// [`Outcome::Denied`] carried on a normal [`Receipt`]. Errors are reserved
/// for events that should not happen during normal operation.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The capability's HMAC chain did not validate against the root key.
    /// In a well-behaved deployment, this means the token was forged or
    /// tampered with — never a routine outcome.
    #[error("capability chain integrity: {0}")]
    Chain(#[from] Error),

    /// The auditor failed to produce or persist a signed receipt. With the
    /// in-memory `sign()` path this is unreachable; the variant exists so
    /// future audit pipelines (gRPC, file rotation) compose cleanly via
    /// `?`.
    #[error("audit: {0}")]
    Audit(#[from] AuditError),
}
