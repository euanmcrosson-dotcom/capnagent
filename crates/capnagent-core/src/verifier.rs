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

use ed25519_dalek::{Signature, Verifier as Ed25519Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::audit::{AuditError, Auditor, Outcome, Receipt};
use crate::capability::{chain_caveat, chain_holder_of_key, Capability, Caveat};
use crate::caveat_dsl;
use crate::context::Context;
use crate::revocation::{RevocationError, RevocationList};
use crate::{Error, Result};

/// Verifies capability tokens against the root key.
pub struct Verifier {
    root_key: Vec<u8>,
    /// Optional revocation list. If present, capabilities whose
    /// identifiers appear in the list are denied at verification time
    /// even if the chain and caveats are otherwise valid. The list's
    /// own signature is checked when it is attached, not on every
    /// verify call.
    revocation_list: Option<RevocationList>,
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
            revocation_list: None,
        }
    }

    /// Attach a [`RevocationList`] to this verifier. The list's
    /// signature is verified once here against the root key; if it
    /// fails, the call returns [`RevocationError::InvalidSignature`]
    /// and the list is *not* installed. Subsequent
    /// [`Verifier::verify_with_context`] calls will deny any
    /// capability whose identifier appears in the list (with an
    /// audit-loggable [`Outcome::Denied`] outcome).
    pub fn with_revocation_list(
        mut self,
        list: RevocationList,
    ) -> std::result::Result<Self, RevocationError> {
        list.verify_signature(&self.root_key)?;
        self.revocation_list = Some(list);
        Ok(self)
    }

    /// Drop any installed revocation list.
    #[must_use]
    pub fn without_revocation_list(mut self) -> Self {
        self.revocation_list = None;
        self
    }

    /// Returns the currently-installed revocation list, if any. Useful
    /// for inspecting state during testing or for surfacing the
    /// `issued_at_ms` of a stale list to operators.
    #[must_use]
    pub fn revocation_list(&self) -> Option<&RevocationList> {
        self.revocation_list.as_ref()
    }

    /// Recompute the HMAC chain for `cap` and compare against its signature
    /// in constant time. Honours `holder_of_key` if present — the chain
    /// folds in the holder-of-key bytes after the identifier and before
    /// any caveats, so altering or removing the binding invalidates the
    /// signature.
    pub fn verify<'a>(&self, cap: &'a Capability) -> Result<Verified<'a>> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.root_key)
            .expect("HMAC accepts keys of any length");
        mac.update(cap.identifier.as_bytes());
        let mut sig = mac.finalize().into_bytes().to_vec();

        if let Some(hok) = &cap.holder_of_key {
            sig = chain_holder_of_key(&sig, hok);
        }

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

        // hok-bound tokens MUST go through verify_with_proof. Calling
        // verify_with_context with a hok-bound token is fail-closed —
        // the verifier has no proof to check, so it denies. The denial
        // is recorded as an outcome (not an error) so the attempt is
        // visible in the audit log.
        if cap.holder_of_key.is_some() {
            return Ok(auditor.sign(
                cap,
                ctx,
                Outcome::Denied {
                    reason: "capability is bound to a holder key; use verify_with_proof".into(),
                },
            ));
        }

        // Leg 2 — revocation. Cryptographically intact tokens may still
        // be denied here if the issuer has explicitly revoked them.
        // Revocation is recorded as an Outcome::Denied (not an Err) so
        // the audit log captures every attempt against a revoked token —
        // exactly the signal incident response needs ("when did the
        // attacker last try the stolen capability?").
        let outcome = match check_revocation(cap, self.revocation_list.as_ref()) {
            Err(reason) => Outcome::Denied { reason },
            Ok(()) => match evaluate_all(&cap.caveats, ctx) {
                // Leg 3 — caveat evaluation. Any failure becomes a Denied
                // outcome with a short, reproducible reason.
                Ok(()) => Outcome::Allowed,
                Err(reason) => Outcome::Denied { reason },
            },
        };

        // Leg 4 — sign. Audit signing is infallible at the type level
        // (HMAC over canonical JSON), but the canonical-JSON encoding can
        // surface a `serde_json::Error` if a Receipt field were ever
        // non-serializable. That can't happen with the current Receipt
        // shape, so this is defensive.
        Ok(auditor.sign(cap, ctx, outcome))
    }

    /// Like [`Verifier::verify_with_context`], but requires a DPoP-style
    /// proof of possession. Required for capabilities issued with
    /// [`crate::CapabilityBuilder::holder_of_key`].
    ///
    /// `challenge` is the bytes the holder signed (typically a hash of
    /// the request — see [`pop_challenge_for`] for a default policy).
    /// `proof` is the raw 64-byte ed25519 signature.
    ///
    /// On a hok-bound capability:
    ///   - **No `holder_of_key`** on the cap → `Outcome::Denied`. Mixing
    ///     proof-required and proof-not-required call sites is a
    ///     configuration mistake; we surface it as a denial rather than
    ///     silently allowing.
    ///   - **Bad signature, wrong key, or malformed `proof`** →
    ///     `Outcome::Denied` with reason `"holder-of-key proof failed"`.
    ///   - **Valid proof** → falls through to the same revocation +
    ///     caveat-evaluation pipeline as `verify_with_context`.
    ///
    /// In every case the receipt is signed and returned, so the audit
    /// log captures the attempt. Errors are reserved for chain forgery
    /// and audit-pipeline failures, same as `verify_with_context`.
    pub fn verify_with_proof(
        &self,
        cap: &Capability,
        ctx: &Context,
        auditor: &Auditor,
        challenge: &[u8],
        proof: &[u8],
    ) -> std::result::Result<Receipt, VerifyError> {
        // Leg 1 — chain integrity (includes hok in the chain).
        self.verify(cap)?;

        // Leg 2 — proof of possession.
        if let Err(reason) = check_proof(cap, challenge, proof) {
            return Ok(auditor.sign(cap, ctx, Outcome::Denied { reason }));
        }

        // Leg 3 — revocation.
        let outcome = match check_revocation(cap, self.revocation_list.as_ref()) {
            Err(reason) => Outcome::Denied { reason },
            // Leg 4 — caveats.
            Ok(()) => match evaluate_all(&cap.caveats, ctx) {
                Ok(()) => Outcome::Allowed,
                Err(reason) => Outcome::Denied { reason },
            },
        };

        Ok(auditor.sign(cap, ctx, outcome))
    }
}

/// Default proof-of-possession challenge for a given context. Returns
/// `SHA-256(canonical-JSON({ id, tool, args_hash, now_ms }))`. Use this
/// on the holder side to compute the bytes to sign, and on the verifier
/// side to compute the bytes to compare against. Both sides must agree
/// on this exact derivation — bytewise — for the proof to verify.
///
/// Callers free to pass their own challenge bytes to
/// [`Verifier::verify_with_proof`] if they want a different policy
/// (e.g. include a server-side nonce). The function is a default, not
/// a requirement.
#[must_use]
pub fn pop_challenge_for(cap: &Capability, ctx: &Context) -> Vec<u8> {
    use sha2::Digest;
    let now_ms = ctx
        .now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    // Match the audit module's args_hash policy so callers don't have
    // to know about the canonical-JSON details.
    let args_hash = ctx.args_hash();
    let payload = serde_json::json!({
        "id": cap.identifier,
        "tool": ctx.tool,
        "args_hash": args_hash,
        "now_ms": now_ms,
    });
    let bytes = serde_json::to_vec(&payload).expect("payload always serializable");
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    hasher.finalize().to_vec()
}

fn check_proof(
    cap: &Capability,
    challenge: &[u8],
    proof: &[u8],
) -> std::result::Result<(), String> {
    let hok = cap
        .holder_of_key
        .as_ref()
        .ok_or_else(|| "capability is not hok-bound; do not use verify_with_proof".to_string())?;

    let pubkey_bytes: [u8; 32] = hok.as_slice().try_into().map_err(|_| {
        format!(
            "malformed holder-of-key public key (expected 32 bytes, got {})",
            hok.len()
        )
    })?;

    let pubkey = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| "invalid ed25519 public key in capability".to_string())?;

    let proof_bytes: [u8; 64] = proof.try_into().map_err(|_| {
        format!(
            "malformed proof signature (expected 64 bytes, got {})",
            proof.len()
        )
    })?;
    let signature = Signature::from_bytes(&proof_bytes);

    pubkey
        .verify(challenge, &signature)
        .map_err(|_| "holder-of-key proof failed".to_string())
}

/// Returns `Err(reason)` if `list` is `Some` and contains `cap.identifier`,
/// otherwise `Ok(())`. Lifted out of `verify_with_context` so it stays
/// trivially auditable.
fn check_revocation(
    cap: &Capability,
    list: Option<&RevocationList>,
) -> std::result::Result<(), String> {
    if let Some(list) = list {
        if list.contains(&cap.identifier) {
            return Err(format!("capability revoked: {}", cap.identifier));
        }
    }
    Ok(())
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
