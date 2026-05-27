//! WebAssembly + JavaScript bindings for `capnagent-core`.
//!
//! This crate is a thin wrapper around the pure-Rust core. Every public
//! item here is a `#[wasm_bindgen]` shim that translates between the
//! Rust API and the JS-friendly API (`Uint8Array` for keys, plain JS
//! objects for `Context`/`Receipt`, throws-on-error for failures).
//!
//! The pure-Rust core stays free of `wasm-bindgen` so it can be used
//! unchanged from native Rust callers — the workspace's separation
//! between `capnagent-core` and `capnagent-wasm` is deliberate.
//!
//! Build the JS-loadable artefact with:
//!
//! ```text
//! wasm-pack build crates/capnagent-wasm --release --target web
//! ```
//!
//! …or, for Node.js consumers:
//!
//! ```text
//! wasm-pack build crates/capnagent-wasm --release --target nodejs
//! ```

#![deny(unsafe_code)]
#![allow(missing_docs)] // Each `#[wasm_bindgen]` item is documented via TS

use std::sync::Arc;

use capnagent_core as core;
use core::nonce_store::{InMemoryNonceStore, NonceStore as CoreNonceStore};
use core::revocation::{RevocationList as CoreRevocationList, Revoker as CoreRevoker};
use serde_wasm_bindgen::{from_value as js_to, to_value as to_js};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// One-time init — wires nicer panic messages into the JS console.
// ---------------------------------------------------------------------------

/// Install a panic hook that forwards Rust panics to `console.error`. Idempotent.
/// JS callers should invoke this once at startup; not calling it just means
/// panics show up as opaque "RuntimeError: unreachable" in the browser.
#[wasm_bindgen(js_name = "init")]
pub fn init() {
    #[cfg(feature = "console-panic-hook")]
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct Issuer(core::Issuer);

#[wasm_bindgen]
impl Issuer {
    /// Construct an Issuer from a raw key (production callers should pass
    /// at least 32 bytes from a CSPRNG).
    #[wasm_bindgen(js_name = "fromKey")]
    pub fn from_key(key: &[u8]) -> Self {
        Self(core::Issuer::from_key(key))
    }

    /// Begin issuing a capability with the given public identifier.
    pub fn issue(&self, identifier: String) -> CapabilityBuilder {
        CapabilityBuilder(Some(self.0.issue(identifier)))
    }
}

#[wasm_bindgen]
pub struct CapabilityBuilder(Option<core::CapabilityBuilder>);

#[wasm_bindgen]
impl CapabilityBuilder {
    /// Append a caveat. Returns `this` so calls can be chained.
    ///
    /// v0.5: pre-validates that `predicate` parses as caveat DSL before
    /// chaining the HMAC. Closes purple-team angle B.2 — an unparseable
    /// predicate (including the empty string) used to chain silently
    /// and produce a token whose verifier always denied. Throws a
    /// JS-side `Error` on parse failure with the parser's own message.
    pub fn caveat(mut self, predicate: String) -> Result<CapabilityBuilder, JsError> {
        core::caveat_dsl::parse(&predicate)
            .map_err(|e| JsError::new(&format!("invalid caveat predicate: {e}")))?;
        let inner = self.0.take().expect("CapabilityBuilder already consumed");
        self.0 = Some(inner.caveat(predicate));
        Ok(self)
    }

    /// Bind this capability to an ed25519 public key (raw 32 bytes), the
    /// DPoP-style holder-of-key surface from `DESIGN.md` §11. Must be
    /// called BEFORE any `.caveat()` — the underlying core asserts on
    /// out-of-order calls. The returned builder produces tokens that
    /// fail `verify_with_context` (with a recorded denial) and require
    /// `verify_with_proof` for use.
    ///
    /// Length is validated here and surfaced as a JS-side `Error`
    /// (rather than a Rust panic / `RuntimeError`) on mismatch — same
    /// pattern as `Auditor.verify`.
    #[wasm_bindgen(js_name = "holderOfKey")]
    pub fn holder_of_key(mut self, pubkey: &[u8]) -> Result<CapabilityBuilder, JsError> {
        if pubkey.len() != 32 {
            return Err(JsError::new(&format!(
                "ed25519 public keys are exactly 32 bytes; got {}",
                pubkey.len()
            )));
        }
        let inner = self.0.take().expect("CapabilityBuilder already consumed");
        self.0 = Some(inner.holder_of_key(pubkey));
        Ok(self)
    }

    /// Finalise the capability.
    ///
    /// v0.5: throws if no caveats have been attached (closes angle C.5
    /// — a no-caveat token is god-mode authorization). Pre-checks the
    /// caveat count via the inner builder so the JS caller gets a
    /// clean `Error` instead of an opaque WASM panic.
    pub fn build(mut self) -> Result<Capability, JsError> {
        let inner = self.0.take().expect("CapabilityBuilder already consumed");
        if inner.caveat_count() == 0 {
            return Err(JsError::new(
                "Capability has zero caveats — a no-caveat token is god-mode authorization. \
                 Attach at least one caveat (e.g. `now <= @<expiry>`) before calling build(). \
                 See angle C.5.",
            ));
        }
        Ok(Capability(inner.build()))
    }
}

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct Capability(core::Capability);

#[wasm_bindgen]
impl Capability {
    /// Decode a previously-serialised token. Throws on malformed input.
    pub fn parse(token: &str) -> Result<Capability, JsError> {
        core::Capability::parse(token)
            .map(Capability)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Encode the capability as a URL-safe, unpadded base64 string.
    pub fn serialize(&self) -> String {
        self.0.serialize()
    }

    /// Append a caveat, producing a strictly narrower capability.
    ///
    /// v0.5: pre-validates `predicate` parses as caveat DSL. Closes
    /// purple-team angle B.2 — the empty string (and any other
    /// unparseable predicate) used to chain silently and produce a
    /// token whose verifier always denied. Any holder in a chain
    /// could thereby brick a delegated cap. Now throws a JS-side
    /// `Error` instead.
    pub fn attenuate(self, predicate: String) -> Result<Capability, JsError> {
        core::caveat_dsl::parse(&predicate)
            .map_err(|e| JsError::new(&format!("invalid attenuation predicate: {e}")))?;
        Ok(Capability(self.0.attenuate(predicate)))
    }

    /// Public identifier carried by the capability.
    #[wasm_bindgen(getter)]
    pub fn identifier(&self) -> String {
        self.0.identifier.clone()
    }

    /// Returns the bound ed25519 public key (32 bytes) for hok-bound
    /// capabilities, or `undefined` for non-hok tokens. The `Option<Vec<u8>>`
    /// is converted by wasm-bindgen to `Uint8Array | undefined` on the JS
    /// side. See `DESIGN.md` §11.
    #[wasm_bindgen(getter, js_name = "holderOfKey")]
    pub fn holder_of_key(&self) -> Option<Vec<u8>> {
        self.0.holder_of_key.clone()
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verifier wrapper.
///
/// Held as `Option<core::Verifier>` so the consuming-style builder
/// methods (`withNonceStore`, `withNonceTtlMs`, `withRevocationList`)
/// can use the `take()` pattern without forcing the underlying core
/// type to add `&mut self` setters. Same shape as `CapabilityBuilder`.
///
/// The `root_key` is duplicated here from `core::Verifier`'s private
/// field so builder methods that need to validate inputs against the
/// root key (e.g. `withRevocationList` checking the list signature)
/// can do so BEFORE consuming the inner. This means a failed install
/// leaves the Verifier handle usable for retry — the alternative
/// (consume-then-fail) leaves a null pointer that breaks the next
/// JS-side call with a confusing error.
///
/// Once a successful builder method is called, the receiver is
/// consumed; calling any method on the consumed handle surfaces as
/// a JS-side `Error` with message
/// `"Verifier already consumed by a builder call"`.
#[wasm_bindgen]
pub struct Verifier {
    inner: Option<core::Verifier>,
    root_key: Vec<u8>,
}

#[wasm_bindgen]
impl Verifier {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Self {
        Self {
            inner: Some(core::Verifier::new(key)),
            root_key: key.to_vec(),
        }
    }

    /// Install a [`NonceStore`] for replay protection on
    /// `verifyWithProof`. Has no effect on `verifyWithContext` —
    /// non-hok bearer tokens are explicitly designed to be reusable.
    /// Returns `this` so calls can be chained.
    #[wasm_bindgen(js_name = "withNonceStore")]
    pub fn with_nonce_store(mut self, store: &NonceStore) -> Result<Verifier, JsError> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("Verifier already consumed by a builder call"))?;
        let dyn_store: Arc<dyn CoreNonceStore> = Arc::clone(&store.0) as _;
        Ok(Verifier {
            inner: Some(inner.with_nonce_store(dyn_store)),
            root_key: self.root_key,
        })
    }

    /// Override the per-nonce TTL in milliseconds. Default is 5 minutes.
    /// Only meaningful in combination with `withNonceStore`.
    /// Returns `this` so calls can be chained.
    #[wasm_bindgen(js_name = "withNonceTtlMs")]
    pub fn with_nonce_ttl_ms(mut self, ttl_ms: u64) -> Result<Verifier, JsError> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("Verifier already consumed by a builder call"))?;
        Ok(Verifier {
            inner: Some(inner.with_nonce_ttl_ms(ttl_ms)),
            root_key: self.root_key,
        })
    }

    /// Whether a `RevocationList` is currently installed.
    ///
    /// Added in v0.4 in response to purple-team round 06: an operator
    /// who silently caught a `withRevocationList` install error could
    /// not previously detect the silent-failed install from the
    /// public API surface. Use this to write postcondition assertions
    /// in deployment-readiness code:
    ///
    /// ```ts
    /// verifier.withRevocationList(list);  // may throw
    /// if (!verifier.hasRevocationList()) {
    ///   throw new Error("revocation install silently failed");
    /// }
    /// ```
    #[wasm_bindgen(js_name = "hasRevocationList")]
    pub fn has_revocation_list(&self) -> Result<bool, JsError> {
        Ok(self.inner()?.has_revocation_list())
    }

    /// Wall-clock the installed revocation list was published, in
    /// milliseconds since UNIX epoch, or `undefined` if no list is
    /// installed.
    ///
    /// Lets operators detect stale lists ("the list is from 6 hours
    /// ago, the freshness window is 1 hour, fail the deploy probe").
    #[wasm_bindgen(js_name = "revocationListIssuedAtMs")]
    pub fn revocation_list_issued_at_ms(&self) -> Result<Option<u64>, JsError> {
        Ok(self.inner()?.revocation_list().map(|l| l.issued_at_ms))
    }

    /// Whether a `NonceStore` is currently installed.
    ///
    /// Same shape as `hasRevocationList`. Lets operators detect the
    /// "hok-bound caps in use but no replay protection installed"
    /// configuration error.
    #[wasm_bindgen(js_name = "hasNonceStore")]
    pub fn has_nonce_store(&self) -> Result<bool, JsError> {
        Ok(self.inner()?.has_nonce_store())
    }

    /// Install a signed [`RevocationList`]. The list's HMAC signature
    /// is verified against the verifier's root key BEFORE installation;
    /// mismatch throws a JS-side `Error` with message `"invalid
    /// revocation-list signature"` AND leaves the receiver unchanged
    /// (a JS-side caller can retry with a different list without
    /// throwing away the Verifier handle).
    ///
    /// This is `&mut self` rather than the consuming `mut self` shape
    /// used by `withNonceStore` / `withNonceTtlMs` — those can never
    /// fail, so the consuming pattern is fine. `withRevocationList`
    /// can fail (signature mismatch), and consume-on-failure would
    /// leave callers with a null pointer they can't recover from.
    ///
    /// Once installed, every subsequent `verifyWithContext` /
    /// `verifyWithProof` call denies any capability whose identifier
    /// is in the list — denial reason
    /// `"capability revoked: <identifier>"`, audit-loggable like every
    /// other denial.
    ///
    /// The TS wrapper layers chainable `return this` on top of this
    /// void-returning surface.
    #[wasm_bindgen(js_name = "withRevocationList")]
    pub fn with_revocation_list(&mut self, list: &RevocationList) -> Result<(), JsError> {
        // Pre-check: verify the list's HMAC against our retained
        // root_key BEFORE touching `self.inner`. On signature mismatch
        // we return Err while leaving `self.inner` untouched.
        list.0
            .verify_signature(&self.root_key)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let inner = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("Verifier already consumed by a builder call"))?;
        // Signature already verified above; this can't fail.
        let installed = inner
            .with_revocation_list(list.0.clone())
            .expect("signature pre-check passed");
        self.inner = Some(installed);
        Ok(())
    }

    /// Chain-only verification. Throws if the HMAC chain doesn't match.
    pub fn verify(&self, cap: &Capability) -> Result<(), JsError> {
        self.inner()?
            .verify(&cap.0)
            .map(|_| ())
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Full pipeline: chain integrity + caveat evaluation + audit signing.
    /// Throws on `VerifyError::Chain` (forged token) and
    /// `VerifyError::Audit`. Caveat denials are NOT thrown — they come back
    /// on the returned `Receipt`'s `outcome` field.
    #[wasm_bindgen(js_name = "verifyWithContext")]
    pub fn verify_with_context(
        &self,
        cap: &Capability,
        ctx: JsValue,
        auditor: &Auditor,
    ) -> Result<JsValue, JsError> {
        let ctx_native = decode_context(ctx)?;
        let receipt = self
            .inner()?
            .verify_with_context(&cap.0, &ctx_native, &auditor.0)
            .map_err(|e| JsError::new(&e.to_string()))?;
        to_js(&receipt).map_err(|e| JsError::new(&e.to_string()))
    }

    /// v0.6.1 — same pipeline as `verifyWithContext`, but accepts the
    /// context as a **raw JSON string** instead of a JS object.
    ///
    /// **When to use this variant.** The default `verifyWithContext`
    /// receives a JS object across the WASM boundary. Because JS's
    /// `Number` IS f64, any sub-ulp precision past `ulp(value)/2` is
    /// rounded out before WASM sees the value. That collapses the v0.6
    /// integer-domain detection on the arg side: an attacker who emits
    /// `{"amount": 50.000000000000001}` over the wire has the digits
    /// stripped by JS's JSON parser, so the source-text fact that the
    /// arg was float-syntactic is lost.
    ///
    /// `verifyWithContextJson` takes the JSON **source** instead, so
    /// `serde_json::from_str` (with `arbitrary_precision` enabled in
    /// `capnagent-core`) preserves the original number text past the
    /// boundary. The v0.6 integer-domain rule in
    /// `caveat_dsl::apply_op` now sees Integer literal vs Float arg
    /// and rejects.
    ///
    /// **Usage.** Wherever you have the original JSON — typically the
    /// raw HTTP request body, a webhook payload, an LLM tool-call as
    /// emitted by the model — pass it directly:
    ///
    /// ```js
    /// const ctxJson = req.rawBody;   // NOT req.body parsed by Express
    /// const receipt = verifier.verifyWithContextJson(cap, ctxJson, auditor);
    /// ```
    ///
    /// If you've already `JSON.parse`-d the data, the precision is
    /// already gone — use the default `verifyWithContext` for that
    /// case, and apply the documented `_cents` mitigation against the
    /// f64-collapse class.
    ///
    /// Throws on `VerifyError::Chain` / `VerifyError::Audit` / invalid
    /// JSON / missing required ctx fields. Caveat denials come back on
    /// the returned `Receipt`'s `outcome` field, same as
    /// `verifyWithContext`.
    #[wasm_bindgen(js_name = "verifyWithContextJson")]
    pub fn verify_with_context_json(
        &self,
        cap: &Capability,
        ctx_json: &str,
        auditor: &Auditor,
    ) -> Result<JsValue, JsError> {
        let ctx_native = decode_context_from_json_str(ctx_json)?;
        let receipt = self
            .inner()?
            .verify_with_context(&cap.0, &ctx_native, &auditor.0)
            .map_err(|e| JsError::new(&e.to_string()))?;
        to_js(&receipt).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Four-gate pipeline (chain → proof → revocation → caveats) for
    /// hok-bound capabilities. `proof` is the raw 64-byte ed25519
    /// signature the holder produced over `challenge`. `challenge` is
    /// arbitrary bytes (use [`pop_challenge_for`] for the documented
    /// default).
    ///
    /// If a [`NonceStore`] has been installed via `withNonceStore`,
    /// `sha256(proof_bytes)` is checked against the store between the
    /// proof and revocation gates; replays surface as
    /// `Outcome::Denied { reason: "proof replay detected" }` — they
    /// are NOT thrown.
    ///
    /// Throws on `VerifyError::Chain` (forged token) and
    /// `VerifyError::Audit`, same shape as `verifyWithContext`. A
    /// proof failure surfaces as `Outcome::Denied` on the returned
    /// receipt with reason `"holder-of-key proof failed"` — it is NOT
    /// thrown. See `DESIGN.md` §11 for the rationale.
    ///
    /// Length validation: `proof.len() == 64` is enforced here and
    /// surfaced as a JS-side `Error` rather than a Rust panic. The
    /// challenge length is unconstrained.
    #[wasm_bindgen(js_name = "verifyWithProof")]
    pub fn verify_with_proof(
        &self,
        cap: &Capability,
        ctx: JsValue,
        auditor: &Auditor,
        challenge: &[u8],
        proof: &[u8],
    ) -> Result<JsValue, JsError> {
        if proof.len() != 64 {
            return Err(JsError::new(&format!(
                "ed25519 proofs are exactly 64 bytes; got {}",
                proof.len()
            )));
        }
        let ctx_native = decode_context(ctx)?;
        let receipt = self
            .inner()?
            .verify_with_proof(&cap.0, &ctx_native, &auditor.0, challenge, proof)
            .map_err(|e| JsError::new(&e.to_string()))?;
        to_js(&receipt).map_err(|e| JsError::new(&e.to_string()))
    }
}

impl Verifier {
    fn inner(&self) -> Result<&core::Verifier, JsError> {
        self.inner
            .as_ref()
            .ok_or_else(|| JsError::new("Verifier already consumed by a builder call"))
    }
}

// ---------------------------------------------------------------------------
// NonceStore — replay protection backing store.
// ---------------------------------------------------------------------------

/// JS-visible handle on an in-memory [`InMemoryNonceStore`]. Construct
/// one and pass it to [`Verifier::with_nonce_store`] to enable replay
/// protection on `verifyWithProof`. The handle stays inspectable from
/// JS (`size`, `isEmpty`, `clear`) even after install — both this
/// wrapper and the verifier hold an `Arc` of the same store.
///
/// Production deployments that need cross-process / cross-restart
/// replay resistance should provide their own `NonceStore` impl in
/// Rust (Redis, Postgres, Trillian) and depend on `capnagent-core`
/// directly.
#[wasm_bindgen]
pub struct NonceStore(Arc<InMemoryNonceStore>);

#[wasm_bindgen]
impl NonceStore {
    /// Construct a fresh, empty in-memory nonce store.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(Arc::new(InMemoryNonceStore::new()))
    }

    /// Number of entries currently held (including expired ones that
    /// have not yet been overwritten). Useful for tests and metrics.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Whether the store has zero entries.
    #[wasm_bindgen(getter, js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Drop all recorded nonces. Useful for tests; production callers
    /// rarely want this.
    pub fn clear(&self) {
        self.0.clear();
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RevocationList + Revoker — issuer-side capability revocation.
// ---------------------------------------------------------------------------

/// A point-in-time, HMAC-signed list of revoked capability
/// identifiers. Issued by [`Revoker::publish`]; installed on a
/// [`Verifier`] via `withRevocationList(...)`.
///
/// Wire-portable: `serialize()` returns base64 bytes the issuer can
/// send to verifiers; `parse(token)` decodes them. The signature is
/// part of the wire format — verifiers re-check it at install time.
///
/// See `docs/DESIGN.md` §10 for the design rationale.
#[wasm_bindgen]
pub struct RevocationList(CoreRevocationList);

#[wasm_bindgen]
impl RevocationList {
    /// Decode a previously-serialized revocation list from its
    /// base64 wire form. Throws `Error` on malformed input.
    pub fn parse(token: &str) -> Result<RevocationList, JsError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let bytes = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|e| JsError::new(&format!("base64 decode: {e}")))?;
        let inner: CoreRevocationList = serde_json::from_slice(&bytes)
            .map_err(|e| JsError::new(&format!("revocation list parse: {e}")))?;
        Ok(RevocationList(inner))
    }

    /// Encode this list as a URL-safe, unpadded base64 string.
    /// Round-trips through `parse`. The signature is included in the
    /// wire format.
    pub fn serialize(&self) -> Result<String, JsError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let bytes = serde_json::to_vec(&self.0)
            .map_err(|e| JsError::new(&format!("revocation list serialize: {e}")))?;
        Ok(URL_SAFE_NO_PAD.encode(&bytes))
    }

    /// Whether `identifier` appears in the revocation list.
    /// O(log n) — the underlying `revoked` vec is required to be sorted.
    pub fn contains(&self, identifier: &str) -> bool {
        self.0.contains(identifier)
    }

    /// Number of revoked identifiers.
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Whether the list has zero revocations.
    #[wasm_bindgen(getter, js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Wall-clock the list was published, milliseconds since UNIX
    /// epoch. Verifiers may reject lists older than a configured
    /// staleness window; that policy lives at the caller, not here.
    #[wasm_bindgen(getter, js_name = "issuedAtMs")]
    pub fn issued_at_ms(&self) -> u64 {
        self.0.issued_at_ms
    }
}

/// Issuer-side helper for building and signing revocation lists.
/// Holds the root key plus the in-memory set of revoked identifiers.
/// Call `publish(issuedAtMs)` to mint a fresh signed snapshot
/// suitable for handing to a [`Verifier`].
#[wasm_bindgen]
pub struct Revoker(CoreRevoker);

#[wasm_bindgen]
impl Revoker {
    /// Construct a Revoker from the same root key the Issuer uses.
    #[wasm_bindgen(constructor)]
    pub fn new(root_key: &[u8]) -> Self {
        Self(CoreRevoker::new(root_key))
    }

    /// Mark a capability identifier as revoked. Idempotent — calling
    /// `revoke("buy-123")` twice is the same as once.
    pub fn revoke(&mut self, identifier: String) {
        self.0.revoke(identifier);
    }

    /// Remove an identifier from the revoked set. Returns `true` if
    /// the entry was present and removed, `false` otherwise. Use
    /// sparingly — "unrevoke" makes auditors nervous and is not
    /// always supported by downstream policy.
    pub fn unrevoke(&mut self, identifier: &str) -> bool {
        self.0.unrevoke(identifier)
    }

    /// Number of currently-revoked identifiers held by the Revoker
    /// (NOT the published-list count, which is fixed at publish time).
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Whether the Revoker has any entries.
    #[wasm_bindgen(getter, js_name = "isEmpty")]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Snapshot the current revoked set into a signed [`RevocationList`].
    /// Pass `issuedAtMs` from a clock authority you trust (NOT
    /// `Date.now()` from inside the verifier — the issuer's clock is
    /// the right authority for "when was this list published").
    pub fn publish(&self, issued_at_ms: u64) -> RevocationList {
        RevocationList(self.0.publish(issued_at_ms))
    }
}

// ---------------------------------------------------------------------------
// pop_challenge_for — default proof-of-possession challenge derivation.
// ---------------------------------------------------------------------------

/// Default challenge derivation for proof-of-possession: the SHA-256 of
/// canonical-JSON `{ id, tool, args_hash, now_ms }`. Both holder and
/// verifier must compute this bytewise-identically — that's the whole
/// point. Returns 32 bytes.
///
/// Callers free to pass their own challenge bytes to
/// [`Verifier::verify_with_proof`] if they want a different policy
/// (e.g. include a server-side nonce). This function is a default,
/// not a requirement.
#[wasm_bindgen(js_name = "popChallengeFor")]
pub fn pop_challenge_for(cap: &Capability, ctx: JsValue) -> Result<Vec<u8>, JsError> {
    let ctx_native = decode_context(ctx)?;
    Ok(core::pop_challenge_for(&cap.0, &ctx_native))
}

// ---------------------------------------------------------------------------
// Auditor
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct Auditor(core::Auditor);

#[wasm_bindgen]
impl Auditor {
    /// Construct an Auditor from a raw key.
    ///
    /// Throws a JS-side `Error` if `key.length < 16` (closes purple-team
    /// angle B.3: a misconfigured deployment that derived its audit key
    /// from an unset env var would silently produce forgeable receipts).
    /// Production callers should pass at least 32 bytes from a CSPRNG.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Result<Auditor, JsError> {
        if key.len() < core::MIN_AUDIT_KEY_LEN {
            return Err(JsError::new(&format!(
                "Auditor key too short: got {} bytes, minimum is {}",
                key.len(),
                core::MIN_AUDIT_KEY_LEN
            )));
        }
        Ok(Self(core::Auditor::new(key)))
    }

    /// Recompute the receipt signature and reject on mismatch.
    pub fn verify(&self, receipt: JsValue) -> Result<(), JsError> {
        let receipt_native: core::Receipt =
            js_to(receipt).map_err(|e| JsError::new(&e.to_string()))?;
        self.0
            .verify(&receipt_native)
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Context decoding
// ---------------------------------------------------------------------------

/// JS-side `Context` shape (mirrored in the TS .d.ts at package level):
///
/// ```ts
/// type Context = {
///   nowMs?: number;          // millis since epoch; defaults to Date.now()
///   caller: string;
///   tool: string;
///   args: unknown;            // arbitrary JSON value
///   env?: Record<string, string>;
/// };
/// ```
///
/// NOTE: numeric values inside `args` go through JS's f64 JSON parser
/// before crossing the WASM boundary, so sub-ulp precision is lost.
/// For full A.1 protection, pass the raw JSON source through
/// `verifyWithContextJson` instead. See that method's doc-comment.
fn decode_context(value: JsValue) -> Result<core::Context, JsError> {
    let parsed: CtxIn = js_to(value).map_err(|e| JsError::new(&e.to_string()))?;
    ctx_in_to_core(parsed)
}

/// v0.6.1: decode the context from a raw JSON string. Used by
/// `verifyWithContextJson` / `verifyWithProofJson` so that
/// `serde_json::from_str` (which honours `arbitrary_precision` in
/// `capnagent-core`'s deps) preserves the original number source
/// text past the parse boundary. The default `decode_context` path
/// receives a JS object that has ALREADY been through JS's f64
/// JSON parser, so the source text is gone before we see it.
fn decode_context_from_json_str(s: &str) -> Result<core::Context, JsError> {
    let parsed: CtxIn =
        serde_json::from_str(s).map_err(|e| JsError::new(&format!("invalid context JSON: {e}")))?;
    ctx_in_to_core(parsed)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CtxIn {
    now_ms: Option<u64>,
    caller: String,
    tool: String,
    args: serde_json::Value,
    env: Option<std::collections::HashMap<String, String>>,
}

fn ctx_in_to_core(parsed: CtxIn) -> Result<core::Context, JsError> {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let now = parsed
        .now_ms
        .map(|ms| UNIX_EPOCH + Duration::from_millis(ms))
        .unwrap_or_else(SystemTime::now);

    Ok(core::Context {
        now,
        caller: parsed.caller,
        tool: parsed.tool,
        args: parsed.args,
        env: parsed.env.unwrap_or_default(),
    })
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    //! Round-trip tests for the WASM boundary, run on wasm32 via
    //! `wasm-pack test --node`. They exercise the chain-only `Verifier::verify`
    //! (no `JsValue`), the caveat/attenuate DSL validation, the no-caveat and
    //! holder-of-key guards, and serialize → parse. They are gated to wasm32
    //! because constructing a `JsError` aborts off-wasm, so a native
    //! `cargo test` cannot run them (and simply skips this module).
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    const KEY: &[u8] = b"capnagent-wasm-test-root-key-001";

    /// Unwrap a `Result<_, JsError>` without depending on `JsError: Debug`
    /// (it doesn't implement it) or tripping clippy's `ok_expect` lint.
    fn ok<T>(r: Result<T, JsError>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(_) => panic!("{what} should have succeeded"),
        }
    }

    #[wasm_bindgen_test]
    fn issue_serialize_parse_verify_round_trip() {
        let builder = ok(
            Issuer::from_key(KEY)
                .issue("buy".into())
                .caveat("tool == \"buy\"".into()),
            "valid caveat",
        );
        let cap = ok(builder.build(), "build with one caveat");
        assert_eq!(cap.identifier(), "buy");

        let token = cap.serialize();
        let parsed = ok(Capability::parse(&token), "token round-trips");
        assert_eq!(parsed.identifier(), "buy");

        // Chain verification passes with the issuing key …
        assert!(Verifier::new(KEY).verify(&parsed).is_ok());
        // … and fails under a different root key (forged / wrong issuer).
        assert!(Verifier::new(b"a-totally-different-32-byte-key!")
            .verify(&parsed)
            .is_err());
    }

    #[wasm_bindgen_test]
    fn build_rejects_zero_caveats() {
        // Angle C.5: a no-caveat token is god-mode authorization.
        let r = Issuer::from_key(KEY).issue("buy".into()).build();
        assert!(
            r.is_err(),
            "build() must reject a capability with no caveats"
        );
    }

    #[wasm_bindgen_test]
    fn caveat_rejects_unparseable_predicate() {
        // Angle B.2: an unparseable predicate must throw, not chain silently.
        let r = Issuer::from_key(KEY)
            .issue("buy".into())
            .caveat("%%% not a predicate %%%".into());
        assert!(r.is_err());
    }

    #[wasm_bindgen_test]
    fn attenuate_validates_and_still_verifies() {
        let cap = ok(
            ok(
                Issuer::from_key(KEY)
                    .issue("buy".into())
                    .caveat("tool == \"buy\"".into()),
                "caveat",
            )
            .build(),
            "build",
        );
        let token = cap.serialize();

        // An unparseable attenuation predicate is rejected (angle B.2).
        let parsed = ok(Capability::parse(&token), "parse");
        assert!(parsed.attenuate("$$$ bogus $$$".into()).is_err());

        // A valid attenuation narrows the cap and still verifies under the key.
        let parsed = ok(Capability::parse(&token), "parse");
        let narrowed = ok(
            parsed.attenuate("arg.amount <= 50_usd".into()),
            "valid attenuation",
        );
        assert!(Verifier::new(KEY).verify(&narrowed).is_ok());
    }

    #[wasm_bindgen_test]
    fn holder_of_key_validates_length_and_round_trips() {
        // Wrong-length pubkey is rejected.
        let bad = Issuer::from_key(KEY)
            .issue("buy".into())
            .holder_of_key(&[1, 2, 3]);
        assert!(bad.is_err(), "ed25519 keys must be exactly 32 bytes");

        // A 32-byte key binds and survives serialize → parse.
        let pubkey = [7u8; 32];
        let builder = ok(
            Issuer::from_key(KEY)
                .issue("buy".into())
                .holder_of_key(&pubkey),
            "32-byte key accepted",
        );
        let builder = ok(builder.caveat("tool == \"buy\"".into()), "caveat");
        let cap = ok(builder.build(), "build");
        let parsed = ok(Capability::parse(&cap.serialize()), "parse");
        assert_eq!(parsed.holder_of_key().as_deref(), Some(&pubkey[..]));
    }

    #[wasm_bindgen_test]
    fn parse_rejects_malformed_token() {
        assert!(Capability::parse("not-a-valid-token").is_err());
    }

    // ── verify pipeline (B3): exercise the full verify surface at the WASM
    // boundary, not just the chain check ──────────────────────────────────

    const AUDIT_KEY: &[u8] = b"capnagent-wasm-test-audit-key-001";
    const CTX_IN_SCOPE: &str =
        r#"{"caller":"x","tool":"checkout.purchase","args":{},"nowMs":1700000000000}"#;
    const CTX_OUT_OF_SCOPE: &str =
        r#"{"caller":"x","tool":"bank.wire","args":{},"nowMs":1700000000000}"#;

    /// Pull `outcome.kind` out of a JsValue receipt.
    fn outcome_kind(receipt: &wasm_bindgen::JsValue) -> String {
        let v: serde_json::Value =
            serde_wasm_bindgen::from_value(receipt.clone()).expect("receipt → json");
        v["outcome"]["kind"]
            .as_str()
            .expect("receipt.outcome.kind")
            .to_string()
    }

    fn scoped_cap(identifier: &str) -> Capability {
        ok(
            ok(
                Issuer::from_key(KEY)
                    .issue(identifier.into())
                    .caveat("tool == \"checkout.purchase\"".into()),
                "caveat",
            )
            .build(),
            "build",
        )
    }

    #[wasm_bindgen_test]
    fn verify_with_context_allows_in_scope_and_denies_out_of_scope() {
        let cap = scoped_cap("checkout");
        let auditor = ok(Auditor::new(AUDIT_KEY), "auditor");
        let v = Verifier::new(KEY);

        let allowed = ok(
            v.verify_with_context_json(&cap, CTX_IN_SCOPE, &auditor),
            "verify in-scope",
        );
        assert_eq!(outcome_kind(&allowed), "allowed");

        let denied = ok(
            v.verify_with_context_json(&cap, CTX_OUT_OF_SCOPE, &auditor),
            "verify out-of-scope",
        );
        assert_eq!(outcome_kind(&denied), "denied");
    }

    #[wasm_bindgen_test]
    fn revoked_capability_is_denied_after_installing_the_list() {
        let cap = scoped_cap("buy-123");
        let auditor = ok(Auditor::new(AUDIT_KEY), "auditor");

        // Not revoked yet → allowed.
        let v = Verifier::new(KEY);
        assert_eq!(
            outcome_kind(&ok(
                v.verify_with_context_json(&cap, CTX_IN_SCOPE, &auditor),
                "verify (not revoked)"
            )),
            "allowed"
        );

        // Issuer revokes the identifier and publishes a signed list.
        let mut revoker = Revoker::new(KEY);
        revoker.revoke("buy-123".into());
        let list = revoker.publish(1_700_000_000_000);

        // Verifier installs it → the same call is now denied.
        let mut v2 = Verifier::new(KEY);
        ok(v2.with_revocation_list(&list), "install revocation list");
        assert!(ok(v2.has_revocation_list(), "has_revocation_list"));
        assert_eq!(
            outcome_kind(&ok(
                v2.verify_with_context_json(&cap, CTX_IN_SCOPE, &auditor),
                "verify (revoked)"
            )),
            "denied"
        );
    }

    #[wasm_bindgen_test]
    fn revocation_list_signed_under_wrong_key_is_rejected() {
        let other_key = b"a-different-32-byte-root-key-here";
        let mut revoker = Revoker::new(other_key);
        revoker.revoke("buy-123".into());
        let forged = revoker.publish(1_700_000_000_000);

        let mut v = Verifier::new(KEY);
        assert!(
            v.with_revocation_list(&forged).is_err(),
            "a list signed under the wrong root key must not install"
        );
    }
}
