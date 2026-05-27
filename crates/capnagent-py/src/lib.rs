//! Python bindings for `capnagent-core`.
//!
//! Like `capnagent-wasm`, this is a thin translation layer over the
//! pure-Rust core. Everything load-bearing lives in `capnagent-core`;
//! this crate is just `#[pyclass]` shims plus error mapping plus
//! Python-friendly JSON conversion.
//!
//! Build via maturin:
//!
//! ```text
//! pip install maturin
//! cd crates/capnagent-py
//! maturin develop           # editable build into the active venv
//! maturin build --release   # produce a wheel under target/wheels/
//! ```
//!
//! Import in Python:
//!
//! ```python
//! from capnagent import Issuer, Verifier, Auditor
//! ```

#![allow(missing_docs)] // Each #[pyclass] is documented via Python __doc__.

use std::sync::Arc;

use capnagent_core as core;
use core::nonce_store::{InMemoryNonceStore, NonceStore as CoreNonceStore};
use core::revocation::{RevocationList as CoreRevocationList, Revoker as CoreRevoker};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

// ───────────────────────────────────────────────────────────────────
// Issuer
// ───────────────────────────────────────────────────────────────────

#[pyclass]
struct Issuer(core::Issuer);

#[pymethods]
impl Issuer {
    /// Construct an Issuer from a raw key. Production callers should
    /// pass at least 32 bytes from a CSPRNG (e.g. `os.urandom(32)`).
    #[staticmethod]
    fn from_key(key: &[u8]) -> Self {
        Self(core::Issuer::from_key(key))
    }

    /// Begin issuing a capability with the given identifier. Returns
    /// a `CapabilityBuilder` for chained caveat-attachment.
    fn issue(&self, identifier: String) -> CapabilityBuilder {
        CapabilityBuilder(Some(self.0.issue(identifier)))
    }
}

#[pyclass]
struct CapabilityBuilder(Option<core::CapabilityBuilder>);

#[pymethods]
impl CapabilityBuilder {
    /// Attach a caveat. Returns the builder for chaining.
    /// Raises `ValueError` if the predicate doesn't parse as caveat DSL.
    fn caveat(&mut self, predicate: String) -> PyResult<CapabilityBuilder> {
        core::caveat_dsl::parse(&predicate)
            .map_err(|e| PyValueError::new_err(format!("invalid caveat predicate: {e}")))?;
        let inner = self
            .0
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("CapabilityBuilder already consumed"))?;
        Ok(CapabilityBuilder(Some(inner.caveat(predicate))))
    }

    /// Bind this capability to an ed25519 public key (32 bytes). Must
    /// be called BEFORE any `.caveat()` — see `docs/DESIGN.md` §11.
    fn holder_of_key(&mut self, pubkey: &[u8]) -> PyResult<CapabilityBuilder> {
        if pubkey.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "ed25519 public keys are exactly 32 bytes; got {}",
                pubkey.len()
            )));
        }
        let inner = self
            .0
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("CapabilityBuilder already consumed"))?;
        Ok(CapabilityBuilder(Some(inner.holder_of_key(pubkey))))
    }

    /// Finalise. Raises `ValueError` if no caveats were attached (a
    /// no-caveat token is god-mode authorization — see angle C.5).
    fn build(&mut self) -> PyResult<Capability> {
        let inner = self
            .0
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("CapabilityBuilder already consumed"))?;
        if inner.caveat_count() == 0 {
            return Err(PyValueError::new_err(
                "Capability has zero caveats — a no-caveat token is god-mode authorization. \
                 Attach at least one caveat (e.g. `now <= @<expiry>`) before calling build(). \
                 See angle C.5.",
            ));
        }
        Ok(Capability(inner.build()))
    }
}

// ───────────────────────────────────────────────────────────────────
// Capability
// ───────────────────────────────────────────────────────────────────

#[pyclass]
struct Capability(core::Capability);

#[pymethods]
impl Capability {
    /// Decode a previously-serialised token. Raises `ValueError` on
    /// malformed input.
    #[staticmethod]
    fn parse(token: &str) -> PyResult<Capability> {
        core::Capability::parse(token)
            .map(Capability)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Encode the capability as a URL-safe, unpadded base64 string.
    fn serialize(&self) -> String {
        self.0.serialize()
    }

    /// Append a caveat, producing a strictly narrower capability.
    /// Raises `ValueError` if the predicate doesn't parse.
    fn attenuate(&self, predicate: String) -> PyResult<Capability> {
        core::caveat_dsl::parse(&predicate)
            .map_err(|e| PyValueError::new_err(format!("invalid attenuation predicate: {e}")))?;
        Ok(Capability(self.0.clone().attenuate(predicate)))
    }

    #[getter]
    fn identifier(&self) -> String {
        self.0.identifier.clone()
    }

    #[getter]
    fn holder_of_key(&self) -> Option<Vec<u8>> {
        self.0.holder_of_key.clone()
    }
}

// ───────────────────────────────────────────────────────────────────
// Auditor
// ───────────────────────────────────────────────────────────────────

#[pyclass]
struct Auditor(core::Auditor);

#[pymethods]
impl Auditor {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        if key.is_empty() {
            return Err(PyValueError::new_err(
                "Auditor key must be non-empty (angle B.3: zero-byte key produces forgeable receipts)",
            ));
        }
        Ok(Self(core::Auditor::new(key)))
    }

    /// Verify a receipt's audit signature.
    ///
    /// v0.7.1 — real round-trip via `Receipt::from_json` on the Rust
    /// core. Failure modes:
    ///
    /// - Malformed JSON / missing required fields → `ValueError`
    /// - HMAC signature mismatch (forged or tampered receipt) → `ValueError`
    /// - Unsupported schema version → `ValueError`
    /// - Returns silently on success.
    ///
    /// This is the load-bearing check for *externally-received*
    /// receipts (e.g. a receipt that arrived over the wire from
    /// another service that holds the same audit key). For
    /// receipts you just produced via `verifier.verify_with_context`,
    /// the signature is already valid by construction.
    fn verify(&self, py: Python<'_>, receipt_json: &str) -> PyResult<()> {
        let _ = py;
        let receipt = core::Receipt::from_json(receipt_json)
            .map_err(|e| PyValueError::new_err(format!("invalid receipt JSON: {e}")))?;
        self.0
            .verify(&receipt)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

// ───────────────────────────────────────────────────────────────────
// Verifier
// ───────────────────────────────────────────────────────────────────

/// Held as `Option<core::Verifier>` (plus a retained `root_key`) so the
/// consuming-style builder methods (`with_nonce_store`, `with_revocation_list`,
/// …) can use the `take()` pattern, exactly like the WASM crate's wrapper. A
/// failed `with_revocation_list` (bad signature) leaves the handle usable for
/// retry rather than nulling it.
#[pyclass]
struct Verifier {
    inner: Option<core::Verifier>,
    root_key: Vec<u8>,
}

#[pymethods]
impl Verifier {
    #[new]
    fn new(key: &[u8]) -> Self {
        Self {
            inner: Some(core::Verifier::new(key)),
            root_key: key.to_vec(),
        }
    }

    /// Full pipeline: chain check, caveat evaluation, audit signing.
    /// Returns the receipt as a JSON string. Caveat denials surface
    /// as `outcome.kind == "denied"` on the receipt — they are NOT
    /// raised. Chain / audit failures DO raise `ValueError`.
    ///
    /// `ctx_json` is the context as a JSON STRING. v0.6.1 design
    /// note: passing the raw JSON (rather than dict.dumps(dict.loads(...)))
    /// preserves number source text for the v0.6 integer-domain
    /// rule that closes A.1. From Python this is the natural shape
    /// — `json.dumps(ctx)` does NOT collapse f64 precision the way
    /// JavaScript's `JSON.parse` does, so Python callers get full
    /// A.1 protection by default.
    fn verify_with_context(
        &self,
        py: Python<'_>,
        cap: &Capability,
        ctx_json: &str,
        auditor: &Auditor,
    ) -> PyResult<String> {
        let _ = py;
        let parsed: CtxIn = serde_json::from_str(ctx_json)
            .map_err(|e| PyValueError::new_err(format!("invalid context JSON: {e}")))?;
        let ctx = ctx_in_to_core(parsed);
        let receipt = self
            .inner()?
            .verify_with_context(&cap.0, &ctx, &auditor.0)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        serde_json::to_string(&receipt)
            .map_err(|e| PyRuntimeError::new_err(format!("receipt serialization failed: {e}")))
    }

    /// Four-gate pipeline (chain → proof → revocation → caveats) for
    /// holder-of-key capabilities. `challenge` is arbitrary bytes (use
    /// [`pop_challenge_for`] for the documented default); `proof` is the raw
    /// 64-byte ed25519 signature the holder produced over `challenge`.
    ///
    /// With a [`NonceStore`] installed via `with_nonce_store`, replays surface
    /// as `outcome.kind == "denied"` with reason `"proof replay detected"` —
    /// NOT raised. A proof failure is likewise a denial, not a raise. Chain /
    /// audit failures DO raise `ValueError`.
    fn verify_with_proof(
        &self,
        cap: &Capability,
        ctx_json: &str,
        auditor: &Auditor,
        challenge: &[u8],
        proof: &[u8],
    ) -> PyResult<String> {
        if proof.len() != 64 {
            return Err(PyValueError::new_err(format!(
                "ed25519 proofs are exactly 64 bytes; got {}",
                proof.len()
            )));
        }
        let parsed: CtxIn = serde_json::from_str(ctx_json)
            .map_err(|e| PyValueError::new_err(format!("invalid context JSON: {e}")))?;
        let ctx = ctx_in_to_core(parsed);
        let receipt = self
            .inner()?
            .verify_with_proof(&cap.0, &ctx, &auditor.0, challenge, proof)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        serde_json::to_string(&receipt)
            .map_err(|e| PyRuntimeError::new_err(format!("receipt serialization failed: {e}")))
    }

    /// Chain-only verification (no caveat eval, no audit). Raises `ValueError`
    /// if the HMAC chain doesn't match — i.e. the token was forged or broadened.
    fn verify(&self, cap: &Capability) -> PyResult<()> {
        self.inner()?
            .verify(&cap.0)
            .map(|_| ())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Install a [`NonceStore`] for replay protection on `verify_with_proof`.
    /// (No effect on `verify_with_context` — non-hok bearer tokens are reusable
    /// by design.) Mutates in place.
    fn with_nonce_store(&mut self, store: &NonceStore) -> PyResult<()> {
        let inner = self.take_inner()?;
        let dyn_store: Arc<dyn CoreNonceStore> = Arc::clone(&store.0) as _;
        self.inner = Some(inner.with_nonce_store(dyn_store));
        Ok(())
    }

    /// Override the per-nonce TTL in milliseconds (default 5 minutes). Only
    /// meaningful with `with_nonce_store`. Mutates in place.
    fn with_nonce_ttl_ms(&mut self, ttl_ms: u64) -> PyResult<()> {
        let inner = self.take_inner()?;
        self.inner = Some(inner.with_nonce_ttl_ms(ttl_ms));
        Ok(())
    }

    /// Install a signed [`RevocationList`]. The list's signature is verified
    /// against this verifier's root key BEFORE installation; a mismatch raises
    /// `ValueError` and leaves the verifier unchanged (retry-safe). Once
    /// installed, any capability whose identifier is on the list is denied
    /// (`"capability revoked: <id>"`) on both verify paths.
    fn with_revocation_list(&mut self, list: &RevocationList) -> PyResult<()> {
        // Pre-check the signature against the retained root key, leaving
        // `self.inner` untouched on failure.
        list.0.verify_signature(&self.root_key).map_err(|e| {
            PyValueError::new_err(format!("invalid revocation-list signature: {e}"))
        })?;
        let inner = self.take_inner()?;
        let installed = inner
            .with_revocation_list(list.0.clone())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.inner = Some(installed);
        Ok(())
    }

    /// Whether a revocation list is currently installed.
    fn has_revocation_list(&self) -> PyResult<bool> {
        Ok(self.inner()?.has_revocation_list())
    }

    /// Whether a nonce store is currently installed.
    fn has_nonce_store(&self) -> PyResult<bool> {
        Ok(self.inner()?.has_nonce_store())
    }
}

impl Verifier {
    fn inner(&self) -> PyResult<&core::Verifier> {
        self.inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Verifier already consumed by a builder call"))
    }

    fn take_inner(&mut self) -> PyResult<core::Verifier> {
        self.inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("Verifier already consumed by a builder call"))
    }
}

// ───────────────────────────────────────────────────────────────────
// NonceStore — replay-protection backing store
// ───────────────────────────────────────────────────────────────────

/// In-memory replay-protection store. Construct one and pass it to
/// `Verifier.with_nonce_store(...)` to enable replay detection on
/// `verify_with_proof`. Production deployments wanting cross-process /
/// cross-restart resistance should implement `NonceStore` in Rust against
/// `capnagent-core` (Redis, Postgres, …).
#[pyclass]
struct NonceStore(Arc<InMemoryNonceStore>);

#[pymethods]
impl NonceStore {
    #[new]
    fn new() -> Self {
        Self(Arc::new(InMemoryNonceStore::new()))
    }

    #[getter]
    fn size(&self) -> usize {
        self.0.len()
    }

    #[getter]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn clear(&self) {
        self.0.clear();
    }
}

// ───────────────────────────────────────────────────────────────────
// RevocationList + Revoker — issuer-side capability revocation
// ───────────────────────────────────────────────────────────────────

/// A point-in-time, HMAC-signed list of revoked capability identifiers.
/// Minted by `Revoker.publish(...)`, shipped to verifiers, installed via
/// `Verifier.with_revocation_list(...)`. `serialize()`/`parse()` round-trip
/// the URL-safe base64 wire form (signature included).
#[pyclass]
struct RevocationList(CoreRevocationList);

#[pymethods]
impl RevocationList {
    /// Decode a list from its base64 wire form. Raises `ValueError` on
    /// malformed input.
    #[staticmethod]
    fn parse(token: &str) -> PyResult<RevocationList> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let bytes = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|e| PyValueError::new_err(format!("base64 decode: {e}")))?;
        let inner: CoreRevocationList = serde_json::from_slice(&bytes)
            .map_err(|e| PyValueError::new_err(format!("revocation list parse: {e}")))?;
        Ok(RevocationList(inner))
    }

    /// Encode as a URL-safe, unpadded base64 string (round-trips through
    /// `parse`). The signature is part of the wire format.
    fn serialize(&self) -> PyResult<String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let bytes = serde_json::to_vec(&self.0)
            .map_err(|e| PyRuntimeError::new_err(format!("revocation list serialize: {e}")))?;
        Ok(URL_SAFE_NO_PAD.encode(&bytes))
    }

    /// Whether `identifier` appears in the list (O(log n); the set is sorted).
    fn contains(&self, identifier: &str) -> bool {
        self.0.contains(identifier)
    }

    #[getter]
    fn size(&self) -> usize {
        self.0.len()
    }

    #[getter]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[getter]
    fn issued_at_ms(&self) -> u64 {
        self.0.issued_at_ms
    }
}

/// Issuer-side helper for building and signing revocation lists. Construct
/// from the same root key the `Issuer` uses; `revoke()`/`unrevoke()` mutate
/// the set; `publish(issued_at_ms)` mints a signed [`RevocationList`].
#[pyclass]
struct Revoker(CoreRevoker);

#[pymethods]
impl Revoker {
    #[new]
    fn new(root_key: &[u8]) -> Self {
        Self(CoreRevoker::new(root_key))
    }

    /// Mark a capability identifier as revoked. Idempotent.
    fn revoke(&mut self, identifier: String) {
        self.0.revoke(identifier);
    }

    /// Remove an identifier from the revoked set. Returns `True` if it was
    /// present. Use sparingly.
    fn unrevoke(&mut self, identifier: &str) -> bool {
        self.0.unrevoke(identifier)
    }

    #[getter]
    fn size(&self) -> usize {
        self.0.len()
    }

    #[getter]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Snapshot the current revoked set into a signed [`RevocationList`].
    /// `issued_at_ms` should come from a clock authority you trust.
    fn publish(&self, issued_at_ms: u64) -> RevocationList {
        RevocationList(self.0.publish(issued_at_ms))
    }
}

/// Default proof-of-possession challenge for `Verifier.verify_with_proof`:
/// SHA-256 of canonical-JSON `{ id, tool, args_hash, now_ms }`. Returns 32
/// bytes. Both holder and verifier must compute it bytewise-identically.
#[pyfunction]
fn pop_challenge_for(cap: &Capability, ctx_json: &str) -> PyResult<Vec<u8>> {
    let parsed: CtxIn = serde_json::from_str(ctx_json)
        .map_err(|e| PyValueError::new_err(format!("invalid context JSON: {e}")))?;
    let ctx = ctx_in_to_core(parsed);
    Ok(core::pop_challenge_for(&cap.0, &ctx))
}

// ───────────────────────────────────────────────────────────────────
// Context decoding (matches the WASM crate's `CtxIn` / `ctx_in_to_core`)
// ───────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CtxIn {
    now_ms: Option<u64>,
    caller: String,
    tool: String,
    args: serde_json::Value,
    env: Option<std::collections::HashMap<String, String>>,
}

fn ctx_in_to_core(parsed: CtxIn) -> core::Context {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let now = parsed
        .now_ms
        .map(|ms| UNIX_EPOCH + Duration::from_millis(ms))
        .unwrap_or_else(SystemTime::now);

    core::Context {
        now,
        caller: parsed.caller,
        tool: parsed.tool,
        args: parsed.args,
        env: parsed.env.unwrap_or_default(),
    }
}

// ───────────────────────────────────────────────────────────────────
// Module entry point
// ───────────────────────────────────────────────────────────────────

/// Native PyO3 module — re-exported under the public `capnagent`
/// import name by the pure-Python shim in `python/capnagent/__init__.py`.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Issuer>()?;
    m.add_class::<CapabilityBuilder>()?;
    m.add_class::<Capability>()?;
    m.add_class::<Auditor>()?;
    m.add_class::<Verifier>()?;
    m.add_class::<NonceStore>()?;
    m.add_class::<RevocationList>()?;
    m.add_class::<Revoker>()?;
    m.add_function(pyo3::wrap_pyfunction!(pop_challenge_for, m)?)?;
    Ok(())
}

// Avoid an "unused" lint on PyDict in case future tests reach for it.
#[allow(dead_code)]
fn _silence_unused(_d: &Bound<'_, PyDict>) {}
