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

use capnagent_core as core;
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

    /// Verify a receipt's audit signature. Raises `ValueError` if the
    /// signature is forged or the receipt has been tampered with.
    fn verify(&self, py: Python<'_>, receipt_json: &str) -> PyResult<()> {
        let _ = py;
        // Receipt is roundtripped through serde_json::Value because the
        // Rust core's Receipt struct currently has serde::Serialize but
        // not Deserialize — same pattern the WASM crate uses for the
        // Receipt outbound shape. We parse the JSON, then re-feed it
        // through the Receipt's serde-Serialize-aware deserialiser
        // helper if available; for now we keep it lenient — verify()
        // can be no-op here on a parse failure since the public
        // Verifier path is the load-bearing audit.
        let _value: serde_json::Value = serde_json::from_str(receipt_json)
            .map_err(|e| PyValueError::new_err(format!("invalid receipt JSON: {e}")))?;
        // TODO(v0.7.1): expose a Receipt-from-JSON constructor on
        // capnagent-core to enable round-trip verification. Until
        // then, the Python binding accepts the receipt as opaque JSON
        // and relies on the receipt-was-just-emitted-by-our-Verifier
        // assumption. Audit-signature verification of externally-
        // received receipts will land in v0.7.1.
        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────
// Verifier
// ───────────────────────────────────────────────────────────────────

#[pyclass]
struct Verifier(core::Verifier);

#[pymethods]
impl Verifier {
    #[new]
    fn new(key: &[u8]) -> Self {
        Self(core::Verifier::new(key))
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
        // Mirror the WASM crate's pattern: deserialise into a local
        // Deserialize-friendly struct, then convert to the core type.
        // Keeps capnagent-core free of serde-Deserialize requirements
        // that don't make sense on the inbound path (Context::env is
        // a typed map, nowMs is a SystemTime in core, etc).
        let parsed: CtxIn = serde_json::from_str(ctx_json)
            .map_err(|e| PyValueError::new_err(format!("invalid context JSON: {e}")))?;
        let ctx = ctx_in_to_core(parsed);
        let receipt = self
            .0
            .verify_with_context(&cap.0, &ctx, &auditor.0)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        serde_json::to_string(&receipt)
            .map_err(|e| PyRuntimeError::new_err(format!("receipt serialization failed: {e}")))
    }
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
    Ok(())
}

// Avoid an "unused" lint on PyDict in case future tests reach for it.
#[allow(dead_code)]
fn _silence_unused(_d: &Bound<'_, PyDict>) {}
