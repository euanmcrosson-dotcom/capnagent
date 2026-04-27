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

use capnagent_core as core;
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
    pub fn caveat(mut self, predicate: String) -> Self {
        let inner = self.0.take().expect("CapabilityBuilder already consumed");
        self.0 = Some(inner.caveat(predicate));
        self
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
    pub fn build(mut self) -> Capability {
        let inner = self.0.take().expect("CapabilityBuilder already consumed");
        Capability(inner.build())
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
    pub fn attenuate(self, predicate: String) -> Capability {
        Capability(self.0.attenuate(predicate))
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

#[wasm_bindgen]
pub struct Verifier(core::Verifier);

#[wasm_bindgen]
impl Verifier {
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Self {
        Self(core::Verifier::new(key))
    }

    /// Chain-only verification. Throws if the HMAC chain doesn't match.
    pub fn verify(&self, cap: &Capability) -> Result<(), JsError> {
        self.0
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
            .0
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
            .0
            .verify_with_proof(&cap.0, &ctx_native, &auditor.0, challenge, proof)
            .map_err(|e| JsError::new(&e.to_string()))?;
        to_js(&receipt).map_err(|e| JsError::new(&e.to_string()))
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
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8]) -> Self {
        Self(core::Auditor::new(key))
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
fn decode_context(value: JsValue) -> Result<core::Context, JsError> {
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CtxIn {
        now_ms: Option<u64>,
        caller: String,
        tool: String,
        args: serde_json::Value,
        env: Option<HashMap<String, String>>,
    }

    let parsed: CtxIn = js_to(value).map_err(|e| JsError::new(&e.to_string()))?;
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
