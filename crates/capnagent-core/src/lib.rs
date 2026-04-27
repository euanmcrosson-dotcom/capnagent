//! capnagent-core — capability-based authority tokens for AI agent tool calls.
//!
//! See `docs/DESIGN.md` at the repo root for the threat model and security argument.
//!
//! # Quick start
//!
//! ```no_run
//! use capnagent_core::{Issuer, Verifier};
//!
//! let secret = b"do-not-commit-this-key-to-git";
//! let cap = Issuer::from_key(secret)
//!     .issue("buy")
//!     .caveat("merchant == \"amazon.com\"")
//!     .caveat("amount <= 50_usd")
//!     .build();
//!
//! let token = cap.serialize();
//! let parsed = capnagent_core::Capability::parse(&token).unwrap();
//! Verifier::new(secret).verify(&parsed).unwrap();
//! ```

#![deny(unsafe_code)]

pub mod audit;
pub mod caveat_dsl;
pub mod context;
pub mod nonce_store;
pub mod revocation;

mod capability;
mod error;
mod hex;
mod issuer;
mod verifier;

pub use capability::{Capability, Caveat};
pub use error::{Error, Result};
pub use issuer::{CapabilityBuilder, Issuer};
pub use verifier::{pop_challenge_for, Verified, Verifier, VerifyError};

// Types from week-2 modules are re-exported here for caller convenience.
// The free functions on `caveat_dsl` (`parse`, `evaluate`, `matches`) are
// deliberately NOT re-exported — callers reach them through
// `capnagent_core::caveat_dsl::*` to keep the crate root narrow.
pub use audit::{
    AuditError, AuditLog, Auditor, ContextSummary, Outcome, Receipt, RECEIPT_SCHEMA_VERSION,
};
pub use caveat_dsl::{DslError, Predicate};
pub use context::{Context, ContextBuilder};
pub use nonce_store::{InMemoryNonceStore, NonceStore};
pub use revocation::{RevocationError, RevocationList, Revoker};
