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

mod capability;
mod error;
mod issuer;
mod verifier;

pub use capability::{Capability, Caveat};
pub use error::{Error, Result};
pub use issuer::{CapabilityBuilder, Issuer};
pub use verifier::{Verified, Verifier};
