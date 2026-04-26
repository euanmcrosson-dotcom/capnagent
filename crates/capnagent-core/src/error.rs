//! Error types.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// All failure modes surfaced by capnagent-core.
#[derive(Debug, Error)]
pub enum Error {
    /// The token's bytes were not well-formed (bad base64 or bad JSON).
    #[error("invalid token format: {0}")]
    InvalidFormat(String),

    /// HMAC chain did not match. Either the key is wrong, the token was
    /// tampered with, or a caveat was added/removed/modified out of band.
    #[error("invalid signature")]
    InvalidSignature,

    /// Base64 decoding failed.
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),

    /// JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
