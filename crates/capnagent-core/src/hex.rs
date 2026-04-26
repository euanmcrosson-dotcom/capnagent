//! Lower-case hexadecimal encoding used by `capability.rs` and `audit.rs`
//! when serializing signature bytes into JSON.
//!
//! Pulled out into its own module so a future format change, lint fix, or
//! constant-time-decoder hardening only needs to land in one place.
//!
//! Use the [`serde_with`] submodule with `#[serde(with = "...")]`:
//!
//! ```ignore
//! #[serde(with = "crate::hex::serde_with")]
//! pub signature: Vec<u8>,
//! ```

/// Encode bytes as lower-case hex, no prefix or separators.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode lower-case or upper-case hex back into bytes. Returns an error
/// string suitable for `serde::de::Error::custom`.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Serde adapter — use as `#[serde(with = "crate::hex::serde_with")]`.
pub mod serde_with {
    use super::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize bytes as lower-case hex string.
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(bytes))
    }

    /// Deserialize a hex string back into bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).map_err(serde::de::Error::custom)
    }
}
