//! Verification context — the facts the verifier controls at the moment of
//! a tool call.
//!
//! See `docs/DESIGN.md` §3 ("Verification context") and `docs/WEEK2_SPEC.md`
//! §2.1. The `Context` is what every caveat is evaluated against; it must be
//! built from facts the verifier observes, never from agent-supplied input.
//!
//! [`Context::args_hash`] produces a SHA-256 hex digest of a canonical-JSON
//! encoding of the args. That digest is the only thing the audit-log module
//! keeps to summarize args, so determinism here is load-bearing for
//! cross-process audit verification.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::SystemTime;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Verifier-controlled facts at the moment of a tool call.
///
/// All caveats from a [`crate::Capability`] are evaluated against an
/// instance of this struct. Build one with [`Context::builder`].
#[derive(Debug, Clone)]
pub struct Context {
    /// Wall-clock time the verifier observed when the call was made.
    pub now: SystemTime,
    /// Identifier for whoever is invoking the tool (e.g. `"agent:planner"`).
    pub caller: String,
    /// Tool name being called (e.g. `"http.post"`).
    pub tool: String,
    /// Tool arguments as JSON. May be any shape; nested lookup is the DSL's
    /// concern, not this module's.
    pub args: Value,
    /// Environment facts the verifier wants caveats to be able to read
    /// (e.g. `region`, `tenant`).
    pub env: HashMap<String, String>,
}

impl Context {
    /// Begin building a new [`Context`] with the documented defaults.
    #[must_use]
    pub fn builder() -> ContextBuilder {
        ContextBuilder::default()
    }

    /// SHA-256 hex digest of the canonical-JSON encoding of [`Self::args`].
    ///
    /// Canonical-JSON here means: object keys sorted lexicographically at
    /// every level of nesting, no whitespace, UTF-8. Numbers are emitted in
    /// the form [`serde_json::Number`] produces them — no normalization
    /// beyond what `serde_json` itself does. Arrays preserve their order
    /// (it is part of the value's identity).
    ///
    /// The digest is lower-case hex, no prefix or separators, 64 chars long.
    /// This function is deterministic by contract: the audit module relies
    /// on it producing the same digest across processes for the same input.
    #[must_use]
    pub fn args_hash(&self) -> String {
        let mut canonical = String::new();
        write_canonical(&self.args, &mut canonical);

        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();

        let mut hex = String::with_capacity(digest.len() * 2);
        for b in digest {
            // Writing to a `String` cannot fail; the `expect` documents that
            // and lets us avoid `unwrap_or_default` swallowing the invariant.
            write!(hex, "{b:02x}").expect("writing hex into a String is infallible");
        }
        hex
    }
}

/// Builder for [`Context`].
///
/// Defaults: `now = SystemTime::now()`, `caller = ""`, `tool = ""`,
/// `args = Value::Null`, `env = empty`. Each setter consumes and returns
/// `self` so calls can be chained; [`ContextBuilder::env`] may be called
/// repeatedly to insert multiple keys.
pub struct ContextBuilder {
    now: SystemTime,
    caller: String,
    tool: String,
    args: Value,
    env: HashMap<String, String>,
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self {
            now: SystemTime::now(),
            caller: String::new(),
            tool: String::new(),
            args: Value::Null,
            env: HashMap::new(),
        }
    }
}

impl ContextBuilder {
    /// Override the wall-clock time the verifier should treat as "now".
    #[must_use]
    pub fn now(mut self, t: SystemTime) -> Self {
        self.now = t;
        self
    }

    /// Set the caller identifier (e.g. `"agent:planner"`).
    #[must_use]
    pub fn caller(mut self, s: impl Into<String>) -> Self {
        self.caller = s.into();
        self
    }

    /// Set the tool name (e.g. `"http.post"`).
    #[must_use]
    pub fn tool(mut self, s: impl Into<String>) -> Self {
        self.tool = s.into();
        self
    }

    /// Set the tool arguments. Replaces any previously-set args.
    #[must_use]
    pub fn args(mut self, v: Value) -> Self {
        self.args = v;
        self
    }

    /// Insert one entry into the environment map. May be called repeatedly;
    /// inserting the same key twice keeps the last value.
    #[must_use]
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    /// Finalize the builder into a [`Context`].
    #[must_use]
    pub fn build(self) -> Context {
        Context {
            now: self.now,
            caller: self.caller,
            tool: self.tool,
            args: self.args,
            env: self.env,
        }
    }
}

/// Serialize a [`serde_json::Value`] to canonical-JSON, appending to `out`.
///
/// Canonical-JSON rules used here:
/// 1. Objects: keys sorted lexicographically. Rust's default `String`
///    ordering is byte-wise, which matches lexicographic order on the
///    UTF-8 byte sequences.
/// 2. No whitespace anywhere — neither between tokens nor inside arrays /
///    objects.
/// 3. Strings use [`serde_json::to_string`], which produces a properly
///    escaped, double-quoted JSON string with no whitespace.
/// 4. Numbers use [`serde_json::Number`]'s display form. We do not
///    normalize: whatever textual representation `serde_json` chose at parse
///    time is what we hash. (Without the `arbitrary_precision` feature, the
///    original textual form is lost on parse anyway; this is the closest
///    approximation that still round-trips through serde_json.)
/// 5. Arrays preserve their input order — that is part of the value's
///    identity in JSON.
///
/// We walk the tree by hand instead of calling `serde_json::to_string` on
/// the whole value because `serde_json` emits objects in whatever order the
/// inner `Map` enumerates, which is not always sorted (depends on the
/// `preserve_order` feature). Doing our own sort is the only way to be
/// sure the output is canonical.
fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            // `serde_json::to_string` on a `&str` produces an escaped,
            // double-quoted JSON string with no whitespace. Infallible for
            // a string value.
            let encoded = serde_json::to_string(s).expect("string serialization is infallible");
            out.push_str(&encoded);
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort keys so we walk the object in canonical order regardless
            // of how `serde_json` happens to enumerate them internally.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let encoded_key =
                    serde_json::to_string(*k).expect("string serialization is infallible");
                out.push_str(&encoded_key);
                out.push(':');
                // Direct indexing is safe — `k` came from `map.keys()`.
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
    }
}
