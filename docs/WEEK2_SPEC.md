# Week 2 — Build Spec (single source of truth for parallel work)

Three independent contributors are implementing the three parts of week 2 in
parallel. This doc locks the interfaces between them so they can ship without
seeing each other's code.

**Read first:** `README.md`, `docs/DESIGN.md`. This doc *only* covers week 2;
threat model and security argument live in DESIGN.md.

---

## File-ownership map (strict — do not edit outside your scope)

| Branch | Owner | Files they may create or edit |
|---|---|---|
| `feat/week2-context` | Terminal B | `crates/capnagent-core/src/context.rs` (new); `crates/capnagent-core/tests/context_tests.rs` (new) |
| `feat/week2-dsl` | Terminal A | `crates/capnagent-core/src/caveat_dsl.rs` (new); `crates/capnagent-core/tests/caveat_dsl_tests.rs` (new) |
| `feat/week2-audit` | Terminal C | `crates/capnagent-core/src/audit.rs` (new); `crates/capnagent-core/tests/audit_tests.rs` (new) |

**Hard rules:**

- Do **not** edit `lib.rs`, `capability.rs`, `issuer.rs`, `verifier.rs`,
  `error.rs`, `Cargo.toml` (workspace or crate), or any other file outside
  your scope. Module-wiring into `lib.rs` is done at merge time, not by you.
- Do **not** add new dependencies. Everything you need is already in
  `crates/capnagent-core/Cargo.toml`: `hmac`, `sha2`, `serde`, `serde_json`,
  `base64`, `subtle`, `thiserror`, plus `proptest` (dev). If you genuinely
  need something else, stop and write a comment in your branch explaining
  why; do not silently add it.
- All public APIs **must match** the contracts in §2 below. Internal types
  and helpers are yours.
- Tests run via `cargo test --test <your_test_file>`. Your branch must be
  green before you stop.

---

## §1. Goal of week 2

Make a capability *actually deny* something. Week 1 proved chain integrity;
week 2 makes capabilities load-bearing for authorization. Three parts:

1. A `Context` type the verifier can build from facts it controls.
2. A tiny caveat DSL that takes `(Caveat, Context)` and answers
   "does this predicate hold?".
3. An audit log that signs and persists every verification decision.

These three parts are merged in week 3 into a higher-level
`Verifier::verify_with_context(...)` flow. Week 2 ships the parts.

---

## §2. Locked type contracts

These are the public APIs each module must expose. Internal representations
and private helpers are at the implementer's discretion.

### 2.1 `context.rs` — owned by Terminal B

```rust
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct Context {
    pub now: SystemTime,
    pub caller: String,
    pub tool: String,
    pub args: serde_json::Value,
    pub env: HashMap<String, String>,
}

impl Context {
    pub fn builder() -> ContextBuilder;
    /// SHA-256 hex of the canonical-JSON encoding of `args`.
    /// Required by the audit module — must be deterministic.
    pub fn args_hash(&self) -> String;
}

pub struct ContextBuilder { /* private */ }

impl ContextBuilder {
    pub fn now(self, t: SystemTime) -> Self;
    pub fn caller(self, s: impl Into<String>) -> Self;
    pub fn tool(self, s: impl Into<String>) -> Self;
    pub fn args(self, v: serde_json::Value) -> Self;
    pub fn env(self, k: impl Into<String>, v: impl Into<String>) -> Self;
    /// Defaults: now = SystemTime::now(), caller = "", tool = "",
    /// args = Value::Null, env = empty.
    pub fn build(self) -> Context;
}
```

Canonical-JSON for `args_hash`: keys sorted lexicographically at every
object level, no whitespace, UTF-8. Numbers serialized in their original
form (no normalization). This determinism is load-bearing for the audit log.

### 2.2 `caveat_dsl.rs` — owned by Terminal A

```rust
use crate::capability::Caveat;
use crate::context::Context;

#[derive(Debug, thiserror::Error)]
pub enum DslError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unknown identifier: {0}")]
    UnknownIdent(String),
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },
    #[error("invalid regex: {0}")]
    Regex(String),
}

#[derive(Debug, Clone)]
pub struct Predicate { /* AST — your choice */ }

pub fn parse(predicate_text: &str) -> Result<Predicate, DslError>;
pub fn evaluate(p: &Predicate, ctx: &Context) -> Result<bool, DslError>;

/// Convenience: parse + evaluate in one shot.
pub fn matches(caveat: &Caveat, ctx: &Context) -> Result<bool, DslError>;
```

#### Grammar (full v0 BNF — do not extend)

```
predicate   ::= ident op value
ident       ::= bare_ident
              | bare_ident "." bare_ident          -- e.g. arg.url, env.region
bare_ident  ::= [a-zA-Z_][a-zA-Z0-9_]*
op          ::= "==" | "!=" | "<=" | ">=" | "<" | ">" | "matches"
value       ::= string | number | timestamp
string      ::= '"' (any char except '"' or '\') '"'
              | '"' '\\' ('n' | 't' | '\\' | '"') '"' '...'  (basic escapes)
number      ::= integer ("_" unit)?
integer     ::= "-"? [0-9]+
unit        ::= "usd" | "eur" | "gbp" | "cents" | "ms" | "s"
timestamp   ::= "@" rfc3339_string                 -- e.g. @2026-04-27T12:00:00Z
```

#### Reserved idents (looked up in `Context`)

| Ident | Type | Source |
|---|---|---|
| `now` | timestamp | `ctx.now` |
| `caller` | string | `ctx.caller` |
| `tool` | string | `ctx.tool` |
| `arg.<key>` or `arg.<key>.<key>...` | string or number | nested lookup in `ctx.args` |
| `env.<key>` | string | `ctx.env.get(key)` |

#### Type rules

- string: `==`, `!=`, `matches` only. `matches` RHS must be a string parsed as a regex (use the `regex` crate IF already in deps; otherwise implement a literal-substring match for v0 and document the limitation in a comment).
- number: `==`, `!=`, `<`, `<=`, `>`, `>=`. Units must match (no implicit conversion); mismatched units => `TypeMismatch`.
- timestamp: `==`, `!=`, `<`, `<=`, `>`, `>=`.

If the spec says the regex crate isn't in deps (it isn't), implement
`matches` as plain `contains` for v0 and put a `// TODO(v0.1): real regex`
comment. Do not add the dep.

#### Examples that must parse and evaluate correctly

```
amount <= 50_usd
merchant == "amazon.com"
now <= @2026-04-27T12:00:00Z
tool == "http.post"
arg.url matches "api.example.com"
caller != "agent:rogue"
```

### 2.3 `audit.rs` — owned by Terminal C

```rust
use std::path::Path;
use crate::capability::{Capability, Caveat};
use crate::context::Context;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Receipt {
    pub capability_identifier: String,
    pub caveats: Vec<Caveat>,
    pub context_summary: ContextSummary,
    pub outcome: Outcome,
    pub timestamp_ms: u64,
    #[serde(with = "hex_serde")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ContextSummary {
    pub caller: String,
    pub tool: String,
    pub args_hash: String,  // From Context::args_hash()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Outcome {
    Allowed,
    Denied { reason: String },
}

pub struct Auditor {
    /* HMAC-SHA256 key for v0; Ed25519 deferred to v0.1. */
}

impl Auditor {
    pub fn new(key: &[u8]) -> Self;

    /// Build and sign a receipt. The signature covers
    /// SHA-256(canonical-JSON of receipt with signature field omitted).
    pub fn sign(
        &self,
        cap: &Capability,
        ctx: &Context,
        outcome: Outcome,
    ) -> Receipt;

    /// Recompute and constant-time-compare the signature.
    pub fn verify(&self, receipt: &Receipt) -> Result<(), AuditError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Append-only newline-delimited JSON log on disk.
pub struct AuditLog { /* private */ }

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self>;
    pub fn append(&mut self, receipt: &Receipt) -> std::io::Result<()>;
    /// Iterate receipts from disk in append order.
    pub fn iter(path: impl AsRef<Path>) -> std::io::Result<Box<dyn Iterator<Item = Result<Receipt, AuditError>>>>;
}

mod hex_serde {
    // Same encoding as capability::hex_serde — duplicate here for
    // module independence. Lower-case hex, no prefix.
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> { /* ... */ }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> { /* ... */ }
}
```

Canonical-JSON for the signature: same rules as `Context::args_hash`
(sorted keys, no whitespace, UTF-8). The `signature` field is omitted from
the bytes that are signed (set to empty Vec or remove the field via a
helper struct — implementer's choice).

---

## §3. Definition of Done (per branch)

Each branch is done when **all** of the following hold:

1. The contracts in §2 compile.
2. Tests in `tests/<your_module>_tests.rs` cover at minimum:
   - The happy path (correct input → correct output).
   - At least three failure modes per public function.
   - Property tests (proptest) for any invariant that can be expressed
     statistically. Examples per module below.
3. `cargo test --test <your_test_file>` is green.
4. `cargo clippy -p capnagent-core --tests -- -D warnings` is clean.
5. `cargo fmt -p capnagent-core` produces no diff.
6. Your branch has 1–N small commits with clear messages. No "wip" or
   "fix" alone — each commit message says what changed and why.
7. You have **not** edited any file outside §1 ownership.

### Suggested test focus per module

**Context (B):** builder defaults; `args_hash` determinism (same input →
same hash; reordering keys → same hash; changing a value → different hash).

**DSL (A):** parser round-trip on all examples in §2.2; rejection of
malformed input (empty, unknown op, missing value, mismatched quotes);
type mismatch errors; happy-path evaluation against a hand-built `Context`;
timestamps before/equal/after `now`; numeric units mismatch yields
`TypeMismatch`.

**Audit (C):** sign+verify round-trip; bit-flipping any byte of the
signature breaks verify; tampering with any receipt field breaks verify;
log append/iterate round-trip; iterating an empty log returns no items.

---

## §4. Out of scope for week 2

Do not build, even if tempted:

- Wiring your module into `Verifier::verify_with_context` — that's the
  week-3 merge step.
- Any change to `lib.rs` module declarations.
- Distributed audit logs / streaming sinks.
- Receipt redaction or PII handling.
- Ed25519 receipt signatures (HMAC for v0; Ed25519 in v0.1).
- A real regex engine if `regex` isn't already in deps (use literal
  contains and TODO).
- Performance work. Correctness first.

---

## §5. Merge protocol (handled by lead, not by parallel branches)

After all three branches are green, the lead will:

1. Fast-forward `feat/week2-context` into `main`.
2. Rebase `feat/week2-dsl` onto `main`, resolve no conflicts (none expected).
3. Rebase `feat/week2-audit` onto `main`, same.
4. Add module declarations to `lib.rs` in a separate "wire week 2" commit.
5. Add the high-level `Verifier::verify_with_context` integration in the
   week-3 PR.

If any branch produced a conflict outside its ownership, the conflict is
the branch's fault and must be reverted there.
