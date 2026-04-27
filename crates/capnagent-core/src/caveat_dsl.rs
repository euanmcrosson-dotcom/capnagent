//! Caveat DSL — parser and evaluator (v0).
//!
//! The DSL is deliberately tiny: a single predicate per caveat, of the form
//! `ident op value`. Each caveat string carried inside a [`Capability`] is one
//! such predicate. The verifier evaluates every caveat against a [`Context`]
//! built from facts the verifier (not the agent) controls.
//!
//! See `docs/WEEK2_SPEC.md` §2.2 for the locked grammar; see `docs/DESIGN.md`
//! §3 for the role this plays in the security argument. This module owns the
//! parser, the evaluator, and the public surface in §2.2 — nothing else.
//!
//! # Security stance
//!
//! This module is part of a security boundary. The parser is aggressively
//! strict: any malformed predicate is rejected, never silently coerced. When
//! the spec is ambiguous, we error out. The evaluator is similarly strict on
//! types — a unit mismatch or a missing context fact yields an error rather
//! than a silent `false`/`true`, so the caller can distinguish "denied" from
//! "could not decide".
//!
//! # Grammar (informally)
//!
//! ```text
//! predicate  ::= ident op value
//! ident      ::= bare_ident ("." bare_ident)*
//! op         ::= "==" | "!=" | "<=" | ">=" | "<" | ">" | "matches"
//! value      ::= string | number | timestamp
//! string     ::= '"' ( char | '\\' ('n'|'t'|'\\'|'"') )* '"'
//! number     ::= integer fractional? ("_" unit)?
//! integer    ::= "-"? digit+
//! fractional ::= "." digit+
//! unit       ::= usd | eur | gbp | cents | ms | s
//! timestamp  ::= "@" rfc3339
//! ```
//!
//! v0.1 widened `number` to accept decimals (`12.99`, `0.01`, `-1.5_usd`).
//! A leading dot (`.99`), a trailing dot (`12.`), or multiple dots
//! (`12.99.5`) are still rejected: an LLM emitting `12.99` for a price is
//! a real production case (the live shopping-agent demo surfaced it),
//! but those three malformed shapes are unambiguous typos that should
//! fail closed rather than be silently coerced.
//!
//! The §2.2 BNF lists `bare_ident "." bare_ident` (two segments). The reserved
//! idents table in the same section requires `arg.<key>.<key>...`, which is
//! more than two segments. We resolve the conflict by accepting one or more
//! `.` continuations syntactically and letting `resolve_ident` decide which
//! roots may dot-chain how deeply. The single-segment form (`now`, `caller`,
//! `tool`) and the multi-segment forms are both valid; everything else is an
//! `UnknownIdent` at evaluation time.

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capability::Caveat;
use crate::context::Context;

/// All failure modes surfaced by the DSL.
#[derive(Debug, thiserror::Error)]
pub enum DslError {
    /// The predicate text is not a syntactically valid `ident op value`.
    #[error("parse error: {0}")]
    Parse(String),
    /// The identifier did not match a reserved root or a known dotted path.
    #[error("unknown identifier: {0}")]
    UnknownIdent(String),
    /// The two sides of a comparison have incompatible types or units, or the
    /// operator is not defined for the operand types.
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        /// Type/unit the evaluator wanted on this side.
        expected: String,
        /// Type/unit it actually saw.
        got: String,
    },
    /// Reserved for a future real-regex implementation. Today, `matches` is a
    /// literal substring check (see `// TODO(v0.1): real regex`), so this
    /// variant is unused — but it stays in the public API per the §2.2
    /// contract so that a future regex backend can surface invalid patterns
    /// without a breaking change. The `allow(dead_code)` is needed because
    /// in the integration-test scaffold this module is included via `#[path]`
    /// (rather than re-exported by the lib), and the dead-code lint there
    /// can't see public consumers.
    #[allow(dead_code)]
    #[error("invalid regex: {0}")]
    Regex(String),
}

/// Parsed predicate. The internal representation is intentionally opaque so
/// we can change it without breaking callers.
#[derive(Debug, Clone)]
pub struct Predicate {
    ident: Ident,
    op: Op,
    value: Value,
}

#[derive(Debug, Clone)]
struct Ident {
    /// One or more segments, e.g. `["caller"]` or `["arg", "url"]`.
    segments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    Matches,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "==",
            Op::Neq => "!=",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Matches => "matches",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Usd,
    Eur,
    Gbp,
    Cents,
    Ms,
    S,
}

impl Unit {
    fn as_str(self) -> &'static str {
        match self {
            Unit::Usd => "usd",
            Unit::Eur => "eur",
            Unit::Gbp => "gbp",
            Unit::Cents => "cents",
            Unit::Ms => "ms",
            Unit::S => "s",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "usd" => Unit::Usd,
            "eur" => Unit::Eur,
            "gbp" => Unit::Gbp,
            "cents" => Unit::Cents,
            "ms" => Unit::Ms,
            "s" => Unit::S,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
enum Value {
    String(String),
    /// (value, unit). v0 carried `i64` here; v0.1 widened to `f64` so the
    /// DSL can accept decimal literals (`12.99`, `0.01`, `-1.5_usd`) and
    /// compare them against decimal JSON args without a type-mismatch
    /// denial. Integer literals (`50`) and integer JSON args still parse
    /// — they're stored as the corresponding `f64` (e.g. `50.0`). See
    /// `apply_op` for the equality-and-ordering policy.
    Number(f64, Option<Unit>),
    /// (seconds since unix epoch, sub-second nanos).
    Timestamp(i64, u32),
}

impl Value {
    fn type_name(&self) -> String {
        match self {
            Value::String(_) => "string".to_string(),
            Value::Number(_, None) => "number".to_string(),
            Value::Number(_, Some(u)) => format!("number({})", u.as_str()),
            Value::Timestamp(..) => "timestamp".to_string(),
        }
    }
}

/// Parse a single predicate. Whitespace between tokens (ident, op, value) is
/// allowed; whitespace inside a token (mid-identifier, mid-number, mid-quoted
/// string body, mid-timestamp) is not.
pub fn parse(predicate_text: &str) -> Result<Predicate, DslError> {
    let mut p = Parser::new(predicate_text);
    p.skip_ws();
    if p.peek().is_none() {
        return Err(DslError::Parse("empty predicate".into()));
    }
    let ident = p.parse_ident()?;
    p.skip_ws();
    let op = p.parse_op()?;
    p.skip_ws();
    let value = p.parse_value()?;
    p.skip_ws();
    if let Some(c) = p.peek() {
        return Err(DslError::Parse(format!(
            "trailing garbage starting with {c:?} at byte {}",
            p.pos
        )));
    }
    Ok(Predicate { ident, op, value })
}

/// Evaluate a parsed predicate against a verification context.
pub fn evaluate(p: &Predicate, ctx: &Context) -> Result<bool, DslError> {
    let lhs = resolve_ident(&p.ident, ctx)?;
    apply_op(p.op, &lhs, &p.value)
}

/// Convenience: parse + evaluate in one shot. The default path used by the
/// verifier in week 3.
pub fn matches(caveat: &Caveat, ctx: &Context) -> Result<bool, DslError> {
    let pred = parse(&caveat.predicate)?;
    evaluate(&pred, ctx)
}

// ───────────────────────── parser internals ─────────────────────────

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn parse_ident(&mut self) -> Result<Ident, DslError> {
        let mut segments = Vec::new();
        segments.push(self.parse_bare_ident()?);
        // Dotted continuation: no whitespace allowed around the '.'.
        while self.peek() == Some('.') {
            self.bump();
            segments.push(self.parse_bare_ident()?);
        }
        Ok(Ident { segments })
    }

    fn parse_bare_ident(&mut self) -> Result<String, DslError> {
        let mut s = String::new();
        match self.peek() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                self.bump();
                s.push(c);
            }
            Some(c) => {
                return Err(DslError::Parse(format!(
                    "expected identifier, found {c:?} at byte {}",
                    self.pos
                )))
            }
            None => return Err(DslError::Parse("expected identifier, found EOF".into())),
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                self.bump();
                s.push(c);
            } else {
                break;
            }
        }
        Ok(s)
    }

    fn parse_op(&mut self) -> Result<Op, DslError> {
        // Try the keyword `matches` first. It must be followed by a non-ident
        // character so we don't munch an identifier prefix.
        let rest = self.rest();
        if let Some(after) = rest.strip_prefix("matches") {
            let next = after.chars().next();
            let is_word_continuation = next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if !is_word_continuation {
                self.pos += "matches".len();
                return Ok(Op::Matches);
            }
        }

        let bytes = rest.as_bytes();
        if bytes.len() >= 2 {
            let two = &bytes[..2];
            let op = match two {
                b"==" => Some(Op::Eq),
                b"!=" => Some(Op::Neq),
                b"<=" => Some(Op::Le),
                b">=" => Some(Op::Ge),
                _ => None,
            };
            if let Some(op) = op {
                self.pos += 2;
                return Ok(op);
            }
        }
        if let Some(&first) = bytes.first() {
            let op = match first {
                b'<' => Some(Op::Lt),
                b'>' => Some(Op::Gt),
                _ => None,
            };
            if let Some(op) = op {
                self.pos += 1;
                return Ok(op);
            }
        }
        Err(DslError::Parse(format!(
            "expected operator (==, !=, <=, >=, <, >, matches) at byte {}",
            self.pos
        )))
    }

    fn parse_value(&mut self) -> Result<Value, DslError> {
        match self.peek() {
            Some('"') => self.parse_string().map(Value::String),
            Some('@') => self.parse_timestamp(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            Some(c) => Err(DslError::Parse(format!(
                "expected value (string, number, or timestamp), found {c:?} at byte {}",
                self.pos
            ))),
            None => Err(DslError::Parse(
                "expected value (string, number, or timestamp), found EOF".into(),
            )),
        }
    }

    fn parse_string(&mut self) -> Result<String, DslError> {
        let open_pos = self.pos;
        match self.bump() {
            Some('"') => {}
            _ => return Err(DslError::Parse(format!("expected '\"' at byte {open_pos}"))),
        }
        let mut s = String::new();
        loop {
            match self.bump() {
                Some('"') => return Ok(s),
                Some('\\') => match self.bump() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('\\') => s.push('\\'),
                    Some('"') => s.push('"'),
                    Some(c) => {
                        return Err(DslError::Parse(format!(
                            "invalid escape '\\{c}' in string literal"
                        )))
                    }
                    None => {
                        return Err(DslError::Parse(
                            "unterminated string: trailing backslash".into(),
                        ))
                    }
                },
                Some(c) => s.push(c),
                None => return Err(DslError::Parse("unterminated string literal".into())),
            }
        }
    }

    fn parse_timestamp(&mut self) -> Result<Value, DslError> {
        let at_pos = self.pos;
        match self.bump() {
            Some('@') => {}
            _ => return Err(DslError::Parse(format!("expected '@' at byte {at_pos}"))),
        }
        let start = self.pos;
        while let Some(c) = self.peek() {
            // A timestamp ends at whitespace or EOF. Anything else is part of
            // it, so a malformed RFC3339 will be rejected by the converter
            // rather than silently truncated.
            if c.is_ascii_whitespace() {
                break;
            }
            self.bump();
        }
        if self.pos == start {
            return Err(DslError::Parse(
                "expected RFC3339 timestamp after '@'".into(),
            ));
        }
        let body = &self.src[start..self.pos];
        let (secs, nanos) = parse_rfc3339(body)
            .map_err(|e| DslError::Parse(format!("invalid timestamp {body:?}: {e}")))?;
        Ok(Value::Timestamp(secs, nanos))
    }

    fn parse_number(&mut self) -> Result<Value, DslError> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.bump();
        }
        let int_digits_start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.bump();
            } else {
                break;
            }
        }
        // The integer part must contain at least one digit. This rejects
        // the leading-dot case (`-.5`) — the bare `.99` shape is rejected
        // earlier by `parse_value`, which only enters `parse_number` on
        // `-` or a digit.
        if self.pos == int_digits_start {
            return Err(DslError::Parse(format!(
                "expected digits in number at byte {start}"
            )));
        }

        // Optional fractional part. v0.1 addition: `12.99`, `0.01`. The
        // BNF requires at least one digit AFTER the dot — a trailing dot
        // (`12.`) is a parse error; treating `12.` as `12.0` would mask
        // a typo on a security boundary. A second `.` (e.g. `12.99.5`)
        // is left in the stream and surfaces as "trailing garbage" from
        // the top-level parser, anchored at the second dot's position.
        if self.peek() == Some('.') {
            self.bump();
            let frac_digits_start = self.pos;
            while let Some(c) = self.peek() {
                if c.is_ascii_digit() {
                    self.bump();
                } else {
                    break;
                }
            }
            if self.pos == frac_digits_start {
                return Err(DslError::Parse(format!(
                    "expected digits after '.' in number at byte {start}"
                )));
            }
        }

        let num_text = &self.src[start..self.pos];
        let value: f64 = num_text
            .parse()
            .map_err(|e| DslError::Parse(format!("invalid number {num_text:?}: {e}")))?;
        // The grammar cannot produce a non-finite f64 (no `NaN`/`Inf`
        // tokens, and any decimal literal in `\d+(\.\d+)?` form is
        // finite). The `apply_op` NaN trap defends against any
        // JSON-derived non-finite value, but here we just assert.
        debug_assert!(value.is_finite(), "BNF cannot produce a non-finite f64");

        let unit = if self.peek() == Some('_') {
            self.bump();
            let unit_text = self.parse_bare_ident()?;
            match Unit::from_str(&unit_text) {
                Some(u) => Some(u),
                None => {
                    return Err(DslError::Parse(format!(
                        "unknown unit {unit_text:?} (allowed: usd, eur, gbp, cents, ms, s)"
                    )))
                }
            }
        } else {
            None
        };

        Ok(Value::Number(value, unit))
    }
}

// ───────────────────────── evaluation ─────────────────────────

fn resolve_ident(ident: &Ident, ctx: &Context) -> Result<Value, DslError> {
    let segs = &ident.segments;
    let dotted = || segs.join(".");
    match segs[0].as_str() {
        "now" => {
            if segs.len() != 1 {
                return Err(DslError::UnknownIdent(dotted()));
            }
            let (s, n) = system_time_to_unix(ctx.now);
            Ok(Value::Timestamp(s, n))
        }
        "caller" => {
            if segs.len() != 1 {
                return Err(DslError::UnknownIdent(dotted()));
            }
            Ok(Value::String(ctx.caller.clone()))
        }
        "tool" => {
            if segs.len() != 1 {
                return Err(DslError::UnknownIdent(dotted()));
            }
            Ok(Value::String(ctx.tool.clone()))
        }
        "arg" => {
            if segs.len() < 2 {
                return Err(DslError::UnknownIdent(dotted()));
            }
            let mut cur: &serde_json::Value = &ctx.args;
            for seg in &segs[1..] {
                cur = match cur {
                    serde_json::Value::Object(map) => match map.get(seg) {
                        Some(v) => v,
                        None => return Err(DslError::UnknownIdent(dotted())),
                    },
                    _ => return Err(DslError::UnknownIdent(dotted())),
                };
            }
            json_to_value(cur).ok_or_else(|| DslError::TypeMismatch {
                expected: "string or integer at arg path".into(),
                got: format!("{} at {}", json_kind(cur), dotted()),
            })
        }
        "env" => {
            if segs.len() != 2 {
                return Err(DslError::UnknownIdent(dotted()));
            }
            ctx.env
                .get(&segs[1])
                .map(|v| Value::String(v.clone()))
                .ok_or_else(|| DslError::UnknownIdent(dotted()))
        }
        _ => Err(DslError::UnknownIdent(dotted())),
    }
}

fn json_to_value(j: &serde_json::Value) -> Option<Value> {
    match j {
        serde_json::Value::String(s) => Some(Value::String(s.clone())),
        // v0.1: accept any finite f64 from JSON. `as_f64()` is total over
        // serde_json's default backend (i64 / u64 / f64) and lossless for
        // values below 2^53; above that, both args side and caveat side
        // route through the same `<f64 as From<i64>>`-style rounding, so
        // they agree. Non-finite (NaN, ±∞) — which standard JSON cannot
        // encode anyway — is rejected so it cannot sneak past `apply_op`'s
        // NaN trap and produce silently-false comparisons.
        serde_json::Value::Number(n) => n
            .as_f64()
            .filter(|f| f.is_finite())
            .map(|v| Value::Number(v, None)),
        _ => None,
    }
}

fn json_kind(j: &serde_json::Value) -> &'static str {
    match j {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        // Reachable only for non-finite JSON numbers; finite numbers are
        // converted by `json_to_value` above.
        serde_json::Value::Number(_) => "non-finite number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Apply a comparison operator to two resolved values. Strings, numbers,
/// and timestamps each have their own per-type rules (see §2.2 type
/// table); cross-type comparisons fail closed with `TypeMismatch`.
///
/// # Numeric equality is exact-binary IEEE-754
///
/// v0.1 widened numeric values to `f64`, so `==` and `!=` follow IEEE-754
/// bit-equality (sign, exponent, mantissa). They are **not** epsilon
/// comparisons. Concretely:
///
/// - `0.1 + 0.2 == 0.3` is `false`. We do not paper over decimal-to-
///   binary rounding, because epsilon thresholds are application-specific
///   and inventing one inside a security boundary would let a $50.0001
///   purchase slip past an `arg.amount == 50` cap. Callers who want
///   tolerant equality should use `<=` / `>=` (or both) instead.
/// - `0.0 == -0.0` is `true` (IEEE-754 says so; `partial_cmp` agrees).
/// - `NaN == NaN` is `false`, but the parser cannot produce NaN and
///   `json_to_value` filters out non-finite JSON numbers, so this branch
///   is unreachable in practice. We still explicitly trap NaN below as
///   defence in depth on a security boundary.
///
/// **Recommendation for callers.** Use `<=` / `>=` for fuzzy-equal
/// quantities (prices, durations, allowances). Reserve `==` for
/// integer-typed identifiers (counts, flags, version numbers) where
/// the bit-equality semantics are what you want.
fn apply_op(op: Op, lhs: &Value, rhs: &Value) -> Result<bool, DslError> {
    match (lhs, rhs) {
        (Value::String(a), Value::String(b)) => match op {
            Op::Eq => Ok(a == b),
            Op::Neq => Ok(a != b),
            Op::Matches => {
                // TODO(v0.1): real regex. v0 does literal substring containment
                // because the `regex` crate is not in the dependency set; the
                // spec explicitly tells us to fall back rather than silently
                // pull in a new dep.
                Ok(a.contains(b.as_str()))
            }
            Op::Lt | Op::Le | Op::Gt | Op::Ge => Err(DslError::TypeMismatch {
                expected: "number or timestamp on left for ordering operator".into(),
                got: format!("string vs string with `{}`", op.as_str()),
            }),
        },
        (Value::Number(a, ua), Value::Number(b, ub)) => {
            if ua != ub {
                return Err(DslError::TypeMismatch {
                    expected: format!("number with unit {}", fmt_unit(ub)),
                    got: format!("number with unit {}", fmt_unit(ua)),
                });
            }
            // NaN guard. The parser cannot emit NaN and `json_to_value`
            // filters non-finite JSON numbers, so this is belt-and-braces.
            // If a NaN ever did slip through, `partial_cmp` would return
            // None and we'd panic on the unwrap — so instead we surface
            // it as a TypeMismatch and let the caller's audit log record
            // a clean deny rather than the verifier crashing.
            if a.is_nan() || b.is_nan() {
                return Err(DslError::TypeMismatch {
                    expected: "finite number".into(),
                    got: "NaN".into(),
                });
            }
            let ord = a
                .partial_cmp(b)
                .expect("non-NaN finite f64s have a total ordering via partial_cmp");
            ordered_to_bool(op, ord)
        }
        (Value::Timestamp(s1, n1), Value::Timestamp(s2, n2)) => {
            ordered_to_bool(op, (*s1, *n1).cmp(&(*s2, *n2)))
        }
        _ => Err(DslError::TypeMismatch {
            expected: rhs.type_name(),
            got: lhs.type_name(),
        }),
    }
}

fn ordered_to_bool(op: Op, ord: Ordering) -> Result<bool, DslError> {
    Ok(match op {
        Op::Eq => ord == Ordering::Equal,
        Op::Neq => ord != Ordering::Equal,
        Op::Lt => ord == Ordering::Less,
        Op::Le => ord != Ordering::Greater,
        Op::Gt => ord == Ordering::Greater,
        Op::Ge => ord != Ordering::Less,
        Op::Matches => {
            return Err(DslError::TypeMismatch {
                expected: "string for `matches`".into(),
                got: "non-string operand".into(),
            })
        }
    })
}

fn fmt_unit(u: &Option<Unit>) -> String {
    match u {
        Some(u) => u.as_str().to_string(),
        None => "(none)".to_string(),
    }
}

// ───────────────────────── timestamp plumbing ─────────────────────────

fn system_time_to_unix(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            // `t` is before the unix epoch. Convert to a (signed seconds,
            // nanos-in-[0, 1e9)) representation that's monotone with the
            // underlying instant, so comparison still works.
            let d = e.duration();
            let secs = d.as_secs() as i64;
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                (-secs, 0)
            } else {
                (-secs - 1, 1_000_000_000 - nanos)
            }
        }
    }
}

/// Hand-rolled RFC 3339 parser, accepting:
///
/// `YYYY-MM-DD T HH:MM:SS [.frac] (Z | [+-]HH:MM)`
///
/// (no spaces, just the form). We intentionally do not depend on `chrono`,
/// `time`, or `jiff` for v0; the parser is small enough to audit by eye and
/// the comparison only needs total ordering, not calendar arithmetic.
fn parse_rfc3339(s: &str) -> Result<(i64, u32), String> {
    let b = s.as_bytes();
    // `YYYY-MM-DDTHH:MM:SS` is 19 bytes; everything beyond is optional.
    if b.len() < 19 {
        return Err(format!("too short ({} bytes, need >= 19)", b.len()));
    }
    let year: i32 = parse_int_exact(&b[0..4])?;
    expect_byte(b, 4, b'-')?;
    let month: u32 = parse_uint_exact(&b[5..7])?;
    expect_byte(b, 7, b'-')?;
    let day: u32 = parse_uint_exact(&b[8..10])?;
    if !matches!(b[10], b'T' | b't') {
        return Err(format!(
            "expected 'T' at position 10, got {:?}",
            b[10] as char
        ));
    }
    let hour: u32 = parse_uint_exact(&b[11..13])?;
    expect_byte(b, 13, b':')?;
    let minute: u32 = parse_uint_exact(&b[14..16])?;
    expect_byte(b, 16, b':')?;
    let second: u32 = parse_uint_exact(&b[17..19])?;

    let mut idx = 19;

    let mut nanos: u32 = 0;
    if idx < b.len() && b[idx] == b'.' {
        idx += 1;
        let frac_start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == frac_start {
            return Err("expected digits after '.'".into());
        }
        let frac = &b[frac_start..idx];
        let mut buf = [b'0'; 9];
        let take = frac.len().min(9);
        buf[..take].copy_from_slice(&frac[..take]);
        nanos = parse_uint_exact(&buf)?;
    }

    if idx >= b.len() {
        return Err("missing timezone designator (need 'Z' or '+HH:MM')".into());
    }
    let (offset_secs, end) = match b[idx] {
        b'Z' | b'z' => (0i64, idx + 1),
        sign @ (b'+' | b'-') => {
            if b.len() < idx + 6 {
                return Err("offset truncated".into());
            }
            if b[idx + 3] != b':' {
                return Err("expected ':' at offset's HH:MM separator".into());
            }
            let sign: i64 = if sign == b'+' { 1 } else { -1 };
            let oh = i64::from(parse_uint_exact::<u32>(&b[idx + 1..idx + 3])?);
            let om = i64::from(parse_uint_exact::<u32>(&b[idx + 4..idx + 6])?);
            if oh > 23 {
                return Err(format!("bad offset hour: {oh}"));
            }
            if om > 59 {
                return Err(format!("bad offset minute: {om}"));
            }
            (sign * (oh * 3600 + om * 60), idx + 6)
        }
        other => {
            return Err(format!(
                "expected 'Z' or '+/-HH:MM', got {:?}",
                other as char
            ))
        }
    };

    if end != b.len() {
        return Err(format!(
            "trailing garbage in timestamp starting at byte {end}"
        ));
    }

    if !(1..=12).contains(&month) {
        return Err(format!("bad month: {month}"));
    }
    let mdays = days_in_month(year, month);
    if !(1..=mdays).contains(&day) {
        return Err(format!("bad day {day} for {year:04}-{month:02}"));
    }
    if hour >= 24 {
        return Err(format!("bad hour: {hour}"));
    }
    if minute >= 60 {
        return Err(format!("bad minute: {minute}"));
    }
    if second > 60 {
        // RFC3339 permits 60 for leap seconds.
        return Err(format!("bad second: {second}"));
    }

    let days = days_from_civil(year, month as i32, day as i32);
    let secs = days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    let secs = secs - offset_secs;
    Ok((secs, nanos))
}

fn expect_byte(b: &[u8], idx: usize, want: u8) -> Result<(), String> {
    if idx >= b.len() {
        return Err(format!(
            "expected {:?} at position {idx}, found EOF",
            want as char
        ));
    }
    if b[idx] != want {
        return Err(format!(
            "expected {:?} at position {idx}, got {:?}",
            want as char, b[idx] as char
        ));
    }
    Ok(())
}

fn parse_int_exact(b: &[u8]) -> Result<i32, String> {
    let s = std::str::from_utf8(b).map_err(|e| format!("non-utf8: {e}"))?;
    s.parse::<i32>()
        .map_err(|e| format!("bad integer {s:?}: {e}"))
}

fn parse_uint_exact<T: std::str::FromStr>(b: &[u8]) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    if b.iter().any(|c| !c.is_ascii_digit()) {
        return Err(format!(
            "expected ASCII digits, got {:?}",
            String::from_utf8_lossy(b)
        ));
    }
    let s = std::str::from_utf8(b).map_err(|e| format!("non-utf8: {e}"))?;
    s.parse::<T>().map_err(|e| format!("bad number {s:?}: {e}"))
}

fn days_in_month(y: i32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Days from the unix epoch to the given proleptic Gregorian date.
/// Howard Hinnant's algorithm — chosen because it is short, branch-light,
/// and numerically exact for any year in i32.
fn days_from_civil(y: i32, m: i32, d: i32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as i64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as i64 * 146097 + doe - 719468
}
