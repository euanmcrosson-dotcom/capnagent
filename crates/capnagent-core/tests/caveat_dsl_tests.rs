//! Integration tests for the caveat DSL parser and evaluator.
//!
//! ## Why the test scaffolding looks unusual
//!
//! The `caveat_dsl` source file lives at `crates/capnagent-core/src/caveat_dsl.rs`
//! and follows the §2.2 contract — it imports `crate::capability::Caveat` and
//! `crate::context::Context`. But:
//!
//! 1. The `feat/week2-dsl` branch is forbidden from editing `lib.rs`, so the
//!    module is not yet declared in the lib. It is wired in at merge time
//!    by the lead (per `docs/WEEK2_SPEC.md` §5).
//! 2. The `Context` type is owned by the parallel `feat/week2-context` branch
//!    and is not available on this branch yet.
//!
//! The test binary therefore compiles the source via `#[path]` and supplies
//! the surrounding `crate::capability` and `crate::context` modules itself.
//! `mod context` matches the locked §2.1 public surface exactly — same fields,
//! same types — so the source compiles unchanged here, and at merge time it
//! will compile unchanged against the real `context.rs`.
//!
//! This way the source file owns the full §2.2 contract and the tests can
//! exercise it before any other branch lands.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proptest::prelude::*;

mod capability {
    //! Shim that re-exports the real `Caveat` from the lib so the source's
    //! `use crate::capability::Caveat;` resolves inside this test binary.
    pub use capnagent_core::Caveat;
}

mod context {
    //! Stub `Context` matching `WEEK2_SPEC.md` §2.1 exactly. This keeps the
    //! test binary independent from `feat/week2-context`. The real module
    //! has the same public fields and types; the source under test does not
    //! depend on `args_hash()` or the builder, so we only need the struct.
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
}

#[path = "../src/caveat_dsl.rs"]
mod caveat_dsl;

use caveat_dsl::{evaluate, matches, parse, DslError};
use context::Context;

// ───────────────────────── helpers ─────────────────────────

fn ts(s: &str) -> SystemTime {
    // Build a SystemTime from an RFC3339-ish string by reusing the same
    // parser the DSL uses. We do this via a public path: parse a predicate
    // `now == @<s>` and extract the timestamp through evaluate-with-now-set.
    // Simpler: do it ourselves by composing UNIX_EPOCH + parsed seconds.
    //
    // We can't re-export `parse_rfc3339` (it's private), so we go through
    // a tiny round-trip: build a `now == @s` predicate with ctx.now equal
    // to UNIX_EPOCH+offset for an offset we compute by binary search? No —
    // overkill. Instead, parse via the DSL and pull the timestamp out by
    // observing that `now == @s` is true iff ctx.now equals that timestamp.
    //
    // Concrete approach: parse seconds-since-epoch directly here, since
    // the test only needs a handful of well-known timestamps.
    parse_rfc3339_for_test(s)
}

/// Local copy of the date math, used only to build test fixtures.
/// Smaller and dumber than the production parser; rejects anything with
/// fractional seconds or non-`Z` offsets.
fn parse_rfc3339_for_test(s: &str) -> SystemTime {
    assert_eq!(
        s.len(),
        20,
        "test helper only handles `YYYY-MM-DDTHH:MM:SSZ`"
    );
    let b = s.as_bytes();
    let year: i32 = std::str::from_utf8(&b[0..4]).unwrap().parse().unwrap();
    let month: i32 = std::str::from_utf8(&b[5..7]).unwrap().parse().unwrap();
    let day: i32 = std::str::from_utf8(&b[8..10]).unwrap().parse().unwrap();
    let hour: u64 = std::str::from_utf8(&b[11..13]).unwrap().parse().unwrap();
    let minute: u64 = std::str::from_utf8(&b[14..16]).unwrap().parse().unwrap();
    let second: u64 = std::str::from_utf8(&b[17..19]).unwrap().parse().unwrap();
    assert!(matches!(b[19], b'Z' | b'z'));

    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = (y - era * 400) as i64;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp as i64 + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146097 + doe - 719468;
    let secs = days * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    assert!(secs >= 0, "test helper assumes timestamp >= unix epoch");
    UNIX_EPOCH + Duration::from_secs(secs as u64)
}

fn ctx_with(now_str: &str, caller: &str, tool: &str) -> Context {
    Context {
        now: ts(now_str),
        caller: caller.into(),
        tool: tool.into(),
        args: serde_json::Value::Null,
        env: HashMap::new(),
    }
}

fn empty_ctx() -> Context {
    Context {
        now: UNIX_EPOCH,
        caller: String::new(),
        tool: String::new(),
        args: serde_json::Value::Null,
        env: HashMap::new(),
    }
}

// ───────────────────────── parser: §2.2 examples round-trip ─────────────────────────

#[test]
fn parses_amount_le_50_usd() {
    parse("amount <= 50_usd").unwrap();
}

#[test]
fn parses_merchant_eq_amazon_com() {
    parse(r#"merchant == "amazon.com""#).unwrap();
}

#[test]
fn parses_now_le_timestamp() {
    parse("now <= @2026-04-27T12:00:00Z").unwrap();
}

#[test]
fn parses_tool_eq_http_post() {
    parse(r#"tool == "http.post""#).unwrap();
}

#[test]
fn parses_arg_url_matches_substring() {
    parse(r#"arg.url matches "api.example.com""#).unwrap();
}

#[test]
fn parses_caller_neq_rogue() {
    parse(r#"caller != "agent:rogue""#).unwrap();
}

#[test]
fn parses_negative_number_with_unit() {
    parse("delta == -100_cents").unwrap();
}

#[test]
fn parses_dotted_arg_path() {
    parse(r#"arg.outer.inner == "ok""#).unwrap();
}

#[test]
fn parses_env_lookup() {
    parse(r#"env.region == "us-east-1""#).unwrap();
}

#[test]
fn parses_with_no_whitespace() {
    parse(r#"tool=="http.post""#).unwrap();
}

#[test]
fn parses_with_extra_internal_whitespace() {
    parse(r#"  tool   ==   "http.post"  "#).unwrap();
}

// ───────────────────────── parser: malformed input rejected ─────────────────────────

#[test]
fn rejects_empty_predicate() {
    assert!(matches!(parse(""), Err(DslError::Parse(_))));
}

#[test]
fn rejects_whitespace_only_predicate() {
    assert!(matches!(parse("   \t  "), Err(DslError::Parse(_))));
}

#[test]
fn rejects_bare_identifier_with_no_op() {
    assert!(matches!(parse("amount"), Err(DslError::Parse(_))));
}

#[test]
fn rejects_ident_with_op_but_no_value() {
    assert!(matches!(parse("amount <= "), Err(DslError::Parse(_))));
}

#[test]
fn rejects_unknown_operator() {
    assert!(matches!(parse("amount === 50"), Err(DslError::Parse(_))));
}

#[test]
fn rejects_assignment_operator() {
    assert!(matches!(parse("amount = 50"), Err(DslError::Parse(_))));
}

#[test]
fn rejects_mismatched_quotes() {
    assert!(matches!(
        parse(r#"merchant == "amazon"#),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_invalid_string_escape() {
    assert!(matches!(parse(r#"x == "\q""#), Err(DslError::Parse(_))));
}

#[test]
fn rejects_unknown_unit() {
    assert!(matches!(parse("price <= 5_chf"), Err(DslError::Parse(_))));
}

#[test]
fn rejects_number_with_no_digits() {
    assert!(matches!(parse("amount == -"), Err(DslError::Parse(_))));
}

#[test]
fn rejects_trailing_garbage() {
    assert!(matches!(
        parse("tool == \"x\" extra"),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_starting_with_digit_ident() {
    assert!(matches!(parse("1amount == 1"), Err(DslError::Parse(_))));
}

#[test]
fn rejects_dot_with_no_continuation() {
    assert!(matches!(parse("arg. == 1"), Err(DslError::Parse(_))));
}

#[test]
fn rejects_space_inside_dotted_ident() {
    // `arg .url ==` should fail: after `arg`, `.url` starts with a non-op.
    assert!(parse(r#"arg .url == "x""#).is_err());
}

#[test]
fn rejects_invalid_timestamp() {
    assert!(matches!(
        parse("now <= @not-a-timestamp"),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_timestamp_without_offset() {
    assert!(matches!(
        parse("now <= @2026-04-27T12:00:00"),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_at_with_no_body() {
    assert!(matches!(parse("now <= @"), Err(DslError::Parse(_))));
}

// ───────────────────────── evaluator: happy paths ─────────────────────────

#[test]
fn eval_caller_equality_true() {
    let p = parse(r#"caller == "agent:planner""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "");
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_caller_equality_false() {
    let p = parse(r#"caller == "agent:planner""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:other", "");
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_caller_neq_excludes_rogue() {
    let p = parse(r#"caller != "agent:rogue""#).unwrap();
    let ok = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "");
    let bad = ctx_with("2026-04-27T00:00:00Z", "agent:rogue", "");
    assert!(evaluate(&p, &ok).unwrap());
    assert!(!evaluate(&p, &bad).unwrap());
}

#[test]
fn eval_tool_equality() {
    let p = parse(r#"tool == "http.post""#).unwrap();
    let ok = ctx_with("2026-04-27T00:00:00Z", "x", "http.post");
    let bad = ctx_with("2026-04-27T00:00:00Z", "x", "bank.wire");
    assert!(evaluate(&p, &ok).unwrap());
    assert!(!evaluate(&p, &bad).unwrap());
}

#[test]
fn eval_now_le_timestamp_before() {
    let p = parse("now <= @2026-04-27T12:00:00Z").unwrap();
    let ctx = ctx_with("2026-04-27T11:59:59Z", "x", "x");
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_now_le_timestamp_equal() {
    let p = parse("now <= @2026-04-27T12:00:00Z").unwrap();
    let ctx = ctx_with("2026-04-27T12:00:00Z", "x", "x");
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_now_le_timestamp_after_is_false() {
    let p = parse("now <= @2026-04-27T12:00:00Z").unwrap();
    let ctx = ctx_with("2026-04-27T12:00:01Z", "x", "x");
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_now_lt_strict_excludes_equal() {
    let p = parse("now < @2026-04-27T12:00:00Z").unwrap();
    let exact = ctx_with("2026-04-27T12:00:00Z", "x", "x");
    let earlier = ctx_with("2026-04-27T11:59:59Z", "x", "x");
    assert!(!evaluate(&p, &exact).unwrap());
    assert!(evaluate(&p, &earlier).unwrap());
}

#[test]
fn eval_now_gt_after() {
    let p = parse("now > @2026-04-27T12:00:00Z").unwrap();
    let later = ctx_with("2026-04-27T12:00:01Z", "x", "x");
    assert!(evaluate(&p, &later).unwrap());
}

#[test]
fn eval_arg_string_equality() {
    let p = parse(r#"arg.merchant == "amazon.com""#).unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"merchant": "amazon.com"});
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_arg_nested_path() {
    let p = parse(r#"arg.outer.inner == "ok""#).unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"outer": {"inner": "ok"}});
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_arg_matches_substring() {
    let p = parse(r#"arg.url matches "api.example.com""#).unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"url": "https://api.example.com/v1/orders"});
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_arg_matches_no_match_is_false() {
    let p = parse(r#"arg.url matches "api.example.com""#).unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"url": "https://attacker.example.org/"});
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_arg_number_le_no_unit() {
    let p = parse("arg.amount <= 100").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 50});
    assert!(evaluate(&p, &ctx).unwrap());
    ctx.args = serde_json::json!({"amount": 150});
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_env_lookup() {
    let p = parse(r#"env.region == "us-east-1""#).unwrap();
    let mut ctx = empty_ctx();
    ctx.env.insert("region".into(), "us-east-1".into());
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn eval_matches_function_round_trip() {
    let cav = capability::Caveat::new(r#"caller == "agent:planner""#);
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "x");
    assert!(matches(&cav, &ctx).unwrap());
}

// ───────────────────────── evaluator: error paths ─────────────────────────

#[test]
fn unknown_root_ident_is_unknown() {
    let p = parse(r#"weather == "sunny""#).unwrap();
    assert!(matches!(
        evaluate(&p, &empty_ctx()),
        Err(DslError::UnknownIdent(_))
    ));
}

#[test]
fn missing_arg_path_is_unknown() {
    let p = parse(r#"arg.missing == "x""#).unwrap();
    assert!(matches!(
        evaluate(&p, &empty_ctx()),
        Err(DslError::UnknownIdent(_))
    ));
}

#[test]
fn missing_env_key_is_unknown() {
    let p = parse(r#"env.region == "us-east-1""#).unwrap();
    assert!(matches!(
        evaluate(&p, &empty_ctx()),
        Err(DslError::UnknownIdent(_))
    ));
}

#[test]
fn dotted_now_is_unknown() {
    let p = parse(r#"now.suffix == "x""#).unwrap();
    assert!(matches!(
        evaluate(&p, &empty_ctx()),
        Err(DslError::UnknownIdent(_))
    ));
}

#[test]
fn arg_resolving_to_object_is_type_mismatch() {
    let p = parse(r#"arg.outer == "x""#).unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"outer": {"inner": 1}});
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

#[test]
fn unit_mismatch_is_type_mismatch() {
    // arg.amount has no unit (it's plain JSON), 50_usd has a unit.
    let p = parse("arg.amount <= 50_usd").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 25});
    let err = evaluate(&p, &ctx).unwrap_err();
    assert!(matches!(err, DslError::TypeMismatch { .. }), "{err:?}");
}

#[test]
fn cross_unit_mismatch_is_type_mismatch() {
    // Compare a usd-tagged literal to a non-tagged arg number.
    let p = parse("arg.amount == 5_eur").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 5});
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

#[test]
fn string_vs_number_is_type_mismatch() {
    let p = parse("caller == 5").unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "x");
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

#[test]
fn matches_on_number_is_type_mismatch() {
    let p = parse("arg.amount matches \"50\"").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 50});
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

#[test]
fn ordering_op_on_strings_is_type_mismatch() {
    let p = parse(r#"caller <= "z""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "x");
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

#[test]
fn timestamp_compared_to_string_is_type_mismatch() {
    let p = parse(r#"now == "2026-04-27T12:00:00Z""#).unwrap();
    let ctx = ctx_with("2026-04-27T12:00:00Z", "x", "x");
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

// ───────────────────────── proptest: parser robustness ─────────────────────────

proptest! {
    /// The parser must never panic on arbitrary input. This is the
    /// security-relevant property: even adversarially-crafted predicate
    /// strings (the agent could try to attenuate with one) must yield a
    /// clean error, not a process-level abort.
    #[test]
    fn parser_does_not_panic_on_arbitrary_text(s in any::<String>()) {
        let _ = parse(&s);
    }

    /// Bytes-level fuzz, including non-UTF-8 boundaries within the slice
    /// the parser sees as `&str`. (Generated as String so it's always valid
    /// UTF-8, but the corpus includes control chars and dotted forms.)
    #[test]
    fn parser_does_not_panic_on_pathological_strings(
        s in r#"[\PC]{0,128}"#
    ) {
        let _ = parse(&s);
    }

    /// Round-trip property: an integer equality predicate built from any
    /// i64 parses successfully and evaluates true against a matching arg.
    #[test]
    fn integer_equality_round_trips(n in any::<i64>()) {
        let pred_text = format!("arg.amount == {n}");
        let p = parse(&pred_text).unwrap_or_else(|e| panic!("parse failed: {e}"));
        let mut ctx = empty_ctx();
        ctx.args = serde_json::json!({"amount": n});
        prop_assert_eq!(evaluate(&p, &ctx).unwrap(), true);
    }

    /// Total ordering on timestamps: for any two unix-epoch offsets,
    /// `now <= @T` and `now > @T` are exactly negations of each other.
    ///
    /// Range is capped at 9999-12-31 (the largest RFC3339 four-digit year)
    /// because the production parser, like RFC3339 itself, only accepts
    /// `date-fullyear = 4DIGIT`. Anything larger is correctly rejected by
    /// the parser; that's covered by `parser_does_not_panic_on_arbitrary_text`.
    #[test]
    fn timestamp_le_and_gt_partition(
        now_secs in 0u64..253_402_300_800u64,
        threshold_secs in 0u64..253_402_300_800u64,
    ) {
        let mut ctx = empty_ctx();
        ctx.now = UNIX_EPOCH + Duration::from_secs(now_secs);

        // Build a threshold timestamp string deterministically without
        // depending on the production parser. We just inject the seconds
        // via a trivial RFC3339 format generator anchored at 2000-01-01.
        let t = format_unix_seconds_as_rfc3339(threshold_secs);
        let le = parse(&format!("now <= @{t}")).unwrap();
        let gt = parse(&format!("now > @{t}")).unwrap();
        let le_v = evaluate(&le, &ctx).unwrap();
        let gt_v = evaluate(&gt, &ctx).unwrap();
        prop_assert_eq!(le_v, !gt_v);
    }
}

/// Format unix seconds as `YYYY-MM-DDTHH:MM:SSZ`. Covers offsets from
/// 1970-01-01T00:00:00Z up through ~2^40 seconds (year 36812ish), which is
/// more than enough headroom for the proptest corpus while staying within
/// our handwritten parser's range.
fn format_unix_seconds_as_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Inverse of `days_from_civil`. Howard Hinnant's algorithm, again.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}
