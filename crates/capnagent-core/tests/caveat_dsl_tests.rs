//! Integration tests for the caveat DSL parser and evaluator.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proptest::prelude::*;

use capnagent_core::caveat_dsl::{evaluate, matches, parse, DslError};
use capnagent_core::Context;

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
    let cav = capnagent_core::Caveat::new(r#"caller == "agent:planner""#);
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

// ───────────────────────── v0.1 §3.1: decimal numbers ─────────────────────────
//
// V0_1_SPEC.md §3.1 widens the `number` BNF to accept `\d+(\.\d+)?`. The
// motivation is real: a live shopping-agent run on Haiku 4.5 emitted
// `arg.amount = 12.99` (the literal price of a USB-C cable in the
// catalog) and capnagent denied with a type-mismatch instead of
// comparing against the `<= 50` cap. Tests below cover the must-parse
// shapes, the must-reject shapes, cross-type comparisons (int caveat
// vs decimal arg and vice versa), unit + decimal interaction, and a
// proptest property for round-trip equality.

// ─── Must-parse: every example in §3.1 ─────────────────────────────────

#[test]
fn parses_decimal_amount_le_12_99() {
    parse("arg.amount <= 12.99").unwrap();
}

#[test]
fn parses_decimal_amount_eq_001() {
    parse("arg.amount == 0.01").unwrap();
}

#[test]
fn parses_decimal_amount_gt_1000_5() {
    parse("arg.amount > 1000.5").unwrap();
}

#[test]
fn parses_decimal_with_unit() {
    parse("arg.amount <= 12.99_usd").unwrap();
}

#[test]
fn parses_integer_zero_still_works() {
    parse("arg.budget == 0").unwrap();
}

#[test]
fn parses_decimal_zero_zero() {
    parse("arg.budget == 0.0").unwrap();
}

#[test]
fn parses_negative_decimal() {
    // The BNF allows a leading `-` on the integer part, so negative
    // decimals fall out for free. Not in the spec example list, but
    // worth nailing down — if the parser ever regresses on this, a
    // refund-credit caveat like `arg.delta >= -10.00` would silently
    // start denying.
    parse("arg.delta >= -10.00").unwrap();
}

// ─── Must-reject: every counterexample in §3.1 ─────────────────────────

#[test]
fn rejects_trailing_dot_in_number() {
    let err = parse("arg.amount <= 12.").unwrap_err();
    assert!(matches!(err, DslError::Parse(_)), "{err:?}");
    if let DslError::Parse(msg) = err {
        // The error should mention what's expected, so a developer
        // reading the audit log can tell typo from invalid input.
        assert!(
            msg.contains("digits after '.'") || msg.contains("number"),
            "parse error message should reference the missing fractional digits, got: {msg}"
        );
    }
}

#[test]
fn rejects_leading_dot_in_number() {
    let err = parse("arg.amount <= .99").unwrap_err();
    assert!(matches!(err, DslError::Parse(_)), "{err:?}");
}

#[test]
fn rejects_multiple_dots_in_number() {
    let err = parse("arg.amount <= 12.99.5").unwrap_err();
    assert!(matches!(err, DslError::Parse(_)), "{err:?}");
}

#[test]
fn rejects_extended_unit_suffix() {
    // Unchanged from v0: the unit table is closed. Extending it
    // implicitly via tokens like `usd_extra` would silently accept
    // typos (`30_usd_per_request`), so the parser stays strict.
    let err = parse("arg.amount <= 12_usd_extra").unwrap_err();
    assert!(matches!(err, DslError::Parse(_)), "{err:?}");
}

#[test]
fn rejects_negative_leading_dot() {
    // `-` followed immediately by a fractional. The integer part must
    // contain at least one digit even when negative.
    let err = parse("arg.amount <= -.5").unwrap_err();
    assert!(matches!(err, DslError::Parse(_)), "{err:?}");
}

// ─── Cross-type comparisons: int caveat ↔ decimal arg ─────────────────

#[test]
fn integer_caveat_vs_decimal_arg_under_threshold() {
    // The headline v0.1 case: an LLM emits `12.99` for a $12.99 item,
    // capability caps spend at `<= 50`. Must allow.
    let p = parse("arg.amount <= 50").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 12.99});
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn integer_caveat_vs_decimal_arg_over_threshold() {
    let p = parse("arg.amount <= 50").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 75.5});
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn decimal_caveat_vs_integer_arg_under_threshold() {
    let p = parse("arg.amount <= 50.5").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 13});
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn decimal_caveat_vs_integer_arg_at_boundary() {
    // 50 == 50.0 in IEEE-754 — exact-binary rules. The caller should
    // pick `<=` here for safe semantics; we still demonstrate that
    // boundary equality is bit-exact.
    let p = parse("arg.amount == 50.0").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 50});
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn decimal_caveat_vs_decimal_arg_under() {
    let p = parse("arg.amount <= 12.99").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 12.99});
    assert!(evaluate(&p, &ctx).unwrap());
}

// ─── Unit + decimal interaction ──────────────────────────────────────

#[test]
fn decimal_with_unit_against_unitless_arg_is_type_mismatch() {
    // Same v0 rule (units must match) — we just confirm decimals do
    // not relax it.
    let p = parse("arg.amount <= 12.99_usd").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 5.50});
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

#[test]
fn decimal_unit_unrecognized_is_parse_error() {
    // `chf` isn't in the unit set. v0.1 doesn't widen the unit table,
    // and we want a parse error (not a runtime TypeMismatch) so the
    // caveat author sees the typo at issuance, not at decision time.
    let err = parse("arg.amount <= 12.99_chf").unwrap_err();
    assert!(matches!(err, DslError::Parse(_)), "{err:?}");
}

// ─── Equality is exact-binary, not epsilon ───────────────────────────

#[test]
fn eq_does_not_paper_over_floating_point_rounding() {
    // 0.1 + 0.2 != 0.3 in IEEE-754 — and the DSL agrees. This is the
    // load-bearing "fail closed" property: the security boundary will
    // not silently treat 50.0001 as equal to 50.
    let p = parse("arg.x == 0.3").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"x": 0.1f64 + 0.2f64});
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn le_handles_floating_point_rounding_safely() {
    // Companion to the test above: callers who want fuzzy equality
    // should reach for `<=` / `>=`. 0.1 + 0.2 is a hair above 0.3,
    // but a `<= 0.3000001` cap holds.
    let p = parse("arg.x <= 0.3000001").unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"x": 0.1f64 + 0.2f64});
    assert!(evaluate(&p, &ctx).unwrap());
}

// ─── Property: round-trip parse + evaluate of any decimal ────────────

proptest! {
    /// For any random decimal `d` (formatted as a fixed-precision
    /// string), parse `arg.x == <d>` and evaluate against
    /// `args.x = <d-as-f64>`. Both sides go through the same
    /// `<f64>::from_str` rounding, so the comparison must hold for
    /// every well-formed decimal string the formatter produces.
    ///
    /// The generators are bounded to keep the formatted strings within
    /// the parser's grammar (`-?\d+\.\d+`). We don't generate
    /// arbitrary `f64` here on purpose — `f64::to_string` can emit
    /// scientific notation (`1e-10`), which the v0.1 grammar
    /// deliberately does NOT accept.
    #[test]
    fn decimal_equality_round_trips(
        int_part in -10_000_000i64..=10_000_000,
        frac_part in 0u32..=999_999,
    ) {
        // Format with leading zero-padding so `frac_part = 5` becomes
        // `.000005`, not `.5`.
        let s = format!("{int_part}.{frac_part:06}");
        let f: f64 = s.parse().expect("formatter produces a parseable decimal");

        let p = parse(&format!("arg.x == {s}"))
            .unwrap_or_else(|e| panic!("parse failed for {s:?}: {e}"));

        let mut ctx = empty_ctx();
        ctx.args = serde_json::json!({"x": f});
        prop_assert!(
            evaluate(&p, &ctx).unwrap(),
            "expected arg.x == {s} to hold against args.x = {f}"
        );
    }
}

// ───────────────────────── boolean composition (v0.1) ─────────────────────────
//
// `OR` / `AND` / parens with standard precedence and short-circuit
// evaluation. Backward-compat: a bare comparison (no boolean op) parses
// and evaluates exactly as it did in v0; the existing 81 tests above
// already cover that surface and must keep passing.

#[test]
fn parses_or_two_comparisons() {
    parse(r#"tool == "x" OR tool == "y""#).unwrap();
}

#[test]
fn parses_and_two_comparisons() {
    parse(r#"caller == "agent:planner" AND tool == "checkout.purchase""#).unwrap();
}

#[test]
fn parses_parens_around_or() {
    parse(r#"(tool == "x" OR tool == "y") AND caller == "agent:planner""#).unwrap();
}

#[test]
fn parses_long_chain_of_ors() {
    parse(r#"tool == "a" OR tool == "b" OR tool == "c" OR tool == "d""#).unwrap();
}

#[test]
fn parses_nested_parens() {
    parse(r#"((tool == "x" OR tool == "y") AND caller == "z") OR caller == "w""#).unwrap();
}

#[test]
fn lowercase_or_and_parsed_as_idents_not_keywords() {
    // The DSL reserves UPPERCASE `OR` / `AND` only — lowercase tokens
    // are treated as identifiers, which keeps the keyword surface
    // visually unambiguous and prevents ambiguity with arg paths like
    // `arg.or` or `env.and`.
    assert!(parse(r#"tool == "x" or tool == "y""#).is_err());
    assert!(parse(r#"tool == "x" and tool == "y""#).is_err());
}

#[test]
fn rejects_dangling_or() {
    assert!(matches!(
        parse(r#"tool == "x" OR"#),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_dangling_and() {
    assert!(matches!(
        parse(r#"tool == "x" AND"#),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_unbalanced_parens_open() {
    assert!(matches!(
        parse(r#"(tool == "x" OR tool == "y""#),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_unbalanced_parens_close() {
    assert!(matches!(parse(r#"tool == "x")"#), Err(DslError::Parse(_))));
}

#[test]
fn rejects_or_at_start() {
    assert!(matches!(
        parse(r#"OR tool == "x""#),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn rejects_and_at_start() {
    assert!(matches!(
        parse(r#"AND tool == "x""#),
        Err(DslError::Parse(_))
    ));
}

#[test]
fn or_keyword_followed_by_word_continuation_is_an_ident() {
    // `ORange == 1` must NOT be parsed as `OR ange == 1`. The keyword
    // consumer requires a non-ident-continuation after the keyword.
    // `ORange` parses syntactically (it's a valid identifier shape) and
    // surfaces as `UnknownIdent` at evaluation — that's the correct
    // failure mode for "valid syntax, no such fact".
    let p = parse("ORange == 1").unwrap();
    assert!(matches!(
        evaluate(&p, &empty_ctx()),
        Err(DslError::UnknownIdent(_))
    ));
}

// ───────────────────────── evaluation: OR ─────────────────────────

#[test]
fn or_first_branch_true_short_circuits() {
    let p = parse(r#"tool == "checkout.purchase" OR tool == "catalog.search""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "checkout.purchase");
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn or_second_branch_true_when_first_false() {
    let p = parse(r#"tool == "checkout.purchase" OR tool == "catalog.search""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "catalog.search");
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn or_both_false_yields_false() {
    let p = parse(r#"tool == "checkout.purchase" OR tool == "catalog.search""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "bank.wire");
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn or_short_circuits_through_error() {
    // `(tool == "x") OR (unknown_root == "y")` — when the first branch
    // is true, the second never evaluates, so the unknown-ident error
    // does not surface. Standard short-circuit semantics; matches what
    // a programmer would expect from `||`.
    let p = parse(r#"tool == "x" OR no_such_root == 1"#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "x");
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn or_propagates_error_from_evaluated_branch() {
    // First branch errors → whole expression errors (no false-positive
    // allow from an unevaluated second branch).
    let p = parse(r#"no_such_root == 1 OR tool == "x""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "x");
    assert!(matches!(evaluate(&p, &ctx), Err(DslError::UnknownIdent(_))));
}

// ───────────────────────── evaluation: AND ─────────────────────────

#[test]
fn and_both_true_yields_true() {
    let p = parse(r#"caller == "agent:planner" AND tool == "checkout.purchase""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "checkout.purchase");
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn and_first_false_short_circuits() {
    let p = parse(r#"caller == "agent:rogue" AND no_such_root == 1"#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "x");
    // First branch false → return false without evaluating the second.
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn and_second_false_yields_false() {
    let p = parse(r#"caller == "agent:planner" AND tool == "bank.wire""#).unwrap();
    let ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "checkout.purchase");
    assert!(!evaluate(&p, &ctx).unwrap());
}

// ───────────────────────── precedence ─────────────────────────

#[test]
fn and_binds_tighter_than_or() {
    // `a OR b AND c` should parse as `a OR (b AND c)`. Construct facts
    // such that exactly one bracketing yields the expected truth value:
    //   a=false, b=true, c=true   → (a OR (b AND c)) = true
    //   a=false, b=true, c=true   → ((a OR b) AND c) = true (same)
    //   a=true,  b=true, c=false  → (a OR (b AND c)) = true
    //                              ((a OR b) AND c) = false  ← differs
    // We check the second row, where the two parsings disagree.
    let p =
        parse(r#"caller == "agent:planner" OR tool == "checkout.purchase" AND arg.flag == "yes""#)
            .unwrap();
    let mut ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "checkout.purchase");
    ctx.args = serde_json::json!({"flag": "no"}); // c is false
                                                  // a is true, so (a OR ...) = true regardless of the AND branch.
                                                  // If precedence were the other way, ((a OR b) AND c) would be
                                                  // (true AND false) = false.
    assert!(evaluate(&p, &ctx).unwrap());
}

#[test]
fn parens_override_precedence() {
    // Now the same a/b/c with explicit parens — and `c=false` makes the
    // result false. Confirms parens change the parse, not just decoration.
    let p = parse(
        r#"(caller == "agent:planner" OR tool == "checkout.purchase") AND arg.flag == "yes""#,
    )
    .unwrap();
    let mut ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "checkout.purchase");
    ctx.args = serde_json::json!({"flag": "no"});
    assert!(!evaluate(&p, &ctx).unwrap());
}

// ───────────────────────── motivating use-case (single-cap version of the demo) ─────────────────────────

#[test]
fn single_capability_now_covers_browse_or_buy() {
    // The shopping-agent demo issued TWO capabilities (browse + buy)
    // because v0 had no `OR`. With v0.1 boolean composition, one
    // capability with a disjunction can authorise both reads and
    // writes — the operational simplification real users asked for.
    let p =
        parse(r#"tool == "catalog.search" OR (tool == "checkout.purchase" AND arg.amount <= 50)"#)
            .unwrap();

    // Allow: catalog search.
    let mut ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "catalog.search");
    assert!(evaluate(&p, &ctx).unwrap());

    // Allow: in-budget purchase.
    ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "checkout.purchase");
    ctx.args = serde_json::json!({"amount": 13});
    assert!(evaluate(&p, &ctx).unwrap());

    // Deny: out-of-budget purchase.
    ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "checkout.purchase");
    ctx.args = serde_json::json!({"amount": 999});
    assert!(!evaluate(&p, &ctx).unwrap());

    // Deny: out-of-scope tool.
    ctx = ctx_with("2026-04-27T00:00:00Z", "agent:planner", "bank.wire");
    assert!(!evaluate(&p, &ctx).unwrap());
}

// ───────────────────────── starts_with (v0.5) ─────────────────────────

#[test]
fn starts_with_anchored_prefix_admits_only_when_prefix_at_byte_zero() {
    // Round 07 closure: a path-prefix caveat written with `starts_with`
    // must NOT admit paths that contain the prefix as a non-anchored
    // substring. With `matches`, "/etc/sandbox-bypass" matches "/sandbox"
    // because matches is contains. With `starts_with` it does not.
    let p = parse(r#"arg.path starts_with "/sandbox""#).unwrap();

    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"path": "/sandbox/file.txt"});
    assert!(evaluate(&p, &ctx).unwrap(), "anchored prefix should match");

    ctx.args = serde_json::json!({"path": "/etc/sandbox-bypass"});
    assert!(
        !evaluate(&p, &ctx).unwrap(),
        "non-anchored substring must not match"
    );

    ctx.args = serde_json::json!({"path": "/etc/passwd"});
    assert!(!evaluate(&p, &ctx).unwrap(), "unrelated path must not match");
}

#[test]
fn starts_with_with_matches_for_substring_round_07_contrast() {
    // Documentation-as-test: same input, different operator, different
    // result. This is the foot-gun the operator was added to fix.
    let with_matches = parse(r#"arg.path matches "/sandbox""#).unwrap();
    let with_starts_with = parse(r#"arg.path starts_with "/sandbox""#).unwrap();

    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"path": "/etc/sandbox-bypass"});
    assert!(
        evaluate(&with_matches, &ctx).unwrap(),
        "matches accepts substring (the foot-gun)"
    );
    assert!(
        !evaluate(&with_starts_with, &ctx).unwrap(),
        "starts_with rejects (the fix)"
    );
}

#[test]
fn starts_with_on_number_is_type_mismatch() {
    let p = parse(r#"arg.amount starts_with "5""#).unwrap();
    let mut ctx = empty_ctx();
    ctx.args = serde_json::json!({"amount": 50});
    assert!(matches!(
        evaluate(&p, &ctx),
        Err(DslError::TypeMismatch { .. })
    ));
}

#[test]
fn starts_with_composes_with_and_or() {
    // The shopping-agent / fs-agent pattern: tool == X AND arg.path
    // starts_with "<sandbox>". Confirm the operator round-trips through
    // the full boolean parser.
    let p = parse(
        r#"tool == "read_file" AND (arg.path starts_with "/sandbox/" OR arg.path starts_with "/var/tmp/")"#,
    )
    .unwrap();

    let mut ctx = ctx_with("2026-04-27T00:00:00Z", "x", "read_file");
    ctx.args = serde_json::json!({"path": "/sandbox/x.txt"});
    assert!(evaluate(&p, &ctx).unwrap());

    ctx.args = serde_json::json!({"path": "/var/tmp/y.log"});
    assert!(evaluate(&p, &ctx).unwrap());

    ctx.args = serde_json::json!({"path": "/etc/passwd"});
    assert!(!evaluate(&p, &ctx).unwrap());
}

#[test]
fn starts_with_keyword_does_not_munch_idents() {
    // `starts_with_x` is a regular identifier-shaped name; the parser
    // must NOT split it into operator + ident. The grammar disallows
    // `arg.starts_with_x`-style segments, but the principle is the same:
    // keyword recognition requires non-ident-continuation.
    let p = parse(r#"arg.starts_with_x == "y""#);
    // This is a legal identifier path (parser-level), even if the
    // segment "starts_with_x" wouldn't resolve at evaluate time. The
    // important point is the parser doesn't error on it.
    assert!(p.is_ok(), "parser must not split starts_with_x as op + ident");
}
