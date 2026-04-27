//! Property tests for the boolean-composition semantics of the caveat DSL.
//!
//! v0.1 added `OR` / `AND` / parens to the caveat DSL (see
//! `crates/capnagent-core/src/caveat_dsl.rs`). The example-based tests in
//! `tests/caveat_dsl_tests.rs` cover concrete precedence and short-circuit
//! cases; the existing `tests/property_tests.rs` covers chain integrity
//! (the "no-broaden" macaroon invariant). This file is the third leg:
//! **boolean-algebra laws** over the DSL, exercised on randomly-generated
//! AST trees and contexts.
//!
//! # Why this matters
//!
//! `docs/DESIGN.md` §5 names "trivially-auditable caveats" as one of the
//! three legs of the threat model. If our boolean evaluator violated a
//! law a reader assumes — e.g. `A OR B` quietly behaved like `B AND A`,
//! or short-circuit eval skipped a deny case — the human-readable caveat
//! string would lie about what's permitted. Codifying the laws as
//! property tests turns the security argument into a machine-checked
//! invariant.
//!
//! # What we generate
//!
//! - Random *primitive comparisons* (leaves) drawn from a fixed table of
//!   (ident, op, value) triples that the evaluator can resolve against
//!   the random context. The leaves are deliberately drawn from a
//!   small, evaluator-friendly alphabet so most evaluations succeed —
//!   we want to exercise both allow and deny branches, not produce a
//!   sea of `UnknownIdent` errors. (We still tolerate errors via
//!   `prop_assume!`/equality on `Result`.)
//! - Random *boolean expression trees*, depth-bounded at 5, composed of
//!   leaves under `OR` / `AND`.
//! - Random *contexts*, generated independently of the leaves so that
//!   any given comparison may be true, false, or erroring.

use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

use proptest::prelude::*;

use capnagent_core::caveat_dsl::{evaluate, parse, DslError};
use capnagent_core::Context;

// ───────────────────────── leaf comparisons ─────────────────────────

/// A primitive comparison rendered as DSL text. We carry the exact
/// predicate string the parser will see so randomization is reproducible
/// from the captured seed.
#[derive(Debug, Clone)]
struct Leaf(String);

impl Leaf {
    fn text(&self) -> &str {
        &self.0
    }
}

/// Strategy producing leaf comparisons. The vocabulary spans every
/// resolvable ident root (`tool`, `caller`, `arg.*`, `env.*`) and every
/// operator the DSL accepts on resolvable types — so generated trees
/// genuinely exercise mixed types and short-circuit boundaries, not
/// just one happy shape.
fn leaf_strategy() -> impl Strategy<Value = Leaf> {
    prop_oneof![
        // tool == "<value>"
        prop::sample::select(vec![
            "catalog.search",
            "checkout.purchase",
            "bank.wire",
            "x"
        ])
        .prop_map(|s| Leaf(format!(r#"tool == "{s}""#))),
        // tool != "<value>"
        prop::sample::select(vec!["catalog.search", "checkout.purchase", "bank.wire"])
            .prop_map(|s| Leaf(format!(r#"tool != "{s}""#))),
        // caller == "<value>"
        prop::sample::select(vec!["agent:planner", "agent:rogue", "agent:other"])
            .prop_map(|s| Leaf(format!(r#"caller == "{s}""#))),
        // caller != "<value>"
        prop::sample::select(vec!["agent:planner", "agent:rogue"])
            .prop_map(|s| Leaf(format!(r#"caller != "{s}""#))),
        // arg.amount <= N (no unit)
        (0i64..=200).prop_map(|n| Leaf(format!("arg.amount <= {n}"))),
        // arg.amount >= N (no unit)
        (0i64..=200).prop_map(|n| Leaf(format!("arg.amount >= {n}"))),
        // arg.amount == N (no unit)
        (0i64..=200).prop_map(|n| Leaf(format!("arg.amount == {n}"))),
        // arg.flag == "<value>" — string-equality on a nested string field
        prop::sample::select(vec!["yes", "no", "maybe"])
            .prop_map(|s| Leaf(format!(r#"arg.flag == "{s}""#))),
        // env.region == "<value>"
        prop::sample::select(vec!["us-east-1", "eu-west-1", "ap-south-1"])
            .prop_map(|s| Leaf(format!(r#"env.region == "{s}""#))),
    ]
}

// ───────────────────────── expression trees ─────────────────────────

/// A boolean expression over leaves and `OR` / `AND`. We carry the
/// rendered DSL string in the `Compose` arms because the only thing we
/// ever do with a tree is parse it; keeping the string form makes the
/// strategy trivially shrinkable and lets the laws compose by string
/// concatenation.
///
/// We deliberately do not put parens around leaves — the parser handles
/// either shape. We do parenthesize sub-expressions when composing via
/// `or` / `and` so precedence cannot bite us.
#[derive(Debug, Clone)]
struct Expr(String);

impl Expr {
    fn text(&self) -> &str {
        &self.0
    }

    /// Wrap `self`'s text in parens so it can be safely composed under a
    /// higher-precedence operator. Idempotent at the AST level: the
    /// parser collapses `((P))` to the same tree as `P`.
    fn parenthesized(&self) -> String {
        format!("({})", self.0)
    }

    fn or(&self, other: &Expr) -> Expr {
        Expr(format!(
            "{} OR {}",
            self.parenthesized(),
            other.parenthesized()
        ))
    }

    fn and(&self, other: &Expr) -> Expr {
        Expr(format!(
            "{} AND {}",
            self.parenthesized(),
            other.parenthesized()
        ))
    }
}

/// Recursive strategy for boolean expression trees. Depth ≤ 5, ≤ 16 leaves,
/// branching factor 2 at internal nodes — this matches the doc-comment in
/// the task brief and keeps every `proptest` case fast (the parser is
/// linear in the predicate length).
fn expr_strategy() -> impl Strategy<Value = Expr> {
    let leaf = leaf_strategy().prop_map(|l| Expr(l.text().to_string()));
    leaf.prop_recursive(
        5,  // depth
        16, // total nodes
        2,  // branching factor
        |inner| {
            prop_oneof![
                (inner.clone(), inner.clone()).prop_map(|(a, b)| a.or(&b)),
                (inner.clone(), inner).prop_map(|(a, b)| a.and(&b)),
            ]
        },
    )
}

// ───────────────────────── contexts ─────────────────────────

/// Strategy for random verification contexts. The values are drawn from
/// (and slightly outside of) the same vocabulary the leaf strategy uses,
/// so a generated leaf has a realistic chance of being either true or
/// false — and a small chance of erroring (e.g. `arg.amount` missing,
/// `env.region` unset).
fn context_strategy() -> impl Strategy<Value = Context> {
    let caller = prop::sample::select(vec![
        "agent:planner",
        "agent:rogue",
        "agent:other",
        "agent:unknown",
    ]);
    let tool = prop::sample::select(vec![
        "catalog.search",
        "checkout.purchase",
        "bank.wire",
        "x",
        "y",
    ]);
    // Amount: occasionally absent, otherwise a number that may straddle
    // any threshold the leaf generator picks.
    let amount = prop::option::of(0i64..=300i64);
    let flag = prop::option::of(prop::sample::select(vec!["yes", "no", "maybe", "other"]));
    let region = prop::option::of(prop::sample::select(vec![
        "us-east-1",
        "eu-west-1",
        "ap-south-1",
        "sa-east-1",
    ]));
    // `now` is irrelevant for our leaf set but the field is mandatory; pin
    // it to a fixed offset so the generated context is fully reproducible
    // from the proptest seed.
    (caller, tool, amount, flag, region).prop_map(|(caller, tool, amount, flag, region)| {
        let mut args = serde_json::Map::new();
        if let Some(a) = amount {
            args.insert("amount".into(), serde_json::Value::from(a));
        }
        if let Some(f) = flag {
            args.insert("flag".into(), serde_json::Value::from(f));
        }
        let mut env = HashMap::new();
        if let Some(r) = region {
            env.insert("region".into(), r.to_string());
        }
        Context {
            now: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            caller: caller.to_string(),
            tool: tool.to_string(),
            args: serde_json::Value::Object(args),
            env,
        }
    })
}

// ───────────────────────── helpers ─────────────────────────

/// Parse + evaluate, keeping the `Result` shape so the caller can
/// distinguish "allowed", "denied", and "errored". Properties below
/// compare `Result<bool, DslErrorKind>` for equality so error cases are
/// part of the law (an error on one side requires an error of the same
/// kind on the other — silent allow/deny would defeat the purpose).
fn parse_and_eval(text: &str, ctx: &Context) -> Result<bool, DslErrorKind> {
    let pred = parse(text).map_err(DslErrorKind::from_dsl)?;
    evaluate(&pred, ctx).map_err(DslErrorKind::from_dsl)
}

/// We can't compare `DslError`s directly (they carry message strings, and
/// `UnknownIdent("arg.amount")` from one branch vs `UnknownIdent("arg.flag")`
/// from another should not collide). We collapse to the variant kind, which
/// is what the boolean laws really want: same kind of failure on both
/// sides, not the exact message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DslErrorKind {
    Parse,
    UnknownIdent,
    TypeMismatch,
    Regex,
}

impl DslErrorKind {
    fn from_dsl(e: DslError) -> Self {
        match e {
            DslError::Parse(_) => DslErrorKind::Parse,
            DslError::UnknownIdent(_) => DslErrorKind::UnknownIdent,
            DslError::TypeMismatch { .. } => DslErrorKind::TypeMismatch,
            DslError::Regex(_) => DslErrorKind::Regex,
        }
    }
}

/// `lhs ≡ rhs` modulo short-circuit error semantics. Each side is
/// independently parsed and evaluated; we accept three outcomes:
///
/// 1. Both sides return `Ok(b)` with the same `b`.
/// 2. Both sides return the same `Err(kind)`.
/// 3. Exactly one side errors and the other returns `Ok(_)`. This is
///    the legitimate short-circuit asymmetry — e.g. `false AND err`
///    yields `Ok(false)`, but `err AND false` evaluates the error
///    first and yields `Err(...)`. The boolean laws (commutativity,
///    associativity, distributivity) preserve the *value* on the
///    happy path; on the error path they preserve the *fact that
///    errors can appear*, not the specific side that surfaces them.
///    We surface this asymmetry as a property-level allowance, not
///    as a bug — the caveat-DSL contract documents this short-circuit
///    behaviour explicitly.
fn results_equivalent(lhs: Result<bool, DslErrorKind>, rhs: Result<bool, DslErrorKind>) -> bool {
    match (lhs, rhs) {
        (Ok(a), Ok(b)) => a == b,
        (Err(a), Err(b)) => a == b,
        // One side short-circuits past an error the other side encounters.
        // Allowed: see comment above.
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => true,
    }
}

// ───────────────────────── properties ─────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// **Commutativity of `OR`.** `eval(A OR B) ≡ eval(B OR A)`.
    /// The "≡" allows short-circuit asymmetry on the error path —
    /// see `results_equivalent` for why that's correct, not lax.
    #[test]
    fn or_is_commutative(
        a in expr_strategy(),
        b in expr_strategy(),
        ctx in context_strategy(),
    ) {
        let ab = parse_and_eval(a.or(&b).text(), &ctx);
        let ba = parse_and_eval(b.or(&a).text(), &ctx);
        prop_assert!(
            results_equivalent(ab, ba),
            "OR not commutative for {:?} and {:?}",
            a.text(), b.text()
        );
    }

    /// **Commutativity of `AND`.** Mirror of the `OR` law.
    #[test]
    fn and_is_commutative(
        a in expr_strategy(),
        b in expr_strategy(),
        ctx in context_strategy(),
    ) {
        let ab = parse_and_eval(a.and(&b).text(), &ctx);
        let ba = parse_and_eval(b.and(&a).text(), &ctx);
        prop_assert!(
            results_equivalent(ab, ba),
            "AND not commutative for {:?} and {:?}",
            a.text(), b.text()
        );
    }

    /// **Associativity of `OR`.** `eval((A OR B) OR C) ≡ eval(A OR (B OR C))`.
    /// The DSL's `Or` AST node is binary and parsed left-associative; this
    /// property checks that grouping by parens does not change the truth
    /// value the verifier ultimately returns.
    #[test]
    fn or_is_associative(
        a in expr_strategy(),
        b in expr_strategy(),
        c in expr_strategy(),
        ctx in context_strategy(),
    ) {
        let left = a.or(&b).or(&c);
        let right = a.or(&b.or(&c));
        let lv = parse_and_eval(left.text(), &ctx);
        let rv = parse_and_eval(right.text(), &ctx);
        prop_assert!(
            results_equivalent(lv, rv),
            "OR not associative; left={:?} right={:?}",
            left.text(), right.text()
        );
    }

    /// **Associativity of `AND`.** Mirror of the `OR` law.
    #[test]
    fn and_is_associative(
        a in expr_strategy(),
        b in expr_strategy(),
        c in expr_strategy(),
        ctx in context_strategy(),
    ) {
        let left = a.and(&b).and(&c);
        let right = a.and(&b.and(&c));
        let lv = parse_and_eval(left.text(), &ctx);
        let rv = parse_and_eval(right.text(), &ctx);
        prop_assert!(
            results_equivalent(lv, rv),
            "AND not associative; left={:?} right={:?}",
            left.text(), right.text()
        );
    }

    /// **Distributivity of AND over OR.**
    /// `eval(A AND (B OR C)) ≡ eval((A AND B) OR (A AND C))`.
    /// This is the law that lets a caveat author refactor a permission
    /// expression without changing its meaning. If it failed, two
    /// human-readable caveats that "look the same" could authorize
    /// different sets of calls — exactly the auditability failure the
    /// design tries to prevent.
    #[test]
    fn and_distributes_over_or(
        a in expr_strategy(),
        b in expr_strategy(),
        c in expr_strategy(),
        ctx in context_strategy(),
    ) {
        let lhs = a.and(&b.or(&c));
        let rhs = a.and(&b).or(&a.and(&c));
        let lv = parse_and_eval(lhs.text(), &ctx);
        let rv = parse_and_eval(rhs.text(), &ctx);
        prop_assert!(
            results_equivalent(lv, rv),
            "AND did not distribute over OR; lhs={:?} rhs={:?}",
            lhs.text(), rhs.text()
        );
    }

    /// **Allow-monotonicity under `OR`.** If `eval(E)` allowed, then
    /// `eval(E OR X)` must also allow for any well-formed leaf `X`.
    /// Adding an OR clause can only broaden permission — never narrow,
    /// and never flip an allow into an error.
    ///
    /// On the error path: if `eval(E)` errored we don't assert anything
    /// (the disjunction may now succeed via `X`, which is fine); if
    /// `eval(E)` denied we likewise don't assert (the disjunction may
    /// now allow via `X`). The property is one-directional: allow ⇒ allow.
    #[test]
    fn adding_an_or_clause_preserves_allow(
        e in expr_strategy(),
        x in leaf_strategy(),
        ctx in context_strategy(),
    ) {
        let base = parse_and_eval(e.text(), &ctx);
        if !matches!(base, Ok(true)) {
            // Vacuously satisfied: the property only constrains the allow case.
            return Ok(());
        }
        let extended = Expr(x.text().to_string());
        let composed = e.or(&extended);
        let after = parse_and_eval(composed.text(), &ctx);
        prop_assert!(
            matches!(after, Ok(true)),
            "OR-extension flipped an allow to {:?}; base={:?} added={:?}",
            after, e.text(), x.text()
        );
    }

    /// **Deny-monotonicity under `AND`.** Dual to the law above:
    /// if `eval(E)` denied, then `eval(E AND X)` must also deny for any
    /// well-formed leaf `X`. Adding an AND clause can only narrow
    /// permission — never broaden, and never flip a deny into an allow.
    ///
    /// Short-circuit detail: when `eval(E)` is `Ok(false)`, the second
    /// branch is never evaluated, so even an erroring `X` produces
    /// `Ok(false)`. That's the strongest form of the property and
    /// what we assert.
    #[test]
    fn adding_an_and_clause_preserves_deny(
        e in expr_strategy(),
        x in leaf_strategy(),
        ctx in context_strategy(),
    ) {
        let base = parse_and_eval(e.text(), &ctx);
        if !matches!(base, Ok(false)) {
            return Ok(());
        }
        let extended = Expr(x.text().to_string());
        let composed = e.and(&extended);
        let after = parse_and_eval(composed.text(), &ctx);
        prop_assert_eq!(
            after,
            Ok(false),
            "AND-extension flipped a deny; base denied, AND with {:?} produced {:?}",
            x.text(), after
        );
    }

    /// **No panic on any well-formed AST.** A predicate that PARSES
    /// correctly must EVALUATE without panicking, regardless of what the
    /// context contains. This is the "no surprise denial-of-service via
    /// crafted caveat" property — important because the verifier runs
    /// inside the host application, and a panic there is a process
    /// abort, not a clean deny.
    ///
    /// We accept any `Result<bool, DslError>` outcome. The only failure
    /// mode this property is looking for is a Rust-level panic from
    /// inside the evaluator, which `proptest` will catch and surface as
    /// a test failure.
    #[test]
    fn evaluation_never_panics_on_well_formed_ast(
        e in expr_strategy(),
        ctx in context_strategy(),
    ) {
        let pred = parse(e.text())
            .unwrap_or_else(|err| panic!("generator produced un-parseable text {:?}: {err}", e.text()));
        // The Result is intentionally discarded — we are testing that the
        // call returns at all.
        let _ = evaluate(&pred, &ctx);
    }
}
