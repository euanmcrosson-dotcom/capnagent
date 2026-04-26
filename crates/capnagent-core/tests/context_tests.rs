//! Tests for the [`Context`] / [`ContextBuilder`] and [`Context::args_hash`]
//! canonical-JSON determinism contract from `docs/WEEK2_SPEC.md` §2.1.
//!
//! `context.rs` is not yet wired into `lib.rs` (per WEEK2_SPEC §1
//! file-ownership rules — module wiring happens at merge time, not on this
//! branch). We pull the source in directly with `#[path]` so this test file
//! still owns nothing outside the assigned scope.

// `missing_docs` is workspace-warn but the `#[path]`-included module exposes
// fully-documented `pub` items already; suppress noise on the rest of this
// integration-test file.
#![allow(missing_docs)]

#[path = "../src/context.rs"]
mod context;

use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use serde_json::{json, Map, Value};

use context::Context;

// ---------------------------------------------------------------------------
// Builder defaults & setters
// ---------------------------------------------------------------------------

#[test]
fn builder_defaults_match_spec() {
    let before = SystemTime::now();
    let ctx = Context::builder().build();
    let after = SystemTime::now();

    assert_eq!(ctx.caller, "");
    assert_eq!(ctx.tool, "");
    assert_eq!(ctx.args, Value::Null);
    assert!(ctx.env.is_empty());
    // `now` defaults to `SystemTime::now()` taken inside `builder()`.
    assert!(
        ctx.now >= before,
        "default now must not precede builder() call"
    );
    assert!(
        ctx.now <= after,
        "default now must not follow build() return"
    );
}

#[test]
fn builder_setters_round_trip_every_field() {
    let pinned = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let ctx = Context::builder()
        .now(pinned)
        .caller("agent:planner")
        .tool("http.post")
        .args(json!({"merchant": "amazon.com", "amount": 42}))
        .env("region", "us-east-1")
        .env("zone", "a")
        .build();

    assert_eq!(ctx.now, pinned);
    assert_eq!(ctx.caller, "agent:planner");
    assert_eq!(ctx.tool, "http.post");
    assert_eq!(ctx.args, json!({"merchant": "amazon.com", "amount": 42}));
    assert_eq!(ctx.env.get("region").map(String::as_str), Some("us-east-1"));
    assert_eq!(ctx.env.get("zone").map(String::as_str), Some("a"));
    assert_eq!(ctx.env.len(), 2);
}

#[test]
fn builder_env_reinsert_overwrites() {
    // Spec says `env(k, v)` inserts; HashMap semantics give last-write-wins.
    let ctx = Context::builder()
        .env("k", "first")
        .env("k", "second")
        .build();
    assert_eq!(ctx.env.get("k").map(String::as_str), Some("second"));
    assert_eq!(ctx.env.len(), 1);
}

// ---------------------------------------------------------------------------
// args_hash basic shape
// ---------------------------------------------------------------------------

#[test]
fn args_hash_is_64_lowercase_hex_chars() {
    let h = Context::builder().args(json!({"a": 1})).build().args_hash();
    assert_eq!(h.len(), 64, "SHA-256 hex must be 64 chars");
    assert!(
        h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "args_hash must be lowercase hex only, got {h:?}"
    );
}

#[test]
fn args_hash_ignores_caller_tool_env() {
    // Only `args` feeds the digest; everything else is summarized elsewhere
    // by the audit module. Confirm that with two contexts that differ in
    // every non-args field but share `args`.
    let shared = json!({"x": 1});
    let a = Context::builder()
        .args(shared.clone())
        .caller("alice")
        .tool("t1")
        .env("k", "v")
        .build();
    let b = Context::builder()
        .args(shared)
        .caller("bob")
        .tool("t2")
        .env("k2", "v2")
        .build();
    assert_eq!(a.args_hash(), b.args_hash());
}

// ---------------------------------------------------------------------------
// args_hash determinism — hand-rolled cases
// ---------------------------------------------------------------------------

#[test]
fn args_hash_is_stable_across_two_builds_of_the_same_value() {
    let v = json!({
        "merchant": "amazon.com",
        "amount": 42,
        "items": ["cable", "adapter"],
        "meta": {"locale": "en-US", "channel": "web"}
    });
    let a = Context::builder().args(v.clone()).build().args_hash();
    let b = Context::builder().args(v).build().args_hash();
    assert_eq!(a, b);
}

#[test]
fn args_hash_invariant_under_top_level_key_reordering() {
    let a = Context::builder()
        .args(json!({"a": 1, "b": 2, "c": 3}))
        .build()
        .args_hash();
    let b = Context::builder()
        .args(json!({"c": 3, "b": 2, "a": 1}))
        .build()
        .args_hash();
    assert_eq!(a, b);
}

#[test]
fn args_hash_invariant_under_nested_key_reordering() {
    let a = Context::builder()
        .args(json!({"outer": {"x": 1, "y": 2, "z": 3}}))
        .build()
        .args_hash();
    let b = Context::builder()
        .args(json!({"outer": {"z": 3, "y": 2, "x": 1}}))
        .build()
        .args_hash();
    assert_eq!(a, b);
}

#[test]
fn args_hash_invariant_under_manually_constructed_reverse_insertion() {
    // Build the same JSON object twice, inserting keys in opposite orders.
    // This exercises the canonicalizer even on a `serde_json::Map` backend
    // that preserves insertion order.
    let pairs = [("alpha", 1), ("beta", 2), ("gamma", 3), ("delta", 4)];

    let mut forward = Map::new();
    for (k, v) in pairs.iter() {
        forward.insert((*k).to_string(), json!(v));
    }
    let mut reverse = Map::new();
    for (k, v) in pairs.iter().rev() {
        reverse.insert((*k).to_string(), json!(v));
    }

    let a = Context::builder()
        .args(Value::Object(forward))
        .build()
        .args_hash();
    let b = Context::builder()
        .args(Value::Object(reverse))
        .build()
        .args_hash();
    assert_eq!(a, b);
}

#[test]
fn args_hash_array_order_matters() {
    // Arrays are ordered in JSON. Reordering them changes the value's
    // identity, so the hash MUST change.
    let a = Context::builder()
        .args(json!([1, 2, 3]))
        .build()
        .args_hash();
    let b = Context::builder()
        .args(json!([3, 2, 1]))
        .build()
        .args_hash();
    assert_ne!(a, b);
}

#[test]
fn args_hash_changes_when_a_value_changes() {
    let a = Context::builder().args(json!({"k": 1})).build().args_hash();
    let b = Context::builder().args(json!({"k": 2})).build().args_hash();
    assert_ne!(a, b);
}

#[test]
fn args_hash_changes_when_a_nested_value_changes() {
    let a = Context::builder()
        .args(json!({"a": {"b": {"c": 1}}}))
        .build()
        .args_hash();
    let b = Context::builder()
        .args(json!({"a": {"b": {"c": 2}}}))
        .build()
        .args_hash();
    assert_ne!(a, b);
}

#[test]
fn args_hash_distinguishes_string_from_number() {
    // `"1"` and `1` are different JSON values; the digest must reflect that.
    let a = Context::builder()
        .args(json!({"k": "1"}))
        .build()
        .args_hash();
    let b = Context::builder().args(json!({"k": 1})).build().args_hash();
    assert_ne!(a, b);
}

#[test]
fn args_hash_distinguishes_null_from_missing() {
    let a = Context::builder()
        .args(json!({"k": null}))
        .build()
        .args_hash();
    let b = Context::builder().args(json!({})).build().args_hash();
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// Property tests — the load-bearing determinism contract
// ---------------------------------------------------------------------------

/// Build an arbitrary `serde_json::Value` of bounded depth and breadth.
fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|i| json!(i)),
        // Restricted string alphabet keeps proptest output readable; the
        // canonicalizer's correctness on any UTF-8 string follows from
        // `serde_json::to_string`'s own escaping behavior.
        "[a-zA-Z0-9 ._:/@-]{0,32}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec(("[a-zA-Z][a-zA-Z0-9_]{0,8}", inner), 0..6).prop_map(|kvs| {
                let mut map = Map::new();
                for (k, v) in kvs {
                    map.insert(k, v);
                }
                Value::Object(map)
            }),
        ]
    })
}

proptest! {
    /// Identical input must produce identical hash, regardless of context.
    /// This is the single most important property the audit module relies
    /// on.
    #[test]
    fn prop_args_hash_is_deterministic(v in arb_json()) {
        let a = Context::builder().args(v.clone()).build().args_hash();
        let b = Context::builder().args(v).build().args_hash();
        prop_assert_eq!(a, b);
    }

    /// Reordering the keys of a top-level JSON object must not change the
    /// hash. Builds two objects from the same key/value set in opposite
    /// insertion orders.
    #[test]
    fn prop_args_hash_invariant_under_key_reorder(
        kvs in prop::collection::vec(
            ("[a-zA-Z][a-zA-Z0-9_]{0,8}", any::<i64>()),
            1..8,
        ),
    ) {
        let mut forward = Map::new();
        for (k, v) in &kvs {
            forward.insert(k.clone(), json!(v));
        }
        let mut reverse = Map::new();
        for (k, v) in kvs.iter().rev() {
            reverse.insert(k.clone(), json!(v));
        }
        // Duplicate keys collapse to last-write-wins; if forward and reverse
        // disagree on the final value for a key, they aren't the same JSON
        // value and the test premise doesn't hold.
        prop_assume!(forward == reverse);

        let a = Context::builder().args(Value::Object(forward)).build().args_hash();
        let b = Context::builder().args(Value::Object(reverse)).build().args_hash();
        prop_assert_eq!(a, b);
    }

    /// Changing a single value inside an otherwise-identical JSON object
    /// must change the hash. (This is collision resistance up to SHA-256;
    /// in practice it always holds.)
    #[test]
    fn prop_args_hash_changes_when_a_value_changes(
        k in "[a-zA-Z][a-zA-Z0-9_]{0,8}",
        v1 in any::<i64>(),
        v2 in any::<i64>(),
    ) {
        prop_assume!(v1 != v2);
        let mut a = Map::new();
        a.insert(k.clone(), json!(v1));
        let mut b = Map::new();
        b.insert(k, json!(v2));

        let ha = Context::builder().args(Value::Object(a)).build().args_hash();
        let hb = Context::builder().args(Value::Object(b)).build().args_hash();
        prop_assert_ne!(ha, hb);
    }
}
