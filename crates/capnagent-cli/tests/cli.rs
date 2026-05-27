//! End-to-end integration tests for the `capnagent` binary: keygen → mint →
//! inspect → verify round-trips, plus the fail-closed key handling.

use std::process::Command;

struct Run {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_capnagent"))
        .args(args)
        .output()
        .expect("spawn capnagent");
    Run {
        ok: out.status.success(),
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn keygen() -> String {
    let r = run(&["keygen"]);
    assert!(r.ok, "keygen failed: {}", r.stderr);
    r.stdout.trim().to_string()
}

#[test]
fn keygen_emits_distinct_32_byte_base64_keys() {
    let a = keygen();
    let b = keygen();
    // STANDARD base64 of 32 bytes is 44 chars (with one '=' pad).
    assert_eq!(a.len(), 44, "expected 44-char base64 key; got {a:?}");
    assert!(a.ends_with('='));
    assert_ne!(a, b, "two keygens must produce different keys");
}

#[test]
fn no_key_fails_closed_with_no_placeholder() {
    // Minting with no key must error — there is no silent public placeholder.
    let r = run(&["--agent", "bot", "--tools", "checkout.purchase"]);
    assert!(!r.ok, "minting without a key must fail");
    assert!(
        r.stderr.to_lowercase().contains("signing key"),
        "stderr should explain the missing key; got: {}",
        r.stderr
    );
}

#[test]
fn mint_inspect_verify_round_trip() {
    let key = keygen();

    // Mint a token scoped to one tool.
    let mint = run(&[
        "--agent",
        "bot",
        "--tools",
        "checkout.purchase",
        "--key",
        &key,
    ]);
    assert!(mint.ok, "mint failed: {}", mint.stderr);
    let token = mint.stdout.trim().to_string();
    assert!(!token.is_empty());

    // `inspect` needs no key and shows the (now verifiable) caveats.
    let insp = run(&["inspect", &token]);
    assert!(insp.ok, "inspect failed: {}", insp.stderr);
    assert!(
        insp.stdout.contains("checkout.purchase"),
        "inspect: {}",
        insp.stdout
    );
    assert!(
        insp.stdout.contains("now <= @"),
        "inspect should show the expiry caveat: {}",
        insp.stdout
    );

    // `verify` against the in-scope tool → allowed → exit 0.
    let ctx_ok = r#"{"caller":"x","tool":"checkout.purchase","args":{},"nowMs":1700000000000}"#;
    let ok = run(&["verify", &token, "--context", ctx_ok, "--key", &key]);
    assert!(
        ok.ok && ok.code == 0,
        "verify (allowed) should exit 0; stderr: {}",
        ok.stderr
    );
    assert!(
        ok.stdout.contains("allowed"),
        "receipt should be allowed: {}",
        ok.stdout
    );

    // `verify` against an out-of-scope tool → denied → exit 2.
    let ctx_bad = r#"{"caller":"x","tool":"bank.wire","args":{},"nowMs":1700000000000}"#;
    let denied = run(&["verify", &token, "--context", ctx_bad, "--key", &key]);
    assert_eq!(
        denied.code, 2,
        "verify (denied) should exit 2; stderr: {}",
        denied.stderr
    );
    assert!(
        denied.stdout.contains("denied"),
        "receipt should be denied: {}",
        denied.stdout
    );
}

#[test]
fn verify_under_wrong_key_is_a_chain_failure() {
    let key = keygen();
    let other = keygen();
    let token = run(&["--agent", "bot", "--tools", "x", "--key", &key])
        .stdout
        .trim()
        .to_string();

    // A forged/wrong-issuer token fails the HMAC chain → exit 1 (not 0/2).
    let ctx = r#"{"caller":"x","tool":"x","args":{},"nowMs":1700000000000}"#;
    let r = run(&["verify", &token, "--context", ctx, "--key", &other]);
    assert_eq!(
        r.code, 1,
        "wrong-key verify should exit 1; stderr: {}",
        r.stderr
    );
    let e = r.stderr.to_lowercase();
    assert!(
        e.contains("chain") || e.contains("verification"),
        "stderr: {}",
        r.stderr
    );
}
