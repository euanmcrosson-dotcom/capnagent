#![allow(missing_docs)]
// `criterion_group!`/`criterion_main!` generate undocumented top-level
// items the workspace's `missing_docs = "warn"` lint flags. Suppress
// for this bench file only.

//! Criterion benchmarks for the 5-gate verify pipeline.
//!
//! Measures the per-call cost of each verifier entry point so we can
//! quote a hard latency number in the README and Show HN. The
//! benchmarks ARE the documentation for "how fast is this?".
//!
//! Each benchmark exercises a different gate combination:
//!
//!   1. `chain_only` — `verify(&cap)`. Just the HMAC chain.
//!   2. `verify_with_context` — chain + caveat evaluation + receipt
//!      sign. Bearer-token path (no proof, no replay).
//!   3. `verify_with_proof` — chain + ed25519 proof + revocation +
//!      caveats + receipt sign. Full hok path. No nonce store
//!      installed.
//!   4. `verify_with_proof_and_replay` — same as (3) but with an
//!      `InMemoryNonceStore` installed. Measures the cost of the
//!      replay-check leg.
//!
//! Capability has 4 caveats including a v0.1 boolean composition with
//! parens, mirroring the kind of cap a real deployment would issue.
//!
//! Run from the workspace root:
//!
//!     cargo bench -p capnagent-core --bench verify_pipeline
//!
//! Criterion writes results to `target/criterion/`. The first line of
//! each report (e.g. `chain_only ... time: [3.2127 µs ...]`) is what
//! ends up in the README.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

use capnagent_core::nonce_store::{InMemoryNonceStore, NonceStore};
use capnagent_core::{pop_challenge_for, Auditor, Capability, Context, Issuer, Verifier};

const ROOT_KEY: &[u8] = b"bench-root-key-32-bytes-pls-thx!";
const AUDIT_KEY: &[u8] = b"bench-audit-key-32-bytes-pls-thx";

fn ctx_for(tool: &str) -> Context {
    Context {
        now: SystemTime::now(),
        caller: "agent:bench".into(),
        tool: tool.into(),
        args: serde_json::json!({ "merchant": "amazon.com", "amount": 12.50 }),
        env: HashMap::new(),
    }
}

fn issue_bearer() -> Capability {
    Issuer::from_key(ROOT_KEY)
        .issue("buy")
        .caveat(r#"caller == "agent:bench""#)
        .caveat("now <= @2099-01-01T00:00:00Z")
        .caveat(
            r#"tool == "catalog.search" OR (tool == "checkout.purchase" AND arg.merchant == "amazon.com" AND arg.amount <= 50.00)"#,
        )
        .build()
}

fn issue_hok(signing_key: &SigningKey) -> Capability {
    Issuer::from_key(ROOT_KEY)
        .issue("buy-hok")
        .holder_of_key(signing_key.verifying_key().as_bytes())
        .caveat(r#"caller == "agent:bench""#)
        .caveat("now <= @2099-01-01T00:00:00Z")
        .caveat(
            r#"tool == "catalog.search" OR (tool == "checkout.purchase" AND arg.merchant == "amazon.com" AND arg.amount <= 50.00)"#,
        )
        .build()
}

fn bench_chain_only(c: &mut Criterion) {
    let cap = issue_bearer();
    let verifier = Verifier::new(ROOT_KEY);
    c.bench_function("chain_only", |b| {
        b.iter(|| {
            let _ = verifier.verify(black_box(&cap)).unwrap();
        })
    });
}

fn bench_verify_with_context(c: &mut Criterion) {
    let cap = issue_bearer();
    let verifier = Verifier::new(ROOT_KEY);
    let auditor = Auditor::new(AUDIT_KEY);
    let ctx = ctx_for("checkout.purchase");
    c.bench_function("verify_with_context", |b| {
        b.iter(|| {
            let _ = verifier
                .verify_with_context(black_box(&cap), black_box(&ctx), black_box(&auditor))
                .unwrap();
        })
    });
}

fn bench_verify_with_proof(c: &mut Criterion) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let cap = issue_hok(&signing_key);
    let verifier = Verifier::new(ROOT_KEY);
    let auditor = Auditor::new(AUDIT_KEY);
    let ctx = ctx_for("checkout.purchase");

    // Pre-compute the proof; the bench measures verifier cost, not
    // signer cost. Real deployments compute the signature once per
    // tool call on the holder's side.
    let challenge = pop_challenge_for(&cap, &ctx);
    let proof = signing_key.sign(&challenge).to_bytes();

    c.bench_function("verify_with_proof", |b| {
        b.iter(|| {
            let _ = verifier
                .verify_with_proof(
                    black_box(&cap),
                    black_box(&ctx),
                    black_box(&auditor),
                    black_box(&challenge),
                    black_box(&proof),
                )
                .unwrap();
        })
    });
}

fn bench_verify_with_proof_and_replay(c: &mut Criterion) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let cap = issue_hok(&signing_key);
    let store = Arc::new(InMemoryNonceStore::new());
    let dyn_store: Arc<dyn NonceStore> = Arc::clone(&store) as _;
    let verifier = Verifier::new(ROOT_KEY).with_nonce_store(dyn_store);
    let auditor = Auditor::new(AUDIT_KEY);

    // Pre-generate a batch of (ctx, challenge, proof) triples. Each
    // iteration rotates through the batch so the nonce store sees a
    // fresh entry without paying for ed25519 signing in the inner
    // loop. Batch size is large enough that the first replay-rejection
    // doesn't fire within a single bench sample (criterion targets
    // ~5s of wall time per bench).
    const BATCH: usize = 65_536;
    let mut fixtures = Vec::with_capacity(BATCH);
    for i in 0..BATCH {
        let ctx = Context {
            now: SystemTime::UNIX_EPOCH
                + std::time::Duration::from_millis(1_700_000_000_000 + i as u64),
            caller: "agent:bench".into(),
            tool: "checkout.purchase".into(),
            args: serde_json::json!({ "merchant": "amazon.com", "amount": 12.50 }),
            env: HashMap::new(),
        };
        let challenge = pop_challenge_for(&cap, &ctx);
        let proof = signing_key.sign(&challenge).to_bytes();
        fixtures.push((ctx, challenge, proof));
    }

    let mut idx: usize = 0;
    c.bench_function("verify_with_proof_and_replay", |b| {
        b.iter(|| {
            let (ctx, challenge, proof) = &fixtures[idx];
            idx = (idx + 1) % BATCH;
            let _ = verifier
                .verify_with_proof(
                    black_box(&cap),
                    black_box(ctx),
                    black_box(&auditor),
                    black_box(challenge),
                    black_box(proof),
                )
                .unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_chain_only,
    bench_verify_with_context,
    bench_verify_with_proof,
    bench_verify_with_proof_and_replay,
);
criterion_main!(benches);
