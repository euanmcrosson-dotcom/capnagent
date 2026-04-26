# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`crates/capnagent-wasm`** — new workspace member providing
  `wasm-bindgen` + `serde-wasm-bindgen` shims around `capnagent-core` for
  JS / WASM consumers. Exposes `Issuer`, `CapabilityBuilder`,
  `Capability`, `Verifier`, `Auditor`, plus an `init()` panic-hook
  installer. Capability JS API uses `Uint8Array` for keys, plain JS
  objects for `Context`/`Receipt`, and throws-on-error semantics.
  Pure-Rust core stays uncontaminated by `wasm-bindgen`.
- CI now runs `cargo clippy` and `cargo check` on the wasm crate, plus
  `cargo test --test integration_tests`, on every push.
- **Integrated entry point: `Verifier::verify_with_context`** wires chain
  integrity + caveat DSL evaluation + audit signing into one call.
  Returns `Result<Receipt, VerifyError>`; the receipt's `outcome` carries
  `Allowed` or `Denied { reason }`. 11 integration tests cover allow,
  deny, malformed-caveat-as-deny, tamper-rejected, cross-key-rejected,
  receipt JSON round-trip, time-caveat semantics, and timestamp recency.
- `VerifyError` enum (variants: `Chain`, `Audit`) re-exported from the
  crate root.
- Caveat DSL parser and evaluator (`caveat_dsl` module): hand-rolled
  recursive-descent parser for the v0 BNF in `docs/WEEK2_SPEC.md` §2.2;
  `parse`, `evaluate`, and `matches` free functions; `Predicate` AST and
  `DslError`. 47 unit tests + 4 proptest invariants.
- Verifier-controlled `Context` (`context` module): builder + canonical-
  JSON `args_hash` deterministic across processes; 17 tests including 3
  proptest invariants for hash determinism.
- Audit-log subsystem (`audit` module): `Receipt`, `ContextSummary`,
  `Outcome`, `Auditor` (HMAC-SHA256 over canonical-JSON-with-signature-
  stripped), append-only NDJSON `AuditLog`; 23 tamper-resistance tests.
- Shared `crate::hex` module factored out of `capability.rs` and
  `audit.rs` to keep the hex encoder in one place.
- `WEEK2_SPEC.md` capturing the locked file-ownership map and type
  contracts that enabled three-terminal parallel implementation.
- `SECURITY.md` with vulnerability disclosure process.
- `.gitattributes` for LF line-ending normalization across platforms.
- (in progress) GitHub Actions CI: `cargo build`, `cargo test` per
  integration target, `cargo clippy`, `cargo fmt --check`,
  `cargo audit`, `cargo deny`.
- (in progress) `deny.toml` for license + advisory + ban policy.

### Changed
- Toolchain-drift fixes against clippy 1.94 / rustfmt 1.94: `&[u8]` over
  `&Vec<u8>`; `is_multiple_of` over `% 2 != 0`; rustfmt-driven
  reformatting in two single-method-call sites.
- Removed flat re-exports of `caveat_dsl` free functions from the crate
  root. Callers reach `parse` / `evaluate` / `matches` through
  `capnagent_core::caveat_dsl::*`.

## [0.0.1] - 2026-04-26

Initial scaffold. Macaroon-style capability core in Rust:

### Added
- `Issuer`, `CapabilityBuilder`, `Capability`, `Caveat`, `Verifier`,
  `Verified` — issue, attenuate, verify with HMAC-SHA256 chain and
  constant-time signature compare.
- URL-safe base64 + JSON serialization for capability tokens.
- 9 proptest cases encoding the cannot-broaden invariant: round-trip,
  attenuation preserves validity, drop-caveat rejects, modify-caveat
  rejects, reorder-caveat rejects, signature-bitflip rejects,
  cross-key-no-verify, adversarial-forgery rejects.
- Threat model and v0 roadmap in `docs/DESIGN.md`.
- Apache-2.0 license.
- `serde_json` pinned to `=1.0.140` to dodge the `zmij` build-script
  block on Windows AppLocker dev machines.

[Unreleased]: https://github.com/euanmcrosson-dotcom/capnagent/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/euanmcrosson-dotcom/capnagent/releases/tag/v0.0.1
