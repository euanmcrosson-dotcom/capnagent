# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **demo: hok scenario now exercises v0.1 boolean composition.** New
  `issueHokCapability(publicKey)` issues ONE hok-bound capability with
  a disjunction + decimal caveat:
  ```
  tool == "catalog.search"
    OR (tool == "checkout.purchase" AND arg.merchant == "amazon.com" AND arg.amount <= 50.00)
  ```
  Both `catalog.search` and `checkout.purchase` route through a
  single guard. `bank.wire` falls outside both branches of the OR
  and is denied. The previous two-capability form
  (`issueHokBrowseCapability` + `issueHokBuyCapability`) is retained
  for backward compat with existing tests but no longer the
  recommended path. CLI's hok summary message updated to flag the
  v0.1 surface.
- **v0.1 — Replay protection (`NonceStore`).** New `nonce_store`
  module exposes the `NonceStore` trait + `InMemoryNonceStore` (TTL
  HashMap) impl. `Verifier::with_nonce_store(store)` is opt-in;
  defaults to no replay check (preserving the v0.1-DPoP baseline).
  When installed, `verify_with_proof` adds a 3rd gate (after chain
  + proof, before revocation): `sha256(proof_bytes)` is recorded;
  re-use within `nonce_ttl_ms` (default 5 minutes) becomes
  `Outcome::Denied { reason: "proof replay detected" }`. Crucially,
  bad proofs are NOT recorded — they don't lock out a legitimate
  retry. `verify_with_context` (non-hok bearer tokens) does not
  consult the store; bearer tokens are explicitly designed to be
  reusable. 14 new tests including a thread-safety stress and a
  TTL-boundary check.
- **v0.1 — Caveat DSL: boolean composition (`OR` / `AND` / parens).**
  BNF extended:
  `predicate ::= or_expr; or_expr ::= and_expr ("OR" and_expr)*; ...`
  with `AND` binding tighter than `OR` and parens for explicit
  grouping. Keywords are uppercase only — `or` and `and` remain
  valid identifiers (so dotted paths like `arg.or` keep working).
  Both operators short-circuit on the boolean value but propagate
  errors from any branch that does evaluate. Backward-compat at
  byte level: every v0 single-comparison caveat parses unchanged.
  Internally, `Predicate` now wraps an `Expr { Compare | And |
  Or }` tree; the public API is unchanged. The shopping-agent
  demo's two-capability split (browse + buy) can now be expressed
  as one capability with a disjunction; documented as the
  motivating use case in the test file. 24 new tests.
- **v0.1 — TS / WASM holder-of-key wire-up + decimal DSL.** Three
  parallel branches landed simultaneously, closing out the JS-facing
  side of the DPoP feature and addressing the only DSL gap surfaced
  during the live LLM demo:
  - `crates/capnagent-wasm`: four new wasm-bindgen exports
    (`CapabilityBuilder.holderOfKey`, `Capability.holderOfKey` getter,
    `Verifier.verifyWithProof`, top-level `popChallengeFor` function).
    Smoke test asserts all four in the generated `.d.ts`.
  - `@capnagent/core`: `holderOfKey()` builder, `holderOfKey` getter,
    `verifyWithProof()` method, `popChallengeFor()` function — all
    with snake↔camel translation through the existing wrapper.
  - `@capnagent/mcp`: optional `signer` field in `WrapOptions`. When
    `capability.holderOfKey` is set, the wrapper computes
    `popChallengeFor(cap, ctx)`, awaits `signer(challenge)`, and
    routes through `verifyWithProof` instead of `verifyWithContext`.
    If a hok-bound capability is passed without a signer, `wrap` /
    `guardCall` throw `MISSING_SIGNER_MESSAGE` synchronously before
    any tool call — same fail-closed semantics as the Rust core.
  - `examples/shopping-agent`: new `hok` scenario in `llm-runner.ts`,
    `demo:llm-hok` npm script, deterministic vitest covering happy
    path + corrupted-signer denial + missing-signer config gate.
    `@noble/ed25519` added as a dep for the keypair generation.
  - **Decimal DSL.** BNF widened to `\d+(\.\d+)?`. Internal `Value`
    moved from `i64` to `f64`. Exact-binary IEEE-754 equality is the
    locked policy (documented in source); `0.1 + 0.2 == 0.3` is
    `false`, callers should use `<=` / `>=` for fuzzy-equal cases.
    NaN is filtered at the boundary (parser cannot emit it; JSON args
    with non-finite numbers fail closed). 22 new tests in
    `caveat_dsl_tests.rs`.
- **v0.1 — DPoP-style holder-of-key.** New optional `holder_of_key`
  field on `Capability` (ed25519 public key bytes) is folded into the
  HMAC chain via a domain-separated step (`HMAC(prev_sig, "__hok:" ||
  pubkey)`), so the binding cannot be added, removed, or changed
  after issuance without invalidating the signature. New issuer
  builder method `holder_of_key(&pubkey)` (must precede `caveat`).
  New verifier entry point `verify_with_proof(cap, ctx, auditor,
  challenge, proof)` runs four gates: chain → proof → revocation →
  caveats. New `pop_challenge_for(cap, ctx)` helper provides the
  default challenge derivation (`SHA-256` over canonical-JSON of
  `{ id, tool, args_hash, now_ms }`). `verify_with_context` now
  fail-closes on hok-bound capabilities (Denied receipt with reason
  pointing to `verify_with_proof`). Backward-compat preserved at the
  byte level: v0 tokens (no hok) take the v0 chain path.
  17 new tests covering chain integration, backward-compat, valid /
  wrong-key / wrong-challenge / malformed proof paths,
  configuration-mistake detection, and audit-log invariants.
  ed25519-dalek 2.x added as a core dep.
- **Week 5 — signed revocation list.** New `revocation` module exposes
  `RevocationList` (HMAC-signed wire format), `Revoker` (issuer-side
  helper), and `RevocationError`. `Verifier::with_revocation_list(list)`
  installs a list after verifying its signature once; subsequent
  `verify_with_context` calls add a third gate (chain → revocation →
  caveats). Revoked capabilities produce `Outcome::Denied` with reason
  `"capability revoked: <id>"`, **not** an error — the audit log
  captures every attempt against a stolen token, exactly the signal
  incident response needs. 18 new tests covering signature tamper
  resistance, key isolation, runtime swap, install-time signature
  validation, and the deny-but-audit semantics. DPoP holder-of-key
  deferred to v0.1 (see `docs/DESIGN.md` §9).

### Fixed

- **shopping-agent demo: legitimate purchase blocked by DSL float
  type-mismatch.** Surfaced during the first live LLM run on Haiku 4.5
  — the model emitted `amount: 12.99` for a $12.99 USB-C cable, and
  the v0 caveat DSL's `arg.amount <= 50` denied the call with a
  type-mismatch (DSL only accepts integer numbers). Quick fix: round
  catalog prices to integer dollars (1299 → 1300, 1899 → 1900) and
  add an explicit "use integer dollar amounts" instruction to both
  scenario system prompts. Decimal support in the DSL is logged as a
  v0.1 backlog item in `docs/DESIGN.md` §9. The security claim was
  unaffected — `bank.wire` never reached the underlying shop in
  either scenario.

### Added (continued)

- **Week 4 — shopping-agent demo, LLM-driven version.** Layered on top
  of the scripted demo: the agent is now a real Claude model called
  through the Anthropic TS SDK, with prompt caching on the system
  prompt and a manual agentic loop that routes every tool call through
  `wrapMCPClient`. Two scenarios:
  - `demo:llm` (honest) — neutral system prompt. Modern Claude usually
    refuses the prompt-injected wire on its own; capnagent is the
    defense-in-depth backstop.
  - `demo:llm-injected` (naive) — system prompt explicitly tells the
    agent to follow tool-output instructions, provoking the bad
    behavior. capnagent denies `bank.wire` before the shop sees it.
  Both scenarios share the load-bearing assertion: `bank.wire` must
  never reach the underlying mock shop. Vitest spec skips when
  `ANTHROPIC_API_KEY` is unset, so CI is unaffected. Default model is
  `claude-opus-4-7`; override with `CAPNAGENT_DEMO_MODEL=claude-haiku-4-5`
  for cheaper runs.
- **Week 4 — shopping-agent demo (scripted version).** New
  `examples/shopping-agent` workspace package implements the
  prompt-injection-proof tool-call demo end-to-end. Two
  capabilities (browse + buy), a mock MCP-shaped client with a
  hostile-product-page injection, and a vitest spec asserting
  the load-bearing claim: even when the agent obeys an injected
  prompt asking it to call `bank.wire`, capnagent denies the call
  before the underlying shop sees it. 3 vitest cases.
- **Week 3 — JS/TS surface landed.**
  - **`packages/capnagent`** (`@capnagent/core` on npm) — idiomatic
    TypeScript wrapper around the WASM artifact. Public API:
    `Issuer` / `CapabilityBuilder` / `Capability` / `Verifier` /
    `Auditor`, `Context` / `Receipt` interfaces, error hierarchy
    (`CapabilityError` → `CapabilityChainError`, `CapabilityAuditError`),
    idempotent `init()`. Full snake↔camel translation at the WASM
    boundary; defensive freezing on receipts. 33 vitest cases.
  - **`packages/capnagent-mcp`** (`@capnagent/mcp` on npm) — adapter
    that wraps any structurally-typed MCP client. `wrapMCPClient`
    intercepts every `tools/call`, builds a per-call `Context` via a
    caller-supplied callback, asks `Verifier.verifyWithContext`,
    short-circuits with `CapabilityDeniedError` (carrying the full
    receipt) on deny, calls through on allow. `guardCall` lower-level
    typed-result form. `onReceipt` errors are swallowed and never
    block the underlying call. 22 vitest cases.
  - **WASM build pipeline** — `wasm-pack build crates/capnagent-wasm
    --target bundler` via `npm run build:wasm`. Cross-platform
    wrappers (`scripts/build-wasm.sh` / `.cmd`); Node smoke test
    (`scripts/wasm-smoke.mjs`) asserting the WEEK3_SPEC §3.1 export
    surface. New CI `wasm-build` job covering the full pipeline.
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
- `npm audit fix --force` bumped `vitest` 2.1.5 → 2.1.9 and
  `vite-plugin-top-level-await` ≥ 1.6 → ^1.2.2. 5 moderate dev-only
  advisories (esbuild dev-server CSRF) remain on `vite-node` /
  `@vitest/mocker` / `vite` / `vitest` paths; documented as accepted
  in `SECURITY.md`.

### Documentation
- `packages/capnagent/README.md` added with consumer setup notes,
  including the required `vite-plugin-wasm` + `vite-plugin-top-level-await`
  configuration snippet for vite/vitest downstream consumers.

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
