# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — `@capnagent/core` deterministic disposal (`dispose()` / `using`)

- `Capability` and `Verifier` now expose `dispose()` and `[Symbol.dispose]`, so
  callers can release a WASM handle eagerly — `using cap = issuer.issue(...)
  .build()` frees it at scope exit, or call `cap.dispose()` explicitly. Both are
  idempotent and double-free-safe.
- Resolves the long-standing "v0.1 will adopt explicit-resource-management once
  `using` is stable" deferral in the package header. The truth, now documented:
  the GC already reclaims handles via wasm-bindgen's FinalizationRegistry (no
  leak, no manual free required) — disposal is purely for deterministic, eager
  release in long-running / memory-sensitive paths. (`lib` gains
  `esnext.disposable` for the `Symbol.dispose` type.)

### Fixed — `@capnagent/core` mis-classified chain-integrity errors on the `verifyWithContext` path

- `verifyWithContext`'s error mapping (`mapWasmError(_, "either")`) sniffed the
  message for `"signature"` before recognizing `"chain"`. A forged/broadened
  token produces `"capability chain integrity: signature mismatch"` — which
  mentions the HMAC *chain* signature — so it was wrongly surfaced as a
  `CapabilityAuditError` instead of a `CapabilityChainError`. `"chain"` now
  wins. (The chain-only `verify()` path was already correct — it uses
  `kind:"chain"`, so the existing broadening tests never exercised this.)
- Found by the new `@capnagent/mcp` end-to-end tests (below); a SDK-level
  regression test was added on the `verifyWithContext` path.

### Tests — `@capnagent/mcp` end-to-end against the real engine

- The adapter's unit tests use a mocked verifier (they prove control flow —
  inner-once, error propagation, `onReceipt` resilience). Added
  `e2e.purple.test.ts` driving `wrapMCPClient` / `guardCall` against the **real
  WASM engine** with real `Issuer`-minted capabilities: round 01 (confused
  deputy — out-of-sandbox/cross-tool calls denied, underlying never invoked),
  round 04 (revoked cap denied via a signed `RevocationList`), round 03
  (tampered cap → `CapabilityChainError` propagated, not remapped), and an
  audit-valid-receipt check on the allow path.

### CLI — `capnagent` is now a full tool (verify / inspect / keygen), and `mint` produces verifiable tokens

- New subcommands:
  - `verify <token> --context <json>` — runs the full pipeline and prints the
    receipt; exit **0** (allowed) / **2** (denied) / **1** (chain or audit
    failure).
  - `inspect <token>` — decode identifier / caveats / holder-of-key without a
    key (no signature check; never implies authenticity).
  - `keygen` — emit a fresh base64 CSPRNG root key.
- **Removed the silent placeholder signing key.** Every key-using path now
  fails closed with a clear message if no `--key` / `CAPNAGENT_KEY` is given —
  a security tool must never mint under a hardcoded public key.
- **Fixed `mint` to emit *verifiable* caveats.** The legacy flat mint previously
  produced caveats that could never pass verification: `tool in [...]` (no `in`
  operator exists in the caveat DSL), bare-ident limits, and `ttl == "24h"`
  (`ttl` is not a context field). Now: `tool == "x"` (OR-chained for multiple
  tools), `arg.<key>` limits, and an enforceable `now <= @<rfc3339>` expiry.
  *Behaviour change:* tokens minted via `capframe bind` now carry different
  (verifiable) caveat text.
- New integration test suite (`tests/cli.rs`): keygen, fail-closed key handling,
  and a mint → inspect → verify allow/deny round-trip.

### Tests — `capnagent-wasm` verify pipeline covered directly

- Added `#[wasm_bindgen_test]` cases (run via `wasm-pack test --node`) for the
  full verify surface, not just the chain check: `verifyWithContextJson`
  allow/deny, revoked-capability denial after `withRevocationList`, and
  rejection of a revocation list signed under the wrong root key.

### Added — `capnagent-py` full API parity (no longer a security subset)

- The Python bindings previously exposed only issue / attenuate /
  `verify_with_context`. They now expose the **complete** core security
  surface, matching the WASM crate:
  - `NonceStore` (replay protection)
  - `RevocationList` + `Revoker` (issuer-side revocation; signed, wire-portable)
  - `Verifier.verify_with_proof` (holder-of-key 4-gate pipeline),
    `verify` (chain-only), `with_nonce_store`, `with_nonce_ttl_ms`,
    `with_revocation_list`, `has_nonce_store`, `has_revocation_list`
  - `pop_challenge_for` (default proof-of-possession challenge)
- Ported purple-team **round 02 (hok-proof replay)** and **round 04
  (capability revocation)** to pytest — impossible before because the API
  didn't exist. The `python-tests` CI job installs `cryptography` for the
  ed25519 proof. 21 Python tests pass.

### Tests / Docs (post-0.8.0 hardening)

- **`capnagent-wasm` now has direct round-trip tests** (6 `#[wasm_bindgen_test]`
  cases run via `wasm-pack test --node`, gated `#[cfg(all(test, target_arch =
  "wasm32"))]` so native `cargo test` skips them): issue → serialize → parse →
  chain-verify, wrong-key rejection, the no-caveat (C.5) and unparseable-caveat
  (B.2) guards, holder-of-key length validation, and malformed-token rejection.
  Wired into CI's `wasm-build` job. Previously the crate had zero direct tests
  (it was covered only transitively through the TS SDK).
- Fixed a stale doc comment in `@capnagent`'s `index.ts` that claimed `./wasm`
  re-exports a `__wasm-stub`; it re-exports the real `crates/capnagent-wasm/pkg/`
  output from `npm run build:wasm`.
- **`capnagent-py` now carries its own adversarial proof.** Ported three
  purple-team rounds to pytest (`tests/test_purple_team.py`): round 01
  (cross-server confused deputy — a path/tool-scoped capability denies the
  hijacked read), round 03 (capability broadening — mutating or dropping a
  caveat is caught by the HMAC chain gate before any caveat evaluation), and
  round 07 (the `matches` substring foot-gun vs the anchored `starts_with`
  fix). Enforced by a new `python-tests` CI job (build wheel → install →
  pytest); all 16 Python tests pass.
- Fixed `crates/capnagent-py/pyproject.toml`: it declared no version source, so
  maturin >= 1.8 refused to build the wheel. Added `dynamic = ["version"]` to
  single-source the version from the Cargo workspace (`version.workspace`).

### Added (v0.8.0 — `capnagent issue --from-caveats`, the Find → Bind CLI handoff)

- **New `capnagent issue --from-caveats <file>` subcommand.** Reads an
  `mcp-recon/v0.1/caveats` artifact and mints one capability token per
  `scope` plan; `deny` (code-execution) tools are reported and
  intentionally NOT granted. Output is
  `{ issued: [{tool, token, caveats}], denied: [{tool, reason}] }`.
  Completes the pipeline end-to-end on the CLI:
  `mcp-recon enumerate → mcp-recon caveats → capnagent issue`.
- Every caveat is validated against the caveat DSL (`caveat_dsl::parse`)
  before a token is minted — a malformed predicate fails closed rather
  than producing a token nobody can evaluate.
- The legacy flat invocation (`--agent --tools --limit --ttl`, dispatched
  by `capframe bind`) is unchanged; the new behaviour is a subcommand.

### Changed (py-v0.7.4 — workspace version aligned with Python release tags)

- **Workspace version bumped `0.0.1` → `0.7.4`.** The Python binding
  inherits `version.workspace = true`, so until now PyPI saw
  `capnagent==0.0.1` even though git tags were `py-v0.7.x`. That
  mismatch was confusing for users (`pip install` reported 0.0.1
  while the GitHub release said 0.7.3). Bumping the workspace
  aligns the entire Rust + Python surface at `0.7.4`.
- Affects `capnagent-core`, `capnagent-wasm`, and `capnagent-py`
  Cargo crates — all now report `0.7.4`. The TypeScript / WASM
  bindings consume the WASM crate locally, so the workspace bump
  is invisible from the JS side. The PyPI-published `capnagent`
  package now matches `0.7.4`.
- **No code changes** beyond the version numbers themselves and
  the cross-crate `version = "0.0.1"` → `"0.7.4"` constraints in
  the WASM and Python crate manifests. Behaviour is byte-identical
  to py-v0.7.3.

### Changed (py-v0.7.2 — slim publish workflow + first wheel-producing release)

- **Dropped `macos-x86_64` from `publish-pypi.yml`.** The `macos-13`
  GitHub Actions runner pool is being deprecated and queued for 20+
  minutes on `py-v0.7.1` without ever starting, blocking the rest of
  the workflow. New Mac hardware is exclusively Apple Silicon (arm64);
  the maintenance vs. yield case for x86_64 macOS wheels is poor.
  macOS x86_64 users can `pip install --no-binary capnagent` to build
  from the sdist (always works because the Rust core is portable).
- **py-v0.7.2 is the first tag that produces distributable wheels.**
  py-v0.7.1 shipped the code (Receipt::from_json, Auditor round-trip,
  publish-pypi.yml) but its workflow run got stuck on the
  macOS-13 queue and was cancelled. py-v0.7.2 contains zero Python
  API changes vs py-v0.7.1 — same `capnagent` package surface.

### Added (v0.7.1 — `Auditor.verify` round-trip + PyPI publish workflow)

- **`Receipt::from_json(s: &str)` on `capnagent-core`** — convenience
  constructor wrapping `serde_json::from_str` against the existing
  `Deserialize` derive on `Receipt`. Round-trips through the signed
  canonical-JSON bytes so callers that move receipts through strings
  (HTTP bodies, log lines, message queues) can rehydrate them without
  reaching into serde directly.
- **Python `Auditor.verify(receipt_json)` is now a real round-trip.**
  v0.7.0 shipped it as a no-op stub pending the core constructor
  above; v0.7.1 wires it end-to-end. Tampered receipts, wrong-key
  receipts, malformed-JSON receipts all surface as `ValueError`. 4
  new Python tests in `tests/test_basic.py` exercise the matrix:
  - `test_auditor_verify_accepts_fresh_receipt` — happy path
  - `test_auditor_verify_rejects_wrong_key` — receipt signed by
    Auditor A is rejected by Auditor B with a different key
  - `test_auditor_verify_rejects_tampered_receipt` — flipping any
    non-signature field (here: outcome) invalidates the HMAC
  - `test_auditor_verify_rejects_malformed_json` — garbage in →
    `ValueError` out, no panic
- **`.github/workflows/publish-pypi.yml`** — multi-platform wheel
  build + PyPI upload triggered by `py-v*` tags. Builds:
  - linux-x86_64 (manylinux auto)
  - windows-x86_64 (MSVC)
  - macos-arm64 (Apple Silicon, macos-14 runner)
  - macos-x86_64 (last x86 macOS runner, macos-13)
  - sdist
  Tag pattern is `py-v*` not bare `v*` so Python-binding releases run
  on a separate stream from Rust-core / WASM releases that use `v*`
  tags. Upload step is guarded by `PYPI_API_TOKEN` presence and
  no-op-skips gracefully if the secret isn't set yet (wheels remain
  available as workflow artifacts for manual `twine upload`).

### Added (v0.7.0 — Python bindings)

- **New crate `capnagent-py`** under `crates/capnagent-py`, exposing
  the capnagent core (Issuer, CapabilityBuilder, Capability,
  Verifier, Auditor) as a Python package via [PyO3](https://pyo3.rs)
  + [maturin](https://maturin.rs). Same pure-Rust core as the WASM
  binding — no separate engine, just a different language surface.
- **Native module name `capnagent._native`**, pure-Python re-export
  shim at `python/capnagent/__init__.py` so callers import the
  friendlier `from capnagent import Issuer, Verifier, Auditor`.
- **`abi3-py38`** so a single wheel covers CPython 3.8 through
  3.13+ (and beyond). Builds for the current platform's triple.
- **8 Python tests** under `crates/capnagent-py/tests/` covering:
  import surface, allow / deny paths, the four high-severity angle
  closures (C.5 no-caveat, B.2 invalid-predicate, B.3 zero-byte
  audit key, **A.1 sub-ulp f64**), and Capability serialize /
  parse round-trip. The A.1 test demonstrates that the Python
  binding gets full A.1 protection by default — Python's
  `json.dumps` preserves number source text in a way that JS's
  `JSON.parse` does not.
- **Example script** at `crates/capnagent-py/examples/basic.py`
  walking allow → deny → audit-receipt-verify.
- **`pyproject.toml`** with maturin build backend, abi3 wheel
  classifiers for Python 3.8–3.13+, Apache-2.0 license metadata.
- **`crates/capnagent-py/README.md`** with quick-start, API table,
  build-from-source instructions, and the "Python gets A.1 closure
  for free" explanation.

Build / install workflow:

```bash
cd crates/capnagent-py
pip install maturin
python -m maturin build --release
pip install target/wheels/capnagent-*.whl
python -m pytest tests/ -v
```

Verified end-to-end on this build: `capnagent-0.0.1-cp38-abi3-
win_amd64.whl`. 8/8 tests pass; `examples/basic.py` produces
allow → deny → audit-signature-ok output.

### Added (v0.6.1 — full A.1 closure across the JS layer)

- **`Verifier.verifyWithContextJson(cap, ctxJson, auditor)`** —
  new public API that accepts the context as a raw JSON string
  instead of a JS object. Closes the residual JS-layer artefact
  of A.1: when callers have the original JSON source (raw HTTP
  body, webhook payload, LLM tool-call as-emitted), passing it
  directly preserves sub-ulp digits across the WASM boundary so
  the v0.6 integer-domain rule in `caveat_dsl::apply_op` can
  fire on the arg side.
- **WASM-side `decode_context_from_json_str`** — uses
  `serde_json::from_str` (honours `arbitrary_precision` from
  `capnagent-core` deps) to preserve number source text. The
  default `decode_context` path remains unchanged for
  backwards-compat with callers passing JS objects.
- **2 new TS tests** in `angles-dsl-edges.angles.test.ts`:
  - `[CLOSED v0.6.1] verifyWithContextJson — full A.1 closure` —
    the exact A.1 reproducer (`amount: 50.000000000000001` against
    `arg.amount <= 50`) is now denied through the JS layer when
    the caller uses the new entry point.
  - Sanity test confirming safe integer cases still pass through.

After v0.6.1 the corpus reads: **4 HIGH found, 4 HIGH closed — both
in the engine AND across the JS layer for callers who use the
JSON-string entry point.** The `verifyWithContext` (JS-object)
entry point retains the JS-layer collapse class; mitigation is the
documented `_cents` form.

### Added (v0.6.0 — A.1 sub-ulp f64 closure)

- **Closes [angle finding A.1](docs/ROADMAP.md): sub-ulp f64 numeric
  coercion silently admits sub-ulp-greater holder values.** The DSL
  evaluator now tracks the syntactic shape of every numeric value
  (Integer vs Float, based on source text) and refuses to compare
  an integer-syntactic caveat literal against a float-syntactic arg
  for ordering or equality operators. Engine-side closure; JS-layer
  follow-on tracked for v0.6.1 / v0.7 (see ROADMAP).
- **`Value::Number` widened to carry a third `NumKind` field** —
  internal structural change. Public API unaffected.
- **`serde_json` `arbitrary_precision` feature enabled in
  `capnagent-core`** so JSON number source text is preserved past
  parse time. Required for the integer-vs-float detection on
  arg-derived values.
- **6 new Rust integration tests** in `crates/capnagent-core/tests/
  caveat_dsl_tests.rs` covering: integer caveat × decimal arg
  rejection in both threshold directions, integer × integer still
  works, fractional-literal escape hatch (`<= 50.0`), cents-form
  escape hatch (`arg.amount_cents <= 5000`), and the exact A.1
  sub-ulp finding (`50.000000000000001` against `<= 50` now errors).
- **TS angle test updated** with a detailed comment explaining the
  JS-layer pre-collapse and the recommended `_cents` mitigation
  for JS callers; new companion test demonstrates the mitigation
  end-to-end.

### Migration (v0.6)

Existing caveats and args that were doing the SAFE thing
(integer × integer, fractional × fractional) continue to work
unchanged.

Existing caveats that were doing the UNSAFE thing (integer caveat
literal `<= 50` admitting fractional holder values) will now error
out with `TypeMismatch`. The error message documents the two
mitigations:

1. **Use a fractional literal** if you actually want approximate
   semantics: rewrite `arg.amount <= 50` as `arg.amount <= 50.0`.
2. **Use the `_cents` form** if you want exact integer semantics:
   rewrite `arg.amount <= 50` as `arg.amount_cents <= 5000` and
   have the agent's tool expose `amount_cents` instead of `amount`.

Choose (2) for monetary intent; that's the recommended pattern
documented in the live shopping-agent demo.

### Added (v0.5.1 — fs-agent coverage)

- **Closes [issue #1](https://github.com/euanmcrosson-dotcom/mcp-guard/issues/1):
  `mcp-fs-agent` example now bounds 10 of the 14 official MCP
  filesystem-server tools (was 3).** The engine was already correct —
  capnagent denied every unauthorised tool — but the example's
  threat-profile transparency was incomplete. v0.5.1 fixes that:
  - **`issueSandboxReadCapability` covers 6 read-side tools** (was 3):
    `read_file`, `read_text_file`, `list_directory`,
    `list_directory_with_sizes`, `directory_tree`, `get_file_info`.
  - **New `issueSandboxWriteCapability`** — separate write-side cap
    covering 4 tools: `write_file`, `edit_file`, `create_directory`,
    `move_file`. `move_file` has BOTH `arg.source` and
    `arg.destination` constrained (so a sandbox file can't be moved
    out, and an outside file can't be moved in to overwrite a
    sandboxed target).
  - **`SANDBOX_READ_TOOLS` and `SANDBOX_WRITE_TOOLS` constants
    exported** as the single source of truth for the example's
    coverage.
  - **4 tools deliberately out of scope** with documented rationale:
    `read_multiple_files` (array-arg shape vs single-string DSL),
    `read_media_file` (binary content not modeled),
    `search_files` (returns paths outside the constrained input
    root), `list_allowed_directories` (server-configuration
    metadata, no path arg to constrain — operator-choice to allow
    unconditionally).
  - **Cross-capability isolation tested:** read-cap holder cannot
    pivot to writes, write-cap holder cannot pivot to reads.
- **`mcp-fs-agent/README.md` rewritten** with a full 14-row tool-
  coverage table — operators can see exactly which tools are
  bounded, by which capability, and why each excluded tool is out of
  scope.
- **Main `README.md` companion-projects section** restructured to
  show the three-layer agent-security stack: `mcp-recon` (recon) →
  `capnagent` (authority) → `mcp-guard` (runtime policy).

### Tests

- `examples/mcp-fs-agent` test count 9 → 30 (+21 v0.5.1 cases).
  Repo total Rust 242 + TS 346 = **588 tests passing** (was 564).

### Added

- **Four-agent parallel angles run — 36 angles, 17 real findings, 4
  HIGH-severity.** Lighter-weight than full purple-team rounds:
  each agent wrote one `*.angles.test.ts` file with ≥5 angles, each
  marked `[FINDING]` if it surfaced a real defect. Total +97 tests
  (`@capnagent/core` 92 → 189). The angles methodology produced
  more findings in one parallel run than the previous 10 rounds
  combined.

  **Four files added** (all under `packages/capnagent/src/__tests__/`):
  - `angles-dsl-edges.angles.test.ts` — Terminal A, 33 tests, 2 FINDINGs
  - `angles-serialization.angles.test.ts` — Terminal B, 24 tests, 3 FINDINGs
  - `angles-composition.angles.test.ts` — Terminal C, 22 tests, 6 FINDINGs
  - `angles-timing.angles.test.ts` — Terminal D, 18 tests, 6 FINDINGs

  **HIGH-severity findings (4):**
  - **A.1: Sub-ulp f64 collapse defeats integer-looking caveats.**
    Holder passes `"amount": 50.000000000000001`; JSON→f64 collapses
    to bit-identical `50.0`; caveat `arg.amount <= 50` admits the
    call. Real authorization bypass class. Mitigation today: use
    units (`50_cents` against integer-cents args).
  - **B.2: `cap.attenuate("")` produces silent permanent-deny
    token.** Empty predicate accepted at attenuation, parses fine,
    chain check passes — but every verify denies because the DSL
    parser can't parse `""`. Any holder in a chain can silently
    brick a delegated cap. Engine fix: validate predicates parse-
    as-DSL at attenuation time, not verify time.
  - **B.3: `Auditor` accepts zero-byte key.** RFC 2104 permits it,
    but a zero-entropy audit key means any attacker who guesses
    "empty" can mint forged receipts. Realistic deployment trap:
    `Buffer.from(process.env.AUDIT_KEY)` when the env var is unset.
    Engine fix: reject keys < 16 bytes at construction.
  - **C.5: Empty-caveat cap is god-mode.** `Issuer.issue("x").build()`
    with NO caveats is valid; chain passes; every context is
    allowed. Engine fix: require ≥1 caveat at `build()` time, or
    add a `requireExpiry()` API gate.

  **MEDIUM-severity findings (2):**
  - **D.1: RevocationList has no freshness window at install** —
    install accepts any-age list (5 years stale OR future). v0.4
    `revocationListIssuedAtMs()` is the introspection point but
    no policy is enforced.
  - **D.5: `Context.nowMs` default panics on wasm32** — JSDoc
    claims `Date.now()` default; actual WASM impl calls
    `SystemTime::now()` which panics with `"time not implemented"`.
    Surfaces as `CapabilityChainError("unreachable")`.

  **LOW / INFORMATIONAL findings (11):**
  - A.2: NUL bytes in DSL string literals (log-spoofing risk)
  - B.1: Negative `nowMs` throws wrong error class with misleading
    "floating point" message
  - C.1: All chain tampers produce opaque `"invalid signature"`
    (incident-response forensics gap)
  - C.2: `attenuate(X).attenuate(X)` doesn't dedupe
  - C.3: Conflicting caveats (`amount <= 50 AND amount > 100`)
    produce useless cap with no warning
  - C.4: Pin caps by reference, not re-serialize (advisory)
  - C.6: `attenuate` consumes via wasm-bindgen `mut self`; reuse
    of original handle throws raw `"null pointer passed to rust"`
    instead of typed CapabilityError
  - D.2: 5-digit-year timestamps parse-then-perma-deny
  - D.3: NonceStore TTL is half-open `[T, T+ttl)` — 1ms window at
    boundary
  - D.4: Receipt `timestampMs` = `ctx.nowMs` (no independent
    auditor clock)
  - D.6: `now ==` is sub-second precision (operator surprise)

  **Critical-path angles that HELD (most operationally important
  news):**
  - **D.5: Concurrent NonceStore (100-way race)** — Mutex
    correctly serializes; exactly 1 admit, 99 denials with
    "proof replay detected". The replay defense is genuinely
    race-safe under load. **This was the highest-stakes test in
    the whole run and it works.**
  - Cryptographic chain + audit MAC + canonical-JSON: rock-solid
    under 1000-caveat chains, CJK Unicode, deep arg nesting,
    shuffled key order. No bypass at the byte level.
  - DSL is robust to structural attacks (deep nesting, missing
    fields, type confusion). The fragility is at numeric-precision
    semantics and edge translation surfaces.
  - hok binding survives attenuation; stripping hok bytes from
    the wire breaks the chain.
  - 100 concurrent verifies route correctly with no state leak.

  **v0.5 backlog grows:** the 4 HIGH-severity findings + 2 MEDIUM
  ones become formal engine fixes. The 11 LOW findings stay as
  regression coverage in the angles test files.

- **Purple-team round 10 — encoding / path-traversal against fs-
  sandbox. Status: BREAKS.** Round 07 found that substring `matches`
  isn't path-aware (lateral substring); round 10 widens the case to
  ESCAPE-shaped traversal: `<sandbox>/../outside/secret.txt` contains
  the sandbox prefix as a substring (so caveat allows) but Node's
  `fs.readFile` resolves the `..` and reads the out-of-sandbox file.
  Captured receipt + verified file contents (`OUT-OF-SANDBOX-SECRET`
  string actually read) are the visceral evidence. PoC at
  `examples/mcp-fs-agent/src/__tests__/encoding-attacks.purple.test.ts`
  — 8 tests, all passing. Same v0.5 fix as round 07 (Context-provider
  canonicalization + `starts_with` DSL operator); round 10 widens
  the case for both halves of the fix because canonicalization alone
  doesn't address round 07's lateral-substring shape, and
  `starts_with` alone doesn't address round 10's escape-after-prefix
  shape.

- **`docs/THREAT_MODEL.md` — canonical in-scope / out-of-scope
  reference.** Single document covering: what capnagent IS, the
  in-scope threats (table of 10 closed rounds with status), the
  out-of-scope threats (table of 12 attack classes that aren't
  capnagent's job, with rationale and pointers to the right defense
  layer for each), the operator-responsibility list distilled from
  rounds 06–10's defender-actionable sections, and the multi-layer-
  defense composition diagram. Replaces ad-hoc "what does capnagent
  defend against?" prose scattered across the README + DESIGN.md.
  Out-of-scope categories explicitly named: many-shot jailbreaking,
  system-prompt extraction, Crescendo, roleplay, DAN, GCG suffix
  attacks, capability-dependent reasoning, side-channel exfil,
  pure-prompt-injection of model reasoning, privilege escalation
  within tool surfaces, root-key compromise, deployment-pipeline
  compromise, TOCTOU races, DoS, distributed replay. Each comes
  with a one-line "right defense for this" pointer to the layer
  that DOES own it.

- **Purple-team rounds 07, 08, 09 — failure-mode tests of existing
  defenses, three rounds in one parallel-worktree pass. The corpus
  matures from "5 rounds all holding" to "9 rounds: 6 closed, 3
  surfacing real defects with engine fixes queued."**

  - **Round 07 — fs-sandbox prefix foot-gun (round 01 failure mode).**
    **Status: BREAKS.** Operator passes a sandbox prefix that LOOKS
    like a path-prefix but, because `matches` is substring-
    containment, lets the cap also permit reads to *unrelated*
    directories sharing the substring. Concrete: cap with
    `sandboxPrefix: "/srv/app"` allows `read_file({ path:
    "/etc/srv/app-leaked-secret" })` — captured receipt has
    `outcome.kind === "allowed"` for the lateral path. The existing
    `issueSandboxReadCapability` validator is a "looks-vaguely-pathlike"
    gate (length ≥ 8 + must contain `/` or `\`), not a path-prefix-
    realism gate. Recommended fix is two-part: (1) add a `starts_with`
    DSL operator anchored at position 0 + requiring trailing
    separator, (2) extend the Context provider to canonicalize
    `arg.path` (resolve symlinks, eliminate `..`, normalize
    separators) before caveat evaluation. PoC at
    `examples/mcp-fs-agent/src/__tests__/sandbox-prefix-footgun.purple.test.ts`
    — 9 deterministic tests, all passing (the "BREAKS" is the
    scenario outcome).

  - **Round 08 — forgot NonceStore on hok-bound caps (round 02 failure
    mode). Status: CLOSED on Run 1.** v0.4's `hasNonceStore()`
    introspection (shipped before this round was even authored)
    enables operators to detect the operator-config gap. Round
    captures a dual-narrative in one Run-1 entry: WITHOUT NonceStore
    a byte-identical replay against an hok-bound cap is silently
    ALLOWED; WITH NonceStore the same replay is correctly DENIED
    with reason "proof replay detected". Both receipts captured
    side-by-side as `gap_receipt` / `fixed_receipt` keys in the
    evidence JSON. PoC at
    `packages/capnagent/src/__tests__/forgot-nonce-store.purple.test.ts`
    — 6 tests, all passing.

  - **Round 09 — IDN homograph in origin allowlist (round 05 failure
    mode). Status: BREAKS.** Operator copies an attacker-supplied URL
    containing a Cyrillic а (U+0430) into the origin allowlist.
    Empirical finding from the round: Node's `URL.origin` canonicalizes
    the homograph to its punycode form (`https://xn--pi-6kc.example.com`),
    and `isExactOrigin` accepts the punycode silently — so any
    operator clipboard / JSON-loader / config-pipeline path that
    auto-canonicalizes unicode → punycode lands the cap with the
    attacker host. The same cap then ALLOWS calls to the homograph
    host AND DENIES calls to the legitimate ASCII origin. Both
    receipts captured side-by-side. Recommended fix is path B (TR39
    mixed-script confusable detection) over path A (ASCII-only),
    because path A rejects every legitimate IDN deployment. PoC at
    `examples/mcp-http-agent/src/__tests__/idn-homograph-origin.purple.test.ts`
    — 13 tests, all passing.

  Test count growth: 185 → 213 TS tests (+28 across rounds 07, 08, 09).
  Engine v0.5 work queue opened: path-canonicalization in fs-agent's
  Context provider + DSL `starts_with` operator (round 07); TR39
  mixed-script detection in `isExactOrigin` (round 09).

- **v0.4 — Verifier introspection methods (`hasRevocationList`,
  `hasNonceStore`, `revocationListIssuedAtMs`).** Closes the gap
  surfaced by purple-team round 06: a silent-failed
  `withRevocationList` install was previously invisible from the
  public API surface. Operators can now write postcondition
  assertions in deployment-readiness code:
  ```ts
  verifier.withRevocationList(list);  // may throw
  if (!verifier.hasRevocationList()) {
    throw new Error("CRITICAL: install silently failed");
  }
  ```
  Three methods added to `Verifier` across the Rust core, WASM
  bindings, and TS wrapper:
  - `hasRevocationList(): boolean`
  - `revocationListIssuedAtMs(): number | undefined` (lets operators
    detect stale lists for freshness-window checks)
  - `hasNonceStore(): boolean` (closes the same shape of gap for
    the opt-in NonceStore defense)
  Round 06 re-runs in Run 2 with the introspection methods
  available; status flips from BREAKS to CLOSED. **First round in
  the corpus to break, drive an engine fix, and close — within a
  single development cycle.** Tests counts: @capnagent/core 84 → 86
  (+2 round 06 v0.4 fix tests).

- **Purple-team round 06 — silent-bypass on revocation-list install
  (operator trap). Status: BREAKS — first round in the corpus to
  surface a real defect.** Round 04 documented the install-time
  fail-closed-but-silent-bypass-mode pattern as a known hazard
  ("paged-alert in production"). Round 06 programmatically proves
  it AND surfaces the deeper finding: the `Verifier` API has no
  introspection methods, so an operator who installed a revocation
  list successfully and an operator who silently swallowed the
  install error are indistinguishable from the public API surface.
  Trigger requires no malicious actor — the standard defensive
  Node.js pattern (`try { withRevocationList(list); } catch (err)
  { logger.warn(err); }`) suffices to silently disable the defense.
  Captured evidence: a v0.2-versioned, HMAC-signed receipt with
  `outcome.kind: "allowed"` for a cap that the operator believed
  was revoked. PoC at
  `packages/capnagent/src/__tests__/silent-bypass-revocation.purple.test.ts`
  — 5 deterministic tests, all passing (the FAIL is the scenario
  outcome, not the test outcome — the test successfully demonstrates
  the defense break). Engine v0.4 work item OPENED: add
  `Verifier.hasRevocationList()` / `hasNonceStore()` /
  `revocationListIssuedAtMs()` so operators can write postcondition
  assertions on install-state. When the fix lands, round 06 re-runs
  with status flipping BREAKS → CLOSED. Generated by applying the
  purple-scaffold "angles methodology" (test FAILURE MODES of
  existing defenses, not new attack classes) to capnagent's corpus.

- **v0.3 — RevocationList + Revoker exposed through WASM/TS.** Closes
  the engine-parity gap surfaced by purple-team round 04 (WASM
  bindings did not yet expose revocation; round 04's PoC was
  Rust-only as a result). `@capnagent/core` now exports `Revoker`
  and `RevocationList` classes plus `Verifier.withRevocationList(list)`.

  - `Revoker(rootKey)` — issuer-side helper. `revoke(id)` /
    `unrevoke(id)` / `publish(issuedAtMs) → RevocationList`.
  - `RevocationList` — `parse(token)` / `serialize()` for wire
    transport (URL-safe base64), `contains(id)`, `size`, `isEmpty`,
    `issuedAtMs` getters.
  - `Verifier.withRevocationList(list)` — install-time signature
    check against the verifier's root key. Mismatch throws
    `CapabilityChainError("invalid revocation-list signature")` AND
    leaves the verifier handle valid for retry. This is `&mut self`
    on the WASM side rather than the consuming pattern used by
    `withNonceStore` / `withNonceTtlMs`, because those can never
    fail — `withRevocationList` can, and consume-on-failure would
    null the JS pointer with no recovery path.
  - The Verifier WASM wrapper now retains `root_key: Vec<u8>` for
    pre-checking list signatures before consuming the inner
    `core::Verifier`. Minor key-duplication footprint; the
    alternative is a far-worse JS API ergonomics story.

  11 new tests in `packages/capnagent/src/__tests__/revocation.test.ts`
  against the real WASM artifact. Round 04's existing Rust PoC
  stands; a future round-04 TS-flavored PoC is now possible against
  this surface.

- **Purple-team rounds 03, 04, 05 — closes every previously-empty
  gate column in the corpus.** Three rounds shipped in a single
  parallel-worktree pass:

  - **Round 03 — Capability broadening (hostile-holder tampering).**
    Fires the `chain ✗` gate column. A hostile holder attempts to
    broaden a capability they hold (drop a caveat, modify a
    caveat's text, splice a signature from a different cap, mint
    under a different root key, zero the signature field). All
    eight tampering variants surface a UNIFORM `CapabilityChainError`
    "invalid signature" — no variance oracle for an attacker, single
    greppable string for ops monitoring. PoC at
    `packages/capnagent/src/__tests__/capability-broadening.purple.test.ts`
    — 12 deterministic tests, real WASM, base64-decode-edit-encode
    for byte-level tampering plus cross-key minting via
    `Issuer.fromKey(ALT_ROOT_KEY)`. The 9 existing Rust proptests in
    `tests/property_tests.rs` are referenced as the formal-proof
    underpinning. Evidence at
    `docs/purple-team/evidence/03-capability-broadening.evidence.json`
    (note: `.evidence.json` not `.receipt.json` — chain failures
    throw before any receipt is signed).

  - **Round 04 — Revocation race (revoked-capability replay).**
    Fires the `revoke ✗` gate column. A holder of a once-legitimate
    capability continues to use it after the issuer publishes a
    signed revocation list. Defense: `Verifier::with_revocation_list(...)`
    consults the list at every verify call; revoked identifiers are
    denied with reason `"capability revoked: <id>"` (string locked
    for greppability). Written in Rust at
    `crates/capnagent-core/tests/round_04_revocation_race.purple.rs`
    because the WASM bindings do not yet expose `RevocationList` —
    11 integration tests, all passing. **Operational finding worth
    flagging: `with_revocation_list` fails CLOSED on signature
    mismatch but in a way that returns a `Result` to the caller —
    if the operator handles the error by ignoring it, the resulting
    `Verifier` has NO list installed (silent-bypass mode). Round
    doc tags this as a paged-alert requirement.** Evidence at
    `docs/purple-team/evidence/04-revocation-race.receipt.json`.

  - **Round 05 — Cross-origin exfil via http-agent.** Fires the
    `caveat ✗` gate column on the http-agent's origin-bounded cap
    (round 01 fires it on the fs-agent; this round demonstrates the
    same defense against a different cap shape and Context-
    normalization pattern). Malicious tool description tries to
    redirect a fully-cooperating agent to GET attacker-controlled
    origins. Defense: verifier-controlled Context provider parses
    `arg.url` via standard `URL` constructor and writes the
    canonical origin into `arg.origin` BEFORE the verifier evaluates
    the caveat. Userinfo splitting (`https://api.good.com@evil.com/x`)
    parses to `https://evil.com`; subdomain confusion
    (`https://api.good.com.evil.com/x`) parses verbatim; malformed
    URLs leave `arg.origin` unset, so equality fails closed. PoC at
    `examples/mcp-http-agent/src/__tests__/cross-origin-exfil.purple.test.ts`
    — 11 deterministic tests using a localhost `node:http` stub
    (no real network). Captured denial reason:
    `caveat failed: tool == "http.get" AND (arg.origin == "https://api.example.com")`.

  Corpus state after this batch: every gate of the 5-gate verify
  pipeline has been exercised by at least one round — chain (all
  five rounds touch the chain leg; round 03 explicitly fires it),
  proof (02), replay (02), revoke (04), caveat (01 + 05). No
  column is empty. Total: 5 closed rounds, 50 PoC tests across 4
  workspace packages + 1 Rust integration target.

- **Purple-team round 02: Replay attack on hok-bound capability.**
  Fires the `replay ✗` gate column the corpus had empty after round
  01. Threat model: attacker captures (cap, ctx, challenge, proof)
  bytes mid-flight and replays them. Defense: NonceStore records
  sha256(proof) of every accepted proof; replays within `nonce_ttl_ms`
  are denied with reason "proof replay detected" (string is locked
  for audit-log greppability). PoC at
  packages/capnagent/src/__tests__/replay-attack.purple.test.ts —
  8 deterministic tests covering positive (allow on first), negative
  (allow on fresh), gate ordering (replay short-circuits before
  caveat), audit-loggability (10 replays produce 10 receipts; under
  identical inputs receipts are byte-identical, operational finding),
  TTL=0 boundary, clear() bypass, and opt-in property (without store
  installed, replays are accepted by design). Round status: CLOSED
  2026-05-04, holds-with-caveat (capability-shape complete; FP-7d
  measurement and durable-backend stress remain operator
  responsibility). Re-validate-by 2026-11-04.

  Captured replay-denial receipt committed at
  docs/purple-team/evidence/02-replay-attack-on-hok-bound-cap.receipt.json.
  Receipt is deterministic — same bytes regardless of who runs the
  regen script — because all inputs (root key, audit key, holder
  key, frozen now_ms, fixed args) are pinned. Regen via
  `npm run -w @capnagent-examples/shopping-agent regen-purple-evidence-02`.

### Changed

- **Purple-team format adopted from detection-engineering convention.**
  Replaced the prior loose markdown shape with a plain-text,
  grep-friendly format with iterative run history (one row per
  retry, capturing Env, Gates, Decision, Latency, FP-7d, Gap-class,
  Gap, Action). Adds seven specific extensions over the
  detection-engineering source: `Gap-class:` (CAPABILITY-CONFIG /
  DEFENSE-LOGIC / OPERATOR-MISCONFIG / OUT-OF-SCOPE / HYPOTHESIS /
  NONE) so failures are aggregable across the corpus; `Env:` per run
  so PASSes don't lie across platforms; `FP-7d:` so CLOSED means
  useful, not just firing; `Coverage:` listing tested + not-yet-
  tested variants so one atomic doesn't claim a whole technique;
  `Known-bypasses:` so PASS is honest; `Re-validate-by:` (default 6
  months) so CLOSED isn't forever; tightened Hypothesis to predict
  both true-positive and true-negative halves (a defense that denies
  everything is not the win condition).
  Round 01 (tool-description injection) migrated to the new format
  preserving all evidence and prose context. `_template.md` and
  `README.md` updated to match.
- **Repositioning: capnagent is now a public purple-team harness for
  MCP and AI-agent tool surfaces** (with a Rust capability-token
  engine underneath), not "a capability-token library." The corpus
  in `docs/purple-team/` is the artifact; the library is the engine
  that powers each round's defense. Pivots the README's lead, the
  Show HN draft, the lobste.rs / r/rust / r/MachineLearning posts,
  and the cold-DM templates to the new framing. No code change —
  pure positioning. Reasoning: "capability tokens for AI agents" is
  a solution looking for a problem; "public purple-team corpus for
  MCP" is a named gap security teams know they have. Also rides MCP
  hype directly.

### Added

- **examples/mcp-shell-agent — third real-world consumer.** New
  workspace package `@capnagent-examples/mcp-shell-agent`. Closes
  the high-risk-tool-surface trifecta (filesystem, HTTP, shell-exec).
  Capability allowlists a specific argv shape — e.g. `git status`,
  `git diff`, `git log` — and denies everything else, including
  `git push`, `rm -rf /`, and `bash -c "..."`. argv-as-array shape
  forces token boundaries, so shell-injection chaining
  (`["git", "status; rm -rf /"]`) can't smuggle past the gate: the
  capability sees one argv element with a non-allowlisted subcommand
  and denies it. Context provider extracts `arg.cmd` (argv[0]) and
  `arg.sub` (argv[1]) so caveats use plain `==` comparisons against
  canonical structural fields. Issuance preconditions reject empty
  cmd/subcommand lists and DSL-unsafe characters at issue time. 17
  deterministic vitest tests with a stub shell client (no real
  subprocesses); runnable demo via
  `npm run -w @capnagent-examples/mcp-shell-agent demo`.
- **v0.2 — receipt schema versioning.** `Receipt` gains a top-of-struct
  `version: u8` field (currently always `1`, exported as
  `capnagent_core::RECEIPT_SCHEMA_VERSION`). The field flows through
  the WASM boundary unchanged — `RawReceipt` and the public TS
  `Receipt` both grow a `version: number` member, and the
  `translate.ts` layer passes it through verbatim. Forward-compat
  fail-closed: `Auditor::verify(receipt)` rejects any receipt whose
  `version` differs from the build's `RECEIPT_SCHEMA_VERSION` and
  returns a dedicated `AuditError::UnsupportedVersion { got, expected }`
  variant so a version-skew miss is distinguishable from a tampering
  attempt at a glance. The auditor's HMAC input is now
  `b"v" || [version_byte] || canonical_json(receipt_minus_signature)`,
  domain-separating the schema version into the MAC so a man-in-the-
  middle cannot rewrite `version` without invalidating the signature
  even if the canonical-JSON layer were later to drop it. Three new
  Rust tests (`receipt_carries_schema_version_one_and_round_trips`,
  `unsupported_version_is_rejected_by_verifier`,
  `signature_locks_in_version_byte`) cover the round trip, the
  fail-closed gate, and the version-locking property of the
  signature input. DESIGN.md gains a new §14 explaining the
  motivation, the wire-format-break semantics of bumping the
  version, and the deployment expectation. Closes the last item on
  the v0.2-deferred list.
- **tests: property-based tests for boolean DSL composition.** New
  `crates/capnagent-core/tests/dsl_property_tests.rs` (8 properties,
  256 cases each = 2048 generated inputs per run). Encodes the
  boolean-algebra laws a reader of a caveat string assumes:
  commutativity (OR, AND), associativity (OR, AND), distributivity
  of AND over OR, allow-monotonicity (appending `OR X` can never
  flip allow → deny), deny-monotonicity (appending `AND X` can
  never flip deny → allow), and a no-panic invariant (any
  parse-success AST evaluates without panicking, regardless of
  context). Closes the security-argument gap noted in the v0.1
  Show HN: previously we proptested chain integrity but not the DSL
  evaluator. No bugs surfaced — all eight laws hold.
- **bench: criterion harness for the verify pipeline.** New
  `crates/capnagent-core/benches/verify_pipeline.rs` measures per-call
  latency for all four verifier entry points: chain-only verify,
  `verify_with_context` (bearer-token full pipeline), `verify_with_proof`
  (hok full pipeline), and `verify_with_proof` with replay store
  installed. Run via `cargo bench -p capnagent-core --bench
  verify_pipeline`. Headline numbers (single-core, criterion 100-sample
  mean): chain-only 1.4 µs, bearer-token 11 µs, hok 56 µs, hok+replay
  170 µs. Sustains ~17 kHz of full hok+replay verifications per core,
  two orders of magnitude above any single agent's call rate. README
  + Show HN post updated with the table and methodology.
- **v0.1 — NonceStore TS/WASM surface.** `@capnagent/core` now exports
  a `NonceStore` class plus `Verifier.withNonceStore(store)` and
  `Verifier.withNonceTtlMs(ttlMs)` builder methods. Backed by the
  existing Rust `InMemoryNonceStore` via fresh `wasm-bindgen` exports.
  The handle stays inspectable from JS (`size`, `isEmpty`, `clear()`)
  even after install — both wrapper and verifier share an `Arc` of
  the same store. Adds 8 new tests against the real WASM artifact
  covering: replay denial with `proof replay detected`, store
  inspection, `clear()` semantics, `withNonceTtlMs(0)` boundary,
  validation of negative / non-integer TTLs, and the default
  no-replay-protection-when-no-store case. Closes the v0.1 backlog
  item "NonceStore TS surface so the replay path is reachable from
  JS too."
- **mcp-fs-agent — real @modelcontextprotocol/sdk integration.** New
  `adaptMCPSDKClient(client)` adapter converts an SDK `Client` to
  `MCPClientLike` so it can flow through `wrapMCPClient` unchanged.
  Runnable demo (`demo:live-mcp`) spawns the official
  `@modelcontextprotocol/server-filesystem` via stdio, connects, and
  walks through the same allow/deny matrix as the in-process demo —
  but against the real server. Opt-in vitest spec
  (`CAPNAGENT_MCP_LIVE=1`) verifies the integration: reads inside the
  sandbox reach the server; reads outside the sandbox AND any
  `write_file` are denied before the server sees them, even when the
  server is configured to allow access to those paths. Establishes
  capnagent as a verified ecosystem integration, not just a
  structural-stub demo.
- **examples/mcp-http-agent — second real-world consumer.** New
  workspace package `@capnagent-examples/mcp-http-agent`. Origin-
  scoped HTTP agent: capability bounds `http.get` to an allowlist of
  origins; `http.post`, `http.put`, `http.delete`, and any GET to a
  non-allowlisted origin are denied before fetch runs. Caveats
  compare against `arg.origin` — a parsed-URL field the verifier-
  controlled Context provider populates via `new URL()`. Defends
  against userinfo splitting (`https://api.good.com@evil.com/x`),
  subdomain confusion (`https://api.good.com.evil.com/x`), and
  malformed URLs (no `arg.origin` → equality check fails closed).
  Issuance preconditions reject empty allowlists and non-canonical
  origins synchronously at issue time. 15 deterministic vitest tests
  using two localhost `node:http` stub servers; runnable demo via
  `npm run -w @capnagent-examples/mcp-http-agent demo` (no real
  network). Establishes the pattern generalizes beyond filesystem to
  the most common AI-agent attack surface (data exfiltration via
  fetch).
- **examples/mcp-fs-agent — first real-world consumer.** New workspace
  package `@capnagent-examples/mcp-fs-agent`. Wraps an MCP-style
  filesystem client through `@capnagent/mcp` with a sandbox-scoped read
  capability composed via v0.1 boolean composition + `matches`:
  ```
  (tool == "read_file"      AND arg.path matches "<sandbox>")
   OR (tool == "list_directory" AND arg.path matches "<sandbox>")
   OR (tool == "directory_tree" AND arg.path matches "<sandbox>")
  ```
  Reads inside the sandbox prefix are allowed; reads outside, plus all
  writes (`write_file`, `create_directory`, `delete_path`), are denied
  before the underlying filesystem client sees them. 9 deterministic
  vitest tests cover the full allow/deny matrix; runnable demo via
  `npm run -w @capnagent-examples/mcp-fs-agent demo` (no API key).
  Documents the substring-vs-prefix property of `matches` and the
  recommended Context-normalization pattern for production deployments.
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
