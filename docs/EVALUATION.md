# Evaluation — how to verify every claim in 5 minutes

A senior reviewer's second question (after "but isn't this just X?")
is "*how do I check the numbers?*" Every quantitative claim in this
repo points at a runnable artifact. This document collects them in
one place so a reviewer never has to grep.

> **Determinism contract.** Every test in the corpus is
> deterministic — no LLM calls, no network, no time-of-day
> dependence. A reviewer cloning the repo at any commit hash gets
> bit-for-bit identical results to ours. If a test ever surfaces as
> flaky, it's a bug, not a "well, sometimes." The one exception:
> the live-MCP integration test in `examples/mcp-fs-agent/` opts
> into a real `@modelcontextprotocol/server-filesystem` subprocess
> and is gated behind a `LIVE_MCP=1` env var.

---

## Five-minute reviewer path

```bash
git clone https://github.com/euanmcrosson-dotcom/capnagent
cd capnagent

# Build (one-time, ~3 min)
npm install
npm run build:wasm
npm run -w @capnagent/core build

# Verify: every claim in the README + corpus + angles run
cargo test                                # 242 Rust tests
npm test --workspaces --if-present        # 322 TS tests

# Performance numbers (criterion, ~30 s)
cargo bench -p capnagent-core --bench verify_pipeline
```

Total time: ~5 minutes once the build cache is warm. Every number
in the README / `THREAT_MODEL.md` / corpus tables comes from one
of those four commands.

---

## Per-round reproduction

Each closed round is a single test command. The PoC is
deterministic; if you can run `npm` or `cargo`, you can reproduce
the result.

| Round | Reproduction command | Expected pass count | Evidence file |
|---|---|---|---|
| 01 | `npm test -w @capnagent-examples/mcp-fs-agent -- tool-poisoning.purple` | 8/8 pass | [`docs/purple-team/evidence/01-tool-poisoning.json`](purple-team/evidence/) |
| 02 | `npm test -w @capnagent/core -- replay-attack.purple` | 8/8 pass | [`docs/purple-team/evidence/02-replay-attack.json`](purple-team/evidence/) |
| 03 | `npm test -w @capnagent/core -- capability-broadening.purple` | 12/12 pass | [`docs/purple-team/evidence/03-capability-broadening.json`](purple-team/evidence/) |
| 04 | `cargo test -p capnagent-core --test round_04_revocation_race.purple` | 11/11 pass | [`docs/purple-team/evidence/04-revocation-race.json`](purple-team/evidence/) |
| 05 | `npm test -w @capnagent-examples/mcp-http-agent -- cross-origin-exfil.purple` | 11/11 pass | [`docs/purple-team/evidence/05-cross-origin-exfil.json`](purple-team/evidence/) |
| 06 | `npm test -w @capnagent/core -- silent-bypass-revocation.purple` | 7/7 pass | [`docs/purple-team/evidence/06-silent-bypass-revocation.json`](purple-team/evidence/) |
| 07 | `npm test -w @capnagent-examples/mcp-fs-agent -- sandbox-prefix-footgun.purple` | all pass (closure asserts denial) | [`docs/purple-team/evidence/07-sandbox-prefix-footgun.json`](purple-team/evidence/) |
| 08 | `npm test -w @capnagent/core -- forgot-nonce-store.purple` | 6/6 pass | [`docs/purple-team/evidence/08-forgot-nonce-store.json`](purple-team/evidence/) |
| 09 | `npm test -w @capnagent-examples/mcp-http-agent -- idn-homograph-origin.purple` | all pass (closure asserts rejection) | [`docs/purple-team/evidence/09-idn-homograph-origin.json`](purple-team/evidence/) |
| 10 | `npm test -w @capnagent-examples/mcp-fs-agent -- encoding-attacks.purple` | all pass (closure asserts denial) | [`docs/purple-team/evidence/10-encoding-attacks.json`](purple-team/evidence/) |

The evidence files in `docs/purple-team/evidence/` are signed
receipts produced by the verifier on the BREAKS run (rounds 06,
07, 09, 10). After the v0.5 fix shipped, the receipts now show
denial outcomes for the same inputs — the regen script
(`bin/regen-purple-evidence-NN.ts` per round) re-runs the
scenario against the current engine and updates the file.

---

## Angles run reproduction

The angles run was 4 parallel agents, 36 angles, 17 findings, 4 of
which are HIGH severity. Each angle is a `.angles.test.ts` file:

```bash
# All four angles files, no LLM calls, deterministic
npm test -w @capnagent/core -- angles
```

Findings tagged `[FINDING]` (an open finding) or
`[CLOSED v0.5]` / `[CLOSED v0.6]` / `[CLOSED v0.6.1]` (post-fix
assertions) are searchable:

```bash
# All open findings (any severity)
grep -r "\[FINDING\]" packages/capnagent/src/__tests__/angles-*.angles.test.ts

# Closed findings by version
grep -rE "\[CLOSED v0\.(5|6|6\.1)\]" packages/capnagent/src/__tests__/angles-*.angles.test.ts
```

**Status as of v0.6.1:** all 4 HIGH-severity angle findings are
closed end-to-end. Some MEDIUM/LOW findings (e.g. NUL bytes
accepted inside DSL string literals — log-truncation risk only)
remain open and are tracked as `[FINDING]` markers in the angles
test files.

| ID | Description | Closed in |
|----|------------|-----------|
| **A.1** | Sub-ulp f64 collapse — `arg.amount <= 50` admits `50.000000000000001` | **v0.6** (Rust DSL evaluator tracks source-text `NumKind`, refuses Integer-literal vs Float-arg comparison) + **v0.6.1** (`Verifier.verifyWithContextJson` so JS callers get the same protection across the WASM boundary) |
| **B.2** | `cap.attenuate("")` produces silent permanent-deny token | v0.5 (pre-validates predicate parses at attenuate time) |
| **B.3** | Auditor accepts zero-byte HMAC key | v0.5 (`Auditor::new` panics with sub-`MIN_AUDIT_KEY_LEN` key) |
| **C.5** | Empty-caveat capability is god-mode | v0.5 (`CapabilityBuilder::build` rejects zero-caveat tokens) |

The full finding list with severity and original `[FINDING]`
locations is in [`CHANGELOG.md`](../CHANGELOG.md) under commit
`805329e` (initial angles run) and the v0.6 / v0.6.1 entries
(A.1 closure).

---

## Performance benchmark reproduction

```bash
cargo bench -p capnagent-core --bench verify_pipeline
```

Output format is standard criterion. Compare your numbers to:

| Benchmark | Mean (Windows 11, Rust 1.x release) | Acceptable variance |
|---|---|---|
| `verify` (chain-only HMAC) | 1.4 µs | ±20% — depends on cache state |
| `verify_with_context` (full bearer) | 10.6 µs | ±15% |
| `verify_with_proof` (full hok) | 56 µs | ±10% — dominated by ed25519 |
| `verify_with_proof + nonce-store` | 170 µs | ±15% — depends on hashmap state |

If you're running on Linux with a more modern CPU, expect 10-30%
faster numbers. The dominant cost in hok paths is ed25519
verification (~45 µs) which is more or less fixed across modern
CPUs.

If your numbers are dramatically slower, check:
- Are you running a `--release` build? (criterion does this by
  default; some IDE integrations don't.)
- Is your host throttled / power-saving? Throughput on a
  laptop on battery is materially lower.

---

## Statistical claims — what we DO and DON'T claim

The evaluation surface is honest about what's measured:

### What we measure
- **Authorization decisions per call:** allowed / denied /
  errored. Every test asserts a specific outcome; flake → bug.
- **Engine performance:** criterion benches at multiple paths.
- **Property invariants:** proptest seeds for the macaroon no-
  broaden invariant and the boolean DSL composition laws (see
  [`crates/capnagent-core/tests/property_tests.rs`](../crates/capnagent-core/tests/property_tests.rs)
  and [`crates/capnagent-core/tests/dsl_property_tests.rs`](../crates/capnagent-core/tests/dsl_property_tests.rs)).

### What we DON'T measure (yet)
- **Cross-model attack-success rates.** capnagent is a structural
  defense, so it doesn't need an LLM-in-the-loop to verify; the
  PoCs simulate the worst case. But that means we can't claim
  "Anthropic models are X% safer than OpenAI under capnagent."
  That's a measurement question for the AI-security probe project,
  not capnagent.
- **Production telemetry.** No deployments yet. Once round 11
  lands against a real partner stack, we'll have the first real
  receipt stream to analyze.
- **Coverage metrics (line / branch coverage).** The Rust workspace
  has high coverage in practice (every gate exercised by ≥1 test),
  but we don't yet publish a coverage badge. **Open task**: add
  tarpaulin to CI.

---

## Falsifiability — what would invalidate a claim

This is the most senior-reviewer-friendly section. Every claim has
a specific input that would falsify it:

| Claim | Falsifying observation |
|---|---|
| "cannot-broaden invariant" (DESIGN.md §5 leg 1) | Any seed under `cargo test --test property_tests` that produces a capability `c'` derived from `c` whose authority strictly exceeds `c`'s. The proptest with 9 cases would catch this. |
| "1.4 µs chain-only verify" | Criterion bench mean > 5 µs on a modern release build. The right-tail variance has been measured at ±20% in our setup. |
| "rounds 07/09/10 closed in v0.5" | Any of those PoCs failing under the current engine. The PoCs assert denial; flake = regression. |
| "B.3 — Auditor rejects sub-16-byte keys" | `new Auditor(new Uint8Array(8))` succeeding. Tested in [`angles-serialization.angles.test.ts`](../packages/capnagent/src/__tests__/angles-serialization.angles.test.ts) under `[CLOSED v0.5]`. |
| "verifier-controlled context" (DESIGN.md §5 leg 2) | A path where the agent's claim about its own `caller` or `now` reaches the caveat evaluator. The Context type is built in the wrapper, not the agent. |
| "trivially-auditable caveats" (DESIGN.md §5 leg 3) | A caveat shape an auditor can't read in ~30 seconds. Caveat DSL is one page of BNF in `caveat_dsl.rs`. |

---

## Reproducibility appendix structure (for paper-track work)

If we ever submit a workshop / SaTML paper based on the corpus,
this is the artifact-evaluation section:

1. **Code:** Apache-2.0, public on GitHub, semantic-version-tagged.
2. **Data:** All PoCs are code; no datasets. All evidence files
   are committed.
3. **Environment:** `Cargo.lock` and `package-lock.json` committed.
   Toolchain pinned: stable Rust + Node 20+. WASM via wasm-pack
   pinned in `package.json`.
4. **Time-to-reproduce:** ~5 minutes from clone to all-green
   (after one-time build cache). Documented above.
5. **Hardware:** any modern x86_64 or aarch64. Native-only paths
   (i.e., the bench) are measured per-host; WASM paths are
   measured against the wasm32-unknown-unknown target which is
   host-portable.

This satisfies the standard ACM artifact-available + artifact-
evaluated criteria.

---

## How to extend this document

When you ship a new round:

1. Add the row to "Per-round reproduction" with the command +
   expected pass count + evidence file.
2. If the round changes a benchmark, update the "Performance
   benchmark reproduction" table.
3. Add the falsifying observation to "Falsifiability" so the
   round's claim has an explicit invalidator.

Keep this document below 5 minutes of reading time. Senior
reviewers don't have more than 5 minutes for any single doc.
