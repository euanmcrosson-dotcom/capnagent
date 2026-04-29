# v0.5 — 4 HIGH closed, rounds 07/09/10 BREAKS → CLOSED

**TL;DR:** the parallel-agent angles run (commit `805329e`)
surfaced 4 HIGH severity defects in capnagent's own engine. v0.5
closes 3 of them and flips three documented BREAKS rounds to
CLOSED in the same batch. A.1 (sub-ulp f64 numeric coercion) is
parked under design discussion for v0.6.

## Closed in this release

### Engine fixes

- **B.2 — `cap.attenuate("")` no longer silently bricks delegated
  caps.** WASM `attenuate` and `caveat` pre-validate predicates
  against the DSL parser at call time. Empty / whitespace /
  unparseable predicates throw at attenuate / issuance time
  rather than chaining and producing permanent-deny tokens.
- **B.3 — `Auditor` rejects sub-16-byte HMAC keys at
  construction.** New `MIN_AUDIT_KEY_LEN = 16` constant. Rust
  core panics on weak keys; WASM constructor surfaces the same
  check as a clean JsError. Closes the deployment trap where an
  audit key derived from an unset env var would silently produce
  forgeable receipts.
- **C.5 — Empty-caveat capabilities are no longer god-mode.**
  WASM `CapabilityBuilder.build()` throws if no caveats have been
  attached. Direct Rust callers can pre-check via the new
  `caveat_count()` getter.
- **`starts_with` DSL operator added.** Anchored prefix check
  (lhs.starts_with(rhs)) for string-on-string comparisons.
  Closes round 07's lateral-substring foot-gun where `matches`
  (substring contains) admitted any path containing the prefix
  anywhere. 5 new proptests cover anchoring, foot-gun contrast,
  type-mismatch, AND/OR composition, and ident non-collision.

### Example fixes

- **fs-agent — path canonicalization.** Context provider runs
  `decodeURIComponent` + `path.resolve` on agent-supplied path
  args before the verifier sees them. Combined with
  `starts_with "<prefix>/" OR == "<prefix>"`, this closes rounds
  07 and 10: lateral-substring, trailing-shadow, embedded-
  prefix, `..`-traversal, and percent-encoded `..` are all denied
  at the gate before the underlying client sees the call.
- **http-agent — TR39 mixed-script rejection.**
  `exactOriginRejectionReason` returns a typed reason instead of
  a boolean. Rejects non-ASCII codepoints and any hostname label
  starting `xn--`. Closes round 09 (operator-pasted-punycode
  exploitation path; the realistic shape after tooling silently
  canonicalizes a Cyrillic URL).

## Corpus state after v0.5

```
10 / 10 rounds closed
 6   hold-with-caveat  (01, 02, 03, 04, 05, 08)
 4   BREAKS → CLOSED   (06 in v0.4; 07, 09, 10 in v0.5)

17 angles findings    4 HIGH    3 closed (B.2, B.3, C.5)
                                1 parked (A.1 — see ROADMAP.md)
```

## Test counts

- **Rust:** 242 tests across 10 integration targets, including
  proptests on the no-broaden invariant, 8 boolean DSL
  composition laws, and 5 new `starts_with` proptests. All green.
- **TypeScript:** 322 tests across 6 workspace packages. All
  green.

## Performance — unchanged

| Path | Mean (criterion, single core, release) |
|------|---|
| chain-only verify | 1.4 µs |
| full bearer pipeline | 11 µs |
| full hok pipeline | 56 µs |
| hok + replay (in-memory store) | 170 µs |

~17 kHz 5-gate verifications/core. The v0.5 changes are
validation-time additions; verify-time cost is unchanged.

## Migration notes

This release contains no breaking API changes for valid inputs.
Code that called `Auditor.new(<32-byte-key>)`, `cap.attenuate(<valid-
predicate>)`, or `Issuer.issue("x").caveat(...).build()` continues
to work identically.

What's changed is how *invalid* inputs are surfaced:

- `new Auditor(new Uint8Array(0))` → throws (was: silently
  produced a useless auditor)
- `cap.attenuate("")` → throws (was: chained silently, denied at
  verify-time)
- `Issuer.issue("x").build()` (no caveats) → throws (was: produced
  a god-mode token)

If your tests pass after upgrading, you weren't relying on any of
these deprecated behaviors.

## Read this for the full picture

- **[CHANGELOG.md](CHANGELOG.md)** — full unfiltered change log
- **[docs/SECURITY-POSTURE.md](docs/SECURITY-POSTURE.md)** —
  OWASP / MITRE / NIST framework mapping after v0.5
- **[docs/EVALUATION.md](docs/EVALUATION.md)** — how to verify
  every claim above in 5 minutes
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — what's coming in v0.6
  (A.1 closure) and beyond

## Acknowledgements

The angles methodology — 4 parallel agents writing adversarial
tests against the engine itself — produced more findings in one
run than the 10 prior purple-team rounds combined. Nothing in
this release would have shipped without that pre-launch
self-review.
