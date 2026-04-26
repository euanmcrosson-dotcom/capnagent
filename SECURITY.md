# Security Policy

capnagent is a security library — capability tokens that bound the authority
of AI-agent tool calls. Bugs here can directly enable confused-deputy
attacks. We treat reports seriously and respond quickly.

## Reporting a vulnerability

**Preferred:** [Open a private security advisory](https://github.com/euanmcrosson/capnagent/security/advisories/new)
on GitHub. This keeps disclosure private until a fix lands.

**Fallback:** email `euanmcrosson@gmail.com` with subject line beginning
`[capnagent-security]`. PGP key on request.

We aim to:

- **Acknowledge** within 72 hours.
- **Provide a remediation plan** within 14 days.
- **Coordinate disclosure** with you on a default 90-day timeline. Shorter
  is fine if a fix is straightforward; longer if the underlying issue is
  systemic. We will agree the timeline with you before any public posting.

If we cannot meet 72 hours, we will at least acknowledge receipt with a
revised timeline.

## What is in scope

- Cryptographic integrity bugs in the macaroon HMAC chain that allow
  broadening, forgery, or cross-key verification.
- Caveat DSL parser bugs that allow a predicate to evaluate to `true` when
  it should evaluate to `false`, or to silently coerce types.
- Audit-log tampering that is not detected by `Auditor::verify` (or the
  inverse: receipts that fail to verify when they should pass).
- Any deviation from the threat model in [`docs/DESIGN.md`](docs/DESIGN.md).
- Memory-safety issues in any unsafe code that lands in this crate. The
  workspace currently sets `unsafe_code = "forbid"`; any unsafe block
  introduced in future work is in scope.
- Dependency-supply-chain compromises observable from the locked `Cargo.lock`.

## What is out of scope (for v0)

- Denial-of-service via large or malformed inputs — resource caveats are
  a v0.1 deliverable.
- Issues only reproducible against pre-release versions (`0.0.x`) that
  have already been superseded.
- Findings against documentation examples or test code unless they reveal
  a library-side bug.
- Side-channel weight extraction from underlying ML models. capnagent does
  not touch model internals.

## Supported versions

| Version | Status |
|---|---|
| 0.0.x | Pre-release. Security fixes on a best-effort basis; no SLA on patch releases. |
| ≥ 0.1.0 | (planned) Tier-1 support. Patches within the disclosure window. |

## Security model

The full threat model lives in [`docs/DESIGN.md`](docs/DESIGN.md) §2. The
three load-bearing legs of the security argument are documented in §5; any
report that breaks one of those three legs is automatically in scope:

1. **Cryptographic integrity.** A holder cannot broaden a capability
   without the root key.
2. **Verifier-controlled context.** Caveats evaluate against facts the
   verifier knows, not facts the agent claims.
3. **Trivially-auditable caveats.** A human can read every caveat on a
   token and predict exactly what it permits.

The property tests in `crates/capnagent-core/tests/property_tests.rs`
encode invariant 1 in code. Any reported violation must, at minimum, be
reproducible there or in an equivalent harness.
