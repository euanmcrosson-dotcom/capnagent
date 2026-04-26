# capnagent

Capability-based authority tokens for AI agent tool calls.

Prompt injection is a confused-deputy attack. capnagent removes the deputy's
ambient authority: every tool call carries a macaroon-style capability that
is attenuable, revocable, and audit-logged. An injected agent can still try
to misbehave; the verifier will reject anything outside the capability's
scope.

> Status: **v0 — week 1 (macaroon core + property tests)**.
> See [`docs/DESIGN.md`](docs/DESIGN.md) for the threat model and roadmap.

## Quick taste

```rust
use capnagent_core::{Issuer, Verifier};

let secret = b"32-bytes-from-a-csprng-please...";

let cap = Issuer::from_key(secret)
    .issue("buy")
    .caveat("merchant == \"amazon.com\"")
    .caveat("amount <= 50_usd")
    .caveat("expires <= 2026-04-27T12:00:00Z")
    .build();

let token = cap.serialize(); // base64url, ~200 bytes typical

// On the verifier side
let parsed = capnagent_core::Capability::parse(&token).unwrap();
Verifier::new(secret).verify(&parsed).unwrap();
```

## What's in this repo

```
crates/
  capnagent-core/      Rust crypto core (issue, attenuate, verify)
docs/
  DESIGN.md            Threat model, abstractions, security argument
```

Coming weeks: caveat DSL evaluator (week 2), MCP adapter (week 3), shopping-
agent demo (week 4), revocation + holder-of-key (week 5), public release
(week 6).

## Build & test

```bash
cargo build
cargo test
```

The property tests in `crates/capnagent-core/tests/property_tests.rs` are
the security argument expressed as code. If any of them fail or flake, the
threat model in `docs/DESIGN.md` is broken — fix the implementation, not
the test.

## License

Apache-2.0.
