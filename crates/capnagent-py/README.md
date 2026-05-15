# capnagent — Python bindings

Python bindings for [capnagent](https://github.com/euanmcrosson-dotcom/capnagent),
the capability-based authority-token engine for AI agent tool calls.

The bindings cover the same surface as the TypeScript/WASM bindings:
`Issuer`, `CapabilityBuilder`, `Capability`, `Verifier`, `Auditor`. The
Rust core (`capnagent-core`) is shared 1:1 — same engine, different
language surface.

## Install

```bash
pip install capnagent
```

(Pre-1.0: built from source via `pip install capnagent` once the
first wheel is published; until then, install from source — see
"Build from source" below.)

## Quick start

```python
import json
import os
from capnagent import Issuer, Verifier, Auditor

root_key  = os.urandom(32)   # production: KMS / secret manager
audit_key = os.urandom(32)

# Issue a scoped capability.
cap = (
    Issuer.from_key(root_key)
    .issue("checkout")
    .caveat('caller == "agent:planner"')
    .caveat('tool == "checkout.purchase"')
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build()
)

verifier = Verifier(root_key)
auditor  = Auditor(audit_key)

# Verify a call: returns a JSON-encoded receipt.
ctx = {
    "caller": "agent:planner",
    "tool": "checkout.purchase",
    "args": {"sku": "USB-C cable", "amount_cents": 1299},
    "nowMs": 1_700_000_000_000,
}
receipt_json = verifier.verify_with_context(cap, json.dumps(ctx), auditor)
receipt = json.loads(receipt_json)
assert receipt["outcome"]["kind"] == "allowed"
```

## API

| Class | Method | Notes |
|---|---|---|
| `Issuer` | `from_key(bytes) -> Issuer` | 32+ bytes from CSPRNG. |
| | `issue(identifier) -> CapabilityBuilder` | |
| `CapabilityBuilder` | `caveat(predicate)` | DSL: see [docs/WEEK2_SPEC.md §2.2](../../docs/WEEK2_SPEC.md). |
| | `holder_of_key(pubkey_32_bytes)` | DPoP-style hok binding. |
| | `build() -> Capability` | Raises if zero caveats (angle C.5). |
| `Capability` | `serialize() -> str` | URL-safe base64. |
| | `parse(token) -> Capability` | Static. |
| | `attenuate(predicate) -> Capability` | Pre-validates parse (angle B.2). |
| `Verifier` | `Verifier(key_bytes)` | |
| | `verify_with_context(cap, ctx_json, auditor) -> str` | Receipt as JSON string. Pass `json.dumps(ctx)` for full A.1 protection. |
| `Auditor` | `Auditor(key_bytes)` | Empty key raises (angle B.3). |
| | `verify(receipt_json)` | Raises on tampered receipt. |

## Why the Python binding gets A.1 closure for free

The v0.6 angle finding A.1 (sub-ulp f64 collapse) has a JS-layer
artefact: JS's `Number` IS `f64`, so `JSON.parse` collapses sub-ulp
digits BEFORE the WASM boundary. v0.6.1 added a JSON-string entry
point to the WASM binding to work around this for JS callers.

**Python doesn't have that problem.** Python's `json.dumps` preserves
arbitrary integer precision (Python ints are unbounded), and `float`
literals round-trip through `repr()` in a way that preserves
syntactic shape. The Rust side parses the JSON string with
`serde_json::from_str` (with `arbitrary_precision`), keeping the
source text past the parse boundary. So the v0.6 integer-domain rule
fires correctly end-to-end through the Python binding by default.

The test `test_v0_6_integer_caveat_rejects_decimal_arg` in
`tests/test_basic.py` exercises this directly.

## Build from source

Prerequisites:
- Rust toolchain (stable)
- Python 3.8+ with development headers
- `pip install maturin`

```bash
cd crates/capnagent-py
maturin develop          # editable install into the current venv
python -m pytest tests/ -v
```

To produce a publishable wheel:

```bash
maturin build --release
# Wheel appears under crates/capnagent-py/target/wheels/
```

## License

Apache-2.0 — same as the Rust core.
