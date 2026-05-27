"""capnagent — capability-based authority tokens for AI agent tool calls.

Python bindings for the Rust core. The native classes are defined in
the `capnagent._native` extension module; this file re-exports them
under stable, friendlier names so callers don't need to know about the
underlying maturin packaging.

Quick start:

    import os
    import json
    from capnagent import Issuer, Verifier, Auditor

    root_key = os.urandom(32)
    audit_key = os.urandom(32)

    cap = (
        Issuer.from_key(root_key)
        .issue("checkout")
        .caveat('caller == "agent:planner"')
        .caveat('tool == "checkout.purchase"')
        .build()
    )

    verifier = Verifier(root_key)
    auditor = Auditor(audit_key)

    ctx = {
        "caller": "agent:planner",
        "tool": "checkout.purchase",
        "args": {},
        "nowMs": 1_700_000_000_000,
    }

    receipt_json = verifier.verify_with_context(cap, json.dumps(ctx), auditor)
    receipt = json.loads(receipt_json)
    assert receipt["outcome"]["kind"] == "allowed"

See the example in `examples/basic.py` for a fuller walk through
allow + deny + denial-receipt-audit.
"""

from __future__ import annotations

from capnagent._native import (
    Auditor,
    Capability,
    CapabilityBuilder,
    Issuer,
    NonceStore,
    RevocationList,
    Revoker,
    Verifier,
    pop_challenge_for,
)

__all__ = [
    "Auditor",
    "Capability",
    "CapabilityBuilder",
    "Issuer",
    "NonceStore",
    "RevocationList",
    "Revoker",
    "Verifier",
    "pop_challenge_for",
]

# Version is set by the maturin build via pyproject.toml; this is a
# fallback for in-tree usage (e.g. `maturin develop` then `python -c
# 'import capnagent; print(capnagent.__version__)'`).
__version__ = "0.8.0"
