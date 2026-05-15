"""Minimal example: issue → verify → deny → audit receipt.

Run after `maturin develop` from `crates/capnagent-py`:

    cd crates/capnagent-py
    maturin develop
    python examples/basic.py
"""

from __future__ import annotations

import json
import os

from capnagent import Auditor, Issuer, Verifier


def main() -> None:
    # In production these come from a KMS / secret manager — both
    # 32-byte CSPRNG outputs.
    root_key = os.urandom(32)
    audit_key = os.urandom(32)

    # ── Issue a scoped capability ───────────────────────────────────
    cap = (
        Issuer.from_key(root_key)
        .issue("checkout")
        .caveat('caller == "agent:planner"')
        .caveat('tool == "checkout.purchase"')
        .caveat("now <= @2099-01-01T00:00:00Z")
        .build()
    )

    verifier = Verifier(root_key)
    auditor = Auditor(audit_key)

    # ── ALLOW path ──────────────────────────────────────────────────
    in_scope = {
        "caller": "agent:planner",
        "tool": "checkout.purchase",
        "args": {"sku": "USB-C cable", "amount_cents": 1299},
        "nowMs": 1_700_000_000_000,
    }
    receipt_json = verifier.verify_with_context(cap, json.dumps(in_scope), auditor)
    receipt = json.loads(receipt_json)
    print(f"in-scope call:    outcome={receipt['outcome']['kind']}")
    assert receipt["outcome"]["kind"] == "allowed"

    # ── DENY path ───────────────────────────────────────────────────
    out_of_scope = {
        "caller": "agent:planner",
        "tool": "bank.wire",
        "args": {"to": "attacker@example", "amount_cents": 3000},
        "nowMs": 1_700_000_000_000,
    }
    receipt_json = verifier.verify_with_context(cap, json.dumps(out_of_scope), auditor)
    receipt = json.loads(receipt_json)
    print(f"out-of-scope call: outcome={receipt['outcome']['kind']}, reason={receipt['outcome'].get('reason')}")
    assert receipt["outcome"]["kind"] == "denied"

    # ── Audit the receipt ──────────────────────────────────────────
    # A tampered receipt would raise ValueError here; a fresh signed
    # one passes silently.
    auditor.verify(receipt_json)
    print("audit signature: ok")


if __name__ == "__main__":
    main()
