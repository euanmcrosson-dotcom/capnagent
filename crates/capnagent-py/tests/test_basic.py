"""Basic smoke tests for the Python bindings.

Run after `maturin develop`:

    cd crates/capnagent-py
    maturin develop
    python -m pytest tests/ -v
"""

from __future__ import annotations

import json
import os

import pytest

from capnagent import Auditor, Capability, CapabilityBuilder, Issuer, Verifier


@pytest.fixture
def keys():
    return os.urandom(32), os.urandom(32)


def test_imports():
    assert Issuer is not None
    assert CapabilityBuilder is not None
    assert Capability is not None
    assert Verifier is not None
    assert Auditor is not None


def test_issue_verify_allow_path(keys):
    root_key, audit_key = keys
    cap = (
        Issuer.from_key(root_key)
        .issue("checkout")
        .caveat('caller == "agent:planner"')
        .caveat('tool == "checkout.purchase"')
        .build()
    )
    verifier = Verifier(root_key)
    auditor = Auditor(audit_key)

    ctx = json.dumps({
        "caller": "agent:planner",
        "tool": "checkout.purchase",
        "args": {},
        "nowMs": 1_700_000_000_000,
    })

    receipt_json = verifier.verify_with_context(cap, ctx, auditor)
    receipt = json.loads(receipt_json)
    assert receipt["outcome"]["kind"] == "allowed"


def test_issue_verify_deny_path(keys):
    root_key, audit_key = keys
    cap = (
        Issuer.from_key(root_key)
        .issue("checkout")
        .caveat('caller == "agent:planner"')
        .caveat('tool == "checkout.purchase"')
        .build()
    )
    verifier = Verifier(root_key)
    auditor = Auditor(audit_key)

    ctx = json.dumps({
        "caller": "agent:planner",
        "tool": "bank.wire",  # different tool
        "args": {},
        "nowMs": 1_700_000_000_000,
    })

    receipt_json = verifier.verify_with_context(cap, ctx, auditor)
    receipt = json.loads(receipt_json)
    assert receipt["outcome"]["kind"] == "denied"


def test_empty_caveat_token_rejected(keys):
    """Angle C.5 closure: no-caveat capabilities are god-mode and
    refused at build time."""
    root_key, _ = keys
    with pytest.raises(ValueError, match=r"god-mode|zero caveats"):
        Issuer.from_key(root_key).issue("x").build()


def test_invalid_caveat_predicate_rejected(keys):
    """Angle B.2 closure: empty / unparseable predicates surface as
    a parse error, not a silent permanent-deny token."""
    root_key, _ = keys
    with pytest.raises(ValueError, match=r"invalid caveat predicate"):
        Issuer.from_key(root_key).issue("x").caveat("")


def test_zero_byte_audit_key_rejected():
    """Angle B.3 closure: zero-byte audit key is refused at Auditor
    construction time."""
    with pytest.raises(ValueError, match=r"non-empty"):
        Auditor(b"")


def test_v0_6_integer_caveat_rejects_decimal_arg(keys):
    """Angle A.1 closure: integer-syntactic caveat literal vs
    float-syntactic arg is rejected at evaluation time. Note: from
    Python this works end-to-end because `json.dumps` preserves the
    source-text shape of numbers, unlike JS's `JSON.parse` which
    collapses sub-ulp f64."""
    root_key, audit_key = keys
    cap = (
        Issuer.from_key(root_key)
        .issue("x")
        .caveat("arg.amount <= 50")  # integer literal
        .build()
    )
    verifier = Verifier(root_key)
    auditor = Auditor(audit_key)

    # The exact A.1 reproducer. We construct the JSON manually so
    # the source text survives — `json.dumps({"amount": 50.000...001})`
    # in Python would re-stringify through Python's float repr, which
    # could collapse the precision. Manual string construction
    # bypasses that.
    ctx_json = (
        '{"caller":"x","tool":"y","args":{"amount":50.000000000000001},'
        '"nowMs":1700000000000}'
    )

    receipt_json = verifier.verify_with_context(cap, ctx_json, auditor)
    receipt = json.loads(receipt_json)
    assert receipt["outcome"]["kind"] == "denied"


def test_serialize_round_trip(keys):
    root_key, _ = keys
    cap = (
        Issuer.from_key(root_key)
        .issue("checkout")
        .caveat('caller == "agent:planner"')
        .build()
    )
    serialized = cap.serialize()
    parsed = Capability.parse(serialized)
    assert parsed.identifier == "checkout"
