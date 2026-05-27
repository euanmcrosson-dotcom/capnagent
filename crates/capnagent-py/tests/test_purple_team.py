"""Purple-team rounds, ported to the Python bindings.

These are the Python-side concrete-evidence counterparts of three rounds from
`docs/purple-team/`, exercised through the public `capnagent` Python surface
(`Issuer` / `Capability` / `Verifier.verify_with_context` / `Auditor`) so the
PyPI package carries its own adversarial proof rather than inheriting it only
from the Rust/TS suites.

Rounds ported here are the ones expressible with the bindings' surface (no
NonceStore / RevocationList / hok-proof is exposed in Python yet, so the
replay/revocation rounds 02/04/06/08 are out of scope):

  - Round 01 — tool-description injection / cross-server confused deputy
  - Round 03 — capability broadening (hostile-holder tampering)
  - Round 07 — fs-sandbox prefix foot-gun (`matches` substring vs `starts_with`)

Run after `maturin develop`:

    cd crates/capnagent-py && maturin develop && python -m pytest tests/ -v
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from capnagent import Auditor, Capability, Issuer, Verifier

NOW_MS = 1_700_000_000_000


@pytest.fixture
def keys():
    return os.urandom(32), os.urandom(32)


def _ctx(tool: str, args: dict | None = None, caller: str = "agent:planner") -> str:
    return json.dumps(
        {"caller": caller, "tool": tool, "args": args or {}, "nowMs": NOW_MS}
    )


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ─── Round 01 — tool-description injection (cross-server confused deputy) ──────


def test_round_01_path_scoped_capability_defeats_confused_deputy(keys):
    """A malicious MCP server's tool description tries to hijack the agent into
    reading `~/.ssh/id_rsa` via a co-installed filesystem server. A capability
    scoped to `tool == "read_file"` AND `arg.path starts_with <sandbox>` denies
    the read regardless of the injection's wording — the gate never sees the
    description, only the resolved tool + path."""
    root_key, audit_key = keys
    sandbox = "/srv/agent-sandbox/"
    cap = (
        Issuer.from_key(root_key)
        .issue("fs.read")
        .caveat('tool == "read_file"')
        .caveat(f'arg.path starts_with "{sandbox}"')
        .build()
    )
    verifier, auditor = Verifier(root_key), Auditor(audit_key)

    def outcome(tool: str, path: str) -> dict:
        receipt = json.loads(
            verifier.verify_with_context(cap, _ctx(tool, {"path": path}), auditor)
        )
        return receipt["outcome"]

    # Negative (true-negative): a legit in-sandbox read is ALLOWED. A defense
    # that denies everything is not the win condition.
    assert outcome("read_file", sandbox + "notes.txt")["kind"] == "allowed"

    # Positive (the attack): exfil of an out-of-sandbox secret is DENIED, no
    # matter how the malicious tool description phrased the target path.
    assert outcome("read_file", "/home/user/.ssh/id_rsa")["kind"] == "denied"

    # A "looks-like-sandbox-but-isn't" sibling is still out of scope → DENIED.
    assert outcome("read_file", "/srv/agent-sandbox-evil/id_rsa")["kind"] == "denied"

    # Cross-tool hijack: listing the secrets dir via a different tool is DENIED
    # by the tool caveat even with an in-sandbox path.
    assert outcome("list_directory", sandbox)["kind"] == "denied"


# ─── Round 03 — capability broadening (hostile-holder tampering) ──────────────


def test_round_03_broadened_capability_is_rejected_by_chain_gate(keys):
    """A hostile holder mutates a caveat to grant themselves wider authority
    than they were issued. The HMAC-SHA256 macaroon chain catches it at the
    FIRST gate: `verify_with_context` raises a chain-integrity error before any
    caveat evaluation runs — the holder can't re-sign without the root key."""
    root_key, audit_key = keys
    cap = (
        Issuer.from_key(root_key)
        .issue("checkout")
        .caveat('caller == "agent:planner"')
        .caveat('tool == "checkout.purchase"')
        .build()
    )
    verifier, auditor = Verifier(root_key), Auditor(audit_key)

    # Negative (true-negative): the unmodified capability verifies cleanly.
    legit = json.loads(
        verifier.verify_with_context(cap, _ctx("checkout.purchase"), auditor)
    )
    assert legit["outcome"]["kind"] == "allowed"

    # Attack: widen the tool caveat (`checkout.purchase` → `bank.wire`) by
    # editing the serialized token directly. parse() does no signature check.
    obj = json.loads(_b64url_decode(cap.serialize()))
    assert obj["caveats"][1]["predicate"] == 'tool == "checkout.purchase"'
    obj["caveats"][1]["predicate"] = 'tool == "bank.wire"'
    forged = Capability.parse(_b64url_encode(json.dumps(obj).encode()))

    # The widened predicate WOULD pass caveat evaluation for a bank.wire call —
    # but the chain gate fires first and rejects the forgery. No receipt.
    with pytest.raises(ValueError, match=r"chain integrity"):
        verifier.verify_with_context(forged, _ctx("bank.wire"), auditor)


def test_round_03_caveat_drop_also_breaks_the_chain(keys):
    """Same threat class: dropping a caveat (rather than mutating one) likewise
    breaks the chain — order and membership are part of the signed payload."""
    root_key, audit_key = keys
    cap = (
        Issuer.from_key(root_key)
        .issue("checkout")
        .caveat('caller == "agent:planner"')
        .caveat('tool == "checkout.purchase"')
        .build()
    )
    verifier, auditor = Verifier(root_key), Auditor(audit_key)

    obj = json.loads(_b64url_decode(cap.serialize()))
    obj["caveats"] = obj["caveats"][:1]  # drop the tool caveat to widen scope
    forged = Capability.parse(_b64url_encode(json.dumps(obj).encode()))

    with pytest.raises(ValueError, match=r"chain integrity"):
        verifier.verify_with_context(forged, _ctx("bank.wire"), auditor)


# ─── Round 07 — fs-sandbox prefix foot-gun (matches vs starts_with) ───────────


def test_round_07_matches_is_a_substring_footgun_starts_with_closes_it(keys):
    """The DSL's `matches` is substring containment, not path-aware prefix. A
    cap scoped with `arg.path matches "/sandbox"` is a foot-gun: a LATERAL path
    that merely *contains* the prefix as a substring slips through. `starts_with`
    is anchored and closes it. This asserts BOTH the documented break and the
    fix, so it doubles as a regression sentinel — if the engine ever makes
    `matches` path-aware, the foot-gun assertion fails loudly."""
    root_key, audit_key = keys
    verifier, auditor = Verifier(root_key), Auditor(audit_key)

    # Lateral path: NOT a child of /sandbox, but contains "/sandbox" as a substring.
    lateral = "/etc/srv/sandbox-leaked/secret.txt"
    legit = "/sandbox/config.json"

    def kind(cap: Capability, path: str) -> str:
        receipt = json.loads(
            verifier.verify_with_context(cap, _ctx("read_file", {"path": path}), auditor)
        )
        return receipt["outcome"]["kind"]

    # FOOT-GUN: `matches` (substring) wrongly ALLOWS the lateral path. This is
    # the documented break (round 07, status BREAKS); the assert encodes the bug.
    cap_matches = (
        Issuer.from_key(root_key).issue("fs").caveat('arg.path matches "/sandbox"').build()
    )
    assert kind(cap_matches, lateral) == "allowed", "round 07 foot-gun changed — update the round"
    assert kind(cap_matches, legit) == "allowed"

    # FIX: `starts_with` (anchored prefix) DENIES the lateral path while still
    # allowing the genuine in-sandbox path.
    cap_prefix = (
        Issuer.from_key(root_key)
        .issue("fs")
        .caveat('arg.path starts_with "/sandbox/"')
        .build()
    )
    assert kind(cap_prefix, lateral) == "denied"
    assert kind(cap_prefix, legit) == "allowed"
