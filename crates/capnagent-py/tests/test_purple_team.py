"""Purple-team rounds, ported to the Python bindings.

These are the Python-side concrete-evidence counterparts of three rounds from
`docs/purple-team/`, exercised through the public `capnagent` Python surface
(`Issuer` / `Capability` / `Verifier.verify_with_context` / `Auditor`) so the
PyPI package carries its own adversarial proof rather than inheriting it only
from the Rust/TS suites.

Rounds ported here (the Python binding now exposes the full security surface —
NonceStore, RevocationList/Revoker, verify_with_proof, pop_challenge_for):

  - Round 01 — tool-description injection / cross-server confused deputy
  - Round 02 — replay of a holder-of-key proof (NonceStore)
  - Round 03 — capability broadening (hostile-holder tampering)
  - Round 04 — capability revocation (signed RevocationList)
  - Round 07 — fs-sandbox prefix foot-gun (`matches` substring vs `starts_with`)

Round 02 needs an ed25519 signer (`cryptography`); it skips if unavailable.

Run after `maturin develop`:

    cd crates/capnagent-py && maturin develop && python -m pytest tests/ -v
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from capnagent import (
    Auditor,
    Capability,
    Issuer,
    NonceStore,
    RevocationList,
    Revoker,
    Verifier,
    pop_challenge_for,
)

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


# ─── Round 04 — capability revocation ─────────────────────────────────────────


def test_round_04_revoked_capability_is_denied(keys):
    """Round 04 — a capability is revoked after issuance. Once the issuer
    publishes a signed RevocationList and the verifier installs it, verifying
    that capability's identifier is denied `capability revoked` — before, the
    same call was allowed."""
    root_key, audit_key = keys
    cap = (
        Issuer.from_key(root_key)
        .issue("buy-123")
        .caveat('tool == "checkout.purchase"')
        .build()
    )
    auditor = Auditor(audit_key)

    # Before revocation: allowed.
    before = json.loads(
        Verifier(root_key).verify_with_context(cap, _ctx("checkout.purchase"), auditor)
    )
    assert before["outcome"]["kind"] == "allowed"

    # Issuer revokes the identifier and publishes a signed snapshot.
    revoker = Revoker(root_key)
    revoker.revoke("buy-123")
    rlist = revoker.publish(NOW_MS)
    assert rlist.contains("buy-123")
    # Wire round-trip the list the way an issuer would ship it to a verifier.
    rlist = RevocationList.parse(rlist.serialize())

    # Verifier installs the list; the same call is now DENIED as revoked.
    v = Verifier(root_key)
    v.with_revocation_list(rlist)
    assert v.has_revocation_list()
    after = json.loads(v.verify_with_context(cap, _ctx("checkout.purchase"), auditor))
    assert after["outcome"]["kind"] == "denied"
    assert "revok" in after["outcome"]["reason"].lower()


def test_round_04_revocation_list_signed_under_wrong_key_is_rejected(keys):
    """A revocation list signed under a different root key must NOT install —
    that integrity check is what stops a forged revocation (or un-revocation)
    from a party who isn't the issuer."""
    root_key, _ = keys
    other_key = os.urandom(32)
    forged = Revoker(other_key)
    forged.revoke("buy-123")
    forged_list = forged.publish(NOW_MS)

    v = Verifier(root_key)
    with pytest.raises(ValueError, match=r"signature|revocation"):
        v.with_revocation_list(forged_list)
    assert not v.has_revocation_list()


# ─── Round 02 — replay of a holder-of-key proof ───────────────────────────────


def test_round_02_replay_of_hok_proof_is_denied(keys):
    """Round 02 — a holder-of-key proof, once used, cannot be replayed when a
    NonceStore is installed. The first `verify_with_proof` allows; replaying the
    exact same (challenge, proof) is denied `proof replay detected`."""
    pytest.importorskip(
        "cryptography", reason="needs an ed25519 signer to produce the proof"
    )
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    root_key, audit_key = keys
    holder_sk = Ed25519PrivateKey.generate()
    holder_pk = holder_sk.public_key().public_bytes_raw()  # raw 32 bytes
    assert len(holder_pk) == 32

    cap = (
        Issuer.from_key(root_key)
        .issue("buy")
        .holder_of_key(holder_pk)  # bind before any caveat (DESIGN.md §11)
        .caveat('tool == "checkout.purchase"')
        .build()
    )
    assert cap.holder_of_key == list(holder_pk) or bytes(cap.holder_of_key) == holder_pk
    auditor = Auditor(audit_key)
    ctx = _ctx("checkout.purchase")

    # Holder derives the default proof-of-possession challenge and signs it.
    challenge = pop_challenge_for(cap, ctx)
    proof = holder_sk.sign(bytes(challenge))  # 64-byte ed25519 signature
    assert len(proof) == 64

    verifier = Verifier(root_key)
    verifier.with_nonce_store(NonceStore())  # turn on replay protection
    assert verifier.has_nonce_store()

    # First use of the proof: allowed.
    first = json.loads(verifier.verify_with_proof(cap, ctx, auditor, challenge, proof))
    assert first["outcome"]["kind"] == "allowed", first

    # Replaying the identical proof: denied.
    replay = json.loads(verifier.verify_with_proof(cap, ctx, auditor, challenge, proof))
    assert replay["outcome"]["kind"] == "denied"
    assert "replay" in replay["outcome"]["reason"].lower()


def test_round_02_wrong_length_proof_is_rejected(keys):
    """An ed25519 proof must be exactly 64 bytes; a short proof is rejected at
    the boundary rather than mis-evaluated."""
    root_key, audit_key = keys
    cap = Issuer.from_key(root_key).issue("buy").caveat('tool == "x"').build()
    verifier = Verifier(root_key)
    with pytest.raises(ValueError, match=r"64 bytes"):
        verifier.verify_with_proof(cap, _ctx("x"), Auditor(audit_key), b"chal", b"too-short")


# ─── Full-surface parity smoke (the bindings are no longer a subset) ──────────


def test_python_binding_exposes_full_security_surface():
    """Guards the B1 goal: the Python package can do replay protection,
    revocation, and holder-of-key proof — not just verify_with_context."""
    for name in ("NonceStore", "RevocationList", "Revoker", "pop_challenge_for"):
        assert name in globals(), f"{name} should be importable from capnagent"
    for method in (
        "verify_with_proof",
        "verify",
        "with_nonce_store",
        "with_nonce_ttl_ms",
        "with_revocation_list",
        "has_nonce_store",
        "has_revocation_list",
    ):
        assert hasattr(Verifier, method), f"Verifier should expose {method}"
