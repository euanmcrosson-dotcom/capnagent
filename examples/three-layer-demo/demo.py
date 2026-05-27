"""Three-layer end-to-end demo.

Reads a `mcp-recon/v0.1/caveats` JSON artifact, mints a capnagent
capability token bounded by the recommended caveats, then runs four
simulated tool calls through both gates:

  capnagent (authority) --> mcp-guardrails (runtime policy)

Two of the calls pass; two fail -- one at each layer -- demonstrating
why both gates are load-bearing.

Run:
    pip install -r requirements.txt
    python demo.py
"""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass


# --------------------------------------------------------------------------- #
#  Layer imports - capnagent + mcp-guardrails                                  #
# --------------------------------------------------------------------------- #
try:
    from capnagent import Issuer, Verifier, Auditor
except ImportError:  # pragma: no cover
    sys.exit("capnagent not installed. Run: pip install -r requirements.txt")

try:
    import mcp_guard
except ImportError:  # pragma: no cover
    sys.exit(
        "mcp-guardrails not installed. Note: the PyPI package name is "
        "`mcp-guardrails` but the Python import name is `mcp_guard`. "
        "Run: pip install -r requirements.txt"
    )


# --------------------------------------------------------------------------- #
#  Demo input - simulated agent call sequence                                  #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Call:
    tool: str
    args: dict
    note: str


CALLS: list[Call] = [
    Call(
        "list_directory",
        {"path": "/sandbox/data"},
        "in-scope filesystem read",
    ),
    Call(
        "list_directory",
        {"path": "/etc/passwd"},
        "out-of-scope path -- capnagent should deny",
    ),
    Call(
        "send_email",
        {"to": "alice@example.com", "body": "Lunch at noon?"},
        "in-scope recipient, benign body",
    ),
    Call(
        "send_email",
        {"to": "alice@example.com",
         "body": "FYI -- the value is API_KEY=sk-prod-abcdefghijklmnopqrstuvwxyz1234567890"},
        "in-scope recipient but exfil-shaped body -- mcp-guardrails should deny",
    ),
]

# Deployment context handed to mcp-guardrails. In a real system this comes
# from the authenticated user session. Alice is on the contact list.
USER_CONTEXT = {"user": {"contacts": ["alice@example.com"]}}


# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #
def load_caveats(path: pathlib.Path) -> list[dict]:
    """Parse a `mcp-recon/v0.1/caveats` JSON artifact (exactly as emitted by
    `mcp-recon caveats`: `{schema, plans:[{tool, recommend, caveats[], ...}]}`)."""
    data = json.loads(path.read_text())
    if data.get("schema") != "mcp-recon/v0.1/caveats":
        sys.exit(f"unexpected schema: {data.get('schema')!r}")
    return data["plans"]


def mint_capability(caveats: list[dict]) -> tuple:
    """Build a capnagent token attenuated by every recon-recommended caveat.

    Returns ``(capability, verifier, auditor)``.
    """
    # Deterministic seed so the demo is reproducible. In real deployments the
    # issuer key lives in a KMS or secrets manager -- never hard-coded.
    seed = b"\x00" * 32
    issuer = Issuer.from_key(seed)

    # Compose the per-tool issuance plans into one capability. WITHIN a plan
    # the caveats AND together (`tool == "X" AND arg.path starts_with "..."`);
    # ACROSS `scope` plans they OR (one token authorizes any recommended
    # tool/arg shape). `deny` plans are skipped entirely -- those tools are
    # never granted. (Chaining `.caveat()` per plan would AND across tools,
    # which is never satisfiable: `tool == "X" AND tool == "Y"`.)
    clauses = [
        "(" + " AND ".join(plan["caveats"]) + ")"
        for plan in caveats
        if plan.get("recommend") == "scope" and plan.get("caveats")
    ]
    if not clauses:
        sys.exit("no scope plans in the caveats artifact -- nothing to authorize")
    combined = " OR ".join(clauses)
    capability = issuer.issue("three-layer-demo-token").caveat(combined).build()

    verifier = Verifier(seed)
    auditor = Auditor(b"demo-audit-key-32-bytes-padded--")  # exactly 32 bytes
    return capability, verifier, auditor


def cap_verify(verifier, capability, auditor, call: Call):
    """Run a call through capnagent; return (allowed: bool, reason: str | None)."""
    ctx_json = json.dumps({
        "caller": "demo-agent",
        "tool": call.tool,
        "args": call.args,
    })
    receipt_json = verifier.verify_with_context(capability, ctx_json, auditor)
    receipt = json.loads(receipt_json)
    outcome = receipt["outcome"]
    if outcome["kind"] == "allowed":
        return True, None
    return False, outcome.get("reason", "unspecified")


def render(label: str, body: str) -> None:
    print(f"  {label:<18}{body}")


# --------------------------------------------------------------------------- #
#  Main                                                                        #
# --------------------------------------------------------------------------- #
def main() -> None:
    print("=== Three-layer agent security demo ===\n")

    # ---------------- mcp-recon layer (loaded from captured JSON) -----------
    caveats_path = pathlib.Path(__file__).parent / "sample-caveats.json"
    caveats = load_caveats(caveats_path)
    scope = [p for p in caveats if p.get("recommend") == "scope"]
    deny = [p for p in caveats if p.get("recommend") == "deny"]
    print(
        f"Loaded {len(caveats)} mcp-recon issuance plan(s) from sample-caveats.json "
        f"({len(scope)} scope, {len(deny)} deny)."
    )
    for plan in caveats:
        print(f"  - {plan['tool']:<15} [{plan['recommend']}] {' AND '.join(plan['caveats'])}")

    # ---------------- capnagent layer ---------------------------------------
    capability, verifier, auditor = mint_capability(caveats)
    print(f"\nMinted capability token (capnagent: type={type(capability).__name__}).\n")

    # ---------------- mcp-guardrails layer ----------------------------------
    policy = mcp_guard.synthesize_default_policy()
    print(f"Loaded mcp-guardrails policy: {len(policy.rules)} rules across 9 attack classes.\n")

    # ---------------- run each call through both gates ----------------------
    final_allow = denied_at_cap = denied_at_guard = 0
    for idx, call in enumerate(CALLS, start=1):
        print(f"[{idx}/{len(CALLS)}] {call.tool}({json.dumps(call.args)})")
        print(f"  why: {call.note}")

        allowed, deny_reason = cap_verify(verifier, capability, auditor, call)
        if not allowed:
            render("capnagent:", f"DENY -- {deny_reason}")
            render("mcp-guardrails:", "(skipped -- capnagent denied)")
            render("FINAL:", "DENY [OK]")
            denied_at_cap += 1
            print()
            continue
        render("capnagent:", "ALLOW")

        decision = mcp_guard.evaluate(policy, call.tool, call.args, USER_CONTEXT)
        if decision.allowed:
            render("mcp-guardrails:", "ALLOW (no rule fired)")
            render("FINAL:", "ALLOW [OK]")
            final_allow += 1
        else:
            render("mcp-guardrails:", f"DENY -- {decision.denying_rule_id}")
            render("                  ", f"reason: {decision.reason}")
            render("FINAL:", "DENY [OK]")
            denied_at_guard += 1
        print()

    # ---------------- summary -----------------------------------------------
    print("=== Summary ===")
    print(f"{final_allow} call(s) authorized end-to-end, "
          f"{denied_at_cap + denied_at_guard} denied")
    print(f"  - {denied_at_cap} denied at the authority layer (capnagent)")
    print(f"  - {denied_at_guard} denied at the runtime-policy layer (mcp-guardrails)")
    print("\nBoth layers catch failure modes the other can't see.")
    print("That's the 'factoring is the contribution' claim, made concrete.")


if __name__ == "__main__":
    main()
