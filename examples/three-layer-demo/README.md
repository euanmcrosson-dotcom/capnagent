# Three-layer end-to-end demo

Runnable example that exercises **all three** projects of the agent-security stack against a single agent's tool calls:

```
[ mcp-recon ]  →  caveats.json  →  [ capnagent ]  →  cap token  →  [ mcp-guardrails ]  →  ALLOW / DENY
   recon                              authority                       runtime policy
```

The recon step is illustrated by a captured `caveats.json` checked into this directory — no live MCP server needed. The other two layers run for real against the PyPI packages.

## What it shows

The demo simulates an agent that wants to call four tools:

| # | Tool call | What capnagent does | What mcp-guardrails does | Final |
|---|---|---|---|---|
| 1 | `list_directory({"path": "/sandbox/data"})` | ALLOW (matches recon-recommended caveat: `arg.path starts_with '/sandbox/'`) | ALLOW (no rule fires) | **ALLOW** |
| 2 | `list_directory({"path": "/etc/passwd"})` | DENY (capnagent caveat denies non-`/sandbox/` paths) | (not reached) | **DENY at capnagent** |
| 3 | `send_email({"to": "alice@example.com", "body": "Lunch at noon?"})` | ALLOW (caveat: `arg.to starts_with "alice@"`) | ALLOW (no rule fires) | **ALLOW** |
| 4 | `send_email({"to": "alice@example.com", "body": "FYI: API_KEY=sk-prod-..."})` | ALLOW (recipient matches caveat) | **DENY** (secret-exfil rule fires on body) | **DENY at mcp-guardrails** |

Calls 2 and 4 are the two failure modes the two layers catch independently. Neither layer alone catches both.

## Run it

```
pip install -r requirements.txt
python demo.py
```

Expected output:

```
=== Three-layer agent security demo ===

Loaded 2 mcp-recon issuance plan(s) from sample-caveats.json (2 scope, 0 deny).
  - list_directory  [scope] tool == "list_directory" AND arg.path starts_with "/sandbox/"
  - send_email      [scope] tool == "send_email" AND arg.to starts_with "alice@"

Minted capability token (capnagent: type=Capability).
Loaded mcp-guardrails policy: 122 rules across 9 attack classes.

[1/4] list_directory({"path": "/sandbox/data"})
  why: in-scope filesystem read
  capnagent:        ALLOW
  mcp-guardrails:   ALLOW (no rule fired)
  FINAL:            ALLOW [OK]

[2/4] list_directory({"path": "/etc/passwd"})
  why: out-of-scope path -- capnagent should deny
  capnagent:        DENY -- caveat failed: ...
  mcp-guardrails:   (skipped -- capnagent denied)
  FINAL:            DENY [OK]

[3/4] send_email({"to": "alice@example.com", "body": "Lunch at noon?"})
  why: in-scope recipient, benign body
  capnagent:        ALLOW
  mcp-guardrails:   ALLOW (no rule fired)
  FINAL:            ALLOW [OK]

[4/4] send_email({"to": "alice@example.com", "body": "FYI -- API_KEY=sk-prod-..."})
  why: in-scope recipient but exfil-shaped body -- mcp-guardrails should deny
  capnagent:        ALLOW
  mcp-guardrails:   DENY -- tool-policy-pii-exfil--send_email--body--default
                    reason: Email payload contains secret-shaped material ...
  FINAL:            DENY [OK]

=== Summary ===
2 call(s) authorized end-to-end, 2 denied
  - 1 denied at the authority layer (capnagent)
  - 1 denied at the runtime-policy layer (mcp-guardrails)
```

## DSL composition note

The demo combines the per-tool caveats into a single capability token using **OR** disjunction:

```
( tool == "list_directory" AND arg.path starts_with "/sandbox/" )
   OR
( tool == "send_email"     AND arg.to   starts_with "alice@"    )
```

Sequential `.caveat()` calls on the builder compose with **AND** semantics — which would require `tool == "list_directory"` and `tool == "send_email"` to both hold for a single call (never satisfiable). For a token that authorizes multiple tools, OR-compose explicitly. The demo script handles this internally; you can also issue one token per tool if you prefer per-tool delegation.

## Why both layers matter

Call **#2** is denied by capnagent because the caveat literally specifies which paths are reachable. mcp-guardrails wouldn't catch this — `/etc/passwd` isn't on its blocklist; the path is just "out of scope" for *this agent's* authority.

Call **#4** passes capnagent because the recipient is in-bound. capnagent's caveat doesn't inspect the email body. mcp-guardrails catches it because the body matches the secret-exfil pattern at the runtime layer.

This is the "factoring is the contribution" claim from the HN post made concrete: each layer catches a class of failure the other can't see.

## The pieces

- **`sample-caveats.json`** — captured output from `mcp-recon caveats ...` (illustrative; the actual file would come from running mcp-recon against a real MCP server). Schema: `mcp-recon/v0.1/caveats`.
- **`demo.py`** — reads caveats, mints a capnagent token, runs the four calls, prints the decision matrix.
- **`requirements.txt`** — pins `capnagent` and `mcp-guardrails`.

## What this demo is NOT

- Not a benchmark. For verify-path throughput, see `cargo bench` in `crates/capnagent-core/`.
- Not a comprehensive evaluation. For that, see [`docs/EVALUATION.md`](../../docs/EVALUATION.md) (10 rounds, 4 HIGH findings closed) and [`docs/purple-team/`](../../docs/purple-team/) (full corpus).
- Not a tutorial on writing caveats. For DSL syntax, see [`docs/DESIGN.md`](../../docs/DESIGN.md) §2.

## Failure modes

If `demo.py` errors:

| Error | Likely cause | Fix |
|---|---|---|
| `ImportError: capnagent` | Stale install | `pip install --upgrade capnagent` |
| `ImportError: mcp_guard` | Different package name | `pip install mcp-guardrails` (note the package name on PyPI is `mcp-guardrails`; the import name is `mcp_guard`) |
| `AttributeError: ... Issuer ...` | Stale install predating the full API | `pip install --upgrade 'capnagent>=0.9.0'` |
| `KeyError: 'plans'` / `unexpected schema` | sample-caveats.json hand-edited | Restore from git |
