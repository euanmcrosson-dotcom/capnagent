# Loom demo script — 3 minutes

Goal: in 3 minutes show a viewer what capnagent + mcp-guardrails + mcp-recon do and why all three matter. Optimized for Twitter/LinkedIn share; pinned at the top of the Show HN comment thread.

---

## Setup before you hit record

- Terminal at 22-24pt font, dark theme, 100 cols wide
- Editor open in a separate window with the example code pasted but not yet shown
- Clean Python venv with all three packages pre-installed:
  ```
  python -m venv /tmp/demo-venv
  source /tmp/demo-venv/bin/activate
  pip install capnagent mcp-guardrails
  npm install -g mcp-recon          # or rely on `npx -y mcp-recon`
  ```
- Loom set to "Cam + Screen", 1080p, microphone tested
- Close email, Slack, IDE notifications

## Shot list (timings include speaking + screen action)

### 0:00 – 0:20 — The problem (no demo, just camera)

> "AI agents call tools now — files, emails, payments. Prompt injection means anything the model sees can hijack which tools it calls. The standard defense is *more LLM judging more LLM*. I think the durable defense is at the **action layer**: structural constraints on what the agent CAN do. So I built a three-tool stack that does exactly that."

### 0:20 – 0:50 — Three installs, three layers

[screen: terminal, type each line and let it land]

```
pip install capnagent
pip install mcp-guardrails
npx -y mcp-recon --help
```

> "Three repos, three installs, three layers. mcp-recon — what does an MCP server even expose? capnagent — what subset of that authority do I delegate to the agent? mcp-guardrails — what gets denied at runtime even if the model goes rogue?"

### 0:50 – 1:30 — capnagent live

[screen: Python REPL]

```python
import json
from capnagent import Issuer, Verifier, Auditor

seed = b"\x00" * 32
iss = Issuer.from_key(seed)
cap = iss.issue("user-token").caveat(
    'tool == "send_email" AND arg.to starts_with "alice@"'
).build()

ver = Verifier(seed)
auditor = Auditor(b"a"*32)

def ask(args):
    ctx = json.dumps({"caller": "agent-1", "tool": "send_email", "args": args})
    return json.loads(ver.verify_with_context(cap, ctx, auditor))["outcome"]["kind"]

print(ask({"to": "alice@example.com"}))   # -> "allowed"
print(ask({"to": "bob@example.com"}))     # -> "denied"
```

> "capnagent mints a capability token bounded by a tiny DSL. Here the only allowed action is sending email to example.com addresses. The verifier evaluates that bound against every call. Hijack the model all you want — the verifier doesn't care."

### 1:30 – 2:00 — The A.1 finding

[screen: side-by-side — caveat DSL `arg.amount <= 50` and a Python eval showing what an attacker tried]

> "A.1 was a HIGH-severity finding I found in my own engine: `arg.amount <= 50` was admitting `amount = 50.00000000000001` because of f64 sub-ulp behavior. Closed end-to-end in v0.6 — the engine now tracks the source-text shape of every numeric value across Rust, WebAssembly, and Python and refuses to compare an integer-syntactic caveat literal against a float-syntactic argument. Reproduced in 449 tests across three languages, all green."

### 2:00 – 2:30 — mcp-guardrails live

[screen: Python REPL]

```python
import mcp_guard

p = mcp_guard.synthesize_default_policy()
print(len(p.rules), "rules across 9 attack classes")

# capnagent let this through — recipient matches "alice@".
# But the body looks like exfil. mcp-guardrails fires at runtime.
ctx = {"user": {"contacts": ["alice@example.com"]}}
decision = mcp_guard.evaluate(p, "send_email", {
    "to": "alice@example.com",
    "body": "Here's the value: API_KEY=sk-prod-..."
}, ctx)
print(decision.allowed, decision.denying_rule_id)
# -> False  tool-policy-pii-exfil--send_email--body--default
```

> "This is the runtime-policy layer. 122 deterministic rules across 9 attack classes — SSRF, indirect injection, PII exfil. TPR 1.00, FPR 0.01 on a 304-case backtest. Even if capnagent says yes, this fires on the actual call. The two layers catch different things by design."

### 2:30 – 3:00 — Close, the ask

[screen: github.com/euanmcrosson-dotcom/capnagent — README top]

> "All three are live, Apache-2.0 or MIT, 449 tests across three languages, zero runtime deps in the core. What I'm asking: if you run an agent platform in production and would let me wire capnagent in front of one of your MCP tool surfaces for an adversarial Round 11 writeup — partner brief is linked in the repo. Free, three weeks, both names on the writeup. Thanks for watching."

---

## After recording

- Trim the head/tail in Loom (1-2 sec each)
- Thumbnail: the three-layer ASCII diagram from the README (screenshot it large)
- Title: **"Capnagent — three-layer agent security in 3 min"**
- Description (Loom):
  > Capability tokens (capnagent), deterministic runtime policy (mcp-guardrails), MCP server reconnaissance (mcp-recon). One install each. All three on PyPI / npm as of 2026-05-15.
  >
  > Repos:
  > - github.com/euanmcrosson-dotcom/capnagent
  > - github.com/euanmcrosson-dotcom/mcp-guard
  > - github.com/euanmcrosson-dotcom/mcp-recon
- Embed the Loom URL as the **first comment on the Show HN thread**, not in the body — HN strips video. Pinned in your account's comment list.

## Optional alts

- **45-second version** for Twitter/LinkedIn: cut sections 1:30-2:00 (skip A.1) and 2:30-3:00 (skip ask). Three installs + capnagent + mcp-guardrails. Same close: "all three live, look at the repo."
- **6-minute deep cut** for security-team audiences: same script, add a section at 3:00 showing the angles methodology (`cargo test --test angles` output) and the 10-round purple-team corpus structure. Use this for podcasts / lab demos, not for HN.

## Failure-mode plan

If you fluff a line: don't re-record. Edit in Loom, or just leave it — the rough takes feel authentic. Worst is "perfect-sounding pitch person" — viewers tune out. The whole point of the format is "engineer demos own work."
