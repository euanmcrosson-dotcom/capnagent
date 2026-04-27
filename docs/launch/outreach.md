# Cold-DM templates for finding the first user

The premise: capnagent works, but it has zero deployments. The
fastest way to get adversarial feedback AND validate the threat
model is to wire it into ONE real agent product, for free, with the
team that's building it.

## Who to target

Look for teams that:

1. Are shipping an agentic product to production (not just a demo).
2. Have agents calling **risky tools** — code execution, file ops,
   payments, send-message-to-X, browser automation, database writes.
3. Are small enough that a DM reaches a human (5–50 person teams).
4. Have a public Slack / Discord / GitHub presence so you can be
   visible and reachable.

Concrete categories where capability bounding has obvious fit:

- AI customer-support tools that take actions on user accounts (refunds,
  password resets, data exports).
- Coding-agent products with shell + filesystem access.
- AI-trading bots with order-placement scopes.
- Browser-automation agents (Playwright + LLM) doing real workflows.
- AI ops tools that run terraform / kubectl / similar.

## Template 1 — DM to a founder/eng-lead

```
Hey — saw [SPECIFIC THING about their product, written like you've
actually used it]. Quick question about your tool-use surface: when
your agent picks up a tool call, what stops it from picking the
wrong one — prompt injection, naive harness, or just an over-broad
user request?

I've been working on a capability-bounding library for exactly this:
the agent holds a token that says what it CAN do (e.g. "GET to
api.example.com only, no POST anywhere"), and the library refuses
out-of-scope calls before the underlying tool sees them. Every
decision is a signed audit log line. Repo:
github.com/euanmcrosson-dotcom/capnagent.

I'm trying to get one real production wiring in front of adversarial
eyes. If your stack is interesting, happy to do the integration for
free as a Friday-afternoon project — I'll write the wrapper, you
keep the audit logs, we both find out where the model breaks.

No expectation; if it's not a fit just ignore. If it is — what's
your most-feared tool-call?
```

## Template 2 — DM to a security/platform engineer

```
Hi — building capability tokens for AI-agent tool calls (Rust
library, WASM/TS bindings, MCP adapter) and looking for security
review from people who've shipped real auth surfaces. Specifically
the threat model is in DESIGN.md §2/§5; the no-broaden invariant
has 9 proptest cases; boolean DSL composition has 8 algebraic-law
proptests. Repo: github.com/euanmcrosson-dotcom/capnagent.

The 5 gates are chain integrity (HMAC), ed25519 holder-of-key (DPoP
shape), replay (sha256(proof) → nonce store), signed revocation
list, and caveat evaluation against a verifier-controlled context.
~17 kHz/core verifications.

If you have 30 min to read DESIGN.md and find one thing I got wrong,
I'll buy you a beer / send a $50 gift card / whatever you want.
Adversarial review is the part I can't do solo.
```

## Template 3 — DM to someone running an MCP server

```
Hey — saw your MCP server [NAME]. Question: how do you currently
authorize the agent on the other end? My read is most MCP servers
trust whoever connects, with whatever scopes the parent app
configured at install time.

Built a library that drops in front of the official @modelcontextprotocol
TS SDK and gates each tools/call against a capability token — agent
can do reads in /home/user/projects, can't write anywhere, can't
execute. Server stays trusting; the gate is the hardening layer.
Live integration test against the official server-filesystem in the
repo. github.com/euanmcrosson-dotcom/capnagent.

Worth a 15-min call if you've thought about this surface? I'm
specifically looking for "yeah, but here's the case you missed"
feedback.
```

## How to actually find these people

- GitHub: search topics `mcp`, `agent`, `llm-agent`, `tool-use`. Filter
  to repos with 100+ stars active in the last 90 days. The maintainers
  are the targets.
- LinkedIn: "AI agent" / "MCP" / "agentic" in title, founder/CTO/staff-
  eng level, company size <100. Search the company's blog for an
  engineer who wrote about their tool-use surface.
- Discords: anthropic-discord, openai-developers, langchain, mcp
  (https://discord.gg/modelcontextprotocol). Lurk for a week, read
  who answers technical questions credibly, DM those people.
- X/Twitter: search "agent tool call" / "prompt injection production"
  / "capability security" — the people quoting Lampson 1974 in 2026
  are your audience.

## Cadence

- Send 5 DMs/week. More than that and the response rate craters
  (people smell a templated outreach campaign).
- Track responses in a plain text file. Most won't reply. Two out of
  five replies is a good rate.
- The point of the first wave isn't conversion; it's calibration.
  The questions you get back tell you what's missing from the
  README, the DESIGN doc, and the threat model.

## What success looks like

- One person reads DESIGN.md and finds something substantive: a
  weakness, a missing gate, a confused argument. Either fix it or
  document why it's intentional.
- One team agrees to the free integration. You write the wrapper
  in a Saturday. They report the first real-world bug within a
  month. That bug is worth more than the next 200 unit tests.
- Two of the three above happen → the project has actual gravity.
  None happen after 50 DMs → revisit positioning, not the library.
