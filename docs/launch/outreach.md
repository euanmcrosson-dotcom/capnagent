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
wrong one — prompt injection, naive harness, or an over-broad user
request?

I've been building a public purple-team corpus for MCP / agent tool
surfaces — github.com/euanmcrosson-dotcom/capnagent — and just
shipped a recon companion that scans any MCP server's tool
surface in 30 seconds and emits a Markdown threat profile plus
copy-pasteable caveats: github.com/euanmcrosson-dotcom/mcp-recon.

10 capnagent rounds closed (tool-poisoning, hok-replay, IDN
homograph, fs path-traversal, etc), and a parallel-agent
adversarial review of the engine itself surfaced 17 issues, 4
HIGH severity (sub-ulp numeric coercion bypass, empty-attenuation
brick, zero-byte audit key, empty-caveat god-mode). v0.5
closed 3 of 4 HIGH; v0.6 closed A.1 in the Rust engine; v0.6.1
closed the residual JS-layer artefact via verifyWithContextJson —
**4 of 4 HIGH closed end-to-end as of v0.6.1.**

I'm looking to add a round against a real production stack. If your
agent surface is interesting, happy to do the integration + write
the round for free as a Friday-afternoon project — I'll wire the
gate, you keep the receipts, we both find out where the defense
breaks.

No expectation; if it's not a fit just ignore. If it is — what's
your most-feared tool-call?
```

## Template 2 — DM to a security/platform engineer

```
Hi — building a public purple-team harness for MCP / AI-agent tool
surfaces and looking for adversarial review. Methodology is
blue-first: each round writes a falsifiable claim, the red side
constructs an attack to falsify it, the PoC simulates worst-case
(model fully cooperates with injection), and the receipt is the
audit-loggable evidence. 10 rounds closed: tool-poisoning / cross-
server confused deputy, hok-replay, capability broadening, revocation
race, cross-origin exfil, IDN homograph, fs-sandbox path-traversal,
encoding attacks. 6 hold-with-caveat, 4 documented BREAKS with fixes
shipped or queued.

Then we ran 4 parallel agents adversarially against our own engine:
36 angles, 17 findings, 4 HIGH severity defects in our own code —
sub-ulp f64 caveat-bypass, empty-attenuation produces a silent brick
token, zero-byte HMAC key accepted by the auditor, empty-caveat cap
authorizes every context. v0.5 SHIPPED and closes 3 of 4 (A.1
sub-ulp f64 is parked under design discussion). The point is that
defects this severe are findable in a public loop — and the corpus
is what makes the loop legible.

Repo: github.com/euanmcrosson-dotcom/capnagent
Methodology + rounds: docs/purple-team/
Threat model: docs/THREAT_MODEL.md

Engine: macaroon-style HMAC chain, ed25519 holder-of-key (DPoP shape),
NonceStore replay protection, signed revocation list, caveat DSL with
boolean composition. ~17 kHz/core verifications. unsafe_code = forbid;
242 Rust tests including no-broaden proptests, 322 TS tests.

If you have 30 min to read one round + the angles findings and find
one thing I got wrong, I'll send a $50 gift card / whatever. The
strongest review I could get right now is somebody breaking round NN
or designing round 11.
```

## Template 3 — DM to someone running an MCP server

```
Hey — saw your MCP server [NAME]. Question: how do you currently
authorize the agent on the other end? Most MCP servers trust whoever
connects, with whatever scopes the parent app configured at install
time. The Invariant Labs tool-poisoning research from 2024 showed
how badly that fails when one of the co-installed servers turns
malicious.

Built a public purple-team harness for this exact surface: each
round documents a defense being tested against an attack scenario,
with runnable PoCs and signed denial receipts as evidence. 10 rounds
closed including the tool-poisoning case against the official
@modelcontextprotocol/server-filesystem, plus a parallel-agent
adversarial review of our own engine that surfaced 4 HIGH severity
defects (v0.5 shipped: 3 of 4 closed; A.1 sub-ulp f64 under design
discussion). Repo:
github.com/euanmcrosson-dotcom/capnagent.

Worth a 15-min call if you've thought about this surface? I'd
specifically value "here's the attack against my server you should
add as round NN" feedback.
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

## First-5 shortlist — a 90-minute workflow

The single most expensive mistake at this stage is "research five
perfect targets" turning into "research forever, send zero DMs."
Time-box the shortlisting so the DMs actually go out.

### Step 1 (20 min) — five archetypes, one target each

Pick ONE concrete person per slot. Don't optimize. The criterion is
"plausibly cares about agent tool-call security" + "reachable in
≤2 clicks." Open a scratch doc and fill these in:

| # | Archetype                                  | Search prompt                                               | Pick      |
|---|--------------------------------------------|-------------------------------------------------------------|-----------|
| 1 | **MCP-server maintainer** (active OSS)      | github.com search: `mcp` topic, sort by recently updated, ≥50 stars | name + repo |
| 2 | **Coding-agent product** founder/eng-lead   | LinkedIn: `coding agent` OR `AI engineer` + "founder" / "head of eng" + company size ≤50 | name + LinkedIn URL |
| 3 | **AI customer-support / refund-action** team | Twitter/X: `agent` + (`refund` OR `cancel` OR `account action`) recent | name + handle |
| 4 | **Agent-security researcher** (academic or industry) | Google Scholar / X: `prompt injection` + `tool use` 2025–2026 | name + paper or post |
| 5 | **Browser-automation agent** founder         | Hacker News Show HN archive + GitHub: `browser agent` recent | name + repo / post |

The five together cover the surface area: maintainer, product
builder, customer-action operator, researcher, browser-automation.
A reply from any one of them is a successful first wave.

### Step 2 (40 min) — per-target one-line context

Open each target's most-recent public post (commit / blog / tweet).
Write ONE concrete sentence about it. This sentence goes into the
`[SPECIFIC THING about their product]` slot in the DM. No sentence,
no DM — generic openers get deleted.

  > "Saw you shipped streaming-tool-call support last week — caught the
  >  edge case where Anthropic's tool_use blocks fragment across SSE chunks."

If you can't write that sentence in 60 seconds, the target is not
warm enough; skip and pick another from the same archetype row.

### Step 3 (30 min) — five DMs out

Use Template 1 (founder/eng-lead) for slots 2/3/5. Template 2
(security engineer) for slot 4. Template 3 (MCP-server maintainer)
for slot 1. Send. Don't tweak the body beyond:

- the `[SPECIFIC THING]` opener (from Step 2)
- the closing question (their most-feared tool call, the round NN
  you'd add against their stack, what they'd want to see in a
  receipt schema, etc.)

### Step 4 (after sending) — wait, don't poll

Track responses in a plain text file: `docs/launch/dm-log.txt` is
fine. Two out of five replies is a good rate. Most won't. The point
of wave one is calibration — the *questions* you get back tell you
what's missing from the README / DESIGN / THREAT_MODEL more
reliably than another self-review.

If wave one returns zero replies after 7 days, the bottleneck is
positioning, not effort — revisit the elevator pitch, not the DM
volume.

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
