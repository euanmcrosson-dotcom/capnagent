# capnagent v0.7 Round 11 — partner brief

One-page reference for prospective partners on what "Round 11
against a real production stack" actually involves. Designed to be
forwarded as-is when somebody asks "what would this cost me?"

## The proposition in one sentence

We wire capnagent in front of one of your agent's tool surfaces in
staging (or production, your call), construct a worst-case
adversarial scenario against it, and co-author the writeup. Both
names on the corpus. We keep the methodology; you keep the receipts.

## What we provide

- **The wiring.** capnagent v0.6.1, with v0.5.1's fs-agent example,
  the MCP adapter, and the JSON-string ctx API for full A.1 closure.
  We adapt it to your tool-call boundary — whether that's MCP, a
  proprietary tool-call shape, LangChain, LlamaIndex, CrewAI, or a
  hand-rolled dispatcher.
- **The attack design.** We pick an attack class from the existing
  10-round corpus (or design a new one specific to your stack) and
  document it blue-first: claim → falsifier → PoC → receipt
  evidence. No real exploitation against your prod data; the PoC
  simulates the worst case under our control.
- **The writeup.** Round 11 goes in `docs/purple-team/11-<partner>.md`
  with the standard shape. We send you the draft before publishing.
  You can redact anything sensitive (specific tool names, business
  context, customer-identifying numbers). The methodology stays
  generic enough to be useful to other defenders without leaking
  your specifics.
- **The fix loop.** If the round surfaces a real engine defect (it
  did in 4 of the first 10), we ship the engine fix in a tagged
  release and credit your team's review. If it surfaces a
  deployment foot-gun, we document it in the round's "operator
  config" section so your platform team has a concrete checklist.

## What we need from you

- **Read-and-write access to ONE staging deployment** with the
  agent calling at least one real (non-mock) tool. Read-only
  is fine if you'd rather observe.
- **A 60-minute video call** to walk the threat model with whoever
  owns the agent. We're listening for: what's the most-feared tool
  call? What's been the closest call so far? What does your existing
  authorization story look like?
- **A second 30-minute call** later in the week to walk the proposed
  round before we run it. Veto on anything that would be
  inappropriate against your stack.
- **A review pass** on the writeup before we merge. You can mark
  it `embargo until <date>` if you want to time the publication
  with a security advisory.

## What it costs you

Roughly:

- **2 calls × 60 min** with whoever owns the agent.
- **~2 hours** of platform-engineering time to give us a staging
  deployment / API key / read-only credentials.
- **~30 minutes** to review the writeup draft.

That's it. No money, no contract — it's a goodwill round.

## What we get

- An external production stack in the corpus, which is the strongest
  single claim we can make ("we red-teamed [partner X]'s agent")
  and the largest credibility multiplier for capnagent adoption.
- One more round of corpus growth, in a methodology that compounds:
  each round forces a documented improvement to the engine or a
  documented residual risk that the next round can attack.

## What you get

- An external review of your agent's tool-call boundary by somebody
  who has spent six months thinking about MCP capability bounding.
- A specific, named threat-model gap if we find one. (We've found
  them in our own engine; we'll find them in yours.)
- A reusable receipt-shape audit pattern if you don't already have
  one. The signed denial receipts are durable evidence that an
  attempted abuse was caught and refused at the gate — useful for
  SOC 2 / ISO 27001 / regulatory conversations.
- A name in the corpus (or a redacted role-only credit, your call).

## Timeline

- **Week 0:** kickoff call, threat-model walk, scope lock.
- **Week 1:** wire capnagent into the staging deployment. Operator
  calls to debug any deployment foot-guns surface as items for
  the writeup's "operator config" section.
- **Week 2:** run the attack PoC, collect receipts, write the
  round. Engine fix (if needed) ships in a tagged patch release.
- **Week 3:** review pass, embargo (if any), publish.

Total: ~3 weeks elapsed, with most of the work concentrated in a
single Saturday afternoon (the round itself).

## Fit signals — who this works for

Strong fit:
- Coding agents with shell or filesystem authority (Cursor / Devin
  / Aider-shape products that ship to real users).
- AI customer-support tools where the agent can take account
  actions (refunds, exports, password resets) on the user's behalf.
- AI-trading bots with order-placement scope, OR rules-engine
  trading where capabilities map cleanly to risk tiers.
- Browser-automation agents (Playwright + LLM) doing real
  workflows for customers.
- MCP-server publishers (Anthropic's own MCP server family, or
  third-party MCP servers — Hashicorp Vault MCP, GitHub MCP,
  Postgres MCP, etc.).

Probably-not fit:
- Pure-chat agents with no tool authority worth bounding.
- Pre-product teams who don't have a stack yet.
- Closed-source teams who can't share even a redacted writeup.

## Decision: yes / no in one DM exchange

If this is interesting: reply with "yes, send the questions."
We send a short list (~5 questions about your stack), you fill
them in, and we have what we need to scope the round. Total time
from yes to scoped: usually 48 hours.

If it's not interesting: just say so. We don't follow up.

## Reference material

- Repo: <https://github.com/euanmcrosson-dotcom/capnagent>
- Methodology: [`docs/purple-team/`](../purple-team/)
- Closed rounds: 10/10
- Engine angles findings: 17/17 documented; 4/4 HIGH closed end-to-end as of v0.6.1
- Companion recon tool: <https://github.com/euanmcrosson-dotcom/mcp-recon>
- Companion runtime-policy tool: <https://github.com/euanmcrosson-dotcom/mcp-guard>
