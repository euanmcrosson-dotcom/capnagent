# How capnagent compares to alternative tools

A senior reviewer's first question is "but isn't this just X?" This
document answers it for the X's that get asked about. The honest
take: capnagent occupies a layer most existing tools don't, and
where there is overlap we explicitly recommend stacking rather than
substituting.

> **One-line positioning.** capnagent is a *capability-bounded
> authorization layer* for AI agent tool calls. Adjacent: detection
> (Lakera, Rebuff), generation-time policy (NeMo Guardrails),
> general policy engines (OPA, Cedar), behavior testing (NVIDIA
> garak). Each addresses a different security layer; the strongest
> deployments use multiple.

## The category landscape

```
                 ┌─────────────────────────────────────────────────────┐
                 │                AI security stack layers             │
                 ├─────────────────────────────────────────────────────┤
LAYER 1          │  Model alignment (RLHF, Constitutional AI)         │
                 │     ↑                                                │
LAYER 2          │  Generation-time guardrails (NeMo, Lakera, Rebuff) │
                 │     ↑                                                │
LAYER 3          │  Tool-authorization layer ← capnagent              │
                 │     ↑                                                │
LAYER 4          │  Organizational policy (OPA, Cedar, IAM)           │
                 │     ↑                                                │
LAYER 5          │  Application-level RBAC / audit                    │
                 └─────────────────────────────────────────────────────┘
```

capnagent does not compete with any layer above or below it. It
fills a layer most stacks today leave empty: between "the model
might do anything" (layer 2's failure mode) and "the org policy
allows broad action" (layer 4's blast radius).

## The matrix

| Tool | Category | What it does | What capnagent adds | Stack order |
|---|---|---|---|---|
| **NeMo Guardrails** (NVIDIA) | Generation-time guardrails | Rails for LLM output: refusal injection, response shaping, topical bounds. Detection-based. | Capability bounds the **action** the model can request, regardless of what passes the rails. | Stack ABOVE capnagent |
| **Lakera Guard** | Prompt-injection detection | Classifier-based detection of malicious inputs. Returns "safe / unsafe" verdicts. | Removes the agent's authority so detection failure has no exfil path. | Stack ABOVE capnagent |
| **Rebuff** | Prompt-injection detection | Heuristic + LLM-based detection of injection attempts. | Same as above — detection-based. | Stack ABOVE capnagent |
| **NVIDIA garak** | Vulnerability scanner | Tests *the model* with adversarial prompts; reports refusal rate per probe family. | Tests *the gate*, not the model. Different layer; complementary measurement. | Run BOTH in CI |
| **OpenAI moderation API** | Content classifier | Classifies output for harassment / violence / etc. | Doesn't bound tool authority. capnagent does. | Stack ABOVE capnagent |
| **Open Policy Agent (OPA) / Rego** | General policy engine | Evaluates external policy against request context. | OPA is principal-based + heavy; capnagent is bearer-based with attenuation. Compose: OPA at org layer, capnagent at agent layer. | Stack BELOW capnagent (org policy) |
| **AWS Cedar** | Policy language | Like OPA. External evaluator, structured policy language. | Same comment as OPA. | Stack BELOW capnagent |
| **AWS IAM / GCP IAM** | Cloud auth | Principal-based capability system for cloud resources. Excellent attenuation primitives (permission boundaries, session policies). | IAM is principal-based; capnagent is bearer-based and operates inside the agent's runtime. The two layer cleanly. | Stack BELOW capnagent |
| **JWT scopes (RFC 8693, etc.)** | Token format | Static `scope` claim listed in the token. | Capabilities *attenuate*; JWT scopes don't. Scopes are a label; caveats are a small program the verifier runs. | Replace JWTs at the agent boundary |
| **MCP server allowlists** (per-server tool config) | Application config | Each MCP server has its own allowlist for what tools it exposes. | Static config doesn't compose across servers (the cross-server confused-deputy problem of round 01). capnagent gives the **client** a structural defense against malicious or mis-configured *servers*. | Use BOTH |
| **[mcp-recon](https://github.com/euanmcrosson-dotcom/mcp-recon)** | MCP reconnaissance CLI | Enumerates an MCP server's tool surface, fuzzes schemas along six adversarial axes, classifies authority against OWASP LLM Top 10 + MITRE ATLAS. As of [v0.2.0](https://github.com/euanmcrosson-dotcom/mcp-recon/releases/tag/v0.2.0) emits a structured `mcp-recon/v0.1/caveats` JSON artifact of capnagent-ready issuance plans. | Recon answers "what authority does this server's tool surface expose?"; capnagent answers "and what subset of that authority do we authorize the agent to use?" | Run mcp-recon FIRST, feed `caveats.json` into capnagent issuance |

## Specifically: vs. detection-based guardrails

The most common confusion: "isn't this just another guardrail?"

It is not.

- **Detection-based guardrails** classify input/output. They have a
  precision/recall tradeoff — false negatives let attacks through,
  false positives kill UX. The state of the art has been converging
  near 90-95% recall on the test sets, which sounds great until you
  notice that a **5% recall miss times a $100k action surface
  equals a $5k expected loss per pull of the lever**.
- **Capability bounding** is structural. The cap defines what the
  agent CAN do. If the model is fully compromised by the most
  sophisticated injection ever crafted, and emits exactly the calls
  the attacker asked for, the verifier still denies anything not
  authorized by the capability. There is no precision/recall
  tradeoff — there's a static set of permitted actions.

This is why we say "**we assume the model has been fully
compromised by the injection.**" That's the worst case the
capability layer is designed for. Detection-based layers above
capnagent reduce the *frequency* of this assumption being true; the
capability layer ensures *blast radius* when it is.

The right deployment posture is **stack both**, not choose one.

## Specifically: vs. NVIDIA garak

garak is a vulnerability scanner that probes the model's
behavior. capnagent is an authorization layer at the tool boundary.

| | garak | capnagent |
|---|---|---|
| What it tests | Model output (refusal rates, jailbreak success) | Tool-call authorization decisions |
| What it produces | Per-probe pass/fail, batch report | Per-call signed receipt |
| Failure mode | Substring-detector false positives (we filed [a PR critique](TODO) on this — see your other AI-security work) | Capability semantics make false positive impossible at the gate (allow / deny is structural) |
| Run cadence | Periodic CI scan | Every tool call in production |
| Right time to run | Pre-deployment | Continuous |

You should run both. If your CI is ever flaky on the garak side, capnagent's coverage is unaffected — it sits at a different layer.

## Specifically: vs. JWT scopes

A surprisingly common pushback: "isn't this just a fancy JWT?"

Concretely:

| | JWT scope | capnagent capability |
|---|---|---|
| Scope syntax | `scope: "read:files write:emails"` | DSL: `tool == "read_file" AND arg.path starts_with "/sandbox/"` |
| Attenuation | Re-issue with smaller scope (requires the issuer) | Any holder can attenuate locally — no issuer roundtrip |
| Holder-of-key proof | DPoP add-on (RFC 9449) | Built in (`holder_of_key` field, ed25519) |
| Audit log | External | Built in (signed receipts) |
| Revocation | External denylist | Signed `RevocationList` with freshness window |
| Fine-grained per-arg constraint | Scope claims are flat strings | `arg.amount <= 50` evaluates against the actual call |

The functional difference: a JWT scope is a *static label* the
checker compares. A capnagent caveat is a *small program* the
verifier evaluates against verifier-controlled context. That's
what makes "amount under $50 to a specific merchant before a
specific date" expressible in a single token.

## Specifically: vs. OPA / Cedar

OPA and Cedar are heavyweight policy engines. capnagent is a
purpose-narrow authorization primitive. They compose well:

```
Org policy (OPA)
  ↓ "this user CAN issue capabilities for tool X"
capnagent (issuance)
  ↓ "this capability bounds action to {tool, args, context}"
capnagent (verification)
  ↓ "this specific call is authorized by this specific cap"
Underlying tool
```

OPA evaluates external policy at issue time (or at every request
if you prefer). capnagent's caveats run at verify time, embedded in
the token. They serve different points in the request lifecycle.

## What capnagent is NOT for

This list saves you a comment thread:

- **Jailbreaking / system-prompt extraction.** Model behavior, not
  authorization. Use guardrails / RLHF / red-teaming.
- **Multi-turn jailbreaks (Crescendo, many-shot, etc.).** Model
  behavior. Same advice.
- **Image-based prompt injection.** If the model emits a tool call,
  the cap denies or admits regardless of *why* the model emitted
  it. So the attack surface this attacks (the model's reasoning
  layer) is upstream of capnagent. Don't confuse this with "image
  injection has no consequences" — it does, *but* its consequences
  reach the world through tool calls, and capnagent bounds those.
- **Unbounded LLM reasoning.** If your agent does damage by
  thinking and not acting (e.g., generating misleading text and
  showing it to a human), no authorization layer helps. The
  authorization layer is for actions that touch the world via
  tools.
- **DDoS / availability.** Use rate limits at the right layer.
- **Supply-chain attacks on the engine itself.** Use SBOM tools,
  `cargo-deny` (we ship `deny.toml`), `cargo-audit`,
  `npm audit`, etc.

## When you might NOT want capnagent

Be honest: capnagent is overkill if:

- Your agent has **only one tool** with a fixed surface and no
  delegation. A static allowlist on that tool is enough.
- Your agent's worst case is **bounded already** by the
  surrounding application (e.g., it can only read public
  information). The exfil channel is already closed by another
  layer.
- You **need < 1 µs verify latency**. capnagent's 1.4 µs chain
  check is already at the noise floor of memory access; if you're
  in a domain where that matters, you're in HFT, not agents.
- You have **no concept of operator policy** — the deployment is
  one user, one agent, one machine. The capability layer has
  little to add over function-level access.

The strongest case for capnagent: an agent with **multiple tools**,
**delegation across subagents**, and a **scope larger than the
current task**. That's where capability bounding earns its weight.
