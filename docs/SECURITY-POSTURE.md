# Security posture — what capnagent defends against

This document maps capnagent's defenses to the three frameworks a
senior security reviewer expects to see referenced: **OWASP LLM Top
10 (2025)**, **MITRE ATLAS** (Adversarial Threat Landscape for AI
Systems), and the **NIST AI Risk Management Framework (AI RMF
1.0)**. Every claim points at a corpus round, a test file, or a
section of [`DESIGN.md`](DESIGN.md) so a reviewer can verify
without trusting prose.

> **Position statement.** capnagent is *not* a guardrail. It is a
> capability-bounded authorization layer — closer in spirit to AWS
> IAM, OPA, or Cedar than to NeMo Guardrails or Lakera Guard. It
> does not detect prompt injection. It removes the agent's ambient
> authority so injection success has no exfil path. See
> [`COMPARISON.md`](COMPARISON.md) for where we sit relative to
> guardrails / detectors / policy engines.

## Quick reference table

| Framework | Items capnagent addresses | Items explicitly out of scope |
|---|---|---|
| OWASP LLM Top 10 (2025) | LLM01 (Prompt Injection — exfil-side), LLM02 (Sensitive Information Disclosure — via attenuation), LLM06 (Excessive Agency — primary), LLM07 (System Prompt Leakage — bounded surface), LLM08 (Vector and Embedding Weaknesses — N/A but bounded) | LLM03 (Supply Chain — the engine itself; covered by `deny.toml`), LLM04 (Data and Model Poisoning — model-internal), LLM05 (Improper Output Handling — caller responsibility), LLM09 (Misinformation — model-internal), LLM10 (Unbounded Consumption — caller's rate-limit problem) |
| MITRE ATLAS | T0051 (LLM Prompt Injection — neutralized), T0044 (Full ML Model Access via tool surface — bounded), T0049 (Exploit Public-Facing Application — denied at gate), TA0040 (Impact via tool calls — bounded) | T0040 (ML Supply Chain Compromise), T0061 (LLM Model Replication), T0005 (Adversarial ML Theft) |
| NIST AI RMF 1.0 | MEASURE 2.6 (Computational efficiency), MEASURE 2.7 (AI system security), MEASURE 2.10 (Privacy), MAP 5.1 (Likelihood/impact characterization), MANAGE 4.1 (Documented post-deployment monitoring — receipts) | GOVERN (organizational policy — out of tool scope), most of MAP (context characterization is the deployer's job) |

The remainder of this document expands each row.

---

## OWASP LLM Top 10 — round-by-round mapping

### LLM01 — Prompt Injection
The biggest item on the list. capnagent's posture is **structural**,
not detection-based. We assume the model has been fully compromised
by the injection and emits exactly the calls the attacker described;
the verifier denies whatever the issued capability does not
authorize.

| LLM01 sub-class | Round | Status | File |
|---|---|---|---|
| Direct injection (system prompt override) | — | Out of scope (model behavior) | — |
| Indirect injection (tool-description) | 01 | holds-with-caveat | [`tool-poisoning.purple.test.ts`](../examples/mcp-fs-agent/src/__tests__/tool-poisoning.purple.test.ts) |
| Cross-server confused deputy | 01 | holds-with-caveat | as above |
| Capability broadening / tampering | 03 | holds-with-caveat | [`capability-broadening.purple.test.ts`](../packages/capnagent/src/__tests__/capability-broadening.purple.test.ts) |
| Cross-origin exfil | 05 | holds-with-caveat | [`cross-origin-exfil.purple.test.ts`](../examples/mcp-http-agent/src/__tests__/cross-origin-exfil.purple.test.ts) |
| IDN homograph in allowlist | 09 | BREAKS → CLOSED v0.5 | [`idn-homograph-origin.purple.test.ts`](../examples/mcp-http-agent/src/__tests__/idn-homograph-origin.purple.test.ts) |

**Specifically NOT defended against** (model-internal, separate layer):
GCG suffix attacks, Crescendo-style multi-turn jailbreaks, role-play
exploits, system-prompt extraction. These are guardrail / RLHF /
moderation problems, not capability problems. See
[`COMPARISON.md`](COMPARISON.md) §"What capnagent is NOT for".

### LLM02 — Sensitive Information Disclosure
Bounded via attenuation. A token issued for `tool == "read_file"
AND arg.path starts_with "/sandbox/"` cannot cause disclosure of
files outside `/sandbox/`, regardless of what the model is induced
to say.

- Round 01: tool-poisoning attempt to read `~/.ssh/id_rsa` — denied
  at gate, never reaches filesystem. PoC is deterministic.
- Round 07/10: substring foot-gun + path traversal — both BREAKS
  shipped CLOSED in v0.5 via `starts_with` operator + path
  canonicalization.

### LLM06 — Excessive Agency
**Primary use case.** The macaroon-style attenuation chain (cannot
broaden without root key, see [`property_tests.rs`](../crates/capnagent-core/tests/property_tests.rs))
is the structural answer to excessive agency. A holder can narrow
their cap before delegating to a subagent; the subagent
cryptographically cannot reverse the narrowing. See
[`DESIGN.md` §5](DESIGN.md) leg 1 for the formal statement.

### LLM07 — System Prompt Leakage
capnagent does not read or modify system prompts. The defense is
that *what the model knows* is not part of the security argument —
the verifier authorizes calls based on facts it controls (issued
capability, runtime context), not on the agent's reasoning. So
system-prompt leakage does not unlock attacker capabilities through
this layer.

---

## MITRE ATLAS technique mapping

ATLAS is the AI-specific extension of MITRE ATT&CK. Every closed
round is tagged with its primary ATLAS technique:

| Round | ATLAS Technique | Tactic |
|---|---|---|
| 01 | T0051 (LLM Prompt Injection — Indirect) | TA0043 (Initial Access) |
| 02 | T0049 (Exploit Public-Facing Application) | TA0001 (Initial Access — replay) |
| 03 | T0030 (Erode ML Model Integrity — capability tampering) | TA0040 (Impact) |
| 04 | T0049 + T0024 (Failure Mode-aware authorization race) | TA0040 |
| 05 | T0048 (External Harms — Financial / Reputational via cross-origin) | TA0040 |
| 06 | T0024 (Validate-then-use bypass) | TA0007 (Discovery) |
| 07 | T0049 (Substring authorization bypass) | TA0001 |
| 08 | T0024 (Replay protection install bypass) | TA0007 |
| 09 | T0049 (IDN homograph in allowlist) | TA0001 |
| 10 | T0049 (Encoding-based authorization bypass) | TA0001 |

The corpus is intentionally biased toward TA0001 (Initial Access)
and TA0040 (Impact) — the two ATLAS tactics where capability
bounding has structural leverage. We do not address TA0006
(Credential Access on the host), TA0008 (Lateral Movement at the
infra layer), or TA0009 (Collection at the data layer); those
belong to the surrounding security architecture.

---

## NIST AI RMF 1.0 — function-level mapping

The AI RMF organizes controls into four functions:
**GOVERN / MAP / MEASURE / MANAGE**. capnagent contributes
primarily to MEASURE and MANAGE, with documentation contributing
to MAP.

### MEASURE
- **MEASURE 2.6 (Computational efficiency)** — criterion benches
  in [`crates/capnagent-core/benches/verify_pipeline.rs`](../crates/capnagent-core/benches/verify_pipeline.rs).
  1.4 µs chain-only / 11 µs bearer / 56 µs hok / 170 µs
  hok+replay. Re-runnable with `cargo bench`.
- **MEASURE 2.7 (AI system security and resilience)** — the
  purple-team corpus is the primary artifact. 10 rounds closed,
  17 angles findings, 4 HIGH self-found, 3 of 4 closed in v0.5.
  Re-runnable per round (see [`EVALUATION.md`](EVALUATION.md)).
- **MEASURE 2.10 (Privacy)** — receipts hash arguments rather than
  storing them ([`audit.rs::ContextSummary`](../crates/capnagent-core/src/audit.rs)),
  so audit logs can be shared without leaking call payloads.

### MANAGE
- **MANAGE 4.1 (Post-deployment monitoring)** — every authorization
  decision (allow OR deny) produces a signed [`Receipt`](../crates/capnagent-core/src/audit.rs)
  containing the capability identifier, caveats, context summary,
  outcome, and HMAC-SHA256 signature. Auditors can verify receipts
  asynchronously without the verifier's signing key being online.

### MAP
- **MAP 5.1 (Likelihood/impact characterization)** — [`THREAT_MODEL.md`](THREAT_MODEL.md)
  enumerates in-scope vs. out-of-scope attack classes with
  rationale + right-defense-layer pointer for every out-of-scope
  item.

### GOVERN — explicitly NOT in scope
GOVERN is organizational (policy, accountability, role
definitions). capnagent is a tool, not a governance regime. A
deployer's GOVERN responsibilities — who issues capabilities, who
audits receipts, who responds to denials — are outside the engine.

---

## What this document does not claim

- **Not a certification.** OWASP / MITRE / NIST mappings here are
  authored by the project, not by the framework owners. Claims
  should be re-verified by any operator using capnagent for
  compliance-driven deployment.
- **Not exhaustive.** We mapped the load-bearing items. A formal
  GRC analysis would be deeper (e.g., AI RMF "Subcategories" rather
  than "Categories").
- **Pre-1.0.** Engine surface may change incrementally before
  v1.0; see [`ROADMAP.md`](ROADMAP.md). Mappings will be re-checked
  at each minor release.

---

## How to extend this document

When you add a new round:

1. Add the row to the OWASP table above with the right LLMxx slot.
2. Add the row to the MITRE ATLAS table with the right TXXX / TAXXX.
3. If the round produces a new measurement artifact (latency,
   denial rate, etc.), reference it under MEASURE 2.7.
4. Update [`THREAT_MODEL.md`](THREAT_MODEL.md) for in/out-of-scope.

Cross-references stay consistent with [`RELATED-WORK.md`](RELATED-WORK.md)
(academic / industry literature) and [`COMPARISON.md`](COMPARISON.md)
(positioning vs. alternative tools).
