# Related work — what capnagent is built on

This document situates capnagent in the academic and industry
literature. The goal is to make it obvious that the work is built
*on* the field rather than parallel to it — a senior reviewer
should be able to skim this in 5 minutes and identify the load-
bearing references.

Citations follow author-year inline so you can spot what's read
without chasing footnotes.

## The capabilities lineage

capnagent's authorization model descends from the *capabilities*
tradition, distinct from access-control-list (ACL) systems. The
key references:

- **Dennis & Van Horn, 1966.** *Programming Semantics for
  Multiprogrammed Computations.* CACM. The original definition of
  a capability as an unforgeable token granting a specific
  authority. Establishes the principle "authority travels with the
  reference, not with the principal" — which is exactly the move
  capnagent makes for AI agents.
- **Saltzer & Schroeder, 1975.** *The Protection of Information
  in Computer Systems.* IEEE. The "principle of least privilege"
  this entire field operates under. capnagent's attenuation
  primitive (any holder can narrow, no holder can broaden) is
  least-privilege made cryptographically enforceable.
- **Lampson, 1974.** *Protection.* The foundational treatment of
  the **confused deputy** problem. capnagent's thesis sentence
  ("prompt injection is a confused-deputy attack") is a direct
  citation. The model has the agent's authority but does not
  control which call to make under it; capability bounding is the
  textbook resolution.
- **Levy, 1984.** *Capability-Based Computer Systems.* The
  monograph treatment of capability OS design (CAP, KeyKOS, EROS).
  Read for the operational vocabulary — "amplification",
  "attenuation", "delegation" — that capnagent re-uses in an
  AI-agent context.

## Macaroons — the wire format

capnagent's wire form is **macaroon-style**:

- **Birgisson et al., 2014.** *Macaroons: Cookies with Contextual
  Caveats for Decentralized Authorization in the Cloud.* NDSS
  2014. The reference design we cite directly in
  [`crates/capnagent-core/src/capability.rs`](../crates/capnagent-core/src/capability.rs).
  Specifically: HMAC chain over identifier + caveats; cannot-broaden
  invariant from the chain's one-way property; third-party caveats
  for delegation. capnagent v0 implements first-party caveats; v0.1
  added boolean composition (OR/AND/parens) which is local to our
  spec, not Birgisson's.

The major divergence from Birgisson: capnagent layers
**holder-of-key** (DPoP-style proof of possession) on top of the
macaroon chain, which Birgisson does not. See next section.

## Proof of possession — DPoP

capnagent's hok layer is modeled on:

- **RFC 9449 (Fett et al., 2023).** *OAuth 2.0 Demonstrating
  Proof of Possession (DPoP).* Establishes the pattern: bind a
  token to a public key; require every use of the token to carry a
  signature over a per-call challenge made with the corresponding
  private key. capnagent's `holder_of_key` field follows this
  pattern with an ed25519 keypair. The challenge derivation
  (`pop_challenge_for`) is documented at the Rust API surface; see
  [`crates/capnagent-core/src/verifier.rs`](../crates/capnagent-core/src/verifier.rs).

The translation from web auth to AI agents: in DPoP, the bearer
token + private key + per-request signature defends against
stolen-token replay. In capnagent the same shape defends against
stolen-capability replay during agent execution. The threat model
is different (an in-process agent vs. a web client), but the
crypto primitive is identical.

## Prompt injection — the attack literature

The attack class capnagent exists to neutralize:

- **Greshake et al., 2023.** *Not what you've signed up for:
  Compromising Real-World LLM-Integrated Applications with
  Indirect Prompt Injection.* The foundational paper. Round 01 of
  the corpus is a structurally-tested instance of this class
  against an MCP filesystem server.
- **Liu et al., 2024.** *Prompt Injection attack against
  LLM-integrated Applications.* USENIX Security 2024. Empirical
  characterization of injection across multiple LLM-integrated
  apps. The corpus's round-by-round measurement style is informed
  by their reproducibility standards.
- **Invariant Labs, April 2025.** *MCP tool-poisoning attacks.*
  The specific attack class round 01 reproduces — a malicious MCP
  server's tool description hijacks a co-installed server's
  authority. Our defense is structural (the gate denies regardless
  of how the call got emitted); their analysis demonstrates why
  detection-based defenses are fragile.

For multi-turn / multi-modal extensions to the attack literature
(Crescendo, many-shot, image-based injection), see
[`COMPARISON.md`](COMPARISON.md) — those attack classes are
explicitly outside capnagent's defense layer because they target
model behavior, not tool authorization.

## The MITRE ATLAS / OWASP LLM frameworks

- **MITRE ATLAS (2024+).** Adversarial Threat Landscape for AI
  Systems. ATLAS is the AI extension of MITRE ATT&CK. Round-by-
  round technique mapping is in [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md).
- **OWASP LLM Top 10 (2025).** The community-curated list of
  LLM application vulnerabilities. capnagent addresses LLM01
  (Prompt Injection — exfil-side), LLM02 (Sensitive Information
  Disclosure), LLM06 (Excessive Agency — primary), LLM07 (System
  Prompt Leakage — bounded surface). Mapping in
  [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md).
- **NIST AI RMF 1.0 (2023).** AI Risk Management Framework.
  capnagent contributes to MEASURE and MANAGE functions; see
  [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md) for the
  function-level mapping.

## The policy-engine alternatives

capnagent is *adjacent to* but *distinct from*:

- **Open Policy Agent (OPA) / Rego.** General-purpose policy as
  code. OPA evaluates external policy against a request; capnagent
  evaluates caveats *embedded in a token* against verifier-controlled
  context. The two compose: an operator can use OPA at a higher
  layer (organizational policy) and capnagent at the
  per-agent-action layer.
- **AWS Cedar.** Amazon's policy language. Same shape as OPA —
  external policy, runtime evaluation. capnagent's caveats are a
  *much* smaller language (one page of BNF) intentionally, so the
  authorization decision is auditable in seconds.
- **AWS IAM / GCP IAM.** Cloud capability systems with a
  delegation model that influenced our terminology
  ("attenuation", "delegation"). IAM is principal-based; capnagent
  is bearer-based with hok proof. Different threat models, but the
  attenuation primitive is conceptually the same as IAM's
  permission boundaries.

For the full comparison matrix (capnagent vs. NeMo Guardrails vs.
Lakera Guard vs. Rebuff vs. NVIDIA garak), see
[`COMPARISON.md`](COMPARISON.md).

## The AI-security tooling lineage

- **NVIDIA garak (Derczynski et al., 2023+).** LLM vulnerability
  scanner. Active prior art for "test the model with adversarial
  prompts and measure refusal rates". garak operates at a
  different layer (model-behavior testing) than capnagent
  (tool-authorization testing) — they complement rather than
  compete. A deployment running both gets behavioral + structural
  coverage.
- **Lakera Guard, NeMo Guardrails, Rebuff.** Detection-based
  guardrails. They classify input/output for prompt injection
  signals. capnagent assumes detection has failed and ensures the
  blast radius is bounded. See [`COMPARISON.md`](COMPARISON.md)
  for "what's the right layer for what."

## Empirical methodology

The corpus's "blue-first, falsifiable claim, signed receipt
evidence" methodology draws on:

- **Carlini et al.** general body of work on adversarial-ML
  evaluation rigor. The pre-registration / explicit hypothesis /
  statistical-claim-with-CI norm is what we aim for in any
  measurement we report.
- **Microsoft AI Red Team** *Lessons from Red Teaming 100
  Generative AI Products* (2024). Strong influence on the
  "structural defense > detection" framing — they note that
  detection-based pipelines have systemic weaknesses against
  adaptive attackers.
- **Anthropic's red-teaming methodology.** *Many-shot
  Jailbreaking* (2024) and the broader frontier-red-team work
  pattern: generate, measure, harden, repeat. The corpus's
  iterative "round → BREAKS → fix → CLOSED" cadence is the same
  shape applied to authorization rather than to model behavior.

## What we are NOT claiming

- **Not novel attack classes.** Round 01 is a known attack class
  (Invariant Labs). Round 09 is IDN homography (decades old).
  Round 10 is path traversal (the OWASP Top 10's most boring
  member). The contribution is the *defense methodology* — public,
  reproducible, falsifiable — not the attacks themselves.
- **Not a full GRC product.** Mapping to OWASP / MITRE / NIST in
  [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md) is descriptive,
  not certificatory. A deployer using capnagent for compliance
  needs to verify the mappings independently.
- **Not a model-behavior fix.** capnagent does nothing for
  jailbreaking, system-prompt extraction, multi-turn escalation,
  or any other class where the attacker controls model output.
  Those need guardrails, RLHF, or moderation — see
  [`COMPARISON.md`](COMPARISON.md).

## Reading list — if you have 90 minutes

1. Birgisson 2014 (macaroons) — the wire format. ~30 min.
2. Lampson 1974 (confused deputy) — the threat. ~10 min.
3. RFC 9449 (DPoP) — the proof-of-possession layer. ~20 min.
4. Greshake 2023 (indirect injection) — the attack class. ~15 min.
5. Invariant Labs MCP tool-poisoning, April 2025 — the canary. ~15 min.

After that you have the load-bearing context for everything else
in this repo.
