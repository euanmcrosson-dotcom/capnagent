# capnagent threat model

> capnagent is a public purple-team harness for MCP / AI-agent tool
> surfaces, plus the Rust capability-token engine that powers the
> defense. This document is the canonical reference for **what
> capnagent defends against and what it explicitly does not**.
>
> The corpus in [`purple-team/`](purple-team/) provides the
> evidentiary backing for every in-scope claim. The out-of-scope
> table below tells reviewers, operators, and adversaries which
> threats are someone else's job.

## What capnagent IS

capnagent gates AI-agent **tool calls** by issuing capability tokens
(macaroon-style chain, ed25519 holder-of-key, signed audit receipts)
and refusing tool calls that exceed the issued capability's scope.
The defense is **structural**: it does not depend on the model's
behavior. An agent that has been fully prompt-injected, is running
a DAN persona, or is gradient-attacked by GCG suffixes will still
have its out-of-scope tool calls refused by the gate, because the
gate sees the structured tool call, not the model's reasoning.

The defense is also **conditional**: it works only when the
operator has issued a tightly-scoped capability and configured the
verifier correctly. capnagent's purple-team corpus tests both: the
structural defense (rounds 01–05) and the operator-ergonomics
failure modes (rounds 06–10).

## In-scope: what capnagent defends against

| Threat class | Round(s) | Status |
|---|---|---|
| Tool-description injection (cross-server confused deputy) | [01](purple-team/01-tool-description-injection.md) | holds-with-caveat |
| Replay of captured hok-bound capability + proof | [02](purple-team/02-replay-attack-on-hok-bound-cap.md) | holds-with-caveat |
| Capability broadening (hostile-holder tampering) | [03](purple-team/03-capability-broadening.md) | holds-with-caveat |
| Use of revoked capability (revocation race) | [04](purple-team/04-revocation-race.md) | holds-with-caveat |
| Cross-origin exfil via fetch / HTTP agent | [05](purple-team/05-cross-origin-exfil.md) | holds-with-caveat |
| Silent-bypass on revocation-list install | [06](purple-team/06-silent-bypass-revocation-install.md) | CLOSED post-v0.4 |
| fs-sandbox prefix lateral-substring foot-gun | [07](purple-team/07-sandbox-prefix-footgun.md) | **BREAKS** (v0.5 queued) |
| Forgot NonceStore on hok-bound caps | [08](purple-team/08-forgot-nonce-store.md) | CLOSED via v0.4 |
| IDN homograph in origin allowlist | [09](purple-team/09-idn-homograph-origin.md) | **BREAKS** (v0.5 queued) |
| Path-traversal / encoding attacks against fs-sandbox | [10](purple-team/10-encoding-attacks.md) | **BREAKS** (v0.5 queued; same fix as round 07) |
| Sub-agent / delegated-capability scope drift | [13](purple-team/13-subagent-scope-drift.md) | holds-with-caveat |

The structural defense holds in every closed round. The three
BREAKS rounds (07, 09, 10) are operator-config foot-guns whose
fixes are queued in v0.5 and which document defender-actionable
mitigations available today.

## Out-of-scope: what capnagent does NOT defend against

These are real threats. They're not capnagent's job. Most are
about **model behavior** (what the model produces) rather than
**tool-call authorization** (what the agent is permitted to do
once it has produced a tool call). capnagent's defense applies at
the latter layer; the former is the model's own alignment work,
the harness vendor's safety classifiers, or a separate sandboxing
layer.

| Threat class | Why out of scope | Right defense for this |
|---|---|---|
| Many-shot jailbreaking | Targets model **content** generation. If the model never emits a tool call, capnagent has nothing to gate. | Model alignment training; output classifiers in the harness. |
| System-prompt extraction | capnagent doesn't see the system prompt or model output. | Server-side system prompt isolation; output filtering. |
| Crescendo / gradual escalation | capnagent gates the FINAL tool-call shape. The conversation path that produced it is irrelevant to the gate. | Conversation-level monitoring + rate limiting. |
| Roleplay / hypothetical framing | Same as Crescendo — the gate decision is on the call, not the framing that led there. | Model alignment + harness-level classifiers. |
| DAN-family persona jailbreaks | capnagent denies the same out-of-scope tool call regardless of which persona produced it. | Model alignment; refusal training. |
| Gradient-based suffix attacks (GCG) | Token-level attack on the model's output distribution. capnagent doesn't see tokens; it sees structured tool calls. | Model robustness; input filtering for known GCG patterns. |
| Capability-dependent reasoning (model reasons about its own tools) | If the agent reasons its way to an out-of-scope tool call, capnagent denies it. The reasoning didn't help. | None needed beyond capnagent — this is what capnagent IS. |
| Side-channel exfil through legitimate response shapes | Even with denied tool calls, an attacker can ask "in-scope" tools to leak data via timing, response shape, or in-band channels. | Argument-shape constraints (more granular caveats); response sanitization. |
| Pure prompt injection of model reasoning (model produces wrong answer / refuses legit work / insults user) | capnagent bounds tool-call AUTHORITY, not model reasoning. A wrong answer that doesn't trigger a tool call is invisible to capnagent. | Model alignment; output review. |
| Privilege escalation within the underlying tool surface | capnagent gates which tool calls are permitted, not what those tools do once invoked. If `git log --exec=...` lets an attacker run shell, that's git's authority, not capnagent's. | OS-level sandboxing (chroot, mount namespaces, containers); finer-grained tool wrappers. |
| Compromise of the issuer's root key | An attacker who steals the root key can issue any capability they want. capnagent doesn't defend against root-key compromise. | KMS / HSM key custody; key rotation procedures; air-gapped issuer. |
| Compromise of the operator's deployment pipeline | An attacker who can modify the operator's config can issue overly-broad caps. capnagent's defense is conditional on operator's correct config. | Supply-chain security (signed configs, attestation); separation of duties. |
| TOCTOU / symlink races between caveat eval and tool execution | capnagent's Context provider sees one path; the underlying tool reads another (after a race). Out of scope unless the Context provider AND the tool client share canonical-path resolution. | OS-level mount-immutable filesystems; explicit canonicalize-then-open patterns. |
| Memory exhaustion / DoS against the verifier | capnagent's verifier is single-shot CPU work (~11 µs bearer, ~56 µs hok). An attacker who can drive 100 kHz of verify calls per process WILL exhaust resources. | Rate limiting upstream of capnagent; bounded request queues. |
| Distributed replay across multiple verifier processes | NonceStore is per-process by default (in-memory). Two verifiers serving the same root key with separate stores will each accept the same proof once. | Shared backing store (Redis, Postgres) for the NonceStore in production. |

## What capnagent depends on the OPERATOR for

The angles methodology in rounds 06–10 surfaced a class of failure
that the structural defense doesn't catch: **operator-config
errors that silently disable the defense.** capnagent's role is to
make these detectable, not to prevent them. The v0.4 introspection
methods (`hasRevocationList()`, `hasNonceStore()`,
`revocationListIssuedAtMs()`) are the engine surface; the
operator-side is responsibility for deployment-readiness probes,
postcondition assertions, and config review.

Concrete operator-side responsibilities:

1. **Issue tightly-scoped capabilities.** A cap with `arg.path
   matches "~"` (broad home-dir read) defeats round 01's defense
   regardless of what capnagent does.
2. **Assert install-state postconditions.** After
   `withRevocationList(list)` or `withNonceStore(store)`, check
   `verifier.hasRevocationList()` / `hasNonceStore()` returns
   `true`. The v0.4 methods make the silent-failed install
   detectable; the operator has to actually check.
3. **Choose realistic TTLs.** `nonce_ttl_ms` defaults to 5 minutes.
   Operators with longer capture-to-replay threat windows must
   tune it.
4. **Deploy a durable NonceStore in production.** The default
   `InMemoryNonceStore` is for development. Production deployments
   need a Redis-backed (or Postgres-backed, etc.) store to survive
   process restarts.
5. **Monitor denial receipts.** A spike in `outcome.kind == "denied"`
   for paths/origins/tools the agent shouldn't be trying to access
   is the highest-signal anomaly indicator capnagent produces.
6. **Compose with OS-level sandboxing.** Even a perfect capnagent
   cap is one tool-side bug away from defeat. Run agents in
   confined OS environments (chroot, namespace, container) as
   defense in depth.

## Composition with other defenses

capnagent is **one layer** in a multi-layer defense:

```
┌─────────────────────────────────────────────────┐
│  Model alignment (refuses obviously-bad reqs)  │ ← model vendor
├─────────────────────────────────────────────────┤
│  Harness-level classifiers (output filters)    │ ← harness vendor
├─────────────────────────────────────────────────┤
│  capnagent (tool-call authorization)           │ ← THIS LIBRARY
├─────────────────────────────────────────────────┤
│  Tool-side input validation                    │ ← tool implementer
├─────────────────────────────────────────────────┤
│  OS-level confinement (chroot / namespace)     │ ← deployment
└─────────────────────────────────────────────────┘
```

Each layer covers what the layers above and below cannot. capnagent
specifically: bounds what the agent CAN do, regardless of what the
model PRODUCES. It is necessary but not sufficient.

## How this document is updated

- Every closed purple-team round adds or updates a row in the
  in-scope table. Status fields stay synchronized with
  `purple-team/README.md`.
- Out-of-scope additions require a brief justification (third
  column). New attack classes that emerge in the field get added
  here OR in the in-scope table — never silently ignored.
- The "defender-actionable" sections of individual rounds compose
  into the operator-responsibility list above. Whenever a round's
  defender-actionable points are non-trivial, this doc gets a
  pointer.
