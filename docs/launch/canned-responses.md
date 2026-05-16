# Canned HN / Lobste.rs / Reddit comment responses

A reference of pre-thought answers for the comment patterns most likely to show up. Goal: reply latency under 90 seconds. Pull from this file, adapt to the specific phrasing of the commenter, post.

The six most predictable responses are already inline in [`hn.md`](hn.md#after-posting). This file extends those with the next tier of likely comments and a few "rare but worth being ready for" ones.

---

## Tier 1 — already covered in hn.md

Cross-reference, not duplication:
- "Can't an attacker just…?" → cannot-broaden invariant + proptest count
- "How is this different from JWT scopes?" → attenuation + macaroon chain + holder-of-key + revocation
- "Why not OPA / Cedar / [policy engine]?" → bearer-token vs policy-engine layer separation
- "DPoP isn't novel." → correct, the novelty is the composition
- "Just use Guardrails AI / Nemo / Llama Guard." → classifier vs deterministic, stack both
- "Three projects is too many." → each stands alone; adopt the layer matching your problem

---

## Tier 2 — likely on a frontpage thread

### "What about rate limiting / cost control?"

> Different layer. capnagent bounds *what* is authorized; rate limiting bounds *how often*. The two compose without overlap — rate-limit at the transport layer (HTTP / token-bucket), then evaluate capnagent at the agent layer. capnagent's audit receipts give you per-call evidence to feed back into the rate-limiter if needed.

### "Have you talked to Anthropic / OpenAI / Google about this?"

> Not yet, but I'd love to. If you're at one of those labs and this seems load-bearing for the agent-platform direction you're going, my email is in the repo. The partner-brief at `docs/launch/partner-brief-v0.7.md` is what I'd hand someone interested in a paid pilot.

### "Is this open-source forever, or is there a commercial fork coming?"

> Apache-2.0 (capnagent + mcp-recon) and MIT (mcp-guardrails). No commercial fork planned. The sustainable models I'm thinking about: support contracts for the engine, custom caveat-language extensions for verticals (finance, healthcare), and eventually a managed audit-log + revocation service for orgs that don't want to operate it themselves. The libraries stay permissive.

### "How does this fail — open or closed?"

> **Fail-closed by design.** Verifier errors return DENY, never ALLOW. Documented in [`SECURITY.md`](../SECURITY.md). The audit receipt records the denial reason so you can debug — but the runtime decision is unconditionally deny on error.

### "Can the model see the capability token?"

> Yes, that's fine. The capability text is not secret — it's a structural constraint. Knowing the cap doesn't help bypass it; the verifier is what enforces, not the cap's contents. (This is the same property as macaroons.) The token contains the bound, the signature, and optionally a holder-of-key public key; secrets are nowhere in the wire format.

### "What if the verifier is compromised?"

> Then everything is broken — same as compromising your IAM policy engine, your JWT validator, or your TLS terminator. capnagent's defense is making the verifier *small enough to audit* (one Rust crate, `unsafe_code = forbid`, 246 tests) and making every decision audit-receipted (so post-hoc detection of misuse is structural). It's not "this can't be compromised"; it's "the surface is minimal and the evidence is undeniable."

### "Why not just sandbox the agent?"

> Sandboxing limits what the runtime can *do* (filesystem, network, syscalls). Capability tokens limit what it's *authorized* to do (which tools, with which arguments). They're different mechanisms operating at different layers:
> - The sandbox stops "the agent forks a process and writes to /etc/passwd."
> - The capability stops "the agent calls the legitimate `send_email` tool to exfil a secret."
>
> A determined attacker who controls the model can still ask the agent to do permitted things in malicious orderings — the sandbox can't see that, only the authorization layer can. Defense in depth: ship both.

### "How is this different from Pomerium / OpenZiti / [next-gen access tool]?"

> Those are network-layer access tools — they decide who can connect to what. capnagent operates *inside* the agent process, deciding which specific tool calls (with which specific args) are permitted. The two are complementary, not competing: Pomerium gates the agent's network identity; capnagent gates the agent's tool authority.

### "Where's the performance benchmark?"

> `cargo bench` in capnagent-core: 1.4 µs chain-only verify, 56 µs full holder-of-key pipeline, ~17 kHz 5-gate verifications per core on a 2024 laptop. Criterion benches run in CI on every push. That's at the noise floor of memory access — verification adds no measurable latency to a tool call.

### "Why Rust? Why not Go / Python / TypeScript?"

> Three reasons:
> 1. **`unsafe_code = forbid`** at the workspace level — the engine's memory-safety story is mechanical, not promised. Same property is harder to achieve in C/C++.
> 2. **Determinism for the verifier** — no GC pauses, no allocator games, no runtime surprises across platforms. A verifier that returns different decisions on different platforms is broken.
> 3. **One core, three bindings** — Python (PyO3, on PyPI), WebAssembly (wasm-bindgen, used by the TypeScript wrapper), and native Rust. Single source of truth, no semantic drift.
>
> Go would also have been fine but `unsafe_code = forbid` is a Rust-specific verifiable invariant that buys mileage in security reviews.

### "What's the threat model? What ARE you assuming?"

> Full statement in [`THREAT_MODEL.md`](../THREAT_MODEL.md). Short version: we assume the model is **fully compromised by the prompt injection** and emits exactly the tool calls the attacker asked for. The capability layer denies anything not authorized by the issued cap, regardless of *why* the model emitted it. What we do NOT defend against: a compromised verifier, a compromised issuer key, or a sandbox escape from the underlying tool. Each of those is a different layer's problem.

### "Doesn't every tool call need network round-trips for verification?"

> No. Verifier runs in-process (Rust, WASM, or PyO3-imported), evaluating the caveat program directly against call-site context. The chain check is ~1.4 µs. Network round-trips are only required if you're using the optional revocation-list fetch, which has a configurable freshness window (default: fetch every 60 s, cache locally).

### "Have you done a third-party security audit?"

> Not a paid third-party audit yet. The closest equivalent is the **angles methodology**: four parallel AI agents writing adversarial test files against the engine, producing 36 angles, 17 findings, 4 HIGH-severity defects — all 4 closed end-to-end with reproducible tests. The methodology and all findings are public in [`docs/EVALUATION.md`](../EVALUATION.md). A paid audit is the right next step at a particular adoption threshold; if your org would help fund one, get in touch.

---

## Tier 3 — rare but worth being ready for

### "Why is the schema mutable JSON instead of [Protobuf / FlatBuffers / Capnproto]?"

> Honest answer: JSON is what every MCP server already speaks, and the verifier doesn't care about wire format. The capnagent core is binding-free — it consumes a deserialized struct. The JSON wrapper is for ergonomic onboarding. If your stack has a faster wire format for the cap blob, swap it.

### "What about quantum-resistance?"

> ed25519 today, post-quantum migration tracked in [`ROADMAP.md`](../ROADMAP.md). The plan is dual-signing (ed25519 + Dilithium / Falcon) once the standards solidify and there's a reason to migrate. The token format is versioned to allow algorithm bumps without re-issuing existing tokens.

### "Why not [Spiffe / SPIRE / SVIDs]?"

> SPIFFE is workload-identity infrastructure — it gives you "this process IS workload X." capnagent is what X is *authorized* to do, expressed as a small program the verifier runs. The two layer cleanly: SPIFFE identifies; capnagent authorizes. Some deployments will run both.

### "Is the audit log tamper-evident?"

> Each receipt is HMAC-signed with a per-deployment key. Tamper-evidence beyond that (e.g. transparency-log style) is on the roadmap — see [`SECURITY-POSTURE.md`](../SECURITY-POSTURE.md). Today, the receipt set is "trust the HMAC key and you trust the log"; future work makes the log structurally append-only.

### "What does this look like in a multi-agent / agent-supervises-agent setting?"

> This is exactly where capnagent earns its weight. A subagent receives a token that's been **attenuated** from the parent's token — strictly weaker, never broader. The chain check (`cannot_broaden_invariant`, 9 proptest cases) holds across delegation. The parent doesn't need to round-trip the issuer to delegate; the holder of any cap can attenuate locally.

### "Where do you keep the issuer key?"

> Out of band, like any signing key — KMS, HSM, or simply a secrets manager for low-stakes deployments. The issuer key never lives in the verifier; the verifier only needs the *public* key. Operational guidance is in [`SECURITY.md`](../SECURITY.md). If you do leak the issuer key, your action is to rotate + add the old key's tokens to the revocation list; capnagent ships both.

### "What's the dependency surface?"

> capnagent-core's `Cargo.toml` has six dependencies, all single-purpose: `ed25519-dalek` (signature), `serde` + `serde_json` (de/serialization), `blake3` (hashing), `subtle` (constant-time compare), `zeroize` (secret wiping). Zero runtime deps in the Python and TypeScript bindings beyond what the platforms ship. `cargo deny` is gated in CI for licenses + advisories.

### "Has anyone broken it yet?"

> The angles methodology has broken it four times — all closed. The 10-round purple-team corpus has broken it four times — all closed. I'd love a Round 11. If you can construct an attack that escapes the cap's bound + DPoP-style proof + revocation freshness window + audit receipt, I'd much rather hear it here than in a CVE filing.

---

## Tone notes

- **Be direct, not defensive.** "Yes" or "no" beats "actually."
- **Cite file paths.** Reviewers respect `docs/THREAT_MODEL.md §3` more than prose.
- **Acknowledge gaps.** "Good catch, that's in [the roadmap / not yet / open issue #N]" beats "but actually that's covered."
- **Don't argue with flag-bait.** If a comment is rage-bait ("LLMs are a scam"), the right answer is no reply. Engagement-feeds-the-troll dynamics on HN are real.
- **Always reply to commenters with karma > 5000.** They tend to attract sub-thread engagement.
- **Reply within 30 minutes for the first hour.** HN's ranking rewards engagement velocity over engagement volume.

## What NOT to do

- Don't post your own follow-up that says "see the post" — write the follow-up to add a *new* technical detail (something you cut from the body for length). Comment-activity ranking rewards original content from the OP.
- Don't tag people who haven't engaged. (You CAN mention "I'd love @simonw to weigh in" but don't @-spam.)
- Don't post the same response to multiple comments. Even small variations help.
- Don't edit the OP body more than once. Repeated edits look defensive.
