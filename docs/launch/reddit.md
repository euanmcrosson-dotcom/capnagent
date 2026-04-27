# Reddit submissions

Three distinct subreddits, three distinct framings. Don't cross-post — tailor each.

## /r/rust

**Where:** https://www.reddit.com/r/rust/submit
**When:** weekday morning UTC.
**Mod-rules check:** /r/rust requires the post to be *about Rust*, not just *built in Rust*. Lead with the Rust-specific decisions, not the security pitch.

### Title

```
Capnagent: a Rust capability-token engine + public purple-team corpus for MCP
```

### Body

```
I built capnagent — a Rust capability-token engine and a public
purple-team test corpus for MCP servers and AI-agent tool surfaces.
The library powers the defense; the corpus is the artifact —
adversarial scenarios with falsifiable claims and runnable PoCs.

Sharing some Rust-specific decisions and looking for feedback.

**Architecture**

- `crates/capnagent-core` is pure-Rust: HMAC-SHA256 macaroon chain,
  ed25519 holder-of-key (DPoP-style), a small caveat DSL with
  OR/AND/parens, audit receipts (versioned, HMAC-signed), revocation
  lists, replay protection via a `NonceStore` trait. No tokio, no
  async; everything is sync-by-design because verification is
  single-shot CPU work.
- `crates/capnagent-wasm` wraps it for JS via wasm-bindgen. WASM
  build is one `wasm-pack build --target bundler` invocation.
- `unsafe_code = forbid` workspace-wide. `clippy --tests --benches
  -- -D warnings` clean in CI.

**Performance** (criterion, single core, release):

  chain-only verify           1.4 µs
  full bearer-token pipeline   11 µs
  full hok pipeline            56 µs
  hok + replay store          170 µs

ed25519-dalek dominates the hok paths (~45 µs). Sustains ~17 kHz
5-gate verifications/core.

**Things I'd like Rust-flavoured feedback on:**

1. The `NonceStore` trait is `Send + Sync`. The default
   `InMemoryNonceStore` is `Mutex<HashMap<Vec<u8>, u64>>`. Under high
   contention this becomes the bottleneck — would `dashmap` or a
   sharded approach be the right move, or should I just document
   "use Redis in prod"?
2. `serde_json::Value` carries the agent-supplied tool-call args.
   The canonical-JSON serialization is what gets HMACed for the
   audit receipt. Anyone using a leaner JSON crate (sonic-rs,
   simd-json) for similar canonical-bytes work?
3. The TS<->WASM boundary uses serde-wasm-bindgen for receipts
   (snake_case round-trip) and `Vec<u8>` for keys/proofs. This works
   but feels heavy. Better patterns?

**Repo:**

  https://github.com/euanmcrosson-dotcom/capnagent

220+ tests in CI including proptests for the macaroon no-broaden
invariant and 8 boolean-algebra laws on the caveat DSL. Apache-2.0.
```

## /r/MachineLearning

**Where:** https://www.reddit.com/r/MachineLearning/submit
**Tag the post `[P]`** (project) — `[R]` (research) is for papers, `[D]` (discussion) is for questions.
**When:** EU evening / US morning is best.
**Caution:** /r/MachineLearning mods are strict about "self-promotion." Lead with the threat model + the demo, not "I built X."

### Title

```
[P] Public purple-team harness for MCP / AI-agent tool surfaces — round 01: tool-poisoning
```

### Body

```
I've been building a public adversarial-test corpus for MCP servers
and AI-agent tool calls. Each round in the corpus is one cycle of
blue-first → red → iterate: write a falsifiable security claim,
construct an attack designed to falsify it, run the attack, capture
a signed denial receipt as evidence, and document the residual
risk honestly.

Round 01 is in: tool-description injection (cross-server confused
deputy). It's the Invariant Labs 2025 attack class — a malicious
MCP server returns a tool description that hijacks the agent's
authority to read other co-installed servers' files (e.g. ~/.ssh/
id_rsa via a legitimate filesystem-MCP). The PoC simulates the
worst case: the agent has been fully compromised by the injection
and emits exactly the calls the malicious description tried to
induce. The structural defense holds — capnagent's capability gate
denies regardless of HOW the call got emitted. 8/8 deterministic
tests pass. The round explicitly documents what the defense does
NOT cover (loose capabilities still lose; in-sandbox secrets are
operator responsibility).

Repo: https://github.com/euanmcrosson-dotcom/capnagent
Methodology + first round: docs/purple-team/

Why this framing matters: most prompt-injection writeups stop at
"here's an attack." This corpus is the inverse — every entry is a
defense being tested against the attack, with reproducible PoCs and
signed receipts so reviewers can verify rather than trust.

The engine underneath is a Rust capability-token library
(macaroon-style chain, ed25519 holder-of-key, replay protection,
revocation list, caveat DSL with boolean composition) wired through
an MCP adapter. Live integration verified against the official
@modelcontextprotocol/server-filesystem.

Looking for adversarial review and suggestions for the next round.
Replay attack on hok-bound caps and capability broadening are
queued — I'd take "you're missing X" feedback over additional
features at this point.
```

## /r/programming

**Where:** https://www.reddit.com/r/programming/submit
**Caution:** This sub is huge but flag-happy. Self-promo gets nuked unless framed as a discussion piece. Skip if you want to play it safe; the lobste.rs and HN posts cover the same audience with better signal.

If you do post, frame it as **"AI agents have a confused-deputy problem; here's a concrete fix"** — not "look at my library."
