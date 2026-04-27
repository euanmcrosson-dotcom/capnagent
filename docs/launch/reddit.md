# Reddit submissions

Three distinct subreddits, three distinct framings. Don't cross-post — tailor each.

## /r/rust

**Where:** https://www.reddit.com/r/rust/submit
**When:** weekday morning UTC.
**Mod-rules check:** /r/rust requires the post to be *about Rust*, not just *built in Rust*. Lead with the Rust-specific decisions, not the security pitch.

### Title

```
Capnagent: macaroon-style capability tokens for AI agent tool calls (Rust + WASM bindings)
```

### Body

```
I built capnagent over the last few weeks — a Rust library for
issuing macaroon-style capability tokens that bound what AI agent
tool calls can do. Wanted to share some of the Rust-specific
decisions and ask for feedback.

**Architecture**

- `crates/capnagent-core` is pure-Rust: HMAC-SHA256 macaroon chain,
  ed25519 holder-of-key (DPoP-style), a small caveat DSL with
  OR/AND/parens, audit receipts, revocation lists, replay protection
  via a `NonceStore` trait. No tokio, no async; everything is
  sync-by-design because verification is single-shot CPU work.
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
[P] Capability-bounded AI agents: tool-call gating without trusting the model
```

### Body

```
Modern frontier models (Claude, GPT-4) are surprisingly hard to
prompt-inject through tool output — alignment training does real
work. But the prompt-injection threat model isn't the only one:
agents can also be compromised by

  - a naive harness that tells the model to follow tool-output
    instructions,
  - an over-broad user request the agent honors literally.

In all three cases, the agent attempts an out-of-scope tool call
because it has the AUTHORITY to do so. Capability-based security
fixes this at the authority layer: the agent doesn't hold an OAuth
token or a database connection; it holds a CAPABILITY that bounds
what it can do.

I built a library implementing this — capnagent — with a 5-gate
verifier (chain integrity, ed25519 proof of possession, replay
protection, revocation, caveat evaluation). The shopping-agent demo
in the repo runs against real Claude Opus 4.7: when the user
explicitly asks for a $50 cable AND a $30 wire transfer in the
same message, the agent attempts both. The cable goes through
(in scope). The wire is denied at the capability gate before it
hits the bank tool. Every decision is signed into a tamper-evident
audit receipt.

The demo is here: <link to GIF in repo>
The library is here: https://github.com/euanmcrosson-dotcom/capnagent

This is a re-application of capability-security ideas (Lampson 1974,
KeyKOS, macaroons 2014) to the AI-agent stack. The novel part is
the composition: macaroon chain → DPoP-style hok → replay → caveat
DSL with boolean composition → MCP adapter — wired so each gate is
independently testable and the security argument has three named
legs you can break.

Curious how production teams are thinking about this. Tool-use
guards I see in the wild are mostly classifier-based ("does this
tool call look bad?") which is exactly the trust-the-model model
this aims to replace.
```

## /r/programming

**Where:** https://www.reddit.com/r/programming/submit
**Caution:** This sub is huge but flag-happy. Self-promo gets nuked unless framed as a discussion piece. Skip if you want to play it safe; the lobste.rs and HN posts cover the same audience with better signal.

If you do post, frame it as **"AI agents have a confused-deputy problem; here's a concrete fix"** — not "look at my library."
