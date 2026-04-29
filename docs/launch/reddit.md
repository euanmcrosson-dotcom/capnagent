# Reddit submissions

Three distinct subreddits, three distinct framings. Don't cross-post — tailor each.

## /r/rust

**Where:** https://www.reddit.com/r/rust/submit
**When:** weekday morning UTC.
**Mod-rules check:** /r/rust requires the post to be *about Rust*, not just *built in Rust*. Lead with the Rust-specific decisions, not the security pitch.

### Title

```
Capnagent (Rust) + mcp-recon (TS): a defensive engine and offensive companion for MCP
```

### Body

```
Shipping two related projects together — defensive engine in
Rust + WASM, offensive companion in TS:

  capnagent  — Rust capability-token engine. Macaroon chain,
               ed25519 hok, signed receipts. Tests an
               adversarial corpus against itself.
  mcp-recon  — TS CLI that reverse-engineers any MCP server's
               tool surface; emits a threat profile +
               recommended capnagent caveat per tool.
               (github.com/euanmcrosson-dotcom/mcp-recon)

This post focuses on the Rust side. Sharing some Rust-specific
decisions and looking for feedback.

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

242 Rust tests (proptests for the macaroon no-broaden invariant
and 8 boolean-algebra laws on the caveat DSL) + 322 TS tests
including a parallel-agent "angles" run that surfaced 17 findings
in our own engine — 4 HIGH severity (sub-ulp f64 caveat-bypass,
empty-attenuation brick, zero-byte audit key accepted, empty-caveat
god-mode token). v0.5 SHIPPED and closes 3 of 4 (sub-ulp f64
remains under design discussion). Apache-2.0.
```

## /r/MachineLearning

**Where:** https://www.reddit.com/r/MachineLearning/submit
**Tag the post `[P]`** (project) — `[R]` (research) is for papers, `[D]` (discussion) is for questions.
**When:** EU evening / US morning is best.
**Caution:** /r/MachineLearning mods are strict about "self-promotion." Lead with the threat model + the demo, not "I built X."

### Title

```
[P] I red-teamed my own AI-agent security library AND scanned every public MCP server
```

### Body

```
Two related projects shipping together:

  capnagent  — capability-bounded authorization for AI agent
               tool calls (Rust + WASM + TS).
  mcp-recon  — reverse-engineer any MCP server's tool surface
               in 30s (TS).
               github.com/euanmcrosson-dotcom/mcp-recon

The recon-then-bound workflow:

  [ mcp-recon ]  →  threat profile  →  [ capnagent ]
     "what is        "what should           "deny anything
      here?"          we allow?"             outside that"

This post is about both, but the methodology comes from
capnagent. I've been building a public adversarial-test corpus
for MCP servers and AI-agent tool calls. Each round writes a
falsifiable security claim, constructs an attack designed to
falsify it, runs the attack worst-case (the agent is assumed
fully compromised by the injection and emits exactly what the
attacker described), and captures a signed denial receipt as
evidence. Reviewers verify by running the suite — no
prose-trust required.

10 rounds are closed (cross-server confused deputy / tool-poisoning,
hok-replay, capability broadening, revocation race, cross-origin
exfil, IDN homograph in origin allowlist, fs-sandbox path-traversal,
encoding attacks, etc). 6 hold-with-caveat; 4 documented BREAKS
with fixes shipped or queued in v0.5.

Then: an "angles" run — 4 parallel agents adversarially testing
the engine itself, each writing >=5 angles in a dedicated test file.
36 angles, 17 findings, 4 HIGH severity defects in our own engine:

  A.1  Sub-ulp f64 collapse: caveat `arg.amount <= 50` admits a
       holder whose `amount` is `50.000000000000001` (authorization
       bypass via numeric coercion).
  B.2  cap.attenuate("") produces a silent permanent-deny token —
       any holder in a chain can brick a delegated cap.
  B.3  Auditor accepts a zero-byte HMAC key (deployment trap if
       the audit key derives from an unset env var).
  C.5  Empty-caveat capability = god-mode. Issuer.issue("x").build()
       with no caveats authorizes every context.

These are not "we tested obvious threats and got the obvious
answer." They are real engineering defects, found and triaged
publicly *before* shipping.

Why this framing matters: most prompt-injection writeups stop at
"here's an attack." Most security libraries stop at "here are our
defenses, trust us." This corpus is the inverse of both — every
entry is a defense being tested against an attack with reproducible
PoCs and signed receipts, AND the engine itself is being adversarially
reviewed in public, with findings logged before fixes.

Engine: Rust capability-token library — macaroon-style HMAC chain,
ed25519 holder-of-key (DPoP-shape), NonceStore replay protection,
signed revocation list, caveat DSL with boolean composition. WASM/TS
bindings; MCP adapter verified live against the official
@modelcontextprotocol/server-filesystem.

Repo: https://github.com/euanmcrosson-dotcom/capnagent
Methodology + rounds: docs/purple-team/
Threat model (what's in/out of scope): docs/THREAT_MODEL.md

Looking for adversarial review of the methodology and the angles
findings. If you can break round NN or design round 11, that's the
conversation I'm here for.
```

## /r/programming

**Where:** https://www.reddit.com/r/programming/submit
**Caution:** This sub is huge but flag-happy. Self-promo gets nuked unless framed as a discussion piece. Skip if you want to play it safe; the lobste.rs and HN posts cover the same audience with better signal.

If you do post, frame it as **"AI agents have a confused-deputy problem; here's a concrete fix"** — not "look at my library."
