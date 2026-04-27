# v0.1 — Build Spec (parallel work)

Three independent contributors are implementing two v0.1 deliverables
in parallel. This doc locks the interfaces between them so they can
ship without seeing each other's code.

**Read first:** `README.md`, `docs/DESIGN.md` (especially §6, §10, §11),
`docs/WEEK3_SPEC.md` (for the stub-driven cross-language pattern).

---

## §1. File-ownership map (strict — do not edit outside your scope)

| Branch | Owner | Files they may create or edit |
|---|---|---|
| `feat/v01-decimal-dsl` | Terminal A | `crates/capnagent-core/src/caveat_dsl.rs`; `crates/capnagent-core/tests/caveat_dsl_tests.rs` |
| `feat/v01-wasm-hok` | Terminal B | `crates/capnagent-wasm/src/lib.rs`; `crates/capnagent-wasm/Cargo.toml` (only to add a dep if strictly necessary) |
| `feat/v01-ts-hok` | Terminal C | `packages/capnagent/**`; `packages/capnagent-mcp/**`; `examples/shopping-agent/**` |

**Hard rules:**

- Terminal A may **not** edit `lib.rs`, `verifier.rs`, `capability.rs`,
  `issuer.rs`, `audit.rs`, `revocation.rs`, `context.rs`, or any
  workspace member outside `capnagent-core`. The DSL extension lives
  entirely in `caveat_dsl.rs` and its test file.
- Terminal B may **not** edit any `crates/capnagent-core/**` file. The
  Rust core is frozen for this round; B is a thin wasm-bindgen wrapper.
- Terminal C may **not** edit `crates/**`. C develops against the
  WASM-export contract in §3.2 via a stub (same pattern as week 3) and
  swaps at merge time.
- All public APIs **must match** the contracts in §3 below. Field names,
  method names, type shapes — no drift.

---

## §2. Goal of v0.1 (this round)

Two deliverables, surfaced from real v0 use:

1. **Decimal numbers in the caveat DSL.** Extend the BNF to accept
   `\d+(\.\d+)?` so an LLM agent emitting a JSON `12.99` for `arg.amount
   <= 50` is compared correctly instead of denied with a type-mismatch.
   Surfaced during the live shopping-agent demo on Haiku 4.5; tracked in
   `docs/DESIGN.md` §9.

2. **TypeScript / WASM holder-of-key wire-up.** The Rust core already
   ships `Capability::holder_of_key`, `CapabilityBuilder::holder_of_key`,
   `Verifier::verify_with_proof`, and `pop_challenge_for` (DESIGN.md §11).
   What's missing: WASM bindings, TS wrappers in `@capnagent/core`,
   optional `signer` field in `@capnagent/mcp`'s `WrapOptions`, and a
   demo scenario in `examples/shopping-agent` that exercises the full
   stack against a real Claude model. This closes the loop so the v0.1
   surface is usable from JS, not just Rust.

---

## §3. Locked contracts

### 3.1 Decimal DSL — `feat/v01-decimal-dsl` (Terminal A)

**BNF extension** (additive — existing integer caveats keep working):

```
number      ::= integer fractional? ("_" unit)?
integer     ::= "-"? [0-9]+
fractional  ::= "." [0-9]+
unit        ::= "usd" | "eur" | "gbp" | "cents" | "ms" | "s"
```

Examples that must parse:

```
arg.amount <= 12.99
arg.amount == 0.01
arg.amount > 1000.5
arg.amount <= 12.99_usd
arg.budget == 0
arg.budget == 0.0
```

Examples that must continue to be rejected:

```
arg.amount <= 12.            (trailing dot)
arg.amount <= .99            (leading dot)
arg.amount <= 12.99.5        (multiple dots)
arg.amount <= 12_usd_extra   (unchanged — units not extended)
```

**Evaluation semantics.** Comparisons treat decimals **as f64**, with
the following discipline:

- An integer caveat (`50`) compared against a decimal `arg.amount` value
  must succeed when `12.99 <= 50` (the integer is treated as `50.0`).
- A decimal caveat (`50.5`) compared against an integer `arg.amount`
  value must succeed when `13 <= 50.5`.
- Unit semantics are unchanged: a unit on the caveat side must match the
  unit on the args side (or both unitless), or it's a `TypeMismatch`.
- Equality is **exact-binary** — `0.1 + 0.2 == 0.3` is `false`. We do
  not introduce epsilon comparison; document this in the parser doc
  comment so callers know.

**No public API change.** `parse`, `evaluate`, `matches` keep their
existing signatures. The internal `Predicate` AST may grow a `Decimal`
variant or extend its `Number` variant — that's an implementation
detail.

**Test focus** (in addition to existing 59 tests, all of which must
keep passing):

- Decimal parsing happy path (the examples above).
- Decimal parsing rejection (the examples above).
- Cross-type comparison: integer caveat vs decimal arg, and vice versa.
- Unit + decimal: `12.99_usd <= 50_usd` works; `12.99_usd <= 50_eur` is
  TypeMismatch.
- A proptest property: for any random decimal `d`, `parse("arg.x ==
  <d>")` followed by evaluate against `args.x = <d>` returns true.

### 3.2 WASM bindings — `feat/v01-wasm-hok` (Terminal B)

The crate's existing `#[wasm_bindgen]` exports stay; this branch
**adds** the items below. Field/method names are locked exactly as
shown — Terminal C develops against this surface and merge breaks if
anything drifts.

```rust
// In crates/capnagent-wasm/src/lib.rs.

#[wasm_bindgen]
impl CapabilityBuilder {
    /// NEW. Bind to an ed25519 public key (raw 32 bytes). Must be
    /// called BEFORE any .caveat() — panics otherwise. JS-side name:
    /// `holderOfKey`.
    #[wasm_bindgen(js_name = "holderOfKey")]
    pub fn holder_of_key(self, pubkey: &[u8]) -> CapabilityBuilder { /* ... */ }
}

#[wasm_bindgen]
impl Capability {
    /// NEW. Returns the bound ed25519 public key (32 bytes) or
    /// `undefined` for non-hok tokens. JS-side: getter `holderOfKey`.
    #[wasm_bindgen(getter, js_name = "holderOfKey")]
    pub fn holder_of_key(&self) -> Option<Vec<u8>> { /* ... */ }
}

#[wasm_bindgen]
impl Verifier {
    /// NEW. Four-gate pipeline: chain → proof → revocation → caveats.
    /// `proof` is the raw 64-byte ed25519 signature produced by the
    /// holder over `challenge`. Returns the receipt as a plain JS
    /// object (same shape as `verifyWithContext`'s return).
    /// JS-side: `verifyWithProof`.
    #[wasm_bindgen(js_name = "verifyWithProof")]
    pub fn verify_with_proof(
        &self,
        cap: &Capability,
        ctx: JsValue,
        auditor: &Auditor,
        challenge: &[u8],
        proof: &[u8],
    ) -> Result<JsValue, JsError> { /* ... */ }
}

/// NEW free function. Default proof-of-possession challenge: SHA-256
/// over canonical-JSON of `{ id, tool, args_hash, now_ms }`. Returns
/// the 32-byte hash. JS-side: `popChallengeFor`.
#[wasm_bindgen(js_name = "popChallengeFor")]
pub fn pop_challenge_for(cap: &Capability, ctx: JsValue) -> Result<Vec<u8>, JsError> {
    /* ... */
}
```

The `Auditor::verify(receipt)` method already exists from the v0 wasm
surface. No change needed to it for hok — receipts from
`verifyWithProof` round-trip through `Auditor.verify` exactly like
receipts from `verifyWithContext`.

**Definition of done:**

- `wasm-pack build crates/capnagent-wasm --target bundler --out-dir pkg`
  succeeds.
- The generated `.d.ts` declares the four new items above with the
  exact JS-side names.
- `npm run smoke:wasm` passes (the smoke test asserts the names of
  exported items; B should add the four new names to that list — the
  smoke test is owned by B's branch via `scripts/wasm-smoke.mjs`).

### 3.3 TS adapter + demo — `feat/v01-ts-hok` (Terminal C)

Three packages get updated. Each has a locked surface.

#### `@capnagent/core` public API

Additions to `packages/capnagent/src/index.ts`:

```ts
export class CapabilityBuilder {
  // ...existing methods...
  /** Must be called BEFORE any caveat(). Throws otherwise. */
  holderOfKey(pubkey: Uint8Array): CapabilityBuilder;
}

export class Capability {
  // ...existing fields...
  /** 32-byte ed25519 public key, or undefined for non-hok tokens. */
  readonly holderOfKey: Uint8Array | undefined;
}

export class Verifier {
  // ...existing methods...
  /**
   * Four-gate pipeline. Returns a Receipt whose outcome reflects
   * the proof check, revocation check, and caveat eval — same
   * shape as verifyWithContext's return.
   *
   * Throws CapabilityChainError on chain forgery.
   */
  verifyWithProof(
    cap: Capability,
    ctx: Context,
    auditor: Auditor,
    challenge: Uint8Array,
    proof: Uint8Array,
  ): Receipt;
}

/**
 * Default proof-of-possession challenge for a (cap, ctx) pair.
 * SHA-256 of canonical-JSON({ id, tool, args_hash, now_ms }). Both
 * holder and verifier must agree bytewise.
 */
export function popChallengeFor(cap: Capability, ctx: Context): Uint8Array;
```

#### `@capnagent/mcp` `WrapOptions` extension

```ts
export interface WrapOptions {
  // ...existing fields...

  /**
   * Required if `capability.holderOfKey` is set. The wrapper will:
   *   1. Compute challenge = popChallengeFor(capability, ctx)
   *   2. Call signer(challenge) to get a 64-byte ed25519 signature
   *   3. Call verifier.verifyWithProof(...)
   *
   * If `capability.holderOfKey` is set and `signer` is undefined,
   * the wrapper throws a configuration error BEFORE calling
   * the underlying tool — same fail-closed semantics as the
   * Rust core.
   */
  signer?: (challenge: Uint8Array) => Uint8Array | Promise<Uint8Array>;
}
```

The `wrapMCPClient` and `guardCall` implementations branch on
`capability.holderOfKey`:

- If unset: existing behavior (`verifier.verifyWithContext`).
- If set + `signer` provided: compute challenge, sign, call
  `verifier.verifyWithProof`.
- If set + `signer` undefined: throw `Error("capability is bound to a
  holder key but no signer was provided in WrapOptions")` synchronously
  before any tool call.

#### `examples/shopping-agent` demo update

Add a fourth scenario, **`hok`**:

- Generates an ed25519 keypair at runtime (use `@noble/ed25519` — pure
  JS, no native deps).
- Issues both browse and buy capabilities with `.holderOfKey(publicKey)`.
- Passes a `signer` that signs the challenge with the private key.
- Runs the same "buy a USB-C cable" flow as `direct`.
- Includes the user prompt asking for a wire transfer (same as `direct`).
- Expected outcome: cable purchase allowed (proof valid + caveats
  hold), wire denied (caveats fail — same scope as `direct`).

A negative test: corrupt the proof bytes once mid-flight and confirm
the call is denied with `proof failed` reason.

NPM script: `"demo:llm-hok": "tsx src/bin/demo-llm.ts hok"`.

#### Stub strategy for parallel dev

Same as week 3. Inside `packages/capnagent/src/__wasm-stub.ts`,
add the four new items (CapabilityBuilder.holderOfKey,
Capability.holderOfKey getter, Verifier.verifyWithProof, popChallengeFor).
Each throws `Error("WASM stub not yet wired")`. At merge time,
`packages/capnagent/src/wasm.ts` already re-exports from the real
WASM; the new items will be there once Terminal B's branch lands.

For C's tests, mock `wasm.ts` with vitest.

---

## §4. Definition of Done (per branch)

Each branch is done when **all** hold:

1. The contracts in §3 compile and match exactly.
2. New tests are added covering the §3 focus list. Existing tests
   must keep passing.
3. `cargo fmt --all --check` and `cargo clippy --workspace --tests
   -- -D warnings` clean (Rust branches A and B).
4. `npm run lint` and `npm run typecheck` clean (TS branch C).
5. Branch has 1–N small commits with clear messages. No "wip" or "fix"
   alone.
6. Branch did not edit any file outside §1 ownership.

---

## §5. Out of scope for this round

Do not build:

- Decimal DSL: epsilon comparison; arbitrary-precision; scientific
  notation. v0.1 is fixed-precision f64 with exact equality.
- WASM bindings: a full Issuer-side keypair-generation API. Holders
  bring their own key (via `signer`); we don't take a position on key
  storage in the core.
- TS adapter: native Web Crypto integration. `@noble/ed25519` is the
  default for v0.1; Web Crypto path is v0.2.
- Demo: HSM / hardware-backed signing in the demo. The demo uses an
  in-memory keypair generated at runtime.

---

## §6. Merge protocol

After all three branches are green:

1. Fast-forward `feat/v01-decimal-dsl` into `master`. Run all 7 Rust
   integration test targets to confirm cross-target compatibility.
2. Rebase `feat/v01-wasm-hok` onto `master`. Run `npm run build:wasm`
   and `npm run smoke:wasm` to verify the WASM artifact carries the
   new exports.
3. Rebase `feat/v01-ts-hok` onto `master`. Replace any remaining
   `__wasm-stub.ts` references with the real path. Run
   `npm test --workspaces` and the new `demo:llm-hok` (with API key
   set, manually). Confirm the screencast captures the visceral
   "bound to holder key, proof verified, scope held" path.

If a branch produced a conflict outside its ownership, the conflict
is the branch's fault and must be reverted there.
