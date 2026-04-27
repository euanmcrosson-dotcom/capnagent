/**
 * Indirection point for the underlying WASM module.
 *
 * Resolves to the wasm-pack output produced by `npm run build:wasm` at
 * the repo root. Run that once after a fresh clone — the `pkg/`
 * directory is gitignored, by design, so the build artifact stays
 * out of version control.
 */

export * from "../../../crates/capnagent-wasm/pkg/capnagent_wasm.js";
export type * from "../../../crates/capnagent-wasm/pkg/capnagent_wasm.js";

/**
 * v0.1 holder-of-key surface, declared here pending the merge of
 * `feat/v01-wasm-hok` (Terminal B). The wasm-pack-generated `.d.ts` does
 * not yet carry these items; module augmentation merges the new
 * methods/getter onto the existing wasm-bindgen classes and adds the
 * top-level `popChallengeFor` free function.
 *
 * Field/method names mirror `docs/V0_1_SPEC.md` §3.2 exactly. At merge
 * time the generated `.d.ts` will declare these directly and this whole
 * augmentation block can be deleted in the same merge step.
 */
declare module "../../../crates/capnagent-wasm/pkg/capnagent_wasm.js" {
  interface CapabilityBuilder {
    /**
     * Bind the in-progress capability to an ed25519 holder-of-key public
     * key (32 raw bytes). Must be called BEFORE any `caveat()` — the
     * Rust core asserts hok-first ordering and will throw otherwise.
     */
    holderOfKey(pubkey: Uint8Array): CapabilityBuilder;
  }
  interface Capability {
    /**
     * Returns the bound ed25519 public key (32 bytes) or `undefined`
     * for non-hok tokens. Folded into the HMAC chain at issuance, so
     * the binding cannot be added/changed after the fact.
     */
    readonly holderOfKey: Uint8Array | undefined;
  }
  interface Verifier {
    /**
     * Four-gate pipeline: chain → proof → revocation → caveats. Returns
     * the same wire-format `RawReceipt` shape as `verifyWithContext`.
     * `proof` is a 64-byte ed25519 signature over `challenge` produced
     * by the holder.
     *
     * Bad proofs become `Outcome::Denied` (audit-loggable) — they are
     * not thrown.
     */
    verifyWithProof(
      cap: Capability,
      ctx: unknown,
      auditor: Auditor,
      challenge: Uint8Array,
      proof: Uint8Array,
    ): RawReceipt;
  }
  /**
   * Default proof-of-possession challenge derivation:
   * `SHA-256(canonical-JSON({ id, tool, args_hash, now_ms }))`.
   * Holder and verifier MUST agree bytewise — that is the whole point.
   */
  function popChallengeFor(cap: Capability, ctx: unknown): Uint8Array;
}

/**
 * Wire-format receipt as it comes back from the WASM boundary, before
 * `translate.rawReceiptToReceipt` reshapes it into the public API.
 *
 * Field names follow the Rust-side serde defaults (snake_case) — the
 * wasm-bindgen-generated `.d.ts` does not declare a TypeScript type for
 * this shape because `serde_wasm_bindgen` produces it as a plain
 * `JsValue`. Declaring it here keeps the wire format documented and
 * type-checked at the only point where capnagent ever names it.
 *
 * Locked by `docs/WEEK3_SPEC.md` §3.1.
 */
export interface RawReceipt {
  capability_identifier: string;
  caveats: Array<{ predicate: string }>;
  context_summary: {
    caller: string;
    tool: string;
    args_hash: string;
  };
  outcome: { kind: "allowed" } | { kind: "denied"; reason: string };
  timestamp_ms: number;
  signature: string;
}
