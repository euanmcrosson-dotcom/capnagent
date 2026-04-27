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
