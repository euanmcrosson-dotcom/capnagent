/**
 * Indirection point for the underlying WASM module.
 *
 * Resolves to the `--target nodejs` wasm-pack output vendored into this
 * package's `wasm/` directory by `npm run build:wasm:node` (run from the
 * repo root). The nodejs target loads the `.wasm` synchronously via
 * `fs.readFileSync` at import time, so the published package runs in plain
 * Node with no bundler. The same path resolves identically from `src/`
 * (tests) and `dist/` (published), since both sit one level under the
 * package root alongside `wasm/`. `wasm/` is gitignored (a build artifact)
 * but shipped in the npm tarball via the `files` allowlist.
 */

export * from "../wasm/capnagent_wasm.js";
export type * from "../wasm/capnagent_wasm.js";

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
  /**
   * Receipt schema version. Currently always `1`. See Rust-side
   * `docs/DESIGN.md` §14 — the verifier rejects unknown versions
   * fail-closed.
   */
  version: number;
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
