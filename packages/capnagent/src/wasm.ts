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
