/**
 * Indirection point for the underlying WASM module.
 *
 * For now this re-exports the in-tree stub at `./__wasm-stub`. At merge
 * time this single file is rewritten to:
 *
 *     export * from "../../../crates/capnagent-wasm/pkg/capnagent_wasm";
 *     export type * from "../../../crates/capnagent-wasm/pkg/capnagent_wasm";
 *
 * That is intentionally the only line that needs to change to swap in the
 * real wasm-pack output. See `docs/WEEK3_SPEC.md` §4.
 */

export * from "./__wasm-stub.js";
export type * from "./__wasm-stub.js";
