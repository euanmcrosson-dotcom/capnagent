/**
 * Deterministic disposal (`dispose()` / `Symbol.dispose`).
 *
 * The GC reclaims WASM handles via wasm-bindgen's FinalizationRegistry, so
 * disposal is optional; these tests cover the eager-release path: it frees the
 * handle, is idempotent, and is wired to `Symbol.dispose` (so `using` works).
 */
import { beforeAll, describe, expect, it } from "vitest";
import { Issuer, Verifier, init } from "../index.js";

const KEY = new Uint8Array(32).fill(0x11);

beforeAll(async () => {
  await init();
});

function makeCap() {
  return Issuer.fromKey(KEY).issue("x").caveat('tool == "t"').build();
}

describe("deterministic disposal", () => {
  it("dispose() releases the handle; use-after-dispose throws", () => {
    const cap = makeCap();
    expect(cap.serialize()).toBeTypeOf("string"); // live before dispose
    cap.dispose();
    // The WASM handle is freed; touching it again is a use-after-free that
    // the wrapper surfaces as a thrown error rather than silent corruption.
    expect(() => cap.serialize()).toThrow();
  });

  it("dispose() is idempotent — double dispose does not throw or double-free", () => {
    const cap = makeCap();
    cap.dispose();
    expect(() => cap.dispose()).not.toThrow();
  });

  it("Symbol.dispose is wired to dispose() (so `using` releases at scope exit)", () => {
    const cap = makeCap();
    expect(typeof cap[Symbol.dispose]).toBe("function");
    cap[Symbol.dispose]();
    expect(() => cap.serialize()).toThrow();
    // Calling it again (as `using` + an explicit dispose would) is safe.
    expect(() => cap[Symbol.dispose]()).not.toThrow();
  });

  it("Verifier exposes idempotent disposal too", () => {
    const v = new Verifier(KEY);
    v.dispose();
    expect(() => v.dispose()).not.toThrow();
    expect(typeof v[Symbol.dispose]).toBe("function");
  });
});
