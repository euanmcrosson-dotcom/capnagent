/**
 * The wrapper's typed-error contract on the security-relevant failure paths.
 *
 * Every public method funnels WASM-boundary throws through `mapWasmError`,
 * which must surface a typed `CapabilityError` (never a raw wasm-bindgen
 * `Error` / `RuntimeError`) so consumers can discriminate failures and never
 * mistake a thrown error for an allow. These paths — ed25519 key validation,
 * the raw-JSON verify entry point (the A.1 f64 mitigation), and use-after-free
 * — are the ones a caller most needs to fail *closed* and *typed*. Behaviour
 * here was confirmed against the real WASM build before assertion.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { Auditor, Issuer, Verifier, init, popChallengeFor } from "../index.js";
import { CapabilityError } from "../errors.js";

const KEY = new Uint8Array(32).fill(0x11);
const AUDIT_KEY = new Uint8Array(16).fill(0x22);

beforeAll(async () => {
  await init();
});

describe("typed-error contract on security paths", () => {
  it("holderOfKey rejects a non-32-byte pubkey with a typed CapabilityError", () => {
    const builder = Issuer.fromKey(KEY).issue("x");
    // ed25519 public keys are exactly 32 bytes. A truncated key must be
    // rejected at binding time, typed, rather than producing a cap whose
    // proof check is undefined.
    let thrown: unknown;
    try {
      builder.holderOfKey(new Uint8Array(5));
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(CapabilityError);
    expect((thrown as Error).message).toContain("32 bytes");
  });

  it("verifyWithContextJson surfaces malformed JSON as a typed error, not an allow", () => {
    const cap = Issuer.fromKey(KEY).issue("x").caveat('tool == "t"').build();
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(KEY);
    // The raw-JSON path is the documented A.1 mitigation entry point. Garbage
    // input must throw a typed error — never return a receipt (which a caller
    // could mistake for an allow).
    expect(() => verifier.verifyWithContextJson(cap, "not json{", auditor)).toThrow(
      CapabilityError,
    );
  });

  it("verifyWithContextJson rejects structurally-valid JSON that is missing context fields", () => {
    const cap = Issuer.fromKey(KEY).issue("x").caveat('tool == "t"').build();
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(KEY);
    // `{}` parses but has no `caller`/`tool` — the deserializer must fail
    // closed (typed), not default the missing facts to something permissive.
    let thrown: unknown;
    try {
      verifier.verifyWithContextJson(cap, "{}", auditor);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(CapabilityError);
    expect((thrown as Error).message).toContain("caller");
  });

  it("popChallengeFor on a disposed capability throws a typed error (no silent UB)", () => {
    const cap = Issuer.fromKey(KEY).issue("y").caveat('tool == "t"').build();
    cap.dispose();
    // Using a freed handle is a programmer error; it must surface as a typed
    // throw at the wrapper boundary, not as undefined behaviour in WASM.
    expect(() => popChallengeFor(cap, { caller: "a", tool: "t", args: {} })).toThrow(
      CapabilityError,
    );
  });
});
