/**
 * End-to-end tests for the public `@capnagent` API.
 *
 * Strategy: mock `./wasm.js` with vitest so we can drive the wrapper
 * deterministically (no real WASM, no real cryptography). Each test
 * imports a fresh copy of `index.ts` via `vi.resetModules()` + dynamic
 * `import`, so the module-level `initPromise` / `ready` flags don't leak
 * across tests.
 *
 * Covers the §5 focus list for Terminal B:
 *   - init() idempotency + before-init guards
 *   - Each public class delegates to the mocked wasm correctly
 *   - verifyWithContext returns a translated, frozen Receipt
 *   - Auditor.verify round-trips a Receipt back to RawReceipt for the wasm side
 *   - Error mapping: chain message -> CapabilityChainError;
 *     audit message  -> CapabilityAuditError
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RawReceipt } from "../wasm.js";

// Hoisted mock state — tests can configure the mocks before each test.
const mocks = vi.hoisted(() => ({
  wasmInit: vi.fn(),
  issuerFromKey: vi.fn(),
  issuerIssue: vi.fn(),
  builderCaveat: vi.fn(),
  builderBuild: vi.fn(),
  builderHolderOfKey: vi.fn(),
  capParse: vi.fn(),
  capSerialize: vi.fn(),
  capAttenuate: vi.fn(),
  capHolderOfKey: vi.fn<() => Uint8Array | undefined>(() => undefined),
  verifierCtor: vi.fn(),
  verifierVerify: vi.fn(),
  verifierVerifyCtx: vi.fn(),
  verifierVerifyProof: vi.fn(),
  auditorCtor: vi.fn(),
  auditorVerify: vi.fn(),
  popChallengeFor: vi.fn<() => Uint8Array>(() => new Uint8Array(32).fill(0xc1)),
}));

// Mock-class design: the wrapper in `index.ts` calls instance methods on
// whatever wasm-side object the static factories return, so the mock
// classes ALWAYS return real instances of themselves. The `mocks.*` spies
// are pure call-recorders for arg/count assertions; tests that need to
// configure return values (e.g. `verifyWithContext` -> RawReceipt,
// `serialize` -> string) use `mockReturnValueOnce` on the relevant spy.
vi.mock("../wasm.js", () => {
  class WasmCapability {
    readonly identifier: string = "id-from-mock";
    static parse(token: string): WasmCapability {
      mocks.capParse(token);
      return new WasmCapability();
    }
    serialize(): string {
      return mocks.capSerialize() as string;
    }
    attenuate(predicate: string): WasmCapability {
      mocks.capAttenuate(predicate);
      return new WasmCapability();
    }
    get holderOfKey(): Uint8Array | undefined {
      return mocks.capHolderOfKey();
    }
    free(): void {
      /* no-op */
    }
  }
  class WasmCapabilityBuilder {
    caveat(predicate: string): WasmCapabilityBuilder {
      mocks.builderCaveat(predicate);
      return this;
    }
    holderOfKey(pubkey: Uint8Array): WasmCapabilityBuilder {
      mocks.builderHolderOfKey(pubkey);
      return this;
    }
    build(): WasmCapability {
      mocks.builderBuild();
      return new WasmCapability();
    }
    free(): void {
      /* no-op */
    }
  }
  class WasmIssuer {
    static fromKey(key: Uint8Array): WasmIssuer {
      mocks.issuerFromKey(key);
      return new WasmIssuer();
    }
    issue(identifier: string): WasmCapabilityBuilder {
      mocks.issuerIssue(identifier);
      return new WasmCapabilityBuilder();
    }
    free(): void {
      /* no-op */
    }
  }
  class WasmVerifier {
    constructor(key: Uint8Array) {
      mocks.verifierCtor(key);
    }
    verify(cap: WasmCapability): void {
      mocks.verifierVerify(cap);
    }
    verifyWithContext(cap: WasmCapability, ctx: unknown, auditor: WasmAuditor): RawReceipt {
      return mocks.verifierVerifyCtx(cap, ctx, auditor) as RawReceipt;
    }
    verifyWithProof(
      cap: WasmCapability,
      ctx: unknown,
      auditor: WasmAuditor,
      challenge: Uint8Array,
      proof: Uint8Array,
    ): RawReceipt {
      return mocks.verifierVerifyProof(cap, ctx, auditor, challenge, proof) as RawReceipt;
    }
    free(): void {
      /* no-op */
    }
  }
  class WasmAuditor {
    constructor(key: Uint8Array) {
      mocks.auditorCtor(key);
    }
    verify(receipt: RawReceipt): void {
      mocks.auditorVerify(receipt);
    }
    free(): void {
      /* no-op */
    }
  }
  return {
    init: mocks.wasmInit,
    Issuer: WasmIssuer,
    CapabilityBuilder: WasmCapabilityBuilder,
    Capability: WasmCapability,
    Verifier: WasmVerifier,
    Auditor: WasmAuditor,
    popChallengeFor: mocks.popChallengeFor,
  };
});

// Reset module state and mock call counts before each test so the
// `initPromise` / `ready` flags inside index.ts start from a clean slate.
beforeEach(() => {
  vi.resetModules();
  for (const m of Object.values(mocks)) {
    m.mockReset();
  }
});

async function loadFresh() {
  return import("../index.js");
}

const SAMPLE_RAW: RawReceipt = {
  version: 1,
  capability_identifier: "buy",
  caveats: [{ predicate: 'merchant == "amazon.com"' }],
  context_summary: {
    caller: "agent:planner",
    tool: "http.post",
    args_hash: "abc",
  },
  outcome: { kind: "allowed" },
  timestamp_ms: 42,
  signature: "deadbeef",
};

// ---------------------------------------------------------------------------
// init()
// ---------------------------------------------------------------------------

describe("init()", () => {
  it("must be called before any other API", async () => {
    const { Issuer, CapabilityError } = await loadFresh();
    expect(() => Issuer.fromKey(new Uint8Array(32))).toThrow(CapabilityError);
    expect(mocks.issuerFromKey).not.toHaveBeenCalled();
  });

  it("constructors also throw before init()", async () => {
    const { Verifier, Auditor, CapabilityError } = await loadFresh();
    expect(() => new Verifier(new Uint8Array(32))).toThrow(CapabilityError);
    expect(() => new Auditor(new Uint8Array(32))).toThrow(CapabilityError);
    expect(mocks.verifierCtor).not.toHaveBeenCalled();
    expect(mocks.auditorCtor).not.toHaveBeenCalled();
  });

  it("calling init() twice serially is a no-op the second time", async () => {
    const m = await loadFresh();
    await m.init();
    await m.init();
    await m.init();
    // wasm.init() must only run once. Idempotency is the contract.
    expect(mocks.wasmInit).toHaveBeenCalledTimes(1);
  });

  it("returns the same in-flight promise for parallel callers", async () => {
    const m = await loadFresh();
    const a = m.init();
    const b = m.init();
    expect(a).toBe(b);
    await Promise.all([a, b]);
    expect(mocks.wasmInit).toHaveBeenCalledTimes(1);
  });

  it("after init() resolves, every API can be used without throwing the not-initialized error", async () => {
    const m = await loadFresh();
    await m.init();
    expect(() => m.Issuer.fromKey(new Uint8Array(32))).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Public class delegation (post-init)
// ---------------------------------------------------------------------------

describe("Issuer / CapabilityBuilder / Capability delegation", () => {
  it("Issuer.fromKey forwards the key bytes to wasm.Issuer.fromKey", async () => {
    const m = await loadFresh();
    await m.init();
    const key = new Uint8Array([1, 2, 3, 4]);
    const issuer = m.Issuer.fromKey(key);
    expect(mocks.issuerFromKey).toHaveBeenCalledWith(key);
    expect(issuer).toBeInstanceOf(m.Issuer);
  });

  it("Issuer.issue -> CapabilityBuilder.caveat -> build round-trip", async () => {
    const m = await loadFresh();
    await m.init();
    const cap = m.Issuer.fromKey(new Uint8Array(32))
      .issue("buy")
      .caveat('merchant == "amazon.com"')
      .build();
    expect(mocks.issuerIssue).toHaveBeenCalledWith("buy");
    expect(mocks.builderCaveat).toHaveBeenCalledWith('merchant == "amazon.com"');
    expect(mocks.builderBuild).toHaveBeenCalledTimes(1);
    expect(cap).toBeInstanceOf(m.Capability);
  });

  it("Capability.parse / serialize / attenuate / identifier all delegate", async () => {
    const m = await loadFresh();
    await m.init();

    const cap = m.Capability.parse("token-abc");
    expect(mocks.capParse).toHaveBeenCalledWith("token-abc");

    mocks.capSerialize.mockReturnValueOnce("serialized!");
    expect(cap.serialize()).toBe("serialized!");

    const narrower = cap.attenuate("amount <= 50_usd");
    expect(mocks.capAttenuate).toHaveBeenCalledWith("amount <= 50_usd");
    expect(narrower).toBeInstanceOf(m.Capability);

    expect(cap.identifier).toBe("id-from-mock");
  });
});

describe("Verifier / Auditor delegation and Receipt translation", () => {
  it("Verifier(key) constructs the wasm verifier with the key", async () => {
    const m = await loadFresh();
    await m.init();
    const key = new Uint8Array([9, 8, 7]);
    new m.Verifier(key);
    expect(mocks.verifierCtor).toHaveBeenCalledWith(key);
  });

  it("Verifier.verify forwards the unwrapped capability to wasm", async () => {
    const m = await loadFresh();
    await m.init();
    const verifier = new m.Verifier(new Uint8Array(32));
    const cap = m.Capability.parse("tok");
    verifier.verify(cap);
    expect(mocks.verifierVerify).toHaveBeenCalledTimes(1);
    // The wrapper must hand the wasm-side instance, not the public wrapper.
    const handed = mocks.verifierVerify.mock.calls[0]?.[0];
    expect(handed).not.toBe(cap);
  });

  it("verifyWithContext returns a translated Receipt with frozen caveats", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyCtx.mockReturnValueOnce(SAMPLE_RAW);

    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    const cap = m.Capability.parse("tok");
    const receipt = verifier.verifyWithContext(
      cap,
      { caller: "agent:planner", tool: "http.post", args: {} },
      auditor,
    );

    expect(receipt.capabilityIdentifier).toBe("buy");
    expect(receipt.contextSummary.argsHash).toBe("abc");
    expect(receipt.timestampMs).toBe(42);
    expect(receipt.outcome).toEqual({ kind: "allowed" });
    expect(Object.isFrozen(receipt.caveats)).toBe(true);
  });

  it("verifyWithContext routes a denied outcome through unchanged", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyCtx.mockReturnValueOnce({
      ...SAMPLE_RAW,
      outcome: { kind: "denied", reason: "tool != http.post" },
    });

    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    const cap = m.Capability.parse("tok");
    const receipt = verifier.verifyWithContext(cap, { caller: "x", tool: "y", args: 1 }, auditor);
    expect(receipt.outcome).toEqual({ kind: "denied", reason: "tool != http.post" });
  });

  it("Auditor.verify hands the wasm side a snake_case RawReceipt (not the public Receipt)", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyCtx.mockReturnValueOnce(SAMPLE_RAW);

    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    const receipt = verifier.verifyWithContext(
      m.Capability.parse("tok"),
      { caller: "x", tool: "y", args: 1 },
      auditor,
    );
    auditor.verify(receipt);

    expect(mocks.auditorVerify).toHaveBeenCalledTimes(1);
    const handed = mocks.auditorVerify.mock.calls[0]?.[0] as RawReceipt;
    expect(handed.capability_identifier).toBe("buy");
    expect(handed.context_summary.args_hash).toBe("abc");
    expect(handed.timestamp_ms).toBe(42);
    // And no camelCase leaked back through.
    const asRecord = handed as unknown as Record<string, unknown>;
    expect(asRecord.capabilityIdentifier).toBeUndefined();
    expect(asRecord.timestampMs).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

describe("error mapping", () => {
  it("Verifier.verify -> CapabilityChainError on any wasm throw", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerify.mockImplementationOnce(() => {
      throw new Error("HMAC chain mismatch");
    });
    const verifier = new m.Verifier(new Uint8Array(32));
    const cap = m.Capability.parse("tok");
    expect(() => verifier.verify(cap)).toThrow(m.CapabilityChainError);
  });

  it("Auditor.verify -> CapabilityAuditError on any wasm throw", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyCtx.mockReturnValueOnce(SAMPLE_RAW);
    mocks.auditorVerify.mockImplementationOnce(() => {
      throw new Error("anything goes here");
    });

    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    const receipt = verifier.verifyWithContext(
      m.Capability.parse("tok"),
      { caller: "x", tool: "y", args: 1 },
      auditor,
    );
    expect(() => auditor.verify(receipt)).toThrow(m.CapabilityAuditError);
  });

  it("verifyWithContext: 'audit'/'signature' message -> CapabilityAuditError", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyCtx.mockImplementationOnce(() => {
      throw new Error("audit signature mismatch");
    });
    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    expect(() =>
      verifier.verifyWithContext(
        m.Capability.parse("tok"),
        { caller: "x", tool: "y", args: 1 },
        auditor,
      ),
    ).toThrow(m.CapabilityAuditError);
  });

  it("verifyWithContext: chain-keyword message -> CapabilityChainError", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyCtx.mockImplementationOnce(() => {
      throw new Error("HMAC chain failed under root key");
    });
    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    expect(() =>
      verifier.verifyWithContext(
        m.Capability.parse("tok"),
        { caller: "x", tool: "y", args: 1 },
        auditor,
      ),
    ).toThrow(m.CapabilityChainError);
  });

  it("error message is preserved in the mapped subclass", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerify.mockImplementationOnce(() => {
      throw new Error("specific original message");
    });
    const verifier = new m.Verifier(new Uint8Array(32));
    try {
      verifier.verify(m.Capability.parse("tok"));
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(m.CapabilityChainError);
      expect((err as Error).message).toBe("specific original message");
    }
  });

  it("non-Error throws are coerced to a CapabilityChainError-or-similar with String()ed message", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerify.mockImplementationOnce(() => {
      // Some wasm-bindgen builds throw raw strings or numbers.
      throw "raw string thrown";
    });
    const verifier = new m.Verifier(new Uint8Array(32));
    expect(() => verifier.verify(m.Capability.parse("tok"))).toThrow(m.CapabilityChainError);
  });
});

// ---------------------------------------------------------------------------
// v0.1 holder-of-key surface
// ---------------------------------------------------------------------------

describe("holder-of-key (v0.1)", () => {
  const PUB = new Uint8Array(32).fill(0x77);
  const CHALLENGE = new Uint8Array(32).fill(0xc1);
  const PROOF = new Uint8Array(64).fill(0x55);

  it("CapabilityBuilder.holderOfKey forwards the key bytes to wasm before any caveat()", async () => {
    const m = await loadFresh();
    await m.init();
    const cap = m.Issuer.fromKey(new Uint8Array(32))
      .issue("buy")
      .holderOfKey(PUB)
      .caveat(`tool == "checkout.purchase"`)
      .build();
    expect(mocks.builderHolderOfKey).toHaveBeenCalledTimes(1);
    expect(mocks.builderHolderOfKey).toHaveBeenCalledWith(PUB);
    // Ordering invariant: holderOfKey was registered before the first caveat.
    const hokOrder = mocks.builderHolderOfKey.mock.invocationCallOrder[0] ?? -1;
    const caveatOrder = mocks.builderCaveat.mock.invocationCallOrder[0] ?? -1;
    expect(hokOrder).toBeLessThan(caveatOrder);
    expect(cap).toBeInstanceOf(m.Capability);
  });

  it("Capability.holderOfKey getter returns the wasm-side bytes for hok tokens", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.capHolderOfKey.mockReturnValueOnce(PUB);
    const cap = m.Capability.parse("tok");
    expect(cap.holderOfKey).toEqual(PUB);
  });

  it("Capability.holderOfKey returns undefined for non-hok tokens", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.capHolderOfKey.mockReturnValueOnce(undefined);
    const cap = m.Capability.parse("tok");
    expect(cap.holderOfKey).toBeUndefined();
  });

  it("Verifier.verifyWithProof translates the raw receipt the same way verifyWithContext does", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyProof.mockReturnValueOnce(SAMPLE_RAW);

    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    const cap = m.Capability.parse("tok");
    const receipt = verifier.verifyWithProof(
      cap,
      { caller: "agent:planner", tool: "http.post", args: {} },
      auditor,
      CHALLENGE,
      PROOF,
    );

    expect(receipt.capabilityIdentifier).toBe("buy");
    expect(receipt.outcome).toEqual({ kind: "allowed" });
    expect(Object.isFrozen(receipt.caveats)).toBe(true);

    // Args were forwarded unwrapped — the wrapper hands wasm the inner
    // capability handle, the public ctx (camelCase), the inner auditor
    // handle, and the raw byte arrays.
    const call = mocks.verifierVerifyProof.mock.calls[0];
    expect(call?.[3]).toBe(CHALLENGE);
    expect(call?.[4]).toBe(PROOF);
  });

  it("Verifier.verifyWithProof routes a denied proof through unchanged", async () => {
    const m = await loadFresh();
    await m.init();
    mocks.verifierVerifyProof.mockReturnValueOnce({
      ...SAMPLE_RAW,
      outcome: { kind: "denied", reason: "holder-of-key proof failed" },
    });
    const verifier = new m.Verifier(new Uint8Array(32));
    const auditor = new m.Auditor(new Uint8Array(32));
    const r = verifier.verifyWithProof(
      m.Capability.parse("tok"),
      { caller: "x", tool: "y", args: 1 },
      auditor,
      CHALLENGE,
      PROOF,
    );
    expect(r.outcome).toEqual({ kind: "denied", reason: "holder-of-key proof failed" });
  });

  it("popChallengeFor delegates to the wasm free function and returns its bytes", async () => {
    const m = await loadFresh();
    await m.init();
    // mockReset() in beforeEach clears the default impl, so reinstate it here.
    mocks.popChallengeFor.mockReturnValueOnce(new Uint8Array(32).fill(0xc1));
    const ctx = { caller: "agent:planner", tool: "http.post", args: {} };
    const out = m.popChallengeFor(m.Capability.parse("tok"), ctx);
    expect(out).toEqual(new Uint8Array(32).fill(0xc1));
    expect(mocks.popChallengeFor).toHaveBeenCalledTimes(1);
  });

  it("popChallengeFor throws CapabilityError before init()", async () => {
    const m = await loadFresh();
    expect(() =>
      m.popChallengeFor(undefined as unknown as InstanceType<typeof m.Capability>, {
        caller: "x",
        tool: "y",
        args: 1,
      }),
    ).toThrow(m.CapabilityError);
  });
});
