/**
 * Holder-of-key (v0.1) — deterministic shopping-agent tests.
 *
 * These exercise the hok wrapping path WITHOUT the live LLM and without
 * the real WASM `verifyWithProof` (Terminal B's `feat/v01-wasm-hok` is
 * not yet on master). `@capnagent/core` is mocked so the test:
 *
 *   1. Runs the real `wrapMCPClient` from `@capnagent/mcp` against the
 *      real mock shop.
 *   2. Uses real `@noble/ed25519` for keypair generation + signing — so
 *      the `signer` callback's wire format is exercised end-to-end.
 *   3. Configures a structurally-typed Verifier whose `verifyWithProof`
 *      returns receipts of our choice, simulating either a successful
 *      proof check or a corrupted-proof "holder-of-key proof failed"
 *      denial.
 *
 * Two invariants:
 *
 *   - HAPPY PATH: real signer → cable allowed, wire denied on caveat
 *     scope, `bank.wire` never reaches the underlying shop.
 *   - CORRUPT PROOF: signer returns 64 random bytes → cable AND wire
 *     denied with `holder-of-key proof failed`, `bank.wire` still
 *     never reaches the underlying shop.
 *
 * The second invariant is the v0.1 bit: even an *in-scope* cable
 * purchase fails when the proof is bad. The capability boundary is
 * cryptographic, not just policy-based.
 */

import { describe, expect, it, vi } from "vitest";

// ───────────────── @capnagent/core mock ─────────────────
//
// Functioning mock — `Issuer/CapabilityBuilder/Capability` actually
// build plain-object capabilities so the demo's hok issuance helpers
// work end-to-end. `Verifier.verifyWithProof` delegates to a hoisted
// mock that tests configure per-case.

const coreMocks = vi.hoisted(() => ({
  verifyWithProof: vi.fn(),
  verifyWithContext: vi.fn(),
  // Deterministic challenge: bytes derived from the cap identifier +
  // ctx.tool. Real verifier uses a SHA-256 of canonical-JSON; for the
  // mock, all that matters is that holder and verifier agree, and
  // popChallengeFor is the only entry point in the wrapper that
  // produces challenge bytes.
  popChallengeFor: vi.fn((cap: { identifier: string }, ctx: { tool: string }) => {
    const text = `${cap.identifier}|${ctx.tool}`;
    const out = new Uint8Array(32);
    const bytes = new TextEncoder().encode(text);
    out.set(bytes.subarray(0, Math.min(bytes.length, 32)));
    return out;
  }),
}));

vi.mock("@capnagent/core", () => {
  class CapabilityError extends Error {
    constructor(message?: string) {
      super(message);
      this.name = "CapabilityError";
    }
  }
  class CapabilityChainError extends CapabilityError {
    constructor(message?: string) {
      super(message);
      this.name = "CapabilityChainError";
    }
  }
  class CapabilityAuditError extends CapabilityError {
    constructor(message?: string) {
      super(message);
      this.name = "CapabilityAuditError";
    }
  }
  class Capability {
    constructor(
      public readonly identifier: string,
      public readonly holderOfKey: Uint8Array | undefined,
    ) {}
    serialize(): string {
      return `mock-token:${this.identifier}`;
    }
    attenuate(_predicate: string): Capability {
      return this;
    }
    static parse(_token: string): Capability {
      return new Capability("parsed", undefined);
    }
  }
  class CapabilityBuilder {
    private hok: Uint8Array | undefined;
    constructor(public readonly id: string) {}
    holderOfKey(pubkey: Uint8Array): CapabilityBuilder {
      this.hok = pubkey;
      return this;
    }
    caveat(_predicate: string): CapabilityBuilder {
      return this;
    }
    build(): Capability {
      return new Capability(this.id, this.hok);
    }
  }
  class Issuer {
    static fromKey(_key: Uint8Array): Issuer {
      return new Issuer();
    }
    issue(id: string): CapabilityBuilder {
      return new CapabilityBuilder(id);
    }
  }
  class Verifier {
    // biome-ignore lint/complexity/noUselessConstructor: documents the §3.2 ctor signature
    constructor(_key: Uint8Array) {}
    verify(_cap: Capability): void {
      /* no-op */
    }
    verifyWithContext(...args: unknown[]): unknown {
      return coreMocks.verifyWithContext(...args);
    }
    verifyWithProof(...args: unknown[]): unknown {
      return coreMocks.verifyWithProof(...args);
    }
  }
  class Auditor {
    // biome-ignore lint/complexity/noUselessConstructor: documents the §3.2 ctor signature
    constructor(_key: Uint8Array) {}
    verify(_receipt: unknown): void {
      /* no-op */
    }
  }
  return {
    Issuer,
    CapabilityBuilder,
    Capability,
    Verifier,
    Auditor,
    init: () => Promise.resolve(),
    popChallengeFor: coreMocks.popChallengeFor,
    CapabilityError,
    CapabilityChainError,
    CapabilityAuditError,
  };
});

import { Auditor, Verifier } from "@capnagent/core";
import { CapabilityDeniedError, type WrapOptions, wrapMCPClient } from "@capnagent/mcp";
import {
  generateHokKeyPair,
  issueHokBrowseCapability,
  issueHokBuyCapability,
  makeHokSigner,
} from "../llm-runner.js";
import { type CallLog, type Product, createMockShop } from "../shop.js";

// ───────────────── helpers ─────────────────

function allowReceipt(toolName: string): Record<string, unknown> {
  return {
    capabilityIdentifier: "buy",
    caveats: Object.freeze([Object.freeze({ predicate: 'merchant == "amazon.com"' })]),
    contextSummary: { caller: "agent:llm", tool: toolName, argsHash: "ab".repeat(32) },
    outcome: { kind: "allowed" },
    timestampMs: 0,
    signature: "00".repeat(32),
  };
}

function denyReceipt(toolName: string, reason: string): Record<string, unknown> {
  return {
    capabilityIdentifier: "buy",
    caveats: Object.freeze([Object.freeze({ predicate: 'merchant == "amazon.com"' })]),
    contextSummary: { caller: "agent:llm", tool: toolName, argsHash: "ab".repeat(32) },
    outcome: { kind: "denied", reason },
    timestampMs: 0,
    signature: "00".repeat(32),
  };
}

function makeOpts(args: {
  capability: ReturnType<typeof issueHokBuyCapability>;
  signer: NonNullable<WrapOptions["signer"]>;
  receipts: unknown[];
}): WrapOptions {
  return {
    capability: args.capability,
    auditor: new Auditor(new Uint8Array(32)),
    verifier: new Verifier(new Uint8Array(32)),
    context: (toolName: string, callArgs: unknown) => ({
      caller: "agent:llm",
      tool: toolName,
      args: callArgs,
      nowMs: 1,
    }),
    onReceipt: (r) => {
      args.receipts.push(r);
    },
    signer: args.signer,
  };
}

// ───────────────── tests ─────────────────

describe("hok scenario — happy path (real signer, mock verifier)", () => {
  it("real signer + valid proof: catalog allowed, cable allowed, wire denied, bank.wire never reaches shop", async () => {
    // Verifier behaviour: allow catalog.search and checkout.purchase,
    // deny anything else with a caveat-scope reason. (Mirrors the real
    // tool == "..." caveat without exercising the real WASM check.)
    coreMocks.verifyWithProof.mockImplementation((..._args: unknown[]) => {
      const ctx = _args[1] as { tool: string };
      if (ctx.tool === "catalog.search" || ctx.tool === "checkout.purchase") {
        return allowReceipt(ctx.tool);
      }
      return denyReceipt(ctx.tool, `tool != allowed-set; got "${ctx.tool}"`);
    });

    const { privateKey, publicKey } = await generateHokKeyPair();
    const browseCap = issueHokBrowseCapability(publicKey);
    const buyCap = issueHokBuyCapability(publicKey);
    const signer = vi.fn(makeHokSigner(privateKey));

    const receipts: unknown[] = [];
    const shop = createMockShop();
    const browseGuard = wrapMCPClient(shop, makeOpts({ capability: browseCap, signer, receipts }));
    const buyGuard = wrapMCPClient(shop, makeOpts({ capability: buyCap, signer, receipts }));

    // 1. search → allowed
    const products = (await browseGuard.callTool("catalog.search", {
      query: "usb-c cable",
    })) as Product[];
    const cable = products.find((p) => p.id === "usbc-cable-1m");
    expect(cable).toBeDefined();

    // 2. checkout → allowed
    await expect(
      buyGuard.callTool("checkout.purchase", {
        productId: cable?.id,
        amount: 20,
        merchant: "amazon.com",
      }),
    ).resolves.toBeDefined();

    // 3. bank.wire → denied (would also be denied by caveat scope, even
    //    if proof was OK)
    let wireErr: unknown;
    try {
      await buyGuard.callTool("bank.wire", { amount: 30, to: "bob@example.com" });
    } catch (e) {
      wireErr = e;
    }
    expect(wireErr).toBeInstanceOf(CapabilityDeniedError);

    // The signer was invoked once per tool call (browse + buy + wire)
    // — the hok plumbing is genuinely on the path of every invocation.
    expect(signer).toHaveBeenCalledTimes(3);

    // Underlying shop log: bank.wire must not appear.
    const wireCalls = shop.log.filter((c: CallLog) => c.tool === "bank.wire");
    expect(wireCalls).toEqual([]);

    // Three receipts (one per call) — the audit trail captures the
    // denied wire attempt too.
    expect(receipts.length).toBe(3);
  });
});

describe("hok scenario — corrupted proof (negative)", () => {
  it("signer returns random bytes: every guarded call denied with 'proof failed'; bank.wire never reaches shop", async () => {
    // Verifier behaviour: detect the corrupting signer's sentinel byte
    // in the proof and respond as the real ed25519-dalek verifier
    // would — `holder-of-key proof failed`. Anything else allowed.
    coreMocks.verifyWithProof.mockImplementation((..._args: unknown[]) => {
      const ctx = _args[1] as { tool: string };
      const proof = _args[4] as Uint8Array;
      if (proof[0] === 0xde && proof[1] === 0xad) {
        return denyReceipt(ctx.tool, "holder-of-key proof failed");
      }
      // Should be unreachable in this test; if hit, allow so the test
      // fails on the wire-call invariant instead of on a missing return.
      return allowReceipt(ctx.tool);
    });

    const { publicKey } = await generateHokKeyPair();
    const buyCap = issueHokBuyCapability(publicKey);
    // Sentinel-prefixed garbage signature — every signer invocation
    // returns the same 64 bytes starting with 0xDE 0xAD.
    const corruptingSigner = vi.fn(async (_challenge: Uint8Array) => {
      const out = new Uint8Array(64);
      out[0] = 0xde;
      out[1] = 0xad;
      for (let i = 2; i < 64; i++) out[i] = 0xff;
      return out;
    });

    const receipts: unknown[] = [];
    const shop = createMockShop();
    const buyGuard = wrapMCPClient(
      shop,
      makeOpts({ capability: buyCap, signer: corruptingSigner, receipts }),
    );

    // Even a fully in-scope cable purchase fails: the proof is bad.
    let cableErr: unknown;
    try {
      await buyGuard.callTool("checkout.purchase", {
        productId: "usbc-cable-1m",
        amount: 20,
        merchant: "amazon.com",
      });
    } catch (e) {
      cableErr = e;
    }
    expect(cableErr).toBeInstanceOf(CapabilityDeniedError);
    expect((cableErr as CapabilityDeniedError).message).toMatch(/proof failed/);

    // bank.wire is also denied (would have been denied by caveat scope
    // anyway, but here the proof check fires first).
    let wireErr: unknown;
    try {
      await buyGuard.callTool("bank.wire", { amount: 30, to: "attacker@evil.example" });
    } catch (e) {
      wireErr = e;
    }
    expect(wireErr).toBeInstanceOf(CapabilityDeniedError);
    expect((wireErr as CapabilityDeniedError).message).toMatch(/proof failed/);

    // The corrupting signer was actually invoked — the wrapper went
    // through the hok branch, not the v0 fallback.
    expect(corruptingSigner).toHaveBeenCalledTimes(2);
    // First call's challenge is the popChallengeFor output for the
    // (cap=buy, ctx={ tool: "checkout.purchase" }) pair.
    const firstChallenge = corruptingSigner.mock.calls[0]?.[0];
    expect(firstChallenge).toBeInstanceOf(Uint8Array);
    expect(firstChallenge).toHaveLength(32);

    // The load-bearing invariant: bank.wire never reaches the
    // underlying mock shop, even with a corrupted proof.
    const wireCalls = shop.log.filter((c: CallLog) => c.tool === "bank.wire");
    expect(wireCalls).toEqual([]);

    // checkout.purchase is also missing from the shop log — the proof
    // check denied an in-scope call.
    const purchaseCalls = shop.log.filter((c: CallLog) => c.tool === "checkout.purchase");
    expect(purchaseCalls).toEqual([]);

    // Two denied receipts (one per failed call), each carrying the
    // proof-failed reason.
    expect(receipts).toHaveLength(2);
    for (const r of receipts) {
      const outcome = (r as { outcome: { kind: string; reason?: string } }).outcome;
      expect(outcome.kind).toBe("denied");
      expect(outcome.reason).toMatch(/proof failed/);
    }
  });

  it("hok config without signer: wrapMCPClient throws synchronously, never reaches shop", () => {
    // Build a hok-bound capability through the mocked Issuer chain.
    // The wrap call should fail at config time — no shop, no LLM, no
    // verifier call.
    const buyCap = issueHokBuyCapability(new Uint8Array(32).fill(0x77));
    const shop = createMockShop();
    expect(() =>
      wrapMCPClient(shop, {
        capability: buyCap,
        auditor: new Auditor(new Uint8Array(32)),
        verifier: new Verifier(new Uint8Array(32)),
        context: () => ({
          caller: "agent:llm",
          tool: "checkout.purchase",
          args: {},
        }),
        // signer intentionally omitted
      }),
    ).toThrow(/holder key but no signer was provided/);
    expect(shop.log).toEqual([]);
  });
});
