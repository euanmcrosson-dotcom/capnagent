import { describe, expect, it, vi } from "vitest";

// See wrap.test.ts for the rationale; same module mock so
// `popChallengeFor` is deterministic and the real WASM is never loaded.
const POP_CHALLENGE_BYTES = new Uint8Array(32).fill(0xc1);
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
  return {
    CapabilityError,
    CapabilityChainError,
    CapabilityAuditError,
    popChallengeFor: vi.fn(() => POP_CHALLENGE_BYTES),
  };
});

import { CapabilityAuditError, CapabilityChainError } from "@capnagent/core";
import { MISSING_SIGNER_MESSAGE, type WrapOptions, guardCall } from "../guard";
import {
  TEST_PUBKEY,
  TEST_SIGNATURE,
  allowReceipt,
  denyReceipt,
  fakeAuditor,
  fakeCap,
  fakeCapability,
  fakeVerifier,
  sampleContext,
} from "./fixtures";

function baseOptions(
  verifier: ReturnType<typeof fakeVerifier>,
  extra: Partial<WrapOptions> = {},
): WrapOptions {
  return {
    capability: fakeCap,
    auditor: fakeAuditor,
    verifier,
    context: () => sampleContext(),
    ...extra,
  };
}

describe("guardCall", () => {
  it("returns { allowed: true, result, receipt } and invokes inner exactly once on allow", async () => {
    const inner = vi.fn().mockResolvedValue(42);
    const verifier = fakeVerifier(() => allowReceipt());

    const out = await guardCall(baseOptions(verifier), "http.post", { qty: 1 }, inner);

    expect(out.allowed).toBe(true);
    if (out.allowed) {
      // narrowing
      expect(out.result).toBe(42);
      expect(out.receipt.outcome).toEqual({ kind: "allowed" });
    }
    expect(inner).toHaveBeenCalledTimes(1);
  });

  it("returns { allowed: false, reason, receipt } WITHOUT invoking inner on deny", async () => {
    const inner = vi.fn();
    const verifier = fakeVerifier(() => denyReceipt("amount > 50_usd"));

    const out = await guardCall(baseOptions(verifier), "bank.wire", { to: "x" }, inner);

    expect(out.allowed).toBe(false);
    if (!out.allowed) {
      expect(out.reason).toBe("amount > 50_usd");
      expect(out.receipt.outcome).toEqual({ kind: "denied", reason: "amount > 50_usd" });
    }
    expect(inner).not.toHaveBeenCalled();
  });

  it("typed result narrowing: both branches of GuardedResult are reachable from tests", async () => {
    const verifier1 = fakeVerifier(() => allowReceipt());
    const a = await guardCall<string>(baseOptions(verifier1), "x", {}, async () => "yes");
    expect(a.allowed).toBe(true);
    if (a.allowed) {
      // statically narrow to { allowed: true; result: string; receipt }
      const upper: string = a.result.toUpperCase();
      expect(upper).toBe("YES");
    }

    const verifier2 = fakeVerifier(() => denyReceipt("nope"));
    const b = await guardCall<string>(baseOptions(verifier2), "x", {}, async () => "yes");
    expect(b.allowed).toBe(false);
    if (!b.allowed) {
      // statically narrow to { allowed: false; reason: string; receipt }
      const reason: string = b.reason;
      expect(reason).toBe("nope");
    }
  });

  it("propagates CapabilityChainError unchanged and does not invoke inner", async () => {
    const inner = vi.fn();
    const chainErr = new CapabilityChainError("bad chain");
    const verifier = fakeVerifier(() => {
      throw chainErr;
    });

    await expect(guardCall(baseOptions(verifier), "x", {}, inner)).rejects.toBe(chainErr);
    expect(inner).not.toHaveBeenCalled();
  });

  it("propagates CapabilityAuditError unchanged", async () => {
    const inner = vi.fn();
    const auditErr = new CapabilityAuditError("tampered");
    const verifier = fakeVerifier(() => {
      throw auditErr;
    });

    await expect(guardCall(baseOptions(verifier), "x", {}, inner)).rejects.toBe(auditErr);
    expect(inner).not.toHaveBeenCalled();
  });

  it("fires onReceipt for both allowed and denied paths", async () => {
    const onReceipt = vi.fn();

    const allowVerifier = fakeVerifier(() => allowReceipt());
    await guardCall(baseOptions(allowVerifier, { onReceipt }), "x", {}, async () => 1);
    expect(onReceipt).toHaveBeenCalledTimes(1);
    expect(onReceipt).toHaveBeenLastCalledWith(
      expect.objectContaining({ outcome: { kind: "allowed" } }),
    );

    const denyVerifier = fakeVerifier(() => denyReceipt("over budget"));
    await guardCall(baseOptions(denyVerifier, { onReceipt }), "x", {}, async () => 1);
    expect(onReceipt).toHaveBeenCalledTimes(2);
    expect(onReceipt).toHaveBeenLastCalledWith(
      expect.objectContaining({ outcome: { kind: "denied", reason: "over budget" } }),
    );
  });

  it("an onReceipt error does not block the inner call on allow", async () => {
    const inner = vi.fn().mockResolvedValue("ok");
    const verifier = fakeVerifier(() => allowReceipt());
    const onReceipt = vi.fn().mockRejectedValue(new Error("disk full"));
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const out = await guardCall(baseOptions(verifier, { onReceipt }), "x", {}, inner);

    expect(out.allowed).toBe(true);
    if (out.allowed) {
      expect(out.result).toBe("ok");
    }
    expect(inner).toHaveBeenCalledTimes(1);
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it("awaits an async ContextProvider before calling the verifier", async () => {
    const verifier = fakeVerifier(() => allowReceipt());
    const ctxFn = vi.fn(async (_name: string, _args: unknown) => sampleContext());
    const inner = vi.fn().mockResolvedValue("ok");

    await guardCall(baseOptions(verifier, { context: ctxFn }), "http.post", { qty: 1 }, inner);

    expect(ctxFn).toHaveBeenCalledWith("http.post", { qty: 1 });
    expect(verifier.verifyWithContext).toHaveBeenCalledTimes(1);
  });
});

describe("guardCall — holder-of-key (v0.1)", () => {
  it("hok-bound capability + signer: signer called with popChallengeFor output, verifyWithProof returns the receipt", async () => {
    const verifier = fakeVerifier(
      () => allowReceipt(),
      () => allowReceipt(),
    );
    const signer = vi.fn().mockResolvedValue(TEST_SIGNATURE);
    const inner = vi.fn().mockResolvedValue(42);

    const out = await guardCall(
      {
        capability: fakeCapability(TEST_PUBKEY),
        auditor: fakeAuditor,
        verifier,
        context: () => sampleContext(),
        signer,
      },
      "checkout.purchase",
      { qty: 1 },
      inner,
    );

    expect(out.allowed).toBe(true);
    if (out.allowed) {
      expect(out.result).toBe(42);
    }
    expect(signer).toHaveBeenCalledWith(POP_CHALLENGE_BYTES);
    expect(verifier.verifyWithProof).toHaveBeenCalledTimes(1);
    expect(verifier.verifyWithContext).not.toHaveBeenCalled();
    expect(inner).toHaveBeenCalledTimes(1);
  });

  it("hok-bound capability + denied proof: returns { allowed: false } without invoking inner", async () => {
    const denied = denyReceipt("holder-of-key proof failed");
    const verifier = fakeVerifier(
      () => allowReceipt(),
      () => denied,
    );
    const signer = vi.fn().mockResolvedValue(TEST_SIGNATURE);
    const inner = vi.fn();

    const out = await guardCall(
      {
        capability: fakeCapability(TEST_PUBKEY),
        auditor: fakeAuditor,
        verifier,
        context: () => sampleContext(),
        signer,
      },
      "x",
      {},
      inner,
    );

    expect(out.allowed).toBe(false);
    if (!out.allowed) {
      expect(out.reason).toBe("holder-of-key proof failed");
    }
    expect(inner).not.toHaveBeenCalled();
    expect(signer).toHaveBeenCalledTimes(1);
  });

  it("hok-bound capability without signer: rejects synchronously, never builds context, never invokes inner", async () => {
    const verifier = fakeVerifier(() => allowReceipt());
    const ctxFn = vi.fn(() => sampleContext());
    const inner = vi.fn();

    await expect(
      guardCall(
        {
          capability: fakeCapability(TEST_PUBKEY),
          auditor: fakeAuditor,
          verifier,
          context: ctxFn,
        },
        "x",
        {},
        inner,
      ),
    ).rejects.toThrow(MISSING_SIGNER_MESSAGE);

    expect(ctxFn).not.toHaveBeenCalled();
    expect(verifier.verifyWithProof).not.toHaveBeenCalled();
    expect(verifier.verifyWithContext).not.toHaveBeenCalled();
    expect(inner).not.toHaveBeenCalled();
  });

  it("non-hok capability still goes through verifyWithContext (unchanged path)", async () => {
    const verifier = fakeVerifier(() => allowReceipt());
    const inner = vi.fn().mockResolvedValue("ok");

    await guardCall(
      {
        capability: fakeCapability(undefined),
        auditor: fakeAuditor,
        verifier,
        context: () => sampleContext(),
      },
      "x",
      {},
      inner,
    );

    expect(verifier.verifyWithContext).toHaveBeenCalledTimes(1);
    expect(verifier.verifyWithProof).not.toHaveBeenCalled();
  });
});
