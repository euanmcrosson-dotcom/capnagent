import { describe, expect, it, vi } from "vitest";

// Mock `@capnagent/core` so:
//  - the runtime `popChallengeFor` returns a deterministic value the
//    hok tests can assert on, AND
//  - the test never has to load the real WASM artifact (which is a
//    workspace-wide concern, not this package's job to exercise).
//
// Type imports below (`Capability`, `Verifier`, etc.) are erased at
// runtime so the mock doesn't need to provide them.
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
import { CapabilityDeniedError } from "../errors";
import { type MCPClientLike, MISSING_SIGNER_MESSAGE, type WrapOptions } from "../guard";
import { wrapMCPClient } from "../wrap";
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

describe("wrapMCPClient — allow path", () => {
  it("invokes the underlying callTool exactly once and forwards its result", async () => {
    const inner = vi.fn().mockResolvedValue("checkout-ok");
    const verifier = fakeVerifier(() => allowReceipt());
    const onReceipt = vi.fn();

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { onReceipt }),
    );
    const out = await wrapped.callTool("http.post", { qty: 1, url: "https://amazon.com/cart" });

    expect(out).toBe("checkout-ok");
    expect(inner).toHaveBeenCalledTimes(1);
    expect(inner).toHaveBeenCalledWith("http.post", { qty: 1, url: "https://amazon.com/cart" });
    expect(onReceipt).toHaveBeenCalledTimes(1);
    expect(onReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: { kind: "allowed" } }),
    );
  });

  it("calls the verifier with the constructed context", async () => {
    const inner = vi.fn().mockResolvedValue(null);
    const verifier = fakeVerifier(() => allowReceipt());
    const ctxFn = vi.fn(() => sampleContext());

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { context: ctxFn }),
    );
    await wrapped.callTool("http.post", { qty: 1 });

    expect(ctxFn).toHaveBeenCalledTimes(1);
    expect(ctxFn).toHaveBeenCalledWith("http.post", { qty: 1 });
    expect(verifier.verifyWithContext).toHaveBeenCalledTimes(1);
    expect(verifier.verifyWithContext).toHaveBeenCalledWith(
      fakeCap,
      expect.objectContaining({ caller: "agent:planner", tool: "http.post" }),
      fakeAuditor,
    );
  });

  it("awaits an async ContextProvider", async () => {
    const inner = vi.fn().mockResolvedValue("ok");
    const verifier = fakeVerifier(() => allowReceipt());
    const ctxFn = vi.fn(async () => sampleContext());

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { context: ctxFn }),
    );
    await wrapped.callTool("http.post", {});

    expect(ctxFn).toHaveBeenCalledTimes(1);
    expect(verifier.verifyWithContext).toHaveBeenCalledTimes(1);
  });
});

describe("wrapMCPClient — deny path", () => {
  it("throws CapabilityDeniedError without invoking the underlying callTool", async () => {
    const inner = vi.fn();
    const verifier = fakeVerifier(() => denyReceipt("amount > 50_usd"));
    const onReceipt = vi.fn();

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { onReceipt }),
    );

    await expect(wrapped.callTool("bank.wire", { to: "attacker" })).rejects.toBeInstanceOf(
      CapabilityDeniedError,
    );
    expect(inner).not.toHaveBeenCalled();
    expect(onReceipt).toHaveBeenCalledTimes(1);
    expect(onReceipt).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: { kind: "denied", reason: "amount > 50_usd" } }),
    );
  });

  it("CapabilityDeniedError carries the full Receipt", async () => {
    const denied = denyReceipt("over budget");
    const verifier = fakeVerifier(() => denied);
    const wrapped = wrapMCPClient<MCPClientLike>({ callTool: vi.fn() }, baseOptions(verifier));

    try {
      await wrapped.callTool("x", {});
      expect.fail("should have thrown CapabilityDeniedError");
    } catch (err) {
      expect(err).toBeInstanceOf(CapabilityDeniedError);
      const e = err as CapabilityDeniedError;
      expect(e.receipt).toEqual(denied);
      expect(e.message).toBe("over budget");
      expect(e.name).toBe("CapabilityDeniedError");
    }
  });

  it("the deny-message falls back to a placeholder if outcome.kind is allowed (defensive)", () => {
    // We don't construct a "denied error from an allowed receipt" in the
    // adapter — but the constructor must be safe even if someone does.
    const oddReceipt = allowReceipt();
    const err = new CapabilityDeniedError(oddReceipt);
    expect(err.message).toBe("denied (no reason)");
    expect(err.receipt).toBe(oddReceipt);
  });
});

describe("wrapMCPClient — verifier error propagation", () => {
  it("propagates CapabilityChainError unchanged and does not invoke the underlying", async () => {
    const inner = vi.fn();
    const onReceipt = vi.fn();
    const chainErr = new CapabilityChainError("bad chain");
    const verifier = fakeVerifier(() => {
      throw chainErr;
    });

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { onReceipt }),
    );

    await expect(wrapped.callTool("x", {})).rejects.toBe(chainErr);
    expect(inner).not.toHaveBeenCalled();
    // No receipt was produced, so onReceipt MUST NOT fire.
    expect(onReceipt).not.toHaveBeenCalled();
  });

  it("propagates CapabilityAuditError unchanged", async () => {
    const auditErr = new CapabilityAuditError("tampered");
    const verifier = fakeVerifier(() => {
      throw auditErr;
    });
    const wrapped = wrapMCPClient<MCPClientLike>({ callTool: vi.fn() }, baseOptions(verifier));

    await expect(wrapped.callTool("x", {})).rejects.toBe(auditErr);
  });

  it("does NOT remap CapabilityChainError to CapabilityDeniedError", async () => {
    const chainErr = new CapabilityChainError("bad chain");
    const verifier = fakeVerifier(() => {
      throw chainErr;
    });
    const wrapped = wrapMCPClient<MCPClientLike>({ callTool: vi.fn() }, baseOptions(verifier));

    try {
      await wrapped.callTool("x", {});
      expect.fail("should have thrown");
    } catch (err) {
      expect(err).toBe(chainErr);
      expect(err).toBeInstanceOf(CapabilityChainError);
      expect(err).not.toBeInstanceOf(CapabilityDeniedError);
    }
  });
});

describe("wrapMCPClient — onReceipt resilience", () => {
  it("an exception in onReceipt does not block the underlying call (allow)", async () => {
    const inner = vi.fn().mockResolvedValue("ok");
    const verifier = fakeVerifier(() => allowReceipt());
    const onReceipt = vi.fn().mockRejectedValue(new Error("disk full"));
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { onReceipt }),
    );
    const out = await wrapped.callTool("x", {});

    expect(out).toBe("ok");
    expect(inner).toHaveBeenCalledTimes(1);
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it("an exception in onReceipt does not change the thrown CapabilityDeniedError (deny)", async () => {
    const inner = vi.fn();
    const verifier = fakeVerifier(() => denyReceipt("nope"));
    const onReceipt = vi.fn().mockRejectedValue(new Error("disk full"));
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { onReceipt }),
    );

    await expect(wrapped.callTool("x", {})).rejects.toBeInstanceOf(CapabilityDeniedError);
    expect(inner).not.toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it("a synchronously-thrown onReceipt error is also swallowed", async () => {
    const inner = vi.fn().mockResolvedValue(true);
    const verifier = fakeVerifier(() => allowReceipt());
    const onReceipt = vi.fn(() => {
      throw new Error("sync boom");
    });
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { onReceipt }),
    );
    const out = await wrapped.callTool("x", {});

    expect(out).toBe(true);
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it("works without an onReceipt callback at all", async () => {
    const inner = vi.fn().mockResolvedValue("ok");
    const verifier = fakeVerifier(() => allowReceipt());

    const wrapped = wrapMCPClient<MCPClientLike>({ callTool: inner }, baseOptions(verifier));
    await expect(wrapped.callTool("x", {})).resolves.toBe("ok");
  });
});

describe("wrapMCPClient — shape preservation", () => {
  it("the wrapped client is a drop-in replacement: extra methods on the input pass through", async () => {
    interface RichClient extends MCPClientLike {
      listTools(): Promise<string[]>;
      readonly serverName: string;
    }
    const verifier = fakeVerifier(() => allowReceipt());
    const inputClient: RichClient = {
      callTool: vi.fn().mockResolvedValue("ok"),
      listTools: vi.fn().mockResolvedValue(["http.post", "fs.read"]),
      serverName: "shopping-srv",
    };

    const wrapped = wrapMCPClient(inputClient, baseOptions(verifier));

    await expect(wrapped.callTool("http.post", {})).resolves.toBe("ok");
    await expect(wrapped.listTools()).resolves.toEqual(["http.post", "fs.read"]);
    expect(wrapped.serverName).toBe("shopping-srv");
  });
});

describe("wrapMCPClient — holder-of-key (v0.1)", () => {
  it("hok-bound capability + signer: signer is called with the popChallengeFor output, verifyWithProof is used", async () => {
    const inner = vi.fn().mockResolvedValue("checkout-ok");
    const verifier = fakeVerifier(
      () => allowReceipt(), // verifyWithContext should NOT be invoked on hok path
      () => allowReceipt(), // verifyWithProof returns allow
    );
    const signer = vi.fn().mockResolvedValue(TEST_SIGNATURE);

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { capability: fakeCapability(TEST_PUBKEY), signer }),
    );
    const out = await wrapped.callTool("checkout.purchase", { qty: 1 });

    expect(out).toBe("checkout-ok");
    expect(signer).toHaveBeenCalledTimes(1);
    expect(signer).toHaveBeenCalledWith(POP_CHALLENGE_BYTES);

    expect(verifier.verifyWithProof).toHaveBeenCalledTimes(1);
    expect(verifier.verifyWithContext).not.toHaveBeenCalled();

    // Inspect the arguments handed to verifyWithProof: cap, ctx, auditor,
    // challenge, proof. (Defensive — locks the call shape.)
    const call = (verifier.verifyWithProof as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call?.[3]).toBe(POP_CHALLENGE_BYTES);
    expect(call?.[4]).toBe(TEST_SIGNATURE);
  });

  it("hok-bound capability + signer returning a Uint8Array directly (sync) is supported", async () => {
    const inner = vi.fn().mockResolvedValue("ok");
    const verifier = fakeVerifier(
      () => allowReceipt(),
      () => allowReceipt(),
    );
    const signer = vi.fn(() => TEST_SIGNATURE); // not a Promise

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { capability: fakeCapability(TEST_PUBKEY), signer }),
    );
    await expect(wrapped.callTool("x", {})).resolves.toBe("ok");
    expect(verifier.verifyWithProof).toHaveBeenCalledTimes(1);
  });

  it("hok-bound capability without signer: wrapMCPClient throws synchronously, no Proxy returned", () => {
    const inner = vi.fn();
    const verifier = fakeVerifier(() => allowReceipt());
    expect(() =>
      wrapMCPClient<MCPClientLike>(
        { callTool: inner },
        baseOptions(verifier, { capability: fakeCapability(TEST_PUBKEY) }),
      ),
    ).toThrow(MISSING_SIGNER_MESSAGE);
    // Critically: the error fired BEFORE any callTool was issued.
    expect(inner).not.toHaveBeenCalled();
  });

  it("non-hok capability (holderOfKey === undefined) takes the v0 path even if a signer is supplied", async () => {
    const inner = vi.fn().mockResolvedValue("ok");
    const verifier = fakeVerifier(() => allowReceipt());
    const signer = vi.fn().mockResolvedValue(TEST_SIGNATURE);

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { capability: fakeCapability(undefined), signer }),
    );
    await wrapped.callTool("x", {});

    expect(verifier.verifyWithContext).toHaveBeenCalledTimes(1);
    expect(verifier.verifyWithProof).not.toHaveBeenCalled();
    expect(signer).not.toHaveBeenCalled();
  });

  it("hok deny path: a Receipt with kind: 'denied' becomes CapabilityDeniedError; underlying NOT called", async () => {
    const inner = vi.fn();
    const denied = denyReceipt("holder-of-key proof failed");
    const verifier = fakeVerifier(
      () => allowReceipt(),
      () => denied, // verifyWithProof returns a deny receipt
    );
    const signer = vi.fn().mockResolvedValue(TEST_SIGNATURE);

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { capability: fakeCapability(TEST_PUBKEY), signer }),
    );
    await expect(wrapped.callTool("x", {})).rejects.toBeInstanceOf(CapabilityDeniedError);
    expect(inner).not.toHaveBeenCalled();
    expect(signer).toHaveBeenCalledTimes(1);
  });

  it("hok path: signer that throws bubbles the error out, underlying NOT called", async () => {
    const inner = vi.fn();
    const verifier = fakeVerifier(
      () => allowReceipt(),
      () => allowReceipt(),
    );
    const signer = vi.fn(() => {
      throw new Error("hardware key unavailable");
    });

    const wrapped = wrapMCPClient<MCPClientLike>(
      { callTool: inner },
      baseOptions(verifier, { capability: fakeCapability(TEST_PUBKEY), signer }),
    );
    await expect(wrapped.callTool("x", {})).rejects.toThrow(/hardware key unavailable/);
    expect(inner).not.toHaveBeenCalled();
    expect(verifier.verifyWithProof).not.toHaveBeenCalled();
  });
});
