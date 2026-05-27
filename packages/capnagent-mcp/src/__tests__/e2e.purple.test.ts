/**
 * End-to-end purple-team tests: the MCP adapter driven against the REAL
 * capnagent engine (WASM), not the mock `fakeVerifier` used by the unit tests.
 *
 * The unit tests prove the adapter's control flow (inner-once, error
 * propagation, onReceipt resilience) with a mocked verifier — a mock that
 * returned `allowed` for everything would pass them. These tests close that
 * gap: a real `Issuer`-minted capability, a real `Verifier`/`Auditor`, real
 * caveat evaluation, and the actual attacks from `docs/purple-team/` driven
 * through `wrapMCPClient` / `guardCall`. The win condition is that the
 * underlying tool is NEVER invoked on a denied/forged call.
 */
import {
  Auditor,
  Capability,
  CapabilityChainError,
  Issuer,
  Revoker,
  Verifier,
  init,
} from "@capnagent/core";
import type { Context } from "@capnagent/core";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { CapabilityDeniedError, guardCall, wrapMCPClient } from "../index";
import type { WrapOptions } from "../index";

const ROOT = new Uint8Array(32).fill(0x07);
const AUDIT = new Uint8Array(32).fill(0x09);
const NOW = 1_700_000_000_000;

beforeAll(async () => {
  await init();
});

function ctxProvider(caller = "agent:planner"): WrapOptions["context"] {
  return (tool: string, args: unknown): Context => ({ caller, tool, args, nowMs: NOW });
}

function opts(capability: Capability, extra: Partial<WrapOptions> = {}): WrapOptions {
  return {
    capability,
    verifier: new Verifier(ROOT),
    auditor: new Auditor(AUDIT),
    context: ctxProvider(),
    ...extra,
  };
}

describe("e2e — adapter + real WASM engine", () => {
  it("round 01 — confused deputy: a path/tool-scoped cap denies the hijacked read; underlying never runs", async () => {
    const cap = Issuer.fromKey(ROOT)
      .issue("fs.read")
      .caveat('tool == "read_file"')
      .caveat('arg.path starts_with "/sandbox/"')
      .build();
    const callTool = vi.fn(async (_name: string, _args: unknown) => "FILE_CONTENTS");
    const client = wrapMCPClient({ callTool }, opts(cap));

    // In-sandbox read → allowed, underlying invoked once.
    await expect(client.callTool("read_file", { path: "/sandbox/notes.txt" })).resolves.toBe(
      "FILE_CONTENTS",
    );
    expect(callTool).toHaveBeenCalledTimes(1);

    // The injection's target (out of sandbox) → denied at the gate.
    await expect(
      client.callTool("read_file", { path: "/home/user/.ssh/id_rsa" }),
    ).rejects.toBeInstanceOf(CapabilityDeniedError);

    // Cross-tool hijack (different tool, in-sandbox path) → denied.
    await expect(
      client.callTool("delete_file", { path: "/sandbox/notes.txt" }),
    ).rejects.toBeInstanceOf(CapabilityDeniedError);

    // The two denials never reached the underlying tool.
    expect(callTool).toHaveBeenCalledTimes(1);
  });

  it("round 04 — revocation: a revoked cap is denied at the adapter; underlying never runs", async () => {
    const cap = Issuer.fromKey(ROOT)
      .issue("buy-123")
      .caveat('tool == "checkout.purchase"')
      .build();

    // Before revocation → allowed.
    const before = await guardCall(opts(cap), "checkout.purchase", {}, async () => "PURCHASED");
    expect(before.allowed).toBe(true);

    // Issuer revokes the id and publishes a signed list; verifier installs it.
    const revoker = new Revoker(ROOT);
    revoker.revoke("buy-123");
    const list = revoker.publish(NOW);
    const verifier = new Verifier(ROOT);
    verifier.withRevocationList(list);

    const inner = vi.fn(async () => "PURCHASED");
    const res = await guardCall(
      { capability: cap, verifier, auditor: new Auditor(AUDIT), context: ctxProvider() },
      "checkout.purchase",
      {},
      inner,
    );
    expect(res.allowed).toBe(false);
    if (!res.allowed) expect(res.reason.toLowerCase()).toContain("revok");
    expect(inner).not.toHaveBeenCalled();
  });

  it("round 03 — broadening: a tampered cap fails the chain; the adapter propagates (not remapped to a denial)", async () => {
    const cap = Issuer.fromKey(ROOT)
      .issue("checkout")
      .caveat('caller == "agent:planner"')
      .caveat('tool == "checkout.purchase"')
      .build();

    // Widen the tool caveat by editing the serialized token directly.
    const obj = JSON.parse(Buffer.from(cap.serialize(), "base64url").toString("utf8"));
    expect(obj.caveats[1].predicate).toBe('tool == "checkout.purchase"');
    obj.caveats[1].predicate = 'tool == "bank.wire"';
    const forged = Capability.parse(Buffer.from(JSON.stringify(obj), "utf8").toString("base64url"));

    const callTool = vi.fn(async (_name: string, _args: unknown) => "WIRED");
    const client = wrapMCPClient({ callTool }, opts(forged));

    // The widened predicate WOULD pass caveat eval — but the chain gate fires
    // first. The adapter surfaces it as CapabilityChainError (a crypto-integrity
    // failure), NOT a CapabilityDeniedError (an authorisation decision).
    await expect(client.callTool("bank.wire", {})).rejects.toBeInstanceOf(CapabilityChainError);
    await expect(client.callTool("bank.wire", {})).rejects.not.toBeInstanceOf(
      CapabilityDeniedError,
    );
    expect(callTool).not.toHaveBeenCalled();
  });

  it("allow path returns a real, audit-valid receipt", async () => {
    const cap = Issuer.fromKey(ROOT).issue("svc").caveat('tool == "t"').build();
    const auditor = new Auditor(AUDIT);
    const res = await guardCall(
      { capability: cap, verifier: new Verifier(ROOT), auditor, context: ctxProvider() },
      "t",
      {},
      async () => "ok",
    );
    expect(res.allowed).toBe(true);
    if (res.allowed) {
      expect(res.receipt.outcome.kind).toBe("allowed");
      // The receipt's audit signature verifies under the same audit key —
      // the adapter returns a genuine, tamper-evident decision record.
      expect(() => auditor.verify(res.receipt)).not.toThrow();
    }
  });
});
