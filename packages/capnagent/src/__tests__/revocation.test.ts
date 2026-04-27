/**
 * Tests for the v0.3 RevocationList + Revoker + Verifier.withRevocationList
 * TS surface. Mirrors `nonce-store.test.ts`'s shape — uses real WASM, no
 * mocks, asserts the structural defense end-to-end.
 *
 * Round 04 of the purple-team corpus exercises the same defense path in
 * Rust. This test suite is the JS-side parity; once it lands, a TS-flavored
 * round 04 PoC becomes possible.
 */

import { describe, expect, it } from "vitest";

import {
  Auditor,
  CapabilityChainError,
  type Context,
  Issuer,
  RevocationList,
  Revoker,
  Verifier,
  init,
} from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xf1);
const WRONG_KEY = new Uint8Array(32).fill(0xf2);
const AUDIT_KEY = new Uint8Array(32).fill(0xf3);

const FUTURE = "now <= @2099-01-01T00:00:00Z";

async function fixture() {
  await init();
  const cap = Issuer.fromKey(ROOT_KEY)
    .issue("buy-revocation-test")
    .caveat(`caller == "agent:test"`)
    .caveat(`tool == "x"`)
    .caveat(FUTURE)
    .build();
  const ctx: Context = {
    caller: "agent:test",
    tool: "x",
    args: {},
    nowMs: 1_700_000_000_000,
  };
  const auditor = new Auditor(AUDIT_KEY);
  return { cap, ctx, auditor };
}

describe("@capnagent/core Revoker + RevocationList", () => {
  it("starts empty", async () => {
    await init();
    const rev = new Revoker(ROOT_KEY);
    expect(rev.size).toBe(0);
    expect(rev.isEmpty).toBe(true);
  });

  it("revoke is idempotent", async () => {
    await init();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("cap-1");
    rev.revoke("cap-1");
    rev.revoke("cap-2");
    expect(rev.size).toBe(2);
  });

  it("unrevoke returns true on hit, false on miss", async () => {
    await init();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("cap-1");
    expect(rev.unrevoke("cap-1")).toBe(true);
    expect(rev.unrevoke("cap-1")).toBe(false);
    expect(rev.size).toBe(0);
  });

  it("publish snapshots a signed RevocationList", async () => {
    await init();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("cap-a");
    rev.revoke("cap-b");
    const list = rev.publish(1_700_000_000_000);
    expect(list.size).toBe(2);
    expect(list.contains("cap-a")).toBe(true);
    expect(list.contains("cap-b")).toBe(true);
    expect(list.contains("cap-c")).toBe(false);
    expect(list.issuedAtMs).toBe(1_700_000_000_000);
  });

  it("RevocationList.serialize round-trips through parse", async () => {
    await init();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("cap-1");
    rev.revoke("cap-2");
    const list = rev.publish(1_700_000_000_000);
    const token = list.serialize();
    const parsed = RevocationList.parse(token);
    expect(parsed.size).toBe(2);
    expect(parsed.contains("cap-1")).toBe(true);
    expect(parsed.contains("cap-2")).toBe(true);
    expect(parsed.issuedAtMs).toBe(1_700_000_000_000);
  });

  it("publish rejects non-integer / negative issuedAtMs", async () => {
    await init();
    const rev = new Revoker(ROOT_KEY);
    expect(() => rev.publish(-1)).toThrow(/non-negative integer/);
    expect(() => rev.publish(1.5)).toThrow(/non-negative integer/);
  });
});

describe("Verifier.withRevocationList — install-time signature check", () => {
  it("installs cleanly when the list was signed under the verifier's root key", async () => {
    const { cap, ctx, auditor } = await fixture();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("buy-revocation-test");
    const list = rev.publish(1_700_000_000_000);

    const verifier = new Verifier(ROOT_KEY).withRevocationList(list);

    const r = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("denied");
    if (r.outcome.kind === "denied") {
      expect(r.outcome.reason).toBe("capability revoked: buy-revocation-test");
    }
  });

  it("THROWS CapabilityChainError when the list was signed under a DIFFERENT key", async () => {
    await init();
    // Forge a list signed under WRONG_KEY but try to install on a
    // verifier built with ROOT_KEY. Install must fail loudly — silent
    // bypass is the bad shape.
    const rev = new Revoker(WRONG_KEY);
    rev.revoke("buy-revocation-test");
    const list = rev.publish(1_700_000_000_000);

    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.withRevocationList(list)).toThrow(CapabilityChainError);
    expect(() => verifier.withRevocationList(list)).toThrow(/invalid revocation-list signature/);
  });

  it("a cap NOT in the list is allowed (negative hypothesis)", async () => {
    const { cap, ctx, auditor } = await fixture();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("some-other-cap");
    const list = rev.publish(1_700_000_000_000);

    const verifier = new Verifier(ROOT_KEY).withRevocationList(list);

    const r = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("allowed");
  });

  it("denial reason format is locked: 'capability revoked: <id>'", async () => {
    const { cap, ctx, auditor } = await fixture();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("buy-revocation-test");
    const list = rev.publish(1_700_000_000_000);

    const verifier = new Verifier(ROOT_KEY).withRevocationList(list);
    const r = verifier.verifyWithContext(cap, ctx, auditor);

    if (r.outcome.kind === "denied") {
      // Greppability lock — ops alerts will key on this prefix.
      expect(r.outcome.reason).toMatch(/^capability revoked: /);
      expect(r.outcome.reason).toBe("capability revoked: buy-revocation-test");
    }
  });

  it("withRevocationList chains with withNonceStore (multi-builder composition)", async () => {
    await init();
    const rev = new Revoker(ROOT_KEY);
    rev.revoke("doesnt-match");
    const list = rev.publish(1_700_000_000_000);

    // Both builders applied to the same Verifier in one chain.
    // Smoke-test that the consume-and-replace pattern doesn't lose
    // either install.
    const { NonceStore } = await import("../index.js");
    const store = new NonceStore();
    const verifier = new Verifier(ROOT_KEY).withRevocationList(list).withNonceStore(store);
    expect(verifier).toBeInstanceOf(Verifier);
  });
});
