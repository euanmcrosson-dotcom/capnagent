/**
 * NonceStore + Verifier replay protection — uses the REAL WASM
 * artifact, not a mock. The whole point is to confirm the JS surface
 * actually exercises the v0.1 replay path end-to-end.
 *
 * Strategy:
 *   1. Issue an hok-bound capability + sign a real ed25519 challenge
 *      with `@noble/ed25519`.
 *   2. Verify with proof — first call allowed, NonceStore now non-empty.
 *   3. Replay the same proof bytes — second call denied with
 *      `proof replay detected`.
 *   4. clear() the store — third call (same bytes) allowed again.
 *   5. TTL boundary — withNonceTtlMs(0) makes every recorded entry
 *      already-expired, so replays go through.
 */

import { describe, expect, it } from "vitest";

// `@noble/ed25519` is a transitive dep via the shopping-agent example;
// importing here keeps this test colocated with the surface it tests.
// If we ever decouple, we'll vendor a small ed25519 helper inline.
import * as ed from "@noble/ed25519";

import {
  Auditor,
  type Context,
  Issuer,
  NonceStore,
  Verifier,
  init,
  popChallengeFor,
} from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xd1);
const AUDIT_KEY = new Uint8Array(32).fill(0xd2);
const HOLDER_SECRET = new Uint8Array(32).fill(0xd3);

async function makeFixture() {
  await init();
  // Use the async path: it backs onto Web Crypto's SubtleCrypto and
  // doesn't require configuring `ed.etc.sha512Sync`.
  const publicKey = await ed.getPublicKeyAsync(HOLDER_SECRET);
  const cap = Issuer.fromKey(ROOT_KEY)
    .issue("hok-replay-test")
    .holderOfKey(publicKey)
    .caveat(`tool == "x"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
  const ctx: Context = {
    caller: "agent:test",
    tool: "x",
    args: { n: 1 },
    nowMs: 1_700_000_000_000,
  };
  const auditor = new Auditor(AUDIT_KEY);
  const challenge = popChallengeFor(cap, ctx);
  const proof = await ed.signAsync(challenge, HOLDER_SECRET);
  return { cap, ctx, auditor, challenge, proof };
}

describe("@capnagent/core NonceStore", () => {
  it("starts empty", async () => {
    await init();
    const store = new NonceStore();
    expect(store.size).toBe(0);
    expect(store.isEmpty).toBe(true);
  });

  it("clear() empties the store", async () => {
    await init();
    const store = new NonceStore();
    expect(store.isEmpty).toBe(true);
    store.clear();
    expect(store.isEmpty).toBe(true);
  });
});

describe("Verifier with NonceStore — replay protection", () => {
  it("first call allowed, replay denied with `proof replay detected`", async () => {
    const { cap, ctx, auditor, challenge, proof } = await makeFixture();
    const store = new NonceStore();
    const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

    const r1 = verifier.verifyWithProof(cap, ctx, auditor, challenge, proof);
    expect(r1.outcome.kind).toBe("allowed");
    expect(store.size).toBe(1);

    const r2 = verifier.verifyWithProof(cap, ctx, auditor, challenge, proof);
    expect(r2.outcome.kind).toBe("denied");
    if (r2.outcome.kind === "denied") {
      expect(r2.outcome.reason).toBe("proof replay detected");
    }
    // Replay should NOT add a new entry — the existing one stands.
    expect(store.size).toBe(1);
  });

  it("clearing the store lets the same proof through again", async () => {
    const { cap, ctx, auditor, challenge, proof } = await makeFixture();
    const store = new NonceStore();
    const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

    expect(verifier.verifyWithProof(cap, ctx, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
    expect(verifier.verifyWithProof(cap, ctx, auditor, challenge, proof).outcome.kind).toBe(
      "denied",
    );

    store.clear();
    expect(store.isEmpty).toBe(true);

    expect(verifier.verifyWithProof(cap, ctx, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
  });

  it("withNonceTtlMs(0) makes entries immediately expired — replays go through", async () => {
    const { cap, ctx, auditor, challenge, proof } = await makeFixture();
    const store = new NonceStore();
    const verifier = new Verifier(ROOT_KEY).withNonceStore(store).withNonceTtlMs(0);

    // TTL of 0 → every recorded entry's expiry is `now`, which is not
    // strictly greater than `now`, so the next try_record sees the
    // entry as already-expired. Both calls are allowed.
    expect(verifier.verifyWithProof(cap, ctx, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
    expect(verifier.verifyWithProof(cap, ctx, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
  });

  it("rejects a negative TTL with CapabilityError", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.withNonceTtlMs(-1)).toThrow(/non-negative integer/);
  });

  it("rejects a non-integer TTL with CapabilityError", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.withNonceTtlMs(1.5)).toThrow(/non-negative integer/);
  });

  it("without a NonceStore, replays still go through (no replay protection by default)", async () => {
    const { cap, ctx, auditor, challenge, proof } = await makeFixture();
    const verifier = new Verifier(ROOT_KEY);
    expect(verifier.verifyWithProof(cap, ctx, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
    expect(verifier.verifyWithProof(cap, ctx, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
  });
});
