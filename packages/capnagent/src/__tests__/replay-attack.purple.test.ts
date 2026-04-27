/**
 * Purple-team PoC for `docs/purple-team/02-replay-attack-on-hok-bound-cap.md`.
 *
 * Round 02 fires the `replay ✗` gate column. The structural defense:
 * a `NonceStore` records `sha256(proof_bytes)` of every accepted
 * proof; subsequent attempts to use the same proof bytes within
 * `nonce_ttl_ms` are denied with reason `"proof replay detected"`.
 *
 * # Threat model (one paragraph)
 *
 * An attacker captures a hok-bound capability + ed25519 proof
 * mid-flight (compromised TLS-terminating proxy, malicious downstream
 * adapter, debug-logged middleware, etc.) and replays both bytes-for-
 * bytes to perform the same authorized action a second time. Without
 * replay protection, this works — the proof is valid, the chain is
 * valid, and the caveats still hold; the verifier has no way to know
 * the holder didn't sign two identical requests intentionally.
 *
 * # Why this test bypasses the wrapper
 *
 * `wrapMCPClient`'s default flow signs a fresh proof per call via the
 * `signer` callback, so identical proof bytes never cross the wire
 * in practice. The threat model assumes the attacker has the bytes
 * already — captured from a previous legitimate call. We model that
 * by holding `now_ms` constant across the two presentations, which
 * makes the derived challenge identical and lets us reuse the same
 * pre-computed signature. That's the closest in-process analogue to
 * "captured-and-replayed."
 *
 * # What the test does NOT cover (cross-reference round doc)
 *
 *   - Cross-process / distributed replay (one verifier accepts, a
 *     parallel verifier with a different in-memory store accepts the
 *     same bytes). Requires Redis-backed `NonceStore`; out of scope
 *     for v0.2.
 *   - TTL-edge replay (caller waits TTL+1ms before replaying).
 *     Capability resistance against this is operator's choice of TTL.
 *   - Adversarial clock control (verifier reads system time and
 *     attacker can rewind it). Out of scope.
 */

import { describe, expect, it } from "vitest";

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

const ROOT_KEY = new Uint8Array(32).fill(0xe1);
const AUDIT_KEY = new Uint8Array(32).fill(0xe2);
const HOLDER_SECRET = new Uint8Array(32).fill(0xe3);

/** Frozen now_ms — keeps the challenge identical across replays. */
const FROZEN_NOW_MS = 1_700_000_000_000;

interface CapturedRequest {
  cap: Awaited<ReturnType<typeof issueHokCap>>;
  ctx: Context;
  challenge: Uint8Array;
  proof: Uint8Array;
}

async function issueHokCap() {
  await init();
  const publicKey = await ed.getPublicKeyAsync(HOLDER_SECRET);
  return Issuer.fromKey(ROOT_KEY)
    .issue("buy-replay-test")
    .holderOfKey(publicKey)
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

/** Simulates a captured legitimate request the attacker now has bytes for. */
async function captureLegitRequest(): Promise<CapturedRequest> {
  const cap = await issueHokCap();
  const ctx: Context = {
    caller: "agent:planner",
    tool: "checkout.purchase",
    args: { merchant: "amazon.com", amount: 20 },
    nowMs: FROZEN_NOW_MS,
  };
  const challenge = popChallengeFor(cap, ctx);
  const proof = await ed.signAsync(challenge, HOLDER_SECRET);
  return { cap, ctx, challenge, proof };
}

describe("Round 02: Replay attack on hok-bound capability", () => {
  describe("structural defense (NonceStore installed, ttl_ms = default)", () => {
    it("first presentation of the captured proof is ALLOWED (positive hypothesis)", async () => {
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

      const r = verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(r.outcome.kind).toBe("allowed");
      expect(store.size).toBe(1);
    });

    it("re-presenting the SAME proof bytes within TTL is DENIED with 'proof replay detected'", async () => {
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

      // Run 1 — legit. Verifier accepts and records the nonce.
      const first = verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(first.outcome.kind).toBe("allowed");

      // Run 2 — REPLAY. Attacker presents the same bytes. Verifier
      // recognizes sha256(proof) as already-seen and denies on
      // replay grounds. This is the gate that fires.
      const replayed = verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(replayed.outcome.kind).toBe("denied");
      if (replayed.outcome.kind === "denied") {
        expect(replayed.outcome.reason).toBe("proof replay detected");
      }

      // Replay does not refresh the existing entry's expiry.
      expect(store.size).toBe(1);
    });

    it("a FRESH proof for the same cap (different now_ms) is ALLOWED — defense doesn't over-tighten (negative hypothesis)", async () => {
      const cap = await issueHokCap();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

      // Two distinct legitimate calls, distinct now_ms → distinct
      // challenges → distinct signatures → distinct nonces. Both
      // should be allowed.
      const ctx1: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 20 },
        nowMs: 1_700_000_000_000,
      };
      const ctx2: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 30 },
        nowMs: 1_700_000_000_005,
      };
      const ch1 = popChallengeFor(cap, ctx1);
      const ch2 = popChallengeFor(cap, ctx2);
      const sig1 = await ed.signAsync(ch1, HOLDER_SECRET);
      const sig2 = await ed.signAsync(ch2, HOLDER_SECRET);

      expect(verifier.verifyWithProof(cap, ctx1, auditor, ch1, sig1).outcome.kind).toBe("allowed");
      expect(verifier.verifyWithProof(cap, ctx2, auditor, ch2, sig2).outcome.kind).toBe("allowed");
      expect(store.size).toBe(2);
    });

    it("replay denial short-circuits BEFORE caveat evaluation (gate ordering)", async () => {
      // The deny reason on a replay is "proof replay detected", not
      // "caveat failed: ...". That confirms the replay leg fires
      // before the caveat leg — which matters because if a captured
      // proof's cap had since expired (now > caveat date), an
      // attacker shouldn't get a confused-but-helpful "caveat failed
      // because expiry" leak. Replay denial precludes any further
      // evaluation; the audit log shows replay attempt unambiguously.
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

      // Accept the first call (records the nonce).
      verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );

      // Replay. Reason is exactly the replay reason — not the
      // caveat reason — even though the caveat would have evaluated
      // identically.
      const replayed = verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(replayed.outcome.kind).toBe("denied");
      if (replayed.outcome.kind === "denied") {
        expect(replayed.outcome.reason).toBe("proof replay detected");
        expect(replayed.outcome.reason).not.toMatch(/caveat failed/);
      }
    });
  });

  describe("audit trail", () => {
    it("ten replay attempts each produce a signed denial receipt — and the receipts are byte-identical because inputs are byte-identical (operational finding)", async () => {
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

      // Establish the nonce in the store.
      verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );

      // Attacker hammers the same bytes ten more times. Each call
      // produces a denial receipt — that's the audit-loggability
      // property.
      const denials: Array<{ reason: string; signature: string }> = [];
      for (let i = 0; i < 10; i++) {
        const r = verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        );
        expect(r.outcome.kind).toBe("denied");
        if (r.outcome.kind === "denied") {
          denials.push({ reason: r.outcome.reason, signature: r.signature });
        }
      }

      expect(denials).toHaveLength(10);
      for (const d of denials) {
        expect(d.reason).toBe("proof replay detected");
        expect(d.signature.length).toBeGreaterThan(0);
      }

      // OPERATIONAL FINDING (round-02 surface):
      //
      // Under identical inputs (same cap + same ctx + same outcome),
      // the canonical-JSON serialized receipt is byte-identical, so
      // the HMAC signature is byte-identical. That's correct HMAC
      // behavior — same input, same MAC.
      //
      // Implication for ops:
      //   - DO count replay attempts at the wrapper / call-site
      //     layer (one event per `callTool` invocation).
      //   - Do NOT count at the audit-log dedup layer (unique
      //     receipt hashes will collapse to 1, hiding the burst).
      //   - Idempotency / cache layers downstream can safely dedup
      //     by receipt hash without losing security signal — but
      //     SHOULD log the dedup count.
      const uniqueSigs = new Set(denials.map((d) => d.signature));
      expect(uniqueSigs.size).toBe(1);
    });
  });

  describe("residual risk (honest acknowledgment of what this defense does NOT cover)", () => {
    it("withNonceTtlMs(0) makes every entry already-expired — replay goes through", async () => {
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store).withNonceTtlMs(0);

      // First call: record nonce with expiry == now → expires immediately.
      expect(
        verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        ).outcome.kind,
      ).toBe("allowed");

      // Replay: try_record sees the existing entry as already-expired
      // and accepts. Documents that operator's TTL choice is
      // load-bearing — too short means no replay protection at all.
      expect(
        verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        ).outcome.kind,
      ).toBe("allowed");
    });

    it("clearing the store lets the same proof through — operator must not auto-clear in prod", async () => {
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

      verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(
        verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        ).outcome.kind,
      ).toBe("denied");

      // Operator clears the store (e.g. periodic GC, or process
      // restart with in-memory backend). Same proof now goes through.
      // Production deployments need a durable backing store + an
      // append-only retention model, NOT a clear() schedule.
      store.clear();

      expect(
        verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        ).outcome.kind,
      ).toBe("allowed");
    });

    it("WITHOUT a NonceStore, the replay goes through — defense is opt-in", async () => {
      // Documents the most important residual risk: capnagent's
      // replay protection only fires if the operator explicitly
      // installed a NonceStore. The default Verifier does NOT
      // protect against replay — bearer tokens are designed to be
      // reusable, and the hok-without-NonceStore configuration is
      // the v0.1 baseline.
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      expect(
        verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        ).outcome.kind,
      ).toBe("allowed");
      expect(
        verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        ).outcome.kind,
      ).toBe("allowed");
    });
  });
});
