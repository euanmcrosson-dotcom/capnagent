/**
 * Purple-team PoC for round 08 — operator forgets to install a NonceStore
 * on a Verifier that handles hok-bound capabilities.
 *
 * # The angles methodology applied (round 02 + round 06 sibling)
 *
 * Round 02 closed `holds-with-caveat`: the hok+NonceStore replay defense
 * holds *when the operator installed the store*. Round 02's residual-risk
 * section flagged the most important known-bypass first: WITHOUT a
 * NonceStore installed, the verifier accepts replays — the defense is
 * opt-in. v0.1's API surface gave operators no way to detect this:
 * a Verifier that issued hok-bound caps and forgot the NonceStore looks
 * identical from the outside to one that installed it correctly.
 *
 * Round 06 (silent-bypass on revocation install) surfaced the deeper
 * shape: introspection methods on `Verifier` are required to make
 * misconfigured-defense states visible. v0.4 shipped them:
 * `hasRevocationList()`, `revocationListIssuedAtMs()`, `hasNonceStore()`.
 *
 * Round 08 tests the operator-trap directly. The hypothesis has both
 * halves:
 *
 * Positive (true-positive): given a hok-bound capability and a Verifier
 * with NO `NonceStore` installed, the operator can DETECT the
 * configuration error via `verifier.hasNonceStore() === false` BEFORE
 * relying on the (non-existent) replay defense.
 *
 * Negative (true-negative): a Verifier WITH a NonceStore installed
 * reports `hasNonceStore() === true` and correctly denies replays.
 * (Round 02 regression coverage.)
 *
 * Plus the demonstration-of-need: confirm the actual gap — without a
 * NonceStore installed, replays succeed. That's what makes the
 * introspection method load-bearing.
 *
 * # Round status (Run 1)
 *
 * CLOSED. v0.4's `hasNonceStore()` shipped before this round was even
 * authored, so the operator-config gap is detectable from day one. The
 * round documents the failure mode AND validates the fix simultaneously.
 *
 * # What this test does NOT cover (cross-reference round doc)
 *
 *   - Operator who installs the store but FORGETS to call the
 *     post-install assertion. There is no API design that defeats
 *     determined operator apathy. Out of scope.
 *   - Bearer-token (non-hok) caps with NonceStore: NonceStore has no
 *     effect on `verifyWithContext`, by design. Documented in the
 *     class doc; not a gap.
 *   - Distributed deployment with separate verifier processes each
 *     reporting `hasNonceStore() === true` but holding independent
 *     in-memory stores: an attacker can present the same proof to
 *     each. Out of scope until a shared `NonceStore` backend ships.
 */

import { describe, expect, it } from "vitest";

import * as ed from "@noble/ed25519";

import {
  Auditor,
  type Context,
  Issuer,
  NonceStore,
  Revoker,
  Verifier,
  init,
  popChallengeFor,
} from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xc8);
const AUDIT_KEY = new Uint8Array(32).fill(0xc7);
const HOLDER_SECRET = new Uint8Array(32).fill(0xc6);

/** Frozen now_ms — same trick as round 02: a constant clock keeps the
 *  challenge identical across the two presentations, which is the
 *  in-process analogue of "captured-and-replayed bytes." */
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
    .issue("buy-no-nonce-store")
    .holderOfKey(publicKey)
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

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

describe("Round 08: operator forgets NonceStore on hok-bound caps", () => {
  describe("the operator-trap (the failure mode being tested)", () => {
    it("fresh Verifier reports hasNonceStore() === false (positive hypothesis: detection works)", async () => {
      // The minimum viable detection. A fresh Verifier with no
      // configuration calls reports the absent NonceStore correctly.
      // This is what an operator's deploy-readiness postcondition
      // would check after issuing a hok-bound cap.
      await init();
      const verifier = new Verifier(ROOT_KEY);
      expect(verifier.hasNonceStore()).toBe(false);
    });

    it("WITHOUT a NonceStore installed, hok-bound replay is silently ALLOWED — the gap (demonstration-of-need)", async () => {
      // Visceral proof of why hasNonceStore() matters: without a store
      // installed, the verifier accepts byte-identical re-presentations
      // of the same proof. This is the round-02 residual-risk bullet
      // ("opt-in property: WITHOUT a NonceStore installed, the verifier
      // accepts replays") rendered as an executable assertion.
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      // Pre-flight introspection: defence is not installed.
      expect(verifier.hasNonceStore()).toBe(false);

      // First call — accepted (legit).
      const first = verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(first.outcome.kind).toBe("allowed");

      // Replay with byte-identical bytes — STILL ACCEPTED. The replay
      // defense is silently absent because the operator never wired a
      // NonceStore. Identical input → identical receipt (HMAC determinism;
      // operational note from round 02).
      const replayed = verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(replayed.outcome.kind).toBe("allowed");

      // Sibling check: an attacker can hammer this verifier indefinitely
      // until the operator notices. Audit log shows ten allowed receipts.
      for (let i = 0; i < 8; i++) {
        const r = verifier.verifyWithProof(
          captured.cap,
          captured.ctx,
          auditor,
          captured.challenge,
          captured.proof,
        );
        expect(r.outcome.kind).toBe("allowed");
      }
    });

    it("the deployment-readiness assertion catches the operator forgetting the install", async () => {
      // The recommended pattern: after wiring up the verifier, assert
      // hasNonceStore() before the verifier handles any production
      // traffic. A forgotten install fails LOUDLY at deploy time
      // instead of silently in production.
      await init();

      function deployReadiness(verifier: Verifier): void {
        if (!verifier.hasNonceStore()) {
          throw new Error(
            "CRITICAL: Verifier has no NonceStore installed but is configured for hok-bound caps",
          );
        }
      }

      // Misconfigured: build a verifier, forget the store, hit the
      // postcondition.
      const misconfigured = new Verifier(ROOT_KEY);
      expect(() => deployReadiness(misconfigured)).toThrow(/CRITICAL/);

      // Fixed: install the store, postcondition passes.
      const fixed = new Verifier(ROOT_KEY).withNonceStore(new NonceStore());
      expect(() => deployReadiness(fixed)).not.toThrow();
      expect(fixed.hasNonceStore()).toBe(true);
    });
  });

  describe("the negative hypothesis (defense holds when NonceStore IS installed — round 02 regression)", () => {
    it("Verifier WITH NonceStore reports hasNonceStore() === true and correctly denies replays", async () => {
      // Combined regression check: introspection AND behavior. With
      // the store installed:
      //   (a) introspection truthfully reports installed
      //   (b) replay denial fires with the locked reason string
      const captured = await captureLegitRequest();
      const auditor = new Auditor(AUDIT_KEY);
      const store = new NonceStore();
      const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

      // (a) Introspection.
      expect(verifier.hasNonceStore()).toBe(true);

      // (b) Behavior — round 02's central PASS test.
      const first = verifier.verifyWithProof(
        captured.cap,
        captured.ctx,
        auditor,
        captured.challenge,
        captured.proof,
      );
      expect(first.outcome.kind).toBe("allowed");

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
    });
  });

  describe("introspection coverage across multiple opt-in defenses", () => {
    it("Verifier with BOTH withRevocationList AND withNonceStore reports both true", async () => {
      // The introspection methods are independent and compose: a
      // verifier with both defenses installed reflects both.
      await init();
      const rev = new Revoker(ROOT_KEY);
      rev.revoke("some-revoked-id");
      const goodList = rev.publish(FROZEN_NOW_MS);

      const verifier = new Verifier(ROOT_KEY)
        .withRevocationList(goodList)
        .withNonceStore(new NonceStore());

      expect(verifier.hasRevocationList()).toBe(true);
      expect(verifier.hasNonceStore()).toBe(true);
      expect(verifier.revocationListIssuedAtMs()).toBe(FROZEN_NOW_MS);
    });

    it("Verifier with ONLY withRevocationList reports hasRevocationList() true and hasNonceStore() false (defenses are independently introspectable)", async () => {
      // Negative-tightening: each defense's introspection method
      // reports its own state, not a generic "any defense installed?"
      // boolean. An operator who installed the revocation list but
      // forgot the NonceStore can detect that exact mistake.
      await init();
      const rev = new Revoker(ROOT_KEY);
      rev.revoke("some-revoked-id");
      const goodList = rev.publish(FROZEN_NOW_MS);

      const verifier = new Verifier(ROOT_KEY).withRevocationList(goodList);

      expect(verifier.hasRevocationList()).toBe(true);
      expect(verifier.hasNonceStore()).toBe(false);
      expect(verifier.revocationListIssuedAtMs()).toBe(FROZEN_NOW_MS);
    });
  });
});
