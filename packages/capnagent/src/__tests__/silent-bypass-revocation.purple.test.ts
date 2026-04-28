/**
 * Purple-team PoC for round 06 — silent-bypass on revocation-list install.
 *
 * # The angles methodology applied to capnagent
 *
 * Rounds 01-05 tested the structural defense against named attacks
 * (the attacker tries X, the gate denies). They closed `holds-with-
 * caveat`. Round 06 is a different shape: it tests a FAILURE MODE of
 * the existing defense — specifically, what happens when the OPERATOR
 * misuses the install API in a realistic way (catches the throw and
 * silently ignores it).
 *
 * Round 04 documented this as a known hazard ("with_revocation_list
 * fails closed but produces a Verifier with NO list installed; flag
 * as paged-alert in production"). This PoC programmatically PROVES it
 * — and surfaces the deeper finding: there is no API on `Verifier`
 * for an operator to verify, after the fact, whether a revocation
 * list is installed. So an operator who installed correctly and an
 * operator who silently swallowed an error look IDENTICAL from the
 * outside.
 *
 * # The hypothesis
 *
 * Positive (true-positive): given a Verifier where the operator
 * BELIEVES a RevocationList was installed but the install actually
 * threw and was silently ignored, `verifyWithContext` on a capability
 * whose identifier IS in the (un-installed) list MUST be denied.
 *
 * Negative (true-negative): a Verifier with a successfully installed
 * list correctly denies revoked caps AND allows non-revoked caps.
 *
 * # The finding
 *
 * The positive hypothesis FAILS. The Verifier has no installed-list
 * introspection method, so an operator cannot detect the
 * silently-failed install before relying on the (non-existent)
 * defense. Capabilities the operator believed were revoked go
 * through unimpeded.
 *
 * Round status: **BREAKS** — defense does not hold for this
 * operator-error path.
 *
 * # The recommended fix (engine-side, follow-up commit)
 *
 * Add introspection methods to `Verifier`:
 *   - `hasRevocationList(): boolean`
 *   - `hasNonceStore(): boolean` (same shape applies to round 02's
 *     opt-in NonceStore defense)
 *   - `revocationListIssuedAtMs(): number | null`
 *
 * With these, operators can write a postcondition assertion in
 * deployment-readiness code:
 *
 *     verifier.withRevocationList(list);  // may throw
 *     if (!verifier.hasRevocationList()) {
 *       throw new Error("CRITICAL: revocation list install silently failed");
 *     }
 *
 * Without them, the silent-bypass is invisible from the API surface.
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

const ROOT_KEY = new Uint8Array(32).fill(0xa1);
const WRONG_KEY = new Uint8Array(32).fill(0xa2);
const AUDIT_KEY = new Uint8Array(32).fill(0xa3);

const FUTURE = "now <= @2099-01-01T00:00:00Z";

interface Fixture {
  cap: ReturnType<typeof Issuer.fromKey>;
  ctx: Context;
  auditor: Auditor;
  capId: string;
}

async function makeFixture(): Promise<{
  cap: ReturnType<ReturnType<typeof Issuer.fromKey>["issue"]>["build"] extends () => infer R
    ? R
    : never;
  ctx: Context;
  auditor: Auditor;
  capId: string;
}> {
  await init();
  const capId = "buy-stolen-token";
  const cap = Issuer.fromKey(ROOT_KEY)
    .issue(capId)
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
  return { cap, ctx, auditor: new Auditor(AUDIT_KEY), capId };
}

describe("Round 06: silent-bypass on revocation-list install", () => {
  describe("the silent-bypass operator-error scenario (the finding)", () => {
    it("operator silently catches the install error → revoked cap goes through unimpeded", async () => {
      const { cap, ctx, auditor, capId } = await makeFixture();

      // Operator builds a revocation list signed under the WRONG
      // key (perhaps because of a config typo, key rotation race,
      // or simply a deploy-time mistake).
      const rev = new Revoker(WRONG_KEY);
      rev.revoke(capId);
      const badList = rev.publish(1_700_000_000_000);

      const verifier = new Verifier(ROOT_KEY);

      // The realistic operator-error pattern: try to install, catch
      // the error, log it, continue.
      let caught: unknown = null;
      try {
        verifier.withRevocationList(badList);
      } catch (e) {
        caught = e;
        // ↑ in real code this is often an empty catch / logger.warn /
        // sentry.captureException, none of which BLOCK execution.
      }
      expect(caught).toBeInstanceOf(CapabilityChainError);

      // Now the operator BELIEVES they have revocation protection.
      // The verifier looks identical to a successfully-installed
      // verifier from the outside: no errors, no obvious state
      // difference. There is no public method on Verifier that
      // tells you "you don't actually have a list installed."

      // Use the verifier as if it were configured. The cap we
      // believed was revoked — goes through.
      const r = verifier.verifyWithContext(cap, ctx, auditor);

      // THE FINDING: defense does NOT hold.
      // We expected: outcome.kind === "denied" with reason
      //              "capability revoked: buy-stolen-token"
      // We got:      outcome.kind === "allowed"
      expect(r.outcome.kind).toBe("allowed");

      // Documents the impact: a real cap that the operator THOUGHT
      // they revoked is silently authorized. Round status: BREAKS.
    });

    it("v0.4 fix: the silent-bypass is now DETECTABLE via hasRevocationList()", async () => {
      // Run 2 (post-fix). The engine v0.4 work added introspection
      // methods to Verifier — `hasRevocationList()`,
      // `revocationListIssuedAtMs()`, `hasNonceStore()` — so an
      // operator can write a postcondition assertion that catches
      // the silent-failed install before relying on the
      // (non-existent) defense.
      const { capId } = await makeFixture();
      const rev = new Revoker(WRONG_KEY);
      rev.revoke(capId);
      const badList = rev.publish(1_700_000_000_000);

      const verifier = new Verifier(ROOT_KEY);

      // Fresh verifier: no list installed, introspection says so.
      expect(verifier.hasRevocationList()).toBe(false);
      expect(verifier.revocationListIssuedAtMs()).toBeUndefined();

      try {
        verifier.withRevocationList(badList);
      } catch {
        // Silent-bypass operator pattern, same as Run 1.
      }

      // THE FIX: the silent-failed install is now detectable.
      // Operator's postcondition catches it.
      expect(verifier.hasRevocationList()).toBe(false);
      expect(verifier.revocationListIssuedAtMs()).toBeUndefined();
    });

    it("v0.4 fix: a successful install reflects in the introspection", async () => {
      const { capId } = await makeFixture();
      const rev = new Revoker(ROOT_KEY); // CORRECT key
      rev.revoke(capId);
      const goodList = rev.publish(1_700_000_000_000);

      const verifier = new Verifier(ROOT_KEY).withRevocationList(goodList);
      expect(verifier.hasRevocationList()).toBe(true);
      expect(verifier.revocationListIssuedAtMs()).toBe(1_700_000_000_000);
    });

    it("v0.4 fix: hasNonceStore mirrors hasRevocationList for the opt-in NonceStore defense", async () => {
      const { NonceStore } = await import("../index.js");
      await init();
      const verifier = new Verifier(ROOT_KEY);
      expect(verifier.hasNonceStore()).toBe(false);

      const installed = new Verifier(ROOT_KEY).withNonceStore(new NonceStore());
      expect(installed.hasNonceStore()).toBe(true);
    });
  });

  describe("the negative hypothesis (defense holds when install succeeds)", () => {
    it("verifier with successfully-installed list denies revoked caps", async () => {
      const { cap, ctx, auditor, capId } = await makeFixture();
      const rev = new Revoker(ROOT_KEY); // CORRECT key
      rev.revoke(capId);
      const goodList = rev.publish(1_700_000_000_000);
      const verifier = new Verifier(ROOT_KEY).withRevocationList(goodList);

      const r = verifier.verifyWithContext(cap, ctx, auditor);
      expect(r.outcome.kind).toBe("denied");
      if (r.outcome.kind === "denied") {
        expect(r.outcome.reason).toBe(`capability revoked: ${capId}`);
      }
    });

    it("verifier with successfully-installed list allows non-revoked caps", async () => {
      const { cap, ctx, auditor } = await makeFixture();
      const rev = new Revoker(ROOT_KEY);
      rev.revoke("some-other-id"); // not the cap under test
      const goodList = rev.publish(1_700_000_000_000);
      const verifier = new Verifier(ROOT_KEY).withRevocationList(goodList);

      const r = verifier.verifyWithContext(cap, ctx, auditor);
      expect(r.outcome.kind).toBe("allowed");
    });
  });

  describe("severity calibration", () => {
    it("the silent-bypass scenario only requires a routine try/catch — not adversarial code", async () => {
      // The operator pattern that triggers this is the SAME pattern
      // every defensive Node.js codebase uses for "log and continue":
      //
      //   try {
      //     verifier.withRevocationList(list);
      //   } catch (err) {
      //     logger.warn("revocation install failed:", err);
      //     // execution continues — the verifier is now silently
      //     // missing its revocation defense
      //   }
      //
      // No malicious actor required. Just standard error handling.
      // That's why this is HIGH severity, not informational.
      //
      // This test exists to document the threat model framing in
      // code: the "attacker" here is operator inertia, not an
      // adversary. The fix is API design, not capability semantics.

      const { cap, ctx, auditor, capId } = await makeFixture();
      const rev = new Revoker(WRONG_KEY);
      rev.revoke(capId);
      const badList = rev.publish(1_700_000_000_000);

      const logger = { warn: (..._args: unknown[]) => {} };
      const verifier = new Verifier(ROOT_KEY);

      // EXACT pattern a defensive codebase would write:
      try {
        verifier.withRevocationList(badList);
      } catch (err) {
        logger.warn("revocation install failed:", err);
      }

      // Cap goes through. Operator's defensive code defeated by
      // their own defensiveness.
      const r = verifier.verifyWithContext(cap, ctx, auditor);
      expect(r.outcome.kind).toBe("allowed");
    });
  });
});
