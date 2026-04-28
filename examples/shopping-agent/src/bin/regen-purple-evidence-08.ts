/**
 * Regenerate the receipt evidence for
 * `docs/purple-team/08-forgot-nonce-store.md`.
 *
 *   npm run -w @capnagent-examples/shopping-agent regen-purple-evidence-08
 *
 * Reproduces the dual-narrative scenario:
 *
 *   1. The GAP — a Verifier with NO NonceStore installed accepts a
 *      byte-identical replay of a hok-bound capability's proof. The
 *      replay defense is silently absent because the operator forgot
 *      to call `withNonceStore(...)`. Captured as `gap_receipt`
 *      (outcome.kind === "allowed" for what should have been denied).
 *
 *   2. The FIX-WHEN-INSTALLED — the same scenario with `withNonceStore`
 *      called. Replay is correctly denied with reason
 *      `"proof replay detected"`. Captured as `fixed_receipt`.
 *
 * Both receipts are emitted into a single annotated JSON object so
 * the round doc can reference one evidence file with two halves.
 *
 * Reproducible across machines: deterministic inputs (frozen now_ms,
 * fixed root/audit/holder keys, fixed args). The receipts are
 * byte-identical regardless of who runs the script.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import * as ed from "@noble/ed25519";

import {
  Auditor,
  type Context,
  Issuer,
  NonceStore,
  Verifier,
  init,
  popChallengeFor,
} from "@capnagent/core";

const ROOT_KEY = new Uint8Array(32).fill(0xc8);
const AUDIT_KEY = new Uint8Array(32).fill(0xc7);
const HOLDER_SECRET = new Uint8Array(32).fill(0xc6);
const FROZEN_NOW_MS = 1_700_000_000_000;

async function main(): Promise<void> {
  await init();

  const publicKey = await ed.getPublicKeyAsync(HOLDER_SECRET);
  const cap = Issuer.fromKey(ROOT_KEY)
    .issue("buy-no-nonce-store")
    .holderOfKey(publicKey)
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();

  const ctx: Context = {
    caller: "agent:planner",
    tool: "checkout.purchase",
    args: { merchant: "amazon.com", amount: 20 },
    nowMs: FROZEN_NOW_MS,
  };
  const challenge = popChallengeFor(cap, ctx);
  const proof = await ed.signAsync(challenge, HOLDER_SECRET);

  // -------------------------------------------------------------------------
  // (1) THE GAP — Verifier with no NonceStore installed.
  // -------------------------------------------------------------------------

  const gapAuditor = new Auditor(AUDIT_KEY);
  const gapVerifier = new Verifier(ROOT_KEY);

  if (gapVerifier.hasNonceStore() !== false) {
    console.error("EXPECTED FAILURE: fresh verifier should report hasNonceStore() === false");
    process.exit(3);
  }

  // Establish the legit first call.
  const gapFirst = gapVerifier.verifyWithProof(cap, ctx, gapAuditor, challenge, proof);
  if (gapFirst.outcome.kind !== "allowed") {
    console.error("UNEXPECTED: legit first call should have been allowed");
    process.exit(3);
  }

  // Replay with the SAME bytes. Should be silently allowed — the gap.
  const gapReplay = gapVerifier.verifyWithProof(cap, ctx, gapAuditor, challenge, proof);
  if (gapReplay.outcome.kind !== "allowed") {
    console.error(
      `UNEXPECTED: gap-scenario replay produced ${gapReplay.outcome.kind}; expected allowed (the gap)`,
    );
    process.exit(3);
  }

  // -------------------------------------------------------------------------
  // (2) THE FIX-WHEN-INSTALLED — same scenario with NonceStore wired.
  // -------------------------------------------------------------------------

  const fixedAuditor = new Auditor(AUDIT_KEY);
  const fixedVerifier = new Verifier(ROOT_KEY).withNonceStore(new NonceStore());

  if (fixedVerifier.hasNonceStore() !== true) {
    console.error("EXPECTED FAILURE: configured verifier should report hasNonceStore() === true");
    process.exit(3);
  }

  const fixedFirst = fixedVerifier.verifyWithProof(cap, ctx, fixedAuditor, challenge, proof);
  if (fixedFirst.outcome.kind !== "allowed") {
    console.error("UNEXPECTED: legit first call (fixed scenario) should have been allowed");
    process.exit(3);
  }

  const fixedReplay = fixedVerifier.verifyWithProof(cap, ctx, fixedAuditor, challenge, proof);
  if (fixedReplay.outcome.kind !== "denied") {
    console.error(
      `SECURITY FAILURE: fixed-scenario replay should have been denied (got ${fixedReplay.outcome.kind})`,
    );
    process.exit(3);
  }
  if (fixedReplay.outcome.reason !== "proof replay detected") {
    console.error(`SECURITY FAILURE: unexpected denial reason: ${fixedReplay.outcome.reason}`);
    process.exit(3);
  }

  // -------------------------------------------------------------------------
  // Write both receipts as a single annotated JSON object.
  // -------------------------------------------------------------------------

  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "08-forgot-nonce-store.receipt.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  const annotated = {
    _annotation: {
      scenario:
        "Operator-trap: a hok-bound capability is in use, but the operator forgot to call `verifier.withNonceStore(...)`. Round 02's defense is silently absent. v0.4's `hasNonceStore()` introspection method now lets operators detect this BEFORE relying on the (non-existent) replay defense. This evidence captures both halves: the gap (replay allowed when no store) and the fix-when-installed (replay denied with the locked reason).",
      gap_expected_outcome: "denied",
      gap_observed_outcome: gapReplay.outcome.kind,
      fixed_expected_outcome: "denied",
      fixed_observed_outcome: fixedReplay.outcome.kind,
      fixed_observed_reason:
        fixedReplay.outcome.kind === "denied" ? fixedReplay.outcome.reason : null,
      detection_mechanism:
        "verifier.hasNonceStore() returns false on the gap-scenario verifier and true on the fixed-scenario verifier. The deployment-readiness postcondition `assert(verifier.hasNonceStore())` catches the forgotten install.",
      finding:
        "Round 08 CLOSED on Run 1 — v0.4's `hasNonceStore()` shipped before this round was authored, so the operator-config gap is detectable from day one. The round documents the failure mode AND validates the fix simultaneously. See docs/purple-team/08-forgot-nonce-store.md.",
    },
    gap_receipt: gapReplay,
    fixed_receipt: fixedReplay,
  };
  await fs.writeFile(evidencePath, `${JSON.stringify(annotated, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log("Round 08 — gap_receipt (replay against verifier without NonceStore):");
  console.log(JSON.stringify(gapReplay, null, 2));
  console.log("");
  console.log("Round 08 — fixed_receipt (replay against verifier WITH NonceStore):");
  console.log(JSON.stringify(fixedReplay, null, 2));
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
