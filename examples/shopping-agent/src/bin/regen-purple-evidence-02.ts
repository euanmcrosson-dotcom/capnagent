/**
 * Regenerate the receipt evidence for
 * `docs/purple-team/02-replay-attack-on-hok-bound-cap.md`.
 *
 *   npm run -w @capnagent-examples/shopping-agent regen-purple-evidence-02
 *
 * Reproduces the replay-attack scenario:
 *   1. Issue a hok-bound capability for shopping.
 *   2. Set up a verifier with NonceStore + default TTL.
 *   3. Sign a proof for a legit call. Verifier accepts.
 *   4. Replay the same bytes. Verifier denies with "proof replay
 *      detected". Capture this denial receipt.
 *
 * Writes the captured denial receipt to
 * `docs/purple-team/evidence/02-replay-attack-on-hok-bound-cap.receipt.json`.
 *
 * Reproducible across machines: the inputs are all deterministic
 * (frozen now_ms, fixed root/audit/holder keys, fixed args) so the
 * captured receipt is byte-identical regardless of who runs the
 * script. That's a property worth pinning — different evidence
 * runs producing different receipts would mean nondeterminism in
 * the canonical-JSON serializer or the HMAC, neither of which
 * should happen.
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

const ROOT_KEY = new Uint8Array(32).fill(0xe1);
const AUDIT_KEY = new Uint8Array(32).fill(0xe2);
const HOLDER_SECRET = new Uint8Array(32).fill(0xe3);
const FROZEN_NOW_MS = 1_700_000_000_000;

async function main(): Promise<void> {
  await init();

  const publicKey = await ed.getPublicKeyAsync(HOLDER_SECRET);
  const cap = Issuer.fromKey(ROOT_KEY)
    .issue("buy-replay-test")
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

  const auditor = new Auditor(AUDIT_KEY);
  const store = new NonceStore();
  const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

  // Legit first call — accepted.
  const first = verifier.verifyWithProof(cap, ctx, auditor, challenge, proof);
  if (first.outcome.kind !== "allowed") {
    console.error("SECURITY FAILURE: first call (legitimate) was not allowed.");
    process.exit(3);
  }

  // Replay — denied.
  const replayed = verifier.verifyWithProof(cap, ctx, auditor, challenge, proof);
  if (replayed.outcome.kind !== "denied") {
    console.error("SECURITY FAILURE: replay was not denied.");
    process.exit(3);
  }
  if (replayed.outcome.reason !== "proof replay detected") {
    console.error(`SECURITY FAILURE: unexpected denial reason: ${replayed.outcome.reason}`);
    process.exit(3);
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "02-replay-attack-on-hok-bound-cap.receipt.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  await fs.writeFile(evidencePath, `${JSON.stringify(replayed, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log("Replay denial receipt:");
  console.log(JSON.stringify(replayed, null, 2));
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
