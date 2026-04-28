/**
 * Regenerate the receipt evidence for
 * `docs/purple-team/06-silent-bypass-revocation-install.md`.
 *
 *   npm run -w @capnagent/core regen-purple-evidence-06
 *
 * Reproduces the silent-bypass scenario:
 *   1. Operator builds a Verifier.
 *   2. Operator tries to install a RevocationList signed under the
 *      WRONG key — install throws CapabilityChainError.
 *   3. Operator catches the throw and logs it (the realistic
 *      defensive Node.js pattern).
 *   4. Operator calls verifyWithContext on a cap whose identifier
 *      is in the (un-installed) list. Cap is ALLOWED.
 *
 * The captured receipt has `outcome.kind === "allowed"` for a cap
 * that the operator believed they had revoked. That's the visceral
 * evidence of the gap.
 *
 * Reproducible across machines: all inputs deterministic.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import {
  Auditor,
  CapabilityChainError,
  type Context,
  Issuer,
  Revoker,
  Verifier,
  init,
} from "@capnagent/core";

const ROOT_KEY = new Uint8Array(32).fill(0xa1);
const WRONG_KEY = new Uint8Array(32).fill(0xa2);
const AUDIT_KEY = new Uint8Array(32).fill(0xa3);
const FROZEN_NOW_MS = 1_700_000_000_000;

async function main(): Promise<void> {
  await init();

  const capId = "buy-stolen-token";
  const cap = Issuer.fromKey(ROOT_KEY)
    .issue(capId)
    .caveat(`caller == "agent:test"`)
    .caveat(`tool == "x"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
  const ctx: Context = {
    caller: "agent:test",
    tool: "x",
    args: {},
    nowMs: FROZEN_NOW_MS,
  };
  const auditor = new Auditor(AUDIT_KEY);

  // Wrong-key list — install will throw.
  const rev = new Revoker(WRONG_KEY);
  rev.revoke(capId);
  const badList = rev.publish(FROZEN_NOW_MS);

  const verifier = new Verifier(ROOT_KEY);

  // The operator pattern under test.
  let installError: unknown = null;
  try {
    verifier.withRevocationList(badList);
  } catch (e) {
    installError = e;
  }
  if (!(installError instanceof CapabilityChainError)) {
    console.error("EXPECTED FAILURE: install should have thrown CapabilityChainError");
    process.exit(3);
  }

  // Verify the supposedly-revoked cap. Should be denied (operator's
  // expectation). Will be allowed (the actual finding).
  const r = verifier.verifyWithContext(cap, ctx, auditor);
  if (r.outcome.kind !== "allowed") {
    console.error(`UNEXPECTED: scenario produced ${r.outcome.kind}; expected allowed (the gap)`);
    process.exit(3);
  }

  // Write the receipt PLUS context about why this receipt is
  // significant.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "06-silent-bypass-revocation-install.receipt.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  const annotated = {
    _annotation: {
      scenario:
        "Silent-bypass on revocation-list install. Operator caught CapabilityChainError from withRevocationList(badList) and ignored it. The verifier has no list installed but the operator believes one is. verifyWithContext on the supposedly-revoked cap returns ALLOWED.",
      expected_outcome: "denied",
      observed_outcome: r.outcome.kind,
      install_error_caught:
        installError instanceof Error ? installError.message : String(installError),
      finding:
        "Defense BREAKS for the operator-error path. See docs/purple-team/06-silent-bypass-revocation-install.md.",
    },
    receipt: r,
  };
  await fs.writeFile(evidencePath, `${JSON.stringify(annotated, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log("Round 06 finding — receipt for the supposedly-revoked cap:");
  console.log(JSON.stringify(annotated, null, 2));
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
