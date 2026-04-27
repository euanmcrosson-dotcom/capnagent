/**
 * Regenerate the evidence for
 * `docs/purple-team/03-capability-broadening.md`.
 *
 *   npm run -w @capnagent-examples/shopping-agent regen-purple-evidence-03
 *
 * Round 03 differs structurally from rounds 01 / 02: chain failures
 * are THROWN, not turned into receipts. There is no `Receipt` to
 * capture for a tampered cap — the Verifier short-circuits before
 * any audit signing happens. So the evidence we record is:
 *
 *   - the captured `error.name` and `error.message` (one entry per
 *     attack variant); these are the strings ops graps would alert
 *     on;
 *   - the serialized base64-JSON cap that was rejected (so a
 *     reviewer can replay the attack independently and confirm the
 *     verifier still throws);
 *   - the negative-leg evidence: a legitimate, untampered cap and
 *     the fact that `verify(...)` returned cleanly.
 *
 * Output is written to
 * `docs/purple-team/evidence/03-capability-broadening.evidence.json`
 * (note: `.evidence.json`, not `.receipt.json` — there is no receipt
 * for chain-failure paths; rounds 01 / 02 each had a denial receipt
 * because their attacks fired the caveat / replay gate, both of
 * which sign a receipt; chain failures don't).
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { Capability, CapabilityChainError, Issuer, Verifier, init } from "@capnagent/core";

const ROOT_KEY = new Uint8Array(32).fill(0xc1);
const ALT_ROOT_KEY = new Uint8Array(32).fill(0xc2);

interface SerializedCap {
  identifier: string;
  holder_of_key?: string;
  caveats: Array<{ predicate: string }>;
  signature: string;
}

function decodeToken(token: string): SerializedCap {
  const json = Buffer.from(token, "base64url").toString("utf8");
  return JSON.parse(json) as SerializedCap;
}

function encodeToken(obj: SerializedCap): string {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

interface VariantEvidence {
  variant: string;
  description: string;
  rejectedToken: string;
  errorName: string;
  errorMessage: string;
  isCapabilityChainError: boolean;
}

function captureVariant(
  name: string,
  description: string,
  buildTampered: () => Capability,
  verifier: Verifier,
): VariantEvidence {
  const tampered = buildTampered();
  const rejectedToken = tampered.serialize();
  try {
    verifier.verify(tampered);
    throw new Error("SECURITY FAILURE: tampered cap was not rejected");
  } catch (e) {
    if (!(e instanceof CapabilityChainError)) {
      // Re-throw — we only want chain errors here.
      throw e;
    }
    return {
      variant: name,
      description,
      rejectedToken,
      errorName: e.name,
      errorMessage: e.message,
      isCapabilityChainError: true,
    };
  }
}

async function main(): Promise<void> {
  await init();

  // The legitimate cap that the attacker started from. Same shape as
  // Round 02's hok-bound version, minus the holder-of-key — Round 03
  // only attacks the chain, which is shared between bearer and hok.
  const legitCap = Issuer.fromKey(ROOT_KEY)
    .issue("buy-broadening-test")
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
  const legitToken = legitCap.serialize();
  const wire = decodeToken(legitToken);

  const verifier = new Verifier(ROOT_KEY);

  // Negative-leg sanity: legit cap verifies cleanly, no throw.
  let legitVerifyOk = false;
  try {
    verifier.verify(legitCap);
    legitVerifyOk = true;
  } catch {
    // intentionally swallowed; the failure surfaces below.
  }
  if (!legitVerifyOk) {
    console.error("SECURITY FAILURE: legit cap did not verify cleanly.");
    process.exit(3);
  }

  const variants: VariantEvidence[] = [];

  variants.push(
    captureVariant(
      "v2-caveat-dropped",
      "Drop the `arg.amount <= 50` caveat from the wire format and re-serialize.",
      () => {
        const w: SerializedCap = {
          ...wire,
          caveats: wire.caveats.filter((c) => !c.predicate.startsWith("arg.amount")),
        };
        return Capability.parse(encodeToken(w));
      },
      verifier,
    ),
  );

  variants.push(
    captureVariant(
      "v3-caveat-mutated",
      "Broaden the amount caveat from `arg.amount <= 50` to `arg.amount <= 5000`.",
      () => {
        const w: SerializedCap = {
          ...wire,
          caveats: wire.caveats.map((c) =>
            c.predicate.startsWith("arg.amount") ? { predicate: "arg.amount <= 5000" } : c,
          ),
        };
        return Capability.parse(encodeToken(w));
      },
      verifier,
    ),
  );

  variants.push(
    captureVariant(
      "v4-signature-zeroed",
      "Overwrite the 32-byte HMAC-SHA256 signature with all zeros.",
      () => Capability.parse(encodeToken({ ...wire, signature: "0".repeat(64) })),
      verifier,
    ),
  );

  variants.push(
    captureVariant(
      "v5-signature-spliced-from-sibling",
      "Splice in the signature from a different cap (same root key, different caveats).",
      () => {
        const sibling = Issuer.fromKey(ROOT_KEY)
          .issue("buy-broadening-test-sibling")
          .caveat(`caller == "agent:planner"`)
          .caveat("arg.amount <= 9999")
          .build();
        const wireSibling = decodeToken(sibling.serialize());
        const w: SerializedCap = { ...wire, signature: wireSibling.signature };
        return Capability.parse(encodeToken(w));
      },
      verifier,
    ),
  );

  variants.push(
    captureVariant(
      "v6-cross-key-forgery",
      "Mint an identical-shaped cap under a different root key; verify under the original key.",
      () =>
        Issuer.fromKey(ALT_ROOT_KEY)
          .issue("buy-broadening-test")
          .caveat(`caller == "agent:planner"`)
          .caveat(`tool == "checkout.purchase"`)
          .caveat(`arg.merchant == "amazon.com"`)
          .caveat("arg.amount <= 50")
          .caveat("now <= @2099-01-01T00:00:00Z")
          .build(),
      verifier,
    ),
  );

  // The evidence document.
  const evidence = {
    round: 3,
    name: "capability-broadening",
    generatedBy: "examples/shopping-agent/src/bin/regen-purple-evidence-03.ts",
    note:
      "Round 03 fires chain ✗ — chain failures throw CapabilityChainError before audit signing, " +
      "so there is no signed denial receipt to capture. We record the (errorName, errorMessage, " +
      "rejected token) triple per variant instead. A reviewer can replay each rejected token " +
      "against `Verifier(ROOT_KEY).verify(...)` and confirm it still throws.",
    rootKeyMaterialDescription:
      "32 bytes of 0xc1 — deterministic test key, NOT for production use.",
    legitCap: {
      token: legitToken,
      verifyResult: "ok-no-throw",
    },
    tamperedVariants: variants,
  };

  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "03-capability-broadening.evidence.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  await fs.writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log(`Captured ${variants.length} chain-failure variants.`);
  for (const v of variants) {
    console.log(`  - ${v.variant}: ${v.errorName} — "${v.errorMessage}"`);
  }
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
