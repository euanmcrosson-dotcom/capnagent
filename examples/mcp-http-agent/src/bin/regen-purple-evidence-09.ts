/**
 * Regenerate the evidence for `docs/purple-team/09-idn-homograph-origin.md`.
 *
 *   npm run -w @capnagent-examples/mcp-http-agent regen-purple-evidence-09
 *
 * Round 09's gap is at ISSUANCE — the validator accepts a punycode
 * homograph origin without warning. So the evidence captured here is
 * NOT a denial receipt (round 05 already shows those). Instead it's
 * a structured snapshot of:
 *
 *   - the homograph input the operator might paste
 *   - what `URL.origin` resolves it to (punycode)
 *   - that issuance succeeded WITHOUT WARNING
 *   - that the resulting cap allowed an http.get to the homograph host
 *   - the allowed-receipt for that call
 *   - that the same cap denied the legitimate ASCII origin (the
 *     operator's actual intent)
 *
 * Output filename uses `.json` rather than `.receipt.json` to signal
 * it is a multi-fact evidence bundle, not a single receipt.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import { createGuardedHttpClient, issueOriginScopedGetCapability } from "../index.js";

const CALLER = "agent:http";

// Cyrillic-а homograph constructed deterministically.
const CYRILLIC_A = String.fromCodePoint(0x0430);
const HOMOGRAPH_UNICODE = `https://${CYRILLIC_A}pi.example.com`;
const HOMOGRAPH_PUNYCODE = "https://xn--pi-6kc.example.com";
const PUBLIC_GOOD_ASCII = "https://api.example.com";

interface EvidenceBundle {
  round: number;
  title: string;
  status: "BREAKS";
  summary: string;
  empirical: {
    homograph_unicode_input: string;
    homograph_unicode_codepoints: ReadonlyArray<string>;
    url_origin_returns: string;
    legitimate_ascii_origin: string;
    homograph_equals_ascii: boolean;
  };
  issuance: {
    allowedOrigins_passed: ReadonlyArray<string>;
    issuance_threw: false;
    issuance_warning: null;
    cap_built_successfully: true;
  };
  cap_behavior: {
    homograph_call_url: string;
    homograph_call_outcome: "allowed";
    homograph_call_receipt: unknown;
    legitimate_ascii_call_url: string;
    legitimate_ascii_call_outcome: "denied";
    legitimate_ascii_call_receipt: unknown;
  };
  conclusion: string;
}

async function main(): Promise<void> {
  await init();

  // We need fetch to actually run for the homograph call (so we can
  // observe the cap allowing it). Use a stub that returns 200 without
  // hitting the network for any URL whose origin matches the punycode
  // homograph; throws otherwise as a regression alarm.
  const fetchStub: typeof fetch = (async (
    input: Parameters<typeof fetch>[0],
  ): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const u = new URL(url);
    if (u.origin === HOMOGRAPH_PUNYCODE) {
      return new Response("hit homograph stand-in", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }
    throw new Error(
      `regen-09: unexpected fetch to ${u.origin} — only the homograph stand-in should be reachable here.`,
    );
  }) as typeof fetch;

  // FOOT-GUN: operator pastes the punycode form of a Cyrillic-а
  // homograph into the allowlist. Issuance succeeds without warning.
  const cap = issueOriginScopedGetCapability({
    allowedOrigins: [HOMOGRAPH_PUNYCODE],
    caller: CALLER,
  });
  if (!cap) {
    console.error("regen-09 FAILED: cap should have been issued.");
    process.exit(3);
  }

  const { client, receipts } = await createGuardedHttpClient({
    capability: cap,
    caller: CALLER,
    fetch: fetchStub,
  });

  // Demonstrate (1): cap allows homograph call
  await client.callTool("http.get", { url: `${HOMOGRAPH_UNICODE}/data` });
  const afterHomograph = receipts.length;
  if (afterHomograph !== 1) {
    console.error(
      `regen-09 FAILED: expected 1 receipt after homograph call, got ${afterHomograph}`,
    );
    process.exit(3);
  }
  const homographReceipt = receipts[0];

  // Demonstrate (2): same cap denies legitimate ASCII origin
  let denied = false;
  try {
    await client.callTool("http.get", { url: `${PUBLIC_GOOD_ASCII}/data` });
  } catch (err) {
    if (err instanceof CapabilityDeniedError) {
      denied = true;
    } else {
      throw err;
    }
  }
  if (!denied) {
    console.error(
      "regen-09 FAILED: legitimate ASCII GET should have been denied by the homograph-only cap.",
    );
    process.exit(3);
  }
  const afterAscii = receipts.length;
  if (afterAscii !== 2) {
    console.error(`regen-09 FAILED: expected 2 receipts after both calls, got ${afterAscii}`);
    process.exit(3);
  }
  const asciiReceipt = receipts[1];

  const bundle: EvidenceBundle = {
    round: 9,
    title: "IDN homograph in origin allowlist",
    status: "BREAKS",
    summary:
      "The http-agent's `issueOriginScopedGetCapability` validator accepts a punycode-form IDN " +
      "homograph (`xn--pi-6kc.example.com`) in `allowedOrigins` without any IDN-confusable check. " +
      "An operator who was tricked into pasting the punycode of a Cyrillic-а homograph (perhaps " +
      "via clipboard/CLI/JSON-loader canonicalization of a visually-disguised attacker URL) " +
      "issues a cap that allows agent calls to the attacker host AND denies calls to the " +
      "legitimate ASCII origin they believed they were allowing.",
    empirical: {
      homograph_unicode_input: HOMOGRAPH_UNICODE,
      homograph_unicode_codepoints: [...HOMOGRAPH_UNICODE].map(
        (c) => `U+${c.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}`,
      ),
      url_origin_returns: new URL(HOMOGRAPH_UNICODE).origin,
      legitimate_ascii_origin: PUBLIC_GOOD_ASCII,
      homograph_equals_ascii: new URL(HOMOGRAPH_UNICODE).origin === PUBLIC_GOOD_ASCII,
    },
    issuance: {
      allowedOrigins_passed: [HOMOGRAPH_PUNYCODE],
      issuance_threw: false,
      issuance_warning: null,
      cap_built_successfully: true,
    },
    cap_behavior: {
      homograph_call_url: `${HOMOGRAPH_UNICODE}/data`,
      homograph_call_outcome: "allowed",
      homograph_call_receipt: homographReceipt,
      legitimate_ascii_call_url: `${PUBLIC_GOOD_ASCII}/data`,
      legitimate_ascii_call_outcome: "denied",
      legitimate_ascii_call_receipt: asciiReceipt,
    },
    conclusion:
      "The validator's structural origin check (`s === u.origin`, no path/userinfo/etc) is " +
      "necessary but not sufficient. Without an IDN-confusable check it cannot distinguish a " +
      "legitimate IDN registration from a homograph attack. Recommended fix is documented in " +
      "the round doc; trade-off is between ASCII-only labels (simple, blocks legitimate IDNs) " +
      "and TR39-aware mixed-script/confusable detection (permissive, more complex).",
  };

  // Write to docs/purple-team/evidence/09-idn-homograph-origin.json
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "09-idn-homograph-origin.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  await fs.writeFile(evidencePath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log("Evidence bundle:");
  console.log(JSON.stringify(bundle, null, 2));
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
