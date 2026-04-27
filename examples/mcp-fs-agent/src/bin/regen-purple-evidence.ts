/**
 * Regenerate the receipt evidence for
 * `docs/purple-team/01-tool-description-injection.md`.
 *
 *   npm run -w @capnagent-examples/mcp-fs-agent regen-purple-evidence
 *
 * Reproduces Stage 3 step 6 of the scenario (the compromised agent
 * emits read_file on an out-of-scope path), captures the resulting
 * denial receipt, and writes it to
 * `docs/purple-team/evidence/01-tool-description-injection.receipt.json`.
 *
 * The script is idempotent — running it again produces a byte-
 * identical receipt EXCEPT for the timestamp and signature (signature
 * varies because the receipt's args_hash includes the random sandbox
 * path which is regenerated each run).
 *
 * The committed evidence is one captured run; reviewers re-running
 * this script will get a different receipt with the same SHAPE,
 * which is what matters for the security claim.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import { createGuardedFsClient, issueSandboxReadCapability } from "../index.js";

const CALLER = "agent:fs";

async function main(): Promise<void> {
  await init();

  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-tpa-evidence-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });

  // Same fake-secret pattern as the PoC test — never points at real
  // ~/.ssh paths.
  const fakeSshKey = path.join(outside, "fake-id-rsa-PRETEND-SECRET");
  await fs.writeFile(fakeSshKey, "PRETEND PRIVATE KEY", "utf8");

  const cap = issueSandboxReadCapability({ sandboxPrefix: sandbox, caller: CALLER });
  const { client, underlying, receipts } = await createGuardedFsClient({
    capability: cap,
    caller: CALLER,
  });

  // Reproduce the attack chain: compromised agent emits the call
  // the malicious description told it to make.
  let denied = false;
  try {
    await client.callTool("read_file", { path: fakeSshKey });
  } catch (err) {
    if (err instanceof CapabilityDeniedError) {
      denied = true;
    } else {
      throw err;
    }
  }

  if (!denied) {
    console.error("SECURITY FAILURE: capnagent did not deny the out-of-scope read.");
    process.exit(3);
  }
  if (underlying.log.length !== 0) {
    console.error("SECURITY FAILURE: the call reached the underlying fs client.");
    process.exit(3);
  }
  if (receipts.length !== 1) {
    console.error(`unexpected receipt count: ${receipts.length}`);
    process.exit(3);
  }

  const receipt = receipts[0];

  // Write the receipt to the evidence dir. The script lives at
  // examples/mcp-fs-agent/src/bin/regen-purple-evidence.ts so the
  // repo root is four `..` up.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "01-tool-description-injection.receipt.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  await fs.writeFile(evidencePath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log("Receipt:");
  console.log(JSON.stringify(receipt, null, 2));

  // Cleanup the tempdir.
  await fs.rm(root, { recursive: true, force: true });
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
