/**
 * Regenerate the receipt evidence for
 * `docs/purple-team/10-encoding-attacks.md`.
 *
 *   npm run -w @capnagent-examples/mcp-fs-agent regen-purple-evidence-10
 *
 * Reproduces the path-traversal scenario:
 *   1. Build a sandbox-scoped read cap for /tmp/<rand>/sandbox/.
 *   2. Plant a secret OUTSIDE the sandbox at /tmp/<rand>/outside/secret.txt.
 *   3. Agent emits read_file on /tmp/<rand>/sandbox/../outside/secret.txt.
 *   4. capnagent's caveat sees the substring `/tmp/<rand>/sandbox/`
 *      in the path and ALLOWS the call.
 *   5. Node's fs.readFile resolves the `..` and reads the secret.
 *
 * The captured receipt has `outcome.kind === "allowed"` for a path
 * that resolves outside the sandbox. Combined with the actual file
 * contents read, that's the visceral evidence of the gap.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { init } from "@capnagent/core";

import { createGuardedFsClient, issueSandboxReadCapability } from "../index.js";

const CALLER = "agent:fs";

async function main(): Promise<void> {
  await init();

  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-encoding-evidence-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(outside, "secret.txt"), "OUT-OF-SANDBOX-SECRET", "utf8");

  const cap = issueSandboxReadCapability({ sandboxPrefix: sandbox, caller: CALLER });
  const { client, receipts } = await createGuardedFsClient({
    capability: cap,
    caller: CALLER,
  });

  const traversalPath = `${sandbox}/../outside/secret.txt`;
  const result = (await client.callTool("read_file", { path: traversalPath })) as string;

  if (result !== "OUT-OF-SANDBOX-SECRET") {
    console.error(`UNEXPECTED: traversal did not exfil — got ${JSON.stringify(result)}`);
    process.exit(3);
  }

  if (receipts.length !== 1) {
    console.error(`unexpected receipt count: ${receipts.length}`);
    process.exit(3);
  }
  const receipt = receipts[0] as { outcome: { kind: string } };
  if (receipt.outcome.kind !== "allowed") {
    console.error(`UNEXPECTED: receipt outcome was ${receipt.outcome.kind}, expected "allowed"`);
    process.exit(3);
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "10-encoding-attacks.receipt.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  const annotated = {
    _annotation: {
      scenario:
        "Path-traversal attack against the sandbox-scoped fs cap. The traversal path /sandbox/../outside/secret.txt CONTAINS the sandbox prefix as a substring, so capnagent's caveat substring-match fires and ALLOWS the call. Node's fs.readFile then resolves the `..` and reads the out-of-sandbox secret. Combined with the verified-read content, this is the gap.",
      sandbox_prefix: sandbox,
      traversal_path_attempted: traversalPath,
      file_actually_read_outside_sandbox: result,
      finding:
        "Defense BREAKS for path-traversal-shaped inputs. Same fix as round 07 (Context-provider canonicalization + starts_with DSL operator).",
    },
    receipt,
  };
  await fs.writeFile(evidencePath, `${JSON.stringify(annotated, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log("Round 10 — receipt for the path-traversal scenario:");
  console.log(JSON.stringify(annotated, null, 2));

  await fs.rm(root, { recursive: true, force: true });
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
