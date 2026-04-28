/**
 * Regenerate the receipt evidence for
 * `docs/purple-team/07-sandbox-prefix-footgun.md`.
 *
 *   npm run -w @capnagent-examples/mcp-fs-agent regen-purple-evidence-07
 *
 * Reproduces the foot-gun: an operator issues a sandbox-scoped read
 * capability whose `sandboxPrefix` is the literal production-shaped
 * path `/srv/app` (which satisfies the existing length/separator
 * validator). The PoC then issues a `read_file` against
 * `/etc/srv/app-leaked-secret` — a path that is NOT under the
 * sandbox dir but DOES contain `/srv/app` as a substring. capnagent's
 * `matches` operator is substring containment (see
 * `crates/capnagent-core/src/caveat_dsl.rs` line ~752), so the caveat
 * passes and the read is allowed.
 *
 * The captured receipt has `outcome.kind === "allowed"` for a path
 * that should have been denied — the visceral evidence of the bug.
 *
 * The script is idempotent — running it again produces a byte-
 * identical receipt EXCEPT for the timestamp and signature (signature
 * varies because the receipt embeds the wallclock).
 *
 * # Why this script uses a mock fs client
 *
 * The threat model is "operator passes a real production-shaped
 * absolute path like `/srv/app`." We obviously cannot create
 * `/etc/srv/app-leaked-secret` on a CI machine, so the underlying
 * fs client is a mock that returns canned responses keyed on path
 * string. The security claim is about whether capnagent's gate
 * ALLOWS the call through to the underlying client — that decision
 * is independent of what the underlying client does.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { init } from "@capnagent/core";
import type { MCPClientLike } from "@capnagent/mcp";

import type { FsCallLog, FsClient } from "../fs-client.js";
import { createGuardedFsClient, issueSandboxReadCapability } from "../index.js";

const CALLER = "agent:fs";
const SANDBOX_PREFIX = "/srv/app";
const LATERAL = "/etc/srv/app-leaked-secret";

function createMockFsClient(): FsClient {
  const log: FsCallLog[] = [];
  const callTool: MCPClientLike["callTool"] = async (name, args) => {
    log.push({ tool: name, args });
    if (name !== "read_file") {
      throw new Error(`mock fs client: unexpected tool ${name}`);
    }
    const p = (args as { path?: unknown }).path;
    if (p !== LATERAL) {
      throw new Error(`mock fs client: unexpected path ${String(p)}`);
    }
    return "PRETEND LATERAL SECRET — substring foot-gun allows this read";
  };
  return {
    callTool,
    get log() {
      return log;
    },
  };
}

async function main(): Promise<void> {
  await init();

  // Construction sanity check — fail loudly if the lateral path
  // doesn't actually contain the sandbox prefix as a substring (e.g.
  // due to a future change in the constants above).
  if (!LATERAL.includes(SANDBOX_PREFIX)) {
    console.error(
      `regen setup error: lateral path ${LATERAL} does not contain sandbox prefix ${SANDBOX_PREFIX}`,
    );
    process.exit(2);
  }

  const underlying = createMockFsClient();

  const cap = issueSandboxReadCapability({ sandboxPrefix: SANDBOX_PREFIX, caller: CALLER });
  const { client, receipts } = await createGuardedFsClient({
    capability: cap,
    caller: CALLER,
    underlying,
  });

  // Reproduce the foot-gun: issue a read against the lateral path.
  // EXPECTED outcome (the bug): the call succeeds.
  let allowed = false;
  let returnedContent: string | null = null;
  try {
    returnedContent = (await client.callTool("read_file", { path: LATERAL })) as string;
    allowed = true;
  } catch (err) {
    console.error(
      "UNEXPECTED: capnagent denied the lateral-path read. The bug may have been fixed (or the engine gained path-aware semantics). Investigate before assuming this is a regression.",
    );
    console.error(err);
    process.exit(3);
  }

  if (!allowed || returnedContent === null) {
    console.error("UNEXPECTED: lateral read did not return content; cannot capture evidence.");
    process.exit(3);
  }
  if (underlying.log.length !== 1) {
    console.error(`unexpected underlying-call count: ${underlying.log.length} (expected 1)`);
    process.exit(3);
  }
  if (receipts.length !== 1) {
    console.error(`unexpected receipt count: ${receipts.length} (expected 1)`);
    process.exit(3);
  }

  const receipt = receipts[0] as { outcome: { kind: string; reason?: string } };
  if (receipt.outcome.kind !== "allowed") {
    console.error(
      `UNEXPECTED: receipt outcome is ${receipt.outcome.kind}, expected "allowed" (the bug evidence).`,
    );
    process.exit(3);
  }

  // Write the receipt to the evidence dir. The script lives at
  // examples/mcp-fs-agent/src/bin/regen-purple-evidence-07.ts so the
  // repo root is four `..` up.
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..", "..");
  const evidencePath = path.join(
    repoRoot,
    "docs",
    "purple-team",
    "evidence",
    "07-sandbox-prefix-footgun.receipt.json",
  );

  await fs.mkdir(path.dirname(evidencePath), { recursive: true });
  await fs.writeFile(evidencePath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");

  console.log(`Wrote evidence to ${evidencePath}`);
  console.log("");
  console.log(`Lateral path read (allowed by substring foot-gun): ${LATERAL}`);
  console.log(`Sandbox prefix the operator passed: ${SANDBOX_PREFIX}`);
  console.log(`Returned content: ${JSON.stringify(returnedContent)}`);
  console.log("");
  console.log("Receipt:");
  console.log(JSON.stringify(receipt, null, 2));
}

main().catch((err) => {
  console.error("error:", err);
  process.exit(1);
});
