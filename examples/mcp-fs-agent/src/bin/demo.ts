/**
 * Runnable demo for the sandbox-scoped filesystem agent.
 *
 *   npm run -w @capnagent-examples/mcp-fs-agent demo
 *
 * Creates a fresh sandbox under the OS temp dir, populates it with a few
 * files, then exercises the capability boundary:
 *
 *   1. read a file inside the sandbox       → allowed
 *   2. list the sandbox directory           → allowed
 *   3. read a file *outside* the sandbox    → denied
 *   4. attempt to write a file              → denied
 *   5. attempt to delete a file             → denied
 *
 * Every decision (allow or deny) is captured in a signed receipt; the
 * demo prints the count + outcome of each at the end.
 *
 * No LLM is involved. The "agent" here is a deterministic script. The
 * point is the capability boundary, not the model.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import { createGuardedFsClient, issueSandboxReadCapability } from "../index.js";

const DIM = "\x1b[2m";
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";

const CALLER = "agent:fs";

interface Step {
  label: string;
  tool: string;
  args: Record<string, unknown>;
  expect: "allow" | "deny";
}

async function main(): Promise<void> {
  await init();

  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-fs-demo-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(sandbox, "hello.txt"), "hi from sandbox", "utf8");
  await fs.writeFile(path.join(outside, "secret.txt"), "do not read", "utf8");

  console.log(`${BOLD}${CYAN}capnagent mcp-fs-agent demo${RESET}`);
  console.log(`${DIM}sandbox:${RESET} ${sandbox}`);
  console.log(`${DIM}outside:${RESET} ${outside}\n`);

  const cap = issueSandboxReadCapability({ sandboxPrefix: sandbox, caller: CALLER });
  const { client, underlying, receipts } = await createGuardedFsClient({
    capability: cap,
    caller: CALLER,
  });

  const steps: Step[] = [
    {
      label: "read_file inside sandbox",
      tool: "read_file",
      args: { path: path.join(sandbox, "hello.txt") },
      expect: "allow",
    },
    {
      label: "list_directory inside sandbox",
      tool: "list_directory",
      args: { path: sandbox },
      expect: "allow",
    },
    {
      label: "read_file OUTSIDE sandbox",
      tool: "read_file",
      args: { path: path.join(outside, "secret.txt") },
      expect: "deny",
    },
    {
      label: "write_file inside sandbox",
      tool: "write_file",
      args: { path: path.join(sandbox, "new.txt"), content: "should not be written" },
      expect: "deny",
    },
    {
      label: "delete_path inside sandbox",
      tool: "delete_path",
      args: { path: path.join(sandbox, "hello.txt") },
      expect: "deny",
    },
  ];

  for (const step of steps) {
    process.stdout.write(`→ ${step.label}\n  ${DIM}${JSON.stringify(step.args)}${RESET}\n`);
    try {
      const result = await client.callTool(step.tool, step.args);
      if (step.expect === "deny") {
        console.error(`  ${RED}✗ UNEXPECTEDLY ALLOWED${RESET}`);
        process.exit(3);
      }
      const preview = JSON.stringify(result).slice(0, 80);
      console.log(`  ${GREEN}✓ allowed${RESET} ${DIM}${preview}${RESET}\n`);
    } catch (err) {
      if (err instanceof CapabilityDeniedError) {
        if (step.expect === "allow") {
          console.error(`  ${RED}✗ UNEXPECTEDLY DENIED${RESET}: ${err.message}`);
          process.exit(3);
        }
        const reason =
          err.receipt.outcome.kind === "denied" ? err.receipt.outcome.reason : "(no reason)";
        console.log(`  ${GREEN}✓ denied${RESET} ${DIM}${reason}${RESET}\n`);
      } else {
        throw err;
      }
    }
  }

  // Sanity: only the two allowed reads + list should have hit the
  // underlying client.
  const reachedTools = underlying.log.map((e) => e.tool).sort();
  const expectedReached = ["list_directory", "read_file"];
  const ok =
    reachedTools.length === expectedReached.length &&
    reachedTools.every((t, i) => t === expectedReached[i]);

  console.log(`${BOLD}─── result ───${RESET}`);
  console.log(`receipts emitted: ${receipts.length}`);
  console.log(
    `tools that reached the underlying fs: ${ok ? `${GREEN}${JSON.stringify(reachedTools)}${RESET}` : `${RED}${JSON.stringify(reachedTools)}${RESET}`}`,
  );
  if (!ok) {
    console.error(
      `${RED}${BOLD}SECURITY FAILURE — wrong tools reached the underlying surface.${RESET}`,
    );
    process.exit(3);
  }

  // Cleanup.
  await fs.rm(root, { recursive: true, force: true });
}

main().catch((err) => {
  console.error(`${RED}error:${RESET}`, err);
  process.exit(1);
});
