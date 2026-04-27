/**
 * Live-MCP demo: spawn the official @modelcontextprotocol/server-filesystem,
 * adapt its SDK client to MCPClientLike, wrap through @capnagent/mcp with
 * a sandbox-scoped capability, and exercise the same allow/deny matrix as
 * the in-process demo — but against the REAL server.
 *
 *   npm run -w @capnagent-examples/mcp-fs-agent demo:live-mcp
 *
 * Requires `npx @modelcontextprotocol/server-filesystem` to be reachable
 * (the script invokes it via `npx -y` so it'll fetch on first run).
 *
 * The official server uses these tool names (as of 2026.1.x):
 *   - read_text_file       → allowed inside sandbox
 *   - list_directory       → allowed inside sandbox
 *   - directory_tree       → allowed inside sandbox
 *   - write_file           → denied (no caveat clause permits it)
 *   - create_directory     → denied
 *   - move_file            → denied
 *   - search_files         → denied (could be added; not in this cap)
 *
 * The capability we issue mirrors the in-process demo's read clauses
 * but uses the SDK's actual tool names.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { Auditor, type Capability, type Context, Issuer, Verifier, init } from "@capnagent/core";
import { CapabilityDeniedError, type WrapOptions, wrapMCPClient } from "@capnagent/mcp";

import { adaptMCPSDKClient } from "../mcp-adapter.js";

const DIM = "\x1b[2m";
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";

const ROOT_KEY = new Uint8Array(32).fill(0xb1);
const AUDIT_KEY = new Uint8Array(32).fill(0xb2);
const CALLER = "agent:live-fs";

function issueLiveSandboxCapability(sandboxPrefix: string): Capability {
  const escapedPrefix = sandboxPrefix.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const readPredicate =
    `(tool == "read_text_file" AND arg.path matches "${escapedPrefix}") ` +
    `OR (tool == "list_directory" AND arg.path matches "${escapedPrefix}") ` +
    `OR (tool == "directory_tree" AND arg.path matches "${escapedPrefix}")`;

  return Issuer.fromKey(ROOT_KEY)
    .issue("fs.read.live")
    .caveat(`caller == "${CALLER}"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .caveat(readPredicate)
    .build();
}

interface Step {
  label: string;
  tool: string;
  args: Record<string, unknown>;
  expect: "allow" | "deny";
}

async function main(): Promise<void> {
  await init();

  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-live-mcp-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(sandbox, "hello.txt"), "hi from sandbox", "utf8");
  await fs.writeFile(path.join(outside, "secret.txt"), "do not read", "utf8");

  console.log(`${BOLD}${CYAN}capnagent live-MCP fs-agent demo${RESET}`);
  console.log(`${DIM}sandbox:${RESET} ${sandbox}`);
  console.log(`${DIM}outside:${RESET} ${outside}`);
  console.log(`${DIM}server: @modelcontextprotocol/server-filesystem (via npx -y)${RESET}\n`);

  // The official filesystem server takes one or more allowed roots as
  // CLI args. We give it BOTH so we can demonstrate that even when the
  // server is configured to allow access to the outside path,
  // capnagent still denies the call before the server sees it.
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["-y", "@modelcontextprotocol/server-filesystem", sandbox, outside],
  });
  const sdkClient = new Client({ name: "capnagent-fs-live", version: "0.0.1" }, {});
  await sdkClient.connect(transport);

  try {
    const adapted = adaptMCPSDKClient(sdkClient);
    const cap = issueLiveSandboxCapability(sandbox);
    const receipts: unknown[] = [];

    const wrapOptions: WrapOptions = {
      capability: cap,
      auditor: new Auditor(AUDIT_KEY),
      verifier: new Verifier(ROOT_KEY),
      context: (toolName: string, callArgs: unknown): Context => ({
        caller: CALLER,
        tool: toolName,
        args: callArgs,
        nowMs: Date.now(),
      }),
      onReceipt: (r) => {
        receipts.push(r);
      },
    };
    const guarded = wrapMCPClient(adapted, wrapOptions);

    const steps: Step[] = [
      {
        label: "read_text_file inside sandbox",
        tool: "read_text_file",
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
        label: "read_text_file OUTSIDE sandbox (server CAN reach it; capnagent denies)",
        tool: "read_text_file",
        args: { path: path.join(outside, "secret.txt") },
        expect: "deny",
      },
      {
        label: "write_file inside sandbox",
        tool: "write_file",
        args: { path: path.join(sandbox, "new.txt"), content: "should not be written" },
        expect: "deny",
      },
    ];

    let exitCode = 0;
    for (const step of steps) {
      process.stdout.write(`→ ${step.label}\n  ${DIM}${JSON.stringify(step.args)}${RESET}\n`);
      try {
        const result = await guarded.callTool(step.tool, step.args);
        if (step.expect === "deny") {
          console.error(`  ${RED}✗ UNEXPECTEDLY ALLOWED${RESET}`);
          exitCode = 3;
          continue;
        }
        const preview = JSON.stringify(result).slice(0, 100);
        console.log(`  ${GREEN}✓ allowed${RESET} ${DIM}${preview}${RESET}\n`);
      } catch (err) {
        if (err instanceof CapabilityDeniedError) {
          if (step.expect === "allow") {
            console.error(`  ${RED}✗ UNEXPECTEDLY DENIED${RESET}: ${err.message}`);
            exitCode = 3;
            continue;
          }
          const reason =
            err.receipt.outcome.kind === "denied"
              ? err.receipt.outcome.reason.slice(0, 100)
              : "(no reason)";
          console.log(`  ${GREEN}✓ denied${RESET} ${DIM}${reason}${RESET}\n`);
        } else {
          throw err;
        }
      }
    }

    console.log(`${BOLD}─── result ───${RESET}`);
    console.log(`receipts emitted:                  ${receipts.length}`);
    console.log(`tool calls forwarded to MCP server: ${adapted.log.length}`);
    console.log(
      `tools that reached the MCP server: ${JSON.stringify(adapted.log.map((e) => e.tool))}`,
    );
    if (adapted.log.length !== 2 || exitCode !== 0) {
      console.error(`${RED}${BOLD}SECURITY FAILURE${RESET}`);
      process.exitCode = 3;
    }
  } finally {
    await sdkClient.close();
    await fs.rm(root, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(`${RED}error:${RESET}`, err);
  process.exit(1);
});
