/**
 * Live-server integration test against the official
 * `@modelcontextprotocol/server-filesystem`.
 *
 * Opt-in: only runs when `CAPNAGENT_MCP_LIVE=1` is set in the
 * environment. The default `npm test` skips this file because:
 *
 *   - it spawns `npx @modelcontextprotocol/server-filesystem` which
 *     fetches from npm on first run (slow, network-dependent),
 *   - it adds non-trivial test latency,
 *   - the in-process `fs.test.ts` already covers the capability gate's
 *     allow/deny matrix deterministically.
 *
 * The point of this file is the integration question: "does the SDK
 * client wired through `adaptMCPSDKClient` actually behave the same
 * way under capnagent?" If the in-process tests pass and this one
 * passes, callers can swap `FsClient` for the SDK with confidence.
 *
 * Run with:
 *
 *     CAPNAGENT_MCP_LIVE=1 npm test -w @capnagent-examples/mcp-fs-agent
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { Auditor, type Capability, type Context, Issuer, Verifier, init } from "@capnagent/core";
import { CapabilityDeniedError, type WrapOptions, wrapMCPClient } from "@capnagent/mcp";

import { adaptMCPSDKClient } from "../mcp-adapter.js";

const ROOT_KEY = new Uint8Array(32).fill(0xb1);
const AUDIT_KEY = new Uint8Array(32).fill(0xb2);
const CALLER = "agent:live-fs";

const live = process.env["CAPNAGENT_MCP_LIVE"] === "1";

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

interface LiveHarness {
  sandbox: string;
  outside: string;
  guarded: ReturnType<typeof wrapMCPClient>;
  underlying: ReturnType<typeof adaptMCPSDKClient>;
  client: Client;
  receipts: unknown[];
  cleanup: () => Promise<void>;
}

async function setupLive(): Promise<LiveHarness> {
  await init();
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-live-mcp-test-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(sandbox, "hello.txt"), "hi from sandbox", "utf8");
  await fs.writeFile(path.join(outside, "secret.txt"), "do not read", "utf8");

  const transport = new StdioClientTransport({
    command: "npx",
    args: ["-y", "@modelcontextprotocol/server-filesystem", sandbox, outside],
  });
  const client = new Client({ name: "capnagent-fs-live-test", version: "0.0.1" }, {});
  await client.connect(transport);

  const adapted = adaptMCPSDKClient(client);
  const cap = issueLiveSandboxCapability(sandbox);
  const receipts: unknown[] = [];

  const options: WrapOptions = {
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
  const guarded = wrapMCPClient(adapted, options);

  return {
    sandbox,
    outside,
    guarded,
    underlying: adapted,
    client,
    receipts,
    cleanup: async () => {
      await client.close();
      await fs.rm(root, { recursive: true, force: true });
    },
  };
}

describe.skipIf(!live)("live MCP filesystem server (CAPNAGENT_MCP_LIVE=1)", () => {
  let h: LiveHarness;

  beforeAll(async () => {
    h = await setupLive();
  }, 60_000);

  afterAll(async () => {
    await h.cleanup();
  });

  it("read_text_file inside sandbox is allowed and reaches the server", async () => {
    const result = (await h.guarded.callTool("read_text_file", {
      path: path.join(h.sandbox, "hello.txt"),
    })) as { content: Array<{ type: string; text?: string }> };
    expect(Array.isArray(result.content)).toBe(true);
    expect(h.underlying.log.map((e) => e.tool)).toContain("read_text_file");
  });

  it("read_text_file OUTSIDE sandbox is denied — server never sees it", async () => {
    const beforeCount = h.underlying.log.length;
    await expect(
      h.guarded.callTool("read_text_file", {
        path: path.join(h.outside, "secret.txt"),
      }),
    ).rejects.toBeInstanceOf(CapabilityDeniedError);
    expect(h.underlying.log.length).toBe(beforeCount);
  });

  it("write_file is denied — capnagent has no clause permitting it", async () => {
    const beforeCount = h.underlying.log.length;
    await expect(
      h.guarded.callTool("write_file", {
        path: path.join(h.sandbox, "new.txt"),
        content: "should not be written",
      }),
    ).rejects.toBeInstanceOf(CapabilityDeniedError);
    expect(h.underlying.log.length).toBe(beforeCount);
    await expect(fs.stat(path.join(h.sandbox, "new.txt"))).rejects.toThrow();
  });
});
