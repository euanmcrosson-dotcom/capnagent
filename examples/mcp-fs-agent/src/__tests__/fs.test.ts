/**
 * Allow/deny matrix for the sandbox-scoped filesystem agent.
 *
 *   - read inside sandbox     → allowed, reaches underlying client
 *   - list inside sandbox     → allowed, reaches underlying client
 *   - tree inside sandbox     → allowed, reaches underlying client
 *   - read outside sandbox    → denied, never reaches underlying client
 *   - write inside sandbox    → denied (no clause permits write_file)
 *   - delete inside sandbox   → denied (no clause permits delete_path)
 *   - mkdir inside sandbox    → denied (no clause permits create_directory)
 *
 * Every test asserts BOTH that the call was correctly allowed/denied AND
 * that the underlying client's `log` reflects only the allowed calls.
 * This is the assertion-of-record for capnagent's central claim: out-of-
 * scope calls do not reach the underlying tool surface.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import {
  type FsCallLog,
  type FsClient,
  createGuardedFsClient,
  issueSandboxReadCapability,
} from "../index.js";

const CALLER = "agent:fs";

interface Harness {
  sandbox: string;
  outside: string;
  client: FsClient;
  underlying: FsClient;
  receipts: ReadonlyArray<unknown>;
}

async function makeHarness(): Promise<Harness> {
  // Two siblings: sandbox/ (in scope) and outside/ (out of scope).
  // Both live under a unique tempdir so the substring `matches` test
  // can't be tricked into accepting an outside path.
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-fs-test-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(sandbox, "hello.txt"), "hi from sandbox", "utf8");
  await fs.writeFile(path.join(outside, "secret.txt"), "do not read", "utf8");

  const cap = issueSandboxReadCapability({ sandboxPrefix: sandbox, caller: CALLER });
  const { client, underlying, receipts } = await createGuardedFsClient({
    capability: cap,
    caller: CALLER,
  });
  return { sandbox, outside, client, underlying, receipts };
}

let h: Harness;

beforeAll(async () => {
  await init();
});

beforeEach(async () => {
  h = await makeHarness();
});

afterEach(async () => {
  // Best-effort cleanup; test root is in os.tmpdir() so the OS will
  // reclaim it eventually anyway.
  await fs.rm(path.dirname(h.sandbox), { recursive: true, force: true });
});

function logToolNames(log: ReadonlyArray<FsCallLog>): string[] {
  return log.map((e) => e.tool);
}

describe("sandbox-scoped filesystem agent", () => {
  describe("allow path", () => {
    it("read_file inside the sandbox is allowed", async () => {
      const result = await h.client.callTool("read_file", {
        path: path.join(h.sandbox, "hello.txt"),
      });
      expect(result).toBe("hi from sandbox");
      expect(logToolNames(h.underlying.log)).toEqual(["read_file"]);
      expect(h.receipts).toHaveLength(1);
    });

    it("list_directory inside the sandbox is allowed", async () => {
      const entries = (await h.client.callTool("list_directory", {
        path: h.sandbox,
      })) as Array<{ name: string }>;
      expect(entries.map((e) => e.name).sort()).toEqual(["hello.txt"]);
      expect(logToolNames(h.underlying.log)).toEqual(["list_directory"]);
    });

    it("directory_tree inside the sandbox is allowed", async () => {
      const tree = (await h.client.callTool("directory_tree", {
        path: h.sandbox,
      })) as { kind: string };
      expect(tree.kind).toBe("directory");
      expect(logToolNames(h.underlying.log)).toEqual(["directory_tree"]);
    });
  });

  describe("deny path", () => {
    it("read_file outside the sandbox is denied — underlying never sees it", async () => {
      await expect(
        h.client.callTool("read_file", {
          path: path.join(h.outside, "secret.txt"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });

    it("write_file is denied even inside the sandbox — capability has no write clause", async () => {
      await expect(
        h.client.callTool("write_file", {
          path: path.join(h.sandbox, "new.txt"),
          content: "should not be written",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
      // And the file genuinely was not created on disk.
      await expect(fs.stat(path.join(h.sandbox, "new.txt"))).rejects.toThrow();
    });

    it("create_directory is denied — no caveat clause matches", async () => {
      await expect(
        h.client.callTool("create_directory", {
          path: path.join(h.sandbox, "subdir"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
      await expect(fs.stat(path.join(h.sandbox, "subdir"))).rejects.toThrow();
    });

    it("delete_path is denied — no caveat clause matches", async () => {
      await expect(
        h.client.callTool("delete_path", {
          path: path.join(h.sandbox, "hello.txt"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
      // hello.txt is still there.
      const stat = await fs.stat(path.join(h.sandbox, "hello.txt"));
      expect(stat.isFile()).toBe(true);
    });
  });

  describe("denial receipts", () => {
    it("every denied call produces a receipt with outcome.kind === 'denied'", async () => {
      await expect(
        h.client.callTool("read_file", {
          path: path.join(h.outside, "secret.txt"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      await expect(
        h.client.callTool("write_file", {
          path: path.join(h.sandbox, "x.txt"),
          content: "x",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);

      expect(h.receipts).toHaveLength(2);
      for (const r of h.receipts) {
        const outcome = (r as { outcome: { kind: string } }).outcome;
        expect(outcome.kind).toBe("denied");
      }
    });
  });

  describe("issuance preconditions", () => {
    it("rejects sandbox prefixes that aren't path-like enough to be safe with `matches`", () => {
      expect(() => issueSandboxReadCapability({ sandboxPrefix: "short", caller: CALLER })).toThrow(
        /unique path-like prefix/,
      );
      expect(() =>
        issueSandboxReadCapability({ sandboxPrefix: "no-slashes-here-yo", caller: CALLER }),
      ).toThrow(/unique path-like prefix/);
    });
  });
});
