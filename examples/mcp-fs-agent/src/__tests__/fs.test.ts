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
  issueSandboxWriteCapability,
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

    it("rejects same-shape preconditions on write capability", () => {
      expect(() => issueSandboxWriteCapability({ sandboxPrefix: "short", caller: CALLER })).toThrow(
        /unique path-like prefix/,
      );
    });
  });

  // ─── v0.5.1: read-side coverage expansion ────────────────────────

  describe("read-side coverage (v0.5.1: 3 → 6 tools)", () => {
    it("read_text_file inside the sandbox is allowed (alias of read_file)", async () => {
      const result = await h.client.callTool("read_text_file", {
        path: path.join(h.sandbox, "hello.txt"),
      });
      expect(result).toBe("hi from sandbox");
      expect(logToolNames(h.underlying.log)).toEqual(["read_text_file"]);
    });

    it("read_text_file outside the sandbox is denied", async () => {
      await expect(
        h.client.callTool("read_text_file", { path: path.join(h.outside, "secret.txt") }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });

    it("list_directory_with_sizes inside is allowed and returns sizes", async () => {
      const entries = (await h.client.callTool("list_directory_with_sizes", {
        path: h.sandbox,
      })) as Array<{ name: string; size: number }>;
      expect(entries.some((e) => e.name === "hello.txt" && e.size > 0)).toBe(true);
      expect(logToolNames(h.underlying.log)).toEqual(["list_directory_with_sizes"]);
    });

    it("list_directory_with_sizes outside is denied", async () => {
      await expect(
        h.client.callTool("list_directory_with_sizes", { path: h.outside }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });

    it("get_file_info inside is allowed and returns stat-shaped data", async () => {
      const info = (await h.client.callTool("get_file_info", {
        path: path.join(h.sandbox, "hello.txt"),
      })) as { kind: string; size: number };
      expect(info.kind).toBe("file");
      expect(info.size).toBeGreaterThan(0);
    });

    it("get_file_info outside is denied", async () => {
      await expect(
        h.client.callTool("get_file_info", { path: path.join(h.outside, "secret.txt") }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });
  });

  // ─── v0.5.1: write-side capability ───────────────────────────────

  describe("write-side capability (new in v0.5.1)", () => {
    let writeHarness: Harness;
    beforeEach(async () => {
      // Build a parallel harness with the WRITE capability.
      const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-fs-write-test-"));
      const sandbox = path.join(root, "sandbox");
      const outside = path.join(root, "outside");
      await fs.mkdir(sandbox, { recursive: true });
      await fs.mkdir(outside, { recursive: true });
      await fs.writeFile(path.join(sandbox, "existing.txt"), "original", "utf8");

      const cap = issueSandboxWriteCapability({ sandboxPrefix: sandbox, caller: CALLER });
      const { client, underlying, receipts } = await createGuardedFsClient({
        capability: cap,
        caller: CALLER,
      });
      writeHarness = { sandbox, outside, client, underlying, receipts };
    });

    afterEach(async () => {
      await fs.rm(path.dirname(writeHarness.sandbox), { recursive: true, force: true });
    });

    it("write_file inside the sandbox is allowed", async () => {
      const target = path.join(writeHarness.sandbox, "new.txt");
      await writeHarness.client.callTool("write_file", { path: target, content: "hello" });
      const onDisk = await fs.readFile(target, "utf8");
      expect(onDisk).toBe("hello");
    });

    it("write_file outside the sandbox is denied", async () => {
      await expect(
        writeHarness.client.callTool("write_file", {
          path: path.join(writeHarness.outside, "evil.txt"),
          content: "x",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      await expect(fs.stat(path.join(writeHarness.outside, "evil.txt"))).rejects.toThrow();
    });

    it("edit_file inside the sandbox is allowed and performs the replacement", async () => {
      const target = path.join(writeHarness.sandbox, "existing.txt");
      const result = (await writeHarness.client.callTool("edit_file", {
        path: target,
        find: "original",
        replace: "edited",
      })) as { replaced: number };
      expect(result.replaced).toBe(1);
      expect(await fs.readFile(target, "utf8")).toBe("edited");
    });

    it("edit_file outside the sandbox is denied", async () => {
      await expect(
        writeHarness.client.callTool("edit_file", {
          path: path.join(writeHarness.outside, "x"),
          find: "a",
          replace: "b",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
    });

    it("create_directory inside the sandbox is allowed", async () => {
      const target = path.join(writeHarness.sandbox, "subdir");
      await writeHarness.client.callTool("create_directory", { path: target });
      const stat = await fs.stat(target);
      expect(stat.isDirectory()).toBe(true);
    });

    it("create_directory outside is denied", async () => {
      await expect(
        writeHarness.client.callTool("create_directory", {
          path: path.join(writeHarness.outside, "subdir"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
    });

    it("move_file with BOTH source and destination inside is allowed", async () => {
      const src = path.join(writeHarness.sandbox, "existing.txt");
      const dst = path.join(writeHarness.sandbox, "moved.txt");
      await writeHarness.client.callTool("move_file", { source: src, destination: dst });
      await expect(fs.stat(dst)).resolves.toBeTruthy();
      await expect(fs.stat(src)).rejects.toThrow();
    });

    it("move_file with source OUTSIDE the sandbox is denied", async () => {
      await fs.writeFile(path.join(writeHarness.outside, "evil-src.txt"), "x", "utf8");
      await expect(
        writeHarness.client.callTool("move_file", {
          source: path.join(writeHarness.outside, "evil-src.txt"),
          destination: path.join(writeHarness.sandbox, "imported.txt"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      await expect(fs.stat(path.join(writeHarness.sandbox, "imported.txt"))).rejects.toThrow();
    });

    it("move_file with destination OUTSIDE the sandbox is denied", async () => {
      await expect(
        writeHarness.client.callTool("move_file", {
          source: path.join(writeHarness.sandbox, "existing.txt"),
          destination: path.join(writeHarness.outside, "exfiltrated.txt"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      // Source still exists (move was denied before any rename happened).
      await expect(fs.stat(path.join(writeHarness.sandbox, "existing.txt"))).resolves.toBeTruthy();
    });

    it("read_file is denied under a WRITE-only capability", async () => {
      // The write cap explicitly does NOT grant read authority. Cross-
      // capability check: an agent holding only the write cap can't
      // pivot to reads.
      await expect(
        writeHarness.client.callTool("read_file", {
          path: path.join(writeHarness.sandbox, "existing.txt"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
    });

    it("delete_path is denied under WRITE cap — example never authorises deletion", async () => {
      await expect(
        writeHarness.client.callTool("delete_path", {
          path: path.join(writeHarness.sandbox, "existing.txt"),
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      await expect(fs.stat(path.join(writeHarness.sandbox, "existing.txt"))).resolves.toBeTruthy();
    });
  });

  // ─── v0.5.1: deliberately out-of-scope tools stay denied ─────────

  describe("out-of-scope tools (deliberately denied under read cap)", () => {
    it("read_multiple_files is denied — array-shape constraint, DSL limitation", async () => {
      await expect(
        h.client.callTool("read_multiple_files", {
          paths: [path.join(h.sandbox, "hello.txt")],
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
    });

    it("search_files is denied — would broaden sandbox to whatever search finds", async () => {
      await expect(
        h.client.callTool("search_files", { path: h.sandbox, pattern: "*.txt" }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
    });

    it("list_allowed_directories is denied — operator-choice to allow unconditionally", async () => {
      await expect(h.client.callTool("list_allowed_directories", {})).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );
    });
  });
});
