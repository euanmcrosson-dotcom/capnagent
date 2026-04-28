/**
 * Purple-team PoC for `docs/purple-team/07-sandbox-prefix-footgun.md`.
 *
 * # Threat model
 *
 * Round 01 closed `holds-with-caveat` for the fs-sandbox defense and
 * explicitly noted as residual risk that the caveat DSL's `matches`
 * operator is implemented as substring containment (see
 * `crates/capnagent-core/src/caveat_dsl.rs` line ~752 — `String::contains`).
 * The round-01 PoC sidestepped the issue by using a per-test random
 * tempdir (so no sibling directory could collide). That made the
 * defense look path-aware. It isn't.
 *
 * This round tests what happens when an operator picks a sandbox
 * prefix that LOOKS like a path-prefix but, because `matches` is
 * substring containment, accidentally also permits reads to unrelated
 * directories whose absolute paths contain the prefix as a substring.
 *
 * Concrete attack shape:
 *   - Operator issues a cap via
 *     `issueSandboxReadCapability({ sandboxPrefix: "/srv/app", caller })`.
 *     The validator at `examples/mcp-fs-agent/src/index.ts` requires the
 *     prefix to be ≥ 8 chars AND contain a path separator. `/srv/app`
 *     satisfies both — issuance is silently accepted.
 *   - A subsequent `read_file` against `/etc/srv/app-leaked-secret`
 *     SHOULD be denied (it is not under the sandbox in any
 *     path-aware sense), but the substring `/srv/app` IS contained in
 *     `/etc/srv/app-leaked-secret`, so the caveat passes and the read
 *     is allowed.
 *
 * # Why the harness uses a mock FsClient (not real fs.readFile)
 *
 * Round 01's PoC writes real files under `os.tmpdir()` because its
 * collisions are constructed only against the unique-tempdir absolute
 * path. Round 07 needs to demonstrate the foot-gun for *literal*
 * production-shaped prefixes like `/srv/app`, where the bug fires
 * against paths like `/etc/srv/app-leaked-secret` that we obviously
 * cannot create on a CI machine. The harness therefore provides a
 * mock `FsClient` whose `callTool` returns canned responses keyed on
 * path string. All paths are pure strings; the security claim is
 * about whether capnagent's gate ALLOWS the call through to the
 * underlying client, not about what the underlying client does.
 *
 * # Hypothesis (both halves required)
 *
 * Positive (true-positive): given a cap issued via
 * `issueSandboxReadCapability({ sandboxPrefix: "/srv/app", caller })`,
 * a `read_file` call whose `arg.path` is a SIBLING/LATERAL path
 * containing `/srv/app` as a substring (e.g. `/etc/srv/app-leaked-secret`)
 * MUST be denied at the gate. **EXPECTED TO FAIL** — that's the
 * round's central finding. The PoC asserts the FAILURE outcome (the
 * read is allowed) so the test passes when the bug is present and
 * would fail (loudly) if the engine ever gained path-aware semantics.
 *
 * Negative (true-negative): the same cap continues to ALLOW legit
 * in-sandbox paths (`/srv/app/config.json`) and DENY obviously-out-of-
 * sandbox paths that don't share the substring (`/home/user/.ssh/id_rsa`
 * — round 01 regression).
 *
 * # Non-coverage
 *
 *   - URL-encoded path traversal (`%2e%2e%2f`) — orthogonal class.
 *   - Unicode-confusable lookalikes — orthogonal class.
 *   - Symlink escape from inside the sandbox — orthogonal class
 *     (round 01 noted this; OS-level normalization is the fix).
 *   - Rust-side equivalent: same `String::contains` lives at
 *     `caveat_dsl.rs` ~752, so the same finding holds for the Rust
 *     verifier path. Out of scope for this TS-side PoC.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { init } from "@capnagent/core";
import { CapabilityDeniedError, type MCPClientLike } from "@capnagent/mcp";

import type { FsCallLog, FsClient } from "../fs-client.js";
import { createGuardedFsClient, issueSandboxReadCapability } from "../index.js";

const CALLER = "agent:fs";
const SANDBOX_PREFIX = "/srv/app";

/**
 * The literal in-sandbox path the negative-hypothesis test reads.
 */
const LEGIT_INSIDE = "/srv/app/config.json";

/**
 * Lateral path: NOT under `/srv/app`, but its absolute path contains
 * `/srv/app` as a substring (`/etc/srv/app-leaked-secret`). This is
 * the canonical foot-gun shape — substring containment fires.
 */
const LATERAL = "/etc/srv/app-leaked-secret";

/**
 * Trailing-character collision: `/srv/app-shadow/secret` starts with
 * the sandbox prefix verbatim, but the next character is `-` rather
 * than `/`. A path-aware prefix-match would reject this; substring
 * containment allows it.
 */
const TRAILING_SHADOW = "/srv/app-shadow/secret";

/**
 * Embedded-prefix path: contains the sandbox prefix mid-string, not
 * at position 0. Substring containment doesn't care where in the
 * string the match occurs.
 */
const EMBEDDED = "/var/log/srv/app/backup";

/**
 * Obviously out-of-sandbox: absolute path does NOT contain the
 * sandbox prefix as a substring. Round 01 regression — defense
 * still holds for this case.
 */
const OBVIOUSLY_OUTSIDE = "/home/user/.ssh/id_rsa";

/**
 * Build a structural FsClient that returns canned responses keyed on
 * the path string. Paths are pure strings; nothing touches the real
 * filesystem. The `log` field records every call that reached the
 * mock — the assertion-of-record for "did capnagent's gate allow
 * the call through to the underlying client?".
 */
function createMockFsClient(responses: Record<string, string>): FsClient {
  const log: FsCallLog[] = [];

  const callTool: MCPClientLike["callTool"] = async (name, args) => {
    log.push({ tool: name, args });
    const path = (args as { path?: unknown }).path;
    if (typeof path !== "string") {
      throw new Error(`mock fs client: missing path arg for ${name}`);
    }
    switch (name) {
      case "read_file": {
        const data = responses[path];
        if (data === undefined) {
          throw new Error(`mock fs client: no canned response for ${path}`);
        }
        return data;
      }
      case "list_directory": {
        // Return a single fake entry indicating the call landed.
        return [{ name: "PRETEND-SECRET", kind: "file" as const }];
      }
      case "directory_tree": {
        return { path, kind: "directory" as const, children: [] };
      }
      case "write_file":
      case "create_directory":
      case "delete_path":
        // Should never be reached (caps don't permit writes); if
        // capnagent ever lets one through, this throw makes the
        // failure visible.
        throw new Error(`mock fs client: write tool ${name} should not be invoked`);
      default:
        throw new Error(`mock fs client: unknown tool ${name}`);
    }
  };

  return {
    callTool,
    get log() {
      return log;
    },
  };
}

interface PurpleHarness {
  underlying: FsClient;
  client: Awaited<ReturnType<typeof createGuardedFsClient>>["client"];
  receipts: ReadonlyArray<unknown>;
}

let h: PurpleHarness;

beforeAll(async () => {
  await init();
});

async function makeHarness(): Promise<PurpleHarness> {
  const underlying = createMockFsClient({
    [LEGIT_INSIDE]: "legit-in-sandbox-content",
    [LATERAL]: "PRETEND LATERAL SECRET — bug allows this",
    [TRAILING_SHADOW]: "PRETEND TRAILING-SHADOW SECRET",
    [EMBEDDED]: "PRETEND EMBEDDED-PATH SECRET",
    [OBVIOUSLY_OUTSIDE]: "PRETEND PRIVATE KEY",
  });

  // Construction sanity: confirm the collision shapes really do
  // contain the sandbox prefix as a substring, and that the
  // obviously-outside path does NOT. If a future change to the
  // chosen paths breaks this, fail fast in setup rather than
  // silently asserting nothing meaningful in the body.
  for (const collision of [LATERAL, TRAILING_SHADOW, EMBEDDED]) {
    if (!collision.includes(SANDBOX_PREFIX)) {
      throw new Error(
        `harness setup error: collision path ${collision} does not contain sandboxPrefix ${SANDBOX_PREFIX}`,
      );
    }
  }
  if (OBVIOUSLY_OUTSIDE.includes(SANDBOX_PREFIX)) {
    throw new Error(
      `harness setup error: OBVIOUSLY_OUTSIDE ${OBVIOUSLY_OUTSIDE} unexpectedly contains the sandbox prefix`,
    );
  }

  const cap = issueSandboxReadCapability({ sandboxPrefix: SANDBOX_PREFIX, caller: CALLER });
  const guarded = await createGuardedFsClient({ capability: cap, caller: CALLER, underlying });

  return {
    underlying,
    client: guarded.client,
    receipts: guarded.receipts,
  };
}

beforeEach(async () => {
  h = await makeHarness();
});

afterEach(() => {
  // No fs cleanup needed — pure-string mock harness.
});

describe("Round 07: fs-sandbox prefix foot-gun [CLOSED v0.5]", () => {
  describe("the foot-gun is closed: lateral / shadow / embedded paths are now denied", () => {
    it("lateral path containing the prefix as substring is DENIED", async () => {
      // v0.5 closure: the issued caveat uses anchored `starts_with`
      // (not substring `matches`) and the prefix carries a trailing
      // separator, so `/etc/srv/app-leaked-secret` does not satisfy
      // `arg.path starts_with "/srv/app/"`. The Context provider
      // additionally canonicalizes any path-shaped arg, so encoding
      // tricks (round 10) collapse to the same comparison.
      await expect(
        h.client.callTool("read_file", { path: LATERAL }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);

      // The underlying client never saw the call.
      expect(h.underlying.log).toEqual([]);

      // Receipt records `denied`.
      expect(h.receipts).toHaveLength(1);
      expect((h.receipts[0] as { outcome: { kind: string } }).outcome.kind).toBe("denied");
    });

    it("trailing-character collision (`/srv/app-shadow/...`) is DENIED", async () => {
      // The trailing-separator on the canonical prefix is what closes
      // this case: `/srv/app-shadow/secret` does not start with
      // `/srv/app/` because byte 8 is `-`, not `/`.
      await expect(
        h.client.callTool("read_file", { path: TRAILING_SHADOW }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });

    it("embedded-prefix path (`/var/log/srv/app/backup`) is DENIED", async () => {
      // Anchored prefix: the sandbox-prefix substring appearing
      // mid-string no longer satisfies the caveat. The path resolves
      // to `/var/log/srv/app/backup` (already absolute, no `..`),
      // which does not start with `/srv/app/`.
      await expect(
        h.client.callTool("read_file", { path: EMBEDDED }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });

    it("list_directory on a lateral dir is DENIED — same closure, different tool clause", async () => {
      // The closure applies uniformly to all three read clauses
      // (`read_file` / `list_directory` / `directory_tree`).
      await expect(
        h.client.callTool("list_directory", { path: LATERAL }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });

    it("path-traversal escape (`/srv/app/../etc/passwd`) is DENIED — closes round 10", async () => {
      // The Context provider runs `path.resolve` on agent-supplied
      // path args, which collapses `..` segments BEFORE the verifier
      // evaluates the caveat. `/srv/app/../etc/passwd` resolves to
      // `/etc/passwd`, which does not start with `/srv/app/`.
      await expect(
        h.client.callTool("read_file", { path: "/srv/app/../etc/passwd" }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });

    it("percent-encoded traversal (`/srv/app/%2e%2e/etc/passwd`) is DENIED — closes round 10", async () => {
      // The Context provider tries `decodeURIComponent` before
      // canonicalizing, so `%2e%2e` becomes `..` and is then
      // collapsed by `path.resolve`.
      await expect(
        h.client.callTool("read_file", { path: "/srv/app/%2e%2e/etc/passwd" }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });
  });

  describe("negative hypothesis (round 01 regression: defense still holds for the obvious cases)", () => {
    it("legit in-sandbox read is allowed and returns the file contents", async () => {
      const result = (await h.client.callTool("read_file", {
        path: LEGIT_INSIDE,
      })) as string;
      expect(result).toBe("legit-in-sandbox-content");
      expect(h.underlying.log.map((e) => e.tool)).toEqual(["read_file"]);
    });

    it("obviously out-of-sandbox path (no prefix substring) is denied", async () => {
      // Round 01 regression: a path that does NOT contain the
      // sandbox-prefix substring is correctly denied. The bug is
      // specifically about paths that DO contain the substring.
      await expect(
        h.client.callTool("read_file", { path: OBVIOUSLY_OUTSIDE }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);

      expect(h.receipts).toHaveLength(1);
      expect((h.receipts[0] as { outcome: { kind: string } }).outcome.kind).toBe("denied");
    });

    it("write_file to ANY path remains denied (no clause permits writes)", async () => {
      // Sanity: even for a path that would pass the substring
      // foot-gun, writes have no allow clause, so write is denied
      // independent of the prefix bug. This isolates the bug to
      // the read-tool clauses.
      await expect(
        h.client.callTool("write_file", {
          path: LEGIT_INSIDE,
          content: "should-not-write",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);
    });
  });

  describe("issuance gap (the foot-gun-able prefix is accepted without warning)", () => {
    it("issueSandboxReadCapability accepts a prefix shaped like `/srv/app` without warning", () => {
      // The validator checks: length ≥ 8 AND contains a path separator.
      // `/srv/app` is 8 chars and contains `/`, so it slips through.
      expect(() =>
        issueSandboxReadCapability({ sandboxPrefix: "/srv/app", caller: CALLER }),
      ).not.toThrow();

      // Other foot-gun-able prefixes the validator currently waves
      // through (all are short common-substring shapes that would
      // collide with many unrelated paths).
      const accepted = ["/srv/app", "/var/log", "/usr/lib", "C:\\srv\\app"];
      for (const p of accepted) {
        expect(() =>
          issueSandboxReadCapability({ sandboxPrefix: p, caller: CALLER }),
        ).not.toThrow();
      }
    });

    it("validator DOES still reject too-short prefixes (e.g. `/tmp`)", () => {
      // Documents the existing gate the validator does enforce.
      // `/tmp` is 4 chars (< 8) — rejected. `/tmp/x` is 6 (< 8) —
      // rejected. The existing gate is a length gate, not a
      // path-aware gate.
      expect(() => issueSandboxReadCapability({ sandboxPrefix: "/tmp", caller: CALLER })).toThrow(
        /sandboxPrefix/,
      );
      expect(() => issueSandboxReadCapability({ sandboxPrefix: "/tmp/x", caller: CALLER })).toThrow(
        /sandboxPrefix/,
      );
      // No separator at all — also rejected.
      expect(() =>
        issueSandboxReadCapability({ sandboxPrefix: "abcdefghij", caller: CALLER }),
      ).toThrow(/sandboxPrefix/);
    });
  });
});
