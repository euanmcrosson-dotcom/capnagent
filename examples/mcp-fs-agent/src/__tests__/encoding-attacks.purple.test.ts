/**
 * Purple-team PoC for round 10 — encoding / normalization attacks
 * against the fs-sandbox defense.
 *
 * # The threat model
 *
 * Round 07 found that substring `matches` is not path-aware: lateral
 * paths sharing the prefix substring (`/etc/srv/app-leaked-secret`
 * vs. `/srv/app`) slip through. Round 10 tests a DIFFERENT class of
 * encoding attack: paths that contain the sandbox prefix AS A
 * SUBSTRING but resolve OUTSIDE the sandbox via path-traversal
 * sequences (`..`), Windows backslash separators, or Unicode
 * normalization tricks.
 *
 * The fundamental issue: capnagent's caveat sees the RAW string
 * bytes, but the underlying fs client (Node's `fs.readFile`)
 * RESOLVES `..` segments and normalizes separators before performing
 * the actual read. So the caveat sees `/sandbox/../etc/passwd`,
 * matches the `/sandbox/` substring, and ALLOWS the call. The fs
 * client then reads `/etc/passwd`. Defense BREAKS.
 *
 * # What this round adds beyond rounds 01 / 07
 *
 *   - Round 01: out-of-scope paths denied. Holds.
 *   - Round 07: lateral paths sharing substring. Breaks.
 *   - Round 10: paths CONTAINING the sandbox-prefix substring AND
 *     escaping via `..` / encoded separators. Breaks.
 *
 * Different attack shapes, same recommended fix (Context-provider
 * canonicalization + `starts_with` DSL operator). Round 10 widens
 * the case for the v0.5 fix.
 *
 * Status: BREAKS (defense does not hold for path-traversal-shaped
 * inputs). Recommended fix lands in v0.5 — same fix as round 07.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import { createGuardedFsClient, issueSandboxReadCapability } from "../index.js";

const CALLER = "agent:fs";

interface Harness {
  root: string;
  sandbox: string;
  outsideSecret: string;
  client: Awaited<ReturnType<typeof createGuardedFsClient>>["client"];
  underlying: Awaited<ReturnType<typeof createGuardedFsClient>>["underlying"];
  receipts: ReadonlyArray<unknown>;
}

let h: Harness;

beforeAll(async () => {
  await init();
});

async function makeHarness(): Promise<Harness> {
  // Root contains BOTH the sandbox and an "outside" sibling.
  // The path-traversal attack reads from outside via /sandbox/../outside.
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-encoding-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(sandbox, "legit.txt"), "in-sandbox content", "utf8");
  const outsideSecret = path.join(outside, "secret.txt");
  await fs.writeFile(outsideSecret, "OUT-OF-SANDBOX-SECRET", "utf8");

  const cap = issueSandboxReadCapability({ sandboxPrefix: sandbox, caller: CALLER });
  const guarded = await createGuardedFsClient({ capability: cap, caller: CALLER });
  return {
    root,
    sandbox,
    outsideSecret,
    client: guarded.client,
    underlying: guarded.underlying,
    receipts: guarded.receipts,
  };
}

beforeEach(async () => {
  h = await makeHarness();
});

afterEach(async () => {
  await fs.rm(h.root, { recursive: true, force: true });
});

describe("Round 10: encoding / normalization attacks against fs-sandbox", () => {
  describe("the path-traversal foot-gun (defense BREAKS)", () => {
    it("/sandbox/../outside/secret.txt is allowed by the gate AND read by the fs client", async () => {
      // The attack: cap is for `<sandbox>`. Agent emits a path that
      // CONTAINS the sandbox prefix as a substring (it's literally
      // there before the `/..`) but resolves OUTSIDE the sandbox.
      // Caveat substring-match fires; fs.readFile resolves `..` and
      // reads the secret.
      const traversalPath = `${h.sandbox}/../outside/secret.txt`;

      const result = (await h.client.callTool("read_file", {
        path: traversalPath,
      })) as string;

      // THE FINDING: out-of-sandbox secret read.
      expect(result).toBe("OUT-OF-SANDBOX-SECRET");
      // The call DID reach the underlying fs client (gate allowed it).
      expect(h.underlying.log).toHaveLength(1);
      expect((h.underlying.log[0]?.args as { path: string }).path).toBe(traversalPath);
    });

    it("/sandbox/legit/../../outside/secret.txt — multi-segment traversal also slips", async () => {
      // Stronger demonstration: even after entering the sandbox, an
      // attacker can climb back out. Substring `/sandbox/` is still
      // present, caveat still fires.
      const escapePath = `${h.sandbox}/legit/../../outside/secret.txt`;
      const result = (await h.client.callTool("read_file", { path: escapePath })) as string;
      expect(result).toBe("OUT-OF-SANDBOX-SECRET");
    });

    it("/sandbox/././././../outside/secret.txt — `.` no-ops + `..` escape also slip", async () => {
      // Idempotent path segments don't change the substring match
      // outcome but stress the canonicalizer fix path.
      const noisy = `${h.sandbox}/./././../outside/secret.txt`;
      const result = (await h.client.callTool("read_file", { path: noisy })) as string;
      expect(result).toBe("OUT-OF-SANDBOX-SECRET");
    });
  });

  describe("encoding shapes that DO NOT slip — defense holds-by-accident", () => {
    it("base64-encoded path string is denied (caveat sees the encoded form)", async () => {
      // The cap matches against substring of the raw bytes. A base64
      // string of `/etc/passwd` does NOT contain the sandbox-prefix
      // substring, so caveat denies. This is a hold-by-accident:
      // capnagent never decodes; it just doesn't match. If the
      // underlying client DID decode base64 args, this would be a
      // gap — operators wiring custom clients with auto-decoding
      // would defeat the gate.
      const b64 = Buffer.from("/etc/passwd", "utf8").toString("base64");
      await expect(h.client.callTool("read_file", { path: b64 })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );
      expect(h.underlying.log).toEqual([]);
    });

    it("percent-encoded `..` (`%2e%2e`) does NOT slip — fs.readFile doesn't URL-decode", async () => {
      // %2e%2e in the path doesn't get decoded by Node's fs.readFile.
      // The substring `/sandbox/` is still present, so caveat allows
      // — but the fs client looks up a literal file with `%2e%2e` in
      // its name. The file doesn't exist, so fs.readFile errors.
      // Allowed by gate, but no exfil because the encoding doesn't
      // round-trip through fs. Pin this so a future code change that
      // adds URL-decoding (e.g. someone wiring a web-fs adapter)
      // gets caught.
      const percentEnc = `${h.sandbox}/%2e%2e/outside/secret.txt`;
      // Caveat allows (substring fires); fs.readFile errors with ENOENT.
      await expect(h.client.callTool("read_file", { path: percentEnc })).rejects.toThrow(
        /ENOENT|no such file/i,
      );
      // The call DID reach the underlying client (the gate let it through).
      expect(h.underlying.log).toHaveLength(1);
    });
  });

  describe("Unicode normalization — operator-side attack", () => {
    it("NFC vs NFD: agent's NFD path is denied against an NFC sandbox prefix", async () => {
      // The sandbox path returned by mkdtemp is in whatever form the
      // OS gives. If the operator builds the cap with one form and
      // the agent emits the other, caveat substring-match denies.
      // This isn't a security break — the worst case is the
      // operator's intent isn't realized for accented paths. But it
      // documents the foot-gun: operators using non-ASCII sandbox
      // prefixes need to ensure the agent's path is in the same
      // normalization form.
      //
      // Test via a proxy: a path that's clearly different bytes
      // from the sandbox prefix gets denied (sanity).
      const denormalized = `${h.sandbox.normalize("NFD")}/legit.txt`;
      // On most systems sandbox.normalize("NFD") === sandbox (no
      // accents in tempdir name). So caveat allows; this test is
      // mostly a placeholder pinning the equivalence under ASCII
      // tempdirs. Worth re-running on a system whose tempdir
      // contains non-ASCII characters.
      try {
        const result = (await h.client.callTool("read_file", {
          path: denormalized,
        })) as string;
        expect(result).toBe("in-sandbox content");
      } catch (e) {
        if (e instanceof CapabilityDeniedError) {
          // Acceptable: the OS gave us a sandbox path with non-ASCII
          // chars and NFC vs NFD diverged. The test still holds —
          // the divergence is observable.
          expect(e).toBeInstanceOf(CapabilityDeniedError);
        } else {
          throw e;
        }
      }
    });
  });

  describe("regression: rounds 01 and 07 still hold", () => {
    it("obvious out-of-sandbox path is still denied (round 01)", async () => {
      await expect(h.client.callTool("read_file", { path: "/etc/passwd" })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );
      expect(h.underlying.log).toEqual([]);
    });

    it("legitimate in-sandbox read still works (negative hypothesis)", async () => {
      const result = (await h.client.callTool("read_file", {
        path: path.join(h.sandbox, "legit.txt"),
      })) as string;
      expect(result).toBe("in-sandbox content");
    });
  });
});
