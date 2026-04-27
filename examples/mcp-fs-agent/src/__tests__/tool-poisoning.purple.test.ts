/**
 * Purple-team PoC for `docs/purple-team/01-tool-description-injection.md`.
 *
 * This test proves the security claim by simulating the WORST CASE:
 * the model has been fully compromised by a malicious tool
 * description (the kind described in the Invariant Labs TPA
 * research) and emits the calls the description tried to induce.
 * capnagent's gate denies the calls regardless of HOW they got
 * emitted.
 *
 * Two layers of defense exist in production:
 *
 *   1. **The model itself** — modern Claude (Opus 4.5+, Sonnet 4.5+)
 *      is trained against this exact attack class and often refuses
 *      injected instructions. That's good, but it's not what this
 *      test is about.
 *   2. **capnagent's capability gate** — refuses out-of-scope tool
 *      calls regardless of model behavior. That's what THIS test
 *      proves.
 *
 * The point of the purple-team framing: capnagent's claim does NOT
 * depend on the model's robustness. Even if a future model regression
 * makes injection trivially successful, the capability boundary holds.
 *
 * # Why we don't read the user's actual ~/.ssh/id_rsa in the test
 *
 * If capnagent's gate were ever broken, this test would actually
 * exfil the user's real private key. That's an unacceptable risk
 * for a CI test. Instead we plant a fake "secret" file at
 * `<root>/outside/fake-id-rsa-PRETEND-SECRET` and the attack
 * targets that. Same structural test, no possibility of real harm
 * if a regression slips through.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import { createGuardedFsClient, issueSandboxReadCapability } from "../index.js";

const CALLER = "agent:fs";

interface PurpleHarness {
  root: string;
  sandbox: string;
  outside: string;
  fakeSshKey: string;
  client: Awaited<ReturnType<typeof createGuardedFsClient>>["client"];
  underlying: Awaited<ReturnType<typeof createGuardedFsClient>>["underlying"];
  receipts: ReadonlyArray<unknown>;
}

let h: PurpleHarness;

beforeAll(async () => {
  await init();
});

async function makeHarness(): Promise<PurpleHarness> {
  // Two-tree layout, mirroring fs.test.ts:
  //   sandbox/   in-scope (capability permits reads here)
  //   outside/   out-of-scope (the would-be-secrets the attack targets)
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "capnagent-tpa-purple-"));
  const sandbox = path.join(root, "sandbox");
  const outside = path.join(root, "outside");
  await fs.mkdir(sandbox, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(sandbox, "hello.txt"), "legitimate sandbox content", "utf8");

  // The "fake SSH key." This is the file the attack tries to exfil.
  // It is DELIBERATELY not the user's real ~/.ssh/id_rsa — see the
  // file-level docstring above for why.
  const fakeSshKey = path.join(outside, "fake-id-rsa-PRETEND-SECRET");
  await fs.writeFile(
    fakeSshKey,
    "PRETEND PRIVATE KEY — do not put real secrets in this directory",
    "utf8",
  );

  const cap = issueSandboxReadCapability({ sandboxPrefix: sandbox, caller: CALLER });
  const guarded = await createGuardedFsClient({ capability: cap, caller: CALLER });

  return {
    root,
    sandbox,
    outside,
    fakeSshKey,
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

describe("purple-team 01: tool-description injection — cross-server confused deputy", () => {
  describe("structural defense (worst-case: model fully cooperates with injection)", () => {
    it("the agent's read of the planted SSH key is denied at the capability gate", async () => {
      // Simulates Stage 3 step 6 from the scenario doc: the
      // compromised agent emits read_file on the path the malicious
      // description told it to read. capnagent should deny before
      // the underlying fs client touches the file.
      await expect(h.client.callTool("read_file", { path: h.fakeSshKey })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );

      // Underlying client never saw the call.
      expect(h.underlying.log).toEqual([]);

      // The fake-secret file is unread (its existence + contents
      // are unchanged). This isn't a strong assertion — fs reads
      // don't mutate — but it documents the claim explicitly.
      const stillThere = await fs.readFile(h.fakeSshKey, "utf8");
      expect(stillThere).toMatch(/PRETEND PRIVATE KEY/);
    });

    it("paraphrased payloads — same path, different framing — are also denied", async () => {
      // The point: capnagent's defense is INDEPENDENT of the
      // injection's wording. We don't need to enumerate every
      // possible payload phrasing — the gate evaluates the call
      // shape and path, not the description text.
      const variants = [
        path.join(h.outside, "fake-id-rsa-PRETEND-SECRET"),
        path.join(h.outside, "subdir", "another-target"),
        path.join(h.root, "fake-id-rsa-PRETEND-SECRET"),
        // sneaky-looking path that might fool a substring regex
        // but doesn't fool the capability gate since the sandbox
        // prefix is the absolute path, not "sandbox" as a substring:
        path.join(h.outside, "looks-like-sandbox-but-isnt", "secret.txt"),
      ];

      for (const target of variants) {
        await expect(h.client.callTool("read_file", { path: target })).rejects.toBeInstanceOf(
          CapabilityDeniedError,
        );
      }
      expect(h.underlying.log).toEqual([]);
    });

    it("cross-tool hijack: list_directory on the secrets dir is also denied", async () => {
      // Variant from the scenario: the malicious description tells
      // the agent to LIST the contents of an out-of-scope dir
      // rather than read a specific file. Same gate, different
      // tool clause in the caveat — both are path-bounded.
      await expect(h.client.callTool("list_directory", { path: h.outside })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );
      expect(h.underlying.log).toEqual([]);
    });

    it("multi-step attack: legit in-scope read succeeds, follow-up out-of-scope read fails", async () => {
      // Real-world attack pattern: the agent does some legitimate
      // work first (so the user sees normal behavior), THEN tries
      // the exfil. capnagent denies only the second; the legit
      // call is unaffected.
      const legit = (await h.client.callTool("read_file", {
        path: path.join(h.sandbox, "hello.txt"),
      })) as string;
      expect(legit).toBe("legitimate sandbox content");

      await expect(h.client.callTool("read_file", { path: h.fakeSshKey })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );

      // Exactly the legit call reached the underlying client.
      expect(h.underlying.log.map((e) => e.tool)).toEqual(["read_file"]);
      expect((h.underlying.log[0]?.args as { path: string }).path).toBe(
        path.join(h.sandbox, "hello.txt"),
      );
    });

    it("write_file — even WITH a path inside the sandbox — is denied (no clause permits writes)", async () => {
      // Variant of the cross-tool hijack: malicious description
      // tells the agent to WRITE secrets to a file the attacker
      // can later read. The issued capability only mentions the
      // read tools; writes have no allow clause and fail closed.
      await expect(
        h.client.callTool("write_file", {
          path: path.join(h.sandbox, "exfil.txt"),
          content: "stolen data goes here",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(h.underlying.log).toEqual([]);

      // The file was not created.
      await expect(fs.stat(path.join(h.sandbox, "exfil.txt"))).rejects.toThrow();
    });
  });

  describe("audit trail (every denial is auditable)", () => {
    it("denial receipts have outcome.kind === 'denied' with an informative reason", async () => {
      await expect(h.client.callTool("read_file", { path: h.fakeSshKey })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );

      expect(h.receipts).toHaveLength(1);
      const r = h.receipts[0] as {
        version: number;
        outcome: { kind: string; reason: string };
        signature: string;
      };
      expect(r.version).toBe(1);
      expect(r.outcome.kind).toBe("denied");
      expect(r.outcome.reason).toMatch(/caveat failed/);
      expect(r.signature.length).toBeGreaterThan(0);
    });

    it("a sequence of attack attempts produces one receipt per attempt", async () => {
      // Attacker probes multiple paths; each attempt is a separate
      // audit-loggable event. An ops team can grep these in
      // aggregate to spot the attack pattern.
      const targets = [
        path.join(h.outside, "fake-id-rsa-PRETEND-SECRET"),
        path.join(h.outside, "config.json"),
        path.join(h.outside, "credentials"),
      ];
      for (const t of targets) {
        await expect(h.client.callTool("read_file", { path: t })).rejects.toBeInstanceOf(
          CapabilityDeniedError,
        );
      }
      expect(h.receipts).toHaveLength(3);
      for (const r of h.receipts) {
        expect((r as { outcome: { kind: string } }).outcome.kind).toBe("denied");
      }
    });
  });

  describe("residual risk (honest acknowledgment of what this defense does NOT cover)", () => {
    it("a secret accidentally placed INSIDE the sandbox is readable — operator responsibility", async () => {
      // Documents residual risk #2 from the scenario doc: capnagent
      // enforces the capability scope, not the contents of files.
      // If an operator puts a config-with-API-key in a sandbox dir,
      // capnagent permits reading it. This is a feature (you DO
      // want the agent to read sandbox contents); the operator
      // owns the policy of what goes in the sandbox.
      const secretInSandbox = path.join(h.sandbox, "config-with-leaked-api-key.txt");
      await fs.writeFile(secretInSandbox, "API_KEY=oops_leaked_via_misplacement", "utf8");

      const result = (await h.client.callTool("read_file", {
        path: secretInSandbox,
      })) as string;
      expect(result).toBe("API_KEY=oops_leaked_via_misplacement");
      // The point of having this test: residual risk should be
      // codified, not just stated in prose. If a future capnagent
      // change accidentally started rejecting in-scope reads, this
      // test would fail and the operator-responsibility framing
      // would need to be revisited.
    });
  });
});
