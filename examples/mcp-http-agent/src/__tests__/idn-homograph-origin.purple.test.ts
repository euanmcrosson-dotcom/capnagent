/**
 * Purple-team PoC for `docs/purple-team/09-idn-homograph-origin.md`.
 *
 * Round 05 closed `holds-with-caveat` for the http-agent's origin-bounded
 * cap. Round 05's coverage section flagged "IDN/punycode homograph" as
 * not-yet-tested. This round tests the gap.
 *
 * # The threat model
 *
 * An operator copies an attacker-supplied URL into the allowlist (e.g.
 * from a phishing email saying "please add this api"). The URL is an
 * IDN homograph — `https://аpi.example.com` where the leading `а` is
 * U+0430 CYRILLIC SMALL LETTER A, not U+0061 LATIN SMALL LETTER A.
 *
 * Visually identical to `https://api.example.com`, completely different
 * host. The operator believes they've allowed `api.example.com`. They've
 * actually allowed an attacker-controlled host.
 *
 * # The empirical observation
 *
 * Node's `URL` constructor follows WHATWG and resolves IDN labels to
 * their **punycode** (ASCII-Compatible Encoding) form on `URL.origin`:
 *
 *   new URL("https://" + "а" + "pi.example.com").origin
 *     === "https://xn--pi-6kc.example.com"
 *
 * This produces a TWO-PRONGED foot-gun:
 *
 * (a) **Raw unicode homograph in allowlist** — the operator pastes
 *     `"https://аpi.example.com"` (with Cyrillic а). `isExactOrigin`'s
 *     final check `s === u.origin` fails because `u.origin` is the
 *     punycode form. Issuance throws — but with a misleading "not an
 *     exact origin" error that doesn't mention IDN, leaving the
 *     operator to debug a URL string that LOOKS canonical to them.
 *
 * (b) **Punycode form of homograph in allowlist** — the operator (or
 *     their tooling) pastes `"https://xn--pi-6kc.example.com"`
 *     directly. `isExactOrigin` accepts it cleanly: it's a valid URL,
 *     in canonical form, no IDN-confusable check is performed. The
 *     resulting cap allows attacker calls to the homograph host. This
 *     is the realistic exploitation path: any URL-canonicalizing
 *     middleware (a copy-paste through a browser, a CLI tool, a
 *     YAML/JSON loader that pre-normalizes) converts the unicode form
 *     to punycode SILENTLY, and the punycode then sails through.
 *
 * # Why we don't actually call attacker.com
 *
 * Like round 05, the test never makes a real network call. The
 * homograph-allowed cap is exercised with a localhost-rewriting fetch
 * stub; if a regression caused the gate to allow a non-mapped origin,
 * the stub throws loudly rather than silently exfiltrating.
 */

import {
  type IncomingMessage,
  type Server,
  type ServerResponse,
  createServer as createHttp,
} from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import {
  type GuardedHttpClient,
  createGuardedHttpClient,
  issueOriginScopedGetCapability,
} from "../index.js";

const CALLER = "agent:http";

// The legitimate ASCII origin the operator MEANS to allow.
const PUBLIC_GOOD_ASCII = "https://api.example.com";

// The Cyrillic-а homograph. The leading `а` is U+0430 (Cyrillic),
// visually identical to ASCII `a` (U+0061). Built explicitly via
// String.fromCodePoint so the codepoint is unambiguous in source.
const CYRILLIC_A = String.fromCodePoint(0x0430);
const HOMOGRAPH_UNICODE = `https://${CYRILLIC_A}pi.example.com`;

// What `URL.origin` resolves the homograph to (punycode / IDNA-2008).
// Pinned as an explicit constant — if a future Node version changed
// the canonicalization, every test that pivots on this value would
// fail loudly with a clear message.
const HOMOGRAPH_PUNYCODE = "https://xn--pi-6kc.example.com";

// Cyrillic-н homograph in `exaнple.com`. The Cyrillic н (U+043D) is
// visually similar to Latin n (U+006E). Used for the visual-confusion
// catalog — a different host class than the Cyrillic-а case.
const CYRILLIC_N = String.fromCodePoint(0x043d);
const EXAMPLE_HOMOGRAPH_UNICODE = `https://exa${CYRILLIC_N}ple.com`;
const EXAMPLE_HOMOGRAPH_PUNYCODE = "https://xn--exaple-rqf.com";

interface TestServer {
  base: string;
  hits: Array<{ url: string; method: string }>;
  close: () => Promise<void>;
}

async function startTestServer(): Promise<TestServer> {
  const hits: Array<{ url: string; method: string }> = [];
  const server: Server = createHttp((req: IncomingMessage, res: ServerResponse) => {
    hits.push({ url: req.url ?? "", method: req.method ?? "" });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`hit ${req.method} ${req.url}`);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;
  return {
    base,
    hits,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/**
 * Same rewriting fetch stub as round 05. Lets the AGENT see one URL
 * (the public-facing homograph the cap accidentally allows) while the
 * actual HTTP request hits the localhost test server. If the gate ever
 * lets a non-mapped origin through, the stub throws — that's a
 * security regression we want to be loud about.
 */
function makeRewritingFetch(public2local: Record<string, string>): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const u = new URL(url);
    const localBase = public2local[u.origin];
    if (!localBase) {
      throw new Error(
        `SECURITY REGRESSION: fetch stub reached for origin ${u.origin} — capnagent's gate should have denied this call before fetch ran.`,
      );
    }
    const rewritten = `${localBase}${u.pathname}${u.search}`;
    return await fetch(rewritten, init);
  }) as typeof fetch;
}

let attackerStandinServer: TestServer;

beforeAll(async () => {
  await init();
  attackerStandinServer = await startTestServer();
});

afterAll(async () => {
  await attackerStandinServer.close();
});

interface PurpleHarness {
  guarded: GuardedHttpClient;
}

/**
 * Build a harness whose cap is allowlisted to the PUNYCODE form of
 * the Cyrillic-а homograph. This simulates the realistic foot-gun:
 * the operator (or tooling) canonicalized the URL before storing it
 * in config, so the unicode origin became `xn--pi-6kc.example.com`
 * with no human-visible warning that this was a homograph.
 *
 * The localhost mapping is keyed on the PUNYCODE origin — so a call
 * to either the unicode form or the punycode form will be routed by
 * the stub (since `URL.origin` normalizes both to the same string).
 */
async function makeHarnessAllowingPunycodeHomograph(): Promise<PurpleHarness> {
  const cap = issueOriginScopedGetCapability({
    allowedOrigins: [HOMOGRAPH_PUNYCODE],
    caller: CALLER,
  });
  const fetchStub = makeRewritingFetch({
    [HOMOGRAPH_PUNYCODE]: attackerStandinServer.base,
  });
  const guarded = await createGuardedHttpClient({
    capability: cap,
    caller: CALLER,
    fetch: fetchStub,
  });
  return { guarded };
}

/**
 * Round 05 regression: clean ASCII allowlist, ASCII GET allowed,
 * homograph GET denied. Used to confirm the negative-hypothesis half.
 */
async function makeHarnessAsciiOnly(): Promise<PurpleHarness> {
  const cap = issueOriginScopedGetCapability({
    allowedOrigins: [PUBLIC_GOOD_ASCII],
    caller: CALLER,
  });
  const fetchStub = makeRewritingFetch({
    [PUBLIC_GOOD_ASCII]: attackerStandinServer.base,
  });
  const guarded = await createGuardedHttpClient({
    capability: cap,
    caller: CALLER,
    fetch: fetchStub,
  });
  return { guarded };
}

describe("purple-team 09: IDN homograph in origin allowlist", () => {
  describe("empirical: what does new URL().origin do with a Cyrillic-а homograph?", () => {
    it("resolves Cyrillic-а IDN to punycode form (xn--pi-6kc.example.com)", () => {
      // THIS IS THE EMPIRICAL ASSERTION OF THE ROUND. If a future Node
      // version changed IDN canonicalization, the rest of this file's
      // assumptions break and the test would fail with a loud, specific
      // message rather than silently passing through.
      expect(new URL(HOMOGRAPH_UNICODE).origin).toBe(HOMOGRAPH_PUNYCODE);
    });

    it("resolves Cyrillic-н homograph to its own distinct punycode", () => {
      expect(new URL(EXAMPLE_HOMOGRAPH_UNICODE).origin).toBe(EXAMPLE_HOMOGRAPH_PUNYCODE);
    });

    it("punycode of homograph is NOT equal to the legitimate ASCII origin", () => {
      // The whole point of the visual confusion is that operators
      // *think* these strings are equal. Empirically they are not.
      expect(HOMOGRAPH_PUNYCODE).not.toBe(PUBLIC_GOOD_ASCII);
      expect(new URL(HOMOGRAPH_UNICODE).origin).not.toBe(PUBLIC_GOOD_ASCII);
    });
  });

  describe("foot-gun (a): operator pastes raw unicode homograph into allowlist", () => {
    it("issuance THROWS — but with a misleading error that doesn't mention IDN", () => {
      // `isExactOrigin` rejects the unicode form because `s === u.origin`
      // fails (input is unicode, origin is punycode). This is accidental
      // partial defense — the operator at least gets an error. But the
      // error message says "not an exact origin," which is bewildering
      // when the URL string LOOKS to the operator like a perfectly
      // canonical scheme://host with no path. The operator is left to
      // debug a problem they cannot see.
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: [HOMOGRAPH_UNICODE],
          caller: CALLER,
        }),
      ).toThrowError(/is not an exact origin/);

      // Pin: the error doesn't mention "IDN", "homograph", "unicode",
      // "punycode", or "confusable". A future-fix should improve this.
      try {
        issueOriginScopedGetCapability({
          allowedOrigins: [HOMOGRAPH_UNICODE],
          caller: CALLER,
        });
      } catch (err) {
        const msg = (err as Error).message;
        expect(msg).not.toMatch(/IDN|homograph|punycode|confusable|mixed.script/i);
      }
    });
  });

  describe("foot-gun (b): operator pastes PUNYCODE form (the realistic exploitation path)", () => {
    it("POSITIVE HYPOTHESIS — issuance SUCCEEDS WITHOUT WARNING (this is the gap)", async () => {
      // The realistic threat: operator's tooling (browser address bar,
      // OS clipboard, CLI URL canonicalizer, JSON config loader, ...)
      // converted the visually-similar Cyrillic-а URL to its punycode
      // form silently. The operator stores the punycode in
      // `allowedOrigins`. There is no IDN-confusable check.
      //
      // The hypothesis says issuance SHOULD warn or reject. Empirically
      // it does NOT — which is the round's BREAKS finding.
      const cap = issueOriginScopedGetCapability({
        allowedOrigins: [HOMOGRAPH_PUNYCODE],
        caller: CALLER,
      });
      expect(cap).toBeDefined();
      // Successful issuance => the cap is built without complaint.
      // This documents the gap.
    });

    it("the resulting cap ALLOWS a homograph-host call — attacker stand-in receives the request", async () => {
      const h = await makeHarnessAllowingPunycodeHomograph();

      // The agent emits an http.get to the unicode homograph form (as
      // it would after a prompt-injection-style attack tells it to
      // call "https://аpi.example.com/data"). The Context normalizer
      // parses the URL → arg.origin = punycode. The caveat compares
      // arg.origin == HOMOGRAPH_PUNYCODE → match → ALLOWED. Fetch
      // runs and the (localhost-stubbed) attacker stand-in receives
      // the request.
      const result = (await h.guarded.client.callTool("http.get", {
        url: `${HOMOGRAPH_UNICODE}/data`,
      })) as { status: number; body: string };
      expect(result.status).toBe(200);
      // The attacker stand-in saw the request. In a non-stubbed
      // deployment, this would be the real attacker-controlled host.
      expect(attackerStandinServer.hits.map((x) => x.url)).toEqual(["/data"]);
    });

    it("calls to the LEGITIMATE ASCII origin are DENIED — operator's intent is misrepresented", async () => {
      const h = await makeHarnessAllowingPunycodeHomograph();

      // The operator believed they allowed `https://api.example.com`.
      // A subsequent agent call to the actual ASCII host is DENIED
      // because the cap is for the homograph's origin, not the ASCII
      // one. This is the visceral expression of the foot-gun: the
      // operator's mental model and the cap's actual semantics
      // disagree.
      await expect(
        h.guarded.client.callTool("http.get", { url: `${PUBLIC_GOOD_ASCII}/data` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
    });
  });

  describe("negative hypothesis (round 05 regression coverage)", () => {
    let h: PurpleHarness;

    beforeEach(async () => {
      h = await makeHarnessAsciiOnly();
      attackerStandinServer.hits.length = 0;
    });

    it("clean ASCII allowlist allows ASCII GETs (round 05 still holds)", async () => {
      const result = (await h.guarded.client.callTool("http.get", {
        url: `${PUBLIC_GOOD_ASCII}/v1/items`,
      })) as { status: number; body: string };
      expect(result.status).toBe(200);
      expect(result.body).toBe("hit GET /v1/items");
    });

    it("clean ASCII allowlist denies homograph GETs (round 05 still holds)", async () => {
      // The Cyrillic-а homograph parses to xn--pi-6kc.example.com,
      // which is not in the ASCII allowlist → denied. This is the
      // round-05 cross-origin-exfil defense behaving correctly when
      // the operator wrote the allowlist correctly.
      await expect(
        h.guarded.client.callTool("http.get", { url: `${HOMOGRAPH_UNICODE}/data` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(attackerStandinServer.hits).toEqual([]);
    });
  });

  describe("visual-confusion catalog (other shapes worth pinning)", () => {
    it("benign control: ASCII-only `https://example.com` issues without surprise", () => {
      // Sanity check that the validator isn't mistakenly flagging
      // legitimate ASCII URLs. (The 'm' here is U+006D — the ordinary
      // ASCII letter, included as the control case in the catalog.)
      const cap = issueOriginScopedGetCapability({
        allowedOrigins: ["https://example.com"],
        caller: CALLER,
      });
      expect(cap).toBeDefined();
    });

    it("Cyrillic-н in `exaнple.com` follows the same pattern: punycode passes, unicode rejected", () => {
      // The Cyrillic-н homograph (U+043D, visually like Latin n).
      // Confirms the pattern is general — not specific to
      // Cyrillic-а — and that the foot-gun shape repeats for any
      // confusable codepoint pair the Unicode TR39 catalog covers.
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: [EXAMPLE_HOMOGRAPH_UNICODE],
          caller: CALLER,
        }),
      ).toThrowError(/is not an exact origin/);

      const cap = issueOriginScopedGetCapability({
        allowedOrigins: [EXAMPLE_HOMOGRAPH_PUNYCODE],
        caller: CALLER,
      });
      expect(cap).toBeDefined();
    });

    it("mixed-script label (Latin + Cyrillic in the same DNS label) is also accepted in punycode form", () => {
      // A label that mixes scripts — `apа.example.com` with `ap` Latin
      // and `а` Cyrillic — is the canonical UTS-39 "mixed-script"
      // confusable. Modern browsers refuse to render this as IDN
      // (they show punycode). capnagent has no equivalent guard:
      // the punycode form sails through.
      const mixedUnicode = `https://ap${CYRILLIC_A}.example.com`;
      const mixedPunycode = new URL(mixedUnicode).origin;
      expect(mixedPunycode).toMatch(/^https:\/\/xn--/);

      // Operator pastes the punycode form: ACCEPTED with no
      // mixed-script warning.
      const cap = issueOriginScopedGetCapability({
        allowedOrigins: [mixedPunycode],
        caller: CALLER,
      });
      expect(cap).toBeDefined();
    });
  });

  describe("threat-surface documentation", () => {
    it("documents that the realistic threat surface is operator config, not agent input", async () => {
      // The agent NEVER chooses the allowlist. The allowlist is
      // operator config. So the threat shape is "attacker tricks
      // operator into allowlisting attacker-controlled host" — not
      // "attacker tricks agent into emitting a confusing URL." The
      // round 05 defense already handles the latter (a homograph URL
      // emitted by the agent normalizes to punycode and fails to
      // match an ASCII allowlist entry — that test passes above).
      //
      // The gap is at issuance: the validator does not flag homograph
      // / mixed-script / confusable inputs. The operator owns the
      // misconfig — and the engine offers no help detecting it.
      //
      // Pin this as a structural test so the "what's the threat
      // surface here" question has an answer in the test file
      // forever, not just in the docs.
      const harnessHomograph = await makeHarnessAllowingPunycodeHomograph();

      // (1) The cap exists and behaves as a permissive cap for the
      //     homograph host (already tested above; reasserted here for
      //     proximity to the threat-model claim).
      await expect(
        harnessHomograph.guarded.client.callTool("http.get", {
          url: `${HOMOGRAPH_UNICODE}/x`,
        }),
      ).resolves.toBeDefined();

      // (2) No warning, no diagnostic, no signal of the foot-gun
      //     anywhere in the receipt stream — receipts only describe
      //     allow/deny outcomes, not allowlist hygiene.
      const r = harnessHomograph.guarded.receipts[0] as {
        outcome: { kind: string };
      };
      expect(r.outcome.kind).toBe("allowed");
    });
  });
});
