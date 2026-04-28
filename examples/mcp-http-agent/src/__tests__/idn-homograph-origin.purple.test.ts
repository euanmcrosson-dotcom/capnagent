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

  describe("foot-gun (a): operator pastes raw unicode homograph into allowlist [CLOSED v0.5]", () => {
    it("issuance THROWS with an error that explicitly names IDN/homograph", () => {
      // v0.5 closure: `exactOriginRejectionReason` detects non-ASCII
      // codepoints in the input string and rejects with a message
      // naming "IDN", "homograph", and "TR39 confusable" so the
      // operator can identify the foot-gun without external knowledge.
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: [HOMOGRAPH_UNICODE],
          caller: CALLER,
        }),
      ).toThrowError(/IDN|homograph|non-ASCII/);
    });
  });

  describe("foot-gun (b): operator pastes PUNYCODE form [CLOSED v0.5]", () => {
    it("issuance THROWS naming the punycode label as the reason", () => {
      // Originally [BREAKS]: issuance succeeded silently because the
      // punycode form is a valid canonical URL. v0.5 walks the
      // hostname's labels and refuses any that begin `xn--` — the
      // IDNA-2008 prefix that uniquely marks an encoded IDN label.
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: [HOMOGRAPH_PUNYCODE],
          caller: CALLER,
        }),
      ).toThrowError(/punycode|xn--|IDN/);
    });

    it("the cap-allowing-homograph harness can no longer be constructed", async () => {
      // makeHarnessAllowingPunycodeHomograph now throws at issuance.
      // This is the structural closure of round 09's exploitation path.
      await expect(makeHarnessAllowingPunycodeHomograph()).rejects.toThrow(
        /punycode|xn--|IDN/,
      );
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

    it("Cyrillic-н in `exaнple.com` is rejected in BOTH unicode AND punycode form [CLOSED v0.5]", () => {
      // The Cyrillic-н homograph (U+043D, visually like Latin n).
      // Confirms the v0.5 closure is general — not specific to
      // Cyrillic-а — and that both shapes (unicode + punycode) are
      // refused by the same `exactOriginRejectionReason` walk.
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: [EXAMPLE_HOMOGRAPH_UNICODE],
          caller: CALLER,
        }),
      ).toThrowError(/IDN|homograph|non-ASCII/);

      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: [EXAMPLE_HOMOGRAPH_PUNYCODE],
          caller: CALLER,
        }),
      ).toThrowError(/punycode|xn--|IDN/);
    });

    it("mixed-script label (Latin + Cyrillic in the same DNS label) is rejected in punycode form [CLOSED v0.5]", () => {
      // A label that mixes scripts — `apа.example.com` with `ap` Latin
      // and `а` Cyrillic — is the canonical UTS-39 "mixed-script"
      // confusable. v0.5 refuses ALL `xn--` labels at the allowlist
      // boundary (stricter than TR39 — see the rationale in
      // `exactOriginRejectionReason`).
      const mixedUnicode = `https://ap${CYRILLIC_A}.example.com`;
      const mixedPunycode = new URL(mixedUnicode).origin;
      expect(mixedPunycode).toMatch(/^https:\/\/xn--/);

      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: [mixedPunycode],
          caller: CALLER,
        }),
      ).toThrowError(/punycode|xn--|IDN/);
    });
  });

  describe("threat-surface documentation [CLOSED v0.5]", () => {
    it("documents that round 09's exploitation path is closed at issuance", async () => {
      // The agent NEVER chooses the allowlist. The allowlist is
      // operator config. So the threat shape is "attacker tricks
      // operator into allowlisting attacker-controlled host" — not
      // "attacker tricks agent into emitting a confusing URL." Round
      // 05 already handles the latter (a homograph URL emitted by the
      // agent normalizes to punycode and fails to match an ASCII
      // allowlist entry).
      //
      // v0.5 closes the issuance side: `exactOriginRejectionReason`
      // refuses both raw-unicode and punycode forms with diagnostics
      // that explicitly name IDN / homograph / TR39. The operator no
      // longer needs out-of-band Unicode knowledge to recognize the
      // foot-gun.
      //
      // Pin: the harness that allowed homograph calls (round 09's
      // BREAKS witness) can no longer be constructed.
      await expect(makeHarnessAllowingPunycodeHomograph()).rejects.toThrow(
        /punycode|xn--|IDN/,
      );
    });
  });
});
