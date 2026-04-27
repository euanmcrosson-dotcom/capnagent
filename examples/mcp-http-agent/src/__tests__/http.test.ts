/**
 * Allow/deny matrix for the origin-scoped HTTP agent.
 *
 *   - GET to allowlisted origin       → allowed, fetch runs, body returned
 *   - GET to non-allowlisted origin   → denied, fetch never runs
 *   - GET with userinfo (`user@host`) → denied (origin parse strips user;
 *                                              the parsed origin is the
 *                                              REAL host, which isn't in
 *                                              the allowlist)
 *   - POST/PUT/DELETE to any origin   → denied (no caveat clause)
 *   - GET with malformed URL          → denied (no `arg.origin` set,
 *                                              equality check fails)
 *
 * No real network. A localhost `node:http` server stands in for both
 * the "good" and "bad" origins; we route via fetch+URL-rewrite stub
 * so the verifier sees the agent's claimed URL while fetch hits the
 * localhost test server.
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
 * localhost test server. We rewrite the host but preserve the path.
 *
 * The capability gate sees `agentVisibleOrigin` because that's what the
 * agent passes; the parsed origin from `new URL()` is the public origin
 * — exactly the substitution we want for the test.
 */
function makeRewritingFetch(public2local: Record<string, string>): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const u = new URL(url);
    const localBase = public2local[u.origin];
    if (!localBase) {
      // The verifier should have denied this; if we got here the agent
      // tried to reach a host that has no test mapping. Make the test
      // assertion clear by failing fast.
      throw new Error(`fetch stub: no local mapping for origin ${u.origin}`);
    }
    const rewritten = `${localBase}${u.pathname}${u.search}`;
    return await fetch(rewritten, init);
  }) as typeof fetch;
}

let testServer: TestServer;
let badServer: TestServer;

beforeAll(async () => {
  await init();
  testServer = await startTestServer();
  badServer = await startTestServer();
});

afterAll(async () => {
  await testServer.close();
  await badServer.close();
});

interface Harness {
  guarded: GuardedHttpClient;
  publicGood: string;
  publicBad: string;
}

const PUBLIC_GOOD = "https://api.example.com";
const PUBLIC_BAD = "https://api.attacker.com";

async function makeHarness(): Promise<Harness> {
  const cap = issueOriginScopedGetCapability({
    allowedOrigins: [PUBLIC_GOOD],
    caller: CALLER,
  });
  const fetchStub = makeRewritingFetch({
    [PUBLIC_GOOD]: testServer.base,
    [PUBLIC_BAD]: badServer.base,
  });
  const guarded = await createGuardedHttpClient({
    capability: cap,
    caller: CALLER,
    fetch: fetchStub,
  });
  return { guarded, publicGood: PUBLIC_GOOD, publicBad: PUBLIC_BAD };
}

let h: Harness;

beforeEach(async () => {
  h = await makeHarness();
  testServer.hits.length = 0;
  badServer.hits.length = 0;
});

describe("origin-scoped HTTP agent", () => {
  describe("allow path", () => {
    it("GET to an allowlisted origin succeeds", async () => {
      const result = (await h.guarded.client.callTool("http.get", {
        url: `${h.publicGood}/v1/items`,
      })) as { status: number; body: string };
      expect(result.status).toBe(200);
      expect(result.body).toBe("hit GET /v1/items");
      expect(testServer.hits.map((x) => x.url)).toEqual(["/v1/items"]);
      expect(badServer.hits).toEqual([]);
    });

    it("GET with query string and path is normalized to origin for the gate", async () => {
      const result = (await h.guarded.client.callTool("http.get", {
        url: `${h.publicGood}/v2/widgets?limit=10`,
      })) as { status: number };
      expect(result.status).toBe(200);
      expect(testServer.hits.map((x) => x.url)).toEqual(["/v2/widgets?limit=10"]);
    });
  });

  describe("deny path — origin", () => {
    it("GET to a non-allowlisted origin is denied — fetch never runs", async () => {
      await expect(
        h.guarded.client.callTool("http.get", { url: `${h.publicBad}/exfil` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(testServer.hits).toEqual([]);
      expect(badServer.hits).toEqual([]);
    });

    it("GET with userinfo splitting is denied — parsed origin is the real host", async () => {
      // url userinfo `api.example.com@evil.com/x` → URL.origin = https://evil.com
      // → not in allowlist → denied.
      await expect(
        h.guarded.client.callTool("http.get", {
          url: "https://api.example.com@evil.com/exfil",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(testServer.hits).toEqual([]);
      expect(badServer.hits).toEqual([]);
    });

    it("GET with subdomain confusion is denied", async () => {
      await expect(
        h.guarded.client.callTool("http.get", {
          url: "https://api.example.com.evil.com/exfil",
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(testServer.hits).toEqual([]);
      expect(badServer.hits).toEqual([]);
    });

    it("GET with malformed URL is denied — no arg.origin to compare against", async () => {
      await expect(
        h.guarded.client.callTool("http.get", { url: "not a url" }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(testServer.hits).toEqual([]);
    });

    it("GET with non-string url is denied", async () => {
      await expect(h.guarded.client.callTool("http.get", { url: 42 })).rejects.toBeInstanceOf(
        CapabilityDeniedError,
      );
      expect(testServer.hits).toEqual([]);
    });
  });

  describe("deny path — method", () => {
    it("POST is denied even to an allowlisted origin", async () => {
      await expect(
        h.guarded.client.callTool("http.post", {
          url: `${h.publicGood}/items`,
          body: '{"x":1}',
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(testServer.hits).toEqual([]);
    });

    it("PUT is denied", async () => {
      await expect(
        h.guarded.client.callTool("http.put", {
          url: `${h.publicGood}/items/42`,
          body: '{"x":2}',
        }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(testServer.hits).toEqual([]);
    });

    it("DELETE is denied", async () => {
      await expect(
        h.guarded.client.callTool("http.delete", { url: `${h.publicGood}/items/42` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      expect(testServer.hits).toEqual([]);
    });
  });

  describe("issuance preconditions", () => {
    it("rejects empty allowlist", () => {
      expect(() => issueOriginScopedGetCapability({ allowedOrigins: [], caller: CALLER })).toThrow(
        /non-empty/,
      );
    });

    it("rejects an origin with a path", () => {
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: ["https://api.example.com/v1"],
          caller: CALLER,
        }),
      ).toThrow(/exact origin/);
    });

    it("rejects an origin with userinfo", () => {
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: ["https://user:pass@api.example.com"],
          caller: CALLER,
        }),
      ).toThrow(/exact origin/);
    });

    it("rejects a malformed origin", () => {
      expect(() =>
        issueOriginScopedGetCapability({
          allowedOrigins: ["not-a-url"],
          caller: CALLER,
        }),
      ).toThrow(/exact origin/);
    });
  });

  describe("audit receipts", () => {
    it("every decision (allow or deny) produces a receipt", async () => {
      await h.guarded.client.callTool("http.get", { url: `${h.publicGood}/a` });
      await expect(
        h.guarded.client.callTool("http.get", { url: `${h.publicBad}/b` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);
      await expect(
        h.guarded.client.callTool("http.post", { url: `${h.publicGood}/c` }),
      ).rejects.toBeInstanceOf(CapabilityDeniedError);

      expect(h.guarded.receipts).toHaveLength(3);
      const outcomes = h.guarded.receipts.map(
        (r) => (r as { outcome: { kind: string } }).outcome.kind,
      );
      expect(outcomes).toEqual(["allowed", "denied", "denied"]);
    });
  });
});
