/**
 * Runnable demo for the origin-scoped HTTP agent.
 *
 *   npm run -w @capnagent-examples/mcp-http-agent demo
 *
 * Spins up two localhost stub HTTP servers (one stands in for an
 * allowlisted origin, one for a non-allowlisted origin), wires fetch
 * through a rewriting stub so the agent's "public" URLs route to
 * localhost without touching the real network, then walks through:
 *
 *   1. GET to allowlisted origin                 → allowed
 *   2. GET with query string + path              → allowed
 *   3. GET to non-allowlisted origin             → denied
 *   4. GET with `user@host` userinfo splitting   → denied
 *   5. GET with `host.evil.com` subdomain trick  → denied
 *   6. POST to allowlisted origin                → denied (no write clause)
 *
 * No LLM, no real network. Deterministic.
 */

import {
  type IncomingMessage,
  type Server,
  type ServerResponse,
  createServer as createHttp,
} from "node:http";
import type { AddressInfo } from "node:net";

import { init } from "@capnagent/core";
import { CapabilityDeniedError } from "@capnagent/mcp";

import { createGuardedHttpClient, issueOriginScopedGetCapability } from "../index.js";

const DIM = "\x1b[2m";
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";

const CALLER = "agent:http";
const PUBLIC_GOOD = "https://api.example.com";
const PUBLIC_BAD = "https://api.attacker.com";

interface Step {
  label: string;
  tool: string;
  args: Record<string, unknown>;
  expect: "allow" | "deny";
}

interface Stub {
  base: string;
  hits: Array<{ url: string; method: string }>;
  close: () => Promise<void>;
}

async function startStub(): Promise<Stub> {
  const hits: Array<{ url: string; method: string }> = [];
  const server: Server = createHttp((req: IncomingMessage, res: ServerResponse) => {
    hits.push({ url: req.url ?? "", method: req.method ?? "" });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`hit ${req.method} ${req.url}`);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${addr.port}`,
    hits,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

function makeRewritingFetch(public2local: Record<string, string>): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], options?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const u = new URL(url);
    const localBase = public2local[u.origin];
    if (!localBase) {
      throw new Error(`fetch stub: no local mapping for origin ${u.origin}`);
    }
    return await fetch(`${localBase}${u.pathname}${u.search}`, options);
  }) as typeof fetch;
}

async function main(): Promise<void> {
  await init();

  const goodStub = await startStub();
  const badStub = await startStub();

  console.log(`${BOLD}${CYAN}capnagent mcp-http-agent demo${RESET}`);
  console.log(`${DIM}allowlisted origin:${RESET} ${PUBLIC_GOOD}`);
  console.log(`${DIM}non-allowlisted:    ${RESET} ${PUBLIC_BAD}`);
  console.log(`${DIM}localhost stubs:    ${RESET} ${goodStub.base} (good), ${badStub.base} (bad)`);
  console.log();

  const cap = issueOriginScopedGetCapability({
    allowedOrigins: [PUBLIC_GOOD],
    caller: CALLER,
  });
  const fetchStub = makeRewritingFetch({
    [PUBLIC_GOOD]: goodStub.base,
    [PUBLIC_BAD]: badStub.base,
  });
  const { client, receipts } = await createGuardedHttpClient({
    capability: cap,
    caller: CALLER,
    fetch: fetchStub,
  });

  const steps: Step[] = [
    {
      label: "GET allowlisted origin",
      tool: "http.get",
      args: { url: `${PUBLIC_GOOD}/v1/items` },
      expect: "allow",
    },
    {
      label: "GET allowlisted origin with query",
      tool: "http.get",
      args: { url: `${PUBLIC_GOOD}/v1/items?limit=10` },
      expect: "allow",
    },
    {
      label: "GET non-allowlisted origin",
      tool: "http.get",
      args: { url: `${PUBLIC_BAD}/exfil` },
      expect: "deny",
    },
    {
      label: "GET userinfo splitting (api.example.com@evil.com)",
      tool: "http.get",
      args: { url: "https://api.example.com@evil.com/exfil" },
      expect: "deny",
    },
    {
      label: "GET subdomain confusion (api.example.com.evil.com)",
      tool: "http.get",
      args: { url: "https://api.example.com.evil.com/exfil" },
      expect: "deny",
    },
    {
      label: "POST allowlisted origin",
      tool: "http.post",
      args: { url: `${PUBLIC_GOOD}/items`, body: '{"x":1}' },
      expect: "deny",
    },
  ];

  let exitCode = 0;
  for (const step of steps) {
    process.stdout.write(`→ ${step.label}\n  ${DIM}${JSON.stringify(step.args)}${RESET}\n`);
    try {
      const result = await client.callTool(step.tool, step.args);
      if (step.expect === "deny") {
        console.error(`  ${RED}✗ UNEXPECTEDLY ALLOWED${RESET}`);
        exitCode = 3;
        continue;
      }
      const preview = JSON.stringify(result).slice(0, 80);
      console.log(`  ${GREEN}✓ allowed${RESET} ${DIM}${preview}${RESET}\n`);
    } catch (err) {
      if (err instanceof CapabilityDeniedError) {
        if (step.expect === "allow") {
          console.error(`  ${RED}✗ UNEXPECTEDLY DENIED${RESET}: ${err.message}`);
          exitCode = 3;
          continue;
        }
        const reason =
          err.receipt.outcome.kind === "denied"
            ? err.receipt.outcome.reason.slice(0, 100)
            : "(no reason)";
        console.log(`  ${GREEN}✓ denied${RESET} ${DIM}${reason}${RESET}\n`);
      } else {
        throw err;
      }
    }
  }

  console.log(`${BOLD}─── result ───${RESET}`);
  console.log(`receipts emitted:                 ${receipts.length}`);
  console.log(
    `requests that hit allowlisted stub: ${goodStub.hits.length === 2 ? `${GREEN}${goodStub.hits.length}${RESET}` : `${RED}${goodStub.hits.length}${RESET}`}`,
  );
  console.log(
    `requests that hit attacker stub:    ${badStub.hits.length === 0 ? `${GREEN}0${RESET}` : `${RED}${badStub.hits.length} (SECURITY FAILURE)${RESET}`}`,
  );

  await goodStub.close();
  await badStub.close();

  if (badStub.hits.length > 0 || goodStub.hits.length !== 2) {
    process.exitCode = 3;
    return;
  }
  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}

main().catch((err) => {
  console.error(`${RED}error:${RESET}`, err);
  process.exit(1);
});
