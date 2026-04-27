/**
 * `@capnagent-examples/mcp-http-agent` — origin-scoped HTTP agent.
 *
 * Wraps a fetch-style MCP client through `@capnagent/mcp` so that:
 *
 *   - `http.get` is allowed when the URL's origin is in the issued
 *     capability's allowlist.
 *   - any GET to a non-allowlisted origin is denied before fetch runs.
 *   - `http.post`, `http.put`, `http.delete` are denied unconditionally
 *     — the issued capability has no clause that mentions them.
 *
 * The capability composes per-origin clauses with `OR`:
 *
 *     tool == "http.get" AND (
 *          arg.origin == "https://api.example.com"
 *       OR arg.origin == "https://api.weather.com"
 *     )
 *
 * Note that we evaluate `arg.origin` (a normalized field), not
 * `arg.url` (the raw input). The `Context` provider parses the URL with
 * the standard `URL` constructor and writes the parsed origin into
 * `arg.origin` BEFORE the verifier sees it. That defends against:
 *
 *   - userinfo splitting:   `https://api.example.com@evil.com/x`
 *                           parsed origin: `https://evil.com`  → denied
 *   - subdomain confusion:  `https://api.example.com.evil.com/`
 *                           parsed origin: `https://api.example.com.evil.com`
 *                                                                → denied
 *   - whitespace tricks, scheme tricks, IDN homographs — all resolved
 *     by `new URL()` before the caveat is evaluated.
 *
 * If the URL fails to parse, `arg.origin` is absent and the equality
 * check on a missing field is `false` → denied. Fail-closed.
 */

import { Auditor, type Capability, type Context, Issuer, Verifier, init } from "@capnagent/core";
import { type WrapOptions, wrapMCPClient } from "@capnagent/mcp";

import { type HttpClient, createHttpClient } from "./http-client.js";

export {
  type HttpCallLog,
  type HttpClient,
  type HttpGetArgs,
  type HttpBodyArgs,
  type HttpDeleteArgs,
  type HttpResponse,
  createHttpClient,
} from "./http-client.js";

const ROOT_KEY = new Uint8Array(32).fill(0xc1);
const AUDIT_KEY = new Uint8Array(32).fill(0xc2);

/**
 * Issue an origin-scoped, time-bounded GET capability.
 *
 * `allowedOrigins` must be exact origins (`https://host[:port]`) — the
 * verifier compares with `==`, NOT substring. Trailing slashes, paths,
 * and query strings in the agent's URL are stripped by `new URL()`
 * before comparison; only the origin reaches the caveat.
 */
export function issueOriginScopedGetCapability(args: {
  allowedOrigins: ReadonlyArray<string>;
  caller: string;
}): Capability {
  const { allowedOrigins, caller } = args;
  if (allowedOrigins.length === 0) {
    throw new Error("issueOriginScopedGetCapability: allowedOrigins must be non-empty");
  }
  for (const origin of allowedOrigins) {
    if (!isExactOrigin(origin)) {
      throw new Error(
        `issueOriginScopedGetCapability: ${JSON.stringify(origin)} is not an exact origin (expected scheme://host[:port] with no path)`,
      );
    }
  }

  // Build: arg.origin == "<o1>" OR arg.origin == "<o2>" OR ...
  const originPredicate = allowedOrigins
    .map((o) => `arg.origin == "${o.replace(/"/g, '\\"')}"`)
    .join(" OR ");
  const fullPredicate = `tool == "http.get" AND (${originPredicate})`;

  return Issuer.fromKey(ROOT_KEY)
    .issue("http.get")
    .caveat(`caller == "${caller}"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .caveat(fullPredicate)
    .build();
}

/**
 * True iff `s` is a fully-qualified origin: scheme + host (+ optional
 * port), with no path, no query, no fragment, no userinfo.
 *
 * The check rejects values that would surprise the caller: e.g. issuing
 * `"https://api.example.com/v1"` would mean the path is part of the
 * comparison string and never match (since the verifier sees
 * `URL.origin`, which strips paths).
 */
function isExactOrigin(s: string): boolean {
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  if (u.username !== "" || u.password !== "") return false;
  if (u.pathname !== "/" && u.pathname !== "") return false;
  if (u.search !== "" || u.hash !== "") return false;
  // `URL.origin` strips trailing slashes and removes default ports;
  // require the input to already be in that canonical form.
  return s === u.origin;
}

export interface GuardedHttpClient {
  client: HttpClient;
  underlying: HttpClient;
  receipts: ReadonlyArray<unknown>;
}

/**
 * Build a guarded HTTP client. The wrapper installs a `Context`
 * provider that parses `arg.url` and writes the canonical origin into
 * `arg.origin`; the caveat compares against that parsed value, not the
 * raw user input.
 *
 * `fetchImpl` is forwarded to the underlying client; tests inject a
 * localhost-bound stub so no real network is hit.
 */
export async function createGuardedHttpClient(args: {
  capability: Capability;
  caller: string;
  fetch?: typeof fetch;
  underlying?: HttpClient;
}): Promise<GuardedHttpClient> {
  await init();
  const fetchOpt = args.fetch !== undefined ? { fetch: args.fetch } : undefined;
  const underlying = args.underlying ?? createHttpClient(fetchOpt);
  const receipts: unknown[] = [];

  const options: WrapOptions = {
    capability: args.capability,
    auditor: new Auditor(AUDIT_KEY),
    verifier: new Verifier(ROOT_KEY),
    context: (toolName: string, callArgs: unknown): Context => {
      const normalized = normalizeArgs(callArgs);
      return {
        caller: args.caller,
        tool: toolName,
        args: normalized,
        nowMs: Date.now(),
      };
    },
    onReceipt: (r) => {
      receipts.push(r);
    },
  };

  const wrapped = wrapMCPClient(underlying, options);
  return { client: wrapped, underlying, receipts };
}

/**
 * Augment the agent's args with parsed-URL fields the caveat can
 * evaluate against. Non-string `url` or unparseable `url` simply
 * doesn't get an `origin` — the equality caveat then fails closed.
 */
function normalizeArgs(callArgs: unknown): unknown {
  if (typeof callArgs !== "object" || callArgs === null) return callArgs;
  const a = callArgs as Record<string, unknown>;
  const rawUrl = a["url"];
  if (typeof rawUrl !== "string") return callArgs;
  try {
    const parsed = new URL(rawUrl);
    return { ...a, origin: parsed.origin, host: parsed.host, protocol: parsed.protocol };
  } catch {
    return callArgs;
  }
}
