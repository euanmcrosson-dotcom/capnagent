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
    const reason = exactOriginRejectionReason(origin);
    if (reason !== null) {
      throw new Error(
        `issueOriginScopedGetCapability: ${JSON.stringify(origin)} rejected: ${reason}`,
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
 * port), with no path, no query, no fragment, no userinfo, and no
 * IDN/punycode/mixed-script confusables in the host.
 *
 * Kept for back-compat with callers that just want a boolean. New
 * callers should use `exactOriginRejectionReason` (returns a string
 * explanation, or `null` if accepted) — its diagnostics survive into
 * issuance error messages.
 */
function isExactOrigin(s: string): boolean {
  return exactOriginRejectionReason(s) === null;
}

/**
 * Validate that `s` is an allowlist-safe origin. Returns `null` if the
 * input is acceptable; otherwise a human-readable reason for rejection
 * suitable for surfacing in an error message at issuance time.
 *
 * v0.5 closes purple-team round 09 (IDN homograph in origin allowlist)
 * by rejecting two foot-gun shapes the previous validator missed:
 *
 *   (a) Non-ASCII characters anywhere in the input string. Pasting
 *       `https://аpi.example.com` (Cyrillic а) used to fail with the
 *       opaque "not an exact origin" error; we now name the issue.
 *   (b) Any DNS label that begins `xn--` (punycode-encoded IDN). This
 *       is the realistic exploitation path — operator tooling
 *       (browser, clipboard, JSON loader) silently canonicalizes a
 *       Cyrillic-а URL into its ASCII punycode form, which then sails
 *       through `URL.origin === s`. Rejecting `xn--` labels here
 *       forces the operator to either choose an ASCII origin or, if
 *       they really do want an IDN, to opt in through a separate path
 *       (which v0.5 does not yet provide — see THREAT_MODEL.md §IDN).
 *
 * This is stricter than TR39 "Highly Restrictive": TR39 would allow
 * punycode-encoded labels whose decoded Unicode is single-script.
 * Implementing the full TR39 confusable-detection table is a bigger
 * dependency than v0.5 wants; the practical compromise is to refuse
 * IDN at the allowlist boundary entirely. The audit-finding called
 * for "TR39 mixed-script detection in isExactOrigin"; rejecting all
 * mixed-script and all punycode is the conservative supremum.
 */
function exactOriginRejectionReason(s: string): string | null {
  // Foot-gun (a): non-ASCII characters in the input string.
  // ASCII range is 0x00–0x7F. The DSL string literal layer also
  // wouldn't tolerate them, but we reject earlier with a useful
  // message so the operator sees "IDN/homograph" rather than a
  // generic parse error.
  for (let i = 0; i < s.length; i++) {
    const cp = s.codePointAt(i);
    if (cp === undefined || cp > 0x7f) {
      return "input contains non-ASCII characters (likely IDN homograph / mixed-script confusable). Use the ASCII form of the origin, or pre-validate with a TR39 confusable check.";
    }
  }

  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return "not a parseable URL";
  }
  if (u.username !== "" || u.password !== "") return "URL contains userinfo (`user:pass@host`)";
  if (u.pathname !== "/" && u.pathname !== "") return "URL contains a path";
  if (u.search !== "" || u.hash !== "") return "URL contains a query string or fragment";
  // `URL.origin` strips trailing slashes and removes default ports;
  // require the input to already be in that canonical form.
  if (s !== u.origin) {
    return `URL is not in canonical-origin form (got ${JSON.stringify(s)}, canonical is ${JSON.stringify(u.origin)})`;
  }
  // Foot-gun (b): hostname contains punycode-encoded IDN labels.
  // Each DNS label is dot-separated; per IDNA-2008, an IDN label is
  // ASCII-encoded as `xn--…`. Detecting this prefix is reliable
  // because `xn--` is the IDNA prefix and never appears in the
  // canonical form of an unencoded ASCII label.
  for (const label of u.hostname.split(".")) {
    if (label.startsWith("xn--")) {
      return "hostname contains a punycode-encoded IDN label (xn--…) — the most common way an IDN homograph slips into an allowlist after operator tooling canonicalizes a Cyrillic / mixed-script URL. v0.5 refuses IDN at this boundary; allowlist the ASCII form, or open a separate API path for IDN if your service genuinely needs it.";
    }
  }
  return null;
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
