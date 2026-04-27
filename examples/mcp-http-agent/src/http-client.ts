/**
 * Minimal MCP-style HTTP client.
 *
 * Implements the `MCPClientLike` structural shape from `@capnagent/mcp`:
 *
 *     interface MCPClientLike { callTool(name: string, args: unknown): Promise<unknown> }
 *
 * Four tools, named to mirror typical agent fetch surfaces:
 *
 *   - `http.get`    — GET a URL, return body + status + headers
 *   - `http.post`   — POST a URL with a JSON or string body
 *   - `http.put`    — PUT a URL with a JSON or string body
 *   - `http.delete` — DELETE a URL
 *
 * The client itself enforces no policy. Just like the filesystem
 * sibling, it's deliberately naive: capnagent is the single, signed,
 * auditable gate. If you bypass `wrapMCPClient` and call this client
 * directly, it'll happily fetch any URL you hand it.
 */

import type { MCPClientLike } from "@capnagent/mcp";

export interface HttpGetArgs {
  url: string;
  headers?: Record<string, string>;
}

export interface HttpBodyArgs {
  url: string;
  body?: string;
  headers?: Record<string, string>;
}

export interface HttpDeleteArgs {
  url: string;
  headers?: Record<string, string>;
}

export interface HttpResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
}

export interface HttpCallLog {
  tool: string;
  url: string;
  method: string;
}

export interface HttpClient extends MCPClientLike {
  readonly log: ReadonlyArray<HttpCallLog>;
}

/**
 * Build an HTTP client. `fetchImpl` defaults to global `fetch`; tests
 * pass in a stub that points at a localhost server, so the suite is
 * fully deterministic and never touches the real network.
 */
export function createHttpClient(args?: { fetch?: typeof fetch }): HttpClient {
  const log: HttpCallLog[] = [];
  const fetchImpl = args?.fetch ?? globalThis.fetch;

  const callTool = async (name: string, callArgs: unknown): Promise<unknown> => {
    switch (name) {
      case "http.get":
        return await doGet(fetchImpl, log, callArgs as HttpGetArgs);
      case "http.post":
        return await doBody(fetchImpl, log, "POST", callArgs as HttpBodyArgs);
      case "http.put":
        return await doBody(fetchImpl, log, "PUT", callArgs as HttpBodyArgs);
      case "http.delete":
        return await doDelete(fetchImpl, log, callArgs as HttpDeleteArgs);
      default:
        throw new Error(`unknown tool: ${name}`);
    }
  };

  return {
    callTool,
    get log() {
      return log;
    },
  };
}

function buildInit(
  method: string,
  args: { headers?: Record<string, string>; body?: string },
): RequestInit {
  const init: RequestInit = { method };
  if (args.headers !== undefined) init.headers = args.headers;
  if (args.body !== undefined) init.body = args.body;
  return init;
}

async function doGet(
  fetchImpl: typeof fetch,
  log: HttpCallLog[],
  args: HttpGetArgs,
): Promise<HttpResponse> {
  log.push({ tool: "http.get", url: args.url, method: "GET" });
  const res = await fetchImpl(args.url, buildInit("GET", args));
  return await toResponse(res);
}

async function doBody(
  fetchImpl: typeof fetch,
  log: HttpCallLog[],
  method: "POST" | "PUT",
  args: HttpBodyArgs,
): Promise<HttpResponse> {
  log.push({ tool: `http.${method.toLowerCase()}`, url: args.url, method });
  const res = await fetchImpl(args.url, buildInit(method, args));
  return await toResponse(res);
}

async function doDelete(
  fetchImpl: typeof fetch,
  log: HttpCallLog[],
  args: HttpDeleteArgs,
): Promise<HttpResponse> {
  log.push({ tool: "http.delete", url: args.url, method: "DELETE" });
  const res = await fetchImpl(args.url, buildInit("DELETE", args));
  return await toResponse(res);
}

async function toResponse(res: Response): Promise<HttpResponse> {
  const headers: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    headers[key] = value;
  });
  return {
    status: res.status,
    body: await res.text(),
    headers,
  };
}
