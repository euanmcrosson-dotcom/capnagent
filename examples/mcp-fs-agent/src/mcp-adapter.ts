/**
 * Adapter from `@modelcontextprotocol/sdk`'s `Client` to our
 * structurally-typed `MCPClientLike` shape.
 *
 * The SDK exposes `client.callTool({ name, arguments })` returning a
 * `{ content, isError }` object; our wrapper expects the simpler
 * `callTool(name, args) → Promise<unknown>` shape. The adapter is two
 * lines of glue plus a small log entry so callers can still inspect
 * what reached the underlying server.
 *
 * Usage:
 *
 *     const transport = new StdioClientTransport({
 *       command: "npx",
 *       args: ["-y", "@modelcontextprotocol/server-filesystem", sandboxPath],
 *     });
 *     const sdkClient = new Client({ name: "capnagent", version: "0.0.1" }, {});
 *     await sdkClient.connect(transport);
 *     const adapted = adaptMCPSDKClient(sdkClient);
 *     // adapted is now MCPClientLike; pass to wrapMCPClient or
 *     // createGuardedFsClient({ underlying: adapted, ... }).
 *
 * Note that the official `@modelcontextprotocol/server-filesystem`
 * uses tool names like `read_text_file`, `list_directory`,
 * `read_media_file`, `directory_tree`, `write_file`, etc. — pick
 * those when issuing capabilities for that server. The names in our
 * in-process `FsClient` were chosen to mirror but are NOT identical
 * (we do not implement `read_media_file`, for instance).
 */

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";

import type { MCPClientLike } from "@capnagent/mcp";

export interface AdaptedMCPClient extends MCPClientLike {
  /** Calls forwarded to the underlying SDK client, in order. */
  readonly log: ReadonlyArray<{ tool: string; args: unknown }>;
}

/**
 * Wrap an `@modelcontextprotocol/sdk` `Client` so it satisfies
 * `MCPClientLike`. The result can be passed straight to
 * `wrapMCPClient(...)` or `createGuardedFsClient({ underlying, ... })`.
 *
 * The adapter records every call in `log` for diagnostics. It does
 * NOT enforce policy of any kind — that's capnagent's job, applied
 * via `wrapMCPClient` on top of this adapter.
 */
export function adaptMCPSDKClient(client: Client): AdaptedMCPClient {
  const log: Array<{ tool: string; args: unknown }> = [];
  return {
    async callTool(name: string, args: unknown): Promise<unknown> {
      log.push({ tool: name, args });
      const result = await client.callTool({
        name,
        arguments: args as Record<string, unknown> | undefined,
      });
      return result;
    },
    get log() {
      return log;
    },
  };
}
