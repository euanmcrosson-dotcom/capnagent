# `@capnagent-examples/mcp-fs-agent`

A sandbox-scoped filesystem agent — the first real-world consumer of
`@capnagent/mcp`. Demonstrates how to:

1. Issue a capability that grants **read-only access inside a specific
   path prefix**, by `OR`-composing per-tool clauses with a path-prefix
   `matches` predicate.
2. Wrap an MCP-style filesystem client through `wrapMCPClient` so every
   `tools/call` is mediated by the capability before the underlying
   surface sees it.
3. Audit every decision — allow or deny — via signed receipts.

The `FsClient` here implements the structural `MCPClientLike` shape
(`callTool(name, args) → Promise<unknown>`). The same wiring works
unchanged with `@modelcontextprotocol/sdk`'s `Client` once you adapt
its `callTool({ name, arguments })` shape — see "Using a real MCP
server" below.

## What the issued capability says

```text
identifier: fs.read
caveats:
  - caller == "agent:fs"
  - now <= @2099-01-01T00:00:00Z
  - (tool == "read_file"      AND arg.path matches "<sandbox>")
 OR (tool == "list_directory" AND arg.path matches "<sandbox>")
 OR (tool == "directory_tree" AND arg.path matches "<sandbox>")
```

There is no clause permitting `write_file`, `create_directory`, or
`delete_path`. Those are denied at the caveat-evaluation gate before
the underlying client is invoked.

## Run it

```bash
# from the repo root
npm run -w @capnagent-examples/mcp-fs-agent demo
```

Expected output:

```
→ read_file inside sandbox            ✓ allowed
→ list_directory inside sandbox       ✓ allowed
→ read_file OUTSIDE sandbox           ✓ denied (caveat predicate failed)
→ write_file inside sandbox           ✓ denied (caveat predicate failed)
→ delete_path inside sandbox          ✓ denied (caveat predicate failed)
tools that reached the underlying fs: ["list_directory", "read_file"]
```

## Test it

```bash
npm test -w @capnagent-examples/mcp-fs-agent
```

The vitest suite asserts the full allow/deny matrix and verifies that
denied calls never reach the underlying client (`underlying.log`).

## A note on `matches`

The v0.1 caveat DSL implements `matches` as substring containment, not
regex or path-prefix. The demo defends against accidental over-match by:

- Running everything inside an `os.tmpdir()` directory with a random
  suffix, so the sandbox prefix isn't a substring of any real path
  outside the test root.
- Refusing sandbox prefixes that aren't path-like (must contain `/` or
  `\` and be ≥ 8 characters).

In production deployments that need exact-prefix semantics, normalize
`arg.path` inside the verifier-controlled `Context` before evaluation —
e.g. resolve symlinks, reject `..`, then prefix-check against an
allow-list. The `Context` is *yours*; the capability gate evaluates
whatever it sees there.

## Using a real MCP server

To swap the in-process `FsClient` for the official
[`@modelcontextprotocol/server-filesystem`](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem),
write a thin adapter that implements `MCPClientLike`:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { MCPClientLike } from "@capnagent/mcp";

export async function connectMCPFs(sandbox: string): Promise<MCPClientLike> {
  const transport = new StdioClientTransport({
    command: "npx",
    args: ["-y", "@modelcontextprotocol/server-filesystem", sandbox],
  });
  const client = new Client({ name: "capnagent-fs-agent", version: "0.0.1" }, {});
  await client.connect(transport);
  return {
    async callTool(name, args) {
      return await client.callTool({
        name,
        arguments: args as Record<string, unknown> | undefined,
      });
    },
  };
}
```

Then pass the result to `createGuardedFsClient({ underlying, ... })`.
The capability gate, audit receipts, and tests all work unchanged —
that's the whole point of `MCPClientLike` being structural.
