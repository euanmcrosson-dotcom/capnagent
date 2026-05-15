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

The example issues **two distinct capabilities** — one read-side, one
write-side — so callers can hold either or both, and the principle of
least authority is preserved by default.

```text
identifier: fs.read                       identifier: fs.write
caveats:                                  caveats:
  - caller == "agent:fs"                    - caller == "agent:fs"
  - now <= @2099-01-01T00:00:00Z            - now <= @2099-01-01T00:00:00Z
  - (tool == "read_file"           AND      - (tool == "write_file"        AND
        arg.path starts_with "<dir>" OR         arg.path starts_with "<dir>" OR
        arg.path == "<exact>")                  arg.path == "<exact>")
 OR (tool == "read_text_file"      AND  OR (tool == "edit_file"         AND
        arg.path starts_with …)                 arg.path starts_with …)
 OR (tool == "list_directory"      AND  OR (tool == "create_directory"  AND
        arg.path starts_with …)                 arg.path starts_with …)
 OR (tool == "list_directory_with_sizes" OR (tool == "move_file" AND
        AND arg.path starts_with …)             arg.source starts_with …
 OR (tool == "directory_tree"      AND          AND arg.destination starts_with …)
        arg.path starts_with …)
 OR (tool == "get_file_info"       AND
        arg.path starts_with …)
```

## Tool-coverage table

The official `@modelcontextprotocol/server-filesystem` exposes 14
tools. v0.5.1 of this example bounds 10 of them across the two
capabilities; the other 4 are deliberately out of scope and
documented below.

| # | Tool | Bounded by | Status |
|---|---|---|---|
| 1 | `read_file` | read cap | ✅ allowed inside sandbox, denied outside |
| 2 | `read_text_file` | read cap | ✅ allowed inside sandbox, denied outside (alias of read_file) |
| 3 | `list_directory` | read cap | ✅ allowed inside sandbox, denied outside |
| 4 | `list_directory_with_sizes` | read cap | ✅ allowed inside sandbox, denied outside |
| 5 | `directory_tree` | read cap | ✅ allowed inside sandbox, denied outside |
| 6 | `get_file_info` | read cap | ✅ allowed inside sandbox, denied outside |
| 7 | `write_file` | write cap | ✅ allowed inside sandbox, denied outside |
| 8 | `edit_file` | write cap | ✅ allowed inside sandbox, denied outside |
| 9 | `create_directory` | write cap | ✅ allowed inside sandbox, denied outside |
| 10 | `move_file` | write cap | ✅ allowed when **both** source and destination are inside sandbox |
| 11 | `read_multiple_files` | — | 🚫 denied by default — array-of-paths arg, DSL works on single-string args. Loop `read_file` instead. |
| 12 | `read_media_file` | — | 🚫 denied by default — binary content not modeled in this stub. |
| 13 | `search_files` | — | 🚫 denied by default — returns paths anywhere under the input root, which would broaden the sandbox to "whatever search can find." |
| 14 | `list_allowed_directories` | — | 🚫 denied by default — server-configuration metadata, no path arg to constrain. Operator can allow unconditionally if desired. |

The example also defines `delete_path` (not in the official server),
which is denied unconditionally by absence of any clause permitting it.

## How the engine enforces this

There is no clause permitting any of the "denied" tools. Those are
refused at the caveat-evaluation gate before the underlying client is
invoked. The READ capability has no write clause; the WRITE capability
has no read clause. An agent that holds only one cannot pivot to the
other.

The address-only attack class (issue #1) is closed: an operator
reading this README sees exactly which tools are bounded, which are
deliberately denied, and the rationale for each — no silent gap.

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

The package ships an `adaptMCPSDKClient` that wraps any
[`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk)
`Client` to satisfy `MCPClientLike`. A runnable demo against the
official
[`@modelcontextprotocol/server-filesystem`](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)
is included:

```bash
npm run -w @capnagent-examples/mcp-fs-agent demo:live-mcp
```

…and an opt-in vitest spec verifies the integration:

```bash
CAPNAGENT_MCP_LIVE=1 npm test -w @capnagent-examples/mcp-fs-agent
```

Skeleton of what `demo:live-mcp` does:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { wrapMCPClient } from "@capnagent/mcp";
import { adaptMCPSDKClient } from "@capnagent-examples/mcp-fs-agent";

const transport = new StdioClientTransport({
  command: "npx",
  args: ["-y", "@modelcontextprotocol/server-filesystem", sandboxPath],
});
const sdkClient = new Client({ name: "capnagent", version: "0.0.1" }, {});
await sdkClient.connect(transport);

const guarded = wrapMCPClient(adaptMCPSDKClient(sdkClient), {
  capability,         // sandbox-scoped read cap
  verifier,
  auditor,
  context: (tool, args) => ({ caller: "agent:fs", tool, args, nowMs: Date.now() }),
});

await guarded.callTool("read_text_file", { path: insideSandbox });
// → reads the file via the real MCP server
await guarded.callTool("read_text_file", { path: outsideSandbox });
// → CapabilityDeniedError, server never sees the call
```

Note that the official server's tool names differ from the
in-process `FsClient` — it uses `read_text_file` (not `read_file`),
adds `read_media_file`, `move_file`, `search_files`, etc. The live
demo's capability uses the official names; consult the server's
docs when issuing capabilities for it.
