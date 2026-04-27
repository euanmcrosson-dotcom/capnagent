/**
 * `@capnagent-examples/mcp-fs-agent` — sandbox-scoped filesystem agent.
 *
 * Wraps an MCP-style filesystem client through `@capnagent/mcp` so that:
 *
 *   - read-only tools (`read_file`, `list_directory`, `directory_tree`)
 *     are allowed when their `path` argument is inside the sandbox prefix.
 *   - any path outside the sandbox is denied before the underlying client
 *     sees it.
 *   - write tools (`write_file`, `create_directory`, `delete_path`) are
 *     denied unconditionally — the issued capability has no clause that
 *     mentions them, so the caveat-evaluation gate refuses them.
 *
 * The capability is one DSL predicate that composes the read-only
 * tool list AND the path-prefix check via `OR` / `AND`:
 *
 *     (tool == "read_file"      AND arg.path matches "<sandbox>")
 *  OR (tool == "list_directory" AND arg.path matches "<sandbox>")
 *  OR (tool == "directory_tree" AND arg.path matches "<sandbox>")
 *
 * Note on `matches`: the v0.1 caveat DSL implements `matches` as substring
 * containment, not regex. That's why the sandbox prefix should be a path
 * component unique enough that no path could legitimately contain it (the
 * demo uses `os.tmpdir()` + a random suffix). For production deployments
 * that need exact-prefix semantics, normalize `arg.path` inside the
 * verifier-controlled `Context` before evaluation.
 */

import { Auditor, type Capability, type Context, Issuer, Verifier, init } from "@capnagent/core";
import { type WrapOptions, wrapMCPClient } from "@capnagent/mcp";

import { type FsClient, createFsClient } from "./fs-client.js";

export {
  type FsCallLog,
  type FsClient,
  type ReadFileArgs,
  type ListDirectoryArgs,
  type DirectoryTreeArgs,
  type WriteFileArgs,
  type CreateDirectoryArgs,
  type DeletePathArgs,
  createFsClient,
} from "./fs-client.js";

/**
 * Demo's root key. In a real deployment this would live in your KMS /
 * env vars / secret manager, NOT in source. The demo holds it inline so
 * the read path is reproducible.
 */
const ROOT_KEY = new Uint8Array(32).fill(0xb1);
const AUDIT_KEY = new Uint8Array(32).fill(0xb2);

/**
 * Issue a sandbox-scoped, time-bounded read capability for the given
 * `sandboxPrefix`. `caller` is baked into the cap so a stolen token
 * can't be presented under a different identity.
 */
export function issueSandboxReadCapability(args: {
  sandboxPrefix: string;
  caller: string;
}): Capability {
  const { sandboxPrefix, caller } = args;
  // Reject sandbox prefixes that would let `matches` accept paths outside
  // the intended sandbox by accident. We require the prefix to be at
  // least 8 characters and to contain a path separator so it can't
  // accidentally be a substring of arbitrary file names.
  if (sandboxPrefix.length < 8 || (!sandboxPrefix.includes("/") && !sandboxPrefix.includes("\\"))) {
    throw new Error(
      `issueSandboxReadCapability: sandboxPrefix must be a unique path-like prefix (got ${JSON.stringify(sandboxPrefix)})`,
    );
  }
  // Embed the prefix into the caveat. We escape backslashes (Windows) and
  // double-quotes; the DSL's string literal syntax doesn't support
  // arbitrary escapes, so a path containing a `"` would fail to parse —
  // that's a correctness property, not a limitation worth working around.
  const escapedPrefix = sandboxPrefix.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const readPredicate =
    `(tool == "read_file"      AND arg.path matches "${escapedPrefix}") ` +
    `OR (tool == "list_directory" AND arg.path matches "${escapedPrefix}") ` +
    `OR (tool == "directory_tree" AND arg.path matches "${escapedPrefix}")`;

  return Issuer.fromKey(ROOT_KEY)
    .issue("fs.read")
    .caveat(`caller == "${caller}"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .caveat(readPredicate)
    .build();
}

/**
 * Build a guarded filesystem client. Returns the structurally-typed
 * `FsClient` (so callers can read `.log` to see what reached the
 * underlying surface) plus the receipts emitted by the verifier — every
 * decision, allow or deny, is appended to the array in order.
 *
 * The capability is required up front; this function does not issue one
 * itself, so callers can compose more interesting policies (e.g. issue a
 * cap, attenuate it further, then wrap).
 */
export async function createGuardedFsClient(args: {
  capability: Capability;
  caller: string;
  underlying?: FsClient;
}): Promise<{ client: FsClient; underlying: FsClient; receipts: ReadonlyArray<unknown> }> {
  await init();
  const underlying = args.underlying ?? createFsClient();
  const receipts: unknown[] = [];

  const options: WrapOptions = {
    capability: args.capability,
    auditor: new Auditor(AUDIT_KEY),
    verifier: new Verifier(ROOT_KEY),
    context: (toolName: string, callArgs: unknown): Context => ({
      caller: args.caller,
      tool: toolName,
      args: callArgs,
      nowMs: Date.now(),
    }),
    onReceipt: (r) => {
      receipts.push(r);
    },
  };

  const wrapped = wrapMCPClient(underlying, options);
  // Re-expose the underlying client's `log` field on the proxy. wrapMCPClient
  // already reflects unknown property accesses through, so `wrapped.log`
  // returns the same array as `underlying.log`.
  return { client: wrapped, underlying, receipts };
}
