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
 * tool list AND the path-prefix check via `OR` / `AND`. v0.5 uses the
 * anchored `starts_with` operator (NOT `matches`, which is substring
 * containment and the source of round 07's lateral-substring foot-gun):
 *
 *     (tool == "read_file"      AND arg.path starts_with "<sandbox>")
 *  OR (tool == "list_directory" AND arg.path starts_with "<sandbox>")
 *  OR (tool == "directory_tree" AND arg.path starts_with "<sandbox>")
 *
 * The Context provider canonicalizes `arg.path` (via `path.resolve`)
 * before the verifier sees it. That collapses `..`, decodes percent-
 * encoding, and normalizes separators — closing rounds 07 + 10. An
 * agent that emits `/sandbox/../etc/passwd` has `arg.path` rewritten
 * to `/etc/passwd` BEFORE the caveat runs; the prefix check then
 * fails closed.
 */

import * as path from "node:path";

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
export { type AdaptedMCPClient, adaptMCPSDKClient } from "./mcp-adapter.js";

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
  // Canonicalize the prefix the same way the Context provider will
  // canonicalize agent-supplied paths, so the prefix the issuer encodes
  // and the values the verifier compares are in the same shape. We
  // build TWO forms:
  //
  //   - `prefixDir` — the path with a trailing separator. Used in the
  //     `starts_with` clause so child paths (e.g. `<sandbox>/file.txt`)
  //     match while sibling-trailing-character collisions
  //     (e.g. `<sandbox>-shadow/...`) do NOT.
  //   - `prefixExact` — the path with NO trailing separator. Used in
  //     an `==` clause so listing the sandbox root itself
  //     (`list_directory(<sandbox>)`) is allowed without bringing back
  //     the trailing-shadow foot-gun.
  //
  // The caveat is `starts_with "<prefixDir>" OR == "<prefixExact>"`,
  // which is exactly "this path is the sandbox root, or a child of
  // it" — anchored, separator-aware, and free of the substring foot-
  // gun.
  const resolved = path.resolve(sandboxPrefix);
  const prefixExact = resolved.endsWith(path.sep) ? resolved.slice(0, -1) : resolved;
  const prefixDir = prefixExact + path.sep;
  // The DSL's string literal syntax doesn't support arbitrary escapes,
  // so we encode backslashes (Windows) and double-quotes; a path
  // containing an unescapable byte fails to parse, which is the
  // correctness property we want (operator gets a clear error, not a
  // silent permissive cap).
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const dirPart = esc(prefixDir);
  const exactPart = esc(prefixExact);
  // v0.5: `starts_with` is anchored at byte 0 — closes round 07's
  // lateral-substring foot-gun where `matches` would admit any path
  // containing the prefix anywhere (e.g. `/etc/<sandbox>-bypass`).
  const insideClause = (tool: string) =>
    `(tool == "${tool}" AND (arg.path starts_with "${dirPart}" OR arg.path == "${exactPart}"))`;
  const readPredicate = `${insideClause("read_file")} OR ${insideClause("list_directory")} OR ${insideClause("directory_tree")}`;

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
      args: canonicalizePathArgs(callArgs),
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

/**
 * Rewrite any `path`-shaped argument the agent supplied so the value
 * the verifier sees is the canonical absolute form — `..` collapsed,
 * separators normalized, percent-encoding decoded.
 *
 * Closes purple-team rounds 07 (sandbox-prefix lateral-substring
 * foot-gun) and 10 (encoding / path-traversal): an agent that emits
 * `{ path: "/sandbox/../etc/passwd" }` has its path rewritten to
 * `/etc/passwd` BEFORE the caveat runs; the anchored `starts_with`
 * prefix check then fails closed against the sandbox root.
 *
 * The canonicalization is intentionally aggressive:
 *
 * - `path.resolve(p)` against the process CWD collapses `..` and `.`
 *   segments and produces an absolute path. Relative inputs are
 *   resolved against CWD; this is the same treatment any underlying
 *   filesystem call would give them, so the caveat sees the same
 *   path the syscall would.
 * - We try `decodeURIComponent` first to unwrap `%2e%2e`-style
 *   traversal that some agents produce when they URL-quote path
 *   segments. Decode failures (invalid `%xx`) leave the input
 *   untouched and let `path.resolve` proceed; either way the result
 *   is checked against the prefix.
 * - We do NOT call `realpath` or otherwise hit the filesystem.
 *   Symlinks are out of scope for this layer (THREAT_MODEL.md notes
 *   they are operator responsibility — a symlink inside the sandbox
 *   pointing out is a deployment foot-gun, not an engine bug).
 *
 * Non-string `path` is returned untouched so non-fs args (e.g.
 * `recursive: true`) flow through unchanged.
 */
function canonicalizePathArgs(callArgs: unknown): unknown {
  if (typeof callArgs !== "object" || callArgs === null) return callArgs;
  const a = callArgs as Record<string, unknown>;
  const rawPath = a["path"];
  if (typeof rawPath !== "string") return callArgs;

  let decoded = rawPath;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    // Malformed percent-encoding — leave as-is and let `path.resolve`
    // do its best. The eventual prefix check is still anchored.
  }
  const canonical = path.resolve(decoded);
  return { ...a, path: canonical };
}
