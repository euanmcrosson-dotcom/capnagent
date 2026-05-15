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
  type ReadTextFileArgs,
  type ListDirectoryArgs,
  type ListDirectoryWithSizesArgs,
  type DirectoryTreeArgs,
  type GetFileInfoArgs,
  type WriteFileArgs,
  type EditFileArgs,
  type CreateDirectoryArgs,
  type MoveFileArgs,
  type DeletePathArgs,
  type FileInfo,
  type DirectoryEntryWithSize,
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
 * The full set of READ-side tool names this example bounds. Single-
 * source-of-truth referenced by both the issuer (builds the predicate)
 * and the example README (table of coverage).
 *
 * Out of scope by design (documented in fs-client.ts):
 *   - `read_multiple_files` (array arg shape, DSL constraint)
 *   - `read_media_file` (binary; not modeled)
 *   - `search_files` (returns paths outside sandbox by design)
 *   - `list_allowed_directories` (no path arg; allow unconditionally
 *     in a real deployment if desired)
 */
export const SANDBOX_READ_TOOLS = [
  "read_file",
  "read_text_file",
  "list_directory",
  "list_directory_with_sizes",
  "directory_tree",
  "get_file_info",
] as const;

/**
 * The full set of WRITE-side tool names bounded by
 * `issueSandboxWriteCapability`. `move_file` has TWO path-shaped args
 * (`source` and `destination`) and the caveat requires BOTH to be in
 * the sandbox — handled as a special case in the predicate.
 *
 * `delete_path` is deliberately NOT in this list — the example never
 * authorises deletion. Mirror the pattern if your deployment wants it.
 */
export const SANDBOX_WRITE_TOOLS = [
  "write_file",
  "edit_file",
  "create_directory",
] as const;

/**
 * Build the sandbox-prefix-pinning fragment shared by both read- and
 * write-side issuers. Returns the pair of (escaped-dir-form, escaped-
 * exact-form) plus a closure that constructs a per-tool clause.
 */
function buildSandboxClauses(sandboxPrefix: string): {
  dirPart: string;
  exactPart: string;
  insideClause: (tool: string, argName?: string) => string;
} {
  if (sandboxPrefix.length < 8 || (!sandboxPrefix.includes("/") && !sandboxPrefix.includes("\\"))) {
    throw new Error(
      `sandboxPrefix must be a unique path-like prefix (got ${JSON.stringify(sandboxPrefix)})`,
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
  const insideClause = (tool: string, argName = "path") =>
    `(tool == "${tool}" AND (arg.${argName} starts_with "${dirPart}" OR arg.${argName} == "${exactPart}"))`;
  return { dirPart, exactPart, insideClause };
}

/**
 * Issue a sandbox-scoped, time-bounded READ capability for the given
 * `sandboxPrefix`. `caller` is baked into the cap so a stolen token
 * can't be presented under a different identity.
 *
 * v0.5.1: covers six tools (was three), mirroring the official MCP
 * filesystem server's read-side surface as documented in the issue #1
 * tool-coverage audit. See `SANDBOX_READ_TOOLS` for the full list,
 * and `fs-client.ts` for the rationale on out-of-scope tools.
 */
export function issueSandboxReadCapability(args: {
  sandboxPrefix: string;
  caller: string;
}): Capability {
  const { sandboxPrefix, caller } = args;
  const { insideClause } = buildSandboxClauses(sandboxPrefix);
  const readPredicate = SANDBOX_READ_TOOLS.map((tool) => insideClause(tool)).join(" OR ");

  return Issuer.fromKey(ROOT_KEY)
    .issue("fs.read")
    .caveat(`caller == "${caller}"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .caveat(readPredicate)
    .build();
}

/**
 * Issue a sandbox-scoped, time-bounded WRITE capability. New in
 * v0.5.1 — the example previously denied all writes; this is the
 * "I want some bounded writes" alternative.
 *
 * Covers: `write_file`, `edit_file`, `create_directory`,
 * `move_file` (where BOTH `source` AND `destination` must be inside
 * the sandbox). Deletion is deliberately omitted — operators wanting
 * delete authority mirror the pattern with an extra clause.
 */
export function issueSandboxWriteCapability(args: {
  sandboxPrefix: string;
  caller: string;
}): Capability {
  const { sandboxPrefix, caller } = args;
  const { insideClause } = buildSandboxClauses(sandboxPrefix);

  // Single-path write tools: write_file, edit_file, create_directory.
  // The default `arg.path` argName is correct for all of them.
  const singlePathClauses = SANDBOX_WRITE_TOOLS.map((tool) => insideClause(tool));

  // move_file is the special case: its args have `source` and
  // `destination`, BOTH of which must be inside the sandbox. The
  // predicate AND-conjoins both checks so an agent can't move a
  // sandboxed file out (or move an outside file in via destination
  // == sandbox to overwrite something).
  const moveClause =
    `(tool == "move_file" ` +
    `AND ${innerClause("source", insideClause)} ` +
    `AND ${innerClause("destination", insideClause)})`;

  const writePredicate = `${singlePathClauses.join(" OR ")} OR ${moveClause}`;

  return Issuer.fromKey(ROOT_KEY)
    .issue("fs.write")
    .caveat(`caller == "${caller}"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .caveat(writePredicate)
    .build();
}

/**
 * Pull the inner part of an insideClause result for a single arg name
 * (without the outer `(tool == "..." AND ...)` wrapper). Used to build
 * the multi-arg `move_file` clause.
 */
function innerClause(
  argName: string,
  insideClauseBuilder: (tool: string, argName?: string) => string,
): string {
  // Build a probe clause and strip the wrapper. We're abusing the
  // existing builder rather than duplicating the escape logic.
  const probe = insideClauseBuilder("__probe__", argName);
  // Strip `(tool == "__probe__" AND ` from the front and `)` from the back.
  return probe.replace(/^\(tool == "__probe__" AND /, "").replace(/\)$/, "");
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
