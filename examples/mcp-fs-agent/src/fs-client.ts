/**
 * Minimal MCP-style filesystem client.
 *
 * Implements the `MCPClientLike` structural shape from `@capnagent/mcp`:
 *
 *     interface MCPClientLike { callTool(name: string, args: unknown): Promise<unknown> }
 *
 * Mirrors a subset of `@modelcontextprotocol/server-filesystem`'s tool
 * surface. v0.5.1 expanded coverage from 6 → 11 tools to address the
 * "example bounds only 3 of the official server's 14 tools" gap
 * (issue #1):
 *
 *   READ-side (bounded by `issueSandboxReadCapability`):
 *     - `read_file`                — read a UTF-8 file
 *     - `read_text_file`           — alias for read_file (server compat)
 *     - `list_directory`           — list immediate children of a directory
 *     - `list_directory_with_sizes`— list + sizes (operator convenience)
 *     - `directory_tree`           — recursive directory listing
 *     - `get_file_info`            — fs.stat metadata
 *
 *   WRITE-side (bounded by `issueSandboxWriteCapability`, new in v0.5.1):
 *     - `write_file`               — write/overwrite a UTF-8 file
 *     - `edit_file`                — apply a string replace (search-and-replace)
 *     - `create_directory`         — `mkdir -p`
 *     - `move_file`                — rename source → destination
 *
 *   Other (NOT bounded by either default capability — deliberately denied):
 *     - `delete_path`              — `rm -rf`. The example never authorises
 *       deletion; if your real server has a delete tool and you want it
 *       bounded, mirror the write-cap predicate with an additional
 *       `(tool == "delete_path" AND ...)` clause.
 *
 *   Out of scope for this example (deliberate omissions, documented in
 *   the example README):
 *     - `read_multiple_files`      — array-of-paths arg shape; the DSL's
 *       `arg.X starts_with Y` works on single string args. Allowing a
 *       multi-path tool safely requires per-element constraint which
 *       this example does not demonstrate. Implement by looping
 *       `read_file` from your agent instead.
 *     - `read_media_file`          — binary content; this stub keeps
 *       behaviour UTF-8-only.
 *     - `search_files`             — by design returns paths outside
 *       the constrained input path; allowing it implicitly broadens
 *       the sandbox to "anything search can find."
 *     - `list_allowed_directories` — server-configuration metadata,
 *       no path argument to constrain. A real deployment can allow it
 *       unconditionally if desired.
 *
 * The whole point of this example is that capnagent gates these calls
 * BEFORE they arrive here — so this client doesn't enforce any sandbox of
 * its own. If you call into it directly (without `wrapMCPClient`), it
 * happily honours whatever path you hand it. That's deliberate: in a
 * production deployment the underlying MCP server is similarly trusting,
 * and capnagent is the single, signed, auditable gate.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";

import type { MCPClientLike } from "@capnagent/mcp";

export interface ReadFileArgs {
  path: string;
}

export interface ListDirectoryArgs {
  path: string;
}

export interface DirectoryTreeArgs {
  path: string;
}

export interface WriteFileArgs {
  path: string;
  content: string;
}

export interface CreateDirectoryArgs {
  path: string;
}

export interface DeletePathArgs {
  path: string;
}

export interface ReadTextFileArgs {
  path: string;
}

export interface ListDirectoryWithSizesArgs {
  path: string;
}

export interface GetFileInfoArgs {
  path: string;
}

export interface EditFileArgs {
  path: string;
  /** literal string to search for */
  find: string;
  /** literal replacement */
  replace: string;
}

export interface MoveFileArgs {
  /** capnagent-MCP adapters treat both `source` and `destination` as
   * path-shaped args; the write capability constrains both. */
  source: string;
  destination: string;
}

export interface FileInfo {
  path: string;
  size: number;
  kind: "file" | "directory" | "other";
  modifiedMs: number;
}

export interface DirectoryEntryWithSize extends DirectoryEntry {
  size: number;
}

export interface DirectoryEntry {
  name: string;
  kind: "file" | "directory" | "other";
}

export interface DirectoryNode {
  path: string;
  kind: "file" | "directory";
  children?: DirectoryNode[];
}

export interface FsCallLog {
  tool: string;
  args: unknown;
}

/**
 * A trusted filesystem client. The `log` field records every call that
 * actually reached this client — the assertion-of-record for "was the
 * underlying tool surface ever touched?".
 */
export interface FsClient extends MCPClientLike {
  readonly log: ReadonlyArray<FsCallLog>;
}

export function createFsClient(): FsClient {
  const log: FsCallLog[] = [];

  const callTool = async (name: string, args: unknown): Promise<unknown> => {
    log.push({ tool: name, args });
    switch (name) {
      case "read_file":
      case "read_text_file":
        return await readFile(args as ReadFileArgs);
      case "list_directory":
        return await listDirectory(args as ListDirectoryArgs);
      case "list_directory_with_sizes":
        return await listDirectoryWithSizes(args as ListDirectoryWithSizesArgs);
      case "directory_tree":
        return await directoryTree(args as DirectoryTreeArgs);
      case "get_file_info":
        return await getFileInfo(args as GetFileInfoArgs);
      case "write_file":
        return await writeFile(args as WriteFileArgs);
      case "edit_file":
        return await editFile(args as EditFileArgs);
      case "create_directory":
        return await createDirectory(args as CreateDirectoryArgs);
      case "move_file":
        return await moveFile(args as MoveFileArgs);
      case "delete_path":
        return await deletePath(args as DeletePathArgs);
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

async function readFile(args: ReadFileArgs): Promise<string> {
  return await fs.readFile(args.path, "utf8");
}

async function listDirectory(args: ListDirectoryArgs): Promise<DirectoryEntry[]> {
  const entries = await fs.readdir(args.path, { withFileTypes: true });
  return entries.map((e) => ({
    name: e.name,
    kind: e.isFile() ? "file" : e.isDirectory() ? "directory" : "other",
  }));
}

async function directoryTree(args: DirectoryTreeArgs): Promise<DirectoryNode> {
  return await walk(args.path);
}

async function walk(p: string): Promise<DirectoryNode> {
  const stat = await fs.stat(p);
  if (stat.isDirectory()) {
    const entries = await fs.readdir(p);
    const children = await Promise.all(entries.map((e) => walk(path.join(p, e))));
    return { path: p, kind: "directory", children };
  }
  return { path: p, kind: "file" };
}

async function writeFile(args: WriteFileArgs): Promise<{ written: number }> {
  await fs.writeFile(args.path, args.content, "utf8");
  return { written: Buffer.byteLength(args.content, "utf8") };
}

async function createDirectory(args: CreateDirectoryArgs): Promise<{ created: string }> {
  await fs.mkdir(args.path, { recursive: true });
  return { created: args.path };
}

async function deletePath(args: DeletePathArgs): Promise<{ deleted: string }> {
  await fs.rm(args.path, { recursive: true, force: true });
  return { deleted: args.path };
}

async function listDirectoryWithSizes(args: ListDirectoryWithSizesArgs): Promise<DirectoryEntryWithSize[]> {
  const entries = await fs.readdir(args.path, { withFileTypes: true });
  const results: DirectoryEntryWithSize[] = [];
  for (const e of entries) {
    const kind = e.isFile() ? "file" : e.isDirectory() ? "directory" : "other";
    let size = 0;
    if (e.isFile()) {
      try {
        const stat = await fs.stat(path.join(args.path, e.name));
        size = stat.size;
      } catch {
        // permission / race — leave size as 0
      }
    }
    results.push({ name: e.name, kind, size });
  }
  return results;
}

async function getFileInfo(args: GetFileInfoArgs): Promise<FileInfo> {
  const stat = await fs.stat(args.path);
  return {
    path: args.path,
    size: stat.size,
    kind: stat.isFile() ? "file" : stat.isDirectory() ? "directory" : "other",
    modifiedMs: stat.mtimeMs,
  };
}

async function editFile(args: EditFileArgs): Promise<{ replaced: number }> {
  const original = await fs.readFile(args.path, "utf8");
  // Literal-string replacement so this is a deterministic surface for tests,
  // not a regex engine.
  let replaced = 0;
  let updated = original;
  while (updated.includes(args.find)) {
    updated = updated.replace(args.find, args.replace);
    replaced += 1;
    if (replaced > 1000) break; // belt-and-braces guard against pathological inputs
  }
  await fs.writeFile(args.path, updated, "utf8");
  return { replaced };
}

async function moveFile(args: MoveFileArgs): Promise<{ from: string; to: string }> {
  await fs.rename(args.source, args.destination);
  return { from: args.source, to: args.destination };
}
