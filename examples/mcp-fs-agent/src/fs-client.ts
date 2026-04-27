/**
 * Minimal MCP-style filesystem client.
 *
 * Implements the `MCPClientLike` structural shape from `@capnagent/mcp`:
 *
 *     interface MCPClientLike { callTool(name: string, args: unknown): Promise<unknown> }
 *
 * Six tools, all named to mirror `@modelcontextprotocol/server-filesystem`:
 *
 *   - `read_file`        — read a UTF-8 file
 *   - `list_directory`   — list immediate children of a directory
 *   - `directory_tree`   — recursive directory listing
 *   - `write_file`       — write/overwrite a UTF-8 file
 *   - `create_directory` — `mkdir -p`
 *   - `delete_path`      — `rm -rf` of a single path
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
        return await readFile(args as ReadFileArgs);
      case "list_directory":
        return await listDirectory(args as ListDirectoryArgs);
      case "directory_tree":
        return await directoryTree(args as DirectoryTreeArgs);
      case "write_file":
        return await writeFile(args as WriteFileArgs);
      case "create_directory":
        return await createDirectory(args as CreateDirectoryArgs);
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
