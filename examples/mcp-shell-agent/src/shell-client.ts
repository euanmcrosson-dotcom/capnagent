/**
 * Minimal MCP-style shell client.
 *
 * Implements the `MCPClientLike` structural shape from `@capnagent/mcp`:
 *
 *     interface MCPClientLike { callTool(name: string, args: unknown): Promise<unknown> }
 *
 * One tool — `shell.exec` — that takes a structured `argv: string[]`
 * (NOT a single command string). The argv-as-array shape is
 * deliberate: it forces caller and capability to agree on token
 * boundaries up front, which sidesteps an entire class of caveat-
 * smuggling bugs that bite shell-string-based gates (quoting, IFS
 * splitting, `;`/`&&` injection).
 *
 * This client is for tests and demos. Production deployments should
 * either spawn a real subprocess (`child_process.spawn(argv[0],
 * argv.slice(1))`) — passing argv as a list, NEVER as a shell string —
 * or talk to a sandboxed runtime (Firecracker, Wasmtime). capnagent's
 * job is to gate the call BEFORE this client is invoked; the client
 * itself enforces no policy.
 */

import type { MCPClientLike } from "@capnagent/mcp";

export interface ShellExecArgs {
  /** Argument vector. argv[0] is the command; argv[1..] are arguments. */
  argv: string[];
  /** Working directory. Optional; the demo client just records it. */
  cwd?: string;
}

export interface ShellResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ShellCallLog {
  argv: string[];
  cwd: string | undefined;
}

/**
 * A trusted shell client. The `log` field records every invocation
 * that reached this client — the assertion-of-record for "did the
 * call get through capnagent's gate?"
 */
export interface ShellClient extends MCPClientLike {
  readonly log: ReadonlyArray<ShellCallLog>;
}

/**
 * Build a stub shell client. Every `shell.exec` call is recorded;
 * the client returns a deterministic synthetic result so tests don't
 * depend on the host system. Production wiring would replace
 * `simulate` with a real `child_process.spawn`.
 */
export function createShellClient(args?: {
  simulate?: (argv: string[], cwd: string | undefined) => ShellResult;
}): ShellClient {
  const log: ShellCallLog[] = [];
  const simulate =
    args?.simulate ??
    ((argv: string[], _cwd: string | undefined): ShellResult => ({
      stdout: `(stub) executed ${JSON.stringify(argv)}`,
      stderr: "",
      exitCode: 0,
    }));

  const callTool = async (name: string, callArgs: unknown): Promise<unknown> => {
    if (name !== "shell.exec") {
      throw new Error(`unknown tool: ${name}`);
    }
    const a = callArgs as ShellExecArgs;
    if (!Array.isArray(a.argv) || a.argv.length === 0) {
      throw new Error("shell.exec: argv must be a non-empty string array");
    }
    log.push({ argv: a.argv, cwd: a.cwd });
    return simulate(a.argv, a.cwd);
  };

  return {
    callTool,
    get log() {
      return log;
    },
  };
}
