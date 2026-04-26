# Week 3 — Build Spec (single source of truth for parallel work)

Three independent contributors are implementing the three parts of week 3 in
parallel. This doc locks the interfaces between them so they can ship
without seeing each other's code.

**Read first:** `README.md`, `docs/DESIGN.md`, `docs/WEEK2_SPEC.md`. This
doc *only* covers week 3 — the JS/TS side of capnagent. Threat model and
core abstractions live in the other two.

---

## §1. File-ownership map (strict — do not edit outside your scope)

| Branch | Owner | Files they may create or edit |
|---|---|---|
| `feat/week3-wasm-build` | Terminal A | `package.json` (root, workspace root); `package-lock.json` (root); `pnpm-workspace.yaml` *or* `npm` workspace config in root `package.json`; `scripts/build-wasm.sh`, `scripts/build-wasm.cmd`; `crates/capnagent-wasm/.gitignore` (add `pkg/`); root `.gitignore` (add `node_modules/`, `packages/*/dist/`, `packages/*/node_modules/`); `.github/workflows/ci.yml` (add a `wasm-build` job, do NOT touch existing jobs); `.github/workflows/wasm.yml` if a new file is preferable |
| `feat/week3-ts-core` | Terminal B | `packages/capnagent/` — everything inside (new directory) |
| `feat/week3-ts-mcp` | Terminal C | `packages/capnagent-mcp/` — everything inside (new directory) |

**Hard rules:**

- Do **not** edit any `crates/capnagent-core/**` file. The Rust core is
  frozen for this week. (Terminal A may touch
  `crates/capnagent-wasm/.gitignore` only.)
- Do **not** edit the existing `cargo`-side CI jobs in
  `.github/workflows/ci.yml`. Terminal A may *add* a new job named
  `wasm-build` and may add the test-runner job from §3.
- Do **not** edit each other's `packages/*/` subtrees.
- All public APIs **must match** the contracts in §3 below.
- Tests run via `npm run test` from the package root (or the
  workspace-aware equivalent). Your branch must be green before you stop.

---

## §2. Goal of week 3

Make capnagent reachable from JavaScript / TypeScript so an MCP-based
agent can call tools through a capability-bearing wrapper. Three parts:

1. A reproducible **WASM build pipeline** that compiles `capnagent-wasm`
   into a node- and browser-loadable artifact.
2. **`@capnagent/core`** — an idiomatic TypeScript wrapper around the
   WASM artifact, exposing classes that match the JS/TS conventions the
   downstream MCP adapter (and any other consumer) will rely on.
3. **`@capnagent/mcp`** — an adapter that wraps an MCP TS-SDK client
   so every `tools/call` is mediated by a capability + context, with
   denials surfacing as a typed error and every decision routed to an
   `Auditor`.

These three parts are merged in week 4 into the shopping-agent demo.
Week 3 ships the parts; the demo composes them.

---

## §3. Locked type contracts

These are the public APIs each module must expose. Internal
representations and helpers are at the implementer's discretion.

### 3.1 WASM artifact — contract from Terminal A → Terminal B

`wasm-pack build crates/capnagent-wasm --target bundler --out-dir pkg`
must produce a directory `crates/capnagent-wasm/pkg/` containing the
standard wasm-bindgen output. The generated `*.d.ts` MUST declare at
least the following classes and types — they come from the `#[wasm_bindgen]`
exports already on `master`, so this is documenting the contract, not
inventing one.

```ts
// File: crates/capnagent-wasm/pkg/capnagent_wasm.d.ts (auto-generated)
export function init(): void;

export class Issuer {
  static fromKey(key: Uint8Array): Issuer;
  issue(identifier: string): CapabilityBuilder;
  free(): void;
}

export class CapabilityBuilder {
  caveat(predicate: string): CapabilityBuilder;
  build(): Capability;
  free(): void;
}

export class Capability {
  static parse(token: string): Capability;
  serialize(): string;
  attenuate(predicate: string): Capability;
  readonly identifier: string;
  free(): void;
}

export class Verifier {
  constructor(key: Uint8Array);
  verify(cap: Capability): void;                    // throws on chain fail
  verifyWithContext(
    cap: Capability,
    ctx: ContextInput,
    auditor: Auditor,
  ): RawReceipt;                                    // throws on Chain/Audit
  free(): void;
}

export class Auditor {
  constructor(key: Uint8Array);
  verify(receipt: RawReceipt): void;                // throws on tamper
  free(): void;
}

// Plain JS object passed to verifyWithContext(). All fields camelCase.
export interface ContextInput {
  nowMs?: number;        // millis since epoch; defaults to Date.now()
  caller: string;
  tool: string;
  args: unknown;          // arbitrary JSON value
  env?: Record<string, string>;
}

// Plain JS object returned by verifyWithContext / passed to Auditor.verify.
// Field names follow the Rust serde defaults (snake_case for fields,
// `kind` tag for the Outcome variant). Terminal B is responsible for
// translating to camelCase in the public @capnagent API.
export interface RawReceipt {
  capability_identifier: string;
  caveats: Array<{ predicate: string }>;
  context_summary: {
    caller: string;
    tool: string;
    args_hash: string;
  };
  outcome:
    | { kind: "allowed" }
    | { kind: "denied"; reason: string };
  timestamp_ms: number;
  signature: string;     // lower-case hex
}
```

Terminal B treats `RawReceipt` as opaque and re-shapes it into a public
`Receipt` (see §3.2). The `RawReceipt` shape is the wire format and must
not be touched by either A or B.

### 3.2 `@capnagent/core` package — contract from Terminal B → Terminal C

The package's `index.ts` exports the following, exactly. Published as
`@capnagent/core` (npm requires `@scope/name` for scoped packages —
bare `@capnagent` is an invalid package name).

```ts
export class Issuer {
  static fromKey(key: Uint8Array): Issuer;
  issue(identifier: string): CapabilityBuilder;
}

export class CapabilityBuilder {
  caveat(predicate: string): CapabilityBuilder;
  build(): Capability;
}

export class Capability {
  static parse(token: string): Capability;
  serialize(): string;
  attenuate(predicate: string): Capability;
  readonly identifier: string;
}

export class Verifier {
  constructor(key: Uint8Array);
  verify(cap: Capability): void;        // throws CapabilityChainError
  verifyWithContext(
    cap: Capability,
    ctx: Context,
    auditor: Auditor,
  ): Receipt;                            // throws CapabilityChainError | CapabilityAuditError
}

export class Auditor {
  constructor(key: Uint8Array);
  verify(receipt: Receipt): void;       // throws CapabilityAuditError
}

export interface Context {
  nowMs?: number;
  caller: string;
  tool: string;
  args: unknown;
  env?: Record<string, string>;
}

export interface Receipt {
  capabilityIdentifier: string;
  caveats: ReadonlyArray<{ predicate: string }>;
  contextSummary: {
    caller: string;
    tool: string;
    argsHash: string;
  };
  outcome: { kind: "allowed" } | { kind: "denied"; reason: string };
  timestampMs: number;
  signature: string;
}

export class CapabilityError extends Error {}
export class CapabilityChainError extends CapabilityError {}
export class CapabilityAuditError extends CapabilityError {}

/// Initialize the underlying WASM module. Idempotent. Must be called
/// (and awaited) before any other API is used. Returns when the module
/// is ready.
export function init(): Promise<void>;
```

**Translation discipline (Terminal B):**

- Convert `RawReceipt` → `Receipt` on every receiver: snake_case →
  camelCase, defensively copy arrays into a frozen wrapper.
- Convert `Receipt` → `RawReceipt` on every sender (i.e. `Auditor.verify`).
- Map WASM-thrown errors (caught from the JS-side generated code) into
  `CapabilityChainError` / `CapabilityAuditError`. Use `instanceof` checks
  on the message or, if wasm-bindgen exposes typed errors, the typed form.
- Rust-side `free()` is **not** exposed in the public API. Manage
  lifetime internally. (For v0, leak — wasm-bindgen objects are GC'd by
  the JS runtime. Add `using` / explicit dispose in v0.1.)
- The `init()` function is **idempotent and required**. All other
  classes must throw a descriptive error if used before `init()` resolves.

### 3.3 `@capnagent/mcp` package — public API

```ts
import type { Capability, Auditor, Receipt, Context } from "@capnagent/core";

/// A Context-builder callback. Called once per tool invocation; receives
/// the tool name and arguments and returns the Context the verifier
/// should evaluate caveats against.
export type ContextProvider = (
  toolName: string,
  args: unknown,
) => Context | Promise<Context>;

/// Result of a guarded tool call. On allow, the underlying tool's result
/// is returned plus the receipt. On deny, the underlying tool was NEVER
/// called and the receipt explains why.
export type GuardedResult<T> =
  | { allowed: true;  result: T;       receipt: Receipt }
  | { allowed: false; reason: string;  receipt: Receipt };

/// A minimal MCP-client surface — just the tools/call shape we need.
/// The real client passed in at runtime can be any object that
/// structurally implements this method.
export interface MCPClientLike {
  callTool(name: string, args: unknown): Promise<unknown>;
}

export interface WrapOptions {
  capability: Capability;
  auditor: Auditor;
  verifier: import("@capnagent/core").Verifier;
  context: ContextProvider;
  /// Called with every Receipt — caller may persist to disk, post to a
  /// pipeline, etc. Errors here MUST NOT block the underlying tool call.
  onReceipt?: (r: Receipt) => void | Promise<void>;
}

export class CapabilityDeniedError extends Error {
  constructor(public readonly receipt: Receipt) {
    super(
      receipt.outcome.kind === "denied"
        ? receipt.outcome.reason
        : "denied (no reason)",
    );
  }
}

/// Wrap an MCP client so every callTool() is gated by a capability.
///
/// Returns a new client with the same shape; the `callTool` method
/// throws CapabilityDeniedError when the verifier denies, and propagates
/// CapabilityChainError / CapabilityAuditError from the verifier
/// unchanged. If the verifier allows, `callTool` calls the wrapped
/// client and returns its result.
export function wrapMCPClient<C extends MCPClientLike>(
  client: C,
  options: WrapOptions,
): C;

/// Lower-level helper: run one verification + audit, return a typed
/// GuardedResult. Useful for non-MCP frameworks.
export function guardCall<T>(
  options: WrapOptions,
  toolName: string,
  args: unknown,
  inner: () => Promise<T>,
): Promise<GuardedResult<T>>;
```

---

## §4. Stub strategy for parallel branches

Terminal B cannot import the real WASM artifact until Terminal A's
branch lands. Terminal C cannot import `@capnagent/core` until B's branch
lands. To keep all three productive in parallel:

### Terminal B's stub for the WASM artifact

Inside `packages/capnagent/src/`, create a file `__wasm-stub.ts` whose
public shape matches §3.1 *exactly* (same class names, same method
signatures, same property names). Implement it however you like — a JS
re-implementation of the macaroon math is overkill; instead, make every
method `throw new Error("WASM stub not yet wired")` and write the TS
wrapper code that *would* call the real WASM as if the stub was real.
Your tests should mock the stub and exercise translation logic only.

At merge time, swap `import * as wasm from "./__wasm-stub"` for
`import * as wasm from "../../crates/capnagent-wasm/pkg/capnagent_wasm"`.
That's a one-line diff.

### Terminal C's stub for `@capnagent/core`

Inside `packages/capnagent-mcp/src/`, create `__capnagent-stub.ts`
matching §3.2 exactly. Same approach — methods that throw with a
descriptive "stub not wired" message. The MCP-adapter logic in C is
mostly orchestration (intercept the call, build context, ask the
verifier, log the receipt, decide). It does not need a real verifier
to be unit-testable; mock the stub.

At merge time, change `from "./__capnagent-stub"` to `from "@capnagent/core"`.

---

## §5. Definition of Done (per branch)

Each branch is done when **all** of the following hold:

1. The contracts in §3 compile and match exactly. Field names, method
   names, type shapes — no drift.
2. `npm run test` (or `pnpm test` if Terminal A picks pnpm) is green
   from the package root.
3. `npm run lint` is clean (you choose the linter; biome is recommended
   as a single-tool TS+formatter).
4. `npm run typecheck` is clean (`tsc --noEmit`).
5. Your branch has 1–N small commits with clear messages.
6. You have **not** edited any file outside §1 ownership.

### Suggested test focus per branch

**Terminal A (WASM build):**

- `wasm-pack build` succeeds in the CI workflow on a clean Linux
  runner. Output `pkg/` contains: `capnagent_wasm_bg.wasm`,
  `capnagent_wasm.js`, `capnagent_wasm.d.ts`, `package.json`.
- A tiny smoke test under `scripts/wasm-smoke.cjs` (or `.mjs`) that
  imports the built artifact in Node and asserts the named exports
  exist (`Issuer`, `Verifier`, `Auditor`, etc.). Runs in the CI job.
- README snippet documenting `npm run build:wasm`.

**Terminal B (`@capnagent/core`):**

- Each public method has a unit test against the stub.
- Round-trip: build a Capability, serialize, parse, verify.
- `verifyWithContext` happy path returns a Receipt with
  `outcome.kind === "allowed"`.
- A caveat that fails returns Receipt with `outcome.kind === "denied"`
  and the reason populated.
- `Auditor.verify` round-trips a receipt that came from
  `verifyWithContext`.
- Error mapping: chain failure → `CapabilityChainError`; tamper →
  `CapabilityAuditError`.
- camelCase translation: a fixture `RawReceipt` with snake_case fields
  becomes a `Receipt` with all expected camelCase fields.

**Terminal C (`@capnagent/mcp`):**

- `wrapMCPClient` returns a client whose `callTool` rejects with
  `CapabilityDeniedError` when the (mocked) verifier returns a denied
  receipt — and the underlying client's `callTool` was NEVER invoked.
- On allow, the underlying client IS invoked exactly once with the
  same arguments and its return value flows through unchanged.
- `onReceipt` is called for both allowed and denied paths.
- An exception in `onReceipt` does not block the underlying call
  (allowed path) and does not change the thrown error (denied path).
- `guardCall` typed-result form: both branches of `GuardedResult`
  reachable from tests.

---

## §6. Out of scope for week 3

Do not build, even if tempted:

- Browser bundling (webpack / rollup / esbuild config). The WASM target
  is `bundler` so consumers can pick. Demos run in Node for v0.
- A custom MCP server. We wrap an existing client; building servers is
  v0.1+.
- Streaming / async-iterable tool calls. v0 is one-shot.
- React / Vue / Solid integration packages. Not until there's a real
  consumer.
- Capability persistence to disk / IndexedDB / database. The Auditor
  already persists receipts; capability storage is the consuming app's
  problem.
- `using`-based RAII for WASM `free()`. Leak for v0; revisit in v0.1
  with explicit-resource-management proposal once it's stable.
- Tooling for ergonomic context-builder DSLs (e.g. "fluent context").
  v0 takes a callback; sugar can come later.

---

## §7. Merge protocol

After all three branches are green:

1. Fast-forward `feat/week3-wasm-build` into `master`. Verify
   `npm run build:wasm` produces a `pkg/` directory locally and
   `crates/capnagent-wasm/pkg/` is gitignored.
2. Rebase `feat/week3-ts-core` onto `master`. Replace the
   `__wasm-stub.ts` import with the real path
   `../../crates/capnagent-wasm/pkg/capnagent_wasm`. Run
   `npm run test` from `packages/capnagent/` — should be green.
3. Rebase `feat/week3-ts-mcp` onto `master`. Replace the
   `__capnagent-stub.ts` import with `@capnagent/core`. Run
   `npm run test` from `packages/capnagent-mcp/` — should be green.
4. A final integration commit:
   - Removes both `__*-stub.ts` files.
   - Bumps `CHANGELOG.md` `[Unreleased]` to capture the three packages.
   - Verifies `npm run test` workspace-wide is green.

If a branch produces a conflict outside its ownership, the conflict is
the branch's fault and must be reverted there.

---

## §8. Tooling decisions (locked, do not relitigate this week)

- **Package manager:** npm 10+ workspaces. (Reason: zero install
  friction, native to Node 20, good enough for a 3-package monorepo.
  pnpm in v0.1 if we feel pain.)
- **TypeScript:** strict mode (`"strict": true`), target `es2022`,
  module `"esnext"`, moduleResolution `"bundler"`.
- **Test runner:** Vitest. (Reason: fast, native ESM, low ceremony.
  No Jest unless a contributor's IDE forces it.)
- **Lint + format:** Biome 1.x. (Reason: one tool replaces eslint +
  prettier.)
- **Module type:** ESM only. No CJS for the public API. CJS interop
  is a v0.1 problem if a consumer needs it.
- **Node target:** Node 20 LTS (currently active LTS through 2026-04;
  we'll bump to 22 LTS at the natural cutover).
