/**
 * Stub matching the wasm-bindgen output described in `docs/WEEK3_SPEC.md`
 * §3.1 — same class names, same method signatures, same property names.
 *
 * Every method throws so the absence of a real WASM artifact is loud, never
 * silent. The wrapper code in `index.ts` and translation logic in
 * `translate.ts` are written *as if* this stub were real; tests mock this
 * module via `vi.mock` and exercise translation/error-mapping in isolation.
 *
 * At merge time, `src/wasm.ts` is rewritten to import from
 * `../../../crates/capnagent-wasm/pkg/capnagent_wasm` instead of this file.
 * That is the single line that needs to change. See WEEK3_SPEC §4.
 */

const NOT_WIRED = "WASM stub not yet wired";

/** Initialize the underlying WASM module. Real wasm-pack output is sync. */
export function init(): void {
  throw new Error(NOT_WIRED);
}

export class Issuer {
  static fromKey(_key: Uint8Array): Issuer {
    throw new Error(NOT_WIRED);
  }
  issue(_identifier: string): CapabilityBuilder {
    throw new Error(NOT_WIRED);
  }
  free(): void {
    // free() is part of the wasm-bindgen contract and must exist on the
    // stub; the wrapper never calls it (lifetime is GC'd for v0).
  }
}

export class CapabilityBuilder {
  caveat(_predicate: string): CapabilityBuilder {
    throw new Error(NOT_WIRED);
  }
  build(): Capability {
    throw new Error(NOT_WIRED);
  }
  free(): void {
    /* see Issuer.free */
  }
}

export class Capability {
  static parse(_token: string): Capability {
    throw new Error(NOT_WIRED);
  }
  serialize(): string {
    throw new Error(NOT_WIRED);
  }
  attenuate(_predicate: string): Capability {
    throw new Error(NOT_WIRED);
  }
  /**
   * Public identifier of the capability. The real wasm-bindgen exports this
   * as a getter; we mirror the type with a readonly field.
   */
  readonly identifier: string = "";
  free(): void {
    /* see Issuer.free */
  }
}

export class Verifier {
  constructor(_key: Uint8Array) {
    throw new Error(NOT_WIRED);
  }
  verify(_cap: Capability): void {
    throw new Error(NOT_WIRED);
  }
  verifyWithContext(_cap: Capability, _ctx: ContextInput, _auditor: Auditor): RawReceipt {
    throw new Error(NOT_WIRED);
  }
  free(): void {
    /* see Issuer.free */
  }
}

export class Auditor {
  constructor(_key: Uint8Array) {
    throw new Error(NOT_WIRED);
  }
  verify(_receipt: RawReceipt): void {
    throw new Error(NOT_WIRED);
  }
  free(): void {
    /* see Issuer.free */
  }
}

/** Plain JS object passed to `verifyWithContext`. All fields camelCase. */
export interface ContextInput {
  nowMs?: number;
  caller: string;
  tool: string;
  args: unknown;
  env?: Record<string, string>;
}

/**
 * Plain JS object returned by `verifyWithContext` and passed to
 * `Auditor.verify`. Field names follow the Rust serde defaults
 * (snake_case for fields, `kind` tag for the Outcome variant).
 *
 * The `@capnagent` package is responsible for translating to camelCase
 * in its public API; consumers never see `RawReceipt`.
 */
export interface RawReceipt {
  capability_identifier: string;
  caveats: Array<{ predicate: string }>;
  context_summary: {
    caller: string;
    tool: string;
    args_hash: string;
  };
  outcome: { kind: "allowed" } | { kind: "denied"; reason: string };
  timestamp_ms: number;
  /** Lower-case hex. */
  signature: string;
}
