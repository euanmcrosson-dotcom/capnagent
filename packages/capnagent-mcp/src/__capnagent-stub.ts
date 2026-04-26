/**
 * Local stub for the `@capnagent` package, matching WEEK3_SPEC §3.2 exactly.
 *
 * Terminal C cannot import the real `@capnagent` until Terminal B's branch
 * (`feat/week3-ts-core`) lands on master. This file makes our package
 * type-checkable and unit-testable in isolation.
 *
 * AT MERGE TIME: delete this file and rewrite every `from "./__capnagent-stub"`
 * import to `from "@capnagent"`. The public shape here is identical to the
 * shape Terminal B is committing to ship; if it drifts, that is a spec bug
 * and one of the two branches has to fix it before merge.
 *
 * Method bodies all `throw new Error("@capnagent stub not yet wired")`.
 * Tests that need to exercise verifier behaviour pass plain JS objects that
 * structurally satisfy the relevant interface — they never `new Verifier()`.
 */

const NOT_WIRED = "@capnagent stub not yet wired";

export class Issuer {
  static fromKey(_key: Uint8Array): Issuer {
    throw new Error(NOT_WIRED);
  }
  issue(_identifier: string): CapabilityBuilder {
    throw new Error(NOT_WIRED);
  }
}

export class CapabilityBuilder {
  caveat(_predicate: string): CapabilityBuilder {
    throw new Error(NOT_WIRED);
  }
  build(): Capability {
    throw new Error(NOT_WIRED);
  }
}

export class Capability {
  readonly identifier: string = "";
  static parse(_token: string): Capability {
    throw new Error(NOT_WIRED);
  }
  serialize(): string {
    throw new Error(NOT_WIRED);
  }
  attenuate(_predicate: string): Capability {
    throw new Error(NOT_WIRED);
  }
}

export class Verifier {
  constructor(_key: Uint8Array) {
    throw new Error(NOT_WIRED);
  }
  verify(_cap: Capability): void {
    throw new Error(NOT_WIRED);
  }
  verifyWithContext(_cap: Capability, _ctx: Context, _auditor: Auditor): Receipt {
    throw new Error(NOT_WIRED);
  }
}

export class Auditor {
  constructor(_key: Uint8Array) {
    throw new Error(NOT_WIRED);
  }
  verify(_receipt: Receipt): void {
    throw new Error(NOT_WIRED);
  }
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

export class CapabilityError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = "CapabilityError";
  }
}

export class CapabilityChainError extends CapabilityError {
  constructor(message?: string) {
    super(message);
    this.name = "CapabilityChainError";
  }
}

export class CapabilityAuditError extends CapabilityError {
  constructor(message?: string) {
    super(message);
    this.name = "CapabilityAuditError";
  }
}

export function init(): Promise<void> {
  return Promise.reject(new Error(NOT_WIRED));
}
