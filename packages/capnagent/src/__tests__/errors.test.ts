/**
 * Tests for the public error hierarchy. The exact instanceof shape is part
 * of the WEEK3_SPEC.md §3.2 contract — Terminal C's MCP adapter and any
 * other consumer relies on it for error discrimination.
 */

import { describe, expect, it } from "vitest";
import { CapabilityAuditError, CapabilityChainError, CapabilityError } from "../errors.js";

describe("error hierarchy", () => {
  it("CapabilityChainError is a CapabilityError is an Error", () => {
    const e = new CapabilityChainError("nope");
    expect(e).toBeInstanceOf(CapabilityChainError);
    expect(e).toBeInstanceOf(CapabilityError);
    expect(e).toBeInstanceOf(Error);
  });

  it("CapabilityAuditError is a CapabilityError is an Error", () => {
    const e = new CapabilityAuditError("tampered");
    expect(e).toBeInstanceOf(CapabilityAuditError);
    expect(e).toBeInstanceOf(CapabilityError);
    expect(e).toBeInstanceOf(Error);
  });

  it("subclasses are not interchangeable", () => {
    const chain = new CapabilityChainError("a");
    const audit = new CapabilityAuditError("b");
    expect(chain).not.toBeInstanceOf(CapabilityAuditError);
    expect(audit).not.toBeInstanceOf(CapabilityChainError);
  });

  it("preserves the message", () => {
    const e = new CapabilityChainError("invalid signature");
    expect(e.message).toBe("invalid signature");
  });

  it("sets a distinct name on each subclass", () => {
    expect(new CapabilityError("x").name).toBe("CapabilityError");
    expect(new CapabilityChainError("x").name).toBe("CapabilityChainError");
    expect(new CapabilityAuditError("x").name).toBe("CapabilityAuditError");
  });
});
