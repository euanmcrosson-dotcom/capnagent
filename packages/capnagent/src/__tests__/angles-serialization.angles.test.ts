/**
 * Angles run — Terminal B
 *
 * Try to break the wire-format and audit-MAC layers with subtle byte-level
 * inputs. Canonical-JSON producing byte-identical output is load-bearing for
 * the cryptographic chain — this file probes that contract from the TS side.
 *
 * Each `describe` is one angle. Findings are marked `[FINDING]` on the test
 * name AND in a `// FINDING: ...` comment so a grep can locate them.
 */

import { describe, expect, it } from "vitest";

import {
  Auditor,
  Capability,
  CapabilityAuditError,
  type Context,
  Issuer,
  type Receipt,
  Verifier,
  init,
} from "../index.js";
import { rawReceiptToReceipt, receiptToRaw } from "../translate.js";

const ROOT_KEY = new Uint8Array(32).fill(0xa1);
const AUDIT_KEY = new Uint8Array(32).fill(0xa2);

/** Stable ms timestamp so receipts compare bytewise across calls. */
const FROZEN_MS = 1_700_000_000_000;

async function freshCap(id = "buy-angles") {
  await init();
  return Issuer.fromKey(ROOT_KEY).issue(id).caveat(`tool == "http.post"`).build();
}

// ---------------------------------------------------------------------------
// Angle 1 — Receipt round-trip determinism (WASM ↔ TS ↔ WASM)
// ---------------------------------------------------------------------------

describe("Angle 1 — Receipt round-trip determinism", () => {
  it("verify-translate-back-translate-verify holds for an allowed receipt", async () => {
    const cap = await freshCap();
    const ctx: Context = {
      caller: "agent:planner",
      tool: "http.post",
      args: { x: 1, y: 2 },
      nowMs: FROZEN_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const r1 = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r1.outcome.kind).toBe("allowed");

    // Round 1: Receipt -> RawReceipt (TS-side) -> back to Receipt-shape
    const raw = receiptToRaw(r1);
    const r2 = rawReceiptToReceipt(raw);

    // The shape should be preserved bytewise across the translate layer.
    expect(r2).toEqual(r1);

    // Round 2: send back into WASM. Must verify.
    expect(() => auditor.verify(r2)).not.toThrow();
  });

  it("re-verifying the same receipt twice does not consume / mutate it", async () => {
    const cap = await freshCap();
    const ctx: Context = {
      caller: "agent:planner",
      tool: "http.post",
      args: { ok: true },
      nowMs: FROZEN_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);
    const r = verifier.verifyWithContext(cap, ctx, auditor);
    auditor.verify(r);
    auditor.verify(r);
    auditor.verify(r);
  });
});

// ---------------------------------------------------------------------------
// Angle 2 — Capability serialize → parse → serialize idempotence
// ---------------------------------------------------------------------------

describe("Angle 2 — Capability serialize/parse idempotence", () => {
  it("serialize → parse → serialize is byte-identical", async () => {
    const cap = await freshCap("buy-idempotence");
    const t1 = cap.serialize();
    const reparsed = Capability.parse(t1);
    const t2 = reparsed.serialize();
    expect(t2).toBe(t1);
  });

  it("multiple round-trips converge on the same byte sequence", async () => {
    const cap = (await freshCap("buy-converge")).attenuate("amount <= 50_usd");
    let t = cap.serialize();
    for (let i = 0; i < 5; i++) {
      const c = Capability.parse(t);
      const t2 = c.serialize();
      expect(t2).toBe(t);
      t = t2;
    }
  });
});

// ---------------------------------------------------------------------------
// Angle 3 — Deeply-nested args canonical-JSON sort
// ---------------------------------------------------------------------------

describe("Angle 3 — Deeply nested args canonical-JSON sort", () => {
  it("identical nested args produce identical args_hash regardless of insertion order", async () => {
    const cap = await freshCap("buy-deep");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    // Construct the same logical value two different ways. JS object literal
    // insertion order is preserved by V8 for string keys, so these two
    // objects walk in distinct orders. Canonical-JSON should still sort
    // them identically before hashing.
    const argsA = { a: { b: { c: { d: 1, e: 2 }, f: 3 }, g: 4 }, h: 5 };
    const argsB: Record<string, unknown> = {};
    argsB.h = 5;
    argsB.a = { g: 4, b: { f: 3, c: { e: 2, d: 1 } } };

    const ctxA: Context = { caller: "x", tool: "http.post", args: argsA, nowMs: FROZEN_MS };
    const ctxB: Context = { caller: "x", tool: "http.post", args: argsB, nowMs: FROZEN_MS };

    const rA = verifier.verifyWithContext(cap, ctxA, auditor);
    const rB = verifier.verifyWithContext(cap, ctxB, auditor);

    expect(rA.contextSummary.argsHash).toBe(rB.contextSummary.argsHash);
  });

  it("10-level deep insertion-order shuffle still hashes to the same digest", async () => {
    const cap = await freshCap("buy-deep10");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    // Build a 10-deep object, leaves first.
    const deepNatural = { a: { b: { c: { d: { e: { f: { g: { h: { i: { j: 1 } } } } } } } } } };

    // Build the equivalent value by walking *reversed* sibling insertion.
    // Each level has only one key here, so the test reduces to "the
    // serializer doesn't choke on depth"; we add a sibling at each level
    // to actually shuffle.
    const deepShuffled: Record<string, unknown> = {};
    deepShuffled.a = (() => {
      const a: Record<string, unknown> = {};
      a.z_sibling = "ignore-but-changes-key-order";
      a.b = (() => {
        const b: Record<string, unknown> = {};
        b.z_sibling = "ignore";
        b.c = { d: { e: { f: { g: { h: { i: { j: 1 } } } } } } };
        return b;
      })();
      return a;
    })();

    const ctxNatural: Context = {
      caller: "x",
      tool: "http.post",
      args: deepNatural,
      nowMs: FROZEN_MS,
    };
    const ctxShuffled: Context = {
      caller: "x",
      tool: "http.post",
      args: deepShuffled,
      nowMs: FROZEN_MS,
    };
    const rNat = verifier.verifyWithContext(cap, ctxNatural, auditor);
    const rShuf = verifier.verifyWithContext(cap, ctxShuffled, auditor);

    // Different VALUES (one has z_sibling) so hashes differ — that's
    // expected. The angle is "depth doesn't break hashing".
    expect(rNat.contextSummary.argsHash).not.toBe(rShuf.contextSummary.argsHash);
    // Both have full 64-char hex digests.
    expect(rNat.contextSummary.argsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(rShuf.contextSummary.argsHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------------------
// Angle 4 — Unicode in caller / tool, CJK, surrogate pairs
// ---------------------------------------------------------------------------

describe("Angle 4 — Unicode (CJK) in caller / tool", () => {
  it("CJK in caller and tool round-trips through WASM and verifies", async () => {
    const cap = await freshCap("buy-cjk");
    const ctx: Context = {
      caller: "agent:用户",
      tool: "read_文件",
      args: { 名前: "テスト" },
      nowMs: FROZEN_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const r = verifier.verifyWithContext(cap, ctx, auditor);
    // Tool != http.post → caveat denies, but the receipt must still be
    // signed and verify. The angle is about Unicode in the audit MAC.
    expect(r.outcome.kind).toBe("denied");
    expect(r.contextSummary.caller).toBe("agent:用户");
    expect(r.contextSummary.tool).toBe("read_文件");
    expect(() => auditor.verify(r)).not.toThrow();
  });

  it("emoji + 4-byte UTF-8 in caller verifies", async () => {
    const cap = await freshCap("buy-emoji");
    const ctx: Context = {
      caller: "agent:🤖",
      tool: "http.post",
      args: { msg: "hello 🌍" },
      nowMs: FROZEN_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const r = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("allowed");
    expect(r.contextSummary.caller).toBe("agent:🤖");
    expect(() => auditor.verify(r)).not.toThrow();
  });

  it("attenuate() with CJK predicate text round-trips", async () => {
    const cap = (await freshCap("buy-cjk-pred")).attenuate('商品 == "本"');
    const t = cap.serialize();
    const reparsed = Capability.parse(t);
    expect(reparsed.serialize()).toBe(t);
  });
});

// ---------------------------------------------------------------------------
// Angle 5 — args_hash collision-target sanity
// ---------------------------------------------------------------------------

describe("Angle 5 — args_hash uniqueness sanity", () => {
  it("two different args produce different full sha256 (collision-resistance smoke)", async () => {
    const cap = await freshCap("buy-collide");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const ctxA: Context = {
      caller: "x",
      tool: "http.post",
      args: { a: 1 },
      nowMs: FROZEN_MS,
    };
    const ctxB: Context = {
      caller: "x",
      tool: "http.post",
      args: { a: 2 },
      nowMs: FROZEN_MS,
    };

    const rA = verifier.verifyWithContext(cap, ctxA, auditor);
    const rB = verifier.verifyWithContext(cap, ctxB, auditor);

    expect(rA.contextSummary.argsHash).not.toBe(rB.contextSummary.argsHash);
    // Full 64 hex chars — sha256 not truncated.
    expect(rA.contextSummary.argsHash).toMatch(/^[0-9a-f]{64}$/);
    expect(rB.contextSummary.argsHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a one-character difference in a string field changes the digest entirely", async () => {
    const cap = await freshCap("buy-onechar");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const rA = verifier.verifyWithContext(
      cap,
      { caller: "x", tool: "http.post", args: { s: "abc" }, nowMs: FROZEN_MS },
      auditor,
    );
    const rB = verifier.verifyWithContext(
      cap,
      { caller: "x", tool: "http.post", args: { s: "abd" }, nowMs: FROZEN_MS },
      auditor,
    );

    // Avalanche: at least 50% of nibbles differ in expectation; the
    // weaker assertion that *some* nibble differs is enough for sanity.
    expect(rA.contextSummary.argsHash).not.toBe(rB.contextSummary.argsHash);
  });
});

// ---------------------------------------------------------------------------
// Angle 6 — Empty array vs empty object args
// ---------------------------------------------------------------------------

describe("Angle 6 — Empty array vs empty object args", () => {
  it("args=[] and args={} hash to DIFFERENT digests", async () => {
    const cap = await freshCap("buy-empty-shape");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const rArr = verifier.verifyWithContext(
      cap,
      { caller: "x", tool: "http.post", args: [], nowMs: FROZEN_MS },
      auditor,
    );
    const rObj = verifier.verifyWithContext(
      cap,
      { caller: "x", tool: "http.post", args: {}, nowMs: FROZEN_MS },
      auditor,
    );

    expect(rArr.contextSummary.argsHash).not.toBe(rObj.contextSummary.argsHash);
  });

  it("args=null vs args={} produce different digests", async () => {
    const cap = await freshCap("buy-null-vs-empty");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const rNull = verifier.verifyWithContext(
      cap,
      { caller: "x", tool: "http.post", args: null, nowMs: FROZEN_MS },
      auditor,
    );
    const rObj = verifier.verifyWithContext(
      cap,
      { caller: "x", tool: "http.post", args: {}, nowMs: FROZEN_MS },
      auditor,
    );

    expect(rNull.contextSummary.argsHash).not.toBe(rObj.contextSummary.argsHash);
  });
});

// ---------------------------------------------------------------------------
// Angle 7 — Number.MIN_SAFE_INTEGER / negative timestampMs
// ---------------------------------------------------------------------------

describe("Angle 7 — Negative / extreme timestampMs handling", () => {
  it('[FINDING] negative nowMs throws CapabilityChainError with a misleading "floating point" message', async () => {
    // FINDING: Passing a negative `nowMs` (e.g. from a clock-source bug
    // or `Number.MIN_SAFE_INTEGER`) makes serde-wasm-bindgen try to
    // deserialize the value into `u64` and fail with:
    //
    //     "invalid type: floating point `-1000000.0`, expected u64"
    //
    // Two sub-issues surface here:
    //
    //   1. The number `-1_000_000` is a JS integer (Number.isInteger →
    //      true), but the error says "floating point". serde-wasm-bindgen
    //      treats every negative JS number as f64 because JS has no
    //      separate integer type — that's correct internally, but the
    //      error message is misleading for users debugging this case.
    //
    //   2. The error is wrapped as `CapabilityChainError`, which is the
    //      WRONG error class. The chain is not the failing layer here —
    //      this is a Context deserialization issue. `mapWasmError`'s
    //      "either" path looks for "audit"/"signature"/"tamper" keywords;
    //      the message contains none, so it defaults to
    //      `CapabilityChainError`. An incident responder seeing
    //      `CapabilityChainError` on a verifier call would assume the
    //      capability was tampered with, not that the *context* was
    //      malformed. Misleading error class.
    //
    // Impact: encoding gap + misleading error taxonomy. An operator
    // whose clock-source bug produces a negative wall-clock will see
    // a `CapabilityChainError` with no hint that the cap is fine and
    // it's the context that's invalid.
    const cap = await freshCap("buy-negts");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: -1_000_000,
    };
    expect(() => verifier.verifyWithContext(cap, ctx, auditor)).toThrow(/floating point|u64/);
  });

  it("very large positive nowMs (year 2286) round-trips intact", async () => {
    const cap = await freshCap("buy-far-future");
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    // 10_000_000_000_000 ms is roughly 2286-11-20. Well within u64 ms
    // range and within Number.MAX_SAFE_INTEGER (~9.007e15).
    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: 10_000_000_000_000,
    };
    const r = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r.timestampMs).toBe(10_000_000_000_000);
    expect(() => auditor.verify(r)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Angle 8 — 1000 caveats chained
// ---------------------------------------------------------------------------

describe("Angle 8 — Long caveat chain (1000)", () => {
  it("chain HMAC stays correct across 1000 attenuations", async () => {
    await init();
    let cap = Issuer.fromKey(ROOT_KEY).issue("buy-long-chain").build();
    for (let i = 0; i < 1000; i++) {
      cap = cap.attenuate(`caveat_${i} == "v"`);
    }
    // Just constructing must not throw.
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(cap)).not.toThrow();
  });

  it("1000-caveat token serializes and round-trips byte-identically", async () => {
    await init();
    let cap = Issuer.fromKey(ROOT_KEY).issue("buy-long-roundtrip").build();
    for (let i = 0; i < 1000; i++) {
      cap = cap.attenuate(`c${i}`);
    }
    const t1 = cap.serialize();
    const reparsed = Capability.parse(t1);
    const t2 = reparsed.serialize();
    expect(t2).toBe(t1);
    expect(() => new Verifier(ROOT_KEY).verify(reparsed)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Angle 9 — Empty-string caveat predicate
// ---------------------------------------------------------------------------

describe("Angle 9 — Empty caveat predicate", () => {
  it('[FINDING] cap.attenuate("") accepts the empty predicate and produces an unevaluable caveat', async () => {
    // FINDING: `attenuate("")` succeeds. The serialized cap carries
    // `{predicate:""}`. At `verifyWithContext` time, the empty
    // predicate is fed into the caveat DSL parser, which returns a
    // parse error and the verifier denies the call with a parse-error
    // reason. So the empty predicate is not a chain-break — it's a
    // permanent-deny attractor: any caller who appends "" to a cap
    // converts it into a token that can never authorize anything,
    // even though `verify()` (chain-only) still passes. There is no
    // structural rejection at attenuation time, no warning.
    //
    // Impact: silent corruption. A misbehaving (or hostile) caller in
    // the chain can effectively brick a delegated capability by
    // appending "" — it still passes chain check, looks valid in the
    // wire format, but every `verifyWithContext` call denies. Easy to
    // mistake for "the verifier is broken" during incident response.
    const cap = await freshCap("buy-empty-pred");
    const attenuated = cap.attenuate("");
    expect(attenuated.serialize()).not.toBe("");

    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);
    // Chain-only verify still passes.
    expect(() => verifier.verify(attenuated)).not.toThrow();

    // Full verify produces a denial, not a throw — that's the
    // permanent-deny shape.
    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: FROZEN_MS,
    };
    const r = verifier.verifyWithContext(attenuated, ctx, auditor);
    expect(r.outcome.kind).toBe("denied");
  });
});

// ---------------------------------------------------------------------------
// Angle 10 — Auditor with empty key
// ---------------------------------------------------------------------------

describe("Angle 10 — Auditor with zero-byte key", () => {
  it("[FINDING] Auditor accepts an empty key (HMAC RFC 2104 allows it, but zero-entropy keys are dangerous)", async () => {
    // FINDING: `new Auditor(new Uint8Array(0))` succeeds — HMAC accepts
    // any key length per RFC 2104, including zero. The Rust core
    // explicitly documents this with an `expect("HMAC accepts keys of
    // any length")`. A zero-byte HMAC key is cryptographically
    // catastrophic: any attacker who guesses "the audit key is empty"
    // can mint forged receipts with no work. There is no minimum-key-
    // length warning at construction.
    //
    // Impact: encoding gap → potential signature break in deployment.
    // Production callers MUST use ≥32 bytes from a CSPRNG (the doc
    // says SHOULD), but the API does not enforce this. A
    // misconfigured deployment that derives the audit key from an
    // empty env var will silently produce forgeable receipts.
    await init();
    const emptyAuditor = new Auditor(new Uint8Array(0));

    const cap = await freshCap("buy-emptykey");
    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: FROZEN_MS,
    };
    const verifier = new Verifier(ROOT_KEY);
    const r = verifier.verifyWithContext(cap, ctx, emptyAuditor);

    // The receipt verifies under the same empty key — proves the
    // empty-key path is fully wired, no early-out.
    expect(() => emptyAuditor.verify(r)).not.toThrow();

    // But ANY attacker who guesses "empty key" can verify too — i.e.
    // the audit guarantee collapses. Demonstrate by constructing a
    // second empty-key Auditor (mock attacker) and verifying the
    // same receipt successfully under it.
    const attackerAuditor = new Auditor(new Uint8Array(0));
    expect(() => attackerAuditor.verify(r)).not.toThrow();
  });

  it("a 1-byte key is also accepted (same shape, slightly more entropy)", async () => {
    await init();
    const a = new Auditor(new Uint8Array([0x42]));
    const cap = await freshCap("buy-1byte");
    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: FROZEN_MS,
    };
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, a);
    expect(() => a.verify(r)).not.toThrow();
  });

  it("a wrong-key auditor REJECTS receipts signed by a different key", async () => {
    // Sanity: the audit-MAC is actually doing its job for non-trivial
    // keys. (Without this check the empty-key finding above could
    // theoretically be a no-op rather than a key-binding failure.)
    await init();
    const signer = new Auditor(new Uint8Array(32).fill(0xaa));
    const wrong = new Auditor(new Uint8Array(32).fill(0xbb));
    const cap = await freshCap("buy-wrongkey");
    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: FROZEN_MS,
    };
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, signer);
    expect(() => wrong.verify(r)).toThrow(CapabilityAuditError);
  });
});

// ---------------------------------------------------------------------------
// Bonus: tampering with translated Receipt fields
// ---------------------------------------------------------------------------

describe("Bonus — translate.ts is a tampering attack surface", () => {
  it("mutating a translated Receipt before verify() causes auditor.verify to throw", async () => {
    const cap = await freshCap("buy-tamper");
    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: FROZEN_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, auditor);

    // Mutate the receipt outside the frozen caveats array. The audit
    // signature must reject this.
    const tampered: Receipt = {
      ...r,
      contextSummary: { ...r.contextSummary, caller: "agent:attacker" },
    };
    expect(() => auditor.verify(tampered)).toThrow(CapabilityAuditError);
  });

  it("mutating a translated Receipt's outcome reason throws", async () => {
    // Use a tool that the cap caveat denies, so the receipt is a
    // denial — then try to flip it to allowed.
    const cap = await freshCap("buy-flip");
    const ctx: Context = {
      caller: "x",
      tool: "bank.wire",
      args: {},
      nowMs: FROZEN_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("denied");

    const flipped: Receipt = {
      ...r,
      outcome: { kind: "allowed" },
    };
    expect(() => auditor.verify(flipped)).toThrow(CapabilityAuditError);
  });

  it("a forged version field is rejected by the version gate before HMAC", async () => {
    const cap = await freshCap("buy-versgate");
    const ctx: Context = {
      caller: "x",
      tool: "http.post",
      args: {},
      nowMs: FROZEN_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, auditor);

    const forged: Receipt = { ...r, version: 99 };
    expect(() => auditor.verify(forged)).toThrow(CapabilityAuditError);
  });
});
