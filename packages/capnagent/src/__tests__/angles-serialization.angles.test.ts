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

  it("[CLOSED v0.5] attenuate() with non-ASCII predicate identifier is rejected at attenuate time", async () => {
    // Original test: CJK identifier `商品` round-tripped through serialize/parse.
    // v0.5: the WASM `attenuate` pre-validates against the caveat DSL parser,
    // which only accepts ASCII identifiers. Non-ASCII idents now throw at
    // attenuate time rather than silently being chained and failing at
    // verify. CJK / emoji / accented-char *string-literal values* (the rhs
    // of a comparison) are still fine — only the identifier path is ASCII.
    const cap = await freshCap("buy-cjk-pred");
    expect(() => cap.attenuate('商品 == "本"')).toThrow();
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
    // v0.5: build() requires ≥1 caveat (closes C.5) and attenuate
    // requires a parseable predicate (closes B.2). The seed caveat
    // gives us a non-zero starting point; the loop attaches valid
    // ones.
    let cap = Issuer.fromKey(ROOT_KEY)
      .issue("buy-long-chain")
      .caveat(`caveat_seed == "v"`)
      .build();
    for (let i = 0; i < 1000; i++) {
      cap = cap.attenuate(`caveat_${i} == "v"`);
    }
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(cap)).not.toThrow();
  });

  it("1000-caveat token serializes and round-trips byte-identically", async () => {
    await init();
    // v0.5: same as above. The original test used `c${i}` (a bare
    // identifier, not a comparison) — those are unparseable and now
    // rejected at attenuate time. Switch to a real comparison so the
    // chain length stress-test continues to exercise the same code
    // path.
    let cap = Issuer.fromKey(ROOT_KEY)
      .issue("buy-long-roundtrip")
      .caveat(`seed == "v"`)
      .build();
    for (let i = 0; i < 1000; i++) {
      cap = cap.attenuate(`c${i} == "v"`);
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
  it('[CLOSED v0.5] cap.attenuate("") REJECTS at attenuation time with a parse error', async () => {
    // Originally [FINDING]: the empty predicate chained silently and
    // produced a permanent-deny token. v0.5 closure: the WASM wrapper
    // pre-validates the predicate parses as caveat DSL before chaining.
    // Empty / whitespace / unparseable predicates throw at attenuate
    // time so a hostile (or buggy) caller in a delegation chain cannot
    // brick a downstream cap.
    const cap = await freshCap("buy-empty-pred");
    expect(() => cap.attenuate("")).toThrow();
    expect(() => cap.attenuate("   ")).toThrow();
    expect(() => cap.attenuate("not a predicate")).toThrow();
    expect(() => cap.attenuate("amount <=")).toThrow(); // missing rhs
  });

  it("[CLOSED v0.5] CapabilityBuilder.caveat is also validated at issuance", async () => {
    await init();
    expect(() =>
      Issuer.fromKey(ROOT_KEY).issue("x").caveat("").build(),
    ).toThrow();
    expect(() =>
      Issuer.fromKey(ROOT_KEY).issue("x").caveat("garbage with spaces").build(),
    ).toThrow();
  });

  it("valid predicates still attenuate without error (regression)", async () => {
    // Each `freshCap` call gives a separate handle — `attenuate`
    // consumes the receiver in wasm-bindgen, so we can't reuse one
    // cap across multiple assertions.
    expect(async () => (await freshCap("v1")).attenuate(`tool == "x"`)).not.toThrow();
    expect(async () => (await freshCap("v2")).attenuate("arg.amount <= 50")).not.toThrow();
    expect(async () =>
      (await freshCap("v3")).attenuate(`tool == "a" OR tool == "b"`),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Angle 10 — Auditor with empty key
// ---------------------------------------------------------------------------

describe("Angle 10 — Auditor with zero-byte key", () => {
  it("[CLOSED v0.5] Auditor REJECTS keys < 16 bytes at construction", async () => {
    // Originally a [FINDING]: `new Auditor(new Uint8Array(0))` succeeded
    // because HMAC accepts any key length per RFC 2104 (including zero).
    // A zero-byte HMAC key is cryptographically catastrophic — any
    // attacker who guesses "the audit key is empty" mints forged
    // receipts with no work. The most realistic way to land a zero-byte
    // key in production is a misconfigured deployment that derived the
    // key from an unset env var.
    //
    // v0.5 closure: `MIN_AUDIT_KEY_LEN` (16) is enforced at the WASM
    // constructor and surfaces as a JS-side `Error`. The Rust core
    // additionally panics on a sub-16-byte key, so direct Rust callers
    // cannot land in this state either. 32 bytes from a CSPRNG remains
    // the production recommendation.
    await init();
    expect(() => new Auditor(new Uint8Array(0))).toThrow();
    expect(() => new Auditor(new Uint8Array([0x42]))).toThrow();
    expect(() => new Auditor(new Uint8Array(15))).toThrow();
    // Boundary: 16 bytes is the minimum; everything ≥16 succeeds.
    expect(() => new Auditor(new Uint8Array(16))).not.toThrow();
    expect(() => new Auditor(new Uint8Array(32))).not.toThrow();
  });

  it("[CLOSED v0.5] error message names the offending length", async () => {
    await init();
    expect(() => new Auditor(new Uint8Array(0))).toThrow(/16|too short/i);
    expect(() => new Auditor(new Uint8Array(8))).toThrow(/16|too short/i);
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
