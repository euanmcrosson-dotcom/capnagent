/**
 * Terminal C — Composition, chaining, and multi-cap edges.
 *
 * Each `describe` block exercises one composition angle from the round
 * brief. We try hard to find places where holding multiple caps,
 * attenuating at runtime, or composing caps in unexpected ways will
 * either bypass a defense or produce a foot-gun.
 *
 * Findings are flagged with `[FINDING]` in the `it(...)` title so a
 * caller running `vitest --run --reporter verbose` can grep them out.
 *
 * The tests run against the real WASM-backed verifier — no mocks. They
 * speak to the public TypeScript surface in `src/index.ts`. When a
 * test needs to manipulate the wire format directly (e.g. to mutate a
 * cap's caveat array post-issuance) it round-trips through
 * `cap.serialize()` / `Capability.parse(...)`, which is the same
 * channel an operator's persistence layer would use.
 */

import { describe, expect, it } from "vitest";

import {
  Auditor,
  Capability,
  CapabilityChainError,
  type Context,
  Issuer,
  Verifier,
  init,
} from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xc1);
const AUDIT_KEY = new Uint8Array(32).fill(0xa1);
const FUTURE = "now <= @2099-01-01T00:00:00Z";

interface SerializedCap {
  identifier: string;
  holder_of_key?: string;
  caveats: Array<{ predicate: string }>;
  signature: string;
}

function decodeToken(token: string): SerializedCap {
  const json = Buffer.from(token, "base64url").toString("utf8");
  return JSON.parse(json) as SerializedCap;
}

function encodeToken(obj: SerializedCap): string {
  const json = JSON.stringify(obj);
  return Buffer.from(json, "utf8").toString("base64url");
}

// nowMs is REQUIRED in every test ctx because the WASM build is
// `--target bundler` (no SystemTime::now() backing); not setting nowMs
// makes the Rust panic "time not implemented on this platform" when
// the verifier reaches into `SystemTime::now()` for caveat evaluation.
// Pin to a fixed timestamp: 2025-01-01T00:00:00Z (well before the
// FUTURE expiry caveat's @2099 cutoff).
const FIXED_NOW_MS = 1_735_689_600_000;

function ctx(overrides: Partial<Context> = {}): Context {
  return {
    nowMs: FIXED_NOW_MS,
    caller: "agent:planner",
    tool: "http.get",
    args: {},
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Angle 1 — Cross-cap substitution
// ---------------------------------------------------------------------------

describe("Angle 1 — Cross-cap substitution (read-only cap presented for a write call)", () => {
  it("a read-only cap (cap A) used in a context that requires cap B's write tool is denied at the caveat gate, NOT the chain gate", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    // Operator issues cap A (read-only http.get).
    const capA = Issuer.fromKey(ROOT_KEY)
      .issue("read-A")
      .caveat(`tool == "http.get"`)
      .caveat(FUTURE)
      .build();

    // Attacker captures cap A and tries to use it for a write call.
    // The verifier must deny — but at the caveat gate (tool != http.get),
    // not the chain gate. The chain is intact; the predicate just
    // doesn't hold.
    const r = verifier.verifyWithContext(
      capA,
      ctx({ tool: "http.post", args: { body: "evil" } }),
      auditor,
    );
    expect(r.outcome.kind).toBe("denied");
    if (r.outcome.kind === "denied") {
      expect(r.outcome.reason).toMatch(/tool/);
    }
  });

  it("attacker swaps cap A's caveats for cap B's caveats (keeping cap A's signature) — chain rejects", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const capA = Issuer.fromKey(ROOT_KEY).issue("read-A").caveat(`tool == "http.get"`).build();
    const capB = Issuer.fromKey(ROOT_KEY).issue("write-B").caveat(`tool == "http.post"`).build();

    const wireA = decodeToken(capA.serialize());
    const wireB = decodeToken(capB.serialize());

    // Splice B's caveats into A's wire format. A's signature was
    // computed for A's caveats — chain rejects.
    wireA.caveats = wireB.caveats;
    const frankenstein = Capability.parse(encodeToken(wireA));
    expect(() => verifier.verify(frankenstein)).toThrow(CapabilityChainError);
  });

  it("[FINDING] cap A's identifier can be SWAPPED to cap B's identifier with cap A's signature → chain rejects, BUT verifier returns a generic 'invalid signature' error that doesn't tell the operator whether identifier or caveats were tampered with", async () => {
    // This isn't a security-bypass finding — the chain still denies.
    // It's a *diagnostics* finding: when the verifier rejects a
    // tampered cap, the operator can't tell from the error message
    // whether the attacker mutated the identifier, dropped a caveat,
    // forged a signature, or swapped a caveat predicate. All four
    // produce the same generic "invalid signature" / "chain integrity"
    // throw. Forensics on a stolen cap is harder than it needs to be.
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const capA = Issuer.fromKey(ROOT_KEY).issue("read-A").caveat(`tool == "http.get"`).build();

    const wireA = decodeToken(capA.serialize());
    wireA.identifier = "write-B"; // attacker claims it's a different cap
    const tampered = Capability.parse(encodeToken(wireA));

    let caught: unknown;
    try {
      verifier.verify(tampered);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CapabilityChainError);
    // The error message is opaque about which field was changed.
    const msg = (caught as Error).message.toLowerCase();
    expect(msg).toMatch(/signature|chain|integrity/);
    // No mention of "identifier" or "caveat" in the diagnostic — the
    // root finding: an operator can't tell the two apart from the
    // public error surface.
    expect(msg).not.toMatch(/identifier|caveat/);
  });
});

// ---------------------------------------------------------------------------
// Angle 2 — Deep attenuation chain
// ---------------------------------------------------------------------------

describe("Angle 2 — Deep attenuation chain (100-deep) still verifies", () => {
  it("a cap attenuated 100 times still verifies and reports all 100 caveats", async () => {
    await init();
    let cap = Issuer.fromKey(ROOT_KEY).issue("deep").caveat(FUTURE).build();
    const N = 100;
    for (let i = 0; i < N; i++) {
      cap = cap.attenuate(`tag.depth_${i} == "ok"`);
    }
    const verifier = new Verifier(ROOT_KEY);

    // Chain check holds.
    expect(() => verifier.verify(cap)).not.toThrow();

    // Caveats survive the round-trip (1 base + 100 attenuated = 101).
    const wire = decodeToken(cap.serialize());
    expect(wire.caveats.length).toBe(N + 1);
  });

  it("100-deep verify completes well under 500ms (latency sanity-check)", async () => {
    await init();
    let cap = Issuer.fromKey(ROOT_KEY).issue("deep-perf").caveat(FUTURE).build();
    for (let i = 0; i < 100; i++) {
      cap = cap.attenuate(`tag.k_${i} == "v"`);
    }
    const verifier = new Verifier(ROOT_KEY);
    const start = performance.now();
    for (let i = 0; i < 50; i++) {
      verifier.verify(cap);
    }
    const elapsed = performance.now() - start;
    // 50 verifies of a 101-caveat cap should be well under 500ms even
    // on slow CI. We're not asserting a tight perf bound, just a "no
    // pathological blow-up" sanity check.
    expect(elapsed).toBeLessThan(500);
  });
});

// ---------------------------------------------------------------------------
// Angle 3 — Same caveat applied twice
// ---------------------------------------------------------------------------

describe("Angle 3 — Same caveat applied twice — no dedupe in serialized form", () => {
  it("[FINDING] attenuating with the same predicate twice produces a cap with TWO copies of the predicate; serialized form does not dedupe", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("dup")
      .caveat(FUTURE)
      .build()
      .attenuate(`caller == "agent:planner"`)
      .attenuate(`caller == "agent:planner"`);

    const wire = decodeToken(cap.serialize());
    // 1 base (FUTURE) + 2 identical attenuations = 3 entries.
    // [FINDING]: serialization keeps both. Storage cost grows linearly
    // with redundant attenuations, and the audit receipt records both
    // copies (slightly noisy audit trail). This is *consistent with
    // the macaroon model* (caveats are an ordered list, not a set) but
    // is a foot-gun for operators who attenuate defensively in a loop
    // and assume the runtime will collapse duplicates.
    expect(wire.caveats.length).toBe(3);
    expect(wire.caveats[1]).toEqual({ predicate: `caller == "agent:planner"` });
    expect(wire.caveats[2]).toEqual({ predicate: `caller == "agent:planner"` });

    // Verify still passes (both predicates evaluate true).
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    const r = verifier.verifyWithContext(cap, ctx({ caller: "agent:planner" }), auditor);
    expect(r.outcome.kind).toBe("allowed");
    expect(r.caveats.length).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Angle 4 — Conflicting caveats (cap permits NOTHING)
// ---------------------------------------------------------------------------

describe("Angle 4 — Conflicting caveats produce a useless cap", () => {
  it("[FINDING] attenuate('arg.amount <= 50').attenuate('arg.amount > 100') is a USELESS cap (denies every call) — no API surface warns about this at attenuation time", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("contradiction")
      .caveat(FUTURE)
      .build()
      .attenuate("arg.amount <= 50")
      .attenuate("arg.amount > 100");

    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    // Every amount fails. The chain is intact; both caveats can never
    // hold simultaneously.
    for (const amount of [10, 50, 75, 100, 200, 1_000_000]) {
      const r = verifier.verifyWithContext(cap, ctx({ args: { amount } }), auditor);
      expect(r.outcome.kind).toBe("denied");
    }

    // [FINDING]: this is the intended "useless cap" semantics
    // (attenuation is monotone — narrower caveats never broaden), but
    // the API offers no static / runtime warning. An operator who
    // accidentally writes attenuate("amount > 100") instead of
    // attenuate("amount <= 100") gets a cap that silently denies
    // every call. The receipt's denial reason names ONE of the two
    // conflicting caveats, not the conflict itself.
  });

  it("conflicting caveats stack with the chain still intact (verify chain check passes)", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("contradiction-chain")
      .caveat("arg.amount <= 50")
      .build()
      .attenuate("arg.amount > 100");
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(cap)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Angle 5 — Hok cap attenuated keeps its hok binding
// ---------------------------------------------------------------------------

describe("Angle 5 — Hok cap attenuated still requires verify_with_proof (hok binding survives)", () => {
  it("an attenuated hok cap STILL surfaces holderOfKey on the public getter", async () => {
    await init();
    // Use a real ed25519 keypair so the hok bytes are well-formed.
    // We don't actually verify the proof in this test — angle 5 is
    // about hok survival across attenuation, not the proof gate.
    const PUB = new Uint8Array(32).fill(0x77);
    const root = Issuer.fromKey(ROOT_KEY).issue("hok-root").holderOfKey(PUB).caveat(FUTURE).build();

    expect(root.holderOfKey).toEqual(PUB);

    const narrowed = root.attenuate("arg.amount <= 50");
    expect(narrowed.holderOfKey).toEqual(PUB);

    // Triple-attenuate.
    const tripleNarrowed = narrowed.attenuate(`tool == "x"`).attenuate(`caller == "y"`);
    expect(tripleNarrowed.holderOfKey).toEqual(PUB);
  });

  it("attempting to use an attenuated hok cap via verifyWithContext (no proof) is denied with a hok-specific reason", async () => {
    await init();
    const PUB = new Uint8Array(32).fill(0x77);
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("hok-attenuated")
      .holderOfKey(PUB)
      .caveat(FUTURE)
      .build()
      .attenuate("arg.amount <= 50");

    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    // The chain still walks (hok binding intact). Caveat evaluation
    // never runs — the verifier short-circuits on "this is hok-bound,
    // use verify_with_proof". The denial reason is hok-specific so
    // the holder can react.
    const r = verifier.verifyWithContext(cap, ctx({ args: { amount: 10 } }), auditor);
    expect(r.outcome.kind).toBe("denied");
    if (r.outcome.kind === "denied") {
      expect(r.outcome.reason).toMatch(/holder|hok|proof/i);
    }
  });

  it("attacker who STRIPS the hok field from the wire format triggers chain rejection", async () => {
    // The hok bytes are folded into the HMAC chain (issuer.rs §5).
    // Removing them from the serialized cap invalidates the signature.
    // This is the load-bearing property: attenuation cannot drop hok
    // because the chain wouldn't match if it did.
    await init();
    const PUB = new Uint8Array(32).fill(0x88);
    const cap = Issuer.fromKey(ROOT_KEY).issue("hok-strip").holderOfKey(PUB).caveat(FUTURE).build();

    const wire = decodeToken(cap.serialize());
    expect(wire.holder_of_key).toBeDefined();

    // Strip the hok field — pretend this is a non-hok cap so the
    // verifier doesn't require a proof. We rebuild without
    // `holder_of_key` rather than using `delete` (biome flags `delete`
    // as suspicious; we want a clean rebuild anyway because the field
    // was optional in the wire schema).
    const stripped = Capability.parse(
      encodeToken({
        identifier: wire.identifier,
        caveats: wire.caveats,
        signature: wire.signature,
      }),
    );

    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(stripped)).toThrow(CapabilityChainError);
  });
});

// ---------------------------------------------------------------------------
// Angle 6 — Multi-cap parallel verify
// ---------------------------------------------------------------------------

describe("Angle 6 — Single Verifier instance handles 100 concurrent verifies with no state leak", () => {
  it("100 concurrent verify calls with distinct caps each return the right per-cap outcome", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    // Mint 100 distinct caps, each with a unique caller-equality caveat.
    // Verifying each against its OWN context returns Allowed; verifying
    // it against a DIFFERENT cap's context returns Denied with the
    // caveat-failure reason. State leakage would manifest as a cap
    // accepted under the wrong context.
    const caps: Capability[] = [];
    for (let i = 0; i < 100; i++) {
      caps.push(
        Issuer.fromKey(ROOT_KEY)
          .issue(`cap-${i}`)
          .caveat(`caller == "agent:${i}"`)
          .caveat(FUTURE)
          .build(),
      );
    }

    // Fan out 100 verify calls in parallel via Promise.all. Even though
    // the WASM/Rust core is synchronous, the v8 micro-task queue
    // interleaves the awaits — if any state were shared between calls,
    // the wrong context could leak.
    const results = await Promise.all(
      caps.map(async (cap, i) => {
        return verifier.verifyWithContext(cap, ctx({ caller: `agent:${i}` }), auditor);
      }),
    );
    for (const r of results) {
      expect(r.outcome.kind).toBe("allowed");
    }
  });

  it("100 concurrent verifies with MIXED valid/invalid contexts route each cap to its correct outcome", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    const caps: Capability[] = [];
    for (let i = 0; i < 100; i++) {
      caps.push(
        Issuer.fromKey(ROOT_KEY)
          .issue(`mixed-${i}`)
          .caveat(`caller == "agent:${i}"`)
          .caveat(FUTURE)
          .build(),
      );
    }

    // Even-indexed caps get the correct caller; odd-indexed get a
    // mismatched caller. After Promise.all, even = Allowed, odd = Denied.
    const results = await Promise.all(
      caps.map(async (cap, i) => {
        const correct = i % 2 === 0;
        return verifier.verifyWithContext(
          cap,
          ctx({ caller: correct ? `agent:${i}` : `agent:${i + 1}` }),
          auditor,
        );
      }),
    );
    for (let i = 0; i < results.length; i++) {
      const expected = i % 2 === 0 ? "allowed" : "denied";
      expect(results[i]?.outcome.kind).toBe(expected);
    }
  });
});

// ---------------------------------------------------------------------------
// Angle 7 — Mutating a cap after handing it to a wrap-style call
// ---------------------------------------------------------------------------

describe("Angle 7 — Capability is immutable from JS; mutating the wire-form object after parse does not affect a previously-verified handle", () => {
  it("the public Capability surface exposes no mutation API — caveats and signature are private", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY).issue("immut").caveat(FUTURE).build();

    // Public surface: identifier (getter), holderOfKey (getter),
    // serialize, attenuate, parse (static). No setters; no public
    // caveats / signature field.
    type CapKeys = keyof Capability;
    const publicKeys = Object.getOwnPropertyNames(Object.getPrototypeOf(cap)) as readonly (
      | CapKeys
      | "constructor"
    )[];

    // No "caveats" / "signature" property on the public class.
    const exposedNames = new Set<string>(publicKeys);
    expect(exposedNames.has("caveats")).toBe(false);
    expect(exposedNames.has("signature")).toBe(false);

    // The internal `_inner` is reachable but documented as @internal —
    // mutating it would still go through wasm-bindgen's accessor layer
    // (caveats live inside the Rust struct behind `#[wasm_bindgen]`),
    // so no JS-side mutation can rewrite the chain.
    expect("_inner" in cap).toBe(true);
  });

  it("[FINDING] decoding the wire-format JSON, mutating the array, and RE-PARSING produces a new cap; the verifier rejects the tamper. BUT a wrap-style helper that re-serializes the cap before calling verifyWithContext could mask the tamper if the helper used object-spread incorrectly", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("wire-tamper")
      .caveat(`tool == "http.get"`)
      .caveat(FUTURE)
      .build();

    // Decode → mutate → re-parse. This is what an attacker (or buggy
    // middleware) does on the wire.
    const wire = decodeToken(cap.serialize());
    wire.caveats = wire.caveats.filter((c) => !c.predicate.startsWith("tool"));
    const tampered = Capability.parse(encodeToken(wire));

    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(tampered)).toThrow(CapabilityChainError);

    // [FINDING]: the original `cap` object was unaffected by the wire
    // tamper — the wrapper holds an opaque Rust handle. So a wrap-style
    // helper that captures the cap by reference (the documented
    // wrapMCPClient pattern) is safe from JS-side mutation. The risk
    // surface is in helpers that *re-serialize* the cap for transport
    // and don't pin the wire bytes — those would be susceptible to
    // mid-flight tampering. The verifier would still reject; the
    // foot-gun is making the operator wonder why their cap stopped
    // working after they "just refactored the cap-passing code".
    const reverify = new Verifier(ROOT_KEY);
    expect(() => reverify.verify(cap)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Angle 8 — Issuer reuse across multiple issuances
// ---------------------------------------------------------------------------

describe("Angle 8 — Issuer reuse across multiple issuances is leak-free", () => {
  it("calling issue() twice on the same Issuer produces two independent caps", async () => {
    await init();
    const issuer = Issuer.fromKey(ROOT_KEY);
    const capA = issuer.issue("cap-a").caveat(`tool == "http.get"`).caveat(FUTURE).build();
    const capB = issuer.issue("cap-b").caveat(`tool == "http.post"`).caveat(FUTURE).build();

    // Different identifiers and different caveats.
    expect(capA.identifier).toBe("cap-a");
    expect(capB.identifier).toBe("cap-b");

    const wireA = decodeToken(capA.serialize());
    const wireB = decodeToken(capB.serialize());
    expect(wireA.caveats[0]?.predicate).toBe(`tool == "http.get"`);
    expect(wireB.caveats[0]?.predicate).toBe(`tool == "http.post"`);

    // Different signatures (would be a serious bug if equal).
    expect(wireA.signature).not.toBe(wireB.signature);

    // Both verify cleanly.
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(capA)).not.toThrow();
    expect(() => verifier.verify(capB)).not.toThrow();
  });

  it("interleaving partial builders does NOT leak caveats between them", async () => {
    await init();
    const issuer = Issuer.fromKey(ROOT_KEY);

    // Start two builders. Add a caveat to A, then B, then A, then B,
    // then build both. Builder state must be per-builder, not on the
    // Issuer.
    const builderA = issuer.issue("inter-A");
    const builderB = issuer.issue("inter-B");

    const a1 = builderA.caveat("arg.x == 1");
    const b1 = builderB.caveat("arg.x == 2");
    const a2 = a1.caveat(FUTURE);
    const b2 = b1.caveat(FUTURE);

    const capA = a2.build();
    const capB = b2.build();

    const wireA = decodeToken(capA.serialize());
    const wireB = decodeToken(capB.serialize());

    expect(wireA.caveats.map((c) => c.predicate)).toEqual(["arg.x == 1", FUTURE]);
    expect(wireB.caveats.map((c) => c.predicate)).toEqual(["arg.x == 2", FUTURE]);

    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(capA)).not.toThrow();
    expect(() => verifier.verify(capB)).not.toThrow();
  });

  it("100 issuances from one Issuer all verify and all have distinct signatures", async () => {
    await init();
    const issuer = Issuer.fromKey(ROOT_KEY);
    const verifier = new Verifier(ROOT_KEY);
    const seenSigs = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const cap = issuer.issue(`bulk-${i}`).caveat(FUTURE).build();
      expect(() => verifier.verify(cap)).not.toThrow();
      const wire = decodeToken(cap.serialize());
      expect(seenSigs.has(wire.signature)).toBe(false);
      seenSigs.add(wire.signature);
    }
    expect(seenSigs.size).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Angle 9 — Empty-caveat cap (the "naked" cap)
// ---------------------------------------------------------------------------

describe("Angle 9 — Empty-caveat cap (naked cap) verifies and matches every Context", () => {
  it("[FINDING] Issuer.issue('naked').build() with NO caveats is a valid cap that ALLOWS every call — operator foot-gun if they forget to add caveats", async () => {
    await init();
    const naked = Issuer.fromKey(ROOT_KEY).issue("naked").build();

    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    // Chain check passes (it's a legitimately-issued cap).
    expect(() => verifier.verify(naked)).not.toThrow();

    // Every context is allowed — there are no caveats to fail.
    const callers = ["agent:planner", "agent:rogue", "anyone-at-all", ""];
    const tools = ["http.get", "http.post", "shell.exec", "anything"];
    for (const caller of callers) {
      for (const tool of tools) {
        const r = verifier.verifyWithContext(
          naked,
          ctx({ caller, tool, args: { whatever: true } }),
          auditor,
        );
        expect(r.outcome.kind).toBe("allowed");
      }
    }

    // [FINDING]: a cap with no caveats is the "god mode" of capnagent.
    // The chain is intact, so every verify passes. The wire form is
    // smaller than a normal cap (no caveats array), which makes a
    // reviewer skim past it. There is NO API-level enforcement of
    // "every cap must have at least one caveat" or "every cap must
    // have an expiry caveat". An operator who calls `.build()` before
    // adding `.caveat(FUTURE)` ships a cap that never expires AND
    // permits every call. This is the #1 highest-impact composition
    // foot-gun in the surface.
    const wire = decodeToken(naked.serialize());
    expect(wire.caveats).toEqual([]);
  });

  it("a defensively-attenuated naked cap denies what its attenuations forbid; a SEPARATELY-held naked cap (no attenuations) still permits everything", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    // Defensive holder narrows their copy.
    const narrowed = Issuer.fromKey(ROOT_KEY)
      .issue("naked-attn")
      .build()
      .attenuate(`tool == "http.get"`)
      .attenuate(FUTURE);

    const allowed = verifier.verifyWithContext(narrowed, ctx({ tool: "http.get" }), auditor);
    expect(allowed.outcome.kind).toBe("allowed");
    const denied = verifier.verifyWithContext(narrowed, ctx({ tool: "http.post" }), auditor);
    expect(denied.outcome.kind).toBe("denied");

    // BUT — a SECOND, never-attenuated copy held by a less-defensive
    // attacker is still god-mode. Attenuation is opt-in; capnagent
    // does not retroactively constrain copies of the parent.
    const reckless = Issuer.fromKey(ROOT_KEY).issue("naked-attn").build();
    const recklessR = verifier.verifyWithContext(reckless, ctx({ tool: "shell.exec" }), auditor);
    expect(recklessR.outcome.kind).toBe("allowed");
  });

  it("[FINDING] Capability.attenuate(...) on the JS wrapper CONSUMES the receiver — using the original handle after attenuation throws 'null pointer passed to rust' instead of a typed CapabilityError; this is a wasm-bindgen ownership leak in the public TS surface", async () => {
    // Reproducer: a single cap reference, attenuated once, then the
    // ORIGINAL handle is reused. The Rust `attenuate(self, ...)`
    // consumes the inner; the JS wrapper does not zero the handle and
    // does not advertise this in its `attenuate(...)` JSDoc, so an
    // operator who writes the obvious-looking
    //
    //     const narrowed = cap.attenuate(predicate);
    //     verifier.verify(cap);  // uses ORIGINAL — boom
    //
    // gets a confusing wasm-bindgen panic ("null pointer passed to
    // rust") instead of a typed CapabilityError telling them they
    // re-used a consumed handle.
    //
    // This is the most likely composition foot-gun a real operator
    // hits in practice — the API LOOKS immutable (returns a new
    // Capability) but is actually consuming. The native Rust API has
    // the same shape but Rust's borrow checker prevents the misuse at
    // compile time; the TS surface erases that protection.
    await init();
    const cap = Issuer.fromKey(ROOT_KEY).issue("foot-gun").caveat(FUTURE).build();

    // First use: success.
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(cap)).not.toThrow();

    // Attenuate. The wrapper returns a brand-new Capability instance
    // for the NARROWER cap, but it has silently consumed the original.
    const narrowed = cap.attenuate(`tool == "http.get"`);
    expect(() => verifier.verify(narrowed)).not.toThrow();

    // Reuse the ORIGINAL handle — this is what an operator would do
    // if they thought attenuate was a pure function. The error that
    // surfaces is "null pointer passed to rust" — opaque, not a
    // typed CapabilityError, no hint that the cap was consumed.
    let caught: unknown;
    try {
      verifier.verify(cap);
    } catch (e) {
      caught = e;
    }
    // [FINDING]: the throw type IS CapabilityChainError (because
    // wasm-bindgen errors that reach mapWasmError default to chain),
    // BUT the message is the wasm-bindgen-internal
    // "null pointer passed to rust" — neither helpful for operators
    // nor distinguishable from a real chain failure.
    expect(caught).toBeInstanceOf(Error);
    const msg = (caught as Error).message.toLowerCase();
    expect(msg).toMatch(/null pointer|passed to rust/);
  });
});

// ---------------------------------------------------------------------------
// Angle X (bonus) — Caveat-list ordering matters at the chain level
// ---------------------------------------------------------------------------

describe("Angle X (bonus) — Reordering caveats invalidates the chain even if the SET of caveats is unchanged", () => {
  it("swapping the order of two caveats in the wire format → chain rejects (ordering is part of the signature)", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("ord")
      .caveat(`tool == "http.get"`)
      .caveat("arg.amount <= 50")
      .caveat(FUTURE)
      .build();

    const wire = decodeToken(cap.serialize());
    // Swap caveat[0] and caveat[1] — the SET is unchanged, but order
    // is part of the chain.
    const reordered = {
      ...wire,
      caveats: [wire.caveats[1], wire.caveats[0], wire.caveats[2]] as Array<{
        predicate: string;
      }>,
    };
    const tampered = Capability.parse(encodeToken(reordered as SerializedCap));
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(tampered)).toThrow(CapabilityChainError);
  });
});
