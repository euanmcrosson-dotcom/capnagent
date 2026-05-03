/**
 * Purple-team PoC for `docs/purple-team/13-subagent-scope-drift.md`.
 *
 * Round 13 fires the `caveat ✗` gate column on a delegated-capability
 * scope-drift attempt, plus the `chain ✗` column on a forge-broader
 * variant. The structural defense: a planner agent holds a broad
 * capability and delegates work to an executor sub-agent by issuing
 * the executor a STRICTLY ATTENUATED cap. capnagent's HMAC-chain
 * macaroon construction mathematically guarantees that nobody — not
 * even the planner — can broaden the executor's cap without the root
 * key. The property test in `crates/capnagent-core/tests/property_tests.rs`
 * proves the math holds for arbitrary inputs; this round shows it
 * end-to-end across a realistic planner-→-executor workflow.
 *
 * # Threat model (one paragraph)
 *
 * A planner agent has a broad shopping capability ("buy at amazon.com,
 * up to $200"). It needs to delegate the actual purchase step to an
 * executor sub-agent. The executor MUST hold a tighter cap — say,
 * up to $50 — because the planner cannot fully trust an executor it
 * spun up from a fresh prompt or pulled from a different vendor's
 * sub-agent registry. The threat is "scope drift": the executor (or
 * an attacker who has compromised it via prompt injection) tries to
 * use more authority than it was delegated. Three concrete drift
 * vectors: (1) presents the executor's narrow cap and asks for the
 * out-of-scope action; (2) hand-mutates the serialized executor cap
 * to relax a caveat; (3) tries to round-trip the executor cap back
 * up to the planner's broader scope by stripping the attenuation
 * caveat. capnagent denies all three at distinct gates.
 *
 * # API note: `Capability.attenuate(...)` is consuming
 *
 * The WASM-bound `attenuate(self, predicate)` (Rust ownership) means
 * the returned cap is the only valid handle after the call; the
 * original wrapper's `_inner` is left dangling and any subsequent
 * use of the original `Capability` instance throws "null pointer
 * passed to rust". The test discipline this round adopts: ALWAYS
 * mint a fresh planner cap when we need both layers; never share a
 * Capability instance across an attenuate() and a subsequent
 * verify(). Operators delegating to executors should follow the
 * same rule — issue once, attenuate immediately for the executor,
 * and keep the planner cap as a separate freshly-issued instance.
 * (`docs/purple-team/13-subagent-scope-drift.md` calls this out as
 * a defender-actionable.)
 *
 * # Why this test bypasses the wrapper
 *
 * `wrapMCPClient` runs one verifier per tool call against one cap;
 * the planner-→-executor delegation is conceptual at this layer (a
 * single process holds both caps and uses whichever applies to the
 * call it is making). We model both roles in-process: the test code
 * builds the planner's cap, derives the executor's narrower cap via
 * `cap.attenuate(...)`, then pretends to be the executor making
 * tool calls. Cross-process delegation (executor in a separate JVM
 * holding only the serialized executor cap) is structurally
 * identical — capnagent's verify is a pure function of (cap, ctx,
 * key) — and is documented as not-yet-tested in the round writeup.
 *
 * # What the test does NOT cover (cross-reference round doc)
 *
 *   - Distributed delegation across processes / hosts. The verifier
 *     is a pure function of (cap, ctx, root_key); the in-process
 *     model is sound. Cross-process is a wiring exercise.
 *   - Revocation propagation from planner to executor. capnagent's
 *     revocation is by-identifier, and attenuation does NOT change
 *     the identifier — so revoking the planner's identifier WILL
 *     also revoke every attenuated descendant. There is no API
 *     today to revoke selectively by chain depth. Documented as
 *     out of scope here; flagged for a future round.
 *   - Operator passing the SAME cap to executor instead of
 *     attenuating. CAPABILITY-CONFIG class — out of scope here;
 *     covered in the round 01-style cap-tightness rounds.
 *   - Operator giving the executor the root key. OUT-OF-SCOPE: any
 *     defense that depends on a secret key fails when the key is
 *     given to the attacker.
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

const ROOT_KEY = new Uint8Array(32).fill(0xd1);
const AUDIT_KEY = new Uint8Array(32).fill(0xd2);

interface SerializedCap {
  identifier: string;
  holder_of_key?: string;
  caveats: Array<{ predicate: string }>;
  signature: string;
}

/** Decode the base64url-JSON wire format produced by `cap.serialize()`. */
function decodeToken(token: string): SerializedCap {
  const json = Buffer.from(token, "base64url").toString("utf8");
  return JSON.parse(json) as SerializedCap;
}

/** Re-encode a wire-format object back into a base64url-JSON token string. */
function encodeToken(obj: SerializedCap): string {
  const json = JSON.stringify(obj);
  return Buffer.from(json, "utf8").toString("base64url");
}

/**
 * Mint a fresh planner cap. Mints inline so each test gets a fresh
 * Capability instance — `attenuate` consumes its input, so sharing
 * an instance across `verify()` and `attenuate()` triggers the
 * null-pointer-passed-to-rust failure. See top-of-file docblock.
 */
async function issuePlannerCap(): Promise<Capability> {
  await init();
  return Issuer.fromKey(ROOT_KEY)
    .issue("shop-planner")
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 200")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

/**
 * Issue an executor cap by attenuating a freshly-minted planner cap.
 * Returns ONLY the executor cap — the planner-cap input is consumed.
 * Callers that want both should call `issuePlannerPair()` instead.
 */
async function issueExecutorCap(): Promise<Capability> {
  const plannerCap = await issuePlannerCap();
  return plannerCap.attenuate("arg.amount <= 50");
}

/**
 * Mint a planner cap AND an executor cap derived from a sibling
 * planner cap. Both caps share the same identifier and root-signed
 * caveat list (the executor just has one extra caveat appended).
 * Both are valid Capability instances usable independently.
 */
async function issuePlannerPair(): Promise<{ planner: Capability; executor: Capability }> {
  const planner = await issuePlannerCap();
  // We need a SECOND planner cap to attenuate without consuming the
  // first one. Macaroon issuance is deterministic over (root_key,
  // identifier, caveat list), so the second instance has the same
  // signature as the first — they're indistinguishable on the wire.
  const plannerForAttenuation = await issuePlannerCap();
  const executor = plannerForAttenuation.attenuate("arg.amount <= 50");
  return { planner, executor };
}

describe("Round 13: Sub-agent / delegated-capability scope drift", () => {
  describe("structural defense (HMAC-chain attenuation, no-broaden invariant)", () => {
    it("the planner cap verifies cleanly under the root key (sanity)", async () => {
      const plannerCap = await issuePlannerCap();
      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(plannerCap)).not.toThrow();
    });

    it("the attenuated executor cap verifies cleanly under the root key (delegation works)", async () => {
      const executorCap = await issueExecutorCap();
      const verifier = new Verifier(ROOT_KEY);

      // Macaroon contract: any holder can append a caveat without root
      // access; the appended caveat is folded into the signature via
      // HMAC(prev_sig, new_caveat). The verifier walks the full chain
      // under the root key and accepts.
      expect(() => verifier.verify(executorCap)).not.toThrow();

      // Inspect the wire format: the executor cap has the planner's
      // 5 caveats plus 1 attenuation caveat appended.
      const executorWire = decodeToken(executorCap.serialize());
      expect(executorWire.caveats.length).toBe(6);
      expect(executorWire.caveats[5]?.predicate).toBe("arg.amount <= 50");
      expect(executorWire.identifier).toBe("shop-planner");
    });

    it("CLAIM 1 — in-scope executor call is ALLOWED (defense doesn't over-tighten)", async () => {
      // Positive hypothesis: the executor's narrower cap PERMITS its
      // legitimate in-scope action. A defense that denies everything
      // is not the win condition.
      const executorCap = await issueExecutorCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      const ctx: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 30 },
        nowMs: 1_700_000_000_000,
      };

      const r = verifier.verifyWithContext(executorCap, ctx, auditor);
      expect(r.outcome.kind).toBe("allowed");
    });

    it("CLAIM 2 — a planner-broad action ($150) presented under the EXECUTOR cap is DENIED", async () => {
      // Positive hypothesis (the no-broaden property, end-to-end):
      // the executor's narrower cap (amount <= 50) DENIES an action
      // that would be in-scope for the broader planner cap (amount <=
      // 200) but is out-of-scope for the executor. This is the whole
      // point of attenuation — the executor cannot exceed its
      // delegated authority.
      const { planner, executor } = await issuePlannerPair();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      // $150 is fine under the planner cap (200), but the executor
      // cap added `amount <= 50` — denied at caveat eval.
      const ctx: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 150 },
        nowMs: 1_700_000_000_000,
      };

      const r = verifier.verifyWithContext(executor, ctx, auditor);
      expect(r.outcome.kind).toBe("denied");
      if (r.outcome.kind === "denied") {
        // The denial reason names the failed caveat. We don't pin the
        // exact string (the engine controls its own deny-reason
        // format) but we assert it references the amount caveat that
        // the attenuation added — proving the attenuation caveat is
        // what fired, not some other gate.
        expect(r.outcome.reason).toMatch(/amount/);
      }

      // Sanity: the SAME context, presented under the planner cap,
      // is allowed — confirming the denial is genuinely about the
      // attenuation, not about the context being malformed.
      const rPlanner = verifier.verifyWithContext(planner, ctx, auditor);
      expect(rPlanner.outcome.kind).toBe("allowed");
    });

    it("CLAIM 3 — fabricating a broader cap from the executor cap WITHOUT the root key fails chain verification", async () => {
      // Positive hypothesis (cryptographic invariant): the attacker
      // holds a legitimately-issued narrow executor cap and tries to
      // forge a broader version by hand-mutating the serialized
      // bytes. Without the root key, every attempt fails at the
      // chain-integrity gate (CapabilityChainError) — BEFORE any
      // caveat evaluation, audit signing, or context inspection.
      //
      // We test three drift vectors:
      //   (a) DROP the attenuation caveat (try to revert the
      //       executor cap to the planner cap's authority).
      //   (b) MUTATE the attenuation caveat's predicate to a wider
      //       bound (50 → 500).
      //   (c) SPLICE the planner cap's signature onto the
      //       executor's structure (try to claim "this narrower
      //       cap was signed at the planner's stage").
      const { planner, executor } = await issuePlannerPair();
      const verifier = new Verifier(ROOT_KEY);

      const executorWire = decodeToken(executor.serialize());
      const plannerWire = decodeToken(planner.serialize());

      // (a) Drop the appended attenuation caveat. Result has the
      // planner's caveat list but the executor's signature — chain
      // does not verify under the root key.
      const droppedWire: SerializedCap = {
        ...executorWire,
        caveats: executorWire.caveats.slice(0, -1),
      };
      const droppedCap = Capability.parse(encodeToken(droppedWire));
      expect(() => verifier.verify(droppedCap)).toThrow(CapabilityChainError);

      // (b) Mutate the attenuation caveat to a wider bound.
      const mutatedWire: SerializedCap = {
        ...executorWire,
        caveats: executorWire.caveats.map((c, i) =>
          i === executorWire.caveats.length - 1 ? { predicate: "arg.amount <= 500" } : c,
        ),
      };
      const mutatedCap = Capability.parse(encodeToken(mutatedWire));
      expect(() => verifier.verify(mutatedCap)).toThrow(CapabilityChainError);

      // (c) Splice the planner cap's signature onto the executor's
      // (now-wider) caveat list. The attacker is trying to claim
      // "this 6-caveat cap was signed at the planner's 5-caveat
      // stage" — which is structurally impossible because the chain
      // signature commits to the FULL caveat list at each stage.
      const splicedWire: SerializedCap = {
        ...executorWire,
        signature: plannerWire.signature,
      };
      const splicedCap = Capability.parse(encodeToken(splicedWire));
      expect(() => verifier.verify(splicedCap)).toThrow(CapabilityChainError);
    });
  });

  describe("nested attenuation (planner → executor → sub-executor)", () => {
    it("each step strictly narrows; the deepest cap is bounded by the tightest caveat at any layer", async () => {
      // Realistic multi-layer delegation: the planner spawns an
      // executor for "amazon.com up to $50", which in turn spawns
      // a sub-executor (e.g. a tool-specific worker) for "amazon.com
      // up to $20". Each attenuation appends one caveat; each cap
      // independently verifies under the root key; each cap is
      // tighter than its parent on the relevant predicate.
      //
      // We mint each layer as a fresh chain because attenuate
      // consumes its input — see the API-note docblock at top of
      // file. Determinism guarantees the wire bytes match what a
      // real planner-→-executor-→-sub-executor delegation would
      // produce.
      const planner = await issuePlannerCap();
      const executor = (await issuePlannerCap()).attenuate("arg.amount <= 50");
      const subExecutor = (await issuePlannerCap())
        .attenuate("arg.amount <= 50")
        .attenuate("arg.amount <= 20");
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      // All three layers verify cleanly under the root key. Note:
      // we re-mint everything fresh after the wire-only inspections
      // below to avoid handle invalidation.
      expect(() => verifier.verify(planner)).not.toThrow();
      expect(() => verifier.verify(executor)).not.toThrow();
      expect(() => verifier.verify(subExecutor)).not.toThrow();

      // $15 — in scope for all three layers. ALLOWED under each.
      const ctxLow: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 15 },
        nowMs: 1_700_000_000_000,
      };
      // Re-mint per-cap because verifyWithContext takes the cap by
      // reference but the WASM handle's lifetime is tied to its
      // wrapper; we want to be defensive about handle reuse.
      const p1 = await issuePlannerCap();
      const e1 = (await issuePlannerCap()).attenuate("arg.amount <= 50");
      const s1 = (await issuePlannerCap())
        .attenuate("arg.amount <= 50")
        .attenuate("arg.amount <= 20");
      expect(verifier.verifyWithContext(p1, ctxLow, auditor).outcome.kind).toBe("allowed");
      expect(verifier.verifyWithContext(e1, ctxLow, auditor).outcome.kind).toBe("allowed");
      expect(verifier.verifyWithContext(s1, ctxLow, auditor).outcome.kind).toBe("allowed");

      // $30 — in scope for planner & executor, OUT of scope for
      // sub-executor. ALLOWED under the first two, DENIED under
      // the deepest.
      const ctxMid: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 30 },
        nowMs: 1_700_000_000_000,
      };
      const p2 = await issuePlannerCap();
      const e2 = (await issuePlannerCap()).attenuate("arg.amount <= 50");
      const s2 = (await issuePlannerCap())
        .attenuate("arg.amount <= 50")
        .attenuate("arg.amount <= 20");
      expect(verifier.verifyWithContext(p2, ctxMid, auditor).outcome.kind).toBe("allowed");
      expect(verifier.verifyWithContext(e2, ctxMid, auditor).outcome.kind).toBe("allowed");
      expect(verifier.verifyWithContext(s2, ctxMid, auditor).outcome.kind).toBe("denied");

      // $100 — in scope for planner only. ALLOWED under planner,
      // DENIED under the two attenuated layers.
      const ctxHigh: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 100 },
        nowMs: 1_700_000_000_000,
      };
      const p3 = await issuePlannerCap();
      const e3 = (await issuePlannerCap()).attenuate("arg.amount <= 50");
      const s3 = (await issuePlannerCap())
        .attenuate("arg.amount <= 50")
        .attenuate("arg.amount <= 20");
      expect(verifier.verifyWithContext(p3, ctxHigh, auditor).outcome.kind).toBe("allowed");
      expect(verifier.verifyWithContext(e3, ctxHigh, auditor).outcome.kind).toBe("denied");
      expect(verifier.verifyWithContext(s3, ctxHigh, auditor).outcome.kind).toBe("denied");
    });

    it("a sub-executor that tries to broaden back to the executor's scope fails chain verification", async () => {
      // Same logic as CLAIM 3, one layer deeper. The attacker holds
      // the sub-executor cap (amount <= 20) and tries to drop the
      // last attenuation to claim the executor's scope (<= 50).
      // Without the root key, the chain check rejects.
      const subExecutor = (await issuePlannerCap())
        .attenuate("arg.amount <= 50")
        .attenuate("arg.amount <= 20");
      const verifier = new Verifier(ROOT_KEY);

      const subWire = decodeToken(subExecutor.serialize());
      expect(subWire.caveats.length).toBe(7); // 5 planner + 2 attenuations
      expect(subWire.caveats[6]?.predicate).toBe("arg.amount <= 20");

      // Drop the deepest attenuation, leaving the executor's caveat
      // list with the sub-executor's signature — chain mismatch.
      const droppedWire: SerializedCap = {
        ...subWire,
        caveats: subWire.caveats.slice(0, -1),
      };
      const tampered = Capability.parse(encodeToken(droppedWire));
      expect(() => verifier.verify(tampered)).toThrow(CapabilityChainError);
    });
  });

  describe("audit trail", () => {
    it("a denied executor scope-drift call produces a signed denial receipt (auditable)", async () => {
      // Caveat denials (unlike chain failures) produce signed
      // receipts. This matters for the operator's audit pipeline:
      // when an executor is found drifting out of scope, ops needs
      // a signed record of which call was attempted and what the
      // denial reason was. Verifies the receipt round-trips through
      // Auditor.verify.
      const executorCap = await issueExecutorCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      const ctx: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 150 },
        nowMs: 1_700_000_000_000,
      };

      const r = verifier.verifyWithContext(executorCap, ctx, auditor);
      expect(r.outcome.kind).toBe("denied");
      expect(r.signature.length).toBeGreaterThan(0);
      expect(r.capabilityIdentifier).toBe("shop-planner");
      // The receipt's HMAC verifies under the audit key — ops can
      // ingest this into a tamper-evident audit log.
      expect(() => auditor.verify(r)).not.toThrow();
    });

    it("a chain-failure scope-drift attempt produces NO receipt (throws before audit signing)", async () => {
      // The deliberate asymmetry from rounds 03 and 11: chain
      // failures THROW with no receipt; only caveat-evaluation
      // denials produce signed receipts. A forged-broader cap
      // attempt fails at the chain leg, so no receipt — and no
      // legitimate audit trail to forge under.
      const executorCap = await issueExecutorCap();
      const verifier = new Verifier(ROOT_KEY);

      const wire = decodeToken(executorCap.serialize());
      const droppedWire: SerializedCap = {
        ...wire,
        caveats: wire.caveats.slice(0, -1),
      };
      const tampered = Capability.parse(encodeToken(droppedWire));

      // verify() returns void; a chain failure throws before any
      // receipt would be produced.
      expect(() => verifier.verify(tampered)).toThrow(CapabilityChainError);
    });
  });

  describe("residual risk (honest acknowledgment of what this defense does NOT cover)", () => {
    it("OPERATOR PASSES THE PLANNER CAP DIRECTLY TO THE EXECUTOR — defense fails because there is no attenuation to enforce", async () => {
      // CAPABILITY-CONFIG class: the operator wires the executor
      // sub-agent with the planner's broad cap instead of an
      // attenuated copy. capnagent has nothing to gate against —
      // the cap passes verify, the call is in-scope under the
      // planner cap. Documented residual risk; defender-actionable
      // is "always call .attenuate() before handing a cap to a
      // less-trusted holder."
      const plannerCap = await issuePlannerCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      // Executor (now wrongly holding the broad cap) makes a $150
      // call. Under the planner cap this is in-scope.
      const ctx: Context = {
        caller: "agent:planner",
        tool: "checkout.purchase",
        args: { merchant: "amazon.com", amount: 150 },
        nowMs: 1_700_000_000_000,
      };
      expect(verifier.verifyWithContext(plannerCap, ctx, auditor).outcome.kind).toBe("allowed");
    });

    it("OPERATOR LEAKS THE ROOT KEY TO THE EXECUTOR — defense fails because the executor can mint any cap it wants", async () => {
      // OUT-OF-SCOPE: any defense that depends on a secret key fails
      // when the key is given to the attacker. capnagent's
      // attenuation guarantees `nobody but a root-key holder can
      // broaden a cap`. If the executor holds the root key, the
      // executor IS a root-key holder — the structural property
      // remains true; the assumption broke.
      await init();
      const stolenKey = ROOT_KEY;
      const arbitraryCap = Issuer.fromKey(stolenKey)
        .issue("attacker-controlled")
        .caveat("arg.amount <= 9999999")
        .build();
      expect(() => new Verifier(ROOT_KEY).verify(arbitraryCap)).not.toThrow();
    });

    it("ATTENUATION DOES NOT MINT A NEW IDENTIFIER — revoking the planner cap also revokes every attenuated descendant", async () => {
      // Subtle but load-bearing for any future "selective
      // descendant revocation" feature: capnagent's revocation is
      // by-identifier, and `.attenuate()` does NOT change the
      // identifier. A planner cap with id "shop-planner" and any
      // executor / sub-executor derived from it all share that
      // single identifier — so revoking the planner identifier
      // revokes every descendant simultaneously. There is no API
      // to revoke just the planner cap and leave executor caps
      // alive (because there is no way to distinguish them by
      // identifier). Documented for the next round; not a defect.
      const plannerCap = await issuePlannerCap();
      const executorCap = await issueExecutorCap();
      expect(plannerCap.identifier).toBe(executorCap.identifier);
      expect(plannerCap.identifier).toBe("shop-planner");
    });
  });
});
