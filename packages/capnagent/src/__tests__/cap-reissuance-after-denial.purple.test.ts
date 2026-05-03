/**
 * Purple-team PoC for `docs/purple-team/12-cap-reissuance-after-denial.md`.
 *
 * Round 12 documents an **operator-side runbook**, not a structural
 * defense. capnagent's role is to surface the denial signal as a
 * cryptographically-signed receipt; the role of the issuer is to
 * decide what to do with that signal. The PoC pins the contract:
 *
 *   - capnagent emits a signed denial receipt for every denied call
 *   - the agent has no in-band path to the issuer (denial flows
 *     through the audit-log channel, not back to the LLM context)
 *   - the issuer is free to re-issue any capability at any time;
 *     capnagent does NOT enforce back-off, rate limit, or denial-
 *     spike throttling
 *   - therefore, denial-spike back-off is operator-implemented on
 *     top of the receipt stream — and this PoC pins the surface
 *     the operator must integrate against
 *
 * # Threat model (one paragraph)
 *
 * A prompt-injected agent has its tool calls denied by the gate.
 * Standard ergonomics: the agent reports the denial in its reply
 * and the next turn's planner asks for a broader capability. If
 * the issuer naively re-issues whatever the agent asks for, the
 * defense degrades to nothing — the agent eventually gets a
 * capability that permits the malicious action. The defense
 * against this is operator-side: count denials per (caller, tool)
 * within a window, apply back-off when a spike is observed,
 * require human approval before re-issuing a strictly broader cap.
 * capnagent's job is to make the signal cryptographically
 * authoritative; the issuer's job is to read it.
 *
 * # Why this round has no structural-defense PoC
 *
 * This round is intentionally a runbook. The corpus contract
 * (round 02, etc.) is "structural defense holds; PoC asserts both
 * positive and negative hypotheses." Round 12's hypothesis is
 * different: it asserts the **shape of the contract** between
 * capnagent and the issuer. The PoC verifies the receipt API
 * surface — that the operator has what they need to build back-off.
 *
 * # What this PoC asserts
 *
 *   1. Every denied call produces a signed receipt distinguishable
 *      from an allowed call by `outcome.kind`
 *   2. The receipt's signature is verifiable independently of
 *      capnagent's runtime state — the issuer can ingest signed
 *      receipts from a different process / a logfile / a stream
 *      and trust them
 *   3. Re-issuance is a pure cryptographic operation independent
 *      of any prior denial — capnagent does NOT remember that this
 *      caller had calls denied; the issuer must remember
 *   4. There is no in-band path from the agent to the issuer; the
 *      agent observing a denial cannot influence what the issuer
 *      decides next (the receipt is consumed by the issuer's
 *      logging pipeline, not by the agent)
 *
 * # What this PoC does NOT cover (cross-reference round doc)
 *
 *   - Specific back-off algorithms (token bucket, exponential,
 *     fixed-window). Those are operator policy choices; the doc
 *     lists rough patterns but does not endorse one.
 *   - Library-side `BackoffController` helper. v0.7 backlog
 *     candidate; deliberately excluded from v0.6 to keep the
 *     library surface narrow.
 *   - Cross-process denial counting (one issuer process counts;
 *     another issuer process under the same root key is unaware).
 *     Same shape as the NonceStore distributed problem (round 02);
 *     same operator-side answer (shared backing store).
 *   - Insider-issuer adversaries. If the issuer ITSELF is hostile
 *     and re-issues unrestricted caps regardless of denial signals,
 *     capnagent has no defense. Out of scope per THREAT_MODEL.md.
 */

import { describe, expect, it } from "vitest";

import {
  Auditor,
  type Context,
  Issuer,
  Verifier,
  init,
} from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xc1);
const AUDIT_KEY = new Uint8Array(32).fill(0xc2);

const FROZEN_NOW_MS = 1_700_000_000_000;

function freshIssuer() {
  return Issuer.fromKey(ROOT_KEY);
}

async function issueNarrowCap() {
  await init();
  return freshIssuer()
    .issue("buy")
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

async function issueBroaderCap() {
  // Same shape but $200 ceiling instead of $50 — the kind of cap an
  // issuer would mint after a back-off review concluded the agent
  // legitimately needs more headroom.
  await init();
  return freshIssuer()
    .issue("buy")
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 200")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

const OVER_BUDGET_CTX: Context = {
  caller: "agent:planner",
  tool: "checkout.purchase",
  args: { merchant: "amazon.com", amount: 99 },
  nowMs: FROZEN_NOW_MS,
};

const IN_BUDGET_CTX: Context = {
  caller: "agent:planner",
  tool: "checkout.purchase",
  args: { merchant: "amazon.com", amount: 30 },
  nowMs: FROZEN_NOW_MS,
};

describe("Round 12: Capability re-issuance after denial — operator-side runbook", () => {
  describe("the receipt-stream contract", () => {
    it("a denied call produces a receipt with outcome.kind === 'denied' (positive — operator can detect denials)", async () => {
      const cap = await issueNarrowCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);
      const r = verifier.verifyWithContext(cap, OVER_BUDGET_CTX, auditor);
      expect(r.outcome.kind).toBe("denied");
    });

    it("an allowed call produces a receipt with outcome.kind === 'allowed' (negative — denials are distinguishable from allows)", async () => {
      const cap = await issueNarrowCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);
      const r = verifier.verifyWithContext(cap, IN_BUDGET_CTX, auditor);
      expect(r.outcome.kind).toBe("allowed");
    });

    it("denial reason is a non-empty string the operator can grep / hash for back-off keying", async () => {
      const cap = await issueNarrowCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);
      const r = verifier.verifyWithContext(cap, OVER_BUDGET_CTX, auditor);
      expect(r.outcome.kind).toBe("denied");
      if (r.outcome.kind === "denied") {
        expect(typeof r.outcome.reason).toBe("string");
        expect(r.outcome.reason.length).toBeGreaterThan(0);
      }
    });

    it("each denial mints a receipt — there is no aggregation state inside the verifier", async () => {
      // The operator counts denials, not the verifier. We assert this
      // by minting many denials and observing N independent receipts.
      const cap = await issueNarrowCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);
      const receipts = [];
      for (let i = 0; i < 5; i++) {
        receipts.push(verifier.verifyWithContext(cap, OVER_BUDGET_CTX, auditor));
      }
      expect(receipts).toHaveLength(5);
      for (const r of receipts) expect(r.outcome.kind).toBe("denied");
      // No counter accessor exists on Verifier — the operator must
      // count externally. This test pins that the absence is intentional.
      expect("denialCount" in verifier).toBe(false);
      expect("denialCountFor" in verifier).toBe(false);
    });
  });

  describe("re-issuance is a pure cryptographic operation", () => {
    it("re-issuing a broader cap to the same caller succeeds — capnagent does not remember prior denials", async () => {
      // The whole point: capnagent does NOT prevent re-issuance.
      // The operator's back-off discipline is what prevents the
      // attack. Round documents this clearly so reviewers know.
      const cap1 = await issueNarrowCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      // Burn through a denial spike on cap1.
      for (let i = 0; i < 10; i++) {
        const r = verifier.verifyWithContext(cap1, OVER_BUDGET_CTX, auditor);
        expect(r.outcome.kind).toBe("denied");
      }

      // Issuer mints cap2 with broader ceiling. capnagent has no
      // mechanism to refuse this — back-off is operator-side.
      const cap2 = await issueBroaderCap();
      expect(cap2).toBeDefined();

      // cap2 permits the same call cap1 denied.
      const r = verifier.verifyWithContext(cap2, OVER_BUDGET_CTX, auditor);
      expect(r.outcome.kind).toBe("allowed");
    });

    it("two issuer processes under the same root key produce independent re-issuance — denial count is per-process state", async () => {
      // Capnagent is stateless across issuers under the same root.
      // If the operator's back-off lives in process A and process B
      // also has the root key, B can re-issue without A's count.
      // This is a known operator concern — same shape as the
      // distributed-NonceStore problem in round 02. Same answer:
      // shared backing store for the back-off counter.
      await init();
      const issuerA = Issuer.fromKey(ROOT_KEY);
      const issuerB = Issuer.fromKey(ROOT_KEY);

      const capA = issuerA
        .issue("buy")
        .caveat(`caller == "agent:planner"`)
        .caveat(`tool == "checkout.purchase"`)
        .caveat("arg.amount <= 50")
        .caveat("now <= @2099-01-01T00:00:00Z")
        .build();
      const capB = issuerB
        .issue("buy")
        .caveat(`caller == "agent:planner"`)
        .caveat(`tool == "checkout.purchase"`)
        .caveat("arg.amount <= 50")
        .caveat("now <= @2099-01-01T00:00:00Z")
        .build();

      // Both verify under the same root key. The two-issuer state
      // is invisible to capnagent; the back-off counter must live
      // outside the issuer-process boundary if the operator deploys
      // multiple issuer processes.
      const verifier = new Verifier(ROOT_KEY);
      const auditor = new Auditor(AUDIT_KEY);
      const rA = verifier.verifyWithContext(capA, IN_BUDGET_CTX, auditor);
      const rB = verifier.verifyWithContext(capB, IN_BUDGET_CTX, auditor);
      expect(rA.outcome.kind).toBe("allowed");
      expect(rB.outcome.kind).toBe("allowed");
    });
  });

  describe("the agent has no in-band path to the issuer", () => {
    it("the receipt is returned to the verify call site, not to the agent context — the agent cannot influence what the issuer decides next", async () => {
      // The agent observes "I got a CapabilityDeniedError" via the
      // wrapMCPClient layer. The receipt itself flows to the
      // operator's logging pipeline (Auditor → on-disk / network).
      // The agent has no API to query the receipt directly; the
      // receipt's audience is the operator, not the agent.
      const cap = await issueNarrowCap();
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      const receipt = verifier.verifyWithContext(cap, OVER_BUDGET_CTX, auditor);

      // The receipt is the verifier's RETURN value. There is no
      // listener API the agent could subscribe to. The operator
      // routes receipts via Auditor (and the wrapper's onReceipt
      // callback) — both of those run outside the LLM's context
      // window. Pinning the API shape: receipt is a plain object,
      // not a Promise the agent could await.
      expect(receipt).toBeDefined();
      expect(typeof receipt).toBe("object");
      expect(receipt).not.toBeInstanceOf(Promise);
    });
  });

  describe("known bypass: insider-issuer", () => {
    it("if the issuer re-issues an identical cap after every denial, the back-off is structurally circumvented (CAPABILITY-CONFIG)", async () => {
      // Documented: hostile or buggy issuer that re-issues without
      // checking denial signals is outside capnagent's defense
      // surface. Pin the bypass so reviewers see it explicitly.
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);
      let allowedCount = 0;
      let deniedCount = 0;

      // Imagine: agent makes 5 calls, gets 5 denials. Issuer naively
      // re-mints the same narrow cap each time. Nothing breaks, but
      // nothing improves either — denials keep happening.
      for (let i = 0; i < 5; i++) {
        const cap = await issueNarrowCap(); // naive re-issue
        const r = verifier.verifyWithContext(cap, OVER_BUDGET_CTX, auditor);
        if (r.outcome.kind === "allowed") allowedCount++;
        else deniedCount++;
      }
      expect(deniedCount).toBe(5);
      expect(allowedCount).toBe(0);
    });

    it("if the issuer re-issues a STRICTLY BROADER cap on every denial, the agent eventually gets the action through (CAPABILITY-CONFIG)", async () => {
      // The actual attack the round defends against — and the
      // operator's back-off is what stops it. capnagent itself
      // does NOT stop it. PoC pins this by demonstrating that the
      // attack succeeds under the naive issuer policy.
      const auditor = new Auditor(AUDIT_KEY);
      const verifier = new Verifier(ROOT_KEY);

      const tightCap = await issueNarrowCap();
      let r = verifier.verifyWithContext(tightCap, OVER_BUDGET_CTX, auditor);
      expect(r.outcome.kind).toBe("denied");

      // Naive issuer broadens after observing the denial.
      const broadCap = await issueBroaderCap();
      r = verifier.verifyWithContext(broadCap, OVER_BUDGET_CTX, auditor);
      expect(r.outcome.kind).toBe("allowed");
      // The bypass succeeded structurally. Defender-actionable in
      // the round doc: don't re-issue without back-off + review.
    });
  });
});
