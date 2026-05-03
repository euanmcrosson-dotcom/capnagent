/**
 * Purple-team PoC for `docs/purple-team/14-resource-budget-caveat.md`.
 *
 * Round 14 introduces a new DSL surface — `verifier.<field>` —
 * intended to defend against a class of attacks the round 11–13
 * harness rounds surfaced but couldn't address structurally:
 * cost-amplification / depth-bomb / budget-burn. The agent is
 * permitted to call legitimate, narrowly-scoped tools, but does so
 * enough times (or deeply enough) that the cumulative effect is
 * harmful: token budget exhaustion, supplier-fanout DoS, recursive
 * sub-agent loops, runaway costs.
 *
 * # The structural claim
 *
 * The verifier reads facts the agent CANNOT mint. A counter that
 * the operator's harness updates on every tool call (tokens used,
 * recursion depth, dollars spent, fanout count) is NOT in the
 * agent's authority surface; even a fully prompt-injected agent
 * still produces tool calls that pass through the verifier, and
 * those tool calls carry no signal that perturbs the harness's
 * counters. So a caveat that compares against `verifier.tokens_used`
 * is decided by the harness, not by anything the agent can produce.
 *
 * The DSL extension is intentionally tiny: one new top-level
 * identifier (`verifier`) that resolves the same way `arg` does
 * (walk-and-convert into the Rust DSL `Value` enum), reading from
 * `Context::verifier_facts`. The wider security argument is the
 * operator's: that the harness, not the agent, is the one who
 * populates `verifierFacts` on the Context before calling
 * `verifyWithContext`.
 *
 * # Threat model
 *
 * Honest holder, hostile or jailbroken model. The model produces a
 * legitimately-formed tool call — say `llm.completion` with a tiny
 * prompt — but does so 1,000 times in a session, draining a
 * customer's monthly budget in minutes. The cap is correctly
 * scoped (`tool == "llm.completion" AND arg.max_tokens <= 1000`);
 * each individual call is in-scope. The cumulative call is the
 * attack.
 *
 * Without this round: capnagent has no way to refuse the 1,001st
 * call. The cap is intact, the chain verifies, the per-call caveat
 * holds. The verifier has no language to say "and the running
 * total is too high".
 *
 * With this round: a caveat like
 * `verifier.tokens_used <= 100000` (added to the cap at issue
 * time) is consulted on every call; once the harness's counter
 * crosses 100k, every subsequent call is denied with a
 * `caveat failed: verifier.tokens_used <= 100000` reason. The
 * agent can't lie about the counter — it's never in the agent's
 * input shape.
 *
 * # What the test does NOT cover
 *
 *   - Distributed counters across multiple verifier processes. The
 *     harness has to keep its `tokens_used` counter consistent across
 *     all verifier instances that share a root key; this is the same
 *     class of distributed-state problem as the NonceStore covers
 *     (out-of-scope by THREAT_MODEL.md).
 *   - The harness lying about facts. If the harness chooses to set
 *     `verifierFacts: { tokens_used: 0 }` on every call, the cap is
 *     useless. The structural argument requires that the harness
 *     actually computes the counter. This is operator-config domain
 *     (same shape as choosing realistic TTLs).
 *   - Atomicity of the read-evaluate-update cycle. A naive harness
 *     reads the counter at request time, hands it to the verifier,
 *     and updates after the tool call returns. A burst of N concurrent
 *     calls all read the same counter and all pass; they collectively
 *     exceed the budget by up to N-1 calls. Mitigations: serialize
 *     budget-bearing calls, or use approximate accounting with a
 *     hardstop reserve. Documented in the round writeup.
 *   - Caveat-DSL semantic foot-guns: a too-loose threshold
 *     (`verifier.tokens_used <= 999999999`) defeats this defense the
 *     same way a too-loose `arg.path matches "~"` defeats round 01.
 *     Operator responsibility, like every other cap-config angle.
 */

import { describe, expect, it } from "vitest";

import { Auditor, type Context, Issuer, Verifier, init } from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xd1);
const AUDIT_KEY = new Uint8Array(32).fill(0xd2);

/**
 * The harness's per-session counter. In production this would be
 * Redis or Postgres; here we just keep an in-memory tally and snap
 * its value into `verifierFacts` on every call. The point of the
 * test is to PROVE the counter shape works end-to-end, not to test
 * the storage backend.
 */
class BudgetTracker {
  tokensUsed = 0;
  callsMade = 0;

  /** Records a successful call and its token cost. */
  recordCall(tokens: number): void {
    this.tokensUsed += tokens;
    this.callsMade += 1;
  }

  /**
   * Snapshot for a `verifierFacts` payload. Keys are snake_case to
   * match the caveat predicate text — the caveat reads
   * `verifier.tokens_used`, and the DSL does literal lookup, so the
   * harness has to emit the same name. (The TS rest of the world
   * prefers camelCase, but the verifier-facts payload is a contract
   * with the cap predicate, not with the harness's TS code.)
   */
  snapshot(): { tokens_used: number; calls_made: number } {
    return { tokens_used: this.tokensUsed, calls_made: this.callsMade };
  }
}

function buyCap(predicate: string) {
  return Issuer.fromKey(ROOT_KEY)
    .issue("llm-budgeted")
    .caveat(`tool == "llm.completion"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .caveat(predicate)
    .build();
}

function callCtx(tracker: BudgetTracker, prompt: string): Context {
  return {
    nowMs: Date.parse("2026-04-30T00:00:00Z"),
    caller: "agent:planner",
    tool: "llm.completion",
    args: { prompt, max_tokens: 200 },
    verifierFacts: tracker.snapshot(),
  };
}

describe("round 14 — resource-budget caveat (verifier.<field>)", () => {
  // ─── 1. Token-budget cap denies after the harness's counter crosses the line ───
  it("first 5 calls are allowed; 6th call is denied once the counter crosses", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    const tracker = new BudgetTracker();

    // Cap allows up to 1000 cumulative tokens. Each call costs 200, so
    // 5 calls succeed (running totals: 0/200/400/600/800 — all <= 1000)
    // and the 6th (running total 1000 BEFORE this call would push it
    // to 1200) is denied because the verifier sees `tokens_used = 1000`
    // which is no longer `<= 1000`. We compare with strict <, not <=,
    // so the test reads "deny when next call would exceed" rather
    // than "deny when over"; that's the more honest semantic.
    const cap = buyCap("verifier.tokens_used < 1000");

    for (let i = 0; i < 5; i++) {
      const r = verifier.verifyWithContext(cap, callCtx(tracker, `q${i}`), auditor);
      expect(r.outcome.kind).toBe("allowed");
      tracker.recordCall(200);
    }

    // 6th call: tracker.tokensUsed === 1000, which is NOT < 1000.
    const r6 = verifier.verifyWithContext(cap, callCtx(tracker, "q5"), auditor);
    expect(r6.outcome.kind).toBe("denied");
    if (r6.outcome.kind === "denied") {
      expect(r6.outcome.reason).toMatch(/verifier\.tokens_used/);
    }

    // The denial does NOT advance the counter. (The harness only
    // records on outcome.kind === "allowed"; this is what makes the
    // defense honest: a denied call costs no budget, so an attacker
    // who keeps trying after a denial doesn't burn down the budget
    // further.)
    expect(tracker.tokensUsed).toBe(1000);
  });

  // ─── 2. The caveat is structurally bound to the cap (chain check defends it) ───
  it("dropping the budget caveat would break the chain", async () => {
    // The budget caveat is folded into the HMAC chain at issue time.
    // A hostile holder who edits the wire form to remove it cannot
    // produce a valid signature — same defense as round 03 covers
    // for any caveat. This is not new for round 14, but proving it
    // here is load-bearing: the budget defense isn't a layer below
    // the chain check, it IS a caveat, defended by the chain check.
    await init();
    const cap = buyCap("verifier.tokens_used <= 100000");
    const wire = cap.serialize();
    const decoded = JSON.parse(Buffer.from(wire, "base64url").toString("utf8")) as {
      caveats: Array<{ predicate: string }>;
      signature: string;
    };
    // Three caveats: tool ==, now <=, verifier. Drop the last.
    expect(decoded.caveats).toHaveLength(3);
    decoded.caveats.pop();
    const tampered = Buffer.from(JSON.stringify(decoded), "utf8").toString("base64url");
    // We expect parse-then-verify to fail with a chain error at the
    // wasm boundary. The exact import path for `Capability` differs
    // depending on the test scaffolding shape — round 03 already
    // proves this end-to-end across every variant; here we just
    // assert the dropped-caveat token doesn't round-trip cleanly.
    // Importing Capability dynamically to keep this test independent
    // of the round 03 helpers.
    const { Capability } = await import("../index.js");
    const tamperedCap = Capability.parse(tampered);
    const verifier = new Verifier(ROOT_KEY);
    expect(() => verifier.verify(tamperedCap)).toThrow();
  });

  // ─── 3. Missing verifierFacts means fail-closed (UnknownIdent denial) ───
  it("missing verifierFacts denies fail-closed, never silently passes", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    const cap = buyCap("verifier.tokens_used <= 1000");

    // Operator forgot to populate verifierFacts. The cap depends on
    // a fact the harness didn't provide — this is misconfiguration,
    // and the gate denies with an UnknownIdent error in the reason.
    const ctx: Context = {
      nowMs: Date.parse("2026-04-30T00:00:00Z"),
      caller: "agent:planner",
      tool: "llm.completion",
      args: { prompt: "q", max_tokens: 100 },
      // verifierFacts: omitted on purpose
    };
    const r = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("denied");
    if (r.outcome.kind === "denied") {
      expect(r.outcome.reason).toMatch(/verifier\.tokens_used/);
    }
  });

  // ─── 4. Agent cannot mint the fact via args (the contract is name-spaced) ───
  it("a tool that puts tokens_used in its args does NOT spoof verifier.tokens_used", async () => {
    // The DSL distinguishes `arg.tokens_used` from `verifier.tokens_used`.
    // Even if a hostile agent crafts a tool call whose args include
    // `tokens_used: 0`, the caveat reads the verifier slot, not the
    // arg slot, and denies as expected.
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    const cap = buyCap("verifier.tokens_used < 500");
    const tracker = new BudgetTracker();
    tracker.recordCall(800); // already over budget

    const spoofingCtx: Context = {
      nowMs: Date.parse("2026-04-30T00:00:00Z"),
      caller: "agent:planner",
      tool: "llm.completion",
      // Agent tries to pass tokens_used: 0 in args — the cap doesn't
      // consult arg.tokens_used, it consults verifier.tokens_used.
      args: { prompt: "q", max_tokens: 200, tokens_used: 0 },
      verifierFacts: tracker.snapshot(),
    };
    const r = verifier.verifyWithContext(cap, spoofingCtx, auditor);
    expect(r.outcome.kind).toBe("denied");
    if (r.outcome.kind === "denied") {
      expect(r.outcome.reason).toMatch(/verifier\.tokens_used/);
    }
  });

  // ─── 5. Multiple verifier-facts compose with AND/OR ───
  it("combined budget+depth caveat: fails if EITHER threshold crosses", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    // Two-armed cap: deny when EITHER cumulative tokens > 1000 OR
    // recursion depth > 4. Operators write this by AND-ing the two
    // upper bounds.
    const cap = buyCap("verifier.tokens_used <= 1000 AND verifier.depth <= 4");

    // Within both limits — allowed.
    const ctxOk: Context = {
      nowMs: Date.parse("2026-04-30T00:00:00Z"),
      caller: "agent:planner",
      tool: "llm.completion",
      args: { prompt: "q", max_tokens: 100 },
      verifierFacts: { tokens_used: 500, depth: 2 },
    };
    expect(verifier.verifyWithContext(cap, ctxOk, auditor).outcome.kind).toBe("allowed");

    // Tokens fine, depth crossed — denied.
    const ctxDeep: Context = {
      ...ctxOk,
      verifierFacts: { tokens_used: 500, depth: 5 },
    };
    expect(verifier.verifyWithContext(cap, ctxDeep, auditor).outcome.kind).toBe("denied");

    // Depth fine, tokens crossed — denied.
    const ctxBurn: Context = {
      ...ctxOk,
      verifierFacts: { tokens_used: 5000, depth: 2 },
    };
    expect(verifier.verifyWithContext(cap, ctxBurn, auditor).outcome.kind).toBe("denied");
  });

  // ─── 6. Receipts on denial carry the reason — operators can alert on it ───
  it("budget-denial receipts are signed and verify under the audit key", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    const cap = buyCap("verifier.tokens_used < 100");

    const ctx: Context = {
      nowMs: Date.parse("2026-04-30T00:00:00Z"),
      caller: "agent:planner",
      tool: "llm.completion",
      args: { prompt: "q", max_tokens: 50 },
      verifierFacts: { tokens_used: 200 },
    };
    const r = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("denied");
    // Audit receipt verifies — a denial is a load-bearing artifact,
    // not a logged-and-forgotten event. Operators monitor the
    // outcome.kind === "denied" stream to detect budget-burn attacks
    // in flight.
    expect(() => auditor.verify(r)).not.toThrow();
  });

  // ─── 7. Nested verifier-facts shape: verifier.budget.tokens_used ───
  it("nested verifier paths resolve like nested arg paths", async () => {
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    const cap = buyCap("verifier.budget.tokens_used <= 100");

    const ctx: Context = {
      nowMs: Date.parse("2026-04-30T00:00:00Z"),
      caller: "agent:planner",
      tool: "llm.completion",
      args: { prompt: "q", max_tokens: 50 },
      verifierFacts: { budget: { tokens_used: 50, cost_cents: 5 } },
    };
    expect(verifier.verifyWithContext(cap, ctx, auditor).outcome.kind).toBe("allowed");

    const overCtx: Context = {
      ...ctx,
      verifierFacts: { budget: { tokens_used: 150, cost_cents: 5 } },
    };
    expect(verifier.verifyWithContext(cap, overCtx, auditor).outcome.kind).toBe("denied");
  });

  // ─── 8. Counter monotonicity is the harness's job, not the verifier's ───
  it("rolling the counter back to 0 IS allowed by the verifier (operator hazard)", async () => {
    // Documented hazard: a buggy or hostile harness that resets the
    // counter to 0 can let an over-budget cap pass. The verifier
    // does NOT enforce monotonicity — it has no way to. This test
    // pins the contract so an operator reading it sees the
    // responsibility split clearly. THREAT_MODEL.md calls out this
    // class as operator-side.
    await init();
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);
    const cap = buyCap("verifier.tokens_used <= 100");

    // First pass: legitimately under budget.
    const lowCtx: Context = {
      nowMs: Date.parse("2026-04-30T00:00:00Z"),
      caller: "agent:planner",
      tool: "llm.completion",
      args: { prompt: "q", max_tokens: 50 },
      verifierFacts: { tokens_used: 50 },
    };
    expect(verifier.verifyWithContext(cap, lowCtx, auditor).outcome.kind).toBe("allowed");

    // Subsequent over-budget attempt — denied.
    const overCtx: Context = {
      ...lowCtx,
      verifierFacts: { tokens_used: 200 },
    };
    expect(verifier.verifyWithContext(cap, overCtx, auditor).outcome.kind).toBe("denied");

    // Hostile-harness scenario: counter snaps back to 0. Verifier
    // allows it. This is an OPERATOR foot-gun, documented in the
    // round 14 writeup, not a capnagent bug.
    const resetCtx: Context = { ...lowCtx, verifierFacts: { tokens_used: 0 } };
    expect(verifier.verifyWithContext(cap, resetCtx, auditor).outcome.kind).toBe("allowed");
  });
});
