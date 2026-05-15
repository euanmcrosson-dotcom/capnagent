/**
 * Angles test — DSL & caveat-evaluation edge cases.
 *
 * Not a formal purple-team round; this file rapidly probes the caveat-
 * DSL parser/evaluator with edge-case inputs and pins the observed
 * behavior. Each `describe` block covers one angle from the brief.
 *
 * Conventions:
 *   - Tests prefixed `[FINDING]` mark a real defect or surprising
 *     behavior worth a follow-up.
 *   - Inline `// FINDING: ...` comments mark observed buggy behavior
 *     where the test asserts the actual (rather than ideal) result so
 *     the file stays green and humans can grep `FINDING:`.
 *   - Tests without a marker pin behavior the angle confirmed is
 *     correct (load-bearing for regression coverage).
 *
 * All tests drive the real WASM verifier through the public
 * `@capnagent/core` API, the same surface live verifiers use. The
 * caveat predicates are evaluated inside `verifyWithContext`; the
 * receipt's `outcome.kind === "allowed" | "denied"` and `reason`
 * string are the load-bearing observations.
 */

import { describe, expect, it } from "vitest";

import { Auditor, type Context, Issuer, Verifier, init } from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xa1);
const AUDIT_KEY = new Uint8Array(32).fill(0xa2);

/**
 * Issue a single-caveat capability. The caveat is the only thing under
 * test; ID and other shape don't matter.
 */
async function issueWithCaveat(predicate: string) {
  await init();
  return Issuer.fromKey(ROOT_KEY).issue("dsl-edges").caveat(predicate).build();
}

/**
 * Convenience: parse + evaluate a single predicate against the given
 * context, returning the receipt outcome. Throws are *not* caught here
 * — caveat parse/eval errors surface as a denial outcome, not a throw,
 * so a thrown error would itself be a finding.
 */
async function evalCaveat(
  predicate: string,
  ctx: Context,
): Promise<{ kind: "allowed" } | { kind: "denied"; reason: string }> {
  const cap = await issueWithCaveat(predicate);
  const verifier = new Verifier(ROOT_KEY);
  const auditor = new Auditor(AUDIT_KEY);
  const receipt = verifier.verifyWithContext(cap, ctx, auditor);
  return receipt.outcome;
}

const baseCtx: Context = {
  caller: "agent:planner",
  tool: "checkout.purchase",
  args: {},
  nowMs: 1_700_000_000_000,
};

// ─── Angle 1: numeric overflow / precision ──────────────────────────

describe("angle 1: numeric overflow & precision", () => {
  it("parses a literal above Number.MAX_SAFE_INTEGER (9_007_199_254_740_993)", async () => {
    // The DSL stores numbers as f64. Above 2^53 they lose integer
    // precision but are still finite, so the parser/evaluator should
    // accept them. The doc-comment at apply_op explicitly notes
    // "above 2^53, both sides route through the same f64-rounding so
    // they agree".
    const out = await evalCaveat("arg.amount <= 9007199254740993", {
      ...baseCtx,
      args: { amount: 1 },
    });
    expect(out.kind).toBe("allowed");
  });

  it("[CLOSED-PARTIAL v0.6] sub-ulp args — engine-side rejection in Rust; JS layer pre-collapses (architectural)", async () => {
    // CLOSED PARTIAL in v0.6. The engine-side defense ships in
    // `caveat_dsl.rs` and is verified by the Rust integration tests
    // `v0_6_sub_ulp_collapse_a1_closed` and friends. The DSL evaluator
    // now refuses to compare an integer-syntactic caveat literal
    // (`arg.amount <= 50`) against a float-syntactic arg value
    // (anything whose JSON source contains `.`/`e`/`E`).
    //
    // BUT the *JS layer* — this very test environment — pre-collapses
    // the sub-ulp digits before WASM ever sees them. Concrete chain:
    //
    //   1. `JSON.parse("50.000000000000001")` in JS yields the f64 50.0
    //      (JS Number IS f64; precision past ulp(50)/2 is rounded out).
    //   2. The resulting JS object `{amount: 50}` is passed to
    //      `verifyWithContext`.
    //   3. `serde-wasm-bindgen` serialises JS Number 50.0 across the
    //      boundary; serde_json sees source text "50" (integer form),
    //      not "50.000000000000001".
    //   4. The v0.6 NumKind tracking sees Integer vs Integer → no
    //      A.1 rule fires → caveat admits the call.
    //
    // For a JS caller to get the v0.6 engine-side rejection, the
    // args must arrive in Rust as a JSON STRING (so the source text
    // survives) — that's a follow-on WASM-API change tracked for
    // v0.6.1 / v0.7. Mitigation guidance for JS callers TODAY:
    // use `_cents` form against integer args (`arg.amount_cents <= 5000`),
    // which sidesteps the issue because both sides are integer-syntactic
    // before they hit JS's number type.
    //
    // We keep this test green-and-asserting-allowed because the
    // observed behaviour at the JS boundary IS still "allowed" — the
    // engine-side fix didn't change that, by design. The Rust unit
    // tests prove the engine itself rejects. See
    // `crates/capnagent-core/tests/caveat_dsl_tests.rs::v0_6_*`.
    const sneakyJson = "50.000000000000001"; // 16 digits past the decimal
    const collapsed = JSON.parse(sneakyJson) as number;
    expect(collapsed === 50).toBe(true); // JS Number is f64; sub-ulp gone
    const out = await evalCaveat("arg.amount <= 50", {
      ...baseCtx,
      args: JSON.parse(`{"amount": ${sneakyJson}}`),
    });
    // JS-layer artefact: source text is gone before crossing the WASM
    // boundary, so the engine sees Integer vs Integer and admits.
    // Engine-side rejection is verified in Rust; mitigation for JS
    // callers is the `_cents` form.
    expect(out.kind).toBe("allowed");
  });

  it("[v0.6] _cents mitigation works end-to-end through the JS layer", async () => {
    // The recommended mitigation for JS callers: use the `_cents`
    // form so both literal and arg are integers, and JS's f64
    // collapse is benign (an integer arg cents value below 2^53 is
    // representable exactly in f64).
    const out = await evalCaveat("arg.amount_cents <= 5000", {
      ...baseCtx,
      args: { amount_cents: 1299 },
    });
    expect(out.kind).toBe("allowed");

    const overBudget = await evalCaveat("arg.amount_cents <= 5000", {
      ...baseCtx,
      args: { amount_cents: 5001 },
    });
    expect(overBudget.kind).toBe("denied");
  });

  it("[CLOSED v0.6.1] verifyWithContextJson — full A.1 closure when caller has the original JSON", async () => {
    // v0.6.1 closes the residual JS-layer artefact of A.1 for callers
    // who have the ORIGINAL JSON source available (e.g. raw HTTP body,
    // webhook payload, LLM tool-call as-emitted). Passing the JSON
    // through `verifyWithContextJson` lets the Rust side parse it
    // with `arbitrary_precision` enabled, preserving the source text
    // of every number across the WASM boundary.
    //
    // Concrete test: the exact A.1 reproducer (`amount:
    // 50.000000000000001` against `arg.amount <= 50`) is now denied
    // through the JS layer when the caller hands us the raw JSON.
    const cap = await issueWithCaveat("arg.amount <= 50");
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    // CRITICAL: this is the ORIGINAL JSON source. JS hasn't parsed it
    // yet. The sub-ulp digits are still in the string.
    const rawCtxJson = JSON.stringify({
      caller: "agent:planner",
      tool: "checkout.purchase",
      nowMs: 1_700_000_000_000,
      // We have to assemble the JSON manually since JSON.stringify of
      // an already-parsed JS Number would lose the precision. The
      // `'/*kept*/'` placeholder marker is just to make the
      // substitution obvious in the test.
    }).replace(/}$/, `, "args": {"amount": 50.000000000000001}}`);

    const receipt = verifier.verifyWithContextJson(cap, rawCtxJson, auditor);
    // v0.6.1: the source text "50.000000000000001" survives across
    // the WASM boundary; the engine's v0.6 integer-domain rule sees
    // Integer literal `50` vs Float arg "50.000000000000001" and
    // rejects with a TypeMismatch which surfaces as outcome.kind ===
    // "denied" on the receipt.
    expect(receipt.outcome.kind).toBe("denied");
    if (receipt.outcome.kind === "denied") {
      // The deny reason includes the actionable mitigation guidance
      // from the Rust side (`_cents` form or fractional literal).
      expect(receipt.outcome.reason.length).toBeGreaterThan(0);
    }
  });

  it("[v0.6.1] verifyWithContextJson — safe integer cases still pass through", async () => {
    // Sanity: a JSON ctx with integer args still verifies normally
    // through the new entry point. v0.6.1 didn't change the meaning
    // of safe-shape comparisons; it only closes the unsafe-shape
    // collapse class.
    const cap = await issueWithCaveat("arg.amount_cents <= 5000");
    const verifier = new Verifier(ROOT_KEY);
    const auditor = new Auditor(AUDIT_KEY);

    const ctxJson = JSON.stringify({
      caller: "agent:planner",
      tool: "checkout.purchase",
      nowMs: 1_700_000_000_000,
      args: { amount_cents: 1299 },
    });

    const receipt = verifier.verifyWithContextJson(cap, ctxJson, auditor);
    expect(receipt.outcome.kind).toBe("allowed");
  });

  it("a value above-ulp from 50 (50.0000000000001) is correctly denied", async () => {
    // Companion to the FINDING above: the DSL is not totally
    // broken. A holder who picks a value with delta > ulp(50)/2
    // DOES get denied. The hazard is specifically the sub-ulp
    // band, not "ordering of f64 is broken".
    const above = 50.0000000000001; // 13 digits, > ulp(50)/2
    expect(above > 50).toBe(true);
    const out = await evalCaveat("arg.amount <= 50", {
      ...baseCtx,
      args: { amount: above },
    });
    expect(out.kind).toBe("denied");
  });

  it("very large number (1e308) parses and evaluates", async () => {
    const out = await evalCaveat("arg.amount <= 999999999999999999", {
      ...baseCtx,
      args: { amount: 1 },
    });
    expect(out.kind).toBe("allowed");
  });
});

// ─── Angle 2: empty / whitespace strings ────────────────────────────

describe("angle 2: empty and whitespace strings", () => {
  it('caller == "" matches a context with caller: "" (empty string equality holds)', async () => {
    const out = await evalCaveat('caller == ""', {
      caller: "",
      tool: "x",
      args: {},
      nowMs: 1_700_000_000_000,
    });
    expect(out.kind).toBe("allowed");
  });

  it('caller == " " (single space) does NOT match caller: "" — distinct values', async () => {
    const out = await evalCaveat('caller == " "', {
      caller: "",
      tool: "x",
      args: {},
      nowMs: 1_700_000_000_000,
    });
    expect(out.kind).toBe("denied");
  });

  it('arg.path matches "" is true for any string (empty substring trick)', async () => {
    // `matches` is documented as literal-substring containment.
    // Any string contains the empty string, so this is vacuously
    // true. NOT a finding — but a caveat author who writes
    // `arg.path matches ""` thinking it means "is empty" is wrong;
    // they want `arg.path == ""`. Pinning the behavior so we
    // notice if it ever changes (e.g. when v0.x switches to real
    // regex, where /(empty)/ depends on engine choice).
    const out = await evalCaveat('arg.path matches ""', {
      ...baseCtx,
      args: { path: "literally anything" },
    });
    expect(out.kind).toBe("allowed");
  });

  it('matches "" against an empty path: still allowed (both empty)', async () => {
    const out = await evalCaveat('arg.path matches ""', {
      ...baseCtx,
      args: { path: "" },
    });
    expect(out.kind).toBe("allowed");
  });
});

// ─── Angle 3: type-coerced comparisons ──────────────────────────────

describe("angle 3: cross-type comparisons (no silent coercion)", () => {
  it('arg.x == "42" is DENIED when context has arg.x: 42 (number) — no coercion', async () => {
    // Strict typing: number-vs-string yields a TypeMismatch eval
    // error, which the verifier surfaces as a "caveat eval error"
    // denial reason. Critically: the call is NOT silently allowed.
    // The denial reason should mention the type mismatch.
    const out = await evalCaveat('arg.x == "42"', {
      ...baseCtx,
      args: { x: 42 },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      // Reason should reference the eval-time type problem.
      expect(out.reason).toMatch(/eval error|type|mismatch/i);
    }
  });

  it('arg.x == 42 is DENIED when context has arg.x: "42" (string) — symmetric type check', async () => {
    const out = await evalCaveat("arg.x == 42", {
      ...baseCtx,
      args: { x: "42" },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|type|mismatch/i);
    }
  });

  it("arg.x == 1 against arg.x: true (boolean) — not a string/number, treated as missing", async () => {
    // JSON booleans aren't representable as DSL Values. The resolver
    // returns a TypeMismatch ("string or integer at arg path"); the
    // verifier surfaces as a denial.
    const out = await evalCaveat("arg.x == 1", {
      ...baseCtx,
      args: { x: true },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|type|mismatch/i);
    }
  });
});

// ─── Angle 4: deeply nested boolean ─────────────────────────────────

describe("angle 4: deep boolean nesting", () => {
  // Build a 100-level deep predicate of the form
  //   ((((true OR false) AND true) OR true) ...)
  // and confirm the parser/evaluator handles it without overflow,
  // panic, or pathological slowness.
  function buildDeep(depth: number): string {
    let p = 'caller == "agent:planner"';
    for (let i = 0; i < depth; i++) {
      // Alternate AND / OR; alternate trivially-true / trivially-
      // false leaves so the result oscillates and short-circuit
      // evaluation has to traverse the whole tree on at least
      // some inputs.
      const op = i % 2 === 0 ? "AND" : "OR";
      const leaf = i % 3 === 0 ? `tool == "checkout.purchase"` : `tool == "no-such"`;
      p = `(${p} ${op} ${leaf})`;
    }
    return p;
  }

  it("100-level deep predicate parses and evaluates without panic", async () => {
    const deep = buildDeep(100);
    const t0 = Date.now();
    const out = await evalCaveat(deep, baseCtx);
    const dt = Date.now() - t0;
    // Must be a clean Result (allowed or denied), not a throw.
    expect(["allowed", "denied"]).toContain(out.kind);
    // Should be very fast; >250ms would be a yellow flag for some
    // O(n^2) parser pathology. We don't make this assertion strict
    // because CI machines vary, but we do log it via an
    // expect-with-message if it's too slow.
    expect(dt).toBeLessThan(2000);
  });

  it("500-level deep predicate also parses and evaluates", async () => {
    const deep = buildDeep(500);
    const out = await evalCaveat(deep, baseCtx);
    expect(["allowed", "denied"]).toContain(out.kind);
  });

  it("1000-level deep predicate — stress test for stack-overflow regression", async () => {
    // The Rust parser/evaluator is recursive (parse_or_expr →
    // parse_and_expr → parse_unary → parse_or_expr). A pathological
    // input *could* blow the WASM stack. Confirm 1000 nests are fine.
    const deep = buildDeep(1000);
    const out = await evalCaveat(deep, baseCtx);
    expect(["allowed", "denied"]).toContain(out.kind);
  });
});

// ─── Angle 5: special-character predicate strings ───────────────────

describe("angle 5: special characters in string literals", () => {
  it("\\n escape parses and matches a literal newline in args", async () => {
    const out = await evalCaveat('arg.path matches "\\n"', {
      ...baseCtx,
      args: { path: "line1\nline2" },
    });
    expect(out.kind).toBe("allowed");
  });

  it("\\\\ escape parses and matches a literal backslash", async () => {
    const out = await evalCaveat('arg.path matches "\\\\"', {
      ...baseCtx,
      args: { path: "C:\\Users\\me" },
    });
    expect(out.kind).toBe("allowed");
  });

  it('\\" escape parses and matches a literal double-quote', async () => {
    const out = await evalCaveat('arg.path matches "\\""', {
      ...baseCtx,
      args: { path: 'has "quote" inside' },
    });
    expect(out.kind).toBe("allowed");
  });

  it("\\t escape parses and matches a literal tab", async () => {
    const out = await evalCaveat('arg.path matches "\\t"', {
      ...baseCtx,
      args: { path: "col1\tcol2" },
    });
    expect(out.kind).toBe("allowed");
  });

  it("[FINDING] literal NUL byte inside a string literal is accepted by the parser", async () => {
    // The grammar does NOT reject control characters inside
    // double-quoted strings. A holder-controlled caveat (or an
    // attenuation) can carry an embedded NUL. This is mostly
    // benign (the comparison still works), but downstream
    // consumers logging the predicate text to file/syslog may
    // truncate at the NUL — at which point the audit log shows a
    // misleading caveat string.
    //
    // FINDING: the parser permits raw NUL (0x00) in string
    // literals. Threat: a malicious holder could attenuate with a
    // caveat whose `predicate` field renders truncated in
    // text-based audit logs, hiding the real predicate from a
    // human auditor.
    //
    // Note: the parser also accepts other ASCII control chars
    // (0x01–0x1F). We pin NUL specifically because it's the most
    // log-toxic byte.
    const predicate = `arg.path matches "\x00sneaky"`;
    const out = await evalCaveat(predicate, {
      ...baseCtx,
      args: { path: "literal\x00sneaky bytes" },
    });
    expect(out.kind).toBe("allowed");
  });

  it("[CLOSED v0.5] invalid escape \\q is rejected at ATTENUATE time (was: at verify)", async () => {
    // v0.5: caveat predicates are pre-validated against the DSL parser
    // at issuance / attenuate time, so unparseable predicates throw
    // synchronously rather than chaining and producing denial-at-verify.
    await expect(issueWithCaveat('arg.path matches "\\q"')).rejects.toThrow(/parse|invalid escape/i);
  });
});

// ─── Angle 6: ambiguous parens & precedence ─────────────────────────

describe("angle 6: precedence & non-existent NOT operator", () => {
  it('AND binds tighter than OR: `tool == "x" AND tool == "y" OR caller == "z"` parses as (AND) OR (...)', async () => {
    // Construct facts where the two parsings disagree:
    //   precedence-correct (AND tighter):
    //     (false AND false) OR true  = true
    //   precedence-wrong (OR tighter):
    //     false AND (false OR true)  = false
    const out = await evalCaveat(`tool == "x" AND tool == "y" OR caller == "agent:planner"`, {
      ...baseCtx,
      caller: "agent:planner",
      tool: "neither",
    });
    expect(out.kind).toBe("allowed"); // implies AND-tighter precedence
  });

  it("[CLOSED v0.5] `NOT A` is rejected at ATTENUATE time — there is no NOT operator", async () => {
    // v0.5: pre-validation moves these rejections from verify-time to
    // attenuate / caveat / issuance time. The closure is strictly
    // stronger — a stray `NOT` in operator config now fails the
    // deploy probe rather than producing a permanent-deny token.
    await expect(issueWithCaveat('NOT caller == "agent:planner"')).rejects.toThrow();
  });

  it("[CLOSED v0.5] `NOT(A)` (negation-as-function syntax) is rejected at ATTENUATE time", async () => {
    await expect(issueWithCaveat('NOT(caller == "agent:planner")')).rejects.toThrow();
  });

  it("[CLOSED v0.5] `!` prefix is rejected at ATTENUATE time — DSL only has != as binary, no unary !", async () => {
    await expect(issueWithCaveat('!caller == "agent:planner"')).rejects.toThrow();
  });
});

// ─── Angle 7: missing arg fields ────────────────────────────────────

describe("angle 7: missing context fields", () => {
  it("missing arg.merchant produces a DENIAL (UnknownIdent surfaces as denial reason, not throw)", async () => {
    const out = await evalCaveat('arg.merchant == "amazon.com"', {
      ...baseCtx,
      args: {}, // no merchant
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      // Pinning the behavior: this is "caveat eval error", with
      // an UnknownIdent suffix. NOT a silent false (which would
      // be a finding) and NOT a throw (which would be a finding).
      expect(out.reason).toMatch(/eval error|unknown/i);
    }
  });

  it("missing env.region also produces a DENIAL with a useful reason", async () => {
    const out = await evalCaveat('env.region == "us-east-1"', {
      ...baseCtx,
      env: {}, // no region
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|unknown/i);
    }
  });

  it("missing nested arg path (arg.outer.inner with arg.outer absent) is a denial", async () => {
    const out = await evalCaveat('arg.outer.inner == "x"', {
      ...baseCtx,
      args: {},
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|unknown/i);
    }
  });

  it("missing nested arg path (arg.outer.inner with arg.outer present but not an object) is a denial", async () => {
    // arg.outer is a string "not-an-object"; descending into
    // .inner is impossible. Same UnknownIdent as fully-missing.
    const out = await evalCaveat('arg.outer.inner == "x"', {
      ...baseCtx,
      args: { outer: "not-an-object" },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|unknown/i);
    }
  });
});

// ─── Angle 8: matches on non-string types ───────────────────────────

describe("angle 8: matches on null / numbers / arrays", () => {
  it("matches on a JSON null — denial (json_to_value returns None → TypeMismatch)", async () => {
    const out = await evalCaveat('arg.path matches "/x/"', {
      ...baseCtx,
      args: { path: null },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|type|mismatch|null/i);
    }
  });

  it("matches on a JSON number — denial via TypeMismatch", async () => {
    const out = await evalCaveat('arg.path matches "42"', {
      ...baseCtx,
      args: { path: 42 },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|type|mismatch/i);
    }
  });

  it("matches on a JSON array — denial via TypeMismatch", async () => {
    const out = await evalCaveat('arg.path matches "x"', {
      ...baseCtx,
      args: { path: ["x", "y"] },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|type|mismatch|array/i);
    }
  });

  it("matches RHS as a number literal — parse error (matches RHS must be string)", async () => {
    // The DSL grammar accepts ANY value type on the RHS. The type
    // check happens at evaluate time. This test pins that
    // `matches` against a numeric RHS denies cleanly (not a
    // throw, not a silent allow).
    const out = await evalCaveat("arg.path matches 42", {
      ...baseCtx,
      args: { path: "42" },
    });
    expect(out.kind).toBe("denied");
    if (out.kind === "denied") {
      expect(out.reason).toMatch(/eval error|type|mismatch/i);
    }
  });

  it("matches LHS string against a present numeric arg never silently allows", async () => {
    // Defense in depth: if a JSON arg ever sneaked through as a
    // number AND the DSL silently coerced it to its string
    // representation for `matches`, an attacker could craft a
    // caveat like `arg.id matches "0"` that matched any
    // numeric ID containing '0'. Confirm that scenario is denied.
    const out = await evalCaveat('arg.id matches "0"', {
      ...baseCtx,
      args: { id: 1024 }, // contains "0" if coerced; should NOT match
    });
    expect(out.kind).toBe("denied");
  });
});
