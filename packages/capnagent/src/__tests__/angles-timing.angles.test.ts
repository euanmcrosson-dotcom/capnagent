/**
 * Terminal D — angles run on capnagent's time / clock / concurrency
 * boundaries.
 *
 * Each `describe` block tests one angle from the Terminal D brief.
 * FINDINGs are tagged with `[FINDING]` in test names so they are easy
 * to grep out of the run output.
 *
 * Surface under test:
 *   - `now <=` / `now ==` predicates in the caveat DSL
 *   - `NonceStore` TTL semantics + concurrency
 *   - `RevocationList.issuedAtMs` install-time freshness
 *   - `Receipt.timestampMs` vs `ctx.nowMs`
 *
 * No FINDING here is intended to fail closed and break the test
 * suite — every test PINS the observed behavior, including behavior
 * that is "merely surprising" and worth documenting for operators.
 * Critical FINDINGs (e.g. concurrent NonceStore allowing >1 success
 * for the same proof) WOULD fail loudly.
 */

import { describe, expect, it } from "vitest";

import * as ed from "@noble/ed25519";

import {
  Auditor,
  CapabilityChainError,
  CapabilityError,
  type Context,
  Issuer,
  NonceStore,
  RevocationList,
  Revoker,
  Verifier,
  init,
  popChallengeFor,
} from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xd0);
const AUDIT_KEY = new Uint8Array(32).fill(0xd1);
const HOLDER_SECRET = new Uint8Array(32).fill(0xd2);

const FROZEN_NOW_MS = 1_700_000_000_000;
// Two minutes past 2026-04-27 (matches the brief's "today's date").
const TODAY_MS = Date.UTC(2026, 3, 27, 12, 0, 0);

async function buildHokFixture(opts: { capId?: string; nowMs?: number } = {}) {
  await init();
  const capId = opts.capId ?? "angles-timing";
  const nowMs = opts.nowMs ?? FROZEN_NOW_MS;
  const publicKey = await ed.getPublicKeyAsync(HOLDER_SECRET);
  const cap = Issuer.fromKey(ROOT_KEY)
    .issue(capId)
    .holderOfKey(publicKey)
    .caveat(`tool == "x"`)
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
  const ctx: Context = {
    caller: "agent:test",
    tool: "x",
    args: { n: 1 },
    nowMs,
  };
  const auditor = new Auditor(AUDIT_KEY);
  const challenge = popChallengeFor(cap, ctx);
  const proof = await ed.signAsync(challenge, HOLDER_SECRET);
  return { cap, ctx, auditor, challenge, proof };
}

// ---------------------------------------------------------------------------
// Angle 1 — Clock skew between issuer and verifier on a RevocationList
// ---------------------------------------------------------------------------

describe("Angle 1 — RevocationList freshness across issuer/verifier clock skew", () => {
  it("install accepts a list with issued_at_ms FAR in the future without complaint (PIN)", async () => {
    await init();
    const revoker = new Revoker(ROOT_KEY);
    revoker.revoke("some-cap");
    // Issuer says the list was published "1 year from now".
    const list = revoker.publish(TODAY_MS + 365 * 24 * 60 * 60 * 1000);

    const verifier = new Verifier(ROOT_KEY).withRevocationList(list);
    expect(verifier.hasRevocationList()).toBe(true);
    // Verifier has no install-time freshness check — operators must
    // implement one themselves via revocationListIssuedAtMs().
    const installed = verifier.revocationListIssuedAtMs();
    expect(installed).toBeGreaterThan(TODAY_MS);
  });

  it("install accepts a list with issued_at_ms 1 minute BEHIND verifier wall-clock (PIN)", async () => {
    await init();
    const revoker = new Revoker(ROOT_KEY);
    revoker.revoke("some-cap");
    const list = revoker.publish(TODAY_MS - 60_000);

    const verifier = new Verifier(ROOT_KEY).withRevocationList(list);
    expect(verifier.hasRevocationList()).toBe(true);
    expect(verifier.revocationListIssuedAtMs()).toBe(TODAY_MS - 60_000);
  });

  it("[FINDING] withRevocationList enforces NO freshness window — stale lists install silently", async () => {
    // FINDING: A revocation list issued by a compromised replica years
    // ago, sitting in cold storage, will install successfully because
    // the signature still verifies and there is no window check.
    // Operators relying on revocation as a defense MUST implement a
    // freshness check using revocationListIssuedAtMs() themselves.
    // Impact: medium — a stale list is safe by content (same revoked
    // identifiers), but a stale list MIGHT MISS recently-revoked
    // identifiers an attacker is currently exploiting.
    await init();
    const revoker = new Revoker(ROOT_KEY);
    revoker.revoke("very-old-cap");
    // 5 years stale.
    const stale = revoker.publish(TODAY_MS - 5 * 365 * 24 * 60 * 60 * 1000);

    const verifier = new Verifier(ROOT_KEY).withRevocationList(stale);
    expect(verifier.hasRevocationList()).toBe(true);
    const stalenessMs = TODAY_MS - (verifier.revocationListIssuedAtMs() ?? 0);
    expect(stalenessMs).toBeGreaterThan(365 * 24 * 60 * 60 * 1000);
  });
});

// ---------------------------------------------------------------------------
// Angle 2 — Cap with `now <= @1970-01-01` (already-expired)
// ---------------------------------------------------------------------------

describe("Angle 2 — Already-expired caveat (now <= @1970-01-01T00:00:00Z)", () => {
  it("verify_with_context returns Outcome::Denied with caveat-failed reason (PIN)", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("expired-cap")
      .caveat(`tool == "x"`)
      .caveat("now <= @1970-01-01T00:00:00Z")
      .build();
    const ctx: Context = {
      caller: "agent:test",
      tool: "x",
      args: {},
      nowMs: TODAY_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);
    const r = verifier.verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("denied");
    if (r.outcome.kind === "denied") {
      expect(r.outcome.reason).toMatch(/caveat failed: now <= @1970-01-01/);
    }
  });

  it("verify_with_context still produces a signed receipt — denial is auditable, not throwy (PIN)", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("expired-cap-2")
      .caveat("now <= @1970-01-01T00:00:00Z")
      .build();
    const ctx: Context = {
      caller: "agent:test",
      tool: "x",
      args: {},
      nowMs: TODAY_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, auditor);
    expect(r.signature.length).toBeGreaterThan(0);
    // Audit signature still validates over the denied-receipt body.
    expect(() => auditor.verify(r)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Angle 3 — Cap with far-future timestamp (5-digit year)
// ---------------------------------------------------------------------------

describe("Angle 3 — Far-future timestamp (5-digit year)", () => {
  it("4-digit year @9999-12-31T23:59:59Z parses and ALLOWS the call (PIN baseline)", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("far-future-4")
      .caveat(`tool == "x"`)
      .caveat("now <= @9999-12-31T23:59:59Z")
      .build();
    const ctx: Context = {
      caller: "agent:test",
      tool: "x",
      args: {},
      nowMs: TODAY_MS,
    };
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, new Auditor(AUDIT_KEY));
    expect(r.outcome.kind).toBe("allowed");
  });

  it("[CLOSED v0.5] 5-digit year @99999-12-31 is rejected at ISSUE time (was: at verify)", async () => {
    // Originally [FINDING]: the RFC3339 parser only accepts 4-digit
    // years, and the caveat builder admitted the predicate without
    // validation, so a `@99999-...` cap silently became a permanent-
    // deny token. v0.5 closure: predicate strings are pre-validated
    // against the DSL parser at issuance, so the operator who tries
    // a "century-long" cap gets an immediate named error — not a
    // permadenied token they have to debug at runtime.
    await init();
    expect(() =>
      Issuer.fromKey(ROOT_KEY)
        .issue("far-future-5")
        .caveat(`tool == "x"`)
        .caveat("now <= @99999-12-31T23:59:59Z")
        .build(),
    ).toThrow(/parse|invalid timestamp|99999/);
  });

  it("negative year @-001-01-01 (1 BC) parses but produces a DENIAL — `now <= 1BC` is false today", async () => {
    // Empirical pin: the RFC3339 parser does accept a `-001` year
    // (parse_int_exact on `-001` returns i32 = -1), so the predicate
    // is well-formed. At verify, `now <= @-001-...` evaluates to
    // false against any present-day clock and the receipt is denied.
    // Not a parse failure — a logical denial. Pinned so a future
    // change to year handling surfaces here.
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("year-negative")
      .caveat("now <= @-001-01-01T00:00:00Z")
      .build();
    const r = new Verifier(ROOT_KEY).verifyWithContext(
      cap,
      { caller: "a", tool: "t", args: {}, nowMs: TODAY_MS },
      new Auditor(AUDIT_KEY),
    );
    expect(r.outcome.kind).toBe("denied");
  });
});

// ---------------------------------------------------------------------------
// Angle 4 — NonceStore TTL boundary
// ---------------------------------------------------------------------------

describe("Angle 4 — NonceStore TTL boundary (T+999 / T+1000 / T+1001)", () => {
  it("[FINDING] expiry is EXCLUSIVE — replay at exactly T+ttl_ms is ALLOWED, not denied", async () => {
    // FINDING: `try_record` uses `existing_expiry > now_ms`, so when
    // `now_ms == expiry`, the entry is treated as already-expired and
    // the replay is ACCEPTED. This is mathematically off-by-one against
    // a naive "TTL covers a closed interval" reading.
    //
    // Impact: low. The expiry-boundary moment is a single ms wide; a
    // racing attacker would need ms-precision timing on a server they
    // do not control. But operators tuning TTL down for memory should
    // remember the actual protection window is half-open `[T, T+ttl)`,
    // not closed `[T, T+ttl]`. Document the TTL contract.
    await init();
    const TTL_MS = 1000;
    const T = 5_000_000;
    const { cap, auditor, challenge, proof } = await buildHokFixture({ nowMs: T });

    const store = new NonceStore();
    const verifier = new Verifier(ROOT_KEY).withNonceStore(store).withNonceTtlMs(TTL_MS);

    // Anchor the entry at T.
    const ctx0: Context = { caller: "agent:test", tool: "x", args: { n: 1 }, nowMs: T };
    expect(verifier.verifyWithProof(cap, ctx0, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );

    // Replay at T+999 — DENIED (still within window).
    const ctx999: Context = { ...ctx0, nowMs: T + 999 };
    expect(verifier.verifyWithProof(cap, ctx999, auditor, challenge, proof).outcome.kind).toBe(
      "denied",
    );

    // Fresh store for the boundary check (otherwise the T+999 deny
    // mutates state we want to inspect cleanly).
    const store2 = new NonceStore();
    const v2 = new Verifier(ROOT_KEY).withNonceStore(store2).withNonceTtlMs(TTL_MS);
    expect(v2.verifyWithProof(cap, ctx0, auditor, challenge, proof).outcome.kind).toBe("allowed");

    // Replay at T+1000 — exactly the expiry. ALLOWED. This is the
    // off-by-one finding.
    const ctx1000: Context = { ...ctx0, nowMs: T + 1000 };
    expect(v2.verifyWithProof(cap, ctx1000, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );

    const store3 = new NonceStore();
    const v3 = new Verifier(ROOT_KEY).withNonceStore(store3).withNonceTtlMs(TTL_MS);
    expect(v3.verifyWithProof(cap, ctx0, auditor, challenge, proof).outcome.kind).toBe("allowed");
    // T+1001 — well past expiry. ALLOWED.
    const ctx1001: Context = { ...ctx0, nowMs: T + 1001 };
    expect(v3.verifyWithProof(cap, ctx1001, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
  });
});

// ---------------------------------------------------------------------------
// Angle 5 — Concurrent NonceStore inserts (CRITICAL)
// ---------------------------------------------------------------------------

describe("Angle 5 — Concurrent NonceStore inserts with the SAME proof bytes", () => {
  it("100 parallel verifyWithProof calls with identical proof bytes admit AT MOST ONE allowed (CRITICAL)", async () => {
    // The Mutex inside InMemoryNonceStore must serialize check-then-
    // insert so only ONE of N concurrent attempts wins. Any race that
    // produces >1 allowed receipt for the same proof bytes would be a
    // CRITICAL finding — replay protection silently broken under load.
    //
    // Note: vitest in the Node target runs JS on a single thread, so
    // "true parallelism" is bounded by the WASM event loop. But
    // Promise.all() over many calls still exercises the Mutex's
    // observed behavior under interleaving — and the Mutex must
    // remain correct under any future multi-threaded host.
    await init();
    const { cap, ctx, auditor, challenge, proof } = await buildHokFixture();
    const store = new NonceStore();
    const verifier = new Verifier(ROOT_KEY).withNonceStore(store);

    const N = 100;
    const tasks = Array.from({ length: N }, () =>
      Promise.resolve().then(() => verifier.verifyWithProof(cap, ctx, auditor, challenge, proof)),
    );
    const receipts = await Promise.all(tasks);

    const allowed = receipts.filter((r) => r.outcome.kind === "allowed").length;
    const denied = receipts.filter((r) => r.outcome.kind === "denied").length;

    expect(allowed).toBe(1);
    expect(denied).toBe(N - 1);
    // Every denial must cite replay, NOT something else (e.g. caveat).
    for (const r of receipts) {
      if (r.outcome.kind === "denied") {
        expect(r.outcome.reason).toBe("proof replay detected");
      }
    }
    expect(store.size).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Angle 6 — Receipt timestamp_ms vs ctx.now_ms
// ---------------------------------------------------------------------------

describe("Angle 6 — Receipt.timestampMs origin (auditor vs verifier clock)", () => {
  it("[FINDING] receipt.timestampMs is sourced from ctx.nowMs — the SAME clock the caveats evaluated against", async () => {
    // FINDING (informational, not a bug): the receipt timestamp_ms is
    // taken from the verifier's ctx.now (see audit.rs::sign), NOT from
    // an independent auditor wall-clock. That is correct — it keeps
    // the receipt internally consistent ("at this time, this caveat
    // held"). The implication for operators:
    //
    //   - If the verifier's clock is wrong, the receipt timestamp is
    //     wrong by the same amount.
    //   - If the verifier's clock is ATTACKER-CONTROLLED (kernel time
    //     poisoning, virtualized clock drift), every receipt is
    //     consistent-with-itself but lies about wall-clock.
    //
    // The audit log is therefore only as trustworthy as the verifier's
    // clock authority. Document this; do not treat it as defense-in-
    // depth against clock attacks.
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("ts-source")
      .caveat(`tool == "x"`)
      .caveat("now <= @2099-01-01T00:00:00Z")
      .build();
    const FAR_PAST_MS = 1_000_000_000_000;
    const ctx: Context = {
      caller: "agent:test",
      tool: "x",
      args: {},
      nowMs: FAR_PAST_MS,
    };
    const auditor = new Auditor(AUDIT_KEY);
    const r = new Verifier(ROOT_KEY).verifyWithContext(cap, ctx, auditor);
    expect(r.outcome.kind).toBe("allowed");
    // Receipt timestamp matches ctx.nowMs EXACTLY — not Date.now().
    expect(r.timestampMs).toBe(FAR_PAST_MS);
    expect(Date.now()).toBeGreaterThan(FAR_PAST_MS); // sanity
  });

  it("ctx omitted nowMs defaults to Date.now() — no wasm32 SystemTime panic", async () => {
    // Was a [FINDING]: omitting `nowMs` hit the Rust `SystemTime::now()`
    // fallback in the Context decoder, which panics on wasm32 ("time not
    // implemented") and poisons the instance — despite the Context.nowMs
    // doc promising a Date.now() default. The wrapper now fills nowMs from
    // Date.now() before crossing into WASM, so the documented contract
    // holds and a caller who omits nowMs gets a normal decision, not an abort.
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("ts-default")
      .caveat(`tool == "x"`)
      .caveat("now <= @2099-01-01T00:00:00Z")
      .build();
    const before = Date.now();
    const r = new Verifier(ROOT_KEY).verifyWithContext(
      cap,
      { caller: "a", tool: "x", args: {} }, // no nowMs supplied
      new Auditor(AUDIT_KEY),
    );
    const after = Date.now();
    expect(r.outcome.kind).toBe("allowed");
    // The receipt timestamp came from the injected Date.now(), inside the
    // call window — proving the default was applied JS-side, not a panic.
    expect(r.timestampMs).toBeGreaterThanOrEqual(before);
    expect(r.timestampMs).toBeLessThanOrEqual(after);
  });

  it("hok path (popChallengeFor + verifyWithProof) also defaults nowMs — no panic", async () => {
    // The @capnagent/mcp adapter's hok flow is exactly
    // popChallengeFor -> sign -> verifyWithProof. Both boundary crossings must
    // default nowMs too, or an hok consumer who omits it aborts mid-flow. The
    // proof verifies over the explicit challenge bytes, so independent
    // defaulting on each call is still sound.
    await init();
    const publicKey = await ed.getPublicKeyAsync(HOLDER_SECRET);
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("hok-default")
      .holderOfKey(publicKey)
      .caveat(`tool == "x"`)
      .caveat("now <= @2099-01-01T00:00:00Z")
      .build();
    const ctx: Context = { caller: "agent:test", tool: "x", args: { n: 1 } }; // no nowMs
    const challenge = popChallengeFor(cap, ctx); // would panic before the fix
    const proof = await ed.signAsync(challenge, HOLDER_SECRET);
    const r = new Verifier(ROOT_KEY).verifyWithProof(
      cap,
      ctx,
      new Auditor(AUDIT_KEY),
      challenge,
      proof,
    );
    expect(r.outcome.kind).toBe("allowed");
  });
});

// ---------------------------------------------------------------------------
// Angle 7 — Concurrent verifies on the SAME Verifier with DIFFERENT caps
// ---------------------------------------------------------------------------

describe("Angle 7 — Concurrent verifyWithContext on a shared Verifier", () => {
  it("100 parallel verifies of distinct caps produce no state cross-talk (PIN)", async () => {
    await init();
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const N = 100;
    const caps = Array.from({ length: N }, (_, i) =>
      Issuer.fromKey(ROOT_KEY)
        .issue(`concurrent-${i}`)
        .caveat(`tool == "tool-${i}"`)
        .caveat("now <= @2099-01-01T00:00:00Z")
        .build(),
    );

    const ctxs: Context[] = caps.map((_, i) => ({
      caller: `caller-${i}`,
      tool: `tool-${i}`,
      args: { i },
      nowMs: FROZEN_NOW_MS + i,
    }));

    const receipts = await Promise.all(
      caps.map((c, i) =>
        Promise.resolve().then(() => {
          const ctx = ctxs[i];
          if (!ctx) throw new Error("unreachable");
          return verifier.verifyWithContext(c, ctx, auditor);
        }),
      ),
    );

    for (let i = 0; i < N; i++) {
      const r = receipts[i];
      expect(r).toBeDefined();
      if (!r) throw new Error("unreachable");
      expect(r.outcome.kind).toBe("allowed");
      expect(r.capabilityIdentifier).toBe(`concurrent-${i}`);
      expect(r.contextSummary.tool).toBe(`tool-${i}`);
      expect(r.contextSummary.caller).toBe(`caller-${i}`);
      expect(r.timestampMs).toBe(FROZEN_NOW_MS + i);
    }
  });
});

// ---------------------------------------------------------------------------
// Angle 8 — Time-monotonic violation (clock goes backward between verifies)
// ---------------------------------------------------------------------------

describe("Angle 8 — Verifier behaves identically across non-monotonic ctx.nowMs", () => {
  it("verify at T then verify at T-10 produces identical Allowed outcomes (PIN)", async () => {
    await init();
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("monotonic")
      .caveat(`tool == "x"`)
      .caveat("now <= @2099-01-01T00:00:00Z")
      .build();
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    const T = FROZEN_NOW_MS;
    const r1 = verifier.verifyWithContext(
      cap,
      { caller: "a", tool: "x", args: {}, nowMs: T },
      auditor,
    );
    const r2 = verifier.verifyWithContext(
      cap,
      { caller: "a", tool: "x", args: {}, nowMs: T - 10 },
      auditor,
    );
    expect(r1.outcome.kind).toBe("allowed");
    expect(r2.outcome.kind).toBe("allowed");
    expect(r1.timestampMs).toBe(T);
    expect(r2.timestampMs).toBe(T - 10);
    // No state from r1 should change r2's outcome.
    expect(r1.capabilityIdentifier).toBe(r2.capabilityIdentifier);
  });

  it("non-monotonic clock does NOT carry NonceStore state across (per-clock TTL is observed)", async () => {
    // If a verifier with a NonceStore observes a backward clock jump,
    // the *recorded* expiry is still in the future relative to the
    // jumped-back clock, so the entry remains effective. Pin this so
    // we don't accidentally regress to a "clear on backward jump"
    // policy that would punch holes in replay protection.
    await init();
    const TTL_MS = 60_000;
    const T = 10_000_000;
    const { cap, auditor, challenge, proof } = await buildHokFixture({ nowMs: T });

    const store = new NonceStore();
    const verifier = new Verifier(ROOT_KEY).withNonceStore(store).withNonceTtlMs(TTL_MS);
    const ctxNow: Context = { caller: "agent:test", tool: "x", args: { n: 1 }, nowMs: T };
    const ctxBack: Context = { ...ctxNow, nowMs: T - 30_000 };

    expect(verifier.verifyWithProof(cap, ctxNow, auditor, challenge, proof).outcome.kind).toBe(
      "allowed",
    );
    // Clock jumped 30s backward — entry's expiry (T+60_000) is still
    // in the future relative to (T-30_000), so the replay is denied.
    expect(verifier.verifyWithProof(cap, ctxBack, auditor, challenge, proof).outcome.kind).toBe(
      "denied",
    );
  });
});

// ---------------------------------------------------------------------------
// Angle 9 — Boundary on `now ==` against an exact-match timestamp
// ---------------------------------------------------------------------------

describe("Angle 9 — Equality on `now` against an exact timestamp", () => {
  it("now == @<exact> matches when ctx.nowMs is exactly that timestamp (PIN)", async () => {
    // The DSL allows `==` on timestamps (ordering-derived: ord ==
    // Equal). RFC3339 timestamps have second precision (with optional
    // fractional). Match an exact second to test equality.
    await init();
    const T_ISO = "2026-04-27T12:00:00Z";
    const T_MS = Date.UTC(2026, 3, 27, 12, 0, 0);
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("eq-now")
      .caveat(`tool == "x"`)
      .caveat(`now == @${T_ISO}`)
      .build();
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);

    // Exact match — ctx.nowMs corresponds to the same UNIX seconds AND
    // zero subsecond nanos. The DSL stores (seconds, nanos) as the
    // ordering key. ctx.now from nowMs of T_MS is exactly (T_MS/1000,
    // 0) so it matches.
    const r = verifier.verifyWithContext(
      cap,
      { caller: "a", tool: "x", args: {}, nowMs: T_MS },
      auditor,
    );
    expect(r.outcome.kind).toBe("allowed");
  });

  it("[FINDING] now == @<sec> against ctx.nowMs offset by 1ms is DENIED — sub-second precision is observable through `==`", async () => {
    // FINDING: The DSL evaluates `now == @<rfc3339>` at sub-second
    // (nanos) precision. ctx.now is built from `UNIX_EPOCH +
    // Duration::from_millis(now_ms)` which preserves milliseconds; the
    // RFC3339 literal without `.fraction` has nanos=0. So a ctx with
    // nowMs = T_MS + 1 fails `now == @<T_ISO>` even though both round
    // to the same wall-clock second.
    //
    // Impact: low. Equality on `now` is unusual. Any operator writing
    // `now == @<T>` is doing something exotic and should be told that
    // the comparison is wall-clock-ms exact, not "anywhere in the
    // second". Recommend operators stick to `<=` / `>=`.
    await init();
    const T_ISO = "2026-04-27T12:00:00Z";
    const T_MS = Date.UTC(2026, 3, 27, 12, 0, 0);
    const cap = Issuer.fromKey(ROOT_KEY).issue("eq-now-offset").caveat(`now == @${T_ISO}`).build();
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);
    const r = verifier.verifyWithContext(
      cap,
      { caller: "a", tool: "x", args: {}, nowMs: T_MS + 1 },
      auditor,
    );
    expect(r.outcome.kind).toBe("denied");
    if (r.outcome.kind === "denied") {
      expect(r.outcome.reason).toMatch(/caveat failed: now ==/);
    }
  });

  it("now != @<T> behaves as inverse of `==` (PIN)", async () => {
    await init();
    const T_ISO = "2026-04-27T12:00:00Z";
    const T_MS = Date.UTC(2026, 3, 27, 12, 0, 0);
    const cap = Issuer.fromKey(ROOT_KEY)
      .issue("neq-now")
      .caveat(`tool == "x"`)
      .caveat(`now != @${T_ISO}`)
      .build();
    const auditor = new Auditor(AUDIT_KEY);
    const verifier = new Verifier(ROOT_KEY);
    // `now == T` so `now != T` is false → denied.
    const exact = verifier.verifyWithContext(
      cap,
      { caller: "a", tool: "x", args: {}, nowMs: T_MS },
      auditor,
    );
    expect(exact.outcome.kind).toBe("denied");
    // `now != T` holds → allowed.
    const off = verifier.verifyWithContext(
      cap,
      { caller: "a", tool: "x", args: {}, nowMs: T_MS + 1 },
      auditor,
    );
    expect(off.outcome.kind).toBe("allowed");
  });
});

// Suppress unused-import warnings for symbols we only use defensively.
void CapabilityChainError;
void CapabilityError;
void RevocationList;
