/**
 * Purple-team PoC for `docs/purple-team/03-capability-broadening.md`.
 *
 * Round 03 fires the `chain ✗` gate column. The structural defense:
 * the HMAC-SHA256 macaroon chain `sig_0 = HMAC(root_key, identifier);
 * sig_i = HMAC(sig_{i-1}, caveat_i.predicate)` is verifiable only by
 * a holder of the root key. Any modification to the serialized
 * capability that the holder did NOT re-authenticate (i.e. without
 * re-signing under the root key, which they can't — they don't have
 * it) MUST cause `Verifier.verify(...)` to throw `CapabilityChainError`
 * BEFORE any caveat evaluation, proof check, or audit signing runs.
 * The throw is the win condition; chain failures short-circuit
 * before audit signing so NO RECEIPT IS PRODUCED.
 *
 * # Threat model (one paragraph)
 *
 * A hostile holder has a legitimately-issued capability. They want to
 * USE more authority than they were granted: drop a caveat to widen
 * the predicate set, mutate a caveat's predicate text to relax a
 * bound (`amount <= 50` → `amount <= 5000`), splice in a signature
 * computed for a different (broader) cap, swap the signature with
 * one minted under a different root key they happen to control, or
 * forge a near-equivalent cap by minting under a wholly different
 * root key. None of these require breaking SHA-256 or HMAC-SHA256;
 * they just require the attacker to be willing to lie about which
 * cap they hold. capnagent's chain integrity check rejects every
 * such tamper-attempt at the FIRST gate, before any caveat
 * evaluation runs — there is no "almost valid, denied at caveat"
 * path that could leak a hint about which caveat is the tight one.
 *
 * # Why this test bypasses the wrapper
 *
 * `wrapMCPClient` always hands the verifier whatever cap bytes it
 * received, so the wrapper itself doesn't filter tampered tokens —
 * it relies entirely on the verifier's chain check. We model the
 * attacker by manipulating the serialized base64-JSON token directly
 * (the wire format is documented in `crates/capnagent-core/src/
 * capability.rs`: `URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cap))`)
 * and by using the public `Issuer` API to mint near-equivalent caps
 * under attacker-chosen keys. Every variant exercises a real WASM
 * verifier path; no mocks.
 *
 * # What the test does NOT cover (cross-reference round doc)
 *
 *   - Brute-force HMAC key recovery. Out of scope by cryptographic
 *     assumption — HMAC-SHA256 with a 32-byte key has no known
 *     practical attack better than 2^128 work. capnagent's defense
 *     is conditional on the operator using a CSPRNG-derived key of
 *     adequate length, which the `Issuer.fromKey` doc encourages.
 *   - Side-channel attacks against the HMAC implementation
 *     (timing, power, fault). Cryptographic-implementation domain;
 *     out of scope for the purple-team corpus. The Rust core uses
 *     `hmac::Mac::verify_slice` with constant-time comparison in
 *     contexts where comparison is needed, but here the verifier
 *     recomputes the chain and compares directly.
 *   - Length-extension attacks. HMAC is not vulnerable to length
 *     extension by construction (unlike raw SHA-256 prefix-MAC).
 *     Documented as not-applicable, not as out-of-scope.
 *   - Caveat-DSL semantic attacks (a tight predicate that's
 *     trivially satisfiable, e.g. `amount <= 9999999999`). Operator-
 *     responsibility; covered by Round 01-style cap-config rounds,
 *     not chain-integrity rounds.
 */

import { describe, expect, it } from "vitest";

import { Capability, CapabilityChainError, Issuer, Verifier, init } from "../index.js";

const ROOT_KEY = new Uint8Array(32).fill(0xc1);
const ALT_ROOT_KEY = new Uint8Array(32).fill(0xc2);

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
  // serde_json default ordering is field-declaration order: identifier,
  // holder_of_key (skipped if None), caveats, signature. We mirror that
  // by writing the keys back in the same order — the test does not
  // depend on order parity, but staying canonical avoids a tampered
  // cap accidentally having a *different* binary representation that
  // round-trips differently.
  const json = JSON.stringify(obj);
  return Buffer.from(json, "utf8").toString("base64url");
}

async function issueLegitCap() {
  await init();
  return Issuer.fromKey(ROOT_KEY)
    .issue("buy-broadening-test")
    .caveat(`caller == "agent:planner"`)
    .caveat(`tool == "checkout.purchase"`)
    .caveat(`arg.merchant == "amazon.com"`)
    .caveat("arg.amount <= 50")
    .caveat("now <= @2099-01-01T00:00:00Z")
    .build();
}

describe("Round 03: Capability broadening attempt", () => {
  describe("structural defense (HMAC chain integrity at the first gate)", () => {
    it("the legitimate, untampered cap verifies cleanly (negative hypothesis)", async () => {
      const cap = await issueLegitCap();
      const verifier = new Verifier(ROOT_KEY);
      // No throw. No receipt either — `verify(...)` returns void on
      // the chain-only path; a returned receipt would only come from
      // `verifyWithContext` / `verifyWithProof`. The point of this
      // negative leg is that the chain check passes silently when
      // nothing's been touched.
      expect(() => verifier.verify(cap)).not.toThrow();
    });

    it("variant 1 — single-byte flip in the middle of the serialized token THROWS CapabilityChainError", async () => {
      const cap = await issueLegitCap();
      const token = cap.serialize();

      // Flip one base64 character roughly in the middle. Any single-
      // character flip in a base64url-encoded JSON string either (a)
      // produces invalid JSON / invalid hex / invalid base64 — `parse`
      // throws and the wrapper maps that to a generic `CapabilityError`
      // (which is still a `CapabilityChainError` ancestor only via
      // `CapabilityError`, NOT a chain error directly), or (b) decodes
      // to a structurally-valid cap whose signature no longer matches
      // — `verify` throws `CapabilityChainError`. We retry with
      // different positions until we land on a flip that produces a
      // parseable-but-invalid cap, which is the case the threat model
      // cares about.
      const mid = Math.floor(token.length / 2);
      let threwChainError = false;
      for (let offset = 0; offset < 16 && !threwChainError; offset++) {
        const idx = mid + offset;
        const ch = token[idx];
        if (ch === undefined) continue;
        // Flip to 'A' if not already, else 'B' — both are valid base64url chars.
        const flipped = ch === "A" ? "B" : "A";
        const tampered = `${token.slice(0, idx)}${flipped}${token.slice(idx + 1)}`;
        try {
          const parsed = Capability.parse(tampered);
          new Verifier(ROOT_KEY).verify(parsed);
          // No throw means we accidentally hit the same byte (no flip
          // happened) — try the next offset.
        } catch (e) {
          // We want a chain-class throw specifically. A parse-class
          // throw (malformed base64 / JSON) is a different defense
          // gate; ignore those and keep searching.
          if (e instanceof CapabilityChainError) {
            threwChainError = true;
          }
        }
      }
      expect(threwChainError).toBe(true);
    });

    it("variant 2 — a caveat dropped from the wire format THROWS CapabilityChainError", async () => {
      const cap = await issueLegitCap();
      const token = cap.serialize();
      const wire = decodeToken(token);

      // Drop the tightest caveat (the amount bound). In the threat
      // model this is the highest-value caveat to drop — without it,
      // an attacker who otherwise satisfies caller/tool/merchant/expiry
      // would be able to spend any amount.
      const before = wire.caveats.length;
      wire.caveats = wire.caveats.filter((c) => !c.predicate.startsWith("arg.amount"));
      expect(wire.caveats.length).toBe(before - 1);

      const tamperedToken = encodeToken(wire);
      const tamperedCap = Capability.parse(tamperedToken);
      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(tamperedCap)).toThrow(CapabilityChainError);
    });

    it("variant 3 — a caveat's predicate text mutated (amount <= 50 → amount <= 5000) THROWS CapabilityChainError", async () => {
      const cap = await issueLegitCap();
      const wire = decodeToken(cap.serialize());

      // Find the amount caveat and broaden it. Any holder COULD
      // attenuate further (`amount <= 25`); the chain protects
      // against widening (`amount <= 5000`). Same byte length is
      // not required — we're not exploiting a length oracle, we're
      // just claiming the existing signature applies to a different
      // predicate, which it doesn't.
      const idx = wire.caveats.findIndex((c) => c.predicate.startsWith("arg.amount"));
      expect(idx).toBeGreaterThanOrEqual(0);
      wire.caveats[idx] = { predicate: "arg.amount <= 5000" };

      const tamperedCap = Capability.parse(encodeToken(wire));
      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(tamperedCap)).toThrow(CapabilityChainError);
    });

    it("variant 4 — signature field zeroed (last 32 bytes overwritten with 0x00) THROWS CapabilityChainError", async () => {
      const cap = await issueLegitCap();
      const wire = decodeToken(cap.serialize());

      // Hex-encoded 32-byte signature → 64 hex chars of zeros. An
      // attacker who has somehow corrupted the wire (or who is
      // probing for a fail-open code path) presents a cap with a
      // null signature and hopes the verifier short-circuits.
      wire.signature = "0".repeat(64);

      const tamperedCap = Capability.parse(encodeToken(wire));
      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(tamperedCap)).toThrow(CapabilityChainError);
    });

    it("variant 5 — signature spliced from a DIFFERENT cap (same root key, different caveats) THROWS CapabilityChainError", async () => {
      // Mint two distinct legitimate caps under the same root key.
      // Both verify on their own. Now splice cap-B's signature onto
      // cap-A's identifier+caveats and present that. The chain no
      // longer matches cap-A's content; the verifier rejects.
      const capA = await issueLegitCap();
      const capB = Issuer.fromKey(ROOT_KEY)
        .issue("buy-broadening-test-sibling")
        .caveat(`caller == "agent:planner"`)
        .caveat("arg.amount <= 9999")
        .build();

      const wireA = decodeToken(capA.serialize());
      const wireB = decodeToken(capB.serialize());
      // Splice B's signature into A's wire format.
      wireA.signature = wireB.signature;

      const splicedCap = Capability.parse(encodeToken(wireA));
      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(splicedCap)).toThrow(CapabilityChainError);
    });

    it("variant 6 — cap minted under a DIFFERENT root key, verified under the original root key THROWS CapabilityChainError", async () => {
      // The attacker controls a different root key entirely. They
      // mint a cap with the same identifier and caveats — internally
      // valid under THEIR key — and present it to a verifier set up
      // against the ORIGINAL key. The chain check rejects: same
      // structure, wrong HMAC root.
      await init();
      const forgedCap = Issuer.fromKey(ALT_ROOT_KEY)
        .issue("buy-broadening-test")
        .caveat(`caller == "agent:planner"`)
        .caveat(`tool == "checkout.purchase"`)
        .caveat(`arg.merchant == "amazon.com"`)
        .caveat("arg.amount <= 50")
        .caveat("now <= @2099-01-01T00:00:00Z")
        .build();

      // Sanity: verifier under the alt key DOES accept the forged
      // cap (it's internally valid; the keys just don't match).
      expect(() => new Verifier(ALT_ROOT_KEY).verify(forgedCap)).not.toThrow();
      // The actual round assertion: under the ORIGINAL root key, it
      // rejects.
      expect(() => new Verifier(ROOT_KEY).verify(forgedCap)).toThrow(CapabilityChainError);
    });

    it("variant 7 — siblings under same root (same identifier, different caveats) each verify on their own — proves verify is bound to ACTUAL caveats, not just the identifier", async () => {
      // This is the inverse of variant 5. Two caps sharing the same
      // root key and the same identifier but different caveat lists
      // are both legitimate (they were each properly built). Each
      // must verify on its own — the chain is over identifier +
      // caveats + (optional) hok, NOT over identifier alone, so two
      // caps with identical identifiers and different caveats have
      // different signatures and both pass independently.
      //
      // The negative property tested here: an attacker can NOT take
      // sibling A, replace its caveats with sibling B's caveats,
      // keep sibling A's signature, and have it pass — variant 5
      // already showed that. But siblings on their own each pass.
      const capA = Issuer.fromKey(ROOT_KEY)
        .issue("siblings-test")
        .caveat("arg.amount <= 50")
        .build();
      const capB = Issuer.fromKey(ROOT_KEY)
        .issue("siblings-test")
        .caveat("arg.amount <= 100")
        .build();

      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(capA)).not.toThrow();
      expect(() => verifier.verify(capB)).not.toThrow();

      // Cross-pollination: A's caveats with B's signature should fail.
      const wireA = decodeToken(capA.serialize());
      const wireB = decodeToken(capB.serialize());
      wireA.signature = wireB.signature;
      const crossed = Capability.parse(encodeToken(wireA));
      expect(() => verifier.verify(crossed)).toThrow(CapabilityChainError);
    });

    it("variant 8 — legitimate narrow-only attenuation followed by verify SUCCEEDS (negative hypothesis: defense doesn't over-tighten)", async () => {
      // The macaroon contract permits ATTENUATION (any holder can
      // narrow). This test confirms the chain check accepts a
      // legitimately-narrowed cap — capnagent doesn't deny every
      // post-issuance modification, just the broadening ones.
      const cap = await issueLegitCap();
      const narrowed = cap.attenuate("arg.amount <= 25");
      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(narrowed)).not.toThrow();

      // Stack two more attenuations to confirm the chain still walks.
      const doubleNarrowed = narrowed
        .attenuate(`arg.merchant == "amazon.com"`)
        .attenuate("arg.amount <= 10");
      expect(() => verifier.verify(doubleNarrowed)).not.toThrow();
    });
  });

  describe("audit trail (or absence of)", () => {
    it("chain failures throw BEFORE audit signing — no receipt is produced for any tampered variant", async () => {
      // The deliberate asymmetry from `verifyWithContext`/
      // `verifyWithProof`: caveat denials produce a SIGNED denial
      // receipt that's auditable; chain failures THROW with no
      // receipt. The rationale (DESIGN.md §11): a failed chain
      // means the cap is forged or corrupt — there is no
      // legitimate audit trail to sign because there is no
      // legitimate cap. Producing a receipt for a chain failure
      // would mean the auditor key signs over a forgery, which is
      // exactly the wrong primitive.
      //
      // This test asserts that property end-to-end: every chain-
      // failure variant from this round throws and never returns
      // a receipt. We don't even need an Auditor in scope —
      // `Verifier.verify(cap)` is the chain-only entry point and
      // doesn't take one.
      const cap = await issueLegitCap();
      const wire = decodeToken(cap.serialize());

      // Run all the same variants that should throw and confirm
      // none of them surface a receipt.
      const tamperedVariants: Array<() => Capability> = [
        // Caveat dropped.
        () => {
          const w = { ...wire, caveats: wire.caveats.slice(0, -1) };
          return Capability.parse(encodeToken(w));
        },
        // Caveat predicate widened.
        () => {
          const w = {
            ...wire,
            caveats: wire.caveats.map((c, i) =>
              i === wire.caveats.length - 1 ? { predicate: "now <= @9999-01-01T00:00:00Z" } : c,
            ),
          };
          return Capability.parse(encodeToken(w));
        },
        // Signature zeroed.
        () => Capability.parse(encodeToken({ ...wire, signature: "0".repeat(64) })),
      ];

      for (const make of tamperedVariants) {
        const tampered = make();
        const receipt: unknown = "no-receipt-produced";
        try {
          new Verifier(ROOT_KEY).verify(tampered);
          // If we got here without throwing, the verifier accepted
          // a tampered cap — that's a SECURITY FAILURE the test
          // would catch. (The chain check returns void, not a
          // receipt, so there is literally nothing to capture; we
          // assert the throw instead.)
          throw new Error("verifier accepted a tampered cap");
        } catch (e) {
          // Confirm we got the right error class. The variants
          // here all hit chain failures (not parse failures), so
          // the wrapper maps them to CapabilityChainError per the
          // table in `index.ts > mapWasmError`.
          expect(e).toBeInstanceOf(CapabilityChainError);
        }
        expect(receipt).toBe("no-receipt-produced");
      }
    });
  });

  describe("residual risk (honest acknowledgment of what this defense does NOT cover)", () => {
    it("AN ATTACKER WHO HAS THE ROOT KEY CAN MINT ANY CAP THEY WANT — chain integrity is not a key-management defense", async () => {
      // The whole defense rests on the root key being secret. If
      // the operator leaks the key (committed to git, stolen from
      // env, exfiltrated by a compromised CI runner), the attacker
      // mints arbitrary caps and they ALL pass `verify`. capnagent
      // has nothing to say about this attack class — it's an
      // operator-side key-management problem.
      //
      // This test makes that residual risk explicit: when the
      // attacker has the key, the whole gate cascade goes green
      // even on a nominally-malicious cap. The defense fails not
      // because of a bug; because the assumption broke.
      await init();
      const stolenKey = ROOT_KEY; // In real life this is a leak.
      const arbitraryCap = Issuer.fromKey(stolenKey)
        .issue("attacker-controlled-id")
        .caveat("arg.amount <= 999999999")
        .build();

      const verifier = new Verifier(ROOT_KEY);
      expect(() => verifier.verify(arbitraryCap)).not.toThrow();
    });

    it("the chain check is BLIND to whether the caveats are tight or loose — verify says nothing about authorization scope, only about authenticity", async () => {
      // Operators who issue overly-broad caveats (`arg.path matches
      // "~"`) will see the chain pass on those too — chain integrity
      // does not gate on caveat semantics. Round 01 covers the
      // caveat-tightness story; this round only covers chain
      // integrity. We document the boundary explicitly so reviewers
      // don't conflate the two.
      const overlyBroadCap = Issuer.fromKey(ROOT_KEY)
        .issue("overly-broad")
        .caveat(`arg.path matches ""`) // matches anything
        .build();
      expect(() => new Verifier(ROOT_KEY).verify(overlyBroadCap)).not.toThrow();
    });
  });
});
