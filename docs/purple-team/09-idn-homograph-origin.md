# Round 09 — IDN homograph in origin allowlist

> Round 05 closed `holds-with-caveat` for the http-agent's origin-bounded
> cap. Round 05's coverage section flagged "IDN/punycode homograph" as
> not-yet-tested — round 09 tests that gap.
>
> The validator (`isExactOrigin`) accepts a punycode-form IDN homograph
> in `allowedOrigins` without any IDN-confusable check. An operator who
> was tricked into pasting a homograph URL (visually identical to the
> legitimate ASCII origin, semantically a different host) issues a cap
> that allows agent calls to the attacker host AND denies calls to the
> legitimate ASCII origin they believed they were allowing.
>
> **Status: BREAKS.** Recommended fix is in `isExactOrigin`: extend it
> with an ASCII-only-label check (simple, but rejects all legitimate
> IDN deployments) OR with a TR39-aware mixed-script / confusable
> detector (permissive, more complex). Fix is NOT shipped — this round
> documents the gap.

```text
Attack class:     CWE-1007 (Insufficient Visual Distinction of
                  Homoglyphs Presenting to User);
                  CWE-602 (Client-Side Enforcement of Server-Side
                  Security — analogue here is "structural-form
                  enforcement of operator-intent semantics");
                  OWASP A04:2021 (Insecure Design);
                  Unicode TR39 (Unicode Security Mechanisms) §5
                  (Confusable Detection).
Hypothesis:       Positive (true-positive): given an operator who passes
                  an IDN homograph (Cyrillic-а variant of the legitimate
                  ASCII origin) to `issueOriginScopedGetCapability`,
                  issuance MUST surface a warning OR reject the input
                  with a message that mentions IDN / homograph /
                  mixed-script / confusable, so the operator can tell
                  WHY the input was suspicious (rather than seeing only
                  a "not an exact origin" error that doesn't explain
                  what's wrong).

                  Negative (true-negative): the same operator passing
                  the clean ASCII origin behaves exactly as round 05
                  expects — legitimate ASCII GETs are allowed, homograph
                  GETs from the agent are denied.

                  The positive hypothesis is EXPECTED TO FAIL — that's
                  the round's central finding. `isExactOrigin` has no
                  IDN check; the punycode form sails through and a
                  homograph-allowing cap is issued silently.
Test (PoC):       examples/mcp-http-agent/src/__tests__/idn-homograph-origin.purple.test.ts
Coverage:         Tested variants:
                    - empirical pin: `new URL("https://" + Cyrillic-а
                      + "pi.example.com").origin` returns the punycode
                      form `https://xn--pi-6kc.example.com` (Node's
                      WHATWG-conformant IDNA-2008 resolution)
                    - empirical pin: punycode of homograph is NOT
                      equal to the legitimate ASCII origin (visual
                      similarity, semantic difference)
                    - foot-gun (a): operator pastes raw unicode
                      homograph in allowlist → issuance throws, BUT
                      the error message says only "not an exact origin"
                      with no mention of IDN / homograph / unicode /
                      punycode / confusable. Pinned via negative
                      regex match — accidental partial defense, NOT
                      principled rejection.
                    - foot-gun (b): operator pastes PUNYCODE form of
                      homograph in allowlist → issuance succeeds
                      WITHOUT WARNING. The realistic exploitation
                      path: any URL-canonicalizing tooling (browser,
                      CLI, JSON loader) silently converts unicode
                      input to punycode before the operator sees it.
                    - resulting cap allows agent http.get to the
                      homograph host (localhost-stubbed; would be
                      attacker-controlled in production)
                    - resulting cap DENIES agent http.get to the
                      legitimate ASCII origin (the operator's actual
                      intent) — visceral expression of the foot-gun
                    - negative-half regression: clean ASCII allowlist
                      allows ASCII GETs and denies homograph GETs
                      emitted by the agent (round 05 still holds)
                    - visual-confusion catalog: Cyrillic-н in
                      `exaнple.com` follows the same shape; benign
                      ASCII control case (`https://example.com`)
                      passes; mixed-script label (Latin + Cyrillic in
                      same DNS label) is also accepted in punycode
                      form
                    - threat-surface pin: receipts only describe
                      allow/deny outcomes; the engine has no signal
                      for "your allowlist contains a homograph"
                  Not yet tested:
                    - other confusable codepoint pairs from the full
                      Unicode TR39 catalog (Greek omicron vs Latin o,
                      Latin l vs digit 1, etc.). Spot-coverage of
                      Cyrillic а/н establishes the pattern; full
                      catalog coverage would be a corpus-pass project,
                      not a gate-test.
                    - mixed-script labels via NFKC-normalizable
                      compatibility-decomposition tricks (e.g. Latin
                      ﬁ ligature → Latin fi). `URL` does NFC, not
                      NFKC, so these can survive in domain labels
                      with a different attack shape.
                    - bidi-control characters in domain labels
                      (RLO/LRO/PDF). Browsers strip these from IDN
                      labels; Node's `URL` mostly does too, but the
                      attack-surface mapping for capnagent's
                      operator-config layer is not characterized.
                    - the engine-side fix itself (since it isn't
                      shipped). When/if a fix lands, those tests go
                      in this PoC's Run-2 section and the round flips
                      BREAKS → CLOSED.
                    - operator UX of the proposed fix: does the
                      ASCII-only error, or the TR39 mixed-script
                      diagnostic, ACTUALLY deflect the operator from
                      pasting the homograph anyway? "Helpful error
                      message" is a UX claim that needs UX testing.
Known-bypasses:   - LEGITIMATE IDN DEPLOYMENTS. An ASCII-only fix
                    rejects every non-ASCII domain (`https://普及.cn`,
                    `https://正規.jp`). For operators serving a
                    user base in non-Latin scripts, ASCII-only is too
                    aggressive. The TR39 mixed-script approach lets
                    single-script IDN labels through and only flags
                    cross-script confusables — but it requires the
                    operator (and the engine) to understand the
                    distinction.
                  - OPERATOR PASTES THE HOMOGRAPH ANYWAY. No engine
                    check defeats determined operator misuse. The
                    bar is "make the failure mode visible at deploy
                    time," not "make it impossible." Same shape as
                    round 06.
                  - SINGLE-SCRIPT NON-LATIN HOMOGRAPHS. If both the
                    legitimate and attacker hosts are wholly in (e.g.)
                    Cyrillic, a TR39 mixed-script check finds nothing
                    suspicious. Confusable-pair detection within a
                    single script is more expensive and more
                    error-prone than mixed-script detection. Out of
                    scope for the proposed fix.
                  - REGISTRY-LEVEL DEFENSES. Most modern TLDs reject
                    or restrict mixed-script registrations at the
                    registry layer (e.g. Verisign's IDN policy on
                    .com prevents Cyrillic-а in pure-Latin labels for
                    new registrations). capnagent runs in a different
                    trust layer; it cannot rely on registry policy
                    being correctly enforced for every host the
                    operator allowlists.
                  - DNS REBINDING / TLS CERT VALIDATION. The cap
                    gates the host the agent presents. Whether the
                    actual fetch reaches the host the operator MEANT
                    is a layer-4/7 concern (DNS, TLS) handled outside
                    capnagent.
Re-validate-by:   2026-10-27   (6 months from BREAKS date; re-run
                                checks for engine fix landing AND
                                regression of the structural origin
                                check)
Owner:            blue-lead
Status:           BREAKS — 2026-04-27 (Run 1 BREAKS; awaiting fix)

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-27 02:34 UTC                              [FAIL]
  Env:          Windows 11 + Node 20.x + capnagent v0.4 worktree
                + in-process HttpClient (mcp-http-agent example,
                fetch routed through a localhost-bound rewriting
                stub that never touches real network). Bearer-token
                cap (no hok); no NonceStore, no RevocationList for
                this round.
  Gates:        chain ✓ | proof - | replay - | revoke - | caveat ✓
                  Chain integrity passed (cap is well-formed; the
                  punycode-form origin in the allowlist is structurally
                  valid). Proof / replay / revoke legs not applicable.
                  Caveat gate ALLOWED the homograph http.get because
                  arg.origin (parsed from the unicode URL) normalizes
                  to the same punycode the cap was issued for. The
                  gate is doing exactly what it was designed to do —
                  the GAP is at issuance, not at verification.
  Decision:     ALLOWED — outcome.kind = "allowed" for the homograph
                  http.get. Negative-hypothesis half held (clean
                  ASCII allowlist allows ASCII GET, denies homograph
                  GET — round 05 still holds).
                Expected (positive hypothesis): issuance to surface
                  an IDN-confusable warning OR reject the punycode
                  form with a message that mentions IDN / homograph /
                  punycode / confusable.
                Observed: issuance succeeds silently. The cap is
                  built without complaint and behaves as a permissive
                  cap for the attacker's host.
  Latency:      n/a — the gap is at issuance (a synchronous
                validator function), not at verify-with-context.
                Verifier latency unchanged from round 05.
  FP-7d:        N/A — this round measures a defense BREAK at
                issuance, not ongoing operational behavior.
  Gap-class:    DEFENSE-LOGIC + OPERATOR-MISCONFIG (joint, same
                shape as round 06)
                  DEFENSE-LOGIC half: `isExactOrigin` checks
                  structural canonical form (no path, no userinfo,
                  matches `URL.origin`) but does no Unicode-script
                  analysis. A punycode-form homograph is canonical
                  by `URL.origin` and passes. The validator has no
                  way to express "this string is structurally
                  fine but visually confusable with a host you
                  probably did NOT mean to allow."
                  OPERATOR-MISCONFIG half: the operator pasted a
                  URL into config that they thought was correct.
                  Joint classification because either half alone
                  would be fine. The intersection is the failure
                  mode.
  Gap:          `isExactOrigin` accepts any URL that round-trips
                through `new URL().origin`. IDN labels (in punycode
                form) round-trip cleanly. The validator therefore
                cannot distinguish legitimate IDN registrations
                (`https://xn--zckzah.test` for `日本語.test`) from
                homograph attacks (`https://xn--pi-6kc.example.com`
                for the Cyrillic-а variant of `api.example.com`).
                Compounded by: standard URL-handling tooling
                (clipboards, address bars, JSON loaders, YAML
                parsers, CLI tools) silently canonicalizes unicode
                input to punycode form, so the operator never SEES
                the unicode they pasted — they see the
                ASCII-looking punycode and have no signal that
                anything was substituted.
  Action:       Round 09 OPENS the engine v0.5 work. The fix is in
                `examples/mcp-http-agent/src/index.ts`'s
                `isExactOrigin` (or, more correctly, in a shared
                helper at the engine layer that any origin-scoped
                cap helper can call). Two paths considered:

                  PATH A (smaller fix now): require ASCII-only
                  labels. Reject any allowlist origin whose
                  punycode form starts with `xn--` OR whose host
                  contains characters outside [a-z0-9.-].
                    Pros: trivial to implement (~5 LOC), zero
                          dependencies, deterministic.
                    Cons: rejects every legitimate IDN. For an
                          operator serving https://普及.cn, this
                          is a non-starter. Forces the operator
                          to type `xn--` every time, which is
                          exactly the kind of footgun that
                          encourages bypass.

                  PATH B (larger fix later): TR39-aware
                  mixed-script / confusable detection.
                  Implement (or import) a Unicode TR39 §5
                  confusable detector. Reject inputs whose
                  decoded labels mix scripts in ways flagged by
                  TR39, OR (stronger) reject any input whose
                  decoded form is confusable with another label
                  in the same allowlist.
                    Pros: permissive of legitimate IDN
                          deployments, principled, matches
                          browser-vendor UX.
                    Cons: complex; requires TR39 data tables
                          (Unicode confusables.txt); engine
                          dependency cost; potential FP-7d burden
                          if the detector flags real
                          deployment-time labels.

                The round doc recommends path B for the engine
                v0.5 work, with path A as a near-term mitigation
                operators can apply at config-load time without
                waiting for the engine fix. Neither is shipped
                here; this round documents the gap.
```

## Evidence

- **Runnable PoC:** [`examples/mcp-http-agent/src/__tests__/idn-homograph-origin.purple.test.ts`](../../examples/mcp-http-agent/src/__tests__/idn-homograph-origin.purple.test.ts) — 13 deterministic tests, all passing (the "FAIL" is the SCENARIO outcome, not the test outcome — the tests successfully demonstrate the defense break).
- **Evidence JSON:** [`evidence/09-idn-homograph-origin.json`](evidence/09-idn-homograph-origin.json) — multi-fact evidence bundle. Includes the empirical `URL.origin` resolution of the Cyrillic-а homograph, the punycode form of the allowlist input, and BOTH the allowed-receipt for the homograph http.get AND the denied-receipt for the legitimate ASCII http.get. The juxtaposition of the two receipts (same cap, opposite outcomes for visually-identical URLs) is the visceral evidence of the foot-gun.
- **Regen script:** `npm run -w @capnagent-examples/mcp-http-agent regen-purple-evidence-09`
- **Linked round:** Round 05 documented this as known-not-tested coverage; round 09 programmatically proves the gap and surfaces the foot-gun shape.

## Notes

### Threat model elaboration

The attacker doesn't need network privileges, a compromised model, or even a successful prompt injection. They just need to convince the OPERATOR to copy a URL string into the allowlist. Realistic attack surfaces:

- Phishing email: "Hi, I'm from the api.example.com team — please add `https://api.example.com` (with Cyrillic а) to your agent's allowlist for the new beta endpoint."
- Compromised vendor documentation: a config-snippet template on a partner's docs page contains a homograph URL.
- Compromised CI/CD config (terraform/yaml/etc.): the homograph is committed to a config file by a compromised contributor; humans reviewing the diff don't notice the codepoint substitution.
- Internal-tool autocomplete that suggests the wrong host: a tool pulls candidate hosts from a poorly-curated source (browser history, OS keychain, a wiki page, an LLM chat-completion) that includes attacker-controlled entries.

In all cases, the operator BELIEVES they are allowlisting `api.example.com`. The bytes on disk say otherwise. capnagent's validator never tells them.

### Why `URL.origin` returns punycode (and why that matters)

Node's `URL` constructor follows the WHATWG URL Living Standard, which mandates IDNA-2008 encoding for non-ASCII domain labels: every codepoint outside [A-Z, a-z, 0-9, '-', '.'] gets replaced by its punycode (xn--…) form on `URL.origin`. This is correct for serialization — the punycode IS what goes into the DNS query. But for origin-allowlist matching, it has a perverse consequence: the operator's intent is encoded in human-readable text, but the validator's comparison is against a wire-format string that humans cannot read. The two pictures of the same host disagree.

The empirical pin in the PoC catches a future Node version that changes this. Both an IDNA regression (origin no longer punycode) and a normalization regression (different punycode for the same input) would surface as test failures.

### Severity framing

Triggering this requires no malicious actor inside the trust boundary. The operator pattern is "paste a URL from a trusted-looking source into config." Severity is HIGH because:

1. The bar to trigger is low — pasting a URL.
2. The visual confusion is empirically perfect — the Cyrillic а and Latin a are typographically indistinguishable in every monospace and proportional font on every modern OS.
3. The consequence is total — the cap allows the attacker's host AND denies the operator's intended host, so legitimate work breaks at the same moment exfiltration is enabled.
4. The detection signal is zero from inside the engine — receipts say "allowed" with the punycode origin, which the operator wouldn't recognize as suspicious without independent IDN literacy.

This is the same severity shape as round 06: a routine operator action lands in a state where a defense the operator believes is in place is silently absent.

### Defender-actionable

For an operator using capnagent's http-agent today (until the engine fix lands):

1. **Do not paste URLs into `allowedOrigins` from untrusted sources.** Treat allowlist edits as security-sensitive code review, not configuration.
2. **At config-load time, reject any allowlist origin whose host starts with `xn--`.** This is path-A in miniature. It will reject legitimate IDN deployments — if you serve one, this is not the right mitigation for you. If you serve only ASCII, this is a one-line guard with high payoff.
   ```ts
   for (const o of allowedOrigins) {
     const u = new URL(o);
     if (u.hostname.split(".").some((label) => label.startsWith("xn--"))) {
       throw new Error(`config rejects IDN host: ${o}`);
     }
   }
   ```
3. **Visually inspect the bytes of any pasted URL.** `cat config.json | xxd | head` — the codepoints reveal the substitution. This is a forensic check, not a preventive one; do it as part of incident response, not routine review.
4. **Pin allowlist origins as canonical strings in source code, not as values pulled from runtime config.** A homograph in a TypeScript source file is reviewable in `git diff`; a homograph in a runtime config file is not.
5. **Monitor allow-receipts for unexpected `xn--` prefixes in `arg.origin`.** A spike in allowed http.get calls whose `arg.origin` is a punycode host the operator didn't intend to allowlist is a high-signal indicator.
6. **When the engine fix lands**, switch to whichever path (A or B) matches your deployment's threat model. Most production deployments will want path B (TR39 mixed-script detection) because it handles both legitimate IDNs and confusables. ASCII-only deployments can keep using path A as a stricter override.

### Source research

- Unicode TR39 (Unicode Security Mechanisms) — the canonical specification for confusable detection. Section 5 (Confusable Detection) describes the algorithm; section 4 (Restriction Levels) describes mixed-script categories.
- WHATWG URL Living Standard — defines the IDNA-2008 mapping `URL` constructor uses on non-ASCII labels. Browsers, Node's `URL`, and most language stdlibs agree on the punycode form for the inputs this round tests.
- CWE-1007 (Insufficient Visual Distinction of Homoglyphs Presenting to User) — the parent CWE category. CWE's framing focuses on user-facing distinction; capnagent's case is operator-facing, but the mechanism is identical.
- Eric Lawrence, *IDN Homograph Attacks* (Microsoft Edge security blog) — describes the same attack class against URL bars; documents the "tooling silently canonicalizes to punycode" failure mode that makes the operator-config foot-gun realistic.
- Mozilla, *About IDN Display Algorithm* — the most rigorous deployed implementation of TR39-style confusable detection. A reference for what path-B looks like in production.
- Round 05 (`docs/purple-team/05-cross-origin-exfil.md`) — the closing-with-caveat round whose `Not yet tested:` section flagged this exact gap. Round 09 fulfills that flag.
- Round 06 (`docs/purple-team/06-silent-bypass-revocation-install.md`) — same operator-error class shape; differs in attack surface (revocation install vs. allowlist hygiene) but identical "operator-action lands in unsafe state with no engine signal" structure.
