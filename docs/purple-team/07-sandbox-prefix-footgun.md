# Round 07 — fs-sandbox prefix foot-gun (round 01 failure mode)

> Round 01 closed `holds-with-caveat` for the fs-sandbox defense and
> noted as residual risk that the caveat DSL's `matches` operator is
> substring containment, not path-aware prefix matching. Round 01's
> PoC sidestepped the issue with per-test random tempdirs. This round
> tests what happens when an operator picks a sandbox prefix that
> *looks* like a path-prefix but accidentally also permits reads to
> unrelated directories whose absolute paths contain the prefix as a
> substring. The defense breaks. **Status: BREAKS.** Recommended fix
> is engine-side: a path-aware `starts_with` DSL operator and/or a
> Context-provider canonicalization step. Documented here, not shipped.

```text
Attack class:     OWASP A04:2021 (Insecure Design); CWE-22 (Improper
                  Limitation of a Pathname); CWE-693 (Protection
                  Mechanism Failure). Adjacent to CWE-185 (Incorrect
                  Regular Expression) — the DSL's `matches` is named
                  like a regex/pattern operator but implemented as
                  substring containment, which mismatches operator
                  expectations for path-prefix scoping.
Hypothesis:       Positive (true-positive): given a cap issued via
                  `issueSandboxReadCapability({ sandboxPrefix: P,
                  caller })`, a `read_file` call whose `arg.path` is a
                  SIBLING/LATERAL path containing P as a substring
                  (but NOT a child of the sandbox dir) MUST be DENIED
                  at the gate.

                  Negative (true-negative): the same cap continues to
                  ALLOW legit in-sandbox paths (`<sandbox>/config.json`)
                  and DENY obviously-out-of-sandbox paths whose
                  absolute path does NOT contain P as a substring
                  (`<root>/home/user/ssh/fake-id-rsa-PRETEND-SECRET`).

                  The positive hypothesis is EXPECTED TO FAIL — that
                  is the round's central finding. The PoC asserts the
                  failing outcome (the read returns content; the
                  receipt is `allowed`) so the test passes when the
                  bug is present and would fail loudly if the engine
                  ever gained path-aware semantics — useful as
                  regression coverage for any future fix.
Test (PoC):       examples/mcp-fs-agent/src/__tests__/sandbox-prefix-footgun.purple.test.ts
Coverage:         Tested variants:
                    - lateral path with prefix as substring
                      (`<root>/etc/srv/app-leaked-secret/...` against
                      `<root>/srv/app` cap) — allowed (THE BUG)
                    - trailing-character collision
                      (`<root>/srv/app-shadow/...` against
                      `<root>/srv/app` cap) — allowed (related shape)
                    - embedded-prefix path
                      (`<root>/var/log/srv/app/backup/...`) — allowed
                      (substring fires mid-string)
                    - cross-tool: list_directory on a lateral dir
                      uses the same caveat clause; same bug fires
                    - negative: legit `<sandbox>/config.json` allowed
                      (hypothesis-negative pin)
                    - negative: obviously-out-of-sandbox path denied
                      (round 01 regression coverage)
                    - negative: write_file remains denied for ALL
                      paths (no clause permits writes — isolates the
                      bug to the read-tool clauses)
                    - issuance gap: `issueSandboxReadCapability`
                      accepts foot-gun-able prefixes
                      (`/srv/app`, `/var/log`, `/usr/lib`,
                      `C:\srv\app`) without warning, while still
                      rejecting too-short prefixes (`/tmp`, `/tmp/x`)
                      and prefixes with no separator (`abcdefghij`)
                  Not yet tested:
                    - URL-encoded path traversal (`%2e%2e%2f`) —
                      orthogonal class; the substring caveat doesn't
                      decode and the underlying fs client doesn't
                      either, so URL-encoding alone is not exploitable
                      here, but worth a sibling round.
                    - Unicode-confusable lookalikes (homoglyphs that
                      LOOK like the sandbox prefix but aren't, e.g.
                      Cyrillic `а` vs Latin `a`). Substring containment
                      would NOT match a homoglyph against an ASCII
                      prefix — a different failure mode.
                    - Symlink escape from inside the sandbox: a
                      symlink at `<sandbox>/escape` pointing to
                      `/etc/passwd`. The caveat is path-string-based;
                      filesystem dereference is OS-level and would
                      happen at the underlying client. OS-level
                      canonicalization is the fix — this round
                      documents it, doesn't test it.
                    - Rust-side equivalent. The same `String::contains`
                      lives at `crates/capnagent-core/src/caveat_dsl.rs`
                      line ~752; the same finding holds for the Rust
                      verifier path. A sibling Rust PoC would mirror
                      this TS test.
                    - Effect of the recommended `starts_with` operator
                      after it lands (regression coverage for the fix
                      — round CLOSES on Run 2 once the engine fix
                      ships).
Known-bypasses:   - The bug IS the bypass. Documenting limits of
                    THIS round's claim:
                    - Operator-aware mitigation (canonicalize then
                      compare in the Context provider) prevents the
                      lateral case but requires every operator to
                      know the foot-gun exists. Round-01-style random
                      tempdir suffixes also prevent it — but only
                      because no real-world filename would contain
                      the suffix by chance, not because the gate is
                      path-aware.
                    - The issuance validator's existing length+separator
                      check catches the WORST shapes (`/tmp`,
                      `abcdef`). It does NOT catch the realistic
                      production shapes (`/srv/app`, `/var/log`).
                      Tightening the validator alone is insufficient —
                      a path-aware caveat semantic is the proper fix.
                  - Out-of-scope: malicious operators. Threat model
                    is operator-mistake / operator-config-drift, not
                    adversarial operators.
                  - Out-of-scope: model-side prompt injection. The
                    bug fires regardless of how the agent was induced
                    to issue the lateral-path call. (Compare round
                    01's framing: the model-vs-cap distinction is
                    irrelevant when the cap itself is too permissive.)
Re-validate-by:   2026-10-27   (default 6 months from BREAKS date.
                                Re-validation will check whether the
                                engine fix has shipped and, if so,
                                flip Status to CLOSED via Run 2 in
                                the same round-06 BREAKS→CLOSED
                                pattern.)
Owner:            blue-lead
Status:           BREAKS — 2026-04-27. Substring-containment caveat
                  semantics are not path-aware; cap issuance accepts
                  prefixes that produce collisions with realistic
                  unrelated paths. Engine fix is documented below
                  (Action) but not shipped in this round.

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-27 UTC                                    [FAIL]
  Env:          Windows 11 + Node 20.x + capnagent v0.4
                + @capnagent/core (real WASM via wasm-pack pkg)
                + in-process fs client (createFsClient)
  Gates:        chain ✓ | proof - | replay - | revoke - | caveat ✓ (incorrectly allows lateral path)
                  Chain integrity passes (the cap is a valid
                  signed cap from the demo root key). Proof and
                  replay don't apply (bearer-token cap, no hok).
                  Revocation list isn't installed — out of scope
                  for this round. The caveat gate is the failure
                  point: it evaluates `arg.path matches "<prefix>"`
                  as `path.contains(prefix)`, which returns true
                  for the lateral path even though the path is not
                  a child of the sandbox dir.
  Decision:     ALLOWED — outcome.kind = "allowed".
                  Expected (positive hypothesis): DENIED with reason
                            matching /caveat failed/.
                  Observed: ALLOWED. The lateral path
                            `<root>/etc/srv/app-leaked-secret/PRETEND-SECRET`
                            is read; the underlying fs client sees
                            the call; the receipt records `allowed`.
                  Negative hypothesis HELD as expected: legit
                  in-sandbox reads succeed, obviously-out-of-sandbox
                  reads (no prefix substring) are still denied.
                  This is the round 01 regression coverage.
  Latency:      ~11 µs (verify_with_context bench mean — same as
                round 01; substring containment is O(n) in path
                length but inputs are tiny).
  FP-7d:        N/A — this round measures a defense BREAK, not
                ongoing operational behavior. The "false-positive"
                framing is inverted here: the bug IS the false-
                negative (denial that should fire, doesn't).
  Gap-class:    DEFENSE-LOGIC + CAPABILITY-CONFIG (joint).
                  DEFENSE-LOGIC: the DSL's `matches` operator
                  semantic (substring containment) is fundamentally
                  not path-aware. No amount of operator vigilance
                  fully closes this — only a string suffix-trick
                  (always end the prefix with a separator) reduces
                  it, and even that fails for embedded-mid-path
                  collisions like `<root>/var/log/srv/app/...`.
                  CAPABILITY-CONFIG: the issuance validator accepts
                  the foot-gun-able prefix without surfacing the
                  risk. A clean-looking `/srv/app` slips through.
                  Joint classification because either half alone
                  would be marginally fixable; the intersection is
                  the failure mode in the field.
  Gap:          The caveat DSL has no path-aware comparison
                operator. `matches` is named like it should imply
                semantic matching but is in fact substring
                containment, mismatching operator expectations for
                path-prefix scoping. Compounded by: the example's
                issuance helper validates only length and separator
                presence, not path-prefix realism — so an operator
                copying the round-01 docstring pattern with a
                production-shaped prefix (`/srv/app`, `/var/www`,
                `/home/svc`) gets a silently-broken cap.
  Action:       Round OPENS the engine v0.5 work. Two-part fix:

                (1) DSL operator. Add a `starts_with` operator to
                    the caveat DSL whose semantic is *prefix*
                    (not substring), normalized to forward-slashes
                    for cross-platform consistency. Example:

                        arg.path starts_with "/srv/app/"

                    Note the trailing separator — required by the
                    operator's contract to prevent the trailing-
                    character collision shape. The operator MUST
                    reject prefixes that don't end in a separator
                    so operators can't accidentally regress to the
                    substring foot-gun.

                (2) Context-provider canonicalization. Update
                    `createGuardedFsClient` in
                    `examples/mcp-fs-agent/src/index.ts` so the
                    `context` callback canonicalizes `arg.path`
                    BEFORE the verifier evaluates the caveat:
                    resolve symlinks, eliminate `..`, normalize
                    separators (Windows `\` → `/`), uppercase
                    drive letters on Windows. Then the caveat
                    compares canonical-against-canonical.

                Both halves are needed. The DSL operator gives
                operators a correct primitive; the Context
                canonicalization defends against
                `..`/symlink/encoded-separator shapes that even a
                correct prefix operator would otherwise miss.

                When the fix lands, this PoC's positive-hypothesis
                tests INVERT: the lateral/trailing/embedded reads
                should now be DENIED. The PoC's three "the bug" `it`
                blocks become regression coverage for the fix; the
                negative-hypothesis `it` blocks stay green as-is.
                Round status flips BREAKS → CLOSED via a Run 2.

                Engine v0.5 is NOT shipped in this round — Round 07
                only documents the failure and the recommended
                shape of the fix.
```

## Evidence

- **Runnable PoC:** [`examples/mcp-fs-agent/src/__tests__/sandbox-prefix-footgun.purple.test.ts`](../../examples/mcp-fs-agent/src/__tests__/sandbox-prefix-footgun.purple.test.ts) — deterministic tests, all passing. The "FAIL" is the SCENARIO outcome, not the test outcome — the tests successfully demonstrate the defense break.
- **Receipt JSON:** [`evidence/07-sandbox-prefix-footgun.receipt.json`](evidence/07-sandbox-prefix-footgun.receipt.json) — the `allowed` receipt produced for a lateral-path read that should have been `denied`. The visceral evidence of the bug.
- **Regen script:** `npm run -w @capnagent-examples/mcp-fs-agent regen-purple-evidence-07`
- **Linked rounds:** Round 01 (`docs/purple-team/01-tool-description-injection.md`) documented this as a residual risk; round 07 programmatically proves it. Round 06 (`docs/purple-team/06-silent-bypass-revocation-install.md`) established the BREAKS→CLOSED pattern within an engine cycle; round 07 follows the same shape, with the fix deferred to engine v0.5.

## Notes

### Why this round matters

Round 01 was honest about the residual risk in the docstring of `issueSandboxReadCapability` and in its `Note on matches` comment in `examples/mcp-fs-agent/src/index.ts`. But "honest about a residual risk in a comment" is not the same as "the failure mode is reproducibly demonstrated and the engine fix is scoped." Round 07 produces the visceral evidence — a receipt with `outcome.kind === "allowed"` for a path that the operator believed was outside the sandbox — and turns the docstring-level acknowledgment into a structured BREAKS round with a documented engine-fix path.

This is the second round in the corpus to BREAK (after round 06's silent-bypass-on-install). The BREAKS pattern is what the angles methodology is built for: rather than re-confirming a structural defense holds against another attack shape, the round tests *the defense's failure modes when realistic operator config patterns interact with the actual semantics of the implementation*.

### Severity framing

Triggering this requires no malicious actor and no model compromise. The operator pattern is the obvious one:

```ts
const cap = issueSandboxReadCapability({
  sandboxPrefix: "/srv/app",  // a real production path, not /tmp/random-suffix
  caller: "agent:fs",
});
```

That's not adversarial code — that's literally what an operator would write reading the round-01 docs without internalizing the substring footnote. Severity is HIGH because the bar to trigger is low (one line of typical operator code), the consequence (lateral-directory reads to anything sharing a substring) is exactly what the sandbox is supposed to prevent, and round 01's `holds-with-caveat` framing arguably understated this — the round-01 PoC's random-tempdir choice avoided the collision class altogether, which made the defense look path-aware when it isn't.

### Why we recommend a structural `starts_with` operator over case-by-case operator vigilance

The operator-side "always include a trailing separator and canonicalize" mitigation is real but fragile:

- It requires every cap-issuing operator to know the foot-gun exists. Round 01's docstring mentions normalization at the Context layer, but does not warn that the trailing-character-collision shape (`<root>/srv/app-shadow/...`) defeats even a trailing-separator-included prefix unless the path being checked is also normalized to end in a separator on directories.
- The embedded-mid-path collision (`<root>/var/log/srv/app/...`) is harder to mitigate operator-side — even with full canonicalization on both sides, a substring `matches` against an absolute path can fire mid-string. The operator's only safe mitigation is "use random suffixes the way round 01's PoC does" — which only works for synthetic test sandboxes, not for production paths an operator wants to lock down.
- A `starts_with` operator with a correct prefix-match semantic (anchored at position 0, requires prefix to end in a separator, normalizes platform-specific separators) makes the right thing the easy thing.

### Defender-actionable

For an operator using `@capnagent-examples/mcp-fs-agent` (or building a similar guarded client) before engine v0.5 ships:

1. **Use random suffixes for sandbox prefixes** — the round 01 pattern of `os.tmpdir() + crypto.randomUUID()` makes substring collisions overwhelmingly unlikely. This is fine for ephemeral test sandboxes but not for stable production paths.
2. **Canonicalize `arg.path` in your `Context` provider** — `path.resolve()` + symlink dereference + `path.normalize()` before the verifier sees the args. This reduces (but does not eliminate) the foot-gun for `..` / encoded-separator / symlink shapes.
3. **Don't use realistic-shaped paths as prefixes** — `/srv/app`, `/var/log`, `/usr/local` are all foot-gun-able. If you must scope to a realistic mount, append a random suffix or a unique component-name segment.
4. **Add a deploy-time assertion** that the issued cap's caveat string contains a unique suffix you control, to catch operator-config drift back to a generic prefix.
5. **Track every issuance** of `issueSandboxReadCapability` and log the prefix; review prefixes on a cadence for foot-gun shapes.

When engine v0.5 lands:

6. **Replace `matches` with `starts_with`** in any caveat that is meant to express path-prefix scoping. Treat `matches` for path arguments as a code smell.
7. **Verify the regen script** flips outcome from `allowed` to `denied` after the engine update, and update the round 07 doc to a Run 2 with status CLOSED.

### Source research

- OWASP A04:2021 — Insecure Design (the broader category covering operator-affordance failures: an API where the natural usage produces a silently-broken security posture).
- CWE-22 — Improper Limitation of a Pathname (the canonical "path can escape its intended scope" framing).
- CWE-185 — Incorrect Regular Expression (named here because the DSL's `matches` operator's name implies a regex-or-pattern-match semantic, but the implementation is substring containment; operators reasonably misread the contract).
- CWE-693 — Protection Mechanism Failure.
- The angles methodology: round 06 established the BREAKS→CLOSED pattern; round 07 is the second instance.
- Round 01 (`docs/purple-team/01-tool-description-injection.md`) — pre-existing documentation of this as a residual risk; round 07 promotes the residual-risk note into a structured BREAKS round.
