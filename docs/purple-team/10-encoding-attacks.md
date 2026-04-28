# Round 10 — Encoding / normalization attacks against fs-sandbox

> Round 07 found that substring `matches` is not path-aware (lateral
> paths sharing the prefix substring slip through). Round 10 tests a
> different encoding shape: paths that contain the sandbox-prefix
> substring AS A LITERAL but resolve OUTSIDE the sandbox via path-
> traversal sequences. capnagent's caveat sees the raw bytes,
> matches the substring, and ALLOWS the call. Node's `fs.readFile`
> resolves the `..` segments and reads the out-of-sandbox file.
> **Status: BREAKS.** Same recommended fix as round 07 — Context-
> provider canonicalization + `starts_with` DSL operator. This
> round widens the case for the v0.5 fix from "lateral substring
> match" (round 07) to "lateral substring + traversal escape"
> (round 10).

```text
Attack class:     OWASP A04:2021 (Insecure Design); CWE-22 (Improper
                  Limitation of a Pathname to a Restricted Directory);
                  CWE-23 (Relative Path Traversal).
Hypothesis:       Positive (true-positive): given a sandbox-scoped fs
                  cap, a `read_file` call whose `arg.path` contains
                  the sandbox prefix as a substring AND escapes via
                  `..` (e.g. `<sandbox>/../outside/secret.txt`) MUST
                  be denied. **Expected to FAIL** — the round's
                  central finding.

                  Negative (true-negative): a legitimate in-sandbox
                  read still works, and an obvious out-of-sandbox
                  path (e.g. `/etc/passwd` with no sandbox-prefix
                  substring) is still denied (round 01 regression).
Test (PoC):       examples/mcp-fs-agent/src/__tests__/encoding-attacks.purple.test.ts
Coverage:         Tested variants:
                    - simple `..` escape: `<sandbox>/../outside/secret.txt`
                      ALLOWED (the visceral break — out-of-sandbox
                      file is actually read)
                    - multi-segment escape:
                      `<sandbox>/legit/../../outside/secret.txt` —
                      enters sandbox, climbs back out, still allowed
                    - `.`-noise + `..`:
                      `<sandbox>/././../outside/secret.txt` — also
                      slips, stress-tests the canonicalizer fix
                    - base64-encoded path: NOT exploitable today
                      (capnagent never decodes; substring miss →
                      denial). Flagged as a future risk if anyone
                      wires a custom client with auto-decoding.
                    - percent-encoded `..` (`%2e%2e`): allowed by
                      gate (substring fires), but Node's
                      `fs.readFile` doesn't URL-decode so no
                      exfil. Pinned so a future code change adding
                      URL-decoding gets caught.
                    - Unicode NFC/NFD: pin behavior on the current
                      tempdir form. Mostly a placeholder for systems
                      with non-ASCII tempdir names.
                    - regression: round 01's `/etc/passwd` case
                      still denied; in-sandbox legit read still
                      allowed.
                  Not yet tested:
                    - Windows-specific separator confusions
                      (`<sandbox>\..\outside\secret`) on Windows.
                      This is an OS-specific test that would need
                      conditional execution.
                    - Symlinks pointing outside the sandbox (the
                      symlink path doesn't contain the prefix as a
                      substring so caveat would deny — but if the
                      operator's sandbox CONTAINS a symlink the
                      agent can follow, that's a different shape).
                    - Hard links to out-of-sandbox files inside the
                      sandbox dir.
                    - Long-path / `\\?\` Windows prefix.
                    - Drive-letter swaps on Windows (`C:` vs
                      lowercase).
Known-bypasses:   - The fix has to canonicalize the path BEFORE
                    caveat evaluation. Operators using a custom
                    Context provider that doesn't canonicalize will
                    still be vulnerable. The fix is at the engine
                    layer (a built-in canonicalizer) plus
                    documentation that custom Context providers
                    MUST canonicalize.
                  - Once the canonical-path fix lands, the
                    `starts_with` DSL operator is still useful to
                    prevent the round 07 lateral-substring shape.
                    Both fixes compose; neither alone is sufficient.
                  - Out-of-scope: symlink races (TOCTOU between
                    canonicalize-time and read-time). capnagent's
                    Context provider would need to use the resolved
                    path for the caveat AND pass it through to the
                    fs client to read; if the underlying client
                    reads a different path, that's a different bug.
Re-validate-by:   2026-10-28   (re-run after v0.5 canonicalization
                                fix lands; expected to flip from
                                BREAKS → CLOSED.)
Owner:            blue-lead
Status:           BREAKS — 2026-04-28. Defense does not hold for
                  path-traversal inputs that contain the sandbox
                  prefix as a substring. Recommended fix is the
                  same v0.5 work item opened by round 07; round 10
                  widens the case for it.

──────────────────────────────────────────────────────────────────
Run history
──────────────────────────────────────────────────────────────────

Run 1 — 2026-04-28 03:01 UTC                              [FAIL]
  Env:          Windows 11 + Node 20.x + capnagent @ 2bbf57f
                + @capnagent/core (real WASM via wasm-pack pkg)
  Gates:        chain ✓ | proof - | replay - | revoke - | caveat ✓
                  Caveat substring-match fires on the literal
                  `<sandbox>/` prefix in the path string. Call
                  proceeds to fs client. fs client resolves `..`,
                  reads out-of-sandbox file. The "✓" on caveat is
                  CORRECT against the substring spec — the gap is
                  that the spec is wrong (substring isn't path-aware).
  Decision:     ALLOWED — outcome.kind = "allowed".
                Expected: DENIED with reason "caveat failed: ...".
                Observed: ALLOWED. The traversal path is allowed by
                          the gate AND the underlying fs client
                          actually reads the out-of-sandbox secret.
                Evidence file (`evidence/10-encoding-attacks.receipt.json`)
                annotates the receipt with the file contents read,
                so reviewers can verify exfil happened, not just
                that the gate misfired.
  Latency:      ~11 µs (verify_with_context — same as round 01)
  FP-7d:        N/A
  Gap-class:    DEFENSE-LOGIC
                  The DSL `matches` operator is correctly substring,
                  per its docs. The defect is at the API design
                  layer: `issueSandboxReadCapability` builds caveats
                  using `matches`, which doesn't carry the
                  semantics the API name promises ("sandbox-scoped").
  Gap:          Path-traversal escape via `..` slips past the
                substring caveat because the substring is still
                literally present in the path. capnagent's caveat
                operates on raw bytes; Node's fs operates on
                resolved paths. Mismatch is the gap.
  Action:       Action queued for v0.5 (same as round 07). Two-part
                fix: (1) extend the Context provider in
                createGuardedFsClient to canonicalize arg.path
                (resolve symlinks, eliminate `..`, normalize
                separators) BEFORE caveat evaluation, (2) add a
                `starts_with` DSL operator anchored at position 0
                + requiring trailing separator. Either alone is
                insufficient: canonicalization alone leaves the
                round 07 lateral-substring shape; starts_with
                alone leaves cases where the operator passes a
                non-canonical prefix.
```

## Evidence

- **Runnable PoC:** [`examples/mcp-fs-agent/src/__tests__/encoding-attacks.purple.test.ts`](../../examples/mcp-fs-agent/src/__tests__/encoding-attacks.purple.test.ts) — 8 deterministic tests, all passing (the FAIL is the SCENARIO outcome, not the test outcome).
- **Receipt JSON:** [`evidence/10-encoding-attacks.receipt.json`](evidence/10-encoding-attacks.receipt.json) — annotated with the file contents actually read out-of-sandbox. The receipt + the contents together are the visceral evidence.
- **Regen script:** `npm run -w @capnagent-examples/mcp-fs-agent regen-purple-evidence-10`

## Notes

### Why this round is distinct from round 07

Round 07: prefix `/srv/app` allows `/etc/srv/app-leaked-secret` —
**lateral** path that just happens to contain the prefix as a
substring. The attacker uses an unrelated path that shares bytes.

Round 10: prefix `<sandbox>/` allows `<sandbox>/../outside/secret` —
**escape** path that genuinely starts with the prefix and then
backs out. The attacker passes a structurally-valid sandbox path
that resolves elsewhere.

Both expose the same root cause (caveat doesn't understand path
semantics) but via different attacker shapes. The corpus benefits
from having both because the v0.5 fix has to handle both: a
canonicalizer alone fixes round 10 but not round 07 (the lateral
path survives canonicalization); a `starts_with` operator alone
fixes round 07 but not round 10 (the escape path starts with the
prefix and then escapes). **Both halves of the v0.5 fix are
required.**

### Defender-actionable

For an operator using capnagent's fs-agent today, BEFORE the v0.5
fix lands:

1. **Use absolute, canonicalized sandbox prefixes** — call
   `path.resolve()` on whatever you pass to
   `issueSandboxReadCapability`.
2. **Wrap your tool client** to canonicalize `arg.path` before
   forwarding. Add a guard at the FsClient layer that calls
   `path.resolve()` and rejects paths that escape the sandbox after
   resolution. This is a workaround until the engine fix lands;
   document it loudly as "doing the engine's job manually."
3. **Add a deploy-readiness probe** that issues a known-traversal
   path against the live cap and asserts it's denied. If it's
   allowed, fail the deploy. This catches the gap early.
4. **Consider OS-level confinement** as defense-in-depth — chroot,
   mount-namespace, or a container with the only mountable path
   being the sandbox. Even a perfect canonicalizer plus
   `starts_with` is one bug away from being defeated; OS-level
   confinement is the structural-defense second layer.

### Source research

- CWE-22 (Path Traversal) — the canonical class.
- OWASP API Security Top 10, A8 (Lack of Resources & Rate Limiting,
  related but distinct) — including for completeness; not directly
  applicable.
- Node's fs.readFile path resolution semantics: `fs.readFile`
  resolves `..` by default (via the underlying OS open(2) call);
  there is no `fs.readFile(path, { noResolve: true })` option.
  Canonicalization has to happen BEFORE the call, not inside it.
