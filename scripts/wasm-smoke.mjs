#!/usr/bin/env node
// Smoke test for the wasm-pack output.
//
// Confirms that `npm run build:wasm` produced the expected files and
// that the generated TypeScript declarations match the locked contract
// in `docs/WEEK3_SPEC.md` §3.1. Keeping the contract check static —
// against the .d.ts — instead of at runtime is deliberate:
//
//   * `--target bundler` output uses the bundler-only
//     `import * as wasm from "./capnagent_wasm_bg.wasm"` syntax. That
//     is gated behind `--experimental-wasm-modules` on Node 20 and is
//     not part of the v0 surface promise. The downstream consumer
//     (Terminal B's @capnagent package) is what actually instantiates
//     the module via a real bundler or wasm-bindgen helper.
//   * Terminal B reads the .d.ts as the source of truth for the
//     class/method shapes it wraps. If the .d.ts drifts, B's wrapper
//     breaks. This script is exactly that contract test, run on every
//     CI build.
//
// We also do a best-effort dynamic ESM import for an end-to-end signal
// when the runtime supports it (Node 22+ / Node 20 with the experimental
// flag). A failure there is reported but does not fail the script — the
// .d.ts assertions are the load-bearing check.

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const pkgDir = resolve(repoRoot, "crates", "capnagent-wasm", "pkg");

let failed = 0;

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  failed++;
}

function ok(msg) {
  console.log(`ok   ${msg}`);
}

// ─── 1. Required artifact files exist ────────────────────────────────────
const requiredFiles = [
  "capnagent_wasm.js",
  "capnagent_wasm_bg.wasm",
  "capnagent_wasm.d.ts",
  "package.json",
];
for (const name of requiredFiles) {
  const p = resolve(pkgDir, name);
  if (existsSync(p)) {
    ok(`pkg/${name} exists`);
  } else {
    fail(`pkg/${name} missing — has \`npm run build:wasm\` been run?`);
  }
}

// If the .d.ts is missing, every later check is meaningless — bail early
// with a clear single failure.
const dtsPath = resolve(pkgDir, "capnagent_wasm.d.ts");
if (!existsSync(dtsPath)) {
  console.error(`\nFAIL: cannot continue without ${dtsPath}`);
  process.exit(1);
}

const dts = readFileSync(dtsPath, "utf8");

// ─── 2. Required exports declared in the .d.ts ───────────────────────────
//
// §3.1 names six classes/functions. We also sanity-check the methods
// that downstream consumers (Terminal B's wrapper, Terminal C's MCP
// adapter) call by name; if the wasm-bindgen `js_name` attributes drift,
// the typed wrapper breaks at compile time on rebase.
const requiredExports = [
  { kind: "function", name: "init" },
  { kind: "class", name: "Issuer" },
  { kind: "class", name: "CapabilityBuilder" },
  { kind: "class", name: "Capability" },
  { kind: "class", name: "Verifier" },
  { kind: "class", name: "Auditor" },
  // v0.1 — holder-of-key surface (DESIGN.md §11, V0_1_SPEC.md §3.2). The
  // four wasm-bindgen items below MUST appear with these exact JS-side
  // names; Terminal C develops the TS wrappers against this contract from
  // a stub, so any drift breaks the merge.
  { kind: "function", name: "popChallengeFor" },
];

for (const { kind, name } of requiredExports) {
  // Match `export class Foo` or `export function init(`. wasm-bindgen
  // emits these declarations one-per-line, so a per-line regex is
  // unambiguous and resistant to formatting drift.
  const re = new RegExp(`^export\\s+${kind}\\s+${name}\\b`, "m");
  if (re.test(dts)) {
    ok(`pkg/capnagent_wasm.d.ts exports ${kind} ${name}`);
  } else {
    fail(`pkg/capnagent_wasm.d.ts is missing exported ${kind} ${name}`);
  }
}

// ─── 3. Method-shape sanity checks for the high-traffic surface ─────────
//
// Terminal B's wrapper calls these by name. If wasm-bindgen renames any
// of them (e.g. js_name attribute change in the Rust crate), the smoke
// test catches it before B's CI does.
const requiredMethodFragments = [
  // Issuer
  /static\s+fromKey\s*\(/,
  /\bissue\s*\(/,
  // CapabilityBuilder
  /\bcaveat\s*\(/,
  /\bbuild\s*\(/,
  // Capability
  /static\s+parse\s*\(/,
  /\bserialize\s*\(/,
  /\battenuate\s*\(/,
  // Verifier
  /\bverify\s*\(/,
  /\bverifyWithContext\s*\(/,
  // v0.1 hok surface — see V0_1_SPEC.md §3.2.
  // Builder method that binds an ed25519 pubkey before any caveat.
  /\bholderOfKey\s*\(/,
  // Capability getter exposing the bound ed25519 pubkey, or undefined
  // for non-hok tokens. wasm-bindgen renders TS getters as bare
  // `readonly holderOfKey:` declarations, so we match the property
  // form rather than `get holderOfKey()`.
  /\breadonly\s+holderOfKey\b/,
  // Verifier four-gate proof-of-possession entry point.
  /\bverifyWithProof\s*\(/,
];

for (const re of requiredMethodFragments) {
  if (re.test(dts)) {
    ok(`d.ts contains expected method fragment ${re}`);
  } else {
    fail(`d.ts is missing expected method fragment ${re}`);
  }
}

// ─── 4. package.json sanity ─────────────────────────────────────────────
//
// wasm-pack writes a package.json declaring the entry points and
// `"type": "module"`. Downstream consumers depend on these. We don't
// assert the precise shape — wasm-pack versions wiggle the keys — but
// we insist on at least one of `module` / `main` and on the `.wasm`
// file being listed in `files` (so that publishing won't strip it).
const pkgJsonPath = resolve(pkgDir, "package.json");
if (existsSync(pkgJsonPath)) {
  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  if (pkgJson.module || pkgJson.main) {
    ok(`pkg/package.json declares an entrypoint (${pkgJson.module ?? pkgJson.main})`);
  } else {
    fail(`pkg/package.json has neither "module" nor "main"`);
  }
  if (Array.isArray(pkgJson.files) && pkgJson.files.some((f) => f.endsWith(".wasm"))) {
    ok(`pkg/package.json files[] includes the .wasm artifact`);
  } else {
    fail(`pkg/package.json files[] does not include a .wasm entry`);
  }
}

// ─── 5. Best-effort runtime import (informational, never fails the script)
//
// The bundler-target output uses `import * as wasm from "./*.wasm"`
// which Node only supports under an experimental flag. We try; if it
// works, that's a stronger end-to-end signal — but a failure here just
// reflects Node's flag state, not a build problem.
try {
  const entry = resolve(pkgDir, "capnagent_wasm.js");
  const mod = await import(pathToFileURL(entry).href);
  const names = [
    "init",
    "Issuer",
    "CapabilityBuilder",
    "Capability",
    "Verifier",
    "Auditor",
    // v0.1 hok surface — `popChallengeFor` is the only free function
    // added; the three class-level additions ride along on the existing
    // class objects and aren't separately exported.
    "popChallengeFor",
  ];
  const missing = names.filter((n) => typeof mod[n] !== "function");
  if (missing.length === 0) {
    ok(`runtime ESM import resolved every named export (${names.join(", ")})`);
  } else {
    console.warn(`note: runtime ESM import resolved but is missing: ${missing.join(", ")}`);
  }
} catch (e) {
  console.warn(
    `note: runtime ESM import skipped — ${e?.message ?? e}\n` +
      `      (this is expected on Node without --experimental-wasm-modules; the .d.ts assertions above are authoritative)`,
  );
}

// ─── Summary ────────────────────────────────────────────────────────────
if (failed > 0) {
  console.error(`\n${failed} smoke check(s) FAILED`);
  process.exit(1);
}
console.log("\nOK: wasm artifact passes all smoke checks");
