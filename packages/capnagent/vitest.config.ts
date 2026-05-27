import { defineConfig } from "vitest/config";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  // Both plugins are required so vitest can resolve the
  // wasm-pack output (`crates/capnagent-wasm/pkg/`) that wasm.ts
  // re-exports. Without them vitest errors with the "ESM integration
  // proposal for Wasm" message at module-load time.
  plugins: [wasm(), topLevelAwait()],
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    globals: false,
    reporters: "default",
    coverage: {
      provider: "v8",
      // Only our hand-written wrapper logic. `wasm.ts` is a re-export shim
      // for the generated wasm-pack bindings (no logic of ours), and
      // `types.ts` is type-only (no runtime statements) — measuring either
      // would distort the gate rather than guard the security surface.
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/wasm.ts", "src/types.ts"],
      reporter: ["text", "json-summary"],
      // Floors sit just below the measured baseline (lines/statements
      // ~91%, functions ~98%, branches ~87%) so an unguarded regression in
      // index.ts — the verify/error-map surface — fails CI, while normal
      // edits keep headroom. Ratchet up as coverage improves; never down.
      thresholds: {
        lines: 90,
        statements: 90,
        functions: 95,
        branches: 85,
      },
    },
  },
});
