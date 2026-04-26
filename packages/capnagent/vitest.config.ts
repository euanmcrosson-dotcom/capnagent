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
  },
});
