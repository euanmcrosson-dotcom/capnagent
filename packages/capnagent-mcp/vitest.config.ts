import { defineConfig } from "vitest/config";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  // Required so vitest can transitively load `@capnagent/core`, whose
  // wasm.ts re-exports the wasm-pack output. Without these vitest errors
  // with the "ESM integration proposal for Wasm" message at module-load.
  plugins: [wasm(), topLevelAwait()],
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    globals: false,
    reporters: "default",
  },
});
