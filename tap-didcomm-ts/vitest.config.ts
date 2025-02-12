import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node", // Default to Node.js environment
    include: ["tests/unit/**/*.test.ts"],
    exclude: ["tests/browser/**/*"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      exclude: [
        "node_modules/**",
        "dist/**",
        "dist-examples/**",
        "coverage/**",
        "**/*.d.ts",
        "tests/**",
        "examples/**",
      ],
    },
    setupFiles: ["tests/node/setup.ts"],
    isolate: true,
    threads: false,
    maxConcurrency: 1,
    maxThreads: 1,
    minThreads: 1,
  },
  resolve: {
    alias: {
      "@": "/src", // Enable @ imports from src directory
    },
  },
});
