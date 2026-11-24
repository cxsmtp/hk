import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "scripts/**/*.test.mjs"],
    exclude: ["tests/e2e/**", "node_modules/**", "dist/**", "**/._*"],
  },
});
