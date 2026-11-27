import { tmpdir } from "node:os";
import { join } from "node:path";

import { defineConfig, devices } from "@playwright/test";

import { ADMIN } from "./e2e/support/accounts";

/**
 * The console's browser end-to-end tests (e2e/): a real API on a fresh SQLite database, the production console build
 * and a small reverse proxy that puts both on one origin, as deploy/compose.yaml's front proxy does (e2e/harness/).
 *
 *   npm run test:e2e                      builds the console, starts everything, runs the tests headless
 *   E2E_SKIP_BUILD=1 npm run test:e2e     reuses an existing build made with NEXT_PUBLIC_API_URL=/api
 *   E2E_PYTHON=/path/to/python            the Python with the API's dependencies (default python3)
 *   PW_CHROMIUM_PATH=/path/to/chrome      a Chromium already on the machine instead of Playwright's download
 *   E2E_EXTRA_BROWSERS=webkit,firefox     also run the responsive checks (e2e/responsive.spec.ts) in WebKit (Safari's
 *                                         engine) and Firefox, where those browsers are installed (npx playwright
 *                                         install webkit firefox); CI runs Chromium only
 *
 * The tests share one installation and run in order, one worker: the first signs in as the first administrator,
 * changes the temporary password and accepts the terms of use; the others build on that.
 */

const port = Number(process.env.E2E_PORT || 13100);
const apiPort = Number(process.env.E2E_API_PORT || 18000);
const webPort = Number(process.env.E2E_WEB_PORT || 13000);
const origin = `http://127.0.0.1:${port}`;
const stateDir = process.env.E2E_STATE_DIR || join(tmpdir(), `hawk-e2e-${apiPort}`);
const python = process.env.E2E_PYTHON || "python3";
const chromiumPath = process.env.PW_CHROMIUM_PATH || "";
const extraBrowsers = (process.env.E2E_EXTRA_BROWSERS || "")
  .split(",")
  .map((name) => name.trim())
  .filter((name): name is "webkit" | "firefox" => name === "webkit" || name === "firefox");
const extraDevice = { webkit: devices["Desktop Safari"], firefox: devices["Desktop Firefox"] };

const apiEnv: Record<string, string> = {
  ENV: "test",
  TZ: "UTC",
  SECRET_KEY: "e2e-secret-key-not-for-production-0123456789",
  SECRET_KEY_LOCK_ENABLED: "false",
  CONNECTOR_SECRETS_KEY: "e2e-connector-key-not-for-production-0123",
  CONNECTOR_SECRETS_KDF_SALT: "e2e-kdf-salt-not-for-production-0123",
  ONPREM_BUNDLE_SIGNING_SECRET: "e2e-onprem-signing-not-for-production-01",
  CANONICAL_ACTION_BINDING_KEY: "e2e-binding-key-not-for-production-0123",
  // One API process and no Redis: sign-in tickets and limits in memory.
  SIGN_IN_STORE: "memory",
  FIRST_RUN_ACCESS: "true",
  ADMIN_EMAIL: ADMIN.email,
  ADMIN_PASSWORD: ADMIN.temporaryPassword,
  WEB_ORIGIN: origin,
  CORS_ORIGINS: origin,
  API_BASE_URL: `${origin}/api`,
  TRUSTED_HOSTS: "127.0.0.1,localhost",
  PYTHONDONTWRITEBYTECODE: "1",
};

const harnessEnv = { E2E_PORT: String(port), E2E_API_PORT: String(apiPort), E2E_WEB_PORT: String(webPort) };

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]] : [["list"]],
  outputDir: "test-results",
  use: {
    baseURL: origin,
    // No trace locally; in CI one is kept for a failed test only (uploaded with the report).
    trace: process.env.CI ? "retain-on-failure" : "off",
    screenshot: "only-on-failure",
    video: "off",
    ...devices["Desktop Chrome"],
    launchOptions: chromiumPath ? { executablePath: chromiumPath } : {},
  },
  projects: [
    // A new installation's first sign-in, once: every other test signs in with the password chosen there.
    { name: "first-run", testMatch: /first-run\.spec\.ts$/, use: { browserName: "chromium" } },
    { name: "console", testIgnore: /first-run\.spec\.ts$/, dependencies: ["first-run"], use: { browserName: "chromium" } },
    // Optional: the same responsive checks in Safari's and Firefox's engines (after the Chromium ones, one at a time).
    ...extraBrowsers.map((name) => ({
      name: `responsive-${name}`,
      testMatch: /responsive\.spec\.ts$/,
      dependencies: ["console"],
      use: { ...extraDevice[name], browserName: name, launchOptions: {} },
    })),
  ],
  webServer: [
    {
      command: `"${python}" e2e/harness/api_server.py --port ${apiPort} --state-dir "${stateDir}"`,
      url: `http://127.0.0.1:${apiPort}/health`,
      env: apiEnv,
      timeout: 120_000,
      reuseExistingServer: false,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: "node e2e/harness/web_server.mjs",
      url: `http://127.0.0.1:${webPort}/login`,
      env: harnessEnv,
      timeout: 420_000,
      reuseExistingServer: false,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: "node e2e/harness/proxy.mjs",
      url: `${origin}/api/health`,
      env: harnessEnv,
      timeout: 30_000,
      reuseExistingServer: false,
    },
  ],
});
