// The console for the browser tests: the production build (next build, then next start), built as infra/Dockerfile.web
// builds it, with the API at /api on the console's own origin (NEXT_PUBLIC_API_URL=/api). E2E_SKIP_BUILD=1 starts an
// existing build instead (it must have been made with NEXT_PUBLIC_API_URL=/api, e.g. by --build-only).
//
//   node e2e/harness/web_server.mjs                (E2E_WEB_PORT)
//   node e2e/harness/web_server.mjs --build-only   only the build (CI runs it as a step of its own)

import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const web = fileURLToPath(new URL("../..", import.meta.url));
const port = String(process.env.E2E_WEB_PORT || 13000);
const next = fileURLToPath(new URL("../../node_modules/next/dist/bin/next", import.meta.url));
const env = { ...process.env, NEXT_PUBLIC_API_URL: "/api", NEXT_TELEMETRY_DISABLED: "1", DEMO_BUILD: "0" };

const buildOnly = process.argv.includes("--build-only");
if (buildOnly || process.env.E2E_SKIP_BUILD !== "1") {
  const built = spawnSync(process.execPath, [next, "build"], { cwd: web, env, stdio: "inherit" });
  if (built.status !== 0 || buildOnly) process.exit(built.status ?? 1);
}

const server = spawn(process.execPath, [next, "start", "--hostname", "127.0.0.1", "--port", port], {
  cwd: web,
  env: { ...env, NODE_ENV: "production" },
  stdio: "inherit",
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.kill(signal));
server.on("exit", (code) => process.exit(code ?? 0));
