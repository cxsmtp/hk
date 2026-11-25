// The demo build, and only it, may contain the demo data fallback (src/lib/demo-fallback.ts): invented "Acme" data that
// stands in for API errors and empty results. A governance console must never show invented evidence, so every other
// build replaces that module with src/lib/demo-fallback-off.ts at compile time (next.config.mjs), and `next build` fails
// when demo flags are set without DEMO_BUILD=1. Only infra/Dockerfile.web.demo sets DEMO_BUILD=1; the production
// Dockerfile (infra/Dockerfile.web) has no way to set it and checks its output for DEMO_FALLBACK_MARKER.

import { fileURLToPath } from "node:url";

/** Public build flags that turn the demo fallback on (read by the browser bundle). */
export const DEMO_FLAG_NAMES = Object.freeze([
  "NEXT_PUBLIC_DEMO_MODE",
  "NEXT_PUBLIC_DEMO_FALLBACK",
  "NEXT_PUBLIC_DEMO_FORCE",
  "NEXT_PUBLIC_DEMO_FILL_EMPTY",
]);

/** A string only the demo fallback module contains: its presence in a build's output means demo data is in it. */
export const DEMO_FALLBACK_MARKER = "hawk-demo-fallback-data";

/** The import the production build replaces, and what it is replaced with. */
export const DEMO_FALLBACK_REQUEST = /^@\/lib\/demo-fallback$/;
export const DEMO_FALLBACK_OFF_PATH = fileURLToPath(new URL("./src/lib/demo-fallback-off.ts", import.meta.url));

export function isDemoBuild(env = process.env) {
  return String(env.DEMO_BUILD ?? "").trim() === "1";
}

/** The demo flags set to anything but empty, "false" or "0". */
export function demoFlagsSet(env = process.env) {
  return DEMO_FLAG_NAMES.filter((name) => {
    const value = String(env[name] ?? "").trim().toLowerCase();
    return value !== "" && value !== "false" && value !== "0";
  });
}

/** Throws when demo flags are set for a build that is not the explicit demo build. */
export function assertDemoFlagsAllowed(env = process.env) {
  const flags = demoFlagsSet(env);
  if (flags.length && !isDemoBuild(env)) {
    throw new Error(
      `Demo data flags (${flags.join(", ")}) are set but this is not a demo build. A production console must never ` +
        "show invented data: unset them, or build the demo image (infra/Dockerfile.web.demo, DEMO_BUILD=1).",
    );
  }
}
