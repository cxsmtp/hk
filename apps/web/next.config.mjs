import { readFileSync } from "node:fs";

import { PHASE_PRODUCTION_BUILD } from "next/constants.js";

import { DEMO_FALLBACK_OFF_PATH, DEMO_FALLBACK_REQUEST, assertDemoFlagsAllowed, isDemoBuild } from "./demo-build.mjs";

/** Hawk AI's version, from the one VERSION file at the root of the repository (apps/api/app/version.py reads it too). */
function hawkVersion() {
  try {
    return readFileSync(new URL("../../VERSION", import.meta.url), "utf8").trim() || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/** @type {(phase: string, context?: unknown, env?: NodeJS.ProcessEnv) => import("next").NextConfig} */
export function hawkNextConfig(phase, _context, env = process.env) {
  const demoBuild = isDemoBuild(env);
  if (phase === PHASE_PRODUCTION_BUILD) {
    // Demo data in a build that is not the demo build fails the build (demo-build.mjs).
    assertDemoFlagsAllowed(env);
  }
  return {
    experimental: {
      externalDir: true,
    },
    env: {
      NEXT_PUBLIC_HAWK_VERSION: hawkVersion(),
      // Inlined at compile time: outside the demo build every demo branch is dead code.
      NEXT_PUBLIC_HAWK_DEMO_BUILD: demoBuild ? "1" : "0",
    },
    webpack(config, { webpack }) {
      if (!demoBuild) {
        // The demo data module is not compiled in at all: its import resolves to the module that has none.
        config.plugins.push(new webpack.NormalModuleReplacementPlugin(DEMO_FALLBACK_REQUEST, DEMO_FALLBACK_OFF_PATH));
      }
      return config;
    },
  };
}

export default hawkNextConfig;
