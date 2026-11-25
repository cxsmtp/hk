import { readFileSync } from "node:fs";

/** Hawk AI's version, from the one VERSION file at the root of the repository (apps/api/app/version.py reads it too). */
function hawkVersion() {
  try {
    return readFileSync(new URL("../../VERSION", import.meta.url), "utf8").trim() || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/** @type {import("next").NextConfig} */
const nextConfig = {
  experimental: {
    externalDir: true,
  },
  env: {
    NEXT_PUBLIC_HAWK_VERSION: hawkVersion(),
  },
};

export default nextConfig;
