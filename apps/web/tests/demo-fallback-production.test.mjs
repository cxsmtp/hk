import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  DEMO_FALLBACK_MARKER,
  DEMO_FALLBACK_OFF_PATH,
  DEMO_FALLBACK_REQUEST,
  assertDemoFlagsAllowed,
  demoFlagsSet,
  isDemoBuild,
} from "../demo-build.mjs";
import { hawkNextConfig } from "../next.config.mjs";
import { registerProductionAliases } from "./fixtures/ts-alias-hooks.mjs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const BUILD_PHASE = "phase-production-build";
// Strings only the invented demo data contains.
const DEMO_DATA_STRINGS = [DEMO_FALLBACK_MARKER, "Acme Enterprise", "Prompt Injection Deterministic"];

test("next build refuses demo flags unless it is the explicit demo build", () => {
  for (const name of ["NEXT_PUBLIC_DEMO_MODE", "NEXT_PUBLIC_DEMO_FALLBACK", "NEXT_PUBLIC_DEMO_FORCE", "NEXT_PUBLIC_DEMO_FILL_EMPTY"]) {
    const env = { NODE_ENV: "production", [name]: "true" };
    assert.deepEqual(demoFlagsSet(env), [name]);
    assert.throws(() => assertDemoFlagsAllowed(env), /not a demo build/, name);
    assert.throws(() => hawkNextConfig(BUILD_PHASE, {}, env), /not a demo build/, name);
    assert.doesNotThrow(() => hawkNextConfig(BUILD_PHASE, {}, { ...env, DEMO_BUILD: "1" }));
  }
  assert.doesNotThrow(() => assertDemoFlagsAllowed({ NEXT_PUBLIC_DEMO_MODE: "false", NEXT_PUBLIC_DEMO_FALLBACK: "" }));
  assert.equal(isDemoBuild({ DEMO_BUILD: "true" }), false);
  assert.equal(isDemoBuild({ DEMO_BUILD: "0" }), false);
  assert.equal(isDemoBuild({ DEMO_BUILD: "1" }), true);
});

test("every build but the demo build compiles the demo data module out", () => {
  class Replacement {
    constructor(request, replacement) {
      this.request = request;
      this.replacement = replacement;
    }
  }
  const webpack = { NormalModuleReplacementPlugin: Replacement };

  const production = hawkNextConfig(BUILD_PHASE, {}, { NODE_ENV: "production" });
  assert.equal(production.env.NEXT_PUBLIC_HAWK_DEMO_BUILD, "0");
  const plugins = production.webpack({ plugins: [] }, { webpack }).plugins;
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0].request, DEMO_FALLBACK_REQUEST);
  assert.equal(plugins[0].replacement, DEMO_FALLBACK_OFF_PATH);
  assert.ok(DEMO_FALLBACK_REQUEST.test("@/lib/demo-fallback"));
  assert.ok(!DEMO_FALLBACK_REQUEST.test("@/lib/demo-fallback-off"));

  const development = hawkNextConfig("phase-development-server", {}, { NEXT_PUBLIC_DEMO_MODE: "true" });
  assert.equal(development.env.NEXT_PUBLIC_HAWK_DEMO_BUILD, "0");
  assert.equal(development.webpack({ plugins: [] }, { webpack }).plugins.length, 1);

  const demo = hawkNextConfig(BUILD_PHASE, {}, { DEMO_BUILD: "1", NEXT_PUBLIC_DEMO_MODE: "true" });
  assert.equal(demo.env.NEXT_PUBLIC_HAWK_DEMO_BUILD, "1");
  assert.equal(demo.webpack({ plugins: [] }, { webpack }).plugins.length, 0);
});

test("the module production builds get has no demo data, and the demo module carries the marker", () => {
  const off = readFileSync(DEMO_FALLBACK_OFF_PATH, "utf8");
  const demo = read("../src/lib/demo-fallback.ts");
  for (const value of DEMO_DATA_STRINGS) {
    assert.equal(off.includes(value), false, value);
    assert.ok(demo.includes(value), value);
  }
  assert.match(demo, /if \(process\.env\.NEXT_PUBLIC_HAWK_DEMO_BUILD !== "1"\) return false;/);
});

test("every demo branch of the API client is behind the compile-time demo build flag", () => {
  const api = read("../src/lib/api.ts");
  assert.match(api, /const DEMO_BUILD = process\.env\.NEXT_PUBLIC_HAWK_DEMO_BUILD === "1";/);
  const uses = api.match(/[^\n]*isDemoFallbackEnabled\(\)[^\n]*/g) || [];
  assert.ok(uses.length >= 4);
  for (const line of uses) {
    assert.match(line, /DEMO_BUILD && isDemoFallbackEnabled\(\)/, line);
  }
});

test("the production image cannot be the demo build and checks its output; the demo image is labelled", () => {
  const production = read("../../../infra/Dockerfile.web");
  assert.match(production, /ENV DEMO_BUILD=0/);
  assert.doesNotMatch(production, /ARG DEMO_BUILD|ARG NEXT_PUBLIC_DEMO/);
  assert.ok(production.includes(`grep -rqs "${DEMO_FALLBACK_MARKER}" .next`));
  const demo = read("../../../infra/Dockerfile.web.demo");
  assert.match(demo, /ENV DEMO_BUILD=1/);
  const banner = read("../src/components/demo-data-banner.tsx");
  assert.match(banner, /Demo data/);
  assert.match(read("../src/app/layout.tsx"), /<DemoDataBanner \/>/);
});

test("in a production build an API error is an error and an empty result stays empty", async () => {
  registerProductionAliases();
  const storage = new Map();
  globalThis.window = globalThis;
  globalThis.localStorage = {
    getItem: (key) => (storage.has(key) ? storage.get(key) : null),
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: (key) => storage.delete(key),
  };
  const answers = [];
  globalThis.fetch = async () => {
    const next = answers.shift();
    return new Response(next.body, { status: next.status, headers: { "content-type": "application/json" } });
  };
  // Even with every demo flag on at run time: only the demo build has demo data.
  Object.assign(process.env, { NEXT_PUBLIC_DEMO_MODE: "true", NEXT_PUBLIC_DEMO_FALLBACK: "true", NEXT_PUBLIC_DEMO_FORCE: "true" });
  const { api } = await import("../src/lib/api.ts");

  answers.push({ status: 422, body: "Refused by the API" });
  await assert.rejects(api.setupStatus(), (error) => {
    assert.match(String(error.message), /Refused by the API/);
    return true;
  });

  answers.push({ status: 200, body: JSON.stringify({ setup: false }) });
  assert.deepEqual(await api.setupStatus(), { setup: false });
});

test("a production build's output, when present, holds no demo data", (t) => {
  const nextDir = new URL("../.next/", import.meta.url);
  const serverFiles = new URL("required-server-files.json", nextDir);
  if (!existsSync(serverFiles)) {
    t.skip("no production build here (npm run build)");
    return;
  }
  const config = JSON.parse(readFileSync(serverFiles, "utf8")).config || {};
  if ((config.env || {}).NEXT_PUBLIC_HAWK_DEMO_BUILD !== "0") {
    t.skip("the build here is the demo build");
    return;
  }
  const found = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (name === "cache") continue;
      if (statSync(path).isDirectory()) walk(path);
      else if (/\.(js|html|json|rsc|txt)$/.test(name)) {
        const text = readFileSync(path, "utf8");
        for (const value of DEMO_DATA_STRINGS) if (text.includes(value)) found.push(`${path}: ${value}`);
      }
    }
  };
  walk(new URL(".", nextDir).pathname);
  assert.deepEqual(found, []);
});
