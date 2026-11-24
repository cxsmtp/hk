import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(new URL("../src/app/surface-coverage/page.tsx", import.meta.url), "utf8");
const panelUrl = new URL("../src/components/control-coverage/control-coverage-panel.tsx", import.meta.url);
const explorerUrl = new URL("../src/components/control-coverage/path-explorer.tsx", import.meta.url);
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("Deployment page mounts Control Coverage without adding navigation", () => {
  assert.equal(existsSync(panelUrl), true);
  assert.match(page, /ControlCoveragePanel/);
  assert.match(page, /NEXT_PUBLIC_CONTROL_COVERAGE_UI_ENABLED/);
  assert.match(page, /CONTROL_COVERAGE_UI_ENABLED\s*\?\s*\(/);
  assert.match(page, /<ControlCoveragePanel \/>/);
});

test("Surface Coverage starts with an operator-friendly control center", () => {
  for (const phrase of [
    "Surface Control Center",
    "What we can see",
    "What we can stop",
    "Still missing",
    "Browser",
    "Endpoint",
    "Runtime / MCP",
    "SaaS & APIs",
    "Test browser control",
    "Enroll endpoint",
    "Connect provider admin",
    "Technical control coverage atlas",
  ]) assert.match(page, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("Control Coverage exposes conservative states and executive questions", () => {
  const source = readFileSync(panelUrl, "utf8");
  for (const phrase of [
    "Evidence-backed enterprise control atlas",
    "Current",
    "Stale",
    "Partial",
    "Regressed",
    "Unsupported",
    "Unknown",
    "Configured · unvalidated",
    "No authoritative Control Coverage paths exist",
  ]) assert.match(source, new RegExp(phrase));
  assert.doesNotMatch(source, /Control Coverage Score/);
  assert.doesNotMatch(source, /risk score/i);
});

test("monitor-only surfaces are never presented as inline", () => {
  const source = readFileSync(panelUrl, "utf8");
  assert.match(source, /exact tool semantics require a verified browser control point/);
  assert.match(source, /semantic intent remains a separate fact/);
  assert.match(source, /Native or SDK action binding/);
  assert.match(source, /Provider, connector, and gateway evidence without assuming/);
});

test("path explorer shows the approved seven-component native path", () => {
  assert.equal(existsSync(explorerUrl), true);
  const source = readFileSync(explorerUrl, "utf8");
  assert.match(source, /asset.*identity.*runtime.*deployment surface.*destination\/tool/is);
  assert.match(source, /evidence_refs/);
  assert.match(source, /identity_type/);
});

test("web contracts call only read-only Control Coverage endpoints", () => {
  assert.match(types, /export type ControlCoverageSummary/);
  assert.match(types, /export type ControlCoveragePathList/);
  assert.match(api, /controlCoverage:.*\/control-coverage\?window_days=/s);
  assert.match(api, /controlCoveragePaths:.*\/control-coverage\/paths\?/s);
  assert.match(api, /controlCoveragePath:.*\/control-coverage\/paths\//s);
  assert.doesNotMatch(api, /controlCoverage[^\n]*method:\s*["']POST/);
});
