import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const panel = readFileSync(
  new URL("../src/components/control-coverage/control-coverage-panel.tsx", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("Phase 8 executive experience exposes the required evidence-backed sections", () => {
  for (const section of [
    "Coverage Summary",
    "Deployment Surfaces",
    "Top Gaps",
    "Coverage Dimensions",
    "Change Since Previous Snapshot",
    "Evidence trail",
  ]) {
    assert.match(panel, new RegExp(section));
  }
  for (const state of [
    "Current",
    "Stale",
    "Partial",
    "Configured · unvalidated",
    "Regressed",
    "Gap",
    "Unsupported",
    "Unknown",
  ]) {
    assert.match(panel, new RegExp(state.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("Phase 8 UI uses the authoritative executive API and preserves the denominator", () => {
  assert.match(api, /executiveControlCoverage:/);
  assert.match(api, /refreshExecutiveControlCoverage:/);
  assert.match(api, /executiveControlCoverageAssessments:/);
  assert.match(api, /executiveControlCoverageAssessment:/);
  assert.match(panel, /api\.executiveControlCoverage\(/);
  assert.match(panel, /validated_coverage_percent/);
  assert.match(panel, /summary\.denominator/);
  assert.match(panel, /summary\.unknown_population/);
  assert.match(panel, /Unknown stays in the denominator/);
  assert.doesNotMatch(panel, /risk score|AI-generated score/i);
});

test("Phase 8 drilldown preserves orthogonal facts and Phase 7 lineage links", () => {
  assert.match(types, /export type ExecutiveControlCoverageSummary/);
  assert.match(types, /export type ExecutiveCoverageAssessmentExplanation/);
  for (const fact of [
    "applicability",
    "deployment_state",
    "capability_state",
    "assurance_state",
    "evidence_quality",
    "expected_control_points",
    "contributing_control_points",
    "missing_contributions",
    "lineage_refs",
  ]) {
    assert.match(types, new RegExp(fact));
    assert.match(panel, new RegExp(fact));
  }
  assert.match(panel, /investigation_links/);
  assert.match(panel, /Why this state exists/);
});

test("surface truth remains separated across all four deployment families", () => {
  for (const surface of ["Browser", "Endpoint", "Runtime", "SaaS & APIs"]) {
    assert.match(panel, new RegExp(surface.replace("&", "&amp;|&")));
  }
  assert.match(panel, /surface_breakdown/);
  assert.match(panel, /dimension_breakdown/);
});

test("valid snapshots do not display raw failed-load banners", () => {
  assert.match(panel, /Showing the latest available coverage snapshot/);
  assert.match(panel, /secondary refresh or drill-down request/);
  assert.doesNotMatch(panel, /Showing the latest available coverage snapshot[\s\S]{0,240}\{error\}/);
  assert.doesNotMatch(panel, /Load failed/);
});
