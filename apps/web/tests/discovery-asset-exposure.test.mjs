import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const component = readFileSync(
  new URL("../src/components/discovery/asset-exposure-intelligence.tsx", import.meta.url),
  "utf8",
);
const detail = readFileSync(
  new URL("../src/components/discovery/discovery-asset-detail.tsx", import.meta.url),
  "utf8",
);
const navigation = readFileSync(
  new URL("../src/lib/navigation.ts", import.meta.url),
  "utf8",
);
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");

test("asset exposure uses five progressive intelligence sections without a dashboard", () => {
  for (const label of [
    "Exposure Summary",
    "Exposure Timeline",
    "Exposure Contributors",
    "Control Coverage",
    "Recommendations & Drill Down",
  ]) {
    assert.match(component, new RegExp(label.replaceAll("&", "&amp;|&")));
  }
  assert.doesNotMatch(navigation, /AI Exposure|Exposure Dashboard/);
  assert.doesNotMatch(component, /aggregate_score|Exposure Dashboard|gauge|radial/i);
});

test("unknown and unavailable remain explicit and never become green or zero", () => {
  assert.match(component, /Unknown/);
  assert.match(component, /Exposure reasoning unavailable/);
  assert.match(component, /projection\.calculation_status === "unavailable"/);
  assert.match(component, /Missing evidence never proves no exposure/);
  assert.doesNotMatch(component, /unknown[^\n]{0,80}(?:0%|text-emerald|bg-emerald)/i);
  assert.doesNotMatch(component, /unavailable[^\n]{0,80}(?:0%|text-emerald|bg-emerald)/i);
});

test("coverage keeps discover authorize prove and contain separate", () => {
  for (const question of [
    "Can Hawk discover it?",
    "Can Hawk authorize it?",
    "Can Hawk prove it?",
    "Can Hawk contain it?",
  ]) {
    assert.match(component, new RegExp(question.replace("?", "\\?")));
  }
});

test("asset page survives exposure failure and graph loads only on disclosure", () => {
  assert.match(detail, /<AssetExposureIntelligence assetId=\{assetId\}/);
  assert.match(component, /setProjection\(null\)/);
  assert.match(component, /Retry reasoning/);
  assert.match(component, /onClick=\{loadGraph\}/);
  assert.doesNotMatch(component, /useEffect\([^)]*loadGraph/);
});

test("typescript and api contracts preserve nullable confidence and read-only calls", () => {
  assert.match(types, /export type ExposureProjection/);
  assert.match(types, /confidence: number \| null/);
  assert.match(types, /evidence_quality: number \| null/);
  assert.match(api, /getDiscoveryAssetExposure:/);
  assert.match(api, /getDiscoveryAssetExposureTimeline:/);
  assert.match(api, /getDiscoveryAssetExposureGraph:/);
  assert.match(api, /query\.set\("as_of", asOf\)/);
  assert.match(component, /source_input_digest === nextProjection\.source_input_digest/);
  assert.match(types, /unknown_dimensions: ExposureDimension\[\]/);
  assert.match(types, /reasoning_trace: string\[\]/);
  assert.doesNotMatch(api, /createDiscoveryAssetExposure|updateDiscoveryAssetExposure/);
});

test("audit context and unavailable history remain explicit", () => {
  assert.match(component, /Evidence quality/);
  assert.match(component, /Last validation/);
  assert.match(component, /item\.reason/);
  assert.match(component, /item\.source_refs\.join/);
  assert.match(component, /historical_exposure_state_unavailable/);
  assert.match(component, /Historical exposure timeline unavailable/);
  assert.doesNotMatch(component, /No derivable exposure change yet/);
});

test("contributor rows preserve and show exact path identity", () => {
  assert.match(component, /factor\.related_source_refs\.join\("\|"\)/);
  assert.match(component, /control_coverage_path:/);
  assert.match(component, /Exact path/);
});
