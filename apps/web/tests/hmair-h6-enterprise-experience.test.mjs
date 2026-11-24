import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const operations = readFileSync(
  new URL("../src/components/discovery/discovery-scan-operations.tsx", import.meta.url),
  "utf8",
);
const detail = readFileSync(
  new URL("../src/components/discovery/discovery-asset-detail.tsx", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("H6 scan operations expose safety, dry run, exclusions, diagnostics and breadth", () => {
  assert.match(operations, /Safety profile/i);
  assert.match(operations, /Metadata only/);
  assert.match(operations, /Dry run/);
  assert.match(operations, /Exclusions/);
  assert.match(operations, /Collector diagnostics/);
  assert.match(operations, /Blind spots/);
  assert.match(operations, /Models/);
  assert.match(operations, /Agents/);
  assert.match(operations, /MCP/);
  assert.match(operations, /Developer AI/);
  assert.match(operations, /SaaS AI/);
  assert.match(operations, /AI-enabled data/);
  assert.match(operations, /Unknown candidates/);
  assert.match(operations, /Control Coverage/);
  assert.match(api, /getHmairScanDiagnostics/);
  assert.match(types, /DiscoveryScanDiagnostics/);
});

test("H6 asset detail exposes the eleven required evidence-backed sections", () => {
  for (const label of [
    "Overview",
    "Discovery Evidence",
    "Configuration",
    "Capabilities",
    "Usage",
    "Users and identities",
    "Reachability",
    "Actions",
    "Control Coverage",
    "Findings",
    "History",
  ]) {
    assert.match(detail, new RegExp(label, "i"));
  }
  assert.match(detail, /getDiscoveryAssetEvidence/);
  assert.match(detail, /getDiscoveryAssetHistory/);
  assert.doesNotMatch(detail, /raw prompt|raw_prompt|credential value/i);
});

test("H6 keeps operations bounded and links review rather than inventing state", () => {
  assert.match(operations, /\/discovery\/unknown/);
  assert.match(operations, /\/discovery\/assets/);
  assert.match(operations, /\/discovery\/findings|\/discovery\/intelligence/);
  assert.match(operations, /exhaustive_claim_permitted/);
  assert.match(operations, /result_truncated/);
  assert.match(operations, /server safety limit/);
  assert.match(operations, /organization-wide/i);
  assert.doesNotMatch(operations, /mock|fixture|fallbackData/i);
});
