import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../src/", import.meta.url);

function source(path) {
  const url = new URL(path, root);
  assert.equal(existsSync(url), true, `${path} must exist`);
  return readFileSync(url, "utf8");
}

test("Phase 2 discovery exposes the five evidence-backed product paths", () => {
  const navigation = source("lib/navigation.ts");
  for (const [label, href] of [
    ["Estate overview", "/discovery/estate"],
    ["Asset records", "/discovery/assets"],
    ["Provider relationships", "/discovery/ecosystems"],
    ["Unresolved AI", "/discovery/unknown"],
    ["Scans", "/discovery/scans"],
  ]) {
    assert.match(navigation, new RegExp(`label: ["']${label}["'][^\\n]+href: ["']${href.replaceAll("/", "\\/")}["']|href: ["']${href.replaceAll("/", "\\/")}["'][^\\n]+label: ["']${label}["']`));
  }

  for (const route of [
    "app/discovery/estate/page.tsx",
    "app/discovery/assets/page.tsx",
    "app/discovery/assets/[id]/page.tsx",
    "app/discovery/ecosystems/page.tsx",
    "app/discovery/unknown/page.tsx",
    "app/discovery/scans/page.tsx",
  ]) {
    source(route);
  }
});

test("asset intelligence is progressive and keeps confidence and evidence visible", () => {
  const inventory = source("components/discovery/discovery-asset-inventory.tsx");
  const detail = source("components/discovery/discovery-asset-detail.tsx");
  assert.match(inventory, /listDiscoveryAssets/);
  assert.match(inventory, /resolution_confidence/);
  assert.match(inventory, /usage_state/);
  assert.match(inventory, /findings_open/);
  assert.match(detail, /getDiscoveryAsset/);
  assert.match(detail, /evidence_node_id|evidence_claim_id/);
  assert.match(detail, /limitations/);
  assert.doesNotMatch(inventory + detail, /mock|fixture|fallbackData/i);
});

test("ecosystem, unknown AI and scan operations use real Hawk APIs", () => {
  const estate = source("components/discovery/ai-estate-intelligence.tsx");
  const ecosystems = source("components/discovery/discovery-ecosystem-map.tsx");
  const unknown = source("components/discovery/discovery-unknown-ai.tsx");
  const scans = source("components/discovery/discovery-scan-operations.tsx");
  assert.match(ecosystems, /listDiscoveryEcosystems/);
  assert.match(source("lib/api.ts"), /getDiscoveryEcosystem/);
  for (const evidenceField of [
    "resolution_method",
    "confidence",
    "evidence_refs",
    "discovery_sources",
    "last_seen_at",
  ]) {
    assert.match(ecosystems, new RegExp(evidenceField));
  }
  assert.match(ecosystems, /Verified graph/);
  assert.match(estate, /Evidence-native components/);
  assert.match(estate, /resolution_method/);
  assert.match(estate, /evidence_refs/);
  assert.doesNotMatch(estate + ecosystems, /Provider × environment|provider\/environment grouping/i);
  assert.match(unknown, /listUnknownAI/);
  assert.match(unknown, /required_action/);
  assert.match(scans, /listHmairScans/);
  assert.match(scans, /getHmairScanProgress/);
  assert.match(scans, /getHmairScanResults/);
  assert.match(scans, /listEndpointMetadataInventoryRuns/);
  assert.match(scans, /createEndpointMetadataInventoryRun/);
  assert.match(scans, /eligible enrolled endpoints/i);
  assert.match(scans, /not an organization-wide deep scan/i);
  assert.match(scans, /unknown_sources/);
  assert.match(scans, /exhaustive_claim_permitted/);
  assert.match(estate, /getDiscoveryCoverage/);
  assert.match(estate, /score_withheld_reason/);
  assert.match(estate, /Unknown/);
  assert.match(source("lib/api.ts"), /endpoint-agent\/discovery\/metadata-inventory-runs/);
  assert.match(source("lib/types.ts"), /EndpointMetadataInventoryRun/);
  assert.doesNotMatch(ecosystems + unknown + scans, /mock|fixture|fallbackData/i);
});
