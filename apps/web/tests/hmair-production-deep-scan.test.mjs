import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { DEMO_READINESS_DEFINITIONS, resolveDemoReadinessState } from "../src/components/discovery/discovery-demo-readiness-state.mjs";
import {
  buildVisibilityRecoveryPayload,
  canSubmitVisibilityRecovery,
  loadUserVisibilityData,
  submitVisibilityRecovery,
} from "../src/components/users/user-visibility-recovery.mjs";

const operations = readFileSync(
  new URL("../src/components/discovery/discovery-scan-operations.tsx", import.meta.url),
  "utf8",
);
const readiness = readFileSync(
  new URL("../src/components/discovery/discovery-demo-readiness.tsx", import.meta.url),
  "utf8",
);
const readinessState = readFileSync(
  new URL("../src/components/discovery/discovery-demo-readiness-state.mjs", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");

test("Deep Scan is preflight-first and describes unconnected coverage truthfully", () => {
  assert.match(operations, /Production Deep Scan/);
  assert.match(operations, /Run Deep Scan preflight/);
  assert.match(operations, /Not connected/);
  assert.match(operations, /cannot claim organization-wide coverage/i);
  assert.match(operations, /Organization-wide verification is unavailable/i);
  assert.doesNotMatch(operations, /Organization-wide claim request/);
  assert.match(operations, /customer authorization reference/i);
  assert.doesNotMatch(operations, /Run Deep Scan[^\n]*onClick=\{launchScan\}/);
});

test("AI Estate scan page is a customer-readable Discovery Command Center", () => {
  assert.match(operations, /Discovery Command Center/);
  assert.match(operations, /Run AI Discovery/);
  assert.match(operations, /Start here: run an AI discovery scan/);
  assert.match(operations, /Sources/);
  assert.match(operations, /Latest scan result/);
  assert.match(operations, /Still not visible/);
  assert.match(operations, /Advanced scan settings and diagnostics/);
  assert.match(operations, /Connect source/);
  assert.match(operations, /Last evidence/);
  assert.match(operations, /Browser/);
  assert.match(operations, /Endpoint/);
  assert.match(operations, /MCP & agents/);
  assert.match(operations, /GitHub \/ SaaS \/ Cloud/);
  assert.match(operations, /SaaS apps without a customer-owned connector/);
  assert.match(operations, /Identity \/ SCIM membership without an IdP source/);
  assert.match(operations, /Cloud/);
  assert.match(operations, /M365 \/ Teams/);
  assert.match(operations, /Full-enterprise coverage is not proven/);
  assert.match(operations, /provider-native verified/);
  assert.match(operations, /monitor-only/);
});

test("the web client uses only bounded Deep Scan contracts", () => {
  assert.match(api, /preflightHmairDeepScan/);
  assert.match(api, /launchHmairDeepScan/);
  assert.match(api, /getHmairDeepScanCoverage/);
  assert.match(api, /deep-scan\/preflight/);
  assert.match(api, /deep-scan/);
  assert.match(api, /\/coverage/);
  assert.match(types, /DeepScanPreflightRequest/);
  assert.match(types, /DeepScanCoverage/);
});

test("demo readiness uses already-loaded evidence and keeps unconnected sources explicit", () => {
  assert.match(operations, /DiscoveryDemoReadiness/);
  assert.match(readinessState, /Endpoint metadata inventory/);
  assert.match(readinessState, /Managed browser/);
  assert.match(readinessState, /Governed MCP and runtime/);
  assert.match(readinessState, /endpoint_group/);
  assert.match(readinessState, /browser_tenant/);
  assert.match(readinessState, /mcp_environment/);
  assert.match(readinessState, /llm_gateway/);
  assert.match(readinessState, /runtime_environment/);
  assert.match(readiness, /Not connected/);
  assert.match(readinessState, /evidence_fresh_at/);
  assert.doesNotMatch(readiness, /api\./);
  assert.doesNotMatch(readinessState, /organization-wide coverage/i);
  assert.doesNotMatch(readinessState, /risk score|risk_rating|coverage percentage/i);
  assert.doesNotMatch(readinessState, /raw prompt|browser history|cookies|credentials|MCP args/i);
});

test("demo readiness renders source coverage truth and endpoint inventory state without a blanket observed label", () => {
  const [endpoint, browser, runtime] = DEMO_READINESS_DEFINITIONS;
  const targets = [
    { target_id: "endpoint-1", target_type: "endpoint_group", identifier: "mac-fleet", active_scan_allowed: true },
    { target_id: "browser-1", target_type: "browser_tenant", identifier: "managed-chrome", active_scan_allowed: true },
    { target_id: "runtime-1", target_type: "mcp_environment", identifier: "governed-runtime", active_scan_allowed: true },
  ];
  const collectors = [
    { collector_id: "endpoint-c", collector_type: "endpoint", supported_targets: ["endpoint_group"], enabled: true, health: "healthy" },
    { collector_id: "browser-c", collector_type: "browser", supported_targets: ["browser_tenant"], enabled: true, health: "healthy" },
    { collector_id: "runtime-c", collector_type: "runtime", supported_targets: ["mcp_environment"], enabled: true, health: "warning" },
  ];

  const stale = resolveDemoReadinessState({
    definition: runtime,
    targets,
    collectors,
    coverageSources: [{ target_type: "mcp_environment", coverage_state: "stale", readiness: "stale", reason: "control_stale", limitation: ["validation overdue"], evidence_fresh_at: "2026-09-08T10:00:00Z" }],
  });
  assert.equal(stale.state, "stale");
  assert.equal(stale.lastEvidenceAt, "2026-09-08T10:00:00Z");
  assert.match(stale.details.join(" "), /control_stale/);
  assert.match(stale.details.join(" "), /validation overdue/);

  const unsupported = resolveDemoReadinessState({
    definition: browser,
    targets,
    collectors,
    coverageSources: [{ target_type: "browser_tenant", coverage_state: "unsupported", readiness: "unsupported", reason: "source_not_supported", limitation: [], evidence_fresh_at: null }],
  });
  assert.equal(unsupported.state, "unsupported");
  assert.equal(unsupported.lastEvidenceAt, null);

  const unknown = resolveDemoReadinessState({ definition: browser, targets, collectors, coverageSources: [] });
  assert.equal(unknown.state, "Configured — evidence pending");

  const completedInventory = resolveDemoReadinessState({
    definition: endpoint,
    targets,
    collectors,
    coverageSources: [],
    latestInventoryRun: { status: "complete", completed_count: 1, failed_count: 0, limitations: ["metadata_only"] },
  });
  assert.equal(completedInventory.state, "Inventory complete");
  assert.equal(completedInventory.lastEvidenceAt, null);
  assert.match(completedInventory.details.join(" "), /completed 1/);
  assert.match(completedInventory.details.join(" "), /metadata_only/);

  const failedInventory = resolveDemoReadinessState({
    definition: endpoint,
    targets,
    collectors,
    coverageSources: [],
    latestInventoryRun: { status: "failed", completed_count: 0, failed_count: 1, limitations: ["agent_unavailable"] },
  });
  assert.equal(failedInventory.state, "Inventory failed");

  const completedHistoricalInventoryWithoutCurrentSource = resolveDemoReadinessState({
    definition: endpoint,
    targets: [],
    collectors: [],
    coverageSources: [],
    latestInventoryRun: { status: "complete", completed_count: 1, failed_count: 0, limitations: ["metadata_only"] },
  });
  assert.equal(completedHistoricalInventoryWithoutCurrentSource.state, "Inventory complete");
  assert.equal(completedHistoricalInventoryWithoutCurrentSource.sourcePathState, "Not connected");
  assert.equal(completedHistoricalInventoryWithoutCurrentSource.lastEvidenceAt, null);

  const mixedRuntimeCoverage = resolveDemoReadinessState({
    definition: runtime,
    targets,
    collectors,
    coverageSources: [
      { target_type: "mcp_environment", coverage_state: "current", readiness: "ready", reason: null, limitation: [], evidence_fresh_at: "2026-09-08T09:00:00Z" },
      { target_type: "llm_gateway", coverage_state: "stale", readiness: "stale", reason: "gateway_validation_overdue", limitation: ["revalidate gateway"], evidence_fresh_at: "2026-09-08T10:00:00Z" },
    ],
  });
  assert.equal(mixedRuntimeCoverage.state, "stale");
  assert.equal(mixedRuntimeCoverage.coverageSources.length, 2);
  assert.equal(mixedRuntimeCoverage.coverageSources[0].target_type, "mcp_environment");
  assert.equal(mixedRuntimeCoverage.coverageSources[1].target_type, "llm_gateway");
  assert.match(mixedRuntimeCoverage.details.join(" "), /gateway_validation_overdue/);
  assert.match(mixedRuntimeCoverage.details.join(" "), /revalidate gateway/);
});

test("visibility recovery validates role and reason, retries safely, and only clears after both view requests succeed", async () => {
  const owner = { user: { id: "owner-1" }, userRole: "owner" };
  const analyst = { user: { id: "analyst-1" }, userRole: "analyst" };
  const expectedPayload = {
    user_id: "owner-1",
    capabilities: ["view_aggregates", "view_user_metadata", "view_action_details"],
    department_scope: [],
    reason: "Security demo review",
  };

  assert.deepEqual(buildVisibilityRecoveryPayload(owner, "Security demo review"), expectedPayload);
  assert.equal(buildVisibilityRecoveryPayload(analyst, "Security demo review"), null);
  assert.equal(buildVisibilityRecoveryPayload(owner, "ab"), null);
  assert.equal(buildVisibilityRecoveryPayload(owner, "a".repeat(1001)), null);
  assert.equal(canSubmitVisibilityRecovery({ session: owner, reason: "Security demo review", isSubmitting: false }), true);
  assert.equal(canSubmitVisibilityRecovery({ session: owner, reason: "ab", isSubmitting: false }), false);
  assert.equal(canSubmitVisibilityRecovery({ session: owner, reason: "Security demo review", isSubmitting: true }), false);
  assert.equal(canSubmitVisibilityRecovery({ session: analyst, reason: "Security demo review", isSubmitting: false }), false);

  let attempts = 0;
  const first = await submitVisibilityRecovery({
    session: owner,
    reason: "Security demo review",
    createGrant: async () => { attempts += 1; throw new Error("transient failure"); },
  });
  assert.equal(first.ok, false);
  assert.equal(first.error?.message, "transient failure");
  const second = await submitVisibilityRecovery({
    session: owner,
    reason: "Security demo review",
    createGrant: async (payload) => { attempts += 1; assert.deepEqual(payload, expectedPayload); },
  });
  assert.equal(second.ok, true);
  assert.equal(attempts, 2);

  const partial = await loadUserVisibilityData({
    loadUsers: async () => ({ items: ["user"] }),
    loadDirectorySummary: async () => { throw new Error("visibility_capability_required"); },
  });
  assert.equal(partial.allSucceeded, false);
  assert.equal(partial.capabilityRequired, true);

  const complete = await loadUserVisibilityData({
    loadUsers: async () => ({ items: ["user"] }),
    loadDirectorySummary: async () => ({ known_user_count: 1 }),
  });
  assert.equal(complete.allSucceeded, true);
  assert.equal(complete.capabilityRequired, false);
});
