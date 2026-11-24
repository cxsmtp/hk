export const DEMO_READINESS_DEFINITIONS = [
  {
    label: "Endpoint metadata inventory",
    targetFamilies: ["endpoint_group"],
    limitation: "An enrolled endpoint target and an enabled collector are required before metadata evidence can be observed.",
    href: "/discovery/assets",
    hrefLabel: "View discovered assets",
  },
  {
    label: "Managed browser",
    targetFamilies: ["browser_tenant"],
    limitation: "Managed browser health and a recent metadata event are required before browser evidence can be shown.",
    href: "/users",
    hrefLabel: "Open user visibility",
  },
  {
    label: "Governed MCP and runtime",
    targetFamilies: ["mcp_environment", "llm_gateway", "runtime_environment"],
    limitation: "A governed runtime or gateway target and an enabled collector are required before signed tool or runtime evidence can be shown.",
    href: "/runtime-intelligence/activity-map",
    hrefLabel: "Open activity lineage",
  },
];

function matches(targetType, families) {
  return families.includes(targetType);
}

function inventoryState(status) {
  const normalized = status.trim().toLowerCase();
  if (normalized === "complete") return "Inventory complete";
  if (normalized === "partially_complete") return "Inventory partial";
  if (normalized === "failed") return "Inventory failed";
  if (normalized === "expired") return "Inventory expired";
  if (normalized === "cancelled") return "Inventory cancelled";
  if (normalized === "running") return "Inventory running";
  return "Inventory queued";
}

function conservativeCoverageState(sources) {
  const states = sources
    .map((source) => String(source.coverage_state || source.readiness || "unknown").trim().toLowerCase())
    .filter(Boolean);
  const priority = ["unsupported", "regressed", "stale", "gap", "partial", "unknown", "not_connected"];
  const material = priority.find((state) => states.includes(state));
  if (material) return material;
  if (new Set(states).size > 1) return "Mixed coverage";
  return states[0] || "unknown";
}

export function resolveDemoReadinessState({
  definition,
  targets,
  collectors,
  coverageSources,
  latestInventoryRun,
}) {
  const matchingTargets = targets.filter((target) => matches(target.target_type, definition.targetFamilies));
  const matchingCollectors = collectors.filter((collector) => collector.supported_targets.some((targetType) => matches(targetType, definition.targetFamilies)));
  const enabledCollectors = matchingCollectors.filter((collector) => collector.enabled);
  const matchingCoverage = coverageSources.filter((source) => matches(source.target_type, definition.targetFamilies));
  const endpointInventory = definition.targetFamilies.includes("endpoint_group") ? latestInventoryRun || null : null;
  const connected = matchingTargets.length > 0 && enabledCollectors.length > 0;
  const details = [];

  if (!connected) details.push(definition.limitation);
  matchingCoverage.forEach((coverage) => {
    details.push(`${coverage.target_type}: coverage state ${coverage.coverage_state || "unknown"}; readiness ${coverage.readiness || "unknown"}.`);
    if (coverage.reason) details.push(`${coverage.target_type} reason: ${coverage.reason}.`);
    coverage.limitation.filter(Boolean).forEach((limitation) => details.push(`${coverage.target_type} limitation: ${limitation}.`));
  });
  if (endpointInventory) {
    details.push(`Inventory status: ${endpointInventory.status}; completed ${endpointInventory.completed_count}; failed ${endpointInventory.failed_count}.`);
    endpointInventory.limitations.filter(Boolean).forEach((limitation) => details.push(`Inventory limitation: ${limitation}.`));
    if (!matchingCoverage.some((coverage) => coverage.evidence_fresh_at)) details.push("Inventory status does not provide a fresh evidence timestamp.");
  }

  const inventoryIsUnhealthy = endpointInventory && ["queued", "running", "failed", "expired", "cancelled", "partially_complete"].includes(endpointInventory.status.trim().toLowerCase());
  const sourcePathState = !connected
    ? "Not connected"
    : matchingCoverage.length
      ? conservativeCoverageState(matchingCoverage)
      : "Configured — evidence pending";
  const state = endpointInventory && (!matchingCoverage.length || inventoryIsUnhealthy)
    ? inventoryState(endpointInventory.status)
    : sourcePathState;
  const lastEvidenceAt = matchingCoverage
    .map((coverage) => coverage.evidence_fresh_at)
    .filter(Boolean)
    .sort((left, right) => new Date(right).getTime() - new Date(left).getTime())[0] || null;

  return {
    state,
    matchingTargets,
    matchingCollectors,
    sourcePathState,
    coverageSources: matchingCoverage,
    lastEvidenceAt,
    details,
    inventory: endpointInventory,
  };
}
