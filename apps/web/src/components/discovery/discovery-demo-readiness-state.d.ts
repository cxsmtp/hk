export type DemoReadinessDefinition = {
  label: string;
  targetFamilies: string[];
  limitation: string;
  href: "/discovery/scans" | "/discovery/assets" | "/users" | "/runtime-intelligence/activity-map";
  hrefLabel: string;
};

export type ReadinessTarget = {
  target_type: string;
  identifier: string;
  active_scan_allowed: boolean;
};

export type ReadinessCollector = {
  collector_type: string;
  supported_targets: string[];
  enabled: boolean;
  health: string;
};

export type ReadinessCoverageSource = {
  target_type: string;
  coverage_state: string;
  readiness: string;
  reason: string | null;
  limitation: string[];
  evidence_fresh_at: string | null;
};

export type EndpointInventory = {
  status: string;
  completed_count: number;
  failed_count: number;
  limitations: string[];
};

export const DEMO_READINESS_DEFINITIONS: DemoReadinessDefinition[];

export function resolveDemoReadinessState(input: {
  definition: DemoReadinessDefinition;
  targets: ReadinessTarget[];
  collectors: ReadinessCollector[];
  coverageSources: ReadinessCoverageSource[];
  latestInventoryRun?: EndpointInventory | null;
}): {
  state: string;
  matchingTargets: ReadinessTarget[];
  matchingCollectors: ReadinessCollector[];
  sourcePathState: string;
  coverageSources: ReadinessCoverageSource[];
  lastEvidenceAt: string | null;
  details: string[];
  inventory: EndpointInventory | null;
};
