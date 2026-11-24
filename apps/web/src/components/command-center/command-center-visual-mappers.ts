import type { CommandCenterDashboardState } from "@/lib/types";

import type {
  EvidenceRiverEvent,
  GovernanceOverviewModel,
  GovernanceSurfaceRow,
  GovernanceTruthState,
  RiverEventKind,
} from "./command-center-visual-types";

type ActivityItem = NonNullable<CommandCenterDashboardState["live_activity_feed"]>["items"][number];
type SurfaceSourceRow = NonNullable<NonNullable<CommandCenterDashboardState["surface_coverage_summary"]>["surface_rows"]>[number];

function finiteNumber(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(0, parsed) : 0;
}

function normalized(value: unknown): string {
  return String(value || "").trim().toLowerCase();
}

function titleCase(value: unknown, fallback = "Unknown"): string {
  const text = String(value || "").trim();
  if (!text) return fallback;
  return text
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function hasEvidence(item: ActivityItem): boolean {
  const evidence = item.decision_explanation?.evidence;
  return Boolean(
    evidence?.evidence_bundle_id
    || evidence?.trace_id
    || evidence?.event_hash
    || evidence?.finding_id
    || evidence?.evidence_refs?.length
  );
}

function evidenceState(item: ActivityItem): EvidenceRiverEvent["evidenceState"] {
  if (hasEvidence(item)) return "verified";
  if (item.finding_id || item.action_trace_url || item.action_graph_url) return "incomplete";
  return "unknown";
}

function eventKind(item: ActivityItem): RiverEventKind {
  const decision = normalized(item.policy_decision);
  if (["block", "blocked", "deny", "denied", "prevent", "prevented"].some((word) => decision.includes(word))) {
    return "enforcement";
  }
  if (["warn", "review", "approval", "challenge"].some((word) => decision.includes(word))) {
    return "intervention";
  }
  if (item.finding_id) return "alert";
  if (hasEvidence(item)) return "proof";
  return "action";
}

function materialEvent(item: ActivityItem): boolean {
  const kind = eventKind(item);
  const action = normalized(item.action_type);
  if (kind !== "action") return true;
  return !["heartbeat", "page_view", "telemetry", "health_check"].some((noise) => action.includes(noise));
}

function compareTimestamp(left: ActivityItem, right: ActivityItem): number {
  const leftTime = Date.parse(String(left.timestamp || ""));
  const rightTime = Date.parse(String(right.timestamp || ""));
  const safeLeft = Number.isFinite(leftTime) ? leftTime : 0;
  const safeRight = Number.isFinite(rightTime) ? rightTime : 0;
  if (safeLeft !== safeRight) return safeLeft - safeRight;
  return String(left.event_id).localeCompare(String(right.event_id));
}

export function mapEvidenceRiverEvents(items: ActivityItem[] = [], limit = 12): EvidenceRiverEvent[] {
  const visibleLimit = Math.min(12, Math.max(1, Math.trunc(limit) || 12));
  const unique = new Map<string, ActivityItem>();

  for (const item of items) {
    const id = String(item.event_id || "").trim();
    if (!id || unique.has(id) || !materialEvent(item)) continue;
    unique.set(id, item);
  }

  return Array.from(unique.values())
    .sort(compareTimestamp)
    .slice(-visibleLimit)
    .map((item) => {
      const proof = evidenceState(item);
      const decision = titleCase(item.policy_decision, "Unknown decision");
      const action = titleCase(item.tool_name || item.action_type, "Observed action");
      const surface = titleCase(item.ai_surface, "Unknown surface");
      const application = titleCase(item.application, surface);
      const actor = item.user_email || item.user_id || item.agent_id || item.machine_id || "Unknown actor";
      return {
        id: item.event_id,
        timestamp: item.timestamp || null,
        kind: eventKind(item),
        surface,
        application,
        action,
        actor,
        decision,
        evidenceState: proof,
        summary: `${application} · ${action}`,
        traceHref: item.action_trace_url || item.trace_url || null,
        evidenceHref: proof === "verified" ? (item.finding_traceability_url || item.action_trace_url || item.trace_url || null) : null,
        findingHref: item.finding_url || (item.finding_id ? `/discovery/findings/${encodeURIComponent(item.finding_id)}` : null),
      } satisfies EvidenceRiverEvent;
    });
}

function surfaceState(row: SurfaceSourceRow): GovernanceTruthState {
  const mode = normalized(row.dominant_control_mode || row.current_mode);
  const coverage = normalized(row.coverage);
  const status = normalized(row.status);
  const inline = finiteNumber(row.inline_prevented) + finiteNumber(row.inline_allowed);
  if (inline > 0 || mode.includes("inline_verified")) return "verified";
  if (
    finiteNumber(row.detected_only) + finiteNumber(row.telemetry_only) + finiteNumber(row.shadow_would_block) > 0
    || ["monitor", "detected", "telemetry", "shadow"].some((word) => mode.includes(word))
  ) return "monitor_only";
  if (
    coverage.includes("not_covered")
    || coverage.includes("outside")
    || status.includes("not_covered")
    || status.includes("outside")
  ) return "not_covered";
  return "unknown";
}

function mapSurface(row: SurfaceSourceRow): GovernanceSurfaceRow {
  return {
    id: String(row.id || row.surface_type || row.label),
    label: row.label || titleCase(row.surface_type),
    state: surfaceState(row),
    eventCount: finiteNumber(row.event_count),
    decisionCount: finiteNumber(row.blocked) + finiteNumber(row.warned) + finiteNumber(row.inline_allowed),
    evidenceLabel: row.proof_label || "Unknown",
    controlLabel: row.primary_control || "Unknown",
    drilldown: row.drilldown || "/surface-coverage",
    applications: Array.isArray(row.apps) ? row.apps.filter(Boolean) : [],
  };
}

function interventionSeries(items: ActivityItem[]): Array<{ label: string; value: number }> {
  const buckets = new Map<string, number>();
  for (const item of items) {
    if (!["enforcement", "intervention"].includes(eventKind(item))) continue;
    const parsed = new Date(String(item.timestamp || ""));
    if (Number.isNaN(parsed.getTime())) continue;
    const key = parsed.toISOString().slice(0, 10);
    buckets.set(key, (buckets.get(key) || 0) + 1);
  }
  return Array.from(buckets.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .slice(-7)
    .map(([date, value]) => ({
      label: new Intl.DateTimeFormat("en", { month: "short", day: "numeric", timeZone: "UTC" }).format(new Date(`${date}T00:00:00Z`)),
      value,
    }));
}

export function deriveGovernanceOverview(data: Partial<CommandCenterDashboardState> | null | undefined): GovernanceOverviewModel {
  const activity = data?.live_activity_feed?.items || [];
  const heatmapRows = data?.runtime_heatmap?.rows || [];
  const surfaceRows = (data?.surface_coverage_summary?.surface_rows || []).map(mapSurface);
  const discoveredCategories = heatmapRows
    .map((row) => ({ label: titleCase(row.surface), value: finiteNumber(row.total) }))
    .filter((row) => row.value > 0)
    .sort((left, right) => right.value - left.value);
  const observedAssets = new Set<string>();
  for (const row of data?.surface_coverage_summary?.surface_rows || []) {
    for (const value of [...(row.apps || []), ...(row.agents || []), ...(row.users || [])]) {
      if (value) observedAssets.add(String(value));
    }
  }
  const stateCounts = surfaceRows.reduce<Record<GovernanceTruthState, number>>(
    (counts, row) => ({ ...counts, [row.state]: counts[row.state] + 1 }),
    { verified: 0, monitor_only: 0, not_covered: 0, unknown: 0 },
  );
  const executedRuns = finiteNumber(data?.simulations?.total_runs);
  const passedRuns = finiteNumber(data?.simulations?.pass_count);
  const failedRuns = finiteNumber(data?.simulations?.fail_count);
  const proofCounts = activity.reduce(
    (counts, item) => {
      const state = evidenceState(item);
      if (state === "verified") counts.verified += 1;
      else if (state === "incomplete") counts.incomplete += 1;
      else counts.unknown += 1;
      return counts;
    },
    { verified: 0, incomplete: 0, unknown: 0 },
  );

  return {
    discovery: {
      observedEvents: heatmapRows.reduce((total, row) => total + finiteNumber(row.total), 0),
      observedAssets: observedAssets.size,
      totalEstateKnown: false,
      categories: discoveredCategories,
    },
    protect: {
      inlineVerified: stateCounts.verified,
      monitorOnly: stateCounts.monitor_only,
      notCovered: stateCounts.not_covered,
      unknown: stateCounts.unknown,
      totalSurfaces: surfaceRows.length,
    },
    validate: {
      executedRuns,
      passedRuns,
      failedRuns,
      passRate: executedRuns > 0 ? Math.round((passedRuns / executedRuns) * 100) : null,
      profile: (data?.control_coverage?.lowest_controls || []).slice(0, 6).map((control) => ({
        control: String(control.control_id || "Control"),
        observed: Math.round(finiteNumber(control.technical_enforcement_score) * 100),
        simulated: Math.round(finiteNumber(control.simulation_pass_rate) * 100),
      })),
    },
    prove: {
      evidenceLinkedActions: proofCounts.verified,
      incompleteActions: proofCounts.incomplete,
      unknownActions: proofCounts.unknown,
    },
    surfaces: surfaceRows,
    interventions: interventionSeries(activity),
    river: mapEvidenceRiverEvents(activity),
  };
}
