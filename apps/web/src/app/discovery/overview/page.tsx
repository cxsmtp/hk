"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { AISystem, Connector, DriftAlert, ExposureScanState, Finding, ShadowAIEntity } from "@/lib/types";


type SeverityKey = "low" | "med" | "high" | "critical";

const severityLabels: Record<SeverityKey, string> = {
  low: "Low",
  med: "Medium",
  high: "High",
  critical: "Critical",
};

const severityColors: Record<SeverityKey, string> = {
  low: "bg-emerald-500",
  med: "bg-amber-500",
  high: "bg-orange-500",
  critical: "bg-red-600",
};

const LOCAL_AGENT_HINTS = [
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  ".local",
  "local_model",
  "litellm",
  "ollama",
  "open-webui",
  "openwebui",
  "lmstudio",
  "vllm",
  "llama.cpp",
  "qwen",
  "llama",
  "mistral",
  "gguf",
];

function scanStatusBadgeClass(status: string): string {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "completed") return "bg-emerald-950 text-emerald-300";
  if (normalized === "running") return "bg-sky-950 text-sky-300";
  if (normalized === "failed") return "bg-rose-950 text-rose-300";
  return "bg-slate-800 text-slate-300";
}

function localAgentStatusBadgeClass(status: string): string {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "promoted" || normalized === "reconciled") return "bg-emerald-950 text-emerald-300";
  if (normalized === "discovered") return "bg-amber-950 text-amber-300";
  if (normalized === "rejected") return "bg-rose-950 text-rose-300";
  return "bg-slate-800 text-slate-300";
}

function emptyScanState(): ExposureScanState {
  return {
    scan_id: null,
    status: "no_data",
    scan_type: "discovery",
    scope: "global",
    scope_value: null,
    last_scan_time: null,
    started_at: null,
    ended_at: null,
    summary: {
      new_ai_apps_detected: 0,
      unknown_apps: 0,
      new_users_detected: 0,
      new_endpoints_detected: 0,
      new_risks_identified: 0,
      alerts_generated: 0,
      total_ai_apps: 0,
    },
    delta: {
      apps_added: [],
      users_added: [],
      endpoints_added: [],
      risks_added: [],
      alerts_added: [],
    },
    links: {
      new_ai_apps: "/shadow-ai?state=new",
      unknown_tools: "/shadow-ai?state=unknown",
      new_users: "/ai-iam?filter=recently_discovered",
      new_endpoints: "/ai-iam?filter=recently_discovered",
      new_risks: "/discovery/findings?source=scan_delta",
      alerts: "/dashboard/command-center?focus=alerts",
      full_report: "/shadow-ai",
    },
    error: null,
    duration_ms: null,
    data_source: "active_runtime_crawl",
    snapshot_counts: {
      apps: 0,
      users: 0,
      endpoints: 0,
      risks: 0,
      alerts: 0,
      unknown_apps: 0,
    },
  };
}

function toDate(value?: string | null): Date | null {
  if (!value) return null;
  const out = new Date(value);
  return Number.isNaN(out.getTime()) ? null : out;
}

function formatDateTime(value?: string | null): string {
  const parsed = toDate(value);
  return parsed ? parsed.toLocaleString() : "-";
}

function formatDurationMs(value?: number | null): string {
  const ms = Number(value || 0);
  if (!Number.isFinite(ms) || ms <= 0) return "-";
  if (ms < 1000) return `${ms}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const rem = Math.round(seconds % 60);
  return `${minutes}m ${rem}s`;
}

function numberOrZero(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return parsed;
}

function maxDateIso(left?: string | null, right?: string | null): string | null {
  const leftDate = toDate(left);
  const rightDate = toDate(right);
  if (!leftDate && !rightDate) return null;
  if (!leftDate) return right ?? null;
  if (!rightDate) return left ?? null;
  return leftDate >= rightDate ? leftDate.toISOString() : rightDate.toISOString();
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out = value
    .map((item) => String(item || "").trim())
    .filter(Boolean);
  return Array.from(new Set(out));
}

function includesLocalAgentHint(value: string | null | undefined): boolean {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return false;
  return LOCAL_AGENT_HINTS.some((token) => normalized.includes(token));
}

function firstNonEmpty(...values: Array<string | null | undefined>): string | null {
  for (const value of values) {
    const normalized = String(value || "").trim();
    if (normalized) return normalized;
  }
  return null;
}

export default function DiscoveryOverviewPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [systems, setSystems] = useState<AISystem[]>([]);
  const [alerts, setAlerts] = useState<DriftAlert[]>([]);
  const [shadowEntities, setShadowEntities] = useState<ShadowAIEntity[]>([]);
  const [scanState, setScanState] = useState<ExposureScanState>(emptyScanState());
  const [loading, setLoading] = useState(true);
  const [hasLoadFailure, setHasLoadFailure] = useState(false);
  const [scanBusy, setScanBusy] = useState(false);

  const loadScanState = useCallback(async () => {
    try {
      const payload = await api.latestScan();
      setScanState(payload);
    } catch {
      setScanState((prev) => (prev?.scan_id ? prev : emptyScanState()));
    }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setHasLoadFailure(false);
    const [findingsResult, connectorsResult, systemsResult, alertsResult, shadowResult, scanResult] = await Promise.allSettled([
      api.listFindings(),
      api.listConnectors(),
      api.listAISystems(),
      api.listDriftAlerts(),
      api.listShadowAIEntities({ page_size: 300 }),
      api.latestScan(),
    ]);

    const sourceNames = ["findings", "connectors", "AI systems", "drift alerts", "shadow AI entities", "scan status"];
    const failedMessages = [
      findingsResult,
      connectorsResult,
      systemsResult,
      alertsResult,
      shadowResult,
      scanResult,
    ]
      .flatMap((result, index) => result.status === "rejected" ? [`${sourceNames[index]}: ${result.reason instanceof Error ? result.reason.message : "Request failed"}`] : [])
      .filter(Boolean);

    if (findingsResult.status === "fulfilled") {
      setFindings(findingsResult.value.items || []);
    }
    if (connectorsResult.status === "fulfilled") {
      setConnectors(connectorsResult.value.items || []);
    }
    if (systemsResult.status === "fulfilled") {
      setSystems(systemsResult.value.items || []);
    }
    if (alertsResult.status === "fulfilled") {
      setAlerts(alertsResult.value.items || []);
    }
    if (shadowResult.status === "fulfilled") {
      setShadowEntities(shadowResult.value.items || []);
    }
    if (scanResult.status === "fulfilled") {
      setScanState(scanResult.value);
    } else {
      setScanState((prev) => (prev?.scan_id ? prev : emptyScanState()));
    }

    if (failedMessages.length > 0) {
      setHasLoadFailure(true);
      const unique = Array.from(new Set(failedMessages));
      toast.error(`Partial refresh: ${unique[0]}. Showing last successful snapshot for unavailable modules.`, {
        id: "discovery-overview-partial-refresh",
      });
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  useEffect(() => {
    if (String(scanState.status || "").toLowerCase() !== "running") return;
    const timer = setInterval(() => {
      loadScanState().catch(() => undefined);
    }, 3000);
    return () => clearInterval(timer);
  }, [loadScanState, scanState.status]);

  const runDiscoveryScan = useCallback(async () => {
    if (scanBusy) return;
    setScanBusy(true);
    try {
      const response = await api.triggerScan({
        scan_type: "discovery",
        scope: "global",
        parameters: {},
      });
      if (response.status === "running") {
        toast.success("AI exposure scan started.");
      } else {
        toast.message("Scan is already running. Refreshing status.");
      }
      await loadScanState();
      load().catch(() => undefined);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to trigger AI exposure scan");
    } finally {
      setScanBusy(false);
    }
  }, [load, loadScanState, scanBusy]);

  const kpis = useMemo(() => {
    const activeTools = new Set<string>();
    connectors.forEach((connector) => {
      if (connector.enabled) activeTools.add(connector.name);
    });
    findings.forEach((finding) => {
      if (finding.ai_tool) activeTools.add(finding.ai_tool);
    });

    const approvedCount = systems.filter((system) => {
      const status = String(system.status || "").toLowerCase();
      return status === "approved" || status === "active";
    }).length;
    const shadowCount = new Set(
      findings
        .filter((finding) => finding.finding_type === "shadow_ai_discovery")
        .map((finding) => finding.ai_tool)
        .filter(Boolean)
    ).size;
    const highSeverityCount = findings.filter(
      (finding) => (finding.severity === "high" || finding.severity === "critical") && (finding.status === "open" || finding.status === "reviewing")
    ).length;
    const teamsAtRisk = new Set(
      findings
        .filter((finding) => (finding.severity === "high" || finding.severity === "critical") && (finding.status === "open" || finding.status === "reviewing"))
        .map((finding) => finding.department || "unassigned")
    ).size;

    return {
      activeAIApps: activeTools.size,
      approvedVsShadow: `${approvedCount} approved / ${shadowCount} shadow`,
      highSeverityCount,
      teamsAtRisk,
    };
  }, [connectors, findings, systems]);

  const localAgents = useMemo(() => {
    return shadowEntities
      .map((entity) => {
        const metadata = asRecord(entity.metadata_json);
        const observedDomains = (entity.observed_domains || []).map((item) => String(item || "").trim()).filter(Boolean);
        const observedProviders = (entity.observed_providers || []).map((item) => String(item || "").trim()).filter(Boolean);
        const sourceIdentifiers = asStringList(metadata.source_identifiers);
        const detectedTools = Array.from(
          new Set([
            ...asStringList(metadata.detected_tools),
            ...asStringList(metadata.tools),
            ...asStringList(metadata.tool_registry),
          ])
        );
        const detectedActions = Array.from(
          new Set([
            ...asStringList(metadata.detected_actions),
            ...asStringList(metadata.actions),
            ...asStringList(metadata.action_scope),
          ])
        );
        const detectedPrivileges = Array.from(
          new Set([
            ...asStringList(metadata.detected_privileges),
            ...asStringList(metadata.privileges),
            ...asStringList(metadata.external_system_access),
          ])
        );

        const localSignals = [
          entity.canonical_name,
          entity.vendor || "",
          entity.deployment_type || "",
          entity.ai_type || "",
          ...observedDomains,
          ...observedProviders,
          ...sourceIdentifiers,
          String(metadata.agent_name || ""),
          String(metadata.model_name || metadata.model || ""),
          String(metadata.runtime_provider || ""),
        ];
        const hasLocalHint = localSignals.some((item) => includesLocalAgentHint(item));

        const isLocalType =
          String(entity.ai_type || "").toLowerCase().includes("local")
          || String(entity.deployment_type || "").toLowerCase().includes("local");

        const shouldInclude = hasLocalHint || isLocalType;
        if (!shouldInclude) return null;

        const runtime = firstNonEmpty(
          typeof metadata.runtime_provider === "string" ? metadata.runtime_provider : null,
          entity.vendor,
          entity.deployment_type,
          entity.ai_type
        ) || "unknown";

        const model = firstNonEmpty(
          typeof metadata.model_name === "string" ? metadata.model_name : null,
          typeof metadata.model === "string" ? metadata.model : null,
          observedProviders[0] || null
        ) || "-";

        const accessSignals = [
          detectedTools.length ? `Tools: ${detectedTools.slice(0, 3).join(", ")}` : null,
          detectedActions.length ? `Actions: ${detectedActions.slice(0, 3).join(", ")}` : null,
          detectedPrivileges.length ? `Privileges: ${detectedPrivileges.slice(0, 3).join(", ")}` : null,
        ].filter(Boolean) as string[];

        return {
          id: entity.id,
          name: firstNonEmpty(
            typeof metadata.agent_name === "string" ? metadata.agent_name : null,
            entity.canonical_name
          ) || "unknown-local-agent",
          domain: firstNonEmpty(
            observedDomains[0] || null,
            sourceIdentifiers.find((item) => includesLocalAgentHint(item)) || null,
            entity.canonical_name
          ) || "-",
          runtime,
          model,
          accessSummary: accessSignals.join(" · "),
          status: entity.discovery_status,
          riskTier: entity.provisional_risk_tier || "MEDIUM",
          linkedAiSystemId: entity.linked_ai_system_id || null,
          lastSeen: entity.last_seen,
          openFindings: numberOrZero(entity.open_findings),
          signalCount: numberOrZero(entity.signal_count),
        };
      })
      .filter((row): row is NonNullable<typeof row> => row !== null)
      .sort((a, b) => (toDate(b.lastSeen)?.getTime() || 0) - (toDate(a.lastSeen)?.getTime() || 0))
      .slice(0, 12);
  }, [shadowEntities]);

  const severitySeries = useMemo(() => {
    const counters: Record<SeverityKey, number> = {
      low: 0,
      med: 0,
      high: 0,
      critical: 0,
    };
    findings.forEach((finding) => {
      const severity = finding.severity as SeverityKey;
      if (severity in counters) counters[severity] += 1;
    });
    return (Object.keys(counters) as SeverityKey[]).map((severity) => ({
      severity,
      count: counters[severity],
    }));
  }, [findings]);

  const shadowTrend = useMemo(() => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const days = 7;
    const byDate = new Map<string, number>();
    for (let i = days - 1; i >= 0; i -= 1) {
      const day = new Date(today);
      day.setDate(today.getDate() - i);
      const key = day.toISOString().slice(0, 10);
      byDate.set(key, 0);
    }
    findings
      .filter((finding) => finding.finding_type === "shadow_ai_discovery")
      .forEach((finding) => {
        const date = toDate(finding.created_at);
        if (!date) return;
        const key = date.toISOString().slice(0, 10);
        if (byDate.has(key)) {
          byDate.set(key, (byDate.get(key) || 0) + 1);
        }
      });
    return Array.from(byDate.entries()).map(([key, count]) => ({
      key,
      label: new Date(`${key}T00:00:00Z`).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
      count,
    }));
  }, [findings]);

  const topApps = useMemo(() => {
    const appMap = new Map<string, { app: string; findings: number; lastSeen: string | null }>();
    findings.forEach((finding) => {
      const app = finding.ai_tool || "unknown";
      const current = appMap.get(app) || { app, findings: 0, lastSeen: null };
      current.findings += 1;
      current.lastSeen = maxDateIso(current.lastSeen, finding.last_seen_at);
      appMap.set(app, current);
    });
    return Array.from(appMap.values())
      .sort((a, b) => (b.findings - a.findings) || (toDate(b.lastSeen)?.getTime() || 0) - (toDate(a.lastSeen)?.getTime() || 0))
      .slice(0, 6);
  }, [findings]);

  const sourceCoverageMix = useMemo(() => {
    const bySource = new Map<string, number>();
    findings.forEach((finding) => {
      const key = String(finding.source_surface || "unknown");
      bySource.set(key, (bySource.get(key) || 0) + 1);
    });
    return Array.from(bySource.entries())
      .map(([source, count]) => ({ source, count }))
      .sort((a, b) => b.count - a.count);
  }, [findings]);

  const recentFindings = useMemo(
    () =>
      [...findings]
        .sort((a, b) => (toDate(b.updated_at)?.getTime() || 0) - (toDate(a.updated_at)?.getTime() || 0))
        .slice(0, 8),
    [findings]
  );

  const recommendedSteps = useMemo(() => {
    const steps: string[] = [];
    if (kpis.highSeverityCount > 0) {
      steps.push(`Triage ${kpis.highSeverityCount} high-severity findings and assign accountable owners this week.`);
    }
    if (alerts.length > 0) {
      steps.push(`Review ${alerts.length} drift alerts and validate control mappings against current policy versions.`);
    }
    if (shadowTrend.some((point) => point.count > 0)) {
      steps.push("Convert repeated shadow AI discoveries into approved tools with governance ownership and policy coverage.");
    }
    if (steps.length === 0 && !loading && !hasLoadFailure) steps.push("Review the latest discovery snapshot and assign owners as evidence arrives.");
    return steps.slice(0, 4);
  }, [alerts.length, hasLoadFailure, kpis.highSeverityCount, loading, shadowTrend]);

  const maxSeverityCount = Math.max(1, ...severitySeries.map((entry) => entry.count));
  const maxShadowCount = Math.max(1, ...shadowTrend.map((entry) => entry.count));
  const scanSummary = scanState.summary || emptyScanState().summary;
  const scanLinks = scanState.links || emptyScanState().links;
  const scanCounts = scanState.snapshot_counts ?? {
    apps: 0,
    users: 0,
    endpoints: 0,
    risks: 0,
    alerts: 0,
    unknown_apps: 0,
  };
  const displayCount = (value: number | string) => loading ? "Loading" : hasLoadFailure ? "Unknown" : value;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="AI Discovery"
          title="Discovery Overview"
          description="Runtime visibility across approved and shadow AI usage with findings-centric risk posture."
        />
        {loading && !findings.length && !connectors.length && !systems.length ? <p role="status" className="text-sm text-slate-500">Loading discovery snapshot…</p> : null}
        {hasLoadFailure ? <p role="status" className="text-sm text-amber-700">Some discovery sources are unavailable. Showing the last successful values; unavailable modules remain identified above.</p> : null}

        <PageSection title="AI Exposure Scan Control" description="Trigger discovery scans here. Command Center displays latest scan output as a read-only summary card.">
          <div id="scan-control" className="scroll-mt-24 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[#1e2433] bg-[#0f1218] p-3">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <Badge className={scanStatusBadgeClass(scanState.status)}>{String(scanState.status || "no_data").toUpperCase()}</Badge>
                <span className="text-xs text-slate-400">
                  Type: {String(scanState.scan_type || "discovery").toUpperCase()}
                </span>
                <span className="text-xs text-slate-500">
                  {scanState.last_scan_time ? `Last scan: ${formatDateTime(scanState.last_scan_time)}` : "No successful scan yet"}
                </span>
                <span className="text-xs text-slate-500">
                  Duration: {formatDurationMs(scanState.duration_ms)}
                </span>
                <span className="text-xs text-slate-500">
                  Source: {scanState.data_source === "active_runtime_crawl" ? "active runtime crawl" : String(scanState.data_source || "-")}
                </span>
                <span className="text-xs text-slate-500">
                  Events crawled: {numberOrZero(scanState.crawl_meta?.runtime_events_crawled)}
                </span>
                <span className="text-xs text-slate-500">
                  Shadow upserts: {numberOrZero(scanState.crawl_meta?.shadow_discovery_upserts)}
                </span>
                <span className="text-xs text-slate-500">
                  Lookback: {numberOrZero(scanState.crawl_meta?.lookback_hours)}h
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" onClick={runDiscoveryScan} disabled={scanBusy || String(scanState.status).toLowerCase() === "running"}>
                  {String(scanState.status).toLowerCase() === "running" ? "Scan Running..." : scanBusy ? "Starting..." : "Run Scan"}
                </Button>
                <Button asChild variant="outline" size="sm">
                  <Link href={scanLinks.full_report || "/shadow-ai"}>View Full Report</Link>
                </Button>
              </div>
            </div>

            {String(scanState.status).toLowerCase() === "failed" ? (
              <div className="rounded-md border border-rose-900/50 bg-rose-950/30 px-3 py-2 text-sm text-rose-300">
                {scanState.error || "Latest scan failed. Retry to regenerate scan deltas."}
              </div>
            ) : null}

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {[
                ["New AI Apps", scanSummary.new_ai_apps_detected, scanLinks.new_ai_apps || "/shadow-ai?state=new"],
                ["Unknown AI Tools", scanSummary.unknown_apps, scanLinks.unknown_tools || "/shadow-ai?state=unknown"],
                ["New Users", scanSummary.new_users_detected, scanLinks.new_users || "/ai-iam?filter=recently_discovered"],
                ["New Endpoints", scanSummary.new_endpoints_detected, scanLinks.new_endpoints || "/ai-iam?filter=recently_discovered"],
                ["New Risks", scanSummary.new_risks_identified, scanLinks.new_risks || "/discovery/findings?source=scan_delta"],
                ["Alerts Generated", scanSummary.alerts_generated, scanLinks.alerts || "/dashboard/command-center?focus=alerts"],
              ].map(([label, rawValue, href]) => {
                const value = numberOrZero(rawValue);
                return (
                  <Link
                    key={String(label)}
                    href={String(href)}
                    className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3 transition hover:border-brand-500/40"
                  >
                    <p className="text-xs uppercase tracking-[0.12em] text-slate-500">{label}</p>
                    <p className={`mt-1 text-2xl font-semibold ${value > 0 ? "text-emerald-300" : "text-slate-100"}`}>
                      {loading || hasLoadFailure ? "Unknown" : value > 0 ? `+${value}` : value}
                    </p>
                  </Link>
                );
              })}
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">Scanned apps: {displayCount(numberOrZero(scanCounts.apps))}</span>
              <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">Scanned users: {displayCount(numberOrZero(scanCounts.users))}</span>
              <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">Scanned endpoints: {displayCount(numberOrZero(scanCounts.endpoints))}</span>
              <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">Scanned risks: {displayCount(numberOrZero(scanCounts.risks))}</span>
              <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">Scanned alerts: {displayCount(numberOrZero(scanCounts.alerts))}</span>
            </div>
          </div>
        </PageSection>

        <KpiStrip
          items={[
            { label: "Active AI Apps", value: displayCount(kpis.activeAIApps), tone: "info" },
            { label: "Approved vs Shadow", value: loading || hasLoadFailure ? "Unknown" : kpis.approvedVsShadow, tone: "warning" },
            { label: "High Severity Findings", value: displayCount(kpis.highSeverityCount), tone: "critical" },
            { label: "Teams at Risk", value: displayCount(kpis.teamsAtRisk), tone: "warning" },
          ]}
        />

        <PageSection
          title={`Discovered Local Agents${localAgents.length ? ` (${localAgents.length})` : ""}`}
          description="Immediate view of localhost and local-runtime agent discoveries from the current Discovery snapshot."
        >
          <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">
              Linked to AI IAM: {localAgents.filter((row) => Boolean(row.linkedAiSystemId)).length}
            </span>
            <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">
              Open findings: {localAgents.reduce((sum, row) => sum + row.openFindings, 0)}
            </span>
            <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">
              Signals observed: {localAgents.reduce((sum, row) => sum + row.signalCount, 0)}
            </span>
          </div>
          <SimpleTable
            columns={["Agent", "Runtime / Model", "Observed Access", "Status", "Last Seen"]}
            emptyLabel="No local agents discovered in this snapshot yet."
            rows={localAgents.map((row) => [
              <div key={`local-agent-${row.id}`} className="space-y-1">
                <p className="font-medium text-slate-100">{row.name}</p>
                <p className="text-xs text-slate-500">{row.domain}</p>
                <Link href="/shadow-ai" className="text-xs text-brand-400 underline underline-offset-2">
                  Open in Shadow AI Explorer
                </Link>
              </div>,
              <div key={`runtime-${row.id}`} className="space-y-1">
                <p className="text-sm text-slate-100">{row.runtime}</p>
                <p className="text-xs text-slate-500">{row.model}</p>
              </div>,
              row.accessSummary || "No scoped tool/action privileges captured yet",
              <div key={`status-${row.id}`} className="space-y-1">
                <Badge className={localAgentStatusBadgeClass(row.status)}>{row.status}</Badge>
                <p className="text-xs text-slate-500">Risk tier: {row.riskTier}</p>
                <p className="text-xs text-slate-500">{row.linkedAiSystemId ? "AI IAM linked" : "AI IAM link pending"}</p>
              </div>,
              formatDateTime(row.lastSeen),
            ])}
          />
          <p className="mt-3 text-xs text-slate-500">
            This panel is populated from already-loaded discovery entities on this page, so you can see local-agent discovery immediately without manual API terminal queries.
          </p>
        </PageSection>

        <div className="grid gap-6 xl:grid-cols-3">
          <PageSection title="Findings by Severity" description="Distribution across all discovery findings.">
            <div className="space-y-3">
              {severitySeries.map((entry) => {
                const width = Math.max(6, Math.round((entry.count / maxSeverityCount) * 100));
                return (
                  <div key={entry.severity}>
                    <div className="mb-1 flex items-center justify-between text-xs text-slate-600">
                      <span>{severityLabels[entry.severity]}</span>
                      <span>{entry.count}</span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-100">
                      <div className={`h-2 rounded-full ${severityColors[entry.severity]}`} style={{ width: `${width}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </PageSection>

          <PageSection title="Shadow AI Over Time" description="7-day trend of shadow discovery findings.">
            <div className="flex items-end gap-2">
              {shadowTrend.map((entry) => {
                const height = Math.max(8, Math.round((entry.count / maxShadowCount) * 100));
                return (
                  <div key={entry.key} className="flex flex-1 flex-col items-center gap-1">
                    <div className="h-28 w-full rounded-md bg-slate-100 p-1">
                      <div className="flex h-full w-full items-end">
                        <div className="w-full rounded bg-brand-600/90" style={{ height: `${height}%` }} />
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-500">{entry.label}</p>
                    <p className="text-xs font-medium text-slate-700">{entry.count}</p>
                  </div>
                );
              })}
            </div>
          </PageSection>

          <PageSection title="Top Apps" description="Highest finding volume by app/tool.">
            <SimpleTable
              columns={["App", "Findings", "Last Seen"]}
              rows={topApps.map((entry) => [entry.app, entry.findings, formatDateTime(entry.lastSeen)])}
            />
          </PageSection>
        </div>

        <div className="grid gap-6 xl:grid-cols-3">
          <div className="xl:col-span-2">
            <PageSection title="Recent Findings" description="Most recent findings across discovery sources.">
              <SimpleTable
                columns={["Finding", "Tool", "Severity", "Status", "Updated"]}
                rows={recentFindings.map((finding) => [
                  <Link
                    key={`recent-${finding.finding_id}`}
                    href={`/discovery/findings/${encodeURIComponent(finding.finding_id)}`}
                    className="text-brand-700 underline underline-offset-2"
                  >
                    {finding.finding_id}
                  </Link>,
                  finding.ai_tool,
                  finding.severity,
                  finding.status,
                  formatDateTime(finding.updated_at),
                ])}
              />
            </PageSection>
          </div>
          <PageSection title="Recommended Next Steps" description="Actionable priorities generated from current discovery posture.">
            <ol className="space-y-3 text-sm text-slate-700">
              {recommendedSteps.map((step) => (
                <li key={step} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
                  {step}
                </li>
              ))}
            </ol>
            {loading ? <p className="mt-3 text-sm text-slate-500">Recommendations will appear after the discovery snapshot loads.</p> : null}
            {hasLoadFailure ? <p className="mt-3 text-sm text-amber-700">Recommendations are withheld until all required sources respond.</p> : null}
            <p className="mt-4 text-xs text-slate-500">
              {loading ? "Loading discovery posture..." : `Based on ${findings.length} findings and ${alerts.length} drift alerts.`}
            </p>
          </PageSection>
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <PageSection title="Source Coverage Mix" description="Findings by source surface for cross-surface shadow posture.">
            <SimpleTable
              columns={["Source Surface", "Findings"]}
              rows={sourceCoverageMix.map((row) => [row.source, row.count])}
            />
          </PageSection>
          <PageSection title="Shadow Entity State" description="Correlated shadow entities and governance progression.">
            <SimpleTable
              columns={["Status", "Count"]}
              rows={[
                ["discovered", shadowEntities.filter((row) => row.discovery_status === "discovered").length],
                ["reconciled", shadowEntities.filter((row) => row.discovery_status === "reconciled").length],
                ["promoted", shadowEntities.filter((row) => row.discovery_status === "promoted").length],
                ["rejected", shadowEntities.filter((row) => row.discovery_status === "rejected").length],
              ]}
            />
          </PageSection>
        </div>
      </div>
    </AppShell>
  );
}
