"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { OperationsConsoleTabs } from "@/components/operations-console-tabs";
import { OperationsLiveFeed } from "@/components/operations-live-feed";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { PlatformModeControl } from "@/components/platform-mode-control";
import { PersonaHome } from "@/components/lifecycle/persona-home";
import { BankingCisoSummaryPanel } from "@/components/banking/banking-ciso-summary";
import { EvidenceRiver } from "@/components/command-center/evidence-river";
import { GovernanceOperations } from "@/components/command-center/governance-operations";
import { GovernanceStoryline } from "@/components/command-center/governance-storyline";
import { deriveGovernanceOverview } from "@/components/command-center/command-center-visual-mappers";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DistributionDonutCard, TrendSparkCard } from "@/components/visual-metrics";
import { useRuntimeIntelligenceStream } from "@/hooks/use-runtime-intelligence-stream";
import { api } from "@/lib/api";
import { API_BASE_URL } from "@/lib/api-url";
import type { CommandCenterDashboardState, FindingDrilldown, PilotHealthState, RuntimeStreamEvent } from "@/lib/types";

const HEATMAP_DECISION_ORDER = ["allow", "warn", "block", "require_approval"] as const;
type ViolationItem = CommandCenterDashboardState["violations"]["items"][number];
type FindingAlertItem = NonNullable<CommandCenterDashboardState["findings_alerts"]>["items"][number];
type DashboardLoadParams = NonNullable<Parameters<typeof api.commandCenterDashboard>[0]>;
type QueuedDashboardLoad = {
  generation: number;
  params: DashboardLoadParams;
  silent: boolean;
  resolvers: Array<(success: boolean) => void>;
};

function numberOrZero(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return parsed;
}

function formatCurrency(value: number): string {
  if (!Number.isFinite(value)) return "$0";
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `$${(value / 1_000_000).toFixed(1)}M`;
  if (abs >= 1_000) return `$${(value / 1_000).toFixed(1)}K`;
  return `$${Math.round(value)}`;
}

function formatDateTime(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function formatPercent(value: number): string {
  if (!Number.isFinite(value)) return "0%";
  return `${Math.round(value * 100)}%`;
}

function severityBadgeClass(value: string): string {
  const sev = String(value || "").toLowerCase();
  if (sev === "critical") return "bg-red-950 text-red-300";
  if (sev === "high") return "bg-rose-950 text-rose-300";
  if (sev === "med" || sev === "medium") return "bg-amber-950 text-amber-300";
  return "bg-emerald-950 text-emerald-300";
}

const VIOLATION_DRILLDOWN_PRIORITY = new Map<string, number>([
  ["chain_graph", 1],
  ["action_graph", 2],
  ["chain_evidence", 3],
  ["evidence", 4],
  ["traceability", 5],
  ["finding_detail", 6],
  ["agent_touchpoints", 7],
  ["action_trace", 8],
  ["default", 9],
]);

function activeViolationDrilldowns(items?: FindingDrilldown[]): FindingDrilldown[] {
  return (items || [])
    .filter((item) => item.enabled !== false && Boolean(item.href))
    .sort((left, right) => {
      const leftRank = VIOLATION_DRILLDOWN_PRIORITY.get(left.type) || 99;
      const rightRank = VIOLATION_DRILLDOWN_PRIORITY.get(right.type) || 99;
      return leftRank - rightRank;
    });
}

function shortDrilldownLabel(item: FindingDrilldown): string {
  const labels: Record<string, string> = {
    chain_graph: "Chain",
    action_graph: "Graph",
    chain_evidence: "Evidence",
    evidence: "Evidence",
    traceability: "Trace",
    finding_detail: "Finding",
    agent_touchpoints: "Agent",
    action_trace: "Trace",
  };
  return labels[item.type] || item.label || "Open";
}

function renderViolationDrilldowns(row: ViolationItem) {
  const drilldowns = activeViolationDrilldowns(row.drilldowns);
  const primary = row.primary_drilldown || drilldowns[0] || {
    type: "finding_detail",
    label: "Finding Detail",
    href: row.investigation_link || row.drilldown,
  };
  const secondary = drilldowns
    .filter((item) => item.href !== primary.href)
    .slice(0, 3);

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button key={`${row.finding_id}-primary`} asChild variant="outline" size="sm">
        <Link href={primary.href}>{shortDrilldownLabel(primary)}</Link>
      </Button>
      {secondary.map((item) => (
        <Button
          key={`${row.finding_id}-${item.type}-${item.href}`}
          asChild
          variant="ghost"
          size="sm"
          className="border border-slate-800 px-2 text-xs text-slate-300 hover:text-slate-50"
        >
          <Link href={item.href}>{shortDrilldownLabel(item)}</Link>
        </Button>
      ))}
    </div>
  );
}

function renderFindingAlertDrilldowns(row: FindingAlertItem) {
  const drilldowns = activeViolationDrilldowns(row.drilldowns);
  const primary = row.primary_drilldown || drilldowns[0] || {
    type: "finding_detail",
    label: "Finding Detail",
    href: row.investigation_link || row.link,
  };
  const secondary = drilldowns
    .filter((item) => item.href !== primary.href)
    .slice(0, 3);

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button key={`${row.finding_id}-primary`} asChild variant="outline" size="sm">
        <Link href={primary.href}>{shortDrilldownLabel(primary)}</Link>
      </Button>
      {secondary.map((item) => (
        <Button
          key={`${row.finding_id}-${item.type}-${item.href}`}
          asChild
          variant="ghost"
          size="sm"
          className="border border-slate-800 px-2 text-xs text-slate-300 hover:text-slate-50"
        >
          <Link href={item.href}>{shortDrilldownLabel(item)}</Link>
        </Button>
      ))}
    </div>
  );
}

function toneFromExposure(score: number): "critical" | "warning" | "success" {
  if (score >= 75) return "critical";
  if (score >= 45) return "warning";
  return "success";
}

function scanStatusBadgeClass(status: string): string {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "completed") return "bg-emerald-950 text-emerald-300";
  if (normalized === "running") return "bg-sky-950 text-sky-300";
  if (normalized === "failed") return "bg-rose-950 text-rose-300";
  return "bg-slate-800 text-slate-300";
}

function sourceHealthBadgeClass(status: string): string {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "success") return "bg-emerald-950 text-emerald-300";
  if (normalized === "failed") return "bg-rose-950 text-rose-300";
  if (normalized === "never") return "bg-amber-950 text-amber-300";
  return "bg-slate-800 text-slate-300";
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

function formatErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    const message = String(error.message || "").trim();
    if (!message) return "Request failed";
    if (message.toLowerCase() === "failed to fetch") {
      return `Cannot reach API sync endpoint. Verify API is running on ${API_BASE_URL} and then retry.`;
    }
    return message;
  }
  if (typeof error === "string") return error;
  return "Request failed";
}

function waitFor(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function isExternalRiskNetworkError(value: string | null | undefined): boolean {
  const message = String(value || "").toLowerCase();
  return (
    message.includes("cannot resolve or reach external hosts") ||
    message.includes("nodename nor servname provided") ||
    message.includes("name or service not known") ||
    message.includes("temporary failure in name resolution") ||
    message.includes("could not resolve host")
  );
}

function formatExternalRiskSourceError(value: string | null | undefined): string {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (isExternalRiskNetworkError(raw)) {
    return "Current API runtime cannot resolve or reach this public feed. Check DNS and outbound internet egress, then run Sync Now again.";
  }
  if (raw.startsWith("source_fetch_failed:")) {
    return raw.replace(/^source_fetch_failed:[^:]+:/, "").trim() || "Fetch failed";
  }
  return raw;
}

function healthBadgeClass(value: string): string {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "ok" || normalized === "healthy") return "bg-emerald-950 text-emerald-300";
  if (normalized === "stale" || normalized === "warn") return "bg-amber-950 text-amber-300";
  if (normalized === "missing" || normalized === "not_connected") return "bg-slate-800 text-slate-300";
  return "bg-rose-950 text-rose-300";
}

function formatLagSeconds(value: number | null | undefined): string {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds < 0) return "n/a";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const rem = Math.round(seconds % 60);
    return `${mins}m ${rem}s`;
  }
  if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return `${days}d ${hours}h`;
}

function heatmapCellClass(decision: string, intensity: number): string {
  const opacity = Math.max(0.12, Math.min(0.92, intensity));
  if (decision === "allow") return `bg-emerald-500/${Math.round(opacity * 100)} text-emerald-100`;
  if (decision === "warn") return `bg-amber-500/${Math.round(opacity * 100)} text-amber-100`;
  if (decision === "block") return `bg-red-500/${Math.round(opacity * 100)} text-red-100`;
  return `bg-cyan-500/${Math.round(opacity * 100)} text-cyan-100`;
}

function formatControlModeLabel(value: string): string {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return "Incomplete";
  return normalized
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function controlModeBadgeClass(value: string): string {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "inline_prevented") return "border border-rose-800 bg-rose-950 text-rose-200";
  if (normalized === "warned") return "border border-amber-800 bg-amber-950 text-amber-200";
  if (normalized === "inline_allowed") return "border border-emerald-800 bg-emerald-950 text-emerald-200";
  if (normalized === "shadow_would_block") return "border border-sky-800 bg-sky-950 text-sky-200";
  if (normalized === "detected_only" || normalized === "telemetry_only") return "border border-slate-700 bg-slate-900 text-slate-300";
  if (normalized === "external_required" || normalized === "external_action_triggered") return "border border-violet-800 bg-violet-950 text-violet-200";
  return "border border-orange-800 bg-orange-950 text-orange-200";
}

const LIVE_FEED_ALLOW_NOISE_ACTIONS = new Set([
  "extension_connected",
  "policy_sync_success",
  "extension_health_status",
]);

type SurfaceCoverageRow = {
  id: string;
  label: string;
  surfaceType: string;
  coverage: string;
  currentMode: string;
  primaryControl: string;
  aliases: string[];
  href: string;
};

const COMMAND_CENTER_SURFACES: SurfaceCoverageRow[] = [
  {
    id: "browser",
    label: "Browser AI",
    surfaceType: "Browser Extension",
    coverage: "Inline prompt, paste, upload, output and browser action control",
    currentMode: "inline_prevented",
    primaryControl: "Business purpose, sensitive data, justification, Shadow AI",
    aliases: ["browser", "browser_extension", "agentic_browser", "chatgpt", "claude", "gemini", "perplexity"],
    href: "/runtime-intelligence/activity-map?surface=browser",
  },
  {
    id: "mcp",
    label: "MCP / Developer Tools",
    surfaceType: "MCP Gateway",
    coverage: "Tool-call authorization, parameter inspection, fingerprint drift",
    currentMode: "inline_prevented",
    primaryControl: "Block write/admin/secret calls; bind approvals to tool metadata",
    aliases: ["mcp", "developer_mcp", "mcp_gateway", "tool_call", "developer"],
    href: "/ai-iam?surface=mcp",
  },
  {
    id: "gateway_sdk",
    label: "LLM Gateway / SDK",
    surfaceType: "Gateway + App Embed",
    coverage: "Model-call policy, prompt/response evidence and API trace",
    currentMode: "inline_allowed",
    primaryControl: "Same authorize_ai_action spine for custom apps and SDK calls",
    aliases: ["gateway", "llm_gateway", "sdk", "api", "azure_openai", "openai"],
    href: "/gateway",
  },
  {
    id: "foundry",
    label: "Microsoft Foundry",
    surfaceType: "Foundry / Azure AI",
    coverage: "Project, agent, model, tool and data-source trace when connected",
    currentMode: "external_required",
    primaryControl: "Inline only when routed through Hawk Gateway; telemetry otherwise",
    aliases: ["foundry", "azure_ai_foundry", "azure_foundry", "azure_openai", "microsoft_foundry"],
    href: "/surface-coverage#foundry",
  },
  {
    id: "copilot",
    label: "Microsoft Copilot",
    surfaceType: "M365 Copilot / Copilot Studio",
    coverage: "Copilot activity, Studio agents, connectors, OAuth/app permissions",
    currentMode: "detected_only",
    primaryControl: "Graph/Purview/Entra evidence with external remediation actions",
    aliases: ["copilot", "m365_copilot", "copilot_studio", "microsoft_copilot", "teams", "sharepoint", "onedrive"],
    href: "/surface-coverage#copilot",
  },
  {
    id: "desktop_proxy",
    label: "Desktop / Local Proxy",
    surfaceType: "SWG / Local AI Proxy",
    coverage: "Desktop AI and native app coverage when routed through proxy/SWG",
    currentMode: "telemetry_only",
    primaryControl: "Telemetry now; inline prevention requires proxy/SWG path",
    aliases: ["desktop", "local_proxy", "swg", "endpoint", "desktop_ai"],
    href: "/surface-coverage",
  },
];

function liveFeedDecisionPriority(decision: string): number {
  const normalized = String(decision || "").toLowerCase();
  if (normalized === "block") return 0;
  if (normalized === "warn") return 1;
  if (normalized === "require_approval" || normalized === "hold") return 2;
  return 3;
}

function isBenignLiveFeedNoise(actionType: string, decision: string): boolean {
  const normalizedDecision = String(decision || "").toLowerCase();
  const normalizedAction = String(actionType || "").trim().toLowerCase();
  return normalizedDecision === "allow" && LIVE_FEED_ALLOW_NOISE_ACTIONS.has(normalizedAction);
}

function AIExposureScanCard({
  scan,
  scanRunning,
  scanActionError,
  onRunScan,
}: {
  scan: CommandCenterDashboardState["ai_exposure_scan"] | undefined;
  scanRunning: boolean;
  scanActionError: string | null;
  onRunScan: () => void;
}) {
  const status = scanRunning ? "running" : String(scan?.status || "no_data").toLowerCase();
  const summary = scan?.summary;
  const links = scan?.links;
  const counts = scan?.snapshot_counts;
  const lastScanTime = scan?.last_scan_time ? new Date(scan.last_scan_time) : null;
  const actionLabel = status === "no_data" ? "Run First Scan" : status === "failed" ? "Retry Scan" : "Run Scan";
  const deltas = [
    {
      label: "New AI Apps",
      value: numberOrZero(summary?.new_ai_apps_detected),
      href: links?.new_ai_apps || "/shadow-ai?state=new",
    },
    {
      label: "Unknown AI Tools",
      value: numberOrZero(summary?.unknown_apps),
      href: links?.unknown_tools || "/shadow-ai?state=unknown",
    },
    {
      label: "New Users",
      value: numberOrZero(summary?.new_users_detected),
      href: links?.new_users || "/ai-iam?filter=recently_discovered",
    },
    {
      label: "New Endpoints",
      value: numberOrZero(summary?.new_endpoints_detected),
      href: links?.new_endpoints || "/ai-iam?filter=recently_discovered",
    },
    {
      label: "New Risks",
      value: numberOrZero(summary?.new_risks_identified),
      href: links?.new_risks || "/discovery/findings?source=scan_delta",
    },
    {
      label: "Alerts Generated",
      value: numberOrZero(summary?.alerts_generated),
      href: links?.alerts || "/dashboard/command-center?focus=alerts",
    },
  ];

  return (
    <PageSection
      title="AI Exposure Scan"
      description="Continuous discovery/risk delta from browser-first Shadow AI and user/device linkage."
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[#1e2433] bg-[#0f1218] p-3">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Badge className={scanStatusBadgeClass(status)}>{status.toUpperCase()}</Badge>
            <span className="text-xs text-slate-400">
              {scan?.scan_type ? `Type: ${String(scan.scan_type).toUpperCase()}` : "Type: DISCOVERY"}
            </span>
            <span className="text-xs text-slate-500">
              {lastScanTime ? `Last scan: ${lastScanTime.toLocaleString()}` : "No scan has run yet"}
            </span>
            <span className="text-xs text-slate-500">
              Duration: {formatDurationMs(scan?.duration_ms)}
            </span>
            <span className="text-xs text-slate-500">
              Source: {scan?.data_source === "active_runtime_crawl" ? "active runtime crawl" : String(scan?.data_source || "-")}
            </span>
            <span className="text-xs text-slate-500">
              Events crawled: {numberOrZero(scan?.crawl_meta?.runtime_events_crawled)}
            </span>
            <span className="text-xs text-slate-500">
              Shadow upserts: {numberOrZero(scan?.crawl_meta?.shadow_discovery_upserts)}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={onRunScan}
              disabled={scanRunning || status === "running"}
              title={status === "running" ? "A discovery scan is already running" : "Run a global AI exposure discovery scan"}
            >
              {status === "running" ? (
                <span className="mr-2 h-3 w-3 animate-spin rounded-full border-2 border-black/40 border-t-black" />
              ) : null}
              {status === "running" ? "Scan in progress..." : actionLabel}
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link href={links?.full_report || "/shadow-ai"}>View Full Report</Link>
            </Button>
          </div>
        </div>

        {scanActionError || status === "failed" ? (
          <div className="rounded-md border border-rose-900/50 bg-rose-950/30 px-3 py-2 text-sm text-rose-300">
            {scanActionError || scan?.error || "Latest scan failed. Retry to refresh delta intelligence."}
          </div>
        ) : null}

        {status === "running" ? (
          <div className="rounded-md border border-sky-900/50 bg-sky-950/30 px-3 py-2 text-sm text-sky-200">
            Scan in progress. Delta metrics will refresh when the worker completes.
          </div>
        ) : null}

        {status === "no_data" ? (
          <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-8 text-center text-sm text-slate-400">
            No scan snapshot yet. Run first discovery scan to populate delta insights.
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {deltas.map((item) => (
              <Link
                key={item.label}
                href={item.href}
                className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3 transition hover:border-brand-500/40"
              >
                <p className="text-xs uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
                <p className={`mt-1 text-2xl font-semibold ${item.value > 0 ? "text-emerald-300" : "text-slate-100"}`}>
                  {item.value > 0 ? `+${item.value}` : item.value}
                </p>
              </Link>
            ))}
          </div>
        )}

        {status === "completed" ? (
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <span className="rounded border border-emerald-900/40 bg-emerald-950/20 px-2 py-1">
              +{numberOrZero(scan?.delta.apps_added?.length)} apps added
            </span>
            <span className="rounded border border-sky-900/40 bg-sky-950/20 px-2 py-1">
              +{numberOrZero(scan?.delta.users_added?.length)} users added
            </span>
            <span className="rounded border border-violet-900/40 bg-violet-950/20 px-2 py-1">
              +{numberOrZero(scan?.delta.endpoints_added?.length)} endpoints added
            </span>
            <span className="rounded border border-rose-900/40 bg-rose-950/20 px-2 py-1">
              +{numberOrZero(scan?.delta.risks_added?.length)} risks added
            </span>
            <span className="rounded border border-slate-700/60 bg-[#0b1220] px-2 py-1">
              scanned {numberOrZero(counts?.apps)} apps / {numberOrZero(counts?.users)} users / {numberOrZero(counts?.endpoints)} endpoints
            </span>
          </div>
        ) : null}
      </div>
    </PageSection>
  );
}

function ExternalRiskIntelCard({
  intel,
  syncing,
  syncError,
  onSyncNow,
}: {
  intel: CommandCenterDashboardState["external_risk_intelligence"] | undefined;
  syncing: boolean;
  syncError: string | null;
  onSyncNow: () => void;
}) {
  const status = String(intel?.sync_status || "no_data").toLowerCase();
  const sourceHealth = intel?.source_health || [];
  const lastSync = intel?.last_sync_at ? new Date(intel.last_sync_at) : null;
  const enabledSourceHealth = sourceHealth.filter((item) => item.enabled);
  const runtimeNetworkBlocked =
    enabledSourceHealth.length > 0 &&
    enabledSourceHealth.every((item) => isExternalRiskNetworkError(item.last_sync_error));

  const metricRows = [
    { label: "Critical Risks", value: numberOrZero(intel?.critical_risks), tone: "text-rose-300" },
    { label: "High/Critical", value: numberOrZero(intel?.high_or_critical_risks), tone: "text-amber-300" },
    { label: "Known Exploited", value: numberOrZero(intel?.known_exploited_items), tone: "text-red-300" },
    { label: "Affected Assets", value: numberOrZero(intel?.affected_assets), tone: "text-sky-300" },
    { label: "New Since Sync", value: numberOrZero(intel?.new_risks_since_last_sync), tone: "text-emerald-300" },
    { label: "Simulations Recommended", value: numberOrZero(intel?.simulations_recommended), tone: "text-violet-300" },
    { label: "Remediation Pending", value: numberOrZero(intel?.remediation_pending), tone: "text-orange-300" },
    { label: "Total ALE (USD)", value: formatCurrency(numberOrZero(intel?.total_ale_usd)), tone: "text-slate-100" },
    { label: "Residual Risk (USD)", value: formatCurrency(numberOrZero(intel?.total_residual_risk_usd)), tone: "text-slate-100" },
  ];

  return (
    <PageSection
      title="External Risk Intelligence"
      description="CVE/advisory intelligence normalized, correlated to assets, and bound to controls/CRQ/remediation."
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[#1e2433] bg-[#0f1218] p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={scanStatusBadgeClass(status)}>{status.toUpperCase()}</Badge>
            <span className="text-xs text-slate-400">
              Last sync: {lastSync ? lastSync.toLocaleString() : "No sync yet"}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={onSyncNow} disabled={syncing}>
              {syncing ? "Syncing..." : "Sync Now"}
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link href={intel?.drilldown || "/monitoring?focus=external-risk"}>Open External Risk</Link>
            </Button>
          </div>
        </div>

        {syncError ? (
          <div className="rounded-md border border-rose-900/50 bg-rose-950/30 px-3 py-2 text-sm text-rose-300">
            External risk sync failed: {syncError}
          </div>
        ) : null}

        {runtimeNetworkBlocked ? (
          <div className="rounded-md border border-amber-900/50 bg-amber-950/25 px-3 py-2 text-sm text-amber-200">
            External feeds are configured, but this API runtime cannot resolve public hosts. Start the API in a terminal with outbound DNS/internet access, then run <span className="font-semibold">Sync Now</span> again.
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {metricRows.map((item) => (
            <div key={item.label} className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
              <p className={`mt-1 text-2xl font-semibold ${item.tone}`}>{item.value}</p>
            </div>
          ))}
        </div>

        <div className="grid gap-3 xl:grid-cols-2">
          <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
            <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Feed Health</p>
            <div className="mt-2 space-y-2">
              {sourceHealth.length ? (
                sourceHealth.map((item) => (
                  <div
                    key={`${item.source}-${item.last_sync_at || "never"}`}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-[#1e2433] bg-[#0b1220] px-3 py-2"
                  >
                    <p className="break-words text-sm text-slate-200">{item.source.toUpperCase()}</p>
                    <div className="flex flex-wrap items-center gap-2">
                      {!item.enabled ? (
                        <Badge className="bg-slate-800 text-slate-300">DISABLED</Badge>
                      ) : null}
                      <Badge className={sourceHealthBadgeClass(item.last_sync_status)}>{item.last_sync_status.toUpperCase()}</Badge>
                      <span className="text-xs text-slate-500">
                        {item.last_sync_at ? new Date(item.last_sync_at).toLocaleTimeString() : "never"}
                      </span>
                    </div>
                    {item.last_sync_error ? (
                      <p className="w-full break-words text-xs text-rose-300">{formatExternalRiskSourceError(item.last_sync_error)}</p>
                    ) : null}
                  </div>
                ))
              ) : (
                <p className="text-sm text-slate-400">No configured feeds.</p>
              )}
            </div>
          </div>

          <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
            <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Coverage By Source</p>
            <div className="mt-2 space-y-2">
              {Object.entries(intel?.coverage_by_source || {}).length ? (
                Object.entries(intel?.coverage_by_source || {})
                  .sort((a, b) => Number(b[1]) - Number(a[1]))
                  .map(([source, count]) => (
                    <div
                      key={source}
                      className="flex items-center justify-between rounded-md border border-[#1e2433] bg-[#0b1220] px-3 py-2"
                    >
                      <p className="text-sm text-slate-200">{source.toUpperCase()}</p>
                      <p className="text-sm font-semibold text-slate-100">{numberOrZero(count)}</p>
                    </div>
                  ))
              ) : (
                <p className="text-sm text-slate-400">No normalized records available.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </PageSection>
  );
}

function PilotHealthCard({
  health,
  error,
  latencyMs,
  dashboardError,
}: {
  health: PilotHealthState | null;
  error: string | null;
  latencyMs: number | null;
  dashboardError: string | null;
}) {
  return (
    <PageSection
      title="Pilot Health"
      description="Fast readiness checks for API reachability, schema state, policy sync, and browser telemetry lag."
    >
      <div className="space-y-5">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Badge className={healthBadgeClass(health?.overall_status || "missing")}>
            {(health?.overall_status || "missing").replace(/_/g, " ").toUpperCase()}
          </Badge>
          <span className="text-sm text-slate-400">
            API latency: {latencyMs !== null ? `${latencyMs}ms` : "n/a"}
          </span>
          {dashboardError ? (
            <span className="text-sm text-rose-300">Command Center refresh degraded</span>
          ) : (
            <span className="text-sm text-emerald-300">Command Center refresh completed</span>
          )}
        </div>

        {error ? (
          <div className="rounded-md border border-rose-900/50 bg-rose-950/30 px-3 py-2 text-sm text-rose-300">
            Pilot health check failed: {error}
          </div>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2 2xl:grid-cols-4">
          <div className="rounded-xl border border-[#1e2433] bg-[#0f1218] p-4">
            <p className="text-xs uppercase tracking-[0.12em] text-slate-500">API Reachable</p>
            <p className="mt-3 text-2xl font-semibold text-slate-100">{health?.api_reachable ? "Yes" : "No"}</p>
          </div>
          <div className="rounded-xl border border-[#1e2433] bg-[#0f1218] p-4">
            <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Schema Health</p>
            <div className="mt-3">
              <Badge className={healthBadgeClass(health?.schema_health?.healthy ? "ok" : "degraded")}>
                {health?.schema_health?.healthy ? "AVAILABLE" : "UNAVAILABLE"}
              </Badge>
            </div>
          </div>
          <div className="rounded-xl border border-[#1e2433] bg-[#0f1218] p-4">
            <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Policy Sync</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Badge className={healthBadgeClass(health?.policy_sync_health?.status || "missing")}>
                {(health?.policy_sync_health?.status || "missing").toUpperCase()}
              </Badge>
              <span className="text-sm text-slate-400">
                q={Number(health?.policy_sync_health?.telemetry_queue_depth || 0)}
              </span>
            </div>
          </div>
          <div className="rounded-xl border border-[#1e2433] bg-[#0f1218] p-4">
            <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Telemetry Lag</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Badge className={healthBadgeClass(health?.telemetry_health?.status || "missing")}>
                {(health?.telemetry_health?.status || "missing").toUpperCase()}
              </Badge>
              <span className="text-sm text-slate-400">{formatLagSeconds(health?.telemetry_health?.lag_seconds)}</span>
            </div>
          </div>
        </div>

        {!health?.schema_health?.healthy ? (
          <p className="text-xs text-rose-300">
            Missing schema elements: {(health?.schema_health?.missing_columns || []).join(", ") || "see /health/schema"}.
          </p>
        ) : null}

        <div className="rounded-xl border border-[#1e2433] bg-[#0f1218] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Deployment Hardening</p>
              <p className="mt-2 text-sm text-slate-400">
                50-user pilot controls for local data residency, managed extension lock, retention, backups, and package hygiene.
              </p>
            </div>
            <Badge className={healthBadgeClass(health?.deployment_hardening?.status || "missing")}>
              {(health?.deployment_hardening?.status || "missing").toUpperCase()}
            </Badge>
          </div>

          <div className="mt-3 grid gap-2 sm:grid-cols-4">
            {[
              ["OK", health?.deployment_hardening?.summary?.ok || 0, "text-emerald-300"],
              ["Warning", health?.deployment_hardening?.summary?.warning || 0, "text-amber-300"],
              ["Failed", health?.deployment_hardening?.summary?.failed || 0, "text-rose-300"],
              ["Manual", health?.deployment_hardening?.summary?.manual_required || 0, "text-sky-300"],
            ].map(([label, value, tone]) => (
              <div key={String(label)} className="rounded-md border border-[#1e2433] bg-[#0b1220] px-3 py-2">
                <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</p>
                <p className={`mt-1 text-lg font-semibold ${tone}`}>{value}</p>
              </div>
            ))}
          </div>

          {(health?.deployment_hardening?.checks || []).some((check) => check.status !== "ok") ? (
            <div className="mt-3 space-y-2">
              {(health?.deployment_hardening?.checks || [])
                .filter((check) => check.status !== "ok")
                .slice(0, 5)
                .map((check) => (
                  <div
                    key={check.id}
                    className="rounded-md border border-[#273044] bg-[#0b1220] px-3 py-2 text-sm"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="font-medium text-slate-200">{check.label}</p>
                      <Badge className={healthBadgeClass(check.status)}>{check.status.toUpperCase()}</Badge>
                    </div>
                    <p className="mt-1 text-xs text-slate-400">{check.message}</p>
                    {check.remediation ? <p className="mt-1 text-xs text-amber-200">{check.remediation}</p> : null}
                  </div>
                ))}
            </div>
          ) : (
            <p className="mt-3 text-xs text-emerald-300">All deployment hardening checks reported OK.</p>
          )}
        </div>
      </div>
    </PageSection>
  );
}

function AdminRunbookCard() {
  return (
    <PageSection
      title="Pilot Admin Runbook"
      description="One-page map for where to configure controls and where to investigate outcomes."
    >
      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
          <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Configure</p>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            <li><Link className="text-brand-300 hover:underline" href="/policies">Policies</Link> · pilot policy pack, scope guardrails, action overrides</li>
            <li><Link className="text-brand-300 hover:underline" href="/trust-center">Trust Center</Link> · approve/track AI assets and ownership</li>
            <li><Link className="text-brand-300 hover:underline" href="/dashboard/command-center">Command Center</Link> · monitor platform mode behavior (discovery vs enforce)</li>
          </ul>
        </div>
        <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
          <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Investigate</p>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            <li><Link className="text-brand-300 hover:underline" href="/runtime-intelligence/activity-map">Runtime Activity</Link> · event decisions, badges, lag</li>
            <li><Link className="text-brand-300 hover:underline" href="/discovery/findings">Findings</Link> · user/machine/app/policy linkage</li>
            <li><Link className="text-brand-300 hover:underline" href="/runtime-intelligence/context-graph">Trace</Link> · event → policy → decision → finding</li>
          </ul>
        </div>
      </div>
    </PageSection>
  );
}

function ExposureGauge({
  score,
  drilldown,
}: {
  score: number;
  drilldown: string;
}) {
  const clamped = Math.max(0, Math.min(100, score));
  const tone = toneFromExposure(clamped);
  const angle = Math.round((clamped / 100) * 360);
  const ring =
    tone === "critical"
      ? `conic-gradient(#ef4444 ${angle}deg, #1f2937 ${angle}deg)`
      : tone === "warning"
        ? `conic-gradient(#f59e0b ${angle}deg, #1f2937 ${angle}deg)`
        : `conic-gradient(#10b981 ${angle}deg, #1f2937 ${angle}deg)`;

  return (
    <PageSection title="Exposure Score Gauge" description="Weighted exposure index from current violations, shadow AI, runtime, and CVE signals.">
      <div className="flex min-w-0 flex-col gap-4">
        <div className="relative mx-auto h-40 w-40 shrink-0">
          <div className="absolute inset-0 rounded-full border border-[#1e2433]" style={{ background: ring }} />
          <div className="absolute inset-[18%] rounded-full border border-[#1e2433] bg-[#0f1218]" />
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
            <p className="text-[10px] uppercase tracking-[0.14em] text-slate-500">Exposure</p>
            <p className="text-4xl font-semibold text-slate-100">{Math.round(clamped)}</p>
            <p className="text-xs text-slate-500">/100</p>
          </div>
        </div>
        <div className="flex min-w-0 flex-col justify-between rounded-lg border border-[#1e2433] bg-[#0f1218] p-4">
          <p className="break-words text-sm text-slate-300">
            {tone === "critical"
              ? "Immediate containment required."
              : tone === "warning"
                ? "Elevated risk requires active triage."
                : "Risk posture currently stable."}
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2 sm:justify-between">
            <Badge className={severityBadgeClass(tone === "critical" ? "critical" : tone === "warning" ? "high" : "low")}>
              {tone.toUpperCase()}
            </Badge>
            <Button asChild variant="outline" size="sm" className="shrink-0">
              <Link href={drilldown}>Drill Down</Link>
            </Button>
          </div>
        </div>
      </div>
    </PageSection>
  );
}

function RuntimeHeatmapCard({
  rows,
  drilldown,
}: {
  rows: CommandCenterDashboardState["runtime_heatmap"]["rows"];
  drilldown: string;
}) {
  const maxCellValue = useMemo(() => {
    const values = rows.flatMap((row) => {
      const requireApproval = numberOrZero(row.counts.require_approval) + numberOrZero(row.counts.hold);
      return [numberOrZero(row.counts.allow), numberOrZero(row.counts.warn), numberOrZero(row.counts.block), requireApproval];
    });
    return Math.max(1, ...values);
  }, [rows]);

  return (
    <PageSection title="Runtime Heatmap" description="Real-time enforcement intensity by surface and decision class.">
      <div className="overflow-x-auto">
        <div className="min-w-[560px] space-y-2">
          <div className="grid grid-cols-[minmax(120px,1.5fr)_repeat(4,minmax(64px,1fr))_minmax(64px,1fr)] gap-2 px-1 text-[11px] uppercase tracking-[0.08em] text-slate-500">
            <div>Surface</div>
            <div className="text-center">Allow</div>
            <div className="text-center">Warn</div>
            <div className="text-center">Block</div>
            <div className="text-center">Approval</div>
            <div className="text-center">Total</div>
          </div>
          {(rows || []).map((row) => {
            const approvalCount = numberOrZero(row.counts.require_approval) + numberOrZero(row.counts.hold);
            const cells = [
              { decision: HEATMAP_DECISION_ORDER[0], value: numberOrZero(row.counts.allow) },
              { decision: HEATMAP_DECISION_ORDER[1], value: numberOrZero(row.counts.warn) },
              { decision: HEATMAP_DECISION_ORDER[2], value: numberOrZero(row.counts.block) },
              { decision: HEATMAP_DECISION_ORDER[3], value: approvalCount },
            ];
            return (
              <div key={row.surface} className="grid grid-cols-[minmax(120px,1.5fr)_repeat(4,minmax(64px,1fr))_minmax(64px,1fr)] items-center gap-2">
                <div className="rounded-md border border-[#1e2433] bg-[#0f1218] px-3 py-2 text-sm text-slate-300 break-words">
                  {row.surface}
                </div>
                {cells.map((cell) => (
                  <div
                    key={`${row.surface}-${cell.decision}`}
                    title={`${row.surface} · ${cell.decision}: ${cell.value}`}
                    className={`rounded-md border border-[#1e2433] px-2 py-2 text-center text-sm font-semibold ${heatmapCellClass(
                      cell.decision,
                      cell.value / maxCellValue
                    )}`}
                  >
                    {cell.value}
                  </div>
                ))}
                <div className="rounded-md border border-[#1e2433] bg-[#0f1218] px-2 py-2 text-center text-sm font-semibold text-slate-200">
                  {row.total}
                </div>
              </div>
            );
          })}
        </div>
      </div>
      <div className="mt-3">
        <Button asChild variant="outline" size="sm">
          <Link href={drilldown}>Open Runtime Activity</Link>
        </Button>
      </div>
    </PageSection>
  );
}

function AIActionControlCard({
  summary,
}: {
  summary: CommandCenterDashboardState["ai_action_control"] | undefined;
}) {
  const controlCounts = summary?.control_mode_counts || {};
  const evidenceCounts = summary?.evidence_status_counts || {};
  const controlRows = [
    "inline_prevented",
    "warned",
    "inline_allowed",
    "shadow_would_block",
    "detected_only",
    "telemetry_only",
    "external_required",
    "external_action_triggered",
    "incomplete",
  ]
    .map((mode) => ({ mode, count: numberOrZero(controlCounts[mode]) }))
    .filter((item) => item.count > 0 || item.mode === "inline_prevented" || item.mode === "warned" || item.mode === "detected_only");

  return (
    <PageSection
      title="AI Action Control"
      description="Control-mode honesty and evidence integrity across normalized AI actions."
    >
      <div className="grid gap-3 sm:grid-cols-4">
        <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
          <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Actions</p>
          <p className="mt-1 text-2xl font-semibold text-slate-100">{numberOrZero(summary?.total_actions)}</p>
        </div>
        <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
          <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Prevented</p>
          <p className="mt-1 text-2xl font-semibold text-rose-300">{numberOrZero(controlCounts.inline_prevented)}</p>
        </div>
        <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
          <p className="text-xs uppercase tracking-[0.12em] text-slate-500">High Risk</p>
          <p className="mt-1 text-2xl font-semibold text-amber-300">{numberOrZero(summary?.high_risk_actions)}</p>
        </div>
        <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
          <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Evidence Complete</p>
          <p className="mt-1 text-2xl font-semibold text-emerald-300">{numberOrZero(evidenceCounts.complete)}</p>
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(220px,0.75fr)_minmax(0,1.25fr)]">
        <div className="space-y-2">
          {controlRows.map((item) => (
            <div key={item.mode} className="flex items-center justify-between gap-3 rounded-md border border-[#1e2433] bg-[#0f1218] px-3 py-2">
              <Badge className={controlModeBadgeClass(item.mode)}>{formatControlModeLabel(item.mode)}</Badge>
              <span className="text-sm font-semibold text-slate-100">{item.count}</span>
            </div>
          ))}
        </div>

        <SimpleTable
          columns={["When", "App / Action", "Mode", "Evidence", "Trace"]}
          rows={(summary?.top_actions || []).slice(0, 6).map((row) => [
            formatDateTime(row.timestamp),
            `${row.ai_app || "-"} / ${row.action_type || "-"}`,
            <Badge key={`${row.action_id}-mode`} className={controlModeBadgeClass(row.control_mode)}>
              {formatControlModeLabel(row.control_mode)}
            </Badge>,
            <Badge key={`${row.action_id}-evidence`} className={row.evidence_status === "complete" ? "bg-emerald-950 text-emerald-300" : "bg-orange-950 text-orange-300"}>
              {formatControlModeLabel(row.evidence_status)}
            </Badge>,
            <Button key={`${row.action_id}-trace`} asChild variant="outline" size="sm">
              <Link href={row.action_trace_url || summary?.drilldown || "/runtime-intelligence/actions"}>Trace</Link>
            </Button>,
          ])}
        />
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
        <span>
          Incomplete evidence: {numberOrZero(evidenceCounts.incomplete)} · Review required: {numberOrZero(summary?.review_required)}
        </span>
        <Button asChild variant="outline" size="sm">
          <Link href={summary?.drilldown || "/runtime-intelligence/actions"}>Open AI Actions</Link>
        </Button>
      </div>
    </PageSection>
  );
}

function surfaceMetricsFor(
  surfaces: CommandCenterDashboardState["surface_coverage_summary"] | undefined,
  row: SurfaceCoverageRow,
) {
  const entries = Object.entries(surfaces?.surfaces || {});
  const matching = entries.filter(([name]) => {
    const normalized = name.toLowerCase();
    return row.aliases.some((alias) => normalized.includes(alias));
  });

  const unique = (values: string[]) => Array.from(new Set(values.filter(Boolean))).slice(0, 4);

  return matching.reduce(
    (acc, [, metrics]) => ({
      event_count: acc.event_count + numberOrZero(metrics.event_count),
      blocked: acc.blocked + numberOrZero(metrics.blocked),
      warned: acc.warned + numberOrZero(metrics.warned),
      apps: unique([...acc.apps, ...(metrics.apps || [])]),
      agents: unique([...acc.agents, ...(metrics.agents || [])]),
      users: unique([...acc.users, ...(metrics.users || [])]),
    }),
    { event_count: 0, blocked: 0, warned: 0, apps: [] as string[], agents: [] as string[], users: [] as string[] },
  );
}

function SurfaceCoverageMatrix({
  summary,
}: {
  summary: CommandCenterDashboardState["surface_coverage_summary"] | undefined;
}) {
  const backendRows = summary?.surface_rows || [];
  const rows = backendRows.length
    ? backendRows.map((surface) => ({
        id: surface.id,
        label: surface.label,
        surfaceType: surface.surface_type,
        coverage: surface.coverage,
        currentMode: surface.current_mode,
        primaryControl: surface.primary_control,
        proofLabel: surface.proof_label,
        status: surface.status,
        href: surface.drilldown,
        metrics: {
          event_count: numberOrZero(surface.event_count),
          blocked: numberOrZero(surface.blocked),
          warned: numberOrZero(surface.warned),
          inline_prevented: numberOrZero(surface.inline_prevented),
          telemetry_only: numberOrZero(surface.telemetry_only),
          detected_only: numberOrZero(surface.detected_only),
          external_required: numberOrZero(surface.external_required),
          apps: surface.apps || [],
          agents: surface.agents || [],
          users: surface.users || [],
        },
      }))
    : COMMAND_CENTER_SURFACES.map((surface) => {
        const metrics = surfaceMetricsFor(summary, surface);
        return {
          ...surface,
          proofLabel: surface.primaryControl,
          status: metrics.event_count ? "observed" : "not_seen",
          metrics: {
            ...metrics,
            inline_prevented: metrics.blocked,
            telemetry_only: 0,
            detected_only: 0,
            external_required: surface.currentMode === "external_required" && metrics.event_count ? metrics.event_count : 0,
          },
        };
      });
  const totals = summary?.totals || {};

  return (
    <PageSection
      title="Surface Coverage Matrix"
      description="One control plane across browser, MCP, gateway, Microsoft AI, SaaS, and desktop surfaces. Rows are explicit about what is inline versus telemetry or external-required."
    >
      <div className="mb-4 grid gap-2 md:grid-cols-4">
        {[
          ["Observed actions", numberOrZero(totals.event_count)],
          ["Inline prevented", numberOrZero(totals.inline_prevented)],
          ["External required", numberOrZero(totals.external_required)],
          ["Telemetry / detected", numberOrZero(totals.telemetry_only) + numberOrZero(totals.detected_only)],
        ].map(([label, value]) => (
          <div key={String(label)} className="rounded border border-[#263149] bg-[#0b101d] px-3 py-2">
            <p className="text-[10px] uppercase tracking-[0.14em] text-slate-500">{label}</p>
            <p className="mt-1 text-xl font-semibold text-slate-100">{Number(value).toLocaleString()}</p>
          </div>
        ))}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1040px] border-separate border-spacing-0 text-left text-sm">
          <thead>
            <tr className="text-xs uppercase tracking-[0.12em] text-slate-500">
              <th className="border-b border-[#1e2433] px-3 py-2">Surface</th>
              <th className="border-b border-[#1e2433] px-3 py-2">Control Posture</th>
              <th className="border-b border-[#1e2433] px-3 py-2">Coverage</th>
              <th className="border-b border-[#1e2433] px-3 py-2">Proof</th>
              <th className="border-b border-[#1e2433] px-3 py-2 text-right">Events</th>
              <th className="border-b border-[#1e2433] px-3 py-2 text-right">Prevented / Warned</th>
              <th className="border-b border-[#1e2433] px-3 py-2 text-right">Telemetry / External</th>
              <th className="border-b border-[#1e2433] px-3 py-2">Observed Assets</th>
              <th className="border-b border-[#1e2433] px-3 py-2">Drilldown</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const observedAssets = [...row.metrics.apps, ...row.metrics.agents].slice(0, 5);
              return (
                <tr key={row.id} className="border-b border-[#1e2433]">
                  <td className="border-b border-[#1e2433] px-3 py-3 align-top">
                    <p className="font-semibold text-slate-100">{row.label}</p>
                    <p className="mt-1 text-xs text-slate-500">{row.surfaceType}</p>
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 align-top">
                    <Badge className={controlModeBadgeClass(row.currentMode)}>
                      {formatControlModeLabel(row.currentMode)}
                    </Badge>
                    <p className="mt-2 text-xs text-slate-500">{row.status.replace(/_/g, " ")}</p>
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 align-top">
                    <p className="max-w-sm text-slate-300">{row.coverage}</p>
                    <p className="mt-1 max-w-sm text-xs text-slate-500">{row.primaryControl}</p>
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 align-top text-slate-300">
                    <p className="max-w-[220px] text-xs">{row.proofLabel}</p>
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 text-right align-top font-semibold text-slate-100">
                    {row.metrics.event_count.toLocaleString()}
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 text-right align-top">
                    <span className="font-semibold text-rose-300">{row.metrics.inline_prevented.toLocaleString()}</span>
                    <span className="px-1 text-slate-600">/</span>
                    <span className="font-semibold text-amber-300">{row.metrics.warned.toLocaleString()}</span>
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 text-right align-top">
                    <span className="font-semibold text-slate-300">
                      {(row.metrics.telemetry_only + row.metrics.detected_only).toLocaleString()}
                    </span>
                    <span className="px-1 text-slate-600">/</span>
                    <span className="font-semibold text-violet-300">{row.metrics.external_required.toLocaleString()}</span>
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 align-top text-slate-300">
                    {observedAssets.length ? observedAssets.join(", ") : <span className="text-slate-500">Awaiting telemetry</span>}
                  </td>
                  <td className="border-b border-[#1e2433] px-3 py-3 align-top">
                    <Button asChild variant="outline" size="sm">
                      <Link href={row.href}>Open</Link>
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
        <span>
          Microsoft Foundry and Copilot rows are intentionally separated: Foundry can be inline only through Gateway routing; Copilot is mostly telemetry/external-required until Graph/Purview/Studio controls are connected.
        </span>
        <Button asChild variant="outline" size="sm">
          <Link href={summary?.drilldown || "/surface-coverage"}>Open Full Coverage</Link>
        </Button>
      </div>
    </PageSection>
  );
}

function CrqImpactCard({
  summary,
}: {
  summary: CommandCenterDashboardState["crq_summary"] | undefined;
}) {
  const scoredCount = numberOrZero(summary?.scored_recommendation_count);
  const topRecommendation = summary?.top_recommendation;

  return (
    <PageSection title="CRQ Financial Impact" description="Decision impact and loss-reduction modeling from runtime recommendations.">
      {scoredCount > 0 ? (
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Estimated Risk Reduction</p>
              <p className="mt-1 text-2xl font-semibold text-emerald-300">
                {formatCurrency(numberOrZero(summary?.total_estimated_risk_reduction_usd))}
              </p>
            </div>
            <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Average Impact Score</p>
              <p className="mt-1 text-2xl font-semibold text-sky-300">
                {Math.round(numberOrZero(summary?.average_decision_impact_score)).toLocaleString()}
              </p>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Scored Recommendations</p>
              <p className="mt-1 text-lg font-semibold text-slate-100">{scoredCount}</p>
            </div>
            <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Average Confidence</p>
              <p className="mt-1 text-lg font-semibold text-slate-100">
                {formatPercent(numberOrZero(summary?.average_confidence))}
              </p>
            </div>
            <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Top Action</p>
              <p className="mt-1 text-lg font-semibold text-slate-100">
                {String(summary?.top_action || topRecommendation?.action || "N/A")
                  .replaceAll("_", " ")
                  .toUpperCase()}
              </p>
            </div>
          </div>

          <div className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
            <p className="text-xs uppercase tracking-[0.12em] text-slate-500">Financial Impact Explanation</p>
            <p className="mt-1 text-sm text-slate-300">
              {String(summary?.financial_impact_explanation || "No impact explanation available.")}
            </p>
            {topRecommendation ? (
              <p className="mt-2 text-xs text-slate-400">
                Top recommendation: {formatCurrency(numberOrZero(topRecommendation.estimated_risk_reduction))} reduction from{" "}
                {formatCurrency(numberOrZero(topRecommendation.base_risk))} base risk (confidence{" "}
                {formatPercent(numberOrZero(topRecommendation.confidence))}).
              </p>
            ) : null}
          </div>

          <div className="flex justify-end">
            <Button asChild variant="outline" size="sm">
              <Link href={summary?.drilldown || "/runtime-intelligence/recommendations"}>Open CRQ Breakdown</Link>
            </Button>
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-8 text-center text-sm text-slate-400">
          No CRQ-scored runtime recommendations in the current filter window.
        </div>
      )}
    </PageSection>
  );
}

type PriorityAction = {
  id: string;
  title: string;
  detail: string;
  href: string;
  tone: "critical" | "warning" | "info" | "success";
  label: string;
};

function TopActionsNow({ actions }: { actions: PriorityAction[] }) {
  return (
    <PageSection
      title="Top actions now"
      description="The highest-value control or investigation work based only on current Hawk evidence."
    >
      {actions.length ? <div className="grid grid-cols-[repeat(auto-fit,minmax(260px,1fr))] gap-3">
        {actions.map((action, index) => (
          <Link
            key={action.id}
            href={action.href}
            className="group rounded-md border border-[#242c3d] bg-[#0d1119] p-4 transition hover:border-[#44527a] hover:bg-[#111725]"
          >
            <div className="flex items-start justify-between gap-3">
              <span className="text-xs font-semibold text-slate-500">0{index + 1}</span>
              <Badge className={severityBadgeClass(action.tone === "critical" ? "critical" : action.tone === "warning" ? "high" : "low")}>
                {action.label}
              </Badge>
            </div>
            <p className="mt-5 text-base font-semibold text-slate-100 group-hover:text-white">{action.title}</p>
            <p className="mt-2 text-sm leading-6 text-slate-400">{action.detail}</p>
            <p className="mt-4 text-xs font-semibold text-[#8b9cff]">Open action →</p>
          </Link>
        ))}
      </div> : <p role="status" className="rounded-md border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-sm text-slate-400">{`No prioritized action is available until the current tenant evidence finishes loading.`}</p>}
    </PageSection>
  );
}

type FourSurfaceDefinition = {
  id: string;
  label: string;
  match: string[];
  inlinePath: string;
  limitation: string;
  href: string;
};

const FOUR_DEPLOYMENT_SURFACES: FourSurfaceDefinition[] = [
  {
    id: "browser",
    label: "Browser Extension",
    match: ["browser"],
    inlinePath: "Managed extension on supported browser AI pages",
    limitation: "Does not cover native apps, unmanaged browsers, or device-wide traffic.",
    href: "/surface-coverage#browser",
  },
  {
    id: "endpoint",
    label: "Endpoint Agent",
    match: ["desktop", "endpoint", "local", "proxy", "meeting"],
    inlinePath: "Local proxy or approved OS enforcement adapter",
    limitation: "Telemetry alone is not prevention; OS-native enforcement must be installed and responding.",
    href: "/surface-coverage#endpoint",
  },
  {
    id: "gateway",
    label: "LLM Gateway",
    match: ["gateway", "sdk", "api", "foundry", "copilot", "saas"],
    inlinePath: "Requests routed through Hawk Gateway or embedded SDK authorization",
    limitation: "Direct provider and Copilot traffic remains telemetry or external-required unless routed inline.",
    href: "/surface-coverage#gateway",
  },
  {
    id: "agent_mcp",
    label: "MCP Gateway",
    match: ["mcp", "agent", "developer", "repo", "ci"],
    inlinePath: "MCP client or agent tool call routed through Hawk",
    limitation: "Direct tool calls outside Hawk cannot be claimed as prevented.",
    href: "/surface-coverage#mcp",
  },
];

function FourSurfaceMatrix({ summary }: { summary: CommandCenterDashboardState["surface_coverage_summary"] | undefined }) {
  const rows = summary?.surface_rows || [];
  const surfaces = FOUR_DEPLOYMENT_SURFACES.map((surface) => {
    const matching = rows.filter((row) => {
      const haystack = `${row.id} ${row.label} ${row.surface_type}`.toLowerCase();
      return surface.match.some((term) => haystack.includes(term));
    });
    const modeCounts = matching.reduce<Record<string, number>>((acc, row) => {
      for (const [mode, count] of Object.entries(row.mode_counts || {})) {
        acc[mode] = numberOrZero(acc[mode]) + numberOrZero(count);
      }
      return acc;
    }, {});
    const eventCount = matching.reduce((total, row) => total + numberOrZero(row.event_count), 0);
    const dominantMode = Object.entries(modeCounts).sort((left, right) => right[1] - left[1])[0]?.[0] || "incomplete";
    return {
      ...surface,
      eventCount,
      dominantMode,
      prevented: matching.reduce((total, row) => total + numberOrZero(row.inline_prevented), 0),
      telemetry: matching.reduce((total, row) => total + numberOrZero(row.telemetry_only) + numberOrZero(row.detected_only), 0),
      external: matching.reduce((total, row) => total + numberOrZero(row.external_required), 0),
    };
  });

  return (
    <PageSection
      title="Four deployment surfaces"
      description="Every surface uses the same AI Action, policy, decision, evidence, and trace spine. The posture below never treats telemetry as prevention."
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-left text-sm">
          <thead>
            <tr className="border-b border-[#242c3d] text-xs uppercase tracking-[0.12em] text-slate-500">
              <th className="px-3 py-3">Surface</th>
              <th className="px-3 py-3">Observed posture</th>
              <th className="px-3 py-3">Inline path</th>
              <th className="px-3 py-3">Honest limitation</th>
              <th className="px-3 py-3 text-right">Actions</th>
              <th className="px-3 py-3 text-right">Prevented</th>
              <th className="px-3 py-3">Open</th>
            </tr>
          </thead>
          <tbody>
            {surfaces.map((surface) => (
              <tr key={surface.id} className="border-b border-[#1d2432] align-top">
                <td className="px-3 py-4 font-semibold text-slate-100">{surface.label}</td>
                <td className="px-3 py-4"><Badge className={controlModeBadgeClass(surface.dominantMode)}>{formatControlModeLabel(surface.dominantMode)}</Badge></td>
                <td className="max-w-xs px-3 py-4 text-slate-300">{surface.inlinePath}</td>
                <td className="max-w-sm px-3 py-4 text-slate-400">{surface.limitation}</td>
                <td className="px-3 py-4 text-right font-semibold text-slate-200">{surface.eventCount.toLocaleString()}</td>
                <td className="px-3 py-4 text-right font-semibold text-rose-300">{surface.prevented.toLocaleString()}</td>
                <td className="px-3 py-4"><Button asChild variant="outline" size="sm"><Link href={surface.href}>Details</Link></Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-slate-500">
        <span>Telemetry / detected: {surfaces.reduce((total, surface) => total + surface.telemetry, 0).toLocaleString()}</span>
        <span>External required: {surfaces.reduce((total, surface) => total + surface.external, 0).toLocaleString()}</span>
      </div>
    </PageSection>
  );
}

function MCPGatewayVisibility({ summary }: { summary: CommandCenterDashboardState["mcp_tool_calls"] }) {
  const metrics = [
    ["Active servers", numberOrZero(summary?.active_mcp_servers), "text-emerald-300"],
    ["Shadow servers", numberOrZero(summary?.shadow_mcp_servers), "text-amber-300"],
    ["Active clients", numberOrZero(summary?.active_ai_clients), "text-sky-300"],
    ["Observed call events", numberOrZero(summary?.tool_calls_today), "text-slate-100"],
    ["Blocked decisions", numberOrZero(summary?.blocked_tool_calls), "text-rose-300"],
    ["High-risk calls", numberOrZero(summary?.high_risk_tool_calls), "text-orange-300"],
    ["Permission drift", numberOrZero(summary?.permission_drift_findings), "text-amber-300"],
    ["Unapproved clients / tools", numberOrZero(summary?.unapproved_clients_or_tools), "text-violet-300"],
  ] as const;

  return (
    <PageSection
      title="MCP Gateway visibility"
      description="Observed MCP inventory and tool-call lifecycle events in the selected dashboard window; one call can contribute multiple stage events."
    >
      <div className="grid grid-cols-2 overflow-hidden rounded-md border border-[#242c3d] sm:grid-cols-4">
        {metrics.map(([label, value, tone]) => (
          <div key={label} className="border-b border-r border-[#1d2432] bg-[#0d1119] p-3 last:border-r-0">
            <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</p>
            <p className={`mt-2 text-2xl font-semibold tabular-nums ${tone}`}>{value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-start justify-between gap-3 rounded-md border border-[#273044] bg-[#0b1220] p-3">
        <div className="max-w-3xl">
          <Badge className={controlModeBadgeClass("detected_only")}>Observed policy outcome</Badge>
          <p className="mt-2 text-sm leading-6 text-slate-300">
            Blocked decisions are an observed policy outcome, not inline prevention, unless route and evidence proof confirms the MCP
            client or agent tool call traversed the Hawk MCP Gateway. Direct tool calls outside that path are not represented as prevented.
          </p>
          {!summary ? <p className="mt-2 text-xs text-amber-300">No MCP gateway summary is available in the current response.</p> : null}
        </div>
        <Button asChild variant="outline" size="sm">
          <Link href="/runtime-intelligence/activity-map?surface=mcp_tool_call">Open MCP activity</Link>
        </Button>
      </div>
    </PageSection>
  );
}

function InteractionSecurityMatrix({
  users,
  activity,
  loading,
  unavailable,
}: {
  users: NonNullable<CommandCenterDashboardState["users_view"]>["items"];
  activity: NonNullable<CommandCenterDashboardState["live_activity_feed"]>["items"];
  loading: boolean;
  unavailable: boolean;
}) {
  const rows = users.map((user) => {
    const identityKeys = new Set(
      [user.user_id, user.user_email]
        .map((value) => String(value || "").trim().toLowerCase())
        .filter(Boolean),
    );
    const observed = activity.filter((item) =>
      [item.user_id, item.user_email]
        .map((value) => String(value || "").trim().toLowerCase())
        .some((value) => Boolean(value) && identityKeys.has(value)),
    );
    const applications = Array.from(
      new Set([...user.connected_apps, ...observed.map((item) => String(item.application || "").trim())].filter(Boolean)),
    );
    const surfaces = Array.from(new Set(observed.map((item) => String(item.ai_surface || "").trim()).filter(Boolean)));
    const prevented = observed.filter((item) => {
      const decision = String(item.policy_decision || "").toLowerCase();
      const evidence = item.decision_explanation?.evidence;
      const hasEvidence = Boolean(
        evidence?.evidence_refs?.length ||
        evidence?.evidence_bundle_id ||
        evidence?.trace_id ||
        evidence?.event_hash ||
        evidence?.finding_id,
      );
      return (decision === "block" || decision === "prevent") && hasEvidence;
    }).length;
    const review = observed.filter((item) => {
      const decision = String(item.policy_decision || "").toLowerCase();
      return decision === "warn" || decision === "require_approval" || decision === "hold" || decision === "hold_for_approval";
    }).length;
    const other = observed.length - prevented - review;
    const risk = Math.max(numberOrZero(user.risk_score), ...observed.map((item) => numberOrZero(item.risk_score)));

    return {
      user,
      applications,
      surfaces,
      actions: observed.length,
      prevented,
      review,
      other,
      risk,
    };
  });
  const emptyLabel = loading
    ? "Loading interaction security data…"
    : unavailable
      ? "Interaction security data is unavailable; current user activity cannot be verified."
      : "No user records are available to correlate with the current activity feed.";

  return (
    <PageSection
      title="Interaction Security by user, app, and surface"
      description="Correlated user inventory and current activity-feed evidence. Prevention counts require block/prevent decisions plus recorded evidence metadata; warnings and approval holds remain review outcomes."
    >
      {loading ? (
        <div className="mb-3 rounded-md border border-sky-900/50 bg-sky-950/25 px-3 py-2 text-sm text-sky-200">
          Loading interaction security data…
        </div>
      ) : unavailable ? (
        <div className="mb-3 rounded-md border border-amber-900/50 bg-amber-950/25 px-3 py-2 text-sm text-amber-200">
          Interaction security data is unavailable; current user activity cannot be verified.
        </div>
      ) : null}
      <SimpleTable
        columns={["User identity", "Connected / observed apps", "Observed surfaces", "Actions", "Prevention / review", "Risk", "Open"]}
        emptyLabel={emptyLabel}
        initialVisibleRows={12}
        rows={rows.map((row) => [
          <div key={`${row.user.user_id}-identity`}>
            <p className="font-semibold text-slate-100">{row.user.user_email || row.user.user_id}</p>
            {row.user.user_email ? <p className="mt-1 text-xs text-slate-500">{row.user.user_id}</p> : null}
          </div>,
          row.applications.join(", ") || "No connected or observed apps",
          row.surfaces.join(", ") || "No activity-feed surface observed",
          <span key={`${row.user.user_id}-actions`} className="font-semibold tabular-nums text-slate-100">{row.actions}</span>,
          <div key={`${row.user.user_id}-outcomes`} className="space-y-1 text-xs">
            <p className="text-rose-300">{row.prevented} prevented</p>
            <p className="text-amber-300">{row.review} review</p>
            <p className="text-slate-400">{row.other} other observed</p>
          </div>,
          <Badge key={`${row.user.user_id}-risk`} className={severityBadgeClass(row.risk >= 0.75 ? "high" : row.risk >= 0.45 ? "medium" : "low")}>
            {Math.round(row.risk * 100)}
          </Badge>,
          <Button key={`${row.user.user_id}-open`} asChild variant="outline" size="sm">
            <Link href={`/interaction-security?user_id=${encodeURIComponent(row.user.user_id)}`}>Open view</Link>
          </Button>,
        ])}
      />
      <div className="mt-3 flex justify-end">
        <Button asChild variant="ghost" size="sm"><Link href="/interaction-security">Open all interaction security</Link></Button>
      </div>
    </PageSection>
  );
}

function AIIAMPosture({
  identity,
  agents,
}: {
  identity: CommandCenterDashboardState["identity_risk"] | undefined;
  agents: CommandCenterDashboardState["agents_view"];
}) {
  const totals = [
    ["Total agents", numberOrZero(identity?.total_agents)],
    ["Active", numberOrZero(identity?.active_agents)],
    ["Risky", numberOrZero(identity?.risky_agents)],
  ] as const;

  return (
    <PageSection title="AI IAM" description="Agent identity, ownership, authority surface, activity, and anomaly posture from the loaded AI IAM state.">
      <div className="grid grid-cols-3 overflow-hidden rounded-md border border-[#242c3d]">
        {totals.map(([label, value]) => (
          <div key={label} className="border-r border-[#1d2432] bg-[#0d1119] p-3 last:border-r-0">
            <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</p>
            <p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      <div className="mt-3">
        <SimpleTable
          columns={["Agent", "Authority / activity", "Status / anomaly", "Risk", "Tools / apps", "Detail"]}
          emptyLabel="No agent records are available in the current AI IAM response."
          rows={(agents?.items || []).slice(0, 10).map((agent) => {
            const authority = identity?.top_agents.find((item) => item.agent_id === agent.agent_id);
            return [
              <div key={`${agent.agent_id}-agent`}>
                <p className="font-semibold text-slate-100">{agent.name || agent.agent_id}</p>
                <p className="mt-1 text-xs text-slate-500">{agent.owner || "Owner not recorded"}</p>
              </div>,
              <div key={`${agent.agent_id}-authority`} className="space-y-1 text-xs">
                <p className="text-slate-300">Max chain depth: {authority?.max_chain_depth ?? "not recorded"}</p>
                <p className="text-slate-500">Observed actions: {numberOrZero(authority?.actions ?? agent.recent_actions.length)}</p>
              </div>,
              <div key={`${agent.agent_id}-status`} className="flex flex-wrap gap-1">
                <Badge className={String(agent.status).toLowerCase() === "active" ? "bg-emerald-950 text-emerald-300" : "bg-slate-800 text-slate-300"}>{agent.status}</Badge>
                {agent.anomaly_flag ? <Badge className="bg-rose-950 text-rose-300">Anomaly</Badge> : <Badge className="bg-slate-900 text-slate-400">No anomaly</Badge>}
              </div>,
              <Badge key={`${agent.agent_id}-risk`} className={severityBadgeClass(agent.risk_score >= 0.75 ? "high" : agent.risk_score >= 0.45 ? "medium" : "low")}>
                {Math.round(numberOrZero(agent.risk_score) * 100)}
              </Badge>,
              <div key={`${agent.agent_id}-tools`} className="space-y-1 text-xs">
                <p className="text-slate-300">Tools: {agent.tools_used.join(", ") || "none observed"}</p>
                <p className="text-slate-500">Apps: {agent.apps_touched.join(", ") || "none observed"}</p>
              </div>,
              <Button key={`${agent.agent_id}-detail`} asChild variant="outline" size="sm">
                <Link href={`/ai-iam/agents/${encodeURIComponent(agent.agent_id)}`}>Agent detail</Link>
              </Button>,
            ];
          })}
        />
      </div>
      <div className="mt-3 flex justify-end">
        <Button asChild variant="ghost" size="sm"><Link href="/ai-iam">Open AI IAM</Link></Button>
      </div>
    </PageSection>
  );
}

function ControlValidationPanel({
  simulations,
  coverage,
}: {
  simulations: CommandCenterDashboardState["simulations"] | undefined;
  coverage: CommandCenterDashboardState["control_coverage"] | undefined;
}) {
  const hasExecutedRuns = numberOrZero(simulations?.total_runs) > 0;
  const coverageMetrics = [
    ["Average maturity", numberOrZero(coverage?.average_maturity)],
    ["Technical enforcement", numberOrZero(coverage?.average_technical_enforcement)],
    ["Coverage score", numberOrZero(coverage?.average_coverage_score)],
  ] as const;

  return (
    <PageSection
      title="Simulation / Control Validation"
      description="Executed simulation evidence is separated from control maturity and coverage posture. Coverage without a run is not labeled validated."
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(280px,0.8fr)_minmax(0,1.2fr)]">
        <div className="rounded-md border border-[#273044] bg-[#0b1220] p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Executed runs</p>
            <Badge className={hasExecutedRuns ? "bg-emerald-950 text-emerald-300" : "bg-slate-800 text-slate-300"}>
              {hasExecutedRuns ? "Executed evidence" : "Not executed"}
            </Badge>
          </div>
          {hasExecutedRuns ? (
            <>
              <div className="mt-4 grid grid-cols-3 gap-2">
                {[
                  ["Runs", numberOrZero(simulations?.total_runs), "text-slate-100"],
                  ["Pass", numberOrZero(simulations?.pass_count), "text-emerald-300"],
                  ["Fail", numberOrZero(simulations?.fail_count), "text-rose-300"],
                ].map(([label, value, tone]) => (
                  <div key={String(label)} className="rounded-md border border-[#1e2433] bg-[#0d1119] p-3 text-center">
                    <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</p>
                    <p className={`mt-2 text-xl font-semibold tabular-nums ${tone}`}>{Number(value).toLocaleString()}</p>
                  </div>
                ))}
              </div>
              <div className="mt-3 space-y-2">
                {(simulations?.recent_runs || []).slice(0, 4).map((run) => {
                  const result = String(run.result || "unknown").toLowerCase();
                  return (
                    <div key={run.run_id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-[#1e2433] bg-[#0d1119] px-3 py-2 text-xs">
                      <div>
                        <p className="font-medium text-slate-200">{run.simulation_id}</p>
                        <p className="mt-1 text-slate-500">{formatDateTime(run.finished_at || run.started_at)} · {run.mode}</p>
                      </div>
                      <Badge className={result === "pass" || result === "passed" ? "bg-emerald-950 text-emerald-300" : result === "fail" || result === "failed" ? "bg-rose-950 text-rose-300" : "bg-slate-800 text-slate-300"}>
                        {result}
                      </Badge>
                    </div>
                  );
                })}
              </div>
            </>
          ) : (
            <p className="mt-4 text-sm leading-6 text-slate-400">
              No simulation runs were executed in this dashboard window. The control scores alongside are posture indicators, not validation results.
            </p>
          )}
          <div className="mt-4"><Button asChild variant="outline" size="sm"><Link href="/simulations">Open simulations</Link></Button></div>
        </div>

        <div className="rounded-md border border-[#273044] bg-[#0b1220] p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-400">Control maturity / coverage</p>
              <p className="mt-1 text-xs text-slate-500">Posture scores on a 0–1 scale; they do not establish that a simulation ran.</p>
            </div>
            <Button asChild variant="outline" size="sm"><Link href="/validation/coverage">Open coverage</Link></Button>
          </div>
          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            {coverageMetrics.map(([label, value]) => (
              <div key={label} className="rounded-md border border-[#1e2433] bg-[#0d1119] p-3">
                <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</p>
                <p className="mt-2 text-xl font-semibold tabular-nums text-slate-100">{value.toFixed(2)} <span className="text-xs font-normal text-slate-500">/ 1.00</span></p>
              </div>
            ))}
          </div>
          <div className="mt-3">
            <SimpleTable
              columns={["Lowest control", "Maturity", "Technical", "Coverage", "Status", "Open"]}
              emptyLabel="No low-coverage control rows are available in the current response."
              rows={(coverage?.lowest_controls || []).slice(0, 6).map((control) => [
                control.control_id,
                control.maturity_score.toFixed(2),
                control.technical_enforcement_score.toFixed(2),
                control.coverage_score.toFixed(2),
                <Badge
                  key={`${control.control_id}-status`}
                  className={hasExecutedRuns ? healthBadgeClass(control.status) : "bg-slate-800 text-slate-300"}
                >
                  {hasExecutedRuns ? control.status : "Posture only"}
                </Badge>,
                <Button key={`${control.control_id}-open`} asChild variant="ghost" size="sm">
                  <Link href={`/validation/coverage?control_id=${encodeURIComponent(control.control_id)}`}>Open control</Link>
                </Button>,
              ])}
            />
          </div>
        </div>
      </div>
    </PageSection>
  );
}

export default function CommandCenterPage() {
  const [data, setData] = useState<CommandCenterDashboardState | null>(null);
  const [pilotHealth, setPilotHealth] = useState<PilotHealthState | null>(null);
  const [loading, setLoading] = useState(true);
  const [tabVisible, setTabVisible] = useState<boolean>(() => (typeof document === "undefined" ? true : !document.hidden));
  const [timeWindow, setTimeWindow] = useState<number>(168);
  const [aiSystemFilter, setAiSystemFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [intentCategoryFilter, setIntentCategoryFilter] = useState<string>("all");
  const [inputSensitivityFilter, setInputSensitivityFilter] = useState<string>("all");
  const [outputSensitivityFilter, setOutputSensitivityFilter] = useState<string>("all");
  const [actionAlignmentFilter, setActionAlignmentFilter] = useState<string>("all");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [lastDashboardLatencyMs, setLastDashboardLatencyMs] = useState<number | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);
  const [externalRiskSyncing, setExternalRiskSyncing] = useState(false);
  const [externalRiskSyncError, setExternalRiskSyncError] = useState<string | null>(null);
  const [scanRunning, setScanRunning] = useState(false);
  const [scanActionError, setScanActionError] = useState<string | null>(null);
  const [dashboardLoadError, setDashboardLoadError] = useState<string | null>(null);
  const [pilotHealthError, setPilotHealthError] = useState<string | null>(null);
  const streamRefreshTimerRef = useRef<number | null>(null);
  const loadInFlightRef = useRef<Promise<void> | null>(null);
  const loadRequestGenerationRef = useRef(0);
  const queuedLoadRef = useRef<QueuedDashboardLoad | null>(null);
  const lastStreamRefreshAtRef = useRef<number>(0);
  const scanRunningRef = useRef(false);

  useEffect(() => {
    const onVisibilityChange = () => {
      setTabVisible(!document.hidden);
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, []);

  const loadPilotHealth = useCallback(async () => {
    const started = typeof performance !== "undefined" ? performance.now() : Date.now();
    try {
      const payload = await api.pilotHealth();
      setPilotHealth(payload);
      setPilotHealthError(null);
      const ended = typeof performance !== "undefined" ? performance.now() : Date.now();
      setLastDashboardLatencyMs(Math.max(0, Math.round(ended - started)));
      return true;
    } catch (error) {
      setPilotHealthError(formatErrorMessage(error));
      return false;
    }
  }, []);

  const drainLoadQueue = useCallback(async () => {
    if (loadInFlightRef.current) return;
    while (true) {
      const drain = (async () => {
        while (queuedLoadRef.current) {
          const request = queuedLoadRef.current;
          queuedLoadRef.current = null;
          const started = typeof performance !== "undefined" ? performance.now() : Date.now();
          if (!request.silent) setLoading(true);
          let success = false;
          try {
            const payload = await api.commandCenterDashboard(request.params);
            success = true;
            if (request.generation === loadRequestGenerationRef.current) {
              setData(payload);
              setDashboardLoadError(null);
              const ended = typeof performance !== "undefined" ? performance.now() : Date.now();
              setLastDashboardLatencyMs(Math.max(0, Math.round(ended - started)));
              setLastUpdated(new Date());
            }
          } catch (error) {
            if (request.generation === loadRequestGenerationRef.current) {
              setDashboardLoadError(formatErrorMessage(error));
            }
          } finally {
            if (!request.silent) setLoading(false);
            request.resolvers.forEach((resolve) => resolve(success));
          }
        }
      })();

      loadInFlightRef.current = drain;
      try {
        await drain;
      } finally {
        if (loadInFlightRef.current === drain) {
          loadInFlightRef.current = null;
        }
      }
      if (!queuedLoadRef.current) return;
    }
  }, []);

  const load = useCallback(
    (forceRefresh = false, silent = false): Promise<boolean> => {
      const generation = loadRequestGenerationRef.current + 1;
      loadRequestGenerationRef.current = generation;
      const params: DashboardLoadParams = {
        time_window_hours: timeWindow,
        ai_system_id: aiSystemFilter !== "all" ? aiSystemFilter : undefined,
        severity: severityFilter !== "all" ? (severityFilter as "low" | "med" | "medium" | "high" | "critical") : undefined,
        intent_category: intentCategoryFilter !== "all" ? intentCategoryFilter : undefined,
        input_sensitivity: inputSensitivityFilter !== "all" ? (inputSensitivityFilter as "none" | "low" | "medium" | "high" | "critical") : undefined,
        output_sensitivity: outputSensitivityFilter !== "all" ? (outputSensitivityFilter as "none" | "low" | "medium" | "high" | "critical") : undefined,
        action_alignment: actionAlignmentFilter !== "all" ? (actionAlignmentFilter as "aligned" | "suspicious" | "out_of_scope" | "unknown") : undefined,
        force_refresh: forceRefresh,
      };

      return new Promise<boolean>((resolve) => {
        const queued = queuedLoadRef.current;
        queuedLoadRef.current = {
          generation,
          params: {
            ...params,
            force_refresh: forceRefresh || Boolean(queued?.params.force_refresh),
          },
          silent: queued ? queued.silent && silent : silent,
          resolvers: [...(queued?.resolvers || []), resolve],
        };
        void drainLoadQueue();
      });
    },
    [timeWindow, aiSystemFilter, severityFilter, intentCategoryFilter, inputSensitivityFilter, outputSensitivityFilter, actionAlignmentFilter, drainLoadQueue]
  );

  useEffect(() => {
    if (!tabVisible) return;
    load(false).catch(() => undefined);
  }, [load, tabVisible]);

  useEffect(() => {
    if (!tabVisible) return undefined;
    const timer = setInterval(() => {
      load(false, true).catch(() => undefined);
    }, 12000);
    return () => clearInterval(timer);
  }, [load, tabVisible]);

  useEffect(() => {
    if (!tabVisible) return undefined;
    loadPilotHealth().catch(() => undefined);
    const timer = setInterval(() => {
      loadPilotHealth().catch(() => undefined);
    }, 20000);
    return () => clearInterval(timer);
  }, [loadPilotHealth, tabVisible]);

  const queueStreamRefresh = useCallback(() => {
    if (!tabVisible) return;
    const now = Date.now();
    if (now - lastStreamRefreshAtRef.current < 4000) return;
    lastStreamRefreshAtRef.current = now;
    if (streamRefreshTimerRef.current !== null) {
      window.clearTimeout(streamRefreshTimerRef.current);
    }
    streamRefreshTimerRef.current = window.setTimeout(() => {
      load(false, true).catch(() => undefined);
      streamRefreshTimerRef.current = null;
    }, 500);
  }, [load, tabVisible]);

  useEffect(
    () => () => {
      if (streamRefreshTimerRef.current !== null) {
        window.clearTimeout(streamRefreshTimerRef.current);
      }
    },
    []
  );

  const onRuntimeStreamEvent = useCallback((streamEvent: RuntimeStreamEvent) => {
    const eventType = String(streamEvent.event_type || "").trim().toLowerCase();
    if (!eventType.startsWith("runtime.")) return;
    queueStreamRefresh();
  }, [queueStreamRefresh]);

  useRuntimeIntelligenceStream({
    channel: "overview",
    enabled: tabVisible,
    onEvent: onRuntimeStreamEvent,
    onReconnect: () => {
      load(false, true).catch(() => undefined);
    },
    onConnectionStateChange: setStreamConnected,
  });

  const syncExternalRiskNow = useCallback(async () => {
    setExternalRiskSyncing(true);
    setExternalRiskSyncError(null);
    try {
      await api.syncExternalRisk();
      const refreshed = await load(true, true);
      if (!refreshed) {
        setExternalRiskSyncError("Sync completed but dashboard refresh failed. Existing data is preserved.");
        return;
      }
      setLastUpdated(new Date());
    } catch (error) {
      const message = formatErrorMessage(error);
      setExternalRiskSyncError(message);
      // Best-effort recovery for transient API restarts during sync operations.
      setTimeout(() => {
        load(false, true).catch(() => undefined);
      }, 1200);
    } finally {
      setExternalRiskSyncing(false);
    }
  }, [load]);

  const runExposureScan = useCallback(async () => {
    if (scanRunningRef.current) return;

    scanRunningRef.current = true;
    setScanRunning(true);
    setScanActionError(null);

    try {
      const triggered = await api.triggerScan({
        scan_type: "discovery",
        scope: "global",
        parameters: {},
      });
      const scanId = String(triggered.scan_id || "").trim();
      if (!scanId) {
        throw new Error("Scan trigger did not return a scan ID.");
      }

      await load(true, true);

      let nextError: string | null = null;
      for (let attempt = 0; attempt < 24; attempt += 1) {
        await waitFor(1500);
        const current = await api.scanById(scanId);
        const currentStatus = String(current.status || "").toLowerCase();
        if (currentStatus === "completed" || currentStatus === "failed") {
          if (currentStatus === "failed") {
            nextError = current.error || "Scan failed. Retry after checking API worker logs.";
          }
          break;
        }
      }

      const refreshed = await load(true, true);
      if (!refreshed) {
        nextError = nextError || "Scan finished but Command Center refresh failed. Existing data is preserved.";
      }
      setScanActionError(nextError);
    } catch (error) {
      setScanActionError(formatErrorMessage(error));
      setTimeout(() => {
        load(false, true).catch(() => undefined);
      }, 1200);
    } finally {
      scanRunningRef.current = false;
      setScanRunning(false);
    }
  }, [load]);

  const riskTrendPoints = useMemo(
    () =>
      (data?.risk_over_time.points || []).map((item) => ({
        label: item.label,
        value: Math.round(numberOrZero(item.risk_score) * 100),
      })),
    [data]
  );
  const observedRiskPeak = riskTrendPoints.reduce((peak, point) => Math.max(peak, numberOrZero(point.value)), 0);
  const observedRiskTone = toneFromExposure(observedRiskPeak);

  const severitySlices = useMemo(() => {
    const counts = data?.severity_distribution.counts || {};
    return [
      { label: "Low", value: numberOrZero(counts.low), color: "#34d399" },
      { label: "Medium", value: numberOrZero(counts.med), color: "#fbbf24" },
      { label: "High", value: numberOrZero(counts.high), color: "#fb7185" },
      { label: "Critical", value: numberOrZero(counts.critical), color: "#ef4444" },
    ];
  }, [data]);

  const exposureScore = numberOrZero(data?.exposure_score.score);
  const totalRiskReduction = numberOrZero(data?.crq_summary?.total_estimated_risk_reduction_usd);
  const crqExposure = numberOrZero(data?.crq_summary?.risk_exposure_usd ?? data?.crq_summary?.total_base_risk_usd);
  const crqReduced = numberOrZero(data?.crq_summary?.risk_reduced_usd ?? totalRiskReduction);
  const crqAtRisk = numberOrZero(data?.crq_summary?.at_risk_if_ignored_usd ?? Math.max(crqExposure - crqReduced, 0));
  const highPriorityRecommendations = useMemo(
    () => (data?.recommendations || []).slice(0, 6),
    [data]
  );

  const blockedActions = useMemo(
    () =>
      (data?.runtime_heatmap.rows || []).reduce(
        (acc, row) => acc + numberOrZero(row.counts.block),
        0
      ),
    [data]
  );
  const liveFeedItems = useMemo(() => {
    const items = data?.live_activity_feed?.items || [];
    const materialItems = items
      .filter((item) => intentCategoryFilter === "all" || String(item.intent_category || "").toLowerCase() === intentCategoryFilter)
      .filter((item) => inputSensitivityFilter === "all" || String(item.input_sensitivity || "").toLowerCase() === inputSensitivityFilter)
      .filter((item) => outputSensitivityFilter === "all" || String(item.output_sensitivity || "").toLowerCase() === outputSensitivityFilter)
      .filter((item) => actionAlignmentFilter === "all" || String(item.action_alignment || "").toLowerCase() === actionAlignmentFilter)
      .filter((item) => !isBenignLiveFeedNoise(item.action_type, item.policy_decision))
      .sort((left, right) => {
        const priorityDelta = liveFeedDecisionPriority(left.policy_decision) - liveFeedDecisionPriority(right.policy_decision);
        if (priorityDelta !== 0) return priorityDelta;
        const rightTime = Date.parse(String(right.timestamp || ""));
        const leftTime = Date.parse(String(left.timestamp || ""));
        return (Number.isFinite(rightTime) ? rightTime : 0) - (Number.isFinite(leftTime) ? leftTime : 0);
      });
    return (materialItems.length ? materialItems : items).slice(0, 4);
  }, [actionAlignmentFilter, data, inputSensitivityFilter, intentCategoryFilter, outputSensitivityFilter]);
  const filteredSurfaceItems = useMemo(() => {
    const items = data?.live_activity_feed?.items || [];
    return items
      .filter((item) => intentCategoryFilter === "all" || String(item.intent_category || "").toLowerCase() === intentCategoryFilter)
      .filter((item) => inputSensitivityFilter === "all" || String(item.input_sensitivity || "").toLowerCase() === inputSensitivityFilter)
      .filter((item) => outputSensitivityFilter === "all" || String(item.output_sensitivity || "").toLowerCase() === outputSensitivityFilter)
      .filter((item) => actionAlignmentFilter === "all" || String(item.action_alignment || "").toLowerCase() === actionAlignmentFilter);
  }, [actionAlignmentFilter, data, inputSensitivityFilter, intentCategoryFilter, outputSensitivityFilter]);
  const intentFilterOptions = useMemo(
    () => {
      const backendOptions = data?.available_filters?.intent_categories || [];
      if (backendOptions.length) return backendOptions;
      return Array.from(new Set((data?.live_activity_feed?.items || []).map((item) => String(item.intent_category || "").toLowerCase()).filter(Boolean))).sort();
    },
    [data]
  );
  const inputSensitivityFilterOptions = data?.available_filters?.input_sensitivities || ["none", "low", "medium", "high", "critical"];
  const outputSensitivityFilterOptions = data?.available_filters?.output_sensitivities || ["none", "low", "medium", "high", "critical"];
  const alignmentFilterOptions = data?.available_filters?.action_alignments || ["aligned", "suspicious", "out_of_scope", "unknown"];
  const timeWindowLabel = timeWindow >= 24 ? `last ${Math.round(timeWindow / 24)} days` : `last ${timeWindow} hours`;
  const priorityActions = useMemo<PriorityAction[]>(() => {
    const actions: PriorityAction[] = [];
    const evidenceIncomplete = numberOrZero(data?.ai_action_control?.evidence_status_counts?.incomplete);
    const highCriticalOpen = numberOrZero(data?.violations.high_critical_open_count);
    const externalRequired = numberOrZero(data?.surface_coverage_summary?.totals?.external_required);

    if (dashboardLoadError) {
      actions.push({
        id: "restore-api",
        title: "Restore current control-plane data",
        detail: "The Command Center cannot refresh from the API. Hawk is not presenting cached data as current enforcement proof.",
        href: "/surface-coverage",
        tone: "critical",
        label: "Service",
      });
    }
    if (pilotHealth && pilotHealth.overall_status === "not_connected") {
      // A new installation: nothing has reported yet, so the first step is to connect something, not a repair.
      actions.push({
        id: "get-started",
        title: "Connect your first AI tool",
        detail: "Nothing reports to Hawk AI yet. Install the browser extension, or connect an AI provider through the gateway, to start seeing AI activity.",
        href: "/deploy",
        tone: "info",
        label: "Get started",
      });
    } else if (pilotHealth && pilotHealth.overall_status !== "ok") {
      actions.push({
        id: "pilot-health",
        title: "Resolve degraded pilot health",
        detail: `Policy sync is ${pilotHealth.policy_sync_health.status}; browser telemetry is ${pilotHealth.telemetry_health.status}.`,
        href: "/surface-coverage",
        tone: "warning",
        label: "Readiness",
      });
    }
    if (highCriticalOpen > 0) {
      actions.push({
        id: "high-findings",
        title: `Investigate ${highCriticalOpen.toLocaleString()} high or critical findings`,
        detail: "Open the evidence-backed finding queue and prioritize actions with proven control or exposure impact.",
        href: "/discovery/findings?severity=high",
        tone: "critical",
        label: "Findings",
      });
    }
    if (evidenceIncomplete > 0) {
      actions.push({
        id: "evidence-incomplete",
        title: `Repair ${evidenceIncomplete.toLocaleString()} incomplete evidence records`,
        detail: "Attribution, policy snapshot, trace, or integrity proof is missing for these AI actions.",
        href: "/auditor",
        tone: "warning",
        label: "Evidence",
      });
    }
    if (externalRequired > 0) {
      actions.push({
        id: "external-enforcement",
        title: `Complete ${externalRequired.toLocaleString()} external enforcement actions`,
        detail: "These actions require Microsoft, Google, IAM, proxy, MDM, EDR, or SaaS administration. Hawk has not labeled them prevented.",
        href: "/surface-coverage",
        tone: "info",
        label: "Coverage",
      });
    }
    return actions.slice(0, 3);
  }, [dashboardLoadError, data, pilotHealth]);
  const governanceOverview = useMemo(() => deriveGovernanceOverview(data), [data]);

  if (process.env.NEXT_PUBLIC_LEGACY_COMMAND_CENTER !== "true") {
    return (
      <AppShell>
        <div className="space-y-6">
          <OperationsConsoleTabs
            tabs={[
              { label: "Overview", href: "/dashboard/command-center" },
              { label: "AI Actions", href: "/runtime-intelligence/overview", matchPrefix: true },
              { label: "Findings", href: "/discovery/findings", matchPrefix: true },
              { label: "Evidence", href: "/auditor", matchPrefix: true },
            ]}
            rightSlot={
              <div className="inline-flex items-center gap-2 text-sm text-emerald-300">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(74,222,128,0.8)]" />
                <span className="font-semibold">{streamConnected ? "Connected" : "Waiting"}</span>
              </div>
            }
          />
          <PageHeader
            eyebrow="AI Command Center"
            title="Overview"
            description="Review prioritized control work and recent activity from the current tenant evidence."
            actions={
              <>
                <div className="inline-flex items-center gap-2 rounded-md border border-[#273044] bg-[#0d1119] px-3 py-2 text-xs text-slate-400">
                  <span className="h-2 w-2 rounded-full bg-emerald-400" />
                  {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : "Waiting for current data"}
                </div>
                <Button variant="outline" onClick={() => load(true)}>Refresh</Button>
              </>
            }
          />

          {dashboardLoadError ? (
            <div className="rounded-md border border-amber-900/50 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
              Live data unavailable: {dashboardLoadError}. Hawk is not treating demo or stale values as current enforcement proof.
            </div>
          ) : null}

          <TopActionsNow actions={priorityActions} />
          <EvidenceRiver events={governanceOverview.river} live={streamConnected} />

          <details className="group rounded-xl border border-white/[0.07] bg-[#091019]">
            <summary className="cursor-pointer list-none px-4 py-3 text-xs font-semibold text-slate-300 hover:text-white">Scope & filters <span className="ml-2 text-[10px] font-normal text-slate-600">Every visual uses this tenant-scoped context</span></summary>
            <div className="border-t border-white/[0.06] p-4">
          <PlatformModeControl compact />

          <PageSection title="Visible scope" description="Every panel below uses this same tenant-scoped filter context.">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <select className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200" value={timeWindow} onChange={(event) => setTimeWindow(Number(event.target.value))} title="Filter by time window">
                {(data?.available_filters.time_window_hours || [24, 72, 168, 336, 720]).map((option) => <option key={option} value={option}>{option >= 24 ? `${Math.round(option / 24)}d` : `${option}h`}</option>)}
              </select>
              <select className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200" value={aiSystemFilter} onChange={(event) => setAiSystemFilter(event.target.value)} title="Filter by AI system">
                <option value="all">All AI systems</option>
                {(data?.available_filters.ai_systems || []).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
              </select>
              <select className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} title="Filter by severity">
                {(data?.available_filters.severity || ["all", "low", "med", "high", "critical"]).map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}
              </select>
              <select className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200" value={intentCategoryFilter} onChange={(event) => setIntentCategoryFilter(event.target.value)} title="Filter by intent category">
                <option value="all">All intents</option>
                {intentFilterOptions.map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}
              </select>
              <select className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200" value={inputSensitivityFilter} onChange={(event) => setInputSensitivityFilter(event.target.value)} title="Filter by input sensitivity">
                <option value="all">All input sensitivity</option>
                {inputSensitivityFilterOptions.map((item) => <option key={item} value={item}>Input {item}</option>)}
              </select>
              <select className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200" value={outputSensitivityFilter} onChange={(event) => setOutputSensitivityFilter(event.target.value)} title="Filter by output sensitivity">
                <option value="all">All output sensitivity</option>
                {outputSensitivityFilterOptions.map((item) => <option key={item} value={item}>Output {item}</option>)}
              </select>
              <select className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200" value={actionAlignmentFilter} onChange={(event) => setActionAlignmentFilter(event.target.value)} title="Filter by action alignment">
                <option value="all">All alignment</option>
                {alignmentFilterOptions.map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}
              </select>
              <Button variant="outline" onClick={() => load(true)}>Apply filters</Button>
            </div>
          </PageSection>
            </div>
          </details>

          <details className="group rounded-2xl border border-white/[0.08] bg-[#091019]">
            <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-200 hover:text-white">Governance context and coverage <span className="ml-2 text-xs font-normal text-slate-600">Storyline, surface coverage, and regulated workflow detail</span></summary>
            <div className="space-y-6 border-t border-white/[0.07] p-4 sm:p-5">
              <GovernanceStoryline model={governanceOverview} />
              <GovernanceOperations model={governanceOverview} priorityActions={priorityActions} />
              <BankingCisoSummaryPanel />
            </div>
          </details>

          <details className="group rounded-2xl border border-white/[0.08] bg-[#091019]">
            <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-200 hover:text-white">Detailed operating view <span className="ml-2 text-xs font-normal text-slate-600">MCP, Interaction Security, AI IAM, validation, findings and runtime controls</span></summary>
            <div className="space-y-6 border-t border-white/[0.07] p-4 sm:p-5">
          <PersonaHome />

          <AIActionControlCard summary={data?.ai_action_control} />
          <FourSurfaceMatrix summary={data?.surface_coverage_summary} />

          <div className="grid items-start gap-6 xl:grid-cols-2">
            <MCPGatewayVisibility summary={data?.mcp_tool_calls} />
            <AIIAMPosture identity={data?.identity_risk} agents={data?.agents_view} />
          </div>
          <InteractionSecurityMatrix
            users={data?.users_view?.items || []}
            activity={data?.live_activity_feed?.items || []}
            loading={loading}
            unavailable={Boolean(dashboardLoadError) || (!loading && !data)}
          />
          <ControlValidationPanel
            simulations={data?.simulations}
            coverage={data?.control_coverage}
          />

          <div className="grid items-start gap-6 xl:grid-cols-2">
            <PageSection title="Risk and policy breakdown" description="Observed risk and open violations only; no synthetic financial or exposure estimates.">
              <div className="grid gap-4 lg:grid-cols-2">
                <TrendSparkCard title="Risk trend" subtitle={`Observed over ${timeWindowLabel}`} points={riskTrendPoints} tone={observedRiskTone} yAxisLabel="Risk score" xAxisLabel="Timeline" />
                <DistributionDonutCard title="Severity distribution" subtitle="Open violations" centerLabel="Open" centerValue={`${data?.severity_distribution.total || 0}`} slices={severitySlices} />
              </div>
            </PageSection>
            <PageSection title="Identity and authority" description="Who is using AI, which agents act for them, and what authority is active.">
              <SimpleTable
                columns={["Identity", "Machines / Tools", "Agents / Action", "Risk"]}
                rows={[
                  ...(data?.users_view?.items || []).slice(0, 4).map((row) => [row.user_email || row.user_id, row.machine_ids.join(", ") || row.connected_apps.join(", ") || "-", row.active_agent_ids.join(", ") || "human user", Math.round(numberOrZero(row.risk_score) * 100)]),
                  ...(data?.agents_view?.items || []).slice(0, 4).map((row) => [row.name || row.agent_id, row.tools_used.join(", ") || "-", row.recent_actions[0]?.action_type || "agent", Math.round(numberOrZero(row.risk_score) * 100)]),
                ]}
              />
            </PageSection>
          </div>

          <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
            <PageSection title="Highest-risk action chain" description="Canonical user-to-agent-to-tool execution steps with policy outcomes.">
              <div className="space-y-2">
                {(data?.attack_trace_view?.steps || []).slice(0, 8).map((step) => (
                  <div key={step.event_id} className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-100">{step.title}</p>
                      <Badge className={severityBadgeClass(step.policy_decision === "block" ? "high" : "low")}>{step.policy_decision}</Badge>
                    </div>
                    <p className="text-xs text-slate-400">{formatDateTime(step.timestamp)} · user {step.user_id || "-"} · agent {step.agent_id || "-"} · machine {step.machine_id || "-"}</p>
                  </div>
                ))}
              </div>
            </PageSection>
            <PageSection title="Microsoft AI surfaces" description="Foundry and Copilot posture with explicit enforcement limitations.">
              <SimpleTable
                columns={["Surface", "Control mode", "Current proof", "Investigation"]}
                rows={[
                  ["Microsoft Foundry", <Badge key="foundry-mode" className={controlModeBadgeClass("external_required")}>External Required</Badge>, "Project, agent, model, tool, identity, and data-source inventory; inline only through Hawk Gateway.", <Button key="foundry-open" asChild variant="outline" size="sm"><Link href="/surface-coverage#foundry">Open trace</Link></Button>],
                  ["M365 Copilot", <Badge key="copilot-mode" className={controlModeBadgeClass("detected_only")}>Detected Only</Badge>, "Graph, Purview, Entra, OAuth, user, app, and data-source evidence where available.", <Button key="copilot-open" asChild variant="outline" size="sm"><Link href="/surface-coverage#copilot">Open trace</Link></Button>],
                  ["Copilot Studio", <Badge key="studio-mode" className={controlModeBadgeClass("external_required")}>External Required</Badge>, "Agent, connector, permission, and remediation context; inline only through a supported hook or gateway.", <Button key="studio-open" asChild variant="outline" size="sm"><Link href="/ai-iam?surface=copilot_studio">Open agents</Link></Button>],
                ]}
              />
            </PageSection>
          </div>

          <div className="grid items-start gap-6 xl:grid-cols-2">
            <PageSection title="Agentic browser control" description="Observed automation and enforcement outcomes across browser agents.">
              <SimpleTable columns={["Metric", "Value"]} rows={[
                ["Automation events", numberOrZero(data?.agentic_browser_activity?.automation_events_today)],
                ["Prevented", numberOrZero(data?.agentic_browser_activity?.prevented_events)],
                ["Warned", numberOrZero(data?.agentic_browser_activity?.warned_automation_events)],
                ["Detected-only", numberOrZero(data?.agentic_browser_activity?.detected_only_events)],
                ["Scope violations", numberOrZero(data?.agentic_browser_activity?.scope_violations)],
                ["High-risk blocked", numberOrZero(data?.agentic_browser_activity?.high_risk_actions_blocked)],
              ]} />
            </PageSection>
            <PageSection title="Intent-aware control" description="Purpose, sensitivity, destination, and action-alignment decisions.">
              <SimpleTable columns={["Metric", "Value"]} rows={[
                ["Intent-aware actions", numberOrZero(data?.intent_aware_activity?.intent_aware_actions)],
                ["Allowed research", numberOrZero(data?.intent_aware_activity?.allowed_research)],
                ["Blocked sensitive inputs", numberOrZero(data?.intent_aware_activity?.blocked_sensitive_inputs)],
                ["Blocked output copies", numberOrZero(data?.intent_aware_activity?.blocked_output_copies)],
                ["Scope violations", numberOrZero(data?.intent_aware_activity?.intent_scope_violations)],
                ["Shadow would-block", numberOrZero(data?.intent_aware_activity?.shadow_would_block)],
              ]} />
            </PageSection>
          </div>

          <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(360px,0.95fr)]">
            <OperationsLiveFeed items={liveFeedItems} total={numberOrZero(data?.live_activity_feed?.total)} drilldown={data?.live_activity_feed?.drilldown || "/runtime-intelligence/activity-map"} timeWindowLabel={timeWindowLabel} />
            <PilotHealthCard health={pilotHealth} error={pilotHealthError} latencyMs={lastDashboardLatencyMs} dashboardError={dashboardLoadError} />
          </div>

          <PageSection title="Findings alerts" description="Recent alert-grade findings with direct graph, evidence, and trace drilldowns.">
            <SimpleTable columns={["Severity", "Finding", "Surface", "Actor", "Recommended action", "Investigation"]} rows={(data?.findings_alerts?.items || []).slice(0, 12).map((row) => [
              <Badge key={`${row.finding_id}-alert-sev`} className={severityBadgeClass(row.severity)}>{row.severity}</Badge>,
              row.finding_type || row.finding_id,
              row.ai_surface || row.app || "-",
              row.user_id || row.agent_id || row.machine_id || "-",
              row.recommended_actions?.[0] || "-",
              renderFindingAlertDrilldowns(row),
            ])} />
          </PageSection>

          <PageSection title="Violations requiring action" description="Open policy violations ranked for investigation and response.">
            <SimpleTable columns={["Severity", "Finding", "Tool", "Status", "Occurrences", "Investigation"]} rows={(data?.violations.items || []).slice(0, 15).map((row) => [
              <Badge key={`${row.finding_id}-sev`} className={severityBadgeClass(row.severity)}>{row.severity}</Badge>,
              row.finding_type,
              row.ai_tool,
              row.status,
              row.occurrence_count,
              renderViolationDrilldowns(row),
            ])} />
          </PageSection>

          <AIExposureScanCard scan={data?.ai_exposure_scan} scanRunning={scanRunning} scanActionError={scanActionError} onRunScan={() => { void runExposureScan(); }} />
            </div>
          </details>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <OperationsConsoleTabs
          tabs={[
            { label: "Current Events", href: "/dashboard/command-center" },
            { label: "Findings", href: "/discovery/findings", matchPrefix: true },
            { label: "Evidence", href: "/auditor", matchPrefix: true },
          ]}
          rightSlot={
            <div className="inline-flex items-center gap-2 rounded-full px-1 py-1 text-sm text-emerald-300">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(74,222,128,0.8)]" />
              <span className="font-semibold">{streamConnected ? "Connected" : "Waiting"}</span>
            </div>
          }
        />
        <PageHeader
          eyebrow="AI Command Center"
          title="AI Operations"
          description={
            loading
              ? "Loading centralized runtime and enforcement telemetry..."
              : "Reference-led event console for runtime decisions, policy outcomes, and fast investigation."
          }
          actions={
            <>
              <div className="inline-flex items-center gap-2 rounded-2xl border border-emerald-900/50 bg-emerald-950/20 px-3 py-2 text-xs text-emerald-300">
                <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
                {`Stream ${streamConnected ? "connected via SSE" : "polling"} · ${lastUpdated ? lastUpdated.toLocaleTimeString() : "syncing"}`}
              </div>
              <select
                className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200"
                value={timeWindow}
                onChange={(event) => setTimeWindow(Number(event.target.value))}
                title="Filter by time window"
              >
                {(data?.available_filters.time_window_hours || [24, 72, 168, 336, 720]).map((option) => (
                  <option key={option} value={option}>
                    {option >= 24 ? `${Math.round(option / 24)}d` : `${option}h`}
                  </option>
                ))}
              </select>
              <select
                className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200"
                value={intentCategoryFilter}
                onChange={(event) => setIntentCategoryFilter(event.target.value)}
                title="Filter by intent category"
              >
                <option value="all">All intents</option>
                {intentFilterOptions.map((item) => (
                  <option key={item} value={item}>
                    {item.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
              <select
                className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200"
                value={inputSensitivityFilter}
                onChange={(event) => setInputSensitivityFilter(event.target.value)}
                title="Filter by input sensitivity"
              >
                <option value="all">All input</option>
                {inputSensitivityFilterOptions.map((item) => (
                  <option key={item} value={item}>
                    Input {item}
                  </option>
                ))}
              </select>
              <select
                className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200"
                value={outputSensitivityFilter}
                onChange={(event) => setOutputSensitivityFilter(event.target.value)}
                title="Filter by output sensitivity"
              >
                <option value="all">All output</option>
                {outputSensitivityFilterOptions.map((item) => (
                  <option key={item} value={item}>
                    Output {item}
                  </option>
                ))}
              </select>
              <select
                className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200"
                value={actionAlignmentFilter}
                onChange={(event) => setActionAlignmentFilter(event.target.value)}
                title="Filter by action alignment"
              >
                <option value="all">All alignment</option>
                {alignmentFilterOptions.map((item) => (
                  <option key={item} value={item}>
                    {item.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
              <select
                className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200"
                value={aiSystemFilter}
                onChange={(event) => setAiSystemFilter(event.target.value)}
                title="Filter by AI system"
              >
                <option value="all">All AI systems</option>
                {(data?.available_filters.ai_systems || []).map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
              <select
                className="rounded-md border border-[#2b3245] bg-[#0f1218] px-3 py-2 text-sm text-slate-200"
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value)}
                title="Filter by severity"
              >
                {(data?.available_filters.severity || ["all", "low", "med", "high", "critical"]).map((item) => (
                  <option key={item} value={item}>
                    {item.toUpperCase()}
                  </option>
                ))}
              </select>
              <Button variant="outline" onClick={() => load(true)}>
                Refresh
              </Button>
              <Button variant="outline" onClick={() => loadPilotHealth()}>
                Health
              </Button>
            </>
          }
        />
        {dashboardLoadError ? (
          <div className="rounded-md border border-amber-900/50 bg-amber-950/30 px-3 py-2 text-sm text-amber-300">
            Dashboard refresh warning: {dashboardLoadError}. Showing cached data only if a prior successful refresh exists.
          </div>
        ) : null}

        <AIExposureScanCard
          scan={data?.ai_exposure_scan}
          scanRunning={scanRunning}
          scanActionError={scanActionError}
          onRunScan={() => {
            void runExposureScan();
          }}
        />

        <AIActionControlCard summary={data?.ai_action_control} />

        <BankingCisoSummaryPanel />

        <SurfaceCoverageMatrix summary={data?.surface_coverage_summary} />

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
          <PilotHealthCard
            health={pilotHealth}
            error={pilotHealthError}
            latencyMs={lastDashboardLatencyMs}
            dashboardError={dashboardLoadError}
          />
          <OperationsLiveFeed
            items={liveFeedItems}
            total={numberOrZero(data?.live_activity_feed?.total)}
            drilldown={data?.live_activity_feed?.drilldown || "/runtime-intelligence/activity-map"}
            timeWindowLabel={timeWindowLabel}
          />
        </div>

        <KpiStrip
          items={[
            { label: "Exposure Score", value: Math.round(exposureScore), tone: toneFromExposure(exposureScore) },
            { label: "Active Incidents", value: numberOrZero(data?.active_incidents.total), tone: "critical" },
            { label: "Blocked Actions", value: blockedActions, tone: blockedActions > 0 ? "warning" : "success" },
            { label: "CRQ Est. Reduction", value: formatCurrency(totalRiskReduction), tone: totalRiskReduction > 0 ? "success" : "info" },
            { label: "High/Critical Open", value: numberOrZero(data?.violations.high_critical_open_count), tone: "critical" },
          ]}
        />
        <KpiStrip
          items={[
            {
              label: "$ Risk Exposure",
              value: formatCurrency(crqExposure),
              tone: crqExposure > 0 ? "critical" : "default",
              tooltip:
                "Source: crq_summary.risk_exposure_usd (fallback: total_base_risk_usd). Formula: sum of base risk across scored recommendations.",
            },
            {
              label: "$ Risk Reduced",
              value: formatCurrency(crqReduced),
              tone: crqReduced > 0 ? "success" : "default",
              tooltip:
                "Source: crq_summary.risk_reduced_usd (fallback: total_estimated_risk_reduction_usd). Formula: sum of estimated risk reduction from recommended actions.",
            },
            {
              label: "$ At Risk if Ignored",
              value: formatCurrency(crqAtRisk),
              tone: crqAtRisk > 0 ? "warning" : "default",
              tooltip:
                "Source: crq_summary.at_risk_if_ignored_usd (fallback: max(risk_exposure_usd - risk_reduced_usd, 0)). Formula: residual financial risk if recommendations are not applied.",
            },
          ]}
        />
        <AdminRunbookCard />
        <ExternalRiskIntelCard
          intel={data?.external_risk_intelligence}
          syncing={externalRiskSyncing}
          syncError={externalRiskSyncError}
          onSyncNow={() => {
            void syncExternalRiskNow();
          }}
        />

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Instant Actions" description="Existing enforcement actions exposed from the command workflow.">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              {(data?.quick_actions || []).map((action) => (
                <Button key={action.action} asChild variant="outline" className="justify-start">
                  <Link href="/dashboard/command-center">{action.label}</Link>
                </Button>
              ))}
            </div>
          </PageSection>

          <PageSection title="Surface Snapshot" description="Current event mix by actor, app, and decision path.">
            <SimpleTable
              columns={["When", "Surface", "Actor", "App / Action", "Decision", "Trace"]}
              rows={filteredSurfaceItems.slice(0, 6).map((row) => [
                formatDateTime(row.timestamp),
                row.ai_surface,
                row.agent_id || row.user_email || row.user_id || "-",
                `${row.application || "-"} / ${row.action_type}`,
                <Badge key={`${row.event_id}-decision`} className={severityBadgeClass(row.policy_decision === "block" ? "high" : "low")}>
                  {row.policy_decision}
                </Badge>,
                <Button key={`${row.event_id}-trace`} asChild variant="outline" size="sm">
                  <Link href={row.action_trace_url || row.trace_url || `/runtime-intelligence/context-graph?event_id=${row.event_id}`}>Trace</Link>
                </Button>,
              ])}
            />
          </PageSection>
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Users Using AI" description="Identity-linked users with machines, apps, agents, and current risk.">
            <SimpleTable
              columns={["User", "Machines", "Apps", "Agents", "Risk"]}
              rows={(data?.users_view?.items || []).slice(0, 8).map((row) => [
                row.user_email || row.user_id,
                row.machine_ids.join(", ") || "-",
                row.connected_apps.join(", ") || "-",
                row.active_agent_ids.join(", ") || "-",
                Math.round(numberOrZero(row.risk_score) * 100),
              ])}
            />
          </PageSection>

          <PageSection title="Active Agents" description="Agent behavior summaries backed by Runtime Intelligence and AI IAM.">
            <SimpleTable
              columns={["Agent", "Tools", "Recent Action", "Findings", "Risk"]}
              rows={(data?.agents_view?.items || []).slice(0, 8).map((row) => [
                row.name || row.agent_id,
                row.tools_used.join(", ") || "-",
                row.recent_actions[0]?.action_type || "-",
                row.linked_findings.join(", ") || "-",
                <Badge key={`${row.agent_id}-risk`} className={row.anomaly_flag ? "bg-rose-950 text-rose-300" : "bg-emerald-950 text-emerald-300"}>
                  {Math.round(numberOrZero(row.risk_score) * 100)}
                </Badge>,
              ])}
            />
          </PageSection>
        </div>

        <div className="grid gap-4 xl:grid-cols-3">
          <PageSection title="Attack Trace View" description="Highest-risk chain reconstructed as UI-ready step cards.">
            <div className="space-y-2">
              {(data?.attack_trace_view?.steps || []).slice(0, 8).map((step) => (
                <div key={step.event_id} className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-slate-100">{step.title}</p>
                    <Badge className={severityBadgeClass(step.policy_decision === "block" ? "high" : "low")}>{step.policy_decision}</Badge>
                  </div>
                  <p className="text-xs text-slate-400">
                    {formatDateTime(step.timestamp)} · user {step.user_id || "-"} · agent {step.agent_id || "-"} · machine {step.machine_id || "-"}
                  </p>
                </div>
              ))}
            </div>
          </PageSection>

          <PageSection title="Microsoft AI Surfaces" description="Foundry and Copilot control posture with control-mode honesty.">
            <SimpleTable
              columns={["Surface", "Mode", "What Hawk Can Prove Now", "Next Control Path"]}
              rows={[
                [
                  "Microsoft Foundry",
                  <Badge key="foundry-mode" className={controlModeBadgeClass("external_required")}>External Required</Badge>,
                  "Project/agent/model usage can land as telemetry; Azure OpenAI calls are inline only when routed through Hawk Gateway.",
                  <Button key="foundry-open" asChild variant="outline" size="sm"><Link href="/surface-coverage#foundry">View Foundry Trace</Link></Button>,
                ],
                [
                  "M365 Copilot",
                  <Badge key="copilot-mode" className={controlModeBadgeClass("detected_only")}>Detected Only</Badge>,
                  "Graph/Purview/Entra activity can show user, app, data source, OAuth scope, finding and remediation trail.",
                  <Button key="copilot-open" asChild variant="outline" size="sm"><Link href="/surface-coverage#copilot">View Copilot Trace</Link></Button>,
                ],
                [
                  "Copilot Studio Agents",
                  <Badge key="studio-mode" className={controlModeBadgeClass("external_required")}>External Required</Badge>,
                  "Agents/connectors/permissions become first-class AI assets; enforcement depends on Studio/admin hooks or gateway routing.",
                  <Button key="studio-open" asChild variant="outline" size="sm"><Link href="/ai-iam?surface=copilot_studio">View Agents</Link></Button>,
                ],
              ]}
            />
          </PageSection>

          <PageSection
            title="Agentic Browser Activity"
            description="Vendor-agnostic browser automation governance across Claude/ChatGPT/Gemini/Perplexity/Codex/custom sources."
          >
            <SimpleTable
              columns={["Metric", "Value"]}
              rows={[
                ["Automation Events", numberOrZero(data?.agentic_browser_activity?.automation_events_today)],
                ["Prevented", numberOrZero(data?.agentic_browser_activity?.prevented_events)],
                ["Warned", numberOrZero(data?.agentic_browser_activity?.warned_automation_events)],
                ["Allowed", numberOrZero(data?.agentic_browser_activity?.allowed_events)],
                ["Detected-only", numberOrZero(data?.agentic_browser_activity?.detected_only_events)],
                ["Incomplete", numberOrZero(data?.agentic_browser_activity?.incomplete_events)],
                ["Blocked Actions", numberOrZero(data?.agentic_browser_activity?.blocked_automation_actions)],
                ["Scope Violations", numberOrZero(data?.agentic_browser_activity?.scope_violations)],
                ["High-Risk Blocked", numberOrZero(data?.agentic_browser_activity?.high_risk_actions_blocked)],
              ]}
            />
            <div className="mt-3 space-y-2 text-xs text-slate-400">
              <p>
                Top domains: {(data?.agentic_browser_activity?.top_domains_with_automation || [])
                  .map((item) => `${item.domain} (${item.count})`)
                  .join(", ") || "-"}
              </p>
              <p>
                Top suspected tools/vendors: {(data?.agentic_browser_activity?.top_suspected_tools_or_vendors || [])
                  .map((item) => `${item.label} (${item.count})`)
                  .join(", ") || "-"}
              </p>
            </div>
            <div className="mt-3">
              <Button asChild variant="outline" size="sm">
                <Link href={data?.agentic_browser_activity?.drilldown || "/runtime-intelligence/activity-map?surface=agentic_browser"}>
                  Open Agentic Browser View
                </Link>
              </Button>
            </div>
          </PageSection>
          <PageSection
            title="Intent-Aware AI Action Control"
            description="Intent, content, destination trust, and action-alignment outcomes across runtime decisions."
          >
            <SimpleTable
              columns={["Metric", "Value"]}
              rows={[
                ["Intent-Aware Actions", numberOrZero(data?.intent_aware_activity?.intent_aware_actions)],
                ["Allowed Research", numberOrZero(data?.intent_aware_activity?.allowed_research)],
                ["Blocked Sensitive Inputs", numberOrZero(data?.intent_aware_activity?.blocked_sensitive_inputs)],
                ["Blocked Output Copies", numberOrZero(data?.intent_aware_activity?.blocked_output_copies)],
                ["Scope Violations", numberOrZero(data?.intent_aware_activity?.intent_scope_violations)],
                ["Sales Data Violations", numberOrZero(data?.intent_aware_activity?.sales_outreach_data_violations)],
                ["Shadow Would-Block", numberOrZero(data?.intent_aware_activity?.shadow_would_block)],
              ]}
            />
            <div className="mt-3 space-y-2 text-xs text-slate-400">
              <p>
                Sensitive public destinations: {(data?.intent_aware_activity?.top_sensitive_destinations || [])
                  .map((item) => `${item.trust_level.replaceAll("_", " ")} (${item.count})`)
                  .join(", ") || "-"}
              </p>
              <p>
                Badges: {Object.entries(data?.intent_aware_activity?.badge_breakdown || {})
                  .filter(([, value]) => numberOrZero(value) > 0)
                  .map(([label, value]) => `${label} (${value})`)
                  .join(", ") || "-"}
              </p>
            </div>
            <div className="mt-3">
              <Button asChild variant="outline" size="sm">
                <Link href={data?.intent_aware_activity?.drilldown || "/runtime-intelligence/activity-map?filter=intent-aware"}>
                  Open Intent-Aware View
                </Link>
              </Button>
            </div>
          </PageSection>
        </div>

        <div className="grid gap-4 xl:grid-cols-2 2xl:grid-cols-12">
          <div className="min-w-0 xl:col-span-2 2xl:col-span-6">
            <TrendSparkCard
              title="Risk Trend Graph"
              subtitle="Aggregated runtime risk over selected window"
              points={riskTrendPoints}
              tone={toneFromExposure(exposureScore)}
              yAxisLabel="Risk score (0-100)"
              xAxisLabel="Window timeline"
            />
            <div className="mt-3">
              <Button asChild variant="outline" size="sm">
                <Link href={data?.risk_over_time.drilldown || "/runtime-intelligence/overview"}>Open Risk Timeline</Link>
              </Button>
            </div>
          </div>

          <div className="min-w-0 xl:col-span-1 2xl:col-span-3">
            <DistributionDonutCard
              title="Severity Donut"
              subtitle="Open violations by severity"
              centerLabel="Open"
              centerValue={`${data?.severity_distribution.total || 0}`}
              slices={severitySlices}
            />
            <div className="mt-3">
              <Button asChild variant="outline" size="sm">
                <Link href={data?.severity_distribution.drilldown || "/discovery/findings"}>Open Violations</Link>
              </Button>
            </div>
          </div>

          <div className="min-w-0 xl:col-span-1 2xl:col-span-3">
            <ExposureGauge score={exposureScore} drilldown={data?.exposure_score.drilldown || "/analytics"} />
          </div>

          <div className="min-w-0 xl:col-span-2 2xl:col-span-7">
            <RuntimeHeatmapCard rows={data?.runtime_heatmap.rows || []} drilldown={data?.runtime_heatmap.drilldown || "/runtime-intelligence/activity-map"} />
          </div>

          <div className="min-w-0 xl:col-span-2 2xl:col-span-5">
            <PageSection title="Recommendation Panel" description="Prescriptive actions ranked by operational priority.">
              <div className="space-y-2">
                {highPriorityRecommendations.map((item) => (
                  <div
                    key={`${item.title}-${item.priority_score}`}
                    className="rounded-md border border-[#1e2433] bg-[#0f1218] p-3"
                    title={item.reasoning}
                  >
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-100 break-words">{item.title}</p>
                      <Badge className={severityBadgeClass(item.severity)}>{item.severity}</Badge>
                    </div>
                    <p className="text-xs text-slate-400 break-words">{item.reasoning}</p>
                    <div className="mt-2 flex items-center justify-between">
                      <p className="text-xs text-slate-500 break-words">
                        {item.action_type} · Priority {item.priority_score}
                      </p>
                      <Button asChild variant="outline" size="sm" className="shrink-0">
                        <Link href={item.module_route || "/dashboard/command-center"}>Act</Link>
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </PageSection>
          </div>

          <div className="xl:col-span-2 2xl:col-span-12">
            <CrqImpactCard summary={data?.crq_summary} />
          </div>
        </div>

        <PageSection title="Findings Alerts" description="Recent alert-grade findings with direct graph, evidence, and trace drilldowns.">
          <SimpleTable
            columns={["Severity", "Finding", "Surface", "Actor", "Recommended Action", "Investigation"]}
            rows={(data?.findings_alerts?.items || []).slice(0, 12).map((row) => [
              <Badge key={`${row.finding_id}-alert-sev`} className={severityBadgeClass(row.severity)}>
                {row.severity}
              </Badge>,
              row.finding_type || row.finding_id,
              row.ai_surface || row.app || "-",
              row.user_id || row.agent_id || row.machine_id || "-",
              row.recommended_actions?.[0] || "-",
              renderFindingAlertDrilldowns(row),
            ])}
          />
        </PageSection>

        <PageSection title="Violations Table" description="Top actionable violations with direct investigation paths.">
          <SimpleTable
            columns={["Severity", "Finding", "Tool", "Status", "Occurrences", "Investigation"]}
            rows={(data?.violations.items || []).slice(0, 15).map((row) => [
              <Badge key={`${row.finding_id}-sev`} className={severityBadgeClass(row.severity)}>
                {row.severity}
              </Badge>,
              row.finding_type,
              row.ai_tool,
              row.status,
              row.occurrence_count,
              renderViolationDrilldowns(row),
            ])}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
