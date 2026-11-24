"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  Coins,
  DatabaseZap,
  Gauge,
  KeyRound,
  Network,
  PlugZap,
  RefreshCw,
  ShieldCheck,
  Users,
} from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { EvidenceTruthPanel } from "@/components/evidence/evidence-truth-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { AIToolsUsageWorkspace, BrowserExtensionHealth, BrowserExtensionRemovalGovernance } from "@/lib/types";

const TABS = [
  ["overview", "Overview"],
  ["providers", "Providers"],
  ["users", "Users & Departments"],
  ["prompts", "Prompts & Actions"],
  ["mcp", "MCP & Tools"],
  ["spend", "Spend & Utilization"],
  ["accounts", "Accounts & Devices"],
  ["data", "Data, Uploads & Downloads"],
  ["browser", "Browser Extension"],
  ["meeting", "Meeting AI"],
  ["policies", "Policies"],
  ["coverage", "Coverage & Gaps"],
  ["connectors", "Connector Health"],
] as const;

const ACTIVITY_VIEWS = [
  { label: "Review activity", ids: ["overview", "prompts", "mcp", "data", "meeting"] },
  { label: "Understand usage", ids: ["providers", "users", "spend", "accounts"] },
  { label: "Check coverage", ids: ["browser", "policies", "coverage", "connectors"] },
] as const;

type TabId = (typeof TABS)[number][0];

const statusClass: Record<string, string> = {
  CURRENT: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  VERIFIED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  OBSERVED: "border-cyan-400/30 bg-cyan-400/10 text-cyan-100",
  CONNECTED: "border-cyan-400/30 bg-cyan-400/10 text-cyan-100",
  HEALTHY: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  ATTESTED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  AUTHORITATIVE: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  PARTIAL: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  SELF_REPORTED: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  OBSERVED_ONLY: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  PARTIAL_EVIDENCE: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  DEGRADED: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  STALE: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  BLOCKED: "border-red-400/30 bg-red-400/10 text-red-100",
  REGRESSED: "border-red-400/30 bg-red-400/10 text-red-100",
  TAMPER_SUSPECTED: "border-red-400/30 bg-red-400/10 text-red-100",
  MISSING_SOURCE: "border-red-400/30 bg-red-400/10 text-red-100",
  DISCONNECTED: "border-slate-400/30 bg-slate-400/10 text-slate-200",
  NOT_COVERED: "border-slate-400/30 bg-slate-400/10 text-slate-200",
  NO_PROVIDER_API: "border-slate-400/30 bg-slate-400/10 text-slate-200",
  UNKNOWN: "border-slate-400/30 bg-slate-400/10 text-slate-200",
  UNSUPPORTED: "border-slate-400/30 bg-slate-400/10 text-slate-200",
};

function valueOf(value: unknown, fallback = "Unavailable") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function recordText(record: Record<string, unknown> | undefined, keys: string[], fallback = "Unavailable") {
  if (!record) return fallback;
  for (const key of keys) {
    const value = record[key];
    if (value !== null && value !== undefined && value !== "") return valueOf(value, fallback);
  }
  return fallback;
}

function numericValue(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function compactMetric(value: unknown, fallback = "Unavailable") {
  const numeric = numericValue(value);
  if (numeric === null) return valueOf(value, fallback);
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 2 }).format(numeric);
}

function moneyValue(currency: string, amount: unknown) {
  const numeric = numericValue(amount);
  if (numeric === null) return `${currency} ${valueOf(amount)}`;
  try {
    return new Intl.NumberFormat("en", {
      style: "currency",
      currency,
      maximumFractionDigits: numeric < 1 ? 4 : 2,
    }).format(numeric);
  } catch {
    return `${currency} ${numeric.toFixed(numeric < 1 ? 4 : 2)}`;
  }
}

function displayTime(value: unknown) {
  if (!value) return "Unavailable";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function humanizeLabel(value: unknown, fallback = "Unavailable") {
  return valueOf(value, fallback).replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function extensionStateValue(health: BrowserExtensionHealth | null): string {
  const raw = String(health?.status || "UNKNOWN").toUpperCase();
  if (raw !== "HEALTHY" && raw !== "CONNECTED" && raw !== "ATTESTED") return raw;
  const heartbeat = health?.latest_heartbeat_at ? Date.parse(health.latest_heartbeat_at) : Number.NaN;
  if (!Number.isFinite(heartbeat)) return "UNKNOWN";
  return Date.now() - heartbeat <= 15 * 60_000 ? raw : "STALE";
}

function StateBadge({ value }: { value: unknown }) {
  const state = valueOf(value, "UNKNOWN").toUpperCase();
  return (
    <Badge className={statusClass[state] || "border-white/10 bg-white/5 text-slate-200"}>
      {state.replaceAll("_", " ")}
    </Badge>
  );
}

function MetricCard({ label, value, hint }: { label: string; value: unknown; hint: string }) {
  return (
    <Card className="border-white/10 bg-[#101721]/85">
      <CardContent className="p-4">
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</p>
        <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-white">{valueOf(value, "—")}</p>
        <p className="mt-1 text-xs leading-5 text-slate-500">{hint}</p>
      </CardContent>
    </Card>
  );
}

function EmptyState({ children }: { children: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-white/15 bg-white/[0.02] p-8 text-center text-sm text-slate-400">
      {children}
    </div>
  );
}

function SourceReadinessPanel({ data }: { data: AIToolsUsageWorkspace }) {
  const readiness = data.authoritative_source_readiness;
  if (!readiness) return null;
  return (
    <Card className="border-cyan-300/15 bg-[#101721]/85">
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-white">
              <PlugZap className="h-5 w-5 text-cyan-300" />
              Authoritative source readiness
            </CardTitle>
            <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-400">
              This is the path to full authoritative control. Observed browser, endpoint, MCP and hook activity stays visible, but it does not become an enterprise denominator, billed spend, seat utilization or full control coverage until the required source connects.
            </p>
          </div>
          <StateBadge value={readiness.overall_status} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 lg:grid-cols-2">
          {readiness.items.map((item) => (
            <article key={item.label} className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="font-semibold text-white">{item.label}</h3>
                <StateBadge value={item.status} />
              </div>
              <p className="mt-2 text-sm leading-6 text-slate-400">{item.why_missing}</p>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Required source</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {item.required_sources.map((source) => (
                      <Badge key={source} className="border-cyan-300/20 bg-cyan-300/[0.08] text-cyan-100">
                        {source.replaceAll("_", " ")}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Observed evidence</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {item.observed_evidence.length ? item.observed_evidence.map((source) => (
                      <Badge key={source} className="border-amber-300/20 bg-amber-300/[0.08] text-amber-100">
                        {source.replaceAll("_", " ")}
                      </Badge>
                    )) : (
                      <Badge className="border-slate-400/20 bg-slate-400/[0.08] text-slate-200">none yet</Badge>
                    )}
                  </div>
                </div>
              </div>
              <p className="mt-3 rounded-xl border border-white/10 bg-black/15 p-3 text-xs leading-5 text-slate-300">
                <span className="font-semibold text-white">Next action:</span> {item.connect_action}
              </p>
            </article>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button asChild className="bg-orange-500 text-black hover:bg-orange-400">
            <Link href="/integrations">Connect sources</Link>
          </Button>
          <Button asChild variant="outline" className="border-white/10 bg-white/5 text-white">
            <Link href="/surface-coverage">Open control coverage</Link>
          </Button>
          <Button asChild variant="outline" className="border-white/10 bg-white/5 text-white">
            <Link href="/validate">Run validation</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function SourceProfilePanel({ data }: { data: AIToolsUsageWorkspace }) {
  const profiles = Object.values(data.provider_source_profiles || {});
  if (!profiles.length) return null;
  return (
    <Card className="border-orange-300/15 bg-[#111823]/85">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-white">
          <KeyRound className="h-5 w-5 text-orange-300" />
          Provider source profiles
        </CardTitle>
        <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-400">
          Provider usage paths are separate. Console/admin APIs, Enterprise analytics, local OTel/proxy estimates and consumer desktop chat do not produce the same spend truth.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {profiles.map((provider) => (
          <section key={provider.provider} className="rounded-2xl border border-white/10 bg-black/15 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-lg font-semibold capitalize text-white">{provider.provider}</h3>
                <p className="text-xs text-slate-500">{provider.source_contract || "provider source contract"}</p>
              </div>
              <StateBadge value={provider.overall_status} />
            </div>
            <div className="mt-4 grid gap-3 lg:grid-cols-2">
              {provider.profiles.map((profile) => (
                <article key={`${provider.provider}-${profile.profile}`} className="rounded-xl border border-white/10 bg-white/[0.025] p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="font-semibold text-white">{profile.profile.replaceAll("_", " ")}</h4>
                    <StateBadge value={profile.status} />
                  </div>
                  <div className="mt-3 grid gap-3 text-xs text-slate-300 md:grid-cols-2">
                    <div>
                      <p className="font-semibold uppercase tracking-[0.14em] text-slate-500">Credential</p>
                      <p className="mt-1 leading-5">{profile.required_credential}</p>
                    </div>
                    <div>
                      <p className="font-semibold uppercase tracking-[0.14em] text-slate-500">Cost provenance</p>
                      <p className="mt-1 leading-5">{profile.cost_label.replaceAll("_", " ")}</p>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {profile.source_types.length ? profile.source_types.map((source) => (
                      <Badge key={source} className="border-cyan-300/20 bg-cyan-300/[0.08] text-cyan-100">
                        {source.replaceAll("_", " ")}
                      </Badge>
                    )) : (
                      <Badge className="border-slate-400/20 bg-slate-400/[0.08] text-slate-200">no source connected</Badge>
                    )}
                  </div>
                  <ul className="mt-3 space-y-1 text-xs leading-5 text-slate-400">
                    {profile.notes.map((note) => (
                      <li key={note}>• {note}</li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
          </section>
        ))}
      </CardContent>
    </Card>
  );
}

export default function AIToolsUsagePage() {
  const [data, setData] = useState<AIToolsUsageWorkspace | null>(null);
  const [extensionHealth, setExtensionHealth] = useState<BrowserExtensionHealth | null>(null);
  const [extensionGovernance, setExtensionGovernance] = useState<BrowserExtensionRemovalGovernance | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [extensionError, setExtensionError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.allSettled([api.aiToolsUsage(), api.browserExtensionHealth(), api.browserExtensionRemovalGovernance()])
      .then(([toolsResult, extensionResult, governanceResult]) => {
        if (toolsResult.status === "fulfilled") {
          setData(toolsResult.value);
          setError(null);
        } else {
          setError(toolsResult.reason instanceof Error ? toolsResult.reason.message : "AI Tools & Usage could not be loaded.");
        }
        if (extensionResult.status === "fulfilled") {
          setExtensionHealth(extensionResult.value);
          setExtensionError(null);
        } else {
          setExtensionHealth(null);
          setExtensionError(extensionResult.reason instanceof Error ? extensionResult.reason.message : "Browser extension health could not be loaded.");
        }
        if (governanceResult.status === "fulfilled") {
          setExtensionGovernance(governanceResult.value);
        } else {
          setExtensionGovernance(null);
        }
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const spendTotals = useMemo(
    () => Object.entries(data?.spend_utilization.totals_by_currency || {}),
    [data],
  );
  const tokenTotals = useMemo(() => {
    const totals: Record<string, number> = {};
    for (const row of data?.usage || []) {
      if (String(row.unit).toLowerCase() !== "tokens") continue;
      const value = numericValue(row.value);
      if (value === null) continue;
      totals[row.metric] = (totals[row.metric] || 0) + value;
    }
    return totals;
  }, [data]);
  const tokenEvidenceRows = useMemo(
    () => (data?.usage || []).filter((row) => String(row.unit).toLowerCase() === "tokens"),
    [data],
  );
  const account = data?.governance.account_device || {};
  const observedAccountSummary = data?.accounts_devices?.summary;
  const observedAccountItems = data?.accounts_devices?.items || [];
  const meeting = data?.meeting_ai || {};
  const seats = data?.spend_utilization.seats;
  const providerNativeConnected = data?.providers.filter((provider) => String(provider.connection_state).toUpperCase() === "CONNECTED").length ?? 0;
  const providerSignalRecordCount = data?.window.provider_signal_record_count ?? data?.window.record_count ?? 0;
  const runtimeProjectionCount = data?.window.runtime_projection_count ?? data?.window.runtime_event_count ?? 0;
  const observedSignals = providerSignalRecordCount + (data?.prompts_actions.total ?? 0) + (data?.overview.providers_observed ?? 0);
  const estimatedSpendRows = (data?.spend_utilization.records || []).filter((row) =>
    ["CLIENT_ESTIMATE", "TRINYA_ESTIMATE", "CONTRACT_RATE_CARD", "CREDIT_CONSUMPTION"].includes(String(row.cost_type || "").toUpperCase()),
  );
  const authoritativeSpendRows = (data?.spend_utilization.records || []).filter((row) =>
    ["PROVIDER_BILLED", "PROVIDER_REPORTED"].includes(String(row.cost_type || "").toUpperCase()),
  );
  const normalizedMcpInventory = Number(data?.mcp_tools.summary.total_servers || 0);
  const observedMcpActivity = Math.max(
    normalizedMcpInventory,
    Number(data?.overview.mcp_servers || 0),
    Number(data?.mcp_tools.summary.used || 0),
    Number(data?.mcp_tools.summary.blocked || 0),
  );
  const denominatorRecord = data?.authoritative_source_readiness?.enterprise_denominator as Record<string, unknown> | undefined;
  const denominatorMethodology = recordText(denominatorRecord, ["methodology", "population", "definition", "scope"]);
  const unknownSpendRows = (data?.spend_utilization.records || []).filter((row) => (
    !authoritativeSpendRows.includes(row) && !estimatedSpendRows.includes(row)
  ));
  const costSource = authoritativeSpendRows.length && estimatedSpendRows.length
    ? "Mixed provider-reported/billed and estimated sources"
    : authoritativeSpendRows.length && unknownSpendRows.length
      ? "Mixed provider-reported/billed and unspecified sources"
      : estimatedSpendRows.length && unknownSpendRows.length
        ? "Mixed estimated and unspecified sources"
        : authoritativeSpendRows.length
          ? "Provider-reported or billed totals"
          : estimatedSpendRows.length
            ? "Client or rate-card estimate"
            : spendTotals.length || unknownSpendRows.length
              ? "Unknown cost source"
              : "Unavailable";
  const providerApiAvailability = Object.entries(data?.provider_source_profiles || {}).map(([providerKey, profile]) => {
    const record = profile as unknown as Record<string, unknown>;
    return {
      provider: recordText(record, ["provider"], providerKey),
      availability: recordText(record, ["api_availability", "provider_api_availability", "api_status", "provider_api_status"]),
    };
  });

  return (
    <AppShell>
      <main className="min-h-screen bg-[#090d13] text-slate-100">
        <header className="border-b border-white/10 bg-[radial-gradient(circle_at_top_right,rgba(251,146,60,0.12),transparent_34%),linear-gradient(135deg,#0c1118,#101827_60%,#080b10)] px-6 py-5 lg:px-8">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-orange-300">Activity</p>
              <h1 className="mt-2 text-3xl font-semibold tracking-[-0.04em] text-white">AI Tools &amp; Usage</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-300">
                Review AI activity, usage and coverage across connected sources. Open a view to inspect the evidence behind each observation.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={load} disabled={loading} className="border-white/10 bg-white/5 text-white">
                <RefreshCw className="mr-2 h-4 w-4" /> Refresh
              </Button>
              <Button onClick={() => setActiveTab("prompts")} className="bg-orange-500 text-black hover:bg-orange-400">Review prompts</Button>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-3 text-xs text-slate-400">
            <span>Period: rolling 30 days</span>
            <span>·</span>
            <span>Records: {valueOf(data?.window.record_count, "0")}</span>
            <span>·</span>
            <span>Freshness: {valueOf(data?.overview.freshness)}</span>
            <span>·</span>
            <span>Last signal: {valueOf(data?.window.last_signal_at)}</span>
          </div>
        </header>

        <section className="space-y-6 px-6 py-6 lg:px-8">
          <nav aria-label="AI Tools and Usage sections" aria-busy={loading} className="space-y-3 rounded-2xl border border-white/10 bg-[#101721]/80 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="text-sm font-semibold text-white">Activity views</h2>{loading && data ? <span role="status" className="text-xs text-amber-200">Updating · earlier evidence remains available</span> : null}</div>
            {ACTIVITY_VIEWS.map((group) => (
              <div key={group.label} className="flex flex-wrap items-center gap-2">
                <span className="w-32 shrink-0 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{group.label}</span>
                {group.ids.map((id) => {
                  const label = TABS.find(([tabId]) => tabId === id)?.[1] || id;
                  return <button key={id} type="button" onClick={() => setActiveTab(id)} aria-pressed={activeTab === id} className={`rounded-lg px-3 py-2 text-xs font-medium transition ${activeTab === id ? "bg-orange-400 text-slate-950" : "border border-white/10 bg-white/[0.03] text-slate-300 hover:text-white"}`}>{label}</button>;
                })}
              </div>
            ))}
          </nav>

          {loading && !data ? <EmptyState>Loading tenant-scoped provider evidence…</EmptyState> : null}
          {error ? (
            <div role="alert" className={`rounded-2xl border p-4 text-sm ${data ? "border-amber-400/30 bg-amber-500/10 text-amber-100" : "border-red-400/30 bg-red-500/10 text-red-100"}`}>
              {data ? `Latest AI Tools & Usage update is unavailable: ${error}. Showing the earlier source snapshot.` : `AI Tools & Usage is unavailable: ${error}`}
            </div>
          ) : null}
          <details className="rounded-2xl border border-white/10 bg-[#101721]/70 p-4 text-sm text-slate-300">
            <summary className="cursor-pointer font-medium text-white">Source and coverage details</summary>
            <div className="mt-4 space-y-3"><Button asChild variant="outline" className="border-white/10 bg-white/5 text-white"><Link href="/ai-ecosystem">Open AI Ecosystem</Link></Button></div>
          <EvidenceTruthPanel
            title="What this page can prove right now"
            description="This view separates observed client activity from provider-native verification, account classification, prompt/action metadata, token/spend provenance, and browser-extension health."
            whyUnknown="If a provider, model, token, spend, account type, upload, download, MCP server, or meeting bot is Unknown, the connected source has not supplied that exact field in the selected window. Connect the source or run a control test instead of assuming absence."
            lastEvidence={data?.window.last_signal_at || extensionHealth?.latest_heartbeat_at || null}
            connectHref="/integrations"
            testHref="/validate"
            sourceMode={observedSignals ? "observed" : "unknown"}
            facts={[
              {
                label: "Provider/model seen from browser",
                value: data?.overview.providers_observed ?? "Unavailable",
                detail: "Browser-observed use is visibility, not provider-native account verification.",
                tone: data?.overview.providers_observed ? "observed" : "unknown",
              },
              {
                label: "Provider-native verified",
                value: data?.providers.filter((provider) => String(provider.connection_state).toUpperCase() === "CONNECTED").length ?? "Unavailable",
                detail: "Requires provider or admin source evidence, not only a browser event.",
                tone: data?.providers.some((provider) => String(provider.connection_state).toUpperCase() === "CONNECTED") ? "verified" : "unknown",
              },
              {
                label: "Personal vs enterprise account",
                value: observedAccountSummary?.account_classes?.join(", ") || "Unavailable",
                detail: "Account class is shown only when source-backed account/device context exists.",
                tone: observedAccountSummary?.account_classes?.length ? "observed" : "unknown",
              },
              {
                label: "Token/spend provenance",
                value: tokenEvidenceRows.length || spendTotals.length ? "Evidence available" : "Unavailable",
                detail: "Billed, provider-reported, rate-card, client-estimated and unavailable states stay separate.",
                tone: tokenEvidenceRows.length || spendTotals.length ? "estimated" : "unknown",
              },
            ]}
          />
          </details>

          {data && activeTab === "overview" ? (
            <>
              <div aria-label="Activity overview metrics" className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <MetricCard label="Providers observed" value={data.overview.providers_observed} hint="At least one tenant-scoped signal; not automatic verification" />
                <MetricCard label="Active AI users" value={data.overview.active_users} hint="Resolved identities in the selected period" />
                <MetricCard label="AI clients" value={data.overview.clients} hint="Desktop, CLI, IDE, web or runtime clients with evidence" />
                <MetricCard label="MCP servers" value={data.mcp_tools.summary.total_servers} hint="Normalized server identities in this evidence window" />
                <MetricCard label="Prompts observed" value={data.prompts_actions.total} hint="Metadata or redacted evidence; raw prompt storage is off" />
                <MetricCard label="Coverage gaps" value={data.coverage_gaps.gaps.length} hint="Unknown and stale paths remain visible" />
              </div>
              <details className="rounded-2xl border border-white/10 bg-[#101721]/70 p-4">
                <summary className="cursor-pointer text-sm font-medium text-white">Source diagnostics: billing, client projections, browser health and leadership detail</summary>
                <div className="mt-4 space-y-4">
                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                    <MetricCard label="Runtime/client projections" value={runtimeProjectionCount || "Unavailable"} hint="Observed-but-not-canonical evidence from browser, hook, MCP or runtime signals" />
                    <MetricCard label="Tokens reported" value={tokenTotals.total_tokens ? compactMetric(tokenTotals.total_tokens) : "Unavailable"} hint="Provider-reported when available; client-estimated token rows stay labelled" />
                    <MetricCard label="Spend evidence" value={spendTotals.length ? spendTotals.map(([currency, amount]) => moneyValue(currency, amount)).join(" · ") : (estimatedSpendRows.length ? "Client estimate available" : "Unavailable")} hint="Billed, reported or explicitly estimated cost only" />
                    <MetricCard label="Provider-native billing" value={authoritativeSpendRows.length ? "Connected" : "Not connected"} hint="Connect provider-admin source for billed spend and seat utilization" />
                    <MetricCard label="Sensitive downloads blocked" value={account.blocked_sensitive_downloads} hint="Recorded block decisions only" />
                    <MetricCard label="Meeting bots detected" value={meeting.detected} hint="Identity-backed observations only" />
                    <MetricCard label="Browser extension" value={extensionHealth?.status ? extensionHealth.status.replaceAll("_", " ") : "Unavailable"} hint="Latest tenant-scoped heartbeat state" />
                    <MetricCard label="Extension heartbeat" value={displayTime(extensionHealth?.latest_heartbeat_at)} hint="Last status signal received from the extension" />
                  </div>
                  <Card className="border-white/10 bg-[#101721]/85">
                <CardHeader>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <CardTitle className="flex items-center gap-2 text-white"><ShieldCheck className="h-5 w-5 text-cyan-300" /> Managed browser extension</CardTitle>
                    <StateBadge value={extensionStateValue(extensionHealth)} />
                  </div>
                </CardHeader>
                <CardContent className="grid gap-3 lg:grid-cols-4">
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Trusted extension ID</p><p className="mt-2 break-all text-sm text-slate-200">{valueOf(extensionHealth?.trusted_extension_id, "Unavailable")}</p></div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Last heartbeat</p><p className="mt-2 text-sm text-slate-200">{displayTime(extensionHealth?.latest_heartbeat_at)}</p></div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Duplicate extension IDs</p><p className="mt-2 text-sm text-slate-200">{extensionHealth?.duplicate_extension_ids?.length ? `${extensionHealth.duplicate_extension_ids.length} observed` : "None observed"}</p></div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Removal / tamper</p><p className="mt-2 text-sm text-slate-200">{extensionHealth?.tamper_events?.length ? `${extensionHealth.tamper_events.length} recent event(s)` : "No recent event"}</p></div>
                  {extensionError ? <p className="lg:col-span-4 rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-xs text-amber-100">{extensionError}</p> : null}
                  <p className="lg:col-span-4 rounded-xl border border-white/10 bg-white/[0.025] p-3 text-xs leading-5 text-slate-400">
                    Extension removal prevention requires managed browser policy or MDM. The platform records disable/removal attempts, admin authorizations and tamper signals; it does not claim that an extension can prevent its own uninstall.
                  </p>
                </CardContent>
                  </Card>
                  <Card className="border-white/10 bg-[#101721]/85">
                <CardHeader><CardTitle className="flex items-center gap-2 text-white"><Gauge className="h-5 w-5 text-cyan-300" /> Leadership view</CardTitle></CardHeader>
                <CardContent className="grid gap-3 lg:grid-cols-5">
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Usage evidence</p><p className="mt-2 text-sm text-slate-300">{data.usage.length ? `${data.usage.length} normalized metric series · ${tokenEvidenceRows.length} token series` : "Unavailable from connected sources"}</p></div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Cost source</p><p className="mt-2 text-sm text-slate-300">{costSource}</p><p className="mt-1 text-xs text-slate-500">{spendTotals.length ? spendTotals.map(([currency, amount]) => moneyValue(currency, amount)).join(" · ") : "No source-backed total"}</p></div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Coverage population</p><p className="mt-2 text-sm text-slate-300">{denominatorMethodology}</p><p className="mt-1 text-xs text-slate-500">Source coverage: {data.overview.source_coverage.join(", ") || "Unavailable"}</p></div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Connector access</p><p className="mt-2 text-sm text-slate-300">{providerNativeConnected ? `${providerNativeConnected} provider connector(s) available` : "Unavailable"}</p><p className="mt-1 text-xs text-slate-500">Admin/provider access is required for authoritative billing and seats.</p></div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-xs uppercase tracking-wider text-slate-500">Adapter implementation</p><p className="mt-2 text-sm text-slate-300">Green status requires source-backed health and implementation evidence.</p></div>
                </CardContent>
                <div className="border-t border-white/10 px-6 py-4"><details><summary className="cursor-pointer text-xs font-medium text-slate-300">Raw source diagnostics</summary><div className="mt-3 space-y-2 text-xs leading-5 text-slate-500"><p>Cost precedence enum: {data.spend_utilization.cost_precedence.join(" → ") || "Unavailable"}</p><p>Denominator methodology: {denominatorMethodology}</p><p>Provider API availability strings:</p><pre className="overflow-x-auto rounded-xl border border-white/10 bg-black/20 p-3 text-slate-400">{providerApiAvailability.length ? JSON.stringify(providerApiAvailability, null, 2) : "Unavailable"}</pre></div></details></div>
                  </Card>
                </div>
              </details>
            </>
          ) : null}

          {data && activeTab === "providers" ? (
            <div className="space-y-4">
              <Card className="border-cyan-300/15 bg-cyan-300/[0.045]">
                <CardHeader><CardTitle className="text-white">Observed provider activity vs provider-native connector</CardTitle></CardHeader>
                <CardContent className="grid gap-3 md:grid-cols-5">
                  <MetricCard label="Observed provider activity" value={data.overview.providers_observed || observedSignals ? data.overview.providers_observed : "No observed provider signal"} hint="Browser, MCP, hook, runtime or client telemetry in this tenant window" />
                  <MetricCard label="Provider-native connector" value={providerNativeConnected} hint="Admin/provider API verification; disconnected does not erase observed browser or MCP evidence" />
                  <MetricCard label="Observed-but-not-canonical" value={runtimeProjectionCount || providerSignalRecordCount || "Unavailable"} hint="Visible as evidence, but not counted as authoritative provider/admin truth" />
                  <MetricCard label="Observed sources" value={data.overview.source_coverage.join(", ") || "Unavailable"} hint="Where the signal came from, not a compliance claim" />
                  <MetricCard label="Last evidence received" value={displayTime(data.window.last_signal_at)} hint="Freshness is shown instead of assuming current state" />
                </CardContent>
              </Card>
              <div className="grid gap-4 xl:grid-cols-2">
                {data.providers.map((provider) => (
                  <Card key={provider.provider} className="border-white/10 bg-[#101721]/85">
                    <CardHeader><div className="flex items-center justify-between"><CardTitle className="capitalize text-white">{provider.provider}</CardTitle><StateBadge value={provider.source_types.length ? "OBSERVED" : provider.connection_state} /></div></CardHeader>
                    <CardContent className="space-y-3 text-sm">
                      <div className="flex justify-between gap-3"><span className="text-slate-500">Products</span><span className="text-right text-slate-200">{provider.products.join(", ") || "Unavailable"}</span></div>
                      <div className="flex justify-between gap-3"><span className="text-slate-500">Signal sources</span><span className="text-right text-slate-200">{provider.source_types.join(", ") || "Unavailable"}</span></div>
                      <div className="flex justify-between gap-3"><span className="text-slate-500">Freshness</span><StateBadge value={provider.freshness} /></div>
                      <div className="flex justify-between gap-3"><span className="text-slate-500">Last event</span><span className="text-right text-slate-300">{valueOf(provider.last_event_at)}</span></div>
                      <p className="rounded-xl border border-white/10 bg-white/[0.025] p-3 text-xs leading-5 text-slate-400">
                        {provider.source_types.length
                          ? "Observed activity exists for this provider. Connect the provider/admin source to verify account ownership, billed spend, seat utilization and provider-native controls."
                          : provider.capability_note}
                      </p>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          ) : null}

          {data && activeTab === "users" ? (
            <Card className="border-white/10 bg-[#101721]/85">
              <CardHeader><CardTitle className="flex items-center gap-2 text-white"><Users className="h-5 w-5 text-cyan-300" /> Users &amp; Departments</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 md:grid-cols-3"><MetricCard label="Users" value={data.overview.active_users} hint="Resolved source identities" /><MetricCard label="Departments" value={data.overview.departments} hint="Source-backed department mappings" /><MetricCard label="Clients" value={data.overview.clients} hint="Observed AI clients" /></div>
                <Button asChild variant="outline" className="border-white/10 bg-white/5 text-white"><Link href="/users">Open User 360 directory</Link></Button>
              </CardContent>
            </Card>
          ) : null}

          {data && activeTab === "prompts" ? (
            <Card className="border-white/10 bg-[#101721]/85">
              <CardHeader><CardTitle className="flex items-center gap-2 text-white"><Activity className="h-5 w-5 text-violet-300" /> Prompts &amp; Actions</CardTitle></CardHeader>
              <CardContent>
                {data.prompts_actions.aggregate_only ? <p className="mb-4 rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-sm text-cyan-100">Your role receives aggregate prompt metadata. Individual details require an authorized security or audit role.</p> : null}
                {data.prompts_actions.items.length ? <div className="space-y-2">{data.prompts_actions.items.map((item, index) => <div key={String(item.id || index)} className="rounded-xl border border-white/10 bg-white/[0.025] p-4 text-sm"><div className="flex flex-wrap items-center justify-between gap-2"><span className="text-white">{valueOf(item.category, "Unclassified request")}</span><StateBadge value={item.policy_decision} /></div><p className="mt-2 text-slate-400">{valueOf(item.redacted_preview, "Prompt content is unavailable from this source.")}</p><p className="mt-2 text-xs text-slate-500">{valueOf(item.provider)} · {valueOf(item.client)} · {valueOf(item.content_level)}</p><details className="mt-3 text-xs text-slate-500"><summary className="cursor-pointer">Technical details</summary><div className="mt-2 space-y-1 font-mono"><p>prompt_id: {valueOf(item.prompt_id)}</p><p>tool_use_id: {valueOf(item.tool_use_id)}</p><p>OTel trace: {valueOf(item.otel_trace_id || item.trace_id)}</p></div></details></div>)}</div> : <EmptyState>No prompt or request metadata is available from the connected sources during this period.</EmptyState>}
              </CardContent>
            </Card>
          ) : null}

          {data && activeTab === "mcp" ? (
            <Card className="border-white/10 bg-[#101721]/85">
              <CardHeader><CardTitle className="flex items-center gap-2 text-white"><Network className="h-5 w-5 text-cyan-300" /> MCP &amp; Tools</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 md:grid-cols-3">
                  <MetricCard label="Observed MCP activity" value={observedMcpActivity} hint="Governed MCP/tool calls or server evidence seen in this tenant window" />
                  <MetricCard label="Normalized MCP inventory" value={normalizedMcpInventory} hint="Reconciled server identities; may lag behind observed calls" />
                  <MetricCard label="Why this can differ" value={observedMcpActivity > normalizedMcpInventory ? "Activity before inventory" : "Inventory current"} hint="A governed call remains visible even before source inventory is fully normalized" />
                </div>
                <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">{Object.entries(data.mcp_tools.summary).map(([label, value]) => <MetricCard key={label} label={label.replaceAll("_", " ")} value={value} hint="Current normalized inventory state" />)}</div>
                {data.mcp_tools.servers.length ? <div className="overflow-x-auto"><table className="w-full min-w-[1020px] text-left text-sm"><thead className="text-[10px] uppercase tracking-wider text-slate-500"><tr>{["MCP server", "Client", "Scope", "Connection", "Tool", "Used", "Trust", "Drift", "Evidence", "Technical details"].map((heading) => <th key={heading} className="px-3 py-2">{heading}</th>)}</tr></thead><tbody>{data.mcp_tools.servers.map((row, index) => <tr key={String(row.id || index)} className="border-t border-white/5"><td className="px-3 py-3 text-white">{valueOf(row.server_identity)}</td><td className="px-3 py-3 text-slate-300">{Array.isArray(row.connected_clients) ? row.connected_clients.join(", ") : "Unavailable"}</td><td className="px-3 py-3 text-slate-400">{valueOf(row.configuration_scope)}</td><td className="px-3 py-3"><StateBadge value={row.connection_state} /></td><td className="px-3 py-3 text-slate-300">{valueOf(row.tool_name)}</td><td className="px-3 py-3 text-slate-300">{valueOf(row.invocation_count, "0")}</td><td className="px-3 py-3"><StateBadge value={row.trust_state} /></td><td className="px-3 py-3"><StateBadge value={row.drift_state} /></td><td className="px-3 py-3 text-slate-400">{valueOf(row.evidence_quality)}</td><td className="px-3 py-3 text-xs text-slate-500"><details><summary className="cursor-pointer">Details</summary><div className="mt-1 space-y-1 font-mono"><p>tool_use_id: {valueOf(row.tool_use_id)}</p><p>OTel trace: {valueOf(row.otel_trace_id || row.trace_id)}</p></div></details></td></tr>)}</tbody></table></div> : <EmptyState>{observedMcpActivity ? `${observedMcpActivity} MCP/tool activity signal(s) exist, but normalized server inventory has not completed yet. Open Live Sessions for the raw decision trail or rerun MCP inventory projection.` : "No MCP configuration, connection or invocation evidence is available in this period."}</EmptyState>}
                <div className="rounded-2xl border border-white/10 bg-[linear-gradient(90deg,rgba(34,211,238,0.08),rgba(139,92,246,0.08))] p-4 text-sm text-slate-300"><span className="text-white">Relationship:</span> User → Device → Claude / Codex / Cursor → MCP Server → Tool → Resource / Destination. Expansion uses bounded tenant queries.</div>
              </CardContent>
            </Card>
          ) : null}

          {data && activeTab === "spend" ? (
            <Card className="border-white/10 bg-[#101721]/85">
              <CardHeader><CardTitle className="flex items-center gap-2 text-white"><Coins className="h-5 w-5 text-amber-300" /> Spend &amp; Utilization</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded-2xl border border-amber-300/15 bg-amber-300/[0.045] p-4 text-sm leading-6 text-amber-50/90">
                  <span className="font-semibold text-amber-100">Token and spend provenance:</span> provider billed → provider reported → contract rate-card → credit consumption → client-estimated usage → unavailable. Client-estimated usage is shown when present, but it is never treated as billing truth.
                  <span className="mt-2 block">Provider-billed spend and provider-admin seat utilization require a connected provider/admin source; browser, MCP and client events remain observed usage evidence only.</span>
                </div>
                <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">{spendTotals.length ? spendTotals.map(([currency, amount]) => <MetricCard key={currency} label={`Total spend · ${currency}`} value={moneyValue(currency, amount)} hint="Chosen source after cost precedence and deduplication" />) : <MetricCard label="Total spend" value="Unavailable" hint="No billed, reported, rate-card or estimated cost source is connected" />}<MetricCard label="Input tokens" value={tokenTotals.input_tokens ? compactMetric(tokenTotals.input_tokens) : "Unavailable" } hint="Reported by provider, hook or runtime control" /><MetricCard label="Output tokens" value={tokenTotals.output_tokens ? compactMetric(tokenTotals.output_tokens) : "Unavailable" } hint="Reported by provider, hook or runtime control" /><MetricCard label="Total tokens" value={tokenTotals.total_tokens ? compactMetric(tokenTotals.total_tokens) : "Unavailable" } hint="Not estimated from prompt text" /><MetricCard label="Usage series" value={data.usage.length} hint="Metrics are kept in their original unit" /><MetricCard label="Productivity score" value="Not generated" hint="Prompt counts are not employee performance evidence" /></div>
                {tokenEvidenceRows.length || data.spend_utilization.records.length ? (
                  <div className="grid gap-4 xl:grid-cols-2">
                    <section aria-label="Token usage evidence" className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
                      <div className="mb-3 flex items-center justify-between gap-2"><div><p className="text-sm font-medium text-white">Token usage evidence</p><p className="mt-1 text-xs text-slate-500">Shown only when a provider, hook or runtime control reports token counts.</p></div><StateBadge value={tokenEvidenceRows.length ? "OBSERVED" : "UNAVAILABLE"} /></div>
                      {tokenEvidenceRows.length ? <div className="overflow-x-auto"><table className="w-full min-w-[560px] text-left text-sm"><thead className="text-[10px] uppercase tracking-wider text-slate-500"><tr>{["Provider", "Metric", "Value", "Unit"].map((heading) => <th key={heading} className="px-3 py-2">{heading}</th>)}</tr></thead><tbody>{tokenEvidenceRows.map((row, index) => <tr key={`${row.provider}-${row.metric}-${index}`} className="border-t border-white/5"><td className="px-3 py-3 text-white">{row.provider}</td><td className="px-3 py-3 text-slate-300">{row.metric.replaceAll("_", " ")}</td><td className="px-3 py-3 text-slate-300">{compactMetric(row.value)}</td><td className="px-3 py-3 text-slate-400">{row.unit}</td></tr>)}</tbody></table></div> : <EmptyState>No token evidence was reported in the selected period.</EmptyState>}
                    </section>
                    <section aria-label="Spend evidence" className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
                      <div className="mb-3 flex items-center justify-between gap-2"><div><p className="text-sm font-medium text-white">Spend evidence</p><p className="mt-1 text-xs text-slate-500">Billed costs win over reported costs, rate cards and client estimates.</p></div><StateBadge value={data.spend_utilization.records.length ? "OBSERVED" : "UNAVAILABLE"} /></div>
                      {data.spend_utilization.records.length ? <div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead className="text-[10px] uppercase tracking-wider text-slate-500"><tr>{["Provider", "Cost type", "Amount", "Currency", "Method"].map((heading) => <th key={heading} className="px-3 py-2">{heading}</th>)}</tr></thead><tbody>{data.spend_utilization.records.map((row, index) => <tr key={String(row.id || index)} className="border-t border-white/5"><td className="px-3 py-3 text-white">{valueOf(row.provider)}</td><td className="px-3 py-3"><StateBadge value={row.cost_type} /></td><td className="px-3 py-3 text-slate-300">{valueOf(row.amount)}</td><td className="px-3 py-3 text-slate-400">{valueOf(row.currency)}</td><td className="px-3 py-3 text-slate-400">{valueOf(row.allocation_method)}</td></tr>)}</tbody></table></div> : <EmptyState>No spend evidence was reported in the selected period.</EmptyState>}
                    </section>
                  </div>
                ) : (
                  <EmptyState>No token or spend evidence was reported by the connected provider, hook, gateway or runtime sources during this period.</EmptyState>
                )}
                <section aria-label="Authoritative provider seat utilization" className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-2"><div><p className="text-sm font-medium text-white">Provider seat utilization</p><p className="mt-1 text-xs text-slate-500">Aggregate provider-admin snapshots only. Individual seat assignment and employee productivity are not reported.</p></div><StateBadge value={seats?.authoritative_snapshot_count ? "CONFIRMED" : "UNAVAILABLE"} /></div>
                  {seats?.authoritative_snapshot_count ? <><div className="grid gap-3 md:grid-cols-4 xl:grid-cols-7"><MetricCard label="Licensed seats" value={seats.total_licensed_seats} hint="Provider-admin licensed population" /><MetricCard label="Assigned seats" value={seats.assigned_seats} hint="Latest snapshot per provider and billing scope" /><MetricCard label="Unassigned seats" value={seats.unassigned_seats} hint="Licensed seats without a reported assignment" /><MetricCard label="Active seats" value={seats.active_seats} hint="Provider-admin aggregate" /><MetricCard label="Inactive seats" value={seats.inactive_seats} hint="Assigned but reported inactive" /><MetricCard label="Never used" value={seats.never_used_seats} hint="Assigned seats with no reported activity" /><MetricCard label="Unknown activity" value={seats.unknown_activity_seats} hint="Assigned seats with activity not classified by the source" /></div><div className="mt-4 overflow-x-auto"><table className="w-full min-w-[980px] text-left text-sm"><thead className="text-[10px] uppercase tracking-wider text-slate-500"><tr>{["Provider", "Product", "Billing scope", "Licensed", "Assigned", "Active", "Never used", "Unknown activity", "Completeness", "Freshness", "Evidence"].map((heading) => <th key={heading} className="px-3 py-2">{heading}</th>)}</tr></thead><tbody>{seats.snapshots.map((snapshot) => <tr key={snapshot.id} className="border-t border-white/5"><td className="px-3 py-3 text-white">{snapshot.provider}</td><td className="px-3 py-3 text-slate-300">{snapshot.product}</td><td className="px-3 py-3 text-slate-400">{valueOf(snapshot.billing_group, "Unspecified")}</td><td className="px-3 py-3 text-slate-300">{snapshot.total_licensed_seats}</td><td className="px-3 py-3 text-slate-300">{snapshot.assigned_seats}</td><td className="px-3 py-3 text-slate-300">{snapshot.active_seats}</td><td className="px-3 py-3 text-slate-300">{snapshot.never_used_seats}</td><td className="px-3 py-3 text-slate-300">{snapshot.unknown_activity_seats}</td><td className="px-3 py-3"><StateBadge value={snapshot.completeness} /></td><td className="px-3 py-3"><StateBadge value={snapshot.freshness} /></td><td className="px-3 py-3"><StateBadge value={snapshot.evidence_quality} /></td></tr>)}</tbody></table></div></> : <EmptyState>Seat utilization is unavailable until a provider-admin aggregate seat snapshot is connected. Provider analytics, client telemetry and estimates are not treated as seat authority.</EmptyState>}
                </section>
                <details className="rounded-xl border border-white/10 bg-white/[0.02] p-3 text-xs text-slate-500"><summary className="cursor-pointer font-medium text-slate-300">Technical cost diagnostics</summary><div className="mt-2 space-y-1"><p>Raw cost precedence order: {data.spend_utilization.cost_precedence.join(" → ") || "Unavailable"}</p><p>Billed and estimated records are not added together.</p></div></details>
              </CardContent>
            </Card>
          ) : null}

          {data && activeTab === "accounts" ? (
            <Card className="border-white/10 bg-[#101721]/85">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-white"><KeyRound className="h-5 w-5 text-cyan-300" /> Accounts &amp; Devices</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                  <MetricCard label="Observed client sessions" value={observedAccountSummary?.observed_sessions ?? "Unavailable"} hint={`Source: ${valueOf(data.accounts_devices?.source, "runtime and browser metadata")}`} />
                  <MetricCard label="Account classes" value={observedAccountSummary?.account_classes?.join(", ") || "Unavailable"} hint="Enterprise, personal, external or unknown where observed" />
                  <MetricCard label="Device assurance" value={observedAccountSummary?.device_assurance?.join(", ") || "Unavailable"} hint="Managed/BYOD/unmanaged/unknown from connected evidence" />
                  <MetricCard label="Clients" value={observedAccountSummary?.clients?.join(", ") || "Unavailable"} hint="Observed AI clients tied to account/device context" />
                  <MetricCard label="Managed compliant" value={account.managed_compliant_devices} hint="Account-boundary control state" />
                  <MetricCard label="Registered BYOD" value={account.registered_byod_devices} hint="Restricted mode where supported" />
                  <MetricCard label="Corporate session denials" value={account.corporate_session_denials} hint="Recorded account-boundary decisions" />
                  <MetricCard label="Blocked sensitive downloads" value={account.blocked_sensitive_downloads} hint="Inline recorded blocks only" />
                </div>
                {observedAccountItems.length ? (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[760px] text-left text-sm">
                      <thead className="text-[10px] uppercase tracking-wider text-slate-500">
                        <tr>{["Provider", "Client", "Account class", "Device assurance", "Surface", "Last event"].map((heading) => <th key={heading} className="px-3 py-2">{heading}</th>)}</tr>
                      </thead>
                      <tbody>
                        {observedAccountItems.slice(0, 25).map((row, index) => (
                          <tr key={`${row.provider || "provider"}-${row.client || "client"}-${index}`} className="border-t border-white/5">
                            <td className="px-3 py-3 text-white">{valueOf(row.provider)}</td>
                            <td className="px-3 py-3 text-slate-300">{valueOf(row.client)}</td>
                            <td className="px-3 py-3"><StateBadge value={row.account_type} /></td>
                            <td className="px-3 py-3"><StateBadge value={row.device_assurance} /></td>
                            <td className="px-3 py-3 text-slate-300">{valueOf(row.surface)}</td>
                            <td className="px-3 py-3 text-slate-400">{displayTime(row.last_event_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <EmptyState>No account or device session evidence was projected for this period.</EmptyState>
                )}
              </CardContent>
            </Card>
          ) : null}

          {data && activeTab === "data" ? (
            <Card className="border-white/10 bg-[#101721]/85">
              <CardHeader><CardTitle className="flex items-center gap-2 text-white"><DatabaseZap className="h-5 w-5 text-orange-300" /> Data, Uploads &amp; Downloads</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 md:grid-cols-4">
                  <MetricCard label="Classified prompt events" value={data.data_controls.classified_prompt_events ?? 0} hint="Count of prompt/request metadata events with source-backed classifications" />
                  <MetricCard label="Upload events" value={data.data_controls.upload_events ?? 0} hint="Source-backed upload decisions or observations" />
                  <MetricCard label="Download events" value={data.data_controls.download_events ?? 0} hint="Source-backed download decisions or observations" />
                  <MetricCard label="Raw values exposed" value={data.data_controls.raw_values_exposed ? "Yes" : "No"} hint="Sensitive raw values stay out of this view by default" />
                </div>
                <div className="flex flex-wrap gap-2">{Array.isArray(data.data_controls.classifications) && data.data_controls.classifications.length ? data.data_controls.classifications.map((item) => <StateBadge key={String(item)} value={item} />) : <span className="text-sm text-slate-400">No source-backed data classifications are available in this period.</span>}</div>
                <p className="rounded-xl border border-white/10 bg-white/[0.025] p-3 text-sm text-slate-400">Sensitive values are not shown in this view. Upload and download decisions remain bound to user, device, account, provider, purpose, destination and control capability.</p>
              </CardContent>
            </Card>
          ) : null}

          {activeTab === "browser" ? (
            <Card className="border-white/10 bg-[#101721]/85">
              <CardHeader>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <CardTitle className="flex items-center gap-2 text-white"><ShieldCheck className="h-5 w-5 text-cyan-300" /> Browser Extension Health</CardTitle>
                  <StateBadge value={extensionStateValue(extensionHealth)} />
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {extensionError ? (
                  <div role="alert" className="rounded-2xl border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-100">
                    Browser extension health could not be loaded. Prompt and action controls remain unchanged. {extensionError}
                  </div>
                ) : null}
                <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                  <MetricCard label="Trusted extension" value={extensionHealth?.trusted_extension_id ? "Configured" : "Unavailable"} hint={`Source: ${humanizeLabel(extensionHealth?.trusted_source, "Unknown source")}. Exact identifier is in Technical details.`} />
                  <MetricCard label="Last heartbeat" value={displayTime(extensionHealth?.latest_heartbeat_at)} hint="Latest status signal written by the extension" />
                  <MetricCard label="Loaded instances" value={extensionHealth?.instances.length ?? 0} hint="Latest instance state grouped by browser/profile/device" />
                  <MetricCard label="Tamper/removal events" value={extensionHealth?.tamper_events.length ?? 0} hint="Unauthorized and admin-authorized disable/removal signals" />
                </div>
                <section className="rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-cyan-100">Extension removal governance</p>
                      <p className="mt-1 text-xs leading-5 text-cyan-100/80">
                        Admin approval is required for disable/removal. Hard prevention requires managed browser policy or MDM; the extension cannot prevent its own uninstall.
                      </p>
                    </div>
                    <StateBadge value={extensionGovernance?.status || "UNKNOWN"} />
                  </div>
                  <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                    {(extensionGovernance?.controls || []).map((control) => (
                      <div key={control.id} className="rounded-xl border border-white/10 bg-slate-950/35 p-3">
                        <div className="flex items-center justify-between gap-2"><p className="text-sm font-medium text-white">{control.label}</p><StateBadge value={control.status} /></div>
                        <p className="mt-2 text-xs leading-5 text-slate-400">{control.description}</p>
                        <p className="mt-2 text-[10px] uppercase tracking-wider text-slate-500">Owner: {control.required_owner.replaceAll("_", " ")}</p>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 grid gap-3 lg:grid-cols-2">
                    <p className="sr-only">Chrome MDM policy and Safari MDM policy statuses are listed below.</p>
                    {(extensionGovernance?.mdm_policies || []).map((policy) => (
                      <div key={policy.browser} className="rounded-xl border border-white/10 bg-slate-950/35 p-4">
                        <div className="flex items-center justify-between gap-2"><p className="capitalize text-sm font-semibold text-white">{policy.browser} MDM policy</p><StateBadge value={policy.status} /></div>
                        <p className="mt-2 text-xs leading-5 text-slate-400">{policy.required_policy} · {policy.purpose}</p>
                        <p className="mt-2 text-xs text-slate-500">Trusted extension: {policy.trusted_extension_id ? "Configured" : "Unavailable"}. Exact identifier is in Technical details.</p>
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 grid gap-3 lg:grid-cols-2">
                    <div className="rounded-xl border border-white/10 bg-slate-950/35 p-4">
                      <p className="text-sm font-semibold text-white">Admin workflow</p>
                      <ol className="mt-3 list-decimal space-y-2 pl-5 text-xs leading-5 text-slate-400">
                        {(extensionGovernance?.admin_workflow || ["Load extension governance to see the admin workflow."]).map((step) => <li key={step}>{step}</li>)}
                      </ol>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-slate-950/35 p-4">
                      <p className="text-sm font-semibold text-white">Audit events</p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {(extensionGovernance?.audit_events || ["extension governance unavailable"]).map((event) => <Badge key={event} className="border-white/10 bg-white/5 text-slate-200">{event}</Badge>)}
                      </div>
                    </div>
                  </div>
                </section>
                {extensionHealth?.duplicate_extension_ids.length ? <p className="rounded-2xl border border-amber-400/20 bg-amber-400/10 p-4 text-sm text-amber-100">Duplicate extension identifiers observed: {extensionHealth.duplicate_extension_ids.length}. Exact identifiers are in Technical details.</p> : null}
                {extensionHealth?.instances.length ? (
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[980px] text-left text-sm">
                      <thead className="text-[10px] uppercase tracking-wider text-slate-500">
                        <tr>{["Instance", "Status", "Heartbeat", "Browser", "Profile", "Endpoint status", "Queue", "Policy status", "Last error", "Technical details"].map((heading) => <th key={heading} className="px-3 py-2">{heading}</th>)}</tr>
                      </thead>
                      <tbody>
                        {extensionHealth.instances.map((row, index) => (
                          <tr key={`${row.extension_id || "extension"}-${index}`} className="border-t border-white/5">
                            <td className="px-3 py-3 text-white">Instance {index + 1}</td>
                            <td className="px-3 py-3"><StateBadge value={row.status || (row.healthy ? "healthy" : "unknown")} /></td>
                            <td className="px-3 py-3 text-slate-300">{displayTime(row.last_heartbeat_at)}</td>
                            <td className="px-3 py-3 text-slate-300">{valueOf(row.browser)}</td>
                            <td className="px-3 py-3 text-slate-300">{valueOf(row.browser_profile)}</td>
                            <td className="px-3 py-3 text-slate-400">{row.endpoint_id || row.hostname ? "Observed" : "Unavailable"}</td>
                            <td className="px-3 py-3 text-slate-300">{valueOf(row.telemetry_queue_depth, "0")}</td>
                            <td className="px-3 py-3 text-slate-400">{row.policy_version ? "Configured" : "Unavailable"}</td>
                            <td className="px-3 py-3 text-slate-400">{valueOf(row.last_error, "—")}</td>
                            <td className="px-3 py-3 text-xs text-slate-500"><details><summary className="cursor-pointer">Details</summary><div className="mt-1 space-y-1 font-mono"><p>Extension ID: {valueOf(row.extension_id)}</p><p>Endpoint ID: {valueOf(row.endpoint_id || row.hostname)}</p><p>Policy version: {valueOf(row.policy_version)}</p></div></details></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : <EmptyState>No extension heartbeat has been received for this tenant in the recent evidence window.</EmptyState>}
                {extensionHealth?.tamper_events.length ? (
                  <section className="space-y-2">
                    <p className="text-sm font-semibold text-white">Removal and tamper evidence</p>
                    {extensionHealth.tamper_events.map((event, index) => (
                      <div key={`${event.observed_at || "tamper"}-${index}`} className="rounded-xl border border-red-400/20 bg-red-500/10 p-4 text-sm">
                        <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-red-100">{event.classification.replaceAll("_", " ")}</span><StateBadge value={event.control_state || event.severity} /></div>
                        <p className="mt-2 text-xs text-slate-400">{humanizeLabel(event.action, "Extension change")} · {humanizeLabel(event.browser, "Browser unavailable")} · {displayTime(event.observed_at)}</p>
                        <details className="mt-2 text-xs text-slate-500"><summary className="cursor-pointer">Technical details</summary><div className="mt-1 space-y-1 font-mono"><p>Extension ID: {valueOf(event.extension_id)}</p><p>Endpoint ID: {valueOf(event.endpoint_id || event.hostname)}</p><p>Browser profile: {valueOf(event.browser_profile)}</p></div></details>
                      </div>
                    ))}
                  </section>
                ) : null}
                <p className="rounded-xl border border-white/10 bg-white/[0.025] p-3 text-xs leading-5 text-slate-400">
                  Coverage follows the managed browser and MDM boundary. Extension health shows status and observed control signals; it cannot prevent its own uninstall.
                </p>
                <details className="rounded-xl border border-white/10 bg-white/[0.02] p-3 text-xs text-slate-500"><summary className="cursor-pointer font-medium text-slate-300">Technical extension diagnostics</summary><div className="mt-2 space-y-2 font-mono"><p>Trusted extension ID: {valueOf(extensionHealth?.trusted_extension_id)}</p><p>Duplicate extension IDs: {extensionHealth?.duplicate_extension_ids.length ? extensionHealth.duplicate_extension_ids.join(", ") : "None observed"}</p><p>Health limitations: {(extensionHealth?.limitations || ["Extension health unavailable"]).join(" · ")}</p><p>Governance trusted extension ID: {valueOf(extensionGovernance?.trusted_extension_id)}</p>{extensionGovernance?.mdm_policies.map((policy) => <div key={policy.browser}><p>{policy.browser} trusted extension ID: {valueOf(policy.trusted_extension_id)}</p><p>{policy.browser} limitations: {policy.limitations.join(" · ") || "None reported"}</p></div>)}</div></details>
              </CardContent>
            </Card>
          ) : null}

          {data && activeTab === "meeting" ? (
            <Card className="border-white/10 bg-[#101721]/85"><CardHeader><CardTitle className="flex items-center gap-2 text-white"><Bot className="h-5 w-5 text-violet-300" /> Meeting AI</CardTitle></CardHeader><CardContent className="grid gap-3 md:grid-cols-4"><MetricCard label="Detected" value={meeting.detected} hint="Identity-backed events" /><MetricCard label="Held" value={meeting.held} hint="Supported platform boundary" /><MetricCard label="Blocked" value={meeting.blocked} hint="Confirmed platform action" /><MetricCard label="Physical recording" value="Unsupported" hint="Independent cameras and phones remain a blind spot" /></CardContent></Card>
          ) : null}

          {data && activeTab === "policies" ? (
            <Card className="border-white/10 bg-[#101721]/85"><CardHeader><CardTitle className="flex items-center gap-2 text-white"><ShieldCheck className="h-5 w-5 text-emerald-300" /> Policies</CardTitle></CardHeader><CardContent className="space-y-4"><p className="text-sm text-slate-300">Manage which AI applications, websites, repositories, and tools people can use. Open Policies to review or change the rules.</p><div className="flex flex-wrap gap-2"><StateBadge value={data.governance.policy.mode} />{data.governance.policy.allowed_operations.slice(0, 8).map((operation) => <StateBadge key={operation} value={operation} />)}</div><Button asChild variant="outline" className="border-white/10 bg-white/5 text-white"><Link href="/protect">Open Policy Control Room</Link></Button></CardContent></Card>
          ) : null}

          {data && activeTab === "coverage" ? (
            <Card className="border-white/10 bg-[#101721]/85"><CardHeader><CardTitle className="flex items-center gap-2 text-white"><AlertTriangle className="h-5 w-5 text-amber-300" /> Coverage &amp; Gaps</CardTitle></CardHeader><CardContent className="space-y-3"><div className="flex items-center gap-3"><StateBadge value={data.coverage_gaps.status} /><span className="text-sm text-slate-400">No adapter is shown green merely because it exists.</span></div>{data.coverage_gaps.gaps.length ? data.coverage_gaps.gaps.map((gap) => <div key={gap} className="rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm text-amber-100">{gap}</div>) : <EmptyState>No current source-backed gaps were returned for this period.</EmptyState>}<Button asChild variant="outline" className="border-white/10 bg-white/5 text-white"><Link href="/surface-coverage">Open detailed Control Coverage</Link></Button></CardContent></Card>
          ) : null}

          {data && activeTab === "connectors" ? (
            <Card className="border-white/10 bg-[#101721]/85"><CardHeader><CardTitle className="flex items-center gap-2 text-white"><KeyRound className="h-5 w-5 text-cyan-300" /> Connector Health</CardTitle><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Review the freshness of evidence received from each source. A recent signal shows collection, not control coverage.</p></CardHeader><CardContent className="space-y-3">{data.connector_health.length ? data.connector_health.map((row, index) => <div key={String(row.provider || index)} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/[0.025] p-4"><div><p className="capitalize text-white">{valueOf(row.provider)}</p><p className="mt-1 text-xs text-slate-500">Sources: {Array.isArray(row.source_types) ? row.source_types.map((source) => humanizeLabel(source)).join(", ") || "Unavailable" : "Unavailable"} · Last evidence: {displayTime(row.last_event_at)}</p></div><div className="flex items-center gap-3"><span className="text-xs text-slate-500">Evidence freshness</span><StateBadge value={row.freshness} /></div></div>) : <EmptyState>No connector health evidence is available from the connected sources.</EmptyState>}<Button asChild variant="outline" className="mt-1 border-white/10 bg-white/5 text-white"><Link href="/integrations">Connect or manage sources</Link></Button></CardContent></Card>
          ) : null}

          {data && activeTab === "coverage" ? <SourceReadinessPanel data={data} /> : null}
          {data && activeTab === "connectors" ? <details className="rounded-2xl border border-white/10 bg-[#101721]/70 p-4"><summary className="cursor-pointer text-sm font-medium text-white">Technical connector diagnostics</summary><div className="mt-4"><SourceProfilePanel data={data} /></div></details> : null}
        </section>
      </main>
    </AppShell>
  );
}
