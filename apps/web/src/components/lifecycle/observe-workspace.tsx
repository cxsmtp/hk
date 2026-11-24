"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowUpRight, Blocks, Clock3, Coins, RefreshCw, Search, ShieldCheck } from "lucide-react";

import { CostProvenanceBadge, GovernanceStatus, TokenProvenanceBadge } from "@/components/lifecycle/governance-status";
import { DetailDrawer } from "@/components/detail-drawer";
import { WorkspaceHeader } from "@/components/lifecycle/workspace-header";
import { WorkspaceLinks } from "@/components/lifecycle/workspace-links";
import { OperationalState } from "@/components/operational-state";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { activitySearchText, mergeActivityPages, presentActivity, type ActivityRecord } from "@/lib/activity-presentation";
import { resolvePresentationState } from "@/lib/presentation-state";
import {
  deriveGovernanceState,
  deriveCostUsage,
  deriveTokenUsage,
  governanceProofFromEvent,
  sessionKeyForEvent,
} from "@/lib/governed-session-state";
import type { ActivityAuditAction, RuntimeActionTrace, RuntimeTimelineEvent } from "@/lib/types";
import { cn } from "@/lib/utils";

type SessionRow = {
  key: string;
  events: RuntimeTimelineEvent[];
  latest: RuntimeTimelineEvent;
  status: ReturnType<typeof deriveGovernanceState>;
  tokens: ReturnType<typeof deriveTokenUsage>;
  cost: ReturnType<typeof deriveCostUsage>;
  calls: number;
  blocked: number;
};

const SURFACES = ["all", "browser", "endpoint", "mcp", "llm", "foundry", "copilot"] as const;
const SURFACE_LABELS: Record<(typeof SURFACES)[number], string> = {
  all: "All surfaces",
  browser: "Browser",
  endpoint: "Endpoint",
  mcp: "MCP",
  llm: "LLM",
  foundry: "Foundry",
  copilot: "Copilot",
};
const ACTIVITY_VIEWS = ["All activity", "Model requests", "Tool calls", "Repository actions", "Device actions", "Uploads", "Warnings", "Failures", "Blocked activity"] as const;
const ACTIVITY_CATEGORY_BY_VIEW: Partial<Record<(typeof ACTIVITY_VIEWS)[number], ActivityRecord["category"]>> = {
  "Model requests": "Model request", "Tool calls": "Tool call", "Repository actions": "Repository action",
  "Device actions": "Device action", Uploads: "Upload", Warnings: "Warning", Failures: "Failure", "Blocked activity": "Blocked",
};

function metadataOf(event: RuntimeTimelineEvent): Record<string, unknown> {
  return event.metadata && typeof event.metadata === "object" ? event.metadata : {};
}

function eventTime(event: RuntimeTimelineEvent): number {
  const parsed = Date.parse(event.timestamp || event.created_at);
  return Number.isFinite(parsed) ? parsed : 0;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function eventUrl(event: RuntimeTimelineEvent): string {
  const metadata = metadataOf(event);
  return stringValue(
    event.api_endpoint
    ?? metadata.url
    ?? metadata.page_url
    ?? metadata.pageUrl
    ?? metadata.tab_url
    ?? metadata.target_url,
  );
}

function appFromUrl(value: string): string | null {
  const lower = value.toLowerCase();
  if (lower.includes("chatgpt.com") || lower.includes("openai.com")) return "ChatGPT";
  if (lower.includes("claude.ai") || lower.includes("anthropic.com")) return "Claude";
  if (lower.includes("gemini.google.com") || lower.includes("bard.google.com")) return "Gemini";
  if (lower.includes("github.com")) return "GitHub";
  if (lower.includes("cursor.com")) return "Cursor";
  if (lower.includes("copilot.microsoft.com")) return "Microsoft Copilot";
  if (lower.includes("hawk.localhost") || lower.includes("127.0.0.1")) return "Local governance gateway";
  return null;
}

function providerFromApp(app: string): string | null {
  const normalized = app.toLowerCase();
  if (normalized.includes("chatgpt") || normalized.includes("openai")) return "OpenAI";
  if (normalized.includes("claude")) return "Anthropic";
  if (normalized.includes("gemini") || normalized.includes("google")) return "Google";
  if (normalized.includes("copilot") || normalized.includes("microsoft")) return "Microsoft";
  return null;
}

function displayApplication(event: RuntimeTimelineEvent): string {
  const metadata = metadataOf(event);
  const urlLabel = appFromUrl(eventUrl(event));
  const raw = stringValue(event.application ?? metadata.application_name ?? metadata.application ?? event.ai_surface);
  const rawDomainLabel = appFromUrl(raw);
  if (rawDomainLabel) return rawDomainLabel;
  if (!raw || ["ai", "unknown", "unknown provider", "desktop-native"].includes(raw.toLowerCase())) {
    return urlLabel || (event.source_surface === "browser" ? "Browser AI app" : event.source_surface || "Observed AI activity");
  }
  return raw;
}

function displayProvider(event: RuntimeTimelineEvent): string {
  const metadata = metadataOf(event);
  const raw = stringValue(event.provider ?? metadata.provider ?? metadata.provider_name);
  if (raw && !["unknown", "unknown provider"].includes(raw.toLowerCase())) return raw;
  return providerFromApp(displayApplication(event)) || "Provider not verified";
}

function humanizeAction(value: string): string {
  const normalized = value.trim().toLowerCase();
  const labels: Record<string, string> = {
    prompt_submit: "Prompt submitted",
    prompt_submitted: "Prompt submitted",
    file_upload: "File uploaded",
    upload: "File uploaded",
    context_invalidated: "Context changed",
    tool_call: "Tool call",
    tool_invocation: "Tool call",
    model_request: "Model request",
    response_received: "Response received",
  };
  if (labels[normalized]) return labels[normalized];
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function displayAction(event: RuntimeTimelineEvent): string {
  const metadata = metadataOf(event);
  const raw = stringValue(event.tool_name ?? event.action_type ?? metadata.action_class ?? metadata.intent ?? event.event_type);
  if (!raw || raw.toLowerCase() === "ai") {
    if (event.source_surface === "browser") return "Prompt / browser action";
    if (event.tool_name) return `Tool call: ${event.tool_name}`;
    return "Observed AI action";
  }
  return humanizeAction(raw);
}

function compactNumber(value: number | null): string {
  if (value === null) return "—";
  return Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function evidenceText(value: unknown): string {
  if (value === null || value === undefined) return "Unavailable";
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function aggregateTokens(events: RuntimeTimelineEvent[]) {
  const usages = events.map((event) => deriveTokenUsage(metadataOf(event)));
  const known = usages.filter((item) => item.total !== null);
  if (!known.length) return deriveTokenUsage({});
  const incomplete = known.length !== usages.length;
  const estimated = incomplete || known.some((item) => item.provenance !== "exact");
  return {
    input: known.reduce((sum, item) => sum + (item.input ?? 0), 0),
    output: known.reduce((sum, item) => sum + (item.output ?? 0), 0),
    cached: known.some((item) => item.cached !== null) ? known.reduce((sum, item) => sum + (item.cached ?? 0), 0) : null,
    total: known.reduce((sum, item) => sum + (item.total ?? 0), 0),
    provenance: estimated ? "estimated" as const : "exact" as const,
  };
}

function aggregateCosts(events: RuntimeTimelineEvent[]): ReturnType<typeof deriveCostUsage> {
  const costs = events.map((event) => deriveCostUsage(metadataOf(event)));
  const known = costs.filter((item) => item.amount !== null && item.currency !== null);
  if (!known.length) return deriveCostUsage({});
  const currencies = new Set(known.map((item) => item.currency));
  if (currencies.size !== 1) return { amount: null, currency: null, provenance: "unknown", source: "mixed" };
  const incomplete = known.length !== costs.length;
  const sources = new Set(known.map((item) => item.source));
  return {
    amount: known.reduce((sum, item) => sum + (item.amount ?? 0), 0),
    currency: known[0].currency,
    provenance: incomplete || known.some((item) => item.provenance !== "exact") ? "estimated" : "exact",
    source: sources.size === 1 ? known[0].source : "mixed",
  };
}

function formatCost(cost: ReturnType<typeof deriveCostUsage>): string {
  if (cost.amount === null || !cost.currency) return "Cost not reported";
  return new Intl.NumberFormat("en", {
    style: "currency",
    currency: cost.currency,
    minimumFractionDigits: 2,
    maximumFractionDigits: 6,
  }).format(cost.amount);
}

function groupSessions(events: RuntimeTimelineEvent[]): SessionRow[] {
  const grouped = new Map<string, RuntimeTimelineEvent[]>();
  for (const event of events) {
    const key = sessionKeyForEvent(event);
    grouped.set(key, [...(grouped.get(key) || []), event]);
  }
  return [...grouped.entries()].map(([key, items]) => {
    const ordered = [...items].sort((left, right) => eventTime(right) - eventTime(left));
    const statuses = ordered.map((event) => {
      const proof = governanceProofFromEvent(event);
      proof.heartbeatFresh = Date.now() - eventTime(event) < 120_000;
      return deriveGovernanceState(proof);
    });
    const rank = { governed: 5, partially_governed: 4, monitor_only: 3, unknown: 2, disconnected: 1 };
    const status = statuses.sort((left, right) => rank[right.state] - rank[left.state])[0] || deriveGovernanceState({});
    return {
      key,
      events: ordered,
      latest: ordered[0],
      status,
      calls: items.filter((item) => Boolean(item.tool_name) || item.event_type.includes("tool")).length,
      blocked: items.filter((item) => ["block", "prevent", "deny"].includes(String(item.policy_decision || item.decision || "").toLowerCase())).length,
      tokens: aggregateTokens(items),
      cost: aggregateCosts(items),
    };
  }).sort((left, right) => eventTime(right.latest) - eventTime(left.latest));
}

function surfaceMatches(event: RuntimeTimelineEvent, filter: string): boolean {
  if (filter === "all") return true;
  const haystack = `${event.source_surface} ${event.ai_surface || ""} ${event.application || ""}`.toLowerCase();
  if (filter === "llm") return /(llm|gateway|sdk|openai|anthropic|model)/.test(haystack);
  return haystack.includes(filter);
}

function formatTimestamp(value?: string): string {
  if (!value) return "Unknown time";
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toLocaleString() : "Unknown time";
}

function metric(metadata: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = metadata[key];
    if (typeof value === "number" && Number.isFinite(value)) return value.toLocaleString();
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "—";
}

export function ObserveWorkspace() {
  const [events, setEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [serverTotal, setServerTotal] = useState(0);
  const [loadedPages, setLoadedPages] = useState(1);
  const loadEpoch = useRef(0);
  const [surface, setSurface] = useState("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [runtimeState, setRuntimeState] = useState<"loading" | "loaded" | "error">("loading");
  const [auditUnavailable, setAuditUnavailable] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [auditActions, setAuditActions] = useState<ActivityAuditAction[]>([]);
  const [selectedAudit, setSelectedAudit] = useState<{ eventId: string; action: ActivityAuditAction | null; unavailable: boolean } | null>(null);
  const [activityView, setActivityView] = useState<(typeof ACTIVITY_VIEWS)[number]>("All activity");
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedTrace, setSelectedTrace] = useState<RuntimeActionTrace | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);

  const load = useCallback(async (silent = false) => {
    const epoch = ++loadEpoch.current;
    if (!silent) { setLoading(true); setRuntimeState("loading"); }
    try {
      const [runtimeResult, auditResult] = await Promise.allSettled([
        Promise.all(Array.from({ length: loadedPages }, (_, index) => index + 1).map((pageNumber) => api.runtimeActivities({ page: pageNumber, page_size: 100 }))),
        api.searchActivityAudit({ page: 1, page_size: 100 }),
      ]);
      if (epoch !== loadEpoch.current) return;
      if (runtimeResult.status === "rejected") {
        setEvents([]);
        setServerTotal(0);
        setAuditActions([]);
        setRuntimeState("error");
        setAuditUnavailable(auditResult.status !== "fulfilled");
        throw runtimeResult.reason;
      }
      setEvents(mergeActivityPages(runtimeResult.value));
      setServerTotal(runtimeResult.value[0]?.total || 0);
      setRuntimeState("loaded");
      setAuditUnavailable(auditResult.status !== "fulfilled");
      setAuditActions(auditResult.status === "fulfilled" ? auditResult.value.items || [] : []);
      setUpdatedAt(new Date());
      setError(null);
    } catch (requestError) {
      if (epoch === loadEpoch.current) setError(requestError instanceof Error ? requestError.message : "Live activity is unavailable");
    } finally {
      if (!silent && epoch === loadEpoch.current) setLoading(false);
    }
  }, [loadedPages]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (!document.hidden) void load(true);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [load]);

  const sessions = useMemo(() => groupSessions(events).filter((session) => {
    if (!surfaceMatches(session.latest, surface)) return false;
    if (!query.trim()) return true;
    const term = query.toLowerCase();
    return session.events.some((event) => `${event.user_email || event.user_id || ""} ${event.agent_id || ""} ${event.application || ""} ${event.tool_name || ""} ${event.model || ""}`.toLowerCase().includes(term));
  }), [events, query, surface]);

  const activityRows = useMemo(() => events.map((event) => presentActivity(
    event as unknown as Record<string, unknown>,
    event.event_id === selectedEventId ? (selectedAudit?.eventId === event.event_id ? selectedAudit.action ?? { prompt_payload: { content_access_level: "CONTENT_UNAVAILABLE" } } : { prompt_payload: { content_access_level: "CONTENT_UNAVAILABLE" } }) : auditActions.find((item) => item.runtime_event_id === event.event_id),
    selectedTrace && selectedTrace.runtime_event?.event_id === event.event_id ? selectedTrace : undefined,
  )), [auditActions, events, selectedAudit, selectedEventId, selectedTrace]);
  const visibleActivityRows = useMemo(() => activityRows.filter((row) => {
    if (activityView !== "All activity") {
      const category = ACTIVITY_CATEGORY_BY_VIEW[activityView];
      if (!row.categories.includes(category as ActivityRecord["category"])) return false;
    }
    return !query.trim() || activitySearchText(row).includes(query.trim().toLowerCase());
  }), [activityRows, activityView, query]);
  const selectedActivity = visibleActivityRows.find((row) => row.id === selectedEventId) || activityRows.find((row) => row.id === selectedEventId) || null;

  useEffect(() => {
    if (!selectedEventId) {
      setSelectedAudit(null);
      setSelectedTrace(null);
      setTraceError(null);
      setTraceLoading(false);
      return;
    }
    let active = true;
    const requestEventId = selectedEventId;
    setSelectedTrace(null);
    setSelectedAudit(null);
    setTraceLoading(true);
    setTraceError(null);
    void Promise.allSettled([
      api.runtimeActionTrace(requestEventId),
      api.searchActivityAudit({ runtime_event_id: requestEventId, page: 1, page_size: 1 }),
    ]).then(([traceResult, auditResult]) => {
      if (!active) return;
      if (traceResult.status === "fulfilled") setSelectedTrace(traceResult.value);
      else setTraceError("Detailed evidence unavailable for this activity.");
      setSelectedAudit({
        eventId: requestEventId,
        action: auditResult.status === "fulfilled" ? auditResult.value.items.find((item) => item.runtime_event_id === requestEventId) || null : null,
        unavailable: auditResult.status !== "fulfilled",
      });
      setTraceLoading(false);
    });
    return () => { active = false; };
  }, [selectedEventId]);

  useEffect(() => {
    if (!sessions.length) setSelectedKey(null);
    else if (!sessions.some((item) => item.key === selectedKey)) setSelectedKey(sessions[0].key);
  }, [selectedKey, sessions]);

  const selected = sessions.find((item) => item.key === selectedKey) || sessions[0] || null;
  const governedCount = sessions.filter((session) => {
    return session.status.state === "governed";
  }).length;
  const knownTokenTotal = sessions.reduce((sum, session) => sum + (session.tokens.total ?? 0), 0);
  const hasKnownTokens = sessions.some((session) => session.tokens.total !== null);
  const governedSessions = sessions.filter((session) => {
    return session.status.state === "governed";
  });
  const governedCost = aggregateCosts(governedSessions.flatMap((session) => session.events));
  const presentationState = resolvePresentationState({
    loading,
    hasData: events.length > 0,
    unavailable: runtimeState === "error",
    stale: Boolean(updatedAt && Date.now() - updatedAt.getTime() > 15 * 60_000),
  });

  return (
    <div className="space-y-5">
      <WorkspaceHeader
        eyebrow="Activity"
        title="Activity"
        description="Follow people and agents across AI clients, prompts, tool calls and queries. Every governance and usage label reflects the evidence Hawk actually received."
        actions={
          <Button variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={cn("mr-2 h-4 w-4", loading && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      <OperationalState
        state={presentationState}
        onRetry={() => void load()}
        description={error ? "Activity source unavailable. No activity count is inferred from the failed source." : undefined}
      />

      <section className="overflow-hidden rounded-[22px] border border-white/[0.07] bg-[#0c1016]" aria-labelledby="activity-table-title">
        <div className="flex flex-col gap-3 border-b border-white/[0.06] p-4">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between"><div><p className="text-xs font-semibold text-slate-200" id="activity-table-title">Activity</p><p className="mt-1 text-[11px] text-slate-600">Allowed means Hawk permitted the request. Outcome requires execution evidence.</p></div><label className="relative block w-full xl:w-80"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="User, agent, tool or model" className="h-10 w-full rounded-xl border border-white/[0.07] bg-black/20 pl-10 pr-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-orange-400/30" /></label></div>
          <div className="flex flex-wrap gap-1.5">{ACTIVITY_VIEWS.map((view) => <button key={view} type="button" onClick={() => setActivityView(view)} className={cn("rounded-lg px-3 py-2 text-[11px] font-medium", activityView === view ? "bg-orange-400/10 text-orange-200" : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200")}>{view}</button>)}</div>
          <p className="text-[11px] text-slate-500">Loaded {events.length.toLocaleString()} of {serverTotal.toLocaleString()} activities. Search and views filter the loaded activities.</p>
        </div>
        <div className="overflow-x-auto"><table className="w-full min-w-[860px] text-left"><thead className="border-b border-white/[0.06] text-[10px] uppercase tracking-[0.12em] text-slate-600"><tr><th className="px-4 py-3 font-semibold">When</th><th className="px-4 py-3 font-semibold">Who / using what</th><th className="px-4 py-3 font-semibold">Action</th><th className="px-4 py-3 font-semibold">Target</th><th className="px-4 py-3 font-semibold">Hawk decision</th><th className="px-4 py-3 font-semibold">Outcome</th></tr></thead><tbody>{visibleActivityRows.map((row) => <tr key={row.id} className="border-b border-white/[0.045] text-xs"><td className="px-4 py-3 text-slate-500">{formatTimestamp(row.when)}</td><td className="px-4 py-3"><button type="button" onClick={() => setSelectedEventId(row.id)} className="text-left font-medium text-slate-200 hover:text-orange-200">{row.actor}<span className="mt-1 block text-[10px] text-slate-600">{row.application}</span></button></td><td className="px-4 py-3 text-slate-300">{row.action}</td><td className="max-w-[220px] truncate px-4 py-3 text-slate-500">{row.target}</td><td className="px-4 py-3"><span className="rounded-full border border-white/[0.08] px-2 py-1 text-[10px] text-slate-300">{row.decision}</span></td><td className="px-4 py-3 text-slate-400">{row.outcome}</td></tr>)}</tbody></table>{runtimeState === "error" ? <p className="px-4 py-10 text-center text-xs text-amber-200">Activity is unavailable until the runtime source responds.</p> : !loading && !visibleActivityRows.length ? <p className="px-4 py-10 text-center text-xs text-slate-600">No activity matches this view.</p> : null}</div>
        {runtimeState === "loaded" && events.length < serverTotal ? <div className="border-t border-white/[0.06] px-4 py-3"><Button variant="outline" disabled={loading} onClick={() => setLoadedPages((pages) => pages + 1)}>Load older activity</Button></div> : null}
        {auditUnavailable ? <p className="border-t border-amber-400/10 px-4 py-3 text-xs text-amber-200">Optional enrichment is unavailable; the activity list remains usable.</p> : null}
      </section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {[
          { label: "Visible sessions", value: loading ? "—" : runtimeState === "error" ? "Unavailable" : sessions.length.toLocaleString(), icon: Activity, note: "Current filter" },
          { label: "Governed", value: loading ? "—" : runtimeState === "error" ? "Unavailable" : governedCount.toLocaleString(), icon: ShieldCheck, note: "All proof requirements met" },
          { label: "Tool calls", value: loading ? "—" : runtimeState === "error" ? "Unavailable" : sessions.reduce((sum, item) => sum + item.calls, 0).toLocaleString(), icon: Blocks, note: "Observed MCP and agent calls" },
          { label: "Session tokens", value: loading || !hasKnownTokens ? "Unknown" : compactNumber(knownTokenTotal), icon: Coins, note: hasKnownTokens ? "Known usage; session rows show provenance" : "Provider or hook did not report usage" },
          { label: "Governed spend", value: loading ? "—" : runtimeState === "error" ? "Unavailable" : formatCost(governedCost), icon: Coins, note: governedCost.provenance === "unknown" ? "No authoritative spend evidence reported" : `${governedCost.provenance} · ${governedCost.source.replaceAll("_", " ")}` },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.label} className="rounded-[20px] border border-white/[0.07] bg-[#0c1016] p-4">
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{item.label}</p>
                <Icon className="h-4 w-4 text-orange-300/70" />
              </div>
              <p className="mt-3 text-2xl font-semibold tracking-[-0.03em] text-white">{item.value}</p>
              <p className="mt-1 text-[11px] text-slate-600">{item.note}</p>
            </div>
          );
        })}
      </section>

      <section className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-4">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex flex-wrap gap-1.5">
            {SURFACES.map((item) => (
              <button key={item} type="button" onClick={() => setSurface(item)} className={cn("rounded-lg px-3 py-2 text-xs font-medium transition", surface === item ? "bg-orange-400/10 text-orange-200 shadow-[inset_0_0_0_1px_rgba(251,146,60,0.18)]" : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200")}>
                {SURFACE_LABELS[item]}
              </button>
            ))}
          </div>
        </div>
      </section>


      <section className="grid min-h-[32rem] gap-4 xl:grid-cols-[minmax(23rem,0.82fr)_minmax(0,1.18fr)]">
        <div className="overflow-hidden rounded-[22px] border border-white/[0.07] bg-[#0c1016]">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3">
            <p className="text-xs font-semibold text-slate-200">Sessions</p>
            <span className="inline-flex items-center gap-1.5 text-[10px] text-slate-600"><Clock3 className="h-3 w-3" />{updatedAt ? `Updated ${updatedAt.toLocaleTimeString()}` : "Waiting for data"}</span>
          </div>
          <div className="max-h-[42rem] overflow-y-auto p-2">
            {runtimeState === "error" ? (
              <div className="m-2 rounded-2xl border border-dashed border-amber-400/15 px-5 py-12 text-center"><p className="text-sm font-medium text-amber-200">Session data is unavailable</p><p className="mt-2 text-xs leading-5 text-slate-600">The runtime source did not respond. Hawk is not treating missing data as an empty session list.</p></div>
            ) : !loading && !sessions.length ? (
              <div className="m-2 rounded-2xl border border-dashed border-white/[0.09] px-5 py-12 text-center">
                <p className="text-sm font-medium text-slate-300">No observed sessions match this view</p>
                <p className="mt-2 text-xs leading-5 text-slate-600">Connect a supported surface or change the filters. Hawk will not create synthetic session activity.</p>
              </div>
            ) : null}
            {sessions.map((session) => {
              const selectedRow = session.key === selected?.key;
              const app = displayApplication(session.latest);
              const provider = displayProvider(session.latest);
              return (
                <button key={session.key} type="button" onClick={() => setSelectedKey(session.key)} className={cn("mb-1 w-full rounded-2xl border p-3.5 text-left transition", selectedRow ? "border-orange-400/20 bg-orange-400/[0.055]" : "border-transparent hover:border-white/[0.06] hover:bg-white/[0.025]")}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-slate-100">{session.latest.user_email || session.latest.user_id || session.latest.agent_id || "Unresolved identity"}</p>
                      <p className="mt-1 truncate text-[11px] text-slate-500">{app} · {provider}{session.latest.model ? ` · ${session.latest.model}` : ""}</p>
                    </div>
                    <GovernanceStatus status={session.status} compact />
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-2 text-[10px] text-slate-600">
                    <span>{session.events.length} events</span><span>·</span><span>{session.calls} calls</span><span>·</span>
                    <span>{compactNumber(session.tokens.total)} tokens</span>
                    <TokenProvenanceBadge provenance={session.tokens.provenance} />
                    <span>·</span><span>{formatCost(session.cost)}</span>
                    <CostProvenanceBadge cost={session.cost} />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-4 sm:p-5">
          {selected ? (() => {
            const metadata = metadataOf(selected.latest);
            const app = displayApplication(selected.latest);
            const provider = displayProvider(selected.latest);
            return (
              <div>
                <div className="flex flex-col gap-4 border-b border-white/[0.06] pb-5 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-2"><GovernanceStatus status={selected.status} /><TokenProvenanceBadge provenance={selected.tokens.provenance} /><CostProvenanceBadge cost={selected.cost} /></div>
                    <h2 className="mt-3 text-xl font-semibold tracking-[-0.025em] text-white">{app}</h2>
                    <p className="mt-1 text-xs text-slate-500">{provider}{selected.latest.model ? ` · ${selected.latest.model}` : ""} · {formatTimestamp(selected.latest.timestamp || selected.latest.created_at)}</p>
                  </div>
                  <Link href={`/runtime-intelligence/action-trace/${encodeURIComponent(selected.latest.event_id)}`} className="inline-flex items-center gap-2 rounded-xl border border-white/[0.08] px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-orange-400/25 hover:text-orange-200">
                    Open trace <ArrowUpRight className="h-3.5 w-3.5" />
                  </Link>
                </div>
                <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                  {[
                    ["Input tokens", compactNumber(selected.tokens.input)],
                    ["Output tokens", compactNumber(selected.tokens.output)],
                    ["Total tokens", compactNumber(selected.tokens.total)],
                    ["Spend", formatCost(selected.cost)],
                    ["Calls", selected.calls.toLocaleString()],
                    ["Rows", metric(metadata, "row_count", "rows", "records")],
                    ["Latency", metric(metadata, "latency_ms", "duration_ms") === "—" ? "—" : `${metric(metadata, "latency_ms", "duration_ms")} ms`],
                  ].map(([label, value]) => <div key={label} className="rounded-2xl border border-white/[0.055] bg-black/15 p-3"><p className="text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-600">{label}</p><p className="mt-2 text-lg font-semibold text-slate-100">{value}</p></div>)}
                </div>
                <div className="mt-5 space-y-2">
                  {selected.events.slice(0, 12).map((event) => {
                    const eventMetadata = metadataOf(event);
                    const decision = String(event.policy_decision || event.decision || "unknown");
                    return (
                      <div key={event.event_id} className="grid gap-3 rounded-2xl border border-white/[0.055] bg-white/[0.015] p-3.5 sm:grid-cols-[7rem_minmax(0,1fr)_auto] sm:items-center">
                        <p className="font-mono text-[10px] text-slate-600">{new Date(event.timestamp || event.created_at).toLocaleTimeString()}</p>
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-slate-200">{displayAction(event)}</p>
                          <p className="mt-1 truncate text-[11px] text-slate-600">{eventUrl(event) || String(eventMetadata.target_resource || eventMetadata.destination || event.source_surface)}</p>
                        </div>
                        <span className={cn("rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.08em]", ["block", "deny", "prevent"].includes(decision.toLowerCase()) ? "border-rose-400/20 bg-rose-400/[0.08] text-rose-300" : "border-emerald-400/20 bg-emerald-400/[0.08] text-emerald-300")}>{decision}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })() : <div className="grid min-h-[28rem] place-items-center text-sm text-slate-600">Select a verified session to inspect its activity.</div>}
        </div>
      </section>

      <DetailDrawer open={Boolean(selectedActivity)} onClose={() => setSelectedEventId(null)} title={selectedActivity ? selectedActivity.action : "Activity"} subtitle={selectedActivity ? `${selectedActivity.decision} · ${selectedActivity.outcome}` : undefined} size="wide">
        {selectedActivity ? <div className="space-y-5 text-sm">
          <section><h4 className="font-semibold text-slate-100">What happened</h4><p className="mt-2 text-xs leading-5 text-slate-400">{selectedActivity.action} on {selectedActivity.target} at {formatTimestamp(selectedActivity.when)}.</p></section>
          <section><h4 className="font-semibold text-slate-100">Who was involved</h4><div className="mt-2 grid gap-2 text-xs text-slate-400 sm:grid-cols-2">{([['Requesting person', selectedActivity.identities.requestingPerson], ['App or agent', selectedActivity.identities.appAgent], ['Executing principal', selectedActivity.identities.executingPrincipal], ['Owner', selectedActivity.identities.owner], ['Author', selectedActivity.identities.author], ['Reviewer', selectedActivity.identities.reviewer], ['Merger', selectedActivity.identities.merger]] as const).filter(([, value]) => value && value !== "Unavailable").map(([label, value]) => <p key={label}>{label}: {value}</p>)}{![selectedActivity.identities.requestingPerson, selectedActivity.identities.appAgent, selectedActivity.identities.executingPrincipal, selectedActivity.identities.owner, selectedActivity.identities.author, selectedActivity.identities.reviewer, selectedActivity.identities.merger].some((value) => value && value !== "Unavailable") ? <p>Identity details are unavailable from this source.</p> : null}</div></section>
          <section><h4 className="font-semibold text-slate-100">Request and result</h4>
            <div className="mt-2 grid gap-2 text-xs text-slate-400 sm:grid-cols-2">{([['Provider', selectedActivity.evidence.provider], ['Model', selectedActivity.evidence.model], ['MCP server', selectedActivity.evidence.mcpServer], ['MCP tool', selectedActivity.evidence.mcpTool], ['Content access', selectedActivity.request.contentAccess], ['Outcome', selectedActivity.outcome]] as const).filter(([, value]) => value && value !== "Unavailable").map(([label, value]) => <p key={label}>{label}: {value}</p>)}{![selectedActivity.evidence.provider, selectedActivity.evidence.model, selectedActivity.evidence.mcpServer, selectedActivity.evidence.mcpTool, selectedActivity.request.contentAccess, selectedActivity.outcome].some((value) => value && value !== "Unavailable") ? <p>Request details are unavailable from this source.</p> : null}</div>
            {selectedActivity.request.preview ? <p className="mt-2 text-xs text-slate-400">Redacted preview: {selectedActivity.request.preview}</p> : null}
            {selectedActivity.evidence.attachmentCount ? <div className="mt-3 text-xs text-slate-400"><p>Files attached: {selectedActivity.evidence.attachmentCount}</p><pre className="mt-1 whitespace-pre-wrap break-words rounded-lg border border-white/[0.07] bg-black/20 p-3">{selectedActivity.evidence.attachments.length ? evidenceText(selectedActivity.evidence.attachments) : "File details were not captured."}</pre></div> : selectedActivity.categories.includes("Upload") ? <p className="mt-3 text-xs text-slate-500">Upload observed; file details were not captured.</p> : null}
            <div className="mt-3 grid gap-3 sm:grid-cols-2"><div><p className="text-xs font-medium text-slate-300">Redacted arguments</p><pre className="mt-1 whitespace-pre-wrap break-words rounded-lg border border-white/[0.07] bg-black/20 p-3 text-xs text-slate-400">{evidenceText(selectedActivity.evidence.redactedArguments)}</pre></div><div><p className="text-xs font-medium text-slate-300">Redacted result</p><pre className="mt-1 whitespace-pre-wrap break-words rounded-lg border border-white/[0.07] bg-black/20 p-3 text-xs text-slate-400">{evidenceText(selectedActivity.evidence.redactedResult)}</pre></div></div>
          </section>
          <section><h4 className="font-semibold text-slate-100">Why Hawk acted</h4><p className="mt-2 text-xs text-slate-400">Policy decision: {selectedActivity.decision}. A permitted decision does not prove execution.</p></section>
          <section><h4 className="font-semibold text-slate-100">Trace evidence</h4><p className="mt-2 text-xs text-slate-400">Action: {selectedActivity.trace.action} · Target: {selectedActivity.trace.target} · Decision: {selectedActivity.trace.decision} · Execution: {selectedActivity.trace.execution}</p><div className="mt-3 grid gap-3 sm:grid-cols-2"><div><p className="text-xs font-medium text-slate-300">Approval</p><pre className="mt-1 whitespace-pre-wrap break-words rounded-lg border border-white/[0.07] bg-black/20 p-3 text-xs text-slate-400">{evidenceText(selectedActivity.evidence.approval)}</pre></div><div><p className="text-xs font-medium text-slate-300">Execution receipt</p><pre className="mt-1 whitespace-pre-wrap break-words rounded-lg border border-white/[0.07] bg-black/20 p-3 text-xs text-slate-400">{evidenceText(selectedActivity.evidence.execution)}</pre></div></div><p className="mt-3 text-xs font-medium text-slate-300">Downstream objects</p><pre className="mt-1 whitespace-pre-wrap break-words rounded-lg border border-white/[0.07] bg-black/20 p-3 text-xs text-slate-400">{selectedActivity.trace.downstreamObjects.length ? evidenceText(selectedActivity.trace.downstreamObjects) : "Unavailable"}</pre></section>
          <section><h4 className="font-semibold text-slate-100">Related activity</h4><p className="mt-2 text-xs text-slate-400">{selectedActivity.related.length ? selectedActivity.related.join(", ") : "No reliable stored related activity reference."}</p>{selectedActivity.references.gitRefs?.length ? <ul className="mt-2 space-y-1 text-xs text-slate-400">{selectedActivity.references.gitRefs.map((ref) => <li key={ref}>{ref}</li>)}</ul> : null}</section>
          <section><h4 className="font-semibold text-slate-100">Capture and retention</h4><p className="mt-2 text-xs text-slate-400">Capture: {selectedActivity.capture} · Retention: {selectedActivity.retention}</p></section>
          {traceLoading ? <p className="text-xs text-slate-500">Loading detailed evidence…</p> : null}{traceError ? <p className="text-xs text-amber-200">{traceError}</p> : null}
          {selectedAudit?.eventId === selectedActivity.id && selectedAudit.unavailable ? <p className="text-xs text-amber-200">Prompt audit details are unavailable for this activity.</p> : null}
          <details><summary className="cursor-pointer text-xs font-semibold text-slate-400">Technical details</summary><pre className="mt-2 max-h-48 overflow-auto rounded-xl border border-white/[0.07] bg-black/20 p-3 text-[10px] text-slate-500">{JSON.stringify({ references: selectedActivity.references, event: selectedActivity.rawEvent, audit: selectedActivity.rawAudit, trace: selectedActivity.rawTrace }, null, 2)}</pre></details>
          <Link href={`/runtime-intelligence/action-trace/${encodeURIComponent(selectedActivity.id)}`} className="inline-flex items-center gap-2 text-xs font-semibold text-orange-200">Open full trace <ArrowUpRight className="h-3.5 w-3.5" /></Link>
        </div> : null}
      </DetailDrawer>

      <WorkspaceLinks links={[
        { href: "/runtime-intelligence/overview", label: "Runtime intelligence", description: "Investigate action chains, anomalies and recommendations." },
        { href: "/interaction-security", label: "Interaction security", description: "Review user, app and surface-level policy decisions." },
        { href: "/monitoring", label: "Monitoring", description: "Inspect operational health and alert telemetry." },
      ]} />
    </div>
  );
}
