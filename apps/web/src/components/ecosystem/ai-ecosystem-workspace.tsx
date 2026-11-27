"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  ChevronRight,
  CircleHelp,
  Eye,
  Layers3,
  Network,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Table2,
  UsersRound,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { EvidenceTruthPanel } from "@/components/evidence/evidence-truth-panel";
import { api } from "@/lib/api";
import type {
  AgentIdentity,
  ControlCoverageSummary,
  DiscoveryEcosystem,
  DiscoveryEstateSummary,
  ExecutiveControlCoverageSummary,
  ListEnvelope,
  MaturityCurveOverview,
  UnknownAIItem,
  PolicyPackPlatformInstance,
  UserVisibilityAction,
  UserVisibilityDepartment,
  UserVisibilityGroup,
  UserVisibilityOrganization,
  UserVisibilityUser,
} from "@/lib/types";

type EcosystemView = "organization" | "departments" | "surfaces" | "policies" | "attention" | "table";
type EcosystemFilters = { department: string; application: string; surface: string };

type OverviewData = {
  organization: UserVisibilityOrganization | null;
  departments: ListEnvelope<UserVisibilityDepartment> | null;
  groups: ListEnvelope<UserVisibilityGroup> | null;
  users: ListEnvelope<UserVisibilityUser> | null;
  estate: DiscoveryEstateSummary | null;
  ecosystems: ListEnvelope<DiscoveryEcosystem> | null;
  unknownAI: ListEnvelope<UnknownAIItem> | null;
  agents: ListEnvelope<AgentIdentity> | null;
  systems: { items: Array<{ id: string; name: string; status: string }> } | null;
  policyPacks: { items: PolicyPackPlatformInstance[]; count: number } | null;
  coverage: ExecutiveControlCoverageSummary | null;
  fallbackCoverage: ControlCoverageSummary | null;
  maturity: MaturityCurveOverview | null;
};

type AttentionItem = {
  id: string;
  title: string;
  detail: string;
  evidence: string;
  href: string;
};

const EMPTY_FILTERS: EcosystemFilters = { department: "", application: "", surface: "" };

const VIEWS: Array<{ id: EcosystemView; label: string; note: string }> = [
  { id: "organization", label: "Organization", note: "AI footprint" },
  { id: "departments", label: "Departments", note: "Scoped adoption" },
  { id: "surfaces", label: "Surface coverage", note: "Control truth" },
  { id: "policies", label: "Policies", note: "Packs and rollout" },
  { id: "attention", label: "Attention", note: "Evidence-backed next steps" },
  { id: "table", label: "Table fallback", note: "Same filtered evidence" },
];

const COVERAGE_LABELS: Record<string, { label: string; className: string }> = {
  covered_current: { label: "Current", className: "border-emerald-300/25 bg-emerald-300/[0.08] text-emerald-100" },
  partially_covered: { label: "Partial", className: "border-cyan-300/25 bg-cyan-300/[0.08] text-cyan-100" },
  configured_unvalidated: { label: "Configured but unvalidated", className: "border-indigo-300/25 bg-indigo-300/[0.08] text-indigo-100" },
  covered_stale: { label: "Stale", className: "border-amber-300/25 bg-amber-300/[0.08] text-amber-100" },
  regressed: { label: "Regressed", className: "border-rose-300/25 bg-rose-300/[0.08] text-rose-100" },
  gap: { label: "Gap", className: "border-orange-300/25 bg-orange-300/[0.08] text-orange-100" },
  unsupported: { label: "Unsupported", className: "border-slate-400/25 bg-slate-400/[0.08] text-slate-200" },
  unknown: { label: "Unknown", className: "border-fuchsia-300/25 bg-fuchsia-300/[0.08] text-fuchsia-100" },
  not_applicable: { label: "Not applicable", className: "border-slate-600/25 bg-slate-600/[0.08] text-slate-400" },
};

const SURFACE_LABELS: Record<string, { label: string; description: string }> = {
  browser: { label: "Browser", description: "Web AI applications, account context, prompts and uploads where connected." },
  endpoint: { label: "Endpoint", description: "Desktop AI, code, files, commands and network activity where connected." },
  runtime: { label: "Runtime", description: "Agent, tool and delegated-action controls at runtime." },
  saas_api: { label: "SaaS & APIs", description: "Provider-native, API and gateway evidence where connected." },
};

function isFulfilled<T>(result: PromiseSettledResult<T>): result is PromiseFulfilledResult<T> {
  return result.status === "fulfilled";
}

function requestFailure(result: PromiseSettledResult<unknown>, label: string): string | null {
  if (result.status === "fulfilled") return null;
  const message = result.reason instanceof Error ? result.reason.message : "Unavailable";
  return `${label}: ${message}`;
}

function readable(value: string | null | undefined, fallback = "Unknown"): string {
  const text = String(value || "").trim();
  return text ? text.replaceAll("_", " ") : fallback;
}

function dateLabel(value?: string | null): string {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function countLabel(value?: number | null): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString() : "Unknown";
}

function availableCount(value?: number | null, fallback = "Needs source"): string {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value.toLocaleString() : fallback;
}

function evidenceListLabel(values: Array<{ value: string; count: number }>, fallback = "Needs source"): string {
  return values.length ? values.map((item) => `${item.value} · ${item.count}`).join(" · ") : fallback;
}

function aggregate(values: Array<string | null | undefined>, limit = 6): Array<{ value: string; count: number }> {
  const counts = new Map<string, number>();
  for (const candidate of values) {
    const value = String(candidate || "").trim();
    if (!value) continue;
    counts.set(value, (counts.get(value) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || left.value.localeCompare(right.value))
    .slice(0, limit);
}

function StatusPill({ state }: { state: string }) {
  const tone = COVERAGE_LABELS[state] || COVERAGE_LABELS.unknown;
  return <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] ${tone.className}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{tone.label}</span>;
}

function MetricCard({ label, value, note, tone = "text-slate-100" }: { label: string; value: string | number; note: string; tone?: string }) {
  return (
    <article className="relative overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0e151f] p-4 shadow-[0_18px_55px_rgba(0,0,0,.16)]">
      <div className="absolute inset-x-4 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
      <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tracking-[-0.04em] ${tone}`}>{value}</p>
      <p className="mt-2 text-xs leading-4 text-slate-500">{note}</p>
    </article>
  );
}

function RelationshipCard({
  eyebrow,
  title,
  value,
  description,
  href,
  action,
  icon: Icon,
}: {
  eyebrow: string;
  title: string;
  value: string | number;
  description: string;
  href: string;
  action: string;
  icon: typeof Network;
}) {
  return (
    <article className="relative min-w-0 overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0c141d] p-4">
      <div className="absolute -right-8 -top-8 h-24 w-24 rounded-full bg-cyan-300/[0.055] blur-2xl" />
      <div className="relative flex items-start justify-between gap-3">
        <div><p className="font-mono text-[8px] uppercase tracking-[0.16em] text-cyan-200/70">{eyebrow}</p><h3 className="mt-2 text-sm font-semibold text-slate-100">{title}</h3></div>
        <span className="grid h-9 w-9 place-items-center rounded-xl border border-cyan-300/15 bg-cyan-300/[0.06]"><Icon className="h-4 w-4 text-cyan-100" /></span>
      </div>
      <p className="relative mt-4 text-3xl font-semibold tracking-[-0.04em] text-white">{value}</p>
      <p className="relative mt-2 min-h-10 text-xs leading-5 text-slate-500">{description}</p>
      <Link href={href} className="relative mt-4 inline-flex items-center gap-1 text-xs font-medium text-cyan-200 hover:text-cyan-100">{action}<ArrowRight className="h-3.5 w-3.5" /></Link>
    </article>
  );
}

export function AIEcosystemWorkspace() {
  const [view, setView] = useState<EcosystemView>("organization");
  const [filters, setFilters] = useState<EcosystemFilters>(EMPTY_FILTERS);
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [actions, setActions] = useState<ListEnvelope<UserVisibilityAction> | null>(null);
  const [selectedDepartment, setSelectedDepartment] = useState<string | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [loadingActions, setLoadingActions] = useState(true);
  const [issues, setIssues] = useState<string[]>([]);

  const loadOverview = useCallback(async () => {
    setLoadingOverview(true);
    const results = await Promise.allSettled([
      api.userVisibilityOrganization(),
      api.userVisibilityDepartments({ page: 1, page_size: 50 }),
      api.userVisibilityGroups({ page: 1, page_size: 50 }),
      api.userVisibilityUsers({ page: 1, page_size: 100 }),
      api.getDiscoveryEstate(),
      api.listDiscoveryEcosystems({ page: 1, page_size: 200 }),
      api.listUnknownAI({ page: 1, page_size: 100 }),
      api.listAgents(),
      api.listAISystems(),
      api.listPolicyPackPlatformInstances(),
      api.executiveControlCoverage(),
      api.controlCoverage(),
      api.maturityCurveOverview(),
    ]);
    const [organization, departments, groups, users, estate, ecosystems, unknownAI, agents, systems, policyPacks, coverage, fallbackCoverage, maturity] = results;
    setOverview({
      organization: isFulfilled(organization) ? organization.value : null,
      departments: isFulfilled(departments) ? departments.value : null,
      groups: isFulfilled(groups) ? groups.value : null,
      users: isFulfilled(users) ? users.value : null,
      estate: isFulfilled(estate) ? estate.value : null,
      ecosystems: isFulfilled(ecosystems) ? ecosystems.value : null,
      unknownAI: isFulfilled(unknownAI) ? unknownAI.value : null,
      agents: isFulfilled(agents) ? agents.value : null,
      systems: isFulfilled(systems) ? systems.value : null,
      policyPacks: isFulfilled(policyPacks) ? policyPacks.value : null,
      coverage: isFulfilled(coverage) ? coverage.value : null,
      fallbackCoverage: isFulfilled(fallbackCoverage) ? fallbackCoverage.value : null,
      maturity: isFulfilled(maturity) ? maturity.value : null,
    });
    setIssues([
      requestFailure(organization, "Organization aggregate"),
      requestFailure(departments, "Department aggregate"),
      requestFailure(groups, "Group metadata"),
      requestFailure(users, "Named-user metadata"),
      requestFailure(estate, "AI estate"),
      requestFailure(ecosystems, "Ecosystem relationships"),
      requestFailure(unknownAI, "Unknown AI evidence"),
      requestFailure(agents, "Agent inventory"),
      requestFailure(policyPacks, "Policy Pack assignments"),
      requestFailure(coverage, "Executive Control Coverage"),
      requestFailure(maturity, "Maturity Curve"),
    ].filter((item): item is string => Boolean(item)));
    setLoadingOverview(false);
  }, []);

  const loadActions = useCallback(async () => {
    setLoadingActions(true);
    try {
      const result = await api.userVisibilityActions({
        ...(filters.department ? { department: filters.department } : {}),
        ...(filters.application ? { application: filters.application } : {}),
        ...(filters.surface ? { surface: filters.surface } : {}),
        page: 1,
        page_size: 100,
      });
      setActions(result);
    } catch (error) {
      setActions(null);
      const message = error instanceof Error ? error.message : "Activity is unavailable";
      setIssues((current) => Array.from(new Set([...current.filter((item) => !item.startsWith("Activity source:")), `Activity source: ${message}`])));
    } finally {
      setLoadingActions(false);
    }
  }, [filters.application, filters.department, filters.surface]);

  useEffect(() => { void loadOverview(); }, [loadOverview]);
  useEffect(() => { void loadActions(); }, [loadActions]);

  const departments = useMemo(() => overview?.departments?.items || [], [overview?.departments]);
  const directoryUsers = useMemo(() => overview?.users?.items || [], [overview?.users]);
  const actionRows = useMemo(() => actions?.items || [], [actions?.items]);
  const unknownAIItems = useMemo(() => overview?.unknownAI?.items || [], [overview?.unknownAI]);
  const observedActionTotal = actions?.total ?? actionRows.length;
  const canonicalAssetTotal = overview?.estate?.assets_total || 0;
  const unresolvedSignalTotal = unknownAIItems.length;
  const observedEvidenceTotal = Math.max(canonicalAssetTotal + unresolvedSignalTotal, observedActionTotal);
  const applications = useMemo(() => aggregate([
    ...(overview?.organization?.applications || []).flatMap((item) => Array.from({ length: Math.min(item.count, 20) }, () => item.name)),
    ...actionRows.map((item) => item.application),
  ]), [actionRows, overview?.organization?.applications]);
  const models = useMemo(() => aggregate(actionRows.map((item) => item.model)), [actionRows]);
  const tools = useMemo(() => aggregate(actionRows.map((item) => item.tool)), [actionRows]);
  const providers = useMemo(() => aggregate(actionRows.map((item) => item.provider)), [actionRows]);
  const accountClasses = useMemo(() => aggregate(actionRows.map((item) => item.account_class)), [actionRows]);
  const personalAccountEvents = useMemo(
    () => actionRows.filter((item) => String(item.account_class || "").toLowerCase().includes("personal")),
    [actionRows],
  );
  const classifiedPersonalEvents = useMemo(
    () => personalAccountEvents.filter((item) => !["", "unknown", "none", "unclassified"].includes(String(item.data_classification || "").toLowerCase())),
    [personalAccountEvents],
  );
  const actionSurfaces = useMemo(() => aggregate(actionRows.map((item) => item.source_surface)), [actionRows]);
  const hasControlCoverage = Boolean(overview?.coverage?.assessment_count || overview?.fallbackCoverage?.headline.counts.denominator);
  const selectedDepartmentSummary = departments.find((item) => item.department === selectedDepartment) || null;
  const selectedDepartmentActions = selectedDepartment ? actionRows.filter((item) => item.department === selectedDepartment) : actionRows;
  const selectedDepartmentUsers = selectedDepartment ? directoryUsers.filter((item) => item.department === selectedDepartment) : [];

  const attentionItems = useMemo<AttentionItem[]>(() => {
    const items: AttentionItem[] = [];
    if (classifiedPersonalEvents.length) {
      items.push({
        id: "personal-classified",
        title: `${classifiedPersonalEvents.length} personal-account action${classifiedPersonalEvents.length === 1 ? "" : "s"} with a known data classification`,
        detail: "Observed in the current tenant evidence. Review the account boundary and sensitive-data policy before expanding enforcement.",
        evidence: `${classifiedPersonalEvents.length} action receipt(s) · current filters`,
        href: "/users",
      });
    }
    for (const gap of overview?.coverage?.top_gaps || []) {
      items.push({
        id: `coverage-${gap.gap_id}`,
        title: `${readable(gap.coverage_state)} control state for ${readable(gap.asset_ref)}`,
        detail: gap.cause || gap.recommended_action || "Review the evidence-backed Control Coverage explanation.",
        evidence: `${gap.surface} · ${gap.evidence_refs.length} evidence reference(s)`,
        href: "/surface-coverage",
      });
    }
    if ((overview?.estate?.shadow_assets || 0) > 0) {
      items.push({
        id: "shadow-assets",
        title: `${overview?.estate?.shadow_assets} shadow AI asset${overview?.estate?.shadow_assets === 1 ? "" : "s"} in the known estate`,
        detail: "This is a discovery count, not a claim that every enterprise AI asset has been observed.",
        evidence: `Discovery estate refreshed ${dateLabel(overview?.estate?.generated_at)}`,
        href: "/discovery/unknown",
      });
    }
    if (unknownAIItems.length) {
      items.push({
        id: "unknown-ai-observed",
        title: `${unknownAIItems.length} unresolved AI signal${unknownAIItems.length === 1 ? "" : "s"} need owner review`,
        detail: "These are observed hypotheses or legacy Shadow AI records. They are visible evidence, but they are not counted as verified assets until reconciled.",
        evidence: `Latest signal ${dateLabel(unknownAIItems[0]?.last_seen_at)}`,
        href: "/discovery/unknown",
      });
    }
    if (overview?.policyPacks && overview.policyPacks.count === 0) {
      items.push({
        id: "no-policy-packs",
        title: "No Policy Pack instances reported",
        detail: "Use the Policy Pack workflow to preview, simulate, and apply a scoped Draft or Monitor rollout.",
        evidence: "Policy Pack instance query returned zero instances",
        href: "/policies",
      });
    }
    return items.slice(0, 5);
  }, [classifiedPersonalEvents.length, overview?.coverage?.top_gaps, overview?.estate?.generated_at, overview?.estate?.shadow_assets, overview?.policyPacks, unknownAIItems]);

  const coverageDistribution: Record<string, number> = overview?.coverage?.state_distribution ?? {};
  const maturityDistribution = overview?.maturity?.executive?.stage_distribution || {};
  const latestActionTimestamp = actionRows.map((item) => item.timestamp).find(Boolean) || null;
  const lastFreshness = overview?.coverage?.computed_at || overview?.estate?.generated_at || latestActionTimestamp || null;

  const selectDepartment = (department: string) => {
    setSelectedDepartment(department);
    setFilters((current) => ({ ...current, department }));
    setView("departments");
  };

  const refresh = () => {
    void loadOverview();
    void loadActions();
  };

  return (
    <section className="space-y-5" aria-label="AI Ecosystem">
      <header className="rounded-xl border border-white/[0.08] bg-[#0a1119] px-4 py-4 sm:px-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-cyan-200/80">AI ecosystem</p>
            <h1 className="mt-1 text-xl font-semibold tracking-tight text-white">AI ecosystem</h1>
            <p className="mt-1 max-w-3xl text-sm text-slate-400">Review AI assets, activity, relationships, and control status from the evidence available to this tenant.</p>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <Button type="button" variant="outline" size="sm" onClick={refresh} disabled={loadingOverview || loadingActions}><RefreshCw className={`mr-2 h-3.5 w-3.5 ${loadingOverview || loadingActions ? "animate-spin" : ""}`} />Refresh evidence</Button>
            <Link href="/policies"><Button type="button" size="sm"><ShieldCheck className="mr-2 h-3.5 w-3.5" />Open Policy Packs</Button></Link>
          </div>
        </div>
      </header>

      <div className="flex flex-wrap gap-2 border-b border-white/[0.08] pb-3" role="tablist" aria-label="AI Ecosystem visual modes">
        {VIEWS.map((item) => {
          const active = view === item.id;
          return <button key={item.id} type="button" role="tab" aria-selected={active} onClick={() => setView(item.id)} className={`shrink-0 rounded-xl border px-3 py-2 text-left transition ${active ? "border-cyan-300/35 bg-cyan-300/[0.08] text-cyan-100" : "border-transparent text-slate-500 hover:border-white/[0.08] hover:bg-white/[0.03] hover:text-slate-200"}`}><span className="block text-sm font-medium">{item.label}</span><span className="mt-0.5 block font-mono text-[8px] uppercase tracking-[0.12em] opacity-70">{item.note}</span></button>;
        })}
      </div>

      <section className="rounded-2xl border border-white/[0.07] bg-[#0c131d] p-4" aria-label="Ecosystem filters">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-end xl:justify-between">
          <div><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Evidence filters</p><p className="mt-1 text-xs text-slate-500">Filters refine the activity evidence shown below. Other evidence summaries update when you refresh the workspace.</p></div>
          <div className="grid gap-2 sm:grid-cols-3">
            <select aria-label="Filter AI Ecosystem by department" value={filters.department} onChange={(event) => { setSelectedDepartment(event.target.value || null); setFilters((current) => ({ ...current, department: event.target.value })); }} className="h-9 rounded-md border border-[#2c3a50] bg-[#0a1018] px-3 text-xs text-slate-200"><option value="">All departments</option>{departments.map((department) => <option key={department.department} value={department.department}>{department.department}</option>)}</select>
            <select aria-label="Filter AI Ecosystem by application" value={filters.application} onChange={(event) => setFilters((current) => ({ ...current, application: event.target.value }))} className="h-9 rounded-md border border-[#2c3a50] bg-[#0a1018] px-3 text-xs text-slate-200"><option value="">All applications</option>{applications.map((application) => <option key={application.value} value={application.value}>{application.value}</option>)}</select>
            <select aria-label="Filter AI Ecosystem by deployment surface" value={filters.surface} onChange={(event) => setFilters((current) => ({ ...current, surface: event.target.value }))} className="h-9 rounded-md border border-[#2c3a50] bg-[#0a1018] px-3 text-xs text-slate-200"><option value="">All surfaces</option>{Object.entries(SURFACE_LABELS).map(([key, surface]) => <option key={key} value={key}>{surface.label}</option>)}</select>
          </div>
        </div>
      </section>

      {issues.length ? <section role="status" className="rounded-2xl border border-amber-300/15 bg-amber-300/[0.04] px-4 py-3 text-xs leading-5 text-amber-100/75"><div className="flex items-start gap-2"><CircleHelp className="mt-0.5 h-4 w-4 shrink-0 text-amber-200" /><div><p className="font-medium text-amber-100">Some source data is unavailable.</p><p className="mt-1">Affected relationships remain Unknown until the source is connected or responds.</p><details className="mt-2"><summary className="cursor-pointer text-amber-100/80">Technical details</summary><p className="mt-2 break-words font-mono text-[10px] text-amber-100/55">{issues.join(" · ")}</p></details></div></div></section> : null}

      <details className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3">
        <summary className="cursor-pointer text-xs font-medium text-slate-300">Evidence summary <span className="ml-2 text-[10px] font-normal text-slate-600">Counts and freshness from current source responses</span></summary>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard label="Observed AI evidence" value={availableCount(observedEvidenceTotal, "Needs source")} note={`${countLabel(canonicalAssetTotal)} verified/canonical · ${countLabel(unresolvedSignalTotal)} unresolved signal${unresolvedSignalTotal === 1 ? "" : "s"} · ${countLabel(observedActionTotal)} observed action${observedActionTotal === 1 ? "" : "s"}.`} />
          <MetricCard label="Active AI users" value={availableCount(overview?.organization?.user_count ?? overview?.users?.total)} note="Tenant-scoped aggregate in the selected lookback window." tone="text-cyan-100" />
          <MetricCard label="Policy Pack instances" value={availableCount(overview?.policyPacks?.count, "Set up packs")} note="Existing instances; rollout state remains separately visible." tone="text-violet-100" />
          <MetricCard label="Last evidence received" value={lastFreshness ? dateLabel(lastFreshness) : "No signal yet"} note="Freshness is displayed instead of treating old data as current." tone="text-amber-100" />
        </div>
      </details>

      {view === "organization" ? (
        <section className="space-y-5">
          <div className="grid gap-3 lg:grid-cols-[1.15fr_1.6fr_1.15fr]">
            <RelationshipCard eyebrow="Root node" title="Organization" value={availableCount(overview?.organization?.user_count ?? overview?.users?.total)} description={`${countLabel(overview?.organization?.action_count)} actions in the aggregate window. User names remain outside this default visual.`} href="/users" action="Open user aggregates" icon={UsersRound} />
            <article className="relative overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0c141e] p-4">
              <div className="absolute left-7 right-7 top-[62px] h-px bg-gradient-to-r from-cyan-300/10 via-cyan-300/55 to-cyan-300/10" />
              <div className="relative flex items-center justify-between gap-3"><div><p className="font-mono text-[8px] uppercase tracking-[0.16em] text-cyan-200/70">Observed organizational spread</p><h2 className="mt-2 text-sm font-semibold text-slate-100">Departments and groups</h2></div><span className="font-mono text-xs text-slate-500">{countLabel(departments.length)} dept · {countLabel(overview?.groups?.total)} groups</span></div>
              <div className="relative mt-5 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {departments.slice(0, 6).map((department) => <button key={department.department} type="button" onClick={() => selectDepartment(department.department)} className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3 text-left transition hover:border-cyan-300/25 hover:bg-cyan-300/[0.04]"><p className="truncate text-sm font-medium text-slate-100">{department.department}</p><p className="mt-1 text-[11px] text-slate-500">{department.user_count} users · {department.action_count} actions</p><p className="mt-2 font-mono text-[8px] uppercase tracking-wider text-cyan-200/70">Observed {dateLabel(department.last_ai_activity)}</p></button>)}
                {!departments.length && <div className="col-span-full rounded-xl border border-dashed border-amber-300/20 bg-amber-300/[0.03] px-4 py-7 text-center text-xs text-amber-100/75">Department mapping needs an identity source. Connect IdP/SCIM or import departments to turn observed users into an organization view.</div>}
              </div>
            </article>
            <RelationshipCard eyebrow="Evidence resolution" title="AI ecosystems" value={availableCount((overview?.ecosystems?.total || 0) + unknownAIItems.length)} description={`${countLabel(overview?.ecosystems?.total)} resolved ecosystem${overview?.ecosystems?.total === 1 ? "" : "s"} · ${countLabel(unknownAIItems.length)} unresolved provider/environment signal${unknownAIItems.length === 1 ? "" : "s"}.`} href="/discovery/ecosystems" action="Inspect relationships" icon={Network} />
          </div>

          <div className="grid gap-3 xl:grid-cols-3">
            <RelationshipCard eyebrow="Usage path" title="Applications & accounts" value={availableCount(applications.length || unknownAIItems.length)} description={`${evidenceListLabel(accountClasses, unknownAIItems.length ? `${unknownAIItems.length} unresolved AI application signal${unknownAIItems.length === 1 ? "" : "s"} awaiting account classification.` : "Needs account classification evidence from browser, provider, or IdP source.")}`} href="/users" action="Open activity" icon={Boxes} />
            <RelationshipCard eyebrow="Runtime path" title="Agents & models" value={availableCount(overview?.agents?.total, models.length ? "Observed models" : "Needs runtime source")} description={`${evidenceListLabel(models, "Needs model evidence from browser/provider/runtime events.")}`} href="/ai-iam" action="Open AI IAM" icon={Sparkles} />
            <RelationshipCard eyebrow="Control overlay" title="Policies & controls" value={availableCount(overview?.policyPacks?.count, hasControlCoverage ? "Coverage observed" : "Needs policy setup")} description={`${overview?.coverage ? `${overview.coverage.assessment_count} coverage assessment(s)` : "Connect or recompute Control Coverage."} ${Object.entries(maturityDistribution).map(([stage, count]) => `${readable(stage)} · ${count}`).join(" · ") || "Maturity needs connected evidence."}`} href="/policies" action="Open Policy Packs" icon={ShieldCheck} />
          </div>

          <section className="rounded-2xl border border-white/[0.07] bg-[#0c141e] p-5"><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-200/70">Observed activity path</p><h2 className="mt-2 text-lg font-semibold text-slate-100">User / agent → application → model → tool → destination</h2><p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">This path uses the tenant evidence available for each step. Raw prompt content is not included in the ecosystem or executive view.</p></div><Link href="/runtime-intelligence/activity-map" className="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-cyan-200 hover:text-cyan-100">Open activity lineage <ArrowRight className="h-3.5 w-3.5" /></Link></div><div className="mt-5 grid gap-2 md:grid-cols-5">{[["Applications", applications, "Needs browser/provider evidence"], ["Providers", providers, "Needs provider or URL evidence"], ["Models", models, "Needs model metadata"], ["Tools / MCP", tools, "Needs MCP/runtime event"], ["Destinations", aggregate(actionRows.map((item) => item.destination)), "Needs destination evidence"]].map(([label, values, fallback]) => <div key={String(label)} className="min-h-28 rounded-xl border border-white/[0.06] bg-black/15 p-3"><p className="font-mono text-[8px] uppercase tracking-[0.14em] text-slate-600">{String(label)}</p><div className="mt-3 space-y-1.5">{(values as Array<{ value: string; count: number }>).map((item) => <p key={item.value} className="truncate text-xs text-slate-200" title={item.value}>{item.value}<span className="ml-1 text-slate-500">{item.count}</span></p>)}{!(values as Array<unknown>).length && <p className="text-xs text-amber-100/65">{String(fallback)}</p>}</div></div>)}</div></section>
        </section>
      ) : null}

      {view === "departments" ? <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(330px,.75fr)]"><div className="space-y-3">{departments.map((department) => <button key={department.department} type="button" onClick={() => selectDepartment(department.department)} className={`w-full rounded-2xl border p-4 text-left transition ${selectedDepartment === department.department ? "border-cyan-300/35 bg-cyan-300/[0.06]" : "border-white/[0.07] bg-[#0d151f] hover:border-white/[0.14]"}`}><div className="flex items-start justify-between gap-4"><div><p className="font-mono text-[8px] uppercase tracking-[0.15em] text-cyan-200/70">Department aggregate</p><p className="mt-2 text-base font-semibold text-slate-100">{department.department}</p></div><ChevronRight className="h-4 w-4 text-slate-500" /></div><div className="mt-4 grid grid-cols-3 gap-2 text-center"><div><p className="font-mono text-lg text-white">{department.user_count}</p><p className="text-[9px] text-slate-600">Users</p></div><div><p className="font-mono text-lg text-white">{department.action_count}</p><p className="text-[9px] text-slate-600">Actions</p></div><div><p className="truncate font-mono text-[10px] text-slate-300">{dateLabel(department.last_ai_activity)}</p><p className="mt-1 text-[9px] text-slate-600">Last activity</p></div></div></button>)}{!departments.length && <div className="rounded-2xl border border-dashed border-white/[0.10] p-8 text-center text-sm text-slate-500">No authorized department aggregate is available.</div>}</div><aside className="rounded-2xl border border-white/[0.07] bg-[#0c141e] p-5"><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-200/70">Department detail</p>{selectedDepartmentSummary ? <div className="mt-3 space-y-5"><div><h2 className="text-xl font-semibold text-white">{selectedDepartmentSummary.department}</h2><p className="mt-1 text-xs text-slate-500">{selectedDepartmentSummary.user_count} visible users · {selectedDepartmentSummary.action_count} recorded actions</p></div><div className="grid grid-cols-2 gap-2"><MetricCard label="Selected actions" value={countLabel(actions?.total)} note="Activity evidence matching the selected filters." /><MetricCard label="Named users" value={countLabel(selectedDepartmentUsers.length)} note="Shown only where existing RBAC permits metadata." /></div><div><p className="font-mono text-[8px] uppercase tracking-wider text-slate-500">Top applications in current result</p><div className="mt-2 flex flex-wrap gap-1.5">{aggregate(selectedDepartmentActions.map((item) => item.application)).map((item) => <span key={item.value} className="rounded-full border border-cyan-300/15 bg-cyan-300/[0.05] px-2 py-1 text-[10px] text-cyan-100">{item.value} · {item.count}</span>)}{!selectedDepartmentActions.length && <span className="text-xs text-slate-600">Unknown</span>}</div></div><div><p className="font-mono text-[8px] uppercase tracking-wider text-slate-500">Authorized User 360 shortcuts</p><div className="mt-2 space-y-2">{selectedDepartmentUsers.slice(0, 5).map((user) => <Link key={user.user_id} href={`/users?user_id=${encodeURIComponent(user.user_id)}`} className="flex items-center justify-between rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-xs text-slate-300 hover:border-cyan-300/25 hover:text-cyan-100"><span className="truncate">{user.display_name || user.email || "Authorized user"}</span><span className="shrink-0 text-cyan-200">Open User 360</span></Link>)}{!selectedDepartmentUsers.length && <p className="text-xs leading-5 text-slate-600">Named user metadata is unavailable or no directory result was returned for this department.</p>}</div></div><div className="flex flex-wrap gap-2"><Link href={`/runtime-intelligence/activity-map?department=${encodeURIComponent(selectedDepartmentSummary.department)}`}><Button type="button" size="sm" variant="outline">Open activity lineage</Button></Link><Link href="/policies"><Button type="button" size="sm">Open Policy Packs</Button></Link></div></div> : <div className="mt-4 rounded-xl border border-dashed border-white/[0.10] p-5 text-sm leading-6 text-slate-500">Select an authorized department to inspect its aggregate evidence and existing drill-downs.</div>}</aside></section> : null}

      {view === "surfaces" ? <section className="space-y-5"><div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">{Object.entries(SURFACE_LABELS).map(([surface, meta]) => { const distribution = overview?.coverage?.surface_breakdown?.[surface]; const observed = actionSurfaces.find((item) => item.value.toLowerCase() === surface)?.count; return <article key={surface} className="rounded-2xl border border-white/[0.07] bg-[#0d151f] p-4"><div className="flex items-start justify-between gap-3"><div><p className="font-mono text-[8px] uppercase tracking-[0.15em] text-cyan-200/70">Control surface</p><h2 className="mt-2 text-base font-semibold text-white">{meta.label}</h2></div><Layers3 className="h-4 w-4 text-cyan-200" /></div><p className="mt-3 min-h-12 text-xs leading-5 text-slate-500">{meta.description}</p><p className="mt-4 font-mono text-xl text-slate-100">{countLabel(observed)}</p><p className="mt-1 text-[10px] text-slate-600">Observed actions in current result</p><div className="mt-4 flex flex-wrap gap-1.5">{distribution ? Object.entries(distribution).filter(([, count]) => Number(count) > 0).map(([state, count]) => <span key={state} title={`${state}: ${count}`}><StatusPill state={state} /></span>) : <StatusPill state="unknown" />}</div></article>; })}</div><section className="rounded-2xl border border-white/[0.07] bg-[#0c141e] p-5"><div className="flex items-start justify-between gap-3"><div><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-200/70">Control Coverage</p><h2 className="mt-2 text-lg font-semibold text-white">Current assurance is distinct from connector presence.</h2><p className="mt-2 max-w-3xl text-xs leading-5 text-slate-500">A surface remains Partial, Stale, Regressed, Unsupported, or Unknown until existing Control Coverage evidence says otherwise. Post-event evidence is not presented as pre-execution enforcement.</p></div><Link href="/surface-coverage" className="shrink-0 text-xs font-medium text-cyan-200 hover:text-cyan-100">Open Control Coverage <ArrowRight className="inline h-3.5 w-3.5" /></Link></div><div className="mt-5 flex flex-wrap gap-2">{Object.entries(COVERAGE_LABELS).filter(([state]) => state !== "not_applicable").map(([state]) => <span key={state} className="flex items-center gap-2 rounded-xl border border-white/[0.06] bg-black/15 px-3 py-2"><StatusPill state={state} /><span className="font-mono text-sm text-slate-100">{coverageDistribution[state] ?? "—"}</span></span>)}</div></section></section> : null}

      {view === "policies" ? <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]"><div className="space-y-3">{(overview?.policyPacks?.items || []).map((pack) => <article key={pack.id} className="rounded-2xl border border-white/[0.07] bg-[#0d151f] p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-mono text-[8px] uppercase tracking-[0.15em] text-violet-200/70">{readable(pack.selected_vertical)} · {readable(pack.selected_department_persona)}</p><h2 className="mt-2 text-base font-semibold text-white">{pack.source_pack_id}</h2><p className="mt-1 text-xs text-slate-500">v{pack.source_pack_version} · {pack.selected_applications.length} selected apps · {pack.selected_surfaces.length} selected surfaces</p></div><span className="rounded-full border border-violet-300/20 bg-violet-300/[0.07] px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-violet-100">{readable(pack.state)}</span></div><div className="mt-4 flex flex-wrap gap-1.5">{pack.selected_surfaces.map((surface) => <span key={surface} className="rounded-full border border-white/[0.08] bg-black/15 px-2 py-1 text-[10px] text-slate-400">{readable(surface)}</span>)}{pack.update_available && <span className="rounded-full border border-amber-300/20 bg-amber-300/[0.07] px-2 py-1 text-[10px] text-amber-100">Update available</span>}</div></article>)}{overview?.policyPacks && overview.policyPacks.count === 0 ? <div className="rounded-2xl border border-dashed border-white/[0.10] p-8 text-center text-sm leading-6 text-slate-500">No Policy Pack instance is present in this tenant response. The existing workflow can create a Draft or Monitor rollout directly, while stronger enforcement retains approval gates.</div> : null}{!overview?.policyPacks ? <div className="rounded-2xl border border-dashed border-amber-300/15 bg-amber-300/[0.025] p-8 text-center text-sm leading-6 text-amber-100/70">Policy Pack assignment visibility is Unknown for this role or tenant.</div> : null}</div><aside className="rounded-2xl border border-violet-300/15 bg-violet-300/[0.04] p-5"><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-violet-200/70">Policy Pack overlay</p><h2 className="mt-2 text-lg font-semibold text-white">Preview, simulate, then stage scope.</h2><p className="mt-2 text-xs leading-5 text-slate-400">The established Policy Pack wizard exposes inheritance, capability coverage, blind spots, parameters, simulation, and authorization rules. This ecosystem page never bypasses that workflow.</p><Link href="/policies" className="mt-5 inline-flex items-center gap-1 text-xs font-medium text-violet-100 hover:text-white">Open Policy Packs <ArrowRight className="h-3.5 w-3.5" /></Link></aside></section> : null}

      {view === "attention" ? <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]"><div className="space-y-3">{attentionItems.map((item) => <Link key={item.id} href={item.href} className="block rounded-2xl border border-white/[0.07] bg-[#0d151f] p-4 transition hover:border-amber-300/25 hover:bg-amber-300/[0.035]"><div className="flex items-start gap-3"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-amber-300/20 bg-amber-300/[0.07]"><AlertTriangle className="h-4 w-4 text-amber-200" /></span><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold text-slate-100">{item.title}</h2><p className="mt-2 text-xs leading-5 text-slate-400">{item.detail}</p><p className="mt-3 font-mono text-[8px] uppercase tracking-[0.12em] text-amber-100/70">Evidence · {item.evidence}</p></div><ChevronRight className="mt-1 h-4 w-4 shrink-0 text-slate-600" /></div></Link>)}{!attentionItems.length && <div className="rounded-2xl border border-dashed border-white/[0.10] p-8 text-center text-sm leading-6 text-slate-500">No evidence-backed attention item is available in the current tenant snapshot. This is not a claim that the organization is risk-free.</div>}</div><aside className="rounded-2xl border border-white/[0.07] bg-[#0c141e] p-5"><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-200/70">Executive guidance</p><h2 className="mt-2 text-lg font-semibold text-white">What leadership should do next</h2><ol className="mt-4 space-y-3 text-xs leading-5 text-slate-400"><li className="rounded-xl border border-white/[0.06] bg-black/15 p-3">Review the highest-priority evidence item and its current control state.</li><li className="rounded-xl border border-white/[0.06] bg-black/15 p-3">Use Policy Packs to simulate scoped Monitor rollouts before enforcement.</li><li className="rounded-xl border border-white/[0.06] bg-black/15 p-3">Revalidate stale, regressed, Unsupported, and Unknown deployment surfaces.</li></ol></aside></section> : null}

      {view === "table" ? <section className="space-y-5"><div className="flex items-start justify-between gap-4"><div><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-200/70">Accessible list fallback</p><h2 className="mt-2 text-lg font-semibold text-white">The same selected evidence in structured form</h2><p className="mt-2 text-xs text-slate-500">Rows reflect the activity evidence and authorized aggregate sources available to this tenant.</p></div><Table2 className="h-5 w-5 text-cyan-200" /></div><div role="table" aria-label="AI Ecosystem structured fallback" className="overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0d151f]"><div role="row" className="grid grid-cols-[1.2fr_.8fr_.8fr_.8fr_.8fr] gap-3 border-b border-white/[0.07] bg-white/[0.03] px-4 py-3 font-mono text-[8px] uppercase tracking-[0.14em] text-slate-500"><span role="columnheader">Department</span><span role="columnheader">Application</span><span role="columnheader">Model</span><span role="columnheader">Tool</span><span role="columnheader">Control state</span></div>{actionRows.map((item) => <div key={item.action_id} role="row" className="grid grid-cols-[1.2fr_.8fr_.8fr_.8fr_.8fr] gap-3 border-b border-white/[0.05] px-4 py-3 text-xs text-slate-300 last:border-0"><span role="cell" className="truncate">{item.department || "Unknown"}</span><span role="cell" className="truncate">{item.application || "Unknown"}</span><span role="cell" className="truncate">{item.model || "Unknown"}</span><span role="cell" className="truncate">{item.tool || "Unknown"}</span><span role="cell"><StatusPill state={String(item.control_state || "unknown").toLowerCase()} /></span></div>)}{!actionRows.length && <div role="row" className="px-4 py-8 text-center text-sm text-slate-500">No action metadata is available for the selected filters.</div>}</div></section> : null}

      <details className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3">
        <summary className="cursor-pointer text-xs font-medium text-slate-300">Evidence rules and source detail</summary>
        <div className="mt-3 space-y-3">
          <EvidenceTruthPanel
            title="AI ecosystem evidence"
            description="Known AI, unresolved signals, and source gaps stay separate so this view never turns missing evidence into a claim."
            whyUnknown="Unknown appears when Hawk has activity without enough source-backed identity, account, model, department, or surface evidence to turn it into a verified graph fact. Connect authoritative source evidence or inspect the unresolved signal queue."
            lastEvidence={lastFreshness}
            connectHref="/integrations"
            testHref="/validate"
            sourceMode={observedEvidenceTotal || actionRows.length ? "observed" : "unknown"}
            facts={[
              { label: "Verified/canonical assets", value: countLabel(canonicalAssetTotal), detail: "Connect authoritative source records before treating observed activity as a known enterprise asset.", tone: canonicalAssetTotal ? "verified" : "unknown" },
              { label: "Human / agent / service identity", value: countLabel((overview?.users?.total || 0) + (overview?.agents?.total || 0)), detail: "Human users, AI agents and service/workload accounts stay distinct when source evidence exists.", tone: overview?.users?.total || overview?.agents?.total ? "observed" : "unknown" },
              { label: "Model / frontier model used", value: models.length ? models.map((model) => model.value).join(", ") : "Unavailable", detail: "Model use is shown from action evidence; frontier classification needs model/provider metadata.", tone: models.length ? "observed" : "unknown" },
              { label: "Policy pack / framework impact", value: countLabel(overview?.policyPacks?.count), detail: "Framework-mapped policy packs remain visible separately from compliance claims.", tone: overview?.policyPacks?.count ? "verified" : "unknown" },
              { label: "Real-time event freshness", value: lastFreshness ? dateLabel(lastFreshness) : "Unavailable", detail: "Freshness is surfaced so stale evidence is not presented as current.", tone: lastFreshness ? "observed" : "unknown" },
              { label: "Observed-but-not-canonical actions", value: countLabel(observedActionTotal), detail: "Canonical assets remain separate from raw observed action evidence until identity and source binding are reconciled.", tone: observedActionTotal ? "observed" : "unknown" },
            ]}
          />
          <p className="text-xs leading-5 text-slate-500">Known graph relationships, unresolved signals, and missing denominators are separate. This page uses only existing discovery, identity, activity, policy, control coverage, and maturity records.</p>
        </div>
      </details>

      <footer className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-3 text-xs text-slate-500"><span><Eye className="mr-1 inline h-3.5 w-3.5 text-cyan-200" />Raw prompt content is not included. Individual detail follows the existing audited reveal workflow.</span><span>{loadingOverview || loadingActions ? "Loading activity evidence…" : issues.length ? "Some activity evidence is unavailable" : "Activity evidence is current to the selected filters"}</span></footer>
    </section>
  );
}
