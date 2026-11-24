"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  CircleDot,
  GitCompareArrows,
  Layers3,
  Radar,
  RefreshCw,
  Route,
  Search,
  ShieldCheck,
} from "lucide-react";

import { PathExplorer } from "@/components/control-coverage/path-explorer";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type {
  ExecutiveControlCoverageSummary,
  ExecutiveCoverageAssessmentExplanation,
  ExecutiveCoverageDistribution,
  ExecutiveCoverageGap,
  ExecutiveCoverageState,
} from "@/lib/types";

const STATE_ORDER: ExecutiveCoverageState[] = [
  "covered_current",
  "covered_stale",
  "partially_covered",
  "configured_unvalidated",
  "regressed",
  "gap",
  "unsupported",
  "unknown",
  "not_applicable",
];

const STATE_META: Record<ExecutiveCoverageState, { label: string; short: string; dot: string; text: string; bar: string }> = {
  covered_current: { label: "Current", short: "Current", dot: "bg-emerald-300", text: "text-emerald-200", bar: "#6ee7b7" },
  covered_stale: { label: "Stale", short: "Stale", dot: "bg-amber-300", text: "text-amber-200", bar: "#fcd34d" },
  partially_covered: { label: "Partial", short: "Partial", dot: "bg-cyan-300", text: "text-cyan-200", bar: "#67e8f9" },
  configured_unvalidated: { label: "Configured · unvalidated", short: "Unvalidated", dot: "bg-indigo-300", text: "text-indigo-200", bar: "#a5b4fc" },
  regressed: { label: "Regressed", short: "Regressed", dot: "bg-rose-300", text: "text-rose-200", bar: "#fda4af" },
  gap: { label: "Gap", short: "Gap", dot: "bg-orange-300", text: "text-orange-200", bar: "#fdba74" },
  unsupported: { label: "Unsupported", short: "Unsupported", dot: "bg-slate-500", text: "text-slate-300", bar: "#64748b" },
  unknown: { label: "Unknown", short: "Unknown", dot: "bg-fuchsia-300", text: "text-fuchsia-200", bar: "#f0abfc" },
  not_applicable: { label: "Not applicable", short: "N/A", dot: "bg-slate-700", text: "text-slate-500", bar: "#334155" },
};

const SURFACES = [
  { key: "browser", label: "Browser", description: "Application and account context; exact tool semantics require a verified browser control point." },
  { key: "endpoint", label: "Endpoint", description: "OS consequence controls for files, processes, and networks; semantic intent remains a separate fact." },
  { key: "runtime", label: "Runtime", description: "Native or SDK action binding at the point where the AI runtime can authorize execution." },
  { key: "saas_api", label: "SaaS & APIs", description: "Provider, connector, and gateway evidence without assuming the endpoint or browser is governed." },
] as const;

function formatPercent(value: number | null): string {
  if (value === null) return "—";
  return `${value.toFixed(value % 1 === 0 ? 0 : 1)}%`;
}

function titleCase(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function StatePill({ state }: { state: ExecutiveCoverageState }) {
  const meta = STATE_META[state];
  return (
    <span className={`inline-flex items-center gap-1.5 border border-white/10 bg-white/[0.035] px-2 py-1 text-[10px] font-medium ${meta.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

function DistributionBar({ distribution }: { distribution: ExecutiveCoverageDistribution }) {
  const total = STATE_ORDER.reduce((sum, state) => sum + (distribution[state] ?? 0), 0);
  if (!total) return <div className="h-2 bg-[#242b3b]" />;
  return (
    <div className="flex h-2 overflow-hidden bg-[#242b3b]" aria-label={`${total} assessed requirements`}>
      {STATE_ORDER.map((state) => {
        const count = distribution[state] ?? 0;
        return count ? (
          <span
            key={state}
            title={`${STATE_META[state].label}: ${count}`}
            style={{ width: `${(count / total) * 100}%`, backgroundColor: STATE_META[state].bar }}
          />
        ) : null;
      })}
    </div>
  );
}

function DistributionLegend({ distribution }: { distribution: ExecutiveCoverageDistribution }) {
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3 xl:grid-cols-5">
      {STATE_ORDER.map((state) => (
        <div key={state} className="flex items-center gap-2 text-[10px]">
          <span className={`h-1.5 w-1.5 rounded-full ${STATE_META[state].dot}`} />
          <span className="text-slate-500">{STATE_META[state].short}</span>
          <span className="ml-auto font-mono text-slate-200">{distribution[state] ?? 0}</span>
        </div>
      ))}
    </div>
  );
}

function EmptyCoverage({ error, onGenerate, busy }: { error: string | null; onGenerate: () => void; busy: boolean }) {
  return (
    <section className="rounded-xl border border-amber-400/25 bg-[#0e141e] p-7">
      <div className="flex max-w-3xl items-start gap-4">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" />
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-amber-300">No executive snapshot</div>
          <h2 className="mt-2 text-xl font-semibold text-slate-50">Coverage is not inferred from incomplete telemetry</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Generate a tenant-scoped snapshot from Hawk&apos;s existing deployment, capability, assurance, bypass, evidence, and lineage records.
          </p>
          {error ? <p className="mt-3 text-xs text-amber-200/80">{error}</p> : null}
          <Button className="mt-5" size="sm" onClick={onGenerate} disabled={busy}>
            <RefreshCw className={`mr-2 h-3.5 w-3.5 ${busy ? "animate-spin" : ""}`} />
            Generate evidence-backed snapshot
          </Button>
        </div>
      </div>
    </section>
  );
}

function GapCard({ gap, active, onSelect }: { gap: ExecutiveCoverageGap; active: boolean; onSelect: () => void }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`w-full border p-3.5 text-left transition ${active ? "border-cyan-300/50 bg-cyan-300/[0.07]" : "border-[#2a3448] bg-[#111722] hover:border-[#42506a]"}`}
    >
      <div className="flex items-center gap-2">
        <span className={`font-mono text-[10px] ${gap.priority === "P0" ? "text-rose-300" : gap.priority === "P1" ? "text-orange-300" : "text-amber-200"}`}>{gap.priority}</span>
        <StatePill state={gap.coverage_state} />
        <span className="ml-auto text-[10px] uppercase tracking-wider text-slate-600">{titleCase(gap.surface)}</span>
      </div>
      <div className="mt-3 text-sm font-medium text-slate-100">{gap.asset_ref}</div>
      <div className="mt-1 text-[11px] text-slate-500">{titleCase(gap.action_class)} · {titleCase(gap.dimension)}</div>
      <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-400">{gap.cause}</p>
    </button>
  );
}

function FactList({ title, values, empty }: { title: string; values: string[]; empty: string }) {
  return (
    <div>
      <div className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-600">{title}</div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {values.length ? values.map((value) => (
          <span key={value} className="max-w-full truncate border border-[#2b3549] bg-[#0d121b] px-2 py-1 font-mono text-[9px] text-slate-400" title={value}>{value}</span>
        )) : <span className="text-[11px] text-slate-600">{empty}</span>}
      </div>
    </div>
  );
}

function AssessmentDetail({ detail }: { detail: ExecutiveCoverageAssessmentExplanation }) {
  const safeLinks = detail.investigation_links.filter((value) => value.startsWith("/runtime-intelligence/"));
  return (
    <section className="border border-cyan-300/20 bg-[#0d141e] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan-300">Why this state exists</div>
          <h4 className="mt-2 text-sm font-semibold text-slate-100">{detail.requirement}</h4>
          <p className="mt-2 text-xs leading-5 text-slate-400">{detail.explanation}</p>
        </div>
        <StatePill state={detail.coverage_state} />
      </div>

      <div className="mt-4 grid gap-px overflow-hidden border border-[#293247] bg-[#293247] sm:grid-cols-2">
        {[
          ["Applicability", `${detail.applicability.state} · ${detail.applicability.reason}`],
          ["Deployment", detail.deployment_state],
          ["Capability", detail.capability_state],
          ["Assurance", detail.assurance_state],
          ["Evidence quality", detail.evidence_quality],
          ["Control plan", detail.control_plan_ref ?? "No plan reference"],
        ].map(([label, value]) => (
          <div key={label} className="bg-[#101722] p-3">
            <div className="text-[9px] uppercase tracking-wider text-slate-600">{label}</div>
            <div className="mt-1 break-words text-[11px] text-slate-300">{value}</div>
          </div>
        ))}
      </div>

      <div className="mt-4 space-y-4">
        <FactList title="Expected control points" values={detail.expected_control_points} empty="None declared" />
        <FactList title="Contributing control points" values={detail.contributing_control_points} empty="No verified contribution" />
        <FactList title="Missing contributions" values={detail.missing_contributions} empty="No missing contribution recorded" />
      </div>

      <div className="mt-4 grid gap-4 border-t border-[#273146] pt-4 lg:grid-cols-2">
        <FactList title="Validation and bypass evidence" values={[...detail.validation_refs, ...detail.bypass_refs]} empty="No validation or bypass reference" />
        <FactList title="Phase 7 lineage" values={detail.lineage_refs} empty="No correlated lineage reference" />
      </div>
      {safeLinks.length ? (
        <div className="mt-4 flex flex-wrap gap-2">
          {safeLinks.map((link) => (
            <a key={link} href={link} className="inline-flex items-center gap-1 text-[10px] font-medium text-cyan-300 hover:text-cyan-200">
              Open investigation <ArrowRight className="h-3 w-3" />
            </a>
          ))}
        </div>
      ) : null}
    </section>
  );
}

export function ControlCoveragePanel() {
  const [summary, setSummary] = useState<ExecutiveControlCoverageSummary | null>(null);
  const [detail, setDetail] = useState<ExecutiveCoverageAssessmentExplanation | null>(null);
  const [selectedAssessment, setSelectedAssessment] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const payload = await api.executiveControlCoverage();
      setSummary(payload);
      setError(null);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Executive Control Coverage is unavailable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      const payload = await api.refreshExecutiveControlCoverage();
      setSummary(payload);
      setDetail(null);
      setSelectedAssessment(null);
      setError(null);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Snapshot generation failed");
    } finally {
      setRefreshing(false);
    }
  }, []);

  const selectGap = useCallback(async (gap: ExecutiveCoverageGap) => {
    setSelectedAssessment(gap.assessment_id);
    setDetailLoading(true);
    try {
      setDetail(await api.executiveControlCoverageAssessment(gap.assessment_id));
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Assessment explanation is unavailable");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const coverageArc = summary?.validated_coverage_percent === null || summary?.validated_coverage_percent === undefined
    ? 0
    : Math.max(0, Math.min(100, summary.validated_coverage_percent));
  const change = summary?.change_since_previous;
  const transitionRows = useMemo(() => Object.entries(change?.transitions ?? {}), [change?.transitions]);

  if (loading && !summary) {
    return (
      <section aria-label="Loading Control Coverage" className="overflow-hidden rounded-xl border border-[#2a3348] bg-[#0d121b]">
        <div className="h-1 bg-cyan-300/50" />
        <div className="grid animate-pulse gap-5 p-6 xl:grid-cols-[280px_1fr]"><div className="h-64 bg-[#171e2a]" /><div className="h-64 bg-[#171e2a]" /></div>
      </section>
    );
  }

  if (!summary) return <EmptyCoverage error={error} onGenerate={() => void refresh()} busy={refreshing} />;

  return (
    <section
      className="relative overflow-hidden rounded-xl border border-[#2a3348] bg-[#0a0f17]"
      style={{ backgroundImage: "radial-gradient(circle at 88% 0%, rgba(34,211,238,.09), transparent 27%), linear-gradient(rgba(64,78,105,.08) 1px, transparent 1px), linear-gradient(90deg, rgba(64,78,105,.08) 1px, transparent 1px)", backgroundSize: "auto, 30px 30px, 30px 30px" }}
    >
      <div className="h-1 bg-gradient-to-r from-emerald-300 via-cyan-300 to-indigo-300" />
      <div className="p-5 md:p-7">
        <header className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.24em] text-cyan-300">Evidence-backed enterprise control atlas</div>
            <h2 className="mt-2 text-2xl font-semibold tracking-tight text-slate-50">Control Coverage</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              What Hawk can currently govern across this exact tenant, action scope, deployment path, and evidence window.
            </p>
          </div>
          <Button size="sm" variant="outline" onClick={() => void refresh()} disabled={refreshing}>
            <RefreshCw className={`mr-2 h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            Recompute from evidence
          </Button>
        </header>

        {error && summary ? (
          <div className="mt-4 border border-cyan-300/20 bg-cyan-300/[0.05] px-4 py-2 text-xs leading-5 text-cyan-100/80">
            Showing the latest available coverage snapshot. A secondary refresh or drill-down request could not complete; existing coverage facts remain unchanged.
          </div>
        ) : null}
        {summary.assessment_count === 0 ? (
          <div className="mt-4 border border-fuchsia-300/25 bg-fuchsia-300/[0.05] px-4 py-3 text-xs leading-5 text-fuchsia-100/80">
            No authoritative Control Coverage paths exist in this tenant snapshot. The denominator is empty, so Hawk is reporting no percentage and makes no gap-free claim.
          </div>
        ) : null}

        <div className="mt-6 grid gap-4 xl:grid-cols-[300px_minmax(0,1fr)]">
          <section className="border border-[#2a3448] bg-[#0e141e]/95 p-5" aria-labelledby="coverage-summary-heading">
            <div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" /><h3 id="coverage-summary-heading" className="text-xs font-semibold text-slate-200">Coverage Summary</h3></div>
            <div className="mt-5 grid place-items-center">
              <div className="grid h-44 w-44 place-items-center rounded-full p-3" style={{ background: `conic-gradient(#6ee7b7 ${coverageArc * 3.6}deg, #212a39 0deg)` }}>
                <div className="grid h-full w-full place-items-center rounded-full border border-[#2c374b] bg-[#0a0f17] text-center">
                  <div><div className="font-mono text-3xl font-semibold text-emerald-200">{formatPercent(summary.validated_coverage_percent)}</div><div className="mt-1 max-w-24 text-[9px] uppercase tracking-[0.16em] text-slate-600">current validated coverage</div></div>
                </div>
              </div>
            </div>
            <div className="mt-5 grid grid-cols-3 gap-px bg-[#2a3448]">
              <div className="bg-[#101722] p-3 text-center"><div className="font-mono text-lg text-slate-100">{summary.state_distribution.covered_current}</div><div className="text-[9px] text-slate-600">Current</div></div>
              <div className="bg-[#101722] p-3 text-center"><div className="font-mono text-lg text-slate-100">{summary.denominator}</div><div className="text-[9px] text-slate-600">Denominator</div></div>
              <div className="bg-[#101722] p-3 text-center"><div className="font-mono text-lg text-fuchsia-200">{summary.unknown_population}</div><div className="text-[9px] text-slate-600">Unknown</div></div>
            </div>
            <p className="mt-3 text-[10px] leading-4 text-slate-500">Unknown stays in the denominator. Not applicable is excluded. No arbitrary weighting is used.</p>
          </section>

          <section className="border border-[#2a3448] bg-[#0e141e]/95 p-5">
            <div className="flex items-center gap-2"><Radar className="h-4 w-4 text-cyan-300" /><h3 className="text-xs font-semibold text-slate-200">Coverage states</h3><span className="ml-auto font-mono text-[9px] text-slate-600">{summary.assessment_count} assessments</span></div>
            <div className="mt-5"><DistributionBar distribution={summary.state_distribution} /></div>
            <div className="mt-4"><DistributionLegend distribution={summary.state_distribution} /></div>
            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              <div className="border-l-2 border-emerald-300/60 pl-3"><div className="text-[9px] uppercase tracking-wider text-slate-600">Scope</div><div className="mt-1 text-sm text-slate-200">{summary.scope.display_name}</div></div>
              <div className="border-l-2 border-cyan-300/60 pl-3"><div className="text-[9px] uppercase tracking-wider text-slate-600">Method</div><div className="mt-1 font-mono text-[11px] text-slate-300">{summary.methodology_version}</div></div>
              <div className="border-l-2 border-indigo-300/60 pl-3"><div className="text-[9px] uppercase tracking-wider text-slate-600">Snapshot</div><div className="mt-1 text-[11px] text-slate-300">{new Date(summary.computed_at).toLocaleString()}</div></div>
            </div>
            <div className="mt-5 border border-[#283247] bg-[#0a1019] p-3">
              <div className="flex items-center gap-2 text-[10px] font-medium text-slate-300"><CircleDot className="h-3.5 w-3.5 text-cyan-300" />Coverage is a point-in-time assertion</div>
              <p className="mt-2 text-[10px] leading-4 text-slate-600">Applicability, deployment, capability, assurance, evidence quality, composed-plan completeness, and bypass reachability remain separate facts.</p>
            </div>
          </section>
        </div>

        <section className="mt-5" aria-labelledby="deployment-surfaces-heading">
          <div className="flex items-center gap-2"><Layers3 className="h-4 w-4 text-indigo-300" /><h3 id="deployment-surfaces-heading" className="text-xs font-semibold text-slate-200">Deployment Surfaces</h3></div>
          <div className="mt-3 grid gap-3 lg:grid-cols-4">
            {SURFACES.map((surface) => {
              const distribution = summary.surface_breakdown[surface.key] ?? Object.fromEntries(STATE_ORDER.map((state) => [state, 0])) as ExecutiveCoverageDistribution;
              const total = STATE_ORDER.reduce((sum, state) => sum + (distribution[state] ?? 0), 0);
              return (
                <article key={surface.key} className="border border-[#293247] bg-[#101620] p-4">
                  <div className="flex items-center justify-between"><h4 className="text-sm font-semibold text-slate-100">{surface.label}</h4><span className="font-mono text-xs text-slate-500">{total}</span></div>
                  <div className="mt-3"><DistributionBar distribution={distribution} /></div>
                  <p className="mt-3 text-[10px] leading-4 text-slate-500">{surface.description}</p>
                </article>
              );
            })}
          </div>
        </section>

        <div className="mt-5 grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,.9fr)]">
          <section className="border border-[#293247] bg-[#0e141e] p-4" aria-labelledby="top-gaps-heading">
            <div className="flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-rose-300" /><h3 id="top-gaps-heading" className="text-xs font-semibold text-slate-200">Top Gaps</h3><span className="ml-auto text-[10px] text-slate-600">Prioritized by state, bypass, criticality</span></div>
            <div className="mt-4 grid gap-2 md:grid-cols-2">
              {summary.top_gaps.length ? summary.top_gaps.slice(0, 8).map((gap) => (
                <GapCard key={gap.gap_id} gap={gap} active={selectedAssessment === gap.assessment_id} onSelect={() => void selectGap(gap)} />
              )) : <div className="md:col-span-2 border border-dashed border-[#30394d] bg-[#0b1119] p-5 text-xs text-slate-500">{summary.assessment_count === 0 ? "No assessment population exists; no gap conclusion can be drawn." : "No open evidence-backed gap exists in this snapshot."}</div>}
            </div>
          </section>
          <div>
            {detailLoading ? <div className="grid min-h-64 place-items-center border border-[#293247] bg-[#0e141e]"><RefreshCw className="h-5 w-5 animate-spin text-cyan-300" /></div> : detail ? <AssessmentDetail detail={detail} /> : (
              <section className="grid min-h-64 place-items-center border border-dashed border-[#30394d] bg-[#0b1119] p-6 text-center">
                <div><Search className="mx-auto h-5 w-5 text-slate-600" /><div className="mt-3 text-sm font-medium text-slate-300">Why this state exists</div><p className="mt-2 max-w-xs text-xs leading-5 text-slate-600">Select a gap to inspect orthogonal facts, expected and contributing controls, evidence, bypasses, and Phase 7 lineage.</p></div>
              </section>
            )}
          </div>
        </div>

        <section className="mt-5 border border-[#293247] bg-[#0e141e] p-4" aria-labelledby="coverage-dimensions-heading">
          <div className="flex items-center gap-2"><Route className="h-4 w-4 text-cyan-300" /><h3 id="coverage-dimensions-heading" className="text-xs font-semibold text-slate-200">Coverage Dimensions</h3></div>
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {Object.entries(summary.dimension_breakdown).map(([dimension, distribution]) => (
              <article key={dimension} className="border border-[#283247] bg-[#101722] p-3">
                <div className="flex items-center justify-between"><span className="text-xs font-medium text-slate-200">{titleCase(dimension)}</span><span className="font-mono text-[10px] text-slate-600">{STATE_ORDER.reduce((sum, state) => sum + (distribution[state] ?? 0), 0)}</span></div>
                <div className="mt-3"><DistributionBar distribution={distribution} /></div>
                <div className="mt-2 flex gap-3 font-mono text-[9px] text-slate-500"><span>{distribution.covered_current ?? 0} current</span><span>{distribution.partially_covered ?? 0} partial</span><span>{distribution.unknown ?? 0} unknown</span></div>
              </article>
            ))}
            {Object.keys(summary.dimension_breakdown).length === 0 ? <div className="md:col-span-2 xl:col-span-3 border border-dashed border-[#30394d] p-4 text-xs text-slate-500">No applicable dimensions can be asserted until authoritative action-path requirements are materialized.</div> : null}
          </div>
        </section>

        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <section className="border border-[#293247] bg-[#0e141e] p-4" aria-labelledby="coverage-change-heading">
            <div className="flex items-center gap-2"><GitCompareArrows className="h-4 w-4 text-indigo-300" /><h3 id="coverage-change-heading" className="text-xs font-semibold text-slate-200">Change Since Previous Snapshot</h3></div>
            {summary.previous_snapshot_id ? (
              <div className="mt-4">
                <div className="grid grid-cols-3 gap-px bg-[#293247]">
                  <div className="bg-[#101722] p-3"><ArrowUpRight className="h-3.5 w-3.5 text-emerald-300" /><div className="mt-2 font-mono text-lg text-slate-100">{change?.introduced ?? 0}</div><div className="text-[9px] text-slate-600">Introduced</div></div>
                  <div className="bg-[#101722] p-3"><CheckCircle2 className="h-3.5 w-3.5 text-cyan-300" /><div className="mt-2 font-mono text-lg text-slate-100">{change?.unchanged ?? 0}</div><div className="text-[9px] text-slate-600">Unchanged</div></div>
                  <div className="bg-[#101722] p-3"><ArrowDownRight className="h-3.5 w-3.5 text-rose-300" /><div className="mt-2 font-mono text-lg text-slate-100">{change?.removed ?? 0}</div><div className="text-[9px] text-slate-600">Removed</div></div>
                </div>
                <div className="mt-3 space-y-2">
                  {transitionRows.length ? transitionRows.map(([transition, count]) => <div key={transition} className="flex items-center justify-between border-b border-[#242d3e] pb-2 text-[10px]"><span className="text-slate-500">{titleCase(transition)}</span><span className="font-mono text-slate-200">{count}</span></div>) : <p className="text-[11px] text-slate-600">No state transitions were recorded.</p>}
                </div>
              </div>
            ) : <p className="mt-4 border border-dashed border-[#30394d] p-4 text-xs text-slate-500">This is the first snapshot for the selected scope. No comparison is inferred.</p>}
          </section>

          <section className="border border-[#293247] bg-[#0e141e] p-4" aria-labelledby="evidence-trail-heading">
            <div className="flex items-center gap-2"><CircleDot className="h-4 w-4 text-emerald-300" /><h3 id="evidence-trail-heading" className="text-xs font-semibold text-slate-200">Evidence trail</h3></div>
            <p className="mt-2 text-[10px] leading-4 text-slate-600">Source versions explain which authoritative Hawk projections produced this immutable snapshot.</p>
            <div className="mt-4 space-y-2">
              {Object.entries(summary.source_versions).length ? Object.entries(summary.source_versions).map(([source, version]) => (
                <div key={source} className="flex items-center justify-between gap-4 border-b border-[#242d3e] pb-2 text-[10px]"><span className="text-slate-500">{titleCase(source)}</span><span className="truncate font-mono text-slate-300" title={version}>{version}</span></div>
              )) : <div className="border border-dashed border-[#30394d] p-4 text-xs text-slate-500">No source version was asserted. Coverage remains bounded to the stored assessment facts.</div>}
            </div>
          </section>
        </div>

        <details className="mt-5 border border-[#293247] bg-[#0d131d]">
          <summary className="cursor-pointer px-4 py-3 text-xs font-medium text-slate-300">Advanced path-level evidence</summary>
          <div className="border-t border-[#293247] p-4"><PathExplorer /></div>
        </details>

        <footer className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-[#273045] pt-4 font-mono text-[9px] uppercase tracking-wider text-slate-600">
          <span>{summary.methodology_version}</span><span>Snapshot {summary.snapshot_id}</span>
        </footer>
      </div>
    </section>
  );
}
