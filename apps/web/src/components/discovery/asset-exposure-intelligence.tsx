"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowUpRight,
  Braces,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Compass,
  Fingerprint,
  GitBranch,
  Network,
  RefreshCw,
  Route,
  ShieldCheck,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type {
  ExposureConclusion,
  ExposureCoverageDimension,
  ExposureExtent,
  ExposureFactor,
  ExposureGraphResponse,
  ExposureProjection,
  ExposureTimelineResponse,
} from "@/lib/types";
import { formatDiscoveryLabel, formatDiscoveryTime } from "./discovery-workspace-frame";


const EXTENTS: ExposureExtent[] = ["none", "limited", "material", "broad", "unknown"];

function extentTone(extent: ExposureExtent): string {
  if (extent === "broad") return "border-violet-300/25 bg-violet-300/[0.08] text-violet-100";
  if (extent === "material") return "border-cyan-300/25 bg-cyan-300/[0.08] text-cyan-100";
  if (extent === "limited") return "border-sky-300/20 bg-sky-300/[0.06] text-sky-100";
  if (extent === "none") return "border-slate-300/15 bg-slate-300/[0.04] text-slate-300";
  return "border-dashed border-slate-500/40 bg-transparent text-slate-400";
}

function confidence(value: number | null): string {
  return value === null ? "Unknown" : `${Math.round(value * 100)}% source confidence`;
}

function ExposurePill({ extent }: { extent: ExposureExtent }) {
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.14em] ${extentTone(extent)}`}>
      {formatDiscoveryLabel(extent)}
    </span>
  );
}

function Panel({
  eyebrow,
  title,
  icon: Icon,
  children,
}: {
  eyebrow: string;
  title: string;
  icon: typeof Compass;
  children: React.ReactNode;
}) {
  return (
    <section className="overflow-hidden rounded-[22px] border border-white/[0.07] bg-[#0b121a]">
      <div className="flex items-start justify-between gap-4 border-b border-white/[0.06] px-4 py-4 sm:px-5">
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan-300/65">{eyebrow}</p>
          <h3 className="mt-1 text-sm font-semibold tracking-[-0.01em] text-white">{title}</h3>
        </div>
        <Icon className="h-4 w-4 text-cyan-200/65" />
      </div>
      <div className="p-4 sm:p-5">{children}</div>
    </section>
  );
}

function FactorRow({ factor }: { factor: ExposureFactor }) {
  const exactPathRefs = factor.related_source_refs.filter((reference) =>
    reference.startsWith("control_coverage_path:"),
  );
  return (
    <div className="grid gap-2 border-b border-white/[0.05] py-3 last:border-0 md:grid-cols-[9rem_minmax(0,1fr)_8rem] md:items-center">
      <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-600">
        {formatDiscoveryLabel(factor.dimension)}
      </span>
      <div className="min-w-0">
        <p className="truncate text-xs text-slate-200">{formatDiscoveryLabel(factor.state)}</p>
        <p className="mt-1 truncate font-mono text-[9px] text-slate-600">{factor.source_type} · {factor.source_id}</p>
        {factor.evidence_refs.length || factor.limitations.length || exactPathRefs.length ? (
          <details className="mt-2 text-[9px] text-slate-500">
            <summary className="cursor-pointer text-slate-600">Evidence details</summary>
            {factor.evidence_refs.length ? <p className="mt-1 break-all">Evidence: {factor.evidence_refs.join(" · ")}</p> : null}
            {exactPathRefs.length ? <p className="mt-1 break-all">Exact path: {exactPathRefs.slice(0, 4).join(" · ")}{exactPathRefs.length > 4 ? ` · +${exactPathRefs.length - 4} more` : ""}</p> : null}
            {factor.limitations.length ? <p className="mt-1">Limits: {factor.limitations.map(formatDiscoveryLabel).join(" · ")}</p> : null}
          </details>
        ) : null}
      </div>
      <div className="text-left md:text-right">
        <p className="font-mono text-[9px] uppercase text-slate-400">{formatDiscoveryLabel(factor.verification_status)}</p>
        <p className="mt-1 text-[9px] text-slate-600">{confidence(factor.confidence)}</p>
      </div>
    </div>
  );
}

function CoverageTile({
  question,
  value,
}: {
  question: string;
  value: ExposureCoverageDimension;
}) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-white/[0.07] bg-white/[0.02] p-4">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/35 to-transparent" />
      <p className="text-[11px] font-medium text-slate-300">{question}</p>
      <div className="mt-3 flex items-center justify-between gap-2">
        <span className="font-mono text-sm text-white">{formatDiscoveryLabel(value.state)}</span>
        <span className="font-mono text-[9px] uppercase text-slate-600">{formatDiscoveryLabel(value.freshness)}</span>
      </div>
      <p className="mt-3 text-[10px] leading-4 text-slate-500">
        {value.path_ids.length} exact path{value.path_ids.length === 1 ? "" : "s"} · {value.assertion_ids.length} assertion{value.assertion_ids.length === 1 ? "" : "s"}
      </p>
      {value.external_control_dependency ? (
        <p className="mt-2 text-[10px] text-violet-200/75">External dependency: {value.external_control_dependency}</p>
      ) : null}
      {value.blind_spots.length ? (
        <p className="mt-2 text-[10px] leading-4 text-amber-100/60">{value.blind_spots.map(formatDiscoveryLabel).join(" · ")}</p>
      ) : null}
    </div>
  );
}

export function AssetExposureIntelligence({ assetId }: { assetId: string }) {
  const [projection, setProjection] = useState<ExposureProjection | null>(null);
  const [timeline, setTimeline] = useState<ExposureTimelineResponse | null>(null);
  const [graph, setGraph] = useState<ExposureGraphResponse | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [graphLoading, setGraphLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setGraph(null);
    try {
      const nextProjection = await api.getDiscoveryAssetExposure(assetId);
      const nextTimeline = nextProjection.calculation_status === "unavailable"
        ? null
        : await api.getDiscoveryAssetExposureTimeline(assetId, 1, nextProjection.as_of);
      setProjection(nextProjection);
      setTimeline(
        nextTimeline?.source_input_digest === nextProjection.source_input_digest
          ? nextTimeline
          : null,
      );
      setSelectedCategory((current) => (
        nextProjection.exposures.some((item) => item.category_id === current)
          ? current
          : nextProjection.exposures[0]?.category_id || null
      ));
    } catch (reason) {
      setProjection(null);
      setTimeline(null);
      setError(reason instanceof Error ? reason.message : "Exposure reasoning unavailable");
    } finally {
      setLoading(false);
    }
  }, [assetId]);

  useEffect(() => {
    void load();
  }, [load]);

  const selected = useMemo<ExposureConclusion | null>(() => {
    if (!projection?.exposures.length) return null;
    return projection.exposures.find((item) => item.category_id === selectedCategory) || projection.exposures[0];
  }, [projection, selectedCategory]);

  const timelineUnavailable = timeline?.limitations.includes(
    "historical_exposure_state_unavailable",
  ) ?? false;

  const loadGraph = useCallback(async () => {
    if (!selected) return;
    if (graph?.category_id === selected.category_id) {
      setGraph(null);
      return;
    }
    setGraphLoading(true);
    try {
      const nextGraph = await api.getDiscoveryAssetExposureGraph(
        assetId,
        selected.category_id,
        projection?.as_of,
      );
      setGraph(
        nextGraph.source_input_digest === projection?.source_input_digest
          ? nextGraph
          : null,
      );
    } catch {
      setGraph(null);
    } finally {
      setGraphLoading(false);
    }
  }, [assetId, graph?.category_id, projection?.as_of, projection?.source_input_digest, selected]);

  if (loading) {
    return (
      <section className="mt-5 grid min-h-56 place-items-center rounded-[24px] border border-white/[0.07] bg-[#0b121a]">
        <div className="text-center"><RefreshCw className="mx-auto h-5 w-5 animate-spin text-cyan-300" /><p className="mt-3 text-xs text-slate-500">Resolving exposure evidence</p></div>
      </section>
    );
  }

  if (!projection || error || projection.calculation_status === "unavailable") {
    return (
      <section className="mt-5 rounded-[24px] border border-dashed border-white/10 bg-[#0b121a] p-6">
        <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-600">AI Exposure Reasoning</p>
        <h2 className="mt-2 text-base font-semibold text-slate-200">Exposure reasoning unavailable</h2>
        <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-500">The AI asset record remains available. Missing evidence never proves no exposure, so Hawk will not substitute a zero or a success state.</p>
        <Button onClick={load} variant="outline" size="sm" className="mt-4 border-white/10 bg-white/[0.025]">
          <RefreshCw className="mr-2 h-3.5 w-3.5" /> Retry reasoning
        </Button>
      </section>
    );
  }

  return (
    <div className="mt-5 space-y-4">
      <section className="relative overflow-hidden rounded-[26px] border border-cyan-300/[0.12] bg-[#09131b] p-5 sm:p-6">
        <div className="absolute -right-16 -top-20 h-52 w-52 rounded-full bg-cyan-300/[0.08] blur-[70px]" />
        <div className="absolute -bottom-20 left-1/3 h-44 w-72 rounded-full bg-violet-400/[0.06] blur-[80px]" />
        <div className="relative">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="font-mono text-[9px] uppercase tracking-[0.23em] text-cyan-300/75">Exposure Summary</p>
              <h2 className="mt-2 text-xl font-semibold tracking-[-0.025em] text-white">What this asset can reach and affect</h2>
              <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-400">Evidence-backed reach, capability, identity and authority. This is not a risk score.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-white/10 px-3 py-1.5 font-mono text-[9px] uppercase tracking-[0.12em] text-slate-400">{formatDiscoveryLabel(projection.calculation_status)}</span>
              <span className="rounded-full border border-white/10 px-3 py-1.5 font-mono text-[9px] uppercase tracking-[0.12em] text-slate-400">Rules {projection.reasoning_rule_version}</span>
            </div>
          </div>

          <div className="mt-5 grid gap-2 sm:grid-cols-5">
            {EXTENTS.map((extent) => (
              <div key={extent} className={`rounded-2xl border p-3 ${extentTone(extent)}`}>
                <p className="font-mono text-[9px] uppercase tracking-[0.14em] opacity-70">{formatDiscoveryLabel(extent)}</p>
                <p className="mt-2 font-mono text-2xl">{projection.extent_distribution[extent]}</p>
              </div>
            ))}
          </div>

          <div className="mt-4 flex flex-wrap gap-2 pb-1">
            {projection.exposures.map((item) => (
              <button
                key={item.category_id}
                type="button"
                onClick={() => { setSelectedCategory(item.category_id); setGraph(null); }}
                className={`min-w-[13rem] rounded-2xl border p-3 text-left transition ${selected?.category_id === item.category_id ? "border-cyan-300/30 bg-cyan-300/[0.06]" : "border-white/[0.07] bg-white/[0.02] hover:border-white/15"}`}
              >
                <div className="flex items-center justify-between gap-2"><span className="text-xs font-medium text-slate-200">{item.label}</span><ExposurePill extent={item.extent} /></div>
                <p className="mt-2 font-mono text-[9px] uppercase text-slate-600">{confidence(item.confidence)} · {formatDiscoveryLabel(item.verification_status)}</p>
              </button>
            ))}
          </div>
        </div>
      </section>

      <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
        <Panel eyebrow="Exposure Timeline" title="Evidence river" icon={GitBranch}>
          {timelineUnavailable ? (
            <div className="rounded-2xl border border-dashed border-white/10 p-6 text-center"><p className="text-xs text-slate-400">Historical exposure timeline unavailable</p><p className="mt-2 text-[10px] leading-4 text-slate-600">Current evidence supports an as-of projection, but not an immutable adjacent before/after state. Hawk will not present an empty history as proof of no change.</p></div>
          ) : !timeline?.items.length ? (
            <div className="rounded-2xl border border-dashed border-white/10 p-6 text-center"><p className="text-xs text-slate-400">No exposure timeline returned</p><p className="mt-2 text-[10px] leading-4 text-slate-600">Timeline evidence is not available in this response.</p></div>
          ) : (
            <div className="relative space-y-1 pl-6 before:absolute before:bottom-2 before:left-[7px] before:top-2 before:w-px before:bg-gradient-to-b before:from-cyan-300/70 before:via-violet-300/35 before:to-transparent">
              {timeline.items.slice(0, 8).map((item, index) => (
                <div key={item.event_id} className="relative rounded-2xl border border-white/[0.055] bg-white/[0.018] p-3">
                  <span className="absolute -left-[22px] top-4 h-3 w-3 rounded-full border border-cyan-200/60 bg-[#0b121a] shadow-[0_0_16px_rgba(103,232,249,0.3)]" style={{ animationDelay: `${index * 120}ms` }} />
                  <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-slate-200">{formatDiscoveryLabel(item.event_type)}</p><span className="font-mono text-[9px] text-slate-600">{formatDiscoveryTime(item.occurred_at)}</span></div>
                  <p className="mt-2 font-mono text-[9px] uppercase text-slate-500">{formatDiscoveryLabel(item.before_extent || "unknown")} → {formatDiscoveryLabel(item.after_extent || "unknown")}</p>
                  <p className="mt-2 text-[10px] leading-4 text-slate-500">{item.changed_factors.map(formatDiscoveryLabel).join(" · ") || "Source relationship changed"}</p>
                  <p className="mt-2 font-mono text-[9px] text-cyan-200/55">{item.source_event_refs[0]}</p>
                  {item.evidence_refs.length || item.limitations.length ? <details className="mt-2 text-[9px] text-slate-600"><summary className="cursor-pointer">Evidence and limitations</summary>{item.evidence_refs.length ? <p className="mt-1 break-all">{item.evidence_refs.join(" · ")}</p> : null}{item.limitations.length ? <p className="mt-1">{item.limitations.map(formatDiscoveryLabel).join(" · ")}</p> : null}</details> : null}
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel eyebrow="Exposure Contributors" title={selected ? `${selected.label} evidence` : "No category selected"} icon={Fingerprint}>
          {!selected ? null : (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2"><ExposurePill extent={selected.extent} /><span className="font-mono text-[9px] uppercase text-slate-500">{confidence(selected.confidence)}</span><span className="font-mono text-[9px] uppercase text-slate-500">Evidence quality: {selected.evidence_quality === null ? "Unknown" : `${Math.round(selected.evidence_quality * 100)}%`}</span><span className="font-mono text-[9px] uppercase text-slate-500">Last validation: {selected.last_validation ? formatDiscoveryTime(selected.last_validation) : "Unknown"}</span><span className="font-mono text-[9px] uppercase text-slate-500">{selected.collector_diversity} collector groups</span></div>
              <div className="max-h-[30rem] overflow-y-auto pr-1">
                {selected.contributors.length ? selected.contributors.map((factor) => <FactorRow key={`${factor.dimension}:${factor.source_type}:${factor.source_id}:${factor.state}:${factor.related_source_refs.join("|")}`} factor={factor} />) : <p className="rounded-2xl border border-dashed border-white/10 p-6 text-center text-xs text-slate-500">Required contributors are Unknown.</p>}
              </div>
              {selected.contradictions.length ? <p className="mt-3 rounded-xl border border-violet-300/15 bg-violet-300/[0.04] p-3 text-[10px] leading-4 text-violet-100/70">{selected.contradictions.length} verified contradiction{selected.contradictions.length === 1 ? "" : "s"}; exact extent withheld.</p> : null}
              {selected.unknown_dimensions.length || selected.limitations.length ? <details className="mt-3 rounded-xl border border-dashed border-white/10 p-3 text-[10px] text-slate-500"><summary className="cursor-pointer text-slate-400">Why this conclusion is limited</summary>{selected.unknown_dimensions.length ? <p className="mt-2">Unknown dimensions: {selected.unknown_dimensions.map(formatDiscoveryLabel).join(" · ")}</p> : null}{selected.limitations.length ? <p className="mt-2">Limitations: {selected.limitations.map(formatDiscoveryLabel).join(" · ")}</p> : null}{selected.reasoning_trace.length ? <p className="mt-2">Reasoning: {selected.reasoning_trace.map(formatDiscoveryLabel).join(" → ")}</p> : null}{selected.evidence_refs.length ? <p className="mt-2 break-all">Evidence: {selected.evidence_refs.join(" · ")}</p> : null}</details> : null}
            </>
          )}
        </Panel>
      </div>

      {selected ? (
        <Panel eyebrow="Control Coverage" title="Can Hawk govern this exposure?" icon={ShieldCheck}>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <CoverageTile question="Can Hawk discover it?" value={selected.coverage.discover} />
            <CoverageTile question="Can Hawk authorize it?" value={selected.coverage.authorize} />
            <CoverageTile question="Can Hawk prove it?" value={selected.coverage.prove} />
            <CoverageTile question="Can Hawk contain it?" value={selected.coverage.contain} />
          </div>
        </Panel>
      ) : null}

      <Panel eyebrow="Recommendations & Drill Down" title="Evidence-bound next actions" icon={Route}>
        <div className="grid gap-4 xl:grid-cols-[1fr_0.85fr]">
          <div className="space-y-2">
            {!selected?.recommendations.length ? <p className="rounded-2xl border border-dashed border-white/10 p-6 text-center text-xs text-slate-500">No supported recommendation can be derived from current evidence.</p> : selected.recommendations.map((item) => (
              <div key={item.recommendation_id} className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-4">
                <Link href={item.product_route} className="group flex items-start justify-between gap-4">
                  <div><p className="text-xs font-medium text-slate-200">{item.governance_action}</p><p className="mt-2 text-[10px] leading-4 text-slate-500">{item.expected_effect}</p><p className="mt-2 font-mono text-[9px] uppercase text-slate-600">{item.prerequisites.length ? item.prerequisites.map(formatDiscoveryLabel).join(" · ") : "No additional prerequisites reported"}</p></div>
                  <ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-600 transition group-hover:text-cyan-200" />
                </Link>
                <details className="mt-3 border-t border-white/[0.06] pt-3 text-[9px] text-slate-500"><summary className="cursor-pointer text-slate-400">Why and supporting evidence</summary><p className="mt-2 leading-4">{item.reason}</p><p className="mt-2 break-all">Sources: {item.source_refs.length ? item.source_refs.join(" · ") : "Unknown"}</p></details>
              </div>
            ))}
          </div>
          <div className="rounded-2xl border border-white/[0.07] bg-[#080e15] p-4">
            <div className="flex items-center justify-between gap-3"><div><p className="text-xs font-medium text-slate-200">Advanced evidence graph</p><p className="mt-1 text-[10px] text-slate-600">Loaded only when requested</p></div><Button size="sm" variant="outline" onClick={loadGraph} disabled={!selected || graphLoading} className="border-white/10 bg-white/[0.025]">{graphLoading ? <RefreshCw className="mr-2 h-3.5 w-3.5 animate-spin" /> : graph ? <ChevronDown className="mr-2 h-3.5 w-3.5" /> : <ChevronRight className="mr-2 h-3.5 w-3.5" />}Drill Down</Button></div>
            {!graph ? <div className="mt-4 grid min-h-36 place-items-center rounded-xl border border-dashed border-white/[0.08]"><div className="text-center"><Network className="mx-auto h-5 w-5 text-slate-700" /><p className="mt-2 text-[10px] text-slate-600">Source references stay collapsed by default.</p></div></div> : <div className="mt-4 space-y-3"><div className="grid grid-cols-2 gap-2"><div className="rounded-xl border border-white/[0.06] p-3"><CircleDot className="h-3.5 w-3.5 text-cyan-300" /><p className="mt-2 font-mono text-lg text-white">{graph.graph.nodes.length}</p><p className="text-[9px] uppercase text-slate-600">Nodes</p></div><div className="rounded-xl border border-white/[0.06] p-3"><Braces className="h-3.5 w-3.5 text-violet-300" /><p className="mt-2 font-mono text-lg text-white">{graph.graph.edges.length}</p><p className="text-[9px] uppercase text-slate-600">Edges</p></div></div><div className="max-h-56 space-y-1 overflow-y-auto">{graph.graph.nodes.slice(0, 18).map((node) => <div key={node.node_id} className="flex items-center justify-between gap-3 rounded-lg bg-white/[0.025] px-3 py-2"><span className="truncate text-[10px] text-slate-300">{node.label}</span><span className="font-mono text-[8px] uppercase text-slate-600">{formatDiscoveryLabel(node.node_type)}</span></div>)}</div>{graph.truncated ? <p className="text-[9px] text-amber-100/60">Graph is bounded; additional source references are available through evidence drill-down.</p> : null}</div>}
          </div>
        </div>
        {projection.failed_authorities.length ? <p className="mt-4 rounded-xl border border-dashed border-slate-500/30 p-3 text-[10px] text-slate-400">Unknown authorities: {projection.failed_authorities.map(formatDiscoveryLabel).join(" · ")}. Missing evidence never proves no exposure.</p> : null}
        {projection.limitations.length || projection.unknown_dimensions.length || projection.conflicts.length ? <details className="mt-3 rounded-xl border border-dashed border-white/10 p-3 text-[10px] text-slate-500"><summary className="cursor-pointer text-slate-400">Projection limitations</summary>{projection.unknown_dimensions.length ? <p className="mt-2">Unknown dimensions: {projection.unknown_dimensions.map(formatDiscoveryLabel).join(" · ")}</p> : null}{projection.conflicts.length ? <p className="mt-2 break-all">Conflicts: {projection.conflicts.join(" · ")}</p> : null}{projection.limitations.length ? <p className="mt-2">{projection.limitations.map(formatDiscoveryLabel).join(" · ")}</p> : null}</details> : null}
      </Panel>
    </div>
  );
}
