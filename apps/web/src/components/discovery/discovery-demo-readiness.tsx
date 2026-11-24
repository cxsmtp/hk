import Link from "next/link";

import { TruthBadge, formatDiscoveryLabel, formatDiscoveryTime } from "./discovery-workspace-frame";
import { DEMO_READINESS_DEFINITIONS, resolveDemoReadinessState } from "./discovery-demo-readiness-state";
import type { DeepScanCoverage, EndpointMetadataInventoryRun, HmairCollectorSummary, HmairTargetSummary } from "@/lib/types";

function ReadinessRow({
  definition,
  targets,
  collectors,
  coverage,
  latestInventoryRun,
}: {
  definition: (typeof DEMO_READINESS_DEFINITIONS)[number];
  targets: HmairTargetSummary[];
  collectors: HmairCollectorSummary[];
  coverage?: DeepScanCoverage | null;
  latestInventoryRun?: EndpointMetadataInventoryRun | null;
}) {
  const readiness = resolveDemoReadinessState({
    definition,
    targets,
    collectors,
    coverageSources: coverage?.sources || [],
    latestInventoryRun,
  });

  return (
    <article className="rounded-xl border border-white/[0.07] bg-black/10 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">{definition.label}</h3>
          <p className="mt-1 text-[11px] leading-5 text-slate-400">{readiness.details[0] || "Registration alone is not verified evidence; current evidence has not been returned."}</p>
        </div>
        <TruthBadge value={readiness.state} />
      </div>

      <div className="mt-3 grid gap-2 text-[11px] text-slate-400 sm:grid-cols-2">
        <p>Targets: {readiness.matchingTargets.length ? readiness.matchingTargets.map((target) => `${target.identifier} (${target.active_scan_allowed ? "scan allowed" : "monitor only"})`).join(" · ") : "Not connected"}</p>
        <p>Collectors: {readiness.matchingCollectors.length ? readiness.matchingCollectors.map((collector) => `${formatDiscoveryLabel(collector.collector_type)} (${collector.enabled ? formatDiscoveryLabel(collector.health) : "disabled"})`).join(" · ") : "Not connected"}</p>
        <p>Current source path: <span className="font-medium text-slate-200">{readiness.sourcePathState}</span></p>
        {readiness.lastEvidenceAt ? <p>Last evidence: {formatDiscoveryTime(readiness.lastEvidenceAt)}</p> : null}
        {readiness.inventory ? <p>Latest inventory request: {formatDiscoveryLabel(readiness.inventory.status)} · completed {readiness.inventory.completed_count} · failed {readiness.inventory.failed_count}</p> : null}
      </div>

      {readiness.details.length > 1 ? <div className="mt-3 space-y-1 text-[10px] leading-4 text-amber-100/75">{readiness.details.slice(1).map((detail) => <p key={detail}>{detail}</p>)}</div> : null}
      {readiness.coverageSources.length ? <div className="mt-3 space-y-2 border-t border-white/[0.06] pt-3">{readiness.coverageSources.map((source, index) => <div key={`${source.target_type}-${index}`} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-[10px] text-slate-400"><div className="flex flex-wrap items-center justify-between gap-2"><span>{formatDiscoveryLabel(source.target_type)} · {formatDiscoveryLabel(source.readiness)}</span><TruthBadge value={source.coverage_state || source.readiness || "unknown"} /></div>{source.evidence_fresh_at ? <p className="mt-1">Evidence timestamp: {formatDiscoveryTime(source.evidence_fresh_at)}</p> : null}{source.reason ? <p className="mt-1">Reason: {source.reason}</p> : null}{source.limitation.filter(Boolean).map((limitation) => <p key={limitation} className="mt-1">Limitation: {limitation}</p>)}</div>)}</div> : null}

      <Link href={definition.href} className="mt-3 inline-flex text-xs font-medium text-cyan-200 hover:text-cyan-100">
        {definition.hrefLabel}
      </Link>
    </article>
  );
}

export function DiscoveryDemoReadiness({
  targets,
  collectors,
  latestInventoryRun,
  coverage,
}: {
  targets: HmairTargetSummary[];
  collectors: HmairCollectorSummary[];
  latestInventoryRun?: EndpointMetadataInventoryRun | null;
  coverage?: DeepScanCoverage | null;
}) {
  return (
    <section className="mt-4 rounded-2xl border border-cyan-300/15 bg-[#0d151e] p-4" aria-label="Discovery demo readiness">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-200/80">Live evidence readiness</p>
          <h2 className="mt-1 text-sm font-semibold text-white">Demo source status</h2>
          <p className="mt-1 max-w-3xl text-[11px] leading-5 text-slate-400">This reflects only the registered targets, enabled collectors, and evidence already loaded on this page.</p>
        </div>
        <Link href="/discovery/scans" className="text-xs font-medium text-cyan-200 hover:text-cyan-100">Open scan operations</Link>
      </div>
      <div className="mt-4 grid gap-3 xl:grid-cols-3">
        {DEMO_READINESS_DEFINITIONS.map((definition) => <ReadinessRow key={definition.label} definition={definition} targets={targets} collectors={collectors} coverage={coverage} latestInventoryRun={latestInventoryRun} />)}
      </div>
    </section>
  );
}
