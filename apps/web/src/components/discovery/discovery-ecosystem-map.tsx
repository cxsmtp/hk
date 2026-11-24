"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowUpRight, CircleAlert, CloudCog, Fingerprint, GitBranch, Network, Radio, RefreshCw, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { DiscoveryEcosystem, ERGEcosystemSummary, UnknownAIItem } from "@/lib/types";
import { DiscoveryEmpty, DiscoveryWorkspaceFrame, formatDiscoveryLabel, formatDiscoveryTime } from "./discovery-workspace-frame";

export function DiscoveryEcosystemMap() {
  const [ecosystems, setEcosystems] = useState<DiscoveryEcosystem[]>([]);
  const [resolvedEcosystems, setResolvedEcosystems] = useState<ERGEcosystemSummary[]>([]);
  const [unknownAI, setUnknownAI] = useState<UnknownAIItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "stale" | "unavailable">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadState((current) => current === "ready" || current === "stale" ? "stale" : "loading");
    try {
      const [response, resolved, unknown] = await Promise.all([
        api.listDiscoveryEcosystems({ page_size: 200 }),
        api.listResolvedEcosystems().catch(() => []),
        api.listUnknownAI({ page_size: 100 }).catch(() => ({ items: [] })),
      ]);
      setEcosystems(response.items || []);
      setResolvedEcosystems(resolved || []);
      setUnknownAI(unknown.items || []);
      setLoadError(null);
      setLoadState("ready");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Ecosystem evidence is unavailable.");
      setLoadState((current) => current === "stale" ? "stale" : "unavailable");
      toast.error(error instanceof Error ? error.message : "Unable to load AI ecosystems");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const totals = useMemo(() => ecosystems.reduce((state, item) => ({
    assets: state.assets + item.asset_count,
    active: state.active + item.active_count,
    shadow: state.shadow + item.shadow_count,
    findings: state.findings + item.finding_count,
  }), { assets: 0, active: 0, shadow: 0, findings: 0 }), [ecosystems]);

  return (
    <DiscoveryWorkspaceFrame
      eyebrow="Evidence Resolution Graph"
      title="AI ecosystems"
      description="Canonical AI assets joined only by fresh, verified relationship evidence. Matching provider or environment labels never create a connection."
      actions={<Button size="sm" variant="outline" onClick={load} disabled={loading} className="border-white/10 bg-white/[0.03] text-slate-200 hover:bg-white/[0.07]"><RefreshCw className={`mr-2 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh map</Button>}
    >
      {loadState === "stale" ? <p role="status" className="mb-4 rounded-xl border border-amber-300/15 bg-amber-300/[0.04] px-4 py-3 text-xs text-amber-100/80">Showing the last successful ecosystem snapshot while refresh is unavailable{loadError ? `: ${loadError}` : ""}.</p> : null}
      {loadState === "unavailable" ? <p role="status" className="mb-4 rounded-xl border border-amber-300/15 bg-amber-300/[0.04] px-4 py-3 text-xs text-amber-100/80">Ecosystem evidence is unavailable. No relationship is inferred from missing sources.</p> : null}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[["Observed ecosystem evidence", (resolvedEcosystems.length || ecosystems.length) + unknownAI.length], ["Evidence-resolved", resolvedEcosystems.length], ["Unresolved AI signals", unknownAI.length], ["Open findings", totals.findings]].map(([label, value]) => (
          <div key={String(label)} className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4"><p className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-600">{label}</p><p className="mt-2 font-mono text-3xl text-white">{value}</p></div>
        ))}
      </div>

      {resolvedEcosystems.length > 0 && (
        <section className="mt-5">
          <div className="mb-3 flex items-center justify-between gap-3"><div><p className="font-mono text-[8px] uppercase tracking-[0.18em] text-emerald-300/70">Canonical reasoning layer</p><h2 className="mt-1 text-sm font-medium text-white">Evidence-resolved ecosystems</h2></div><span className="font-mono text-[8px] text-slate-600">{resolvedEcosystems.length} current</span></div>
          <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
            {resolvedEcosystems.map((ecosystem) => {
              const confidence = ecosystem.confidence === null ? 0 : Math.round(ecosystem.confidence * 100);
              return <Link key={ecosystem.ecosystem_id} href={`/discovery/ecosystems/${encodeURIComponent(ecosystem.ecosystem_id)}`} className="group relative overflow-hidden rounded-[26px] border border-emerald-300/10 bg-[#09141b] p-5 shadow-[0_20px_70px_rgba(0,0,0,.22)] transition duration-300 hover:-translate-y-0.5 hover:border-emerald-300/25">
                <div className="absolute -right-12 -top-12 h-36 w-36 rounded-full bg-emerald-300/[0.07] blur-3xl" />
                <div className="relative flex items-start justify-between gap-4"><div className="min-w-0"><div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-300" /><span className="font-mono text-[8px] uppercase tracking-[0.15em] text-emerald-200/70">{formatDiscoveryLabel(ecosystem.resolution_state)}</span></div><h3 className="mt-3 truncate text-base text-white">{ecosystem.canonical_name}</h3><p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">{formatDiscoveryLabel(ecosystem.ecosystem_class)}</p></div><div className="grid h-16 w-16 shrink-0 place-items-center rounded-full" style={{ background: `conic-gradient(${ecosystem.confidence === null ? "#f59e0b" : "#2dd4bf"} ${ecosystem.confidence === null ? 12 : confidence}%, rgba(255,255,255,.06) 0)` }}><div className="grid h-[52px] w-[52px] place-items-center rounded-full bg-[#09141b] font-mono text-xs text-white">{ecosystem.confidence === null ? "?" : `${confidence}%`}</div></div></div>
                <div className="relative mt-4 grid grid-cols-3 gap-2">{[["Members", ecosystem.member_count], ["Quality", ecosystem.evidence_quality === null ? "?" : `${Math.round(ecosystem.evidence_quality * 100)}%`], ["Conflicts", ecosystem.outstanding_contradictions]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-white/[0.05] bg-black/10 py-2 text-center"><p className="font-mono text-lg text-slate-100">{String(value)}</p><p className="font-mono text-[7px] uppercase tracking-wider text-slate-600">{label}</p></div>)}</div>
                <div className="relative mt-4 flex items-center justify-between border-t border-white/[0.06] pt-3"><span className="text-[10px] text-slate-500">Validated {formatDiscoveryTime(ecosystem.last_validated_at)}</span><span className="inline-flex items-center gap-1 text-[10px] text-emerald-200">Why & evidence <ArrowUpRight className="h-3 w-3" /></span></div>
              </Link>;
            })}
          </div>
        </section>
      )}

      {loading ? <div className="mt-5 grid min-h-64 place-items-center rounded-2xl border border-white/[0.07] bg-[#0d151e]"><RefreshCw className="h-5 w-5 animate-spin text-cyan-300" /></div> : !ecosystems.length ? <div className="mt-5">{unknownAI.length ? (
        <section className="rounded-2xl border border-amber-300/12 bg-amber-300/[0.025] p-5">
          <div className="flex items-start gap-3"><CircleAlert className="mt-1 h-5 w-5 shrink-0 text-amber-200" /><div><p className="font-mono text-[9px] uppercase tracking-[0.18em] text-amber-200">Unresolved ecosystem evidence</p><h2 className="mt-2 text-base font-semibold text-white">{unknownAI.length} observed AI signal{unknownAI.length === 1 ? "" : "s"} awaiting reconciliation</h2><p className="mt-2 text-xs leading-5 text-slate-400">No canonical ecosystem is resolved yet, but observed provider/application evidence is available in the Unknown AI queue.</p></div></div>
          <div className="mt-4 grid gap-2 md:grid-cols-2">{unknownAI.slice(0, 6).map((item) => <Link key={`${item.subject_kind}-${item.subject_id}`} href="/discovery/unknown" className="rounded-xl border border-white/[0.06] bg-black/15 p-3 transition hover:border-amber-300/25"><p className="truncate text-sm font-medium text-slate-100">{item.label}</p><p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">{formatDiscoveryLabel(item.probable_type)} · {Math.round(item.confidence * 100)}% confidence</p></Link>)}</div>
        </section>
      ) : <DiscoveryEmpty title="No evidence-backed ecosystem" detail="Hawk needs canonical assets and verified relationship evidence before it can resolve a connected ecosystem." />}</div> : (
        <div className="mt-5 grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {ecosystems.map((ecosystem, index) => {
            const confidence = Math.round(ecosystem.confidence * 100);
            const connected = ecosystem.resolution_method === "verified_evidence_graph_component";
            const primaryEvidence = ecosystem.evidence_refs[0];
            return (
              <article key={ecosystem.ecosystem_id} className="group relative overflow-hidden rounded-[26px] border border-white/[0.07] bg-[#0b141d] p-5 shadow-[0_18px_70px_rgba(0,0,0,0.22)] transition duration-300 hover:-translate-y-0.5 hover:border-cyan-300/25">
                <div className={`absolute -right-12 -top-14 h-40 w-40 rounded-full blur-3xl ${index % 2 ? "bg-violet-400/[0.09]" : "bg-cyan-400/[0.09]"}`} />
                <div className="relative">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex min-w-0 items-center gap-3">
                      <span className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-white/10 bg-white/[0.04]"><CloudCog className="h-4.5 w-4.5 text-cyan-200" /></span>
                      <div className="min-w-0">
                        <h2 className="truncate text-sm font-semibold text-white">{formatDiscoveryLabel(ecosystem.provider)}</h2>
                        <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.15em] text-slate-600">{formatDiscoveryLabel(ecosystem.environment)}</p>
                        <span className={`mt-2 inline-flex rounded-full border px-2 py-0.5 font-mono text-[8px] uppercase tracking-[0.12em] ${connected ? "border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200" : "border-amber-300/20 bg-amber-300/[0.06] text-amber-200"}`}>{connected ? "Verified graph" : "Isolated asset"}</span>
                      </div>
                    </div>
                    <div className="relative grid h-16 w-16 shrink-0 place-items-center rounded-full" style={{ background: `conic-gradient(${connected ? "#2dd4bf" : "#f59e0b"} ${confidence}%, rgba(255,255,255,0.06) 0)` }} aria-label={`Connection confidence ${confidence}%`}>
                      <div className="grid h-[52px] w-[52px] place-items-center rounded-full bg-[#0b141d]"><span className="font-mono text-sm text-white">{connected ? `${confidence}%` : "?"}</span></div>
                    </div>
                  </div>

                  <div className="mt-4 grid grid-cols-4 gap-2 text-center">{[["Assets", ecosystem.asset_count], ["Active", ecosystem.active_count], ["Shadow", ecosystem.shadow_count], ["Findings", ecosystem.finding_count]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-white/[0.05] bg-black/10 py-2"><p className="font-mono text-lg text-slate-100">{value}</p><p className="font-mono text-[7px] uppercase tracking-wider text-slate-600">{label}</p></div>)}</div>

                  <div className="relative mt-4 overflow-hidden rounded-2xl border border-white/[0.06] bg-black/15 px-3 py-3">
                    <div className="absolute left-8 right-8 top-[25px] h-px bg-gradient-to-r from-cyan-300/20 via-cyan-300/60 to-emerald-300/20" />
                    {connected && <span className="absolute left-[34%] top-[22px] h-1.5 w-1.5 rounded-full bg-cyan-200 shadow-[0_0_12px_#67e8f9] motion-safe:animate-pulse" />}
                    <div className="relative grid grid-cols-3 text-center">
                      <div className="grid justify-items-center gap-1.5"><span className="grid h-7 w-7 place-items-center rounded-full border border-cyan-300/20 bg-[#0b141d]"><Radio className="h-3 w-3 text-cyan-200" /></span><span className="font-mono text-[7px] uppercase tracking-wider text-slate-500">Sources</span></div>
                      <div className="grid justify-items-center gap-1.5"><span className="grid h-7 w-7 place-items-center rounded-full border border-violet-300/20 bg-[#0b141d]"><GitBranch className="h-3 w-3 text-violet-200" /></span><span className="font-mono text-[7px] uppercase tracking-wider text-slate-500">Relations</span></div>
                      <div className="grid justify-items-center gap-1.5"><span className="grid h-7 w-7 place-items-center rounded-full border border-emerald-300/20 bg-[#0b141d]"><Fingerprint className="h-3 w-3 text-emerald-200" /></span><span className="font-mono text-[7px] uppercase tracking-wider text-slate-500">Evidence</span></div>
                    </div>
                  </div>

                  <div className="mt-4">
                    <div className="flex items-center justify-between"><p className="font-mono text-[8px] uppercase tracking-[0.16em] text-slate-600">Discovery sources</p><span className="font-mono text-[8px] text-slate-600">{ecosystem.discovery_sources.length} observed</span></div>
                    <div className="mt-2 flex min-h-6 flex-wrap gap-1.5">{ecosystem.discovery_sources.length ? ecosystem.discovery_sources.slice(0, 4).map((source) => <span key={source} className="rounded-full border border-cyan-300/10 bg-cyan-300/[0.035] px-2 py-1 font-mono text-[8px] text-cyan-100/75">{formatDiscoveryLabel(source.replace("asset_projection:", ""))}</span>) : <span className="font-mono text-[9px] text-amber-200/70">Unknown</span>}</div>
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-2 rounded-xl border border-white/[0.05] bg-white/[0.02] p-3 text-[10px]">
                    <div><p className="font-mono text-[7px] uppercase tracking-wider text-slate-600">Evidence</p><p className="mt-1 truncate font-mono text-slate-300" title={primaryEvidence}>{primaryEvidence ? `${ecosystem.evidence_refs.length} ref · ${primaryEvidence.slice(0, 8)}` : "Unknown"}</p></div>
                    <div><p className="font-mono text-[7px] uppercase tracking-wider text-slate-600">Last seen</p><p className="mt-1 font-mono text-slate-300">{formatDiscoveryTime(ecosystem.last_seen_at)}</p></div>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-1.5">{ecosystem.asset_types.map((type) => <span key={type} className="rounded-full border border-white/[0.07] bg-white/[0.025] px-2 py-1 font-mono text-[8px] uppercase text-slate-500">{formatDiscoveryLabel(type)}</span>)}</div>
                  {ecosystem.limitations[0] && <p className="mt-3 rounded-xl border border-amber-300/10 bg-amber-300/[0.035] px-3 py-2 text-[10px] leading-4 text-amber-100/65">{formatDiscoveryLabel(ecosystem.limitations[0])}</p>}
                  <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-3"><span className="flex items-center gap-1.5 text-[10px] text-slate-500"><Network className="h-3 w-3" /> {ecosystem.asset_ids.length} canonical node{ecosystem.asset_ids.length === 1 ? "" : "s"}</span>{ecosystem.asset_ids[0] ? <Link href={`/discovery/assets/${encodeURIComponent(ecosystem.asset_ids[0])}`} className="inline-flex items-center gap-1 text-[10px] text-cyan-200 transition hover:text-cyan-100">Inspect evidence <ArrowUpRight className="h-3 w-3" /></Link> : null}</div>
                </div>
              </article>
            );
          })}
        </div>
      )}
      <div className="mt-5 rounded-2xl border border-amber-300/10 bg-amber-300/[0.025] p-4 text-xs leading-5 text-amber-100/75">Resolved ecosystem totals and unresolved AI signals are shown separately. Missing providers or environments are never treated as absent unless a complete authoritative denominator proves absence.</div>
    </DiscoveryWorkspaceFrame>
  );
}
