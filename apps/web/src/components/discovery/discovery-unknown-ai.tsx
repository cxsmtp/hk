"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { CircleHelp, RefreshCw, SearchCheck, ShieldQuestion } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { UnknownAIItem } from "@/lib/types";
import { confidenceLabel, DiscoveryEmpty, DiscoveryWorkspaceFrame, formatDiscoveryLabel, formatDiscoveryTime, TruthBadge } from "./discovery-workspace-frame";

export function DiscoveryUnknownAI() {
  const [items, setItems] = useState<UnknownAIItem[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.listUnknownAI({ page_size: 200 });
      setItems(response.items || []);
    } catch (error) {
      setItems([]);
      toast.error(error instanceof Error ? error.message : "Unable to load Unknown AI queue");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const states = useMemo(() => ({
    ambiguous: items.filter((item) => item.contradiction_state !== "none" || item.confidence < 0.6).length,
    stale: items.filter((item) => item.freshness === "stale").length,
    verifying: items.filter((item) => item.verification_state === "verifying").length,
  }), [items]);

  return (
    <DiscoveryWorkspaceFrame
      eyebrow="Uncertainty is a product state"
      title="Unknown AI investigation"
      description="Unresolved signals, contradictory evidence, and unsupported attribution remain visible until verification confirms or rejects a hypothesis."
      actions={<Button size="sm" variant="outline" onClick={load} disabled={loading} className="border-white/10 bg-white/[0.03] text-slate-200 hover:bg-white/[0.07]"><RefreshCw className={`mr-2 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh queue</Button>}
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[["Unresolved signals", items.length], ["Ambiguous/contradicted", states.ambiguous], ["Stale evidence", states.stale], ["Verification active", states.verifying]].map(([label, value]) => <div key={String(label)} className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4"><p className="font-mono text-[9px] uppercase tracking-[0.17em] text-slate-600">{label}</p><p className="mt-2 font-mono text-3xl text-white">{value}</p></div>)}
      </div>

      <div className="mt-5 grid gap-3 lg:grid-cols-4">
        <div className="rounded-2xl border border-cyan-300/10 bg-cyan-300/[0.035] p-4">
          <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-200/70">Investigation queue</p>
          <p className="mt-2 text-sm font-medium text-white">Unknown does not mean invisible.</p>
          <p className="mt-1 text-[11px] leading-5 text-slate-400">Each card keeps the evidence node, confidence, freshness and next verification action visible.</p>
        </div>
        <Button asChild variant="outline" className="h-full justify-start border-white/10 bg-white/[0.03] p-4 text-left text-slate-100">
          <Link href="/runtime-intelligence/activity-map">Review evidence</Link>
        </Button>
        <Button asChild variant="outline" className="h-full justify-start border-white/10 bg-white/[0.03] p-4 text-left text-slate-100">
          <Link href="/integrations">Connect source</Link>
        </Button>
        <Button asChild variant="outline" className="h-full justify-start border-white/10 bg-white/[0.03] p-4 text-left text-slate-100">
          <Link href="/discovery/scans">Run bounded scan</Link>
        </Button>
      </div>

      {loading ? <div className="mt-5 grid min-h-64 place-items-center rounded-2xl border border-white/[0.07] bg-[#0d151e]"><RefreshCw className="h-5 w-5 animate-spin text-cyan-300" /></div> : !items.length ? <div className="mt-5"><DiscoveryEmpty title="No unresolved hypothesis in the known scope" detail="This does not establish that no unknown AI exists outside current collection coverage. Connect source or run bounded scan to expand the investigation queue." /></div> : (
        <div className="mt-5 grid gap-3 lg:grid-cols-2">
          {items.map((item) => (
            <article key={`${item.subject_kind}-${item.subject_id}`} className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4">
              <div className="flex items-start gap-3"><span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-amber-300/10 bg-amber-300/[0.05]"><ShieldQuestion className="h-4 w-4 text-amber-200" /></span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-start justify-between gap-2"><div><h2 className="truncate text-sm font-semibold text-white">{item.label}</h2><p className="mt-1 font-mono text-[9px] uppercase tracking-[0.13em] text-slate-600">{formatDiscoveryLabel(item.subject_kind)} · {formatDiscoveryLabel(item.probable_type)}</p></div><span className="rounded-xl border border-amber-300/15 bg-amber-300/[0.06] px-2.5 py-1 font-mono text-sm text-amber-100">{confidenceLabel(item.confidence)}</span></div>
                <div className="mt-3 flex flex-wrap gap-1.5"><TruthBadge value={item.verification_state} /><TruthBadge value={item.freshness} /><TruthBadge value={item.contradiction_state} /></div>
                <div className="mt-3 rounded-xl border border-cyan-300/10 bg-cyan-300/[0.025] p-3"><p className="flex items-center gap-1.5 font-mono text-[8px] uppercase tracking-[0.15em] text-cyan-300/70"><SearchCheck className="h-3 w-3" /> Required verification action</p><p className="mt-1 text-xs leading-5 text-slate-300">{item.required_action}</p></div>
                <div className="mt-3 grid gap-1 text-[10px] text-slate-500 sm:grid-cols-2"><span>Last seen: {formatDiscoveryTime(item.last_seen_at)}</span><span className="break-all font-mono">Evidence: {item.evidence_node_id}</span></div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button asChild size="sm" variant="outline" className="border-white/10 bg-white/[0.03] text-slate-100"><Link href="/runtime-intelligence/activity-map">Review evidence</Link></Button>
                  <Button asChild size="sm" variant="outline" className="border-white/10 bg-white/[0.03] text-slate-100"><Link href="/discovery/scans">Resolve selected unknown</Link></Button>
                </div>
              </div></div>
            </article>
          ))}
        </div>
      )}

      <div className="mt-5 grid gap-3 lg:grid-cols-3">
        {[['No signal', 'Hawk makes no asset claim and preserves the Unknown boundary.'], ['Weak or conflicting signal', 'Hawk retains a hypothesis and queues bounded verification.'], ['Corroborated signal', 'Resolution may create or attach a canonical asset with evidence lineage.']].map(([title, detail], index) => <div key={title} className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-4"><div className="flex items-center gap-2"><CircleHelp className="h-4 w-4 text-slate-500" /><span className="font-mono text-[9px] uppercase tracking-[0.15em] text-slate-500">0{index + 1}</span></div><p className="mt-3 text-sm font-medium text-slate-200">{title}</p><p className="mt-1 text-[11px] leading-5 text-slate-500">{detail}</p></div>)}
      </div>
    </DiscoveryWorkspaceFrame>
  );
}
