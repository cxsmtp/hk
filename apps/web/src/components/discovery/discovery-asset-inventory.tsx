"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Boxes, Filter, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { DiscoveryAssetSummary } from "@/lib/types";
import {
  confidenceLabel,
  DiscoveryEmpty,
  DiscoveryWorkspaceFrame,
  formatDiscoveryLabel,
  formatDiscoveryTime,
  TruthBadge,
} from "./discovery-workspace-frame";

const SELECT_STYLE = "h-9 rounded-xl border border-white/10 bg-[#0c141d] px-3 text-xs text-slate-300 outline-none transition focus:border-cyan-300/40";

export function DiscoveryAssetInventory() {
  const [assets, setAssets] = useState<DiscoveryAssetSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [assetType, setAssetType] = useState("");
  const [usageState, setUsageState] = useState("");
  const [shadowStatus, setShadowStatus] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.listDiscoveryAssets({
        search: query.trim() || undefined,
        asset_type: assetType || undefined,
        usage_state: usageState || undefined,
        shadow_status: shadowStatus || undefined,
        page_size: 200,
      });
      setAssets(response.items || []);
      setTotal(response.total || 0);
    } catch (error) {
      setAssets([]);
      setTotal(0);
      toast.error(error instanceof Error ? error.message : "Unable to load AI assets");
    } finally {
      setLoading(false);
    }
  }, [assetType, query, shadowStatus, usageState]);

  useEffect(() => {
    const handle = window.setTimeout(load, 220);
    return () => window.clearTimeout(handle);
  }, [load]);

  const types = useMemo(() => [...new Set(assets.map((asset) => asset.asset_type))].sort(), [assets]);
  const unresolved = assets.filter((asset) => asset.resolution_state !== "confirmed").length;
  const active = assets.filter((asset) => ["active", "high_usage"].includes(asset.usage_state)).length;
  const openFindings = assets.reduce((sum, asset) => sum + asset.findings_open, 0);

  return (
    <DiscoveryWorkspaceFrame
      eyebrow="AI Asset Intelligence"
      title="AI asset inventory"
      description="Review AI assets, their evidence and current status. Confidence and lineage remain available in each asset detail."
      actions={
        <>
          <Link href="/discovery/unknown" className="inline-flex h-9 items-center gap-2 rounded-xl border border-amber-300/20 bg-amber-300/[0.06] px-3 text-xs text-amber-100 transition hover:bg-amber-300/10">
            <ShieldAlert className="h-3.5 w-3.5" /> Review unknown AI
          </Link>
          <Button size="sm" variant="outline" onClick={load} disabled={loading} className="border-white/10 bg-white/[0.03] text-slate-200 hover:bg-white/[0.07]">
            <RefreshCw className={`mr-2 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ["Canonical assets", total, "Current tenant inventory"],
          ["Observed active", active, "Evidence of actual use"],
          ["Needs resolution", unresolved, "Probable or ambiguous"],
          ["Open findings", openFindings, "Evidence-backed only"],
        ].map(([label, value, note]) => (
          <div key={String(label)} className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4">
            <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-slate-500">{label}</p>
            <p className="mt-2 font-mono text-3xl text-white">{value}</p>
            <p className="mt-1 text-[11px] text-slate-500">{note}</p>
          </div>
        ))}
      </div>

      <div className="mt-5 flex flex-col gap-3 rounded-2xl border border-white/[0.07] bg-[#0d151e] p-3 lg:flex-row lg:items-center">
        <div className="relative min-w-0 flex-1">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-600" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search canonical name, provider, product or framework" className="h-9 w-full rounded-xl border border-white/10 bg-[#081019] pl-9 pr-3 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-cyan-300/40" />
        </div>
        <div className="flex flex-wrap gap-2">
          <span className="inline-flex items-center gap-1.5 px-1 font-mono text-[9px] uppercase tracking-[0.15em] text-slate-600"><Filter className="h-3 w-3" /> Filters</span>
          <select value={assetType} onChange={(event) => setAssetType(event.target.value)} className={SELECT_STYLE} aria-label="Asset type">
            <option value="">All types</option>
            {types.map((value) => <option key={value} value={value}>{formatDiscoveryLabel(value)}</option>)}
          </select>
          <select value={usageState} onChange={(event) => setUsageState(event.target.value)} className={SELECT_STYLE} aria-label="Usage state">
            <option value="">All usage</option>
            {['active', 'high_usage', 'occasional', 'historical', 'never_observed', 'unknown'].map((value) => <option key={value} value={value}>{formatDiscoveryLabel(value)}</option>)}
          </select>
          <select value={shadowStatus} onChange={(event) => setShadowStatus(event.target.value)} className={SELECT_STYLE} aria-label="Shadow AI state">
            <option value="">All governance</option>
            {['managed', 'approved', 'unmanaged', 'personal', 'unknown'].map((value) => <option key={value} value={value}>{formatDiscoveryLabel(value)}</option>)}
          </select>
        </div>
      </div>

      <div className="mt-5 overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0b121a]">
        <div className="hidden grid-cols-[minmax(16rem,2fr)_1fr_1fr_1fr_7rem] gap-3 border-b border-white/[0.06] px-4 py-3 font-mono text-[9px] uppercase tracking-[0.18em] text-slate-600 lg:grid">
          <span>AI asset</span><span>Evidence / status</span><span>Usage</span><span>Reach</span><span className="text-right">Findings</span>
        </div>
        {loading ? (
          <div className="grid min-h-64 place-items-center"><RefreshCw className="h-5 w-5 animate-spin text-cyan-300" /></div>
        ) : !assets.length ? (
          <div className="p-4"><DiscoveryEmpty title="No assets match these filters" detail="Connect a source or adjust the filters to review supported AI asset evidence." /></div>
        ) : (
          <div className="divide-y divide-white/[0.05]">
            {assets.map((asset) => (
              <Link key={asset.asset_id} href={`/discovery/assets/${encodeURIComponent(asset.asset_id)}`} className="group grid gap-3 px-4 py-4 transition hover:bg-cyan-300/[0.025] lg:grid-cols-[minmax(16rem,2fr)_1fr_1fr_1fr_7rem] lg:items-center">
                <div className="flex min-w-0 items-start gap-3">
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-cyan-300/10 bg-cyan-300/[0.05] text-cyan-200"><Boxes className="h-4 w-4" /></span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-2"><span className="truncate text-sm font-medium text-slate-100">{asset.canonical_name}</span><ArrowUpRight className="h-3.5 w-3.5 text-slate-700 transition group-hover:text-cyan-300" /></span>
                    <span className="mt-1 block truncate font-mono text-[9px] uppercase tracking-[0.12em] text-slate-600">{formatDiscoveryLabel(asset.asset_type)} · {formatDiscoveryLabel(asset.provider)} · seen {formatDiscoveryTime(asset.last_seen_at)}</span>
                  </span>
                </div>
                <div className="flex items-center gap-2"><TruthBadge value={asset.resolution_state} /><span className="font-mono text-[10px] text-slate-500">{confidenceLabel(asset.resolution_confidence)}</span></div>
                <div><TruthBadge value={asset.usage_state} /><p className="mt-1 font-mono text-[8px] uppercase text-slate-600">{formatDiscoveryLabel(asset.usage_verification_state)}</p></div>
                <div className="font-mono text-[10px] text-slate-400"><span className="text-slate-100">{asset.capabilities_count}</span> cap · <span className="text-slate-100">{asset.reachability_count}</span> paths<br/><span className="text-slate-600">{asset.identities_count} identities</span></div>
                <div className="text-right"><span className={`font-mono text-lg ${asset.findings_open ? "text-rose-300" : "text-emerald-300"}`}>{asset.findings_open}</span><p className="font-mono text-[8px] uppercase text-slate-600">Open</p></div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </DiscoveryWorkspaceFrame>
  );
}
