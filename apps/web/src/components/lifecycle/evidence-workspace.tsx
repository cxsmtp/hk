"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Archive, Clock3, FileCheck2, Fingerprint, RefreshCw } from "lucide-react";

import { WorkspaceHeader } from "@/components/lifecycle/workspace-header";
import { WorkspaceLinks } from "@/components/lifecycle/workspace-links";
import { OperationalState } from "@/components/operational-state";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { EvidenceNode, JobStatusItem } from "@/lib/types";
import { cn } from "@/lib/utils";

function humanizeJobName(value: string): string {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

export function EvidenceWorkspace() {
  const [nodes, setNodes] = useState<EvidenceNode[]>([]);
  const [jobs, setJobs] = useState<JobStatusItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nodesState, setNodesState] = useState<"loading" | "loaded" | "error">("loading");
  const [jobsState, setJobsState] = useState<"loading" | "loaded" | "error">("loading");
  async function load() {
    setLoading(true);
    const [evidenceResult, statusResult] = await Promise.allSettled([api.listEvidenceNodes(), api.listJobStatus(3)]);
    const unavailable: string[] = [];
    if (evidenceResult.status === "fulfilled") {
      setNodes(evidenceResult.value.items || []);
      setNodesState("loaded");
    } else {
      setNodesState("error");
      unavailable.push("Evidence source");
    }
    if (statusResult.status === "fulfilled") {
      setJobs(statusResult.value.items || []);
      setJobsState("loaded");
    } else {
      setJobsState("error");
      unavailable.push("Audit job status");
    }
    setError(unavailable.length ? `${unavailable.join(" and ")} unavailable. Available records remain visible.` : null);
    setLoading(false);
  }
  useEffect(() => { void load(); }, []);
  const latest = useMemo(() => [...nodes].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0], [nodes]);
  const freshness = latest ? Math.max(0, Date.now() - Date.parse(latest.created_at)) : null;
  const freshnessLabel = freshness === null ? "Unknown" : freshness < 15 * 60_000 ? "Current" : freshness < 24 * 60 * 60_000 ? "Aging" : "Stale";
  const failedJobs = jobs.flatMap((job) => job.runs).filter((run) => run.status === "fail").length;
  const presentationState = resolvePresentationState({
    loading,
    hasData: nodes.length > 0 || jobs.length > 0,
    unavailable: Boolean(error),
    stale: Boolean(latest && freshness !== null && freshness >= 24 * 60 * 60_000),
  });
  return <div className="space-y-5">
    <WorkspaceHeader eyebrow="Evidence" title="Prove what Hawk observed and controlled" description="Trace decisions from identity and policy through execution, evidence nodes, audit jobs and exportable proof without treating missing artifacts as success." actions={<Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("mr-2 h-4 w-4", loading && "animate-spin")} />Refresh evidence</Button>} />
    <OperationalState state={presentationState} onRetry={() => void load()} description={error ? "Evidence source unavailable. No proof count is inferred from the failed source." : undefined} />
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">{[
      { label: "Evidence nodes", value: loading ? "—" : nodesState === "error" ? "Unavailable" : nodes.length.toLocaleString(), icon: FileCheck2 },
      { label: "Freshness", value: loading ? "—" : nodesState === "error" ? "Unavailable" : freshnessLabel, icon: Clock3 },
      { label: "Evidence types", value: loading ? "—" : nodesState === "error" ? "Unavailable" : new Set(nodes.map((node) => node.node_type)).size.toLocaleString(), icon: Fingerprint },
      { label: "Failed audit jobs", value: loading ? "—" : jobsState === "error" ? "Unavailable" : failedJobs.toLocaleString(), icon: Archive },
    ].map((item) => { const MetricIcon = item.icon; return <div key={item.label} className="rounded-[20px] border border-white/[0.07] bg-[#0c1016] p-4"><div className="flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">{item.label}</p><MetricIcon className="h-4 w-4 text-orange-300/70" /></div><p className="mt-3 text-2xl font-semibold text-white">{item.value}</p></div>; })}</section>
    <section className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
      <div className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-5"><div className="flex items-center justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-orange-300/70">Proof ledger</p><h2 className="mt-2 text-lg font-semibold text-white">Recent evidence</h2></div><Button asChild variant="outline" size="sm"><Link href="/auditor">Open auditor</Link></Button></div><div className="mt-4 space-y-2">{nodes.slice(0, 14).map((node) => <div key={node.id} className="grid gap-2 rounded-2xl border border-white/[0.055] bg-white/[0.018] p-3.5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center"><div className="min-w-0"><p className="truncate text-sm font-medium text-slate-200">{node.label || node.signal_type}</p><p className="mt-1 text-[10px] text-slate-600">{new Date(node.created_at).toLocaleString()}</p></div><details className="text-[10px] text-slate-500"><summary className="cursor-pointer">Technical details</summary><div className="mt-2 space-y-1 font-mono"><p>UUID: {node.id}</p><p>Type: {node.node_type}</p><p>Signal: {node.signal_type}</p><p>Source: evidence node API</p></div></details></div>)}{!loading && nodesState === "error" ? <p className="rounded-2xl border border-dashed border-amber-400/20 p-8 text-center text-sm text-amber-200">Evidence source unavailable. Hawk is not claiming post-action proof.</p> : !loading && !nodes.length ? <p className="rounded-2xl border border-dashed border-white/[0.08] p-8 text-center text-sm text-slate-600">No evidence nodes are available. Hawk is not claiming post-action proof.</p> : null}</div></div>
      <div className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-5"><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Audit processing</p><h2 className="mt-2 text-lg font-semibold text-white">Audit checks</h2><div className="mt-4 space-y-2">{jobs.map((job) => { const recent = job.runs[0]; return <div key={job.job_name} className="rounded-2xl border border-white/[0.055] bg-white/[0.018] p-3.5"><div className="flex items-center justify-between gap-3"><p className="text-sm font-medium text-slate-200">{humanizeJobName(job.job_name)}</p><span className={cn("rounded-full border px-2 py-1 text-[9px] font-semibold uppercase", recent?.status === "success" ? "border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-300" : recent?.status === "fail" ? "border-rose-400/20 bg-rose-400/[0.07] text-rose-300" : "border-slate-400/20 text-slate-500")}>{recent?.status || "Unknown"}</span></div><p className="mt-2 text-[10px] text-slate-600">{recent?.finished_at ? new Date(recent.finished_at).toLocaleString() : "No recorded execution"}</p><details className="mt-2 text-[10px] text-slate-500"><summary className="cursor-pointer">Technical details</summary><div className="mt-2 space-y-1 font-mono"><p>Raw job name: {job.job_name}</p><p>Source: audit job status API</p><p>Status: {recent?.status || "Unknown"}</p></div></details></div>; })}{!loading && jobsState === "error" ? <p className="rounded-2xl border border-dashed border-amber-400/20 p-8 text-center text-sm text-amber-200">Audit job status is unavailable.</p> : !loading && !jobs.length ? <p className="rounded-2xl border border-dashed border-white/[0.08] p-8 text-center text-sm text-slate-600">No audit checks have run.</p> : null}</div></div>
    </section>
    <WorkspaceLinks links={[
      { href: "/auditor", label: "Automated auditor", description: "Review control posture and export evidence packs." },
      { href: "/auditor/conflicts", label: "Resolve conflicts", description: "Handle contradictions in evidence and assertions." },
      { href: "/runtime-intelligence/activity-map", label: "Action traces", description: "Follow evidence back to the observed execution path." },
    ]} />
  </div>;
}
