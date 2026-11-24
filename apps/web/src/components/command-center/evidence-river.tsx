"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, { type Edge, type Node } from "reactflow";
import { Activity, AlarmClock, ArrowRight, CheckCircle2, FileCheck2, Pause, Play, ShieldAlert, ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";

import type { EvidenceRiverEvent, RiverEventKind } from "./command-center-visual-types";

const KIND_META: Record<RiverEventKind, { label: string; color: string; border: string; icon: typeof Activity }> = {
  action: { label: "Action", color: "#60a5fa", border: "border-blue-400/35", icon: Activity },
  alert: { label: "Alert", color: "#fb7185", border: "border-rose-400/35", icon: ShieldAlert },
  intervention: { label: "Intervention", color: "#f5b942", border: "border-amber-300/40", icon: AlarmClock },
  enforcement: { label: "Enforcement", color: "#ef5b5b", border: "border-red-400/45", icon: ShieldCheck },
  proof: { label: "Proof", color: "#5eead4", border: "border-emerald-300/40", icon: FileCheck2 },
};

function formatTime(timestamp: string | null): string {
  if (!timestamp) return "Unknown time";
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  return new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
}

function EventNodeLabel({ event, isNew }: { event: EvidenceRiverEvent; isNew: boolean }) {
  const meta = KIND_META[event.kind];
  const Icon = meta.icon;
  return (
    <div className={cn("hawk-evidence-river-node min-w-[142px] rounded-xl border bg-[#0a111a]/95 p-2.5 text-left shadow-[0_16px_44px_rgba(0,0,0,0.35)]", meta.border, isNew && "hawk-evidence-river-new")}>
      <div className="flex items-center justify-between gap-2">
        <span className="grid h-7 w-7 place-items-center rounded-full border border-white/10" style={{ color: meta.color }}><Icon className="h-3.5 w-3.5" /></span>
        <span className="text-[9px] tabular-nums text-slate-600">{formatTime(event.timestamp)}</span>
      </div>
      <p className="mt-2 truncate text-[10px] font-semibold text-slate-100">{event.application}</p>
      <p className="mt-0.5 truncate text-[9px]" style={{ color: meta.color }}>{meta.label} · {event.decision}</p>
    </div>
  );
}

function InvestigationCard({ event, onResume }: { event: EvidenceRiverEvent; onResume: () => void }) {
  return (
    <div className="absolute bottom-3 left-1/2 z-20 w-[min(92%,480px)] -translate-x-1/2 rounded-xl border border-orange-300/30 bg-[#080d14]/95 p-4 shadow-[0_24px_80px_rgba(0,0,0,0.62)] backdrop-blur">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0"><p className="text-[10px] font-bold uppercase tracking-[0.18em] text-orange-300">Flow paused for investigation</p><h3 className="mt-2 truncate text-sm font-semibold text-white">{event.summary}</h3><p className="mt-1 text-[10px] text-slate-500">{event.actor} · {event.decision} · evidence {event.evidenceState}</p></div>
        <button type="button" onClick={onResume} className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-white/10 px-2.5 py-2 text-[10px] font-semibold text-slate-200 hover:border-orange-300/30 hover:text-orange-200"><Play className="h-3.5 w-3.5" />Resume flow</button>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {event.traceHref ? <Link href={event.traceHref} className="rounded-md border border-white/10 px-2.5 py-1.5 text-[10px] font-semibold text-slate-200 hover:text-white">Open trace</Link> : null}
        {event.evidenceHref ? <Link href={event.evidenceHref} className="rounded-md border border-emerald-300/20 px-2.5 py-1.5 text-[10px] font-semibold text-emerald-200">Open evidence</Link> : null}
        {event.findingHref ? <Link href={event.findingHref} className="rounded-md border border-rose-300/20 px-2.5 py-1.5 text-[10px] font-semibold text-rose-200">Open finding</Link> : null}
      </div>
    </div>
  );
}

export function EvidenceRiver({ events, live }: { events: EvidenceRiverEvent[]; live: boolean }) {
  const visibleEvents = events.slice(-8);
  const seenIds = useRef<Set<string> | null>(null);
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedEvent = visibleEvents.find((event) => event.id === selectedId) || null;
  const paused = Boolean(selectedEvent);

  useEffect(() => {
    const current = new Set(visibleEvents.map((event) => event.id));
    if (seenIds.current === null) {
      seenIds.current = current;
      return;
    }
    const added = new Set(Array.from(current).filter((id) => !seenIds.current?.has(id)));
    seenIds.current = new Set([...(seenIds.current || []), ...current]);
    if (!added.size) return;
    setNewIds(added);
    const timer = window.setTimeout(() => setNewIds(new Set()), 2200);
    return () => window.clearTimeout(timer);
  }, [visibleEvents]);

  const nodes = useMemo<Node[]>(() => visibleEvents.map((event, index) => ({
    id: event.id,
    position: { x: index * 205, y: 58 + ((index % 3) * 34) },
    data: { label: <EventNodeLabel event={event} isNew={newIds.has(event.id)} /> },
    style: { border: 0, background: "transparent", padding: 0, width: 150 },
    selectable: true,
    draggable: false,
  })), [newIds, visibleEvents]);

  const edges = useMemo<Edge[]>(() => visibleEvents.slice(1).flatMap((event, index) => {
    const source = visibleEvents[index].id;
    const target = event.id;
    const color = KIND_META[event.kind].color;
    return [
      { id: `river-base-${source}-${target}`, source, target, type: "default", animated: false, style: { stroke: "#132d38", strokeWidth: 14, opacity: 0.7 } },
      { id: `river-mid-${source}-${target}`, source, target, type: "default", animated: false, style: { stroke: color, strokeWidth: 5, opacity: 0.42 } },
      { id: `river-flow-${source}-${target}`, source, target, type: "default", animated: !paused, style: { stroke: "#dbeafe", strokeWidth: 1.5, opacity: 0.82 } },
    ];
  }), [paused, visibleEvents]);

  return (
    <section className={cn("hawk-evidence-river relative overflow-hidden rounded-2xl border border-white/[0.09] bg-[#071019]", paused && "hawk-evidence-river-paused")} aria-label="Live Evidence River">
      <div className="flex flex-col gap-3 border-b border-white/[0.07] px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <h2 className="text-[11px] font-bold uppercase tracking-[0.22em] text-slate-100">Evidence River</h2>
          <span className="inline-flex items-center gap-2 text-[10px] text-slate-500"><span className={cn("h-2 w-2 rounded-full", live ? "bg-emerald-300" : "bg-amber-300")} />{live ? "Live stream connected" : "Polling for current evidence"}</span>
          {(Object.keys(KIND_META) as RiverEventKind[]).map((kind) => <span key={kind} className="inline-flex items-center gap-1.5 text-[9px] text-slate-500"><span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: KIND_META[kind].color }} />{KIND_META[kind].label}</span>)}
        </div>
        {paused ? <span className="inline-flex items-center gap-1.5 text-[10px] font-medium text-orange-300"><Pause className="h-3.5 w-3.5" />Visual flow paused; ingestion continues</span> : null}
      </div>

      {visibleEvents.length ? (
        <div className="relative">
          <div className="pointer-events-none absolute left-4 top-3 z-10 text-[9px] font-bold uppercase tracking-widest text-slate-600">Past</div>
          <div className="pointer-events-none absolute right-4 top-3 z-10 inline-flex items-center gap-2 text-[9px] font-bold uppercase tracking-widest text-orange-300">Now<ArrowRight className="h-3.5 w-3.5" /></div>
          <div className="hidden h-[310px] md:block">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodeClick={(_, node) => setSelectedId(node.id)}
              fitView
              fitViewOptions={{ padding: 0.18, minZoom: 0.42, maxZoom: 1 }}
              minZoom={0.3}
              maxZoom={1.2}
              nodesConnectable={false}
              nodesDraggable={false}
              elementsSelectable
              panOnDrag={false}
              zoomOnScroll={false}
              zoomOnPinch={false}
              zoomOnDoubleClick={false}
              preventScrolling={false}
              proOptions={{ hideAttribution: true }}
              aria-label="Chronological evidence event flow"
            />
          </div>
          <ol className="space-y-2 p-4 pt-10 md:hidden" aria-label="Chronological evidence event stream">
            {visibleEvents.map((event) => {
              const meta = KIND_META[event.kind];
              return <li key={event.id}><button type="button" onClick={() => setSelectedId(event.id)} className={cn("flex w-full items-center gap-3 rounded-xl border bg-white/[0.018] p-3 text-left", meta.border)}><span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: meta.color }} /><span className="min-w-0 flex-1"><span className="block truncate text-xs font-semibold text-slate-200">{event.summary}</span><span className="mt-1 block text-[10px] text-slate-600">{meta.label} · {formatTime(event.timestamp)}</span></span></button></li>;
            })}
          </ol>
          {selectedEvent ? <InvestigationCard event={selectedEvent} onResume={() => setSelectedId(null)} /> : null}
        </div>
      ) : (
        <div className="grid min-h-[240px] place-items-center px-5 text-center"><div><CheckCircle2 className="mx-auto h-6 w-6 text-slate-700" /><p className="mt-3 text-sm font-medium text-slate-300">No material actions in this scope</p><p className="mt-1 text-[11px] text-slate-600">The river will update when Hawk receives a real action, alert, intervention, enforcement outcome, or evidence proof.</p></div></div>
      )}
    </section>
  );
}
