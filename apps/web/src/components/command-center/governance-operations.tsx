"use client";

import Link from "next/link";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ArrowUpRight, CircleHelp, Eye, ShieldAlert, ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";

import type { EvidenceRiverEvent, GovernanceOverviewModel, GovernanceTruthState } from "./command-center-visual-types";

export type GovernancePriorityAction = {
  id: string;
  title: string;
  detail: string;
  href: string;
  tone: "critical" | "warning" | "info" | "success";
  label: string;
};

function Panel({ title, description, children, className }: { title: string; description?: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-2xl border border-white/[0.08] bg-[#091019] p-4 sm:p-5", className)}>
      <div className="mb-4">
        <h2 className="text-[11px] font-bold uppercase tracking-[0.2em] text-orange-300">{title}</h2>
        {description ? <p className="mt-1.5 text-[11px] text-slate-500">{description}</p> : null}
      </div>
      {children}
    </section>
  );
}

const STATE_META: Record<GovernanceTruthState, { label: string; color: string; icon: typeof ShieldCheck }> = {
  verified: { label: "Inline verified", color: "text-emerald-300", icon: ShieldCheck },
  monitor_only: { label: "Monitor-only", color: "text-amber-300", icon: Eye },
  not_covered: { label: "Not covered", color: "text-rose-300", icon: ShieldAlert },
  unknown: { label: "Unknown", color: "text-slate-500", icon: CircleHelp },
};

function RelativeTime({ timestamp }: { timestamp: string | null }) {
  if (!timestamp) return <span>Unknown time</span>;
  const milliseconds = Date.now() - new Date(timestamp).getTime();
  if (!Number.isFinite(milliseconds)) return <span>Unknown time</span>;
  const minutes = Math.max(0, Math.round(milliseconds / 60000));
  if (minutes < 60) return <span>{minutes}m ago</span>;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return <span>{hours}h ago</span>;
  return <span>{Math.round(hours / 24)}d ago</span>;
}

function RecentEvent({ event }: { event: EvidenceRiverEvent }) {
  const state = event.evidenceState === "verified" ? "Evidence linked" : event.decision;
  return (
    <Link href={event.traceHref || event.findingHref || "/runtime-intelligence/activity-map"} className="group flex items-start gap-3 border-b border-white/[0.055] py-3 last:border-b-0">
      <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", event.kind === "enforcement" ? "bg-rose-400" : event.evidenceState === "verified" ? "bg-emerald-300" : "bg-amber-300")} />
      <span className="min-w-0 flex-1"><span className="block truncate text-xs font-medium text-slate-200 group-hover:text-white">{state}: {event.action}</span><span className="mt-1 block truncate text-[10px] text-slate-600">{event.application} · {event.surface}</span></span>
      <span className="shrink-0 text-[10px] text-slate-600"><RelativeTime timestamp={event.timestamp} /></span>
    </Link>
  );
}

export function GovernanceOperations({ model, priorityActions }: { model: GovernanceOverviewModel; priorityActions: GovernancePriorityAction[] }) {
  const recent = model.river.slice(-4).reverse();
  const recommendation = priorityActions[0];
  return (
    <div className="grid gap-4 xl:grid-cols-12">
      <Panel title="Observed interventions" description="Policy interventions present in the current activity feed; this is not a full-estate rate." className="xl:col-span-5">
        {model.interventions.length ? (
          <div className="h-52" role="img" aria-label={`${model.interventions.reduce((total, point) => total + point.value, 0)} observed interventions across ${model.interventions.length} days.`}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={model.interventions} margin={{ top: 8, right: 8, bottom: 0, left: -24 }}>
                <CartesianGrid stroke="#263244" strokeDasharray="3 5" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={{ stroke: "#334155" }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0b111a", border: "1px solid #263044", borderRadius: 10, fontSize: 11 }} />
                <Area type="monotone" dataKey="value" name="Interventions" stroke="#f5b942" fill="#f5b942" fillOpacity={0.12} strokeWidth={2} dot={{ r: 4, fill: "#f5b942", stroke: "#0b111a", strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : <div className="grid h-52 place-items-center rounded-xl border border-dashed border-white/10 text-xs text-slate-500">No observed interventions in the current feed.</div>}
      </Panel>

      <Panel title="Coverage by surface" description="Asset-level deployment posture from current Hawk control metadata." className="xl:col-span-4">
        {model.surfaces.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[460px] text-left text-[10px]">
              <thead><tr className="border-b border-white/[0.07] text-slate-600"><th className="pb-2 font-medium">Surface</th><th className="pb-2 font-medium">Posture</th><th className="pb-2 text-right font-medium">Events</th><th className="pb-2 text-right font-medium">Proof</th></tr></thead>
              <tbody>
                {model.surfaces.slice(0, 8).map((row) => {
                  const state = STATE_META[row.state];
                  const Icon = state.icon;
                  return (
                    <tr key={row.id} className="border-b border-white/[0.05] last:border-b-0">
                      <td className="py-2.5 pr-2"><Link href={row.drilldown} className="font-semibold text-slate-200 hover:text-orange-200">{row.label}</Link></td>
                      <td className="py-2.5 pr-2"><span className={cn("inline-flex items-center gap-1.5", state.color)}><Icon className="h-3.5 w-3.5" />{state.label}</span></td>
                      <td className="py-2.5 text-right tabular-nums text-slate-300">{row.eventCount}</td>
                      <td className="max-w-[120px] truncate py-2.5 pl-2 text-right text-slate-500" title={row.evidenceLabel}>{row.evidenceLabel}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <div className="grid h-52 place-items-center rounded-xl border border-dashed border-white/10 px-4 text-center text-xs text-slate-500">No verified deployment surfaces in the current scope.</div>}
      </Panel>

      <Panel title="Priority queue" description="Evidence-backed work ordered by operational impact." className="xl:col-span-3">
        <ol className="space-y-2">
          {priorityActions.slice(0, 3).map((action, index) => (
            <li key={action.id}>
              <Link href={action.href} className="group flex gap-3 rounded-xl border border-white/[0.07] bg-white/[0.018] p-3 hover:border-orange-300/30 hover:bg-orange-400/[0.035]">
                <span className={cn("grid h-7 w-7 shrink-0 place-items-center rounded-md text-xs font-bold", action.tone === "critical" ? "bg-rose-500/20 text-rose-200" : action.tone === "warning" ? "bg-amber-400/20 text-amber-200" : "bg-slate-700/50 text-slate-200")}>{index + 1}</span>
                <span className="min-w-0 flex-1"><span className="line-clamp-2 text-[11px] font-semibold leading-4 text-slate-200 group-hover:text-white">{action.title}</span><span className="mt-1 block truncate text-[9px] uppercase tracking-wider text-slate-600">{action.label}</span></span>
                <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-slate-600 group-hover:text-orange-300" />
              </Link>
            </li>
          ))}
        </ol>
      </Panel>

      <Panel title="Deployment recommendation" className="xl:col-span-6">
        {recommendation ? (
          <div className="flex flex-col gap-4 rounded-xl border border-orange-300/20 bg-orange-400/[0.035] p-4 sm:flex-row sm:items-center">
            <span className="grid h-12 w-12 shrink-0 place-items-center rounded-xl border border-orange-300/25 bg-orange-400/[0.08] text-orange-300"><ShieldCheck className="h-6 w-6" /></span>
            <div className="min-w-0 flex-1"><p className="text-sm font-semibold text-slate-100">{recommendation.title}</p><p className="mt-1 line-clamp-2 text-[11px] leading-5 text-slate-500">{recommendation.detail}</p></div>
            <Link href={recommendation.href} className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-orange-300/25 px-3 py-2 text-[11px] font-semibold text-orange-200 hover:bg-orange-400/10">View recommendation <ArrowUpRight className="h-3.5 w-3.5" /></Link>
          </div>
        ) : <p className="text-xs text-slate-500">No deployment recommendation is available.</p>}
      </Panel>

      <Panel title="Recent activity" className="xl:col-span-6">
        {recent.length ? <div>{recent.map((event) => <RecentEvent key={event.id} event={event} />)}</div> : <p className="py-8 text-center text-xs text-slate-500">No material activity in the current feed.</p>}
      </Panel>
    </div>
  );
}
