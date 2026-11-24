"use client";

import type { ReactNode } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Legend,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { CircleHelp, FlaskConical, ScrollText, Search, ShieldCheck } from "lucide-react";

import type { GovernanceOverviewModel } from "./command-center-visual-types";

const ESTATE_COLORS = ["#f5b942", "#5eead4", "#8b7cf6", "#60a5fa", "#fb7185", "#94a3b8"];

function Stage({
  number,
  title,
  subtitle,
  icon,
  children,
}: {
  number: string;
  title: string;
  subtitle: string;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <article
      tabIndex={0}
      className="min-w-0 border-b border-white/[0.07] px-5 py-5 outline-none transition focus-visible:ring-2 focus-visible:ring-orange-400/70 lg:border-b-0 lg:border-r last:lg:border-r-0"
      aria-labelledby={`governance-stage-${number}`}
    >
      <div className="flex items-start gap-3">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-orange-300/30 bg-orange-400/[0.07] text-sm font-semibold text-orange-200">
          {number}
        </span>
        <span className="mt-1 text-orange-300">{icon}</span>
        <div className="min-w-0">
          <h2 id={`governance-stage-${number}`} className="text-xs font-bold uppercase tracking-[0.18em] text-slate-100">{title}</h2>
          <p className="mt-1 text-[11px] text-slate-500">{subtitle}</p>
        </div>
      </div>
      <div className="mt-5">{children}</div>
    </article>
  );
}

function EmptyVisual({ children }: { children: ReactNode }) {
  return (
    <div className="grid h-44 place-items-center rounded-xl border border-dashed border-white/10 bg-black/10 px-4 text-center text-xs text-slate-500">
      {children}
    </div>
  );
}

function DiscoverStage({ model }: { model: GovernanceOverviewModel["discovery"] }) {
  const hasData = model.categories.length > 0;
  return (
    <div>
      <div className="mb-3 flex items-center gap-2 text-xs font-semibold text-slate-200">
        Observed estate
        <CircleHelp className="h-3.5 w-3.5 text-slate-600" aria-hidden="true" />
      </div>
      {hasData ? (
        <div className="grid grid-cols-[minmax(0,1fr)_118px] items-center gap-2" role="img" aria-label={`${model.observedEvents} observed events across ${model.categories.length} surfaces. Total estate is unknown.`}>
          <div className="relative h-44 min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={model.categories} dataKey="value" nameKey="label" cx="50%" cy="50%" innerRadius="50%" outerRadius="72%" stroke="#081019" strokeWidth={2}>
                  {model.categories.map((item, index) => <Cell key={item.label} fill={ESTATE_COLORS[index % ESTATE_COLORS.length]} />)}
                </Pie>
                <Pie data={[{ name: "Unknown beyond observed", value: 1 }]} dataKey="value" cx="50%" cy="50%" innerRadius="84%" outerRadius="85%" fill="transparent" stroke="#64748b" strokeDasharray="4 5" isAnimationActive={false} />
                <Tooltip contentStyle={{ background: "#0b111a", border: "1px solid #263044", borderRadius: 10, fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
              <div>
                <p className="text-2xl font-semibold text-white">{model.observedEvents.toLocaleString()}</p>
                <p className="mt-0.5 text-[10px] leading-4 text-slate-500">observed<br />events</p>
              </div>
            </div>
          </div>
          <div className="space-y-2">
            {model.categories.slice(0, 5).map((item, index) => (
              <div key={item.label} className="flex items-center justify-between gap-2 text-[10px]">
                <span className="flex min-w-0 items-center gap-2 text-slate-400"><span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: ESTATE_COLORS[index % ESTATE_COLORS.length] }} />{item.label}</span>
                <span className="font-semibold tabular-nums text-slate-200">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      ) : <EmptyVisual>No observed estate events in the current scope.</EmptyVisual>}
      <div className="mt-3 flex items-center justify-between gap-3 border-t border-white/[0.06] pt-3 text-[10px]">
        <span className="font-medium text-slate-300">Unknown beyond observed</span>
        <span className="text-slate-600">No verified estate denominator</span>
      </div>
    </div>
  );
}

function ProtectStage({ model }: { model: GovernanceOverviewModel["protect"] }) {
  const data = [{
    name: "Surfaces",
    "Inline verified": model.inlineVerified,
    "Monitor-only": model.monitorOnly,
    "Not covered": model.notCovered,
    Unknown: model.unknown,
  }];
  const entries = [
    ["Inline verified", model.inlineVerified, "#5eead4", "Pre-action authority evidenced"],
    ["Monitor-only", model.monitorOnly, "#f5b942", "Observation without stop authority"],
    ["Not covered", model.notCovered, "#ef5b5b", "Outside current control"],
    ["Unknown", model.unknown, "#64748b", "Insufficient verification"],
  ] as const;
  return (
    <div>
      <div className="mb-3 text-xs font-semibold text-slate-200">Enforcement posture</div>
      {model.totalSurfaces > 0 ? (
        <div className="h-36" role="img" aria-label={`${model.inlineVerified} inline verified, ${model.monitorOnly} monitor-only, ${model.notCovered} not covered, ${model.unknown} unknown surfaces.`}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 10, right: 5, bottom: 10, left: 5 }}>
              <XAxis type="number" hide domain={[0, "dataMax"]} />
              <YAxis type="category" dataKey="name" hide />
              <Tooltip contentStyle={{ background: "#0b111a", border: "1px solid #263044", borderRadius: 10, fontSize: 11 }} />
              <Bar dataKey="Inline verified" stackId="posture" fill="#5eead4" radius={[8, 0, 0, 8]} />
              <Bar dataKey="Monitor-only" stackId="posture" fill="#f5b942" />
              <Bar dataKey="Not covered" stackId="posture" fill="#ef5b5b" />
              <Bar dataKey="Unknown" stackId="posture" fill="#64748b" radius={[0, 8, 8, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : <EmptyVisual>No deployment surfaces are verified in this scope.</EmptyVisual>}
      <div className="mt-1 grid gap-2 sm:grid-cols-2 lg:grid-cols-1 2xl:grid-cols-2">
        {entries.map(([label, value, color, description]) => (
          <div key={label} className="flex gap-2 rounded-lg border border-white/[0.055] bg-white/[0.018] p-2">
            <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />
            <div><p className="text-[10px] font-semibold text-slate-200">{label} · {value}</p><p className="mt-0.5 text-[9px] leading-4 text-slate-600">{description}</p></div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ValidateStage({ model }: { model: GovernanceOverviewModel["validate"] }) {
  const canCompare = model.executedRuns > 0 && model.profile.length >= 3;
  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <span className="text-xs font-semibold text-slate-200">Simulation vs observed</span>
        <span className="text-[10px] text-slate-500">Executed simulations: {model.executedRuns}</span>
      </div>
      {canCompare ? (
        <div className="h-52" role="img" aria-label={`Observed technical enforcement compared with executed simulation pass rate across ${model.profile.length} controls.`}>
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={model.profile} outerRadius="68%">
              <PolarGrid stroke="#334155" />
              <PolarAngleAxis dataKey="control" tick={{ fill: "#94a3b8", fontSize: 9 }} />
              <Radar name="Observed enforcement" dataKey="observed" stroke="#5eead4" fill="#5eead4" fillOpacity={0.12} strokeWidth={2} />
              <Radar name="Simulated pass rate" dataKey="simulated" stroke="#f5b942" fill="#f5b942" fillOpacity={0.06} strokeDasharray="5 4" />
              <Legend wrapperStyle={{ fontSize: 10, color: "#94a3b8" }} />
              <Tooltip contentStyle={{ background: "#0b111a", border: "1px solid #263044", borderRadius: 10, fontSize: 11 }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      ) : <EmptyVisual>{model.executedRuns > 0 ? "Comparable per-control evidence is unavailable." : "No executed simulations in this scope."}</EmptyVisual>}
      <div className="mt-3 grid grid-cols-3 gap-2 text-center">
        <div><p className="text-lg font-semibold text-white">{model.executedRuns}</p><p className="text-[9px] uppercase tracking-wider text-slate-600">Executed</p></div>
        <div><p className="text-lg font-semibold text-emerald-300">{model.passedRuns}</p><p className="text-[9px] uppercase tracking-wider text-slate-600">Passed</p></div>
        <div><p className="text-lg font-semibold text-rose-300">{model.failedRuns}</p><p className="text-[9px] uppercase tracking-wider text-slate-600">Failed</p></div>
      </div>
      <p className="mt-3 text-[10px] leading-4 text-slate-600">Simulation results remain validation evidence; they do not establish runtime coverage.</p>
    </div>
  );
}

function ProveStage({ model, river }: { model: GovernanceOverviewModel["prove"]; river: GovernanceOverviewModel["river"] }) {
  const proven = river.filter((item) => item.evidenceState === "verified").slice(-5).reverse();
  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <span className="text-xs font-semibold text-slate-200">Evidence chain</span>
        <span className="text-[10px] font-semibold text-orange-300">Evidence-linked · {model.evidenceLinkedActions}</span>
      </div>
      {proven.length ? (
        <ol className="space-y-1" aria-label="Recent evidence-linked actions">
          {proven.map((item, index) => (
            <li key={item.id} className="relative grid grid-cols-[14px_minmax(0,1fr)] gap-3 py-2">
              {index < proven.length - 1 ? <span className="absolute bottom-0 left-[6px] top-4 w-px bg-slate-700" aria-hidden="true" /> : null}
              <span className="relative mt-1 h-3.5 w-3.5 rounded-full border-2 border-[#0a1018] bg-emerald-300 ring-1 ring-emerald-300" aria-hidden="true" />
              <div className="min-w-0"><p className="truncate text-[11px] font-medium text-slate-200">{item.summary}</p><p className="mt-1 text-[9px] text-slate-600">{item.decision} · {item.surface}</p></div>
            </li>
          ))}
        </ol>
      ) : <EmptyVisual>No evidence-linked actions are available in the current feed.</EmptyVisual>}
      <div className="mt-3 grid grid-cols-3 gap-2 border-t border-white/[0.06] pt-3 text-center">
        <div><p className="text-base font-semibold text-emerald-300">{model.evidenceLinkedActions}</p><p className="text-[9px] text-slate-600">Verified</p></div>
        <div><p className="text-base font-semibold text-amber-300">{model.incompleteActions}</p><p className="text-[9px] text-slate-600">Incomplete</p></div>
        <div><p className="text-base font-semibold text-slate-300">{model.unknownActions}</p><p className="text-[9px] text-slate-600">Unknown</p></div>
      </div>
    </div>
  );
}

export function GovernanceStoryline({ model }: { model: GovernanceOverviewModel }) {
  return (
    <section className="overflow-hidden rounded-2xl border border-white/[0.08] bg-[#091019] shadow-[0_26px_90px_rgba(0,0,0,0.28)]" aria-label="Governance Storyline">
      <div className="grid lg:grid-cols-4">
        <Stage number="1" title="Discover" subtitle="Understand the observed estate" icon={<Search className="h-4 w-4" aria-hidden="true" />}>
          <DiscoverStage model={model.discovery} />
        </Stage>
        <Stage number="2" title="Protect" subtitle="Enforce and monitor" icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />}>
          <ProtectStage model={model.protect} />
        </Stage>
        <Stage number="3" title="Validate" subtitle="Test what matters" icon={<FlaskConical className="h-4 w-4" aria-hidden="true" />}>
          <ValidateStage model={model.validate} />
        </Stage>
        <Stage number="4" title="Prove" subtitle="Assemble defensible evidence" icon={<ScrollText className="h-4 w-4" aria-hidden="true" />}>
          <ProveStage model={model.prove} river={model.river} />
        </Stage>
      </div>
    </section>
  );
}
