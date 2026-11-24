"use client";

import { ArrowRight, CircleAlert, GitBranch, ScanSearch, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ActivityLineageCertainty, ActivityLineageProjection } from "@/lib/types";

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function compact(value: unknown, fallback = "Unknown"): string {
  if (value === null || value === undefined || value === "") return fallback;
  const rendered = typeof value === "string" ? value : JSON.stringify(value);
  return rendered.length > 160 ? `${rendered.slice(0, 157)}…` : rendered;
}

function certaintyClass(certainty: ActivityLineageCertainty | string): string {
  if (certainty === "CONFIRMED") return "border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-200";
  if (certainty === "CORRELATED") return "border-cyan-400/30 bg-cyan-400/[0.08] text-cyan-200";
  if (certainty === "INFERRED") return "border-dashed border-amber-400/40 bg-amber-400/[0.07] text-amber-200";
  return "border-dotted border-slate-500/50 bg-slate-500/[0.06] text-slate-300";
}

function integrityClass(result: string): string {
  if (["MATCHED", "SEMANTICALLY_MATCHED"].includes(result)) return "border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-200";
  if (["DRIFTED", "FAILED", "BLOCKED"].includes(result)) return "border-rose-400/30 bg-rose-400/[0.08] text-rose-200";
  if (["PARTIAL", "PENDING"].includes(result)) return "border-amber-400/30 bg-amber-400/[0.08] text-amber-200";
  return "border-slate-500/40 bg-slate-500/[0.08] text-slate-300";
}

const questionLabels: Array<[string, string]> = [
  ["originating_actor", "Originating actor"],
  ["executing_principal", "Executing principal"],
  ["represented_subject", "Represented subject"],
  ["purpose_and_authority", "Purpose & authority"],
  ["tools_or_services", "Tools & services"],
  ["resources_targets_destinations", "Resources & targets"],
];

export function ActivityLineageInvestigation({ data }: { data: ActivityLineageProjection }) {
  const orderedNodes = [...data.nodes]
    .sort((left, right) => left.ordinal - right.ordinal)
    .filter((node) => !["DECISION_RECEIPT", "EXECUTION_PERMIT", "EXECUTION_RECEIPT", "VALIDATION_RUN", "DRIFT_SIGNAL"].includes(node.node_type))
    .slice(0, 16);
  const evidenceCount = new Set(data.nodes.flatMap((node) => node.evidence_refs)).size;
  const comparison = data.authorised_vs_executed;
  const executed = comparison.executed;

  return (
    <div className="space-y-5">
      <section className="overflow-hidden rounded-2xl border border-cyan-300/15 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.10),transparent_36%),linear-gradient(135deg,#101622,#0b0f17_65%)] shadow-[0_24px_80px_rgba(0,0,0,0.28)]">
        <div className="grid gap-5 p-5 lg:grid-cols-[1.4fr_0.6fr] lg:p-6">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.24em] text-cyan-300/80">AI Action Investigation</span>
              <Badge className={`border ${data.lineage.status === "COMPLETE" ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-200" : "border-amber-400/30 bg-amber-400/10 text-amber-200"}`}>
                {data.lineage.status}
              </Badge>
              <Badge className={`border ${integrityClass(comparison.result)}`}>{comparison.result}</Badge>
            </div>
            <h2 className="mt-4 text-2xl font-semibold tracking-tight text-white">One action. One evidence chain.</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              A tenant-scoped reconstruction of who initiated the action, which authority and agents carried it,
              what Hawk authorised, what executed, and which proof remains incomplete.
            </p>
            <div className="mt-5 flex flex-wrap gap-2 text-[11px] text-slate-400">
              <span className="rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5">Action {data.lineage.seed_action_id}</span>
              <span className="rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5">{data.nodes.length} entities</span>
              <span className="rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5">{data.edges.length} established relationships</span>
              <span className="rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5">{evidenceCount} evidence references</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 self-start">
            <div className="rounded-xl border border-white/[0.07] bg-black/20 p-3">
              <p className="font-mono text-[9px] uppercase tracking-widest text-slate-500">Drift dimensions</p>
              <p className={`mt-2 text-2xl font-semibold ${comparison.drift_fields.length ? "text-rose-200" : "text-emerald-200"}`}>{comparison.drift_fields.length}</p>
            </div>
            <div className="rounded-xl border border-white/[0.07] bg-black/20 p-3">
              <p className="font-mono text-[9px] uppercase tracking-widest text-slate-500">Blind spots</p>
              <p className={`mt-2 text-2xl font-semibold ${data.blind_spots.length ? "text-amber-200" : "text-emerald-200"}`}>{data.blind_spots.length}</p>
            </div>
            <div className="col-span-2 rounded-xl border border-white/[0.07] bg-black/20 p-3">
              <p className="font-mono text-[9px] uppercase tracking-widest text-slate-500">Immutable source watermark</p>
              <p className="mt-2 break-all font-mono text-[10px] text-cyan-200/75">{data.lineage.source_watermark}</p>
            </div>
          </div>
        </div>
      </section>

      <Card className="border-white/[0.07] bg-[#0d121b]">
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-mono text-[9px] uppercase tracking-[0.22em] text-cyan-300/70">Established lineage</p>
              <CardTitle className="mt-2 flex items-center gap-2 text-base text-white"><GitBranch className="h-4 w-4 text-cyan-300" /> Evidence river</CardTitle>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(["CONFIRMED", "CORRELATED", "INFERRED", "UNKNOWN"] as ActivityLineageCertainty[]).map((certainty) => (
                <Badge key={certainty} className={`border font-mono text-[8px] ${certaintyClass(certainty)}`}>{certainty}</Badge>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto pb-2">
            <div className="flex min-w-max items-stretch gap-0">
              {orderedNodes.map((node, index) => (
                <div key={node.id} className="flex items-center">
                  <article className={`w-48 rounded-xl border p-3 ${certaintyClass(node.certainty)}`}>
                    <div className="flex items-start justify-between gap-2">
                      <span className="font-mono text-[8px] uppercase tracking-widest opacity-70">{humanize(node.node_type)}</span>
                      <span className="h-2 w-2 shrink-0 rounded-full bg-current opacity-70" />
                    </div>
                    <p className="mt-3 break-words text-xs font-semibold text-white">{node.label}</p>
                    <p className="mt-2 break-all font-mono text-[8px] opacity-60">{node.authority_type}</p>
                    <div className="mt-3 flex items-center justify-between gap-2 font-mono text-[8px] uppercase">
                      <span>{node.certainty}</span>
                      <span>{node.evidence_quality}</span>
                    </div>
                  </article>
                  {index < orderedNodes.length - 1 ? (
                    <div className="relative flex w-10 items-center justify-center text-cyan-300/35">
                      <span className="absolute h-px w-full bg-gradient-to-r from-cyan-300/10 via-cyan-300/60 to-cyan-300/10" />
                      <ArrowRight className="relative h-3.5 w-3.5 animate-pulse" />
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
          <p className="mt-3 text-[10px] leading-4 text-slate-500">
            Layout is ordinal for readability. Relationship labels and certainty come from the bounded edge set; visual proximity alone is not evidence of causality.
          </p>
        </CardContent>
      </Card>

      <section className="grid gap-4 xl:grid-cols-2">
        <Card className="border-cyan-300/10 bg-[#0d121b]">
          <CardHeader className="pb-3">
            <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan-300/70">Decision authority</p>
            <CardTitle className="text-base text-white">Authorised</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(comparison.authorised).map(([field, card]) => (
              <div key={field} className="grid grid-cols-[9rem_1fr] gap-3 border-b border-white/[0.05] py-2 text-xs last:border-0">
                <span className="text-slate-500">{humanize(field)}</span>
                <span className={card.state === "OBSERVED" ? "break-words text-slate-200" : "text-slate-600"}>{card.state === "OBSERVED" ? compact(card.value) : `Unknown · ${card.reason_code || "not persisted"}`}</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card className="border-violet-300/10 bg-[#0d121b]">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-violet-300/70">Execution evidence</p>
                <CardTitle className="mt-1 text-base text-white">Executed</CardTitle>
              </div>
              <Badge className={`border ${integrityClass(comparison.result)}`}>{comparison.result}</Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(executed).filter(([field]) => !["evidence_refs", "reason_code", "state"].includes(field)).map(([field, value]) => (
              <div key={field} className="grid grid-cols-[9rem_1fr] gap-3 border-b border-white/[0.05] py-2 text-xs last:border-0">
                <span className="text-slate-500">{humanize(field)}</span>
                <span className={value ? "break-all font-mono text-[10px] text-slate-200" : "text-slate-600"}>{compact(value)}</span>
              </div>
            ))}
            {comparison.drift_fields.length ? (
              <div className="mt-3 rounded-xl border border-rose-400/20 bg-rose-400/[0.06] p-3">
                <p className="font-mono text-[9px] uppercase tracking-widest text-rose-200">Material drift</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {comparison.drift_fields.map((field) => <Badge key={field} className="border border-rose-400/25 bg-rose-400/10 text-rose-200">{humanize(field)}</Badge>)}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.25fr_0.75fr]">
        <Card className="border-white/[0.07] bg-[#0d121b]">
          <CardHeader className="pb-3">
            <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-emerald-300/70">Controls & evidence</p>
            <CardTitle className="flex items-center gap-2 text-base text-white"><ShieldCheck className="h-4 w-4 text-emerald-300" /> Current assurance</CardTitle>
          </CardHeader>
          <CardContent>
            {data.control_assurance.length ? (
              <div className="space-y-2">
                {data.control_assurance.map((control) => (
                  <div key={control.assertion_id} className="grid gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 sm:grid-cols-[1fr_auto]">
                    <div>
                      <p className="text-xs font-medium text-slate-200">{humanize(control.capability)}</p>
                      <p className="mt-1 font-mono text-[9px] text-slate-500">Last validated {control.last_validated_at || "Unknown"}</p>
                    </div>
                    <Badge className={`border ${control.assurance_state === "CURRENT" ? certaintyClass("CONFIRMED") : control.assurance_state === "REGRESSED" ? integrityClass("DRIFTED") : certaintyClass("UNKNOWN")}`}>
                      {control.assurance_state || "UNKNOWN"}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : <p className="text-sm text-slate-500">Control assurance is Unknown for this action.</p>}
          </CardContent>
        </Card>
        <Card className="border-white/[0.07] bg-[#0d121b]">
          <CardHeader className="pb-3">
            <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-slate-400">Investigator answers</p>
            <CardTitle className="flex items-center gap-2 text-base text-white"><ScanSearch className="h-4 w-4 text-cyan-300" /> What the evidence says</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {questionLabels.map(([key, label]) => {
              const answer = data.questions[key];
              return (
                <div key={key} className="rounded-lg border border-white/[0.05] bg-black/10 px-3 py-2">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-[10px] text-slate-500">{label}</span>
                    <Badge className={`border font-mono text-[8px] ${certaintyClass(answer?.state || "UNKNOWN")}`}>{answer?.state || "UNKNOWN"}</Badge>
                  </div>
                  <p className="mt-1 text-[10px] leading-4 text-slate-300">{answer?.state === "UNKNOWN" ? humanize(answer.reason_code || "evidence unavailable") : compact(answer?.value)}</p>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </section>

      {(data.findings.length || data.blind_spots.length) ? (
        <Card className="border-amber-300/10 bg-[#0d121b]">
          <CardHeader className="pb-3">
            <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-amber-300/70">Findings & visibility limits</p>
            <CardTitle className="flex items-center gap-2 text-base text-white"><CircleAlert className="h-4 w-4 text-amber-300" /> Evidence gaps stay visible</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-2 md:grid-cols-2">
            {data.findings.map((finding) => (
              <div key={finding.id} className="rounded-xl border border-rose-400/15 bg-rose-400/[0.04] p-3">
                <div className="flex items-center justify-between gap-3"><p className="text-xs font-medium text-slate-200">{finding.title}</p><Badge>{finding.severity}</Badge></div>
                <p className="mt-2 text-[10px] text-slate-500">{humanize(finding.reason_code)} · {finding.evidence_refs.length} evidence refs</p>
              </div>
            ))}
            {data.blind_spots.map((blindSpot) => (
              <div key={blindSpot} className="rounded-xl border border-amber-400/15 bg-amber-400/[0.035] p-3">
                <p className="font-mono text-[9px] uppercase tracking-widest text-amber-200">Unknown / unverified</p>
                <p className="mt-2 text-xs text-slate-300">{humanize(blindSpot)}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
