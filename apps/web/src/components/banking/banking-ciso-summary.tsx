"use client";

import Link from "next/link";
import { AlertTriangle, Bot, Database, Route, ShieldCheck, Wrench } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { PageSection } from "@/components/page-section";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { BankingCisoSummary } from "@/lib/types";

function humanize(value: string): string {
  return String(value || "unknown").replaceAll("_", " ");
}

function shortReference(value: string): string {
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function boundaryTone(status: BankingCisoSummary["subject_boundary_status"]): string {
  if (status === "evidence_backed") return "border-emerald-400/25 bg-emerald-400/10 text-emerald-200";
  if (status === "gaps_present") return "border-rose-400/25 bg-rose-400/10 text-rose-200";
  return "border-amber-400/25 bg-amber-400/10 text-amber-200";
}

export function BankingCisoSummaryPanel() {
  const [summary, setSummary] = useState<BankingCisoSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setSummary(await api.bankingCisoSummary());
    } catch (reason) {
      setSummary(null);
      setError(reason instanceof Error ? reason.message : "Banking transaction evidence unavailable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const verification = summary?.consequential_execution_verified_percent;
  const metrics = [
    ["Observed transactions", error ? "Unknown" : summary?.observed_transaction_count ?? 0, "Bounded evidence window"],
    ["Inline blockable", error ? "Unknown" : summary?.inline_blockable_count ?? 0, "Exact route binding present"],
    ["Execution verified", error || verification == null ? "Unknown" : `${verification}%`, "Consequential transactions only"],
    ["Drifted", error ? "Unknown" : summary?.drifted_transaction_count ?? 0, "Receipt or execution divergence"],
  ] as const;

  return (
    <PageSection
      title="Regulated AI transactions"
      description="CISO view over observed customer-facing banking evidence. This is a bounded transaction denominator, not an estate-wide claim."
    >
      <div className="overflow-hidden rounded-3xl border border-cyan-400/15 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.08),transparent_34%),#0a0f17]">
        <div className="flex flex-col gap-4 border-b border-white/[0.06] p-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-2xl border border-cyan-300/20 bg-cyan-300/10 text-cyan-200">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white">Customer boundary and execution proof</p>
              <p className="mt-1 text-xs text-slate-500">
                {loading ? "Loading observed evidence…" : summary?.evidence_window || "No verified evidence window"}
                {summary?.truncated ? " · truncated" : ""}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge className={`border ${boundaryTone(summary?.subject_boundary_status || "unknown")}`}>
              Subject boundary · {humanize(summary?.subject_boundary_status || "unknown")}
            </Badge>
            <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>Refresh</Button>
          </div>
        </div>

        {error ? (
          <div className="m-5 flex items-start gap-3 rounded-2xl border border-amber-400/15 bg-amber-400/[0.06] p-4 text-sm text-amber-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <div><p className="font-semibold">Unknown · evidence unavailable</p><p className="mt-1 text-xs text-amber-200/70">{error}</p></div>
          </div>
        ) : null}

        <div className="grid gap-px bg-white/[0.06] md:grid-cols-2 xl:grid-cols-4">
          {metrics.map(([label, value, hint]) => (
            <div key={label} className="bg-[#0a0f17] p-5">
              <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-600">{label}</p>
              <p className="mt-3 text-2xl font-semibold tracking-tight text-white">{loading ? "—" : value}</p>
              <p className="mt-1 text-xs text-slate-500">{hint}</p>
            </div>
          ))}
        </div>

        <div className="grid gap-4 p-5 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.8fr)]">
          <div className="grid gap-3 md:grid-cols-3">
            {[
              [Bot, "Agents", summary?.customer_facing_agents || []],
              [Wrench, "Tools", summary?.tool_references || []],
              [Database, "Data reach", summary?.data_reach || []],
            ].map(([Icon, label, values]) => {
              const TypedIcon = Icon as typeof Bot;
              const typedValues = values as string[];
              return (
                <div key={String(label)} className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-4">
                  <div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><TypedIcon className="h-4 w-4 text-cyan-300" />{String(label)}</div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {typedValues.length ? typedValues.slice(0, 8).map((value) => (
                      <span key={value} className="rounded-full border border-white/[0.07] bg-black/20 px-2 py-1 text-[10px] text-slate-400">{humanize(value)}</span>
                    )) : <span className="text-xs text-amber-200">Unknown</span>}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-200"><Route className="h-4 w-4 text-cyan-300" />Recent proof paths</div>
              <span className="text-[10px] text-slate-600">{error ? "Unknown" : summary?.observe_only_count || 0} observe-only</span>
            </div>
            <div className="mt-3 space-y-2">
              {(summary?.recent_transactions || []).slice(0, 5).map((transaction) => (
                <Link
                  key={transaction.ai_transaction_id}
                  href={`/runtime-intelligence/transactions/${encodeURIComponent(transaction.ai_transaction_id)}`}
                  className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.05] bg-black/20 px-3 py-2 transition hover:border-cyan-300/20"
                >
                  <div className="min-w-0"><p className="truncate text-xs font-medium text-slate-200">{humanize(transaction.tool_reference)}</p><p className="mt-0.5 text-[10px] text-slate-600">{shortReference(transaction.ai_transaction_id)} · {humanize(transaction.transport)}</p></div>
                  <Badge className={transaction.coverage_complete ? "bg-emerald-950 text-emerald-300" : "bg-amber-950 text-amber-300"}>{transaction.coverage_complete ? "Complete" : "Gap"}</Badge>
                </Link>
              ))}
              {!loading && !(summary?.recent_transactions || []).length ? <p className="py-4 text-center text-xs text-amber-200">Unknown · no regulated transaction evidence</p> : null}
            </div>
          </div>
        </div>

        {(summary?.control_gaps || []).length ? (
          <div className="flex flex-wrap items-center gap-2 border-t border-white/[0.06] px-5 py-3 text-[10px] text-slate-500">
            <span className="font-semibold uppercase tracking-[0.14em] text-amber-300">Current gaps</span>
            {summary!.control_gaps.map((gap) => <span key={gap} className="rounded-full border border-amber-400/10 bg-amber-400/[0.04] px-2 py-1">{humanize(gap)}</span>)}
          </div>
        ) : null}
      </div>
    </PageSection>
  );
}
