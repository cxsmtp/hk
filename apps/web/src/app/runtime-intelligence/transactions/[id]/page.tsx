"use client";

import {
  AlertTriangle,
  ArrowRight,
  Bot,
  CheckCircle2,
  CircleDot,
  Fingerprint,
  Landmark,
  Route,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type {
  BankingCoverageDimension,
  BankingCoverageStatus,
  BankingTimelineEvent,
  BankingTransactionProjection,
} from "@/lib/types";


const COVERAGE_ORDER = [
  "subject",
  "identity",
  "purpose",
  "model",
  "function",
  "mcp",
  "direct_api",
  "parameter_binding",
  "target_binding",
  "destination_binding",
  "approval_binding",
  "execution_visibility",
  "execution_verification",
  "response_assurance",
  "bypass",
] as const;

const STAGE_LABELS: Record<string, string> = {
  authenticated: "Customer authenticated",
  agent_run: "Agent run",
  model_request: "Model request",
  action_proposed: "Action proposed",
  hawk_decision: "Hawk decision",
  approval: "Approval",
  execution: "Execution",
  bank_evidence: "Bank evidence",
  verification: "Execution verification",
  model_response: "Model response",
  response_assurance: "Response assurance",
  customer_response: "Customer response",
  sentinel_export: "Sentinel export",
};

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function shortReference(value: string): string {
  if (!value || value === "unknown") return "Unknown";
  if (value.length <= 28) return value;
  return `${value.slice(0, 15)}…${value.slice(-8)}`;
}

function coverageTone(status: BankingCoverageStatus): string {
  if (status === "covered") return "border-emerald-300/25 bg-emerald-300/[0.08] text-emerald-100";
  if (status === "not_covered") return "border-rose-300/25 bg-rose-300/[0.08] text-rose-100";
  if (status === "not_applicable") return "border-slate-600/40 bg-slate-800/35 text-slate-400";
  return "border-amber-300/25 bg-amber-300/[0.08] text-amber-100";
}

function coverageDot(status: BankingCoverageStatus): string {
  if (status === "covered") return "bg-emerald-300 shadow-[0_0_12px_rgba(110,231,183,0.65)]";
  if (status === "not_covered") return "bg-rose-300 shadow-[0_0_12px_rgba(253,164,175,0.55)]";
  if (status === "not_applicable") return "bg-slate-600";
  return "bg-amber-300 shadow-[0_0_12px_rgba(252,211,77,0.5)]";
}

function timelineTone(state: BankingTimelineEvent["state"]): string {
  if (state === "observed") return "border-emerald-300/35 bg-emerald-300/10 text-emerald-100";
  if (state === "blocked") return "border-rose-300/35 bg-rose-300/10 text-rose-100";
  if (state === "pending") return "border-cyan-300/35 bg-cyan-300/10 text-cyan-100";
  return "border-amber-300/35 bg-amber-300/10 text-amber-100";
}

function formatTime(value: string): string {
  if (!value || value === "unknown") return "Time unknown";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function receiptTone(value: string): string {
  return value && value !== "unknown" ? "text-cyan-100" : "text-amber-200";
}

function CoverageCard({ name, dimension }: { name: string; dimension: BankingCoverageDimension }) {
  return (
    <article className={`group relative overflow-hidden rounded-xl border p-3.5 transition duration-200 hover:-translate-y-0.5 ${coverageTone(dimension.status)}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] opacity-65">{humanize(name)}</p>
          <p className="mt-2 text-sm font-semibold">{humanize(dimension.status)}</p>
        </div>
        <span className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${coverageDot(dimension.status)}`} />
      </div>
      <p className="mt-2 min-h-10 text-xs leading-5 opacity-75">{dimension.reason}</p>
      <p className="mt-3 font-mono text-[10px] opacity-55">
        {dimension.evidence_refs.length ? `${dimension.evidence_refs.length} evidence ref${dimension.evidence_refs.length === 1 ? "" : "s"}` : "No evidence reference"}
      </p>
    </article>
  );
}

function ReceiptPanel({ title, ids }: { title: string; ids: string[] }) {
  return (
    <div className="rounded-xl border border-white/[0.08] bg-[#080d13] p-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600">{title}</p>
      {ids.length ? (
        <div className="mt-3 space-y-2">
          {ids.map((id) => (
            <p key={id} className={`break-all rounded-lg border border-cyan-300/10 bg-cyan-300/[0.04] px-3 py-2 font-mono text-[11px] ${receiptTone(id)}`}>{id}</p>
          ))}
        </div>
      ) : <p className="mt-3 text-sm text-amber-200">Unknown · no receipt evidence</p>}
    </div>
  );
}

export default function BankingTransactionPage() {
  const params = useParams<{ id: string }>();
  const transactionId = decodeURIComponent(String(params.id || ""));
  const [transaction, setTransaction] = useState<BankingTransactionProjection | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const payload = await api.bankingTransaction(transactionId);
        if (!cancelled) setTransaction(payload);
      } catch (reason) {
        const message = reason instanceof Error ? reason.message : "Unable to load AI transaction";
        if (!cancelled) {
          setTransaction(null);
          setError(message);
          toast.error(message);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    if (transactionId) load().catch(() => undefined);
    return () => { cancelled = true; };
  }, [transactionId]);

  const blindSpots = useMemo(
    () => Object.entries(transaction?.coverage || {}).filter(([, dimension]) =>
      dimension.status === "unknown" || dimension.status === "not_covered"),
    [transaction],
  );
  const evidenceReferences = useMemo(
    () => Array.from(new Set([
      ...(transaction?.decision_receipt_ids || []),
      ...(transaction?.execution_receipt_ids || []),
      ...Object.values(transaction?.coverage || {}).flatMap((dimension) => dimension.evidence_refs),
    ])),
    [transaction],
  );
  const decision = transaction?.decision || "unknown";
  const integrity = transaction?.integrity_status || "unknown";

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence · Regulated transaction"
          title="AI Transaction"
          description="One subject-bound chain from authentication through action authorization, execution proof, response assurance, and customer release. Unknown evidence stays Unknown."
          actions={
            <div className="flex flex-wrap gap-2">
              <RuntimeIntelligenceTabs />
              <Button asChild variant="outline"><Link href={`/runtime-intelligence/transactions/${encodeURIComponent(transactionId)}/diagnostics`}>Developer diagnostics</Link></Button>
              <Button asChild variant="outline"><Link href="/runtime-intelligence/overview">Back to Runtime Intelligence</Link></Button>
            </div>
          }
        />

        {error ? <div role="alert" className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">{error}</div> : null}

        <KpiStrip items={[
          { label: "Transaction", value: shortReference(transaction?.ai_transaction_id || transactionId), hint: loading ? "Loading evidence…" : "End-to-end correlation", tone: "info" },
          { label: "Decision", value: humanize(decision), hint: transaction?.selected_controls.join(" · ") || "No selected control evidence", tone: decision === "allow" ? "success" : decision === "block" ? "critical" : "warning" },
          { label: "Integrity", value: humanize(integrity), hint: transaction?.drift_flags.length ? `${transaction.drift_flags.length} drift flag(s)` : "No recorded drift flag", tone: integrity === "matched" ? "success" : integrity === "drift_detected" ? "critical" : "warning" },
          { label: "Transport", value: humanize(transaction?.transport || "unknown"), hint: `${humanize(transaction?.target_class || "unknown")} → ${humanize(transaction?.destination_class || "unknown")}`, tone: "info" },
          { label: "Coverage", value: transaction?.coverage_complete ? "Complete" : "Incomplete", hint: transaction?.coverage_complete ? "Every applicable dimension has evidence" : `${blindSpots.length} blind spot${blindSpots.length === 1 ? "" : "s"} remain`, tone: transaction?.coverage_complete ? "success" : "warning" },
        ]} />

        <section className="relative overflow-hidden rounded-2xl border border-cyan-300/15 bg-[radial-gradient(circle_at_15%_0%,rgba(34,211,238,0.09),transparent_38%),linear-gradient(145deg,#071019_0%,#090d13_55%,#100d08_100%)] p-5 shadow-[0_28px_80px_rgba(0,0,0,0.28)]">
          <div aria-hidden="true" className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-200/60 to-transparent" />
          <div className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
            <div>
              <div className="flex items-center gap-2 text-cyan-100"><Landmark className="h-4 w-4" /><p className="text-xs font-semibold uppercase tracking-[0.16em]">Trusted transaction spine</p></div>
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                {[
                  [Fingerprint, "Subject", `${humanize(transaction?.subject_type || "unknown")} · ${shortReference(transaction?.subject_reference || "unknown")}`],
                  [ShieldCheck, "Purpose", humanize(transaction?.business_purpose || "unknown")],
                  [Bot, "Agent chain", transaction?.agent_chain.length ? transaction.agent_chain.join(" → ") : "Unknown"],
                  [CircleDot, "Model", humanize(transaction?.model || "unknown")],
                  [Route, "Action", `${humanize(transaction?.action_class || "unknown")} · ${humanize(transaction?.transport || "unknown")}`],
                  [ShieldAlert, "Control result", `${humanize(decision)} · ${humanize(integrity)}`],
                ].map(([Icon, label, value]) => {
                  const Glyph = Icon as typeof Fingerprint;
                  return (
                    <div key={String(label)} className="rounded-xl border border-white/[0.08] bg-black/20 p-3.5">
                      <div className="flex items-center gap-2 text-slate-500"><Glyph className="h-3.5 w-3.5" /><p className="text-[10px] font-semibold uppercase tracking-[0.14em]">{String(label)}</p></div>
                      <p className="mt-2 break-words text-sm font-medium text-slate-100">{String(value)}</p>
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="rounded-xl border border-white/[0.08] bg-black/25 p-4">
              <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Assurance legend</p>
              <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
                {[
                  ["Covered", "bg-emerald-300"],
                  ["Not covered", "bg-rose-300"],
                  ["Unknown", "bg-amber-300"],
                  ["Not applicable", "bg-slate-600"],
                ].map(([label, dot]) => <div key={label} className="flex items-center gap-2 rounded-lg border border-white/[0.06] px-3 py-2 text-slate-300"><span className={`h-2 w-2 rounded-full ${dot}`} />{label}</div>)}
              </div>
              <p className="mt-4 text-xs leading-5 text-slate-500">Coverage is evaluated per dimension. Hawk does not average missing evidence into a marketing score.</p>
            </div>
          </div>
        </section>

        <PageSection title="Control Coverage" description="Independent, evidence-backed dimensions for this exact transaction. Not Applicable is not counted as protection; Unknown is never promoted.">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-5">
            {COVERAGE_ORDER.map((name) => {
              const dimension = transaction?.coverage[name];
              return <CoverageCard key={name} name={name} dimension={dimension || { status: "unknown", reason: "Evidence has not loaded", evidence_refs: [] }} />;
            })}
          </div>
        </PageSection>

        <PageSection title="Transaction timeline" description="A single immutable chain. Missing stages are omitted rather than reconstructed from assumptions.">
          <div className="overflow-x-auto pb-2">
            <ol className="flex min-w-max items-stretch gap-0">
              {(transaction?.timeline || []).map((event, index, events) => (
                <li key={`${event.stage}:${index}`} className="flex items-center">
                  <article className={`relative w-56 rounded-xl border p-4 ${timelineTone(event.state)}`}>
                    <div className="flex items-center justify-between gap-3">
                      {event.state === "observed" ? <CheckCircle2 className="h-4 w-4" /> : event.state === "blocked" ? <ShieldAlert className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4" />}
                      <Badge className="border-current/20 bg-transparent text-[9px] uppercase tracking-wider">{event.state}</Badge>
                    </div>
                    <p className="mt-4 text-sm font-semibold">{STAGE_LABELS[event.stage] || humanize(event.stage)}</p>
                    <p className="mt-1 text-[11px] opacity-65">{formatTime(event.occurred_at)}</p>
                    <p className="mt-3 font-mono text-[10px] opacity-55">{event.evidence_refs.length} evidence ref{event.evidence_refs.length === 1 ? "" : "s"}</p>
                  </article>
                  {index < events.length - 1 ? (
                    <div aria-hidden="true" className="relative h-px w-12 overflow-hidden bg-cyan-200/20">
                      <span className="absolute inset-y-0 left-0 w-6 animate-[transaction-flow_1.8s_linear_infinite] bg-gradient-to-r from-transparent via-cyan-200 to-transparent" />
                      <ArrowRight className="absolute -right-1 -top-2 h-4 w-4 text-cyan-300/50" />
                    </div>
                  ) : null}
                </li>
              ))}
            </ol>
            {!loading && !transaction?.timeline.length ? <p className="py-8 text-center text-sm text-amber-200">Unknown · no transaction timeline evidence</p> : null}
          </div>
        </PageSection>

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Receipts" description="Exact IDs from Hawk's existing signed receipt chain.">
            <div className="grid gap-3 md:grid-cols-2">
              <ReceiptPanel title="Decision Receipt" ids={transaction?.decision_receipt_ids || []} />
              <ReceiptPanel title="Execution Receipt" ids={transaction?.execution_receipt_ids || []} />
            </div>
          </PageSection>

          <PageSection title="Drift & blind spots" description="Material divergence and missing assurance are shown separately.">
            <div className="space-y-3">
              {transaction?.drift_flags.length ? transaction.drift_flags.map((flag) => (
                <div key={flag} className="flex gap-3 rounded-xl border border-rose-300/20 bg-rose-300/[0.07] p-3 text-sm text-rose-100"><ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" /><span>{humanize(flag)}</span></div>
              )) : <div className="flex gap-3 rounded-xl border border-emerald-300/15 bg-emerald-300/[0.06] p-3 text-sm text-emerald-100"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" /><span>No material drift flag is present in the current evidence.</span></div>}
              {blindSpots.map(([name, dimension]) => (
                <div key={name} className={`rounded-xl border p-3 ${coverageTone(dimension.status)}`}>
                  <div className="flex items-center justify-between gap-3"><p className="text-sm font-semibold">{humanize(name)}</p><span className="text-[10px] font-semibold uppercase tracking-wider">{humanize(dimension.status)}</span></div>
                  <p className="mt-1 text-xs leading-5 opacity-75">{dimension.reason}</p>
                </div>
              ))}
            </div>
          </PageSection>
        </div>

        <PageSection title="Evidence references" description="Progressive drilldown references only; raw customer, account, prompt, response, and transaction values are intentionally absent.">
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {evidenceReferences.map((reference) => <p key={reference} className="break-all rounded-lg border border-white/[0.07] bg-[#080d13] px-3 py-2 font-mono text-[11px] text-slate-400">{reference}</p>)}
          </div>
          {!evidenceReferences.length ? <p className="text-sm text-amber-200">Unknown · no evidence references</p> : null}
          <div className="mt-4 flex flex-wrap gap-2">
            <Button asChild variant="outline"><Link href="/evidence">Open evidence explorer</Link></Button>
            <Button asChild variant="outline"><Link href="/policies">Open policy</Link></Button>
            <Button asChild variant="outline"><Link href="/surface-coverage">Open control plan</Link></Button>
          </div>
        </PageSection>
        <style jsx global>{`
          @keyframes transaction-flow {
            from { transform: translateX(-100%); }
            to { transform: translateX(250%); }
          }
        `}</style>
      </div>
    </AppShell>
  );
}
