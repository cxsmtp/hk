"use client";

import {
  AlertTriangle,
  Braces,
  Fingerprint,
  Gauge,
  GitCompareArrows,
  HeartPulse,
  Network,
  ReceiptText,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { BankingTransactionProjection, NativeControlPointHealth } from "@/lib/types";


function humanize(value: string): string {
  return String(value || "unknown").replaceAll("_", " ");
}

function safeValue(value?: string | null): string {
  return value && value !== "unknown" ? value : "Unknown";
}

function DiagnosticCard({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: typeof Network;
  label: string;
  value: string;
  detail: string;
}) {
  const unknown = value === "Unknown";
  return (
    <article className="rounded-xl border border-white/[0.08] bg-[#090e15] p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-slate-500">
          <Icon className="h-4 w-4" />
          <p className="text-[10px] font-semibold uppercase tracking-[0.15em]">{label}</p>
        </div>
        <Badge className={unknown ? "bg-amber-950 text-amber-200" : "bg-cyan-950 text-cyan-200"}>
          {unknown ? "No evidence" : "Observed"}
        </Badge>
      </div>
      <p className={`mt-3 break-all text-sm font-semibold ${unknown ? "text-amber-200" : "text-slate-100"}`}>{value}</p>
      <p className="mt-2 text-xs leading-5 text-slate-500">{detail}</p>
    </article>
  );
}

function ReceiptList({ title, values }: { title: string; values: string[] }) {
  return (
    <div className="rounded-xl border border-white/[0.08] bg-black/20 p-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-600">{title}</p>
      <div className="mt-3 space-y-2">
        {values.length ? values.map((value) => (
          <p key={value} className="break-all rounded-lg border border-cyan-300/10 bg-cyan-300/[0.04] px-3 py-2 font-mono text-[11px] text-cyan-100">{value}</p>
        )) : <p className="text-sm text-amber-200">Unknown · no correlated receipt</p>}
      </div>
    </div>
  );
}

export default function BankingTransactionDiagnosticsPage() {
  const params = useParams<{ id: string }>();
  const transactionId = decodeURIComponent(String(params.id || ""));
  const [transaction, setTransaction] = useState<BankingTransactionProjection | null>(null);
  const [controlHealth, setControlHealth] = useState<NativeControlPointHealth | null>(null);
  const [controlHealthError, setControlHealthError] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      setControlHealth(null);
      setControlHealthError("");
      try {
        const payload = await api.bankingTransaction(transactionId);
        if (cancelled) return;
        setTransaction(payload);
        if (payload.control_point_reference !== "unknown") {
          try {
            const health = await api.nativeControlPointHealth(payload.control_point_reference);
            if (!cancelled) setControlHealth(health);
          } catch {
            if (!cancelled) setControlHealthError("Exact control-point health is unavailable");
          }
        }
      } catch (reason) {
        if (!cancelled) {
          setTransaction(null);
          setError(reason instanceof Error ? reason.message : "Developer evidence unavailable");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    if (transactionId) void load();
    return () => { cancelled = true; };
  }, [transactionId]);

  const failedValidation = useMemo(() => {
    if (!transaction) return [];
    const missingCoverage = Object.entries(transaction.coverage)
      .filter(([, value]) => value.status === "unknown" || value.status === "not_covered")
      .map(([name, value]) => `${humanize(name)}: ${value.reason}`);
    return [...transaction.drift_flags.map(humanize), ...missingCoverage];
  }, [transaction]);

  const integrationMethod = transaction
    ? `${humanize(transaction.transport)} · ${humanize(transaction.tool_reference)}`
    : "Unknown";
  const middlewareHealth = controlHealth ? humanize(controlHealth.health_state) : "Unknown";
  const observedLatency = controlHealth?.observed_latency_ms == null
    ? "Unknown"
    : `${controlHealth.observed_latency_ms} ms`;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence · Engineering"
          title="Developer diagnostics"
          description="Exact integration and receipt material for one pseudonymous transaction. Runtime health, latency, and test state remain Unknown unless transaction-bound evidence exists."
          actions={
            <Button asChild variant="outline">
              <Link href={`/runtime-intelligence/transactions/${encodeURIComponent(transactionId)}`}>Back to CISO transaction view</Link>
            </Button>
          }
        />

        {error ? (
          <div role="alert" className="flex gap-3 rounded-xl border border-rose-300/25 bg-rose-300/[0.07] p-4 text-sm text-rose-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <div><p className="font-semibold">Unknown · diagnostics unavailable</p><p className="mt-1 text-xs text-rose-200/70">{error}</p></div>
          </div>
        ) : null}

        <PageSection title="Integration contract" description="Observed canonical material only. Hawk does not reconstruct missing middleware or provider telemetry.">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <DiagnosticCard icon={Network} label="Integration method" value={loading ? "Unknown" : integrationMethod} detail="Canonical transport and tool reference recorded for this transaction." />
            <DiagnosticCard icon={HeartPulse} label="Middleware health" value={middlewareHealth} detail={controlHealth ? `Exact control point ${controlHealth.integration_id}; callback ${humanize(controlHealth.callback_health)}.` : controlHealthError || "No exact control-point reference is bound to this transaction."} />
            <DiagnosticCard icon={ShieldCheck} label="Policy version" value={loading ? "Unknown" : safeValue(transaction?.policy_version)} detail="Server-owned policy version bound to the decision material." />
            <DiagnosticCard icon={Braces} label="Action schema" value={loading ? "Unknown" : safeValue(transaction?.action_schema)} detail="Canonical action schema recorded before execution authorization." />
            <DiagnosticCard icon={Fingerprint} label="Tool fingerprint" value={loading ? "Unknown" : safeValue(transaction?.tool_fingerprint_reference)} detail="Inventory/schema fingerprint reference—not provider display text." />
            <DiagnosticCard icon={Gauge} label="Observed latency" value={observedLatency} detail={controlHealth?.observed_latency_ms == null ? "No measured latency is available for the exact bound control point." : "Current measured control-point latency; not transaction end-to-end latency."} />
            <DiagnosticCard icon={GitCompareArrows} label="Failed validation" value={failedValidation.length ? `${failedValidation.length} issue(s)` : transaction ? "None observed" : "Unknown"} detail="Drift and evidence gaps from this exact transaction, not a global test result." />
            <DiagnosticCard icon={ReceiptText} label="Test failures" value="Unknown" detail="No signed acceptance-run result is correlated to this transaction." />
          </div>
        </PageSection>

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Receipt correlation" description="Existing Hawk receipt IDs; no parallel banking receipt is introduced.">
            <div className="grid gap-3 md:grid-cols-2">
              <ReceiptList title="Decision Receipt" values={transaction?.decision_receipt_ids || []} />
              <ReceiptList title="Execution Receipt" values={transaction?.execution_receipt_ids || []} />
            </div>
          </PageSection>

          <PageSection title="Validation detail" description="Material failures and incomplete coverage remain visible to the integration owner.">
            <div className="space-y-2">
              {failedValidation.length ? failedValidation.map((item) => (
                <div key={item} className="rounded-lg border border-rose-300/15 bg-rose-300/[0.05] px-3 py-2 text-xs leading-5 text-rose-100">{item}</div>
              )) : transaction ? (
                <div className="rounded-lg border border-emerald-300/15 bg-emerald-300/[0.05] px-3 py-2 text-xs text-emerald-100">
                  No failed validation is recorded. Coverage complete: {transaction.coverage_complete ? "yes" : "no"}.
                </div>
              ) : <p className="text-sm text-amber-200">Unknown · transaction evidence has not loaded</p>}
            </div>
          </PageSection>
        </div>

        <PageSection title="Integration snippet" description="Illustrative ordering contract only; environment-specific identity and credentials remain outside the page.">
          <pre className="overflow-x-auto rounded-xl border border-white/[0.08] bg-[#070b10] p-4 text-xs leading-6 text-slate-300"><code>{`// Hawk must be the final mutation-capable gate.
var decision = await hawk.AuthorizeAsync(canonicalAction, cancellationToken);
await hawk.RevalidateAsync(decision.ReceiptId, canonicalAction.Hash, cancellationToken);
var result = await next(cancellationToken); // exactly once; never called on block
await hawk.ReportExecutionAsync(decision.ReceiptId, result, cancellationToken);`}</code></pre>
          <p className="mt-3 text-xs text-slate-500">Subject, customer, account, prompt, response, token, and raw tool arguments are intentionally absent from this diagnostic view.</p>
        </PageSection>
      </div>
    </AppShell>
  );
}
