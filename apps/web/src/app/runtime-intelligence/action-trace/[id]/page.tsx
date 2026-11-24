"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { ActivityLineageInvestigation } from "@/components/runtime-intelligence/activity-lineage-investigation";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { buildActionIntegrityAuthorityView } from "@/lib/action-integrity-authority";
import type { ActionIntegrityDetail, ActivityLineageProjection } from "@/lib/types";

function text(value: unknown, fallback = "-"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function shortId(value: string | null | undefined): string {
  if (!value) return "Unknown";
  return value.length <= 26 ? value : `${value.slice(0, 12)}…${value.slice(-10)}`;
}

function storedTransactionHrefs(detail: ActionIntegrityDetail | null): string[] {
  if (!detail) return [];
  const references = [
    ...detail.browser_hrefs,
    ...detail.timeline.flatMap((stage) => stage.browser_hrefs || []),
  ];
  return Array.from(new Set(
    references
      .map((reference) => (typeof reference.href === "string" ? reference.href : ""))
      .filter((href) => href.startsWith("/runtime-intelligence/transactions/")),
  ));
}

export default function StoredActionDetailPage() {
  const params = useParams<{ id: string }>();
  // Next supplies the decoded dynamic segment. Decoding again changes literal
  // percent sequences and would violate the registry's decode-exactly-once rule.
  const runtimeEventId = String(params.id || "");
  const [detail, setDetail] = useState<ActionIntegrityDetail | null>(null);
  const [lineage, setLineage] = useState<ActivityLineageProjection | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lineageError, setLineageError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError("");
      setLineageError("");
      try {
        const [detailResult, lineageResult] = await Promise.allSettled([
          api.actionIntegrityDetail(runtimeEventId),
          api.activityLineageByRuntimeEvent(runtimeEventId, { depth: 3, limit: 100 }),
        ]);
        if (cancelled) return;
        if (detailResult.status === "fulfilled") setDetail(detailResult.value);
        else throw detailResult.reason;
        if (lineageResult.status === "fulfilled") setLineage(lineageResult.value);
        else {
          setLineage(null);
          setLineageError(lineageResult.reason instanceof Error ? lineageResult.reason.message : "Unable to load AI activity lineage");
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : "Unable to load stored Action Detail";
        if (!cancelled) {
          setDetail(null);
          setLineage(null);
          setError(message);
          toast.error(message);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    if (runtimeEventId) load().catch(() => undefined);
    return () => { cancelled = true; };
  }, [runtimeEventId]);

  const authority = useMemo(() => buildActionIntegrityAuthorityView(detail), [detail]);
  const approval = detail?.authorisation.approval_request;
  const approvalRequestId = detail?.identity.approval_request_id;
  const approvalHref = runtimeEventId && approvalRequestId && approval?.state === "OBSERVED"
    ? `/interaction-security?runtime_event_id=${encodeURIComponent(runtimeEventId)}&approval_request_id=${encodeURIComponent(approvalRequestId)}`
    : null;
  const transactionHrefs = useMemo(() => storedTransactionHrefs(detail), [detail]);
  const observedStages = authority.timeline.filter((stage) => stage.state === "OBSERVED").length;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence · Action Integrity"
          title="AI Action Investigation"
          description="Action-centric lineage over tenant-scoped stored authority. Hawk separates confirmed, correlated, inferred, and unknown relationships and never reconstructs missing proof from timestamps."
          actions={
            <div className="flex flex-wrap gap-2">
              <RuntimeIntelligenceTabs />
              {approvalHref ? (
                <Button asChild variant="outline">
                  <Link href={approvalHref}>Review stored approval</Link>
                </Button>
              ) : null}
              {transactionHrefs.map((href) => (
                <Button key={href} asChild variant="outline">
                  <Link href={href}>Open AI Transaction</Link>
                </Button>
              ))}
            </div>
          }
        />

        {error ? <div className="rounded-lg border border-rose-900/50 bg-rose-950/25 px-4 py-3 text-sm text-rose-200">Stored action evidence is unavailable. No lifecycle result is inferred.</div> : null}
        {lineageError ? <div className="rounded-lg border border-amber-900/50 bg-amber-950/20 px-4 py-3 text-sm text-amber-200">Related activity is unavailable. Stored action evidence remains available below.</div> : null}
        {error || lineageError ? <details className="rounded-lg border border-white/[0.08] bg-white/[0.02] px-4 py-3 text-xs text-slate-400"><summary className="cursor-pointer font-medium text-slate-200">Technical details</summary><pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words text-[11px] text-slate-500">{[error, lineageError].filter(Boolean).join("\n")}</pre></details> : null}

        {lineage ? <ActivityLineageInvestigation data={lineage} /> : null}

        <KpiStrip items={[
          { label: "Runtime event", value: shortId(detail?.identity.runtime_event_id || runtimeEventId), hint: "Tenant-scoped route key", tone: "info" },
          { label: "Stored sections", value: authority.sections.length, hint: "Context through execution", tone: "info" },
          { label: "Observed stages", value: observedStages, hint: "Evidence-backed only", tone: observedStages ? "success" : "default" },
          { label: "Unknown stages", value: authority.timeline.length - observedStages, hint: "Never inferred from a matching ID", tone: "warning" },
        ]} />

        <PageSection
          title="Stored authority"
          description="The five sections below use only records explicitly referenced by this runtime event. Each observation requires a tenant-valid Evidence Node."
        >
          <SimpleTable
            columns={["Section", "Stored field", "State", "Value", "Occurred", "Reason"]}
            rows={authority.sections.flatMap((section) => section.fields.map((field) => [
              section.label,
              field.field,
              <Badge key={`${section.key}:${field.field}:state`} className={field.state === "OBSERVED" ? "bg-emerald-500/20 text-emerald-200" : "bg-slate-500/20 text-slate-200"}>{field.state}</Badge>,
              field.state === "OBSERVED" ? text(field.value) : "Unknown",
              field.occurred_at || "-",
              field.reason_code || "-",
            ]))}
            emptyLabel={loading ? "Loading stored Action Detail…" : "No stored authority is available for this runtime event."}
          />
        </PageSection>

        <PageSection title="Action lifecycle" description="The immutable 14-stage order. A stage is observed only with its stored authority and tenant-valid evidence.">
          <ol className="grid gap-2 lg:grid-cols-2">
            {authority.timeline.map((stage) => (
              <li key={stage.event_type} className="grid grid-cols-[2.25rem_1fr] gap-3 rounded-lg border border-[#232a3a] bg-[#0d1119] p-3">
                <span className="font-mono text-xs text-brand-300">{String(stage.stage_ordinal).padStart(2, "0")}</span>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-semibold text-slate-100">{stage.event_type.replaceAll("_", " ")}</p>
                    <Badge className={stage.state === "OBSERVED" ? "bg-emerald-500/20 text-emerald-200" : "bg-slate-500/20 text-slate-200"}>{stage.state}</Badge>
                  </div>
                  <p className="mt-1 break-words text-xs text-slate-400">{stage.state === "OBSERVED" ? text(stage.value) : `Unknown${stage.reason_code ? ` · ${stage.reason_code}` : ""}`}</p>
                </div>
              </li>
            ))}
          </ol>
        </PageSection>

        <PageSection title="Evidence references" description="Stored proof links for each action stage. Missing proof stays visible and is never inferred.">
          <SimpleTable
            columns={["Stage", "Evidence", "Reason"]}
            rows={authority.timeline.map((stage) => [
              stage.event_type,
              stage.state === "OBSERVED" && Array.isArray(stage.evidence_node_ids) && stage.evidence_node_ids.length
                ? stage.evidence_node_ids.join(", ")
                : "Not covered",
              stage.reason_code || "-",
            ])}
          />
        </PageSection>

        <details className="rounded-lg border border-white/[0.08] bg-white/[0.02] px-4 py-3 text-xs text-slate-400">
          <summary className="cursor-pointer font-medium text-slate-200">Technical details</summary>
          <p className="mt-2 leading-5">Authority remains bound to stored records and tenant-valid evidence nodes. Presentation surfaces do not provide authority. When the stored record emits an AI Transaction reference, follow it through the linked transaction route.</p>
        </details>

        <PageSection title="Drift & blind spots" description="This view reports only stored integrity evidence. It does not synthesize a comparison or an execution result when the linked record is absent.">
          <SimpleTable
            columns={["Check", "State", "Stored reference"]}
            rows={[
              ["Decision Receipt", detail?.authorisation.decision_receipt.state || "UNKNOWN", shortId(detail?.identity.decision_receipt_id)],
              ["Execution Receipt", detail?.execution.execution_receipts.state || "UNKNOWN", shortId(detail?.identity.execution_receipt_ids?.[0])],
              ["Approval binding", detail?.authorisation.approval_binding.state || "UNKNOWN", shortId(detail?.identity.approval_binding_id)],
              ["Outcome integrity", detail?.execution.outcome_integrity.state || "UNKNOWN", "Stored evidence required"],
            ]}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
