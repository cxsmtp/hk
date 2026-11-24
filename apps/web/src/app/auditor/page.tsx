"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { ModuleReportPanel } from "@/components/module-report-panel";
import { OperationalState } from "@/components/operational-state";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { SimpleTable } from "@/components/simple-table";
import { Button } from "@/components/ui/button";
import { RankedBarsCard, TrendSparkCard } from "@/components/visual-metrics";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { AuditEvidenceExplanation, AuditorControlPostureView, AuditorDashboard } from "@/lib/types";

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function asDateString(value: unknown): string {
  const text = String(value || "").trim();
  if (!text) return "-";
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return text;
  return parsed.toLocaleString();
}

function summarizeReportError(value: string | null): string | undefined {
  if (!value) return undefined;
  const normalized = value.toLowerCase();
  if (normalized.includes("governance_fail_secure") || normalized.includes("fail_secure")) {
    return "Report sources unavailable. Fail-secure controls remain active; no report result is inferred.";
  }
  return "Report sources unavailable. No report result is inferred until a source responds.";
}

function AuditorContent() {
  const searchParams = useSearchParams();
  const requestedEvidenceId = String(searchParams.get("evidence_id") || "").trim();
  const [dashboard, setDashboard] = useState<AuditorDashboard | null>(null);
  const [frameworkPosture, setFrameworkPosture] = useState<AuditorControlPostureView | null>(null);
  const [selectedProofId, setSelectedProofId] = useState<string>("");
  const [linkedEvidence, setLinkedEvidence] = useState<AuditEvidenceExplanation | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const [dashboardPayload, posturePayload] = await Promise.all([
        api.dashboard() as Promise<AuditorDashboard>,
        api.auditorControlPosture({ group_by: "framework" }),
      ]);
      setDashboard(dashboardPayload);
      setFrameworkPosture(posturePayload);
      setLoadError(null);
    } catch (error) {
      setDashboard(null);
      setFrameworkPosture(null);
      setLoadError(error instanceof Error ? error.message : "Report sources are unavailable.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load().catch(() => {
      setDashboard(null);
      setFrameworkPosture(null);
    });
  }, []);

  useEffect(() => {
    if (!requestedEvidenceId) {
      setLinkedEvidence(null);
      return;
    }
    api.auditEvidence(requestedEvidenceId)
      .then((payload) => {
        setLinkedEvidence(payload);
        setSelectedProofId(payload.evidence_id);
      })
      .catch(() => {
        setLinkedEvidence(null);
        setSelectedProofId(requestedEvidenceId);
      });
  }, [requestedEvidenceId]);

  async function exportSnapshot() {
    try {
      const result = (await api.exportAudit({})) as { artifacts: { json: string; csv: string; hash: string } };
      toast.success(`Exported JSON: ${result.artifacts.json}`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Export failed");
    }
  }

  const postureBars = useMemo(() => {
    if (!dashboard) return [] as Array<{ label: string; value: number; hint: string }>;
    return [
      { label: "Healthy", value: dashboard.healthy_count, hint: "Controls with healthy maturity posture" },
      { label: "Needs Review", value: dashboard.needs_review_count, hint: "Controls that need evidence review" },
      { label: "Contested", value: dashboard.contested_count, hint: "Controls with conflicting evidence" },
      { label: "Open Conflicts", value: dashboard.open_conflicts_count, hint: "Conflicts pending adjudication" },
    ];
  }, [dashboard]);

  const snapshotsTrend = useMemo(() => {
    if (!dashboard?.recent_snapshots?.length) return [] as Array<{ label: string; value: number }>;
    const counts = new Map<string, number>();
    (dashboard.recent_snapshots || []).forEach((item) => {
      const row = asRecord(item);
      const key = String(row.created_at || row.timestamp || "").slice(5, 10) || "-";
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return Array.from(counts.entries()).map(([label, value]) => ({ label, value }));
  }, [dashboard]);

  const proofFeedRows = useMemo(() => {
    const enforcement = (dashboard?.recent_enforcement_events || []).map((item, idx) => {
      const row = asRecord(item);
      const id = String(row.id || row.request_id || `enf-${idx}`);
      return {
        id,
        type: "enforcement",
        title: String(row.request_id || row.id || "event"),
        status: String(row.final_decision || "-"),
        createdAt: asDateString(row.timestamp || row.created_at),
      };
    });

    const snapshots = (dashboard?.recent_snapshots || []).map((item, idx) => {
      const row = asRecord(item);
      const id = String(row.id || `snapshot-${idx}`);
      return {
        id,
        type: "snapshot",
        title: String(row.id || row.artifact_path || "snapshot"),
        status: String(row.trigger_type || "snapshot"),
        createdAt: asDateString(row.created_at || row.timestamp),
      };
    });

    const linked = linkedEvidence ? [{
      id: linkedEvidence.evidence_id,
      type: linkedEvidence.signal_type || "evidence",
      title: linkedEvidence.label || linkedEvidence.evidence_id,
      status: linkedEvidence.decision || "linked",
      createdAt: asDateString(linkedEvidence.created_at),
    }] : [];
    return [...linked, ...enforcement, ...snapshots].slice(0, 20);
  }, [dashboard, linkedEvidence]);

  useEffect(() => {
    if (!proofFeedRows.length) {
      setSelectedProofId("");
      return;
    }
    if (requestedEvidenceId && !proofFeedRows.some((row) => row.id === requestedEvidenceId)) {
      setSelectedProofId(requestedEvidenceId);
      return;
    }
    if (!selectedProofId || !proofFeedRows.some((row) => row.id === selectedProofId)) {
      setSelectedProofId(proofFeedRows[0].id);
    }
  }, [proofFeedRows, requestedEvidenceId, selectedProofId]);

  const selectedProof = useMemo(
    () => proofFeedRows.find((row) => row.id === selectedProofId) || proofFeedRows[0] || null,
    [proofFeedRows, selectedProofId]
  );
  const reportState = resolvePresentationState({
    loading,
    hasData: Boolean(dashboard || frameworkPosture || proofFeedRows.length),
    unavailable: Boolean(loadError),
  });
  const reportHasSnapshot = Boolean(dashboard || frameworkPosture);

  const owaspBreakdown = useMemo(() => {
    const rows = frameworkPosture?.rows || [];
    const normalizedRows = rows.map((row) => {
      const label = String(row.group_label || "");
      return {
        ...row,
        normalized: label.toLowerCase(),
      };
    });

    const agentic = normalizedRows.filter(
      (row) => row.normalized.includes("owasp") && row.normalized.includes("agentic")
    );
    const mcp = normalizedRows.filter(
      (row) => row.normalized.includes("owasp") && row.normalized.includes("mcp")
    );
    const llm = normalizedRows.filter((row) => row.normalized.includes("owasp") && row.normalized.includes("llm"));
    const otherOwasp = normalizedRows.filter(
      (row) =>
        row.normalized.includes("owasp") &&
        !agentic.some((item) => item.group_key === row.group_key) &&
        !mcp.some((item) => item.group_key === row.group_key) &&
        !llm.some((item) => item.group_key === row.group_key)
    );

    const allScoped = [...agentic, ...mcp];
    const totalControls = allScoped.reduce((sum, row) => sum + row.controls_total, 0);
    const implemented = allScoped.reduce((sum, row) => sum + row.implemented_controls, 0);
    const partial = allScoped.reduce((sum, row) => sum + row.partial_controls, 0);
    const missing = allScoped.reduce((sum, row) => sum + row.not_implemented_controls, 0);

    const breakdownRows = allScoped.map((row) => [
      row.group_label,
      row.controls_total,
      row.implemented_controls,
      row.partial_controls,
      row.not_implemented_controls,
      row.avg_maturity_score.toFixed(2),
      row.avg_confidence_score.toFixed(2),
      row.ai_system_count,
    ]);

    return {
      agentic,
      mcp,
      llm,
      otherOwasp,
      totalControls,
      implemented,
      partial,
      missing,
      breakdownRows,
    };
  }, [frameworkPosture]);

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Auditor"
          title="Audit reports"
          description="Maturity-linked evidence reporting with immutable export artifacts and live proof chain visibility."
          actions={
            <Button variant="outline" onClick={() => load()}>
              Refresh
            </Button>
          }
        />

        <OperationalState
          state={reportState}
          title={loadError ? "Audit reports unavailable" : undefined}
          onRetry={() => void load()}
          description={summarizeReportError(loadError)}
        />
        {loadError ? <details className="rounded-xl border border-white/[0.08] bg-white/[0.02] px-4 py-3 text-xs text-slate-400"><summary className="cursor-pointer font-medium text-slate-200">Technical details</summary><pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words text-[11px] text-slate-500">{loadError}</pre></details> : null}

        <KpiStrip
          items={[
            { label: "Avg Maturity", value: loading ? "—" : dashboard?.average_maturity?.toFixed(2) ?? "Unavailable", tone: "success" },
            { label: "Avg Confidence", value: loading ? "—" : dashboard?.average_confidence?.toFixed(2) ?? "Unavailable", tone: "info" },
            { label: "Tracked Controls", value: loading ? "—" : dashboard?.maturity_count ?? "Unavailable", tone: "default" },
            { label: "Open Conflicts", value: loading ? "—" : dashboard?.open_conflicts_count ?? "Unavailable", tone: "critical" },
          ]}
        />

        <PageSection title="Audit Actions" description="Generate export packs and adjudicate contested evidence.">
          <div className="flex flex-wrap gap-2">
            <Button onClick={exportSnapshot}>Export Audit Snapshot (CSV/JSON)</Button>
            <Button asChild variant="outline">
              <Link href="/auditor/conflicts">Resolve Evidence Conflicts</Link>
            </Button>
          </div>
        </PageSection>

        <div className="grid items-start gap-4 xl:grid-cols-[360px_1fr]">
          <PageSection title="Proof Feed" description="Most recent auditable events and snapshot artifacts.">
            <div className="max-h-[32rem] space-y-2 overflow-y-auto pr-1">
              {proofFeedRows.length ? (
                proofFeedRows.map((row) => {
                  const active = row.id === selectedProof?.id;
                  return (
                    <button
                      key={row.id}
                      type="button"
                      onClick={() => setSelectedProofId(row.id)}
                      className={`w-full rounded-lg border px-3 py-3 text-left transition ${active ? "border-brand-500/50 bg-brand-500/10" : "border-[#2a3348] bg-[#0f1218] hover:border-brand-500/30"}`}
                    >
                      <p className="truncate text-sm font-semibold text-slate-100">{row.title}</p>
                      <p className="mt-1 text-xs text-slate-400">{row.type} · {row.status}</p>
                      <p className="text-xs text-slate-500">{row.createdAt}</p>
                    </button>
                  );
                })
              ) : (
                <p className="text-sm text-slate-500">{loading && !reportHasSnapshot ? "Loading proof artifacts…" : "No recent proof artifacts."}</p>
              )}
            </div>
          </PageSection>

          <PageSection title="Proof Inspector" description="Visual summary for selected proof item.">
            {selectedProof ? (
              <div className="space-y-3">
                <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {[
                    ["Reference ID", selectedProof.id],
                    ["Type", selectedProof.type],
                    ["Status", selectedProof.status],
                    ["Created", selectedProof.createdAt],
                    ["Maturity Coverage", dashboard ? `${dashboard.maturity_count} controls tracked` : "Unavailable"],
                    ["Open Conflicts", dashboard ? String(dashboard.open_conflicts_count) : "Unavailable"],
                  ].map(([label, value]) => (
                    <div key={label} className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-2">
                      <p className="text-[11px] uppercase tracking-[0.08em] text-slate-500">{label}</p>
                      <p className="mt-1 break-words text-sm font-semibold text-slate-100">{value}</p>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-sm text-slate-500">Select a proof feed item to inspect.</p>
            )}
          </PageSection>
        </div>

        {reportHasSnapshot ? (
          <div className="grid gap-4 xl:grid-cols-2">
            <RankedBarsCard
              title="Control Posture Breakdown"
              subtitle="How current evidence maps to maturity posture"
              items={postureBars}
            />
            <TrendSparkCard
              title="Snapshot Activity"
              subtitle="Recent snapshot creation cadence"
              points={snapshotsTrend}
              tone={(dashboard?.open_conflicts_count || 0) > 0 ? "warning" : "success"}
              yAxisLabel="Snapshots created"
              xAxisLabel="Recent timeline"
            />
          </div>
        ) : (
          <div className="rounded-xl border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-sm text-slate-400">
            {loading ? "Loading audit posture and snapshot activity…" : "Audit posture and snapshot activity are unavailable."}
          </div>
        )}

        <PageSection
          title="OWASP Agentic + MCP Breakdown Report"
          description="Explicit framework report for OWASP Agentic 2026 and OWASP MCP mappings, linked to implemented controls."
        >
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-4">
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-2">
                <p className="text-[11px] uppercase tracking-[0.08em] text-slate-500">Agentic Framework Rows</p>
                <p className="mt-1 text-xl font-semibold text-slate-100">{loading && !frameworkPosture ? "—" : owaspBreakdown.agentic.length}</p>
              </div>
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-2">
                <p className="text-[11px] uppercase tracking-[0.08em] text-slate-500">MCP Framework Rows</p>
                <p className="mt-1 text-xl font-semibold text-slate-100">{loading && !frameworkPosture ? "—" : owaspBreakdown.mcp.length}</p>
              </div>
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-2">
                <p className="text-[11px] uppercase tracking-[0.08em] text-slate-500">Mapped Controls (A+M)</p>
                <p className="mt-1 text-xl font-semibold text-slate-100">{loading && !frameworkPosture ? "—" : owaspBreakdown.totalControls}</p>
              </div>
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-2">
                <p className="text-[11px] uppercase tracking-[0.08em] text-slate-500">Implementation Split</p>
                <p className="mt-1 text-sm font-semibold text-slate-100">
                  {loading && !frameworkPosture ? "Loading framework posture…" : `${owaspBreakdown.implemented} implemented · ${owaspBreakdown.partial} partial · ${owaspBreakdown.missing} missing`}
                </p>
              </div>
            </div>

            {loading && !frameworkPosture ? (
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-3 text-sm text-slate-300">Loading framework mappings…</div>
            ) : owaspBreakdown.breakdownRows.length ? (
              <SimpleTable
                columns={[
                  "Framework",
                  "Controls",
                  "Implemented",
                  "Partial",
                  "Not Implemented",
                  "Avg Maturity",
                  "Avg Confidence",
                  "AI Systems",
                ]}
                rows={owaspBreakdown.breakdownRows}
              />
            ) : (
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-3 text-sm text-slate-300">
                No explicit OWASP Agentic or OWASP MCP framework mappings are currently present in control posture data.
              </div>
            )}

            <div className="grid gap-3 lg:grid-cols-2">
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-3">
                <p className="text-xs uppercase tracking-[0.08em] text-slate-500">OWASP LLM Framework Rows</p>
                <p className="mt-1 text-lg font-semibold text-slate-100">{loading && !frameworkPosture ? "—" : owaspBreakdown.llm.length}</p>
              </div>
              <div className="rounded-md border border-[#2a3348] bg-[#101524] px-3 py-3">
                <p className="text-xs uppercase tracking-[0.08em] text-slate-500">Other OWASP Rows</p>
                <p className="mt-1 text-lg font-semibold text-slate-100">{loading && !frameworkPosture ? "—" : owaspBreakdown.otherOwasp.length}</p>
              </div>
            </div>
          </div>
        </PageSection>

        <ModuleReportPanel
          footprintTitle="Audit Footprint"
          analyticsTitle="Auditor Analytics"
          footprintItems={[
            { label: "Tracked Controls", value: loading && !dashboard ? "—" : dashboard?.maturity_count ?? "Unavailable", tone: "info" },
            { label: "Needs Review", value: loading && !dashboard ? "—" : dashboard?.needs_review_count ?? "Unavailable", tone: "warning" },
            { label: "Contested Controls", value: loading && !dashboard ? "—" : dashboard?.contested_count ?? "Unavailable", tone: "critical" },
            { label: "Open Conflicts", value: loading && !dashboard ? "—" : dashboard?.open_conflicts_count ?? "Unavailable", tone: "critical" },
          ]}
          analyticsItems={[
            { label: "Average Maturity", value: loading && !dashboard ? "—" : dashboard?.average_maturity?.toFixed(2) ?? "Unavailable", tone: "success" },
            { label: "Average Confidence", value: loading && !dashboard ? "—" : dashboard?.average_confidence?.toFixed(2) ?? "Unavailable", tone: "info" },
            { label: "Healthy Controls", value: loading && !dashboard ? "—" : dashboard?.healthy_count ?? "Unavailable", tone: "success" },
            { label: "Recent Snapshots", value: loading && !dashboard ? "—" : dashboard?.recent_snapshots?.length ?? "Unavailable", tone: "default" },
          ]}
        />

        <PageSection title="Auditor Status Breakdown" description="Current posture buckets.">
          <SimpleTable
            columns={["Signal", "Value"]}
            rows={[
              ["Needs Review", loading && !dashboard ? "—" : dashboard?.needs_review_count ?? "Unavailable"],
              ["Contested Controls", loading && !dashboard ? "—" : dashboard?.contested_count ?? "Unavailable"],
              ["Healthy Controls", loading && !dashboard ? "—" : dashboard?.healthy_count ?? "Unavailable"],
              ["Open Conflicts", loading && !dashboard ? "—" : dashboard?.open_conflicts_count ?? "Unavailable"],
            ]}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}

export default function AuditorPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#080b12]" />}>
      <AuditorContent />
    </Suspense>
  );
}
