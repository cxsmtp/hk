"use client";

import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { resolvePresentationState, type PresentationState } from "@/lib/presentation-state";
import type { AIOrchestrationResult, Connector, DeploymentCoverageSummary, DriftAlert } from "@/lib/types";

export default function MonitoringPage() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [alerts, setAlerts] = useState<DriftAlert[]>([]);
  const [deploymentCoverage, setDeploymentCoverage] = useState<DeploymentCoverageSummary | null>(null);
  const [name, setName] = useState("Custom Connector");
  const [guidanceLoadingId, setGuidanceLoadingId] = useState("");
  const [selectedGuidanceAlertId, setSelectedGuidanceAlertId] = useState("");
  const [guidanceByAlert, setGuidanceByAlert] = useState<Record<string, AIOrchestrationResult>>({});
  const [presentationState, setPresentationState] = useState<PresentationState>("loading");
  const hasDataRef = useRef(false);

  const load = useCallback(async () => {
    const hadData = hasDataRef.current;
    setPresentationState(resolvePresentationState({ loading: true, hasData: hadData, stale: hadData }));
    try {
      const [conns, drift, coverage] = await Promise.all([
        api.listConnectors(),
        api.listDriftAlerts(),
        api.deploymentCoverage(),
      ]);
      setConnectors(conns.items || []);
      setAlerts(drift.items || []);
      setDeploymentCoverage(coverage);
      hasDataRef.current = Boolean(coverage) || Boolean(conns.items?.length) || Boolean(drift.items?.length);
      setPresentationState(resolvePresentationState({ loading: false, hasData: hasDataRef.current }));
    } catch {
      setPresentationState(resolvePresentationState({ loading: false, hasData: hadData, unavailable: true }));
      throw new Error("Monitoring sources did not respond");
    }
  }, []);

  useEffect(() => {
    load().catch(() => {
      // Keep any previously loaded rows visible and label the source state explicitly.
    });
  }, [load]);

  async function createConnector(e: FormEvent) {
    e.preventDefault();
    try {
      await api.createConnector({
        name,
        provider_key: "gemini",
        connector_type: "gemini",
        config: { poll_interval_sec: 900 },
      });
      toast.success("Connector created");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Create connector failed");
    }
  }

  async function generateDriftGuidance(alert: DriftAlert) {
    setGuidanceLoadingId(alert.id);
    try {
      const result = await api.generateDriftRemediationGuidance(alert.id, {
        task_type: "drift_explanation",
        data_sensitivity: "internal",
        allowed_remediation_types: [
          "policy_update",
          "restrict_permission",
          "review_owner",
          "run_simulation",
          "ticket",
          "investigate",
          "rollback",
        ],
      });
      setGuidanceByAlert((current) => ({ ...current, [alert.id]: result }));
      setSelectedGuidanceAlertId(alert.id);
      toast.success("Drift remediation guidance generated.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to generate drift guidance");
    } finally {
      setGuidanceLoadingId("");
    }
  }

  const selectedGuidance = selectedGuidanceAlertId ? guidanceByAlert[selectedGuidanceAlertId] || null : null;

  return (
    <AppShell>
      <div className="space-y-6">
        <OperationalState
          state={presentationState}
          onRetry={() => void load()}
          description={presentationState === "unavailable" ? "Monitoring sources are unavailable. Existing records remain unchanged." : undefined}
        />
        <PageSection
          title="Deployment Coverage"
          description="Cross-surface AI coverage posture for browser, gateway, connectors, and network/API telemetry."
        >
          {deploymentCoverage ? (
            <>
              <div className="grid gap-3 md:grid-cols-4">
                <div className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Overall Coverage</p>
                  <p className="text-2xl font-semibold text-slate-900">{deploymentCoverage.coverage_percent.toFixed(2)}%</p>
                </div>
                <div className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Enforceable Surfaces Observed</p>
                  <p className="text-2xl font-semibold text-slate-900">
                    {deploymentCoverage.enforcement_capability?.enforceable_surfaces_observed ?? 0}
                  </p>
                </div>
                <div className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Monitoring-only Surfaces Observed</p>
                  <p className="text-2xl font-semibold text-slate-900">
                    {deploymentCoverage.enforcement_capability?.monitoring_only_surfaces_observed ?? 0}
                  </p>
                </div>
                <div className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Connector Enablement</p>
                  <p className="text-2xl font-semibold text-slate-900">
                    {deploymentCoverage.connector_posture.enabled_connectors}/{deploymentCoverage.connector_posture.total_connectors}
                  </p>
                </div>
              </div>

              <div className="mt-4">
                <SimpleTable
                  columns={["Surface", "Covered", "Events", "Policy Bound", "Last Seen"]}
                  rows={(deploymentCoverage.surfaces || []).map((row) => [
                    `${row.label} (${row.coverage_percent.toFixed(0)}%)`,
                    row.covered ? "yes" : "no",
                    String(row.observed_event_count),
                    String(row.policy_enforced_count),
                    row.last_seen_at ? new Date(row.last_seen_at).toLocaleString() : "-",
                  ])}
                />
              </div>

              <details className="mt-4 rounded-xl border border-white/[0.08] bg-[#0a0f16]">
                <summary className="cursor-pointer list-none px-4 py-3 text-sm font-semibold text-slate-200">Technical telemetry breakdowns</summary>
                <div className="border-t border-white/[0.07] p-4">
              <div className="grid gap-4 lg:grid-cols-2">
                <SimpleTable
                  columns={["Observed Surface", "Event Count"]}
                  rows={Object.entries(deploymentCoverage.observed_surface_counts || {})
                    .sort((a, b) => b[1] - a[1])
                    .map(([surface, count]) => [surface, String(count)])}
                />
                <SimpleTable
                  columns={["Observed Provider Category", "Event Count"]}
                  rows={Object.entries(deploymentCoverage.observed_provider_category_counts || {})
                    .sort((a, b) => b[1] - a[1])
                    .map(([category, count]) => [category, String(count)])}
                />
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <SimpleTable
                  columns={["Coverage Slice", "Count"]}
                  rows={Object.entries(deploymentCoverage.coverage_by_surface_type || {})
                    .sort((a, b) => b[1] - a[1])
                    .map(([label, count]) => [label, String(count)])}
                />
                <SimpleTable
                  columns={["Supported Provider Category", "Catalog Entries"]}
                  rows={Object.entries(deploymentCoverage.provider_catalog?.supported_provider_counts || {})
                    .sort((a, b) => b[1] - a[1])
                    .map(([category, count]) => [category, String(count)])}
                />
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <SimpleTable
                  columns={["Observed Provider", "Event Count"]}
                  rows={Object.entries(deploymentCoverage.observed_provider_counts || {})
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 12)
                    .map(([provider, count]) => [provider, String(count)])}
                />
                <SimpleTable
                  columns={["Blind-spot Category", "Unseen Providers"]}
                  rows={Object.entries(deploymentCoverage.provider_blind_spots_by_category || {})
                    .sort((a, b) => b[1].length - a[1].length)
                    .map(([category, providers]) => [category, String(providers.length)])}
                />
              </div>

              <div className="mt-4">
                <SimpleTable
                  columns={["Provider", "Enforceable", "Monitoring-only", "Unsupported"]}
                  rows={Object.entries(deploymentCoverage.provider_surface_mode_counts || {})
                    .sort((a, b) => {
                      const totalA = Object.values(a[1] || {}).reduce((acc, item) => acc + Number(item || 0), 0);
                      const totalB = Object.values(b[1] || {}).reduce((acc, item) => acc + Number(item || 0), 0);
                      return totalB - totalA;
                    })
                    .slice(0, 12)
                    .map(([provider, modes]) => [
                      provider,
                      String(modes?.enforceable || 0),
                      String(modes?.monitoring_only || 0),
                      String(modes?.unsupported || 0),
                    ])}
                />
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <div className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="mb-2 text-xs uppercase tracking-wide text-slate-500">Enforcement Surface Gaps</p>
                  <div className="flex flex-wrap gap-2">
                    {(deploymentCoverage.enforcement_capability?.enforcement_surface_gaps || []).length ? (
                      (deploymentCoverage.enforcement_capability?.enforcement_surface_gaps || []).map((gap) => (
                        <span key={`enf-${gap}`} className="rounded-full border border-rose-300 bg-rose-50 px-2 py-1 text-xs text-rose-700">
                          {gap}
                        </span>
                      ))
                    ) : (
                      <span className="text-sm text-emerald-700">No enforcement-surface gaps.</span>
                    )}
                  </div>
                </div>
                <div className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="mb-2 text-xs uppercase tracking-wide text-slate-500">Monitoring Surface Gaps</p>
                  <div className="flex flex-wrap gap-2">
                    {(deploymentCoverage.enforcement_capability?.monitoring_surface_gaps || []).length ? (
                      (deploymentCoverage.enforcement_capability?.monitoring_surface_gaps || []).map((gap) => (
                        <span key={`mon-${gap}`} className="rounded-full border border-amber-300 bg-amber-50 px-2 py-1 text-xs text-amber-700">
                          {gap}
                        </span>
                      ))
                    ) : (
                      <span className="text-sm text-emerald-700">No monitoring-surface gaps.</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="mt-4 rounded-md border border-amber-200 bg-amber-50 p-3">
                <p className="mb-2 text-xs uppercase tracking-wide text-amber-700">Coverage Gaps / Blind Spots</p>
                <div className="flex flex-wrap gap-2">
                  {(deploymentCoverage.gaps || []).length > 0 ? (
                    (deploymentCoverage.gaps || []).map((gap) => (
                      <span key={gap} className="rounded-full border border-amber-300 bg-white px-2 py-1 text-xs text-amber-800">
                        {gap}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-emerald-700">No active coverage gaps detected.</span>
                  )}
                </div>
              </div>
                </div>
              </details>
            </>
          ) : (
            <p className="text-sm text-slate-600">Coverage telemetry is loading.</p>
          )}
        </PageSection>

        <PageSection title="Continuous Monitoring" description="Source health from connector pulls and drift alerts. Connector ingest stubs remain visible; raw telemetry remains available in Technical telemetry breakdowns.">
          <form className="mb-4 flex gap-2" onSubmit={createConnector}>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
            <Button type="submit">Create Connector</Button>
          </form>
          <SimpleTable
            columns={["Name", "Type", "Status", "Last Pull", "Signals"]}
            rows={connectors.map((c) => [
              c.name,
              c.provider_key || c.connector_type,
              c.last_pull_status || c.status,
              c.last_run_at ? new Date(c.last_run_at).toLocaleString() : "-",
              String(c.last_signal_count ?? 0),
            ])}
          />
        </PageSection>

        <PageSection title="Drift Alerts">
          <SimpleTable
            columns={["Alert ID", "Title", "Status", "Actions"]}
            rows={alerts.map((a) => [
              a.id,
              a.title,
              a.status,
              <Button
                key={`drift-guidance-${a.id}`}
                variant="outline"
                onClick={() => generateDriftGuidance(a)}
                disabled={guidanceLoadingId === a.id}
              >
                {guidanceLoadingId === a.id ? "Generating..." : "Generate Guidance"}
              </Button>,
            ])}
          />
        </PageSection>

        <PageSection
          title="AI Remediation Guidance"
          description="Bounded reasoning plan for selected drift alert. Enforcement remains deterministic."
        >
          {selectedGuidance ? (
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-3">
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-400">Model Route</p>
                  <p className="text-sm font-semibold text-slate-100 break-words">
                    {selectedGuidance.provider} / {selectedGuidance.model}
                  </p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-400">Prompt Template</p>
                  <p className="text-sm font-semibold text-slate-100 break-all">{selectedGuidance.prompt_template_id}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-400">Trace ID</p>
                  <p className="text-sm font-semibold text-slate-100 break-all">{selectedGuidance.trace_id}</p>
                </div>
              </div>

              <div className="rounded-xl border border-[#2a3348] bg-[#101524] p-4">
                <p className="text-sm font-semibold text-slate-100">
                  {selectedGuidance.remediation_guidance?.summary || "No summary returned"}
                </p>
                <p className="mt-1 text-sm text-slate-300">
                  {selectedGuidance.remediation_guidance?.root_cause_hypothesis || "-"}
                </p>
                <p className="mt-2 text-xs text-slate-400">
                  Priority: {selectedGuidance.remediation_guidance?.priority || "-"} · Confidence:{" "}
                  {typeof selectedGuidance.remediation_guidance?.confidence === "number"
                    ? selectedGuidance.remediation_guidance.confidence.toFixed(2)
                    : "-"}
                </p>
              </div>

              <SimpleTable
                columns={["Step", "Action", "Description", "Approval", "Frameworks"]}
                rows={(selectedGuidance.remediation_guidance?.recommended_steps || []).map((step) => [
                  step.step_order,
                  step.action_type,
                  step.description,
                  step.requires_approval ? "required" : "not_required",
                  step.linked_frameworks.join(", ") || "-",
                ])}
              />
            </div>
          ) : (
            <p className="text-sm text-slate-500">Generate guidance from a drift alert row to inspect remediation recommendations.</p>
          )}
        </PageSection>
      </div>
    </AppShell>
  );
}
