"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { OperationalState } from "@/components/operational-state";
import { SimpleTable } from "@/components/simple-table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type {
  Control,
  ControlCoverage,
  ControlExplorerState,
  FrameworkCoverage,
  RuntimeControlViewState,
  SimulationControlViewState,
  SimulationCoverageSummary,
  SimulationHeatmap,
  SimulationTrendSeries,
} from "@/lib/types";
import type { PresentationState } from "@/lib/presentation-state";

function heatmapCellClasses(value: number, maxValue: number): string {
  if (value <= 0) {
    return "bg-slate-900/80 text-slate-400";
  }
  const ratio = maxValue > 0 ? value / maxValue : 0;
  if (ratio >= 0.7) {
    return "bg-rose-800/80 text-rose-100 font-semibold";
  }
  if (ratio >= 0.4) {
    return "bg-amber-700/80 text-amber-100 font-semibold";
  }
  return "bg-emerald-800/80 text-emerald-100 font-semibold";
}

function formatUsd(value: number | undefined): string {
  const numeric = Number(value || 0);
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(numeric);
}

function ValidationCoverageContent() {
  const searchParams = useSearchParams();
  const requestedControlId = String(searchParams.get("control_id") || "").trim();
  const [controls, setControls] = useState<Array<Pick<Control, "id" | "name">>>([]);
  const [selectedControl, setSelectedControl] = useState<string>("");
  const [frameworkName, setFrameworkName] = useState("NIST AI RMF");
  const [minSimulations, setMinSimulations] = useState(1);
  const [controlCoverage, setControlCoverage] = useState<ControlCoverage | null>(null);
  const [frameworkCoverage, setFrameworkCoverage] = useState<FrameworkCoverage | null>(null);
  const [summary, setSummary] = useState<SimulationCoverageSummary | null>(null);
  const [heatmap, setHeatmap] = useState<SimulationHeatmap | null>(null);
  const [trends, setTrends] = useState<SimulationTrendSeries | null>(null);

  const [controlExplorer, setControlExplorer] = useState<ControlExplorerState | null>(null);
  const [runtimeControlView, setRuntimeControlView] = useState<RuntimeControlViewState | null>(null);
  const [simulationControlView, setSimulationControlView] = useState<SimulationControlViewState | null>(null);
  const [explorerFramework, setExplorerFramework] = useState("");
  const [explorerCategory, setExplorerCategory] = useState("");
  const [explorerRiskTag, setExplorerRiskTag] = useState("");
  const [runtimeLookbackHours, setRuntimeLookbackHours] = useState(24);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const selectedControlLabel = useMemo(
    () => controls.find((item) => item.id === selectedControl)?.name || selectedControl,
    [controls, selectedControl],
  );

  const heatmapMaxCell = useMemo(() => {
    if (!heatmap) return 0;
    let maxValue = 0;
    for (const row of heatmap.rows) {
      for (const category of heatmap.categories) {
        const value = Number(row.cells[category] || 0);
        if (value > maxValue) maxValue = value;
      }
    }
    return maxValue;
  }, [heatmap]);

  async function loadControls() {
    const payload = await api.listControls();
    const rows = payload.items || [];
    setControls(rows);
  }

  useEffect(() => {
    setSelectedControl((current) => {
      const requestedControl = controls.find((control) => control.id === requestedControlId);
      if (requestedControlId) return requestedControl?.id || controls[0]?.id || "";
      if (current && controls.some((control) => control.id === current)) return current;
      return controls[0]?.id || "";
    });
  }, [controls, requestedControlId]);

  async function loadControlFoundation() {
    try {
      const explorer = await api.controlExplorer({
        foundation_only: true,
        framework: explorerFramework || undefined,
        category: explorerCategory || undefined,
        risk_tag: explorerRiskTag || undefined,
      });
      setControlExplorer(explorer);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Control explorer unavailable");
      toast.error(err instanceof Error ? err.message : "Control explorer fetch failed");
    }

    try {
      const runtimeView = await api.runtimeControlView(runtimeLookbackHours, true);
      setRuntimeControlView(runtimeView);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Runtime control view unavailable");
      toast.error(err instanceof Error ? err.message : "Runtime control view fetch failed");
    }

    try {
      const simulationView = await api.simulationControlView(true);
      setSimulationControlView(simulationView);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Simulation control view unavailable");
      toast.error(err instanceof Error ? err.message : "Simulation control view fetch failed");
    }
  }

  useEffect(() => {
    setLoading(true);
    void Promise.allSettled([
      loadControls().catch((err) => { setLoadError(err instanceof Error ? err.message : "Controls unavailable"); }),
      api.simulationCoverageSummary().then(setSummary).catch((err) => { setLoadError(err instanceof Error ? err.message : "Coverage summary unavailable"); }),
      api.simulationCoverageHeatmap().then(setHeatmap).catch((err) => { setLoadError(err instanceof Error ? err.message : "Coverage heatmap unavailable"); }),
      api.simulationCoverageTrends(14).then(setTrends).catch((err) => { setLoadError(err instanceof Error ? err.message : "Coverage trends unavailable"); }),
      loadControlFoundation(),
    ]).then(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function fetchControlCoverage() {
    if (!selectedControl) return;
    try {
      const payload = await api.controlValidationCoverage(selectedControl, 20);
      setControlCoverage(payload as ControlCoverage);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Control coverage unavailable");
      toast.error(err instanceof Error ? err.message : "Control coverage fetch failed");
    }
  }

  async function fetchFrameworkCoverage() {
    try {
      const payload = await api.frameworkCoverage(frameworkName, minSimulations);
      setFrameworkCoverage(payload as FrameworkCoverage);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Framework coverage unavailable");
      toast.error(err instanceof Error ? err.message : "Framework coverage fetch failed");
    }
  }

  useEffect(() => {
    if (!selectedControl) return;
    fetchControlCoverage().catch(() => null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedControl]);

  const hasEvidence = Boolean(controlExplorer || runtimeControlView || simulationControlView || summary || heatmap || trends || controlCoverage || frameworkCoverage);
  const presentationState: PresentationState = loading
    ? "loading"
    : loadError
      ? hasEvidence ? "stale" : "unavailable"
      : hasEvidence ? "ready-populated" : "ready-empty";

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Validation"
          title="Validation coverage"
          description="Choose a control, run a safe test, and inspect the evidence-backed coverage that follows."
          actions={<Button asChild><Link href="/validate">Run a control test</Link></Button>}
        />
        <OperationalState state={presentationState} onRetry={() => void loadControlFoundation()} description={loadError ? `${loadError}. Existing coverage evidence remains visible where available.` : undefined} />
        <details className="rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-200">Coverage methodology</summary>
          <p className="border-t border-white/[0.07] px-4 py-3 text-sm leading-6 text-slate-400">Coverage links controls to runtime evidence and persisted simulation results. Missing or stale sources stay visible as unavailable, partial, or unknown; a mapping alone does not prove enforcement.</p>
        </details>
        <PageSection
          title="Control Explorer"
          description="Operationalized control taxonomy mapped to frameworks, runtime enforcement points, and simulation coverage."
        >
          <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-4">
            <Input value={explorerFramework} onChange={(e) => setExplorerFramework(e.target.value)} placeholder="framework filter" />
            <Input value={explorerCategory} onChange={(e) => setExplorerCategory(e.target.value)} placeholder="category filter" />
            <Input value={explorerRiskTag} onChange={(e) => setExplorerRiskTag(e.target.value)} placeholder="risk tag filter" />
            <Button onClick={loadControlFoundation}>Refresh Control Foundation</Button>
          </div>

          {controlExplorer && (
            <>
              <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ Risk Exposure</p>
                  <p className="mt-1 text-xl font-semibold text-rose-300">{formatUsd(controlExplorer.crq_summary?.risk_exposure_usd)}</p>
                </div>
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ Risk Reduced</p>
                  <p className="mt-1 text-xl font-semibold text-emerald-300">{formatUsd(controlExplorer.crq_summary?.risk_reduced_usd)}</p>
                </div>
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ At Risk if Ignored</p>
                  <p className="mt-1 text-xl font-semibold text-amber-300">{formatUsd(controlExplorer.crq_summary?.at_risk_if_ignored_usd)}</p>
                </div>
              </div>
              <p className="mb-3 text-sm text-slate-300">
                controls: <strong>{controlExplorer.total_controls}</strong>/{(controlExplorer.foundation_control_ids || []).length || 20} foundation | frameworks covered:{" "}
                {Object.keys(controlExplorer.framework_counts || {}).length}
              </p>
              <SimpleTable
                columns={[
                  "Control ID",
                  "Control",
                  "Category",
                  "Severity",
                  "Frameworks",
                  "Enforcement Points",
                  "Risk Tags",
                  "Simulations",
                  "Pass Rate",
                  "$ Risk Exposure",
                  "$ Risk Reduced",
                  "$ At Risk if Ignored",
                ]}
                rows={controlExplorer.controls.map((row) => [
                  row.control_id,
                  row.control_name,
                  row.category,
                  row.severity,
                  Array.from(new Set((row.frameworks || []).map((item) => String(item.framework || "")).filter(Boolean))).join(", ") || "-",
                  (row.enforcement_points || []).join(", ") || "-",
                  (row.risk_tags || []).join(", ") || "-",
                  String(row.simulation_count),
                  `${row.simulation_pass_rate_percent}%`,
                  formatUsd(row.financials?.risk_exposure_usd),
                  formatUsd(row.financials?.risk_reduced_usd),
                  formatUsd(row.financials?.at_risk_if_ignored_usd),
                ])}
              />
            </>
          )}
        </PageSection>

        <PageSection
          title="Runtime Control View"
          description="Runtime event to control_id mapping with triggered and missed control visibility over a time window."
        >
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Input
              value={String(runtimeLookbackHours)}
              onChange={(e) => setRuntimeLookbackHours(Number(e.target.value || "24"))}
              className="w-28"
              type="number"
              min={1}
              max={24 * 30}
            />
            <Button variant="outline" onClick={loadControlFoundation}>Refresh Runtime View</Button>
          </div>

          {runtimeControlView && (
            <>
              <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ Risk Exposure</p>
                  <p className="mt-1 text-xl font-semibold text-rose-300">{formatUsd(runtimeControlView.crq_summary?.risk_exposure_usd)}</p>
                </div>
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ Risk Reduced</p>
                  <p className="mt-1 text-xl font-semibold text-emerald-300">{formatUsd(runtimeControlView.crq_summary?.risk_reduced_usd)}</p>
                </div>
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ At Risk if Ignored</p>
                  <p className="mt-1 text-xl font-semibold text-amber-300">{formatUsd(runtimeControlView.crq_summary?.at_risk_if_ignored_usd)}</p>
                </div>
              </div>
              <p className="mb-3 text-sm text-slate-300">
                lookback: {runtimeControlView.lookback_hours}h | events: {runtimeControlView.event_count} | controls triggered: {runtimeControlView.control_count}
              </p>
              <SimpleTable
                columns={[
                  "Control ID",
                  "Control",
                  "Category",
                  "Severity",
                  "Triggered",
                  "Missed",
                  "Source Surfaces",
                  "Risk Tags",
                  "$ Risk Exposure",
                  "$ Risk Reduced",
                  "$ At Risk if Ignored",
                ]}
                rows={runtimeControlView.controls.map((row) => [
                  row.control_id,
                  row.control_name,
                  row.category,
                  row.severity,
                  String(row.trigger_count),
                  String(row.miss_count),
                  Object.entries(row.source_surface_counts || {})
                    .map(([key, value]) => `${key}:${value}`)
                    .join(", ") || "-",
                  Object.entries(row.risk_tag_counts || {})
                    .map(([key, value]) => `${key}:${value}`)
                    .join(", ") || "-",
                  formatUsd(row.financials?.risk_exposure_usd),
                  formatUsd(row.financials?.risk_reduced_usd),
                  formatUsd(row.financials?.at_risk_if_ignored_usd),
                ])}
              />
            </>
          )}
        </PageSection>

        <PageSection
          title="Simulation Control View"
          description="Control-to-simulation execution mapping with pass/fail realism over observed runs."
        >
          {simulationControlView && (
            <>
              <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ Risk Exposure</p>
                  <p className="mt-1 text-xl font-semibold text-rose-300">{formatUsd(simulationControlView.crq_summary?.risk_exposure_usd)}</p>
                </div>
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ Risk Reduced</p>
                  <p className="mt-1 text-xl font-semibold text-emerald-300">{formatUsd(simulationControlView.crq_summary?.risk_reduced_usd)}</p>
                </div>
                <div className="rounded-md border border-[#2a3246] bg-[#0b1325] p-3">
                  <p className="text-xs uppercase tracking-wide text-slate-400">$ At Risk if Ignored</p>
                  <p className="mt-1 text-xl font-semibold text-amber-300">{formatUsd(simulationControlView.crq_summary?.at_risk_if_ignored_usd)}</p>
                </div>
              </div>
              <SimpleTable
                columns={[
                  "Control ID",
                  "Control",
                  "Category",
                  "Severity",
                  "Simulations",
                  "Runs",
                  "Pass Rate",
                  "Result Breakdown",
                  "$ Risk Exposure",
                  "$ Risk Reduced",
                  "$ At Risk if Ignored",
                ]}
                rows={simulationControlView.controls.map((row) => [
                  row.control_id,
                  row.control_name,
                  row.category,
                  row.severity,
                  String(row.simulation_count),
                  String(row.run_count),
                  `${row.pass_rate_percent}%`,
                  `pass:${row.result_breakdown.pass} fail:${row.result_breakdown.fail} partial:${row.result_breakdown.partial} not_exec:${row.result_breakdown.not_executable}`,
                  formatUsd(row.financials?.risk_exposure_usd),
                  formatUsd(row.financials?.risk_reduced_usd),
                  formatUsd(row.financials?.at_risk_if_ignored_usd),
                ])}
              />
            </>
          )}
        </PageSection>

        <PageSection title="Control Coverage" description="Control-to-simulation mapping, pass-rate trend, and maturity impact visibility.">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <select
              className="h-9 min-w-[260px] rounded-md border border-[#2a3246] bg-[#0b1325] px-3 text-sm text-slate-100"
              value={selectedControl}
              onChange={(e) => setSelectedControl(e.target.value)}
            >
              {controls.map((control) => (
                <option key={control.id} value={control.id}>
                  {control.id} - {control.name}
                </option>
              ))}
            </select>
            <Button variant="outline" onClick={fetchControlCoverage}>
              Refresh Control Coverage
            </Button>
          </div>

          {controlCoverage && (
            <>
              <p className="mb-3 text-sm text-slate-300">
                <strong>{selectedControlLabel}</strong> | simulations: {controlCoverage.coverage_summary.simulation_count} | runs:{" "}
                {controlCoverage.coverage_summary.run_count} | pass-rate: {(controlCoverage.coverage_summary.overall_pass_rate * 100).toFixed(2)}%
              </p>
              <SimpleTable
                columns={["Simulation", "Category", "Target Module", "Version"]}
                rows={controlCoverage.mapped_simulations.map((row) => [row.name, row.category, row.target_module, row.version])}
              />
              <div className="mt-4">
                <SimpleTable
                  columns={["Run", "Simulation ID", "Result", "Pass Rate", "Iterations", "Started At"]}
                  rows={controlCoverage.pass_rate_trend.map((row) => [
                    row.run_id,
                    row.simulation_id,
                    row.result,
                    `${(row.pass_rate * 100).toFixed(2)}%`,
                    String(row.iterations),
                    new Date(row.started_at).toLocaleString(),
                  ])}
                />
              </div>
            </>
          )}
        </PageSection>

        <PageSection title="Framework Coverage" description="% controls with at least X simulations mapped to framework references.">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <Input value={frameworkName} onChange={(e) => setFrameworkName(e.target.value)} className="max-w-xs" placeholder="NIST AI RMF" />
            <Input
              value={String(minSimulations)}
              onChange={(e) => setMinSimulations(Number(e.target.value || "1"))}
              className="w-24"
              type="number"
              min={1}
            />
            <Button onClick={fetchFrameworkCoverage}>Compute Framework Coverage</Button>
          </div>

          {frameworkCoverage && (
            <>
              <p className="mb-3 text-sm text-slate-300">
                Framework <strong>{frameworkCoverage.framework}</strong>: {frameworkCoverage.coverage_percent.toFixed(2)}% coverage (
                {frameworkCoverage.covered_controls}/{frameworkCoverage.total_controls} controls at min {frameworkCoverage.min_simulations} simulations)
              </p>
              <SimpleTable
                columns={["Control ID", "Control Name", "Simulation Count", "Covered"]}
                rows={frameworkCoverage.controls.map((row) => [row.control_id, row.control_name, String(row.simulation_count), row.covered ? "yes" : "no"])}
              />
            </>
          )}
        </PageSection>

        {summary && (
          <PageSection
            title="Category And Pack Coverage"
            description="Category-level breadth, trigger-source linkage, and pack readiness."
          >
            <p className="mb-3 text-sm text-slate-300">
              defs: {summary.totals.simulation_definitions} | runs: {summary.totals.simulation_runs} | packs: {summary.totals.pack_count} | controls without sims:{" "}
              {summary.missing_links.controls_without_simulations.length}
            </p>
            <SimpleTable
              columns={["Category", "Simulation Count"]}
              rows={summary.category_coverage.map((row) => [row.category, String(row.simulation_count)])}
            />
            <div className="mt-4">
              <SimpleTable
                columns={["Pack", "Categories", "Sims", "Runs", "Pass Rate", "Ready"]}
                rows={summary.pack_coverage.map((row) => [
                  row.name,
                  row.categories.join(", "),
                  String(row.simulation_count),
                  String(row.run_count),
                  `${Math.round(row.pass_rate * 100)}%`,
                  row.target_ready ? "yes" : "no",
                ])}
              />
            </div>
          </PageSection>
        )}

        {heatmap && (
          <PageSection title="Framework x Category Heatmap" description="Simulation count density across framework and category dimensions.">
            <div className="overflow-x-auto rounded-lg border border-slate-700">
              <table className="min-w-full border-collapse text-sm">
                <thead>
                  <tr className="bg-slate-950">
                    <th className="border border-slate-700 px-3 py-2 text-left text-slate-100">Framework</th>
                    {heatmap.categories.map((category) => (
                      <th key={category} className="border border-slate-700 px-3 py-2 text-left text-slate-100">
                        {category}
                      </th>
                    ))}
                    <th className="border border-slate-700 px-3 py-2 text-left text-slate-100">Total</th>
                  </tr>
                </thead>
                <tbody>
                  {heatmap.rows.map((row) => (
                    <tr key={row.framework}>
                      <td className="border border-slate-700 bg-slate-950 px-3 py-2 font-medium text-slate-100">{row.framework}</td>
                      {heatmap.categories.map((category) => {
                        const value = Number(row.cells[category] || 0);
                        const tone = heatmapCellClasses(value, heatmapMaxCell);
                        return (
                          <td key={`${row.framework}:${category}`} className={`border border-slate-700 px-3 py-2 ${tone}`}>
                            {value}
                          </td>
                        );
                      })}
                      <td className="border border-slate-700 bg-slate-950 px-3 py-2 font-semibold text-slate-100">{row.total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </PageSection>
        )}

        {trends && (
          <PageSection title="Simulation Run Trends" description={`Daily run/pass/fail trend over ${trends.lookback_days} days.`}>
            <SimpleTable
              columns={["Day", "Runs", "Passes", "Fails", "Pass Rate"]}
              rows={trends.series.map((row) => [
                row.day,
                String(row.total_runs),
                String(row.passes),
                String(row.fails),
                `${Math.round(row.pass_rate * 100)}%`,
              ])}
            />
          </PageSection>
        )}
      </div>
    </AppShell>
  );
}

export default function ValidationCoveragePage() {
  return (
    <Suspense fallback={<div className="p-6 text-sm text-slate-400">Loading validation coverage…</div>}>
      <ValidationCoverageContent />
    </Suspense>
  );
}
