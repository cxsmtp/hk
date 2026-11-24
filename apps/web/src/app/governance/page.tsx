"use client";

import { useMemo } from "react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { OperationalState } from "@/components/operational-state";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { RowActions } from "@/components/row-actions";
import { SimpleTable } from "@/components/simple-table";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { AIOrchestrationResult, AISystem } from "@/lib/types";
import type { PresentationState } from "@/lib/presentation-state";
import { FilterInput, FilterLabel, FilterSelect, TableFilters } from "@/components/table-filters";

export default function GovernancePage() {
  const [systems, setSystems] = useState<AISystem[]>([]);
  const [riskFilter, setRiskFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");
  const [guidanceLoadingId, setGuidanceLoadingId] = useState("");
  const [selectedGuidanceSystemId, setSelectedGuidanceSystemId] = useState("");
  const [guidanceBySystem, setGuidanceBySystem] = useState<Record<string, AIOrchestrationResult>>({});
  const [presentationState, setPresentationState] = useState<PresentationState>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);

  async function load() {
    setPresentationState(systems.length ? "stale" : "loading");
    try {
      const payload = await api.listAISystems();
      const items = payload.items || [];
      setSystems(items);
      setLoadError(null);
      setPresentationState(items.length ? "ready-populated" : "ready-empty");
    } catch (cause) {
      setLoadError(cause instanceof Error ? cause.message : "AI system inventory is unavailable.");
      setPresentationState(systems.length ? "stale" : "unavailable");
      throw cause;
    }
  }

  useEffect(() => {
    void load().catch(() => undefined);
    // Initial tenant-scoped hydration only; refreshes are explicit user actions.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const riskOptions = useMemo(
    () => Array.from(new Set(systems.map((item) => String(item.risk_tier || "")))).filter(Boolean).sort(),
    [systems]
  );
  const statusOptions = useMemo(
    () => Array.from(new Set(systems.map((item) => String(item.status || "")))).filter(Boolean).sort(),
    [systems]
  );

  const filteredSystems = useMemo(
    () =>
      systems.filter((item) => {
        if (riskFilter && String(item.risk_tier || "") !== riskFilter) return false;
        if (statusFilter && String(item.status || "") !== statusFilter) return false;
        if (search) {
          const hay = `${item.name} ${item.description} ${item.id}`.toLowerCase();
          if (!hay.includes(search.toLowerCase())) return false;
        }
        return true;
      }),
    [systems, riskFilter, statusFilter, search]
  );
  const highRiskCount = useMemo(
    () => systems.filter((s) => ["HIGH", "CRITICAL", "high", "critical"].includes(String(s.risk_tier))).length,
    [systems]
  );
  const approvedCount = useMemo(
    () => systems.filter((s) => ["approved", "active", "APPROVED", "ACTIVE"].includes(String(s.status))).length,
    [systems]
  );
  const draftCount = useMemo(
    () => systems.filter((s) => String(s.status).toLowerCase() === "draft").length,
    [systems]
  );

  async function updateState(aiSystemId: string, payload: Partial<AISystem>) {
    try {
      await api.updateAISystem(aiSystemId, payload);
      toast.success("AI system updated");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Update failed");
    }
  }

  async function generateGovernanceGuidance(system: AISystem) {
    setGuidanceLoadingId(system.id);
    try {
      const result = await api.generateAISystemRemediationGuidance(system.id, {
        task_type: "vulnerability_analysis",
        data_sensitivity: "sensitive",
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
      setGuidanceBySystem((current) => ({ ...current, [system.id]: result }));
      setSelectedGuidanceSystemId(system.id);
      toast.success("Governance remediation guidance generated.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to generate governance guidance");
    } finally {
      setGuidanceLoadingId("");
    }
  }

  const selectedGuidance = selectedGuidanceSystemId ? guidanceBySystem[selectedGuidanceSystemId] || null : null;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Trust Center"
          title="AI Governance"
          description="AI system inventory, lifecycle, and risk tier governance."
          actions={
            <Button variant="outline" onClick={() => load()}>
              Refresh
            </Button>
          }
        />

        <OperationalState
          state={presentationState}
          onRetry={() => void load().catch(() => undefined)}
          description={loadError ? `AI system inventory unavailable: ${loadError}. Existing rows remain visible.` : undefined}
        />

        <TableFilters
          actions={
            <Button variant="outline" onClick={() => {
              setRiskFilter("");
              setStatusFilter("");
              setSearch("");
            }}>
              Clear Filters
            </Button>
          }
        >
          <FilterLabel label="Risk Tier">
            <FilterSelect
              value={riskFilter}
              onChange={setRiskFilter}
              options={[{ value: "", label: "All" }, ...riskOptions.map((value) => ({ value, label: value }))]}
            />
          </FilterLabel>

          <FilterLabel label="Status">
            <FilterSelect
              value={statusFilter}
              onChange={setStatusFilter}
              options={[{ value: "", label: "All" }, ...statusOptions.map((value) => ({ value, label: value }))]}
            />
          </FilterLabel>

          <FilterLabel label="Search">
            <FilterInput value={search} onChange={setSearch} placeholder="Name, description, id..." />
          </FilterLabel>
        </TableFilters>

        <PageSection title="AI Systems" description={`${filteredSystems.length} systems`}>
          <SimpleTable
            columns={["Name", "Risk Tier", "Status", "Description", "Actions"]}
            rows={filteredSystems.map((s) => [
              s.name,
              s.risk_tier,
              s.status,
              s.description,
              <RowActions
                key={`actions-${s.id}`}
                actions={[
                  { label: "Set HIGH", onClick: () => updateState(s.id, { risk_tier: "HIGH" }), variant: "outline" },
                  { label: "Approve", onClick: () => updateState(s.id, { status: "approved" }), variant: "default" },
                  {
                    label: guidanceLoadingId === s.id ? "Generating..." : "AI Guidance",
                    onClick: () => generateGovernanceGuidance(s),
                    variant: "outline",
                  },
                ]}
              />,
            ])}
            emptyLabel={presentationState === "unavailable" ? "Unavailable: AI system inventory did not respond." : "No AI systems match the current filters."}
          />
        </PageSection>

        <KpiStrip
          items={[
            { label: "AI Systems", value: systems.length, tone: "info" },
            { label: "Filtered", value: filteredSystems.length, tone: "default" },
            { label: "High/Critical", value: highRiskCount, tone: "critical" },
            { label: "Approved/Active", value: approvedCount, tone: "success" },
            { label: "Draft / Pending", value: draftCount, tone: draftCount ? "warning" : "default" },
          ]}
        />

        <details className="rounded-xl border border-slate-800 bg-slate-950/40 p-4">
          <summary className="cursor-pointer text-sm font-semibold text-slate-200">Framework mappings and evidence paths</summary>
          <div className="mt-4 grid gap-3 lg:grid-cols-[1.2fr_0.8fr]">
            <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-4">
              <p className="text-sm font-semibold text-slate-100">India and global AI governance mappings</p>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Open RBI FREE-AI, MeitY, DPDP, SEBI, IMDA Agentic AI, EU AI Act, OWASP GenAI/Agentic, and MITRE ATLAS mappings.
                Each mapping shows mapped controls and direct paths to policy packs, simulations, control coverage, and evidence requirements.
              </p>
              <p className="mt-2 text-xs leading-5 text-amber-200">Governance Atlas uses mapped controls only; it does not mark a tenant as certified compliant.</p>
            </div>
            <div className="grid gap-2 text-sm">
              <a className="rounded-md border border-slate-700 bg-slate-950/70 px-3 py-2 text-brand-200 hover:border-brand-500/60" href="/protect?section=governance-atlas">Open Governance Atlas</a>
              <a className="rounded-md border border-slate-700 bg-slate-950/70 px-3 py-2 text-brand-200 hover:border-brand-500/60" href="/simulations?framework=governance-atlas">Open framework-driven simulations</a>
              <a className="rounded-md border border-slate-700 bg-slate-950/70 px-3 py-2 text-brand-200 hover:border-brand-500/60" href="/surface-coverage?framework=governance-atlas">Open framework-driven control coverage</a>
            </div>
          </div>
        </details>

        <PageSection
          title="AI Governance Guidance"
          description="Bounded remediation guidance for selected Trust Center system. Enforcement remains deterministic."
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
            <p className="text-sm text-slate-500">Use “AI Guidance” in the AI Systems table to generate governance recommendations.</p>
          )}
        </PageSection>
      </div>
    </AppShell>
  );
}
