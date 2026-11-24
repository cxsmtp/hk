"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { OperationalState } from "@/components/operational-state";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { Finding } from "@/lib/types";


type FindingFilters = {
  severity_filter: string;
  department_filter: string;
  tool_filter: string;
  status_filter: string;
  finding_type_filter: string;
};

const DEFAULT_FILTERS: FindingFilters = {
  severity_filter: "",
  department_filter: "",
  tool_filter: "",
  status_filter: "",
  finding_type_filter: "",
};

const STATUS_OPTIONS = ["open", "reviewing", "resolved", "accepted_risk"];
const SEVERITY_OPTIONS = ["low", "med", "high", "critical"];

function toDate(value?: string | null): Date | null {
  if (!value) return null;
  const out = new Date(value);
  return Number.isNaN(out.getTime()) ? null : out;
}

function formatDate(value?: string | null): string {
  const parsed = toDate(value);
  return parsed ? parsed.toLocaleString() : "-";
}

function trimText(value: string, max = 90): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}...`;
}

function compactId(value: string, head = 8, tail = 8): string {
  if (!value) return "-";
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function isLikelyUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export default function DiscoveryFindingsPage() {
  const router = useRouter();
  const [filters, setFilters] = useState<FindingFilters>(DEFAULT_FILTERS);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [catalog, setCatalog] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  async function loadCatalog() {
    const response = await api.listFindings({ page_size: 500 });
    setCatalog(response.items || []);
  }

  async function loadFindings() {
    setLoading(true);
    try {
      const response = await api.listFindings({
        severity_filter: filters.severity_filter || undefined,
        department_filter: filters.department_filter || undefined,
        tool_filter: filters.tool_filter || undefined,
        status_filter: filters.status_filter || undefined,
        finding_type_filter: filters.finding_type_filter || undefined,
        page_size: 200,
      });
      setFindings(response.items || []);
      setLoadError(null);
    } catch (err) {
      setFindings([]);
      setLoadError(err instanceof Error ? err.message : "Findings source unavailable.");
      toast.error(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }

  async function refreshAll() {
    await Promise.all([loadCatalog(), loadFindings()]);
  }

  useEffect(() => {
    loadCatalog().catch(() => setCatalog([]));
  }, []);

  useEffect(() => {
    loadFindings().catch(() => setFindings([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.severity_filter, filters.department_filter, filters.tool_filter, filters.status_filter, filters.finding_type_filter]);

  const departmentOptions = useMemo(
    () => Array.from(new Set(catalog.map((item) => item.department).filter(Boolean) as string[])).sort(),
    [catalog]
  );
  const toolOptions = useMemo(
    () => Array.from(new Set(catalog.map((item) => item.ai_tool).filter(Boolean))).sort(),
    [catalog]
  );
  const typeOptions = useMemo(
    () => Array.from(new Set(catalog.map((item) => item.finding_type).filter(Boolean))).sort(),
    [catalog]
  );
  const highOpenCount = useMemo(
    () =>
      findings.filter(
        (finding) =>
          (finding.severity === "high" || finding.severity === "critical") &&
          (finding.status === "open" || finding.status === "reviewing")
      ).length,
    [findings]
  );
  const findingsState = resolvePresentationState({ loading, hasData: findings.length > 0, unavailable: Boolean(loadError) });

  async function runAction(finding: Finding, action: "assign" | "escalate" | "validate" | "ticket" | "accept_risk" | "status") {
    setBusyId(finding.finding_id);
    try {
      if (action === "assign") {
        const raw = window.prompt(
          "Assign owner (enter tenant user UUID or department name)",
          finding.user_id || finding.department || ""
        );
        if (raw === null) return;
        const value = raw.trim();
        if (!value) return;
        if (isLikelyUuid(value)) {
          await api.assignFindingOwner(finding.finding_id, { owner_user_id: value });
        } else {
          await api.assignFindingOwner(finding.finding_id, { owner_department: value });
        }
        toast.success("Owner assigned");
      }

      if (action === "escalate") {
        const reason = window.prompt("Escalation reason (optional)", "High priority triage required.");
        await api.escalateFinding(finding.finding_id, { reason: reason || undefined });
        toast.success("Finding escalated");
      }

      if (action === "validate") {
        if (!finding.ai_system_id) {
          toast.error("Validation requires a governed AI system link. Promote this application in Discovery first.");
          return;
        }
        const defPayload = await api.listSimulationDefinitions();
        const simulationIds = (defPayload.items || []).slice(0, 3).map((item) => item.id);
        if (!simulationIds.length) {
          toast.error("No simulation definitions available. Open Simulations and create at least one definition.");
          return;
        }
        const result = await api.runFindingValidationPack(finding.finding_id, {
          mode: "deterministic",
          limit: 3,
          simulation_ids: simulationIds,
        });
        const failedRuns = result.runs.filter((item) => item.result === "fail").length;
        toast.success(`Validation pack ran ${result.total_runs} simulations (${failedRuns} failed).`);
      }

      if (action === "ticket") {
        const system = window.prompt("Ticket system", "jira") || "jira";
        const note = window.prompt("Ticket note (optional)", "");
        const result = await api.createFindingTicket(finding.finding_id, {
          system,
          note: note || undefined,
        });
        toast.success(`Ticket created: ${result.ticket_id}`);
      }

      if (action === "accept_risk") {
        const note = window.prompt("Risk acceptance note (optional)", "");
        await api.acceptFindingRecommendation(finding.finding_id, note || undefined);
        toast.success("Risk accepted");
      }

      if (action === "status") {
        const next = window.prompt(
          "Set status (open|reviewing|resolved|accepted_risk)",
          finding.status
        );
        if (!next) return;
        const normalized = next.trim().toLowerCase();
        const allowed = ["open", "reviewing", "resolved", "accepted_risk"];
        if (!allowed.includes(normalized)) {
          toast.error("Invalid status value");
          return;
        }
        await api.updateFindingStatus(
          finding.finding_id,
          normalized as "open" | "reviewing" | "resolved" | "accepted_risk"
        );
        toast.success("Finding status updated");
      }

      await refreshAll();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="AI Discovery"
          title="Findings"
          description="Operational findings queue with owner assignment, escalation, validation, ticketing, and risk acceptance."
        />

        <OperationalState
          state={findingsState}
          onRetry={() => void loadFindings()}
          description={loadError ? `Findings source unavailable: ${loadError}. No queue count is inferred.` : undefined}
        />

        <KpiStrip
          items={[
            { label: "Findings Returned", value: findings.length, tone: "info" },
            { label: "High / Critical Open", value: highOpenCount, tone: highOpenCount ? "critical" : "success" },
            {
              label: "Accepted Risk",
              value: findings.filter((finding) => finding.status === "accepted_risk").length,
              tone: "warning",
            },
            { label: "Unique Tools", value: new Set(findings.map((finding) => finding.ai_tool)).size, tone: "default" },
          ]}
        />

        <PageSection title="Filters" description="Filter findings by risk and ownership context.">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
            <label className="space-y-1 text-xs font-medium text-slate-600">
              Severity
              <select
                className="h-10 w-full rounded-md border bg-white px-3 text-sm"
                value={filters.severity_filter}
                onChange={(event) => setFilters((prev) => ({ ...prev, severity_filter: event.target.value }))}
              >
                <option value="">All</option>
                {SEVERITY_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1 text-xs font-medium text-slate-600">
              Department
              <select
                className="h-10 w-full rounded-md border bg-white px-3 text-sm"
                value={filters.department_filter}
                onChange={(event) => setFilters((prev) => ({ ...prev, department_filter: event.target.value }))}
              >
                <option value="">All</option>
                {departmentOptions.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1 text-xs font-medium text-slate-600">
              Tool
              <select
                className="h-10 w-full rounded-md border bg-white px-3 text-sm"
                value={filters.tool_filter}
                onChange={(event) => setFilters((prev) => ({ ...prev, tool_filter: event.target.value }))}
              >
                <option value="">All</option>
                {toolOptions.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1 text-xs font-medium text-slate-600">
              Status
              <select
                className="h-10 w-full rounded-md border bg-white px-3 text-sm"
                value={filters.status_filter}
                onChange={(event) => setFilters((prev) => ({ ...prev, status_filter: event.target.value }))}
              >
                <option value="">All</option>
                {STATUS_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1 text-xs font-medium text-slate-600">
              Finding Type
              <select
                className="h-10 w-full rounded-md border bg-white px-3 text-sm"
                value={filters.finding_type_filter}
                onChange={(event) => setFilters((prev) => ({ ...prev, finding_type_filter: event.target.value }))}
              >
                <option value="">All</option>
                {typeOptions.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="mt-4 flex justify-end">
            <Button
              variant="outline"
              onClick={() => setFilters(DEFAULT_FILTERS)}
              disabled={!filters.severity_filter && !filters.department_filter && !filters.tool_filter && !filters.status_filter && !filters.finding_type_filter}
            >
              Clear Filters
            </Button>
          </div>
        </PageSection>

        <PageSection
          title="Findings Table"
          description={loading ? "Loading findings..." : `${findings.length} findings returned`}
        >
          <SimpleTable
            columns={[
              "Finding",
              "Tool",
              "Source",
              "Severity",
              "Status",
              "Type",
              "Department",
              "Policy",
              "Updated",
              "Recommended Action",
              "Actions",
            ]}
            rows={findings.map((finding) => [
              <Link
                key={`${finding.finding_id}-detail`}
                href={`/discovery/findings/${encodeURIComponent(finding.finding_id)}`}
                className="text-brand-700 underline underline-offset-2"
                title={finding.finding_id}
              >
                {compactId(finding.finding_id)}
              </Link>,
              <span key={`${finding.finding_id}-tool`} className="break-words" title={finding.ai_tool}>
                {trimText(finding.ai_tool || "-", 28)}
              </span>,
              finding.source_surface || "-",
              <Badge key={`${finding.finding_id}-severity`} className="capitalize">
                {finding.severity}
              </Badge>,
              <Badge key={`${finding.finding_id}-status`} className="capitalize">
                {finding.status}
              </Badge>,
              <span key={`${finding.finding_id}-type`} className="break-words" title={finding.finding_type}>
                {trimText(finding.finding_type || "-", 32)}
              </span>,
              <span key={`${finding.finding_id}-dept`} className="break-words" title={finding.department || finding.user_id || "-"}>
                {trimText(finding.department || finding.user_id || "-", 28)}
              </span>,
              <span key={`${finding.finding_id}-policy`} title={finding.policy_version_id || "-"}>
                {compactId(finding.policy_version_id || "-", 8, 6)}
              </span>,
              formatDate(finding.updated_at),
              trimText(finding.recommended_action || "-", 80),
              <div key={`${finding.finding_id}-actions`} className="flex flex-wrap gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busyId === finding.finding_id}
                  onClick={() => runAction(finding, "assign")}
                >
                  Assign Owner
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busyId === finding.finding_id}
                  onClick={() => runAction(finding, "escalate")}
                >
                  Escalate
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busyId === finding.finding_id}
                  onClick={() => runAction(finding, "status")}
                >
                  Update Status
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busyId === finding.finding_id || !finding.ai_system_id}
                  onClick={() =>
                    router.push(
                      `/simulations?finding_id=${encodeURIComponent(finding.finding_id)}&ai_system_id=${encodeURIComponent(
                        finding.ai_system_id || ""
                      )}`
                    )
                  }
                >
                  Open Simulations
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busyId === finding.finding_id || !finding.ai_system_id}
                  onClick={() => runAction(finding, "validate")}
                >
                  Run Validation
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busyId === finding.finding_id}
                  onClick={() => runAction(finding, "ticket")}
                >
                  Create Ticket
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={busyId === finding.finding_id}
                  onClick={() => runAction(finding, "accept_risk")}
                >
                  Accept Risk
                </Button>
              </div>,
            ])}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
