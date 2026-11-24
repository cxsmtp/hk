"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { OperationalState } from "@/components/operational-state";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { RowActions } from "@/components/row-actions";
import { SimpleTable } from "@/components/simple-table";
import { Button } from "@/components/ui/button";
import { FilterLabel, FilterSelect, TableFilters } from "@/components/table-filters";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { ControlConflict } from "@/lib/types";

type StatusFilter = "open" | "resolved" | "all";

export default function AuditorConflictsPage() {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("open");
  const [conflicts, setConflicts] = useState<ControlConflict[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(async (filter: StatusFilter) => {
    setLoading(true);
    try {
      const payload = await api.listConflicts(filter);
      setConflicts(payload.items || []);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Conflict source unavailable.");
      toast.error(err instanceof Error ? err.message : "Failed to load conflicts");
      setConflicts([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load(statusFilter).catch(() => undefined);
  }, [load, statusFilter]);

  const conflictState = resolvePresentationState({ loading, hasData: conflicts.length > 0, unavailable: Boolean(loadError) });

  async function resolve(conflictId: string, decision: "accept_positive" | "accept_negative" | "inconclusive") {
    const notes = window.prompt("Resolution notes", "Manual adjudication from auditor") ?? "";
    try {
      await api.resolveConflict(conflictId, { decision, notes });
      toast.success("Conflict resolved");
      await load(statusFilter);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to resolve conflict");
    }
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Auditor"
          title="Resolve Evidence Conflicts"
          description="Manual adjudication for contradictory evidence with audit trail."
          actions={
            <Button variant="outline" onClick={() => load(statusFilter)}>
              Refresh
            </Button>
          }
        />

        <OperationalState
          state={conflictState}
          onRetry={() => void load(statusFilter)}
          description={loadError ? "Conflict source unavailable. No conflict count is inferred." : undefined}
        />

        <KpiStrip
          items={[
            { label: "Conflicts", value: loading && !conflicts.length ? "—" : conflicts.length, tone: "warning" },
            { label: "Open", value: loading && !conflicts.length ? "—" : conflicts.filter((item) => item.status === "open").length, tone: "critical" },
            { label: "Resolved", value: loading && !conflicts.length ? "—" : conflicts.filter((item) => item.status === "resolved").length, tone: "success" },
            { label: "Source state", value: loadError ? "Unavailable" : loading ? (conflicts.length ? "Refreshing" : "Loading") : "Ready", tone: loadError ? "critical" : loading ? "info" : "default" },
          ]}
        />

        <TableFilters
          actions={
            <Button variant="outline" onClick={() => setStatusFilter("open")}>
              Reset to Open
            </Button>
          }
        >
          <FilterLabel label="Conflict Status">
            <FilterSelect
              value={statusFilter}
              onChange={(value) => setStatusFilter(value as StatusFilter)}
              options={[
                { value: "open", label: "Open" },
                { value: "resolved", label: "Resolved" },
                { value: "all", label: "All" },
              ]}
            />
          </FilterLabel>
        </TableFilters>

        <PageSection title="Conflict Queue" description={loading && !conflicts.length ? "Loading conflict evidence…" : `${conflicts.length} conflicts`}>
        <SimpleTable
          columns={[
            "Conflict ID",
            "AI System",
            "Control",
            "Status",
            "Signals (+/-)",
            "Detected",
            "Resolved",
            "Actions",
          ]}
          rows={conflicts.map((conflict) => [
            conflict.id,
            conflict.ai_system_id,
            conflict.control_id,
            conflict.status,
            `${conflict.positive_signals}/${conflict.negative_signals}`,
            new Date(conflict.detected_at).toLocaleString(),
            conflict.resolved_at ? new Date(conflict.resolved_at).toLocaleString() : "-",
            conflict.status === "open" ? (
              <RowActions
                key={`${conflict.id}-actions`}
                actions={[
                  { label: "Accept +", onClick: () => resolve(conflict.id, "accept_positive"), variant: "outline" },
                  { label: "Accept -", onClick: () => resolve(conflict.id, "accept_negative"), variant: "outline" },
                  { label: "Inconclusive", onClick: () => resolve(conflict.id, "inconclusive"), variant: "default" },
                ]}
              />
            ) : (
              conflict.resolution_decision || "-"
            ),
          ])}
          emptyLabel={loading ? "Loading conflict evidence…" : loadError ? "Conflict source unavailable." : "No conflicts match the selected status."}
        />
      </PageSection>
      </div>
    </AppShell>
  );
}
