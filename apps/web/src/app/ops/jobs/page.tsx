"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { PageSection } from "@/components/page-section";
import { OperationalState } from "@/components/operational-state";
import { SimpleTable } from "@/components/simple-table";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { JobStatusList, ScheduledJobRun } from "@/lib/types";
import type { PresentationState } from "@/lib/presentation-state";


function formatTime(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}


export default function OpsJobsPage() {
  const [items, setItems] = useState<JobStatusList["items"]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setLoadError(null);
    try {
      const result: JobStatusList = await api.listJobStatus(5);
      setItems(result.items || []);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Scheduled job status is unavailable.");
      toast.error(err instanceof Error ? err.message : "Failed to load job status");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
  }, []);

  const latestRows = items.map((item) => {
    const latestRun: ScheduledJobRun | undefined = item.runs?.[0];
    return {
      jobName: item.job_name,
      startedAt: latestRun?.started_at,
      finishedAt: latestRun?.finished_at,
      status: latestRun?.status || "unknown",
      error: latestRun?.error_message || "-",
    };
  });
  const presentationState: PresentationState = loading
    ? "loading"
    : loadError
      ? items.length ? "stale" : "unavailable"
      : items.length ? "ready-populated" : "ready-empty";

  return (
    <AppShell>
      <OperationalState
        state={presentationState}
        onRetry={() => void load()}
        description={loadError ? `Scheduled job status is unavailable: ${loadError}. Existing rows remain visible.` : "No scheduled job runs were reported; this does not indicate service health."}
      />
      <PageSection title="Scheduled Background Work" description="Recent scheduled work and source health. A scheduler may provide these runs, but this view does not assume a specific scheduler implementation.">
        <div className="mb-4">
          <Button onClick={load} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </Button>
        </div>

        <SimpleTable
          columns={["Job", "Started At", "Finished At", "Status", "Error"]}
          rows={latestRows.map((row) => [
            row.jobName,
            formatTime(row.startedAt),
            formatTime(row.finishedAt),
            row.status,
            row.error,
          ])}
          emptyLabel={loadError ? "Unavailable: scheduled job status did not respond." : "No scheduled job runs were reported yet."}
        />
      </PageSection>
    </AppShell>
  );
}
