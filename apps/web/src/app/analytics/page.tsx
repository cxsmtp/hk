"use client";

import { useEffect, useMemo, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { OperationalState } from "@/components/operational-state";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { DistributionDonutCard, RankedBarsCard, TrendSparkCard } from "@/components/visual-metrics";
import { api } from "@/lib/api";
import type { EnforcementEvent, Finding, MaturityRow, SimulationRun } from "@/lib/types";

function dayKey(daysAgo: number): string {
  const point = new Date();
  point.setDate(point.getDate() - daysAgo);
  return point.toISOString().slice(0, 10);
}

function seriesFromDates(items: Array<{ ts: string }>, days: number) {
  const keys = Array.from({ length: days }, (_, idx) => dayKey(days - 1 - idx));
  const totals = new Map<string, number>(keys.map((key) => [key, 0]));
  items.forEach((item) => {
    const key = (item.ts || "").slice(0, 10);
    if (!totals.has(key)) return;
    totals.set(key, (totals.get(key) || 0) + 1);
  });
  return keys.map((key) => ({ label: key.slice(5), value: totals.get(key) || 0 }));
}

export default function AnalyticsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [events, setEvents] = useState<EnforcementEvent[]>([]);
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [maturity, setMaturity] = useState<MaturityRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.listFindings({ page_size: 1000 }),
      api.listEnforcementEvents(),
      api.listSimulationRuns(),
      api.listMaturity(),
    ])
      .then(([findingPayload, eventPayload, runPayload, maturityPayload]) => {
        setFindings(findingPayload.items || []);
        setEvents(eventPayload.items || []);
        setRuns(runPayload.items || []);
        setMaturity(maturityPayload.items || []);
        setLoadError(null);
      })
      .catch((error) => {
        setLoadError(error instanceof Error ? error.message : "Analytics data is unavailable");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const findingsTrend = useMemo(
    () => seriesFromDates(findings.map((row) => ({ ts: row.updated_at || row.created_at })), 21),
    [findings]
  );
  const blockTrend = useMemo(
    () => seriesFromDates(events.filter((row) => row.final_decision === "block").map((row) => ({ ts: row.timestamp })), 21),
    [events]
  );
  const warnTrend = useMemo(
    () => seriesFromDates(events.filter((row) => row.final_decision === "warn").map((row) => ({ ts: row.timestamp })), 21),
    [events]
  );
  const simFailureTrend = useMemo(
    () => seriesFromDates(runs.filter((row) => row.results?.result === "fail").map((row) => ({ ts: row.started_at })), 21),
    [runs]
  );
  const severitySlices = useMemo(() => {
    const count = (severity: Finding["severity"]) => findings.filter((row) => row.severity === severity).length;
    return [
      { label: "Critical", value: count("critical"), color: "#f87171" },
      { label: "High", value: count("high"), color: "#fb923c" },
      { label: "Medium", value: count("med"), color: "#fbbf24" },
      { label: "Low", value: count("low"), color: "#60a5fa" },
    ];
  }, [findings]);
  const repeatedTools = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((row) => {
      counts.set(row.ai_tool, (counts.get(row.ai_tool) || 0) + 1);
    });
    return Array.from(counts.entries())
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [findings]);
  const controlsBelow2 = useMemo(
    () => maturity.filter((row) => row.maturity_score < 2).length,
    [maturity]
  );
  const warningToBlock = useMemo(() => {
    const warn = events.filter((row) => row.final_decision === "warn").length;
    const block = events.filter((row) => row.final_decision === "block").length;
    return warn ? (block / warn).toFixed(2) : "0.00";
  }, [events]);
  const hasData = findings.length > 0 || events.length > 0 || runs.length > 0 || maturity.length > 0;
  const analyticsState = loadError ? (hasData ? "stale" : "unavailable") : loading ? "loading" : hasData ? "ready-populated" : "ready-empty";

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Executive Analytics"
          title="Analytics"
          description="Cross-module trend analytics for adoption, enforcement, findings, and control resilience."
        />

        <OperationalState
          state={analyticsState}
          title={loadError ? "Analytics data unavailable" : undefined}
          description={loadError ? "The analytics sources could not be reached. No zero values are being substituted for the missing response." : undefined}
        />

        {analyticsState === "ready-populated" ? <>
        <KpiStrip
          items={[
            { label: "Findings (21d)", value: findings.length, tone: "warning" },
            { label: "Enforcement Events", value: events.length, tone: "info" },
            { label: "Warning→Block Ratio", value: warningToBlock, tone: Number(warningToBlock) > 0.7 ? "critical" : "warning" },
            { label: "Controls < 2.0", value: controlsBelow2, tone: controlsBelow2 ? "critical" : "success" },
          ]}
        />

        <div className="grid gap-4 xl:grid-cols-3">
          <TrendSparkCard
            title="Findings Volume (21d)"
            subtitle="All findings activity"
            points={findingsTrend}
            tone="warning"
            yAxisLabel="Findings count"
            xAxisLabel="Last 21 days"
          />
          <TrendSparkCard
            title="Block Decisions (21d)"
            subtitle="Runtime block decisions over time"
            points={blockTrend}
            tone="critical"
            yAxisLabel="Block decisions"
            xAxisLabel="Last 21 days"
          />
          <DistributionDonutCard
            title="Findings Severity Mix"
            subtitle="Current distribution of finding severity"
            centerLabel="Findings"
            centerValue={`${findings.length}`}
            slices={severitySlices}
          />
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <TrendSparkCard
            title="Warning Decisions (21d)"
            subtitle="Pre-block warning activity"
            points={warnTrend}
            tone="info"
            yAxisLabel="Warning decisions"
            xAxisLabel="Last 21 days"
          />
          <TrendSparkCard
            title="Simulation Failures (21d)"
            subtitle="Validation failures over time"
            points={simFailureTrend}
            tone="critical"
            yAxisLabel="Failed simulations"
            xAxisLabel="Last 21 days"
          />
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <RankedBarsCard
            title="Repeated Violator Tools"
            subtitle="Tools with repeated findings concentration"
            items={repeatedTools}
          />
          <PageSection title="Analytics Summary Table" description="Direct metrics for leadership reporting.">
            <SimpleTable
              columns={["Metric", "Value"]}
              rows={[
                ["Total findings", findings.length],
                ["Total enforcement events", events.length],
                ["Total simulation runs", runs.length],
                ["Controls tracked", maturity.length],
                ["Controls below maturity 2.0", controlsBelow2],
                ["Warning to block ratio", warningToBlock],
              ]}
            />
          </PageSection>
        </div>
        </> : null}
      </div>
    </AppShell>
  );
}
