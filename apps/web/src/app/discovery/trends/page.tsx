"use client";

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";


function toDate(value?: string | null): Date | null {
  if (!value) return null;
  const out = new Date(value);
  return Number.isNaN(out.getTime()) ? null : out;
}

function dateKey(value?: string | null): string {
  const date = toDate(value);
  if (!date) return "unknown";
  return date.toISOString().slice(0, 10);
}

function buildWindow(days: number): string[] {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const out: string[] = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    out.push(d.toISOString().slice(0, 10));
  }
  return out;
}

export default function DiscoveryTrendsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "stale" | "unavailable">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    setLoadState((current) => current === "ready" || current === "stale" ? "stale" : "loading");
    api.listFindings({ page_size: 1000 })
      .then((payload) => {
        setFindings(payload.items || []);
        setLoadError(null);
        setLoadState("ready");
      })
      .catch((err) => {
        setLoadError(err instanceof Error ? err.message : "Trend data is unavailable.");
        setLoadState((current) => current === "stale" ? "stale" : "unavailable");
        toast.error(err instanceof Error ? err.message : "Failed to load trends");
      });
  }, []);

  const dailySeries = useMemo(() => {
    const keys = buildWindow(14);
    const rows = keys.map((key) => ({
      key,
      adoption: 0,
      shadow: 0,
      highSeverity: 0,
      warns: 0,
      blocks: 0,
      controlDegradation: 0,
    }));
    const byKey = new Map(rows.map((row) => [row.key, row]));

    findings.forEach((finding) => {
      const key = dateKey(finding.updated_at || finding.created_at);
      const row = byKey.get(key);
      if (!row) return;
      row.adoption += 1;
      if (finding.finding_type === "shadow_ai_discovery") row.shadow += 1;
      if (finding.severity === "high" || finding.severity === "critical") row.highSeverity += 1;
      if (finding.finding_type === "browser_interaction_security") {
        if (finding.severity === "critical") row.blocks += 1;
        if (finding.severity === "med" || finding.severity === "high") row.warns += 1;
      }
      if (finding.finding_type === "drift_alert") row.controlDegradation += 1;
    });
    return rows;
  }, [findings]);

  const departmentRows = useMemo(() => {
    const byDept = new Map<string, number>();
    findings.forEach((finding) => {
      const key = finding.department || "unassigned";
      byDept.set(key, (byDept.get(key) || 0) + 1);
    });
    return Array.from(byDept.entries())
      .map(([department, count]) => ({ department, count }))
      .sort((a, b) => b.count - a.count);
  }, [findings]);

  const repeatedTools = useMemo(() => {
    const byTool = new Map<string, { count: number; high: number }>();
    findings.forEach((finding) => {
      const key = finding.ai_tool || "unknown";
      const bucket = byTool.get(key) || { count: 0, high: 0 };
      bucket.count += 1;
      if (finding.severity === "high" || finding.severity === "critical") bucket.high += 1;
      byTool.set(key, bucket);
    });
    return Array.from(byTool.entries())
      .map(([tool, value]) => ({ tool, count: value.count, high: value.high }))
      .sort((a, b) => (b.high - a.high) || (b.count - a.count))
      .slice(0, 10);
  }, [findings]);

  const sourceSurfaceRows = useMemo(() => {
    const bySurface = new Map<string, { total: number; high: number }>();
    findings.forEach((finding) => {
      const key = String(finding.source_surface || "unknown");
      const bucket = bySurface.get(key) || { total: 0, high: 0 };
      bucket.total += 1;
      if (finding.severity === "high" || finding.severity === "critical") {
        bucket.high += 1;
      }
      bySurface.set(key, bucket);
    });
    return Array.from(bySurface.entries())
      .map(([sourceSurface, value]) => ({ sourceSurface, total: value.total, high: value.high }))
      .sort((a, b) => b.total - a.total);
  }, [findings]);

  return (
    <AppShell>
      <div className="space-y-6">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-brand-500">AI Discovery</p>
          <h2 className="text-2xl font-semibold text-slate-900">Trends</h2>
          <p className="text-sm text-slate-600">Adoption, shadow usage, severity progression, and enforcement trend lines.</p>
          {loadState === "loading" && !findings.length ? <p role="status" className="mt-2 text-sm text-slate-500">Loading observed trends…</p> : null}
          {loadState === "stale" ? <p role="status" className="mt-2 text-sm text-amber-700">Showing the last successful trend snapshot while refresh is unavailable{loadError ? `: ${loadError}` : ""}.</p> : null}
          {loadState === "unavailable" ? <p role="status" className="mt-2 text-sm text-amber-700">Trend data is unavailable. No zero values are being substituted.</p> : null}
        </div>

        <PageSection title="Adoption / Shadow / Severity Over Time" description="14-day trend built from findings timeline.">
          <SimpleTable
            columns={["Date", "AI App Adoption", "Shadow Usage", "High Severity", "Warns", "Blocks", "Control Degradation"]}
            emptyLabel={loadState === "loading" ? "Loading observed trends…" : loadState === "unavailable" ? "Trend data is unavailable." : "No observed trend points are available yet."}
            rows={loadState === "ready" || loadState === "stale" ? dailySeries.map((row) => [
              new Date(`${row.key}T00:00:00Z`).toLocaleDateString(),
              row.adoption,
              row.shadow,
              row.highSeverity,
              row.warns,
              row.blocks,
              row.controlDegradation,
            ]) : []}
          />
        </PageSection>

        <div className="grid gap-6 xl:grid-cols-2">
          <PageSection title="Source Surface Mix" description="Cross-surface discovery and finding volume.">
            <SimpleTable
              columns={["Source Surface", "Total Findings", "High/Critical"]}
              emptyLabel={loadState === "unavailable" ? "Trend source data is unavailable." : "No observed source activity is available yet."}
              rows={loadState === "ready" || loadState === "stale" ? sourceSurfaceRows.map((row) => [row.sourceSurface, row.total, row.high]) : []}
            />
          </PageSection>
          <PageSection title="Findings by Department" description="Department-level concentration of risk findings.">
            <SimpleTable
              columns={["Department", "Findings"]}
              emptyLabel={loadState === "unavailable" ? "Department trend data is unavailable." : "No observed department activity is available yet."}
              rows={loadState === "ready" || loadState === "stale" ? departmentRows.map((row) => [row.department, row.count]) : []}
            />
          </PageSection>
          <PageSection title="Repeated Violators / Tools" description="Most frequent high-risk tools observed.">
            <SimpleTable
              columns={["Tool", "Total Findings", "High/Critical"]}
              emptyLabel={loadState === "unavailable" ? "Tool trend data is unavailable." : "No observed tool activity is available yet."}
              rows={loadState === "ready" || loadState === "stale" ? repeatedTools.map((row) => [row.tool, row.count, row.high]) : []}
            />
          </PageSection>
        </div>
      </div>
    </AppShell>
  );
}
