"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useMemo } from "react";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { ModuleReportPanel } from "@/components/module-report-panel";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DistributionDonutCard, RankedBarsCard, TrendSparkCard } from "@/components/visual-metrics";
import { api } from "@/lib/api";
import type { AuditorDashboard, DiscoveryApplication, EnforcementEvent, Finding, MaturityRow, PolicyPack, SimulationRun } from "@/lib/types";

function toDate(value?: string | null): Date | null {
  if (!value) return null;
  const out = new Date(value);
  return Number.isNaN(out.getTime()) ? null : out;
}

function dayKey(daysAgo: number): string {
  const point = new Date();
  point.setDate(point.getDate() - daysAgo);
  return point.toISOString().slice(0, 10);
}

export default function DashboardPage() {
  const [maturity, setMaturity] = useState<MaturityRow[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [applications, setApplications] = useState<DiscoveryApplication[]>([]);
  const [events, setEvents] = useState<EnforcementEvent[]>([]);
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [packs, setPacks] = useState<PolicyPack[]>([]);
  const [auditor, setAuditor] = useState<AuditorDashboard | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "stale" | "unavailable">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);

  async function load() {
    setLoadState((current) => current === "ready" || current === "stale" ? "stale" : "loading");
    try {
      const [maturityPayload, findingsPayload, appPayload, eventsPayload, runsPayload, packPayload, auditorPayload] = await Promise.all([
        api.listMaturity(), api.listFindings({ page_size: 1000 }), api.listDiscoveryApplications({ page_size: 200 }),
        api.listEnforcementEvents(), api.listSimulationRuns(), api.listPolicyPacks(), api.dashboard(),
      ]);
      setMaturity(maturityPayload.items || []);
      setFindings(findingsPayload.items || []);
      setApplications(appPayload.items || []);
      setEvents(eventsPayload.items || []);
      setRuns(runsPayload.items || []);
      setPacks(packPayload.items || []);
      setAuditor(auditorPayload as AuditorDashboard);
      setLoadError(null);
      setLoadState("ready");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Dashboard data is unavailable.");
      setLoadState((current) => current === "stale" ? "stale" : "unavailable");
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
  }, []);

  const avg = maturity.length ? maturity.reduce((acc, r) => acc + r.maturity_score, 0) / maturity.length : 0;
  const highFindings = useMemo(
    () =>
      findings.filter(
        (row) => row.status !== "resolved" && (row.severity === "high" || row.severity === "critical")
      ).length,
    [findings]
  );
  const shadowApps = useMemo(
    () => applications.filter((app) => app.status === "discovered" || app.status === "monitoring").length,
    [applications]
  );
  const blockRate = useMemo(() => {
    if (!events.length) return 0;
    const blocks = events.filter((item) => item.final_decision === "block").length;
    return Math.round((blocks / events.length) * 100);
  }, [events]);
  const simFailureRate = useMemo(() => {
    if (!runs.length) return 0;
    const failed = runs.filter((item) => item.results?.result === "fail").length;
    return Math.round((failed / runs.length) * 100);
  }, [runs]);
  const topApps = useMemo(
    () => [...applications].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5),
    [applications]
  );
  const topTeams = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((item) => {
      const team = item.department || "unassigned";
      counts.set(team, (counts.get(team) || 0) + 1);
    });
    return Array.from(counts.entries())
      .map(([team, count]) => ({ team, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [findings]);
  const findingsTrend = useMemo(() => {
    const keys = Array.from({ length: 14 }, (_, idx) => dayKey(13 - idx));
    const totals = new Map<string, number>(keys.map((key) => [key, 0]));
    findings.forEach((item) => {
      const key = (item.updated_at || item.created_at || "").slice(0, 10);
      if (!totals.has(key)) return;
      totals.set(key, (totals.get(key) || 0) + 1);
    });
    return keys.map((key) => ({ label: key.slice(5), value: totals.get(key) || 0 }));
  }, [findings]);
  const enforcementTrend = useMemo(() => {
    const keys = Array.from({ length: 14 }, (_, idx) => dayKey(13 - idx));
    const totals = new Map<string, number>(keys.map((key) => [key, 0]));
    events.forEach((item) => {
      const key = (item.timestamp || "").slice(0, 10);
      if (!totals.has(key)) return;
      totals.set(key, (totals.get(key) || 0) + 1);
    });
    return keys.map((key) => ({ label: key.slice(5), value: totals.get(key) || 0 }));
  }, [events]);
  const appStatusSlices = useMemo(() => {
    const count = (status: DiscoveryApplication["status"]) => applications.filter((item) => item.status === status).length;
    return [
      { label: "Approved", value: count("approved"), color: "#34d399" },
      { label: "Monitoring", value: count("monitoring"), color: "#60a5fa" },
      { label: "Discovered", value: count("discovered"), color: "#fbbf24" },
      { label: "Blocked", value: count("blocked"), color: "#f87171" },
    ];
  }, [applications]);
  const moduleRows = useMemo(
    () => [
      {
        module: "Governance",
        metric: `${applications.length} apps / ${shadowApps} shadow`,
        status: shadowApps > 0 ? "attention" : "healthy",
        action: "Approve or block discovered tools",
        href: "/governance",
      },
      {
        module: "Policies",
        metric: `${packs.filter((item) => String(item.status).toLowerCase() === "active").length} active packs`,
        status: packs.some((item) => String(item.status).toLowerCase() === "active") ? "healthy" : "attention",
        action: "Activate runtime pack coverage",
        href: "/policies",
      },
      {
        module: "Interaction Security",
        metric: `${events.length} events / ${blockRate}% block rate`,
        status: blockRate > 30 ? "critical" : "healthy",
        action: "Review guardian matrix & approvals",
        href: "/interaction-security",
      },
      {
        module: "AI IAM",
        metric: `${findings.filter((item) => item.risk_category === "agent_misuse").length} agent misuse findings`,
        status: findings.some((item) => item.risk_category === "agent_misuse" && item.status !== "resolved") ? "attention" : "healthy",
        action: "Tighten chain depth and kill-switch outliers",
        href: "/ai-iam",
      },
      {
        module: "Simulations",
        metric: `${runs.length} runs / ${simFailureRate}% fail rate`,
        status: simFailureRate > 40 ? "critical" : "healthy",
        action: "Run deterministic pack for open findings",
        href: "/simulations",
      },
      {
        module: "Auditor",
        metric: `${auditor?.open_conflicts_count ?? 0} open conflicts`,
        status: (auditor?.open_conflicts_count ?? 0) > 0 ? "attention" : "healthy",
        action: "Resolve contested controls and export evidence",
        href: "/auditor",
      },
    ],
    [applications.length, auditor?.open_conflicts_count, blockRate, events.length, findings, packs, runs.length, shadowApps, simFailureRate]
  );
  const moduleRiskBars = useMemo(() => {
    const raw = moduleRows.map((row) => {
      let score = 20;
      if (row.status === "attention") score = 55;
      if (row.status === "critical") score = 85;
      return { label: row.module, value: score, hint: row.metric };
    });
    return raw;
  }, [moduleRows]);
  const recentCritical = useMemo(
    () =>
      [...findings]
        .filter((item) => item.severity === "critical" || item.severity === "high")
        .sort((a, b) => (toDate(b.updated_at)?.getTime() || 0) - (toDate(a.updated_at)?.getTime() || 0))
        .slice(0, 5),
    [findings]
  );
  const actionBacklog = useMemo(() => {
    const list: string[] = [];
    if (shadowApps > 0) list.push(`Convert ${shadowApps} discovered/monitoring apps into governed or blocked posture.`);
    if (highFindings > 0) list.push(`Triage ${highFindings} high/critical open findings and assign accountable owners.`);
    if (simFailureRate > 20) list.push(`Run deterministic simulation packs on high-risk controls to reduce ${simFailureRate}% failure rate.`);
    if ((auditor?.open_conflicts_count ?? 0) > 0) list.push(`Resolve ${auditor?.open_conflicts_count ?? 0} auditor evidence conflicts before export.`);
    if (!list.length && loadState === "ready") list.push("Review the latest evidence queue and continue the approved governance cadence.");
    return list.slice(0, 5);
  }, [auditor?.open_conflicts_count, highFindings, loadState, shadowApps, simFailureRate]);
  const hasSourceData = loadState === "ready" || loadState === "stale";

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Trust Center"
          title="Command Center"
          description="Centralized executive operations view for AI footprint, risk analytics, and module-level action."
              actions={
                <>
                  <Button asChild>
                    <Link href="/dashboard/command-center">AI Command Center</Link>
                  </Button>
                  <Button asChild variant="outline">
                <Link href="/analytics">Analytics</Link>
              </Button>
              <Button asChild variant="outline">
                <Link href="/ai-footprint">AI Footprint</Link>
              </Button>
              <Button asChild variant="outline">
                <Link href="/discovery/executive-summary">Executive Summary</Link>
              </Button>
              <Button variant="outline" onClick={() => load()}>
                Refresh
              </Button>
            </>
          }
        />
        {loadState === "loading" && !applications.length && !findings.length ? <p role="status" className="text-sm text-slate-500">Loading current dashboard evidence…</p> : null}
        {loadState === "stale" ? <p role="status" className="text-sm text-amber-300">Showing the last successful dashboard snapshot while refresh is unavailable{loadError ? `: ${loadError}` : ""}.</p> : null}
        {loadState === "unavailable" ? <p role="status" className="text-sm text-amber-300">Dashboard data is unavailable. No zero values are being substituted.</p> : null}

        <PageSection title="Immediate Action Backlog" description="Executive operating queue for this week.">
          {hasSourceData && actionBacklog.length ? (
            <ol className="space-y-2 text-sm text-slate-300">
              {actionBacklog.map((item, idx) => (
                <li key={item} className="rounded-md border border-[#1e2433] bg-[#0f1218] px-3 py-2">
                  <span className="mr-2 font-semibold text-brand-300">{idx + 1}.</span>
                  {item}
                </li>
              ))}
            </ol>
          ) : (
            <p role="status" className="text-sm text-slate-500">
              {hasSourceData ? "No open actions are present in the current evidence." : "Action backlog will appear when dashboard evidence is available."}
            </p>
          )}
        </PageSection>

        {hasSourceData ? <>
        <PageSection title="Top AI Footprint (By Risk Score)" description="Highest-risk applications currently seen in runtime telemetry and discovery.">
          <SimpleTable
            columns={["Tool", "Vendor", "Status", "Risk Score", "Open Findings", "Owner"]}
            rows={topApps.map((row) => [
              row.tool_name,
              row.vendor,
              row.status,
              row.risk_score,
              row.findings_open,
              row.owner_label || "-",
            ])}
          />
        </PageSection>

        <KpiStrip
          items={[
            { label: "Average Maturity", value: avg.toFixed(2), tone: avg < 2.5 ? "warning" : "success" },
            { label: "High/Critical Open Findings", value: highFindings, tone: highFindings ? "critical" : "success" },
            { label: "Shadow AI Applications", value: shadowApps, tone: shadowApps ? "warning" : "success" },
            {
              label: "Simulation Failure Rate",
              value: `${simFailureRate}%`,
              tone: simFailureRate > 40 ? "critical" : simFailureRate > 20 ? "warning" : "success",
            },
          ]}
        />

        <div className="grid gap-4 xl:grid-cols-3">
          <TrendSparkCard
            title="Finding Trend (14d)"
            subtitle="Open and resolved findings activity over the last 14 days"
            points={findingsTrend}
            tone={highFindings ? "critical" : "success"}
            yAxisLabel="Findings count"
            xAxisLabel="Last 14 days"
          />
          <TrendSparkCard
            title="Enforcement Trend (14d)"
            subtitle="Gateway enforcement event volume"
            points={enforcementTrend}
            tone={blockRate > 30 ? "critical" : "info"}
            yAxisLabel="Enforcement events"
            xAxisLabel="Last 14 days"
          />
          <DistributionDonutCard
            title="AI Footprint Composition"
            subtitle="Discovery and governance status split"
            centerLabel="Apps"
            centerValue={`${applications.length}`}
            slices={appStatusSlices}
          />
        </div>

        <ModuleReportPanel
          footprintTitle="AI Footprint"
          analyticsTitle="Command Analytics"
          footprintItems={[
            { label: "Governed AI Systems", value: new Set(applications.map((row) => row.ai_system_id).filter(Boolean)).size, tone: "info" },
            { label: "Discovered Applications", value: applications.length, tone: "default" },
            { label: "Open Findings", value: findings.filter((item) => item.status !== "resolved").length, tone: "warning" },
            { label: "Controls Tracked", value: maturity.length, tone: "info" },
          ]}
          analyticsItems={[
            { label: "Enforcement Block Rate", value: `${blockRate}%`, tone: blockRate > 30 ? "critical" : "success" },
            { label: "Simulation Fail Rate", value: `${simFailureRate}%`, tone: simFailureRate > 40 ? "critical" : "warning" },
            { label: "Avg Auditor Confidence", value: auditor?.average_confidence?.toFixed(2) || "0.00", tone: "info" },
            { label: "Open Auditor Conflicts", value: auditor?.open_conflicts_count ?? 0, tone: (auditor?.open_conflicts_count ?? 0) > 0 ? "critical" : "success" },
          ]}
        />

        <div className="grid gap-4 xl:grid-cols-2">
          <RankedBarsCard
            title="Module Risk Heat"
            subtitle="Normalized risk index by module (0-100)"
            items={moduleRiskBars}
            maxValue={100}
          />
          <div aria-hidden="true" />
        </div>

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Top Teams at Risk" description="Departments with highest findings concentration.">
            <SimpleTable
              columns={["Team", "Findings"]}
              rows={topTeams.map((item) => [item.team, item.count])}
            />
          </PageSection>
          <PageSection title="Recent High-Risk Findings" description="Most recent high and critical findings requiring response.">
            <SimpleTable
              columns={["Finding", "Severity", "Tool", "Status", "Updated"]}
              rows={recentCritical.map((item) => [item.finding_id, item.severity, item.ai_tool, item.status, new Date(item.updated_at).toLocaleString()])}
            />
          </PageSection>
        </div>

        <PageSection title="Module Command Matrix" description="Unified module reporting with action ownership for executive operations cadence.">
          <SimpleTable
            columns={["Module", "Signal", "Status", "Recommended Action", "Open"]}
            rows={moduleRows.map((row) => [
              row.module,
              row.metric,
              <Badge
                key={`${row.module}-status`}
                className={
                  row.status === "critical"
                    ? "bg-red-950 text-red-300"
                    : row.status === "attention"
                      ? "bg-amber-950 text-amber-300"
                      : "bg-emerald-950 text-emerald-300"
                }
              >
                {row.status}
              </Badge>,
              row.action,
              <Button key={`${row.module}-open`} asChild variant="outline" size="sm">
                <Link href={row.href}>Open</Link>
              </Button>,
            ])}
          />
        </PageSection>

        <PageSection title="Control Maturity Snapshot" description="Cross-module control confidence and evidence-linked posture.">
          <div className="mb-4 flex items-center gap-3">
            <Badge>Average Maturity: {avg.toFixed(2)}</Badge>
            <Badge>{maturity.length} controls tracked</Badge>
          </div>
          <SimpleTable
            columns={["Control", "Technical", "Simulation", "Coverage", "Maturity"]}
            rows={maturity.map((m) => [m.control_id, m.technical_enforcement_score.toFixed(2), m.simulation_pass_rate.toFixed(2), m.coverage_score.toFixed(2), m.maturity_score.toFixed(2)])}
          />
        </PageSection>
        </> : null}
      </div>
    </AppShell>
  );
}
