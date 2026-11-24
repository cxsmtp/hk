"use client";

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { AISystem, DiscoveryApplication, Finding } from "@/lib/types";


function toDate(value?: string | null): Date | null {
  if (!value) return null;
  const out = new Date(value);
  return Number.isNaN(out.getTime()) ? null : out;
}

function previousWeekIsoDate(): string {
  const date = new Date();
  date.setDate(date.getDate() - 7);
  return date.toISOString();
}

export default function DiscoveryExecutiveSummaryPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [apps, setApps] = useState<DiscoveryApplication[]>([]);
  const [systems, setSystems] = useState<AISystem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.listFindings({ page_size: 1000 }),
      api.listDiscoveryApplications({ page_size: 500 }),
      api.listAISystems(),
    ])
      .then(([findingsPayload, appsPayload, systemsPayload]) => {
        setFindings(findingsPayload.items || []);
        setApps(appsPayload.items || []);
        setSystems(systemsPayload.items || []);
        setLoadError(null);
      })
      .catch((err) => {
        setLoadError(err instanceof Error ? err.message : "Executive summary data is unavailable");
        toast.error(err instanceof Error ? err.message : "Failed to load executive summary");
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const riskPosture = useMemo(() => {
    if (loading) return "Loading";
    if (loadError && !findings.length && !apps.length && !systems.length) return "Unavailable";
    if (!findings.length && !apps.length && !systems.length) return "No observed data";
    const openCritical = findings.filter((f) => f.status !== "resolved" && f.severity === "critical").length;
    const openHigh = findings.filter((f) => f.status !== "resolved" && f.severity === "high").length;
    const shadowApps = apps.filter((app) => app.status === "discovered" || app.status === "monitoring").length;
    if (openCritical > 0 || shadowApps > 8) return "High";
    if (openHigh > 0 || shadowApps > 3) return "Moderate";
    return "Controlled";
  }, [apps, findings, loadError, loading, systems]);

  const hasData = findings.length > 0 || apps.length > 0 || systems.length > 0;
  const presentationState = loadError ? (hasData ? "stale" : "unavailable") : loading ? "loading" : hasData ? "ready-populated" : "ready-empty";

  const topApps = useMemo(() => {
    return [...apps]
      .sort((a, b) => (b.risk_score - a.risk_score) || ((toDate(b.last_seen_at)?.getTime() || 0) - (toDate(a.last_seen_at)?.getTime() || 0)))
      .slice(0, 5);
  }, [apps]);

  const topTeams = useMemo(() => {
    const byTeam = new Map<string, number>();
    findings.forEach((finding) => {
      const key = finding.department || "unassigned";
      byTeam.set(key, (byTeam.get(key) || 0) + 1);
    });
    return Array.from(byTeam.entries())
      .map(([team, count]) => ({ team, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [findings]);

  const topFindings = useMemo(() => {
    return [...findings]
      .sort((a, b) => {
        const severityRank = (value: string) => {
          if (value === "critical") return 4;
          if (value === "high") return 3;
          if (value === "med") return 2;
          return 1;
        };
        return (severityRank(b.severity) - severityRank(a.severity)) || ((toDate(b.updated_at)?.getTime() || 0) - (toDate(a.updated_at)?.getTime() || 0));
      })
      .slice(0, 5);
  }, [findings]);

  const weeklyChanges = useMemo(() => {
    const since = toDate(previousWeekIsoDate())?.getTime() || 0;
    const recent = findings.filter((finding) => (toDate(finding.updated_at)?.getTime() || 0) >= since);
    const newShadow = recent.filter((finding) => finding.finding_type === "shadow_ai_discovery").length;
    const newCritical = recent.filter((finding) => finding.severity === "critical").length;
    const resolved = recent.filter((finding) => finding.status === "resolved").length;
    return { newShadow, newCritical, resolved };
  }, [findings]);

  const prioritizedSteps = useMemo(() => {
    const steps: string[] = [];
    if (weeklyChanges.newCritical > 0) steps.push(`Escalate ${weeklyChanges.newCritical} new critical findings to owners and admins.`);
    if (weeklyChanges.newShadow > 0) steps.push(`Convert ${weeklyChanges.newShadow} newly discovered tools into governed applications or block them.`);
    if (apps.some((app) => app.status === "discovered")) steps.push("Coach unowned shadow usage and assign owners for all discovered tools.");
    if (systems.some((system) => String(system.status).toLowerCase() === "draft")) steps.push("Approve or retire draft AI systems to reduce unmanaged production use.");
    if (!steps.length) steps.push("Maintain monitoring cadence and re-run validation packs for top-risk controls.");
    return steps.slice(0, 5);
  }, [apps, systems, weeklyChanges.newCritical, weeklyChanges.newShadow]);

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="AI Discovery"
          title="Executive summary"
          description="Concise weekly AI risk posture for leadership decisions, grounded in the current tenant evidence."
        />
        <OperationalState
          state={presentationState}
          title={loadError ? "Executive summary data unavailable" : undefined}
          description={loadError ? "The source response could not be loaded. Existing records remain visible when available; retry from the source page." : undefined}
        />

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-slate-600">Current AI Risk Posture</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-semibold">{riskPosture}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-slate-600">Top 5 Apps</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-semibold">{topApps.length}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-slate-600">Top 5 Teams</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-semibold">{topTeams.length}</p>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-slate-600">Top 5 Findings</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-semibold">{topFindings.length}</p>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-6 xl:grid-cols-3">
          <PageSection title="Top 5 Apps" description="Highest risk score applications this week.">
            <SimpleTable
              columns={["Tool", "Status", "Risk", "Owner"]}
              rows={topApps.map((app) => [app.tool_name, app.status, app.risk_score, app.owner_label || "-"])}
            />
          </PageSection>
          <PageSection title="Top 5 Teams" description="Teams with highest finding concentration.">
            <SimpleTable
              columns={["Team", "Findings"]}
              rows={topTeams.map((row) => [row.team, row.count])}
            />
          </PageSection>
          <PageSection title="Top 5 Findings" description="Most urgent findings by severity and freshness.">
            <SimpleTable
              columns={["Finding", "Severity", "Tool", "Status"]}
              rows={topFindings.map((finding) => [finding.finding_id, finding.severity, finding.ai_tool, finding.status])}
            />
          </PageSection>
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <PageSection title="Key Changes Since Last Week" description="Movement in shadow and critical risk signals.">
            <SimpleTable
              columns={["Metric", "Value"]}
              rows={[
                ["New shadow AI discoveries", weeklyChanges.newShadow],
                ["New critical findings", weeklyChanges.newCritical],
                ["Resolved findings", weeklyChanges.resolved],
              ]}
            />
          </PageSection>

          <PageSection title="Prioritized Next Steps" description="Monitor / coach / enforce / validate / escalate decisions.">
            <ol className="space-y-3 text-sm text-slate-700">
              {prioritizedSteps.map((step) => (
                <li key={step} className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
                  {step}
                </li>
              ))}
            </ol>
          </PageSection>
        </div>
      </div>
    </AppShell>
  );
}
