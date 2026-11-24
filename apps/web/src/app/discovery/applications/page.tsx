"use client";

import Link from "next/link";
import { useMemo, useState, useEffect } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { DetailDrawer } from "@/components/detail-drawer";
import { KpiStrip } from "@/components/kpi-strip";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { DiscoveryApplication, Finding, ShadowAIEntity, ShadowAIEntityDetail } from "@/lib/types";


const SHADOW_STATUS_OPTIONS = ["", "discovered", "reconciled", "promoted", "rejected"] as const;
const SHADOW_SOURCE_OPTIONS = ["", "browser", "endpoint", "dns", "proxy", "gateway", "connector", "aiiam", "monitoring"] as const;

function toDate(value?: string | null): Date | null {
  if (!value) return null;
  const out = new Date(value);
  return Number.isNaN(out.getTime()) ? null : out;
}

function formatDate(value?: string | null): string {
  const parsed = toDate(value);
  return parsed ? parsed.toLocaleString() : "-";
}

function normalizeRisk(value?: string | null): string {
  const normalized = String(value || "").trim().toUpperCase();
  if (!normalized) return "MEDIUM";
  return normalized;
}

function isLikelyUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export default function DiscoveryApplicationsPage() {
  const [applications, setApplications] = useState<DiscoveryApplication[]>([]);
  const [shadowEntities, setShadowEntities] = useState<ShadowAIEntity[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedShadowId, setSelectedShadowId] = useState<string | null>(null);
  const [selectedShadowDetail, setSelectedShadowDetail] = useState<ShadowAIEntityDetail | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [shadowStatusFilter, setShadowStatusFilter] = useState<(typeof SHADOW_STATUS_OPTIONS)[number]>("");
  const [shadowSourceFilter, setShadowSourceFilter] = useState<(typeof SHADOW_SOURCE_OPTIONS)[number]>("");
  const [loadState, setLoadState] = useState<"loading" | "ready" | "stale" | "unavailable">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);

  async function load() {
    setLoadState((current) => current === "ready" || current === "stale" ? "stale" : "loading");
    try {
      const [applicationsPayload, shadowPayload, findingsPayload] = await Promise.all([
        api.listDiscoveryApplications({ page_size: 300 }),
        api.listShadowAIEntities({
          page_size: 300,
          status_filter: shadowStatusFilter || undefined,
          source_surface: shadowSourceFilter || undefined,
        }),
        api.listFindings({ page_size: 500 }),
      ]);
      setApplications(applicationsPayload.items || []);
      setShadowEntities(shadowPayload.items || []);
      setFindings(findingsPayload.items || []);
      setLoadError(null);
      setLoadState("ready");
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Discovery application data is unavailable.");
      setLoadState((current) => current === "stale" ? "stale" : "unavailable");
      toast.error(err instanceof Error ? err.message : "Failed to load discovery applications");
    }
  }

  async function loadShadowDetail(entityId: string) {
    try {
      const detail = await api.getShadowAIEntity(entityId);
      setSelectedShadowDetail(detail);
    } catch (err) {
      setSelectedShadowDetail(null);
      toast.error(err instanceof Error ? err.message : "Failed to load shadow entity detail");
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shadowStatusFilter, shadowSourceFilter]);

  useEffect(() => {
    if (!selectedShadowId) {
      setSelectedShadowDetail(null);
      return;
    }
    loadShadowDetail(selectedShadowId).catch(() => undefined);
  }, [selectedShadowId]);

  const sortedApps = useMemo(
    () =>
      [...applications].sort(
        (a, b) =>
          (b.risk_score - a.risk_score) ||
          ((toDate(b.last_seen_at)?.getTime() || 0) - (toDate(a.last_seen_at)?.getTime() || 0))
      ),
    [applications]
  );

  const sortedShadowEntities = useMemo(
    () =>
      [...shadowEntities].sort(
        (a, b) =>
          (b.confidence_score - a.confidence_score) ||
          ((toDate(b.last_seen)?.getTime() || 0) - (toDate(a.last_seen)?.getTime() || 0))
      ),
    [shadowEntities]
  );

  const selected = useMemo(
    () => sortedApps.find((item) => item.id === selectedId) || null,
    [sortedApps, selectedId]
  );

  const selectedFindings = useMemo(() => {
    if (!selected) return [];
    return findings
      .filter((finding) => finding.ai_tool === selected.tool_name)
      .sort((a, b) => (toDate(b.updated_at)?.getTime() || 0) - (toDate(a.updated_at)?.getTime() || 0));
  }, [findings, selected]);

  const selectedEvidenceIds = useMemo(
    () => Array.from(new Set(selectedFindings.flatMap((finding) => finding.evidence_node_ids || []))).filter(Boolean),
    [selectedFindings]
  );

  const selectedTrend = useMemo(() => {
    if (!selected) return [];
    const windowDays = 7;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const byDate = new Map<string, { date: string; count: number; high: number }>();
    for (let i = windowDays - 1; i >= 0; i -= 1) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      byDate.set(key, { date: key, count: 0, high: 0 });
    }
    selectedFindings.forEach((finding) => {
      const date = toDate(finding.updated_at || finding.created_at);
      if (!date) return;
      const key = date.toISOString().slice(0, 10);
      const bucket = byDate.get(key);
      if (!bucket) return;
      bucket.count += 1;
      if (finding.severity === "high" || finding.severity === "critical") {
        bucket.high += 1;
      }
    });
    return Array.from(byDate.values());
  }, [selected, selectedFindings]);

  const appKpis = useMemo(() => {
    const approved = applications.filter((item) => item.status === "approved").length;
    const shadow = applications.filter((item) => item.status === "discovered").length;
    const blocked = applications.filter((item) => item.status === "blocked").length;
    const atRisk = applications.filter((item) => item.risk_score >= 70).length;
    const shadowDiscovered = shadowEntities.filter((item) => item.discovery_status === "discovered").length;
    const shadowPromoted = shadowEntities.filter((item) => item.discovery_status === "promoted").length;
    return { approved, shadow, blocked, atRisk, shadowDiscovered, shadowPromoted };
  }, [applications, shadowEntities]);

  async function refreshAndKeepSelection(id?: string) {
    await load();
    if (id) setSelectedId(id);
  }

  async function refreshAndKeepShadowSelection(id?: string) {
    await load();
    if (id) {
      setSelectedShadowId(id);
      await loadShadowDetail(id);
    }
  }

  async function runAction(
    app: DiscoveryApplication,
    action: "approve" | "keep_monitoring" | "block" | "assign_owner" | "set_risk"
  ) {
    async function syncExtensionPolicyAfterDecision(decision: "approve" | "block") {
      try {
        await api.extensionPolicySync();
      } catch (err) {
        const detail = err instanceof Error && err.message ? ` (${err.message})` : "";
        toast.warning(
          `Saved ${decision} decision, but extension policy auto-sync failed${detail}. Extension will refresh on next heartbeat.`
        );
      }
    }

    const key = `${app.id}:${action}`;
    setBusyAction(key);
    try {
      if (action === "approve") {
        const tier = window.prompt(
          "Risk tier for promotion (LOW|MEDIUM|HIGH|CRITICAL)",
          normalizeRisk(app.provisional_risk_tier)
        );
        const risk = normalizeRisk(tier || app.provisional_risk_tier || "MEDIUM");
        await api.promoteDiscoveryApplication(app.id, {
          action: "approve",
          provisional_risk_tier: risk,
        });
        toast.success("Application promoted to Trust Center governance.");
        await syncExtensionPolicyAfterDecision("approve");
      }

      if (action === "keep_monitoring") {
        const tier = window.prompt(
          "Provisional risk tier (LOW|MEDIUM|HIGH|CRITICAL)",
          normalizeRisk(app.provisional_risk_tier)
        );
        const risk = normalizeRisk(tier || app.provisional_risk_tier || "MEDIUM");
        await api.promoteDiscoveryApplication(app.id, {
          action: "keep_monitoring",
          provisional_risk_tier: risk,
        });
        toast.success("Application set to monitoring.");
      }

      if (action === "block") {
        const reason = window.prompt("Block reason", "Unapproved high-risk usage");
        await api.blockDiscoveryApplication(app.id, { reason: reason || undefined });
        toast.success("Application blocked.");
        await syncExtensionPolicyAfterDecision("block");
      }

      if (action === "assign_owner") {
        const raw = window.prompt(
          "Owner (tenant user UUID or department name)",
          app.owner_user_id || app.owner_department || ""
        );
        if (raw === null) return;
        const value = raw.trim();
        if (!value) return;
        if (isLikelyUuid(value)) {
          await api.assignDiscoveryApplicationOwner(app.id, { owner_user_id: value });
        } else {
          await api.assignDiscoveryApplicationOwner(app.id, { owner_department: value });
        }
        toast.success("Owner assigned.");
      }

      if (action === "set_risk") {
        const tier = window.prompt(
          "Set provisional risk tier (LOW|MEDIUM|HIGH|CRITICAL)",
          normalizeRisk(app.provisional_risk_tier)
        );
        if (!tier) return;
        await api.promoteDiscoveryApplication(app.id, {
          action: "keep_monitoring",
          provisional_risk_tier: normalizeRisk(tier),
        });
        toast.success("Provisional risk tier updated.");
      }

      await refreshAndKeepSelection(app.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusyAction(null);
    }
  }

  async function runShadowAction(
    entity: ShadowAIEntityDetail,
    action: "promote" | "link" | "reject" | "merge"
  ) {
    const key = `${entity.id}:${action}`;
    setBusyAction(key);
    try {
      if (action === "promote") {
        await api.promoteShadowAIEntity(entity.id, { force: true });
        toast.success("Shadow entity promoted to Trust Center candidate.");
      }
      if (action === "link") {
        const aiSystemId = window.prompt("Link to AI system id", entity.linked_ai_system_id || "");
        if (!aiSystemId) return;
        await api.linkShadowAIEntityToAISystem(entity.id, { ai_system_id: aiSystemId.trim() });
        toast.success("Shadow entity linked to AI system.");
      }
      if (action === "reject") {
        const reason = window.prompt("Reject reason", "false_positive");
        await api.rejectShadowAIEntity(entity.id, { reason: reason || undefined });
        toast.success("Shadow entity rejected.");
      }
      if (action === "merge") {
        const targetEntityId = window.prompt("Merge into target shadow entity id", "");
        if (!targetEntityId) return;
        await api.mergeShadowAIEntities(entity.id, { target_entity_id: targetEntityId.trim() });
        toast.success("Shadow entity merged.");
      }
      await refreshAndKeepShadowSelection(entity.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Shadow AI action failed");
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="AI Discovery"
          title="Applications"
          description="Unified discovery for governed applications and shadow AI entities with governance transition controls."
        />
        {loadState === "loading" && !applications.length && !shadowEntities.length ? <p role="status" className="text-sm text-slate-500">Loading observed applications…</p> : null}
        {loadState === "stale" ? <p role="status" className="text-sm text-amber-300">Showing the last successful application snapshot while refresh is unavailable{loadError ? `: ${loadError}` : ""}.</p> : null}
        {loadState === "unavailable" ? <p role="status" className="text-sm text-amber-300">Discovery application data is unavailable. Existing actions remain available when a snapshot returns.</p> : null}

        <KpiStrip
          items={[
            { label: "Applications", value: loadState === "loading" ? "Loading" : loadState === "unavailable" ? "Unknown" : applications.length, tone: "info" },
            { label: "Approved", value: loadState === "loading" || loadState === "unavailable" ? "Unknown" : appKpis.approved, tone: "success" },
            { label: "Shadow Apps", value: loadState === "loading" || loadState === "unavailable" ? "Unknown" : appKpis.shadow, tone: "warning" },
            { label: "Blocked / High Risk", value: loadState === "loading" || loadState === "unavailable" ? "Unknown" : `${appKpis.blocked} / ${appKpis.atRisk}`, tone: "critical" },
            { label: "Shadow Entities", value: loadState === "loading" || loadState === "unavailable" ? "Unknown" : `${appKpis.shadowDiscovered} discovered`, tone: "warning" },
            { label: "Promoted", value: loadState === "loading" || loadState === "unavailable" ? "Unknown" : appKpis.shadowPromoted, tone: "success" },
          ]}
        />

        <PageSection title="AI Tools" description="Lifecycle from discovered to governed and enforced.">
          <SimpleTable
            columns={["Tool", "Vendor", "Status", "Last Seen", "Users", "Risk Score", "Owner", "Recommended Action", "Details"]}
            rows={sortedApps.map((app) => [
              app.tool_name,
              app.vendor,
              <Badge key={`${app.id}-status`}>{app.status}</Badge>,
              formatDate(app.last_seen_at),
              app.findings_total,
              app.risk_score,
              app.owner_label || "-",
              app.recommended_action.length > 90 ? `${app.recommended_action.slice(0, 90)}...` : app.recommended_action,
              <Button key={`${app.id}-details`} size="sm" variant="outline" onClick={() => setSelectedId(app.id)}>
                View
              </Button>,
            ])}
            emptyLabel={loadState === "unavailable" ? "Application data is unavailable." : loadState === "loading" ? "Loading observed applications…" : "No observed applications match this view."}
          />
        </PageSection>

        <PageSection title="Shadow AI Entities" description="Cross-surface correlated entities pending governance reconciliation.">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <label className="text-xs text-slate-500">
                Status Filter
                <select
                  className="ml-2 h-9 rounded-md border border-slate-300 bg-white px-2 text-sm"
                  value={shadowStatusFilter}
                  onChange={(event) => setShadowStatusFilter(event.target.value as (typeof SHADOW_STATUS_OPTIONS)[number])}
                >
                  {SHADOW_STATUS_OPTIONS.map((value) => (
                    <option key={value || "all"} value={value}>
                      {value ? value : "all"}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-slate-500">
                Source Filter
                <select
                  className="ml-2 h-9 rounded-md border border-slate-300 bg-white px-2 text-sm"
                  value={shadowSourceFilter}
                  onChange={(event) => setShadowSourceFilter(event.target.value as (typeof SHADOW_SOURCE_OPTIONS)[number])}
                >
                  {SHADOW_SOURCE_OPTIONS.map((value) => (
                    <option key={value || "all"} value={value}>
                      {value ? value : "all"}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <Button variant="outline" size="sm" onClick={() => load().catch(() => undefined)}>
              Refresh
            </Button>
          </div>
          <SimpleTable
            columns={["Entity", "Status", "Confidence", "Risk", "Seen Via", "Signals", "Linked AI System", "Findings", "Details"]}
            rows={sortedShadowEntities.map((entity) => [
              entity.canonical_name,
              <Badge key={`${entity.id}-status`}>{entity.discovery_status}</Badge>,
              `${entity.confidence_score.toFixed(2)} (${entity.confidence_level})`,
              entity.provisional_risk_tier || "-",
              (entity.source_surfaces || []).join(", ") || "-",
              entity.signal_count,
              entity.linked_ai_system_id || "-",
              entity.open_findings,
              <Button key={`${entity.id}-details`} size="sm" variant="outline" onClick={() => setSelectedShadowId(entity.id)}>
                View
              </Button>,
            ])}
            emptyLabel={loadState === "unavailable" ? "Shadow AI data is unavailable." : loadState === "loading" ? "Loading observed shadow AI…" : "No observed shadow AI entities match these filters."}
          />
        </PageSection>
      </div>

      {selected ? (
        <DetailDrawer
          open={Boolean(selected)}
          onClose={() => setSelectedId(null)}
          title={selected.tool_name}
          subtitle={`${selected.vendor} · status ${selected.status} · last seen ${formatDate(selected.last_seen_at)}`}
        >
          <div className="space-y-6">
            <div className="grid gap-4 md:grid-cols-4">
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">Risk Score</p>
                <p className="text-lg font-semibold text-slate-100">{selected.risk_score}</p>
              </div>
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">Findings</p>
                <p className="text-lg font-semibold text-slate-100">{selected.findings_total}</p>
              </div>
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">Open Findings</p>
                <p className="text-lg font-semibold text-slate-100">{selected.findings_open}</p>
              </div>
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">AI System</p>
                <p className="text-sm font-semibold break-all text-slate-100">{selected.ai_system_id || "-"}</p>
              </div>
            </div>

            <PageSection title="Governance Actions" description="Move this application from discovered to governed and enforced.">
              <div className="grid gap-2 md:grid-cols-2">
                <Button onClick={() => runAction(selected, "approve")} disabled={busyAction === `${selected.id}:approve`}>
                  Approve
                </Button>
                <Button variant="outline" onClick={() => runAction(selected, "keep_monitoring")} disabled={busyAction === `${selected.id}:keep_monitoring`}>
                  Keep Monitoring
                </Button>
                <Button variant="destructive" onClick={() => runAction(selected, "block")} disabled={busyAction === `${selected.id}:block`}>
                  Block
                </Button>
                <Button variant="outline" onClick={() => runAction(selected, "assign_owner")} disabled={busyAction === `${selected.id}:assign_owner`}>
                  Assign Owner
                </Button>
                <Button variant="outline" onClick={() => runAction(selected, "set_risk")} disabled={busyAction === `${selected.id}:set_risk`}>
                  Set Provisional Risk Tier
                </Button>
              </div>
            </PageSection>

            <PageSection title="Linked Findings" description="Traceability into discovery findings and evidence.">
              <SimpleTable
                columns={["Finding", "Type", "Severity", "Status", "Updated", "Policy"]}
                rows={selectedFindings.map((finding) => [
                  <Link
                    key={`finding-${finding.finding_id}`}
                    href={`/discovery/findings/${encodeURIComponent(finding.finding_id)}`}
                    className="text-brand-300 underline underline-offset-2"
                  >
                    {finding.finding_id}
                  </Link>,
                  finding.finding_type,
                  finding.severity,
                  finding.status,
                  formatDate(finding.updated_at),
                  finding.policy_version_id || "-",
                ])}
              />
            </PageSection>

            <PageSection title="Recent Trend" description="7-day finding trend for this application.">
              <SimpleTable
                columns={["Date", "Total Findings", "High/Critical"]}
                rows={selectedTrend.map((row) => [new Date(`${row.date}T00:00:00Z`).toLocaleDateString(), row.count, row.high])}
              />
            </PageSection>

            <PageSection title="Evidence IDs" description="Evidence links generated from discovery and governance transitions.">
              <div className="flex flex-wrap gap-2">
                {selectedEvidenceIds.length ? (
                  selectedEvidenceIds.map((id) => (
                    <code key={id} className="rounded-md border border-[#1e2433] bg-[#13161f] px-2 py-1 text-xs text-slate-300">
                      {id}
                    </code>
                  ))
                ) : (
                  <p className="text-sm text-slate-500">No linked evidence IDs.</p>
                )}
              </div>
            </PageSection>
          </div>
        </DetailDrawer>
      ) : null}

      {selectedShadowDetail ? (
        <DetailDrawer
          open={Boolean(selectedShadowDetail)}
          onClose={() => setSelectedShadowId(null)}
          title={selectedShadowDetail.canonical_name}
          subtitle={`status ${selectedShadowDetail.discovery_status} · confidence ${selectedShadowDetail.confidence_score.toFixed(2)} (${selectedShadowDetail.confidence_level})`}
        >
          <div className="space-y-6">
            <div className="grid gap-4 md:grid-cols-4">
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">Risk Tier</p>
                <p className="text-lg font-semibold text-slate-100">{selectedShadowDetail.provisional_risk_tier || "-"}</p>
              </div>
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">Signals</p>
                <p className="text-lg font-semibold text-slate-100">{selectedShadowDetail.signal_count}</p>
              </div>
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">Open Findings</p>
                <p className="text-lg font-semibold text-slate-100">{selectedShadowDetail.open_findings}</p>
              </div>
              <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
                <p className="text-xs text-slate-500">Linked AI System</p>
                <p className="text-sm font-semibold break-all text-slate-100">{selectedShadowDetail.linked_ai_system_id || "-"}</p>
              </div>
            </div>

            <PageSection title="Governance Actions" description="Promote, link, reject, or merge correlated shadow entities.">
              <div className="grid gap-2 md:grid-cols-2">
                <Button onClick={() => runShadowAction(selectedShadowDetail, "promote")} disabled={busyAction === `${selectedShadowDetail.id}:promote`}>
                  Promote Candidate
                </Button>
                <Button variant="outline" onClick={() => runShadowAction(selectedShadowDetail, "link")} disabled={busyAction === `${selectedShadowDetail.id}:link`}>
                  Link to AI System
                </Button>
                <Button variant="destructive" onClick={() => runShadowAction(selectedShadowDetail, "reject")} disabled={busyAction === `${selectedShadowDetail.id}:reject`}>
                  Reject
                </Button>
                <Button variant="outline" onClick={() => runShadowAction(selectedShadowDetail, "merge")} disabled={busyAction === `${selectedShadowDetail.id}:merge`}>
                  Merge Entity
                </Button>
              </div>
            </PageSection>

            <PageSection title="Signal Attribution" description="Cross-surface signal provenance for this entity.">
              <SimpleTable
                columns={["Surface", "Source Event", "Domain", "Provider", "Tool", "API Endpoint", "Source Details", "User", "When"]}
                rows={selectedShadowDetail.signals.map((signal) => [
                  signal.source_surface,
                  signal.source_event_id,
                  signal.domain || "-",
                  signal.provider || "-",
                  signal.tool_name || "-",
                  signal.api_endpoint || "-",
                  [
                    String((signal.raw_fingerprint || {}).process_name || ""),
                    String((signal.raw_fingerprint || {}).queried_domain || ""),
                    String((signal.raw_fingerprint || {}).request_domain || ""),
                  ]
                    .filter(Boolean)
                    .join(" · ") || "-",
                  signal.user_id || signal.agent_id || "-",
                  formatDate(signal.created_at),
                ])}
              />
            </PageSection>

            <PageSection title="Observed Attributes" description="Entity-level correlation dimensions and linked proof references.">
              <div className="space-y-3 text-sm text-slate-300">
                <p>Seen via: {(selectedShadowDetail.source_surfaces || []).join(", ") || "-"}</p>
                <p>
                  Confidence reasoning:{" "}
                  {Array.isArray((selectedShadowDetail.metadata_json || {}).confidence_reasoning)
                    ? ((selectedShadowDetail.metadata_json || {}).confidence_reasoning as Array<unknown>).map((item) => String(item)).join(", ")
                    : "-"}
                </p>
                <p>
                  Signal breakdown:{" "}
                  {Object.entries(
                    selectedShadowDetail.signals.reduce<Record<string, number>>((acc, row) => {
                      const key = String(row.source_surface || "unknown");
                      acc[key] = (acc[key] || 0) + 1;
                      return acc;
                    }, {})
                  )
                    .map(([key, value]) => `${key}:${value}`)
                    .join(" · ") || "-"}
                </p>
                <p>Observed domains: {(selectedShadowDetail.observed_domains || []).join(", ") || "-"}</p>
                <p>Observed providers: {(selectedShadowDetail.observed_providers || []).join(", ") || "-"}</p>
                <p>Observed tools: {(selectedShadowDetail.observed_tools || []).join(", ") || "-"}</p>
                <p>First seen: {formatDate(selectedShadowDetail.first_seen)}</p>
                <p>Last seen: {formatDate(selectedShadowDetail.last_seen)}</p>
              </div>
            </PageSection>

            <PageSection title="Linked Findings" description="Discovery findings tied to this shadow entity.">
              <div className="flex flex-wrap gap-2">
                {selectedShadowDetail.linked_findings.length ? (
                  selectedShadowDetail.linked_findings.map((findingId) => (
                    <Link
                      key={findingId}
                      href={`/discovery/findings/${encodeURIComponent(findingId)}`}
                      className="text-brand-300 underline underline-offset-2"
                    >
                      {findingId}
                    </Link>
                  ))
                ) : (
                  <p className="text-sm text-slate-500">No linked findings.</p>
                )}
              </div>
            </PageSection>

            <PageSection title="Evidence IDs" description="Evidence graph references associated with this entity.">
              <div className="flex flex-wrap gap-2">
                {selectedShadowDetail.evidence_node_ids.length ? (
                  selectedShadowDetail.evidence_node_ids.map((id) => (
                    <code key={id} className="rounded-md border border-[#1e2433] bg-[#13161f] px-2 py-1 text-xs text-slate-300">
                      {id}
                    </code>
                  ))
                ) : (
                  <p className="text-sm text-slate-500">No evidence IDs linked.</p>
                )}
              </div>
            </PageSection>
          </div>
        </DetailDrawer>
      ) : null}
    </AppShell>
  );
}
