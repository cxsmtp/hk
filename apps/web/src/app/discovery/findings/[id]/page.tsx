"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { OperationalState } from "@/components/operational-state";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { ProofTimeline } from "@/components/proof-timeline";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { AIOrchestrationResult, FindingTraceability, RuntimeTrace } from "@/lib/types";

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

function flattenPayload(
  source: Record<string, unknown>,
  prefix = "",
  depth = 0,
  out: Array<[string, string]> = []
): Array<[string, string]> {
  if (depth > 3 || out.length > 60) return out;
  Object.entries(source).forEach(([key, value]) => {
    if (out.length > 60) return;
    const label = prefix ? `${prefix}.${key}` : key;
    if (value === null || value === undefined) {
      out.push([label, "null"]);
      return;
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out.push([label, String(value)]);
      return;
    }
    if (Array.isArray(value)) {
      out.push([label, `array(${value.length})`]);
      value.slice(0, 8).forEach((entry, idx) => {
        if (entry && typeof entry === "object" && !Array.isArray(entry)) {
          flattenPayload(entry as Record<string, unknown>, `${label}[${idx}]`, depth + 1, out);
        } else {
          out.push([`${label}[${idx}]`, String(entry)]);
        }
      });
      return;
    }
    if (typeof value === "object") {
      flattenPayload(value as Record<string, unknown>, label, depth + 1, out);
    }
  });
  return out;
}

function toneForStatus(status: "complete" | "partial" | "missing") {
  if (status === "complete") return "bg-emerald-500/15 text-emerald-200 border-emerald-500/40";
  if (status === "partial") return "bg-amber-500/15 text-amber-200 border-amber-500/40";
  return "bg-red-500/15 text-red-200 border-red-500/40";
}

function selectEvidenceHighlights(rows: Array<[string, string]>): Array<[string, string]> {
  if (!rows.length) return [];
  const priorityKeys = [
    "decision",
    "base_decision",
    "enforcement_action",
    "reason",
    "reason_code",
    "reason_codes",
    "policy_version",
    "confidence",
    "confidence_tier",
    "risk_score",
    "risk_level",
    "guardian_contract_id",
    "control_id",
    "control_ids",
    "correlation_id",
    "request_id",
    "domain",
    "source_surface",
  ];
  const usedFields = new Set<string>();
  const selected: Array<[string, string]> = [];

  for (const key of priorityKeys) {
    const match = rows.find(([field, value]) => {
      const normalized = field.toLowerCase();
      return (normalized === key || normalized.endsWith(`.${key}`)) && value && value !== "null";
    });
    if (!match) continue;
    if (usedFields.has(match[0])) continue;
    selected.push(match);
    usedFields.add(match[0]);
    if (selected.length >= 8) break;
  }

  if (selected.length < 6) {
    rows.forEach((entry) => {
      if (selected.length >= 8) return;
      if (usedFields.has(entry[0])) return;
      if (!entry[1] || entry[1] === "null") return;
      selected.push(entry);
      usedFields.add(entry[0]);
    });
  }

  return selected.slice(0, 8);
}

export default function DiscoveryFindingDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const findingId = decodeURIComponent((params?.id || "").toString());
  const [traceability, setTraceability] = useState<FindingTraceability | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [guidanceLoading, setGuidanceLoading] = useState(false);
  const [guidanceResult, setGuidanceResult] = useState<AIOrchestrationResult | null>(null);
  const [enforcementBusy, setEnforcementBusy] = useState<string | null>(null);
  const [linkedTrace, setLinkedTrace] = useState<RuntimeTrace | null>(null);
  const [traceBusy, setTraceBusy] = useState(false);

  async function load() {
    if (!findingId) return;
    setLoading(true);
    try {
      const payload = await api.getFindingTraceability(findingId);
      setTraceability(payload);
      setLoadError(null);
    } catch (err) {
      setTraceability(null);
      setLoadError(err instanceof Error ? err.message : "Finding traceability is unavailable.");
      toast.error(err instanceof Error ? err.message : "Failed to load finding traceability");
    } finally {
      setLoading(false);
    }
  }

  async function generateGuidance() {
    if (!findingId) return;
    setGuidanceLoading(true);
    try {
      const result = await api.generateFindingRemediationGuidance(findingId, {
        task_type: "remediation_guidance",
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
      setGuidanceResult(result);
      toast.success("Remediation guidance generated.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to generate remediation guidance");
    } finally {
      setGuidanceLoading(false);
    }
  }

  useEffect(() => {
    load().catch(() => setTraceability(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findingId]);

  useEffect(() => {
    if (!traceability?.evidence_nodes?.length) {
      setSelectedEvidenceId(null);
      return;
    }
    if (!selectedEvidenceId || !traceability.evidence_nodes.some((node) => node.id === selectedEvidenceId)) {
      setSelectedEvidenceId(traceability.evidence_nodes[0].id);
    }
  }, [traceability, selectedEvidenceId]);

  async function runDiscoveryAction(action: "approve" | "keep_monitoring" | "block" | "assign_owner" | "set_risk") {
    const app = traceability?.discovery_application;
    if (!app) {
      toast.error("No discovery application linked to this finding.");
      return;
    }
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
    const busyKey = `${app.id}:${action}`;
    setBusyAction(busyKey);
    try {
      if (action === "approve") {
        const tier = window.prompt("Risk tier for promotion (LOW|MEDIUM|HIGH|CRITICAL)", normalizeRisk(app.provisional_risk_tier));
        await api.promoteDiscoveryApplication(app.id, {
          action: "approve",
          provisional_risk_tier: normalizeRisk(tier || app.provisional_risk_tier || "MEDIUM"),
        });
        toast.success("Application promoted to governed AI system.");
        await syncExtensionPolicyAfterDecision("approve");
      }

      if (action === "keep_monitoring") {
        const tier = window.prompt("Provisional risk tier (LOW|MEDIUM|HIGH|CRITICAL)", normalizeRisk(app.provisional_risk_tier));
        await api.promoteDiscoveryApplication(app.id, {
          action: "keep_monitoring",
          provisional_risk_tier: normalizeRisk(tier || app.provisional_risk_tier || "MEDIUM"),
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
        const raw = window.prompt("Owner (tenant user UUID or department name)", app.owner_user_id || app.owner_department || "");
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
        const tier = window.prompt("Set provisional risk tier (LOW|MEDIUM|HIGH|CRITICAL)", normalizeRisk(app.provisional_risk_tier));
        if (!tier) return;
        await api.promoteDiscoveryApplication(app.id, {
          action: "keep_monitoring",
          provisional_risk_tier: normalizeRisk(tier),
        });
        toast.success("Provisional risk tier updated.");
      }

      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Governance action failed");
    } finally {
      setBusyAction(null);
    }
  }

  async function runEnforcementAction(action: "block_user" | "enforce_policy" | "disable_agent" | "revoke_token") {
    if (!traceability?.finding) return;
    setEnforcementBusy(action);
    try {
      if (action === "block_user") {
        if (!traceability.finding.user_id) {
          toast.error("This finding has no linked user.");
          return;
        }
        await api.blockUser(traceability.finding.user_id, {
          reason: `Blocked from finding ${traceability.finding.finding_id}`,
        });
        toast.success("User blocked.");
      }
      if (action === "enforce_policy") {
        if (!traceability.finding.user_id) {
          toast.error("This finding has no linked user.");
          return;
        }
        await api.enforceUserPolicy(traceability.finding.user_id, {
          reason: `Policy enforced from finding ${traceability.finding.finding_id}`,
        });
        toast.success("Policy enforced for user.");
      }
      if (action === "disable_agent") {
        if (!traceability.finding.agent_id) {
          toast.error("This finding has no linked agent.");
          return;
        }
        await api.disableAgent(traceability.finding.agent_id);
        toast.success("Agent disabled.");
      }
      if (action === "revoke_token") {
        const rawTokenId = window.prompt("Capability token id to revoke");
        if (!rawTokenId) return;
        const tokenId = rawTokenId.trim();
        if (!tokenId) return;
        await api.revokeAgentToken(tokenId);
        toast.success(`Token revoked: ${tokenId}`);
      }
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Enforcement action failed");
    } finally {
      setEnforcementBusy(null);
    }
  }

  async function loadRuntimeTrace(eventId: string) {
    if (!eventId) return;
    setTraceBusy(true);
    try {
      const payload = await api.runtimeTrace(eventId);
      setLinkedTrace(payload);
      toast.success(`Loaded trace for ${eventId}`);
    } catch (err) {
      setLinkedTrace(null);
      toast.error(err instanceof Error ? err.message : "Failed to load runtime trace");
    } finally {
      setTraceBusy(false);
    }
  }

  const uniqueControlIds = useMemo(() => {
    if (!traceability) return [];
    return Array.from(new Set(traceability.related_controls.map((item) => item.id)));
  }, [traceability]);

  const selectedEvidence = useMemo(() => {
    if (!traceability?.evidence_nodes?.length) return null;
    return traceability.evidence_nodes.find((node) => node.id === selectedEvidenceId) || traceability.evidence_nodes[0];
  }, [selectedEvidenceId, traceability]);

  const selectedEvidencePayloadRows = useMemo(() => {
    if (!selectedEvidence?.payload || typeof selectedEvidence.payload !== "object") return [] as Array<[string, string]>;
    return flattenPayload(selectedEvidence.payload);
  }, [selectedEvidence]);
  const selectedEvidenceHighlights = useMemo(
    () => selectEvidenceHighlights(selectedEvidencePayloadRows),
    [selectedEvidencePayloadRows]
  );
  const findingState = resolvePresentationState({ loading, hasData: Boolean(traceability), unavailable: Boolean(loadError) });

  const timelineHealth = useMemo(() => {
    if (!traceability) return { complete: 0, partial: 0, missing: 0 };
    return traceability.proof_timeline.reduce(
      (acc, step) => {
        acc[step.status] += 1;
        return acc;
      },
      { complete: 0, partial: 0, missing: 0 }
    );
  }, [traceability]);

  const chainEvents = useMemo(() => {
    if (!traceability) return [] as Array<{ when: string; type: string; title: string; status: string; evidenceCount: number }>;
    const enforcement = traceability.enforcement_events.map((event) => ({
      when: event.timestamp,
      type: "enforcement",
      title: event.request_id,
      status: event.final_decision,
      evidenceCount: event.evidence_nodes_created.length,
    }));
    const simulations = traceability.simulation_runs.map((run) => ({
      when: run.started_at,
      type: "simulation",
      title: run.simulation_id,
      status: run.result,
      evidenceCount: run.evidence_node_ids.length,
    }));
    const snapshots = traceability.auditor_snapshots.map((snapshot) => ({
      when: snapshot.created_at,
      type: "auditor_snapshot",
      title: snapshot.id,
      status: snapshot.trigger_type,
      evidenceCount: 0,
    }));

    return [...enforcement, ...simulations, ...snapshots].sort(
      (a, b) => (toDate(b.when)?.getTime() || 0) - (toDate(a.when)?.getTime() || 0)
    );
  }, [traceability]);

  if (!findingId) {
    return (
      <AppShell>
        <PageSection title="Finding Detail" description="Invalid finding id.">
          <p className="text-sm text-slate-500">No finding id in route.</p>
        </PageSection>
      </AppShell>
    );
  }

  const finding = traceability?.finding;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="AI Discovery"
          title="Finding Traceability"
          description={loading ? "Loading..." : finding ? `Finding ${finding.finding_id}` : "Finding not found"}
          actions={
            <Button variant="outline" onClick={() => router.push("/discovery/findings")}>
              Back to Findings
            </Button>
          }
        />

        <OperationalState
          state={findingState}
          onRetry={() => void load()}
          description={loadError ? `Finding traceability unavailable: ${loadError}. Evidence and actions remain unavailable until the source responds.` : undefined}
        />

        {traceability && finding ? (
          <>
            <KpiStrip
              items={[
                {
                  label: "Severity",
                  value: String(finding.severity).toUpperCase(),
                  tone: finding.severity === "critical" || finding.severity === "high" ? "critical" : "warning",
                },
                { label: "Status", value: String(finding.status).toUpperCase(), tone: finding.status === "resolved" ? "success" : "info" },
                { label: "Evidence Nodes", value: traceability.evidence_nodes.length, tone: "info" },
                { label: "Timeline Health", value: `${timelineHealth.complete}/${traceability.proof_timeline.length}`, tone: "default" },
              ]}
            />

            <PageSection title="Traceability Flow" description="Visual chain from signal detection to governance and proof outcomes.">
              <div className="grid gap-3 md:grid-cols-5">
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs uppercase tracking-[0.08em] text-slate-500">Signal</p>
                  <p className="mt-1 text-sm font-semibold text-slate-100">{finding.source_surface || "runtime"}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs uppercase tracking-[0.08em] text-slate-500">Finding</p>
                  <p className="mt-1 text-sm font-semibold text-slate-100">{finding.finding_type}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs uppercase tracking-[0.08em] text-slate-500">Controls</p>
                  <p className="mt-1 text-sm font-semibold text-slate-100">{uniqueControlIds.length} mapped</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs uppercase tracking-[0.08em] text-slate-500">Validation</p>
                  <p className="mt-1 text-sm font-semibold text-slate-100">{traceability.simulation_runs.length} runs</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs uppercase tracking-[0.08em] text-slate-500">Audit</p>
                  <p className="mt-1 text-sm font-semibold text-slate-100">{traceability.auditor_snapshots.length} snapshots</p>
                </div>
              </div>

              <div className="mt-4 grid gap-2 md:grid-cols-3">
                <div className={`rounded-md border px-3 py-2 text-sm ${toneForStatus("complete")}`}>
                  Complete Steps: {timelineHealth.complete}
                </div>
                <div className={`rounded-md border px-3 py-2 text-sm ${toneForStatus("partial")}`}>
                  Partial Steps: {timelineHealth.partial}
                </div>
                <div className={`rounded-md border px-3 py-2 text-sm ${toneForStatus("missing")}`}>
                  Missing Steps: {timelineHealth.missing}
                </div>
              </div>
            </PageSection>

            <PageSection title="Finding Metadata" description="Core metadata, policy association, and recommended action.">
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-300">Finding Type</p>
                  <p className="font-medium text-slate-100 break-words">{finding.finding_type}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-300">Risk Category</p>
                  <p className="font-medium text-slate-100 break-words">{finding.risk_category}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-300">Department / Owner</p>
                  <p className="font-medium text-slate-100 break-words">{finding.department || finding.user_id || "-"}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-300">Source Surface</p>
                  <p className="font-medium text-slate-100 break-words">{finding.source_surface || "-"}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-300">Machine</p>
                  <p className="font-medium text-slate-100 break-words">{finding.machine_id || "-"}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-300">Policy Version</p>
                  <p className="font-medium text-slate-100 break-words">
                    {traceability.policy_version
                      ? `${traceability.policy_version.version} (${traceability.policy_version.id})`
                      : finding.policy_version_id || "-"}
                  </p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3 md:col-span-2">
                  <p className="text-xs text-slate-300">Recommended Action</p>
                  <p className="whitespace-pre-wrap text-sm text-slate-100 break-words">{finding.recommended_action || "-"}</p>
                </div>
              </div>
            </PageSection>

            <PageSection title="Immediate Enforcement Actions" description="Take deterministic action directly from this finding context.">
              <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
                <Button
                  variant="destructive"
                  disabled={!finding.user_id || enforcementBusy === "block_user"}
                  onClick={() => runEnforcementAction("block_user")}
                >
                  {enforcementBusy === "block_user" ? "Blocking..." : "Block User"}
                </Button>
                <Button
                  variant="outline"
                  disabled={!finding.user_id || enforcementBusy === "enforce_policy"}
                  onClick={() => runEnforcementAction("enforce_policy")}
                >
                  {enforcementBusy === "enforce_policy" ? "Applying..." : "Enforce Policy"}
                </Button>
                <Button
                  variant="destructive"
                  disabled={!finding.agent_id || enforcementBusy === "disable_agent"}
                  onClick={() => runEnforcementAction("disable_agent")}
                >
                  {enforcementBusy === "disable_agent" ? "Disabling..." : "Disable Agent"}
                </Button>
                <Button
                  variant="outline"
                  disabled={!finding.agent_id || enforcementBusy === "revoke_token"}
                  onClick={() => runEnforcementAction("revoke_token")}
                >
                  {enforcementBusy === "revoke_token" ? "Revoking..." : "Revoke Token"}
                </Button>
                <Button
                  variant="outline"
                  disabled={traceBusy || !(finding.related_event_ids && finding.related_event_ids.length)}
                  onClick={() => loadRuntimeTrace((finding.related_event_ids || [])[0] || "")}
                >
                  {traceBusy ? "Loading Trace..." : "Open Runtime Trace"}
                </Button>
              </div>
              <p className="text-xs text-slate-500">
                Linked events: {(finding.related_event_ids || []).join(", ") || "none"}
              </p>
            </PageSection>

            {linkedTrace ? (
              <PageSection title="Linked Runtime Trace" description="Ordered runtime event chain attached to this finding.">
                <SimpleTable
                  columns={["Time", "Event", "Decision", "User", "Agent", "Machine", "App"]}
                  rows={linkedTrace.events.map((event) => [
                    formatDate(event.created_at),
                    event.event_id,
                    event.decision,
                    event.user_id || "-",
                    event.agent_id || "-",
                    event.machine_id || "-",
                    event.application || event.tool_name || "-",
                  ])}
                />
              </PageSection>
            ) : null}

            <PageSection
              title="AI Remediation Guidance"
              description="Bounded reasoning guidance with full prompt/retrieval/model traceability. Deterministic enforcement remains authoritative."
            >
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Button onClick={generateGuidance} disabled={guidanceLoading}>
                    {guidanceLoading ? "Generating..." : "Generate Remediation Guidance"}
                  </Button>
                  {guidanceResult ? (
                    <Button
                      variant="outline"
                      onClick={async () => {
                        try {
                          const ticket = await api.generateAIReasoningTicketPayload(guidanceResult.trace_id, "jira");
                          window.navigator.clipboard.writeText(ticket.description).catch(() => undefined);
                          toast.success("Jira payload generated (description copied).");
                        } catch (err) {
                          toast.error(err instanceof Error ? err.message : "Failed to generate Jira payload");
                        }
                      }}
                    >
                      Generate Jira Payload
                    </Button>
                  ) : null}
                </div>

                {guidanceResult ? (
                  <div className="space-y-4">
                    <div className="grid gap-3 md:grid-cols-3">
                      <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                        <p className="text-xs text-slate-300">Model Route</p>
                        <p className="font-medium text-slate-100 break-words">
                          {guidanceResult.provider} / {guidanceResult.model}
                        </p>
                      </div>
                      <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                        <p className="text-xs text-slate-300">Prompt Template</p>
                        <p className="font-medium text-slate-100 break-all">{guidanceResult.prompt_template_id}</p>
                      </div>
                      <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                        <p className="text-xs text-slate-300">Trace ID</p>
                        <p className="font-medium text-slate-100 break-all">{guidanceResult.trace_id}</p>
                      </div>
                    </div>

                    <div className="rounded-xl border border-[#2a3348] bg-[#101524] p-4">
                      <p className="text-sm font-semibold text-slate-100">
                        {guidanceResult.remediation_guidance?.summary || "No summary returned"}
                      </p>
                      <p className="mt-2 text-sm text-slate-300">
                        {guidanceResult.remediation_guidance?.root_cause_hypothesis || "-"}
                      </p>
                      <p className="mt-2 text-xs text-slate-400">
                        Priority: {guidanceResult.remediation_guidance?.priority || "-"} · Confidence:{" "}
                        {typeof guidanceResult.remediation_guidance?.confidence === "number"
                          ? guidanceResult.remediation_guidance.confidence.toFixed(2)
                          : "-"}
                      </p>
                    </div>

                    <SimpleTable
                      columns={["Step", "Action", "Description", "Approval", "Frameworks"]}
                      rows={(guidanceResult.remediation_guidance?.recommended_steps || []).map((step) => [
                        step.step_order,
                        step.action_type,
                        step.description,
                        step.requires_approval ? "required" : "not_required",
                        step.linked_frameworks.join(", ") || "-",
                      ])}
                    />
                  </div>
                ) : (
                  <p className="text-sm text-slate-500">No AI guidance generated yet for this finding.</p>
                )}
              </div>
            </PageSection>

            <PageSection title="Discovery to Governance Actions" description="Promote or block the linked discovery application from this finding.">
              {traceability.discovery_application ? (
                <div className="space-y-4">
                  <div className="grid gap-3 md:grid-cols-3">
                    <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                      <p className="text-xs text-slate-300">Application</p>
                      <p className="font-medium text-slate-100 break-words">{traceability.discovery_application.tool_name}</p>
                    </div>
                    <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                      <p className="text-xs text-slate-300">Status</p>
                      <p className="font-medium text-slate-100 break-words">{traceability.discovery_application.status}</p>
                    </div>
                    <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                      <p className="text-xs text-slate-300">AI System</p>
                      <p className="font-medium break-all text-slate-100">{traceability.discovery_application.ai_system_id || "-"}</p>
                    </div>
                  </div>
                  <div className="grid gap-2 md:grid-cols-2">
                    <Button
                      onClick={() => runDiscoveryAction("approve")}
                      disabled={busyAction === `${traceability.discovery_application.id}:approve`}
                    >
                      Approve
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => runDiscoveryAction("keep_monitoring")}
                      disabled={busyAction === `${traceability.discovery_application.id}:keep_monitoring`}
                    >
                      Keep Monitoring
                    </Button>
                    <Button
                      variant="destructive"
                      onClick={() => runDiscoveryAction("block")}
                      disabled={busyAction === `${traceability.discovery_application.id}:block`}
                    >
                      Block
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => runDiscoveryAction("assign_owner")}
                      disabled={busyAction === `${traceability.discovery_application.id}:assign_owner`}
                    >
                      Assign Owner
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => runDiscoveryAction("set_risk")}
                      disabled={busyAction === `${traceability.discovery_application.id}:set_risk`}
                    >
                      Set Provisional Risk Tier
                    </Button>
                    <Button variant="outline" onClick={() => router.push("/discovery/applications")}>
                      Open Applications
                    </Button>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-slate-500">No discovery application is linked yet. Trigger discovery ingestion for this tool first.</p>
              )}
            </PageSection>

            <PageSection title="Evidence Explorer" description="Select evidence to inspect normalized payload fields and correlation metadata.">
              <div className="grid items-start gap-4 xl:grid-cols-[360px_1fr]">
                <div className="max-h-[34rem] space-y-2 overflow-y-auto pr-1">
                  {traceability.evidence_nodes.length ? (
                    traceability.evidence_nodes.map((node) => {
                      const active = node.id === selectedEvidence?.id;
                      return (
                        <button
                          key={node.id}
                          type="button"
                          onClick={() => setSelectedEvidenceId(node.id)}
                          className={`w-full rounded-lg border px-3 py-3 text-left transition ${
                            active
                              ? "border-brand-500/50 bg-brand-500/10"
                              : "border-[#2a3348] bg-[#0f1218] hover:border-brand-500/30"
                          }`}
                        >
                          <div className="mb-1 flex items-center justify-between gap-2">
                            <code className="truncate text-xs text-slate-200">{node.id}</code>
                            <Badge>{node.signal_type}</Badge>
                          </div>
                          <p className="truncate text-sm text-slate-300">{node.label}</p>
                          <p className="mt-1 text-xs text-slate-500">{formatDate(node.created_at)} · corr {node.correlation_id || "-"}</p>
                        </button>
                      );
                    })
                  ) : (
                    <p className="text-sm text-slate-500">No linked evidence nodes.</p>
                  )}
                </div>

                <div className="rounded-xl border border-[#2a3348] bg-[#101524] p-4">
                  {selectedEvidence ? (
                    <>
                      <div className="mb-3 flex items-center justify-between gap-2">
                        <div>
                          <p className="text-sm font-semibold text-slate-100">{selectedEvidence.label}</p>
                          <p className="text-xs text-slate-400">
                            {selectedEvidence.node_type} · {selectedEvidence.signal_type} · {formatDate(selectedEvidence.created_at)}
                          </p>
                        </div>
                        <Badge>{selectedEvidence.signal_type}</Badge>
                      </div>

                      {selectedEvidenceHighlights.length ? (
                        <div className="mb-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                          {selectedEvidenceHighlights.map(([field, value]) => (
                            <div key={field} className="rounded-md border border-[#2a3348] bg-[#0f1218] px-2.5 py-2">
                              <p className="truncate text-[11px] uppercase tracking-[0.08em] text-slate-500">{field}</p>
                              <p className="mt-1 truncate text-sm font-semibold text-slate-100" title={value}>
                                {value}
                              </p>
                            </div>
                          ))}
                        </div>
                      ) : null}

                      <div className="max-h-[30rem] overflow-y-auto pr-1">
                        <SimpleTable
                          columns={["Field", "Value"]}
                          rows={selectedEvidencePayloadRows.length
                            ? selectedEvidencePayloadRows.map(([field, value]) => [field, value])
                            : [["payload", "No scalar payload fields available"]]}
                        />
                      </div>
                    </>
                  ) : (
                    <p className="text-sm text-slate-500">Select an evidence node to inspect payload fields.</p>
                  )}
                </div>
              </div>
            </PageSection>

            <PageSection title="Related Controls" description="Controls mapped to this finding.">
              <SimpleTable
                columns={["Control ID", "Category", "Name", "Description"]}
                rows={traceability.related_controls.map((control) => [
                  control.id,
                  control.category,
                  control.name,
                  control.description || "-",
                ])}
              />
            </PageSection>

            <PageSection title="Proof Timeline" description="End-to-end traceability from detection to auditor visibility.">
              <ProofTimeline steps={traceability.proof_timeline} formatDate={formatDate} />
            </PageSection>

            <div className="grid gap-6 xl:grid-cols-2">
              <PageSection title="Enforcement & Simulation Chain" description="Evaluation and validation records tied to this finding.">
                <SimpleTable
                  columns={["When", "Type", "Reference", "Decision/Result", "Evidence"]}
                  rows={chainEvents.map((row) => [
                    formatDate(row.when),
                    row.type,
                    row.title,
                    row.status,
                    row.evidenceCount,
                  ])}
                />
              </PageSection>

              <PageSection title="Maturity & Auditor Visibility" description="Control maturity effects and auditor snapshot visibility.">
                <SimpleTable
                  columns={["Type", "ID", "Status", "When", "Notes"]}
                  rows={[
                    ...traceability.maturity_effects.map((row) => [
                      "maturity",
                      row.control_id,
                      `${row.status} (${row.maturity_score.toFixed(2)})`,
                      formatDate(row.updated_at),
                      `confidence ${row.confidence_score.toFixed(2)}`,
                    ]),
                    ...traceability.auditor_snapshots.map((snapshot) => [
                      "snapshot",
                      snapshot.id,
                      snapshot.trigger_type,
                      formatDate(snapshot.created_at),
                      snapshot.artifact_path,
                    ]),
                  ]}
                />
              </PageSection>
            </div>

            <PageSection title="Traceability Summary" description="Quick chain integrity signals.">
              <ul className="space-y-2 text-sm text-slate-700">
                <li className="rounded border border-[#2a3348] bg-[#101524] px-3 py-2 text-slate-100">Evidence nodes linked: {traceability.evidence_nodes.length}</li>
                <li className="rounded border border-[#2a3348] bg-[#101524] px-3 py-2 text-slate-100">Related controls mapped: {uniqueControlIds.length}</li>
                <li className="rounded border border-[#2a3348] bg-[#101524] px-3 py-2 text-slate-100">Simulation runs tied to finding: {traceability.simulation_runs.length}</li>
                <li className="rounded border border-[#2a3348] bg-[#101524] px-3 py-2 text-slate-100">Auditor snapshots in scope: {traceability.auditor_snapshots.length}</li>
              </ul>
            </PageSection>
          </>
        ) : (
          <PageSection title="Finding Traceability" description="No traceability payload loaded.">
            <p className="text-sm text-slate-500">{loading ? "Loading traceability..." : "Finding could not be loaded."}</p>
          </PageSection>
        )}
      </div>
    </AppShell>
  );
}
