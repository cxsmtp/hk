"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { DiscoveryEvidenceSummary } from "@/components/discovery/discovery-evidence-summary";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { FilterLabel, FilterSelect, TableFilters } from "@/components/table-filters";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { deriveAgentRuntimeProfile } from "@/lib/agent-runtime-profile";
import type { AIOrchestrationResult, ShadowAIEntity, ShadowAIEntityDetail, ShadowAISignal } from "@/lib/types";

function formatDate(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function formatFixed(value: unknown, digits = 2, fallback = "0.00"): string {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return numeric.toFixed(digits);
}

export default function ShadowAIPage() {
  const [eventType, setEventType] = useState("unsanctioned_model_usage");
  const [entities, setEntities] = useState<ShadowAIEntity[]>([]);
  const [unresolvedSignals, setUnresolvedSignals] = useState<ShadowAISignal[]>([]);
  const [providerCatalog, setProviderCatalog] = useState<Array<Record<string, unknown>>>([]);
  const [coverage, setCoverage] = useState<Record<string, unknown>>({});
  const [surfaceFilter, setSurfaceFilter] = useState<string>("");
  const [selectedEntityId, setSelectedEntityId] = useState<string>("");
  const [selectedEntity, setSelectedEntity] = useState<ShadowAIEntityDetail | null>(null);
  const [busyAction, setBusyAction] = useState<string>("");
  const [guidanceLoading, setGuidanceLoading] = useState(false);
  const [guidanceResult, setGuidanceResult] = useState<AIOrchestrationResult | null>(null);
  const [lastIngestSummary, setLastIngestSummary] = useState<{
    title: string;
    details: string;
    entitiesDelta: number;
    unresolvedDelta: number;
    createdAt: string;
  } | null>(null);
  const [ingestHistory, setIngestHistory] = useState<Array<{ id: string; label: string; outcome: string; createdAt: string }>>([]);

  async function load() {
    try {
      const [entityPayload, unresolvedPayload, coveragePayload, catalogPayload] = await Promise.all([
        api.listShadowAIEntities({ page_size: 200, source_surface: surfaceFilter || undefined }),
        api.listShadowAIUnresolvedSignals({ page_size: 200 }),
        api.shadowAICoverage(),
        api.shadowAIProviderCatalog(),
      ]);
      const nextEntities = entityPayload.items || [];
      const nextUnresolved = unresolvedPayload.items || [];
      setEntities(nextEntities);
      setUnresolvedSignals(nextUnresolved);
      setCoverage(coveragePayload || {});
      setProviderCatalog(catalogPayload || []);

      const requestedEntity = new URLSearchParams(window.location.search).get("entity");
      const firstEntity = requestedEntity || nextEntities[0]?.id || "";
      if (!selectedEntityId && firstEntity) {
        setSelectedEntityId(firstEntity);
      }
      if (selectedEntityId && selectedEntityId !== requestedEntity && !nextEntities.some((item) => item.id === selectedEntityId)) {
        setSelectedEntityId(firstEntity);
        if (!firstEntity) setSelectedEntity(null);
      }
      return { entityCount: nextEntities.length, unresolvedCount: nextUnresolved.length };
    } catch (err) {
      setEntities([]);
      setUnresolvedSignals([]);
      setCoverage({});
      setProviderCatalog([]);
      toast.error(err instanceof Error ? err.message : "Failed to load shadow AI intelligence");
      return { entityCount: 0, unresolvedCount: 0 };
    }
  }

  async function loadEntityDetail(entityId: string) {
    if (!entityId) {
      setSelectedEntity(null);
      return;
    }
    try {
      const detail = await api.getShadowAIEntity(entityId);
      setSelectedEntity(detail);
    } catch (err) {
      setSelectedEntity(null);
      toast.error(err instanceof Error ? err.message : "Failed to load shadow AI entity detail");
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [surfaceFilter]);

  useEffect(() => {
    if (!selectedEntityId && entities.length > 0) {
      setSelectedEntityId(entities[0].id);
      return;
    }
    if (selectedEntityId) {
      loadEntityDetail(selectedEntityId).catch(() => undefined);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedEntityId, entities.length]);

  useEffect(() => {
    setGuidanceResult(null);
  }, [selectedEntityId]);

  async function ingest(e: FormEvent) {
    e.preventDefault();
    try {
      const before = { entities: entities.length, unresolved: unresolvedSignals.length };
      await api.ingestShadowEvent({
        event_type: eventType,
        payload: { source: "ui", severity: "high", note: "manual shadow discovery" },
      });
      toast.success("Shadow AI event ingested");
      const after = await load();
      setLastIngestSummary({
        title: "Manual event ingested",
        details: `${eventType} through monitoring stream`,
        entitiesDelta: after.entityCount - before.entities,
        unresolvedDelta: after.unresolvedCount - before.unresolved,
        createdAt: new Date().toISOString(),
      });
      setIngestHistory((prev) => [
        {
          id: `manual-${Date.now()}`,
          label: eventType,
          outcome: `entities ${after.entityCount - before.entities >= 0 ? "+" : ""}${after.entityCount - before.entities}`,
          createdAt: new Date().toISOString(),
        },
        ...prev.slice(0, 9),
      ]);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to ingest shadow event");
    }
  }

  async function ingestScenario(surface: "browser" | "endpoint" | "dns" | "proxy" | "gateway" | "connector", label: string) {
    const before = { entities: entities.length, unresolved: unresolvedSignals.length };
    try {
      const correlationId = `demo-${surface}-${Date.now()}`;
      if (surface === "endpoint") {
        await api.ingestShadowAIEndpoint({
          process_name: "python",
          command_line: "python app.py --provider=openai",
          destination_domain: "api.openai.com",
          destination_ip: "104.18.0.10",
          bytes_sent: 2048,
          bytes_received: 4096,
          inferred_provider: "OpenAI",
          tenant_id: "auto",
          correlation_id: correlationId,
        });
      } else if (surface === "dns") {
        await api.ingestShadowAIDNS({
          queried_domain: "claude.ai",
          resolved_ip: "104.18.30.11",
          query_count: 5,
          source_system: "corp-dns",
          correlation_id: correlationId,
        });
      } else if (surface === "proxy") {
        await api.ingestShadowAIProxy({
          request_domain: "chat.openai.com",
          full_url: "https://chat.openai.com/backend-api/conversation",
          method: "POST",
          response_code: 200,
          bytes_sent: 8192,
          bytes_received: 16384,
          app_category: "ai_chat",
          correlation_id: correlationId,
        });
      } else {
        await api.ingestShadowEvent({
          event_type: "unsanctioned_model_usage",
          payload: {
            source_surface: surface,
            provider: "OpenAI",
            domain: "chat.openai.com",
            correlation_id: correlationId,
            note: `${surface} scenario`,
          },
        });
      }

      const after = await load();
      setLastIngestSummary({
        title: `${label} ingested`,
        details: `source ${surface} · correlation ${correlationId}`,
        entitiesDelta: after.entityCount - before.entities,
        unresolvedDelta: after.unresolvedCount - before.unresolved,
        createdAt: new Date().toISOString(),
      });
      setIngestHistory((prev) => [
        {
          id: `${surface}-${Date.now()}`,
          label,
          outcome: `entities ${after.entityCount - before.entities >= 0 ? "+" : ""}${after.entityCount - before.entities}, unresolved ${after.unresolvedCount - before.unresolved >= 0 ? "+" : ""}${after.unresolvedCount - before.unresolved}`,
          createdAt: new Date().toISOString(),
        },
        ...prev.slice(0, 9),
      ]);
      toast.success(`${label} ingested`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `${label} ingest failed`);
    }
  }

  async function runAction(action: "promote" | "reject" | "link") {
    if (!selectedEntity) return;
    const key = `${selectedEntity.id}:${action}`;
    setBusyAction(key);
    try {
      if (action === "promote") {
        await api.promoteShadowAIEntity(selectedEntity.id, { force: true });
        toast.success("Entity promoted to Trust Center PROPOSED candidate.");
      }

      if (action === "reject") {
        const reason = window.prompt("Reject reason", "false_positive") || "false_positive";
        await api.rejectShadowAIEntity(selectedEntity.id, { reason });
        toast.success("Entity marked as rejected.");
      }

      if (action === "link") {
        const aiSystemId = window.prompt("Link to existing AI system id", selectedEntity.linked_ai_system_id || "");
        if (!aiSystemId) return;
        await api.linkShadowAIEntityToAISystem(selectedEntity.id, { ai_system_id: aiSystemId.trim() });
        toast.success("Entity linked to existing AI system.");
      }

      await load();
      await loadEntityDetail(selectedEntity.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusyAction("");
    }
  }

  async function generateShadowGuidance() {
    if (!selectedEntity) return;
    setGuidanceLoading(true);
    try {
      const result = await api.generateShadowEntityRemediationGuidance(selectedEntity.id, {
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
      toast.success("Shadow AI remediation guidance generated.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to generate shadow AI guidance");
    } finally {
      setGuidanceLoading(false);
    }
  }

  const kpis = useMemo(() => {
    const discovered = entities.filter((item) => item.discovery_status === "discovered").length;
    const reconciled = entities.filter((item) => item.discovery_status === "reconciled").length;
    const promoted = entities.filter((item) => item.discovery_status === "promoted").length;
    const rejected = entities.filter((item) => item.discovery_status === "rejected").length;
    const highConfidence = entities.filter((item) => item.confidence_level === "high").length;
    return { discovered, reconciled, promoted, rejected, highConfidence };
  }, [entities]);

  const surfaceCoverageRows = useMemo(() => {
    const coverageRecord = asRecord(coverage);
    const defaults = ["browser", "endpoint", "dns", "proxy", "gateway", "connector", "aiiam", "monitoring"];
    const explicit = defaults
      .map((surface) => {
        const raw = coverageRecord[surface];
        if (typeof raw === "number") return [surface, raw] as const;
        const nested = asRecord(raw);
        if (typeof nested.count === "number") return [surface, nested.count] as const;
        if (typeof nested.discovered === "number") return [surface, nested.discovered] as const;
        return [surface, 0] as const;
      })
      .filter(([, value]) => value > 0);

    if (explicit.length) return explicit;

    const inferred = new Map<string, number>();
    entities.forEach((entity) => {
      (entity.source_surfaces || []).forEach((surface) => {
        inferred.set(surface, (inferred.get(surface) || 0) + 1);
      });
    });

    return Array.from(inferred.entries()).sort((a, b) => b[1] - a[1]);
  }, [coverage, entities]);
  const surfaceOptions = useMemo(
    () =>
      ["browser", "endpoint", "dns", "proxy", "gateway", "connector", "aiiam", "monitoring"]
        .map((value) => ({ value, label: value })),
    []
  );
  const topSignalsBySurface = useMemo(() => {
    if (!selectedEntity) return [];
    const counts = new Map<string, number>();
    selectedEntity.signals.forEach((signal) => {
      counts.set(signal.source_surface, (counts.get(signal.source_surface) || 0) + 1);
    });
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [selectedEntity]);
  const confidenceReasoning = useMemo(() => {
    if (!selectedEntity) return [];
    const raw = asRecord(selectedEntity.metadata_json).confidence_reasoning;
    if (!Array.isArray(raw)) return [];
    return raw.map((item) => String(item)).filter(Boolean);
  }, [selectedEntity]);
  const runtimeProfile = useMemo(
    () => deriveAgentRuntimeProfile(selectedEntity?.metadata_json),
    [selectedEntity],
  );

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Discovery Engine"
          title="Shadow AI Discovery"
          description="Cross-surface shadow AI correlation, confidence scoring, and governance reconciliation."
          actions={
            <Button variant="outline" onClick={() => load()}>
              Refresh
            </Button>
          }
        />

        <KpiStrip
          items={[
            { label: "Entities", value: entities.length, tone: "info" },
            { label: "High Confidence", value: kpis.highConfidence, tone: "warning" },
            { label: "Promoted", value: kpis.promoted, tone: "success" },
            { label: "Unresolved Signals", value: unresolvedSignals.length, tone: "critical" },
          ]}
        />

        <TableFilters>
          <FilterLabel label="Surface">
            <FilterSelect
              value={surfaceFilter}
              onChange={setSurfaceFilter}
              options={[{ value: "", label: "All surfaces" }, ...surfaceOptions]}
            />
          </FilterLabel>
        </TableFilters>

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Discovery Status" description="Entity lifecycle posture across reconciliation workflow.">
            <SimpleTable
              columns={["Status", "Count"]}
              rows={[
                ["discovered", kpis.discovered],
                ["reconciled", kpis.reconciled],
                ["promoted", kpis.promoted],
                ["rejected", kpis.rejected],
              ]}
            />
          </PageSection>
          <PageSection title="Source Coverage" description="Which discovery surfaces are feeding the current shadow AI entity set.">
            <SimpleTable
              columns={["Surface", "Observed Entities"]}
              rows={surfaceCoverageRows.map(([surface, count]) => [surface, count])}
            />
          </PageSection>
        </div>

        <PageSection title="Shadow Entity Explorer" description="Select an entity to inspect confidence reasoning and cross-surface evidence.">
          <div className="grid gap-4 xl:grid-cols-[360px_1fr]">
            <div className="space-y-2">
              {entities.length ? (
                entities
                  .slice()
                  .sort((a, b) => b.confidence_score - a.confidence_score)
                  .map((entity) => {
                    const active = entity.id === selectedEntity?.id;
                    return (
                      <button
                        key={entity.id}
                        type="button"
                        onClick={() => setSelectedEntityId(entity.id)}
                        className={`w-full rounded-lg border px-3 py-3 text-left transition ${
                          active
                            ? "border-brand-500/50 bg-brand-500/10"
                            : "border-[#2a3348] bg-[#0f1218] hover:border-brand-500/30"
                        }`}
                      >
                        <div className="mb-1 flex items-center justify-between gap-2">
                          <p className="truncate text-sm font-semibold text-slate-100">{entity.canonical_name}</p>
                          <Badge>{entity.discovery_status}</Badge>
                        </div>
                        <p className="text-xs text-slate-400">
                          confidence {(entity.confidence_score * 100).toFixed(0)}% ({entity.confidence_level}) · risk {entity.provisional_risk_tier || "-"}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">first seen {formatDate(entity.first_seen)} · last seen {formatDate(entity.last_seen)}</p>
                      </button>
                    );
                  })
              ) : (
                <p className="text-sm text-slate-500">No shadow entities detected yet.</p>
              )}
            </div>

            <div className="space-y-4 rounded-xl border border-[#2a3348] bg-[#101524] p-4">
              {selectedEntity ? (
                <>
                  <div className="grid gap-3 md:grid-cols-4">
                    <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                      <p className="text-xs text-slate-500">Confidence</p>
                      <p className="text-xl font-semibold text-slate-100">{(selectedEntity.confidence_score * 100).toFixed(0)}%</p>
                    </div>
                    <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                      <p className="text-xs text-slate-500">Risk Tier</p>
                      <p className="text-xl font-semibold text-slate-100">{selectedEntity.provisional_risk_tier || "-"}</p>
                    </div>
                    <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                      <p className="text-xs text-slate-500">Signals</p>
                      <p className="text-xl font-semibold text-slate-100">{selectedEntity.signal_count}</p>
                    </div>
                    <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                      <p className="text-xs text-slate-500">Open Findings</p>
                      <p className="text-xl font-semibold text-slate-100">{selectedEntity.open_findings}</p>
                    </div>
                  </div>

                  <div className="grid gap-2 md:grid-cols-3">
                    <Button onClick={() => runAction("promote")} disabled={busyAction === `${selectedEntity.id}:promote`}>
                      Promote to Trust Center
                    </Button>
                    <Button variant="outline" onClick={() => runAction("link")} disabled={busyAction === `${selectedEntity.id}:link`}>
                      Link to Existing AI System
                    </Button>
                    <Button variant="destructive" onClick={() => runAction("reject")} disabled={busyAction === `${selectedEntity.id}:reject`}>
                      Reject
                    </Button>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" onClick={generateShadowGuidance} disabled={guidanceLoading}>
                      {guidanceLoading ? "Generating..." : "Generate Remediation Guidance"}
                    </Button>
                    {guidanceResult ? (
                      <Button
                        variant="outline"
                        onClick={async () => {
                          try {
                            const ticket = await api.generateAIReasoningTicketPayload(guidanceResult.trace_id, "jira");
                            await window.navigator.clipboard.writeText(ticket.description);
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
                    <PageSection
                      title="AI Remediation Guidance"
                      description="Bounded reasoning guidance for governance handoff. Deterministic enforcement remains authoritative."
                    >
                      <div className="space-y-4">
                        <div className="grid gap-3 md:grid-cols-3">
                          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                            <p className="text-xs text-slate-500">Model Route</p>
                            <p className="text-sm font-semibold text-slate-100 break-words">
                              {guidanceResult.provider} / {guidanceResult.model}
                            </p>
                          </div>
                          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                            <p className="text-xs text-slate-500">Prompt Template</p>
                            <p className="text-sm font-semibold text-slate-100 break-all">{guidanceResult.prompt_template_id}</p>
                          </div>
                          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                            <p className="text-xs text-slate-500">Trace ID</p>
                            <p className="text-sm font-semibold text-slate-100 break-all">{guidanceResult.trace_id}</p>
                          </div>
                        </div>
                        <div className="rounded-xl border border-[#2a3348] bg-[#0f1218] p-4">
                          <p className="text-sm font-semibold text-slate-100">
                            {guidanceResult.remediation_guidance?.summary || "No summary returned"}
                          </p>
                          <p className="mt-1 text-sm text-slate-300">
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
                    </PageSection>
                  ) : null}

                  <SimpleTable
                    columns={["Field", "Value"]}
                    rows={[
                      ["Canonical Name", selectedEntity.canonical_name],
                      ["Status", selectedEntity.discovery_status],
                      ["Approval Status", selectedEntity.approved_status || "unknown"],
                      ["Vendor", selectedEntity.vendor || "-"],
                      ["Deployment Type", selectedEntity.deployment_type || "-"],
                      ["AI Type", selectedEntity.ai_type || "-"],
                      ["Risk Score", formatFixed(selectedEntity.risk_score, 2, "0.00")],
                      ["Usage Count", selectedEntity.usage_count],
                      ["Unique Users", selectedEntity.unique_users],
                      ["Endpoints", selectedEntity.endpoints_count],
                      ["Linked AI System", selectedEntity.linked_ai_system_id || "-"],
                      ["Sources", Array.isArray(selectedEntity.source_surfaces) ? selectedEntity.source_surfaces.join(", ") || "-" : "-"],
                    ]}
                  />

                  {runtimeProfile ? (
                    <PageSection
                      title={`${runtimeProfile.agentName} Runtime Evidence`}
                      description="Endpoint-bound self-registration shows the observed runtime and supported routes. Authorization remains unclaimed until Hawk records a signed pre-action decision."
                    >
                      <div className="space-y-4">
                        <div className="grid gap-3 md:grid-cols-4">
                          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                            <p className="text-xs text-slate-500">Runtime</p>
                            <p className="mt-1 text-sm font-semibold text-slate-100">{runtimeProfile.runtimeProvider}</p>
                          </div>
                          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                            <p className="text-xs text-slate-500">Model</p>
                            <p className="mt-1 text-sm font-semibold text-slate-100">
                              {runtimeProfile.modelProvider} / {runtimeProfile.modelName}
                            </p>
                          </div>
                          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                            <p className="text-xs text-slate-500">Active Gmail Route</p>
                            <p className="mt-1 text-sm font-semibold text-slate-100">{runtimeProfile.activeTransport}</p>
                          </div>
                          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                            <p className="text-xs text-slate-500">Control Evidence</p>
                            <Badge className="mt-1">{runtimeProfile.controlState}</Badge>
                          </div>
                        </div>

                        <SimpleTable
                          columns={["Capability", "Transport", "Destination", "Status", "Evidence"]}
                          rows={runtimeProfile.integrations.map((integration) => [
                            integration.capability,
                            integration.transport,
                            integration.destinationDomain,
                            integration.active ? "active" : "supported",
                            integration.evidenceBasis,
                          ])}
                          emptyLabel="No integration routes reported"
                        />

                        <SimpleTable
                          columns={["Evidence Field", "Observed Value"]}
                          rows={[
                            ["Agent ID", runtimeProfile.agentId],
                            ["Registration basis", runtimeProfile.evidenceBasis],
                            ["Requested mode", runtimeProfile.requestedMode],
                            ["Pre-action surfaces", runtimeProfile.preActionSurfaces.join(", ") || "none reported"],
                            ["Models", runtimeProfile.models.join(", ") || runtimeProfile.modelName],
                            ["Tools", runtimeProfile.tools.join(", ") || "none reported"],
                            ["Actions", runtimeProfile.actions.join(", ") || "none reported"],
                            ["Privileges", runtimeProfile.privileges.join(", ") || "none reported"],
                            ["Listening ports", runtimeProfile.listeningPorts.join(", ") || "none reported"],
                          ]}
                        />
                      </div>
                    </PageSection>
                  ) : null}

                  <PageSection title="Why This Entity Exists" description="Confidence reasoning and source agreement from identity correlation.">
                    {confidenceReasoning.length ? (
                      <ul className="space-y-1 text-sm text-slate-300">
                        {confidenceReasoning.map((line) => (
                          <li key={line} className="rounded border border-[#2a3348] bg-[#0f1218] px-2 py-1">
                            {line}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-slate-500">No explicit confidence reasoning available for this entity.</p>
                    )}
                  </PageSection>

                  <PageSection title="Cross-Surface Breakdown" description="How many signals came from each discovery surface.">
                    <SimpleTable
                      columns={["Surface", "Signals"]}
                      rows={topSignalsBySurface.map(([surface, count]) => [surface, count])}
                    />
                  </PageSection>

                  <div className="grid gap-4 xl:grid-cols-2">
                    <PageSection title="Usage by Users" description="Users linked to this AI app through browser/runtime activity.">
                      <SimpleTable
                        columns={["User", "Interactions", "Sensitive", "Last Seen"]}
                        rows={(selectedEntity.usage_by_user || []).map((row) => [
                          row.user_id,
                          row.count,
                          row.high_sensitivity_events || 0,
                          formatDate(row.last_seen),
                        ])}
                      />
                    </PageSection>
                    <PageSection title="Usage by Endpoints" description="Endpoints where this AI app was observed.">
                      <SimpleTable
                        columns={["Endpoint", "Interactions", "Sensitive", "Last Seen"]}
                        rows={(selectedEntity.usage_by_endpoint || []).map((row) => [
                          row.endpoint_id,
                          row.count,
                          row.high_sensitivity_events || 0,
                          formatDate(row.last_seen),
                        ])}
                      />
                    </PageSection>
                  </div>

                  <DiscoveryEvidenceSummary entity={selectedEntity} />
                  <PageSection title="Contributing Signals" description="Source attribution, observation time and evidence type. Imported network observations do not establish AI interaction.">
                    <SimpleTable
                      columns={["Source", "Domain", "Provider", "Model", "Tool", "User", "Observed", "Evidence type"]}
                      rows={selectedEntity.signals.map((signal) => [
                        signal.source_surface,
                        signal.domain || "-",
                        signal.provider || "-",
                        signal.model_name || "-",
                        signal.tool_name || "-",
                        signal.user_id || signal.agent_id || "-",
                        formatDate(signal.created_at),
                        String(signal.raw_fingerprint?.observation_state || "unknown"),
                      ])}
                    />
                  </PageSection>

                  <PageSection title="Linked Governance & Evidence" description="Direct links to investigation objects, not raw JSON blobs.">
                    <SimpleTable
                      columns={["Object", "Reference"]}
                      rows={[
                        ...selectedEntity.linked_findings.map((findingId) => [
                          "Finding",
                          <Link key={`finding-${findingId}`} className="text-brand-300 underline underline-offset-2" href={`/discovery/findings/${findingId}`}>
                            {findingId}
                          </Link>,
                        ]),
                        ...selectedEntity.evidence_node_ids.map((evidenceId) => ["Evidence Node", evidenceId]),
                      ]}
                    />
                  </PageSection>
                </>
              ) : (
                <p className="text-sm text-slate-500">Select a shadow entity to inspect confidence, risk, and source attribution.</p>
              )}
            </div>
          </div>
        </PageSection>

        <details className="rounded-xl border border-[#2a3348] bg-[#0b1018]">
          <summary className="cursor-pointer list-none px-4 py-3 text-sm font-semibold text-slate-200">Technical tools <span className="ml-2 text-xs font-normal text-slate-500">Ingest and simulate discovery signals</span></summary>
          <div className="border-t border-[#2a3348] p-4">
            <PageSection title="Ingest Shadow Event" description="Manual ingestion entry point for demo or triage workflows.">
              <form className="flex gap-2" onSubmit={ingest}>
                <Input value={eventType} onChange={(e) => setEventType(e.target.value)} />
                <Button type="submit">Ingest Shadow Event</Button>
              </form>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button variant="outline" onClick={() => ingestScenario("browser", "Browser unknown AI usage")}>Simulate Browser Signal</Button>
                <Button variant="outline" onClick={() => ingestScenario("endpoint", "Endpoint model API usage")}>Simulate Endpoint Signal</Button>
                <Button variant="outline" onClick={() => ingestScenario("dns", "DNS AI domain lookup")}>Simulate DNS Signal</Button>
                <Button variant="outline" onClick={() => ingestScenario("proxy", "Proxy model traffic")}>Simulate Proxy Signal</Button>
                <Button variant="outline" onClick={() => ingestScenario("gateway", "Gateway unsanctioned request")}>Simulate Gateway Signal</Button>
                <Button variant="outline" onClick={() => ingestScenario("connector", "Connector discovery signal")}>Simulate Connector Signal</Button>
              </div>

              {lastIngestSummary ? (
                <div className="mt-4 grid gap-2 rounded-lg border border-[#2a3348] bg-[#0f1218] p-3 md:grid-cols-4">
                  <div><p className="text-xs text-slate-500">Latest Ingest</p><p className="text-sm font-semibold text-slate-100">{lastIngestSummary.title}</p></div>
                  <div><p className="text-xs text-slate-500">Outcome</p><p className="text-sm text-slate-100">entities {lastIngestSummary.entitiesDelta >= 0 ? "+" : ""}{lastIngestSummary.entitiesDelta}</p></div>
                  <div><p className="text-xs text-slate-500">Unresolved Delta</p><p className="text-sm text-slate-100">{lastIngestSummary.unresolvedDelta >= 0 ? "+" : ""}{lastIngestSummary.unresolvedDelta}</p></div>
                  <div><p className="text-xs text-slate-500">At</p><p className="text-sm text-slate-100">{formatDate(lastIngestSummary.createdAt)}</p></div>
                </div>
              ) : null}
            </PageSection>
          </div>
        </details>

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Unresolved Signals" description="Low-confidence clusters waiting for reconciliation.">
            <SimpleTable
              columns={["Surface", "Event", "Domain", "Provider", "User/Agent", "Created"]}
              rows={unresolvedSignals.map((signal) => [
                signal.source_surface,
                signal.source_event_id,
                signal.domain || "-",
                signal.provider || "-",
                signal.user_id || signal.agent_id || "-",
                formatDate(signal.created_at),
              ])}
            />
          </PageSection>

          <PageSection title="Provider Catalog" description="Known AI provider/domain catalog used in shadow correlation logic.">
            <SimpleTable
              columns={["Domain/Host", "Provider", "Category", "Source Hint"]}
              rows={providerCatalog.slice(0, 20).map((entry, idx) => [
                String(entry.domain || entry.hostname || entry.pattern || `entry-${idx}`),
                String(entry.provider || entry.vendor || "-"),
                String(entry.category || entry.type || "-"),
                String(entry.source_hint || entry.confidence_hint || "-"),
              ])}
            />
          </PageSection>
        </div>

        <PageSection title="Ingest Activity Feed" description="Most recent ingestion actions and observed outcomes.">
          <SimpleTable
            columns={["Scenario", "Outcome", "Timestamp"]}
            rows={ingestHistory.map((item) => [item.label, item.outcome, formatDate(item.createdAt)])}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
