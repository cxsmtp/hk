"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { AgentFlowFilterPanel } from "@/components/runtime-intelligence/agent-flow-filter-panel";
import { AgentFlowStep, AgentFlowVertical } from "@/components/runtime-intelligence/agent-flow-vertical";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { parseDate } from "@/components/runtime-intelligence/utils";
import { Button } from "@/components/ui/button";
import { useRuntimeIntelligenceStream } from "@/hooks/use-runtime-intelligence-stream";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { RuntimeChainGraph, RuntimeStreamEvent, RuntimeTimelineEvent } from "@/lib/types";

const ENTITY_ORDER = ["user", "agent", "tool", "ai_system", "resource", "action"];

function decisionTone(value: string): AgentFlowStep["decisionTone"] {
  const decision = String(value || "").trim().toLowerCase();
  if (decision === "allow" || decision === "approved") return "allow";
  if (decision === "block" || decision === "deny" || decision === "denied") return "block";
  if (["warn", "redact", "require_justification", "hold_for_approval", "require_approval"].includes(decision)) return "warn";
  return "unknown";
}

function asNumber(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(1, parsed));
}

function normalizeEventType(value: string): string {
  const text = String(value || "runtime_action").trim();
  if (!text) return "runtime_action";
  return text
    .split("_")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function buildFlowSteps(graph: RuntimeChainGraph | null, chainEvents: RuntimeTimelineEvent[]): AgentFlowStep[] {
  if (!graph) return [];
  const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
  const eventsById = new Map(chainEvents.map((event) => [event.event_id, event]));

  const incomingEntities = new Map<string, string[]>();
  const parentActionByNodeId = new Map<string, string>();
  graph.edges.forEach((edge) => {
    const target = nodesById.get(edge.to_node);
    if (!target || target.type !== "action") return;
    if (edge.relation_type === "context.parent_action") {
      const parentNode = nodesById.get(edge.from_node);
      const resolvedParentEventId =
        String(edge.parent_action_id || "").trim() ||
        String(parentNode?.entity_id || "").trim() ||
        String(edge.from_node || "").replace(/^action:/, "").trim();
      if (resolvedParentEventId) parentActionByNodeId.set(target.id, resolvedParentEventId);
      return;
    }
    const bucket = incomingEntities.get(target.id) || [];
    bucket.push(edge.from_node);
    incomingEntities.set(target.id, bucket);
  });

  const steps = graph.nodes
    .filter((node) => node.type === "action")
    .map((node) => {
      const metadata = (node.metadata || {}) as Record<string, unknown>;
      const eventId = String(node.entity_id || node.id).replace(/^action:/, "");
      const event = eventsById.get(eventId);
      const decision =
        String(event?.decision || metadata.decision || metadata.final_decision || "unknown").trim().toLowerCase() || "unknown";

      const participantNodes = Array.from(new Set(incomingEntities.get(node.id) || []))
        .map((participantNodeId) => nodesById.get(participantNodeId))
        .filter((participant): participant is NonNullable<typeof participant> => Boolean(participant))
        .filter((participant) => participant.type !== "action")
        .sort((a, b) => ENTITY_ORDER.indexOf(a.type) - ENTITY_ORDER.indexOf(b.type));

      const participants = participantNodes.map((participant) => ({
        nodeType: participant.type,
        entityId: String(participant.entity_id || participant.id),
      }));

      const eventEvidence = Array.isArray(event?.evidence_node_ids) ? event?.evidence_node_ids : [];
      const metadataEvidence = Array.isArray(metadata.evidence_node_ids)
        ? metadata.evidence_node_ids.map((item) => String(item)).filter(Boolean)
        : [];
      const evidenceNodeIds = Array.from(new Set([...eventEvidence, ...metadataEvidence]));

      const agentIds = Array.from(
        new Set(
          [
            ...participants.filter((part) => part.nodeType === "agent").map((part) => part.entityId),
            String(event?.agent_id || "").trim(),
          ].filter(Boolean)
        )
      );

      return {
        id: node.id,
        eventId,
        action: normalizeEventType(String(event?.event_type || metadata.event_type || metadata.action_type || "runtime_action")),
        decision,
        decisionTone: decisionTone(decision),
        timestamp:
          String(event?.created_at || metadata.created_at || node.created_at || "").trim() || null,
        sourceSurface: String(event?.source_surface || metadata.source_surface || "runtime").trim() || "runtime",
        riskScore: asNumber(event?.risk_score ?? metadata.risk_score ?? 0),
        participants,
        agentIds,
        parentActionId: parentActionByNodeId.get(node.id) || null,
        evidenceNodeIds,
      } satisfies AgentFlowStep;
    });

  if (!steps.length) return [];

  const stepsByEventId = new Map(steps.map((step) => [step.eventId, step]));
  const childrenByParent = new Map<string, AgentFlowStep[]>();
  steps.forEach((step) => {
    if (!step.parentActionId) return;
    const bucket = childrenByParent.get(step.parentActionId) || [];
    bucket.push(step);
    childrenByParent.set(step.parentActionId, bucket);
  });

  const byTimeAsc = (left: AgentFlowStep, right: AgentFlowStep) =>
    (parseDate(left.timestamp)?.getTime() || 0) - (parseDate(right.timestamp)?.getTime() || 0);

  const ordered: AgentFlowStep[] = [];
  const visited = new Set<string>();
  const visit = (step: AgentFlowStep) => {
    if (visited.has(step.id)) return;
    visited.add(step.id);
    ordered.push(step);
    const children = (childrenByParent.get(step.eventId) || []).sort(byTimeAsc);
    children.forEach((child) => visit(child));
  };

  const roots = steps
    .filter((step) => !step.parentActionId || !stepsByEventId.has(step.parentActionId))
    .sort(byTimeAsc);
  roots.forEach((root) => visit(root));
  steps.sort(byTimeAsc).forEach((step) => visit(step));
  return ordered;
}

export default function RuntimeIntelligenceAgentFlowsPage() {
  const [events, setEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [chainIdInput, setChainIdInput] = useState("");
  const [loadedChainId, setLoadedChainId] = useState("");
  const [graph, setGraph] = useState<RuntimeChainGraph | null>(null);
  const [chainEvents, setChainEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [agentFilter, setAgentFilter] = useState("all");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [timeFilter, setTimeFilter] = useState("all");
  const [busy, setBusy] = useState(false);
  const [streamConnected, setStreamConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadBaseData = useCallback(async () => {
    setLoading(true);
    try {
      const eventPayload = await api.runtimeEvents({ page_size: 500 });
      const runtimeEvents = eventPayload.items || [];
      setEvents(runtimeEvents);
      if (!chainIdInput.trim()) {
        const candidate = runtimeEvents.find((event) => String(event.chain_id || event.correlation_id || "").trim());
        if (candidate) {
          setChainIdInput(String(candidate.chain_id || candidate.correlation_id || ""));
        }
      }
      setLoadError(null);
    } catch (error) {
      setEvents([]);
      setLoadError(error instanceof Error ? error.message : "Runtime activity is unavailable.");
    } finally {
      setLoading(false);
    }
  }, [chainIdInput]);

  const loadChainById = useCallback(async (chainId: string) => {
    try {
      const [chainPayload, chainEventPayload] = await Promise.all([
        api.runtimeChainGraph(chainId),
        api.runtimeEvents({ chain_id: chainId, page_size: 500 }),
      ]);
      setGraph(chainPayload);
      setChainEvents(chainEventPayload.items || []);
      setLoadedChainId(chainId);
      setLoadError(null);
    } catch (error) {
      setGraph(null);
      setChainEvents([]);
      setLoadedChainId("");
      setLoadError(error instanceof Error ? error.message : "Agent flow is unavailable.");
      throw error;
    }
  }, []);

  useEffect(() => {
    loadBaseData().catch(() => undefined);
  }, [loadBaseData]);

  async function loadChain() {
    const chainId = chainIdInput.trim();
    if (!chainId) return;
    setBusy(true);
    try {
      await loadChainById(chainId);
      setSelectedStepId(null);
      setAgentFilter("all");
      setDecisionFilter("all");
      setTimeFilter("all");
    } catch (error) {
      setGraph(null);
      setChainEvents([]);
      setLoadedChainId("");
      setSelectedStepId(null);
      setLoadError(error instanceof Error ? error.message : "Agent flow is unavailable.");
    } finally {
      setBusy(false);
    }
  }

  const onStreamEvent = useCallback((streamEvent: RuntimeStreamEvent) => {
    const payload = streamEvent.payload || {};
    if (streamEvent.event_type === "runtime.activity.created") {
      const eventId = String(payload.event_id || "").trim();
      if (!eventId) return;
      const incoming: RuntimeTimelineEvent = {
        event_id: eventId,
        tenant_id: String(streamEvent.tenant_id || "").trim(),
        source_surface: String(payload.source_surface || "runtime").trim(),
        event_type: String(payload.event_type || "runtime_event").trim(),
        ai_system_id: String(payload.ai_system_id || "").trim() || null,
        user_id: String(payload.user_id || "").trim() || null,
        agent_id: String(payload.agent_id || "").trim() || null,
        decision: String(payload.decision || "unknown").trim().toLowerCase(),
        reason_code: String(payload.reason_code || "").trim() || null,
        evidence_node_ids: Array.isArray(payload.evidence_node_ids)
          ? payload.evidence_node_ids.map((item) => String(item)).filter(Boolean)
          : [],
        correlation_id: String(payload.correlation_id || "").trim() || null,
        chain_id: String(payload.chain_id || "").trim() || null,
        context_id: String(payload.context_id || "").trim() || null,
        tool_name: String(payload.tool_name || "").trim() || null,
        tool_category: String(payload.tool_category || "").trim() || null,
        api_endpoint: String(payload.api_endpoint || "").trim() || null,
        risk_score: Number(payload.risk_score || 0),
        created_at: String(payload.created_at || new Date().toISOString()),
      };
      setEvents((current) => [incoming, ...current.filter((event) => event.event_id !== incoming.event_id)].slice(0, 600));
      if (loadedChainId && incoming.chain_id === loadedChainId) {
        setChainEvents((current) => [incoming, ...current.filter((event) => event.event_id !== incoming.event_id)].slice(0, 500));
      }
      return;
    }

    if (streamEvent.event_type === "runtime.chain.updated" && loadedChainId) {
      const chainId = String(payload.chain_id || "").trim();
      if (chainId && chainId === loadedChainId) {
        loadChainById(loadedChainId).catch(() => undefined);
      }
    }
  }, [loadChainById, loadedChainId]);

  useRuntimeIntelligenceStream({
    channel: "activity",
    onEvent: onStreamEvent,
    onReconnect: () => {
      loadBaseData().catch(() => undefined);
      if (loadedChainId) {
        loadChainById(loadedChainId).catch(() => undefined);
      }
    },
    onConnectionStateChange: setStreamConnected,
  });

  useRuntimeIntelligenceStream({
    channel: "chains",
    onEvent: onStreamEvent,
    onReconnect: () => {
      if (loadedChainId) {
        loadChainById(loadedChainId).catch(() => undefined);
      }
    },
  });

  const chainSuggestions = useMemo(
    () =>
      Array.from(
        new Set(
          events
            .map((event) => String(event.chain_id || event.correlation_id || "").trim())
            .filter(Boolean)
        )
      ).slice(0, 8),
    [events]
  );

  const allSteps = useMemo(() => buildFlowSteps(graph, chainEvents), [graph, chainEvents]);

  const agentOptions = useMemo(() => {
    const counts = new Map<string, { label: string; count: number }>();
    allSteps.forEach((step) => {
      step.agentIds.forEach((agentId) => {
        const current = counts.get(agentId);
        if (!current) {
          counts.set(agentId, { label: agentId, count: 1 });
          return;
        }
        current.count += 1;
      });
    });
    return Array.from(counts.entries())
      .map(([id, data]) => ({ id, label: data.label, count: data.count }))
      .sort((left, right) => right.count - left.count);
  }, [allSteps]);

  const filteredSteps = useMemo(() => {
    const now = Date.now();
    const timeWindowMs =
      timeFilter === "15m"
        ? 15 * 60 * 1000
        : timeFilter === "1h"
          ? 60 * 60 * 1000
          : timeFilter === "6h"
            ? 6 * 60 * 60 * 1000
            : timeFilter === "24h"
              ? 24 * 60 * 60 * 1000
              : timeFilter === "7d"
                ? 7 * 24 * 60 * 60 * 1000
                : null;
    return allSteps.filter((step) => {
      if (agentFilter !== "all" && !step.agentIds.includes(agentFilter)) return false;
      if (decisionFilter !== "all" && step.decisionTone !== decisionFilter) return false;
      if (timeWindowMs !== null) {
        const stepAt = parseDate(step.timestamp)?.getTime();
        if (!stepAt) return false;
        if (stepAt < now - timeWindowMs) return false;
      }
      return true;
    });
  }, [allSteps, agentFilter, decisionFilter, timeFilter]);

  useEffect(() => {
    if (!selectedStepId) return;
    if (!filteredSteps.some((step) => step.id === selectedStepId)) {
      setSelectedStepId(null);
    }
  }, [filteredSteps, selectedStepId]);

  const blockedCount = useMemo(
    () => filteredSteps.filter((step) => step.decisionTone === "block").length,
    [filteredSteps]
  );

  const warnedCount = useMemo(
    () => filteredSteps.filter((step) => step.decisionTone === "warn").length,
    [filteredSteps]
  );
  const agentFlowState = resolvePresentationState({ loading, hasData: events.length > 0 || Boolean(graph), unavailable: Boolean(loadError) });
  const initialLoading = loading && !events.length && !graph && !chainEvents.length;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="Agent Flows"
          description="Step-by-step vertical execution view for agent chains with decision and time-based filtering."
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button variant="outline" onClick={() => loadBaseData()}>
                {streamConnected ? "Live Stream On" : "Reconnect Stream"}
              </Button>
            </>
          }
        />

        <OperationalState
          state={agentFlowState}
          onRetry={() => void loadBaseData()}
          description={loadError ? "Agent flow source unavailable. No chain or step count is inferred." : undefined}
        />

        <KpiStrip
          items={[
            { label: "Loaded Chain", value: loading ? "—" : loadedChainId || "-", tone: loadedChainId ? "info" : "default" },
            { label: "Visible Steps", value: loading ? "—" : filteredSteps.length, tone: "info" },
            { label: "Blocked Decisions", value: loading ? "—" : blockedCount, tone: blockedCount ? "critical" : "success" },
            { label: "Warn/Hold Decisions", value: loading ? "—" : warnedCount, tone: warnedCount ? "warning" : "success" },
            {
              label: "Chain Risk",
              value: loading ? "—" : graph ? Number(graph.risk_score || 0).toFixed(2) : "Unavailable",
              hint: "Aggregate risk from runtime chain",
              tone:
                Number(graph?.risk_score || 0) >= 0.67
                  ? "critical"
                  : Number(graph?.risk_score || 0) >= 0.34
                    ? "warning"
                    : "success",
            },
          ]}
        />

        {initialLoading ? (
          <p className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-sm text-slate-400">Loading agent flow data…</p>
        ) : (
          <PageSection title="Flow Filters" description="Load a chain and filter by agent, time window, or decision outcome.">
            <AgentFlowFilterPanel
              chainIdInput={chainIdInput}
              onChainIdInputChange={setChainIdInput}
              onLoadChain={loadChain}
              busy={busy}
              chainSuggestions={chainSuggestions}
              agentOptions={agentOptions}
              agentFilter={agentFilter}
              onAgentFilterChange={setAgentFilter}
              decisionFilter={decisionFilter}
              onDecisionFilterChange={setDecisionFilter}
              timeFilter={timeFilter}
              onTimeFilterChange={setTimeFilter}
              totalSteps={allSteps.length}
              visibleSteps={filteredSteps.length}
              onResetFilters={() => {
                setAgentFilter("all");
                setDecisionFilter("all");
                setTimeFilter("all");
              }}
            />
          </PageSection>
        )}

        <PageSection title="Execution Flow" description="Vertical step sequence: action, decision, timestamp, and evidence links.">
          {initialLoading ? <p className="text-sm text-slate-400">Loading execution steps…</p> : <AgentFlowVertical
            steps={filteredSteps}
            selectedStepId={selectedStepId}
            onSelectedStepIdChange={setSelectedStepId}
          />}
        </PageSection>
      </div>
    </AppShell>
  );
}
