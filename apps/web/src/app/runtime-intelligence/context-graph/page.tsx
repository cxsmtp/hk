"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { RuntimeContextGraphView } from "@/components/runtime-intelligence/context-graph-view";
import { RuntimeContextNodeDetailsPanel } from "@/components/runtime-intelligence/context-node-details-panel";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { formatDateTime } from "@/components/runtime-intelligence/utils";
import { SimpleTable } from "@/components/simple-table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useRuntimeIntelligenceStream } from "@/hooks/use-runtime-intelligence-stream";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { RuntimeChainGraph, RuntimeStreamEvent, RuntimeTimelineEvent } from "@/lib/types";

export default function RuntimeIntelligenceContextGraphPage() {
  const [contextIdInput, setContextIdInput] = useState("");
  const [loadedContextId, setLoadedContextId] = useState("");
  const [graph, setGraph] = useState<RuntimeChainGraph | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [events, setEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const [streamConnected, setStreamConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const payload = await api.runtimeEvents({ page_size: 400 });
      setEvents(payload.items || []);
      setLoadError(null);
    } catch (error) {
      setEvents([]);
      setLoadError(error instanceof Error ? error.message : "Runtime activity is unavailable.");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadContextGraphById = useCallback(async (contextId: string) => {
    try {
      const payload = await api.runtimeContextGraph(contextId);
      setGraph(payload);
      setLoadedContextId(contextId);
      setSelectedNodeId(payload.nodes[0]?.id || null);
      setLoadError(null);
      return payload;
    } catch (error) {
      setGraph(null);
      setLoadedContextId("");
      setSelectedNodeId(null);
      setLoadError(error instanceof Error ? error.message : "Context graph is unavailable.");
      throw error;
    }
  }, []);

  useEffect(() => {
    loadEvents().catch(() => undefined);
  }, [loadEvents]);

  const contextSuggestions = useMemo(
    () =>
      Array.from(
        new Set(
          events
            .map((event) => String(event.context_id || "").trim())
            .filter(Boolean)
        )
      ).slice(0, 8),
    [events]
  );

  async function loadGraph(event?: FormEvent) {
    event?.preventDefault();
    const contextId = contextIdInput.trim();
    if (!contextId) {
      toast.error("Enter a context id.");
      return;
    }

    setBusy(true);
    try {
      const payload = await loadContextGraphById(contextId);
      if (!payload.nodes.length) {
        toast.message("Context graph loaded, but no nodes are currently linked.");
      }
    } catch (err) {
      setGraph(null);
      setLoadedContextId("");
      setSelectedNodeId(null);
      setLoadError(err instanceof Error ? err.message : "Context graph is unavailable.");
      toast.error(err instanceof Error ? err.message : "Unable to load context graph");
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
      setEvents((current) => [incoming, ...current.filter((event) => event.event_id !== incoming.event_id)].slice(0, 500));
      if (loadedContextId && incoming.context_id === loadedContextId) {
        loadContextGraphById(loadedContextId).catch(() => undefined);
      }
      return;
    }

    if (streamEvent.event_type === "runtime.chain.updated" && loadedContextId) {
      const contextId = String(payload.context_id || "").trim();
      if (contextId && contextId === loadedContextId) {
        loadContextGraphById(loadedContextId).catch(() => undefined);
      }
    }
  }, [loadContextGraphById, loadedContextId]);

  useRuntimeIntelligenceStream({
    channel: "chains",
    onEvent: onStreamEvent,
    onReconnect: () => {
      loadEvents().catch(() => undefined);
      if (loadedContextId) {
        loadContextGraphById(loadedContextId).catch(() => undefined);
      }
    },
    onConnectionStateChange: setStreamConnected,
  });

  useRuntimeIntelligenceStream({
    channel: "activity",
    onEvent: onStreamEvent,
  });

  const relatedEvents = useMemo(
    () =>
      loadedContextId
        ? events.filter((event) => String(event.context_id || "").trim() === loadedContextId)
        : [],
    [events, loadedContextId]
  );

  const highRiskNodeCount = useMemo(() => {
    if (!graph) return 0;
    return graph.nodes.filter((node) => Number(node.metadata?.risk_score || 0) >= 0.67).length;
  }, [graph]);

  const contextClusterCount = useMemo(() => {
    if (!graph) return 0;
    const set = new Set<string>();
    graph.nodes.forEach((node) => {
      const contextId = String(node.metadata?.context_id || loadedContextId || "").trim() || "unassigned";
      set.add(contextId);
    });
    return set.size;
  }, [graph, loadedContextId]);
  const contextGraphState = resolvePresentationState({ loading, hasData: events.length > 0 || Boolean(graph), unavailable: Boolean(loadError) });
  const initialLoading = loading && !events.length && !graph;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="Context Graph"
          description="Relationship graph for user, agent, tool, AI system, and data entities clustered by context."
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button variant="outline" onClick={() => loadEvents().catch(() => undefined)}>
                {streamConnected ? "Live Stream On" : "Reconnect Stream"}
              </Button>
              <Button variant="outline" onClick={() => setGraph(null)}>
                Clear Graph
              </Button>
            </>
          }
        />

        <OperationalState
          state={contextGraphState}
          onRetry={() => void loadEvents()}
          description={loadError ? "Context graph source unavailable. No relationship count is inferred." : undefined}
        />

        <PageSection title="Context Query" description="Load one context id to visualize all entity relationships and risk links.">
          <form className="space-y-3" onSubmit={loadGraph}>
            <div className="flex flex-wrap gap-2">
              <Input
                value={contextIdInput}
                onChange={(inputEvent) => setContextIdInput(inputEvent.target.value)}
                placeholder="Enter context_id"
              />
              <Button type="submit" disabled={busy}>
                {busy ? "Loading..." : "Load Context Graph"}
              </Button>
            </div>
            {contextSuggestions.length ? (
              <div className="flex flex-wrap gap-2">
                {contextSuggestions.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    className="rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-1 text-xs text-slate-300 hover:border-brand-500/40 hover:text-brand-200"
                    onClick={() => setContextIdInput(suggestion)}
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            ) : null}
          </form>
        </PageSection>

        <KpiStrip
          items={[
            { label: "Loaded Context", value: loading ? "—" : loadedContextId || "-", tone: loadedContextId ? "info" : "default" },
            { label: "Context Clusters", value: loading ? "—" : contextClusterCount, tone: "info" },
            { label: "Nodes", value: loading ? "—" : graph?.nodes.length || 0, tone: "info" },
            { label: "Edges", value: loading ? "—" : graph?.edges.length || 0, tone: "info" },
            { label: "High-Risk Nodes", value: loading ? "—" : highRiskNodeCount, tone: highRiskNodeCount ? "critical" : "success" },
          ]}
        />

        <div className="grid gap-4 xl:grid-cols-[1.7fr_1fr]">
          <PageSection title="Graph View" description="Clustered by context_id with high-risk nodes highlighted for quick triage.">
            {initialLoading ? <p className="text-sm text-slate-400">Loading context graph evidence…</p> : <RuntimeContextGraphView
              graph={graph}
              events={relatedEvents}
              loadedContextId={loadedContextId}
              selectedNodeId={selectedNodeId}
              onSelectedNodeIdChange={setSelectedNodeId}
            />}
          </PageSection>

          <PageSection title="Node Details" description="Linked entities, risk score, and violations for the selected node.">
            {initialLoading ? <p className="text-sm text-slate-400">Loading linked entities…</p> : <RuntimeContextNodeDetailsPanel
              graph={graph}
              events={relatedEvents}
              selectedNodeId={selectedNodeId}
              loadedContextId={loadedContextId}
            />}
          </PageSection>
        </div>

        <PageSection
          title="Linked Runtime Events"
          description="Events linked to the loaded context for incident explanation and audit handoff."
        >
          <SimpleTable
            columns={["Time", "Source", "Event", "Decision", "Correlation", "Evidence"]}
            rows={relatedEvents.map((event) => [
              formatDateTime(event.created_at),
              event.source_surface,
              event.event_type,
              event.decision,
              event.correlation_id || event.event_id,
              event.evidence_node_ids.length,
            ])}
            emptyLabel={initialLoading ? "Loading linked runtime events…" : loadError ? "Linked runtime events are unavailable." : "No linked runtime events for this context."}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
