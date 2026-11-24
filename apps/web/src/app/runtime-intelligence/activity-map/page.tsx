"use client";

import { useSearchParams } from "next/navigation";
import { FormEvent, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import {
  type ActivityMapEdgeDetail,
  type ActivityMapNodeDetail,
  RuntimeActivityMapGraph,
} from "@/components/runtime-intelligence/activity-map-graph";
import { RuntimeActivityMapSidePanel } from "@/components/runtime-intelligence/activity-map-side-panel";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { parseDate } from "@/components/runtime-intelligence/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useRuntimeIntelligenceStream } from "@/hooks/use-runtime-intelligence-stream";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { RuntimeChainGraph, RuntimeStreamEvent, RuntimeTimelineEvent } from "@/lib/types";

function matchesSurfaceFilter(event: RuntimeTimelineEvent, surfaceFilter: string): boolean {
  const normalized = surfaceFilter.trim().toLowerCase();
  if (!normalized) return true;
  const sourceSurface = String(event.source_surface || "").trim().toLowerCase();
  const eventType = String(event.event_type || "").trim().toLowerCase();
  const canonicalFields = [
    event.ai_surface,
    event.action_type,
    event.metadata?.ai_surface,
    event.metadata?.action_type,
    event.metadata?.operation,
  ].map((value) => String(value || "").trim().toLowerCase());
  if (normalized === "mcp_tool_call") {
    return sourceSurface.includes("mcp") || eventType.includes("mcp_tool_call") || canonicalFields.some((value) => value.includes("mcp"));
  }
  return sourceSurface === normalized || eventType === normalized || canonicalFields.some((value) => value === normalized);
}

function RuntimeIntelligenceActivityMapContent() {
  const searchParams = useSearchParams();
  const surfaceFilter = String(searchParams.get("surface") || "").trim().toLowerCase();
  const requestedChainId = String(searchParams.get("chain_id") || "").trim();
  const [events, setEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [chainIdInput, setChainIdInput] = useState(requestedChainId);
  const [loadedChainId, setLoadedChainId] = useState("");
  const [graph, setGraph] = useState<RuntimeChainGraph | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [selectedNodeDetail, setSelectedNodeDetail] = useState<ActivityMapNodeDetail | null>(null);
  const [selectedEdgeDetail, setSelectedEdgeDetail] = useState<ActivityMapEdgeDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [streamConnected, setStreamConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadBaseData = useCallback(async () => {
    setLoading(true);
    try {
      const eventPayload = await api.runtimeEvents({ page_size: 500 });
      const runtimeEvents = (eventPayload.items || []).filter((event) => matchesSurfaceFilter(event, surfaceFilter));
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
  }, [chainIdInput, surfaceFilter]);

  const refreshChainGraph = useCallback(async (chainId: string) => {
    try {
      const payload = await api.runtimeChainGraph(chainId);
      setGraph(payload);
    } catch (error) {
      setGraph(null);
      setLoadError(error instanceof Error ? error.message : "Chain graph is unavailable.");
    }
  }, []);

  useEffect(() => {
    loadBaseData().catch(() => undefined);
  }, [loadBaseData]);

  useEffect(() => {
    if (!requestedChainId || requestedChainId === loadedChainId) return;
    let cancelled = false;
    setChainIdInput(requestedChainId);
    setBusy(true);
    api.runtimeChainGraph(requestedChainId)
      .then((payload) => {
        if (cancelled) return;
        setGraph(payload);
        setLoadedChainId(requestedChainId);
        setSelectedNodeId(null);
        setSelectedEdgeId(null);
        setSelectedNodeDetail(null);
        setSelectedEdgeDetail(null);
        if (!payload.nodes.length) {
          toast.message("No chain graph nodes found for this id yet.");
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setGraph(null);
        setLoadedChainId("");
        const message = err instanceof Error ? err.message : "Unable to load chain graph";
        setLoadError(message);
        toast.error(message);
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [loadedChainId, requestedChainId]);

  useEffect(() => {
    if (!autoRefresh || streamConnected) return;
    const timer = setInterval(() => {
      loadBaseData().catch(() => undefined);
    }, 25000);
    return () => clearInterval(timer);
  }, [autoRefresh, loadBaseData, streamConnected]);

  const onStreamEvent = useCallback((streamEvent: RuntimeStreamEvent) => {
    const payload = streamEvent.payload || {};
    if (streamEvent.event_type === "runtime.activity.created") {
      const eventId = String(payload.event_id || "").trim();
      if (eventId) {
        const incoming: RuntimeTimelineEvent = {
          event_id: eventId,
          tenant_id: String(streamEvent.tenant_id || "").trim(),
          source_surface: String(payload.source_surface || "runtime").trim(),
          ai_surface: String(payload.ai_surface || "").trim() || null,
          event_type: String(payload.event_type || "runtime_event").trim(),
          action_type: String(payload.action_type || "").trim() || undefined,
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
          metadata:
            payload.metadata && typeof payload.metadata === "object" && !Array.isArray(payload.metadata)
              ? payload.metadata as Record<string, unknown>
              : {},
          risk_score: Number(payload.risk_score || 0),
          created_at: String(payload.created_at || new Date().toISOString()),
        };
        if (matchesSurfaceFilter(incoming, surfaceFilter)) {
          setEvents((current) => [incoming, ...current.filter((event) => event.event_id !== incoming.event_id)].slice(0, 600));
        }
      }
    }

    if (loadedChainId) {
      const chainId = String(payload.chain_id || "").trim();
      if (
        streamEvent.event_type === "runtime.chain.updated" && chainId && chainId === loadedChainId
      ) {
        refreshChainGraph(loadedChainId).catch(() => undefined);
      }
      if (
        streamEvent.event_type === "runtime.activity.created" && chainId && chainId === loadedChainId
      ) {
        refreshChainGraph(loadedChainId).catch(() => undefined);
      }
    }
  }, [loadedChainId, refreshChainGraph, surfaceFilter]);

  useRuntimeIntelligenceStream({
    channel: "activity",
    enabled: autoRefresh,
    onEvent: onStreamEvent,
    onReconnect: () => {
      loadBaseData().catch(() => undefined);
      if (loadedChainId) {
        refreshChainGraph(loadedChainId).catch(() => undefined);
      }
    },
    onConnectionStateChange: setStreamConnected,
  });

  useRuntimeIntelligenceStream({
    channel: "chains",
    enabled: autoRefresh,
    onEvent: onStreamEvent,
  });

  async function loadGraph(event?: FormEvent) {
    event?.preventDefault();
    const chainId = chainIdInput.trim();
    if (!chainId) {
      toast.error("Enter a chain id or correlation id to render the activity map.");
      return;
    }
    setBusy(true);
    try {
      const payload = await api.runtimeChainGraph(chainId);
      setGraph(payload);
      setLoadedChainId(chainId);
      setSelectedNodeId(null);
      setSelectedEdgeId(null);
      setSelectedNodeDetail(null);
      setSelectedEdgeDetail(null);
      if (!payload.nodes.length) {
        toast.message("No chain graph nodes found for this id yet.");
      }
    } catch (err) {
      setGraph(null);
      setLoadedChainId("");
      setSelectedNodeId(null);
      setSelectedEdgeId(null);
      setSelectedNodeDetail(null);
      setSelectedEdgeDetail(null);
      toast.error(err instanceof Error ? err.message : "Unable to load chain graph");
    } finally {
      setBusy(false);
    }
  }

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

  const chainEvents = useMemo(
    () =>
      loadedChainId
        ? events.filter((event) => String(event.chain_id || event.correlation_id || "").trim() === loadedChainId)
        : [],
    [events, loadedChainId]
  );

  const latestChainEventAt = useMemo(
    () =>
      chainEvents.reduce((latest, event) => {
        const date = parseDate(event.created_at);
        if (!date) return latest;
        if (!latest || date > latest) return date;
        return latest;
      }, null as Date | null),
    [chainEvents]
  );
  const activityMapState = resolvePresentationState({ loading, hasData: events.length > 0 || Boolean(graph), unavailable: Boolean(loadError) });
  const initialLoading = loading && !events.length && !graph;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="Activity chain"
          description={surfaceFilter
            ? `Activity chain filtered to ${surfaceFilter.replaceAll("_", " ")} runtime events.`
            : "Follow an activity chain with a chain or correlation reference across user, agent, tool, and AI-system activity."}
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button variant="outline" onClick={() => setAutoRefresh((value) => !value)}>
                {autoRefresh ? "Live Stream On" : "Live Stream Off"}
              </Button>
              <Button variant="outline" onClick={() => loadBaseData()}>
                Refresh
              </Button>
            </>
          }
        />

        <OperationalState
          state={activityMapState}
          onRetry={() => void loadBaseData()}
          description={loadError ? "Runtime activity unavailable. No chain or graph count is inferred." : undefined}
        />

        <PageSection title="Load an activity chain" description="Enter a chain or correlation reference to explore connected activity.">
          <form className="space-y-3" onSubmit={loadGraph}>
            <div className="flex flex-wrap gap-2">
              <Input
                value={chainIdInput}
                onChange={(inputEvent) => setChainIdInput(inputEvent.target.value)}
                placeholder="Enter a chain or correlation reference"
              />
              <Button type="submit" disabled={busy}>
                {busy ? "Loading..." : "Load Activity Map"}
              </Button>
            </div>
            {chainSuggestions.length ? (
              <div className="flex flex-wrap gap-2">
                {chainSuggestions.map((suggestion) => (
                  <button
                    key={suggestion}
                    type="button"
                    className="rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-1 text-xs text-slate-300 hover:border-brand-500/40 hover:text-brand-200"
                    onClick={() => setChainIdInput(suggestion)}
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            ) : null}
          </form>
          <details className="mt-3 rounded-md border border-[#2a3348] bg-[#0b1220] px-3 py-2 text-xs text-slate-400">
            <summary className="cursor-pointer font-medium text-slate-300">Technical details</summary>
            <p className="mt-2">Runtime event fields chain_id and correlation_id identify references. The graph uses React Flow and loads large chains progressively.</p>
          </details>
        </PageSection>

        <KpiStrip
          items={[
            { label: "Loaded Chain", value: loading ? "—" : loadedChainId || "-", tone: loadedChainId ? "info" : "default" },
            { label: "Chain Nodes", value: loading ? "—" : graph?.nodes.length || 0, tone: "info" },
            { label: "Chain Edges", value: loading ? "—" : graph?.edges.length || 0, tone: "info" },
            {
              label: "Latest Event In Chain",
              value: loading ? "—" : latestChainEventAt ? latestChainEventAt.toLocaleTimeString() : "-",
              hint: loading ? "Loading runtime events" : latestChainEventAt ? latestChainEventAt.toLocaleDateString() : "",
              tone: latestChainEventAt ? "success" : "default",
            },
            {
              label: "Chain Risk",
              value: loading ? "—" : graph ? Number(graph.risk_score || 0).toFixed(2) : "Unavailable",
              hint: "Aggregate runtime chain risk score",
              tone:
                Number(graph?.risk_score || 0) >= 0.67
                  ? "critical"
                  : Number(graph?.risk_score || 0) >= 0.34
                    ? "warning"
                    : "success",
            },
          ]}
        />

        <div className="grid gap-4 xl:grid-cols-[1.7fr_1fr]">
          <PageSection
            title="Graph"
            description="Explore connected activity, decisions, and supporting evidence as the activity chain loads."
          >
            {initialLoading ? (
              <p className="text-sm text-slate-400">Loading chain activity and graph evidence…</p>
            ) : (
              <RuntimeActivityMapGraph
                graph={graph}
                chainEvents={chainEvents}
                selectedNodeId={selectedNodeId}
                selectedEdgeId={selectedEdgeId}
                onSelectedNodeIdChange={setSelectedNodeId}
                onSelectedEdgeIdChange={setSelectedEdgeId}
                onNodeDetailChange={setSelectedNodeDetail}
                onEdgeDetailChange={setSelectedEdgeDetail}
              />
            )}
          </PageSection>
          <PageSection
            title="Inspector"
            description="Click a node for risk/policies/recent actions, or click an edge for action detail, decision, and evidence links."
          >
            {initialLoading ? <p className="text-sm text-slate-400">Loading chain inspector…</p> : <RuntimeActivityMapSidePanel nodeDetail={selectedNodeDetail} edgeDetail={selectedEdgeDetail} />}
          </PageSection>
        </div>
      </div>
    </AppShell>
  );
}

export default function RuntimeIntelligenceActivityMapPage() {
  return (
    <Suspense fallback={<div className="p-6 text-sm text-slate-400">Loading activity map…</div>}>
      <RuntimeIntelligenceActivityMapContent />
    </Suspense>
  );
}
