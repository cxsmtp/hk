"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { LiveActivityFeed } from "@/components/runtime-intelligence/live-activity-feed";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { RuntimeOverviewMetricCards } from "@/components/runtime-intelligence/overview-metric-cards";
import { RiskDistributionChart } from "@/components/runtime-intelligence/risk-distribution-chart";
import { TopViolationsTable } from "@/components/runtime-intelligence/top-violations-table";
import { formatDateTime, parseDate } from "@/components/runtime-intelligence/utils";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { Button } from "@/components/ui/button";
import { useRuntimeIntelligenceStream } from "@/hooks/use-runtime-intelligence-stream";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { RuntimePattern, RuntimeStreamEvent, RuntimeTimelineEvent, RuntimeTrace } from "@/lib/types";

function isBlockedDecision(decision: string): boolean {
  const normalized = String(decision || "").toLowerCase();
  return normalized === "block" || normalized === "deny" || normalized === "denied";
}

function safeRisk(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(1, parsed));
}

export default function RuntimeIntelligenceOverviewPage() {
  const [events, setEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [patterns, setPatterns] = useState<RuntimePattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);
  const [selectedEventId, setSelectedEventId] = useState<string>("");
  const [selectedTrace, setSelectedTrace] = useState<RuntimeTrace | null>(null);
  const [traceLoading, setTraceLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [eventPayload, patternPayload] = await Promise.all([
        api.runtimeActivities({ page_size: 500 }),
        api.runtimePatterns({ page_size: 250 }),
      ]);
      setEvents(eventPayload.items || []);
      setPatterns(patternPayload.items || []);
      setLastUpdated(new Date());
      setLoadError(null);
    } catch (error) {
      setEvents([]);
      setPatterns([]);
      setLoadError(error instanceof Error ? error.message : "Runtime activity is unavailable.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  useEffect(() => {
    if (!autoRefresh || streamConnected) return;
    const timer = setInterval(() => {
      load().catch(() => undefined);
    }, 15000);
    return () => clearInterval(timer);
  }, [autoRefresh, load, streamConnected]);

  const onStreamEvent = useCallback((streamEvent: RuntimeStreamEvent) => {
    const payload = streamEvent.payload || {};
    if (streamEvent.event_type === "runtime.activity.created") {
      const eventId = String(payload.event_id || "").trim();
      if (!eventId) return;
      const incoming: RuntimeTimelineEvent = {
        event_id: eventId,
        tenant_id: String(streamEvent.tenant_id || "").trim(),
        source_surface: String(payload.source_surface || "runtime").trim(),
        ai_surface: String(payload.ai_surface || payload.source_surface || "runtime").trim(),
        event_type: String(payload.event_type || "runtime_event").trim(),
        ai_system_id: String(payload.ai_system_id || "").trim() || null,
        application: String(payload.application || payload.app_id || payload.tool_name || "").trim() || null,
        user_id: String(payload.user_id || "").trim() || null,
        machine_id: String(payload.machine_id || payload.endpoint_id || "").trim() || null,
        browser_type: String(payload.browser_type || payload.browser || "").trim() || null,
        agent_id: String(payload.agent_id || "").trim() || null,
        model: String(payload.model || payload.model_name || payload.provider || "").trim() || null,
        decision: String(payload.decision || "unknown").trim().toLowerCase(),
        control_triggered: Array.isArray(payload.control_triggered)
          ? payload.control_triggered.map((item) => String(item)).filter(Boolean)
          : [],
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
        risk_score: safeRisk(payload.risk_score),
        created_at: String(payload.created_at || new Date().toISOString()),
      };
      setEvents((current) => [incoming, ...current.filter((item) => item.event_id !== incoming.event_id)].slice(0, 600));
      setLastUpdated(new Date());
      return;
    }

    if (streamEvent.event_type === "runtime.pattern.detected") {
      const patternId = String(payload.pattern_id || "").trim();
      if (!patternId) return;
      const incoming: RuntimePattern = {
        pattern_id: patternId,
        type: String(payload.type || "runtime_pattern").trim(),
        frequency: Number(payload.frequency || 1),
        severity: String(payload.severity || "low").trim(),
        affected_entities: Array.isArray(payload.affected_entities)
          ? payload.affected_entities
            .map((item) => {
              const row = item as Record<string, unknown>;
              const entityType = String(row.type || row.entity_type || "").trim();
              const entityId = String(row.id || row.entity_id || "").trim();
              if (!entityType || !entityId) return null;
              return { entity_type: entityType, entity_id: entityId };
            })
            .filter((item): item is { entity_type: string; entity_id: string } => Boolean(item))
          : [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      setPatterns((current) => [incoming, ...current.filter((item) => item.pattern_id !== incoming.pattern_id)].slice(0, 400));
      setLastUpdated(new Date());
    }
  }, []);

  useRuntimeIntelligenceStream({
    channel: "overview",
    enabled: autoRefresh,
    onEvent: onStreamEvent,
    onReconnect: () => {
      load().catch(() => undefined);
    },
    onConnectionStateChange: setStreamConnected,
  });

  const sortedEvents = useMemo(
    () =>
      [...events]
        .sort((a, b) => (parseDate(b.created_at)?.getTime() || 0) - (parseDate(a.created_at)?.getTime() || 0)),
    [events]
  );

  const selectedEvent = useMemo(
    () => sortedEvents.find((item) => item.event_id === selectedEventId) || sortedEvents[0] || null,
    [selectedEventId, sortedEvents]
  );

  const fetchTrace = useCallback(async (eventId: string) => {
    if (!eventId) return;
    setTraceLoading(true);
    try {
      const payload = await api.runtimeTrace(eventId);
      setSelectedTrace(payload);
      setSelectedEventId(eventId);
    } catch (err) {
      setSelectedTrace(null);
      toast.error(err instanceof Error ? err.message : "Failed to load runtime trace");
    } finally {
      setTraceLoading(false);
    }
  }, []);

  const blockUser = useCallback(async (userId: string) => {
    if (!userId) return;
    const reason = "Blocked from Runtime Intelligence activity panel.";
    const busyKey = `block-user:${userId}`;
    setActionBusy(busyKey);
    try {
      await api.blockUser(userId, { reason });
      toast.success(`User blocked: ${userId}`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to block user");
    } finally {
      setActionBusy("");
    }
  }, [load]);

  const enforceUserPolicy = useCallback(async (userId: string) => {
    if (!userId) return;
    const reason = "Policy enforcement applied from Runtime Intelligence activity panel.";
    const busyKey = `enforce-user:${userId}`;
    setActionBusy(busyKey);
    try {
      await api.enforceUserPolicy(userId, { reason });
      toast.success(`Policy enforced for user: ${userId}`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to enforce policy");
    } finally {
      setActionBusy("");
    }
  }, [load]);

  const disableAgent = useCallback(async (agentId: string) => {
    if (!agentId) return;
    const busyKey = `disable-agent:${agentId}`;
    setActionBusy(busyKey);
    try {
      await api.disableAgent(agentId);
      toast.success(`Agent disabled: ${agentId}`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to disable agent");
    } finally {
      setActionBusy("");
    }
  }, [load]);

  const revokeToken = useCallback(async (event: RuntimeTimelineEvent) => {
    const tokenId = window.prompt("Capability token id to revoke");
    if (!tokenId) return;
    const normalized = tokenId.trim();
    if (!normalized) return;
    const busyKey = `revoke-token:${event.event_id}`;
    setActionBusy(busyKey);
    try {
      await api.revokeAgentToken(normalized);
      toast.success(`Token revoked: ${normalized}`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to revoke token");
    } finally {
      setActionBusy("");
    }
  }, [load]);

  const totalActions = events.length;
  const blockedActions = useMemo(
    () => events.filter((event) => isBlockedDecision(event.decision)).length,
    [events]
  );

  const activeAgents = useMemo(
    () =>
      new Set(
        events
          .map((event) => String(event.agent_id || "").trim())
          .filter(Boolean)
      ).size,
    [events]
  );

  const aggregateRiskScore = useMemo(() => {
    if (!events.length) return 0;
    const avg = events.reduce((acc, event) => acc + safeRisk(event.risk_score), 0) / events.length;
    return avg;
  }, [events]);

  const initialLoading = loading && !events.length && !patterns.length;
  const topMetricCards = useMemo(
    () => [
      { label: "Total Actions", value: initialLoading ? "—" : totalActions, tone: "info" as const },
      { label: "Blocked Actions", value: initialLoading ? "—" : blockedActions, tone: blockedActions ? ("critical" as const) : ("success" as const) },
      { label: "Active Agents", value: initialLoading ? "—" : activeAgents, tone: activeAgents ? ("info" as const) : ("default" as const) },
      {
        label: "Risk Score (Aggregate)",
        value: initialLoading ? "—" : aggregateRiskScore.toFixed(2),
        hint: initialLoading ? "Waiting for runtime evidence" : `${Math.round(aggregateRiskScore * 100)}% weighted risk` ,
        tone: aggregateRiskScore >= 0.67 ? ("critical" as const) : aggregateRiskScore >= 0.34 ? ("warning" as const) : ("success" as const),
      },
    ],
    [activeAgents, aggregateRiskScore, blockedActions, initialLoading, totalActions]
  );

  const runtimeState = resolvePresentationState({ loading, hasData: events.length > 0 || patterns.length > 0, unavailable: Boolean(loadError) });

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="Overview"
          description="Executive and operational summary of AI behavior across runtime actions."
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button variant="outline" onClick={() => setAutoRefresh((value) => !value)}>
                {autoRefresh ? "Live Stream On" : "Live Stream Off"}
              </Button>
              <Button variant="outline" onClick={() => load()}>
                Refresh
              </Button>
            </>
          }
        />

        <OperationalState
          state={runtimeState}
          onRetry={() => void load()}
          description={loadError ? "Runtime sources unavailable. No healthy or complete posture is inferred." : undefined}
        />

        <RuntimeOverviewMetricCards items={topMetricCards} />

        <div className="grid gap-4 xl:grid-cols-[1.7fr_1fr]">
          <div className="space-y-4">
            <PageSection title="Risk Distribution" description="Action risk breakdown across Low / Medium / High tiers.">
              {initialLoading ? <p className="text-sm text-slate-400">Loading risk distribution…</p> : <RiskDistributionChart events={events} />}
            </PageSection>

            <PageSection title="Top Violations" description="Most frequent policy-related violation patterns from runtime correlation.">
              {initialLoading ? <p className="text-sm text-slate-400">Loading top violations…</p> : <TopViolationsTable patterns={patterns} />}
            </PageSection>
          </div>

          <PageSection
            title="Live Activity Feed"
            description={
              loading
                ? "Refreshing runtime stream..."
                : `${streamConnected ? "SSE connected" : "SSE reconnecting"} · Last updated ${formatDateTime(lastUpdated?.toISOString())}`
            }
          >
            <LiveActivityFeed
              events={sortedEvents.slice(0, 60)}
              loading={loading}
              busyAction={actionBusy}
              onSelectEvent={(event) => fetchTrace(event.event_id)}
              onBlockUser={(userId) => blockUser(userId)}
              onEnforcePolicy={(userId) => enforceUserPolicy(userId)}
              onDisableAgent={(agentId) => disableAgent(agentId)}
              onRevokeToken={(event) => revokeToken(event)}
            />
          </PageSection>
        </div>

        <PageSection title="Trace Explorer" description="End-to-end ordered event chain for selected runtime event.">
          {traceLoading ? (
            <p className="text-sm text-slate-400">Loading trace...</p>
          ) : selectedTrace ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 text-xs text-slate-400">
                <span>Key: {selectedTrace.trace_key}</span>
                <span>Type: {selectedTrace.trace_key_type}</span>
                <span>Events: {selectedTrace.event_count}</span>
              </div>
              <LiveActivityFeed
                events={selectedTrace.events}
                loading={false}
                busyAction={actionBusy}
                onSelectEvent={(event) => setSelectedEventId(event.event_id)}
                onBlockUser={(userId) => blockUser(userId)}
                onEnforcePolicy={(userId) => enforceUserPolicy(userId)}
                onDisableAgent={(agentId) => disableAgent(agentId)}
                onRevokeToken={(event) => revokeToken(event)}
              />
            </div>
          ) : (
            <p className="text-sm text-slate-500">
              Select an event from the live feed to load the full trace chain.
            </p>
          )}
          {selectedEvent ? (
            <p className="mt-2 text-xs text-slate-500">
              Selected event: {selectedEvent.event_id}
            </p>
          ) : null}
        </PageSection>
      </div>
    </AppShell>
  );
}
