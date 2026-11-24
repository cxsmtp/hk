"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { formatDateTime, severityBadgeClass } from "@/components/runtime-intelligence/utils";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useRuntimeIntelligenceStream } from "@/hooks/use-runtime-intelligence-stream";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { AIOrchestrationResult, RuntimePattern, RuntimeStreamEvent } from "@/lib/types";

type SeveritySort = "high_to_low" | "low_to_high";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  med: 2,
  low: 1,
};

function severityRank(severity: string): number {
  return SEVERITY_RANK[String(severity || "").toLowerCase()] || 0;
}

function affectedAgents(pattern: RuntimePattern): string[] {
  return pattern.affected_entities
    .filter((entity) => String(entity.entity_type || "").toLowerCase() === "agent")
    .map((entity) => String(entity.entity_id || "").trim())
    .filter(Boolean);
}

export default function RuntimeIntelligencePatternsPage() {
  const [patterns, setPatterns] = useState<RuntimePattern[]>([]);
  const [selectedAgentFilter, setSelectedAgentFilter] = useState("all");
  const [severitySort, setSeveritySort] = useState<SeveritySort>("high_to_low");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);
  const [guidanceLoadingId, setGuidanceLoadingId] = useState("");
  const [selectedGuidancePatternId, setSelectedGuidancePatternId] = useState("");
  const [guidanceByPattern, setGuidanceByPattern] = useState<Record<string, AIOrchestrationResult>>({});

  async function load() {
    setLoading(true);
    try {
      const patternPayload = await api.runtimePatterns({ page_size: 400 });
      setPatterns(patternPayload.items || []);
      setLoadError(null);
    } catch (error) {
      setPatterns([]);
      setLoadError(error instanceof Error ? error.message : "Runtime patterns are unavailable.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
  }, []);

  const onStreamEvent = useCallback((streamEvent: RuntimeStreamEvent) => {
    const payload = streamEvent.payload || {};
    if (streamEvent.event_type !== "runtime.pattern.detected") return;
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
    setPatterns((current) => [incoming, ...current.filter((pattern) => pattern.pattern_id !== incoming.pattern_id)].slice(0, 500));
  }, []);

  useRuntimeIntelligenceStream({
    channel: "patterns",
    onEvent: onStreamEvent,
    onReconnect: () => {
      load().catch(() => undefined);
    },
    onConnectionStateChange: setStreamConnected,
  });

  const patternState = resolvePresentationState({ loading, hasData: patterns.length > 0, unavailable: Boolean(loadError) });
  const initialLoading = loading && !patterns.length;

  async function generatePatternGuidance(pattern: RuntimePattern) {
    setGuidanceLoadingId(pattern.pattern_id);
    try {
      const result = await api.generateRuntimePatternRemediationGuidance(pattern.pattern_id, {
        task_type: "control_gap_analysis",
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
      setGuidanceByPattern((current) => ({ ...current, [pattern.pattern_id]: result }));
      setSelectedGuidancePatternId(pattern.pattern_id);
      toast.success("Runtime pattern remediation guidance generated.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to generate runtime pattern guidance");
    } finally {
      setGuidanceLoadingId("");
    }
  }

  const criticalPatterns = useMemo(
    () => patterns.filter((pattern) => String(pattern.severity || "").toLowerCase() === "critical").length,
    [patterns]
  );

  const affectedAgentsCount = useMemo(() => {
    const agents = new Set<string>();
    patterns.forEach((pattern) => {
      affectedAgents(pattern).forEach((agentId) => agents.add(agentId));
    });
    return agents.size;
  }, [patterns]);

  const agentOptions = useMemo(() => {
    const counts = new Map<string, number>();
    patterns.forEach((pattern) => {
      affectedAgents(pattern).forEach((agentId) => {
        counts.set(agentId, (counts.get(agentId) || 0) + 1);
      });
    });
    return Array.from(counts.entries()).sort((left, right) => right[1] - left[1]);
  }, [patterns]);

  const filteredPatterns = useMemo(() => {
    const filtered = patterns.filter((pattern) => {
      if (selectedAgentFilter === "all") return true;
      return affectedAgents(pattern).includes(selectedAgentFilter);
    });

    return filtered.sort((left, right) => {
      const severityDelta = severityRank(right.severity) - severityRank(left.severity);
      const direction = severitySort === "high_to_low" ? 1 : -1;
      if (severityDelta !== 0) return severityDelta * direction;
      return right.frequency - left.frequency;
    });
  }, [patterns, selectedAgentFilter, severitySort]);

  const highSeverityCount = useMemo(() => {
    return filteredPatterns.filter((pattern) => severityRank(pattern.severity) >= 3).length;
  }, [filteredPatterns]);

  const topExampleTypes = useMemo(() => {
    const types = new Set<string>();
    filteredPatterns.forEach((pattern) => {
      const text = String(pattern.type || "").trim();
      if (text) types.add(text);
    });
    return Array.from(types).slice(0, 4);
  }, [filteredPatterns]);
  const selectedGuidance = selectedGuidancePatternId ? guidanceByPattern[selectedGuidancePatternId] || null : null;

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="Patterns & Anomalies"
          description="Detected behavioral risks from runtime correlation, with severity sorting and agent-based filtering."
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button variant="outline" onClick={() => load().catch(() => undefined)}>
                {streamConnected ? "Live Stream On" : "Reconnect Stream"}
              </Button>
              <Button variant="outline" onClick={() => load()}>
                Refresh
              </Button>
            </>
          }
        />

        <OperationalState
          state={patternState}
          onRetry={() => void load()}
          description={loadError ? "Runtime patterns unavailable. No anomaly count is inferred." : undefined}
        />

        <KpiStrip
          items={[
            { label: "Detected Patterns", value: loading ? "—" : patterns.length, tone: "info" },
            { label: "Critical Patterns", value: loading ? "—" : criticalPatterns, tone: criticalPatterns ? "critical" : "success" },
            { label: "High/Critical (Filtered)", value: loading ? "—" : highSeverityCount, tone: highSeverityCount ? "warning" : "success" },
            { label: "Affected Agents", value: loading ? "—" : affectedAgentsCount, tone: "info" },
          ]}
        />

        <PageSection
          title="Filters"
          description={loading ? "Loading patterns..." : "Filter by affected agent and sort by severity."}
        >
          <div className="grid gap-2 md:grid-cols-3">
            <label className="text-xs text-slate-400">
              Agent
              <select
                className="mt-1 w-full rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-sm text-slate-100"
                value={selectedAgentFilter}
                onChange={(event) => setSelectedAgentFilter(event.target.value)}
              >
                <option value="all">All agents</option>
                {agentOptions.map(([agentId, count]) => (
                  <option key={agentId} value={agentId}>
                    {`${agentId} (${count})`}
                  </option>
                ))}
              </select>
            </label>

            <label className="text-xs text-slate-400">
              Sort
              <select
                className="mt-1 w-full rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-sm text-slate-100"
                value={severitySort}
                onChange={(event) => setSeveritySort(event.target.value as SeveritySort)}
              >
                <option value="high_to_low">Severity: High to Low</option>
                <option value="low_to_high">Severity: Low to High</option>
              </select>
            </label>

            <div className="rounded-md border border-[#2a3348] bg-[#0f1218] px-3 py-2 text-xs text-slate-400">
              <p className="uppercase tracking-[0.15em] text-slate-500">Example Patterns</p>
              <p className="mt-1 text-slate-200">
                {topExampleTypes.length
                  ? topExampleTypes.join(" · ")
                  : "repeated prompt injection · abnormal tool usage · data exfil attempts"}
              </p>
            </div>
          </div>
        </PageSection>

        <PageSection title="Detected Patterns" description="Behavioral risks with severity, frequency, and affected agents.">
          <SimpleTable
            columns={["Pattern Type", "Frequency", "Severity", "Affected Agents", "Updated", "Actions"]}
            rows={filteredPatterns.map((pattern) => {
              const agents = affectedAgents(pattern);
              return [
                pattern.type,
                pattern.frequency,
                <Badge key={`${pattern.pattern_id}-severity`} className={severityBadgeClass(pattern.severity)}>
                  {pattern.severity}
                </Badge>,
                agents.length ? agents.slice(0, 3).join(" · ") : "-",
                formatDateTime(pattern.updated_at),
                <Button
                  key={`pattern-guidance-${pattern.pattern_id}`}
                  variant="outline"
                  onClick={() => generatePatternGuidance(pattern)}
                  disabled={guidanceLoadingId === pattern.pattern_id}
                >
                  {guidanceLoadingId === pattern.pattern_id ? "Generating..." : "Generate Guidance"}
                </Button>,
              ];
            })}
            emptyLabel={initialLoading ? "Loading detected patterns…" : loadError ? "Runtime patterns are unavailable." : "No detected patterns match the current filters."}
          />
        </PageSection>

        <PageSection
          title="AI Remediation Guidance"
          description="Bounded reasoning plan for selected runtime pattern. Enforcement remains deterministic."
        >
          {selectedGuidance ? (
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-3">
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-400">Model Route</p>
                  <p className="text-sm font-semibold text-slate-100 break-words">
                    {selectedGuidance.provider} / {selectedGuidance.model}
                  </p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-400">Prompt Template</p>
                  <p className="text-sm font-semibold text-slate-100 break-all">{selectedGuidance.prompt_template_id}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                  <p className="text-xs text-slate-400">Trace ID</p>
                  <p className="text-sm font-semibold text-slate-100 break-all">{selectedGuidance.trace_id}</p>
                </div>
              </div>

              <div className="rounded-xl border border-[#2a3348] bg-[#101524] p-4">
                <p className="text-sm font-semibold text-slate-100">
                  {selectedGuidance.remediation_guidance?.summary || "No summary returned"}
                </p>
                <p className="mt-1 text-sm text-slate-300">
                  {selectedGuidance.remediation_guidance?.root_cause_hypothesis || "-"}
                </p>
                <p className="mt-2 text-xs text-slate-400">
                  Priority: {selectedGuidance.remediation_guidance?.priority || "-"} · Confidence:{" "}
                  {typeof selectedGuidance.remediation_guidance?.confidence === "number"
                    ? selectedGuidance.remediation_guidance.confidence.toFixed(2)
                    : "-"}
                </p>
              </div>

              <SimpleTable
                columns={["Step", "Action", "Description", "Approval", "Frameworks"]}
                rows={(selectedGuidance.remediation_guidance?.recommended_steps || []).map((step) => [
                  step.step_order,
                  step.action_type,
                  step.description,
                  step.requires_approval ? "required" : "not_required",
                  step.linked_frameworks.join(", ") || "-",
                ])}
              />
            </div>
          ) : (
            <p className="text-sm text-slate-500">
              Generate guidance from any pattern row to view structured remediation steps with traceability.
            </p>
          )}
        </PageSection>

        <PageSection title="Anomaly Examples" description="Common anomaly categories tracked by runtime correlation.">
          <SimpleTable
            columns={["Example", "What It Indicates"]}
            rows={[
              ["repeated_prompt_injection_attempts", "Repeated hostile/unsafe prompt behavior against protected systems."],
              ["abnormal_tool_sequence", "Unexpected tool call order or unusual tool chaining behavior."],
              ["data_exfiltration_pattern", "Potential sensitive data movement to risky external targets."],
            ]}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
