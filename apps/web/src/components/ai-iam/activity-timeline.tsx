"use client";

import { useMemo, useState } from "react";

import { DecisionExplanationSidePanel } from "@/components/decision-explanation";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { RuntimeTimelineEvent } from "@/lib/types";

function formatClock(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "--:--";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

function normalizeDecision(value: string): string {
  return String(value || "unknown").trim().toLowerCase();
}

function decisionTone(value: string): "allow" | "warn" | "block" | "unknown" {
  const decision = normalizeDecision(value);
  if (decision === "allow" || decision === "approved") return "allow";
  if (decision === "block" || decision === "deny" || decision === "denied") return "block";
  if (["warn", "redact", "require_justification", "hold_for_approval", "require_approval"].includes(decision)) return "warn";
  return "unknown";
}

function decisionBadgeClass(value: string): string {
  const tone = decisionTone(value);
  if (tone === "allow") return "border-emerald-500/40 bg-emerald-500/20 text-emerald-200";
  if (tone === "warn") return "border-amber-500/40 bg-amber-500/20 text-amber-200";
  if (tone === "block") return "border-rose-500/40 bg-rose-500/20 text-rose-200";
  return "";
}

function dotClass(value: string): string {
  const tone = decisionTone(value);
  if (tone === "allow") return "bg-emerald-400";
  if (tone === "warn") return "bg-amber-400";
  if (tone === "block") return "bg-rose-400";
  return "bg-slate-500";
}

function prettyDecision(value: string): string {
  const decision = normalizeDecision(value);
  if (!decision) return "Unknown";
  return decision.split("_").map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`).join(" ");
}

function prettyEventType(value: string): string {
  const text = String(value || "runtime_event");
  return text.split("_").map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`).join(" ");
}

export function ActivityTimeline({
  events,
  agents,
  defaultAgentId,
}: {
  events: RuntimeTimelineEvent[];
  agents: Array<{ id: string; name: string }>;
  defaultAgentId?: string;
}) {
  const [agentFilter, setAgentFilter] = useState(defaultAgentId || "all");
  const [decisionFilter, setDecisionFilter] = useState("all");
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);

  const decisionOptions = useMemo(
    () => Array.from(new Set(events.map((event) => normalizeDecision(event.decision)).filter(Boolean))).sort(),
    [events]
  );

  const filteredEvents = useMemo(() => {
    return events
      .filter((event) => {
        if (agentFilter !== "all" && String(event.agent_id || "") !== agentFilter) return false;
        if (decisionFilter !== "all" && normalizeDecision(event.decision) !== decisionFilter) return false;
        return true;
      })
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      .slice(0, 80);
  }, [events, agentFilter, decisionFilter]);

  return (
    <div className="space-y-3">
      <div className="grid gap-2 md:grid-cols-[minmax(180px,220px)_minmax(180px,220px)]">
        <label className="text-xs text-slate-400">
          Agent
          <select
            className="mt-1 w-full rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-sm text-slate-100"
            value={agentFilter}
            onChange={(event) => setAgentFilter(event.target.value)}
          >
            <option value="all">All agents</option>
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.name}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-slate-400">
          Decision
          <select
            className="mt-1 w-full rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-sm text-slate-100"
            value={decisionFilter}
            onChange={(event) => setDecisionFilter(event.target.value)}
          >
            <option value="all">All decisions</option>
            {decisionOptions.map((decision) => (
              <option key={decision} value={decision}>
                {prettyDecision(decision)}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid gap-3 xl:grid-cols-[1fr_360px]">
        <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
          <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
            <span>Timeline</span>
            <span>{`${filteredEvents.length} events`}</span>
          </div>
          <div className="max-h-[360px] overflow-auto pr-1">
            <div className="space-y-3">
              {filteredEvents.length ? (
                filteredEvents.map((event) => (
                  <div key={event.event_id} className="grid grid-cols-[16px_1fr] gap-2">
                    <div className="relative flex justify-center">
                      <span className={`mt-1 h-3 w-3 rounded-full ${dotClass(event.decision)}`} />
                      <span className="absolute left-1/2 top-4 h-full w-px -translate-x-1/2 bg-[#26324a]" />
                    </div>
                    <div className="rounded-md border border-[#243049] bg-[#121827] px-3 py-2">
                      <p className="text-sm text-slate-100">
                        <span className="text-slate-400">{`[${formatClock(event.created_at)}] `}</span>
                        {`${prettyEventType(event.event_type)} -> ${prettyDecision(event.decision)}`}
                      </p>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                        <Badge className={decisionBadgeClass(event.decision)}>{prettyDecision(event.decision)}</Badge>
                        <span>{`agent: ${event.agent_id || "-"}`}</span>
                        <span>{`surface: ${event.source_surface}`}</span>
                        {event.reason_code ? <span>{`reason: ${event.reason_code}`}</span> : null}
                      </div>
                      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                        {event.evidence_node_ids.slice(0, 3).map((evidenceId) => (
                          <button
                            key={`${event.event_id}:${evidenceId}`}
                            type="button"
                            className="text-brand-200 underline-offset-2 hover:underline"
                            onClick={() => setSelectedEvidenceId(evidenceId)}
                          >
                            {`Evidence ${evidenceId.slice(0, 8)}...`}
                          </button>
                        ))}
                        {decisionTone(event.decision) === "block" && event.evidence_node_ids.length ? (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setSelectedEvidenceId(event.evidence_node_ids[0])}
                          >
                            Explain Decision
                          </Button>
                        ) : null}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-sm text-slate-500">No runtime events match the current filters.</p>
              )}
            </div>
          </div>
        </div>

        <DecisionExplanationSidePanel
          open={Boolean(selectedEvidenceId)}
          evidenceId={selectedEvidenceId}
          title="Decision Explainer"
          onClear={() => setSelectedEvidenceId(null)}
          emptyState="Select a blocked event and click Explain Decision."
        />
      </div>
    </div>
  );
}
