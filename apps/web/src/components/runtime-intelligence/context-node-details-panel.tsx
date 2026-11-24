"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

import { DecisionExplanationModal } from "@/components/decision-explanation";
import { decisionBadgeClass, decisionLabel, formatDateTime } from "@/components/runtime-intelligence/utils";
import { Badge } from "@/components/ui/badge";
import type { RuntimeChainGraph, RuntimeTimelineEvent } from "@/lib/types";

function toNumber(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(1, parsed));
}

function normalizeType(value: string): string {
  const text = String(value || "").trim().toLowerCase();
  if (text === "resource") return "data";
  return text || "unknown";
}

function relationLabel(value: string): string {
  return String(value || "related")
    .replace(/^context\./, "")
    .replaceAll("_", " ")
    .replaceAll(".", " -> ");
}

function nodeMatchesEvent(nodeType: string, entityId: string, event: RuntimeTimelineEvent): boolean {
  if (!entityId) return false;
  if (nodeType === "action") return event.event_id === entityId;
  if (nodeType === "agent") return String(event.agent_id || "") === entityId;
  if (nodeType === "user") return String(event.user_id || "") === entityId;
  if (nodeType === "tool") return String(event.tool_name || "") === entityId || String(event.tool_category || "") === entityId;
  if (nodeType === "ai_system") return String(event.ai_system_id || "") === entityId;
  if (nodeType === "data") return String(event.api_endpoint || "") === entityId;
  return false;
}

function riskLabel(score: number): string {
  if (score >= 0.67) return "High";
  if (score >= 0.34) return "Medium";
  return "Low";
}

export function RuntimeContextNodeDetailsPanel({
  graph,
  events,
  selectedNodeId,
  loadedContextId,
}: {
  graph: RuntimeChainGraph | null;
  events: RuntimeTimelineEvent[];
  selectedNodeId: string | null;
  loadedContextId: string;
}) {
  const [modalEvidenceId, setModalEvidenceId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  function openDecisionExplanation(evidenceId: string) {
    setModalEvidenceId(evidenceId);
    setModalOpen(true);
  }

  const detail = useMemo(() => {
    if (!graph || !selectedNodeId) return null;

    const node = graph.nodes.find((item) => item.id === selectedNodeId);
    if (!node) return null;

    const type = normalizeType(node.type);
    const entityId = String(node.entity_id || node.id).replace(/^action:/, "");
    const contextId = String(node.metadata?.context_id || loadedContextId || "").trim() || "unassigned";

    const nodeById = new Map(graph.nodes.map((item) => [item.id, item]));
    const neighborRows = graph.edges
      .filter((edge) => edge.from_node === node.id || edge.to_node === node.id)
      .map((edge) => {
        const isSource = edge.from_node === node.id;
        const otherNode = nodeById.get(isSource ? edge.to_node : edge.from_node);
        return {
          direction: isSource ? "outgoing" : "incoming",
          relation: relationLabel(edge.relation_type),
          nodeType: normalizeType(String(otherNode?.type || "unknown")),
          entityId: String(otherNode?.entity_id || otherNode?.id || "unknown"),
        };
      });

    const linkedEntities = Array.from(
      new Map(
        neighborRows.map((row) => [`${row.nodeType}:${row.entityId}:${row.relation}:${row.direction}`, row])
      ).values()
    ).slice(0, 24);

    const relatedEvents = events
      .filter((event) => nodeMatchesEvent(type, entityId, event))
      .sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime());

    const explicitRisk = toNumber(node.metadata?.risk_score);
    const eventRisk = relatedEvents.length ? Math.max(...relatedEvents.map((event) => toNumber(event.risk_score))) : 0;
    const riskScore = Math.max(explicitRisk, eventRisk);

    const violations = relatedEvents
      .filter((event) => {
        const decision = String(event.decision || "").toLowerCase();
        if (["block", "deny", "denied", "warn", "redact", "hold_for_approval", "require_approval", "require_justification"].includes(decision)) {
          return true;
        }
        return Boolean(String(event.reason_code || "").trim());
      })
      .slice(0, 15);

    return {
      node,
      type,
      entityId,
      contextId,
      linkedEntities,
      riskScore,
      violations,
      relatedEvents,
    };
  }, [events, graph, loadedContextId, selectedNodeId]);

  if (!detail) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-10 text-center text-sm text-slate-400">
        Click a graph node to inspect linked entities, risk, and violations.
      </div>
    );
  }

  return (
    <div className="space-y-4 rounded-lg border border-[#2a3348] bg-[#101524] p-4">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Node</p>
        <p className="mt-1 text-lg font-semibold text-slate-100">{detail.entityId}</p>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span>{`type: ${detail.type}`}</span>
          <span>{`context: ${detail.contextId}`}</span>
          <span>{`events: ${detail.relatedEvents.length}`}</span>
        </div>
      </div>

      <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
        <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
          <span>Risk Score</span>
          <span>{detail.riskScore.toFixed(2)}</span>
        </div>
        <div className="h-2 rounded bg-[#1b2231]">
          <div
            className={`h-2 rounded transition-all ${
              detail.riskScore >= 0.67 ? "bg-rose-500" : detail.riskScore >= 0.34 ? "bg-amber-500" : "bg-emerald-500"
            }`}
            style={{ width: `${Math.round(detail.riskScore * 100)}%` }}
          />
        </div>
        <p className="mt-2 text-xs text-slate-500">{`Risk level: ${riskLabel(detail.riskScore)}`}</p>
      </div>

      <div>
        <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Linked Entities</p>
        <div className="max-h-[220px] space-y-2 overflow-auto pr-1">
          {detail.linkedEntities.length ? (
            detail.linkedEntities.map((entity) => (
              <div key={`${entity.nodeType}:${entity.entityId}:${entity.relation}:${entity.direction}`} className="rounded border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-xs text-slate-300">
                <p className="font-semibold text-slate-100">{`${entity.nodeType}:${entity.entityId}`}</p>
                <p className="text-slate-400">{`${entity.direction} · ${entity.relation}`}</p>
              </div>
            ))
          ) : (
            <p className="text-xs text-slate-500">No linked entities found for this node.</p>
          )}
        </div>
      </div>

      <div>
        <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Violations</p>
        <div className="max-h-[280px] space-y-2 overflow-auto pr-1">
          {detail.violations.length ? (
            detail.violations.map((event) => (
              <div key={event.event_id} className="rounded border border-[#2a3348] bg-[#0f1218] p-2">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <Badge className={decisionBadgeClass(event.decision)}>{decisionLabel(event.decision)}</Badge>
                  <span className="text-[11px] text-slate-500">{formatDateTime(event.created_at)}</span>
                </div>
                <p className="text-xs text-slate-200">{event.event_type}</p>
                {event.reason_code ? <p className="text-[11px] text-slate-400">{`reason: ${event.reason_code}`}</p> : null}
                {event.evidence_node_ids.length ? (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {event.evidence_node_ids.slice(0, 3).map((evidenceId) => (
                      <span key={`${event.event_id}:${evidenceId}`} className="inline-flex items-center gap-1">
                        <Link
                          href={`/auditor?evidence_id=${encodeURIComponent(evidenceId)}`}
                          className="text-[11px] text-brand-200 underline-offset-2 hover:underline"
                        >
                          {`evidence ${evidenceId.slice(0, 8)}...`}
                        </Link>
                        <button
                          type="button"
                          className="text-[11px] text-slate-300 underline-offset-2 hover:text-brand-200 hover:underline"
                          onClick={() => openDecisionExplanation(evidenceId)}
                        >
                          explain
                        </button>
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            ))
          ) : (
            <p className="text-xs text-slate-500">No violations observed for this node in current context events.</p>
          )}
        </div>
      </div>
      <DecisionExplanationModal
        open={modalOpen}
        evidenceId={modalEvidenceId}
        onOpenChange={(open) => {
          setModalOpen(open);
          if (!open) setModalEvidenceId(null);
        }}
      />
    </div>
  );
}
