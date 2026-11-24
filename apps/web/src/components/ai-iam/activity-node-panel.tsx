"use client";

import { useMemo } from "react";

import { Badge } from "@/components/ui/badge";
import type { RuntimeChainGraph, RuntimeContextNode } from "@/lib/types";

type DecisionTone = "allow" | "warn" | "block" | "unknown";

function normalizeDecision(value: unknown): DecisionTone {
  const text = String(value || "").toLowerCase();
  if (text === "allow" || text === "approved") return "allow";
  if (text === "block" || text === "deny" || text === "denied") return "block";
  if (["warn", "redact", "require_justification", "hold_for_approval", "require_approval"].includes(text)) return "warn";
  return "unknown";
}

function decisionBadgeClass(tone: DecisionTone): string {
  if (tone === "allow") return "border-emerald-500/40 bg-emerald-500/20 text-emerald-200";
  if (tone === "warn") return "border-amber-500/40 bg-amber-500/20 text-amber-200";
  if (tone === "block") return "border-rose-500/40 bg-rose-500/20 text-rose-200";
  return "";
}

function safeDate(value: string | null | undefined): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function parseScore(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const num = Number(value);
  if (!Number.isFinite(num)) return null;
  return Math.max(0, Math.min(1, num));
}

type RecentAction = {
  id: string;
  decision: DecisionTone;
  eventType: string;
  sourceSurface: string;
  riskScore: number | null;
  createdAt?: string | null;
};

function extractAction(node: RuntimeContextNode): RecentAction {
  return {
    id: node.entity_id || node.id,
    decision: normalizeDecision(node.metadata?.decision),
    eventType: String(node.metadata?.event_type || "runtime_event"),
    sourceSurface: String(node.metadata?.source_surface || "unknown"),
    riskScore: parseScore(node.metadata?.risk_score),
    createdAt: node.created_at || String(node.metadata?.created_at || ""),
  };
}

export function ActivityNodePanel({
  graph,
  selectedNodeId,
}: {
  graph: RuntimeChainGraph | null;
  selectedNodeId: string | null;
}) {
  const details = useMemo(() => {
    if (!graph || !selectedNodeId) return null;
    const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
    const selected = nodeById.get(selectedNodeId);
    if (!selected) return null;

    const connectedEdges = graph.edges.filter(
      (edge) => edge.from_node === selectedNodeId || edge.to_node === selectedNodeId
    );

    const actionNodeIds = new Set<string>();
    if (selected.type === "action") actionNodeIds.add(selected.id);
    connectedEdges.forEach((edge) => {
      const neighborId = edge.from_node === selectedNodeId ? edge.to_node : edge.from_node;
      const neighbor = nodeById.get(neighborId);
      if (neighbor?.type === "action") actionNodeIds.add(neighbor.id);
      if (selected.type === "action") {
        const maybeAction = nodeById.get(neighborId);
        if (maybeAction?.type === "action") actionNodeIds.add(neighborId);
      }
    });

    const recentActions = Array.from(actionNodeIds)
      .map((id) => nodeById.get(id))
      .filter(Boolean)
      .map((node) => extractAction(node as RuntimeContextNode))
      .sort((a, b) => new Date(String(b.createdAt || "")).getTime() - new Date(String(a.createdAt || "")).getTime())
      .slice(0, 8);

    const policySet = new Set<string>();
    const addPolicy = (value: unknown) => {
      const text = String(value || "").trim();
      if (text) policySet.add(text);
    };
    addPolicy(selected.metadata?.policy_id);
    addPolicy(selected.metadata?.policy_version_id);
    addPolicy(selected.metadata?.governance_version);
    recentActions.forEach((action) => {
      addPolicy(action.eventType);
      addPolicy(action.sourceSurface);
    });

    const selectedRisk = parseScore(selected.metadata?.risk_score);
    const aggregateRisk = selectedRisk ?? (recentActions.length
      ? Math.max(...recentActions.map((item) => Number(item.riskScore || 0)))
      : graph.risk_score);

    return {
      selected,
      connectedEdges,
      recentActions,
      policiesApplied: Array.from(policySet).slice(0, 10),
      aggregateRisk: Math.max(0, Math.min(1, Number(aggregateRisk || 0))),
    };
  }, [graph, selectedNodeId]);

  if (!graph) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-sm text-slate-400">
        Node details appear here after loading a chain and selecting a node.
      </div>
    );
  }

  if (!details) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-sm text-slate-400">
        Select a node in the map to inspect risk, policy context, and recent actions.
      </div>
    );
  }

  return (
    <div className="space-y-4 rounded-lg border border-[#2a3348] bg-[#101524] p-4">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Selected Node</p>
        <p className="mt-1 text-lg font-semibold text-slate-100">{details.selected.entity_id || details.selected.id}</p>
        <p className="text-xs text-slate-400">{`Type: ${details.selected.type}`}</p>
      </div>

      <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
        <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
          <span>Risk score</span>
          <span>{details.aggregateRisk.toFixed(2)}</span>
        </div>
        <div className="h-2 rounded bg-[#1b2231]">
          <div
            className="h-2 rounded bg-brand-500 transition-all"
            style={{ width: `${Math.round(details.aggregateRisk * 100)}%` }}
          />
        </div>
      </div>

      <div>
        <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Policies Applied</p>
        <div className="flex flex-wrap gap-2">
          {details.policiesApplied.length ? details.policiesApplied.map((item) => <Badge key={item}>{item}</Badge>) : (
            <span className="text-xs text-slate-500">No policy metadata attached to this node yet.</span>
          )}
        </div>
      </div>

      <div>
        <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Recent Actions</p>
        <div className="space-y-2">
          {details.recentActions.length ? details.recentActions.map((action) => (
            <div key={action.id} className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-2">
              <div className="mb-1 flex items-center justify-between gap-2">
                <Badge className={decisionBadgeClass(action.decision)}>{action.decision}</Badge>
                <span className="text-[11px] text-slate-500">{safeDate(action.createdAt)}</span>
              </div>
              <p className="text-xs text-slate-200">{action.eventType}</p>
              <p className="text-[11px] text-slate-500">{`source: ${action.sourceSurface} · risk: ${(action.riskScore ?? 0).toFixed(2)}`}</p>
            </div>
          )) : (
            <span className="text-xs text-slate-500">No connected action nodes found.</span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="rounded border border-[#2a3348] bg-[#0f1218] p-2 text-slate-300">
          <p className="text-[11px] text-slate-500">Connected Edges</p>
          <p className="text-base font-semibold text-slate-100">{details.connectedEdges.length}</p>
        </div>
        <div className="rounded border border-[#2a3348] bg-[#0f1218] p-2 text-slate-300">
          <p className="text-[11px] text-slate-500">Chain Risk</p>
          <p className="text-base font-semibold text-slate-100">{graph.risk_score.toFixed(2)}</p>
        </div>
      </div>
    </div>
  );
}
