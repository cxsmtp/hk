"use client";

import { useEffect, useMemo, useState } from "react";
import ReactFlow, { Background, Controls, Edge, MarkerType, MiniMap, Node, Panel } from "reactflow";

import { decisionValue } from "@/components/runtime-intelligence/utils";
import type { RuntimeChainGraph, RuntimeTimelineEvent } from "@/lib/types";

type DecisionTone = "allow" | "warn" | "block" | "unknown";

const EDGE_PAGE_SIZE = 360;
const TYPE_ORDER = ["user", "agent", "tool", "ai_system", "data", "action", "other"];

function toNumber(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(1, parsed));
}

function normalizeType(value: string): string {
  const text = String(value || "other").trim().toLowerCase();
  if (text === "resource") return "data";
  if (TYPE_ORDER.includes(text)) return text;
  return "other";
}

function short(value: string, limit = 30): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, limit - 3)}...`;
}

function nodeTitle(type: string, entityId: string): string {
  return `${type}\n${short(entityId || "unknown")}`;
}

function decisionTone(value: unknown): DecisionTone {
  const decision = decisionValue(value);
  if (decision === "allow" || decision === "approved") return "allow";
  if (decision === "block" || decision === "deny" || decision === "denied") return "block";
  if (["warn", "redact", "require_justification", "hold_for_approval", "require_approval"].includes(decision)) return "warn";
  return "unknown";
}

function tonePriority(value: DecisionTone): number {
  if (value === "block") return 3;
  if (value === "warn") return 2;
  if (value === "allow") return 1;
  return 0;
}

function edgeColor(tone: DecisionTone): string {
  if (tone === "allow") return "#16a34a";
  if (tone === "warn") return "#eab308";
  if (tone === "block") return "#ef4444";
  return "#475569";
}

function nodeStyle({
  selected,
  highRisk,
  tone,
}: {
  selected: boolean;
  highRisk: boolean;
  tone: DecisionTone;
}): { border: string; background: string; text: string; shadow: string } {
  if (highRisk || tone === "block") {
    return {
      border: selected ? "#f43f5e" : "#be123c",
      background: "#3f0a1f",
      text: "#fecdd3",
      shadow: selected ? "0 0 0 2px rgba(244,63,94,0.35)" : "0 0 0 1px rgba(190,24,93,0.35)",
    };
  }
  if (tone === "warn") {
    return {
      border: selected ? "#f59e0b" : "#d97706",
      background: "#40220a",
      text: "#fde68a",
      shadow: selected ? "0 0 0 2px rgba(245,158,11,0.28)" : "none",
    };
  }
  if (tone === "allow") {
    return {
      border: selected ? "#22c55e" : "#15803d",
      background: "#052e16",
      text: "#bbf7d0",
      shadow: selected ? "0 0 0 2px rgba(34,197,94,0.25)" : "none",
    };
  }
  return {
    border: selected ? "#3b82f6" : "#334155",
    background: "#0f172a",
    text: "#cbd5e1",
    shadow: selected ? "0 0 0 2px rgba(59,130,246,0.24)" : "none",
  };
}

function matchesNodeEvent(nodeType: string, entityId: string, event: RuntimeTimelineEvent): boolean {
  if (!entityId) return false;
  if (nodeType === "action") return event.event_id === entityId;
  if (nodeType === "agent") return String(event.agent_id || "") === entityId;
  if (nodeType === "user") return String(event.user_id || "") === entityId;
  if (nodeType === "tool") return String(event.tool_name || "") === entityId || String(event.tool_category || "") === entityId;
  if (nodeType === "ai_system") return String(event.ai_system_id || "") === entityId;
  if (nodeType === "data" || nodeType === "resource") return String(event.api_endpoint || "") === entityId;
  return false;
}

function nodeContextId(node: RuntimeChainGraph["nodes"][number], loadedContextId?: string): string {
  const value = String(node.metadata?.context_id || node.metadata?.source_context_id || "").trim();
  if (value) return value;
  return loadedContextId || "unassigned";
}

export function RuntimeContextGraphView({
  graph,
  events,
  loadedContextId,
  selectedNodeId,
  onSelectedNodeIdChange,
}: {
  graph: RuntimeChainGraph | null;
  events: RuntimeTimelineEvent[];
  loadedContextId: string;
  selectedNodeId: string | null;
  onSelectedNodeIdChange: (nodeId: string | null) => void;
}) {
  const [visibleEdgeCount, setVisibleEdgeCount] = useState(EDGE_PAGE_SIZE);

  useEffect(() => {
    setVisibleEdgeCount(EDGE_PAGE_SIZE);
  }, [graph?.nodes.length, graph?.edges.length, loadedContextId]);

  const derived = useMemo(() => {
    if (!graph) {
      return {
        nodes: [] as Node[],
        edges: [] as Edge[],
        hiddenEdges: 0,
        contextCount: 0,
        highRiskCount: 0,
      };
    }

    const nodesById = new Map(graph.nodes.map((node) => [node.id, node]));
    const edgesShown = (graph.edges || []).slice(0, visibleEdgeCount);
    const hiddenEdges = Math.max(0, (graph.edges || []).length - edgesShown.length);

    const toneByEdge = new Map<string, DecisionTone>();
    const edgeByNodeId = new Map<string, typeof edgesShown>();
    edgesShown.forEach((edge) => {
      const fromNode = nodesById.get(edge.from_node);
      const toNode = nodesById.get(edge.to_node);
      const fromEventId = String(fromNode?.entity_id || "").replace(/^action:/, "");
      const toEventId = String(toNode?.entity_id || "").replace(/^action:/, "");
      const event =
        events.find((item) => item.event_id === fromEventId) ||
        events.find((item) => item.event_id === toEventId) ||
        null;
      const tone = decisionTone(event?.decision || toNode?.metadata?.decision || fromNode?.metadata?.decision);
      toneByEdge.set(edge.id, tone);
      const fromBucket = edgeByNodeId.get(edge.from_node) || [];
      fromBucket.push(edge);
      edgeByNodeId.set(edge.from_node, fromBucket);
      const toBucket = edgeByNodeId.get(edge.to_node) || [];
      toBucket.push(edge);
      edgeByNodeId.set(edge.to_node, toBucket);
    });

    const allContexts = new Set<string>();
    const groups = new Map<string, RuntimeChainGraph["nodes"]>();
    graph.nodes.forEach((node) => {
      const contextId = nodeContextId(node, loadedContextId);
      allContexts.add(contextId);
      const bucket = groups.get(contextId) || [];
      bucket.push(node);
      groups.set(contextId, bucket);
    });

    let highRiskCount = 0;
    const nodeRiskById = new Map<string, number>();
    const nodeToneById = new Map<string, DecisionTone>();
    graph.nodes.forEach((node) => {
      const type = normalizeType(node.type);
      const entityId = String(node.entity_id || node.id).replace(/^action:/, "");
      const relatedEvents = events.filter((event) => matchesNodeEvent(type, entityId, event));
      const explicitRisk = toNumber(node.metadata?.risk_score);
      const eventRisk = relatedEvents.length ? Math.max(...relatedEvents.map((event) => toNumber(event.risk_score))) : 0;
      const riskScore = Math.max(explicitRisk, eventRisk);
      nodeRiskById.set(node.id, riskScore);
      if (riskScore >= 0.67) highRiskCount += 1;

      let bestTone: DecisionTone = decisionTone(node.metadata?.decision);
      const incidentEdges = edgeByNodeId.get(node.id) || [];
      incidentEdges.forEach((edge) => {
        const tone = toneByEdge.get(edge.id) || "unknown";
        if (tonePriority(tone) > tonePriority(bestTone)) bestTone = tone;
      });
      nodeToneById.set(node.id, bestTone);
    });

    const contextOrder = Array.from(groups.keys()).sort((a, b) => a.localeCompare(b));
    const contextColumn = new Map(contextOrder.map((id, index) => [id, index]));

    const nodes: Node[] = [];
    contextOrder.forEach((contextId) => {
      const groupNodes = groups.get(contextId) || [];
      const typed = new Map<string, RuntimeChainGraph["nodes"]>();
      groupNodes.forEach((node) => {
        const type = normalizeType(node.type);
        const bucket = typed.get(type) || [];
        bucket.push(node);
        typed.set(type, bucket);
      });
      TYPE_ORDER.forEach((type, typeIndex) => {
        const bucket = typed.get(type) || [];
        bucket.sort((left, right) => String(left.entity_id || "").localeCompare(String(right.entity_id || "")));
        bucket.forEach((node, rowIndex) => {
          const risk = nodeRiskById.get(node.id) || 0;
          const tone = nodeToneById.get(node.id) || "unknown";
          const selected = node.id === selectedNodeId;
          const highRisk = risk >= 0.67;
          const visual = nodeStyle({ selected, highRisk, tone });
          const cluster = contextColumn.get(contextId) || 0;
          const x = cluster * 1420 + typeIndex * 210;
          const y = rowIndex * 112;

          nodes.push({
            id: node.id,
            position: { x, y },
            data: { label: nodeTitle(type, String(node.entity_id || node.id)) },
            draggable: false,
            style: {
              width: 190,
              borderRadius: 12,
              border: `1px solid ${visual.border}`,
              background: visual.background,
              color: visual.text,
              whiteSpace: "pre-line",
              fontSize: 12,
              padding: 8,
              boxShadow: visual.shadow,
            },
          });
        });
      });
    });

    const edges: Edge[] = edgesShown
      .filter((edge) => nodesById.has(edge.from_node) && nodesById.has(edge.to_node))
      .map((edge) => {
        const tone = toneByEdge.get(edge.id) || "unknown";
        return {
          id: edge.id,
          source: edge.from_node,
          target: edge.to_node,
          label: short(String(edge.relation_type || "related"), 26),
          labelStyle: { fontSize: 10, fill: "#94a3b8" },
          markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor(tone) },
          style: {
            stroke: edgeColor(tone),
            strokeWidth: 2.1,
          },
          interactionWidth: 28,
          animated: tone === "warn" || tone === "block",
        } as Edge;
      });

    return {
      nodes,
      edges,
      hiddenEdges,
      contextCount: allContexts.size,
      highRiskCount,
    };
  }, [events, graph, loadedContextId, selectedNodeId, visibleEdgeCount]);

  if (!graph) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-10 text-center text-sm text-slate-400">
        Load a context id to render relationship topology.
      </div>
    );
  }

  return (
    <div className="h-[660px] overflow-hidden rounded-lg border border-[#2a3348] bg-[#0b1220]">
      <ReactFlow
        nodes={derived.nodes}
        edges={derived.edges}
        fitView
        minZoom={0.1}
        maxZoom={2}
        onNodeClick={(_, node) => onSelectedNodeIdChange(node.id)}
        onPaneClick={() => onSelectedNodeIdChange(null)}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={20} />
        <MiniMap nodeBorderRadius={4} />
        <Controls showInteractive />
        <Panel position="top-left" className="rounded bg-[#0b1220]/90 px-2 py-1 text-xs text-slate-300">
          {`Contexts ${derived.contextCount} · Nodes ${derived.nodes.length} · Edges ${derived.edges.length} · High Risk ${derived.highRiskCount}`}
        </Panel>
        {derived.hiddenEdges > 0 ? (
          <Panel position="top-right">
            <button
              type="button"
              className="rounded border border-brand-500/40 bg-brand-500/20 px-2 py-1 text-xs text-brand-200 hover:bg-brand-500/30"
              onClick={() => setVisibleEdgeCount((count) => count + EDGE_PAGE_SIZE)}
            >
              Load More Edges
            </button>
          </Panel>
        ) : null}
      </ReactFlow>
    </div>
  );
}

