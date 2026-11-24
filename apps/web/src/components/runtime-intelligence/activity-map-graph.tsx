"use client";

import { useEffect, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  Edge,
  MarkerType,
  MiniMap,
  Node,
  Panel,
} from "reactflow";

import type { RuntimeChainGraph, RuntimeTimelineEvent } from "@/lib/types";

type DecisionTone = "allow" | "warn" | "block" | "unknown";

export type ActivityMapNodeDetail = {
  id: string;
  type: string;
  entityId: string;
  label: string;
  riskScore: number;
  policiesApplied: string[];
  recentActions: RuntimeTimelineEvent[];
};

export type ActivityMapEdgeDetail = {
  id: string;
  relationType: string;
  fromNodeLabel: string;
  toNodeLabel: string;
  decision: string;
  actionDetails: string;
  evidenceNodeIds: string[];
  linkedEvent: RuntimeTimelineEvent | null;
};

const EDGE_PAGE_SIZE = 320;
const TYPE_ORDER = ["user", "agent", "tool", "ai_system", "resource", "action"];

function short(value: string, limit = 30): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, limit - 3)}...`;
}

function normalizeDecision(value: unknown): DecisionTone {
  const text = String(value || "").trim().toLowerCase();
  if (text === "allow" || text === "approved") return "allow";
  if (text === "block" || text === "deny" || text === "denied") return "block";
  if (["warn", "redact", "require_justification", "hold_for_approval", "require_approval"].includes(text)) return "warn";
  return "unknown";
}

function tonePriority(tone: DecisionTone): number {
  if (tone === "block") return 3;
  if (tone === "warn") return 2;
  if (tone === "allow") return 1;
  return 0;
}

function toneStroke(tone: DecisionTone): string {
  if (tone === "allow") return "#16a34a";
  if (tone === "warn") return "#eab308";
  if (tone === "block") return "#ef4444";
  return "#475569";
}

function nodePalette(tone: DecisionTone): { background: string; border: string; text: string } {
  if (tone === "allow") return { background: "#052e16", border: "#16a34a", text: "#86efac" };
  if (tone === "warn") return { background: "#422006", border: "#eab308", text: "#fde047" };
  if (tone === "block") return { background: "#450a0a", border: "#ef4444", text: "#fecaca" };
  return { background: "#0f172a", border: "#334155", text: "#cbd5e1" };
}

function nodeTitle(type: string, entityId: string): string {
  return `${type}\n${short(entityId || "unknown")}`;
}

function toNumber(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(1, parsed));
}

function nodeEventMatches(nodeType: string, entityId: string, event: RuntimeTimelineEvent): boolean {
  if (!entityId) return false;
  if (nodeType === "action") return event.event_id === entityId;
  if (nodeType === "agent") return String(event.agent_id || "") === entityId;
  if (nodeType === "user") return String(event.user_id || "") === entityId;
  if (nodeType === "tool") {
    return String(event.tool_name || "") === entityId || String(event.tool_category || "") === entityId;
  }
  if (nodeType === "ai_system") return String(event.ai_system_id || "") === entityId;
  if (nodeType === "resource") return String(event.api_endpoint || "") === entityId;
  return false;
}

export function RuntimeActivityMapGraph({
  graph,
  chainEvents,
  selectedNodeId,
  selectedEdgeId,
  onSelectedNodeIdChange,
  onSelectedEdgeIdChange,
  onNodeDetailChange,
  onEdgeDetailChange,
}: {
  graph: RuntimeChainGraph | null;
  chainEvents: RuntimeTimelineEvent[];
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  onSelectedNodeIdChange: (id: string | null) => void;
  onSelectedEdgeIdChange: (id: string | null) => void;
  onNodeDetailChange: (detail: ActivityMapNodeDetail | null) => void;
  onEdgeDetailChange: (detail: ActivityMapEdgeDetail | null) => void;
}) {
  const [visibleEdgeCount, setVisibleEdgeCount] = useState(EDGE_PAGE_SIZE);

  useEffect(() => {
    setVisibleEdgeCount(EDGE_PAGE_SIZE);
  }, [graph?.nodes.length, graph?.edges.length]);

  const derived = useMemo(() => {
    if (!graph) {
      return {
        nodes: [] as Node[],
        edges: [] as Edge[],
        nodeDetails: new Map<string, ActivityMapNodeDetail>(),
        edgeDetails: new Map<string, ActivityMapEdgeDetail>(),
        hiddenEdgeCount: 0,
      };
    }

    const eventsById = new Map(chainEvents.map((event) => [event.event_id, event]));
    const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
    const allEdges = graph.edges || [];
    const shownEdges = allEdges.slice(0, visibleEdgeCount);
    const hiddenEdgeCount = Math.max(0, allEdges.length - shownEdges.length);

    const nodeIdsInEdges = new Set<string>();
    shownEdges.forEach((edge) => {
      nodeIdsInEdges.add(edge.from_node);
      nodeIdsInEdges.add(edge.to_node);
    });
    if (selectedNodeId) nodeIdsInEdges.add(selectedNodeId);
    if (selectedEdgeId) {
      const selected = graph.edges.find((edge) => edge.id === selectedEdgeId);
      if (selected) {
        nodeIdsInEdges.add(selected.from_node);
        nodeIdsInEdges.add(selected.to_node);
      }
    }
    if (!nodeIdsInEdges.size) {
      graph.nodes.slice(0, 150).forEach((node) => nodeIdsInEdges.add(node.id));
    }

    const visibleNodesRaw = graph.nodes.filter((node) => nodeIdsInEdges.has(node.id));
    const visibleNodeMap = new Map(visibleNodesRaw.map((node) => [node.id, node]));

    const linkedEventForEdge = (edgeId: string) => {
      const edge = nodeById.size ? graph.edges.find((item) => item.id === edgeId) : null;
      if (!edge) return null;
      const fromNode = nodeById.get(edge.from_node);
      const toNode = nodeById.get(edge.to_node);
      if (toNode?.type === "action" && eventsById.has(toNode.entity_id)) return eventsById.get(toNode.entity_id) || null;
      if (fromNode?.type === "action" && eventsById.has(fromNode.entity_id)) return eventsById.get(fromNode.entity_id) || null;
      if (edge.parent_action_id && eventsById.has(edge.parent_action_id)) return eventsById.get(edge.parent_action_id) || null;
      return null;
    };

    const edgeDecisionById = new Map<string, DecisionTone>();
    shownEdges.forEach((edge) => {
      const linkedEvent = linkedEventForEdge(edge.id);
      const fromNode = nodeById.get(edge.from_node);
      const toNode = nodeById.get(edge.to_node);
      const decision =
        normalizeDecision(linkedEvent?.decision) ||
        normalizeDecision(toNode?.metadata?.decision) ||
        normalizeDecision(fromNode?.metadata?.decision);
      edgeDecisionById.set(edge.id, decision);
    });

    const edgesByNodeId = new Map<string, typeof shownEdges>();
    shownEdges.forEach((edge) => {
      const fromEdges = edgesByNodeId.get(edge.from_node) || [];
      fromEdges.push(edge);
      edgesByNodeId.set(edge.from_node, fromEdges);

      const toEdges = edgesByNodeId.get(edge.to_node) || [];
      toEdges.push(edge);
      edgesByNodeId.set(edge.to_node, toEdges);
    });

    const nodeDetails = new Map<string, ActivityMapNodeDetail>();
    const nodeTone = new Map<string, DecisionTone>();

    visibleNodesRaw.forEach((node) => {
      const relatedEvents = chainEvents
        .filter((event) => nodeEventMatches(node.type, node.entity_id, event))
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
        .slice(0, 8);

      const incidentEdges = edgesByNodeId.get(node.id) || [];
      let bestTone: DecisionTone = "unknown";
      incidentEdges.forEach((edge) => {
        const tone = edgeDecisionById.get(edge.id) || "unknown";
        if (tonePriority(tone) > tonePriority(bestTone)) bestTone = tone;
      });
      if (node.type === "action" && bestTone === "unknown") {
        bestTone = normalizeDecision(node.metadata?.decision);
      }
      nodeTone.set(node.id, bestTone);

      const policySet = new Set<string>();
      const addPolicy = (value: unknown) => {
        const text = String(value || "").trim();
        if (text) policySet.add(text);
      };
      addPolicy(node.metadata?.policy_version_id);
      addPolicy(node.metadata?.policy_id);
      addPolicy(node.metadata?.governance_version);
      incidentEdges.forEach((edge) => {
        const fromNode = visibleNodeMap.get(edge.from_node);
        const toNode = visibleNodeMap.get(edge.to_node);
        addPolicy(fromNode?.metadata?.policy_version_id);
        addPolicy(toNode?.metadata?.policy_version_id);
      });
      if (!policySet.size) addPolicy("runtime.guardian_contract");

      const explicitRisk = toNumber(node.metadata?.risk_score);
      const eventRisk = relatedEvents.length ? Math.max(...relatedEvents.map((event) => toNumber(event.risk_score))) : 0;
      const riskScore = Math.max(explicitRisk, eventRisk);

      nodeDetails.set(node.id, {
        id: node.id,
        type: node.type,
        entityId: node.entity_id,
        label: nodeTitle(node.type, node.entity_id),
        riskScore,
        policiesApplied: Array.from(policySet).slice(0, 10),
        recentActions: relatedEvents,
      });
    });

    const grouped = new Map<string, typeof visibleNodesRaw>();
    visibleNodesRaw.forEach((node) => {
      const key = TYPE_ORDER.includes(node.type) ? node.type : "action";
      const bucket = grouped.get(key) || [];
      bucket.push(node);
      grouped.set(key, bucket);
    });

    const typeColumn = new Map<string, number>();
    TYPE_ORDER.forEach((type, idx) => typeColumn.set(type, idx));

    const nodes: Node[] = [];
    Array.from(grouped.keys())
      .sort((a, b) => (typeColumn.get(a) ?? 99) - (typeColumn.get(b) ?? 99))
      .forEach((type) => {
        const column = typeColumn.get(type) ?? TYPE_ORDER.length;
        const rows = grouped.get(type) || [];
        rows.sort((a, b) => String(a.entity_id || "").localeCompare(String(b.entity_id || "")));
        rows.forEach((node, row) => {
          const tone = nodeTone.get(node.id) || "unknown";
          const palette = nodePalette(tone);
          const selected = node.id === selectedNodeId;
          nodes.push({
            id: node.id,
            position: { x: 280 * column, y: 120 * row },
            data: { label: nodeTitle(node.type, node.entity_id) },
            draggable: false,
            style: {
              width: 230,
              borderRadius: 12,
              border: selected ? `2px solid ${palette.border}` : `1px solid ${palette.border}`,
              background: palette.background,
              color: palette.text,
              whiteSpace: "pre-line",
              fontSize: 12,
              padding: 8,
              boxShadow: selected ? `0 0 0 2px ${palette.border}33` : "none",
            },
          });
        });
      });

    const edgeDetails = new Map<string, ActivityMapEdgeDetail>();
    const edges: Edge[] = shownEdges
      .filter((edge) => visibleNodeMap.has(edge.from_node) && visibleNodeMap.has(edge.to_node))
      .map((edge) => {
        const linkedEvent = linkedEventForEdge(edge.id);
        const tone = edgeDecisionById.get(edge.id) || "unknown";
        const fromNode = visibleNodeMap.get(edge.from_node);
        const toNode = visibleNodeMap.get(edge.to_node);
        const decision = linkedEvent?.decision || String(toNode?.metadata?.decision || fromNode?.metadata?.decision || "unknown");
        const evidenceNodeIds = linkedEvent?.evidence_node_ids || [];
        edgeDetails.set(edge.id, {
          id: edge.id,
          relationType: edge.relation_type,
          fromNodeLabel: fromNode ? `${fromNode.type}:${fromNode.entity_id}` : edge.from_node,
          toNodeLabel: toNode ? `${toNode.type}:${toNode.entity_id}` : edge.to_node,
          decision,
          actionDetails: linkedEvent
            ? `${linkedEvent.event_type} via ${linkedEvent.source_surface}`
            : edge.relation_type,
          evidenceNodeIds,
          linkedEvent,
        });

        const selected = edge.id === selectedEdgeId;
        return {
          id: edge.id,
          source: edge.from_node,
          target: edge.to_node,
          label: short(edge.relation_type || "action", 24),
          labelStyle: { fontSize: 10, fill: "#94a3b8" },
          markerEnd: { type: MarkerType.ArrowClosed, color: toneStroke(tone) },
          style: {
            stroke: toneStroke(tone),
            strokeWidth: selected ? 3.2 : 2.2,
          },
          interactionWidth: 28,
          animated: tone === "warn" || tone === "block",
        } as Edge;
      });

    return { nodes, edges, nodeDetails, edgeDetails, hiddenEdgeCount };
  }, [chainEvents, graph, selectedEdgeId, selectedNodeId, visibleEdgeCount]);

  useEffect(() => {
    if (!selectedNodeId) {
      onNodeDetailChange(null);
      return;
    }
    onNodeDetailChange(derived.nodeDetails.get(selectedNodeId) || null);
  }, [derived.nodeDetails, onNodeDetailChange, selectedNodeId]);

  useEffect(() => {
    if (!selectedEdgeId) {
      onEdgeDetailChange(null);
      return;
    }
    onEdgeDetailChange(derived.edgeDetails.get(selectedEdgeId) || null);
  }, [derived.edgeDetails, onEdgeDetailChange, selectedEdgeId]);

  if (!graph) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-10 text-center text-sm text-slate-400">
        Load a chain to render the Activity Map.
      </div>
    );
  }

  return (
    <div className="h-[620px] overflow-hidden rounded-lg border border-[#2a3348] bg-[#0b1220]">
      <ReactFlow
        nodes={derived.nodes}
        edges={derived.edges}
        fitView
        minZoom={0.15}
        maxZoom={2}
        onNodeClick={(_, node) => {
          onSelectedNodeIdChange(node.id);
          onSelectedEdgeIdChange(null);
        }}
        onEdgeClick={(_, edge) => {
          onSelectedEdgeIdChange(edge.id);
          onSelectedNodeIdChange(null);
        }}
        onPaneClick={() => {
          onSelectedNodeIdChange(null);
          onSelectedEdgeIdChange(null);
        }}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={20} />
        <MiniMap nodeBorderRadius={4} />
        <Controls showInteractive />
        <Panel position="top-left" className="rounded bg-[#0b1220]/90 px-2 py-1 text-xs text-slate-300">
          {`Nodes ${derived.nodes.length} · Edges ${derived.edges.length}${derived.hiddenEdgeCount ? ` · +${derived.hiddenEdgeCount} hidden` : ""}`}
        </Panel>
        {derived.hiddenEdgeCount > 0 ? (
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

