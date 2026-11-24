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

import type { RuntimeChainGraph } from "@/lib/types";

type DecisionTone = "allow" | "warn" | "block" | "unknown";

const EDGE_PAGE_SIZE = 250;
const TYPE_ORDER = ["user", "agent", "tool", "resource", "ai_system", "action"];

function normalizeDecision(value: unknown): DecisionTone {
  const text = String(value || "").toLowerCase();
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

function toneClasses(tone: DecisionTone): { background: string; border: string; text: string } {
  if (tone === "allow") return { background: "#052e16", border: "#16a34a", text: "#86efac" };
  if (tone === "warn") return { background: "#422006", border: "#eab308", text: "#fde047" };
  if (tone === "block") return { background: "#450a0a", border: "#ef4444", text: "#fca5a5" };
  return { background: "#0f172a", border: "#334155", text: "#cbd5e1" };
}

function shortLabel(value: string, limit = 26): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, limit - 3)}...`;
}

export function ActivityMapGraph({
  graph,
  selectedNodeId,
  onSelectedNodeChange,
}: {
  graph: RuntimeChainGraph | null;
  selectedNodeId: string | null;
  onSelectedNodeChange: (nodeId: string | null) => void;
}) {
  const [visibleEdgeCount, setVisibleEdgeCount] = useState(EDGE_PAGE_SIZE);

  useEffect(() => {
    setVisibleEdgeCount(EDGE_PAGE_SIZE);
  }, [graph?.nodes.length, graph?.edges.length]);

  const mapped = useMemo(() => {
    if (!graph) return { nodes: [] as Node[], edges: [] as Edge[], hiddenEdgeCount: 0 };

    const allEdges = graph.edges || [];
    const shownEdges = allEdges.slice(0, visibleEdgeCount);
    const hiddenEdgeCount = Math.max(0, allEdges.length - shownEdges.length);

    const nodeById = new Map((graph.nodes || []).map((node) => [node.id, node]));
    const adjacency = new Map<string, Set<string>>();
    shownEdges.forEach((edge) => {
      const fromSet = adjacency.get(edge.from_node) || new Set<string>();
      fromSet.add(edge.to_node);
      adjacency.set(edge.from_node, fromSet);
      const toSet = adjacency.get(edge.to_node) || new Set<string>();
      toSet.add(edge.from_node);
      adjacency.set(edge.to_node, toSet);
    });

    const connectedNodeIds = new Set<string>();
    shownEdges.forEach((edge) => {
      connectedNodeIds.add(edge.from_node);
      connectedNodeIds.add(edge.to_node);
    });
    if (selectedNodeId) connectedNodeIds.add(selectedNodeId);
    if (!connectedNodeIds.size) {
      (graph.nodes || []).slice(0, 100).forEach((node) => connectedNodeIds.add(node.id));
    }

    const visibleNodes = (graph.nodes || []).filter((node) => connectedNodeIds.has(node.id));

    const actionDecisionByNodeId = new Map<string, DecisionTone>();
    visibleNodes.forEach((node) => {
      if (node.type !== "action") return;
      const decision = normalizeDecision(node.metadata?.decision);
      actionDecisionByNodeId.set(node.id, decision);
    });

    const toneForNode = (nodeId: string): DecisionTone => {
      const current = nodeById.get(nodeId);
      if (!current) return "unknown";
      if (current.type === "action") return actionDecisionByNodeId.get(nodeId) || "unknown";

      let best: DecisionTone = "unknown";
      const direct = adjacency.get(nodeId) || new Set<string>();
      direct.forEach((neighbor) => {
        const directTone = actionDecisionByNodeId.get(neighbor);
        if (directTone && tonePriority(directTone) > tonePriority(best)) best = directTone;
      });
      if (best !== "unknown") return best;

      direct.forEach((neighbor) => {
        const secondHop = adjacency.get(neighbor) || new Set<string>();
        secondHop.forEach((candidate) => {
          const secondTone = actionDecisionByNodeId.get(candidate);
          if (secondTone && tonePriority(secondTone) > tonePriority(best)) best = secondTone;
        });
      });
      return best;
    };

    const grouped = new Map<string, typeof visibleNodes>();
    visibleNodes.forEach((node) => {
      const key = TYPE_ORDER.includes(node.type) ? node.type : "action";
      const bucket = grouped.get(key) || [];
      bucket.push(node);
      grouped.set(key, bucket);
    });

    const typeToColumn = new Map<string, number>();
    TYPE_ORDER.forEach((type, index) => typeToColumn.set(type, index));

    const nodes: Node[] = [];
    const sortedTypes = Array.from(grouped.keys()).sort(
      (a, b) => (typeToColumn.get(a) ?? TYPE_ORDER.length + 1) - (typeToColumn.get(b) ?? TYPE_ORDER.length + 1)
    );
    sortedTypes.forEach((type) => {
      const column = typeToColumn.get(type) ?? TYPE_ORDER.length;
      const rows = grouped.get(type) || [];
      rows.sort((a, b) => String(a.entity_id || "").localeCompare(String(b.entity_id || "")));
      rows.forEach((node, row) => {
        const tone = toneForNode(node.id);
        const palette = toneClasses(tone);
        nodes.push({
          id: node.id,
          position: { x: 280 * column, y: 120 * row },
          data: {
            label: `${node.type}\n${shortLabel(node.entity_id || node.id)}`,
          },
          draggable: false,
          style: {
            width: 230,
            borderRadius: 12,
            border: `1px solid ${palette.border}`,
            background: palette.background,
            color: palette.text,
            whiteSpace: "pre-line",
            fontSize: 12,
            padding: 8,
          },
        });
      });
    });

    const edges: Edge[] = shownEdges
      .filter((edge) => connectedNodeIds.has(edge.from_node) && connectedNodeIds.has(edge.to_node))
      .map((edge) => ({
        id: edge.id,
        source: edge.from_node,
        target: edge.to_node,
        label: shortLabel(edge.relation_type || "action", 22),
        labelStyle: { fontSize: 10, fill: "#94a3b8" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#475569" },
        style: { stroke: "#475569", strokeWidth: 1.3 },
      }));

    return { nodes, edges, hiddenEdgeCount };
  }, [graph, visibleEdgeCount, selectedNodeId]);

  if (!graph) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-10 text-center text-sm text-slate-400">
        Load a chain to render the Activity Map.
      </div>
    );
  }

  return (
    <div className="h-[560px] overflow-hidden rounded-lg border border-[#2a3348] bg-[#0b1220]">
      <ReactFlow
        nodes={mapped.nodes}
        edges={mapped.edges}
        fitView
        minZoom={0.2}
        maxZoom={1.8}
        proOptions={{ hideAttribution: true }}
        onNodeClick={(_, node) => onSelectedNodeChange(node.id)}
        onPaneClick={() => onSelectedNodeChange(null)}
      >
        <Background color="#1e293b" gap={20} />
        <MiniMap nodeBorderRadius={4} />
        <Controls showInteractive={false} />
        <Panel position="top-left" className="rounded bg-[#0b1220]/90 px-2 py-1 text-xs text-slate-300">
          {`Nodes ${mapped.nodes.length} · Edges ${mapped.edges.length}${mapped.hiddenEdgeCount ? ` · +${mapped.hiddenEdgeCount} hidden` : ""}`}
        </Panel>
        {mapped.hiddenEdgeCount > 0 ? (
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
