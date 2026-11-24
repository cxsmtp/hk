"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { RefreshCw, ZoomIn, ZoomOut } from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { AISystem, AgentIdentity, DiscoveryApplication, Finding } from "@/lib/types";

type FootprintNodeType = "user" | "approved_tool" | "risky_tool" | "shadow_tool" | "agent" | "system";
type EdgeKind = "approved" | "risk" | "shadow" | "warning";

type FootprintNode = {
  id: string;
  label: string;
  type: FootprintNodeType;
  x: number;
  y: number;
  alertCount: number;
  meta: Record<string, string | number | null>;
};

type FootprintEdge = {
  id: string;
  from: string;
  to: string;
  kind: EdgeKind;
  count: number;
};

type GraphBuildResult = {
  nodes: FootprintNode[];
  edges: FootprintEdge[];
  usersCount: number;
  approvedCount: number;
  riskyCount: number;
  shadowCount: number;
  agentCount: number;
  systemCount: number;
  totalAlerts: number;
};

const CANVAS_WIDTH = 1400;
const CANVAS_HEIGHT = 780;

const NODE_STYLE: Record<FootprintNodeType, { ring: string; fill: string; glow: string; label: string }> = {
  user: { ring: "#4f8ef7", fill: "#0d1d34", glow: "rgba(79,142,247,0.45)", label: "User" },
  approved_tool: { ring: "#22c55e", fill: "#102918", glow: "rgba(34,197,94,0.45)", label: "Approved Tool" },
  risky_tool: { ring: "#ef4444", fill: "#2b1417", glow: "rgba(239,68,68,0.45)", label: "Risky Tool" },
  shadow_tool: { ring: "#facc15", fill: "#2d270a", glow: "rgba(250,204,21,0.45)", label: "Shadow AI" },
  agent: { ring: "#a855f7", fill: "#241132", glow: "rgba(168,85,247,0.45)", label: "AI Agent" },
  system: { ring: "#06b6d4", fill: "#0e2530", glow: "rgba(6,182,212,0.45)", label: "System" },
};

const EDGE_STYLE: Record<EdgeKind, { stroke: string; dash?: string }> = {
  approved: { stroke: "#475569" },
  risk: { stroke: "#ef4444" },
  shadow: { stroke: "#facc15", dash: "8 6" },
  warning: { stroke: "#fb923c" },
};

function hashValue(input: string): number {
  let hash = 0;
  for (let i = 0; i < input.length; i += 1) hash = (hash * 31 + input.charCodeAt(i)) % 1000003;
  return hash;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function spacedY(index: number, total: number, start: number, end: number): number {
  if (total <= 1) return (start + end) / 2;
  return start + (index / (total - 1)) * (end - start);
}

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

function nodeTypeForApp(app: DiscoveryApplication): FootprintNodeType {
  if (app.status === "blocked") return "risky_tool";
  if (app.status === "approved" && app.risk_score >= 75) return "risky_tool";
  if (app.status === "approved") return "approved_tool";
  return "shadow_tool";
}

function edgeKindForFinding(finding: Finding, appType?: FootprintNodeType): EdgeKind {
  if (finding.severity === "critical" || finding.severity === "high") return "risk";
  if (finding.finding_type.includes("shadow") || appType === "shadow_tool") return "shadow";
  if (finding.severity === "med") return "warning";
  return "approved";
}

function buildGraph(apps: DiscoveryApplication[], systems: AISystem[], agents: AgentIdentity[], findings: Finding[]): GraphBuildResult {
  const nodes: FootprintNode[] = [];
  const edges = new Map<string, FootprintEdge>();
  const nodeMap = new Map<string, FootprintNode>();

  const userPool = Array.from(
    new Set([
      ...findings.map((row) => row.user_id || "").filter(Boolean),
      ...apps.map((row) => row.owner_label || row.owner_user_id || "").filter(Boolean),
    ])
  ).slice(0, 8);

  userPool.forEach((label, idx) => {
    const jitter = ((hashValue(label) % 61) - 30) * 0.8;
    const node: FootprintNode = {
      id: `user:${label}`,
      label,
      type: "user",
      x: 170 + jitter,
      y: spacedY(idx, userPool.length, 120, 650),
      alertCount: 0,
      meta: { category: "user" },
    };
    nodes.push(node);
    nodeMap.set(node.id, node);
  });

  const toolByName = new Map<string, DiscoveryApplication>();
  apps.forEach((app) => {
    toolByName.set(normalize(app.tool_name), app);
  });

  const approvedApps = apps.filter((app) => nodeTypeForApp(app) === "approved_tool");
  const riskyApps = apps.filter((app) => nodeTypeForApp(app) === "risky_tool");
  const shadowApps = apps.filter((app) => nodeTypeForApp(app) === "shadow_tool");

  const addToolNodes = (rows: DiscoveryApplication[], type: FootprintNodeType, xCenter: number) => {
    rows.forEach((app, idx) => {
      const jitterX = ((hashValue(app.id) % 71) - 35) * 0.8;
      const jitterY = ((hashValue(app.tool_key) % 41) - 20) * 0.7;
      const node: FootprintNode = {
        id: `tool:${app.id}`,
        label: app.tool_name,
        type,
        x: xCenter + jitterX,
        y: spacedY(idx, rows.length, 140, 640) + jitterY,
        alertCount: Math.max(0, Number(app.findings_open || 0)),
        meta: {
          vendor: app.vendor,
          status: app.status,
          risk_score: app.risk_score,
          ai_system_id: app.ai_system_id || null,
        },
      };
      nodes.push(node);
      nodeMap.set(node.id, node);
    });
  };

  addToolNodes(riskyApps, "risky_tool", 520);
  addToolNodes(approvedApps, "approved_tool", 700);
  addToolNodes(shadowApps, "shadow_tool", 860);

  const agentRows = agents.slice(0, 8);
  agentRows.forEach((agent, idx) => {
    const node: FootprintNode = {
      id: `agent:${agent.id}`,
      label: agent.name,
      type: "agent",
      x: 980 + ((hashValue(agent.id) % 41) - 20) * 0.9,
      y: spacedY(idx, agentRows.length, 170, 680),
      alertCount: 0,
      meta: { status: agent.status, max_chain_depth: agent.max_chain_depth },
    };
    nodes.push(node);
    nodeMap.set(node.id, node);
  });

  const systemRows = systems.slice(0, 8);
  systemRows.forEach((system, idx) => {
    const node: FootprintNode = {
      id: `system:${system.id}`,
      label: system.name,
      type: "system",
      x: 1200 + ((hashValue(system.id) % 31) - 15) * 0.7,
      y: spacedY(idx, systemRows.length, 160, 680),
      alertCount: 0,
      meta: { risk_tier: system.risk_tier, status: system.status },
    };
    nodes.push(node);
    nodeMap.set(node.id, node);
  });

  const addEdge = (from: string, to: string, kind: EdgeKind) => {
    if (!nodeMap.has(from) || !nodeMap.has(to)) return;
    const key = `${from}::${to}::${kind}`;
    const existing = edges.get(key);
    if (existing) {
      existing.count += 1;
      return;
    }
    edges.set(key, {
      id: `edge:${edges.size + 1}`,
      from,
      to,
      kind,
      count: 1,
    });
  };

  findings.forEach((finding) => {
    const app = toolByName.get(normalize(finding.ai_tool || ""));
    const toolNodeId = app ? `tool:${app.id}` : "";
    const userLabel =
      finding.user_id ||
      app?.owner_label ||
      app?.owner_user_id ||
      userPool[hashValue(finding.finding_id) % userPool.length];
    const userNodeId = `user:${userLabel}`;
    const appType = app ? nodeTypeForApp(app) : undefined;
    const kind = edgeKindForFinding(finding, appType);

    if (toolNodeId) addEdge(userNodeId, toolNodeId, kind);
    const open = finding.status !== "resolved";
    if (open && nodeMap.has(userNodeId)) nodeMap.get(userNodeId)!.alertCount += 1;
    if (open && toolNodeId && nodeMap.has(toolNodeId)) nodeMap.get(toolNodeId)!.alertCount += 1;
  });

  apps.forEach((app) => {
    if (!app.ai_system_id) return;
    const toolNodeId = `tool:${app.id}`;
    const systemNodeId = `system:${app.ai_system_id}`;
    const appType = nodeTypeForApp(app);
    const kind: EdgeKind = appType === "shadow_tool" ? "shadow" : appType === "risky_tool" ? "risk" : "approved";
    addEdge(toolNodeId, systemNodeId, kind);
  });

  if (agentRows.length && apps.length) {
    agentRows.forEach((agent, idx) => {
      const targetApp = apps[idx % apps.length];
      const targetSystem = systems[idx % Math.max(1, systems.length)];
      const kind: EdgeKind = nodeTypeForApp(targetApp) === "risky_tool" ? "warning" : "approved";
      addEdge(`agent:${agent.id}`, `tool:${targetApp.id}`, kind);
      if (targetSystem) addEdge(`agent:${agent.id}`, `system:${targetSystem.id}`, "approved");
    });
  }

  const totalAlerts = findings.filter((row) => row.status !== "resolved").length;
  const builtEdges = Array.from(edges.values());
  return {
    nodes,
    edges: builtEdges,
    usersCount: nodes.filter((n) => n.type === "user").length,
    approvedCount: nodes.filter((n) => n.type === "approved_tool").length,
    riskyCount: nodes.filter((n) => n.type === "risky_tool").length,
    shadowCount: nodes.filter((n) => n.type === "shadow_tool").length,
    agentCount: nodes.filter((n) => n.type === "agent").length,
    systemCount: nodes.filter((n) => n.type === "system").length,
    totalAlerts,
  };
}

export default function AIFootprintPage() {
  const [apps, setApps] = useState<DiscoveryApplication[]>([]);
  const [systems, setSystems] = useState<AISystem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agents, setAgents] = useState<AgentIdentity[]>([]);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "stale" | "unavailable">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [nodes, setNodes] = useState<FootprintNode[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string>("");
  const [viewport, setViewport] = useState({ x: 0, y: 0, scale: 1 });
  const svgRef = useRef<SVGSVGElement | null>(null);
  const dragRef = useRef<
    | { mode: "pan"; pointerId: number; startX: number; startY: number; baseX: number; baseY: number }
    | { mode: "node"; pointerId: number; nodeId: string; startWorldX: number; startWorldY: number; baseNodeX: number; baseNodeY: number }
    | null
  >(null);

  async function load() {
    setLoadState((current) => current === "ready" || current === "stale" ? "stale" : "loading");
    try {
      const [appsPayload, systemsPayload, findingsPayload, agentsPayload] = await Promise.all([
        api.listDiscoveryApplications({ page_size: 500 }),
        api.listAISystems(),
        api.listFindings({ page_size: 1000 }),
        api.listAgents(),
      ]);
      setApps(appsPayload.items || []);
      setSystems(systemsPayload.items || []);
      setFindings(findingsPayload.items || []);
      setAgents(agentsPayload.items || []);
      setLoadError(null);
      setLoadState("ready");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Footprint data is unavailable.");
      setLoadState((current) => current === "stale" ? "stale" : "unavailable");
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
  }, []);

  const graph = useMemo(() => buildGraph(apps, systems, agents, findings), [apps, systems, agents, findings]);

  useEffect(() => {
    setNodes(graph.nodes);
    setSelectedNodeId(graph.nodes[0]?.id || "");
    setViewport({ x: 0, y: 0, scale: 1 });
  }, [graph.nodes]);

  const nodeById = useMemo(() => {
    const out = new Map<string, FootprintNode>();
    nodes.forEach((node) => out.set(node.id, node));
    return out;
  }, [nodes]);

  const selectedNode = selectedNodeId ? nodeById.get(selectedNodeId) || null : null;
  const selectedEdges = useMemo(
    () => graph.edges.filter((edge) => edge.from === selectedNodeId || edge.to === selectedNodeId),
    [graph.edges, selectedNodeId]
  );
  const topAlerts = useMemo(
    () =>
      [...nodes]
        .filter((node) => node.alertCount > 0)
        .sort((a, b) => b.alertCount - a.alertCount)
        .slice(0, 5),
    [nodes]
  );
  const hasSourceData = loadState === "ready" || loadState === "stale";

  function worldPoint(clientX: number, clientY: number) {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };
    return {
      x: (clientX - rect.left - viewport.x) / viewport.scale,
      y: (clientY - rect.top - viewport.y) / viewport.scale,
    };
  }

  function onCanvasPointerDown(event: React.PointerEvent<SVGSVGElement>) {
    const isNodeTarget = (event.target as HTMLElement).dataset.node === "true";
    if (isNodeTarget) return;
    dragRef.current = {
      mode: "pan",
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      baseX: viewport.x,
      baseY: viewport.y,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function onNodePointerDown(event: React.PointerEvent<SVGGElement>, node: FootprintNode) {
    event.stopPropagation();
    const pt = worldPoint(event.clientX, event.clientY);
    dragRef.current = {
      mode: "node",
      pointerId: event.pointerId,
      nodeId: node.id,
      startWorldX: pt.x,
      startWorldY: pt.y,
      baseNodeX: node.x,
      baseNodeY: node.y,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function onPointerMove(event: React.PointerEvent<SVGSVGElement>) {
    const current = dragRef.current;
    if (!current || current.pointerId !== event.pointerId) return;

    if (current.mode === "pan") {
      const dx = event.clientX - current.startX;
      const dy = event.clientY - current.startY;
      setViewport((prev) => ({ ...prev, x: current.baseX + dx, y: current.baseY + dy }));
      return;
    }

    const pt = worldPoint(event.clientX, event.clientY);
    const dx = pt.x - current.startWorldX;
    const dy = pt.y - current.startWorldY;
    setNodes((prev) =>
      prev.map((node) =>
        node.id === current.nodeId
          ? {
              ...node,
              x: clamp(current.baseNodeX + dx, 40, CANVAS_WIDTH - 40),
              y: clamp(current.baseNodeY + dy, 40, CANVAS_HEIGHT - 40),
            }
          : node
      )
    );
  }

  function onPointerUp(event: React.PointerEvent<SVGSVGElement>) {
    const current = dragRef.current;
    if (!current || current.pointerId !== event.pointerId) return;
    dragRef.current = null;
    event.currentTarget.releasePointerCapture(event.pointerId);
  }

  function onWheel(event: React.WheelEvent<SVGSVGElement>) {
    event.preventDefault();
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mouseX = event.clientX - rect.left;
    const mouseY = event.clientY - rect.top;
    const prevScale = viewport.scale;
    const nextScale = clamp(prevScale * (event.deltaY > 0 ? 0.92 : 1.08), 0.65, 2.2);
    const worldX = (mouseX - viewport.x) / prevScale;
    const worldY = (mouseY - viewport.y) / prevScale;
    const nextX = mouseX - worldX * nextScale;
    const nextY = mouseY - worldY * nextScale;
    setViewport({ x: nextX, y: nextY, scale: nextScale });
  }

  const metricCards = [
    { label: "Users", value: hasSourceData ? graph.usersCount : "Unknown", color: "text-blue-400", border: "border-blue-500/60" },
    { label: "Approved AI", value: hasSourceData ? graph.approvedCount : "Unknown", color: "text-emerald-400", border: "border-emerald-500/60" },
    { label: "Risky AI", value: hasSourceData ? graph.riskyCount : "Unknown", color: "text-red-400", border: "border-red-500/60" },
    { label: "Shadow AI", value: hasSourceData ? graph.shadowCount : "Unknown", color: "text-amber-300", border: "border-amber-400/70" },
    { label: "Agents", value: hasSourceData ? graph.agentCount : "Unknown", color: "text-violet-400", border: "border-violet-500/70" },
    { label: "Systems", value: hasSourceData ? graph.systemCount : "Unknown", color: "text-cyan-400", border: "border-cyan-500/70" },
    { label: "Total Alerts", value: hasSourceData ? graph.totalAlerts : "Unknown", color: "text-red-400", border: "border-red-500/70" },
  ];

  return (
    <AppShell>
      <div className="space-y-5">
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-brand-400">{"// AI FOOTPRINT"}</p>
          <h1 className="mt-1 text-4xl font-black tracking-tight text-slate-100">AI Identity & Footprint Graph</h1>
          <p className="mt-2 text-sm text-slate-400">
            Evidence-backed map of observed users, AI tools, agents and systems. Click nodes to investigate. Drag to explore. Scroll to zoom.
          </p>
          {loadState === "loading" && !graph.nodes.length ? <p role="status" className="mt-2 text-xs text-slate-500">Loading observed footprint…</p> : null}
          {loadState === "stale" ? <p role="status" className="mt-2 text-xs text-amber-300">Showing the last successful footprint snapshot while refresh is unavailable{loadError ? `: ${loadError}` : ""}.</p> : null}
          {loadState === "unavailable" ? <p role="status" className="mt-2 text-xs text-amber-300">Footprint data is unavailable. No synthetic users or systems are shown.</p> : null}
        </div>

        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-7">
          {metricCards.map((item) => (
            <div
              key={item.label}
              className={`rounded-xl border bg-[#121826]/80 px-4 py-3 backdrop-blur ${item.border}`}
            >
              <p className="text-xs uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
              <p className={`mt-1 text-4xl font-black leading-none ${item.color}`}>{item.value}</p>
            </div>
          ))}
        </div>

        <section className="rounded-2xl border border-[#263248] bg-[#101621]/95 shadow-[0_20px_60px_rgba(3,6,12,0.6)]">
          <header className="border-b border-[#233047] px-5 py-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-4">
                <p className="text-xl font-bold text-slate-100">Observed AI Footprint</p>
                <span className="inline-flex items-center gap-2 rounded-full border border-slate-500/40 bg-slate-500/10 px-3 py-1 text-xs font-semibold text-slate-300">
                  {loadState === "ready" ? "CURRENT SNAPSHOT" : loadState === "stale" ? "STALE SNAPSHOT" : loadState === "loading" ? "LOADING" : "UNAVAILABLE"}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button variant="outline" size="sm" onClick={() => setViewport((prev) => ({ ...prev, scale: clamp(prev.scale * 1.1, 0.65, 2.2) }))}>
                  <ZoomIn className="mr-1 h-4 w-4" /> Zoom
                </Button>
                <Button variant="outline" size="sm" onClick={() => setViewport((prev) => ({ ...prev, scale: clamp(prev.scale * 0.9, 0.65, 2.2) }))}>
                  <ZoomOut className="mr-1 h-4 w-4" /> Out
                </Button>
                <Button variant="outline" size="sm" onClick={() => {
                  setNodes(graph.nodes);
                  setViewport({ x: 0, y: 0, scale: 1 });
                }}>
                  <RefreshCw className="mr-1 h-4 w-4" /> Reset
                </Button>
              </div>
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-slate-400">
              <span className="inline-flex items-center gap-2"><span className="h-[2px] w-8 bg-slate-500" /> Approved connection</span>
              <span className="inline-flex items-center gap-2"><span className="h-[2px] w-8 bg-red-500" /> Risk connection</span>
              <span className="inline-flex items-center gap-2"><span className="h-[2px] w-8 border-b-2 border-dashed border-amber-400" /> Shadow / unapproved</span>
              <span className="inline-flex items-center gap-2"><span className="h-[2px] w-8 bg-orange-400" /> Warning</span>
            </div>
          </header>

          <div className="relative h-[680px] overflow-hidden rounded-b-2xl">
            {!graph.nodes.length ? (
              <div role="status" className="absolute inset-0 z-10 grid place-items-center bg-[#0a1020]/95 px-6 text-center text-sm text-slate-500">
                {loadState === "loading" ? "Loading observed footprint…" : loadState === "unavailable" ? "Footprint data is unavailable for this tenant." : "No observed footprint data is available for this tenant yet."}
              </div>
            ) : null}
            <svg
              ref={svgRef}
              viewBox={`0 0 ${CANVAS_WIDTH} ${CANVAS_HEIGHT}`}
              className="h-full w-full touch-none select-none bg-[#0a1020]"
              onPointerDown={onCanvasPointerDown}
              onPointerMove={onPointerMove}
              onPointerUp={onPointerUp}
              onPointerCancel={onPointerUp}
              onWheel={onWheel}
            >
              <defs>
                <pattern id="gridPattern" width="44" height="44" patternUnits="userSpaceOnUse">
                  <path d="M 44 0 L 0 0 0 44" fill="none" stroke="#1c2740" strokeWidth="1" />
                </pattern>
              </defs>
              <rect width={CANVAS_WIDTH} height={CANVAS_HEIGHT} fill="url(#gridPattern)" />

              <g transform={`translate(${viewport.x},${viewport.y}) scale(${viewport.scale})`}>
                {graph.edges.map((edge) => {
                  const from = nodeById.get(edge.from);
                  const to = nodeById.get(edge.to);
                  if (!from || !to) return null;
                  const style = EDGE_STYLE[edge.kind];
                  const selected = selectedNodeId && (edge.from === selectedNodeId || edge.to === selectedNodeId);
                  return (
                    <line
                      key={edge.id}
                      x1={from.x}
                      y1={from.y}
                      x2={to.x}
                      y2={to.y}
                      stroke={style.stroke}
                      strokeWidth={selected ? 3.4 : 2}
                      strokeDasharray={style.dash}
                      opacity={selectedNodeId ? (selected ? 0.95 : 0.22) : 0.7}
                    />
                  );
                })}

                {nodes.map((node) => {
                  const style = NODE_STYLE[node.type];
                  const isSelected = node.id === selectedNodeId;
                  return (
                    <g
                      key={node.id}
                      data-node="true"
                      transform={`translate(${node.x},${node.y})`}
                      onPointerDown={(event) => onNodePointerDown(event, node)}
                      onClick={() => setSelectedNodeId(node.id)}
                      style={{ cursor: "grab" }}
                    >
                      <circle r={isSelected ? 35 : 28} fill="none" stroke={style.glow} strokeWidth={isSelected ? 14 : 10} opacity={0.55} />
                      <circle r={isSelected ? 24 : 21} fill={style.fill} stroke={style.ring} strokeWidth={isSelected ? 3.4 : 2.2} />
                      <text
                        x={0}
                        y={46}
                        textAnchor="middle"
                        fill="#9fb3d9"
                        fontSize={15}
                        fontWeight={600}
                        style={{ pointerEvents: "none" }}
                      >
                        {node.label}
                      </text>
                      {node.alertCount > 0 ? (
                        <g transform="translate(18,-20)">
                          <circle r={12} fill="#facc15" stroke="#111827" strokeWidth={2.5} />
                          <text x={0} y={5} textAnchor="middle" fill="#111827" fontSize={11} fontWeight={800}>
                            {node.alertCount}
                          </text>
                        </g>
                      ) : null}
                    </g>
                  );
                })}
              </g>
            </svg>

            <aside className="absolute right-4 top-4 w-64 rounded-xl border border-[#394668] bg-[#0c1426]/95 p-3">
              <p className="text-[11px] uppercase tracking-[0.12em] text-slate-400">Alert Hotspots</p>
              <div className="mt-2 space-y-2">
                {!hasSourceData ? (
                  <p role="status" className="text-sm text-slate-500">
                    {loadState === "loading" ? "Loading alert evidence…" : "Alert evidence is unavailable."}
                  </p>
                ) : topAlerts.length ? (
                  topAlerts.map((node) => (
                    <button
                      key={`alert-${node.id}`}
                      className="flex w-full items-center justify-between rounded-md border border-amber-400/30 bg-amber-500/10 px-3 py-2 text-left text-sm text-amber-200 hover:bg-amber-500/20"
                      onClick={() => setSelectedNodeId(node.id)}
                    >
                      <span className="truncate font-semibold">{node.label}</span>
                      <span>{node.alertCount} alerts</span>
                    </button>
                  ))
                ) : (
                  <p className="text-sm text-slate-500">No open alerts.</p>
                )}
              </div>
            </aside>

            <aside className="absolute bottom-4 left-4 max-w-md rounded-xl border border-[#344161] bg-[#0c1426]/95 p-3">
              {selectedNode ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-4">
                    <p className="text-sm font-bold text-slate-100">{selectedNode.label}</p>
                    <span className="rounded border border-[#3d4c6f] bg-[#13203a] px-2 py-0.5 text-[11px] uppercase tracking-[0.08em] text-slate-300">
                      {NODE_STYLE[selectedNode.type].label}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    Connections: {selectedEdges.length} · Alerts: {selectedNode.alertCount}
                  </p>
                  <div className="grid gap-1 text-xs text-slate-400">
                    {Object.entries(selectedNode.meta).map(([key, value]) => (
                      <p key={`${selectedNode.id}-${key}`}>
                        <span className="text-slate-500">{key}:</span> {value ?? "-"}
                      </p>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-sm text-slate-400">Click any node to inspect context and links.</p>
              )}
            </aside>
          </div>
        </section>
      </div>
    </AppShell>
  );
}
