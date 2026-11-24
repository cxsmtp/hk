"use client";

import Link from "next/link";
import { useMemo } from "react";

import { Badge } from "@/components/ui/badge";
import type {
  AgentBlastRadius,
  AgentTouchpointEdge,
  AgentTouchpointEvidenceSummary,
  AgentTouchpointRiskBadge,
  AgentTouchpointTimelineItem,
  AgentTouchpoints,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const NODE_TYPE_ORDER = [
  "human_user",
  "user",
  "agent",
  "foundry_agent",
  "copilot_agent",
  "mcp_server",
  "mcp_tool",
  "tool",
  "data_source",
  "saas_app",
  "repo",
  "evidence_bundle",
  "domain",
  "api",
];

const NODE_LABELS: Record<string, string> = {
  human_user: "User",
  user: "User",
  agent: "Agent",
  foundry_agent: "Foundry Agent",
  copilot_agent: "Copilot Agent",
  mcp_server: "MCP Server",
  mcp_tool: "MCP Tool",
  tool: "Tool",
  data_source: "Data Source",
  saas_app: "SaaS App",
  repo: "Repo",
  evidence_bundle: "Evidence",
  domain: "Domain",
  api: "API",
};

function shortId(value: string, limit = 34): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, limit - 8)}...${value.slice(-5)}`;
}

function riskClass(risk?: string | null): string {
  const value = String(risk || "").toLowerCase();
  if (value === "critical") return "border-rose-500/70 bg-rose-950/40 text-rose-100";
  if (value === "high") return "border-orange-500/60 bg-orange-950/35 text-orange-100";
  if (value === "medium") return "border-amber-500/60 bg-amber-950/30 text-amber-100";
  return "border-slate-700 bg-slate-900/70 text-slate-200";
}

function modeClass(mode?: string | null): string {
  const value = String(mode || "").toLowerCase();
  if (value === "inline_prevented") return "border-rose-500/70 bg-rose-950/35 text-rose-100";
  if (value === "inline_allowed") return "border-emerald-500/60 bg-emerald-950/30 text-emerald-100";
  if (value === "warned" || value === "shadow_would_block") return "border-amber-500/60 bg-amber-950/30 text-amber-100";
  if (value === "telemetry_only" || value === "detected_only") return "border-sky-500/50 bg-sky-950/25 text-sky-100";
  if (value === "external_required" || value === "external_action_triggered") {
    return "border-violet-500/60 bg-violet-950/30 text-violet-100";
  }
  return "border-slate-700 bg-slate-900/70 text-slate-200";
}

function nodeTone(type: string): string {
  if (type.includes("agent")) return "border-brand-500/45 bg-brand-950/20";
  if (type.includes("mcp") || type === "tool") return "border-cyan-500/40 bg-cyan-950/20";
  if (type === "data_source" || type === "repo") return "border-amber-500/40 bg-amber-950/20";
  if (type === "saas_app" || type === "api") return "border-violet-500/40 bg-violet-950/20";
  if (type === "evidence_bundle") return "border-emerald-500/40 bg-emerald-950/20";
  return "border-slate-700 bg-slate-950/60";
}

function scoreTone(value: number): string {
  if (value >= 0.75) return "text-rose-200";
  if (value >= 0.45) return "text-amber-200";
  return "text-emerald-200";
}

function badgeClass(severity?: string | null): string {
  const value = String(severity || "").toLowerCase();
  if (value === "critical") return "border-rose-400/70 bg-rose-950/35 text-rose-100";
  if (value === "high") return "border-orange-400/70 bg-orange-950/35 text-orange-100";
  if (value === "medium") return "border-amber-400/60 bg-amber-950/30 text-amber-100";
  return "border-slate-700 bg-slate-900/70 text-slate-200";
}

function formatLabel(value?: string | null): string {
  return String(value || "unknown").replaceAll("_", " ");
}

function percent(value: number): string {
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

function deriveEvidenceSummary(edges: AgentTouchpointEdge[]): AgentTouchpointEvidenceSummary {
  const edgesWithEvidence = edges.filter((edge) => edge.evidence_bundle_id).length;
  return {
    total_edges: edges.length,
    edges_with_evidence: edgesWithEvidence,
    missing_evidence: Math.max(0, edges.length - edgesWithEvidence),
    completeness_score: edges.length ? edgesWithEvidence / edges.length : 0,
  };
}

function deriveRiskBadges(edges: AgentTouchpointEdge[]): AgentTouchpointRiskBadge[] {
  const badges: AgentTouchpointRiskBadge[] = [];
  if (edges.some((edge) => ["high", "critical"].includes(String(edge.risk_level || "").toLowerCase()) && ["mcp_tool", "tool"].includes(edge.target_node_type))) {
    badges.push({ id: "high_risk_tool_action", label: "High-risk tool action", severity: "critical" });
  }
  if (edges.some((edge) => edge.control_mode === "inline_prevented")) {
    badges.push({ id: "inline_prevention", label: "Inline prevention observed", severity: "high" });
  }
  if (edges.some((edge) => edge.control_mode === "external_required")) {
    badges.push({ id: "external_enforcement_required", label: "External enforcement required", severity: "medium" });
  }
  if (edges.some((edge) => edge.target_node_type === "saas_app")) {
    badges.push({ id: "saas_touchpoint", label: "SaaS/admin touchpoint", severity: "medium" });
  }
  if (edges.some((edge) => ["data_source", "repo"].includes(edge.target_node_type))) {
    badges.push({ id: "sensitive_resource_reach", label: "Data or repo reach", severity: "medium" });
  }
  if (edges.some((edge) => !edge.evidence_bundle_id)) {
    badges.push({ id: "incomplete_evidence", label: "Incomplete evidence", severity: "medium" });
  }
  return badges;
}

function deriveTimeline(edges: AgentTouchpointEdge[]): AgentTouchpointTimelineItem[] {
  return edges
    .slice()
    .sort((a, b) => String(a.last_seen_at || "").localeCompare(String(b.last_seen_at || "")))
    .map((edge) => ({
      id: edge.id,
      chain_id: edge.chain_id,
      action_id: edge.action_id,
      event: edge.edge_type,
      source: {
        type: edge.source_node_type,
        id: edge.source_node_id,
      },
      target: {
        type: edge.target_node_type,
        id: edge.target_node_id,
      },
      control_mode: edge.control_mode,
      risk_level: edge.risk_level,
      evidence_bundle_id: edge.evidence_bundle_id,
      evidence_linked: Boolean(edge.evidence_bundle_id),
      last_seen_at: edge.last_seen_at,
    }));
}

function countBy<T extends string>(values: T[]): Record<T, number> {
  return values.reduce(
    (acc, value) => {
      acc[value] = (acc[value] || 0) + 1;
      return acc;
    },
    {} as Record<T, number>,
  );
}

type TouchpointNode = {
  key: string;
  type: string;
  id: string;
  incoming: number;
  outgoing: number;
};

export function buildAgentTouchpointNodes(edges: AgentTouchpointEdge[]): TouchpointNode[] {
  const nodes = new Map<string, TouchpointNode>();
  edges.forEach((edge) => {
    const sourceKey = `${edge.source_node_type}:${edge.source_node_id}`;
    const targetKey = `${edge.target_node_type}:${edge.target_node_id}`;
    const source = nodes.get(sourceKey) || {
      key: sourceKey,
      type: edge.source_node_type,
      id: edge.source_node_id,
      incoming: 0,
      outgoing: 0,
    };
    source.outgoing += 1;
    nodes.set(sourceKey, source);

    const target = nodes.get(targetKey) || {
      key: targetKey,
      type: edge.target_node_type,
      id: edge.target_node_id,
      incoming: 0,
      outgoing: 0,
    };
    target.incoming += 1;
    nodes.set(targetKey, target);
  });
  return Array.from(nodes.values()).sort((a, b) => {
    const ai = NODE_TYPE_ORDER.indexOf(a.type);
    const bi = NODE_TYPE_ORDER.indexOf(b.type);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi) || a.id.localeCompare(b.id);
  });
}

export function AgentTouchpointGraph({
  touchpoints,
  blastRadius,
}: {
  touchpoints: AgentTouchpoints | null;
  blastRadius: AgentBlastRadius | null;
}) {
  const edges = useMemo(() => touchpoints?.edges || [], [touchpoints?.edges]);
  const nodes = useMemo(() => buildAgentTouchpointNodes(edges), [edges]);
  const evidenceSummary = touchpoints?.evidence_summary || deriveEvidenceSummary(edges);
  const riskBadges = touchpoints?.risk_badges?.length ? touchpoints.risk_badges : deriveRiskBadges(edges);
  const timeline = touchpoints?.timeline?.length ? touchpoints.timeline : deriveTimeline(edges);
  const controlModeCounts = useMemo(() => countBy(edges.map((edge) => String(edge.control_mode || "unknown"))), [edges]);
  const highRiskEdgeCount = edges.filter((edge) => ["high", "critical"].includes(String(edge.risk_level || "").toLowerCase())).length;
  const groupedNodes = useMemo(() => {
    const groups = new Map<string, TouchpointNode[]>();
    nodes.forEach((node) => {
      const group = groups.get(node.type) || [];
      group.push(node);
      groups.set(node.type, group);
    });
    return Array.from(groups.entries());
  }, [nodes]);

  const metricCards = [
    { label: "Tools", value: blastRadius ? blastRadius.reachable_tools_count : "Unknown" },
    { label: "MCP Servers", value: blastRadius ? blastRadius.reachable_mcp_servers_count : "Unknown" },
    { label: "SaaS Apps", value: blastRadius ? blastRadius.reachable_saas_apps_count : "Unknown" },
    { label: "Data Sources", value: blastRadius ? blastRadius.reachable_data_sources_count : "Unknown" },
    { label: "External Destinations", value: blastRadius ? blastRadius.external_destinations_count : "Unknown" },
    { label: "Persistent Effects", value: blastRadius ? blastRadius.persistent_side_effects_count : "Unknown" },
    { label: "High Risk Actions", value: blastRadius ? blastRadius.high_risk_actions_count : "Unknown" },
  ];

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[#2a3348] bg-[#0b1220] p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-slate-100">Investigation Summary</p>
            <p className="text-xs text-slate-500">Observed action-chain evidence for this agent, separated from theoretical reach.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {riskBadges.length ? (
              riskBadges.map((badge) => (
                <span key={badge.id} className={cn("rounded-full border px-2.5 py-1 text-xs font-semibold", badgeClass(badge.severity))}>
                  {badge.label}
                </span>
              ))
            ) : (
              <span className="rounded-full border border-emerald-500/50 bg-emerald-950/25 px-2.5 py-1 text-xs font-semibold text-emerald-100">
                No chain risk badges
              </span>
            )}
          </div>
        </div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <div className="rounded-lg border border-[#263149] bg-[#101524] p-3">
            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Observed Edges</p>
            <p className="mt-2 text-2xl font-semibold text-slate-100">{evidenceSummary.total_edges}</p>
          </div>
          <div className="rounded-lg border border-[#263149] bg-[#101524] p-3">
            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Evidence Complete</p>
            <p className={cn("mt-2 text-2xl font-semibold", !evidenceSummary.total_edges || evidenceSummary.completeness_score < 1 ? "text-amber-200" : "text-emerald-200")}>
              {evidenceSummary.total_edges ? percent(evidenceSummary.completeness_score) : "Unknown"}
            </p>
          </div>
          <div className="rounded-lg border border-[#263149] bg-[#101524] p-3">
            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Missing Evidence</p>
            <p className={cn("mt-2 text-2xl font-semibold", evidenceSummary.missing_evidence ? "text-amber-200" : "text-slate-100")}>
              {evidenceSummary.missing_evidence}
            </p>
          </div>
          <div className="rounded-lg border border-[#263149] bg-[#101524] p-3">
            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Inline Prevented</p>
            <p className="mt-2 text-2xl font-semibold text-rose-100">{controlModeCounts.inline_prevented || 0}</p>
          </div>
          <div className="rounded-lg border border-[#263149] bg-[#101524] p-3">
            <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">High/Critical</p>
            <p className="mt-2 text-2xl font-semibold text-orange-100">{highRiskEdgeCount}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Potential Blast Radius</p>
          <p className={cn("mt-2 text-3xl font-semibold", blastRadius ? scoreTone(blastRadius.overall_blast_radius_score) : "text-amber-200")}>
            {blastRadius ? Math.round(blastRadius.overall_blast_radius_score * 100) : "Unknown"}
          </p>
          <p className="mt-1 text-xs text-slate-500">{blastRadius?.snapshot_id ? `snapshot ${shortId(blastRadius.snapshot_id, 18)}` : "No blast-radius response"}</p>
        </div>
        {metricCards.map((card) => (
          <div key={card.label} className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">{card.label}</p>
            <p className="mt-2 text-2xl font-semibold text-slate-100">{card.value}</p>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-[#2a3348] bg-[#0b1220] p-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-sm font-semibold text-slate-100">Observed Touchpoint Graph</p>
            <p className="text-xs text-slate-500">Observed relationships across identity, tools, data, SaaS, and evidence.</p>
          </div>
          <Badge>{`${nodes.length} nodes / ${edges.length} edges`}</Badge>
        </div>

        {nodes.length ? (
          <div className="overflow-x-auto pb-2">
            <div className="flex min-w-max gap-3">
              {groupedNodes.map(([type, group]) => (
                <div key={type} className="w-[230px] shrink-0">
                  <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                    {NODE_LABELS[type] || type.replaceAll("_", " ")}
                  </p>
                  <div className="space-y-2">
                    {group.slice(0, 8).map((node) => (
                      <div key={node.key} className={cn("rounded-lg border p-3", nodeTone(node.type))}>
                        <p className="break-words text-sm font-semibold text-slate-100">{shortId(node.id)}</p>
                        <p className="mt-1 text-xs text-slate-500">{`${node.outgoing} out · ${node.incoming} in`}</p>
                      </div>
                    ))}
                    {group.length > 8 ? (
                      <div className="rounded-lg border border-dashed border-slate-700 px-3 py-2 text-xs text-slate-500">
                        {`+${group.length - 8} more`}
                      </div>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-slate-700 px-4 py-8 text-center text-sm text-slate-500">
            No touchpoint edges have been observed for this agent yet.
          </div>
        )}
      </div>

      <div className="rounded-lg border border-[#2a3348] bg-[#0b1220] p-4">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="text-sm font-semibold text-slate-100">Chain Replay Timeline</p>
            <p className="text-xs text-slate-500">Chronological chain steps from actor to tool, SaaS, data, and evidence.</p>
          </div>
          <Badge>{`${timeline.length} steps`}</Badge>
        </div>
        {timeline.length ? (
          <div className="space-y-2">
            {timeline.slice(0, 10).map((item, index) => (
              <div key={item.id} className="grid gap-3 rounded-lg border border-[#20283a] bg-[#101524] p-3 md:grid-cols-[42px_1.4fr_1fr_1fr]">
                <div className="flex h-8 w-8 items-center justify-center rounded-full border border-brand-500/40 bg-brand-950/25 text-xs font-semibold text-brand-100">
                  {index + 1}
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-100">{formatLabel(item.event)}</p>
                  <p className="mt-1 truncate text-xs text-slate-400">
                    {`${NODE_LABELS[String(item.source.type || "")] || formatLabel(item.source.type)} ${shortId(String(item.source.id || "unknown"), 22)} → ${
                      NODE_LABELS[String(item.target.type || "")] || formatLabel(item.target.type)
                    } ${shortId(String(item.target.id || "unknown"), 22)}`}
                  </p>
                </div>
                <div className="flex flex-wrap items-start gap-2">
                  <span className={cn("rounded-full border px-2 py-0.5 text-xs", modeClass(item.control_mode))}>{item.control_mode || "unknown"}</span>
                  <span className={cn("rounded-full border px-2 py-0.5 text-xs", riskClass(item.risk_level))}>{item.risk_level || "low"}</span>
                </div>
                <div className="flex flex-wrap items-start gap-2 text-xs">
                  {item.chain_id ? (
                    <Link className="rounded-full border border-brand-500/40 px-2 py-0.5 text-brand-100 hover:border-brand-300" href={`/runtime-intelligence/chains/${encodeURIComponent(item.chain_id)}/graph`}>
                      Graph
                    </Link>
                  ) : null}
                  {item.chain_id && item.evidence_linked ? (
                    <Link className="rounded-full border border-emerald-500/40 px-2 py-0.5 text-emerald-100 hover:border-emerald-300" href={`/runtime-intelligence/chains/${encodeURIComponent(item.chain_id)}/evidence`}>
                      Evidence
                    </Link>
                  ) : (
                    <span className="rounded-full border border-slate-700 px-2 py-0.5 text-slate-500">No evidence</span>
                  )}
                </div>
              </div>
            ))}
            {timeline.length > 10 ? <p className="px-1 text-xs text-slate-500">{`Showing 10 of ${timeline.length} steps.`}</p> : null}
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-slate-700 px-4 py-8 text-center text-sm text-slate-500">
            No chain replay is available for this agent yet.
          </div>
        )}
      </div>

      <div className="overflow-hidden rounded-lg border border-[#2a3348]">
        <div className="grid grid-cols-[1.2fr_1.2fr_1fr_1fr] border-b border-[#2a3348] bg-[#101524] px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
          <span>Source → Target</span>
          <span>Relationship</span>
          <span>Mode / Risk</span>
          <span>Evidence</span>
        </div>
        <div className="divide-y divide-[#20283a]">
          {edges.slice(0, 30).map((edge) => (
            <div key={edge.id} className="grid grid-cols-[1.2fr_1.2fr_1fr_1fr] gap-2 px-3 py-3 text-sm">
              <div className="min-w-0">
                <p className="truncate text-slate-100">{shortId(edge.source_node_id, 26)}</p>
                <p className="truncate text-slate-400">{`${edge.source_node_type} → ${edge.target_node_type}`}</p>
                <p className="truncate text-slate-300">{shortId(edge.target_node_id, 26)}</p>
              </div>
              <div className="min-w-0">
                <p className="truncate text-slate-100">{edge.edge_type}</p>
                {edge.chain_id ? (
                  <Link className="text-xs text-brand-200 hover:text-brand-100" href={`/runtime-intelligence/chains/${encodeURIComponent(edge.chain_id)}/graph`}>
                    {`chain ${shortId(edge.chain_id, 22)}`}
                  </Link>
                ) : (
                  <p className="text-xs text-slate-500">no chain</p>
                )}
              </div>
              <div className="flex flex-wrap items-start gap-2">
                <span className={cn("rounded-full border px-2 py-0.5 text-xs", modeClass(edge.control_mode))}>
                  {edge.control_mode || "unknown"}
                </span>
                <span className={cn("rounded-full border px-2 py-0.5 text-xs", riskClass(edge.risk_level))}>
                  {edge.risk_level || "low"}
                </span>
              </div>
              <div className="min-w-0 text-xs">
                {edge.evidence_bundle_id ? (
                  edge.chain_id ? (
                    <Link className="break-all text-emerald-200 hover:text-emerald-100" href={`/runtime-intelligence/chains/${encodeURIComponent(edge.chain_id)}/evidence`}>
                      {shortId(edge.evidence_bundle_id, 26)}
                    </Link>
                  ) : (
                    <span className="break-all text-emerald-200">{shortId(edge.evidence_bundle_id, 26)}</span>
                  )
                ) : (
                  <span className="text-slate-500">not linked</span>
                )}
              </div>
            </div>
          ))}
          {!edges.length ? (
            <div className="px-3 py-6 text-center text-sm text-slate-500">No relationship edges available.</div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
