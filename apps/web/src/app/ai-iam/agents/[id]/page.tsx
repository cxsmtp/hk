"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { ActivityMapGraph } from "@/components/ai-iam/activity-map-graph";
import { ActivityNodePanel } from "@/components/ai-iam/activity-node-panel";
import { ActivityTimeline } from "@/components/ai-iam/activity-timeline";
import { AgentTouchpointGraph } from "@/components/ai-iam/agent-touchpoint-graph";
import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type {
  AgentBlastRadius,
  AgentTouchpoints,
  AIOrchestrationResult,
  AgentDetail,
  RuntimeAgentChain,
  RuntimeTimelineEvent,
} from "@/lib/types";

function formatDate(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function normalizeDecision(value?: string | null): string {
  return String(value || "").trim().toLowerCase();
}

function decisionTone(value?: string | null): "allow" | "warn" | "block" | "other" {
  const decision = normalizeDecision(value);
  if (decision === "allow" || decision === "approved") return "allow";
  if (decision === "block" || decision === "deny" || decision === "denied") return "block";
  if (["warn", "redact", "hold_for_approval", "require_approval", "require_justification"].includes(decision)) return "warn";
  return "other";
}

function riskTone(score: number): "success" | "warning" | "critical" {
  if (score >= 75) return "success";
  if (score >= 50) return "warning";
  return "critical";
}

export default function AgentDetailPage() {
  const params = useParams<{ id: string }>();
  const agentId = String(params?.id || "");

  const [loading, setLoading] = useState(true);
  const [agent, setAgent] = useState<AgentDetail | null>(null);
  const [events, setEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [chain, setChain] = useState<RuntimeAgentChain | null>(null);
  const [touchpoints, setTouchpoints] = useState<AgentTouchpoints | null>(null);
  const [blastRadius, setBlastRadius] = useState<AgentBlastRadius | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [guidanceLoading, setGuidanceLoading] = useState(false);
  const [guidanceResult, setGuidanceResult] = useState<AIOrchestrationResult | null>(null);

  const load = useCallback(async () => {
    if (!agentId) return;
    setLoading(true);
    try {
      const [agentPayload, eventPayload, chainPayload, touchpointPayload, blastRadiusPayload] = await Promise.all([
        api.getAgent(agentId),
        api.runtimeEvents({ agent_id: agentId, page_size: 500 }),
        api.runtimeChainByAgent(agentId),
        api.agentTouchpoints(agentId).catch(() => null),
        api.agentBlastRadius(agentId).catch(() => null),
      ]);
      setAgent(agentPayload);
      setEvents(eventPayload.items || []);
      setChain(chainPayload);
      setTouchpoints(touchpointPayload);
      setBlastRadius(blastRadiusPayload);
      setSelectedNodeId(chainPayload.nodes[0]?.id || null);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load agent dashboard");
      setAgent(null);
      setEvents([]);
      setChain(null);
      setTouchpoints(null);
      setBlastRadius(null);
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    load();
  }, [load]);

  async function generateAgentGuidance() {
    if (!agent?.id) return;
    setGuidanceLoading(true);
    try {
      const result = await api.generateAgentRemediationGuidance(agent.id, {
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
      setGuidanceResult(result);
      toast.success("AI IAM remediation guidance generated.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to generate AI IAM guidance");
    } finally {
      setGuidanceLoading(false);
    }
  }

  const decisionStats = useMemo(() => {
    const out = { allow: 0, warn: 0, block: 0, other: 0 };
    events.forEach((event) => {
      out[decisionTone(event.decision)] += 1;
    });
    return out;
  }, [events]);

  const toolsUsed = useMemo(() => {
    const counts = new Map<string, number>();
    events.forEach((event) => {
      const key = event.tool_name || event.tool_category || event.api_endpoint || event.event_type || "unknown";
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return Array.from(counts.entries())
      .map(([tool, count]) => ({ tool, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15);
  }, [events]);

  const violations = useMemo(
    () =>
      events
        .filter((event) => {
          const tone = decisionTone(event.decision);
          return tone === "block" || tone === "warn";
        })
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
        .slice(0, 20),
    [events]
  );

  const behaviorScore = useMemo(() => {
    if (!events.length) return null;
    const blocks = decisionStats.block;
    const warns = decisionStats.warn;
    const avgRisk = events.reduce((acc, event) => acc + Number(event.risk_score || 0), 0) / events.length;
    const score = 100 - blocks * 12 - warns * 5 - avgRisk * 30;
    return Math.max(0, Math.round(score));
  }, [events, decisionStats.block, decisionStats.warn]);

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="AI IAM"
          title={agent ? `Agent Detail · ${agent.name}` : "Agent Detail"}
          description="Identity, capabilities, runtime behavior, and violations for this agent."
          actions={
            <div className="flex gap-2">
              <Button variant="outline" asChild>
                <Link href="/ai-iam">Back To AI IAM</Link>
              </Button>
              <Button variant="outline" onClick={() => load()}>
                Refresh
              </Button>
            </div>
          }
        />

        <nav
          aria-label="Agent investigation domains"
          className="flex gap-2 overflow-x-auto rounded-xl border border-[#2a3348] bg-[#0b1220] p-2"
        >
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#overview">Overview</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#runtime">Runtime</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#touchpoints">Touchpoints</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#blast-radius">Blast Radius</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#actions">Actions</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#permissions">Permissions</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#policies">Policies</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#findings">Findings</a>
          <a className="whitespace-nowrap rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-[#171d2b] hover:text-white" href="#evidence">Evidence</a>
        </nav>

        <div id="overview" className="scroll-mt-24">
          <KpiStrip
            items={[
              { label: "Behavior Score", value: behaviorScore ?? "Unknown", tone: behaviorScore === null ? "default" : riskTone(behaviorScore), hint: behaviorScore === null ? "No runtime evidence" : "Derived from loaded runtime decisions" },
              { label: "Total Decisions", value: events.length, tone: "info" },
              { label: "Blocked", value: decisionStats.block, tone: decisionStats.block ? "critical" : "default" },
              { label: "Warn/Hold", value: decisionStats.warn, tone: decisionStats.warn ? "warning" : "default" },
              { label: "Tools Used", value: toolsUsed.length, tone: "default" },
            ]}
          />
        </div>

        <PageSection
          title="Reach evidence states"
          description="Configured authority, observed runtime evidence, and simulated validation are kept distinct."
        >
          <div className="grid gap-3 lg:grid-cols-3">
            <div id="permissions" className="scroll-mt-24 rounded-lg border border-[#2a3348] bg-[#0f1218] p-4">
              <p className="text-sm font-semibold text-slate-100">Configured reach</p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                {agent
                  ? `${(agent.action_scope || []).length} actions, ${(agent.tool_registry || []).length} tools, ${(agent.external_system_access || []).length} external systems.`
                  : "Configured authority is unavailable."}
              </p>
            </div>
            <div id="touchpoints" className="scroll-mt-24 rounded-lg border border-[#2a3348] bg-[#0f1218] p-4">
              <p className="text-sm font-semibold text-slate-100">Observed reach</p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                {touchpoints
                  ? `${touchpoints.total_edges} observed touchpoint edges; ${touchpoints.evidence_summary?.missing_evidence || 0} missing evidence links.`
                  : "No observed touchpoint response is available."}
              </p>
            </div>
            <div id="blast-radius" className="scroll-mt-24 rounded-lg border border-amber-500/30 bg-amber-950/10 p-4">
              <p className="text-sm font-semibold text-amber-100">Simulated reach</p>
              <p className="mt-2 text-xs leading-5 text-amber-100/70">
                No simulated reach evidence is present in this response. Potential blast radius below is computed separately and is not presented as a simulation result.
              </p>
            </div>
          </div>
        </PageSection>

        <PageSection title="Identity" description="Agent identity and lifecycle context.">
          {loading ? (
            <p className="text-sm text-slate-400">Loading agent identity...</p>
          ) : agent ? (
            <SimpleTable
              columns={["Attribute", "Value"]}
              rows={[
                ["Agent ID", agent.id],
                ["Status", agent.status],
                ["Type", agent.agent_type || "workflow_agent"],
                ["Autonomy Level", agent.autonomy_level || "medium"],
                ["Description", agent.description || "-"],
                ["Owner Attested", formatDate(agent.owner_attested_at)],
                ["Attestation Expiry", formatDate(agent.owner_attestation_expiry)],
              ]}
            />
          ) : (
            <p className="text-sm text-rose-300">Agent not found.</p>
          )}
        </PageSection>

        <div id="policies" className="scroll-mt-24">
        <PageSection title="Capabilities" description="Allowed scope, inheritance, and external access.">
          {agent ? (
            <div className="grid gap-3 md:grid-cols-3">
              <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Action Scope</p>
                <div className="flex flex-wrap gap-2">
                  {(agent.action_scope || []).length ? (
                    (agent.action_scope || []).map((scope) => <Badge key={scope}>{scope}</Badge>)
                  ) : (
                    <span className="text-xs text-slate-500">No explicit scope set.</span>
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Tool Registry</p>
                <div className="flex flex-wrap gap-2">
                  {(agent.tool_registry || []).length ? (
                    (agent.tool_registry || []).map((tool) => <Badge key={tool}>{tool}</Badge>)
                  ) : (
                    <span className="text-xs text-slate-500">No explicit tool allow-list set.</span>
                  )}
                </div>
              </div>
              <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
                <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Control Limits</p>
                <div className="space-y-1 text-sm text-slate-200">
                  <p>{`Max Chain Depth: ${agent.max_chain_depth}`}</p>
                  <p>{`Capability Inheritance: ${agent.capability_inheritance ? "Enabled" : "Disabled"}`}</p>
                </div>
                <p className="mt-2 text-xs text-slate-500">External Systems</p>
                <div className="mt-1 flex flex-wrap gap-2">
                  {(agent.external_system_access || []).length ? (
                    (agent.external_system_access || []).map((target) => <Badge key={target}>{target}</Badge>)
                  ) : (
                    <span className="text-xs text-slate-500">No external systems listed.</span>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-500">No capability data available.</p>
          )}
        </PageSection>
        </div>

        <PageSection
          title="AI IAM Guidance"
          description="Bounded remediation guidance for least-privilege and agent behavior hardening."
        >
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Button onClick={generateAgentGuidance} disabled={guidanceLoading || !agent}>
                {guidanceLoading ? "Generating..." : "Generate Remediation Guidance"}
              </Button>
              {guidanceResult ? (
                <Button
                  variant="outline"
                  onClick={async () => {
                    try {
                      const ticket = await api.generateAIReasoningTicketPayload(guidanceResult.trace_id, "jira");
                      await window.navigator.clipboard.writeText(ticket.description);
                      toast.success("Jira payload generated (description copied).");
                    } catch (err) {
                      toast.error(err instanceof Error ? err.message : "Failed to generate Jira payload");
                    }
                  }}
                >
                  Generate Jira Payload
                </Button>
              ) : null}
            </div>

            {guidanceResult ? (
              <>
                <div className="grid gap-3 md:grid-cols-3">
                  <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                    <p className="text-xs text-slate-400">Model Route</p>
                    <p className="text-sm font-semibold text-slate-100 break-words">
                      {guidanceResult.provider} / {guidanceResult.model}
                    </p>
                  </div>
                  <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                    <p className="text-xs text-slate-400">Prompt Template</p>
                    <p className="text-sm font-semibold text-slate-100 break-all">{guidanceResult.prompt_template_id}</p>
                  </div>
                  <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
                    <p className="text-xs text-slate-400">Trace ID</p>
                    <p className="text-sm font-semibold text-slate-100 break-all">{guidanceResult.trace_id}</p>
                  </div>
                </div>
                <div className="rounded-xl border border-[#2a3348] bg-[#101524] p-4">
                  <p className="text-sm font-semibold text-slate-100">
                    {guidanceResult.remediation_guidance?.summary || "No summary returned"}
                  </p>
                  <p className="mt-1 text-sm text-slate-300">
                    {guidanceResult.remediation_guidance?.root_cause_hypothesis || "-"}
                  </p>
                  <p className="mt-2 text-xs text-slate-400">
                    Priority: {guidanceResult.remediation_guidance?.priority || "-"} · Confidence:{" "}
                    {typeof guidanceResult.remediation_guidance?.confidence === "number"
                      ? guidanceResult.remediation_guidance.confidence.toFixed(2)
                      : "-"}
                  </p>
                </div>
                <SimpleTable
                  columns={["Step", "Action", "Description", "Approval", "Frameworks"]}
                  rows={(guidanceResult.remediation_guidance?.recommended_steps || []).map((step) => [
                    step.step_order,
                    step.action_type,
                    step.description,
                    step.requires_approval ? "required" : "not_required",
                    step.linked_frameworks.join(", ") || "-",
                  ])}
                />
              </>
            ) : (
              <p className="text-sm text-slate-500">
                Generate guidance to get policy and capability remediation recommendations for this agent.
              </p>
            )}
          </div>
        </PageSection>

        <div id="actions" className="scroll-mt-24">
        <PageSection title="Tools Used" description="Most frequently observed tools/surfaces in runtime activity.">
          <SimpleTable
            columns={["Tool/Surface", "Events"]}
            rows={toolsUsed.map((row) => [row.tool, row.count])}
          />
        </PageSection>
        </div>

        <div id="findings" className="scroll-mt-24">
        <PageSection title="Violations" description="Recent blocked/warned actions for this agent.">
          <SimpleTable
            columns={["Time", "Decision", "Reason", "Event"]}
            rows={violations.map((event) => [
              formatDate(event.created_at),
              event.decision,
              event.reason_code || "-",
              event.event_type,
            ])}
          />
        </PageSection>
        </div>

        <div id="runtime" className="scroll-mt-24">
        <PageSection title="Activity Map" description="Latest chain graph for this agent identity.">
          <div className="mb-3 flex flex-wrap gap-2">
            <Badge>{`chain: ${chain?.chain_id || "-"}`}</Badge>
            <Badge>{`risk: ${Number(chain?.risk_score || 0).toFixed(2)}`}</Badge>
            <Badge>{`events: ${chain?.event_count || 0}`}</Badge>
          </div>
          <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
            <ActivityMapGraph
              graph={chain}
              selectedNodeId={selectedNodeId}
              onSelectedNodeChange={setSelectedNodeId}
            />
            <ActivityNodePanel graph={chain} selectedNodeId={selectedNodeId} />
          </div>
        </PageSection>
        </div>

        <div id="evidence" className="scroll-mt-24">
          <PageSection
            title="Agent Touchpoints & Blast Radius"
            description="Observed reach across agents, MCP tools, Foundry/Copilot surfaces, SaaS apps, data sources, and evidence."
          >
            <AgentTouchpointGraph touchpoints={touchpoints} blastRadius={blastRadius} />
          </PageSection>
        </div>

        <PageSection title="Timeline" description="Detailed decision trail scoped to this agent.">
          <ActivityTimeline
            key={`agent-detail:${agentId}`}
            events={events}
            agents={agent ? [{ id: agent.id, name: agent.name }] : []}
            defaultAgentId={agentId}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
