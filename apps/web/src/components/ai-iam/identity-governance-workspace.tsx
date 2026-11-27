"use client";

import Link from "next/link";
import {
  ArrowRight,
  CheckCircle2,
  FileCheck2,
  Fingerprint,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserRoundCheck,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { DetailDrawer } from "@/components/detail-drawer";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { AIIAMIdentityProfile, AgentIdentity, EnforcementEvent } from "@/lib/types";
import { cn } from "@/lib/utils";

type IdentityGovernanceWorkspaceProps = {
  agents: AgentIdentity[];
  profiles: AIIAMIdentityProfile[];
  events: EnforcementEvent[];
  selectedAgentId: string;
  loadState: OperationalLoadState;
  onSelectAgent: (agentId: string) => void;
};

type InvestigationTab = "overview" | "violations" | "policy" | "evidence";
type WorkspaceView = "identities" | "violations";
type OperationalLoadState = "loading" | "ready" | "stale" | "unavailable";

const INVESTIGATION_TABS: Array<{ id: InvestigationTab; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "violations", label: "Violations" },
  { id: "policy", label: "Policy" },
  { id: "evidence", label: "Evidence" },
];
const VIOLATION_COLORS = ["#fb7185", "#f59e0b", "#38bdf8", "#a78bfa"];

function humanize(value?: string | null): string {
  const normalized = String(value || "").trim();
  return normalized ? normalized.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) : "Unknown";
}

function formatDate(value?: string | null): string {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function eventBelongsToAgent(event: EnforcementEvent, agent: AgentIdentity): boolean {
  if (String(event.actor_type || "").toLowerCase() !== "agent") return false;
  const actorId = String(event.actor_id || "").toLowerCase();
  const agentId = String(agent.id || "").toLowerCase();
  const agentName = String(agent.name || "").toLowerCase();
  return actorId === agentId || actorId === agentName;
}

function isViolation(event: EnforcementEvent): boolean {
  const decision = String(event.final_decision || "").toLowerCase();
  return ["block", "blocked", "deny", "denied", "warn", "warning", "hold_for_approval", "require_approval"].includes(decision);
}

function statusTone(status?: string | null): string {
  const normalized = String(status || "").toLowerCase();
  if (["active", "approved", "healthy"].includes(normalized)) return "border-emerald-400/25 bg-emerald-400/10 text-emerald-200";
  if (["blocked", "isolated", "revoked", "disabled"].includes(normalized)) return "border-rose-400/25 bg-rose-400/10 text-rose-200";
  return "border-amber-400/25 bg-amber-400/10 text-amber-200";
}

export function IdentityGovernanceWorkspace({
  agents,
  profiles,
  events,
  selectedAgentId,
  loadState,
  onSelectAgent,
}: IdentityGovernanceWorkspaceProps) {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [drawerAgentId, setDrawerAgentId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<InvestigationTab>("overview");
  const [workspaceView, setWorkspaceView] = useState<WorkspaceView>("identities");

  const profileByIdentity = useMemo(
    () => new Map(profiles.map((profile) => [profile.identity_id.toLowerCase(), profile])),
    [profiles],
  );
  const eventsByAgent = useMemo(
    () => new Map(agents.map((agent) => [agent.id, events.filter((event) => eventBelongsToAgent(event, agent))])),
    [agents, events],
  );
  const statuses = useMemo(
    () => Array.from(new Set(agents.map((agent) => String(agent.status || "unknown")))).sort(),
    [agents],
  );
  const filteredAgents = useMemo(() => {
    const query = search.trim().toLowerCase();
    return agents.filter((agent) => {
      if (statusFilter !== "all" && String(agent.status || "unknown") !== statusFilter) return false;
      const profile = profileByIdentity.get(agent.id.toLowerCase());
      if (!query) return true;
      return `${agent.name} ${agent.id} ${profile?.owner || ""} ${agent.agent_type || ""}`.toLowerCase().includes(query);
    });
  }, [agents, profileByIdentity, search, statusFilter]);

  const allAgentEvents = useMemo(() => Array.from(eventsByAgent.values()).flat(), [eventsByAgent]);
  const visibleViolations = useMemo(
    () => [...allAgentEvents.filter(isViolation)].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()),
    [allAgentEvents],
  );
  const violationTrend = useMemo(() => {
    const counts = new Map<string, number>();
    visibleViolations.forEach((event) => {
      const date = new Date(event.timestamp);
      if (Number.isNaN(date.getTime())) return;
      const key = date.toISOString().slice(0, 10);
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return Array.from(counts.entries()).sort(([left], [right]) => left.localeCompare(right)).map(([date, value]) => ({
      date,
      label: new Date(`${date}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
      value,
    }));
  }, [visibleViolations]);
  const decisionBreakdown = useMemo(() => {
    const counts = new Map<string, number>();
    visibleViolations.forEach((event) => {
      const decision = String(event.final_decision || "unknown").toLowerCase();
      counts.set(decision, (counts.get(decision) || 0) + 1);
    });
    return Array.from(counts.entries()).map(([decision, value], index) => ({ decision: humanize(decision), value, color: VIOLATION_COLORS[index % VIOLATION_COLORS.length] }));
  }, [visibleViolations]);
  const knownOwners = agents.filter((agent) => Boolean(profileByIdentity.get(agent.id.toLowerCase())?.owner?.trim())).length;
  const violationCount = allAgentEvents.filter(isViolation).length;
  const evidenceLinkedCount = allAgentEvents.filter((event) => Boolean(event.evidence_nodes_created?.length)).length;
  const metricValue = (value: number) => loadState === "loading" ? "Loading" : loadState === "unavailable" ? "Unknown" : value;

  const drawerAgent = agents.find((agent) => agent.id === drawerAgentId) || null;
  const drawerProfile = drawerAgent ? profileByIdentity.get(drawerAgent.id.toLowerCase()) || null : null;
  const drawerEvents = drawerAgent
    ? [...(eventsByAgent.get(drawerAgent.id) || [])].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    : [];
  const drawerViolations = drawerEvents.filter(isViolation);
  const evidenceIds = Array.from(new Set(drawerEvents.flatMap((event) => event.evidence_nodes_created || []).filter(Boolean)));
  const latestObservedAt = drawerEvents[0]?.timestamp;

  function inspectAgent(agentId: string) {
    onSelectAgent(agentId);
    setDrawerAgentId(agentId);
    setActiveTab("overview");
  }

  function inspectViolation(event: EnforcementEvent) {
    const actorId = String(event.actor_id || "").toLowerCase();
    const agent = agents.find((item) => item.id.toLowerCase() === actorId || item.name.toLowerCase() === actorId);
    if (!agent) return;
    onSelectAgent(agent.id);
    setDrawerAgentId(agent.id);
    setActiveTab("violations");
  }

  return (
    <section className="min-w-0 max-w-full overflow-hidden rounded-xl border border-[#2a3348] bg-[#0a0f17] shadow-[0_18px_60px_rgba(0,0,0,.2)]" aria-labelledby="identity-governance-title">
      <header className="border-b border-[#283247] bg-[#101620] px-4 py-5 md:px-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-orange-300">Identity → violation → control → proof</p>
            <h2 id="identity-governance-title" className="mt-2 text-xl font-semibold text-slate-50">Agent Identity Governance</h2>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-400">
              See who owns each AI identity, what it can reach, where policy intervened, and which decisions have linked evidence.
            </p>
          </div>
          <Button asChild variant="outline">
            <Link href="/protect">Open Policy Builder <ArrowRight className="ml-2 h-4 w-4" aria-hidden="true" /></Link>
          </Button>
        </div>
      </header>

      {loadState === "unavailable" ? (
        <div role="status" className="border-b border-amber-400/20 bg-amber-400/[0.05] px-4 py-3 text-xs text-amber-200 md:px-6">Identity data is unavailable. Hawk is not interpreting a failed request as an empty tenant.</div>
      ) : loadState === "stale" ? (
        <div role="status" className="border-b border-amber-400/20 bg-amber-400/[0.05] px-4 py-3 text-xs text-amber-200 md:px-6">Showing the last successful identity snapshot while live refresh is unavailable.</div>
      ) : null}

      <div className="grid grid-cols-2 border-b border-[#283247] xl:grid-cols-4">
        {[
          { label: "Identities", value: metricValue(agents.length), icon: Fingerprint, tone: loadState === "unavailable" ? "text-amber-300" : "text-cyan-300" },
          { label: "Known owners", value: metricValue(knownOwners), icon: UserRoundCheck, tone: loadState === "unavailable" ? "text-amber-300" : knownOwners === agents.length && agents.length ? "text-emerald-300" : "text-amber-300" },
          { label: "Violations", value: metricValue(violationCount), icon: ShieldAlert, tone: loadState === "unavailable" ? "text-amber-300" : violationCount ? "text-rose-300" : "text-emerald-300" },
          { label: "Evidence-linked actions", value: metricValue(evidenceLinkedCount), icon: FileCheck2, tone: loadState === "unavailable" ? "text-amber-300" : evidenceLinkedCount ? "text-emerald-300" : "text-amber-300" },
        ].map(({ label, value, icon: Icon, tone }, index) => (
          <div key={label} className={cn("border-[#283247] p-4", index < 2 && "border-b xl:border-b-0", index % 2 === 0 && "border-r", (index === 1 || index === 2) && "xl:border-r")}>
            <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.12em] text-slate-500">
              <Icon className={cn("h-3.5 w-3.5", tone)} aria-hidden="true" />
              {label}
            </div>
            <p className="mt-2 text-2xl font-semibold text-slate-100">{value}</p>
          </div>
        ))}
      </div>

      <nav aria-label="AI identity workspace views" className="flex items-center gap-1 border-b border-[#283247] bg-[#0b1018] px-4 py-2 md:px-6">
        <button
          type="button"
          onClick={() => setWorkspaceView("identities")}
          className={cn("rounded-md px-3 py-2 text-xs font-semibold transition", workspaceView === "identities" ? "bg-orange-400/10 text-orange-200" : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200")}
        >Identities</button>
        <button
          type="button"
          onClick={() => setWorkspaceView("violations")}
          className={cn("rounded-md px-3 py-2 text-xs font-semibold transition", workspaceView === "violations" ? "bg-orange-400/10 text-orange-200" : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200")}
        >Violations</button>
        <Link href="/protect" className="rounded-md px-3 py-2 text-xs font-semibold text-slate-500 transition hover:bg-white/[0.04] hover:text-slate-200">Policies</Link>
      </nav>
      <div role="status" className="border-b border-[#283247] bg-[#0d121b] px-4 py-3 text-xs leading-5 text-slate-500 md:px-6">
        Permission detail and emergency controls are unavailable in this summary when the source does not provide them. Technical controls remain in Advanced AI IAM tools below.
      </div>

      {workspaceView === "identities" ? <>
      <div className="flex flex-col gap-3 border-b border-[#283247] bg-[#0d121b] p-4 md:flex-row md:items-center md:justify-between">
        <div className="relative w-full md:max-w-md">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" aria-hidden="true" />
          <Input value={search} onChange={(event) => setSearch(event.target.value)} className="pl-9" placeholder="Search identity, owner, or type" aria-label="Search identities" />
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-500">
          Status
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="h-10 rounded-md border border-[#303a50] bg-[#0b1018] px-3 text-sm text-slate-200 outline-none focus:border-orange-400/60"
          >
            <option value="all">All statuses</option>
            {statuses.map((status) => <option key={status} value={status}>{humanize(status)}</option>)}
          </select>
        </label>
      </div>

      <div className="divide-y divide-[#20293a] md:hidden">
        {filteredAgents.map((agent) => {
          const profile = profileByIdentity.get(agent.id.toLowerCase());
          const agentEvents = [...(eventsByAgent.get(agent.id) || [])].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
          const violations = agentEvents.filter(isViolation).length;
          const permissions = profile?.permissions;
          const authorityCount = permissions
            ? permissions.actions.length + permissions.tools.length + permissions.data.length
            : loadState === "ready" ? (agent.action_scope?.length || 0) + (agent.tool_registry?.length || 0) + (agent.external_system_access?.length || 0) : "Unavailable";
          return (
            <article key={`${agent.id}:mobile`} className={cn("space-y-4 p-4", selectedAgentId === agent.id && "bg-orange-400/[0.035]")}>
              <div className="flex min-w-0 items-start justify-between gap-3">
                <button type="button" onClick={() => inspectAgent(agent.id)} className="min-w-0 text-left">
                  <span className="block truncate text-sm font-semibold text-slate-100">{agent.name}</span>
                  <span className="mt-1 block truncate font-mono text-[10px] text-slate-600">{agent.id}</span>
                </button>
                <Badge className={cn("shrink-0 rounded-sm font-mono text-[9px] uppercase", statusTone(agent.status))}>{humanize(agent.status)}</Badge>
              </div>
              <dl className="grid grid-cols-2 gap-3 text-xs">
                <div><dt className="text-slate-600">Owner</dt><dd className={cn("mt-1 truncate", profile?.owner?.trim() ? "text-slate-300" : "font-medium text-amber-200")}>{profile?.owner?.trim() || "Unknown owner"}</dd></div>
                <div><dt className="text-slate-600">Permission detail</dt><dd className="mt-1 font-semibold text-slate-200">{authorityCount === "Unavailable" ? "Unavailable" : `${authorityCount} scopes`}</dd></div>
                <div><dt className="text-slate-600">Violations</dt><dd className={cn("mt-1 font-semibold", violations ? "text-rose-200" : "text-emerald-200")}>{violations}</dd></div>
                <div><dt className="text-slate-600">Last observed</dt><dd className="mt-1 text-slate-300">{formatDate(agentEvents[0]?.timestamp)}</dd></div>
              </dl>
              <Button type="button" variant="outline" size="sm" onClick={() => inspectAgent(agent.id)} className="w-full">
                Inspect identity <ArrowRight className="ml-2 h-3.5 w-3.5" aria-hidden="true" />
              </Button>
            </article>
          );
        })}
      </div>

      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[940px] text-left">
          <thead className="border-b border-[#283247] bg-[#0c1119] text-[10px] uppercase tracking-[0.12em] text-slate-600">
            <tr>
              <th className="px-4 py-3 font-semibold md:px-6">Identity</th>
              <th className="px-4 py-3 font-semibold">Owner</th>
              <th className="px-4 py-3 font-semibold">Permission detail</th>
              <th className="px-4 py-3 font-semibold">Violations</th>
              <th className="px-4 py-3 font-semibold">Last observed</th>
              <th className="px-4 py-3 font-semibold"><span className="sr-only">Action</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#20293a]">
            {filteredAgents.map((agent) => {
              const profile = profileByIdentity.get(agent.id.toLowerCase());
              const agentEvents = [...(eventsByAgent.get(agent.id) || [])].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
              const violations = agentEvents.filter(isViolation).length;
              const permissions = profile?.permissions;
              const authorityCount = permissions
                ? permissions.actions.length + permissions.tools.length + permissions.data.length
                : loadState === "ready" ? (agent.action_scope?.length || 0) + (agent.tool_registry?.length || 0) + (agent.external_system_access?.length || 0) : "Unavailable";
              return (
                <tr key={agent.id} className={cn("transition hover:bg-white/[0.025]", selectedAgentId === agent.id && "bg-orange-400/[0.035]")}>
                  <td className="px-4 py-4 md:px-6">
                    <button type="button" onClick={() => inspectAgent(agent.id)} className="text-left">
                      <span className="block text-sm font-semibold text-slate-100 hover:text-orange-200">{agent.name}</span>
                      <span className="mt-1 block font-mono text-[10px] text-slate-600">{agent.id}</span>
                    </button>
                    <div className="mt-2 flex items-center gap-2">
                      <Badge className={cn("rounded-sm font-mono text-[9px] uppercase", statusTone(agent.status))}>{humanize(agent.status)}</Badge>
                      <span className="text-[10px] text-slate-600">{humanize(profile?.type || agent.agent_type || "agent")}</span>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-sm text-slate-300">
                    {profile?.owner?.trim() || <span className="font-medium text-amber-200">Unknown owner</span>}
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-sm font-semibold text-slate-200">{authorityCount}</span>
                    {authorityCount !== "Unavailable" ? <span className="ml-1 text-xs text-slate-600">scopes</span> : null}
                  </td>
                  <td className="px-4 py-4">
                    <span className={cn("text-sm font-semibold", violations ? "text-rose-200" : "text-emerald-200")}>{violations}</span>
                  </td>
                  <td className="px-4 py-4 text-xs text-slate-400">{formatDate(agentEvents[0]?.timestamp)}</td>
                  <td className="px-4 py-4 text-right">
                    <Button type="button" variant="ghost" size="sm" onClick={() => inspectAgent(agent.id)}>
                      Investigate <ArrowRight className="ml-2 h-3.5 w-3.5" aria-hidden="true" />
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!filteredAgents.length ? (
          <div className="p-8 text-center text-sm text-slate-500">{loadState === "unavailable" ? "Identity data is unavailable." : loadState === "loading" ? "Loading identities…" : "No identities match the current filters."}</div>
        ) : null}
      </div>
      </> : null}

      {workspaceView === "violations" ? (
        <div className="min-h-[24rem]">
          <div className="flex flex-col gap-2 border-b border-[#283247] bg-[#0d121b] p-4 md:flex-row md:items-end md:justify-between md:px-6">
            <div>
              <p className="text-sm font-semibold text-slate-100">Observed policy interventions</p>
              <p className="mt-1 text-xs text-slate-500">Warn, block, deny, and approval-hold decisions from the loaded enforcement window.</p>
            </div>
            <p className="text-xs tabular-nums text-slate-500">{loadState === "unavailable" ? "Unknown" : `${visibleViolations.length} observed`}</p>
          </div>
          <div className="grid gap-3 border-b border-[#283247] p-4 lg:grid-cols-3 md:p-6">
            <section className="rounded-lg border border-[#293348] bg-[#101620] p-4 lg:col-span-2" aria-labelledby="violation-trend-title">
              <div><h3 id="violation-trend-title" className="text-xs font-semibold text-slate-200">Violations over time</h3><p className="mt-1 text-[10px] text-slate-600">Observed enforcement decisions in the loaded window.</p></div>
              {violationTrend.length ? (
                <div className="mt-4 h-48" role="img" aria-label={`${visibleViolations.length} observed violations across ${violationTrend.length} dates`}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={violationTrend} margin={{ top: 8, right: 8, bottom: 0, left: -24 }}>
                      <CartesianGrid stroke="#263244" strokeDasharray="3 5" vertical={false} />
                      <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={{ stroke: "#334155" }} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ background: "#0b111a", border: "1px solid #263044", borderRadius: 8, fontSize: 11 }} />
                      <Area type="monotone" dataKey="value" name="Violations" stroke="#fb7185" fill="#fb7185" fillOpacity={0.12} strokeWidth={2} dot={{ r: 3, fill: "#fb7185", stroke: "#101620", strokeWidth: 2 }} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : <div className="mt-4 grid h-48 place-items-center rounded-md border border-dashed border-white/[0.08] text-xs text-slate-600">{loadState === "unavailable" ? "Violation data is unavailable." : "No violation trend is available."}</div>}
            </section>
            <section className="rounded-lg border border-[#293348] bg-[#101620] p-4" aria-labelledby="decision-breakdown-title">
              <div><h3 id="decision-breakdown-title" className="text-xs font-semibold text-slate-200">Decisions</h3><p className="mt-1 text-[10px] text-slate-600">Distribution by observed decision.</p></div>
              {decisionBreakdown.length ? (
                <div className="mt-3 h-48" role="img" aria-label={`Decision distribution across ${visibleViolations.length} observed violations`}><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={decisionBreakdown} dataKey="value" nameKey="decision" innerRadius={40} outerRadius={62} paddingAngle={3} stroke="none">{decisionBreakdown.map((item) => <Cell key={item.decision} fill={item.color} />)}</Pie><Tooltip contentStyle={{ background: "#0b111a", border: "1px solid #263044", borderRadius: 8, fontSize: 11 }} /><Legend verticalAlign="bottom" iconType="circle" wrapperStyle={{ fontSize: 10, color: "#94a3b8" }} /></PieChart></ResponsiveContainer></div>
              ) : <div className="mt-4 grid h-48 place-items-center rounded-md border border-dashed border-white/[0.08] text-xs text-slate-600">{loadState === "unavailable" ? "Violation data is unavailable." : "No decision distribution is available."}</div>}
            </section>
          </div>
          <div className="divide-y divide-[#20293a] md:hidden">
            {visibleViolations.map((event) => (
              <article key={`${event.id}:violation-mobile`} className="space-y-3 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-100">{humanize(event.final_decision)}</p><p className="mt-1 truncate text-xs text-slate-500">{event.tool_name || event.api_endpoint || "Unknown action surface"}</p></div>
                  <Badge className={cn("rounded-sm font-mono text-[9px] uppercase", statusTone(event.final_decision))}>{humanize(event.final_decision)}</Badge>
                </div>
                <dl className="grid grid-cols-2 gap-3 text-xs">
                  <div><dt className="text-slate-600">Identity</dt><dd className="mt-1 truncate text-slate-300">{event.actor_id || "Unknown"}</dd></div>
                  <div><dt className="text-slate-600">Policy</dt><dd className="mt-1 truncate text-slate-300">{event.policy_version_id || "Unknown"}</dd></div>
                  <div><dt className="text-slate-600">Observed</dt><dd className="mt-1 text-slate-300">{formatDate(event.timestamp)}</dd></div>
                  <div><dt className="text-slate-600">Evidence</dt><dd className="mt-1 text-slate-300">{event.evidence_nodes_created?.length || 0} linked</dd></div>
                </dl>
                <Button type="button" variant="outline" size="sm" className="w-full" onClick={() => inspectViolation(event)}>Investigate violation</Button>
              </article>
            ))}
          </div>
          <div className="hidden overflow-x-auto md:block">
            <table className="w-full min-w-[900px] text-left">
              <thead className="border-b border-[#283247] bg-[#0c1119] text-[10px] uppercase tracking-[0.12em] text-slate-600"><tr><th className="px-6 py-3 font-semibold">Decision</th><th className="px-4 py-3 font-semibold">Identity</th><th className="px-4 py-3 font-semibold">Action surface</th><th className="px-4 py-3 font-semibold">Policy</th><th className="px-4 py-3 font-semibold">Evidence</th><th className="px-4 py-3 font-semibold">Observed</th><th className="px-6 py-3"><span className="sr-only">Action</span></th></tr></thead>
              <tbody className="divide-y divide-[#20293a]">
                {visibleViolations.map((event) => (
                  <tr key={event.id} className="transition hover:bg-white/[0.025]">
                    <td className="px-6 py-4"><Badge className={cn("rounded-sm font-mono text-[9px] uppercase", statusTone(event.final_decision))}>{humanize(event.final_decision)}</Badge></td>
                    <td className="px-4 py-4 text-sm font-medium text-slate-200">{event.actor_id || "Unknown"}</td>
                    <td className="px-4 py-4 text-xs text-slate-400">{event.tool_name || event.api_endpoint || "Unknown"}</td>
                    <td className="px-4 py-4 max-w-48 truncate text-xs text-slate-400">{event.policy_version_id || "Unknown"}</td>
                    <td className="px-4 py-4 text-xs text-slate-300">{event.evidence_nodes_created?.length || 0} linked</td>
                    <td className="px-4 py-4 text-xs text-slate-400">{formatDate(event.timestamp)}</td>
                    <td className="px-6 py-4 text-right"><Button type="button" variant="ghost" size="sm" onClick={() => inspectViolation(event)}>Investigate <ArrowRight className="ml-2 h-3.5 w-3.5" /></Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!visibleViolations.length ? <div className="p-10 text-center text-sm text-slate-500">{loadState === "unavailable" ? "Violation data is unavailable." : "No policy violations were observed in the loaded telemetry window."}</div> : null}
        </div>
      ) : null}

      <DetailDrawer
        open={Boolean(drawerAgent)}
        title={drawerAgent?.name || "AI identity"}
        subtitle={drawerAgent ? `${humanize(drawerProfile?.type || drawerAgent.agent_type || "agent")} · ${humanize(drawerAgent.status)}` : undefined}
        onClose={() => setDrawerAgentId(null)}
      >
        {drawerAgent ? (
          <div className="space-y-5">
            <div role="tablist" aria-label="AI identity investigation tabs" className="flex flex-wrap gap-1 border-b border-[#283247] pb-2">
              {INVESTIGATION_TABS.map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    "shrink-0 rounded-md px-3 py-2 text-xs font-semibold transition",
                    activeTab === tab.id ? "bg-orange-400/10 text-orange-200" : "text-slate-500 hover:bg-white/5 hover:text-slate-200",
                  )}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {activeTab === "overview" ? (
              <div role="tabpanel" className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  {[
                    ["Accountable owner", drawerProfile?.owner?.trim() || "Unknown owner"],
                    ["Identity status", humanize(drawerAgent.status)],
                    ["Last observed", formatDate(latestObservedAt)],
                    ["Model", drawerProfile?.model || "Unknown"],
                    ["Environment", drawerProfile?.environment?.join(", ") || "Unknown"],
                    ["Autonomy", humanize(drawerAgent.autonomy_level)],
                  ].map(([label, value]) => (
                    <div key={label} className="border border-[#293348] bg-[#101620] p-3">
                      <p className="text-[10px] uppercase tracking-[0.1em] text-slate-600">{label}</p>
                      <p className={cn("mt-2 break-words text-sm font-medium", value.startsWith("Unknown") ? "text-amber-200" : "text-slate-200")}>{value}</p>
                    </div>
                  ))}
                </div>
                <div className="border border-[#293348] bg-[#101620] p-4">
                  <p className="text-xs font-semibold text-slate-200">Authority path</p>
                  <div className="mt-3 grid gap-3 sm:grid-cols-3">
                    <div><p className="text-[10px] text-slate-600">Tools</p><p className="mt-1 text-sm text-slate-300">{drawerProfile?.permissions.tools.length ?? drawerAgent.tool_registry?.length ?? 0}</p></div>
                    <div><p className="text-[10px] text-slate-600">Data</p><p className="mt-1 text-sm text-slate-300">{drawerProfile?.permissions.data.length ?? drawerAgent.external_system_access?.length ?? 0}</p></div>
                    <div><p className="text-[10px] text-slate-600">Actions</p><p className="mt-1 text-sm text-slate-300">{drawerProfile?.permissions.actions.length ?? drawerAgent.action_scope?.length ?? 0}</p></div>
                  </div>
                </div>
                <Button asChild variant="outline">
                  <Link href={`/ai-iam/agents/${encodeURIComponent(drawerAgent.id)}`}>Open full identity detail</Link>
                </Button>
              </div>
            ) : null}

            {activeTab === "violations" ? (
              <div role="tabpanel" className="space-y-3">
                {drawerViolations.length ? drawerViolations.map((event) => (
                  <article key={event.id} className="border border-[#293348] bg-[#101620] p-4">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-slate-100">{humanize(event.final_decision)}</p>
                        <p className="mt-1 text-xs text-slate-500">{event.tool_name || event.api_endpoint || "Unknown action surface"}</p>
                      </div>
                      <Badge className={cn("rounded-sm font-mono text-[9px] uppercase", statusTone(event.final_decision))}>{humanize(event.final_decision)}</Badge>
                    </div>
                    <dl className="mt-4 grid gap-2 text-xs sm:grid-cols-2">
                      <div><dt className="text-slate-600">Policy</dt><dd className="mt-1 break-all text-slate-300">{event.policy_version_id || "Unknown"}</dd></div>
                      <div><dt className="text-slate-600">Observed</dt><dd className="mt-1 text-slate-300">{formatDate(event.timestamp)}</dd></div>
                      <div><dt className="text-slate-600">Correlation</dt><dd className="mt-1 break-all text-slate-300">{event.correlation_id || "Unknown"}</dd></div>
                      <div><dt className="text-slate-600">Evidence</dt><dd className="mt-1 text-slate-300">{event.evidence_nodes_created?.length || 0} linked</dd></div>
                    </dl>
                  </article>
                )) : (
                  <div className="border border-dashed border-[#33405a] p-5 text-sm text-slate-500">No violations were observed in the loaded telemetry window.</div>
                )}
              </div>
            ) : null}

            {activeTab === "policy" ? (
              <div role="tabpanel" className="space-y-4">
                <div className="border border-[#293348] bg-[#101620] p-4">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-100"><ShieldCheck className="h-4 w-4 text-emerald-300" aria-hidden="true" />Policy assignment</div>
                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    {drawerProfile?.controls.triggered_controls.length
                      ? `${drawerProfile.controls.triggered_controls.length} controls were observed for this identity.`
                      : "No triggered control assignment is present in the loaded identity profile."}
                  </p>
                  {drawerProfile?.controls.triggered_controls.length ? (
                    <div className="mt-3 flex flex-wrap gap-2">{drawerProfile.controls.triggered_controls.map((control) => <Badge key={control}>{control}</Badge>)}</div>
                  ) : null}
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Link href="/protect" className="group border border-[#293348] bg-[#101620] p-4 transition hover:border-orange-400/40">
                    <p className="text-sm font-semibold text-slate-100">Policy</p>
                    <p className="mt-1 text-xs text-slate-500">Open the business-intent builder and scope a governed change.</p>
                    <span className="mt-3 inline-flex items-center text-xs font-semibold text-orange-200">Build policy <ArrowRight className="ml-1 h-3.5 w-3.5" /></span>
                  </Link>
                  <Link href="/simulations" className="group border border-[#293348] bg-[#101620] p-4 transition hover:border-cyan-400/40">
                    <p className="text-sm font-semibold text-slate-100">Simulation</p>
                    <p className="mt-1 text-xs text-slate-500">Validate a control safely before publishing enforcement.</p>
                    <span className="mt-3 inline-flex items-center text-xs font-semibold text-cyan-200">Run validation <ArrowRight className="ml-1 h-3.5 w-3.5" /></span>
                  </Link>
                </div>
              </div>
            ) : null}

            {activeTab === "evidence" ? (
              <div role="tabpanel" className="space-y-3">
                {evidenceIds.length ? evidenceIds.map((evidenceId) => (
                  <Link
                    key={evidenceId}
                    href={`/auditor?evidence_id=${encodeURIComponent(evidenceId)}`}
                    className="flex items-center justify-between gap-3 border border-[#293348] bg-[#101620] p-4 transition hover:border-emerald-400/35"
                  >
                    <span className="min-w-0">
                      <span className="flex items-center gap-2 text-sm font-semibold text-slate-100"><CheckCircle2 className="h-4 w-4 text-emerald-300" aria-hidden="true" />Linked evidence reference</span>
                      <span className="mt-1 block truncate font-mono text-[10px] text-slate-500">{evidenceId}</span>
                    </span>
                    <ArrowRight className="h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
                  </Link>
                )) : (
                  <div className="border border-dashed border-amber-400/25 bg-amber-400/[0.04] p-5">
                    <p className="text-sm font-semibold text-amber-200">No verified evidence</p>
                    <p className="mt-1 text-xs leading-5 text-slate-500">Loaded decisions do not contain an evidence node reference. Hawk does not infer proof from a decision alone.</p>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        ) : null}
      </DetailDrawer>
    </section>
  );
}
