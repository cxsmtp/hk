"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Check, Eye, FileCheck2, Loader2, Plus, Search, ShieldCheck, Sparkles } from "lucide-react";
import { toast } from "sonner";

import { DetailDrawer } from "@/components/detail-drawer";
import { WorkspaceHeader } from "@/components/lifecycle/workspace-header";
import { WorkspaceLinks } from "@/components/lifecycle/workspace-links";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { buildScopedRuleDraft, matchObservedEventAgainstRule } from "@/lib/policy-builder-state";
import type { PolicyPack, PolicyScopedRule, PolicyVersion, RunningPolicyStatus, RuntimeTimelineEvent } from "@/lib/types";
import { cn } from "@/lib/utils";

const STEPS = ["Intent", "Scope", "Action", "Validate", "Publish"] as const;
const TEMPLATES = [
  { id: "mcp-write", title: "MCP write protection", description: "Control write, delete and administrative tools before execution.", surfaces: ["mcp"], actions: ["write", "delete", "admin"] },
  { id: "sensitive-export", title: "Sensitive data export", description: "Prevent customer or regulated data from leaving approved destinations.", surfaces: ["browser", "llm_gateway", "mcp"], actions: ["export", "upload", "send"] },
  { id: "agent-authority", title: "Agent authority boundary", description: "Require approval when an agent exceeds its delegated scope.", surfaces: ["agent", "mcp", "endpoint"], actions: ["tool_call", "admin", "write"] },
  { id: "shadow-ai", title: "Unapproved AI application", description: "Monitor or block unapproved models and applications by user or group.", surfaces: ["browser", "endpoint"], actions: ["prompt", "upload"] },
] as const;
const DEPLOYMENT_METHODS = [
  { value: "browser", label: "Browser Extension", helper: "Observe browser AI activity and inline browser decisions." },
  { value: "mcp", label: "MCP Gateway", helper: "Observe MCP server and tool calls with gateway control evidence." },
  { value: "llm_gateway", label: "LLM Gateway", helper: "Observe provider and model requests through the governed gateway." },
  { value: "endpoint", label: "Endpoint Agent", helper: "Observe device actions where endpoint evidence is supplied." },
] as const;
const ADVANCED_EVENT_CONTEXTS = ["agent", "foundry", "copilot"] as const;

function parseCsv(value: string): string[] {
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
}

export function PolicyBuilder() {
  const [step, setStep] = useState(0);
  const [packs, setPacks] = useState<PolicyPack[]>([]);
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [events, setEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [running, setRunning] = useState<RunningPolicyStatus | null>(null);
  const [packId, setPackId] = useState("");
  const [templateId, setTemplateId] = useState<string>(TEMPLATES[0].id);
  const [surfaces, setSurfaces] = useState<string[]>([...TEMPLATES[0].surfaces]);
  const [users, setUsers] = useState("");
  const [agents, setAgents] = useState("");
  const [tools, setTools] = useState("");
  const [applications, setApplications] = useState("");
  const [domains, setDomains] = useState("");
  const [providers, setProviders] = useState("");
  const [models, setModels] = useState("");
  const [mcpServers, setMcpServers] = useState("");
  const [operations, setOperations] = useState("");
  const [actionTypes, setActionTypes] = useState(TEMPLATES[0].actions.join(", "));
  const [decision, setDecision] = useState<"allow" | "warn" | "require_approval" | "block">("warn");
  const [confirmed, setConfirmed] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [builderOpen, setBuilderOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  useEffect(() => {
    Promise.all([
      api.listPolicyPacks(),
      api.runtimeActivities({ page: 1, page_size: 100 }).catch(() => ({ items: [], total: 0, page: 1, page_size: 100 })),
      api.runningPolicyStatus().catch(() => null),
    ]).then(async ([packPayload, eventPayload, runningPayload]) => {
      setLoadError("");
      const nextPacks = packPayload.items || [];
      setPacks(nextPacks);
      setEvents(eventPayload.items || []);
      setRunning(runningPayload);
      const preferred = nextPacks.find((item) => item.status.toLowerCase() === "active")?.id || nextPacks[0]?.id || "";
      setPackId(preferred);
      if (preferred) {
        const payload = await api.listPolicyVersions(preferred);
        setVersions(payload.items || []);
      }
    }).catch((error) => {
      const message = error instanceof Error ? error.message : "Unable to load policy workspace";
      setLoadError(message);
      toast.error(message);
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!packId) { setVersions([]); return; }
    api.listPolicyVersions(packId).then((payload) => setVersions(payload.items || [])).catch(() => setVersions([]));
  }, [packId]);

  const template = TEMPLATES.find((item) => item.id === templateId) || TEMPLATES[0];
  const userScope = useMemo(() => parseCsv(users), [users]);
  const agentScope = useMemo(() => parseCsv(agents), [agents]);
  const toolScope = useMemo(() => parseCsv(tools), [tools]);
  const applicationScope = useMemo(() => parseCsv(applications), [applications]);
  const domainScope = useMemo(() => parseCsv(domains), [domains]);
  const providerScope = useMemo(() => parseCsv(providers), [providers]);
  const modelScope = useMemo(() => parseCsv(models), [models]);
  const mcpServerScope = useMemo(() => parseCsv(mcpServers), [mcpServers]);
  const operationScope = useMemo(() => parseCsv(operations), [operations]);
  const actionTypeScope = useMemo(() => parseCsv(actionTypes), [actionTypes]);
  const previewRule = useMemo(() => buildScopedRuleDraft({
    ruleId: `${template.id}-preview`,
    userIds: userScope,
    agentIds: agentScope,
    sourceSurfaces: surfaces,
    tools: toolScope,
    actionTypes: actionTypeScope,
    actionOperations: operationScope,
    applications: applicationScope,
    domains: domainScope,
    providers: providerScope,
    models: modelScope,
    mcpServers: mcpServerScope,
    decision,
  }), [actionTypeScope, agentScope, applicationScope, decision, domainScope, modelScope, mcpServerScope, operationScope, providerScope, surfaces, template.id, toolScope, userScope]);
  const observedMatchResults = useMemo(() => events.map((event) => ({
    event,
    result: matchObservedEventAgainstRule({
      user_id: event.user_id,
      agent_id: event.agent_id,
      source_surface: event.source_surface,
      tool_name: event.tool_name,
      action_type: event.action_type,
      operation: typeof event.metadata?.operation === "string" ? event.metadata.operation : undefined,
      application: event.application || (typeof event.metadata?.application === "string" ? event.metadata.application : undefined),
      domain: typeof event.metadata?.domain === "string" ? event.metadata.domain : undefined,
      url: typeof event.metadata?.url === "string" ? event.metadata.url : event.api_endpoint,
      provider: event.provider || (typeof event.metadata?.provider === "string" ? event.metadata.provider : undefined),
      model: event.model || (typeof event.metadata?.model === "string" ? event.metadata.model : undefined),
      mcp_server: typeof event.metadata?.mcp_server === "string" ? event.metadata.mcp_server : undefined,
    }, previewRule),
  })), [events, previewRule]);
  const observedMatches = useMemo(() => observedMatchResults.filter((item) => item.result === "match").map((item) => item.event), [observedMatchResults]);
  const observedUnknown = observedMatchResults.filter((item) => item.result === "unknown").length;
  const observedBlocks = observedMatches.filter((event) => ["block", "deny", "prevent"].includes(String(event.policy_decision || event.decision || "").toLowerCase())).length;
  const observedInterventions = events.filter((event) => ["warn", "block", "blocked", "deny", "denied", "prevent", "require_approval", "hold_for_approval"].includes(String(event.policy_decision || event.decision || "").toLowerCase())).length;
  const activePacks = packs.filter((pack) => pack.status.toLowerCase() === "active").length;
  const runningByPack = useMemo(() => new Map((running?.running_versions || []).map((item) => [item.pack_id, item])), [running]);
  const filteredPacks = useMemo(() => packs.filter((pack) => {
    if (statusFilter !== "all" && pack.status.toLowerCase() !== statusFilter) return false;
    if (!search.trim()) return true;
    const query = search.trim().toLowerCase();
    return `${pack.name} ${pack.description} ${pack.id}`.toLowerCase().includes(query);
  }), [packs, search, statusFilter]);
  const needsEnforcementConfirmation = decision === "block" || decision === "require_approval";

  function openBuilder(targetPackId?: string) {
    if (targetPackId) setPackId(targetPackId);
    setStep(0);
    setConfirmed(false);
    setBuilderOpen(true);
  }

  function chooseTemplate(id: string) {
    const selected = TEMPLATES.find((item) => item.id === id) || TEMPLATES[0];
    setTemplateId(selected.id);
    setSurfaces([...selected.surfaces]);
    setActionTypes(selected.actions.join(", "));
  }

  function toggleSurface(surface: string) {
    setSurfaces((current) => current.includes(surface) ? current.filter((item) => item !== surface) : [...current, surface]);
  }

  async function publish() {
    if (!packId) { toast.error("Select an existing policy pack"); return; }
    const base = [...versions].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0];
    if (!base) { toast.error("The selected pack has no base policy version"); return; }
    if (needsEnforcementConfirmation && !confirmed) { toast.error("Confirm enforcement before publishing"); return; }
    setPublishing(true);
    try {
      const created = await api.createPolicyVersion(packId, {
        version: `lifecycle-${new Date().toISOString().replace(/[:.]/g, "-")}`,
        scope: base.scope,
        enforcement_defaults: { ...base.enforcement_defaults, default_decision: decision === "allow" ? "allow" : decision },
        guardian_contracts: base.guardian_contracts,
      });
      const draftedRule = buildScopedRuleDraft({
        ruleId: `${template.id}-${Date.now()}`,
        priority: decision === "block" ? 10 : 50,
        description: template.description,
        userIds: userScope,
        agentIds: agentScope,
        sourceSurfaces: surfaces,
        tools: toolScope,
      actionTypes: actionTypeScope,
        actionOperations: operationScope,
        applications: applicationScope,
        domains: domainScope,
        providers: providerScope,
        models: modelScope,
        mcpServers: mcpServerScope,
        decision,
        reasonCode: `lifecycle_${template.id.replaceAll("-", "_")}`,
        explanation: `${template.title} created through the reviewed lifecycle policy workflow.`,
        recommendedAction: decision === "block" ? "Use an approved tool or request a scoped exception." : "Review the governed action and its evidence.",
      });
      const rule: PolicyScopedRule = {
        ...draftedRule,
        subjects: { ...draftedRule.subjects, actor_types: ["human", "agent", "service"] },
        metadata: {
          builder: "hawk_lifecycle_v1",
          validation_window: "latest_100_observed_events",
          observed_matches: observedMatches.length,
          validation_is_simulation: false,
        },
      };
      await api.updatePolicyVersionScopedRules(created.id, [rule]);
      const pack = packs.find((item) => item.id === packId);
      if (pack && pack.status.toLowerCase() !== "active") await api.updatePolicyPack(pack.id, { status: "active" });
      toast.success(`Policy ${created.version} published`);
      const payload = await api.listPolicyVersions(packId);
      setVersions(payload.items || []);
      setBuilderOpen(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Policy publish failed");
    } finally {
      setPublishing(false);
    }
  }

  return (
    <div className="space-y-5">
      <WorkspaceHeader
        eyebrow="Policies"
        title="Policies"
        description="Choose what Hawk should allow, warn about, require approval for, or block, then review the evidence before publishing."
        actions={(
          <>
            <Button onClick={() => openBuilder()}><Plus className="mr-2 h-4 w-4" />Create policy</Button>
            <Button asChild variant="outline"><Link href="/policies">Policy library</Link></Button>
          </>
        )}
      />

      <section className="grid overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0f16] divide-y divide-white/[0.07] sm:grid-cols-2 sm:divide-x sm:divide-y-0 xl:grid-cols-4" aria-label="Policy control metrics">
        {[
          ["Total policies", loadError ? "Unknown" : loading ? "Loading" : packs.length, loadError ? "Policy data is unavailable" : "Policy packs returned by the tenant API"],
          ["Active policies", loadError ? "Unknown" : loading ? "Loading" : activePacks, loadError ? "Policy data is unavailable" : "Packs currently marked active"],
          ["Running versions", loadError ? "Unknown" : loading ? "Loading" : running?.running_versions.length ?? "Unknown", loadError ? "Runtime policy status is unavailable" : "Versions reported by runtime status"],
          ["Observed interventions", loadError ? "Unknown" : loading ? "Loading" : observedInterventions, loadError ? "Runtime activity is unavailable" : `Measured in the latest ${events.length} loaded actions`],
        ].map(([label, value, hint]) => (
          <div key={label} className="px-4 py-3.5">
            <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-600">{label}</p>
            <p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">{value}</p>
            <p className="mt-1 text-[10px] text-slate-600">{hint}</p>
          </div>
        ))}
      </section>

      <section className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0f16]" aria-labelledby="policy-catalog-title">
        <header className="flex flex-col gap-3 border-b border-white/[0.07] p-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h2 id="policy-catalog-title" className="text-sm font-semibold text-slate-100">Policies</h2>
            <p className="mt-1 text-xs text-slate-500">Runtime truth comes from the current pack state and running-policy response.</p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="relative block sm:w-72">
              <span className="sr-only">Search policies</span>
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search policies" className="h-10 w-full rounded-lg border border-white/[0.08] bg-black/20 pl-9 pr-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" />
            </label>
            <label>
              <span className="sr-only">Filter policy status</span>
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className="h-10 rounded-lg border border-white/[0.08] bg-[#0b1018] px-3 text-sm text-slate-300 outline-none focus:border-orange-400/30">
                <option value="all">All statuses</option>
                <option value="active">Active</option>
                <option value="draft">Draft</option>
                <option value="retired">Retired</option>
              </select>
            </label>
          </div>
        </header>

        <div className="divide-y divide-white/[0.055] md:hidden">
          {filteredPacks.map((pack) => {
            const runtime = runningByPack.get(pack.id);
            return (
              <article key={`${pack.id}:mobile`} className="space-y-3 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-100">{pack.name}</p><p className="mt-1 line-clamp-2 text-xs text-slate-500">{pack.description || "No description"}</p></div>
                  <span className={cn("rounded-full border px-2 py-1 text-[9px] font-semibold uppercase", pack.status.toLowerCase() === "active" ? "border-emerald-400/20 text-emerald-300" : "border-white/[0.08] text-slate-500")}>{pack.status}</span>
                </div>
                <dl className="grid grid-cols-2 gap-3 text-xs"><div><dt className="text-slate-600">Running version</dt><dd className="mt-1 text-slate-300">{runtime?.version || "Not reported"}</dd></div><div><dt className="text-slate-600">Default decision</dt><dd className="mt-1 capitalize text-slate-300">{runtime?.default_decision || "Unknown"}</dd></div></dl>
                <Button type="button" variant="outline" size="sm" className="w-full" onClick={() => openBuilder(pack.id)}>Build new version</Button>
              </article>
            );
          })}
        </div>

        <div className="hidden overflow-x-auto md:block">
          <table className="w-full min-w-[860px] text-left">
            <thead className="border-b border-white/[0.07] text-[10px] uppercase tracking-[0.12em] text-slate-600"><tr><th className="px-5 py-3 font-semibold">Policy</th><th className="px-4 py-3 font-semibold">Status</th><th className="px-4 py-3 font-semibold">Running version</th><th className="px-4 py-3 font-semibold">Decision</th><th className="px-4 py-3 font-semibold">Runtime</th><th className="px-5 py-3"><span className="sr-only">Action</span></th></tr></thead>
            <tbody className="divide-y divide-white/[0.055]">
              {filteredPacks.map((pack) => {
                const runtime = runningByPack.get(pack.id);
                return (
                  <tr key={pack.id} className="transition hover:bg-white/[0.025]">
                    <td className="px-5 py-4"><p className="text-sm font-semibold text-slate-100">{pack.name}</p><p className="mt-1 max-w-md truncate text-xs text-slate-600">{pack.description || pack.id}</p></td>
                    <td className="px-4 py-4"><span className={cn("inline-flex rounded-full border px-2 py-1 text-[9px] font-semibold uppercase", pack.status.toLowerCase() === "active" ? "border-emerald-400/20 bg-emerald-400/[0.04] text-emerald-300" : "border-white/[0.08] text-slate-500")}>{pack.status}</span></td>
                    <td className="px-4 py-4 text-xs text-slate-300">{runtime?.version || "Not reported"}</td>
                    <td className="px-4 py-4 text-xs capitalize text-slate-300">{runtime?.default_decision || "Unknown"}</td>
                    <td className="px-4 py-4 text-xs text-slate-500">{runtime ? "Running" : "Not reported"}</td>
                    <td className="px-5 py-4 text-right"><Button type="button" variant="ghost" size="sm" onClick={() => openBuilder(pack.id)}>Build version <ArrowRight className="ml-2 h-3.5 w-3.5" /></Button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!filteredPacks.length ? <div className="p-8 text-center text-sm text-slate-500">{loadError ? "Policy data is unavailable. Refresh after restoring API access." : loading ? "Loading policies…" : "No policies match the current filters."}</div> : null}
      </section>

      <DetailDrawer open={builderOpen} onClose={() => setBuilderOpen(false)} title="Create policy" subtitle="Set the scope and decision, review the matching evidence, then publish." size="wide">
        <div className="grid gap-2 sm:grid-cols-5" aria-label="Policy creation steps">
          {STEPS.map((label, index) => (
            <button key={label} type="button" onClick={() => setStep(index)} className={cn("rounded-lg border px-3 py-3 text-left transition", index === step ? "border-orange-400/25 bg-orange-400/[0.07]" : index < step ? "border-emerald-400/15 bg-emerald-400/[0.035]" : "border-white/[0.055] bg-white/[0.015]")}>
              <span className={cn("grid h-6 w-6 place-items-center rounded-full border text-[10px] font-semibold", index < step ? "border-emerald-400/20 text-emerald-300" : index === step ? "border-orange-400/25 text-orange-300" : "border-white/[0.08] text-slate-600")}>{index < step ? <Check className="h-3.5 w-3.5" /> : index + 1}</span>
              <span className="mt-2 block text-xs font-semibold text-slate-200">{label}</span>
            </button>
          ))}
        </div>

        <div className="mt-5 min-h-[24rem] rounded-xl border border-white/[0.06] bg-black/15 p-5 sm:p-6">
          {step === 0 ? (
            <div><p className="text-sm font-semibold text-white">What outcome should Hawk govern?</p><p className="mt-1 text-xs text-slate-500">Templates set a starting scope; every field remains reviewable.</p><div className="mt-5 grid gap-3 md:grid-cols-2">{TEMPLATES.map((item) => <button key={item.id} type="button" onClick={() => chooseTemplate(item.id)} className={cn("rounded-2xl border p-4 text-left transition", templateId === item.id ? "border-orange-400/25 bg-orange-400/[0.06]" : "border-white/[0.06] bg-white/[0.018] hover:bg-white/[0.035]")}><div className="flex items-center gap-2"><Sparkles className={cn("h-4 w-4", templateId === item.id ? "text-orange-300" : "text-slate-600")} /><p className="text-sm font-semibold text-slate-100">{item.title}</p></div><p className="mt-2 text-xs leading-5 text-slate-500">{item.description}</p></button>)}</div></div>
          ) : null}

          {step === 1 ? (
            <div><p className="text-sm font-semibold text-white">Choose where the rule applies</p><p className="mt-1 text-xs text-slate-500">Selectors match exact context values returned on governed paths. A missing context value does not match.</p><div className="mt-5"><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Deployment paths</p><div className="mt-2 grid gap-2 sm:grid-cols-2">{DEPLOYMENT_METHODS.map((item) => <button key={item.value} type="button" onClick={() => toggleSurface(item.value)} className={cn("rounded-xl border p-3 text-left transition", surfaces.includes(item.value) ? "border-orange-400/25 bg-orange-400/[0.07] text-orange-200" : "border-white/[0.07] text-slate-500")}><span className="block text-xs font-semibold">{item.label}</span><span className="mt-1 block text-[10px] leading-4 text-slate-600">{item.helper}</span></button>)}</div></div><details className="mt-4 rounded-xl border border-white/[0.07] bg-white/[0.015]"><summary className="cursor-pointer px-3 py-2.5 text-xs font-semibold text-slate-300">Advanced event source context</summary><div className="border-t border-white/[0.06] px-3 py-3 text-xs text-slate-500">{ADVANCED_EVENT_CONTEXTS.map((item) => <button key={item} type="button" onClick={() => toggleSurface(item)} className={cn("mr-2 rounded-lg border px-2.5 py-1.5 capitalize", surfaces.includes(item) ? "border-orange-400/25 text-orange-200" : "border-white/[0.08] text-slate-500")}>{item}</button>)}<p className="mt-3">These refine event matching and are event context, not installation methods.</p></div></details><div className="mt-5 grid gap-4 md:grid-cols-2"><label className="text-xs text-slate-400">Users<input value={users} onChange={(event) => setUsers(event.target.value)} placeholder="user@bank.com, user-id" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label><label className="text-xs text-slate-400">Agents<input value={agents} onChange={(event) => setAgents(event.target.value)} placeholder="agent-id" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label><label className="text-xs text-slate-400">Applications<input value={applications} onChange={(event) => setApplications(event.target.value)} placeholder="Exact reported name, such as Claude Desktop or ChatGPT" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /><span className="mt-1 block text-[10px] text-slate-600">Use the application name returned on the governed path. If that path does not provide application context, the rule does not match.</span></label><label className="text-xs text-slate-400">Websites / domains<input value={domains} onChange={(event) => setDomains(event.target.value)} placeholder="example.com, sub.example.com" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /><span className="mt-1 block text-[10px] text-slate-600">Hawk normalizes these to hostnames and subdomains; individual URL paths are not separate selectors.</span></label><label className="text-xs text-slate-400">AI providers<input value={providers} onChange={(event) => setProviders(event.target.value)} placeholder="OpenAI, Anthropic" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label><label className="text-xs text-slate-400">Models<input value={models} onChange={(event) => setModels(event.target.value)} placeholder="gpt-5, claude-3" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label><label className="text-xs text-slate-400">MCP servers<input value={mcpServers} onChange={(event) => setMcpServers(event.target.value)} placeholder="repo-server" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label><label className="text-xs text-slate-400">MCP tools<input value={tools} onChange={(event) => setTools(event.target.value)} placeholder="filesystem.write_file" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label><label className="text-xs text-slate-400">Action types<input value={actionTypes} onChange={(event) => setActionTypes(event.target.value)} placeholder="write, export, admin" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label><label className="text-xs text-slate-400">Operations<input value={operations} onChange={(event) => setOperations(event.target.value)} placeholder="read, write" className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-black/20 px-3 text-sm text-slate-200 outline-none placeholder:text-slate-700 focus:border-orange-400/30" /></label></div></div>
          ) : null}

          {step === 2 ? (
            <div><p className="text-sm font-semibold text-white">Choose the pre-action response</p><p className="mt-1 text-xs text-slate-500">Allow records that policy permitted the request; it does not prove execution or success. Approval and block require explicit confirmation before publish.</p><div className="mt-5 grid gap-3 md:grid-cols-2">{[
              ["allow", "Allow", "Permit the request and record the decision. Execution remains a separate outcome."],
              ["warn", "Warn", "Show guidance and record that the user continued."],
              ["require_approval", "Require approval", "Hold the action until an authorized reviewer decides."],
              ["block", "Block", "Prevent the governed action before it reaches the target."],
            ].map(([value, label, description]) => <button key={value} type="button" onClick={() => { setDecision(value as typeof decision); setConfirmed(false); }} className={cn("rounded-2xl border p-4 text-left transition", decision === value ? "border-orange-400/25 bg-orange-400/[0.06]" : "border-white/[0.06] bg-white/[0.018]")}><p className="text-sm font-semibold text-slate-100">{label}</p><p className="mt-2 text-xs leading-5 text-slate-500">{description}</p></button>)}</div></div>
          ) : null}

          {step === 3 ? (
            <div><div className="flex items-center gap-2"><Eye className="h-4 w-4 text-orange-300" /><p className="text-sm font-semibold text-white">Observed impact preview</p></div><p className="mt-2 text-xs leading-5 text-slate-500">This is a runtime-equivalent exact match against the latest {events.length} observed events. It is not a simulation and does not prove that a control will prevent future execution.</p><div className="mt-5 grid gap-3 sm:grid-cols-3">{[["Observed matches", observedMatches.length], ["Previously blocked", observedBlocks], ["Unknown matches", observedUnknown]].map(([label, value]) => <div key={label} className="rounded-2xl border border-white/[0.06] bg-white/[0.018] p-4"><p className="text-[10px] uppercase tracking-[0.14em] text-slate-600">{label}</p><p className="mt-2 text-2xl font-semibold text-white">{value}</p></div>)}</div>{!events.length ? <div className="mt-4 rounded-xl border border-amber-400/15 bg-amber-400/[0.05] p-3 text-xs text-amber-200">No runtime activity was available. Preview remains Unknown and publish will not claim validated coverage.</div> : null}</div>
          ) : null}

          {step === 4 ? (
            <div><div className="flex items-center gap-2"><FileCheck2 className="h-4 w-4 text-orange-300" /><p className="text-sm font-semibold text-white">Review and publish</p></div>{!userScope.length && !agentScope.length && !applicationScope.length && !domainScope.length && !providerScope.length && !modelScope.length && !mcpServerScope.length && !toolScope.length && !actionTypeScope.length && !operationScope.length ? <div className="mt-4 rounded-xl border border-amber-400/20 bg-amber-400/[0.06] p-3 text-xs text-amber-200"><strong>Broad scope:</strong> all matching activity on the selected deployment paths.</div> : null}<div className="mt-5 grid gap-3 md:grid-cols-2">{[["Intent", template.title], ["Deployment paths", surfaces.join(", ") || "None selected"], ["Users", userScope.join(", ") || "All users"], ["Agents", agentScope.join(", ") || "All agents"], ["Applications", applicationScope.join(", ") || "All applications"], ["Websites / domains", domainScope.join(", ") || "All domains"], ["AI providers", providerScope.join(", ") || "All providers"], ["Models", modelScope.join(", ") || "All models"], ["MCP servers", mcpServerScope.join(", ") || "All servers"], ["MCP tools", toolScope.join(", ") || "All tools"], ["Action types", actionTypeScope.join(", ") || "All action types"], ["Operations", operationScope.join(", ") || "All operations"], ["Decision", decision.replaceAll("_", " ")], ["Observed matches", events.length ? observedMatches.length.toString() : "Unknown"], ["Target pack", packs.find((item) => item.id === packId)?.name || "Not selected"]].map(([label, value]) => <div key={label} className="rounded-2xl border border-white/[0.055] bg-white/[0.018] p-3.5"><p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">{label}</p><p className="mt-2 text-sm font-medium capitalize text-slate-200">{value}</p></div>)}</div><label className="mt-5 block text-xs text-slate-400">Policy pack<select value={packId} onChange={(event) => setPackId(event.target.value)} className="mt-2 h-11 w-full rounded-xl border border-white/[0.07] bg-[#0c1016] px-3 text-sm text-slate-200 outline-none"><option value="">Select an existing pack</option>{packs.map((pack) => <option key={pack.id} value={pack.id}>{pack.name} · {pack.status}</option>)}</select></label>{needsEnforcementConfirmation ? <label className="mt-4 flex cursor-pointer items-start gap-3 rounded-xl border border-rose-400/15 bg-rose-400/[0.04] p-3 text-xs text-slate-300"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} className="mt-0.5" /><span><strong className="block text-rose-200">Confirm enforcement</strong>I understand this version can hold or prevent matching actions when the platform is in Enforce mode.</span></label> : null}<Button className="mt-5" onClick={() => void publish()} disabled={publishing || loading || !packId || (needsEnforcementConfirmation && !confirmed)}>{publishing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}Publish policy version</Button></div>
          ) : null}
        </div>

        <div className="mt-5 flex items-center justify-between border-t border-white/[0.07] pt-4">
          <Button variant="outline" disabled={step === 0} onClick={() => setStep((current) => Math.max(0, current - 1))}><ArrowLeft className="mr-2 h-4 w-4" />Back</Button>
          {step < STEPS.length - 1 ? <Button onClick={() => setStep((current) => Math.min(STEPS.length - 1, current + 1))}>Continue to {STEPS[step + 1]}<ArrowRight className="ml-2 h-4 w-4" /></Button> : null}
        </div>
      </DetailDrawer>

      <WorkspaceLinks links={[
        { href: "/maturity", label: "Maturity Curve", description: "Turn evidence-backed usage baselines into reviewed policy rollouts." },
        { href: "/interaction-security", label: "Interaction Security", description: "Review live decisions and per-user controls." },
        { href: "/governance", label: "Governance", description: "Inspect governance status and approval workflows." },
        { href: "/policies", label: "Advanced policies", description: "Manage guardian contracts and fine-grained scoped rules." },
      ]} />
    </div>
  );
}
