"use client";

import { FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { KpiStrip } from "@/components/kpi-strip";
import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { api } from "@/lib/api";
import type {
  PolicyPackCapabilityCoverage,
  PolicyPackFrameworkAtlas,
  PolicyPackFrameworkAtlasItem,
  PolicyPackPlatformDefinition,
  PolicyPackPlatformInstance,
} from "@/lib/types";

const WIZARD_STEPS = [
  "Choose pack",
  "Map scope",
  "Configure & simulate",
  "Review & apply",
];

function csv(value: string): string[] {
  return Array.from(new Set(value.split(",").map((item) => item.trim()).filter(Boolean)));
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : "The policy-pack request could not be completed.";
}

function rolloutNotEnabled(error: unknown): boolean {
  return /policy_pack_platform_not_enabled|tenant_rollout_not_enabled/i.test(message(error));
}

function displayCount(state: "loading" | "loaded" | "error", count: number): string | number {
  if (state === "error") return "Unavailable";
  if (state === "loading") return "…";
  return count;
}

function capabilityTone(value: string): string {
  if (value === "available") return "text-emerald-300";
  if (value === "partial" || value === "unknown") return "text-amber-300";
  return "text-rose-300";
}

export function PolicyPackPlatformWorkspace() {
  const [catalog, setCatalog] = useState<PolicyPackPlatformDefinition[]>([]);
  const [instances, setInstances] = useState<PolicyPackPlatformInstance[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [selected, setSelected] = useState<PolicyPackPlatformDefinition | null>(null);
  const [coverage, setCoverage] = useState<PolicyPackCapabilityCoverage | null>(null);
  const [vertical, setVertical] = useState("");
  const [department, setDepartment] = useState("");
  const [catalogSurface, setCatalogSurface] = useState("");
  const [targetDepartment, setTargetDepartment] = useState("");
  const [surface, setSurface] = useState("browser");
  const [application, setApplication] = useState("");
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [group, setGroup] = useState("");
  const [user, setUser] = useState("");
  const [rollout, setRollout] = useState("DRAFT");
  const [parameters, setParameters] = useState("{}");
  const [disabledTemplates, setDisabledTemplates] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [applying, setApplying] = useState(false);
  const [selectedInstanceId, setSelectedInstanceId] = useState("");
  const [effectiveActor, setEffectiveActor] = useState("");
  const [effective, setEffective] = useState<Record<string, unknown> | null>(null);
  const [updateDefinitionId, setUpdateDefinitionId] = useState("");
  const [updatePreview, setUpdatePreview] = useState<Record<string, unknown> | null>(null);
  const [groupName, setGroupName] = useState("");
  const [groupType, setGroupType] = useState("static");
  const [groupMembers, setGroupMembers] = useState("");
  const [groupResult, setGroupResult] = useState<{ id: string; group_key: string } | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [catalogState, setCatalogState] = useState<"loading" | "loaded" | "error">("loading");
  const [instanceState, setInstanceState] = useState<"loading" | "loaded" | "error">("loading");
  const [frameworkState, setFrameworkState] = useState<"loading" | "loaded" | "error">("loading");
  const [coverageState, setCoverageState] = useState<"loading" | "loaded" | "error">("loading");
  const [wizardStep, setWizardStep] = useState(0);
  const [frameworkAtlas, setFrameworkAtlas] = useState<PolicyPackFrameworkAtlas | null>(null);
  const [frameworkFilter, setFrameworkFilter] = useState("");

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    if (query.get("source") !== "github-repository-control") return;
    const applicationValue = query.get("application");
    const requestedSurfaces = csv(query.get("surface") || "");
    const userValue = query.get("user");
    const groupValue = query.get("group");
    const parameterValue = query.get("parameters");
    if (applicationValue) setApplication(applicationValue);
    if (requestedSurfaces.length) setSurface(requestedSurfaces[0]);
    if (userValue) setUser(userValue);
    if (groupValue) setGroup(groupValue);
    if (parameterValue) {
      try {
        const parsed = JSON.parse(parameterValue);
        if (parsed && !Array.isArray(parsed) && typeof parsed === "object") {
          setParameters(JSON.stringify(parsed, null, 2));
        }
      } catch {
        // Ignore malformed external prefill data; the normal validated form remains available.
      }
    }
    setWizardStep(1);
  }, []);

  async function loadCatalog() {
    const [catalogResult, instanceResult, frameworkResult] = await Promise.allSettled([
      api.listPolicyPackPlatformCatalog({ vertical: vertical || undefined, department_persona: department || undefined, surface: catalogSurface || undefined }),
      api.listPolicyPackPlatformInstances(),
      api.listPolicyPackPlatformFrameworkAtlas(),
    ]);
    setCatalogState(catalogResult.status === "fulfilled" ? "loaded" : "error");
    setInstanceState(instanceResult.status === "fulfilled" ? "loaded" : "error");
    setFrameworkState(frameworkResult.status === "fulfilled" ? "loaded" : "error");
    setUnavailable([catalogResult, instanceResult, frameworkResult].every((result) => result.status === "rejected" && rolloutNotEnabled(result.reason)));
    setCatalog(catalogResult.status === "fulfilled" ? catalogResult.value.items || [] : []);
    setInstances(instanceResult.status === "fulfilled" ? instanceResult.value.items || [] : []);
    setFrameworkAtlas(frameworkResult.status === "fulfilled" ? frameworkResult.value : null);
    if (catalogResult.status === "fulfilled") setSelectedId((current) => current || catalogResult.value.items?.[0]?.id || "");
    if (instanceResult.status === "fulfilled") setSelectedInstanceId((current) => current || instanceResult.value.items?.[0]?.id || "");
  }

  useEffect(() => {
    setLoading(true);
    loadCatalog()
      .catch((error) => {
        setCatalogState("error");
        setInstanceState("error");
        setFrameworkState("error");
        setUnavailable(rolloutNotEnabled(error));
      })
      .finally(() => setLoading(false));
    // The library is deliberately reloaded only when a user changes a filter.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vertical, department, catalogSurface]);

  useEffect(() => {
    if (!selectedId) {
      setSelected(null);
      setCoverage(null);
      setCoverageState("loading");
      return;
    }
    setCoverageState("loading");
    setCoverage(null);
    Promise.all([
      api.getPolicyPackPlatformDefinition(selectedId),
      api.previewPolicyPackPlatformDefinition(selectedId, surface ? [surface] : undefined),
    ])
      .then(([definition, preview]) => {
        setSelected(definition);
        setCoverage(preview.capability_coverage);
        setCoverageState("loaded");
        setDisabledTemplates([]);
      })
      .catch((error) => {
        setCoverage(null);
        setCoverageState("error");
        toast.error(message(error));
      });
  }, [selectedId, surface]);

  const selectedReady = selected?.id === selectedId;
  const frameworkFocus = [
    { id: "rbi-free-ai-2025", label: "RBI FREE-AI" },
    { id: "meity-india-ai-governance-guidelines-2025", label: "MeitY AI Guidelines" },
    { id: "dpdp-act-2023", label: "DPDP" },
    { id: "sebi-ai-ml-reporting-2019", label: "SEBI AI/ML" },
    { id: "imda-agentic-ai-governance-framework-2026", label: "IMDA Agentic AI" },
    { id: "eu-ai-act", label: "EU AI Act" },
    { id: "owasp-genai-llm-top-10-2026", label: "OWASP GenAI" },
    { id: "mitre-atlas", label: "MITRE ATLAS" },
  ];
  const frameworkItems = frameworkAtlas?.items || [];
  const catalogByStableId = new Map(catalog.map((item) => [item.stable_pack_id, item]));
  const catalogByDefinitionId = new Map(catalog.map((item) => [item.id, item]));
  const visibleFrameworkItems = (frameworkFilter
    ? frameworkItems.filter((item) => item.framework_id === frameworkFilter)
    : frameworkItems.filter((item) => {
      const focused = frameworkFocus.some((focus) => focus.id === item.framework_id);
      const mappedToVisiblePack = item.policy_pack_stable_ids.some((stableId) => catalogByStableId.has(stableId));
      const productRelevant = item.policy_pack_stable_ids.some((stableId) => stableId.includes("india") || stableId.includes("agentic"));
      return focused || mappedToVisiblePack || productRelevant;
    })
  ).slice(0, 8);

  function definitionIdForFramework(item: PolicyPackFrameworkAtlasItem): string | null {
    const overlayStableId = item.policy_pack_stable_ids.find((stableId) => catalogByStableId.get(stableId)?.pack_family === "framework_overlay");
    if (overlayStableId) return catalogByStableId.get(overlayStableId)?.id || null;
    const visibleStableId = item.policy_pack_stable_ids.find((stableId) => catalogByStableId.has(stableId));
    if (visibleStableId) return catalogByStableId.get(visibleStableId)?.id || null;
    return item.policy_pack_definition_ids.find((definitionId) => catalogByDefinitionId.has(definitionId)) || item.policy_pack_definition_ids[0] || null;
  }

  function selectFrameworkPack(item: PolicyPackFrameworkAtlasItem) {
    const definitionId = definitionIdForFramework(item);
    if (!definitionId) {
      toast.error("No policy pack is available for this framework mapping.");
      return;
    }
    setSelectedId(definitionId);
    setWizardStep(0);
    toast.success("Framework mapping selected. Preview the pack, simulate, then apply.");
  }

  function nextWizardStep() {
    if (wizardStep === 0 && !selectedReady) {
      toast.error("Select a policy pack before continuing.");
      return;
    }
    if (wizardStep === 2) {
      try {
        const parsed = JSON.parse(parameters || "{}");
        if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("parameters_must_be_object");
      } catch {
        toast.error("Customer parameters must be a JSON object.");
        return;
      }
    }
    setWizardStep((current) => current + 1);
  }

  if (unavailable) {
    return (
      <PageSection title="Policy Packs" description="The Policy Pack platform is available only after tenant rollout is enabled.">
        <p className="text-sm text-slate-400">This tenant has not been enrolled in the Policy Pack platform yet.</p>
      </PageSection>
    );
  }

  async function applyPack(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (wizardStep !== WIZARD_STEPS.length - 1) {
      nextWizardStep();
      return;
    }
    if (!selectedReady || !selected) return;
    let customerParameters: Record<string, unknown>;
    try {
      const parsed = JSON.parse(parameters || "{}");
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("parameters_must_be_object");
      customerParameters = parsed as Record<string, unknown>;
    } catch {
      toast.error("Customer parameters must be a JSON object.");
      return;
    }
    const assignment: Record<string, unknown> = { organization: "all" };
    if (surface) assignment.deployment_surface = csv(surface);
    if (application) assignment.application = csv(application);
    if (provider) assignment.provider = csv(provider);
    if (model) assignment.model = csv(model);
    if (group) assignment.directory_group = csv(group);
    if (user) assignment.user = csv(user);
    if (targetDepartment) assignment.department = csv(targetDepartment);
    setApplying(true);
    try {
      const result = await api.applyPolicyPackPlatformDefinition(selected.id, {
        assignments: [assignment],
        customer_parameters: customerParameters,
        local_overrides: {},
        disabled_template_ids: disabledTemplates,
        added_customer_templates: [],
        requested_state: rollout,
      });
      setInstances((current) => [result.instance, ...current]);
      setSelectedInstanceId(result.instance.id);
      setCoverage(result.capability_coverage);
      toast.success(`${selected.name} is now ${result.instance.state.toLowerCase()}.`);
    } catch (error) {
      toast.error(message(error));
    } finally {
      setApplying(false);
    }
  }

  async function simulate(instanceId: string) {
    try {
      const result = await api.simulatePolicyPackPlatformInstance(instanceId);
      toast.success(`Simulation ${result.status.toLowerCase()}: ${result.sample_count} historical actions evaluated.`);
      await loadCatalog();
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function transition(instanceId: string, target: string) {
    try {
      const result = await api.transitionPolicyPackPlatformInstance(instanceId, target);
      setInstances((current) => current.map((item) => item.id === result.id ? result : item));
      toast.success(`Policy pack moved to ${result.state.toLowerCase()}.`);
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function explainEffective() {
    try {
      const result = await api.policyPackPlatformEffectivePolicy({ actor_user_id: effectiveActor, application, provider, model, source_surface: surface });
      setEffective(result.final);
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function compareUpdate() {
    if (!selectedInstanceId || !updateDefinitionId) return;
    try {
      setUpdatePreview(await api.comparePolicyPackPlatformUpdate(selectedInstanceId, updateDefinitionId));
    } catch (error) {
      toast.error(message(error));
    }
  }

  async function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!groupName.trim()) return;
    try {
      const result = await api.createPolicyPackPlatformGroup({
        group_key: groupName.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
        name: groupName.trim(),
        group_type: groupType,
        membership_rule: {},
        member_user_ids: csv(groupMembers),
        nested_group_ids: [],
      });
      setGroupResult(result);
      setGroup(result.group_key);
      toast.success(`Group ${result.name} is ready for assignment.`);
    } catch (error) {
      toast.error(message(error));
    }
  }

  return (
    <div id="policy-packs" className="space-y-5" data-ui="policy-pack-platform">
      <PageSection title="Policy Packs" description="Choose a reusable baseline, map it to the right people and AI surfaces, then simulate before enforcing.">
        <KpiStrip
          items={[
            { label: "Available packs", value: displayCount(catalogState, catalog.length), tone: "default" },
            { label: "Customer instances", value: displayCount(instanceState, instances.length), tone: instances.length ? "success" : "default" },
            { label: "Verified block surfaces", value: catalogState === "error" ? "Unavailable" : displayCount(coverageState, coverage?.verified_pre_execution_block_surfaces.length ?? 0), tone: coverage?.verified_pre_execution_block_surfaces.length ? "success" : "warning" },
            { label: "Guided stages", value: WIZARD_STEPS.length, tone: "default" },
          ]}
        />
        <div className="mt-4 grid gap-2 md:grid-cols-3">
          <select className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={vertical} onChange={(event) => setVertical(event.target.value)}>
            <option value="">All verticals</option>
            <option value="universal">Universal</option>
            <option value="bfsi">BFSI</option>
            <option value="insurance">Insurance</option>
            <option value="telecom">Telecom</option>
            <option value="payments">Payments</option>
            <option value="real_estate">Real Estate</option>
            <option value="banking">Banking (legacy)</option>
          </select>
          <Input value={department} onChange={(event) => setDepartment(event.target.value)} placeholder="Department or persona" />
          <label className="space-y-1 text-xs text-slate-500"><span>Source or product context</span><select aria-label="Source or product context" className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={catalogSurface} onChange={(event) => setCatalogSurface(event.target.value)}>
            <option value="">All deployment surfaces</option><option value="browser">Browser</option><option value="endpoint">Endpoint</option><option value="runtime">Runtime</option><option value="saas_api">SaaS & APIs</option><option value="mcp_gateway">MCP Gateway</option><option value="provider_native_hook">Provider native hook</option>
          </select></label>
        </div>
        <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4" data-ui="policy-pack-apply-wizard">
          {WIZARD_STEPS.map((step, index) => <div key={step} className={index === wizardStep ? "rounded-md border border-brand-500/70 bg-brand-500/10 px-3 py-2 text-xs text-brand-100" : index < wizardStep ? "rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-xs text-emerald-200" : "rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-400"}><span className="mr-1">{index + 1}.</span>{step}</div>)}
        </div>
      </PageSection>

      <PageSection title="Governance Atlas" description="Start from a governance framework, see mapped controls, then open policy packs, simulations, coverage, and evidence requirements through the same typed workflow.">
        <div className="rounded-md border border-amber-500/25 bg-amber-500/5 p-3 text-xs leading-5 text-amber-100">
          Governance mappings are informative references that drive policy visibility and rollout. They show mapped controls and required evidence; the tenant is not certified compliant because a mapping exists.
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          {["Framework-driven policy recommendations", "Framework-driven control coverage", "Framework-driven simulations", "Framework-driven evidence requirements"].map((label) => (
            <div key={label} className="rounded-md border border-slate-800 bg-slate-950/60 p-3 text-xs font-medium text-slate-200">{label}</div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" onClick={() => setFrameworkFilter("")} className={!frameworkFilter ? "rounded-md border border-brand-500/70 bg-brand-500/10 px-3 py-2 text-xs text-brand-100" : "rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-400"}>All focus frameworks</button>
          {frameworkFocus.map((item) => (
            <button key={item.id} type="button" onClick={() => setFrameworkFilter(item.id)} className={frameworkFilter === item.id ? "rounded-md border border-brand-500/70 bg-brand-500/10 px-3 py-2 text-xs text-brand-100" : "rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-400"}>
              {item.label}
            </button>
          ))}
        </div>
        <div className="mt-4 grid gap-3 lg:grid-cols-2">
          {visibleFrameworkItems.map((item) => (
            <div key={item.framework_id} className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-slate-100">{item.title || item.framework_id}</p>
                  <p className="mt-1 text-[11px] uppercase tracking-[0.12em] text-slate-500">{item.framework_id} · {item.status}</p>
                </div>
                <span className="rounded-full border border-slate-700 px-2 py-1 text-[10px] uppercase tracking-widest text-slate-400">{item.policy_pack_stable_ids.length} packs</span>
              </div>
              <p className="mt-3 text-xs leading-5 text-slate-400">{item.recommended_action}</p>
              <p className="mt-2 text-xs leading-5 text-amber-200">{item.compliance_note || item.claim_boundary}</p>
              <div className="mt-3 grid gap-2 text-xs text-slate-400 sm:grid-cols-2">
                <p><span className="text-slate-500">Jurisdiction</span><br />{item.jurisdiction || "Global"} · {item.framework_family || "Governance reference"}</p>
                <p><span className="text-slate-500">Policy packs</span><br />{item.policy_pack_names.slice(0, 3).join(" · ") || "Mapped pack unavailable"}</p>
                <p><span className="text-slate-500">Surfaces</span><br />{item.surfaces.slice(0, 6).join(", ") || "Surface declared during preview"}</p>
                <p><span className="text-slate-500">Mapped controls</span><br />{(item.mapped_control_families || []).slice(0, 3).join(" · ") || "Controls load with mapped pack preview"}</p>
              </div>
              <div className="mt-3 rounded-md border border-slate-800 bg-slate-950/70 p-3 text-xs text-slate-400">
                <p className="font-medium text-slate-200">Policy recommendations</p>
                <ul className="mt-2 list-disc space-y-1 pl-4">{(item.policy_recommendations || [item.recommended_action]).slice(0, 3).map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ul>
              </div>
              <div className="mt-3 grid gap-2 text-xs text-slate-400 sm:grid-cols-3">
                <a className="rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-brand-200 hover:border-brand-500/60" href={item.control_coverage?.href || "/deployment/surface-coverage"}>Open coverage</a>
                <a className="rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-brand-200 hover:border-brand-500/60" href={item.simulation_links?.[0]?.href || "/simulations"}>Open simulations</a>
                <a className="rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2 text-brand-200 hover:border-brand-500/60" href={item.evidence_href || "/evidence"}>Evidence requirements</a>
              </div>
              <p className="mt-3 text-xs leading-5 text-slate-500">{(item.evidence_requirements || []).slice(0, 3).join(" · ") || "Evidence requirements are inherited from the mapped templates."}</p>
              <Button className="mt-4" type="button" variant="outline" onClick={() => selectFrameworkPack(item)}>Preview and apply mapped pack</Button>
            </div>
          ))}
          {frameworkState === "error" ? <p className="rounded-md border border-amber-400/20 bg-amber-400/[0.06] p-4 text-sm text-amber-200">Framework mappings unavailable. Retry by refreshing this page.</p> : !loading && !visibleFrameworkItems.length ? (
            <p className="rounded-md border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-500">No framework mappings are available for the current catalog filters.</p>
          ) : null}
        </div>
      </PageSection>

      <div className={wizardStep === 0 ? "grid gap-5 xl:grid-cols-[0.9fr_1.4fr]" : "space-y-5"}>
        {wizardStep === 0 ? (
        <PageSection title="Pack library" description="Vendor and customer definitions are configuration only; they cannot carry executable code.">
          <div className="space-y-2">
            {catalog.map((item) => (
              <button key={item.id} type="button" onClick={() => setSelectedId(item.id)} className={`w-full rounded-lg border p-3 text-left transition ${selectedId === item.id ? "border-brand-500/70 bg-brand-500/10" : "border-slate-800 bg-slate-950/50 hover:border-slate-600"}`}>
                <div className="flex items-center justify-between gap-3"><span className="text-sm font-semibold text-slate-100">{item.name}</span><span className="text-[10px] uppercase tracking-widest text-slate-500">{item.package_entitlement}</span></div>
                <p className="mt-1 text-xs leading-5 text-slate-400">{item.description}</p>
                <p className="mt-2 text-[11px] text-slate-500">{item.vertical} · {item.department_persona} · v{item.version}</p>
              </button>
            ))}
            {catalogState === "error" ? <p className="text-sm text-amber-200">Policy Pack catalog unavailable. Retry by refreshing this page.</p> : !loading && !catalog.length ? <p className="text-sm text-slate-500">No pack matches these filters.</p> : null}
          </div>
        </PageSection>
        ) : null}

        <PageSection title={selectedReady && selected ? `Apply: ${selected.name}` : "Select a policy pack"} description={selected?.description || "Choose a pack from the library to see its prerequisites and templates."}>
          {selectedReady && selected ? (
            <form className="space-y-4" onSubmit={applyPack}>
              {wizardStep === 0 ? (
                <div className="rounded-md border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-300">
                  <p className="font-medium text-slate-100">{selected.name} is ready to map.</p>
                  <p className="mt-1 text-xs leading-5 text-slate-400">This pack is typed configuration. Applying it does not create a compliance or certification claim.</p>
                </div>
              ) : null}

              {wizardStep === 1 ? (
                <div className="grid gap-3 md:grid-cols-2">
                  <label className="space-y-1 text-xs text-slate-500"><span>Source or product context</span><select aria-label="Source or product context" className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={surface} onChange={(event) => setSurface(event.target.value)}>
                    <option value="browser">Browser</option><option value="endpoint">Endpoint</option><option value="runtime">Runtime</option><option value="saas_api">SaaS & APIs</option><option value="mcp_gateway">MCP Gateway</option><option value="provider_native_hook">Provider native hook</option>
                  </select></label>
                  <div className="space-y-2 rounded-md border border-slate-800 bg-slate-950/40 p-3 md:col-span-1"><p className="text-xs font-medium text-slate-300">Product or source context</p><p className="text-[11px] leading-5 text-slate-500">These optional targets refine the policy; they are not deployment methods.</p><Input aria-label="Application product" value={application} onChange={(event) => setApplication(event.target.value)} placeholder="Applications (comma separated)" /><Input aria-label="Provider source" value={provider} onChange={(event) => setProvider(event.target.value)} placeholder="Providers (comma separated)" /><Input aria-label="Model source" value={model} onChange={(event) => setModel(event.target.value)} placeholder="Models (comma separated)" /></div>
                  <Input value={group} onChange={(event) => setGroup(event.target.value)} placeholder="Directory group key or ID" />
                  <Input value={user} onChange={(event) => setUser(event.target.value)} placeholder="User IDs (comma separated)" />
                  <Input value={targetDepartment} onChange={(event) => setTargetDepartment(event.target.value)} placeholder="Target departments (comma separated)" />
                  <p className="self-center text-xs leading-5 text-slate-500">When no narrower target is supplied, the existing service applies the organization baseline and remains authoritative for tenant-scoped assignment checks.</p>
                </div>
              ) : null}

              {wizardStep === 2 ? (
                <>
                  <div className="grid gap-3 lg:grid-cols-3">
                    <div><p className="text-[11px] uppercase tracking-[0.12em] text-slate-500">Signals needed</p><p className="mt-1 text-sm text-slate-300">{selected.required_signals.join(", ") || "None declared"}</p></div>
                    <div><p className="text-[11px] uppercase tracking-[0.12em] text-slate-500">Supported surfaces</p><p className="mt-1 text-sm text-slate-300">{selected.supported_deployment_surfaces.join(", ") || "Not declared"}</p></div>
                    <div><p className="text-[11px] uppercase tracking-[0.12em] text-slate-500">Default rollout</p><p className="mt-1 text-sm text-slate-300">{selected.default_rollout}</p></div>
                  </div>
                  {selected.inherited_pack_refs.length ? <div className="rounded-md border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-300"><b className="text-slate-100">Inherited packs</b><p className="mt-1 text-slate-400">{selected.inherited_pack_refs.join(" · ")}</p></div> : null}
                  {typeof selected.framework_mappings.disclaimer === "string" ? <p className="text-xs text-slate-500">{selected.framework_mappings.disclaimer}</p> : null}
                  <label className="block text-xs text-slate-400">Customer parameters (typed JSON)<textarea className="mt-1 min-h-20 w-full rounded-md border border-slate-700 bg-slate-950 p-2 font-mono text-xs text-slate-200" value={parameters} onChange={(event) => setParameters(event.target.value)} /></label>
                  <div><p className="mb-2 text-xs font-medium text-slate-300">Included templates — disable only with an explicit customer decision</p>{(selected.inherited_templates || []).length ? <><p className="mb-2 text-xs text-slate-500">Inherited controls</p><div className="grid gap-2 md:grid-cols-2">{(selected.inherited_templates || []).map((template) => <label key={template.template_id} className="flex gap-2 rounded-md border border-slate-800 p-2 text-xs text-slate-300"><input type="checkbox" checked={!disabledTemplates.includes(template.template_id)} onChange={(event) => setDisabledTemplates((current) => event.target.checked ? current.filter((id) => id !== template.template_id) : [...current, template.template_id])} /><span><b className="text-slate-100">{template.title}</b><br />{template.human_explanation || template.reason}<br /><span className="text-slate-500">{template.source_pack?.stable_pack_id || "Inherited"} · {template.decision} · {template.criticality}</span></span></label>)}</div></> : null}{(selected.templates || []).length ? <><p className="mb-2 mt-3 text-xs text-slate-500">This pack’s local controls</p><div className="grid gap-2 md:grid-cols-2">{(selected.templates || []).map((template) => <label key={template.template_id} className="flex gap-2 rounded-md border border-slate-800 p-2 text-xs text-slate-300"><input type="checkbox" checked={!disabledTemplates.includes(template.template_id)} onChange={(event) => setDisabledTemplates((current) => event.target.checked ? current.filter((id) => id !== template.template_id) : [...current, template.template_id])} /><span><b className="text-slate-100">{template.title}</b><br />{template.human_explanation || template.reason}<br /><span className="text-slate-500">{template.decision} · {template.criticality}</span></span></label>)}</div></> : null}</div>
                  <div className="rounded-md border border-amber-500/25 bg-amber-500/5 p-3 text-xs text-amber-100"><b>Simulation and coverage</b><p className="mt-1 leading-5">The current capability report appears below. Create this pack in Draft, Monitor, or Warn, then use the customer-instance simulation before any stronger transition.</p></div>
                </>
              ) : null}

              {wizardStep === 3 ? (
                <>
                  <div className="grid gap-2 rounded-md border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-300 sm:grid-cols-2">
                    <p><span className="text-slate-500">Pack</span><br />{selected.stable_pack_id} · v{selected.version}</p>
                    <p><span className="text-slate-500">Surface</span><br />{surface || "No surface selected"}</p>
                    <p><span className="text-slate-500">People</span><br />{group || user || targetDepartment || "Organization baseline"}</p>
                    <p><span className="text-slate-500">AI targets</span><br />{application || provider || model || "All compatible targets"}</p>
                  </div>
                  <label className="block text-xs text-slate-400">Initial rollout<select className="mt-1 h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={rollout} onChange={(event) => setRollout(event.target.value)}><option value="DRAFT">Draft</option><option value="MONITORING">Monitor</option><option value="WARNING">Warn</option></select></label>
                  <div className="flex flex-wrap gap-2"><Button type="submit" disabled={applying}>{applying ? "Applying…" : "Apply in " + rollout.toLowerCase()}</Button><span className="self-center text-xs text-slate-500">Broad blocking moves require a passed simulation and a separate authorized approver.</span></div>
                </>
              ) : null}

              <div className="flex items-center justify-between gap-2 border-t border-slate-800 pt-4">
                {wizardStep > 0 ? <Button type="button" variant="outline" onClick={() => setWizardStep((current) => current - 1)}>Previous</Button> : <span />}
                {wizardStep < WIZARD_STEPS.length - 1 ? <Button type="button" onClick={nextWizardStep}>Next: {WIZARD_STEPS[wizardStep + 1]}</Button> : null}
              </div>
            </form>
          ) : <p className="text-sm text-slate-500">{catalogState === "error" ? "Policy Pack catalog unavailable." : loading ? "Loading selected pack…" : "Select a pack to begin."}</p>}
        </PageSection>
      </div>

      <PageSection title="Capability-aware coverage" description="A surface is never represented as pre-execution enforcement unless its currently healthy deployment proves it.">
        {coverageState === "error" ? <p className="mb-3 text-sm text-amber-200">Capability preview unavailable. Verified surfaces cannot be determined.</p> : null}
        <SimpleTable columns={["Surface", "Visibility", "Warn", "Approval", "Pre-action block", "Evidence", "Verification", "Health"]} rows={(coverage?.surfaces || []).map((item) => [item.surface, <span key="v" className={capabilityTone(item.visibility)}>{item.visibility}</span>, item.warning, item.approval, <span key="b" className={capabilityTone(item.pre_execution_block)}>{item.pre_execution_block}</span>, item.post_execution_evidence, item.independent_verification, item.health.join(", ")])} emptyLabel={catalogState === "error" || coverageState === "error" ? "Unavailable: capability preview could not be loaded." : "No capability preview is available for this pack."} />
        {(coverage?.known_blind_spots || []).length ? <div className="mt-3 rounded-md border border-amber-500/25 bg-amber-500/5 p-3 text-xs text-amber-200"><b>Known blind spots</b><ul className="mt-1 list-disc space-y-1 pl-4">{coverage?.known_blind_spots.map((spot) => <li key={spot}>{spot}</li>)}</ul></div> : null}
      </PageSection>

      <div className="grid gap-5 xl:grid-cols-2">
        <PageSection title="Customer instances and rollout" description="Draft and monitor are direct. Enforcement stays behind simulation, capability, and separate-approver gates.">
          {instanceState === "error" ? <p className="mb-3 text-sm text-amber-200">Customer instances unavailable. Retry by refreshing this page.</p> : null}
          <SimpleTable columns={["Pack", "Version", "State", "Assignments", "Actions"]} rows={instances.map((item) => [item.source_pack_id, item.source_pack_version, item.state, `${item.selected_applications.length} apps · ${item.selected_surfaces.length} surfaces`, <div key={item.id} className="flex flex-wrap gap-1"><Button size="sm" variant="outline" onClick={() => { setSelectedInstanceId(item.id); simulate(item.id); }}>Simulate</Button>{item.state === "DRAFT" ? <Button size="sm" variant="outline" onClick={() => transition(item.id, "MONITORING")}>Monitor</Button> : null}</div>])} emptyLabel={instanceState === "error" ? "Unavailable: customer instances could not be loaded." : "No customer instances have been created."} />
        </PageSection>
        <PageSection title="Effective policy explanation" description="See the source pack, inherited assignment path, customer overrides, exception and final precedence for one context.">
          <div className="flex gap-2"><Input value={effectiveActor} onChange={(event) => setEffectiveActor(event.target.value)} placeholder="User ID" /><Button variant="outline" onClick={explainEffective}>Explain</Button></div>
          {effective ? <pre className="mt-3 overflow-auto rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">{JSON.stringify(effective, null, 2)}</pre> : <p className="mt-3 text-xs text-slate-500">No context selected yet.</p>}
        </PageSection>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <PageSection title="Update center" description="Vendor updates compare the prior pack, new vendor definition, and customer-local overrides before adoption.">
          <div className="grid gap-2 sm:grid-cols-2"><select className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={selectedInstanceId} onChange={(event) => setSelectedInstanceId(event.target.value)}><option value="">Select customer instance</option>{instances.map((item) => <option key={item.id} value={item.id}>{item.source_pack_id} · {item.state}</option>)}</select><Input value={updateDefinitionId} onChange={(event) => setUpdateDefinitionId(event.target.value)} placeholder="New vendor definition ID" /></div>
          <Button className="mt-2" variant="outline" onClick={compareUpdate} disabled={!selectedInstanceId || !updateDefinitionId}>Compare update</Button>
          {updatePreview ? <pre className="mt-3 overflow-auto rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">{JSON.stringify(updatePreview, null, 2)}</pre> : <p className="mt-3 text-xs text-slate-500">Customer overrides remain unchanged until an administrator reviews and accepts a conflict-free update.</p>}
        </PageSection>
        <PageSection title="Groups and cohorts" description="Create static or IdP-synchronized groups here. Behavior cohorts use concrete AI events, never opaque employee risk scoring.">
          <form className="space-y-2" onSubmit={createGroup}><Input value={groupName} onChange={(event) => setGroupName(event.target.value)} placeholder="Group name" /><div className="grid grid-cols-2 gap-2"><select className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={groupType} onChange={(event) => setGroupType(event.target.value)}><option value="static">Static</option><option value="scim">SCIM / IdP synced</option><option value="dynamic_attribute">Dynamic attribute</option><option value="security_behavior">Security behavior</option><option value="temporary_rollout">Temporary rollout</option></select><Input value={groupMembers} onChange={(event) => setGroupMembers(event.target.value)} placeholder="Member user IDs" /></div><Button type="submit" variant="outline">Create group</Button></form>{groupResult ? <p className="mt-3 text-xs text-emerald-300">Ready: {groupResult.group_key}. Use this group key in the apply workflow.</p> : null}
        </PageSection>
      </div>
    </div>
  );
}
