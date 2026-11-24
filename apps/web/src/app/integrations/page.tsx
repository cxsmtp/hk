"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Building2, CheckCircle2, Cloud, DatabaseZap, ExternalLink, Github, KeyRound, Network, PlugZap, ShieldCheck, UsersRound } from "lucide-react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { ConnectorControlRoom } from "@/components/integrations/connector-control-room";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { shouldApplyConnectorOperation } from "@/lib/connector-control-room-state";
import type { Connector, ConnectorEvaluation, ConnectorProviderCatalogItem, EnterpriseDenominatorItem, EnterpriseDenominatorStatus, SourceConnectionSetupFamily, SourceConnectionSetupFlow } from "@/lib/types";

const MICROSOFT_GRAPH_PROVIDERS = new Set([
  "entra_id",
  "microsoft_365",
  "outlook",
  "teams",
  "onedrive_sharepoint",
  "office_apps",
  "microsoft_defender",
  "power_platform",
]);

const SOURCE_FLOW_ICON: Record<SourceConnectionSetupFamily, typeof Github> = {
  github: Github,
  m365_teams: Building2,
  identity: UsersRound,
  saas: PlugZap,
  cloud: Cloud,
};

const SOURCE_FLOW_PROVIDER_PREFERENCE: Record<SourceConnectionSetupFamily, string[]> = {
  github: ["hmair_github_cloud", "hmair_github_ghes"],
  m365_teams: ["teams", "microsoft_365", "entra_id", "hmair_microsoft365_copilot"],
  identity: ["entra_id", "scim", "okta", "google_workspace"],
  saas: ["slack", "google_workspace", "jira", "salesforce", "microsoft_365"],
  cloud: ["aws", "azure_openai", "microsoft_foundry", "gcp", "openai_enterprise"],
};

const SOURCE_FLOW_CONNECTOR_NAMES: Record<SourceConnectionSetupFamily, string> = {
  github: "GitHub Repository Source",
  m365_teams: "M365 and Teams Source",
  identity: "Identity Directory Source",
  saas: "SaaS Application Source",
  cloud: "Cloud AI Runtime Source",
};

const SOURCE_FLOW_PRIMARY_HREF: Record<SourceConnectionSetupFamily, string> = {
  github: "/control-coverage/source-control/github-repository-boundary",
  m365_teams: "#microsoft-graph-setup",
  identity: "#advanced-source-setup",
  saas: "#advanced-source-setup",
  cloud: "#advanced-source-setup",
};

function githubProviderLabel(providerKey: string): string {
  if (providerKey === "hmair_github_cloud" || providerKey === "github") return "GitHub Cloud";
  if (providerKey === "hmair_github_ghes") return "GitHub Enterprise Server";
  return providerKey;
}

function providerDisplayName(providerKey: string, providers: ConnectorProviderCatalogItem[]): string {
  const normalized = providerKey.trim().toLowerCase();
  const known: Record<string, string> = {
    hmair_microsoft365_copilot: "Microsoft 365 Copilot",
    hmair_github_cloud: "GitHub Cloud",
    hmair_github_ghes: "GitHub Enterprise Server",
    microsoft_365: "Microsoft 365",
    azure_openai: "Azure OpenAI",
    openai_enterprise: "OpenAI Enterprise",
    google_workspace: "Google Workspace",
  };
  if (known[normalized]) return known[normalized];
  const provider = providers.find((item) => item.provider_key.toLowerCase() === normalized);
  if (provider?.display_name && !/^[A-Z0-9_ -]+$/.test(provider.display_name)) return provider.display_name;
  return githubProviderLabel(normalized).replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

const FALLBACK_SOURCE_SETUP_FLOWS: SourceConnectionSetupFlow[] = [
  {
    family: "github",
    title: "GitHub repositories",
    summary: "Connect a GitHub App, choose a repository, then review which AI tools and actions to allow.",
    entrypoint_href: "/control-coverage/source-control/github-repository-boundary",
    provider_keys: ["github"],
    visibility: [
      "Repositories connected to the tenant",
      "Human users, teams, service accounts, and AI agents touching a repo",
      "Repo action decisions for Claude, Codex, Cursor, CLI, and MCP tools",
    ],
    required_authority: [
      "GitHub account owner or organization admin",
      "Selected repository authorization or GitHub App installation",
    ],
    credential_requirements: [
      "GitHub App installation or approved MCP repository session",
      "Repository owner/name and allowed action policy",
    ],
    validation_mode: "Run one allowed repo read and one blocked outside-repo request; both must create evidence.",
    limitations: [
      "Personal GitHub accounts do not prove organization membership unless a GitHub organization source is connected.",
    ],
    status: "setup_required",
  },
  {
    family: "m365_teams",
    title: "Microsoft 365 and Teams",
    summary: "Connect Teams, SharePoint, OneDrive and meeting evidence for note-taker, file sharing, and Microsoft 365 tenant visibility.",
    entrypoint_href: "#microsoft-graph-setup",
    provider_keys: ["teams", "microsoft_365", "entra_id"],
    visibility: [
      "Teams meeting and note-taker evidence where Graph permissions allow it",
      "SharePoint/OneDrive upload and download context",
      "Microsoft tenant and account boundary signals",
    ],
    required_authority: [
      "Microsoft tenant administrator consent",
      "Customer-approved Graph application permissions",
    ],
    credential_requirements: [
      "Tenant ID, application client ID, redirect URI, and client secret",
      "Selected permission profile: PoC safe, standard, or full enterprise",
    ],
    validation_mode: "Prepare admin consent, save credentials, then run a live metadata pull.",
    limitations: [
      "No Teams or file-control claim is made until Microsoft returns live tenant evidence.",
    ],
    status: "setup_required",
  },
  {
    family: "identity",
    title: "Identity and groups",
    summary: "Connect the directory source that proves users, departments, groups, managers, contractors, and service identities.",
    entrypoint_href: "#advanced-source-setup",
    provider_keys: ["entra_id", "scim", "okta", "google_workspace"],
    visibility: [
      "Authoritative user and group denominator",
      "Department, manager, contractor, and service-account context",
      "Policy assignment and effective-policy scope",
    ],
    required_authority: [
      "Identity administrator approval",
      "Read-only directory or SCIM source credentials",
    ],
    credential_requirements: [
      "Directory tenant or SCIM endpoint",
      "Approved service credential with read access",
    ],
    validation_mode: "Pull a bounded directory snapshot and reconcile users/groups against observed AI activity.",
    limitations: [
      "Observed prompts alone cannot prove the full employee or device population.",
    ],
    status: "setup_required",
  },
  {
    family: "saas",
    title: "SaaS applications",
    summary: "Connect approved SaaS systems so AI actions can be tied to real business apps, records, resources, and destinations.",
    entrypoint_href: "#advanced-source-setup",
    provider_keys: ["slack", "google_workspace", "jira", "salesforce", "microsoft_365"],
    visibility: [
      "AI access to SaaS records and destinations",
      "External sharing, upload/download, and app-account context",
      "Business-system resources touched by AI workflows",
    ],
    required_authority: [
      "Application owner approval",
      "Customer-owned API/export credentials",
    ],
    credential_requirements: [
      "SaaS admin API token or approved export source",
      "Scope, retention, and purpose mapping",
    ],
    validation_mode: "Run a live source pull and show records, freshness, limitations, and affected controls.",
    limitations: [
      "A browser observation of a SaaS page does not prove provider-native SaaS coverage.",
    ],
    status: "setup_required",
  },
  {
    family: "cloud",
    title: "Cloud and AI runtimes",
    summary: "Connect cloud projects, AI gateways, provider workspaces, and runtime logs for model, agent, and workload visibility.",
    entrypoint_href: "#advanced-source-setup",
    provider_keys: ["aws", "gcp", "azure_openai", "openai_enterprise", "microsoft_foundry"],
    visibility: [
      "Cloud projects, model APIs, provider workspaces, and workload identities",
      "Runtime agents, tools, MCP servers, and API destinations",
      "Provider-reported usage where the provider exposes it",
    ],
    required_authority: [
      "Cloud or provider workspace administrator approval",
      "Read-only inventory/usage export authority",
    ],
    credential_requirements: [
      "Cloud account/project/workspace identifier",
      "Approved service credential or billing/usage export",
    ],
    validation_mode: "Validate one live inventory or usage pull and keep browser, endpoint, runtime, and provider-native evidence separate.",
    limitations: [
      "Provider billing and seat utilization require provider/admin source connections; they are not inferred from prompts.",
    ],
    status: "setup_required",
  },
];

export default function IntegrationsPage() {
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [providers, setProviders] = useState<ConnectorProviderCatalogItem[]>([]);
  const [sourceSetupFlows, setSourceSetupFlows] = useState<SourceConnectionSetupFlow[]>([]);
  const [authorityStatus, setAuthorityStatus] = useState<EnterpriseDenominatorStatus | null>(null);
  const [selectedSourceFamily, setSelectedSourceFamily] = useState<SourceConnectionSetupFamily | null>(null);
  const [selectedConnectorId, setSelectedConnectorId] = useState<string | null>(null);
  const [evaluation, setEvaluation] = useState<ConnectorEvaluation | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [evaluationError, setEvaluationError] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<string>("entra_id");
  const [connectorName, setConnectorName] = useState("Enterprise Connector");
  const [baseUrl, setBaseUrl] = useState("");
  const [tokenValue, setTokenValue] = useState("");
  const [microsoftTenantId, setMicrosoftTenantId] = useState("");
  const [microsoftClientId, setMicrosoftClientId] = useState("");
  const [microsoftClientSecret, setMicrosoftClientSecret] = useState("");
  const [microsoftRedirectUri, setMicrosoftRedirectUri] = useState("https://hawk.localhost:3443/integrations");
  const [microsoftPermissionMode, setMicrosoftPermissionMode] = useState("poc_safe");
  const [microsoftConsentUrl, setMicrosoftConsentUrl] = useState("");
  const [microsoftScopes, setMicrosoftScopes] = useState<string[]>([]);
  const [microsoftWorking, setMicrosoftWorking] = useState(false);
  const [loadState, setLoadState] = useState<"loading" | "loaded" | "error">("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const selectedConnectorRef = useRef<string | null>(null);
  const evaluationOperationRef = useRef(0);

  const provider = useMemo(
    () => providers.find((item) => item.provider_key === selectedProvider) || null,
    [providers, selectedProvider],
  );
  const isMicrosoftProvider = MICROSOFT_GRAPH_PROVIDERS.has(selectedProvider);
  const microsoftRepairTarget = useMemo(() => {
    const selected = connectors.find((connector) => connector.id === selectedConnectorId);
    if (selected?.provider_key === selectedProvider) return selected;
    return connectors.find((connector) => connector.provider_key === selectedProvider) || null;
  }, [connectors, selectedConnectorId, selectedProvider]);

  const load = useCallback(async () => {
    setLoadState("loading");
    setLoadError(null);
    const results = await Promise.allSettled([
      api.listConnectorProviders(),
      api.listConnectors(),
      api.sourceConnectionSetupCatalog(),
      api.enterpriseDenominatorAuthority(),
    ]);
    const [providerResult, connectorResult, sourceSetupResult, authorityResult] = results;
    const failures = results.filter((result) => result.status === "rejected");
    if (failures.length) {
      const first = failures[0];
      const message = first.status === "rejected" && first.reason instanceof Error ? first.reason.message : "Integration status is unavailable";
      setLoadError(/401|403|unauthorized|invalid token|token expired/i.test(message) ? "Sign in is needed to load integration status." : "Integration status unavailable. Retry to load connected sources.");
    }
    if (providerResult.status !== "fulfilled" || connectorResult.status !== "fulfilled") {
      setLoadState(failures.length ? "error" : "loaded");
      return;
    }
    const providerPayload = providerResult.value;
    const connectorPayload = connectorResult.value;
    const sourceSetupPayload = sourceSetupResult.status === "fulfilled" ? sourceSetupResult.value : null;
    const authorityPayload = authorityResult.status === "fulfilled" ? authorityResult.value : null;
    const nextProviders = providerPayload.items || [];
    const nextConnectors = connectorPayload.items || [];
    setProviders(nextProviders);
    setConnectors(nextConnectors);
    setSourceSetupFlows(sourceSetupPayload?.items || []);
    setAuthorityStatus(authorityPayload);
    setSelectedProvider((current) => (
      nextProviders.some((item) => item.provider_key === current)
        ? current
        : nextProviders[0]?.provider_key || "entra_id"
    ));
    setSelectedConnectorId((current) => {
      const nextSelection = current && nextConnectors.some((connector) => connector.id === current)
        ? current
        : nextConnectors[0]?.id || null;
      selectedConnectorRef.current = nextSelection;
      return nextSelection;
    });
    setLoadState(failures.length ? "error" : "loaded");
  }, []);

  useEffect(() => {
    load().catch((error: unknown) => {
      setLoadState("error");
      setLoadError(/401|403|unauthorized|invalid token|token expired/i.test(error instanceof Error ? error.message : "") ? "Sign in is needed to load integration status." : "Integration status unavailable. Retry to load connected sources.");
      setProviders([]);
      setConnectors([]);
      setSourceSetupFlows([]);
      setAuthorityStatus(null);
      toast.error(error instanceof Error ? error.message : "Connector fleet unavailable");
    });
  }, [load]);

  useEffect(() => {
    if (!selectedConnectorId) {
      setEvaluation(null);
      setEvaluationError(null);
      return;
    }

    let active = true;
    const requestedConnectorId = selectedConnectorId;
    setEvaluation(null);
    setEvaluationError(null);
    api.connectorEvaluation(requestedConnectorId)
      .then((payload) => {
        if (
          active
          && payload.connector.id === requestedConnectorId
          && requestedConnectorId === selectedConnectorRef.current
        ) {
          setEvaluation(payload);
        }
      })
      .catch((error: unknown) => {
        if (active && requestedConnectorId === selectedConnectorRef.current) {
          setEvaluationError(error instanceof Error ? error.message : "Connector evaluation unavailable");
        }
      });
    return () => {
      active = false;
    };
  }, [selectedConnectorId]);

  const selectConnector = useCallback((connectorId: string) => {
    evaluationOperationRef.current += 1;
    selectedConnectorRef.current = connectorId;
    setEvaluating(false);
    setSelectedConnectorId(connectorId);
  }, []);

  const selectedSourceFlow = useMemo(
    () => {
      const flows = sourceSetupFlows.length ? sourceSetupFlows : FALLBACK_SOURCE_SETUP_FLOWS;
      return flows.find((flow) => flow.family === selectedSourceFamily) || flows[0] || null;
    },
    [sourceSetupFlows, selectedSourceFamily],
  );

  const chooseSourceFlow = useCallback((flow: SourceConnectionSetupFlow) => {
    setSelectedSourceFamily(flow.family);
    setConnectorName(SOURCE_FLOW_CONNECTOR_NAMES[flow.family]);
    const providerPreference = SOURCE_FLOW_PROVIDER_PREFERENCE[flow.family] || flow.provider_keys;
    const matchedProvider = providerPreference.find((providerKey) => (
      providers.some((providerItem) => providerItem.provider_key === providerKey)
    ));
    if (matchedProvider && flow.family !== "github") {
      setSelectedProvider(matchedProvider);
    }
    if (flow.family === "m365_teams") {
      setMicrosoftPermissionMode("poc_safe");
    }
    toast.info(flow.family === "github" ? "Open GitHub controls to connect an account and choose a repository." : `${flow.title} setup selected`);
  }, [providers]);

  async function createConnector() {
    try {
      const config: Record<string, unknown> = { polling_interval_sec: 900 };
      if (baseUrl.trim()) {
        config.base_url = baseUrl.trim();
      }
      await api.createConnector({
        name: connectorName,
        provider_key: selectedProvider,
        connector_type: selectedProvider,
        auth_type: "bearer",
        enabled: true,
        polling_interval_minutes: 15,
        config,
        secrets: tokenValue.trim() ? { access_token: tokenValue.trim() } : {},
      });
      toast.success("Connector created");
      setTokenValue("");
      await load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Connector creation failed");
    }
  }

  function microsoftBootstrapPayload(createConnector: boolean) {
    return {
      connector_id: microsoftRepairTarget?.id,
      name: connectorName.trim() || `${provider?.display_name || "Microsoft Graph"} Connector`,
      provider_key: selectedProvider,
      tenant_id: microsoftTenantId.trim(),
      client_id: microsoftClientId.trim(),
      redirect_uri: microsoftRedirectUri.trim(),
      permission_mode: microsoftPermissionMode,
      include_optional_scopes: false,
      create_connector: createConnector,
      enabled: true,
      polling_interval_minutes: 15,
      ...(createConnector ? { client_secret: microsoftClientSecret } : {}),
      state: crypto.randomUUID(),
    };
  }

  async function prepareMicrosoftConsent() {
    setMicrosoftWorking(true);
    try {
      const prepared = await api.bootstrapMicrosoftConnector({
        ...microsoftBootstrapPayload(false),
        create_connector: false,
      });
      setMicrosoftConsentUrl(prepared.consent_url || "");
      setMicrosoftScopes(prepared.selected_scopes || []);
      toast.success("Microsoft admin-consent request prepared");
    } catch (error) {
      setMicrosoftConsentUrl("");
      setMicrosoftScopes([]);
      toast.error(error instanceof Error ? error.message : "Microsoft consent setup failed");
    } finally {
      setMicrosoftWorking(false);
    }
  }

  async function saveAndVerifyMicrosoftConnector() {
    setMicrosoftWorking(true);
    try {
      const saved = await api.bootstrapMicrosoftConnector({
        ...microsoftBootstrapPayload(true),
        create_connector: true,
      });
      setMicrosoftClientSecret("");
      if (!saved.connector_id) throw new Error("Microsoft connector was not saved");
      setSelectedConnectorId(saved.connector_id);
      selectedConnectorRef.current = saved.connector_id;
      await api.pullConnectorNow(saved.connector_id);
      await load();
      toast.success(saved.updated ? "Microsoft connector repaired and verified" : "Microsoft connector created and verified");
    } catch (error) {
      setMicrosoftClientSecret("");
      toast.error(error instanceof Error ? error.message : "Microsoft connector verification failed");
    } finally {
      setMicrosoftWorking(false);
    }
  }

  async function runLiveEvaluation(connectorId: string) {
    const operationId = evaluationOperationRef.current + 1;
    evaluationOperationRef.current = operationId;
    setEvaluating(true);
    setEvaluationError(null);
    try {
      await api.pullConnectorNow(connectorId);
      await load();
      const verifiedEvaluation = await api.connectorEvaluation(connectorId);
      if (!shouldApplyConnectorOperation({
        operationId,
        currentOperationId: evaluationOperationRef.current,
        requestedConnectorId: connectorId,
        selectedConnectorId: selectedConnectorRef.current,
        responseConnectorId: verifiedEvaluation.connector.id,
      })) {
        return;
      }
      setEvaluation(verifiedEvaluation);
      if (verifiedEvaluation.latest_pull?.status === "error") {
        const message = verifiedEvaluation.latest_pull.error || "Connector pull failed";
        setEvaluationError(message);
        toast.error(message);
        return;
      }
      toast.success("Connector evaluation completed");
    } catch (error) {
      if (
        operationId === evaluationOperationRef.current
        && connectorId === selectedConnectorRef.current
      ) {
        const message = error instanceof Error ? error.message : "Evaluation failed";
        setEvaluationError(message);
        toast.error(message);
      }
    } finally {
      if (operationId === evaluationOperationRef.current) {
        setEvaluating(false);
      }
    }
  }

  const sourceSetupPanel = (
    <section className="mb-6 border border-cyan-400/20 bg-[linear-gradient(135deg,rgba(8,145,178,0.08),rgba(15,23,42,0.30))] p-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-cyan-200">Source connection setup</p>
          <h2 className="mt-2 text-lg font-semibold text-slate-50">Connect a source, then run a scan or control test</h2>
          <p className="mt-2 max-w-4xl text-xs leading-5 text-slate-400">
            Start with the source you want to prove. Each path uses customer-owned credentials and tenant-scoped validation. No coverage is claimed until validation produces fresh evidence.
          </p>
          {!sourceSetupFlows.length ? (
            <p className="mt-2 inline-flex border border-amber-300/20 bg-amber-300/[0.06] px-2 py-1 text-[11px] text-amber-100">
              Setup catalog has not returned live rows yet, so these cards show the supported setup paths without claiming connected data.
            </p>
          ) : null}
        </div>
        <a
          href="/control-coverage/source-control/github-repository-boundary"
          className="inline-flex items-center justify-center gap-2 border border-cyan-300/30 bg-cyan-300/[0.08] px-3 py-2 text-xs font-semibold text-cyan-100 hover:bg-cyan-300/[0.14]"
        >
          Connect or manage GitHub <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </div>
      <div className="mt-4 grid gap-3 lg:grid-cols-5">
        {(sourceSetupFlows.length ? sourceSetupFlows : FALLBACK_SOURCE_SETUP_FLOWS).map((flow) => {
          const Icon = SOURCE_FLOW_ICON[flow.family] || Network;
          const active = selectedSourceFlow?.family === flow.family;
          return (
            <button
              key={flow.family}
              type="button"
              onClick={() => chooseSourceFlow(flow)}
              className={`min-h-[220px] border p-4 text-left transition ${
                active
                  ? "border-cyan-300/60 bg-cyan-300/[0.10]"
                  : "border-white/[0.08] bg-[#0b1018]/70 hover:border-cyan-300/30 hover:bg-cyan-300/[0.05]"
              }`}
            >
              <span className="inline-flex h-9 w-9 items-center justify-center border border-cyan-300/20 bg-cyan-300/[0.08] text-cyan-200">
                <Icon className="h-4 w-4" />
              </span>
              <h3 className="mt-3 text-sm font-semibold text-slate-100">{flow.family === "github" ? "GitHub" : flow.title}</h3>
              <p className="mt-2 text-[11px] leading-5 text-slate-400">{flow.family === "github" ? "Connect a GitHub App, choose a repository, then review which AI tools and actions to allow." : flow.summary}</p>
              <div className="mt-3 flex flex-wrap gap-1">
                {flow.provider_keys.slice(0, 3).map((providerKey) => (
                  <span key={providerKey} className="border border-white/[0.08] bg-white/[0.03] px-2 py-1 font-mono text-[8px] uppercase tracking-[0.08em] text-slate-400">
                    {flow.family === "github" ? githubProviderLabel(providerKey) : providerDisplayName(providerKey, providers)}
                  </span>
                ))}
              </div>
            </button>
          );
        })}
      </div>
      {selectedSourceFlow ? (
        <div className="mt-4 grid gap-3 border border-white/[0.08] bg-[#080d14]/80 p-4 lg:grid-cols-[1fr_1fr_1fr_auto]">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Visibility unlocked</p>
            <ul className="mt-2 space-y-1 text-[11px] leading-5 text-slate-300">
              {(selectedSourceFlow.family === "github" ? ["GitHub accounts and repositories", "People and teams when GitHub provides them", "AI activity when governed tools report it"] : selectedSourceFlow.visibility.slice(0, 3)).map((item) => <li key={item}>• {item}</li>)}
            </ul>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Required admin authority</p>
            <ul className="mt-2 space-y-1 text-[11px] leading-5 text-slate-300">
              {(selectedSourceFlow.family === "github" ? ["A GitHub account owner or organization admin", "Permission to install a GitHub App on selected repositories"] : selectedSourceFlow.required_authority.slice(0, 2)).map((item) => <li key={item}>• {item}</li>)}
            </ul>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">Validation and limits</p>
            <p className="mt-2 text-[11px] leading-5 text-slate-300">{selectedSourceFlow.family === "github" ? "Validate the connection and run an inventory scan. Choosing a repository prepares a draft; approval happens in Policies." : selectedSourceFlow.validation_mode}</p>
            <p className="mt-2 text-[11px] leading-5 text-amber-100">{selectedSourceFlow.family === "github" ? "Personal accounts do not prove organization membership. Access is only known where GitHub and governed tools provide evidence." : selectedSourceFlow.limitations[0]}</p>
          </div>
          <div className="flex items-start lg:justify-end">
            <a
              href={SOURCE_FLOW_PRIMARY_HREF[selectedSourceFlow.family] || selectedSourceFlow.entrypoint_href}
              className="inline-flex whitespace-nowrap border border-cyan-300/35 bg-cyan-300/[0.10] px-3 py-2 text-xs font-semibold text-cyan-100 hover:bg-cyan-300/[0.16]"
            >
              {selectedSourceFlow.family === "github" ? "Connect or manage GitHub" : "Set up source"}
            </a>
          </div>
        </div>
      ) : null}
    </section>
  );

  const authorityStateCopy: Record<EnterpriseDenominatorItem["state"], { label: string; className: string; icon: typeof AlertTriangle }> = {
    authoritative: {
      label: "Authoritative",
      className: "border-emerald-300/30 bg-emerald-300/[0.09] text-emerald-100",
      icon: CheckCircle2,
    },
    partial: {
      label: "Partial",
      className: "border-amber-300/30 bg-amber-300/[0.08] text-amber-100",
      icon: AlertTriangle,
    },
    observed_only: {
      label: "Observed only",
      className: "border-cyan-300/25 bg-cyan-300/[0.07] text-cyan-100",
      icon: DatabaseZap,
    },
    missing: {
      label: "Missing source",
      className: "border-rose-300/25 bg-rose-300/[0.07] text-rose-100",
      icon: AlertTriangle,
    },
  };

  const authorityPanel = authorityStatus ? (
    <section className="mb-6 overflow-hidden border border-white/[0.08] bg-[#0b111a]/95">
      <details>
      <summary className="flex cursor-pointer items-center justify-between gap-3 px-4 py-3 text-sm font-semibold text-slate-200">
        <span>Source readiness</span>
        <span className="text-xs font-normal text-slate-400">{authorityStatus.authoritative_count}/{authorityStatus.total_domains} authoritative sources</span>
      </summary>
      <div className="border-t border-white/[0.08]">
      <div className="flex flex-col gap-4 border-b border-white/[0.08] bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.12),transparent_34%),linear-gradient(135deg,rgba(15,23,42,0.96),rgba(8,13,20,0.98))] p-5 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.24em] text-cyan-200">Provider source readiness</p>
          <h2 className="mt-2 text-xl font-semibold text-slate-50">Connect sources for complete coverage</h2>
          <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-400">
            Browser, endpoint, MCP, and AI-client activity shows what happened here. Provider and directory sources add the population context needed for broader coverage.
          </p>
        </div>
        <div className="min-w-[220px] border border-cyan-300/20 bg-cyan-300/[0.06] p-4">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-100">Authoritative domains</p>
          <p className="mt-2 text-3xl font-semibold text-white">{authorityStatus.authoritative_count}/{authorityStatus.total_domains}</p>
          <p className="mt-1 text-[11px] capitalize text-slate-400">{authorityStatus.overall_state.replaceAll("_", " ")}</p>
        </div>
      </div>
      <div className="grid gap-3 p-4 xl:grid-cols-7">
        {authorityStatus.items.map((item) => {
          const state = authorityStateCopy[item.state];
          const Icon = state.icon;
          return (
            <article key={item.domain} className="flex min-h-[260px] flex-col border border-white/[0.08] bg-[#081019]/75 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-white">{item.label}</h3>
                  <p className="mt-1 text-[10px] uppercase tracking-[0.14em] text-slate-500">{item.required_source_title || "Source required"}</p>
                </div>
                <span className={`inline-flex items-center gap-1.5 border px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em] ${state.className}`}>
                  <Icon className="h-3 w-3" /> {state.label}
                </span>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-2 text-[11px]">
                <div className="border border-white/[0.07] bg-white/[0.025] p-2">
                  <p className="uppercase tracking-[0.12em] text-slate-500">Denominator</p>
                  <p className="mt-1 font-mono text-slate-100">{item.denominator ?? "—"}</p>
                </div>
                <div className="border border-white/[0.07] bg-white/[0.025] p-2">
                  <p className="uppercase tracking-[0.12em] text-slate-500">Connections</p>
                  <p className="mt-1 font-mono text-slate-100">{item.connection_count}</p>
                </div>
              </div>
              <p className="mt-4 text-[11px] leading-5 text-slate-300">{item.next_action}</p>
              <p className="mt-3 text-[10px] leading-4 text-slate-500">{item.limitation}</p>
              {item.evidence.length ? (
                <p className="mt-3 font-mono text-[9px] leading-4 text-cyan-200/80">{item.evidence.slice(0, 2).join(" · ")}</p>
              ) : null}
              <div className="mt-auto pt-4">
                <a
                  href={item.connect_href}
                  className="inline-flex items-center gap-2 text-[11px] font-semibold text-cyan-200 underline decoration-cyan-300/35 underline-offset-4"
                >
                  {item.authoritative ? "Manage source" : "Connect source"} <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </article>
          );
        })}
      </div>
      <div className="border-t border-white/[0.08] p-4">
        <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">How to reach full authoritative control</p>
        <ol className="mt-3 grid gap-2 text-[11px] leading-5 text-slate-300 md:grid-cols-2 xl:grid-cols-3">
          {authorityStatus.how_to_get_full_authority.map((step, index) => (
            <li key={step} className="border border-white/[0.07] bg-white/[0.025] p-3">
              <span className="mr-2 font-mono text-cyan-200">{String(index + 1).padStart(2, "0")}</span>
              {step}
            </li>
          ))}
        </ol>
      </div>
      </div>
      </details>
    </section>
  ) : (
    <section className="mb-6 border border-amber-300/20 bg-amber-300/[0.05] p-4">
      <p className="text-sm font-semibold text-amber-100">Enterprise authority map unavailable</p>
      <p className="mt-1 text-xs text-slate-400">The API could not return source-denominator status. Existing controls remain unchanged.</p>
    </section>
  );

  const setupPanel = (
    <div>
      {authorityPanel}
      <div id="advanced-source-setup" className="mb-3 border border-white/[0.08] bg-white/[0.025] p-3">
        <p className="text-xs font-semibold text-slate-100">Advanced source setup</p>
        <p className="mt-1 text-[11px] leading-5 text-slate-400">
          Use this only when you already have the provider key or API credential. For GitHub, use the repository picker above.
        </p>
        {!providers.length ? (
          <p className="mt-2 text-[11px] text-amber-100">Connector provider catalog is not loaded yet. The source cards above still show what to connect and why.</p>
        ) : null}
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <label htmlFor="connector-provider" className="text-xs font-medium text-slate-400">Provider</label>
          <select
            id="connector-provider"
            className="mt-1 h-10 w-full rounded-md border border-[#303a50] bg-[#0b1018] px-3 text-sm text-slate-200 outline-none focus:border-brand-400/60 focus:ring-1 focus:ring-brand-400/30"
            value={selectedProvider}
            onChange={(event) => setSelectedProvider(event.target.value)}
          >
            {providers.map((item) => (
              <option key={item.provider_key} value={item.provider_key}>
                {item.display_name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="connector-name" className="text-xs font-medium text-slate-400">Connector name</label>
          <Input id="connector-name" className="mt-1" value={connectorName} onChange={(event) => setConnectorName(event.target.value)} />
        </div>
      </div>
      {isMicrosoftProvider ? (
        <section id="microsoft-graph-setup" className="mt-4 overflow-hidden border border-cyan-400/20 bg-[linear-gradient(135deg,rgba(8,145,178,0.08),rgba(15,23,42,0.25))]">
          <div className="flex flex-col gap-3 border-b border-cyan-400/15 p-4 md:flex-row md:items-start md:justify-between">
            <div className="flex gap-3">
              <span className="grid h-9 w-9 shrink-0 place-items-center border border-cyan-300/25 bg-cyan-300/[0.08] text-cyan-200"><ShieldCheck className="h-4 w-4" /></span>
              <div>
                <h3 className="text-sm font-semibold text-slate-100">Microsoft Graph tenant authorization</h3>
                <p className="mt-1 max-w-3xl text-[11px] leading-5 text-slate-400">Prepare the exact application permissions, complete Microsoft tenant-admin consent, then save the customer-owned service principal and run a live metadata pull.</p>
              </div>
            </div>
            <span className="border border-amber-300/20 bg-amber-300/[0.06] px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-amber-100">
              {microsoftRepairTarget ? "Repair existing connector" : "New connector"}
            </span>
          </div>
          <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-4">
            <div><label htmlFor="microsoft-tenant-id" className="text-xs font-medium text-slate-400">Directory tenant ID</label><Input id="microsoft-tenant-id" className="mt-1" value={microsoftTenantId} onChange={(event) => setMicrosoftTenantId(event.target.value)} autoComplete="off" /></div>
            <div><label htmlFor="microsoft-client-id" className="text-xs font-medium text-slate-400">Application client ID</label><Input id="microsoft-client-id" className="mt-1" value={microsoftClientId} onChange={(event) => setMicrosoftClientId(event.target.value)} autoComplete="off" /></div>
            <div><label htmlFor="microsoft-redirect-uri" className="text-xs font-medium text-slate-400">Registered redirect URI</label><Input id="microsoft-redirect-uri" className="mt-1" value={microsoftRedirectUri} onChange={(event) => setMicrosoftRedirectUri(event.target.value)} autoComplete="off" /></div>
            <div><label htmlFor="microsoft-permission-mode" className="text-xs font-medium text-slate-400">Permission profile</label><select id="microsoft-permission-mode" value={microsoftPermissionMode} onChange={(event) => setMicrosoftPermissionMode(event.target.value)} className="mt-1 h-10 w-full rounded-md border border-[#303a50] bg-[#0b1018] px-3 text-sm text-slate-200"><option value="poc_safe">PoC safe</option><option value="standard">Standard</option><option value="full_enterprise">Full enterprise</option></select></div>
          </div>
          <div className="grid gap-3 border-t border-white/[0.06] p-4 lg:grid-cols-[1fr_auto] lg:items-end">
            <div><label htmlFor="microsoft-client-secret" className="flex items-center gap-2 text-xs font-medium text-slate-400"><KeyRound className="h-3.5 w-3.5" /> Client secret</label><Input id="microsoft-client-secret" className="mt-1" value={microsoftClientSecret} onChange={(event) => setMicrosoftClientSecret(event.target.value)} type="password" autoComplete="new-password" placeholder="Used only for encrypted connector storage" /></div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={prepareMicrosoftConsent} disabled={microsoftWorking || !microsoftTenantId.trim() || !microsoftClientId.trim() || !microsoftRedirectUri.trim()}>Prepare admin consent</Button>
              <Button onClick={saveAndVerifyMicrosoftConnector} disabled={microsoftWorking || loadState !== "loaded" || !provider || provider.is_stub || !microsoftTenantId.trim() || !microsoftClientId.trim() || !microsoftClientSecret || !microsoftRedirectUri.trim()}>Save credentials and verify</Button>
            </div>
          </div>
          {microsoftConsentUrl ? <div className="border-t border-cyan-400/15 bg-cyan-400/[0.035] p-4"><a href={microsoftConsentUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 text-xs font-semibold text-cyan-200 underline decoration-cyan-300/40 underline-offset-4">Open Microsoft admin consent <ExternalLink className="h-3.5 w-3.5" /></a><p className="mt-2 text-[11px] leading-5 text-slate-400">Microsoft must confirm consent. Returning to Hawk does not itself prove that the permissions were granted; only a successful live pull changes connector evidence.</p>{microsoftScopes.length ? <p className="mt-2 font-mono text-[9px] leading-4 text-slate-500">Requested: {microsoftScopes.join(" · ")}</p> : null}</div> : null}
        </section>
      ) : (
        <>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div><label htmlFor="connector-base-url" className="text-xs font-medium text-slate-400">Base URL (optional)</label><Input id="connector-base-url" className="mt-1" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} placeholder="https://…" /></div>
            <div><label htmlFor="connector-token" className="text-xs font-medium text-slate-400">Access token / API key</label><Input id="connector-token" className="mt-1" value={tokenValue} onChange={(event) => setTokenValue(event.target.value)} type="password" autoComplete="off" /></div>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-3"><Button onClick={createConnector} disabled={loadState !== "loaded" || !connectorName.trim() || !selectedProvider || !provider || provider.is_stub || !provider.supports_live_pull}>Create connector</Button>{provider ? <p className="text-xs text-slate-500">{provider.supports_live_pull && !provider.is_stub ? "Live pull supported" : `Unavailable for setup: ${provider.stub_reason || "provider catalog does not support writes"}`}</p> : <p className="text-xs text-amber-200">Integration provider catalog unavailable.</p>}</div>
        </>
      )}
    </div>
  );

  return (
    <AppShell>
      <ConnectorControlRoom
        connectors={connectors}
        providers={providers}
        selectedConnectorId={selectedConnectorId}
        evaluation={evaluation}
        evaluating={evaluating}
        evaluationError={evaluationError}
        onSelect={selectConnector}
        onEvaluate={runLiveEvaluation}
        onConfigureProvider={(providerItem) => {
          setSelectedProvider(providerItem.provider_key);
          setConnectorName(`${providerDisplayName(providerItem.provider_key, providers)} Connector`);
          toast.info(`${providerDisplayName(providerItem.provider_key, providers)} setup selected`);
        }}
        connectionGuide={sourceSetupPanel}
        loadState={loadState}
        loadError={loadError}
        setupPanel={setupPanel}
      />
    </AppShell>
  );
}
