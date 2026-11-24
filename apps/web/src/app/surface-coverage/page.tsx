"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { ControlCoveragePanel } from "@/components/control-coverage/control-coverage-panel";
import { EvidenceTruthPanel } from "@/components/evidence/evidence-truth-panel";
import { NativeControlMatrix } from "@/components/control-coverage/native-control-matrix";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { CommandCenterDashboardState, RuntimeTimelineEvent } from "@/lib/types";

const CONTROL_COVERAGE_UI_ENABLED = process.env.NEXT_PUBLIC_CONTROL_COVERAGE_UI_ENABLED === "true";

type SurfaceRuntimeSummary = {
  event_count: number;
  blocked: number;
  warned: number;
  apps: string[];
  agents: string[];
  users: string[];
};

type SurfaceCard = {
  name: string;
  status: "Inline now" | "Inline when routed" | "Telemetry + gateway inline" | "Telemetry / external-required" | "Proxy/SWG required";
  controlMode: string;
  observes: string;
  capabilities: string[];
  limitation: string;
  href: string;
};

const SURFACE_CARDS: SurfaceCard[] = [
  {
    name: "Browser Extension",
    status: "Inline now",
    controlMode: "inline_prevented / warned / inline_allowed",
    observes: "Prompt submit, paste, file upload, drag/drop, visible output copy, and browser AI actions.",
    capabilities: [
      "Sensitive input blocking",
      "Business Purpose Boundary",
      "Justification + evidence",
      "Shadow AI discovery",
    ],
    limitation: "Only managed browser sessions are inline. Incognito and unmanaged browsers need policy enforcement.",
    href: "/dashboard/command-center",
  },
  {
    name: "MCP / Developer Gateway",
    status: "Inline when routed",
    controlMode: "inline_prevented / review / external_required",
    observes: "MCP tool calls, tool parameters, write/admin/secret actions, and developer agent handoffs.",
    capabilities: [
      "Tool fingerprinting",
      "Parameter validation",
      "Approval binding",
      "Agent blast radius",
    ],
    limitation: "Prevention requires the MCP client/server path to route through Hawk gateway or proxy.",
    href: "/ai-iam",
  },
  {
    name: "LLM Gateway / SDK",
    status: "Inline when routed",
    controlMode: "inline_prevented / inline_allowed / warned",
    observes: "Model calls from internal apps, API clients, SDKs, and approved app embeds.",
    capabilities: [
      "authorize_ai_action",
      "Need-to-know control",
      "Policy snapshots",
      "Evidence bundles",
    ],
    limitation: "Direct provider API calls are bypass unless gateway, SDK, SWG, or proxy routing is enforced.",
    href: "/interaction-security",
  },
  {
    name: "Microsoft Foundry",
    status: "Telemetry + gateway inline",
    controlMode: "telemetry_only / detected_only / inline_prevented when gateway-routed",
    observes: "Foundry projects, agents, model deployments, Entra identities, tools, and Azure OpenAI calls.",
    capabilities: [
      "Project / agent / model inventory",
      "Entra and service principal mapping",
      "Tool / data-source / action trace",
      "Gateway bypass detection",
    ],
    limitation: "Inline prevention requires Foundry or Azure OpenAI calls to route through Hawk Gateway or SDK.",
    href: "/surface-coverage#foundry",
  },
  {
    name: "Microsoft Copilot",
    status: "Telemetry / external-required",
    controlMode: "telemetry_only / detected_only / external_required",
    observes: "M365 Copilot activity, Copilot Studio agents/connectors, OAuth grants, and app permissions.",
    capabilities: [
      "OAuth/app permission risk",
      "Sensitive exposure findings",
      "Copilot Studio connector trace",
      "External remediation actions",
    ],
    limitation: "Most enforcement uses Microsoft admin, Purview, Entra, or connector controls, so Hawk labels it honestly.",
    href: "/surface-coverage#copilot",
  },
  {
    name: "Desktop / SWG / Local Proxy",
    status: "Proxy/SWG required",
    controlMode: "telemetry_only / external_required / inline_prevented when proxied",
    observes: "Native AI apps, CLI/API traffic, desktop tools, and local AI provider traffic where routed.",
    capabilities: [
      "Local telemetry",
      "SWG/proxy decision API",
      "Desktop app inventory",
      "External enforcement trace",
    ],
    limitation: "Hawk does not claim endpoint-wide prevention without proxy, SWG, gateway, or managed agent path.",
    href: "/dashboard/command-center",
  },
];

const OPERATOR_SURFACES = [
  {
    name: "Browser",
    state: "Observed when extension is healthy",
    badge: "Demo-ready path",
    tone: "good",
    sees: "AI web apps, prompts, paste, upload/download attempts, account hints, and browser policy decisions.",
    stops: "Prompt submission, copy/paste, upload, and risky browser actions where the managed extension is active.",
    missing: "Provider-native billing, exact tenant account proof, and unmanaged browsers require provider/admin or MDM signals.",
    action: "Test browser control",
    href: "/dashboard/command-center",
  },
  {
    name: "MCP Gateway",
    state: "Governed when routed through gateway",
    badge: "Route required",
    tone: "info",
    sees: "Claude, Codex, Cursor, agents, MCP servers, tool calls, repository scope, and allow/block decisions.",
    stops: "Tool calls, repo write/PR actions, admin/secret actions, and unsafe MCP requests routed through the gateway.",
    missing: "Direct tools that bypass the gateway remain outside pre-execution enforcement.",
    action: "Open MCP evidence",
    href: "/ai-tools-usage",
  },
  {
    name: "LLM Gateway",
    state: "Governed when model traffic is routed",
    badge: "Route required",
    tone: "info",
    sees: "Model requests from internal apps, API clients, SDKs, and approved application embeds.",
    stops: "Prompts and responses when the app uses Hawk Gateway or an approved SDK route.",
    missing: "Direct provider API calls remain outside pre-request control until gateway or SDK routing is enforced.",
    action: "Open LLM controls",
    href: "/interaction-security",
  },
  {
    name: "Endpoint Agent",
    state: "Needs enrolled signed device",
    badge: "Setup required",
    tone: "warn",
    sees: "Installed AI apps, local client metadata, files/process/network context, and endpoint heartbeat.",
    stops: "Endpoint commands and local file actions only after endpoint identity and policy freshness are current.",
    missing: "No hard endpoint claim without signed heartbeat, current policy, and command receipt evidence.",
    action: "Enroll endpoint",
    href: "/discovery/scans",
  },
];

type FoundryProjectRow = {
  key: string;
  project: string;
  workspace: string;
  subscription: string;
  resourceGroup: string;
  events: number;
  lastSeen: string;
};

type FoundryAgentRow = {
  key: string;
  agent: string;
  model: string;
  deployment: string;
  controlMode: string;
  latestAction: string;
  events: number;
};

type FoundryAuthorityRow = {
  key: string;
  servicePrincipal: string;
  managedIdentity: string;
  entraApp: string;
  authority: string;
  events: number;
};

type FoundryInventory = {
  projects: FoundryProjectRow[];
  agents: FoundryAgentRow[];
  authorities: FoundryAuthorityRow[];
  tools: string[];
  dataSources: string[];
  gatewayRouted: number;
  telemetryOnly: number;
  recent: RuntimeTimelineEvent[];
};

type CopilotWorkloadRow = {
  key: string;
  workload: string;
  app: string;
  sensitivity: string;
  controlMode: string;
  events: number;
  lastSeen: string;
};

type CopilotAgentRow = {
  key: string;
  agent: string;
  environment: string;
  connectors: string[];
  scopes: string[];
  controlMode: string;
  events: number;
};

type CopilotPermissionRow = {
  key: string;
  appName: string;
  appId: string;
  scopes: string[];
  remediationActions: string[];
  status: string;
  events: number;
};

type CopilotInventory = {
  workloads: CopilotWorkloadRow[];
  agents: CopilotAgentRow[];
  permissions: CopilotPermissionRow[];
  sensitiveExposures: number;
  externalRequired: number;
  telemetryOnly: number;
  remediationActions: string[];
  recent: RuntimeTimelineEvent[];
};

function toRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function metadataOf(event: RuntimeTimelineEvent): Record<string, unknown> {
  return toRecord(event.metadata);
}

function textValue(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
    if (typeof value === "boolean") return value ? "true" : "false";
  }
  return null;
}

function arrayValue(value: unknown): string[] {
  if (Array.isArray(value)) {
    return [...new Set(value.map((item) => textValue(item)).filter((item): item is string => Boolean(item)))];
  }
  const single = textValue(value);
  if (!single) return [];
  if (single.includes(",")) {
    return [...new Set(single.split(",").map((item) => item.trim()).filter(Boolean))];
  }
  return [single];
}

function controlModeFor(event: RuntimeTimelineEvent): string {
  const metadata = metadataOf(event);
  const aiAction = toRecord(metadata.ai_action);
  const policy = toRecord(aiAction.policy);
  const mode = textValue(metadata.control_mode, metadata.control_mode_hint, policy.control_mode);
  if (mode) return mode;
  if (event.decision === "block") return "inline_prevented";
  if (event.decision === "warn") return "warned";
  return "telemetry_only";
}

function gatewayRouted(event: RuntimeTimelineEvent): boolean {
  const metadata = metadataOf(event);
  return metadata.gateway_routed === true || metadata.gateway_enforced === true || metadata.transport === "gateway";
}

function formatFoundryDate(value?: string | null): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toLocaleString();
}

function buildFoundryInventory(events: RuntimeTimelineEvent[]): FoundryInventory {
  const projects = new Map<string, FoundryProjectRow>();
  const agents = new Map<string, FoundryAgentRow>();
  const authorities = new Map<string, FoundryAuthorityRow>();
  const tools = new Set<string>();
  const dataSources = new Set<string>();
  let gatewayCount = 0;
  let telemetryOnly = 0;

  for (const event of events) {
    const metadata = metadataOf(event);
    const mode = controlModeFor(event);
    if (gatewayRouted(event)) gatewayCount += 1;
    if (mode === "telemetry_only" || mode === "detected_only") telemetryOnly += 1;

    const project = textValue(metadata.foundry_project_name, metadata.project_name, metadata.foundry_project_id, metadata.project_id) || "Unknown project";
    const workspace = textValue(metadata.workspace_id, metadata.workspace_name) || "-";
    const subscription = textValue(metadata.subscription_id) || "-";
    const resourceGroup = textValue(metadata.resource_group) || "-";
    const projectKey = `${project}|${workspace}|${subscription}`;
    const existingProject = projects.get(projectKey);
    projects.set(projectKey, {
      key: projectKey,
      project,
      workspace,
      subscription,
      resourceGroup,
      events: (existingProject?.events ?? 0) + 1,
      lastSeen: existingProject?.lastSeen && Date.parse(existingProject.lastSeen) > Date.parse(event.created_at)
        ? existingProject.lastSeen
        : event.created_at,
    });

    const agent = textValue(metadata.agent_name, event.agent_id, metadata.agent_id) || "Unknown agent";
    const model = textValue(event.model, metadata.model, metadata.model_name, metadata.provider) || "-";
    const deployment = textValue(metadata.model_deployment, metadata.model_deployment_id, metadata.deployment_name) || "-";
    const agentKey = `${agent}|${model}|${deployment}`;
    const existingAgent = agents.get(agentKey);
    agents.set(agentKey, {
      key: agentKey,
      agent,
      model,
      deployment,
      controlMode: mode,
      latestAction: event.action_type || event.event_type || "-",
      events: (existingAgent?.events ?? 0) + 1,
    });

    const servicePrincipal = textValue(metadata.service_principal_id) || "-";
    const managedIdentity = textValue(metadata.managed_identity_id) || "-";
    const entraApp = textValue(metadata.entra_app_id) || "-";
    const authority = textValue(metadata.authority, metadata.authority_type) || "-";
    const authorityKey = `${servicePrincipal}|${managedIdentity}|${entraApp}|${authority}`;
    const existingAuthority = authorities.get(authorityKey);
    authorities.set(authorityKey, {
      key: authorityKey,
      servicePrincipal,
      managedIdentity,
      entraApp,
      authority,
      events: (existingAuthority?.events ?? 0) + 1,
    });

    for (const tool of [...arrayValue(metadata.tool_names), ...arrayValue(event.tool_name), ...arrayValue(metadata.tool)]) {
      tools.add(tool);
    }
    for (const dataSource of [...arrayValue(metadata.data_source_ids), ...arrayValue(metadata.data_source)]) {
      dataSources.add(dataSource);
    }
  }

  return {
    projects: [...projects.values()].sort((left, right) => right.events - left.events),
    agents: [...agents.values()].sort((left, right) => right.events - left.events),
    authorities: [...authorities.values()].sort((left, right) => right.events - left.events),
    tools: [...tools].sort(),
    dataSources: [...dataSources].sort(),
    gatewayRouted: gatewayCount,
    telemetryOnly,
    recent: [...events].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at)).slice(0, 8),
  };
}

function buildCopilotInventory(events: RuntimeTimelineEvent[]): CopilotInventory {
  const workloads = new Map<string, CopilotWorkloadRow>();
  const agents = new Map<string, CopilotAgentRow>();
  const permissions = new Map<string, CopilotPermissionRow>();
  const remediationActions = new Set<string>();
  let sensitiveExposures = 0;
  let externalRequired = 0;
  let telemetryOnly = 0;

  for (const event of events) {
    const metadata = metadataOf(event);
    const mode = controlModeFor(event);
    const externalStatus = textValue(metadata.external_action_status);
    const remediation = arrayValue(metadata.remediation_actions);
    if (remediation.length > 0 || mode === "external_required" || externalStatus === "external_required") {
      externalRequired += 1;
    }
    if (mode === "telemetry_only" || mode === "detected_only") telemetryOnly += 1;
    remediation.forEach((item) => remediationActions.add(item));

    const sensitivity = textValue(metadata.sensitivity_label, event.policy_decision, event.reason_code) || "-";
    if (sensitivity !== "-") sensitiveExposures += 1;
    const workload = textValue(metadata.workload, metadata.source_app, metadata.copilot_type, event.application) || "Microsoft Copilot";
    const app = textValue(event.application, metadata.copilot_type, metadata.source) || "copilot";
    const workloadKey = `${workload}|${app}|${sensitivity}`;
    const existingWorkload = workloads.get(workloadKey);
    workloads.set(workloadKey, {
      key: workloadKey,
      workload,
      app,
      sensitivity,
      controlMode: mode,
      events: (existingWorkload?.events ?? 0) + 1,
      lastSeen: existingWorkload?.lastSeen && Date.parse(existingWorkload.lastSeen) > Date.parse(event.created_at)
        ? existingWorkload.lastSeen
        : event.created_at,
    });

    const source = textValue(metadata.source);
    const agentName = textValue(metadata.agent_name, event.agent_id, metadata.oauth_app_name);
    if (source === "microsoft_copilot_studio" || agentName) {
      const connectors = [
        ...arrayValue(metadata.connector_names),
        ...arrayValue(metadata.connector_name),
        ...arrayValue(metadata.tool_names),
      ];
      const scopes = [...arrayValue(metadata.oauth_scopes), ...arrayValue(metadata.permission_scopes)];
      const environment = textValue(metadata.environment_id) || "-";
      const agent = agentName || "Copilot Studio agent";
      const agentKey = `${agent}|${environment}`;
      const existingAgent = agents.get(agentKey);
      agents.set(agentKey, {
        key: agentKey,
        agent,
        environment,
        connectors: [...new Set([...(existingAgent?.connectors ?? []), ...connectors])].sort(),
        scopes: [...new Set([...(existingAgent?.scopes ?? []), ...scopes])].sort(),
        controlMode: mode,
        events: (existingAgent?.events ?? 0) + 1,
      });
    }

    const appName = textValue(metadata.oauth_app_name, metadata.agent_name, metadata.copilot_type, event.application) || "Microsoft Copilot";
    const appId = textValue(metadata.oauth_app_id, metadata.entra_app_id) || "-";
    const scopes = [...arrayValue(metadata.permission_scopes), ...arrayValue(metadata.oauth_scopes)];
    if (appId !== "-" || scopes.length > 0 || remediation.length > 0) {
      const permissionKey = `${appName}|${appId}`;
      const existingPermission = permissions.get(permissionKey);
      permissions.set(permissionKey, {
        key: permissionKey,
        appName,
        appId,
        scopes: [...new Set([...(existingPermission?.scopes ?? []), ...scopes])].sort(),
        remediationActions: [...new Set([...(existingPermission?.remediationActions ?? []), ...remediation])].sort(),
        status: externalStatus || mode,
        events: (existingPermission?.events ?? 0) + 1,
      });
    }
  }

  return {
    workloads: [...workloads.values()].sort((left, right) => right.events - left.events),
    agents: [...agents.values()].sort((left, right) => right.events - left.events),
    permissions: [...permissions.values()].sort((left, right) => right.events - left.events),
    sensitiveExposures,
    externalRequired,
    telemetryOnly,
    remediationActions: [...remediationActions].sort(),
    recent: [...events].sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at)).slice(0, 8),
  };
}

function statusClass(status: SurfaceCard["status"]): string {
  if (status === "Inline now") return "border-emerald-500/40 bg-emerald-500/10 text-emerald-200";
  if (status === "Inline when routed") return "border-sky-500/40 bg-sky-500/10 text-sky-200";
  if (status === "Telemetry + gateway inline") return "border-violet-500/40 bg-violet-500/10 text-violet-200";
  if (status === "Telemetry / external-required") return "border-amber-500/40 bg-amber-500/10 text-amber-200";
  return "border-slate-500/40 bg-slate-500/10 text-slate-200";
}

function surfaceBadgeClass(tone: string): string {
  if (tone === "good") return "border-emerald-500/40 bg-emerald-500/10 text-emerald-200";
  if (tone === "warn") return "border-amber-500/40 bg-amber-500/10 text-amber-200";
  if (tone === "info") return "border-sky-500/40 bg-sky-500/10 text-sky-200";
  return "border-slate-500/40 bg-slate-500/10 text-slate-200";
}

function controlModeClass(mode: string): string {
  if (mode === "inline_prevented") return "border-emerald-500/40 bg-emerald-500/10 text-emerald-200";
  if (mode === "inline_allowed") return "border-sky-500/40 bg-sky-500/10 text-sky-200";
  if (mode === "warned" || mode === "external_required") return "border-amber-500/40 bg-amber-500/10 text-amber-200";
  if (mode === "detected_only" || mode === "telemetry_only") return "border-slate-500/40 bg-slate-500/10 text-slate-200";
  return "border-violet-500/40 bg-violet-500/10 text-violet-200";
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <Card className="rounded-lg">
      <CardContent className="p-4">
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</div>
        <div className="mt-2 text-2xl font-semibold text-slate-100">{value}</div>
      </CardContent>
    </Card>
  );
}

export default function SurfaceCoveragePage() {
  const [dashboard, setDashboard] = useState<CommandCenterDashboardState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [foundryEvents, setFoundryEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [foundryError, setFoundryError] = useState<string | null>(null);
  const [foundryLoading, setFoundryLoading] = useState(true);
  const [copilotEvents, setCopilotEvents] = useState<RuntimeTimelineEvent[]>([]);
  const [copilotError, setCopilotError] = useState<string | null>(null);
  const [copilotLoading, setCopilotLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFoundryLoading(true);
    setCopilotLoading(true);
    api.commandCenterDashboard({ time_window_hours: 168 })
      .then((payload) => {
        if (cancelled) return;
        setDashboard(payload);
        setError(null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Surface coverage refresh failed");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    api.runtimeEvents({ source_surface: "foundry", page_size: 100 })
      .then((payload) => {
        if (cancelled) return;
        setFoundryEvents(payload.items ?? []);
        setFoundryError(null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setFoundryError(err instanceof Error ? err.message : "Foundry event refresh failed");
      })
      .finally(() => {
        if (!cancelled) setFoundryLoading(false);
      });
    api.runtimeEvents({ source_surface: "copilot", page_size: 100 })
      .then((payload) => {
        if (cancelled) return;
        setCopilotEvents(payload.items ?? []);
        setCopilotError(null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setCopilotError(err instanceof Error ? err.message : "Copilot event refresh failed");
      })
      .finally(() => {
        if (!cancelled) setCopilotLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const runtimeSurfaces = useMemo(() => {
    const summary = dashboard?.surface_coverage_summary?.surfaces ?? {};
    return Object.entries(summary).sort(([, left], [, right]) => right.event_count - left.event_count);
  }, [dashboard]);

  const totals = useMemo(() => {
    return runtimeSurfaces.reduce(
      (acc, [, surface]) => {
        acc.events += surface.event_count;
        acc.blocked += surface.blocked;
        acc.warned += surface.warned;
        return acc;
      },
      { events: 0, blocked: 0, warned: 0 },
    );
  }, [runtimeSurfaces]);
  const foundryInventory = useMemo(() => buildFoundryInventory(foundryEvents), [foundryEvents]);
  const copilotInventory = useMemo(() => buildCopilotInventory(copilotEvents), [copilotEvents]);

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="AI Action Control"
          title="Surface Coverage"
          description="A single view of where Hawk is inline, where traffic must be routed, and where visibility is telemetry-only or external-required. Every surface feeds the same AI Action, policy, evidence, and trace spine."
          actions={(
            <div className="flex flex-wrap gap-2">
              <Button asChild variant="outline" size="sm">
                <Link href="/dashboard/command-center">Command Center</Link>
              </Button>
              <Button asChild variant="secondary" size="sm">
                <Link href="/integrations">Integrations</Link>
              </Button>
            </div>
          )}
        />

        <PageSection
          title="Surface Control Center"
          description="Start with a concrete method: browser extension, MCP gateway, LLM gateway, or endpoint agent."
        >
          <div className="grid gap-4 xl:grid-cols-4">
            {OPERATOR_SURFACES.map((surface) => (
              <Card
                key={surface.name}
                id={surface.name === "Browser" ? "browser-extension" : surface.name === "Endpoint Agent" ? "endpoint-agent" : surface.name === "MCP Gateway" ? "mcp-gateway" : surface.name === "LLM Gateway" ? "llm-gateway" : undefined}
                className="rounded-xl border-[#2a3348] bg-[#0f131d] scroll-mt-24"
              >
                <CardHeader className="space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-200">
                        {surface.name}
                      </div>
                      <CardTitle className="mt-2 text-xl">{surface.state}</CardTitle>
                    </div>
                    <Badge className={surfaceBadgeClass(surface.tone)}>{surface.badge}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 text-sm leading-6">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">What we can see</div>
                    <p className="mt-1 text-slate-300">{surface.sees}</p>
                  </div>
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">What we can stop</div>
                    <p className="mt-1 text-slate-300">{surface.stops}</p>
                  </div>
                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-amber-100">
                    <span className="font-semibold">Still missing: </span>
                    {surface.missing}
                  </div>
                  <Button asChild size="sm" variant="outline" className="w-full justify-center">
                    <Link href={surface.href}>{surface.action}</Link>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </PageSection>

        <EvidenceTruthPanel
          title="Surface control status"
          description="Each method states what Hawk can observe, what it can stop, and which route or source is still required."
          whyUnknown="A surface is Unknown when no fresh capability, validation, route, or control-point evidence exists for that surface in this tenant. Adapter existence alone is not enough."
          lastEvidence={foundryEvents[0]?.created_at || copilotEvents[0]?.created_at || null}
          connectHref="/integrations"
          testHref="/validate"
          sourceMode={totals.events ? "observed" : "unknown"}
          facts={[
            {
              label: "Browser",
              value: "Extension / managed browser",
              detail: "Prompt, paste, upload and account context when the managed extension is healthy.",
              tone: "observed",
            },
            {
              label: "Endpoint",
              value: "Agent / MDM path",
              detail: "File, process, command and local network controls need an enrolled device identity.",
              tone: "unknown",
            },
            {
              label: "Runtime / MCP",
              value: "Gateway-routed only",
              detail: "Tool calls are enforceable only when Claude, Codex, Cursor or agents route through the governed MCP/runtime path.",
              tone: totals.events ? "observed" : "unknown",
            },
            {
              label: "SaaS & APIs",
              value: "Provider-native separate",
              detail: "Provider-native verification is separate from browser observation and requires an admin/provider connector.",
              tone: "unknown",
            },
          ]}
        />

        <PageSection
          title="Next actions to make coverage real"
          description="Use these actions instead of treating an empty denominator as a product failure."
        >
          <div className="grid gap-3 md:grid-cols-4">
            {[
              ["1", "Test browser prompt block", "Send one safe blocked prompt from Chrome, then open Action Explorer and Evidence."],
              ["2", "Enroll this endpoint", "Generate a signed endpoint heartbeat and run one harmless command-control test."],
              ["3", "Route MCP clients", "Connect Claude/Codex/Cursor through the governed MCP gateway and run allow/block repo tests."],
              ["4", "Connect provider admin", "Add OpenAI, Anthropic, Google, M365, GitHub, identity, or cloud admin sources for authoritative denominators."],
            ].map(([step, title, body]) => (
              <div key={step} className="rounded-lg border border-[#2a3348] bg-[#101521] p-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full border border-brand-400/40 bg-brand-400/10 text-sm font-bold text-brand-200">
                    {step}
                  </div>
                  <div className="text-sm font-semibold text-slate-100">{title}</div>
                </div>
                <p className="mt-3 text-sm leading-6 text-slate-400">{body}</p>
              </div>
            ))}
          </div>
        </PageSection>

        <details className="rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-200">Advanced coverage evidence</summary>
          <div className="border-t border-white/[0.07] p-4">
            <NativeControlMatrix />
          </div>
        </details>

        <div className="grid gap-3 md:grid-cols-4">
          <Metric label="Observed Surface Events" value={loading ? "..." : totals.events} />
          <Metric label="Inline Blocks" value={loading ? "..." : totals.blocked} />
          <Metric label="Warnings / Reviews" value={loading ? "..." : totals.warned} />
          <Metric label="Configured Surfaces" value={SURFACE_CARDS.length} />
        </div>

        {error ? (
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
            Surface telemetry could not refresh: {error}. The control-surface model below is still available.
          </div>
        ) : null}

        <details className="rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-200">Control mode definitions</summary>
          <div className="border-t border-white/[0.07] p-4">
          <div className="grid gap-3 md:grid-cols-4">
            {[
              ["Inline Prevented", "Hawk blocked before execution."],
              ["Inline When Routed", "Hawk can block only if the path goes through Gateway, SDK, MCP proxy, or extension."],
              ["Telemetry Only", "Hawk observed after or outside the path."],
              ["External Required", "Hawk needs Microsoft, Google, SWG, MDM, EDR, or SaaS admin control to enforce."],
            ].map(([label, text]) => (
              <div key={label} className="rounded-lg border border-[#2a3348] bg-[#0f131d] p-4">
                <div className="text-sm font-semibold text-slate-100">{label}</div>
                <div className="mt-2 text-sm leading-6 text-slate-400">{text}</div>
              </div>
            ))}
          </div>
          </div>
        </details>

        <details className="rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-200">Detailed surface capability map</summary>
          <div className="grid gap-4 border-t border-white/[0.07] p-4 lg:grid-cols-2">
            {SURFACE_CARDS.map((surface) => (
            <Card key={surface.name} className="rounded-lg">
              <CardHeader className="pb-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <CardTitle>{surface.name}</CardTitle>
                  <Badge className={statusClass(surface.status)}>{surface.status}</Badge>
                </div>
                <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                  {surface.controlMode}
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Observed Path</div>
                  <p className="mt-2 text-sm leading-6 text-slate-300">{surface.observes}</p>
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {surface.capabilities.map((capability) => (
                    <div key={capability} className="rounded-md border border-[#263047] bg-[#101521] px-3 py-2 text-sm text-slate-300">
                      {capability}
                    </div>
                  ))}
                </div>
                <div className="rounded-md border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-sm leading-6 text-amber-100">
                  {surface.limitation}
                </div>
                <Button asChild variant="ghost" size="sm" className="px-0 text-brand-300 hover:bg-transparent">
                  <Link href={surface.href}>Open related view</Link>
                </Button>
              </CardContent>
            </Card>
            ))}
          </div>
        </details>

        {CONTROL_COVERAGE_UI_ENABLED ? (
          <details className="rounded-xl border border-white/[0.08] bg-[#0a0f16]">
            <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-200">Technical control coverage atlas</summary>
            <div className="border-t border-white/[0.07] p-4"><ControlCoveragePanel /></div>
          </details>
        ) : null}

        <details className="rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-200">Advanced product and telemetry evidence</summary>
          <div className="space-y-6 border-t border-white/[0.07] p-4">
        <div id="foundry" className="scroll-mt-24">
          <PageSection
            title="Microsoft Foundry Surface"
            description="Foundry projects, agents, model deployments, Entra authority, tools, data sources, and Azure OpenAI calls normalized into the same AI Action trace."
          >
            <div className="grid gap-3 md:grid-cols-5">
              <Metric label="Foundry Events" value={foundryLoading ? "..." : foundryEvents.length} />
              <Metric label="Projects" value={foundryLoading ? "..." : foundryInventory.projects.length} />
              <Metric label="Agents / Models" value={foundryLoading ? "..." : foundryInventory.agents.length} />
              <Metric label="Gateway Routed" value={foundryLoading ? "..." : foundryInventory.gatewayRouted} />
              <Metric label="Telemetry Only" value={foundryLoading ? "..." : foundryInventory.telemetryOnly} />
            </div>

            {foundryError ? (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
                Foundry events could not refresh: {foundryError}.
              </div>
            ) : null}

            {foundryEvents.length > 0 ? (
              <div className="grid gap-4 xl:grid-cols-2">
                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>Projects / Workspaces</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[680px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">Project</th>
                            <th className="px-4 py-3">Workspace</th>
                            <th className="px-4 py-3">Subscription</th>
                            <th className="px-4 py-3">Resource Group</th>
                            <th className="px-4 py-3">Events</th>
                            <th className="px-4 py-3">Last Seen</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {foundryInventory.projects.slice(0, 6).map((project) => (
                            <tr key={project.key} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3 font-semibold text-slate-100">{project.project}</td>
                              <td className="px-4 py-3">{project.workspace}</td>
                              <td className="px-4 py-3">{project.subscription}</td>
                              <td className="px-4 py-3">{project.resourceGroup}</td>
                              <td className="px-4 py-3">{project.events}</td>
                              <td className="px-4 py-3">{formatFoundryDate(project.lastSeen)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>

                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>Agents / Model Deployments</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[620px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">Agent</th>
                            <th className="px-4 py-3">Model</th>
                            <th className="px-4 py-3">Deployment</th>
                            <th className="px-4 py-3">Control Mode</th>
                            <th className="px-4 py-3">Latest Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {foundryInventory.agents.slice(0, 6).map((agent) => (
                            <tr key={agent.key} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3 font-semibold text-slate-100">{agent.agent}</td>
                              <td className="px-4 py-3">{agent.model}</td>
                              <td className="px-4 py-3">{agent.deployment}</td>
                              <td className="px-4 py-3">
                                <Badge className={controlModeClass(agent.controlMode)}>{agent.controlMode}</Badge>
                              </td>
                              <td className="px-4 py-3">{agent.latestAction}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>

                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>Tools + Data Sources</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Tools</div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {(foundryInventory.tools.length ? foundryInventory.tools : ["No tool calls observed yet"]).slice(0, 12).map((tool) => (
                          <Badge key={tool} className="border-sky-500/30 bg-sky-500/10 text-sky-200">{tool}</Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">Data Sources</div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {(foundryInventory.dataSources.length ? foundryInventory.dataSources : ["No data-source references observed yet"]).slice(0, 12).map((dataSource) => (
                          <Badge key={dataSource} className="border-violet-500/30 bg-violet-500/10 text-violet-200">{dataSource}</Badge>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>Identity / Authority Mapping</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[680px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">Service Principal</th>
                            <th className="px-4 py-3">Managed Identity</th>
                            <th className="px-4 py-3">Entra App</th>
                            <th className="px-4 py-3">Authority</th>
                            <th className="px-4 py-3">Events</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {foundryInventory.authorities.slice(0, 6).map((authority) => (
                            <tr key={authority.key} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3">{authority.servicePrincipal}</td>
                              <td className="px-4 py-3">{authority.managedIdentity}</td>
                              <td className="px-4 py-3">{authority.entraApp}</td>
                              <td className="px-4 py-3">{authority.authority}</td>
                              <td className="px-4 py-3">{authority.events}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>

                <Card className="rounded-lg xl:col-span-2">
                  <CardHeader>
                    <CardTitle>Recent Foundry Action Trace</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[920px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">Time</th>
                            <th className="px-4 py-3">Action</th>
                            <th className="px-4 py-3">App / Agent</th>
                            <th className="px-4 py-3">Decision</th>
                            <th className="px-4 py-3">Control Mode</th>
                            <th className="px-4 py-3">Chain</th>
                            <th className="px-4 py-3">Evidence</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {foundryInventory.recent.map((event) => (
                            <tr key={event.event_id} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3">{formatFoundryDate(event.created_at)}</td>
                              <td className="px-4 py-3 font-semibold text-slate-100">{event.action_type || event.event_type}</td>
                              <td className="px-4 py-3">{event.application || event.agent_id || event.ai_system_id || "-"}</td>
                              <td className="px-4 py-3">{event.decision}</td>
                              <td className="px-4 py-3">
                                <Badge className={controlModeClass(controlModeFor(event))}>{controlModeFor(event)}</Badge>
                              </td>
                              <td className="px-4 py-3">
                                {event.chain_id ? (
                                  <Link className="text-brand-300 hover:text-brand-200" href={`/runtime-intelligence/chains/${event.chain_id}/graph`}>
                                    {event.chain_id.slice(0, 8)}
                                  </Link>
                                ) : "-"}
                              </td>
                              <td className="px-4 py-3">{event.evidence_node_ids?.length ?? 0}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>
              </div>
            ) : (
              <div className="rounded-lg border border-[#2a3348] bg-[#0f131d] px-4 py-6 text-sm leading-6 text-slate-400">
                {foundryLoading
                  ? "Loading Foundry telemetry..."
                  : "No Foundry events yet. Send Foundry project, agent, model, Entra identity, tool, and data-source activity into POST /surface-coverage/microsoft/foundry/events to populate this trace."}
              </div>
            )}
          </PageSection>
        </div>

        <div id="copilot" className="scroll-mt-24">
          <PageSection
            title="Microsoft Copilot Surface"
            description="M365 Copilot and Copilot Studio events normalized into Hawk's action-control spine. This view is explicit about telemetry-only visibility and external-required remediation."
          >
            <div className="grid gap-3 md:grid-cols-6">
              <Metric label="Copilot Events" value={copilotLoading ? "..." : copilotEvents.length} />
              <Metric label="Workloads" value={copilotLoading ? "..." : copilotInventory.workloads.length} />
              <Metric label="Studio Agents" value={copilotLoading ? "..." : copilotInventory.agents.length} />
              <Metric label="OAuth / Apps" value={copilotLoading ? "..." : copilotInventory.permissions.length} />
              <Metric label="Sensitive Exposure" value={copilotLoading ? "..." : copilotInventory.sensitiveExposures} />
              <Metric label="External Required" value={copilotLoading ? "..." : copilotInventory.externalRequired} />
            </div>

            {copilotError ? (
              <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-100">
                Copilot telemetry could not refresh: {copilotError}
              </div>
            ) : null}

            {copilotEvents.length > 0 ? (
              <div className="mt-4 grid gap-4 xl:grid-cols-2">
                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>M365 Copilot Workloads</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[760px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">Workload</th>
                            <th className="px-4 py-3">App</th>
                            <th className="px-4 py-3">Sensitivity</th>
                            <th className="px-4 py-3">Events</th>
                            <th className="px-4 py-3">Mode</th>
                            <th className="px-4 py-3">Last Seen</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {copilotInventory.workloads.map((row) => (
                            <tr key={row.key} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3 font-semibold text-slate-100">{row.workload}</td>
                              <td className="px-4 py-3">{row.app}</td>
                              <td className="px-4 py-3">{row.sensitivity}</td>
                              <td className="px-4 py-3">{row.events}</td>
                              <td className="px-4 py-3">
                                <Badge className={controlModeClass(row.controlMode)}>{row.controlMode}</Badge>
                              </td>
                              <td className="px-4 py-3">{formatFoundryDate(row.lastSeen)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>

                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>Copilot Studio Agents + Connectors</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[820px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">Agent</th>
                            <th className="px-4 py-3">Environment</th>
                            <th className="px-4 py-3">Connectors</th>
                            <th className="px-4 py-3">OAuth Scopes</th>
                            <th className="px-4 py-3">Events</th>
                            <th className="px-4 py-3">Mode</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {copilotInventory.agents.map((row) => (
                            <tr key={row.key} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3 font-semibold text-slate-100">{row.agent}</td>
                              <td className="px-4 py-3">{row.environment}</td>
                              <td className="px-4 py-3">{row.connectors.join(", ") || "-"}</td>
                              <td className="px-4 py-3">{row.scopes.join(", ") || "-"}</td>
                              <td className="px-4 py-3">{row.events}</td>
                              <td className="px-4 py-3">
                                <Badge className={controlModeClass(row.controlMode)}>{row.controlMode}</Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>

                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>OAuth / App Permissions + Remediation</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[820px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">App</th>
                            <th className="px-4 py-3">App ID</th>
                            <th className="px-4 py-3">Scopes</th>
                            <th className="px-4 py-3">Remediation</th>
                            <th className="px-4 py-3">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {copilotInventory.permissions.map((row) => (
                            <tr key={row.key} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3 font-semibold text-slate-100">{row.appName}</td>
                              <td className="px-4 py-3">{row.appId}</td>
                              <td className="px-4 py-3">{row.scopes.join(", ") || "-"}</td>
                              <td className="px-4 py-3">{row.remediationActions.join(", ") || "-"}</td>
                              <td className="px-4 py-3">
                                <Badge className={controlModeClass(row.status)}>{row.status}</Badge>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>

                <Card className="rounded-lg">
                  <CardHeader>
                    <CardTitle>Recent Copilot Action Trace</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="overflow-hidden rounded-lg border border-[#2a3348]">
                      <table className="w-full min-w-[880px] text-left text-sm">
                        <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                          <tr>
                            <th className="px-4 py-3">Time</th>
                            <th className="px-4 py-3">Action</th>
                            <th className="px-4 py-3">Actor</th>
                            <th className="px-4 py-3">Application</th>
                            <th className="px-4 py-3">Decision</th>
                            <th className="px-4 py-3">Mode</th>
                            <th className="px-4 py-3">Evidence</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#253049]">
                          {copilotInventory.recent.map((event) => (
                            <tr key={event.event_id} className="bg-[#0f131d] text-slate-300">
                              <td className="px-4 py-3">{formatFoundryDate(event.created_at)}</td>
                              <td className="px-4 py-3 font-semibold text-slate-100">{event.action_type || event.event_type}</td>
                              <td className="px-4 py-3">{event.user_email || event.user_id || event.agent_id || "-"}</td>
                              <td className="px-4 py-3">{event.application || event.provider || "-"}</td>
                              <td className="px-4 py-3">{event.decision}</td>
                              <td className="px-4 py-3">
                                <Badge className={controlModeClass(controlModeFor(event))}>{controlModeFor(event)}</Badge>
                              </td>
                              <td className="px-4 py-3">{event.evidence_node_ids?.length ?? 0}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>
              </div>
            ) : (
              <div className="mt-4 rounded-lg border border-[#2a3348] bg-[#0f131d] px-4 py-6 text-sm leading-6 text-slate-400">
                {copilotLoading
                  ? "Loading Copilot telemetry..."
                  : "No Copilot events yet. Ingest M365 Copilot activity into POST /surface-coverage/microsoft/copilot/events and Copilot Studio connector activity into POST /surface-coverage/microsoft/copilot-studio/events."}
              </div>
            )}
          </PageSection>
        </div>

        <PageSection
          title="Observed Telemetry"
          description="Live counts from Command Center surface coverage. Empty rows mean no fresh telemetry has landed for that surface yet."
        >
          {runtimeSurfaces.length > 0 ? (
            <div className="overflow-hidden rounded-lg border border-[#2a3348]">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="bg-[#101521] text-xs uppercase tracking-[0.16em] text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Surface</th>
                    <th className="px-4 py-3">Events</th>
                    <th className="px-4 py-3">Blocked</th>
                    <th className="px-4 py-3">Warned</th>
                    <th className="px-4 py-3">Apps</th>
                    <th className="px-4 py-3">Users</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#253049]">
                  {runtimeSurfaces.map(([name, surface]: [string, SurfaceRuntimeSummary]) => (
                    <tr key={name} className="bg-[#0f131d] text-slate-300">
                      <td className="px-4 py-3 font-semibold text-slate-100">{name}</td>
                      <td className="px-4 py-3">{surface.event_count}</td>
                      <td className="px-4 py-3">{surface.blocked}</td>
                      <td className="px-4 py-3">{surface.warned}</td>
                      <td className="px-4 py-3">{surface.apps.slice(0, 4).join(", ") || "-"}</td>
                      <td className="px-4 py-3">{surface.users.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="rounded-lg border border-[#2a3348] bg-[#0f131d] px-4 py-6 text-sm text-slate-400">
              {loading ? "Loading surface telemetry..." : "No surface telemetry yet. Browser extension events should appear here after policy sync and telemetry ingest succeed."}
            </div>
          )}
        </PageSection>

        <PageSection
          title="Customer Demo Path"
          description="Use these as the targeted story instead of showing every module. Each step lands in the same action-control evidence trail."
        >
          <div className="grid gap-3 md:grid-cols-4">
            {[
              ["Browser AI", "Paste business email into ChatGPT, require justification, then show action, decision, evidence, and trace."],
              ["MCP / Developer", "Allow read-only tool calls, block write/admin/secret actions, then open Agent Touchpoint Graph."],
              ["Foundry", "Show project, agent, model, service principal, data-source, and gateway-routed call trace."],
              ["Copilot", "Show Copilot activity, Studio connector/OAuth risk, and external-required remediation path."],
            ].map(([title, body]) => (
              <div key={title} className="rounded-lg border border-[#2a3348] bg-[#0f131d] p-4">
                <div className="text-sm font-semibold text-slate-100">{title}</div>
                <p className="mt-2 text-sm leading-6 text-slate-400">{body}</p>
              </div>
            ))}
          </div>
        </PageSection>
          </div>
        </details>
      </div>
    </AppShell>
  );
}
