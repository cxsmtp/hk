export type AgentRuntimeIntegrationView = {
  capability: string;
  transport: string;
  destinationDomain: string;
  active: boolean;
  evidenceBasis: string;
};

export type AgentRuntimeProfileView = {
  agentId: string;
  agentName: string;
  runtimeProvider: string;
  modelProvider: string;
  modelName: string;
  models: string[];
  tools: string[];
  actions: string[];
  privileges: string[];
  listeningPorts: number[];
  activeTransport: string;
  integrations: AgentRuntimeIntegrationView[];
  controlState: string;
  requestedMode: string;
  preActionSurfaces: string[];
  evidenceBasis: string;
};

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function text(value: unknown, fallback = "unknown"): string {
  const normalized = typeof value === "string" ? value.trim() : "";
  return normalized || fallback;
}

function strings(value: unknown, maxItems = 32): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value
        .slice(0, maxItems)
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
}

function ports(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value
        .slice(0, 16)
        .filter((item): item is number => Number.isInteger(item) && item > 0 && item <= 65535),
    ),
  );
}

export function deriveAgentRuntimeProfile(metadata: unknown): AgentRuntimeProfileView | null {
  const entityMetadata = asRecord(metadata);
  const profile = asRecord(entityMetadata.agent_runtime_profile);
  const agentId = text(profile.agent_id, "");
  const agentName = text(profile.agent_name, "");
  if (!agentId && !agentName) return null;

  const binding = asRecord(profile.control_binding);
  const integrations = Array.isArray(profile.integration_transports)
    ? profile.integration_transports.slice(0, 16).flatMap((value) => {
        const route = asRecord(value);
        const capability = text(route.capability, "");
        const transport = text(route.transport, "");
        const destinationDomain = text(route.destination_domain, "");
        const evidenceBasis = text(route.evidence_basis, "");
        if (!capability || !transport || !destinationDomain || !evidenceBasis) return [];
        return [{
          capability,
          transport,
          destinationDomain,
          active: route.active === true,
          evidenceBasis,
        }];
      })
    : [];

  return {
    agentId: agentId || "unknown",
    agentName: agentName || agentId || "Unknown agent",
    runtimeProvider: text(profile.runtime_provider),
    modelProvider: text(profile.model_provider),
    modelName: text(profile.model_name),
    models: strings(profile.models, 16),
    tools: strings(profile.tools),
    actions: strings(profile.actions),
    privileges: strings(profile.privileges),
    listeningPorts: ports(profile.listening_ports),
    activeTransport: text(profile.active_integration_transport),
    integrations,
    controlState: text(entityMetadata.control_binding_state),
    requestedMode: text(binding.mode, "monitor"),
    preActionSurfaces: strings(binding.pre_action_surfaces, 8),
    evidenceBasis: text(entityMetadata.evidence_basis || profile.evidence_basis),
  };
}
