import { createHash } from "node:crypto";


const GMAIL_TOOLS = {
  GMAIL_FETCH_EMAILS: {
    action: "email.read",
    resource: "gmail://mailbox",
    sideEffect: false,
  },
  GMAIL_CREATE_DRAFT: {
    action: "email.draft.create",
    resource: "gmail://drafts",
    sideEffect: true,
  },
  GMAIL_SEND_EMAIL: {
    action: "email.send",
    resource: "gmail://outbound",
    sideEffect: true,
  },
};

const TOOL_NAMES = ["web_search", ...Object.keys(GMAIL_TOOLS)];
const ACTIONS = ["web.read", ...Object.values(GMAIL_TOOLS).map((tool) => tool.action)];


export class HawkAgentBindingBlockedError extends Error {
  constructor(reasonCode = "hawk_endpoint_authorization_required", decision = null) {
    super("Hawk blocked the Agent OS action");
    this.name = "HawkAgentBindingBlockedError";
    this.reasonCode = reasonCode;
    this.decision = decision;
  }
}


export function detectGmailTransport(env = process.env) {
  const explicit = String(env.GMAIL_TRANSPORT || "").trim().toLowerCase();
  if (explicit === "composio" || explicit === "google_direct") return explicit;
  if (String(env.COMPOSIO_API_KEY || "").trim()) return "composio";
  return "unknown";
}


function gmailDestination(transport) {
  if (transport === "composio") return "backend.composio.dev";
  if (transport === "google_direct") return "gmail.googleapis.com";
  return "unknown.invalid";
}


function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, stableValue(value[key])]),
  );
}


function argumentHash(args) {
  return createHash("sha256")
    .update(JSON.stringify(stableValue(args || {})))
    .digest("hex");
}


function requireAuthorized(decision) {
  const finalDecision = String(decision?.final_decision || decision?.decision || "").toLowerCase();
  if (
    decision?.endpoint_authorized !== true
    || decision?.decision_source !== "endpoint_agent"
    || !["allow", "warn"].includes(finalDecision)
  ) {
    throw new HawkAgentBindingBlockedError(
      String(decision?.reason_code || "hawk_endpoint_authorization_required"),
      decision || null,
    );
  }
  return decision;
}


function boundedModels(models) {
  if (!Array.isArray(models)) return [];
  return [...new Set(models.map((model) => String(model || "").trim()).filter(Boolean))].slice(0, 16);
}


async function defaultClient(env) {
  const socketPath = String(env.HAWK_ENDPOINT_SOCKET_PATH || "").trim();
  const thumbprint = String(env.HAWK_ENDPOINT_TRUSTED_DEVICE_THUMBPRINT || "").trim().toLowerCase();
  if (!socketPath || !/^[0-9a-f]{64}$/.test(thumbprint)) {
    throw new HawkAgentBindingBlockedError("hawk_endpoint_trust_configuration_missing");
  }
  const { HawkClient } = await import("@hawk-ai/sdk/endpoint");
  return new HawkClient({
    mode: "endpoint",
    endpointSocketPath: socketPath,
    endpointTrustedDeviceThumbprint: thumbprint,
    clientName: "agent-os",
    clientVersion: "1.0.0",
  });
}


export async function createAgentOsBinding(options = {}) {
  const env = options.env || process.env;
  const client = options.hawkClient || await defaultClient(env);
  const gmailTransport = detectGmailTransport(env);
  const aiSystemId = String(env.HAWK_AGENT_AI_SYSTEM_ID || "").trim();
  const agentMode = String(env.HAWK_AGENT_MODE || "enforce").trim().toLowerCase() === "monitor"
    ? "monitor"
    : "enforce";
  const capabilityTokenProvider = options.capabilityTokenProvider
    || (() => String(env.HAWK_AGENT_CAPABILITY_TOKEN || "").trim());
  let lastRegistration = null;
  let lastDecision = null;

  async function register({ models = [] } = {}) {
    const registration = {
      agent_id: "agent-os-local",
      agent_name: "Agent OS",
      agent_version: "1.0.0",
      runtime_provider: "node",
      model_provider: "ollama",
      model_name: boundedModels(models)[0] || "qwen3.5:9b",
      models: boundedModels(models),
      detected_tools: [...TOOL_NAMES],
      detected_actions: [...ACTIONS],
      detected_privileges: ["internet", "mailbox.read", "mailbox.write", "local_model.execute"],
      listening_ports: [Number(env.PORT || 4000), Number(env.AGENT_OS_UI_PORT || 5174)]
        .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535),
      integration_transports: [
        {
          capability: "gmail",
          transport: "composio",
          destination_domain: "backend.composio.dev",
          active: gmailTransport === "composio",
          evidence_basis: gmailTransport === "composio" ? "runtime_configuration" : "supported_binding",
        },
        {
          capability: "gmail",
          transport: "google_direct",
          destination_domain: "gmail.googleapis.com",
          active: gmailTransport === "google_direct",
          evidence_basis: gmailTransport === "google_direct" ? "runtime_configuration" : "supported_binding",
        },
        {
          capability: "web_search",
          transport: "tavily_direct",
          destination_domain: "api.tavily.com",
          active: Boolean(String(env.TAVILY_API_KEY || "").trim()),
          evidence_basis: "runtime_configuration",
        },
        {
          capability: "llm",
          transport: "local_ollama",
          destination_domain: "localhost",
          active: true,
          evidence_basis: "runtime_configuration",
        },
      ],
      active_integration_transport: gmailTransport,
      control_binding: {
        mode: agentMode,
        pre_action_surfaces: ["llm", "developer_agent"],
      },
    };
    lastRegistration = await client.endpointRegisterAgent(registration);
    return lastRegistration;
  }

  async function authorizeLlm({ prompt, model }) {
    if (!aiSystemId) {
      throw new HawkAgentBindingBlockedError("hawk_ai_system_configuration_missing");
    }
    try {
      lastDecision = await client.endpointLlm({
        ai_system_id: aiSystemId,
        actor_type: "agent",
        actor_id: "agent-os-local",
        prompt: String(prompt || ""),
        provider: "ollama",
        model: String(model || "qwen3.5:9b"),
        api_endpoint: "http://localhost:11434/api/chat",
        tool_category: "local_llm",
      });
      return requireAuthorized(lastDecision);
    } catch (error) {
      if (error instanceof HawkAgentBindingBlockedError) throw error;
      throw new HawkAgentBindingBlockedError("hawk_endpoint_unavailable");
    }
  }

  async function authorizeTool({ toolName, args = {} }) {
    if (!aiSystemId) {
      throw new HawkAgentBindingBlockedError("hawk_ai_system_configuration_missing");
    }
    const gmail = GMAIL_TOOLS[toolName];
    const descriptor = toolName === "web_search"
      ? {
          action: "web.read",
          resource: "web://search",
          sideEffect: false,
          transport: "tavily_direct",
          destination: "api.tavily.com",
        }
      : gmail
        ? {
            ...gmail,
            transport: gmailTransport,
            destination: gmailDestination(gmailTransport),
          }
        : null;
    if (!descriptor) throw new HawkAgentBindingBlockedError("unsupported_agent_tool");
    if (gmail && gmailTransport === "unknown") {
      throw new HawkAgentBindingBlockedError("gmail_transport_unverified");
    }
    const capabilityToken = String(await capabilityTokenProvider()).trim();
    if (!capabilityToken) {
      throw new HawkAgentBindingBlockedError("capability_token_unavailable");
    }
    try {
      lastDecision = await client.endpointDeveloperAgent({
        ai_system_id: aiSystemId,
        actor_id: "agent-os-local",
        capability_token: capabilityToken,
        action: descriptor.action,
        resource: descriptor.resource,
        tool_name: toolName,
        provider: descriptor.transport,
        model: "qwen3.5:9b",
        tool_category: gmail ? "email" : "web_search",
        api_endpoint: `https://${descriptor.destination}`,
        data_source: gmail ? "gmail" : "public_web",
        tool_usage_meta: {
          integration_transport: descriptor.transport,
          destination_domain: descriptor.destination,
          side_effect: descriptor.sideEffect,
          parameter_hash: argumentHash(args),
          evidence_basis: "endpoint_pre_action_binding",
        },
      });
      return requireAuthorized(lastDecision);
    } catch (error) {
      if (error instanceof HawkAgentBindingBlockedError) throw error;
      throw new HawkAgentBindingBlockedError("hawk_endpoint_unavailable");
    }
  }

  return {
    activeGmailTransport: gmailTransport,
    register,
    authorizeLlm,
    authorizeTool,
    async withLlmAuthorization(input, execute) {
      const hawk = await authorizeLlm(input);
      return { hawk, result: await execute(hawk) };
    },
    async withToolAuthorization(input, execute) {
      const hawk = await authorizeTool(input);
      return { hawk, result: await execute(hawk) };
    },
    status() {
      return {
        activeGmailTransport: gmailTransport,
        aiSystemConfigured: Boolean(aiSystemId),
        mode: agentMode,
        registration: lastRegistration,
        lastDecision: lastDecision
          ? {
              decision: lastDecision.final_decision || lastDecision.decision,
              controlMode: lastDecision.control_mode,
              evidenceRef: lastDecision.evidence_bundle_id || null,
            }
          : null,
      };
    },
  };
}
