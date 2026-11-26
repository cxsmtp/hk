import type {
  HawkBaseResponse,
  LlmInterceptRequest,
  ResponseControlCoverage,
} from "../src/index.js";
import type {
  EndpointDecisionReceipt,
  EndpointDeveloperAgentRequest,
  HawkEndpointClientOptions,
} from "../src/node-client.js";

const endpointOptions = {
  mode: "endpoint",
  endpointSocketPath: "/private/tmp/hawk/agent.sock",
  endpointTrustedDeviceThumbprint: "a".repeat(64),
  clientName: "bank-app",
} satisfies HawkEndpointClientOptions;
void endpointOptions;

const endpointReceipt = {
  request_id: "request-1",
  surface: "sdk",
  decision: "allow",
  control_mode: "inline_allowed",
  reason_code: "endpoint_allowed",
  evidence_ref: null,
  client_name: "bank-app",
  client_version: "1.0.0",
  process_id: 42,
} satisfies EndpointDecisionReceipt;
// @ts-expect-error raw prompts are not part of endpoint receipt types.
endpointReceipt.prompt;

const developerAgentRequest = {
  ai_system_id: "developer-agent",
  actor_id: "agent-1",
  capability_token: "short-lived-capability-token",
  action: "repository.read",
  resource: "repo:///settings/guide",
} satisfies EndpointDeveloperAgentRequest;
void developerAgentRequest;

// @ts-expect-error endpoint developer-agent calls require an explicit capability token.
const missingDeveloperCapability: EndpointDeveloperAgentRequest = {
  ai_system_id: "developer-agent",
  actor_id: "agent-1",
  action: "repository.read",
  resource: "repo:///settings/guide",
};
void missingDeveloperCapability;

const coverageValues: ResponseControlCoverage[] = [
  "complete",
  "partial",
  "request_only",
  "post_execution",
  "unknown",
];

const response = {
  response_control_coverage: "complete",
  chain_id: "bank-chain-1",
  parent_action_id: "parent-action-1",
} satisfies HawkBaseResponse;

const request = {
  ai_system_id: "ai-system-1",
  actor_type: "agent",
  actor_id: "agent-1",
  prompt: "Summarize approved controls",
  chain_id: response.chain_id,
  parent_action_id: response.parent_action_id,
} satisfies LlmInterceptRequest;

void request;

// @ts-expect-error response-control coverage is intentionally a closed vocabulary.
const unsupportedCoverage: ResponseControlCoverage = "caller_defined";
void unsupportedCoverage;
