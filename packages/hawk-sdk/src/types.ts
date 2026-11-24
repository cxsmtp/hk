export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export type HawkDecision =
  | "allow"
  | "warn"
  | "block"
  | "redact"
  | "review"
  | "step_up"
  | "require_approval"
  | "require_second_approval"
  | "require_justification"
  | "shadow_would_block"
  | "detect_only";

export type HawkControlMode =
  | "inline_prevented"
  | "inline_allowed"
  | "warned"
  | "shadow_would_block"
  | "detected_only"
  | "telemetry_only"
  | "external_required"
  | "external_action_triggered"
  | "incomplete";

export type ResponseControlCoverage =
  | "complete"
  | "partial"
  | "request_only"
  | "post_execution"
  | "unknown";

export type HawkThreatType =
  | "prompt_injection"
  | "jailbreak"
  | "system_prompt_leakage"
  | "encoding_obfuscation"
  | "excessive_agency"
  | "privilege_escalation"
  | "rag_poisoning"
  | "context_poisoning"
  | "tool_output_injection"
  | "goal_manipulation"
  | "identity_spoofing"
  | "deceptive_behavior"
  | "resource_exhaustion"
  | "code_execution"
  | "sensitive_data_leakage"
  | "output_asymmetry"
  | "memory_poisoning"
  | "tool_poisoning"
  | string;

export type ThreatFrameworkRefs = {
  owasp_llm?: string | null;
  owasp_agentic?: string | null;
  mitre_atlas?: string | null;
};

export type HawkGuardianResult = {
  guardian_id?: string;
  guardian_contract_id?: string;
  decision?: HawkDecision | string;
  confidence?: number;
  threat_types?: HawkThreatType[];
  framework_refs?: ThreatFrameworkRefs;
  actions_taken?: JsonObject;
  [key: string]: unknown;
};

export type HawkBackendClientOptions = {
  mode?: "backend";
  apiUrl: string;
  tenantId: string;
  accessToken?: string;
  apiKey?: string;
  fetchImpl?: typeof fetch;
};

export type HawkEndpointClientOptions = {
  mode: "endpoint";
  endpointSocketPath: string;
  /** Non-secret SHA-256 pin for the enrolled endpoint device public key. */
  endpointTrustedDeviceThumbprint: string;
  endpointTimeoutMs?: number;
  endpointMaxRequestBytes?: number;
  endpointMaxResponseBytes?: number;
  clientName?: string;
  clientVersion?: string;
};

export type HawkClientOptions = HawkBackendClientOptions | HawkEndpointClientOptions;

export type EndpointSurface =
  | "llm"
  | "sdk"
  | "developer_agent"
  | "foundry"
  | "data_transfer";

export type EndpointDecisionReceipt = {
  request_id: string;
  surface: EndpointSurface;
  decision: "allow" | "warn" | "block";
  control_mode: string;
  reason_code: string;
  evidence_ref: string | null;
  client_name: string;
  client_version: string;
  process_id: number;
};

export type EndpointDecisionResponse = HawkBaseResponse & {
  final_decision: "allow" | "warn" | "block";
  decision: "allow" | "warn" | "block";
  control_mode: string;
  reason_code: string;
  evidence_bundle_id: string | null;
  endpoint_authorized: boolean;
  decision_source: "endpoint_agent" | "endpoint_agent_monitor" | "endpoint_agent_fail_secure";
  endpoint_surface: EndpointSurface;
  would_decision?: HawkDecision | string;
  receipt: EndpointDecisionReceipt;
};

export type EndpointIntegrationTransport =
  | "composio"
  | "google_direct"
  | "tavily_direct"
  | "local_ollama"
  | "unknown";

export type EndpointAgentIntegration = {
  capability: string;
  transport: EndpointIntegrationTransport;
  destination_domain: string;
  active: boolean;
  evidence_basis: "runtime_configuration" | "supported_binding" | "observed_action";
};

export type EndpointAgentRegistrationRequest = {
  agent_id: string;
  agent_name: string;
  agent_version: string;
  runtime_provider: string;
  model_provider: string;
  model_name: string;
  models: string[];
  detected_tools: string[];
  detected_actions: string[];
  detected_privileges: string[];
  listening_ports: number[];
  integration_transports: EndpointAgentIntegration[];
  active_integration_transport: EndpointIntegrationTransport;
  control_binding: {
    mode: "monitor" | "enforce";
    pre_action_surfaces: EndpointSurface[];
  };
};

export type EndpointAgentRegistrationResponse = {
  status: "registered";
  registration_id: string;
  evidence_state: "sdk_self_registration";
  control_state: "monitor_only";
  active_integration_transport: EndpointIntegrationTransport;
  evidence_ref: string | null;
};

export type EndpointLlmRequest = LlmInterceptRequest;
export type EndpointSdkRequest = LlmInterceptRequest;

export type EndpointDeveloperAgentRequest = {
  ai_system_id: string;
  actor_id: string;
  capability_token: string;
  action: string;
  resource: string;
  tool_name?: string;
  [key: string]: unknown;
};

export type EndpointFoundryRequest = LlmInterceptRequest;

export type EndpointDataTransferRequest = {
  copied_text: string;
  copied_text_hash?: string;
  source_domain?: string;
  source_app?: string;
  destination_domain?: string;
  destination_app?: string;
  [key: string]: unknown;
};

export type HawkBaseResponse = {
  final_decision?: string;
  decision?: string;
  control_mode?: HawkControlMode | string;
  reason_code?: string;
  audit_log_id?: string | null;
  evidence_node_id?: string | null;
  evidence_bundle_id?: string | null;
  finding_id?: string | null;
  runtime_event_id?: string | null;
  chain_id?: string | null;
  parent_action_id?: string | null;
  response_control_coverage?: ResponseControlCoverage;
  guardian_results?: HawkGuardianResult[];
  final_actions?: JsonObject;
  [key: string]: unknown;
};

export type NormalizedHawkDecision = {
  decision: HawkDecision | string;
  controlMode: HawkControlMode | string;
  allowed: boolean;
  blocked: boolean;
  requiresReview: boolean;
  reasonCode?: string;
  evidenceBundleId?: string | null;
  auditLogId?: string | null;
  response: HawkBaseResponse;
};

export type HawkGuardedResult<THawk extends HawkBaseResponse, TResult> = {
  hawk: THawk;
  result: TResult;
};

export type LlmInterceptRequest = {
  ai_system_id: string;
  actor_type: "human" | "agent" | "service" | "oauth_app" | "unknown" | string;
  actor_id: string;
  request_id?: string;
  prompt: string;
  context_summary?: string;
  attachments_meta?: JsonObject[];
  tool_output?: string | null;
  response_text?: string | null;
  provider?: string | null;
  model?: string | null;
  model_version?: string | null;
  tool_name?: string | null;
  tool_category?: string | null;
  api_endpoint?: string | null;
  data_source?: string | null;
  tool_usage_meta?: JsonObject | JsonObject[] | null;
  context_id?: string | null;
  chain_id?: string | null;
  chain_depth?: number | null;
  parent_action_id?: string | null;
  parent_agent_id?: string | null;
  [key: string]: unknown;
};

export type LlmInterceptResponse = HawkBaseResponse;

export type McpAuthorizeRequest = {
  ai_system_id: string;
  actor_id: string;
  capability_token: string;
  action: string;
  resource: string;
  chain_depth?: number;
  request_id?: string;
  provider?: string | null;
  model?: string | null;
  model_version?: string | null;
  tool_name?: string | null;
  tool_category?: string | null;
  api_endpoint?: string | null;
  data_source?: string | null;
  tool_usage_meta?: JsonObject | JsonObject[] | null;
  context_id?: string | null;
  chain_id?: string | null;
  parent_action_id?: string | null;
  session_id?: string | null;
  initiating_user_id?: string | null;
  session_context?: JsonObject | null;
  dynamic_permission?: JsonObject | null;
  [key: string]: unknown;
};

export type McpAuthorizeResponse = HawkBaseResponse;

export type McpToolScanRequest = {
  mcp_server_id: string;
  tool_name: string;
  tool_version?: string;
  description?: string;
  schema?: JsonObject;
  examples?: JsonValue[];
  manifest?: JsonObject | null;
  chain_id?: string | null;
  [key: string]: unknown;
};

export type ToolScanFinding = {
  detector?: string;
  threat_types?: HawkThreatType[];
  decision?: HawkDecision | string;
  framework_refs?: ThreatFrameworkRefs;
  [key: string]: unknown;
};

export type McpToolScanResponse = HawkBaseResponse & {
  trust_status?: "approved" | "changed" | "unknown" | "blocked" | "under_review" | string;
  tool_fingerprint_id?: string | null;
  finding_type?: string | null;
  tool_poisoning_decision?: HawkDecision | string;
  tool_scan_findings?: ToolScanFinding[];
  risk_factors?: string[];
};

export type CopyContext = {
  source_url?: string | null;
  source_domain?: string | null;
  source_app_name?: string | null;
  source_surface_type?: string;
  source_classification_hint?: string;
  copied_text_hash: string;
  copied_text_preview_redacted?: string | null;
  timestamp?: string | null;
  [key: string]: unknown;
};

export type PasteContext = {
  destination_url?: string | null;
  destination_domain?: string | null;
  destination_app_name?: string | null;
  destination_surface_type?: string;
  destination_input_context?: string;
  timestamp?: string | null;
  [key: string]: unknown;
};

export type DataTransferCheckRequest = {
  correlation_id?: string | null;
  tenant_id?: string | null;
  copy_context: CopyContext;
  paste_context: PasteContext;
  policy_version?: string | null;
  platform_mode?: "discovery" | "enforce" | null;
  browser?: string | null;
  browser_version?: string | null;
  browser_profile?: string | null;
  extension_name?: string | null;
  extension_version?: string | null;
  endpoint_id?: string | null;
  hostname?: string | null;
  device_type?: string | null;
  os_type?: string | null;
  os_version?: string | null;
  ip_address?: string | null;
  location?: string | null;
  prompt_storage_mode?: string | null;
  submitter_name?: string | null;
  submitter_email?: string | null;
  submitter_role?: string | null;
  submitter_department?: string | null;
  actor_role?: string | null;
  actor_department?: string | null;
  user_email?: string | null;
  [key: string]: unknown;
};

export type DataTransferCheckResponse = HawkBaseResponse & {
  decision: "allow" | "warn" | "block" | "require_justification";
  explanation?: string;
  recommended_action?: string;
  justification_required?: boolean;
};

export type DataTransferJustifyRequest = DataTransferCheckRequest & {
  justification: string;
  policy_decision: {
    decision: string;
    reason_code?: string | null;
    policy_version?: string | null;
    platform_mode?: "discovery" | "enforce" | null;
    [key: string]: unknown;
  };
};

export type DataTransferJustifyResponse = HawkBaseResponse & {
  decision: "allow" | "block";
  explanation?: string;
  recommended_action?: string;
};
