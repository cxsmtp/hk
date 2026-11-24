import type {
  DataTransferCheckRequest,
  DataTransferCheckResponse,
  DataTransferJustifyRequest,
  DataTransferJustifyResponse,
  HawkBaseResponse,
  HawkBackendClientOptions,
  HawkGuardedResult,
  HawkGuardianResult,
  HawkThreatType,
  NormalizedHawkDecision,
  JsonValue,
  LlmInterceptRequest,
  LlmInterceptResponse,
  McpAuthorizeRequest,
  McpAuthorizeResponse,
  McpToolScanRequest,
  McpToolScanResponse,
  ThreatFrameworkRefs,
} from "./types.js";

const SDK_HEADER = "@hawk-ai/sdk/0.2.0";

type BackendConfig = {
  apiUrl: string;
  tenantId: string;
  bearerToken: string;
  fetchImpl: typeof fetch;
};

export class HawkApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "HawkApiError";
    this.status = status;
    this.body = body;
  }
}

export class HawkActionBlockedError extends Error {
  readonly response: HawkBaseResponse;
  readonly decision: string;
  readonly controlMode: string;
  readonly reasonCode: string | undefined;

  constructor(message: string, normalized: NormalizedHawkDecision) {
    super(message);
    this.name = "HawkActionBlockedError";
    this.response = normalized.response;
    this.decision = normalized.decision;
    this.controlMode = normalized.controlMode;
    this.reasonCode = normalized.reasonCode;
  }
}

export class HawkClient {
  private readonly backend: BackendConfig;

  constructor(options: HawkBackendClientOptions) {
    this.backend = createBackendConfig(options);
  }

  llmIntercept(payload: LlmInterceptRequest): Promise<LlmInterceptResponse> {
    return this.postJson<LlmInterceptResponse>("/gateway/llm/intercept", payload);
  }

  async guardLlmAction(payload: LlmInterceptRequest): Promise<LlmInterceptResponse> {
    const response = await this.llmIntercept(payload);
    assertHawkAllowed(response, "Hawk blocked the LLM action");
    return response;
  }

  async withLlmAuthorization<TResult>(
    payload: LlmInterceptRequest,
    execute: (hawk: LlmInterceptResponse) => Promise<TResult> | TResult,
  ): Promise<HawkGuardedResult<LlmInterceptResponse, TResult>> {
    const hawk = await this.guardLlmAction(payload);
    const result = await execute(hawk);
    return { hawk, result };
  }

  mcpAuthorize(payload: McpAuthorizeRequest): Promise<McpAuthorizeResponse> {
    return this.postJson<McpAuthorizeResponse>("/gateway/mcp/authorize", payload);
  }

  async guardMcpToolCall(payload: McpAuthorizeRequest): Promise<McpAuthorizeResponse> {
    const response = await this.mcpAuthorize(payload);
    assertHawkAllowed(response, "Hawk blocked the MCP tool action");
    return response;
  }

  async withMcpAuthorization<TResult>(
    payload: McpAuthorizeRequest,
    execute: (hawk: McpAuthorizeResponse) => Promise<TResult> | TResult,
  ): Promise<HawkGuardedResult<McpAuthorizeResponse, TResult>> {
    const hawk = await this.guardMcpToolCall(payload);
    const result = await execute(hawk);
    return { hawk, result };
  }

  scanMcpTool(payload: McpToolScanRequest): Promise<McpToolScanResponse> {
    return this.postJson<McpToolScanResponse>("/gateway/mcp/tools/scan", payload);
  }

  dataTransferCheck(payload: DataTransferCheckRequest): Promise<DataTransferCheckResponse> {
    return this.postJson<DataTransferCheckResponse>("/runtime-control/data-transfer-check", payload);
  }

  async guardDataTransfer(payload: DataTransferCheckRequest): Promise<DataTransferCheckResponse> {
    const response = await this.dataTransferCheck(payload);
    assertHawkAllowed(response, "Hawk blocked or paused the data transfer");
    return response;
  }

  dataTransferJustify(payload: DataTransferJustifyRequest): Promise<DataTransferJustifyResponse> {
    return this.postJson<DataTransferJustifyResponse>("/runtime-control/data-transfer-justify", payload);
  }

  private async postJson<TResponse>(path: string, payload: unknown): Promise<TResponse> {
    const backend = this.backend;
    const response = await backend.fetchImpl(`${backend.apiUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${backend.bearerToken}`,
        "X-Tenant-ID": backend.tenantId,
        "X-Hawk-SDK": SDK_HEADER,
      },
      body: JSON.stringify(payload),
    });

    const body = await parseBody(response);
    if (!response.ok) {
      throw new HawkApiError(`Hawk API request failed with status ${response.status}`, response.status, body);
    }
    return body as TResponse;
  }
}

function createBackendConfig(options: HawkBackendClientOptions): BackendConfig {
  if (!options.apiUrl.trim()) {
    throw new Error("HawkClient requires apiUrl");
  }
  if (!options.tenantId.trim()) {
    throw new Error("HawkClient requires tenantId");
  }
  const bearerToken = options.accessToken ?? options.apiKey;
  if (!bearerToken?.trim()) {
    throw new Error("HawkClient requires accessToken or apiKey");
  }
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (!fetchImpl) {
    throw new Error("HawkClient requires a fetch implementation");
  }

  return {
    apiUrl: options.apiUrl.replace(/\/+$/, ""),
    tenantId: options.tenantId,
    bearerToken,
    fetchImpl,
  };
}

export function normalizeHawkDecision(response: HawkBaseResponse): NormalizedHawkDecision {
  const decision = String(response.final_decision ?? response.decision ?? "unknown");
  const controlMode = String(response.control_mode ?? inferControlMode(decision));
  const requiresReview = REVIEW_DECISIONS.has(decision);
  const blocked =
    BLOCK_DECISIONS.has(decision) || requiresReview || BLOCK_CONTROL_MODES.has(controlMode);

  const normalized: NormalizedHawkDecision = {
    decision,
    controlMode,
    allowed: !blocked,
    blocked,
    requiresReview,
    response,
  };
  if (typeof response.reason_code === "string") {
    normalized.reasonCode = response.reason_code;
  }
  if (response.evidence_bundle_id !== undefined) {
    normalized.evidenceBundleId = response.evidence_bundle_id;
  }
  if (response.audit_log_id !== undefined) {
    normalized.auditLogId = response.audit_log_id;
  }
  return normalized;
}

export function assertHawkAllowed(response: HawkBaseResponse, message = "Hawk blocked the AI action"): void {
  const normalized = normalizeHawkDecision(response);
  if (normalized.blocked) {
    throw new HawkActionBlockedError(message, normalized);
  }
}

export type HawkThreatFinding = {
  guardianId: string;
  decision: string;
  threatTypes: HawkThreatType[];
  frameworks: ThreatFrameworkRefs;
};

/**
 * Extract the OWASP LLM / OWASP Agentic / MITRE ATLAS threats a Hawk response
 * flagged. Useful for surfacing coverage in tests and customer environments.
 */
export function hawkThreatFindings(response: HawkBaseResponse): HawkThreatFinding[] {
  const guardians = (response?.guardian_results ?? []) as HawkGuardianResult[];
  const out: HawkThreatFinding[] = [];
  for (const guardian of guardians) {
    const threatTypes = guardian?.threat_types ?? [];
    const frameworks = guardian?.framework_refs ?? {};
    if (threatTypes.length === 0 && !frameworks.owasp_llm && !frameworks.owasp_agentic && !frameworks.mitre_atlas) {
      continue;
    }
    out.push({
      guardianId: String(guardian?.guardian_id ?? guardian?.guardian_contract_id ?? "unknown"),
      decision: String(guardian?.decision ?? "unknown"),
      threatTypes,
      frameworks,
    });
  }
  return out;
}

/** Distinct threat-type labels a Hawk response flagged. */
export function hawkThreatTypes(response: HawkBaseResponse): HawkThreatType[] {
  const seen = new Set<HawkThreatType>();
  for (const finding of hawkThreatFindings(response)) {
    for (const threat of finding.threatTypes) {
      seen.add(threat);
    }
  }
  return [...seen];
}

/** Throw HawkActionBlockedError if an MCP tool scan is not safe to load. */
export function assertToolSafe(scan: McpToolScanResponse, message = "Hawk flagged an unsafe MCP tool"): void {
  const decision = String(scan?.tool_poisoning_decision ?? scan?.decision ?? scan?.final_decision ?? "allow");
  const blocked = BLOCK_DECISIONS.has(decision) || REVIEW_DECISIONS.has(decision) || scan?.trust_status === "blocked";
  if (blocked) {
    throw new HawkActionBlockedError(message, normalizeHawkDecision(scan));
  }
}

async function parseBody(response: Response): Promise<JsonValue | unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }
  const contentType = response.headers.get("Content-Type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(text) as JsonValue;
    } catch {
      return text;
    }
  }
  return text;
}

const BLOCK_DECISIONS = new Set([
  "block",
  "redact",
  "step_up",
  "require_approval",
  "require_second_approval",
  "require_justification",
]);

const REVIEW_DECISIONS = new Set(["review"]);

const BLOCK_CONTROL_MODES = new Set(["inline_prevented", "external_required", "incomplete"]);

function inferControlMode(decision: string): string {
  if (decision === "allow") {
    return "inline_allowed";
  }
  if (decision === "warn") {
    return "warned";
  }
  if (decision === "shadow_would_block") {
    return "shadow_would_block";
  }
  if (BLOCK_DECISIONS.has(decision) || REVIEW_DECISIONS.has(decision)) {
    return "inline_prevented";
  }
  return "incomplete";
}
