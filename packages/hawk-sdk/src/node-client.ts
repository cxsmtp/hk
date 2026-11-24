import {
  HawkClient as HawkBackendClient,
  assertHawkAllowed,
} from "./client.js";
import { HawkEndpointClientError, HawkEndpointTransport } from "./endpoint.js";
import type {
  DataTransferCheckRequest,
  DataTransferCheckResponse,
  DataTransferJustifyRequest,
  DataTransferJustifyResponse,
  EndpointAgentRegistrationRequest,
  EndpointAgentRegistrationResponse,
  EndpointDataTransferRequest,
  EndpointDecisionResponse,
  EndpointDeveloperAgentRequest,
  EndpointFoundryRequest,
  EndpointLlmRequest,
  EndpointSdkRequest,
  HawkClientOptions,
  HawkEndpointClientOptions,
  HawkGuardedResult,
  LlmInterceptRequest,
  LlmInterceptResponse,
  McpAuthorizeRequest,
  McpAuthorizeResponse,
  McpToolScanRequest,
  McpToolScanResponse,
} from "./types.js";

/** Node client supporting both the remote backend and local endpoint-agent IPC. */
export class HawkClient {
  private readonly backend: HawkBackendClient | undefined;
  private readonly endpointOptions: HawkEndpointClientOptions | undefined;
  private endpointPromise: Promise<HawkEndpointTransport> | undefined;

  constructor(options: HawkClientOptions) {
    if (options.mode === "endpoint") {
      if (!options.endpointSocketPath.trim()) {
        throw new Error("HawkClient endpoint mode requires endpointSocketPath");
      }
      if (!/^[0-9a-f]{64}$/.test(
        String(options.endpointTrustedDeviceThumbprint ?? "").trim().toLowerCase(),
      )) {
        throw new HawkEndpointClientError();
      }
      this.endpointOptions = options;
      this.backend = undefined;
      return;
    }
    this.endpointOptions = undefined;
    this.backend = new HawkBackendClient(options);
  }

  llmIntercept(payload: LlmInterceptRequest): Promise<LlmInterceptResponse> {
    if (this.endpointOptions) return this.endpointLlm(payload);
    return this.requireBackend().llmIntercept(payload);
  }

  async endpointLlm(payload: EndpointLlmRequest): Promise<EndpointDecisionResponse> {
    return (await this.requireEndpoint()).evaluate("llm", payload);
  }

  async endpointSdk(payload: EndpointSdkRequest): Promise<EndpointDecisionResponse> {
    return (await this.requireEndpoint()).evaluate("sdk", payload);
  }

  async endpointDeveloperAgent(payload: EndpointDeveloperAgentRequest): Promise<EndpointDecisionResponse> {
    if (!payload.capability_token.trim()) {
      throw new Error("endpointDeveloperAgent requires capability_token");
    }
    return (await this.requireEndpoint()).evaluate("developer_agent", payload);
  }

  async endpointFoundry(payload: EndpointFoundryRequest): Promise<EndpointDecisionResponse> {
    return (await this.requireEndpoint()).evaluate("foundry", {
      ...payload,
      provider: "microsoft_foundry",
      foundry_attribution: "sdk_endpoint_binding",
    });
  }

  async endpointDataTransfer(payload: EndpointDataTransferRequest): Promise<EndpointDecisionResponse> {
    if (typeof payload.copied_text !== "string" || payload.copied_text.length === 0) {
      throw new Error("endpointDataTransfer requires direct copied_text");
    }
    return (await this.requireEndpoint()).evaluate("data_transfer", payload);
  }

  async endpointRegisterAgent(
    payload: EndpointAgentRegistrationRequest,
  ): Promise<EndpointAgentRegistrationResponse> {
    return (await this.requireEndpoint()).registerAgent(payload);
  }

  async guardLlmAction(payload: LlmInterceptRequest): Promise<LlmInterceptResponse> {
    const response = await this.llmIntercept(payload);
    if (this.endpointOptions) assertEndpointAuthorized(response as EndpointDecisionResponse);
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
    return this.requireBackend().mcpAuthorize(payload);
  }

  guardMcpToolCall(payload: McpAuthorizeRequest): Promise<McpAuthorizeResponse> {
    return this.requireBackend().guardMcpToolCall(payload);
  }

  withMcpAuthorization<TResult>(
    payload: McpAuthorizeRequest,
    execute: (hawk: McpAuthorizeResponse) => Promise<TResult> | TResult,
  ): Promise<HawkGuardedResult<McpAuthorizeResponse, TResult>> {
    return this.requireBackend().withMcpAuthorization(payload, execute);
  }

  scanMcpTool(payload: McpToolScanRequest): Promise<McpToolScanResponse> {
    return this.requireBackend().scanMcpTool(payload);
  }

  dataTransferCheck(payload: DataTransferCheckRequest): Promise<DataTransferCheckResponse> {
    return this.requireBackend().dataTransferCheck(payload);
  }

  guardDataTransfer(payload: DataTransferCheckRequest): Promise<DataTransferCheckResponse> {
    return this.requireBackend().guardDataTransfer(payload);
  }

  dataTransferJustify(payload: DataTransferJustifyRequest): Promise<DataTransferJustifyResponse> {
    return this.requireBackend().dataTransferJustify(payload);
  }

  private requireBackend(): HawkBackendClient {
    if (!this.backend) throw new Error("HawkClient backend method requires backend mode");
    return this.backend;
  }

  private requireEndpoint(): Promise<HawkEndpointTransport> {
    if (!this.endpointOptions) throw new Error("HawkClient endpoint method requires endpoint mode");
    this.endpointPromise ??= Promise.resolve(new HawkEndpointTransport(this.endpointOptions));
    return this.endpointPromise;
  }
}

export class HawkEndpointAuthorizationRequiredError extends Error {
  readonly response: EndpointDecisionResponse;

  constructor(response: EndpointDecisionResponse) {
    super("Hawk endpoint enforce-mode authorization is required");
    this.name = "HawkEndpointAuthorizationRequiredError";
    this.response = response;
  }
}

export function assertEndpointAuthorized(response: EndpointDecisionResponse): void {
  if (response.endpoint_authorized !== true || response.decision_source !== "endpoint_agent") {
    throw new HawkEndpointAuthorizationRequiredError(response);
  }
}

export {
  HawkEndpointClientError,
  HawkEndpointTransport,
  verifyEndpointBrokerResponse,
} from "./endpoint.js";
export {
  HawkActionBlockedError,
  HawkApiError,
  assertHawkAllowed,
  assertToolSafe,
  hawkThreatFindings,
  hawkThreatTypes,
  normalizeHawkDecision,
} from "./client.js";
export type { HawkThreatFinding } from "./client.js";
export type {
  EndpointAgentIntegration,
  EndpointAgentRegistrationRequest,
  EndpointAgentRegistrationResponse,
  EndpointDataTransferRequest,
  EndpointDecisionReceipt,
  EndpointDecisionResponse,
  EndpointDeveloperAgentRequest,
  EndpointFoundryRequest,
  EndpointLlmRequest,
  EndpointSdkRequest,
  EndpointSurface,
  EndpointIntegrationTransport,
  HawkClientOptions,
  HawkEndpointClientOptions,
} from "./types.js";
