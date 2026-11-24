export const ENDPOINT_NATIVE_HOST = "com.hawk.endpoint_agent";
export const ENDPOINT_PROTOCOL_VERSION = 1 as const;

type NativeMessageCallback = (response?: unknown) => void;

export type NativeMessagingRuntime = {
  readonly lastError?: { message?: string };
  sendNativeMessage(
    application: string,
    message: object,
    callback: NativeMessageCallback
  ): void;
};

export type EndpointAgentDecision = Record<string, unknown> & {
  ok: true;
  action?: string;
  control_mode?: string;
};

export type EndpointAgentEvaluation = {
  ok: boolean;
  endpointAvailable: boolean;
  endpointAuthorized: boolean;
  source: "endpoint_agent_native" | "endpoint_agent_unavailable";
  protocolVersion: typeof ENDPOINT_PROTOCOL_VERSION;
  requestId: string;
  decision?: EndpointAgentDecision;
  error?: string;
};

export type EndpointAgentIdentity = {
  ok: boolean;
  endpointAvailable: boolean;
  endpointIdentityVerified: boolean;
  protocolVersion: typeof ENDPOINT_PROTOCOL_VERSION;
  requestId: string;
  endpointId?: string;
  userId?: string;
  userEmail?: string;
  error?: string;
};

type EndpointAgentOptions = {
  runtime?: NativeMessagingRuntime;
  requestId?: () => string;
  timeoutMs?: number;
};

type EndpointFirstOptions<T> = {
  endpointEvaluate?: (payload: Record<string, unknown>) => Promise<EndpointAgentEvaluation>;
  mapNonAuthorized?: (endpoint: EndpointAgentEvaluation) => T;
};

const ENDPOINT_AUTHORIZATION_UNVERIFIED = "endpoint_authorization_unverified";
// The endpoint agent may spend up to 8 seconds on its backend decision. Keep a
// 2-second native-messaging/IPC margin so Chrome does not start a duplicate
// backend fallback while a valid endpoint decision is still in flight.
export const DEFAULT_NATIVE_MESSAGE_TIMEOUT_MS = 10_000;

export function normalizeEndpointDecisionAction(
  decision: EndpointAgentDecision
): "allow" | "warn" | "block" {
  const action = String(decision.action || "").trim().toLowerCase();
  if (action === "allow") return "allow";
  if (action === "warn") return "warn";
  if (action === "scope") {
    const detail = decision.detail && typeof decision.detail === "object"
      ? decision.detail as Record<string, unknown>
      : {};
    const constraintsEnforced = detail.constraints_enforced === true
      && detail.constraints_enforcement_surface === "browser_extension";
    return constraintsEnforced ? "allow" : "block";
  }
  return "block";
}

export function endpointPlatformMode(decision: EndpointAgentDecision): "discovery" | "enforce" {
  const controlMode = String(decision.control_mode || "").trim().toLowerCase();
  return controlMode === "monitor"
    || controlMode.startsWith("monitor_")
    || controlMode.startsWith("shadow_")
    ? "discovery"
    : "enforce";
}

function isVerifiedMonitorDecision(
  decision: EndpointAgentDecision | undefined
): decision is EndpointAgentDecision {
  if (!decision || decision.ok !== true) return false;
  const controlMode = String(decision.control_mode || "").trim().toLowerCase();
  return controlMode === "monitor"
    || controlMode.startsWith("monitor_")
    || controlMode.startsWith("shadow_");
}

export function blockedInteractionResult(_endpoint: EndpointAgentEvaluation) {
  return {
    decision: "block" as const,
    tier: "clear_positive" as const,
    reason_codes: [ENDPOINT_AUTHORIZATION_UNVERIFIED],
    policy_version: "endpoint-agent",
    platform_mode: "enforce" as const,
    input_signal_types: ["endpoint_agent_native", "endpoint_authorization_unverified"],
    audit_log_id: "",
    evidence_node_id: "",
  };
}

export function blockedInteractionV2Result(_endpoint: EndpointAgentEvaluation) {
  return {
    decision: "block" as const,
    reason: ENDPOINT_AUTHORIZATION_UNVERIFIED,
    policy_id: "endpoint-agent",
    control_ids: [],
    user_message: "Hawk could not verify endpoint authorization, so the action was blocked.",
    admin_summary: "Endpoint agent was reachable but did not return a verified authorization decision.",
    evidence_required: true,
    input_signal_types: ["endpoint_agent_native", "endpoint_authorization_unverified"],
    reason_codes: [ENDPOINT_AUTHORIZATION_UNVERIFIED],
  };
}

export function blockedDataTransferResult(_endpoint: EndpointAgentEvaluation) {
  return {
    decision: "block" as const,
    reason_code: ENDPOINT_AUTHORIZATION_UNVERIFIED,
    explanation: "Hawk could not verify endpoint authorization, so the transfer was blocked.",
    recommended_action: "cancel_transfer",
    justification_required: false,
    audit_log_id: "",
    evidence_node_id: "",
    policy_version: "endpoint-agent",
    platform_mode: "enforce" as const,
  };
}

export function endpointDecisionMetadata(input: {
  decisionSource: "endpoint_agent_native" | "endpoint_agent_native_non_authorized" | "backend_fallback";
  endpoint: EndpointAgentEvaluation;
}) {
  return {
    endpointAvailable: input.endpoint.endpointAvailable,
    endpointAuthorized: input.endpoint.endpointAuthorized,
    decisionSource: input.decisionSource,
  };
}

function unavailable(requestId: string, error: string): EndpointAgentEvaluation {
  return {
    ok: false,
    endpointAvailable: false,
    endpointAuthorized: false,
    source: "endpoint_agent_unavailable",
    protocolVersion: ENDPOINT_PROTOCOL_VERSION,
    requestId,
    error,
  };
}

function newRequestId(): string {
  return globalThis.crypto?.randomUUID?.() || `chrome-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function getEndpointIdentityWithEndpointAgent(
  options: EndpointAgentOptions = {}
): Promise<EndpointAgentIdentity> {
  const runtime = options.runtime || chrome.runtime;
  const requestId = (options.requestId || newRequestId)();
  const requestedTimeout = Number(options.timeoutMs);
  const timeoutMs = Number.isFinite(requestedTimeout) && requestedTimeout > 0
    ? Math.max(10, Math.min(10_000, requestedTimeout))
    : DEFAULT_NATIVE_MESSAGE_TIMEOUT_MS;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: EndpointAgentIdentity) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(result);
    };
    const failed = (error: string, endpointAvailable = false): EndpointAgentIdentity => ({
      ok: false,
      endpointAvailable,
      endpointIdentityVerified: false,
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId,
      error,
    });
    const timeout = setTimeout(() => finish(failed("native_host_timeout")), timeoutMs);

    try {
      runtime.sendNativeMessage(
        ENDPOINT_NATIVE_HOST,
        {
          protocol_version: ENDPOINT_PROTOCOL_VERSION,
          request_id: requestId,
          op: "identity",
        },
        (rawResponse) => {
          const connectionError = runtime.lastError?.message;
          if (settled) return;
          if (connectionError) {
            finish(failed(connectionError));
            return;
          }
          if (!rawResponse || typeof rawResponse !== "object") {
            finish(failed("native_host_no_response"));
            return;
          }
          const response = rawResponse as Record<string, unknown>;
          const responseMatches = response.protocol_version === ENDPOINT_PROTOCOL_VERSION
            && response.request_id === requestId;
          const endpointAvailable = responseMatches && response.endpoint_available === true;
          const endpointId = String(response.endpoint_id || "").trim();
          const endpointIdentityVerified = endpointAvailable
            && response.endpoint_identity_verified === true
            && response.ok === true
            && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(endpointId);
          if (!endpointIdentityVerified) {
            finish(failed(String(response.error || "endpoint_identity_unverified"), endpointAvailable));
            return;
          }
          finish({
            ok: true,
            endpointAvailable: true,
            endpointIdentityVerified: true,
            protocolVersion: ENDPOINT_PROTOCOL_VERSION,
            requestId,
            endpointId,
            userId: String(response.user_id || "").trim() || undefined,
            userEmail: String(response.user_email || "").trim().toLowerCase() || undefined,
          });
        }
      );
    } catch (error) {
      finish(failed(error instanceof Error ? error.message : String(error)));
    }
  });
}

function sendEndpointRequest(
  surface: "browser" | "data_transfer",
  payload: Record<string, unknown>,
  options: EndpointAgentOptions = {}
): Promise<EndpointAgentEvaluation> {
  const runtime = options.runtime || chrome.runtime;
  const requestId = (options.requestId || newRequestId)();
  const normalizedPayload = { ...payload, surface };
  const requestedTimeout = Number(options.timeoutMs);
  const timeoutMs = Number.isFinite(requestedTimeout) && requestedTimeout > 0
    ? Math.max(10, Math.min(10_000, requestedTimeout))
    : DEFAULT_NATIVE_MESSAGE_TIMEOUT_MS;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: EndpointAgentEvaluation) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve(result);
    };
    const timeout = setTimeout(() => {
      finish(unavailable(requestId, "native_host_timeout"));
    }, timeoutMs);
    try {
      runtime.sendNativeMessage(
        ENDPOINT_NATIVE_HOST,
        {
          protocol_version: ENDPOINT_PROTOCOL_VERSION,
          request_id: requestId,
          op: "evaluate",
          ...(surface !== "browser" ? { surface } : {}),
          payload: normalizedPayload,
        },
        (rawResponse) => {
          const connectionError = runtime.lastError?.message;
          if (settled) return;
          if (connectionError) {
            finish(unavailable(requestId, connectionError));
            return;
          }
          if (!rawResponse || typeof rawResponse !== "object") {
            finish(unavailable(requestId, "native_host_no_response"));
            return;
          }

          const response = rawResponse as Record<string, unknown>;
          const responseMatches = response.protocol_version === ENDPOINT_PROTOCOL_VERSION
            && response.request_id === requestId;
          const endpointAvailable = responseMatches && response.endpoint_available === true;
          const endpointAuthorized = endpointAvailable
            && response.endpoint_authorized === true
            && response.ok === true;
          const verifiedDecision = endpointAvailable && response.ok === true
            ? response as EndpointAgentDecision
            : undefined;
          const verifiedMonitorDecision = isVerifiedMonitorDecision(verifiedDecision);

          if (!endpointAvailable) {
            finish(unavailable(requestId, String(response.error || "endpoint_agent_unavailable")));
            return;
          }

          finish({
            ok: endpointAuthorized,
            endpointAvailable: true,
            endpointAuthorized,
            source: "endpoint_agent_native",
            protocolVersion: ENDPOINT_PROTOCOL_VERSION,
            requestId,
            decision: endpointAuthorized || verifiedMonitorDecision
              ? verifiedDecision
              : undefined,
            ...(!endpointAuthorized ? { error: String(response.error || "endpoint_authorization_failed") } : {}),
          });
        }
      );
    } catch (error) {
      finish(unavailable(requestId, error instanceof Error ? error.message : String(error)));
    }
  });
}

export function evaluateWithEndpointAgent(
  payload: Record<string, unknown>,
  options: EndpointAgentOptions = {}
): Promise<EndpointAgentEvaluation> {
  return sendEndpointRequest("browser", payload, options);
}

export function evaluateDataTransferWithEndpointAgent(
  payload: Record<string, unknown>,
  options: EndpointAgentOptions = {}
): Promise<EndpointAgentEvaluation> {
  return sendEndpointRequest("data_transfer", payload, options);
}

export async function evaluateEndpointFirst<T>(
  payload: Record<string, unknown>,
  backendFallback: () => Promise<T>,
  mapDecision: (decision: EndpointAgentDecision) => T,
  options: EndpointFirstOptions<T> = {}
): Promise<{
  result: T;
  decisionSource: "endpoint_agent_native" | "endpoint_agent_native_non_authorized" | "backend_fallback";
  endpoint: EndpointAgentEvaluation;
}> {
  const endpoint = await (options.endpointEvaluate || evaluateWithEndpointAgent)(payload);
  if (endpoint.endpointAuthorized && endpoint.decision) {
    return {
      result: mapDecision(endpoint.decision),
      decisionSource: "endpoint_agent_native",
      endpoint,
    };
  }
  if (endpoint.endpointAvailable && isVerifiedMonitorDecision(endpoint.decision)) {
    return {
      result: mapDecision(endpoint.decision),
      decisionSource: "endpoint_agent_native_non_authorized",
      endpoint,
    };
  }
  if (endpoint.endpointAvailable) {
    if (!options.mapNonAuthorized) {
      throw new Error(endpoint.error || "endpoint_authorization_failed");
    }
    return {
      result: options.mapNonAuthorized(endpoint),
      decisionSource: "endpoint_agent_native_non_authorized",
      endpoint,
    };
  }
  return {
    result: await backendFallback(),
    decisionSource: "backend_fallback",
    endpoint,
  };
}
