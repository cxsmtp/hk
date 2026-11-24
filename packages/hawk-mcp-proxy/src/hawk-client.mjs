const KNOWN_REASONS = new Set([
  'agent_session_revoked', 'agent_session_expired', 'agent_session_inactive',
  'agent_session_required', 'mcp_session_authority_denied',
  'governance_context_blocked', 'governance_fail_secure',
  'tool_fingerprint_unapproved', 'tool_metadata_drift',
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class HawkGatewayError extends Error {
  constructor({ httpStatus = null, reasonCode = 'http_error', correlationId = null } = {}) {
    super('Hawk gateway request failed');
    this.name = 'HawkGatewayError';
    this.httpStatus = Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599 ? httpStatus : null;
    this.reasonCode = KNOWN_REASONS.has(reasonCode) || ['request_schema_invalid', 'unauthenticated', 'forbidden', 'not_found', 'conflict', 'rate_limited', 'service_unavailable', 'internal_error', 'http_error', 'transport_error', 'timeout', 'response_invalid'].includes(reasonCode) ? reasonCode : 'http_error';
    this.correlationId = typeof correlationId === 'string' && UUID.test(correlationId) ? correlationId : null;
  }
}

export function safeHawkReason(status, parsed) {
  const raw = parsed?.detail?.reason_code;
  if (typeof raw === 'string' && KNOWN_REASONS.has(raw)) return raw;
  return ({ 401: 'unauthenticated', 403: 'forbidden', 404: 'not_found', 409: 'conflict', 422: 'request_schema_invalid', 429: 'rate_limited' })[status]
    || (status >= 500 ? status === 503 ? 'service_unavailable' : 'internal_error' : 'http_error');
}

export class HawkGatewayClient {
  constructor({ apiUrl, tenantId, accessToken, timeoutMs = 8000 }) {
    if (!apiUrl || !apiUrl.trim()) {
      throw new Error("HAWK_API_URL is required");
    }
    if (!tenantId || !tenantId.trim()) {
      throw new Error("HAWK_TENANT_ID is required");
    }
    if (!accessToken || !accessToken.trim()) {
      throw new Error("HAWK_ACCESS_TOKEN is required");
    }
    this.apiUrl = apiUrl.replace(/\/+$/, "");
    this.tenantId = tenantId;
    this.accessToken = accessToken;
    this.timeoutMs = timeoutMs;
  }

  authorize(payload) {
    const { client_app: _clientApp, ...gatewayPayload } = payload;
    return this.#post("/gateway/mcp/authorize", gatewayPayload);
  }

  scanTool(payload, options = {}) {
    return this.#post("/gateway/mcp/tools/scan", payload, options);
  }

  async #post(path, payload, { signal } = {}) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) {
      controller.abort();
    } else {
      signal?.addEventListener("abort", abort, { once: true });
    }
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      let response;
      try {
        response = await fetch(`${this.apiUrl}${path}`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${this.accessToken}`,
          "Content-Type": "application/json",
          "X-Tenant-ID": this.tenantId,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      } catch {
        throw new HawkGatewayError({ reasonCode: controller.signal.aborted ? 'timeout' : 'transport_error' });
      }
      let parsed;
      try {
        const text = await response.text();
        parsed = text ? JSON.parse(text) : {};
      } catch {
        parsed = {};
        if (response.ok) throw new HawkGatewayError({ httpStatus: response.status, reasonCode: 'response_invalid' });
      }
      if (!response.ok) {
        throw new HawkGatewayError({ httpStatus: response.status, reasonCode: safeHawkReason(response.status, parsed), correlationId: response.headers?.get?.('x-request-id') });
      }
      return parsed;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }
}
