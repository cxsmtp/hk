import {
  createHash,
  createPublicKey,
  randomUUID,
  verify as verifySignature,
} from "node:crypto";
import { lstat, type Stats } from "node:fs/promises";
import { createConnection } from "node:net";
import { dirname } from "node:path";

import type {
  EndpointAgentRegistrationRequest,
  EndpointAgentRegistrationResponse,
  EndpointDecisionReceipt,
  EndpointDecisionResponse,
  EndpointSurface,
  HawkEndpointClientOptions,
} from "./types.js";

const PROTOCOL_VERSION = 1;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REQUEST_BYTES = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_REQUEST_ID_CHARS = 128;
const MAX_LABEL_CHARS = 128;
const SAFE_LABEL = /^[A-Za-z0-9][A-Za-z0-9_.:/-]*$/;
const REGISTRATION_SECRET_KEY = /(token|secret|password|authorization|credential|prompt|content|body|query|recipient|email_address)/i;

const CALLER_RESERVED_KEYS = new Set([
  "adapter_path",
  "client_metadata",
  "control_mode",
  "decision_source",
  "endpoint_authorized",
  "endpoint_available",
  "inline",
  "inline_authorized",
  "op",
  "pre_action",
  "pre_action_verified",
  "process_metadata",
  "protocol_version",
  "receipt",
  "request_id",
  "surface",
]);

const SENSITIVE_CONTENT_KEYS = new Set([
  "access_token",
  "api_key",
  "authorization",
  "bearer_token",
  "capability_token",
  "copied_text",
  "password",
  "prompt",
  "response_text",
  "secret",
  "tool_output",
]);

const PASSTHROUGH_ACTIONS = new Set(["allow", "warn", "block"]);
const DISCLOSED_ACTIONS = new Set([
  "allow",
  "block",
  "hold_for_approval",
  "redact",
  "review",
  "scope",
  "warn",
]);
const FAIL_CLOSED_ACTIONS = new Set([
  "hold_for_approval",
  "redact",
  "require_approval",
  "require_justification",
  "require_second_approval",
  "review",
  "step_up",
]);
const VALID_CONTROL_MODES = new Set([
  "external_required",
  "inline_allowed",
  "inline_authorized",
  "inline_prevented",
  "monitor_would_allow",
  "monitor_would_block",
  "monitor_would_review",
  "monitor_would_warn",
  "review_required",
  "scoped",
  "warned",
]);

type SocketIdentity = {
  device: number;
  inode: number;
  owner: number;
  parentDevice: number;
  parentInode: number;
  parentOwner: number;
};

type EndpointWireResponse = Record<string, unknown>;

export class HawkEndpointClientError extends Error {
  constructor() {
    super("Hawk endpoint authorization failed");
    this.name = "HawkEndpointClientError";
  }
}

/** Node-only, fail-closed transport for Hawk endpoint-agent IPC v1. */
export class HawkEndpointTransport {
  private readonly socketPath: string;
  private readonly timeoutMs: number;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private readonly clientName: string;
  private readonly clientVersion: string;
  private readonly trustedDeviceThumbprint: string;

  constructor(options: HawkEndpointClientOptions) {
    if (!options.endpointSocketPath.trim()) {
      throw new HawkEndpointClientError();
    }
    this.socketPath = options.endpointSocketPath;
    this.timeoutMs = positiveInteger(options.endpointTimeoutMs, DEFAULT_TIMEOUT_MS);
    this.maxRequestBytes = positiveInteger(options.endpointMaxRequestBytes, DEFAULT_MAX_REQUEST_BYTES);
    this.maxResponseBytes = positiveInteger(options.endpointMaxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES);
    this.clientName = safeClientLabel(options.clientName, "hawk-sdk");
    this.clientVersion = safeClientLabel(options.clientVersion, "0.2.0");
    this.trustedDeviceThumbprint = options.endpointTrustedDeviceThumbprint.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(this.trustedDeviceThumbprint)) {
      throw new HawkEndpointClientError();
    }
  }

  async evaluate(surface: EndpointSurface, payload: unknown): Promise<EndpointDecisionResponse> {
    const sanitizedPayload = sanitizePayload(payload);
    const requestId = randomUUID().slice(0, MAX_REQUEST_ID_CHARS);
    const request = {
      ...sanitizedPayload,
      protocol_version: PROTOCOL_VERSION,
      op: "evaluate",
      request_id: requestId,
      surface,
      client_metadata: {
        name: this.clientName,
        version: this.clientVersion,
        runtime: "node",
        runtime_version: process.version,
      },
      process_metadata: {
        pid: process.pid,
        platform: process.platform,
        architecture: process.arch,
      },
    };
    const response = await this.exchange(request);
    return verifiedDecision(
      response,
      requestId,
      surface,
      this.clientName,
      this.clientVersion,
      sensitiveValues(payload),
    );
  }

  async registerAgent(
    payload: EndpointAgentRegistrationRequest,
  ): Promise<EndpointAgentRegistrationResponse> {
    assertSecretFreeRegistration(payload);
    const sanitizedPayload = sanitizePayload(payload);
    const requestId = randomUUID().slice(0, MAX_REQUEST_ID_CHARS);
    const request = {
      ...sanitizedPayload,
      protocol_version: PROTOCOL_VERSION,
      op: "register_agent",
      request_id: requestId,
      client_metadata: {
        name: this.clientName,
        version: this.clientVersion,
        runtime: "node",
        runtime_version: process.version,
      },
      process_metadata: {
        pid: process.pid,
        platform: process.platform,
        architecture: process.arch,
      },
    };
    const response = await this.exchange(request);
    return verifiedRegistration(response, requestId);
  }

  private async exchange(request: Record<string, unknown>): Promise<EndpointWireResponse> {
    let encoded: string;
    try {
      encoded = `${JSON.stringify(request)}\n`;
    } catch {
      throw new HawkEndpointClientError();
    }
    if (new TextEncoder().encode(encoded).byteLength > this.maxRequestBytes) {
      throw new HawkEndpointClientError();
    }

    let expectedIdentity: SocketIdentity;
    try {
      expectedIdentity = await trustedSocketIdentity(this.socketPath);
    } catch {
      throw new HawkEndpointClientError();
    }

    return new Promise<EndpointWireResponse>((resolve, reject) => {
      let complete = false;
      let buffered = "";
      let receivedBytes = 0;
      const socket = createConnection({ path: this.socketPath });
      socket.setEncoding("utf8");

      const finish = (response?: EndpointWireResponse): void => {
        if (complete) return;
        complete = true;
        clearTimeout(timer);
        socket.destroy();
        if (response) resolve(response);
        else reject(new HawkEndpointClientError());
      };
      const timer = setTimeout(() => finish(), this.timeoutMs);

      socket.once("connect", () => {
        void trustedSocketIdentity(this.socketPath, expectedIdentity)
          .then(() => {
            if (!complete) socket.write(encoded);
          })
          .catch(() => finish());
      });
      socket.on("data", (...args: unknown[]) => {
        const chunk = args[0];
        if (typeof chunk !== "string") {
          finish();
          return;
        }
        receivedBytes += new TextEncoder().encode(chunk).byteLength;
        if (receivedBytes > this.maxResponseBytes) {
          finish();
          return;
        }
        buffered += chunk;
        const newline = buffered.indexOf("\n");
        if (newline < 0) return;
        if (buffered.slice(newline + 1).trim()) {
          finish();
          return;
        }
        try {
          const parsed: unknown = JSON.parse(buffered.slice(0, newline));
          if (!isPlainObject(parsed)) throw new Error("invalid response");
          finish(verifyEndpointBrokerResponse(parsed, this.trustedDeviceThumbprint));
        } catch {
          finish();
        }
      });
      socket.once("end", () => finish());
      socket.once("error", () => finish());
    });
  }
}

function verifiedRegistration(
  response: EndpointWireResponse,
  requestId: string,
): EndpointAgentRegistrationResponse {
  const status = String(response.status ?? "");
  const registrationId = String(response.registration_id ?? "");
  const evidenceState = String(response.evidence_state ?? "");
  const controlState = String(response.control_state ?? "");
  const transport = String(response.active_integration_transport ?? "");
  const evidenceRef = response.evidence_ref == null ? null : String(response.evidence_ref);
  if (
    response.ok !== true
    || response.request_id !== requestId
    || status !== "registered"
    || !registrationId
    || evidenceState !== "sdk_self_registration"
    || controlState !== "monitor_only"
    || !["composio", "google_direct", "tavily_direct", "local_ollama", "unknown"].includes(transport)
  ) {
    throw new HawkEndpointClientError();
  }
  return {
    status: "registered",
    registration_id: registrationId,
    evidence_state: "sdk_self_registration",
    control_state: "monitor_only",
    active_integration_transport: transport as EndpointAgentRegistrationResponse["active_integration_transport"],
    evidence_ref: evidenceRef,
  };
}

function assertSecretFreeRegistration(value: unknown): void {
  const visit = (entry: unknown): void => {
    if (Array.isArray(entry)) {
      for (const item of entry) visit(item);
      return;
    }
    if (!isPlainObject(entry)) return;
    for (const [key, nested] of Object.entries(entry)) {
      if (REGISTRATION_SECRET_KEY.test(key)) throw new HawkEndpointClientError();
      visit(nested);
    }
  };
  if (!isPlainObject(value)) throw new HawkEndpointClientError();
  visit(value);
}

/** Verify and unwrap a device-key-signed endpoint broker response. */
export function verifyEndpointBrokerResponse(
  response: unknown,
  expectedThumbprint: string,
  nowSeconds = Date.now() / 1000,
): EndpointWireResponse {
  try {
    if (!isPlainObject(response) || !isPlainObject(response.broker_auth)) {
      throw new Error("unsigned response");
    }
    const auth = response.broker_auth;
    const thumbprint = String(auth.key_thumbprint ?? "").trim().toLowerCase();
    const expected = String(expectedThumbprint ?? "").trim().toLowerCase();
    const issuedAt = Number(auth.issued_at);
    if (
      !/^[0-9a-f]{64}$/.test(expected)
      || thumbprint !== expected
      || auth.version !== "hawk-local-broker-v1"
      || auth.algorithm !== "ES256"
      || !Number.isInteger(issuedAt)
      || issuedAt > nowSeconds + 30
      || nowSeconds - issuedAt > 120
    ) throw new Error("untrusted response");

    const publicKey = createPublicKey(String(auth.public_key_pem ?? ""));
    const jwk = publicKey.export({ format: "jwk" });
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
      throw new Error("unsupported key");
    }
    const actualThumbprint = createHash("sha256").update(JSON.stringify({
      crv: "P-256",
      kty: "EC",
      x: jwk.x,
      y: jwk.y,
    })).digest("hex");
    if (actualThumbprint !== thumbprint) throw new Error("key mismatch");

    const signedPayload = String(auth.signed_payload ?? "");
    const signature = String(auth.signature ?? "");
    if (
      !signedPayload
      || signedPayload.length > DEFAULT_MAX_RESPONSE_BYTES * 2
      || !/^[A-Za-z0-9_-]+$/.test(signedPayload)
      || !signature
      || !/^[A-Za-z0-9_-]+$/.test(signature)
    ) throw new Error("invalid signature envelope");
    const statement = [
      "hawk-local-broker-v1",
      "ES256",
      String(auth.endpoint_id ?? ""),
      String(issuedAt),
      thumbprint,
      signedPayload,
    ].join("\n");
    if (!verifySignature(
      "sha256",
      new TextEncoder().encode(statement),
      publicKey,
      decodeBase64Url(signature),
    )) throw new Error("invalid signature");
    const authenticated: unknown = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(signedPayload)),
    );
    if (!isPlainObject(authenticated)) throw new Error("invalid payload");
    return { ...authenticated, broker_auth: { ...auth } };
  } catch {
    throw new HawkEndpointClientError();
  }
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function verifiedDecision(
  response: EndpointWireResponse,
  requestId: string,
  surface: EndpointSurface,
  clientName: string,
  clientVersion: string,
  sensitive: ReadonlySet<string>,
): EndpointDecisionResponse {
  if (response.ok !== true || response.request_id !== requestId) {
    throw new HawkEndpointClientError();
  }

  const action = normalizedToken(response.action);
  const controlMode = normalizedToken(response.control_mode);
  if (!action || !controlMode || !VALID_CONTROL_MODES.has(controlMode)) {
    throw new HawkEndpointClientError();
  }

  let decision: "allow" | "warn" | "block";
  if (PASSTHROUGH_ACTIONS.has(action)) {
    decision = action as "allow" | "warn" | "block";
  } else if (FAIL_CLOSED_ACTIONS.has(action)) {
    decision = "block";
  } else if (action === "scope") {
    // A generic SDK cannot apply resource constraints on the caller's behalf.
    // Scope therefore remains fail closed even if the endpoint reports that
    // the backend supplied constraints.
    decision = "block";
  } else {
    throw new HawkEndpointClientError();
  }

  if (
    controlMode === "inline_prevented"
    || controlMode === "external_required"
    || controlMode === "review_required"
    || controlMode === "scoped"
  ) {
    decision = "block";
  }

  const monitorOnly = controlMode.startsWith("monitor_would_");
  const responseSource = normalizedToken(response.source);
  const backendAuthoritative = responseSource === "backend";
  const wouldDecision = monitorOnly ? disclosedWouldDecision(response, controlMode) : undefined;
  const effectiveControlMode = decision === "block" && action !== "block"
    ? "inline_prevented"
    : controlMode;
  const reasonCode = safeResponseLabel(response.reason, sensitive, "endpoint_policy_decision");
  const evidenceRef = nullableSafeResponseLabel(response.evidence_ref, sensitive);
  const receipt: EndpointDecisionReceipt = {
    request_id: requestId,
    surface,
    decision,
    control_mode: effectiveControlMode,
    reason_code: reasonCode,
    evidence_ref: evidenceRef,
    client_name: clientName,
    client_version: clientVersion,
    process_id: process.pid,
  };

  return {
    final_decision: decision,
    decision,
    control_mode: effectiveControlMode,
    reason_code: reasonCode,
    evidence_bundle_id: evidenceRef,
    endpoint_authorized: !monitorOnly && (backendAuthoritative || decision === "block"),
    decision_source: monitorOnly
      ? "endpoint_agent_monitor"
      : backendAuthoritative
        ? "endpoint_agent"
        : "endpoint_agent_fail_secure",
    endpoint_surface: surface,
    ...(wouldDecision ? { would_decision: wouldDecision } : {}),
    receipt,
  };
}

function disclosedWouldDecision(response: EndpointWireResponse, controlMode: string): string {
  if (isPlainObject(response.detail)) {
    const disclosed = normalizedToken(response.detail.would_action);
    if (disclosed && DISCLOSED_ACTIONS.has(disclosed)) return disclosed;
  }
  if (controlMode === "monitor_would_block") return "block";
  if (controlMode === "monitor_would_review") return "review";
  if (controlMode === "monitor_would_warn") return "warn";
  return "allow";
}

function sanitizePayload(payload: unknown): Record<string, unknown> {
  if (!isPlainObject(payload)) throw new HawkEndpointClientError();
  return sanitizeObject(payload);
}

function sanitizeObject(value: Record<string, unknown>): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (CALLER_RESERVED_KEYS.has(key)) continue;
    const sanitized = sanitizeValue(entry);
    if (sanitized !== undefined) output[key] = sanitized;
  }
  return output;
}

function sanitizeValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new HawkEndpointClientError();
    return value;
  }
  if (Array.isArray(value)) return value.map(sanitizeValue);
  if (isPlainObject(value)) return sanitizeObject(value);
  if (value === undefined) return undefined;
  throw new HawkEndpointClientError();
}

function sensitiveValues(payload: unknown): Set<string> {
  const values = new Set<string>();
  collectSensitiveValues(payload, values);
  return values;
}

function collectSensitiveValues(value: unknown, output: Set<string>): void {
  if (Array.isArray(value)) {
    for (const entry of value) collectSensitiveValues(entry, output);
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    if (SENSITIVE_CONTENT_KEYS.has(key.toLowerCase()) && typeof entry === "string" && entry) {
      output.add(entry);
    }
    collectSensitiveValues(entry, output);
  }
}

function safeResponseLabel(value: unknown, sensitive: ReadonlySet<string>, fallback: string): string {
  const label = normalizedLabel(value);
  if (!label || containsSensitiveValue(label, sensitive)) return fallback;
  return label;
}

function nullableSafeResponseLabel(value: unknown, sensitive: ReadonlySet<string>): string | null {
  const label = normalizedLabel(value);
  return label && !containsSensitiveValue(label, sensitive) ? label : null;
}

function normalizedLabel(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const label = value.trim();
  return label.length > 0 && label.length <= MAX_LABEL_CHARS && SAFE_LABEL.test(label) ? label : null;
}

function normalizedToken(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const token = value.trim().toLowerCase();
  return token.length > 0 && token.length <= MAX_LABEL_CHARS && SAFE_LABEL.test(token) ? token : null;
}

function containsSensitiveValue(label: string, sensitive: ReadonlySet<string>): boolean {
  for (const value of sensitive) {
    if (
      value === label
      || (value.length >= 16 && label.includes(value))
      || (label.length >= 16 && value.includes(label))
    ) return true;
  }
  return false;
}

function safeClientLabel(value: string | undefined, fallback: string): string {
  return normalizedLabel(value) ?? fallback;
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && Number(value) > 0 ? Math.floor(Number(value)) : fallback;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

async function trustedSocketIdentity(
  socketPath: string,
  expected?: SocketIdentity,
): Promise<SocketIdentity> {
  if (typeof process.getuid !== "function") throw new HawkEndpointClientError();
  const currentUid = process.getuid();
  const [socketStat, parentStat] = await Promise.all([lstat(socketPath), lstat(dirname(socketPath))]);
  assertTrustedSocket(socketStat, parentStat, currentUid);
  const identity: SocketIdentity = {
    device: socketStat.dev,
    inode: socketStat.ino,
    owner: socketStat.uid,
    parentDevice: parentStat.dev,
    parentInode: parentStat.ino,
    parentOwner: parentStat.uid,
  };
  if (expected && Object.keys(identity).some((key) => {
    const typedKey = key as keyof SocketIdentity;
    return identity[typedKey] !== expected[typedKey];
  })) {
    throw new HawkEndpointClientError();
  }
  return identity;
}

function assertTrustedSocket(socketStat: Stats, parentStat: Stats, currentUid: number): void {
  if (
    !socketStat.isSocket()
    || socketStat.uid !== currentUid
    || (socketStat.mode & 0o777) !== 0o600
    || !parentStat.isDirectory()
    || parentStat.uid !== currentUid
    || (parentStat.mode & 0o022) !== 0
  ) {
    throw new HawkEndpointClientError();
  }
}
