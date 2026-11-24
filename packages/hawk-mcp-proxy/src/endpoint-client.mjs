import {
  createHash,
  createPublicKey,
  randomUUID,
  verify as verifySignature,
} from "node:crypto";
import { lstat } from "node:fs/promises";
import { createConnection } from "node:net";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const VALID_ACTIONS = new Set([
  "allow",
  "warn",
  "scope",
  "hold_for_approval",
  "block",
]);
const VALID_PRE_ACTION_MODES = new Set([
  "inline_authorized",
  "inline_allowed",
  "inline_prevented",
  "warned",
  "scoped",
  "external_required",
  "review_required",
  "monitor_would_allow",
  "monitor_would_warn",
  "monitor_would_review",
  "monitor_would_block",
]);

export class HawkEndpointClientError extends Error {
  constructor() {
    super("Hawk endpoint authorization failed");
    this.name = "HawkEndpointClientError";
  }
}

export class HawkEndpointClient {
  constructor({
    socketPath,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxRequestBytes = DEFAULT_MAX_REQUEST_BYTES,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    trustedDeviceThumbprint = "",
  }) {
    if (typeof socketPath !== "string" || !socketPath.trim()) {
      throw new HawkEndpointClientError();
    }
    this.socketPath = normalizeSocketPath(socketPath);
    this.timeoutMs = positiveInteger(timeoutMs, DEFAULT_TIMEOUT_MS);
    this.maxRequestBytes = positiveInteger(
      maxRequestBytes,
      DEFAULT_MAX_REQUEST_BYTES,
    );
    this.maxResponseBytes = positiveInteger(
      maxResponseBytes,
      DEFAULT_MAX_RESPONSE_BYTES,
    );
    this.trustedDeviceThumbprint = String(trustedDeviceThumbprint || "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(this.trustedDeviceThumbprint)) {
      throw new HawkEndpointClientError();
    }
  }

  async authorize(payload, options = {}) {
    const requestId = randomUUID();
    const response = await this.#exchange({
      ...(isPlainObject(payload) ? payload : {}),
      protocol_version: 1,
      request_id: requestId,
      op: "evaluate",
      surface: "mcp",
    }, options);
    return verifiedDecision(response, requestId);
  }

  async scanTool(payload, options = {}) {
    let descriptor;
    try {
      if (!isPlainObject(payload)) throw new TypeError("invalid descriptor");
      const schema = payload.schema ?? {};
      const examples = payload.examples ?? [];
      const manifest = payload.manifest ?? null;
      if (
        !isPlainObject(schema)
        || !Array.isArray(examples)
        || (manifest !== null && !isPlainObject(manifest))
      ) {
        throw new TypeError("invalid descriptor");
      }
      descriptor = JSON.parse(canonicalJson({
        mcp_server_id: String(payload.mcp_server_id || "").trim(),
        tool_name: String(payload.tool_name || "").trim(),
        tool_version: String(payload.tool_version || "unknown").trim() || "unknown",
        description: String(payload.description || ""),
        schema,
        examples,
        manifest,
        chain_id: payload.chain_id == null ? null : String(payload.chain_id),
      }));
      if (!descriptor.mcp_server_id || !descriptor.tool_name) {
        throw new TypeError("invalid descriptor");
      }
    } catch {
      throw new HawkEndpointClientError();
    }
    const requestId = randomUUID();
    const response = await this.#exchange({
      ...descriptor,
      protocol_version: 1,
      request_id: requestId,
      op: "mcp_tool_scan",
      surface: "mcp",
    }, options);
    return verifiedScan(response, requestId);
  }

  async governanceStatus({ clientApp } = {}, options = {}) {
    const requestId = randomUUID();
    const response = await this.#exchange({
      protocol_version: 1,
      request_id: requestId,
      op: "governance_status",
      client_app: String(clientApp || "").trim().slice(0, 128),
    }, options);
    return verifiedGovernanceStatus(response, requestId);
  }

  async #exchange(request, { signal } = {}) {
    let encoded;
    try {
      encoded = `${JSON.stringify(request)}\n`;
    } catch {
      return Promise.reject(new HawkEndpointClientError());
    }
    if (Buffer.byteLength(encoded, "utf8") > this.maxRequestBytes) {
      throw new HawkEndpointClientError();
    }

    let expectedIdentity;
    try {
      expectedIdentity = await trustedSocketIdentity(this.socketPath);
    } catch {
      throw new HawkEndpointClientError();
    }

    return new Promise((resolve, reject) => {
      let complete = false;
      let receivedBytes = 0;
      let buffered = Buffer.alloc(0);
      const socket = createConnection({ path: this.socketPath });
      const finish = (error, response) => {
        if (complete) return;
        complete = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        socket.destroy();
        if (error) reject(new HawkEndpointClientError());
        else resolve(response);
      };
      const onAbort = () => finish(true);
      const timer = setTimeout(() => finish(true), this.timeoutMs);

      if (signal?.aborted) {
        finish(true);
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      socket.once("connect", async () => {
        try {
          await trustedSocketIdentity(this.socketPath, expectedIdentity);
          if (!complete) socket.write(encoded);
        } catch {
          finish(true);
        }
      });
      socket.on("data", (chunk) => {
        receivedBytes += chunk.length;
        if (receivedBytes > this.maxResponseBytes) {
          finish(true);
          return;
        }
        buffered = Buffer.concat([buffered, chunk]);
        const newline = buffered.indexOf(0x0a);
        if (newline === -1) return;
        const trailing = buffered.subarray(newline + 1).toString("utf8").trim();
        if (trailing) {
          finish(true);
          return;
        }
        try {
          const parsed = JSON.parse(buffered.subarray(0, newline).toString("utf8"));
          if (!isPlainObject(parsed)) throw new Error("invalid response");
          finish(
            false,
            verifyBrokerResponse(parsed, this.trustedDeviceThumbprint),
          );
        } catch {
          finish(true);
        }
      });
      socket.once("end", () => finish(true));
      socket.once("error", () => finish(true));
    });
  }
}

function verifiedDecision(response, requestId) {
  if (
    response.ok !== true
    || !Object.prototype.hasOwnProperty.call(response, "request_id")
    || response.request_id !== requestId
  ) {
    throw new HawkEndpointClientError();
  }
  const action = String(response.action || "").trim().toLowerCase();
  const controlMode = String(response.control_mode || "").trim().toLowerCase();
  if (!VALID_ACTIONS.has(action) || !VALID_PRE_ACTION_MODES.has(controlMode)) {
    throw new HawkEndpointClientError();
  }
  if (action === "scope" && response.constraints_enforced !== true) {
    throw new HawkEndpointClientError();
  }
  const monitorOnly = controlMode.startsWith("monitor_would_");
  const policyId = cleanIdentifier(
    response.policy_id
    || response.policy_version_id
    || response?.detail?.policy_id
    || response?.detail?.policy_version_id,
  );
  const result = {
    decision: action,
    control_mode: controlMode,
    evidence_ref: response.evidence_ref || null,
    endpoint_authorized: !monitorOnly,
  };
  if (policyId) {
    result.policy_id = policyId;
  }
  if (monitorOnly) {
    result.decision_source = "endpoint_agent_monitor";
    result.would_decision = String(response?.detail?.would_action || "").trim().toLowerCase()
      || controlMode.slice("monitor_would_".length);
  }
  if (action === "scope") result.constraints_enforced = true;
  return result;
}

function cleanIdentifier(value) {
  const normalized = String(value || "").trim();
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(normalized)
    ? normalized
    : null;
}

function verifiedScan(response, requestId) {
  const trustStatus = String(response?.trust_status || "").trim().toLowerCase();
  const poisoningDecision = String(
    response?.tool_poisoning_decision || "",
  ).trim().toLowerCase();
  if (
    response?.ok !== true
    || response.request_id !== requestId
    || response.status !== "completed"
    || !nonEmptyString(response.scan_result_id)
    || !nonEmptyString(response.tool_fingerprint_id)
    || !nonEmptyString(response.evidence_bundle_id)
    || !["approved", "unknown", "changed"].includes(trustStatus)
    || !["allow", "warn", "redact", "hold_for_approval", "block"].includes(poisoningDecision)
    || !Array.isArray(response.risk_factors)
    || response.risk_factors.some((factor) => typeof factor !== "string")
    || typeof response.idempotent_replay !== "boolean"
  ) {
    throw new HawkEndpointClientError();
  }
  return {
    status: "completed",
    scan_result_id: response.scan_result_id,
    tool_fingerprint_id: response.tool_fingerprint_id,
    trust_status: trustStatus,
    risk_factors: [...response.risk_factors],
    evidence_bundle_id: response.evidence_bundle_id,
    tool_poisoning_decision: poisoningDecision,
    idempotent_replay: response.idempotent_replay,
  };
}

function verifiedGovernanceStatus(response, requestId) {
  const state = String(response?.state || "").trim().toLowerCase();
  const evidenceRef = nonEmptyString(response?.evidence_ref) ? response.evidence_ref : null;
  if (
    response?.ok !== true
    || response.request_id !== requestId
    || response.schema_version !== 1
    || !["governed", "blocked", "monitor", "unknown"].includes(state)
    || response.connected !== true
    || (!["unknown"].includes(state) && !evidenceRef)
  ) {
    throw new HawkEndpointClientError();
  }
  const usage = isPlainObject(response.token_usage) ? response.token_usage : {};
  const tokenTotal = Number.isInteger(usage.total) && usage.total >= 0 ? usage.total : null;
  const tokenProvenance = tokenTotal !== null && ["exact", "estimated"].includes(usage.provenance)
    ? usage.provenance
    : "unknown";
  const cost = isPlainObject(response.cost_usage) ? response.cost_usage : {};
  const costAmount = typeof cost.amount === "number" && Number.isFinite(cost.amount) && cost.amount >= 0
    ? cost.amount
    : null;
  const costCurrency = /^[A-Z]{3}$/.test(String(cost.currency || "").trim().toUpperCase())
    ? String(cost.currency).trim().toUpperCase()
    : null;
  const costSource = ["provider_billed", "provider_reported", "customer_rate_card", "calculated_estimate", "mixed"].includes(cost.source)
    ? cost.source
    : "unknown";
  const costProvenance = costAmount !== null && costCurrency !== null && costSource !== "unknown" && ["exact", "estimated"].includes(cost.provenance)
    ? cost.provenance
    : "unknown";
  return {
    schema_version: 1,
    state,
    label: String(response.label || "Unknown").slice(0, 64),
    connected: true,
    client_app: nonEmptyString(response.client_app) ? response.client_app.slice(0, 128) : null,
    adapter_path: nonEmptyString(response.adapter_path) ? response.adapter_path.slice(0, 64) : null,
    server_id: nonEmptyString(response.server_id) ? response.server_id.slice(0, 256) : null,
    session_id: nonEmptyString(response.session_id) ? response.session_id.slice(0, 256) : null,
    available_tool_count: Number.isInteger(response.available_tool_count) ? response.available_tool_count : null,
    tool_call_count: Number.isInteger(response.tool_call_count) ? response.tool_call_count : 0,
    token_usage: { total: tokenTotal, provenance: tokenProvenance },
    cost_usage: costProvenance === "unknown"
      ? { amount: null, currency: null, provenance: "unknown", source: "unknown" }
      : { amount: costAmount, currency: costCurrency, provenance: costProvenance, source: costSource },
    latest_decision: String(response.latest_decision || "unknown").slice(0, 64),
    control_mode: String(response.control_mode || "unknown").slice(0, 64),
    evidence_ref: evidenceRef,
    policy_id: nonEmptyString(response.policy_id) ? response.policy_id.slice(0, 256) : null,
  };
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(",")}}`;
  }
  throw new TypeError("unsupported metadata");
}

function isPlainObject(value) {
  return Boolean(
    value
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null),
  );
}

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function nonEmptyString(value) {
  return typeof value === "string" && Boolean(value.trim());
}

function normalizeSocketPath(value) {
  const socketPath = String(value || "").trim();
  if (socketPath === "~") return homedir();
  if (socketPath.startsWith("~/")) {
    return join(homedir(), socketPath.slice(2));
  }
  return socketPath;
}

async function trustedSocketIdentity(socketPath, expected = null) {
  if (typeof process.getuid !== "function") {
    throw new HawkEndpointClientError();
  }
  const currentUid = process.getuid();
  const [socketStat, parentStat] = await Promise.all([
    lstat(socketPath),
    lstat(dirname(socketPath)),
  ]);
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
  const identity = {
    device: socketStat.dev,
    inode: socketStat.ino,
    owner: socketStat.uid,
    parentDevice: parentStat.dev,
    parentInode: parentStat.ino,
    parentOwner: parentStat.uid,
  };
  if (
    expected
    && Object.keys(identity).some((key) => identity[key] !== expected[key])
  ) {
    throw new HawkEndpointClientError();
  }
  return identity;
}

export function verifyBrokerResponse(response, expectedThumbprint, nowSeconds = Date.now() / 1000) {
  try {
    if (!isPlainObject(response) || !isPlainObject(response.broker_auth)) {
      throw new Error("unsigned response");
    }
    const auth = response.broker_auth;
    const thumbprint = String(auth.key_thumbprint || "").trim().toLowerCase();
    const expected = String(expectedThumbprint || "").trim().toLowerCase();
    const issuedAt = Number(auth.issued_at);
    if (
      !/^[0-9a-f]{64}$/.test(expected)
      || thumbprint !== expected
      || auth.version !== "hawk-local-broker-v1"
      || auth.algorithm !== "ES256"
      || !Number.isInteger(issuedAt)
      || issuedAt > nowSeconds + 30
      || nowSeconds - issuedAt > 120
    ) {
      throw new Error("untrusted response");
    }
    const publicKey = createPublicKey(String(auth.public_key_pem || ""));
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
    const signedPayload = String(auth.signed_payload || "");
    const signature = String(auth.signature || "");
    if (
      !signedPayload
      || signedPayload.length > DEFAULT_MAX_RESPONSE_BYTES * 2
      || !/^[A-Za-z0-9_-]+$/.test(signedPayload)
      || !signature
      || !/^[A-Za-z0-9_-]+$/.test(signature)
    ) {
      throw new Error("invalid signature envelope");
    }
    const statement = [
      "hawk-local-broker-v1",
      "ES256",
      String(auth.endpoint_id || ""),
      String(issuedAt),
      thumbprint,
      signedPayload,
    ].join("\n");
    if (!verifySignature(
      "sha256",
      Buffer.from(statement),
      publicKey,
      Buffer.from(signature, "base64url"),
    )) {
      throw new Error("invalid signature");
    }
    const authenticated = JSON.parse(Buffer.from(signedPayload, "base64url").toString("utf8"));
    if (!isPlainObject(authenticated)) throw new Error("invalid payload");
    return { ...authenticated, broker_auth: { ...auth } };
  } catch {
    throw new HawkEndpointClientError();
  }
}
