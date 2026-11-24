import { getExtensionBuildHash } from "./build-info";
import { fetchWithTenantAuth, getCachedPolicy, getSettings, STORAGE_KEYS, type BrowserType, type ExtensionSettings } from "./policy-sync";

const ENDPOINT_ID_KEY = "endpointId";
const ENDPOINT_CONTEXT_KEY = "endpointContext";

export type BrowserEventType =
  | "ai_domain_visit"
  | "ai_app_opened"
  | "prompt_drafted"
  | "prompt_submitted"
  | "paste_into_ai_app"
  | "file_upload_attempted"
  | "policy_warned"
  | "policy_blocked"
  | "prompt_warned"
  | "prompt_blocked"
  | "prompt_held"
  | "unknown_ai_detected"
  | "agent_runtime_discovered"
  | "browser_automation_action"
  | "browser_automation_detected"
  | "browser_automation_blocked"
  | "file_upload_detected"
  | "output_flagged"
  | "clipboard_copy_detected"
  | "clipboard_paste_detected"
  | "clipboard_cut_detected"
  | "data_transfer_check"
  | "data_transfer_justification"
  | "meeting_ai_notetaker_detected"
  | "meeting_ai_notetaker_block_requested"
  | "extension_health_status"
  | "extension_installed"
  | "extension_connected"
  | "policy_sync_success"
  | "policy_sync_failed"
  | "context_invalidated"
  | "context_recovered"
  | "backend_unreachable"
  | "telemetry_queued"
  | "extension_error";

export type BrowserTelemetryEvent = {
  correlation_id?: string;
  tenant_id?: string;
  browser?: BrowserType;
  browser_version?: string;
  browser_profile?: string;
  extension_name?: string;
  extension_version?: string;
  extension_build_hash?: string;
  endpoint_id?: string;
  hostname?: string;
  device_type?: "laptop" | "desktop" | "vm";
  os_type?: "mac" | "windows" | "linux";
  os_version?: string;
  ip_address?: string;
  location?: string;
  user_id?: string;
  user_email?: string;
  session_id?: string;
  tab_id?: string;
  event_type: BrowserEventType;
  domain: string;
  url?: string;
  page_title?: string;
  timestamp?: string;
  policy_version?: string;
  platform_mode?: "discovery" | "enforce";
  action_taken?: string;
  prompt_preview_redacted?: string;
  input_signal_types?: string[];
  file_meta?: Array<Record<string, unknown>>;
  ai_system_id?: string;
  severity?: string;
  agent_id?: string;
  agent_name?: string;
  model_name?: string;
  runtime_provider?: string;
  agent_environment?: string;
  detected_tools?: string[];
  detected_actions?: string[];
  detected_privileges?: string[];
  automation_suspected?: boolean;
  automation_confidence?: number;
  suspected_tool?: string;
  automation_indicators?: string[];
  meeting_surface?: "google_meet" | "microsoft_teams" | "unknown";
  notetaker_provider?: string;
  notetaker_label?: string;
  participant_visible?: boolean;
  control_mode?: "inline_prevented" | "inline_allowed" | "warned" | "shadow_would_block" | "detected_only" | "telemetry_only" | "external_required" | "external_action_triggered" | "incomplete" | string;
  enterprise_managed?: boolean;
  policy_locked?: boolean;
};

export type DataTransferContext = {
  source_url?: string;
  source_domain?: string;
  source_app_name?: string;
  source_surface_type?: "ai_tool" | "internal_app" | "email" | "slack" | "document" | "unknown";
  source_classification_hint?: "protected" | "unknown" | "public";
  copied_text_hash: string;
  copied_text_preview_redacted?: string;
  timestamp?: string;
};

export type DataTransferDestinationContext = {
  destination_url?: string;
  destination_domain?: string;
  destination_app_name?: string;
  destination_surface_type?: "email" | "slack" | "ai_tool" | "saas" | "unknown";
  destination_input_context?: "compose_box" | "chat_box" | "form_field" | "unknown";
  timestamp?: string;
};

export type DataTransferCheckPayload = {
  correlation_id?: string;
  tenant_id?: string;
  copy_context: DataTransferContext;
  paste_context: DataTransferDestinationContext;
  file_meta?: Array<Record<string, unknown>>;
  policy_version?: string;
  platform_mode?: "discovery" | "enforce";
  browser_profile?: string;
  browser_version?: string;
  extension_name?: string;
  extension_version?: string;
  extension_build_hash?: string;
  endpoint_id?: string;
  hostname?: string;
  device_type?: "laptop" | "desktop" | "vm";
  os_type?: "mac" | "windows" | "linux";
  os_version?: string;
  ip_address?: string;
  location?: string;
  user_id?: string;
  user_email?: string;
  actor_role?: string;
  actor_department?: string;
};

export type DataTransferCheckResponse = {
  decision: "allow" | "warn" | "block" | "require_justification";
  reason_code: string;
  explanation: string;
  recommended_action: string;
  justification_required: boolean;
  audit_log_id: string;
  evidence_node_id: string;
  finding_id?: string | null;
  runtime_event_id?: string | null;
  policy_version: string;
  platform_mode: "discovery" | "enforce" | string;
  destination_ai_system_id?: string | null;
};

export type DataTransferJustifyPayload = {
  correlation_id?: string;
  tenant_id?: string;
  justification: string;
  submitter_name?: string;
  submitter_email?: string;
  submitter_role?: string;
  submitter_department?: string;
  copy_context: DataTransferContext;
  paste_context: DataTransferDestinationContext;
  policy_decision: {
    decision: "allow" | "warn" | "block" | "require_justification";
    reason_code?: string;
    policy_version?: string;
    platform_mode?: "discovery" | "enforce";
  };
  file_meta?: Array<Record<string, unknown>>;
  policy_version?: string;
  platform_mode?: "discovery" | "enforce";
  browser_profile?: string;
  browser_version?: string;
  extension_name?: string;
  extension_version?: string;
  extension_build_hash?: string;
  endpoint_id?: string;
  hostname?: string;
  device_type?: "laptop" | "desktop" | "vm";
  os_type?: "mac" | "windows" | "linux";
  os_version?: string;
  ip_address?: string;
  location?: string;
  user_id?: string;
  user_email?: string;
  actor_role?: string;
  actor_department?: string;
};

export type DataTransferJustifyResponse = {
  decision: "allow" | "block";
  reason_code: string;
  explanation: string;
  recommended_action: string;
  audit_log_id: string;
  evidence_node_id: string;
  finding_id?: string | null;
  runtime_event_id?: string | null;
  policy_version: string;
  platform_mode: "discovery" | "enforce" | string;
  destination_ai_system_id?: string | null;
  destination_app_name?: string | null;
};

export type InteractionEvalPayload = {
  correlation_id?: string;
  tenant_id?: string;
  prompt_hash: string;
  prompt_preview_redacted: string;
  domain: string;
  url?: string;
  page_title?: string;
  policy_version?: string;
  platform_mode?: "discovery" | "enforce";
  input_signal_types?: string[];
  file_meta?: Array<Record<string, unknown>>;
  ai_system_id?: string;
  timeout_ms?: number;
  browser?: BrowserType;
  browser_profile?: string;
  browser_version?: string;
  extension_name?: string;
  extension_version?: string;
  extension_build_hash?: string;
  endpoint_id?: string;
  hostname?: string;
  device_type?: "laptop" | "desktop" | "vm";
  os_type?: "mac" | "windows" | "linux";
  os_version?: string;
  ip_address?: string;
  location?: string;
  user_id?: string;
  user_email?: string;
  actor_role?: string;
  actor_department?: string;
};

export type InteractionEvalResponse = {
  decision: "allow" | "warn" | "block";
  tier: "clear_negative" | "ambiguous" | "clear_positive";
  reason_codes: string[];
  policy_version: string;
  platform_mode: "discovery" | "enforce";
  correlation_id?: string;
  input_signal_types: string[];
  audit_log_id: string;
  evidence_node_id: string;
  finding_id?: string | null;
};

export type InteractionEvaluatePayload = {
  ai_action: Record<string, unknown>;
  context: Record<string, unknown>;
  content_signals?: Record<string, unknown>;
  app_profile?: Record<string, unknown>;
  policy_version?: string;
  legacy_interaction_payload?: InteractionEvalPayload;
};

export type InteractionEvaluateResponse = {
  decision: "allow" | "warn" | "block" | "step_up";
  reason: string;
  policy_id: string;
  control_ids: string[];
  user_message: string;
  admin_summary: string;
  evidence_required: boolean;
  input_signal_types: string[];
  reason_codes: string[];
};

type QueuedTelemetryEvent = BrowserTelemetryEvent & {
  __retry_attempts?: number;
  __next_retry_at_ms?: number;
  __scope?: string;
};

type TelemetryEnqueueOptions = {
  flushImmediately?: boolean;
};

const TELEMETRY_RETRY_BASE_DELAY_MS = 30_000;
const TELEMETRY_URGENT_RETRY_BASE_DELAY_MS = 1_000;
const TELEMETRY_RETRY_MAX_DELAY_MS = 5 * 60_000;
const TELEMETRY_QUEUE_KEY = "telemetryQueueV1";
const TELEMETRY_QUEUE_MAX_EVENTS = 200;
const TELEMETRY_URGENT_EVENT_TYPES = new Set<BrowserEventType>([
  "prompt_submitted",
  "prompt_warned",
  "prompt_blocked",
  "prompt_held",
  "policy_warned",
  "policy_blocked",
  "data_transfer_check",
  "file_upload_attempted",
  "file_upload_detected",
]);
const queue: QueuedTelemetryEvent[] = [];
let queueHydrated = false;
let interactionEvaluateRouteState: "unknown" | "available" | "missing" = "unknown";

type EndpointContext = {
  endpoint_id: string;
  hostname?: string;
  device_type: "laptop" | "desktop" | "vm";
  os_type?: "mac" | "windows" | "linux";
  os_version?: string;
  browser_version?: string;
  extension_name?: string;
};

type PilotIdentityContext = {
  user_id?: string;
  user_email?: string;
};

function parseBrowserVersion(): string | undefined {
  const userAgent = String(globalThis.navigator?.userAgent || "");
  const matched =
    userAgent.match(/(?:Edg|Chrome|Firefox)\/([0-9.]+)/i) ||
    userAgent.match(/Version\/([0-9.]+)\s+Safari/i);
  return matched?.[1];
}

function getExtensionManifestName(): string {
  try {
    return String(chrome.runtime.getManifest().name || "Hawk AI").trim()
      || "Hawk AI";
  } catch {
    return "Hawk AI";
  }
}

function parseOsVersion(): string | undefined {
  const userAgent = String(globalThis.navigator?.userAgent || "");
  const mac = userAgent.match(/Mac OS X ([0-9_]+)/i);
  if (mac?.[1]) return mac[1].replace(/_/g, ".");
  const windows = userAgent.match(/Windows NT ([0-9.]+)/i);
  if (windows?.[1]) return windows[1];
  const android = userAgent.match(/Android ([0-9.]+)/i);
  if (android?.[1]) return android[1];
  return undefined;
}

function mapPlatformOs(value: string | undefined): "mac" | "windows" | "linux" | undefined {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "mac") return "mac";
  if (normalized === "win" || normalized === "windows") return "windows";
  if (normalized === "linux") return "linux";
  return undefined;
}

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return atob(padded);
}

function parseJwtPayload(token: string): Record<string, unknown> {
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3 || !parts[1]) return {};
  try {
    return JSON.parse(decodeBase64Url(parts[1])) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function identityFromSettings(settings: ExtensionSettings): PilotIdentityContext {
  const payload = parseJwtPayload(settings.accessToken);
  const userId = String(payload.user_id || payload.sub || payload.uid || "").trim();
  const userEmail = String(payload.email || settings.authEmail || "").trim().toLowerCase();
  return {
    user_id: userId || undefined,
    user_email: userEmail || undefined,
  };
}

function telemetryQueueScope(settings: ExtensionSettings): string | null {
  const tenant = String(settings.tenantId || "").trim();
  const backend = String(settings.backendUrl || "").trim();
  const identity = identityFromSettings(settings);
  const actor = identity.user_id || identity.user_email;
  if (!tenant || !backend || !actor) return null;
  let origin: string;
  try {
    origin = new URL(backend).origin.toLowerCase();
  } catch {
    return null;
  }
  return JSON.stringify([tenant, origin, actor]);
}

export async function getPilotIdentityContext(settingsOverride?: ExtensionSettings): Promise<PilotIdentityContext> {
  const settings = settingsOverride || await getSettings();
  return identityFromSettings(settings);
}

async function hydrateEndpointContext(): Promise<EndpointContext> {
  const settings = await getSettings();
  const stored = await chrome.storage.local.get([ENDPOINT_ID_KEY, ENDPOINT_CONTEXT_KEY, STORAGE_KEYS.pilotHostname]);
  const existingContext = stored[ENDPOINT_CONTEXT_KEY] as EndpointContext | undefined;
  const endpoint_id = String(stored[ENDPOINT_ID_KEY] || existingContext?.endpoint_id || "").trim();
  const configuredHostname = String(settings.pilotHostname || stored[STORAGE_KEYS.pilotHostname] || "").trim();
  const browserVersion = parseBrowserVersion() || existingContext?.browser_version;
  const extensionName = getExtensionManifestName();
  const osVersion = settings.pilotOsVersion || parseOsVersion() || existingContext?.os_version || "unknown";
  if (
    endpoint_id
    && existingContext?.os_type
    && existingContext?.browser_version
    && existingContext?.hostname
    && existingContext?.os_version
    && (!configuredHostname || existingContext.hostname === configuredHostname)
    && existingContext.browser_version === browserVersion
    && existingContext.extension_name === extensionName
    && existingContext.os_version === osVersion
    && existingContext.device_type === settings.pilotDeviceType
  ) {
    return existingContext;
  }

  const runtime = await chrome.runtime.getPlatformInfo();
  const resolvedEndpointId = endpoint_id || `ep_${createCorrelationId().replace(/[^a-zA-Z0-9]/g, "").slice(0, 32)}`;
  const nextContext: EndpointContext = {
    endpoint_id: resolvedEndpointId,
    hostname: configuredHostname || existingContext?.hostname || `unknown-host-${resolvedEndpointId.slice(-8)}`,
    device_type: settings.pilotDeviceType || existingContext?.device_type || "laptop",
    os_type: mapPlatformOs(runtime.os),
    os_version: osVersion,
    browser_version: browserVersion,
    extension_name: extensionName,
  };

  await chrome.storage.local.set({
    [ENDPOINT_ID_KEY]: nextContext.endpoint_id,
    [ENDPOINT_CONTEXT_KEY]: nextContext,
  });
  return nextContext;
}

export async function getEndpointContext(): Promise<EndpointContext> {
  try {
    return await hydrateEndpointContext();
  } catch {
    const endpointId = `ep_${createCorrelationId().replace(/[^a-zA-Z0-9]/g, "").slice(0, 32)}`;
    return {
      endpoint_id: endpointId,
      hostname: `unknown-host-${endpointId.slice(-8)}`,
      device_type: "laptop",
      os_type: undefined,
      os_version: parseOsVersion() || "unknown",
      browser_version: parseBrowserVersion(),
      extension_name: getExtensionManifestName(),
    };
  }
}

export async function applyAttestedEndpointIdentity(identity: {
  endpointId?: string;
  endpointIdentityVerified: boolean;
}): Promise<void> {
  const endpointId = String(identity.endpointId || "").trim();
  if (
    !identity.endpointIdentityVerified
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(endpointId)
  ) {
    throw new Error("endpoint_identity_unverified");
  }
  const current = await getEndpointContext();
  const nextContext: EndpointContext = {
    ...current,
    endpoint_id: endpointId,
  };
  await chrome.storage.local.set({
    [ENDPOINT_ID_KEY]: endpointId,
    [ENDPOINT_CONTEXT_KEY]: nextContext,
  });
}

export function createCorrelationId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `corr-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

let runtimeSessionId: string | null = null;

function getRuntimeSessionId(): string {
  if (!runtimeSessionId) {
    runtimeSessionId = `sess_${createCorrelationId().replace(/[^a-zA-Z0-9]/g, "").slice(0, 32)}`;
  }
  return runtimeSessionId;
}

function sanitizeQueuedTelemetryEvents(value: unknown): QueuedTelemetryEvent[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (item && typeof item === "object" ? item as QueuedTelemetryEvent : null))
    .filter((item): item is QueuedTelemetryEvent => Boolean(item?.event_type && item?.domain))
    .slice(-TELEMETRY_QUEUE_MAX_EVENTS);
}

async function hydrateTelemetryQueueOnce(): Promise<void> {
  if (queueHydrated) return;
  queueHydrated = true;
  try {
    const stored = await chrome.storage.local.get([TELEMETRY_QUEUE_KEY]);
    const persisted = sanitizeQueuedTelemetryEvents(stored[TELEMETRY_QUEUE_KEY]);
    if (persisted.length && queue.length === 0) {
      queue.push(...persisted);
    }
  } catch {
    // Keep the in-memory queue usable even if Chrome storage is temporarily
    // unavailable. The next enqueue/flush attempt will try to persist again.
  }
}

async function persistTelemetryQueue(): Promise<void> {
  try {
    await chrome.storage.local.set({
      [TELEMETRY_QUEUE_KEY]: queue.slice(-TELEMETRY_QUEUE_MAX_EVENTS),
    });
  } catch {
    // Do not throw from persistence; callers still keep the in-memory queue.
  }
}

export async function enqueueTelemetryEvent(event: BrowserTelemetryEvent, options: TelemetryEnqueueOptions = {}): Promise<void> {
  await hydrateTelemetryQueueOnce();
  const settings = await getSettings();
  const cachedPolicy = await getCachedPolicy();
  const endpoint = await getEndpointContext();
  const identity = await getPilotIdentityContext(settings);
  const scope = telemetryQueueScope(settings);
  if (!scope) return;
  const extensionBuildHash = getExtensionBuildHash();
  const payload: BrowserTelemetryEvent = {
    ...event,
    correlation_id: event.correlation_id || createCorrelationId(),
    timestamp: event.timestamp || new Date().toISOString(),
    policy_version: event.policy_version || cachedPolicy?.policy_version,
    platform_mode: event.platform_mode || cachedPolicy?.platform_mode,
    endpoint_id: event.endpoint_id || endpoint.endpoint_id,
    hostname: event.hostname || endpoint.hostname,
    device_type: event.device_type || endpoint.device_type,
    os_type: event.os_type || endpoint.os_type,
    os_version: event.os_version || endpoint.os_version,
    browser_version: event.browser_version || endpoint.browser_version,
    extension_name: event.extension_name || endpoint.extension_name || getExtensionManifestName(),
    extension_build_hash: event.extension_build_hash || extensionBuildHash,
    user_id: event.user_id || identity.user_id,
    user_email: event.user_email || identity.user_email,
    session_id: event.session_id || getRuntimeSessionId(),
  };
  queue.push({ ...payload, __scope: scope });
  if (queue.length > TELEMETRY_QUEUE_MAX_EVENTS) {
    queue.splice(0, queue.length - TELEMETRY_QUEUE_MAX_EVENTS);
  }
  await persistTelemetryQueue();
  if (options.flushImmediately) {
    await flushTelemetryQueue();
  }
}

export function getTelemetryQueueDepth(): number {
  return queue.length;
}

export function getTelemetryNextRetryDelayMs(now = Date.now()): number {
  const retryTimes = queue
    .map((event) => Number(event.__next_retry_at_ms || 0))
    .filter((value) => Number.isFinite(value) && value > now);
  if (!retryTimes.length) return 0;
  return Math.max(0, Math.min(...retryTimes) - now);
}

function telemetryRetryDelayMs(event: QueuedTelemetryEvent, attempts: number): number {
  const baseDelay = TELEMETRY_URGENT_EVENT_TYPES.has(event.event_type)
    ? TELEMETRY_URGENT_RETRY_BASE_DELAY_MS
    : TELEMETRY_RETRY_BASE_DELAY_MS;
  return Math.min(TELEMETRY_RETRY_MAX_DELAY_MS, baseDelay * Math.max(1, attempts));
}

async function postTelemetryEvent(event: QueuedTelemetryEvent): Promise<boolean> {
  const settings = await getSettings();
  if (!event.__scope || event.__scope !== telemetryQueueScope(settings)) return false;
  if (!settings.tenantId || !settings.backendUrl) {
    throw new Error("Telemetry settings incomplete");
  }
  const extensionVersion = chrome.runtime.getManifest().version;
  const extensionBuildHash = getExtensionBuildHash();
  const extensionName = getExtensionManifestName();
  const endpoint = await getEndpointContext();
  const identity = await getPilotIdentityContext(settings);

  const { __scope: _scope, __retry_attempts: _attempts, __next_retry_at_ms: _retryAt, ...wireEvent } = event as QueuedTelemetryEvent;
  const response = await fetchWithTenantAuth("/telemetry/browser", {
    method: "POST",
    body: JSON.stringify({
      ...wireEvent,
      tenant_id: settings.tenantId,
      browser: event.browser || settings.browser,
      browser_version: event.browser_version || endpoint.browser_version,
      browser_profile: event.browser_profile || settings.browserProfile,
      extension_name: event.extension_name || endpoint.extension_name || extensionName,
      extension_version: event.extension_version || extensionVersion,
      extension_build_hash: event.extension_build_hash || extensionBuildHash,
      endpoint_id: event.endpoint_id || endpoint.endpoint_id,
      hostname: event.hostname || endpoint.hostname,
      device_type: event.device_type || endpoint.device_type,
      os_type: event.os_type || endpoint.os_type,
      os_version: event.os_version || endpoint.os_version,
      ip_address: event.ip_address,
      location: event.location,
      user_id: event.user_id || identity.user_id,
      user_email: event.user_email || identity.user_email,
      enterprise_managed: event.enterprise_managed ?? settings.enterpriseManaged,
      policy_locked: event.policy_locked ?? settings.policyLocked,
    }),
  }, {
    settings,
    extraHeaders: {
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`Telemetry ingest failed: ${response.status}`);
  }
  return true;
}

export async function flushTelemetryQueue(): Promise<void> {
  await hydrateTelemetryQueueOnce();
  if (!queue.length) return;
  const currentScope = telemetryQueueScope(await getSettings());
  if (!currentScope) return;
  queue.splice(0, queue.length, ...queue.filter((event) => event.__scope === currentScope));
  if (!queue.length) {
    await persistTelemetryQueue();
    return;
  }
  const now = Date.now();
  const snapshot = queue.splice(0, queue.length);
  const batch = snapshot.filter((event) => Number(event.__next_retry_at_ms || 0) <= now);
  const deferred = snapshot.filter((event) => Number(event.__next_retry_at_ms || 0) > now);
  queue.push(...deferred);
  await persistTelemetryQueue();
  for (const event of batch) {
    try {
      await postTelemetryEvent(event);
      await persistTelemetryQueue();
    } catch {
      const attempts = Number(event.__retry_attempts || 0) + 1;
      const delayMs = telemetryRetryDelayMs(event, attempts);
      queue.push({
        ...event,
        __retry_attempts: attempts,
        __next_retry_at_ms: Date.now() + delayMs,
      });
      await persistTelemetryQueue();
    }
  }
  await persistTelemetryQueue();
}

export async function evaluateInteraction(payload: InteractionEvalPayload): Promise<InteractionEvalResponse> {
  const settings = await getSettings();
  if (!settings.tenantId || !settings.backendUrl) {
    throw new Error("Extension settings incomplete");
  }
  const extensionVersion = chrome.runtime.getManifest().version;
  const extensionBuildHash = getExtensionBuildHash();
  const extensionName = getExtensionManifestName();
  const endpoint = await getEndpointContext();
  const identity = await getPilotIdentityContext(settings);

  const response = await fetchWithTenantAuth("/telemetry/browser/interaction-eval", {
    method: "POST",
    body: JSON.stringify({
      ...payload,
      tenant_id: settings.tenantId,
      correlation_id: payload.correlation_id || createCorrelationId(),
      browser: payload.browser || settings.browser,
      browser_profile: payload.browser_profile || settings.browserProfile,
      browser_version: payload.browser_version || endpoint.browser_version,
      extension_name: payload.extension_name || endpoint.extension_name || extensionName,
      extension_version: payload.extension_version || extensionVersion,
      extension_build_hash: payload.extension_build_hash || extensionBuildHash,
      endpoint_id: payload.endpoint_id || endpoint.endpoint_id,
      hostname: payload.hostname || endpoint.hostname,
      device_type: payload.device_type || endpoint.device_type,
      os_type: payload.os_type || endpoint.os_type,
      os_version: payload.os_version || endpoint.os_version,
      ip_address: payload.ip_address,
      location: payload.location,
      user_id: payload.user_id || identity.user_id,
      user_email: payload.user_email || identity.user_email,
      actor_role: payload.actor_role || settings.actorRole,
      actor_department: payload.actor_department || settings.actorDepartment,
      enterprise_managed: settings.enterpriseManaged,
      policy_locked: settings.policyLocked,
    }),
  }, {
    settings,
    extraHeaders: {
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`Interaction eval failed: ${response.status}`);
  }
  return await response.json() as InteractionEvalResponse;
}

export async function evaluateInteractionV2(payload: InteractionEvaluatePayload): Promise<InteractionEvaluateResponse> {
  const legacyPayload = payload.legacy_interaction_payload;
  if (interactionEvaluateRouteState === "missing") {
    if (!legacyPayload) {
      throw new Error("Interaction evaluate route unavailable and no fallback payload provided");
    }
    const fallback = await evaluateInteraction(legacyPayload);
    return {
      decision: fallback.decision === "block" ? "block" : fallback.decision === "allow" ? "allow" : "warn",
      reason: (fallback.reason_codes || []).join(", ") || `${fallback.decision}_by_policy`,
      policy_id: fallback.policy_version || "unknown",
      control_ids: [],
      user_message: (fallback.reason_codes || []).join(", ") || "Decision applied by policy.",
      admin_summary: "Legacy interaction-eval fallback used.",
      evidence_required: fallback.decision !== "allow",
      input_signal_types: Array.isArray(fallback.input_signal_types) ? fallback.input_signal_types : [],
      reason_codes: Array.isArray(fallback.reason_codes) ? fallback.reason_codes : [],
    };
  }

  const settings = await getSettings();
  if (!settings.tenantId || !settings.backendUrl) {
    throw new Error("Extension settings incomplete");
  }
  const extensionVersion = chrome.runtime.getManifest().version;
  const extensionBuildHash = getExtensionBuildHash();
  const extensionName = getExtensionManifestName();
  const endpoint = await getEndpointContext();
  const identity = await getPilotIdentityContext(settings);
  const response = await fetchWithTenantAuth("/interaction/evaluate", {
    method: "POST",
    body: JSON.stringify({
      ...payload,
      tenant_id: settings.tenantId,
      browser: settings.browser,
      browser_profile: settings.browserProfile,
      browser_version: endpoint.browser_version,
      extension_name: endpoint.extension_name || extensionName,
      extension_version: extensionVersion,
      extension_build_hash: extensionBuildHash,
      endpoint_id: endpoint.endpoint_id,
      hostname: endpoint.hostname,
      device_type: endpoint.device_type,
      os_type: endpoint.os_type,
      os_version: endpoint.os_version,
      user_id: identity.user_id,
      user_email: identity.user_email,
      enterprise_managed: settings.enterpriseManaged,
      policy_locked: settings.policyLocked,
      correlation_id: createCorrelationId(),
    }),
  }, {
    settings,
    extraHeaders: {
      "Content-Type": "application/json",
    },
  });
  if (response.ok) {
    interactionEvaluateRouteState = "available";
    return await response.json() as InteractionEvaluateResponse;
  }

  if (response.status === 404 || response.status === 405) {
    interactionEvaluateRouteState = "missing";
  }

  if (!legacyPayload) {
    throw new Error(`Interaction evaluate failed: ${response.status}`);
  }
  const legacyResult = await evaluateInteraction(legacyPayload);
  const decision = legacyResult.decision === "allow"
    ? "allow"
    : legacyResult.decision === "block"
      ? "block"
      : "warn";
  const reasonCodes = Array.isArray(legacyResult.reason_codes) ? legacyResult.reason_codes : [];
  const reason = reasonCodes.join(", ") || `${decision}_by_policy`;
  return {
    decision,
    reason,
    policy_id: legacyResult.policy_version || "unknown",
    control_ids: [],
    user_message: reason,
    admin_summary: `Fallback decision ${decision} from legacy interaction evaluation.`,
    evidence_required: decision !== "allow",
    input_signal_types: Array.isArray(legacyResult.input_signal_types) ? legacyResult.input_signal_types : [],
    reason_codes: reasonCodes,
  };
}

export async function evaluateDataTransfer(payload: DataTransferCheckPayload): Promise<DataTransferCheckResponse> {
  const settings = await getSettings();
  if (!settings.tenantId || !settings.backendUrl) {
    throw new Error("Extension settings incomplete");
  }
  const extensionVersion = chrome.runtime.getManifest().version;
  const extensionBuildHash = getExtensionBuildHash();
  const extensionName = getExtensionManifestName();
  const endpoint = await getEndpointContext();
  const identity = await getPilotIdentityContext(settings);

  const response = await fetchWithTenantAuth("/runtime-control/data-transfer-check", {
    method: "POST",
    body: JSON.stringify({
      ...payload,
      tenant_id: settings.tenantId,
      correlation_id: payload.correlation_id || createCorrelationId(),
      browser_profile: payload.browser_profile || settings.browserProfile,
      browser_version: payload.browser_version || endpoint.browser_version,
      extension_name: payload.extension_name || endpoint.extension_name || extensionName,
      extension_version: payload.extension_version || extensionVersion,
      extension_build_hash: payload.extension_build_hash || extensionBuildHash,
      endpoint_id: payload.endpoint_id || endpoint.endpoint_id,
      hostname: payload.hostname || endpoint.hostname,
      device_type: payload.device_type || endpoint.device_type,
      os_type: payload.os_type || endpoint.os_type,
      os_version: payload.os_version || endpoint.os_version,
      ip_address: payload.ip_address,
      location: payload.location,
      user_id: payload.user_id || identity.user_id,
      user_email: payload.user_email || identity.user_email,
      actor_role: payload.actor_role || settings.actorRole,
      actor_department: payload.actor_department || settings.actorDepartment,
      enterprise_managed: settings.enterpriseManaged,
      policy_locked: settings.policyLocked,
    }),
  }, {
    settings,
    extraHeaders: {
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`Data transfer check failed: ${response.status}`);
  }
  return await response.json() as DataTransferCheckResponse;
}

export async function submitDataTransferJustification(
  payload: DataTransferJustifyPayload,
): Promise<DataTransferJustifyResponse> {
  const settings = await getSettings();
  if (!settings.tenantId || !settings.backendUrl) {
    throw new Error("Extension settings incomplete");
  }
  const extensionVersion = chrome.runtime.getManifest().version;
  const extensionBuildHash = getExtensionBuildHash();
  const extensionName = getExtensionManifestName();
  const endpoint = await getEndpointContext();
  const identity = await getPilotIdentityContext(settings);

  const response = await fetchWithTenantAuth("/runtime-control/data-transfer-justify", {
    method: "POST",
    body: JSON.stringify({
      ...payload,
      tenant_id: settings.tenantId,
      correlation_id: payload.correlation_id || createCorrelationId(),
      browser_profile: payload.browser_profile || settings.browserProfile,
      browser_version: payload.browser_version || endpoint.browser_version,
      extension_name: payload.extension_name || endpoint.extension_name || extensionName,
      extension_version: payload.extension_version || extensionVersion,
      extension_build_hash: payload.extension_build_hash || extensionBuildHash,
      endpoint_id: payload.endpoint_id || endpoint.endpoint_id,
      hostname: payload.hostname || endpoint.hostname,
      device_type: payload.device_type || endpoint.device_type,
      os_type: payload.os_type || endpoint.os_type,
      os_version: payload.os_version || endpoint.os_version,
      ip_address: payload.ip_address,
      location: payload.location,
      user_id: payload.user_id || identity.user_id,
      user_email: payload.user_email || payload.submitter_email || identity.user_email,
      submitter_name: payload.submitter_name,
      submitter_email: payload.submitter_email,
      submitter_role: payload.submitter_role,
      submitter_department: payload.submitter_department,
      actor_role: payload.actor_role || payload.submitter_role || settings.actorRole,
      actor_department: payload.actor_department || payload.submitter_department || settings.actorDepartment,
      enterprise_managed: settings.enterpriseManaged,
      policy_locked: settings.policyLocked,
    }),
  }, {
    settings,
    extraHeaders: {
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`Data transfer justification failed: ${response.status}`);
  }
  return await response.json() as DataTransferJustifyResponse;
}
