import {
  classifyDomainStatus,
  domainMatches,
  fetchWithTenantAuth,
  getCachedPolicy,
  getSettings,
  STORAGE_KEYS,
  SUPPORTED_AI_DOMAINS,
  syncPolicyNow,
  type ExtensionPolicy,
} from "./policy-sync";
import { getExtensionBuildHash } from "./build-info";
import {
  blockedDataTransferResult,
  blockedInteractionResult,
  blockedInteractionV2Result,
  evaluateDataTransferWithEndpointAgent,
  evaluateEndpointFirst,
  evaluateWithEndpointAgent,
  endpointDecisionMetadata,
  endpointPlatformMode,
  getEndpointIdentityWithEndpointAgent,
  normalizeEndpointDecisionAction,
  type EndpointAgentDecision,
} from "./endpoint-agent";
import {
  createCorrelationId,
  applyAttestedEndpointIdentity,
  enqueueTelemetryEvent,
  evaluateDataTransfer,
  evaluateInteraction,
  evaluateInteractionV2,
  flushTelemetryQueue,
  getEndpointContext,
  getPilotIdentityContext,
  getTelemetryNextRetryDelayMs,
  getTelemetryQueueDepth,
  submitDataTransferJustification,
  type BrowserTelemetryEvent,
} from "./telemetry";
import { classifyDiscoveryEligibility, domainFromUrl } from "./discovery-heuristics";
import { endpointDataTransferPayload, endpointInteractionPayload } from "./endpoint-payload";

const POLICY_ALARM = "policy-sync";
const TELEMETRY_ALARM = "telemetry-flush";
const HEALTH_ALARM = "extension-health-status";
const HEALTH_LAST_AT_KEY = "lastHealthReportAt";
const HEALTH_LAST_STATUS_KEY = "lastHealthReportStatus";
const AUTOMATION_LOCK_KEY = "automationLockState";
const POLICY_CACHE_MAX_AGE_MS = 30_000;
const AUTOMATION_LOCK_TTL_MS = 5 * 60 * 1000;
const TELEMETRY_FLUSH_MIN_RETRY_DELAY_MS = 30_000;
const POLICY_MANAGED_DOMAINS = [
  "mail.google.com",
  "outlook.office.com",
  "outlook.live.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
];
const MEETING_SURFACE_DOMAINS = [
  "meet.google.com",
  "teams.microsoft.com",
  "teams.live.com",
  "teams.cloud.microsoft",
];
const TRUSTED_CONTROL_PLANE_HOSTS = ["localhost", "127.0.0.1", "::1"];
const TRUSTED_CONTROL_PLANE_PATH_PREFIXES = [
  "/",
  "/dashboard",
  "/trust-center",
  "/analytics",
  "/ai-footprint",
  "/guided-demo",
  "/interaction-security",
  "/shadow-ai",
  "/ai-iam",
  "/monitoring",
  "/integrations",
  "/simulations",
  "/validation-coverage",
  "/automated-auditor",
  "/discovery",
];

const CONTENT_SCRIPT_SCOPED_DOMAINS = new Set(
  [...SUPPORTED_AI_DOMAINS, ...POLICY_MANAGED_DOMAINS, ...MEETING_SURFACE_DOMAINS, "app.slack.com", "localhost", "127.0.0.1"]
    .map((value) => value.replace(/^www\./, ""))
);

const discoveryEmissionCache = new Map<string, number>();
let lastExtensionError: string | null = null;
let lastObservedTab: { domain: string; url: string | null } = { domain: "", url: null };
let lastHealthReportAttemptMs = 0;
let telemetryFlushInFlight: Promise<void> | null = null;

function endpointDecisionAction(decision: EndpointAgentDecision): "allow" | "warn" | "block" {
  return normalizeEndpointDecisionAction(decision);
}

function endpointReason(decision: EndpointAgentDecision): string {
  return String(decision.reason || "endpoint_policy_decision");
}

type AutomationLockState = {
  active: boolean;
  activated_at: string;
  expires_at: string;
  confidence: number;
  suspected_tool: string | null;
  indicators: string[];
  source_event_type: string;
  source_domain: string;
};

function shouldEmitDiscoveryEvent(domain: string, eventType: string, action: string): boolean {
  const key = `${eventType}:${domain}:${action}`;
  const now = Date.now();
  const previous = discoveryEmissionCache.get(key) || 0;
  if (now - previous < 120_000) return false;
  discoveryEmissionCache.set(key, now);
  return true;
}

function _toFiniteNumber(value: unknown): number {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

function _extractAutomationIndicators(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(
    new Set(
      value
        .map((item) => String(item || "").trim().toLowerCase())
        .filter(Boolean)
    )
  );
}

async function getAutomationLockState(): Promise<AutomationLockState | null> {
  const stored = await chrome.storage.local.get([AUTOMATION_LOCK_KEY]);
  const lock = stored[AUTOMATION_LOCK_KEY] as AutomationLockState | null | undefined;
  if (!lock || typeof lock !== "object") return null;
  const expiresAtMs = Date.parse(String(lock.expires_at || ""));
  if (!Number.isFinite(expiresAtMs) || Date.now() >= expiresAtMs) {
    await chrome.storage.local.remove(AUTOMATION_LOCK_KEY);
    return null;
  }
  if (!lock.active) return null;
  return lock;
}

async function setAutomationLockState(input: {
  confidence: number;
  suspectedTool: string | null;
  indicators: string[];
  sourceEventType: string;
  sourceDomain: string;
}): Promise<void> {
  const now = Date.now();
  const lock: AutomationLockState = {
    active: true,
    activated_at: new Date(now).toISOString(),
    expires_at: new Date(now + AUTOMATION_LOCK_TTL_MS).toISOString(),
    confidence: Math.max(0, Math.min(1, _toFiniteNumber(input.confidence))),
    suspected_tool: input.suspectedTool || null,
    indicators: Array.from(new Set(input.indicators)).slice(0, 24),
    source_event_type: input.sourceEventType,
    source_domain: input.sourceDomain,
  };
  await chrome.storage.local.set({ [AUTOMATION_LOCK_KEY]: lock });
}

function shouldActivateAutomationLock(payload: Record<string, unknown>): boolean {
  const eventType = String(payload.event_type || "").trim().toLowerCase();
  if (eventType === "browser_automation_blocked") return true;
  if (eventType === "browser_automation_action") {
    const actionTaken = String(payload.action_taken || "").trim().toLowerCase();
    if (actionTaken.startsWith("block:")) return true;
  }
  if (eventType !== "browser_automation_detected") return false;

  const suspected = Boolean(payload.automation_suspected);
  const confidence = _toFiniteNumber(payload.automation_confidence);
  const indicators = _extractAutomationIndicators(payload.automation_indicators);
  const signalTypes = Array.isArray(payload.input_signal_types)
    ? payload.input_signal_types.map((item) => String(item || "").toLowerCase())
    : [];
  const hasDebugBannerSignal = indicators.includes("automation_banner_debugging_browser")
    || signalTypes.some((item) => item.includes("automation_indicator:automation_banner_debugging_browser"));

  return suspected && (confidence >= 0.85 || hasDebugBannerSignal);
}

async function maybeUpdateAutomationLockFromTelemetry(payload: Record<string, unknown>): Promise<void> {
  if (!shouldActivateAutomationLock(payload)) return;
  await setAutomationLockState({
    confidence: _toFiniteNumber(payload.automation_confidence),
    suspectedTool: String(payload.suspected_tool || "").trim() || null,
    indicators: _extractAutomationIndicators(payload.automation_indicators),
    sourceEventType: String(payload.event_type || ""),
    sourceDomain: String(payload.domain || ""),
  });
}

function _isRiskyDomainUnderPolicy(domain: string, policy: ExtensionPolicy): boolean {
  const status = classifyDomainStatus(domain, policy);
  if (status === "blocked" || status === "critical") return true;
  if (status === "unknown" && String(policy.unknown_domain_behavior || "").toLowerCase() === "block") return true;
  return false;
}

function _extractPathname(rawUrl: string | null | undefined): string {
  if (!rawUrl) return "";
  try {
    return new URL(rawUrl).pathname.toLowerCase();
  } catch {
    return "";
  }
}

function _isTrustedControlPlaneUrl(domain: string, rawUrl: string | null | undefined): boolean {
  const path = _extractPathname(rawUrl);
  const isTrustedHost = TRUSTED_CONTROL_PLANE_HOSTS.some((host) => domainMatches(domain, host))
    || domain.includes("hawk");
  if (!isTrustedHost) return false;
  return TRUSTED_CONTROL_PLANE_PATH_PREFIXES.some((prefix) =>
    path === prefix || path.startsWith(`${prefix}/`)
  );
}

async function maybeBlockTabFromAutomationLock(tab: chrome.tabs.Tab): Promise<void> {
  if (!tab.id) return;
  const domain = domainFromUrl(tab.url);
  if (!domain) return;
  if (_isTrustedControlPlaneUrl(domain, tab.url)) return;
  const lock = await getAutomationLockState();
  if (!lock) return;
  const { policy } = await resolvePolicy(false);
  if (!policy || policy.platform_mode !== "enforce") return;
  if (!_isRiskyDomainUnderPolicy(domain, policy)) return;

  await enqueueTelemetryEvent({
    event_type: "browser_automation_blocked",
    domain,
    url: tab.url || undefined,
    page_title: tab.title || undefined,
    action_taken: "block_risky_domain_navigation",
    input_signal_types: [
      "automation_lock_active",
      "automation_tab_navigation_blocked",
      ...(lock.suspected_tool ? [`suspected_tool:${lock.suspected_tool}`] : []),
    ],
    policy_version: policy.policy_version,
    platform_mode: policy.platform_mode,
    automation_suspected: true,
    automation_confidence: lock.confidence,
    suspected_tool: lock.suspected_tool ?? undefined,
    automation_indicators: lock.indicators,
    severity: "critical",
  });
  scheduleTelemetryFlush();
  await chrome.tabs.remove(tab.id);
}

async function safeSyncPolicyNow(): Promise<void> {
  try {
    await syncPolicyNow();
    lastExtensionError = null;
  } catch (error) {
    lastExtensionError = `policy_sync_failed:${String(error)}`;
  }
}

async function syncAttestedEndpointIdentity(): Promise<boolean> {
  const identity = await getEndpointIdentityWithEndpointAgent();
  if (!identity.ok || !identity.endpointIdentityVerified || !identity.endpointId) {
    return false;
  }
  const settings = await getSettings();
  const browserIdentity = await getPilotIdentityContext(settings);
  if (identity.userId && browserIdentity.user_id && identity.userId !== browserIdentity.user_id) {
    lastExtensionError = "endpoint_identity_user_mismatch";
    return false;
  }
  await applyAttestedEndpointIdentity(identity);
  if (lastExtensionError === "endpoint_identity_user_mismatch") {
    lastExtensionError = null;
  }
  return true;
}

async function resolvePolicy(forceSync = false): Promise<{ policy: Awaited<ReturnType<typeof getCachedPolicy>>; fromSync: boolean }> {
  let policy = await getCachedPolicy();
  let shouldSync = forceSync || !policy;

  if (!shouldSync) {
    const state = await chrome.storage.local.get([STORAGE_KEYS.lastSyncAt]);
    const lastSyncAtRaw = String(state[STORAGE_KEYS.lastSyncAt] || "").trim();
    const lastSyncAtMs = lastSyncAtRaw ? Date.parse(lastSyncAtRaw) : Number.NaN;
    const isStale = !Number.isFinite(lastSyncAtMs) || Date.now() - lastSyncAtMs > POLICY_CACHE_MAX_AGE_MS;
    shouldSync = isStale;
  }

  if (!shouldSync) {
    return { policy, fromSync: false };
  }

  try {
    policy = await syncPolicyNow();
    lastExtensionError = null;
    return { policy, fromSync: true };
  } catch (error) {
    lastExtensionError = `policy_sync_failed:${String(error)}`;
    return { policy, fromSync: false };
  }
}

async function reportExtensionStatus(trigger: string): Promise<void> {
  const settings = await getSettings();
  if (!settings.tenantId || !settings.backendUrl) return;
  if (!settings.accessToken && !settings.refreshToken) return;

  // The native host can become available after the MV3 worker starts (for
  // example after endpoint-agent repair or a browser restart). Re-attest on
  // every bounded status interval so a previously generated browser ID cannot
  // remain the long-lived source identity. Failure leaves the existing
  // identity untouched and Deep Scan readiness partial.
  try {
    await syncAttestedEndpointIdentity();
  } catch (error) {
    lastExtensionError = `endpoint_identity_sync_failed:${String(error)}`;
  }

  const policy = await getCachedPolicy();
  const state = await chrome.storage.local.get([STORAGE_KEYS.lastSyncAt]);
  const lastSyncAt = String(state[STORAGE_KEYS.lastSyncAt] || "").trim() || null;
  const queueDepth = getTelemetryQueueDepth();
  const manifest = chrome.runtime.getManifest();
  const extensionName = String(manifest.name || "Hawk AI").trim() || "Hawk AI";
  const extensionVersion = manifest.version;
  const extensionBuildHash = getExtensionBuildHash();
  const endpoint = await getEndpointContext();
  const identity = await getPilotIdentityContext(settings);
  const healthy = !!policy && !!lastSyncAt && !lastExtensionError;
  const statusValue = healthy ? "ok" : "degraded";
  const correlationId = createCorrelationId();

  try {
    const response = await fetchWithTenantAuth("/extension/status", {
      method: "POST",
      body: JSON.stringify({
        correlation_id: correlationId,
        browser: settings.browser,
        browser_version: endpoint.browser_version,
        browser_profile: settings.browserProfile,
        extension_name: endpoint.extension_name || extensionName,
        extension_version: extensionVersion,
        extension_build_hash: extensionBuildHash,
        api_base_url: settings.backendUrl,
        backendUrl: settings.backendUrl,
        tenant_id: settings.tenantId,
        tenantId: settings.tenantId,
        enterprise_managed: settings.enterpriseManaged,
        policy_locked: settings.policyLocked,
        endpoint_id: endpoint.endpoint_id,
        hostname: endpoint.hostname,
        device_type: endpoint.device_type,
        os_type: endpoint.os_type,
        os_version: endpoint.os_version,
        user_id: identity.user_id,
        user_email: identity.user_email,
        healthy,
        status: statusValue,
        status_trigger: trigger,
        last_sync_at: lastSyncAt,
        telemetry_queue_depth: queueDepth,
        policy_version: policy?.policy_version,
        platform_mode: policy?.platform_mode,
        last_error: lastExtensionError,
        active_domain: lastObservedTab.domain || null,
        active_url: stripSensitiveUrlParts(lastObservedTab.url),
      }),
    }, {
      settings,
      extraHeaders: {
        "Content-Type": "application/json",
      },
    });
    if (!response.ok) {
      throw new Error(`status_report_failed:${response.status}`);
    }
    lastExtensionError = null;
  } catch (error) {
    lastExtensionError = `status_report_failed:${String(error)}`;
  } finally {
    await chrome.storage.local.set({
      [HEALTH_LAST_AT_KEY]: new Date().toISOString(),
      [HEALTH_LAST_STATUS_KEY]: statusValue,
    });
  }
}

function stripSensitiveUrlParts(value: string | null | undefined): string | null {
  const raw = String(value || "").trim();
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    return `${parsed.origin}${parsed.pathname || "/"}`;
  } catch {
    return null;
  }
}

function scheduleHealthReport(trigger: string, force = false): void {
  const now = Date.now();
  if (!force && now - lastHealthReportAttemptMs < 60_000) return;
  lastHealthReportAttemptMs = now;
  void reportExtensionStatus(trigger);
}

function scheduleTelemetryFlush(): void {
  if (telemetryFlushInFlight) return;
  telemetryFlushInFlight = flushTelemetryQueue()
    .then(() => {
      lastExtensionError = null;
    })
    .catch((error) => {
      lastExtensionError = `telemetry_flush_failed:${String(error)}`;
    })
    .finally(() => {
      telemetryFlushInFlight = null;
      if (getTelemetryQueueDepth() > 0) {
        const retryDelayMs = getTelemetryNextRetryDelayMs();
        if (retryDelayMs <= 0) {
          scheduleTelemetryFlush();
        } else {
          chrome.alarms.create(TELEMETRY_ALARM, {
            when: Date.now() + Math.max(TELEMETRY_FLUSH_MIN_RETRY_DELAY_MS, retryDelayMs),
          });
        }
      }
    });
}

function shouldFlushTelemetryImmediately(payload: Record<string, unknown>): boolean {
  const eventType = String(payload.event_type || "");
  return [
    "prompt_submitted",
    "prompt_warned",
    "prompt_blocked",
    "prompt_held",
    "policy_warned",
    "policy_blocked",
    "data_transfer_check",
    "file_upload_attempted",
    "file_upload_detected",
    "extension_health_status",
    "extension_connected",
    "context_invalidated",
    "context_recovered",
    "backend_unreachable",
    "telemetry_queued",
    "extension_error",
  ].includes(eventType);
}

async function maybeEmitDomainDiscoveryFromTab(tab: chrome.tabs.Tab): Promise<void> {
  const domain = domainFromUrl(tab.url);
  if (!domain) return;
  const discovery = classifyDiscoveryEligibility(
    {
      domain,
      url: tab.url,
      title: tab.title,
    },
    {
      policyManagedDomains: POLICY_MANAGED_DOMAINS,
      scopedDomains: CONTENT_SCRIPT_SCOPED_DOMAINS,
    }
  );
  if (!discovery.eligible) return;

  lastObservedTab = { domain, url: tab.url || null };

  if (CONTENT_SCRIPT_SCOPED_DOMAINS.has(domain)) {
    return;
  }

  const forceSync = discovery.hint === "policy_managed_domain";
  const { policy } = await resolvePolicy(forceSync);
  if (!policy) return;

  const status = classifyDomainStatus(domain, policy);
  const visitSignalTypes = [
    status === "unknown" ? "domain_policy_mismatch" : "domain_known",
    "tab_observer",
    ...(discovery.hint ? [`discovery_hint:${discovery.hint}`] : []),
  ];
  if (shouldEmitDiscoveryEvent(domain, "ai_domain_visit", status)) {
    await enqueueTelemetryEvent({
      event_type: "ai_domain_visit",
      domain,
      url: tab.url || undefined,
      page_title: tab.title || undefined,
      action_taken: status,
      input_signal_types: visitSignalTypes,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
    });
  }

  if (status === "unknown" && shouldEmitDiscoveryEvent(domain, "unknown_ai_detected", policy.unknown_domain_behavior)) {
    const unknownSignalTypes = [
      "domain_policy_mismatch",
      "tab_observer",
      ...(discovery.hint ? [`discovery_hint:${discovery.hint}`] : []),
    ];
    await enqueueTelemetryEvent({
      event_type: "unknown_ai_detected",
      domain,
      url: tab.url || undefined,
      page_title: tab.title || undefined,
      action_taken: policy.unknown_domain_behavior,
      input_signal_types: unknownSignalTypes,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
      severity: "high",
    });
  }

  scheduleTelemetryFlush();
}

async function initializeExtensionRuntime(): Promise<void> {
  await chrome.alarms.create(POLICY_ALARM, { periodInMinutes: 5 });
  await chrome.alarms.create(TELEMETRY_ALARM, { periodInMinutes: 1 });
  await chrome.alarms.create(HEALTH_ALARM, { periodInMinutes: 2 });
  await syncAttestedEndpointIdentity();
  await safeSyncPolicyNow();
  scheduleTelemetryFlush();
  scheduleHealthReport("startup", true);
}

chrome.runtime.onInstalled.addListener(() => {
  void initializeExtensionRuntime();
  void enqueueTelemetryEvent({
    event_type: "extension_installed",
    domain: "extension.local",
    action_taken: "installed",
    input_signal_types: ["lifecycle:on_installed"],
  }).then(() => {
    scheduleTelemetryFlush();
  }).catch(() => undefined);
});

chrome.runtime.onStartup.addListener(() => {
  void initializeExtensionRuntime();
  void enqueueTelemetryEvent({
    event_type: "extension_connected",
    domain: "extension.local",
    action_taken: "startup",
    input_signal_types: ["lifecycle:on_startup"],
  }).then(() => {
    scheduleTelemetryFlush();
  }).catch(() => undefined);
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === POLICY_ALARM) {
    void safeSyncPolicyNow();
    return;
  }
  if (alarm.name === TELEMETRY_ALARM) {
    scheduleTelemetryFlush();
    return;
  }
  if (alarm.name === HEALTH_ALARM) {
    scheduleHealthReport("alarm");
  }
});

chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  const urlChanged = Boolean(changeInfo.url);
  if (!urlChanged && changeInfo.status !== "complete") return;
  void maybeBlockTabFromAutomationLock(tab).catch((error) => {
    lastExtensionError = `automation_lock_block_failed:${String(error)}`;
  });
  if (changeInfo.status !== "complete") return;
  void maybeEmitDomainDiscoveryFromTab(tab).catch((error) => {
    lastExtensionError = `tab_discovery_failed:${String(error)}`;
  });
});

chrome.runtime.onMessage.addListener((message: any, _sender, sendResponse) => {
  const type = String(message?.type || "");

  if (type === "ENDPOINT_AGENT_EVALUATE") {
    void evaluateWithEndpointAgent((message.payload || {}) as Record<string, unknown>)
      .then((result) => {
        sendResponse({ ok: result.ok, result });
      })
      .catch((error) => {
        sendResponse({
          ok: false,
          result: {
            ok: false,
            endpointAvailable: false,
            endpointAuthorized: false,
            source: "endpoint_agent_unavailable",
            error: String(error),
          },
        });
      });
    return true;
  }

  if (type === "GET_POLICY") {
    void (async () => {
      const forceSync = Boolean(message?.forceSync);
      const { policy, fromSync } = await resolvePolicy(forceSync);
      if (!policy) {
        sendResponse({ ok: false, error: "Policy unavailable" });
        return;
      }
      const status = classifyDomainStatus(String(message.domain || ""), policy);
      scheduleHealthReport("get_policy");
      sendResponse({ ok: true, policy, domainStatus: status, policyRefreshed: fromSync });
    })();
    return true;
  }

  if (type === "SYNC_POLICY_NOW") {
    void (async () => {
      try {
        const policy = await syncPolicyNow();
        lastExtensionError = null;
        scheduleHealthReport("manual_sync", true);
        sendResponse({ ok: true, policy });
      } catch (error) {
        lastExtensionError = `policy_sync_failed:${String(error)}`;
        sendResponse({ ok: false, error: String(error) });
      }
    })();
    return true;
  }

  if (type === "TELEMETRY_EVENT") {
    const payload = (message.payload || {}) as BrowserTelemetryEvent;
    sendResponse({ ok: true, accepted: true });
    void (async () => {
      try {
        await maybeUpdateAutomationLockFromTelemetry(payload);
        const flushImmediately = shouldFlushTelemetryImmediately(payload);
        await enqueueTelemetryEvent(payload, { flushImmediately });
        if (!flushImmediately) scheduleTelemetryFlush();
        lastExtensionError = null;
        scheduleHealthReport("telemetry_event");
      } catch (error) {
        lastExtensionError = `telemetry_event_failed:${String(error)}`;
      }
    })();
    return false;
  }

  if (type === "INTERACTION_EVAL") {
    void (async () => {
      try {
        const evaluated = await evaluateEndpointFirst(
          endpointInteractionPayload(message.payload || {}),
          () => evaluateInteraction(message.payload),
          (decision) => {
            const action = endpointDecisionAction(decision);
            const reason = endpointReason(decision);
            return {
              decision: action,
              tier: action === "block" ? "clear_positive" : action === "allow" ? "clear_negative" : "ambiguous",
              reason_codes: [reason],
              policy_version: "endpoint-agent",
              platform_mode: endpointPlatformMode(decision),
              input_signal_types: ["endpoint_agent_native"],
              audit_log_id: String(decision.evidence_ref || ""),
              evidence_node_id: String(decision.evidence_ref || ""),
            };
          },
          { mapNonAuthorized: blockedInteractionResult }
        );
        lastExtensionError = null;
        sendResponse({
          ok: true,
          result: evaluated.result,
          ...endpointDecisionMetadata(evaluated),
        });
      } catch (error) {
        lastExtensionError = `interaction_eval_failed:${String(error)}`;
        sendResponse({ ok: false, error: String(error) });
      }
    })();
    return true;
  }

  if (type === "INTERACTION_EVALUATE") {
    void (async () => {
      try {
        const evaluated = await evaluateEndpointFirst(
          endpointInteractionPayload(message.payload || {}),
          () => evaluateInteractionV2(message.payload),
          (decision) => {
            const action = endpointDecisionAction(decision);
            const reason = endpointReason(decision);
            return {
              decision: action,
              reason,
              policy_id: "endpoint-agent",
              control_ids: [],
              user_message: reason,
              admin_summary: `Endpoint agent decision: ${action}.`,
              evidence_required: action !== "allow",
              input_signal_types: ["endpoint_agent_native"],
              reason_codes: [reason],
            };
          },
          { mapNonAuthorized: blockedInteractionV2Result }
        );
        lastExtensionError = null;
        sendResponse({
          ok: true,
          result: evaluated.result,
          ...endpointDecisionMetadata(evaluated),
        });
      } catch (error) {
        lastExtensionError = `interaction_evaluate_failed:${String(error)}`;
        sendResponse({ ok: false, error: String(error) });
      }
    })();
    return true;
  }

  if (type === "DATA_TRANSFER_CHECK") {
    void (async () => {
      try {
        const evaluated = await evaluateEndpointFirst(
          endpointDataTransferPayload(message.payload || {}),
          () => evaluateDataTransfer(message.payload),
          (decision) => {
            const action = endpointDecisionAction(decision);
            const reason = endpointReason(decision);
            return {
              decision: action,
              reason_code: reason,
              explanation: reason,
              recommended_action: action === "block" ? "cancel_transfer" : "continue",
              justification_required: false,
              audit_log_id: String(decision.evidence_ref || ""),
              evidence_node_id: String(decision.evidence_ref || ""),
              policy_version: "endpoint-agent",
              platform_mode: endpointPlatformMode(decision),
            };
          },
          {
            endpointEvaluate: evaluateDataTransferWithEndpointAgent,
            mapNonAuthorized: blockedDataTransferResult,
          }
        );
        lastExtensionError = null;
        sendResponse({
          ok: true,
          result: evaluated.result,
          ...endpointDecisionMetadata(evaluated),
        });
      } catch (error) {
        lastExtensionError = `data_transfer_check_failed:${String(error)}`;
        sendResponse({ ok: false, error: String(error) });
      }
    })();
    return true;
  }

  if (type === "DATA_TRANSFER_JUSTIFY") {
    void (async () => {
      try {
        const result = await submitDataTransferJustification(message.payload);
        lastExtensionError = null;
        sendResponse({ ok: true, result });
      } catch (error) {
        lastExtensionError = `data_transfer_justify_failed:${String(error)}`;
        sendResponse({ ok: false, error: String(error) });
      }
    })();
    return true;
  }

  if (type === "REPORT_EXTENSION_HEALTH") {
    void (async () => {
      try {
        await reportExtensionStatus("manual_request");
        sendResponse({ ok: true });
      } catch (error) {
        sendResponse({ ok: false, error: String(error) });
      }
    })();
    return true;
  }

  if (type === "GET_EXTENSION_STATE") {
    void (async () => {
      const settings = await getSettings();
      const stored = await chrome.storage.local.get([
        STORAGE_KEYS.lastSyncAt,
        STORAGE_KEYS.cachedPolicy,
        STORAGE_KEYS.backendUrl,
        STORAGE_KEYS.tenantId,
        HEALTH_LAST_AT_KEY,
        HEALTH_LAST_STATUS_KEY,
        AUTOMATION_LOCK_KEY,
      ]);
      sendResponse({
        ok: true,
        lastSyncAt: stored[STORAGE_KEYS.lastSyncAt] || null,
        lastHealthReportAt: stored[HEALTH_LAST_AT_KEY] || null,
        lastHealthReportStatus: stored[HEALTH_LAST_STATUS_KEY] || null,
        policy: stored[STORAGE_KEYS.cachedPolicy] || null,
        backendUrl: stored[STORAGE_KEYS.backendUrl] || "",
        tenantId: stored[STORAGE_KEYS.tenantId] || "",
        hasRefreshToken: Boolean(settings.refreshToken),
        tokenStorage: "session",
        telemetryQueueDepth: getTelemetryQueueDepth(),
        automationLockState: stored[AUTOMATION_LOCK_KEY] || null,
        lastError: lastExtensionError,
      });
    })();
    return true;
  }

  if (type === "CLEAR_AUTOMATION_LOCK") {
    void (async () => {
      await chrome.storage.local.remove(AUTOMATION_LOCK_KEY);
      sendResponse({ ok: true });
    })();
    return true;
  }

  return false;
});
