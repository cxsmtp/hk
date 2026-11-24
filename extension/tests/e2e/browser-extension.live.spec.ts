import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { chromium, expect, test, type BrowserContext, type Page, type TestInfo } from "@playwright/test";

type JsonRecord = Record<string, unknown>;

type CapturedBackendCall = {
  method: string;
  url: string;
  path: string;
  requestBody: JsonRecord | null;
  responseStatus: number;
  responseBody: JsonRecord | null;
  capturedAt: string;
};

type TenantSession = {
  accessToken: string;
  refreshToken: string;
  tenantId: string;
  email: string;
};

type ExtensionState = {
  lastSyncAt: string | null;
  policyVersion: string | null;
  platformMode: string | null;
  telemetryQueueDepth: number;
  healthStatus: string | null;
};

type DiscoveryApplicationRow = {
  id: string;
  tool_name: string;
  tool_key: string;
  status: string;
  metadata_json: JsonRecord;
};

type ListEnvelope<T> = {
  items: T[];
  total: number;
  page: number;
  page_size: number;
};

type ExtensionFlowAssertionResult = {
  telemetryEventType: string;
  domain: string;
  correlationId: string;
  auditLogId: string;
  evidenceNodeId: string;
  runtimeEventId: string;
  findingId: string | null;
  discoveryApplicationId: string;
  discoveryStatus: string;
};

type LaunchResult = {
  context: BrowserContext;
  page: Page;
  userDataDir: string;
  capturedCalls: CapturedBackendCall[];
  extensionState: ExtensionState;
  healthCall: CapturedBackendCall;
  harPath: string;
  navigationBlockedByClient: boolean;
};

const E2E_WAIT_TIMEOUT_MS = Number(process.env.EXT_E2E_TIMEOUT_MS || 30_000);

const RUN_LIVE_BACKEND = process.env.EXT_E2E_LIVE_BACKEND === "1";

const currentFilePath = fileURLToPath(import.meta.url);
const currentDir = path.dirname(currentFilePath);
const extensionPath = path.resolve(currentDir, "..", "..");
const requiredBundleFiles = [
  path.join(extensionPath, "dist", "service-worker.js"),
  path.join(extensionPath, "dist", "content-script.js"),
  path.join(extensionPath, "dist", "options.js"),
];

const backendBaseUrl = String(process.env.EXT_E2E_BACKEND_URL || "http://localhost:8000").replace(/\/+$/, "");

const approvedOrigin = String(process.env.EXT_E2E_APPROVED_ORIGIN || "https://chat.openai.com");
const blockedOrigin = String(process.env.EXT_E2E_BLOCKED_ORIGIN || "https://claude.ai");
const unknownOrigin = String(process.env.EXT_E2E_UNKNOWN_ORIGIN || "https://poe.com");
const promptOrigin = String(process.env.EXT_E2E_PROMPT_ORIGIN || "https://chat.openai.com");

const approvedDomain = new URL(approvedOrigin).hostname.replace(/^www\./, "").toLowerCase();
const blockedDomain = new URL(blockedOrigin).hostname.replace(/^www\./, "").toLowerCase();
const unknownDomain = new URL(unknownOrigin).hostname.replace(/^www\./, "").toLowerCase();
const promptDomain = new URL(promptOrigin).hostname.replace(/^www\./, "").toLowerCase();

const backendPassword = String(process.env.EXT_E2E_PASSWORD || "Password123!");
const headed = process.env.EXT_E2E_HEADED === "0" ? false : true;

let suiteSession: TenantSession | null = null;

function requireSuiteSession(): TenantSession {
  if (!suiteSession) {
    throw new Error("Live backend suite session was not initialized in beforeAll");
  }
  return suiteSession;
}

function normalizeDomain(raw: string): string {
  return String(raw || "").trim().toLowerCase().replace(/^www\./, "");
}

function toolKeyForDomain(domain: string): string {
  const raw = normalizeDomain(domain);
  if (!raw) return "unknown";
  const chars: string[] = [];
  let previousSeparator = false;
  for (const char of raw) {
    if (/[a-z0-9]/.test(char)) {
      chars.push(char);
      previousSeparator = false;
      continue;
    }
    if (!previousSeparator) {
      chars.push("_");
      previousSeparator = true;
    }
  }
  return chars.join("").replace(/^_+|_+$/g, "") || "unknown";
}

function parseJsonSafe(value: string | null | undefined): JsonRecord | null {
  if (!value || !value.trim()) return null;
  try {
    return JSON.parse(value) as JsonRecord;
  } catch {
    return null;
  }
}

async function waitFor<T>(predicate: () => T | null | undefined, timeoutMs: number, label: string): Promise<T> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = predicate();
    if (value) return value;
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function waitForEitherVisible(
  page: Page,
  selectors: string[],
  timeoutMs: number,
  label: string
): Promise<string> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    for (const selector of selectors) {
      try {
        const visible = await page.locator(selector).isVisible();
        if (visible) return selector;
      } catch {
        continue;
      }
    }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function waitForCall(
  capturedCalls: CapturedBackendCall[],
  predicate: (call: CapturedBackendCall) => boolean,
  timeoutMs: number,
  label: string
): Promise<CapturedBackendCall> {
  return await waitFor(() => capturedCalls.find(predicate), timeoutMs, label);
}

function assertExtensionBundleExists(): void {
  const missing = requiredBundleFiles.filter((filePath) => !fs.existsSync(filePath));
  if (missing.length > 0) {
    throw new Error(`Extension bundle missing. Run 'npm run build' in extension first. Missing: ${missing.join(", ")}`);
  }
}

function asListEnvelope<T>(payload: JsonRecord, label: string): ListEnvelope<T> {
  const items = payload.items;
  if (!Array.isArray(items)) {
    throw new Error(`${label}: expected list envelope items`);
  }
  return payload as unknown as ListEnvelope<T>;
}

class BackendClient {
  private readonly baseUrl: string;
  private session: TenantSession | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  setSession(session: TenantSession): void {
    this.session = session;
  }

  getSession(): TenantSession {
    if (!this.session) {
      throw new Error("Backend session is not initialized");
    }
    return this.session;
  }

  private async request<T = JsonRecord>(
    method: string,
    pathSuffix: string,
    body: JsonRecord | null = null,
    expectedStatus: number = 200,
    includeAuth = true
  ): Promise<T> {
    const url = `${this.baseUrl}${pathSuffix}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (includeAuth) {
      const session = this.getSession();
      headers.Authorization = `Bearer ${session.accessToken}`;
      headers["X-Tenant-ID"] = session.tenantId;
    }
    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const raw = await response.text();
    if (response.status !== expectedStatus) {
      throw new Error(`${method} ${pathSuffix} failed with ${response.status}: ${raw}`);
    }
    if (!raw) {
      return {} as T;
    }
    return JSON.parse(raw) as T;
  }

  async ensureBackendHealthy(): Promise<void> {
    const response = await fetch(`${this.baseUrl}/health`);
    if (!response.ok) {
      throw new Error(`Backend health check failed with ${response.status}`);
    }
  }

  async registerFreshOwner(): Promise<TenantSession> {
    const suffix = `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
    const email = `ext-live-${suffix}@example.com`;
    const payload = await this.request<JsonRecord>(
      "POST",
      "/auth/register",
      {
        email,
        password: backendPassword,
        full_name: "Extension Live Owner",
      },
      200,
      false
    );
    const accessToken = String(payload.access_token || "");
    const refreshToken = String(payload.refresh_token || "");
    const tenants = Array.isArray(payload.tenants) ? (payload.tenants as JsonRecord[]) : [];
    const tenantId = String((tenants[0] || {}).id || "");
    if (!accessToken || !refreshToken || !tenantId) {
      throw new Error("Failed to register live extension test owner");
    }
    const session: TenantSession = { accessToken, refreshToken, tenantId, email };
    this.setSession(session);
    return session;
  }

  async getExtensionPolicySync(): Promise<JsonRecord> {
    return await this.request<JsonRecord>("GET", "/extension/policy-sync");
  }

  async emitUnknownDomainDiscovery(domain: string): Promise<JsonRecord> {
    return await this.request<JsonRecord>("POST", "/telemetry/browser", {
      correlation_id: `ext-live-seed-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      event_type: "unknown_ai_detected",
      domain,
      url: `https://${domain}/`,
      page_title: `${domain} seed`,
      action_taken: "discover",
      input_signal_types: ["domain_policy_mismatch"],
      browser: "chrome",
      browser_profile: "ext-live-seed",
      extension_version: "0.1.0",
    });
  }

  async listDiscoveryApplications(): Promise<ListEnvelope<DiscoveryApplicationRow>> {
    const payload = await this.request<JsonRecord>("GET", "/discovery/applications?page=1&page_size=500");
    return asListEnvelope<DiscoveryApplicationRow>(payload, "discovery.applications");
  }

  async findDiscoveryApplicationByDomain(domain: string): Promise<DiscoveryApplicationRow | null> {
    const toolKey = toolKeyForDomain(domain);
    const list = await this.listDiscoveryApplications();
    const matched = list.items.find((item) => {
      const name = normalizeDomain(String(item.tool_name || ""));
      const key = String(item.tool_key || "");
      return name === normalizeDomain(domain) || key === toolKey;
    });
    return matched || null;
  }

  async ensureDiscoveryStatus(domain: string, targetStatus: "approved" | "blocked"): Promise<DiscoveryApplicationRow> {
    let application = await this.findDiscoveryApplicationByDomain(domain);
    if (!application) {
      await this.emitUnknownDomainDiscovery(domain);
      await sleep(250);
      application = await this.findDiscoveryApplicationByDomain(domain);
    }
    if (!application) {
      throw new Error(`Unable to create/find discovery application for ${domain}`);
    }

    if (targetStatus === "approved" && application.status !== "approved") {
      await this.request<JsonRecord>("POST", `/discovery/applications/${application.id}/promote`, {
        action: "approve",
        provisional_risk_tier: "HIGH",
      });
    }
    if (targetStatus === "blocked" && application.status !== "blocked") {
      await this.request<JsonRecord>("POST", `/discovery/applications/${application.id}/block`, {
        reason: "Extension live e2e blocked domain fixture",
      });
    }

    const refreshed = await this.findDiscoveryApplicationByDomain(domain);
    if (!refreshed) {
      throw new Error(`Discovery application disappeared for ${domain}`);
    }
    if (refreshed.status !== targetStatus) {
      throw new Error(`Discovery status for ${domain} is ${refreshed.status}, expected ${targetStatus}`);
    }
    return refreshed;
  }

  async listAuditLogs(): Promise<ListEnvelope<{ id: string }>> {
    const payload = await this.request<JsonRecord>("GET", "/trust-center/audit-logs?page=1&page_size=500");
    return asListEnvelope<{ id: string }>(payload, "trust-center.audit-logs");
  }

  async listEvidenceNodes(): Promise<ListEnvelope<{ id: string }>> {
    const payload = await this.request<JsonRecord>("GET", "/trust-center/evidence/nodes?page=1&page_size=500");
    return asListEnvelope<{ id: string }>(payload, "trust-center.evidence.nodes");
  }

  async listFindings(): Promise<ListEnvelope<{ finding_id: string }>> {
    const payload = await this.request<JsonRecord>("GET", "/findings?page=1&page_size=500");
    return asListEnvelope<{ finding_id: string }>(payload, "findings");
  }

  async listRuntimeEvents(correlationId: string): Promise<ListEnvelope<{ event_id: string }>> {
    const payload = await this.request<JsonRecord>(
      "GET",
      `/runtime-intelligence/events?page=1&page_size=500&source_surface=browser&correlation_id=${encodeURIComponent(correlationId)}`
    );
    return asListEnvelope<{ event_id: string }>(payload, "runtime-intelligence.events");
  }

  async createAuditorSnapshotAndAssertEvidence(evidenceNodeId: string): Promise<void> {
    const exportPayload = await this.request<JsonRecord>("POST", "/auditor/export", {
      ai_system_id: null,
    });
    const downloadUrl = String(exportPayload.download_url || "");
    if (!downloadUrl) {
      throw new Error("auditor export missing download_url");
    }
    const response = await fetch(`${this.baseUrl}${downloadUrl}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${this.getSession().accessToken}`,
        "X-Tenant-ID": this.getSession().tenantId,
      },
    });
    if (!response.ok) {
      const raw = await response.text();
      throw new Error(`auditor snapshot download failed ${response.status}: ${raw}`);
    }
    const content = await response.text();
    const parsed = parseJsonSafe(content) || {};
    const links = Array.isArray(parsed.evidence_links) ? (parsed.evidence_links as JsonRecord[]) : [];
    const linked = links.some((item) => String(item.node_id || "") === evidenceNodeId);
    expect(linked).toBeTruthy();
  }
}

function buildFixturePage(domain: string, pageType: "approved" | "blocked" | "unknown" | "prompt"): string {
  return `
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>${domain} ${pageType} fixture</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 24px; }
      textarea { width: 100%; max-width: 860px; min-height: 160px; }
      #send-button { margin-top: 12px; padding: 8px 14px; }
    </style>
  </head>
  <body>
    <h1 data-testid="fixture-title">${domain}</h1>
    <p>Fixture type: ${pageType}</p>
    <textarea id="prompt" placeholder="Type prompt"></textarea>
    <button id="send-button" type="button">Send</button>
  </body>
</html>
`.trim();
}

async function routeFixturePages(context: BrowserContext): Promise<void> {
  const fixtures: Array<{ origin: string; type: "approved" | "blocked" | "unknown" | "prompt" }> = [
    { origin: approvedOrigin, type: "approved" },
    { origin: blockedOrigin, type: "blocked" },
    { origin: unknownOrigin, type: "unknown" },
    { origin: promptOrigin, type: "prompt" },
  ];
  const uniqueByOrigin = new Map<string, "approved" | "blocked" | "unknown" | "prompt">();
  for (const fixture of fixtures) {
    uniqueByOrigin.set(fixture.origin, fixture.type);
  }
  for (const [origin, type] of uniqueByOrigin.entries()) {
    const fixture = { origin, type };
    const domain = normalizeDomain(new URL(fixture.origin).hostname);
    await context.route(`${fixture.origin}/**`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body: buildFixturePage(domain, fixture.type),
      });
    });
  }
}

function captureBackendCalls(context: BrowserContext, capturedCalls: CapturedBackendCall[]): void {
  context.on("response", async (response) => {
    const url = response.url();
    if (!url.startsWith(backendBaseUrl)) return;
    const request = response.request();
    const pathName = (() => {
      try {
        return new URL(url).pathname;
      } catch {
        return "";
      }
    })();
    const requestBody = parseJsonSafe(request.postData() || "");
    let responseBody: JsonRecord | null = null;
    try {
      responseBody = parseJsonSafe(await response.text());
    } catch {
      responseBody = null;
    }
    capturedCalls.push({
      method: request.method(),
      url,
      path: pathName,
      requestBody,
      responseStatus: response.status(),
      responseBody,
      capturedAt: new Date().toISOString(),
    });
  });
}

async function configureExtension(
  context: BrowserContext,
  session: TenantSession,
  browserProfile: string,
  options: { disableDynamicRules?: boolean } = {}
): Promise<ExtensionState> {
  const worker = context.serviceWorkers()[0] || (await context.waitForEvent("serviceworker"));
  const extensionId = new URL(worker.url()).hostname;
  const optionsPage = await context.newPage();
  try {
    await optionsPage.goto(`chrome-extension://${extensionId}/options.html`);
    return await optionsPage.evaluate(
      async ({ backendUrl, accessToken, refreshToken, tenantId, browserProfile, timeoutMs, disableDynamicRules }) => {
        const sleepMs = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
        const send = async <T>(message: Record<string, unknown>): Promise<T> => {
          let lastError: string | null = null;
          for (let attempt = 0; attempt < 20; attempt += 1) {
            const result = await new Promise<{ response: any; runtimeError: string | null }>((resolve) => {
              chrome.runtime.sendMessage(message, (response) => {
                resolve({
                  response,
                  runtimeError: chrome.runtime.lastError ? chrome.runtime.lastError.message : null,
                });
              });
            });
            if (!result.runtimeError) {
              return result.response as T;
            }
            lastError = result.runtimeError;
            await sleepMs(100);
          }
          throw new Error(lastError || `runtime_send_failed:${String(message.type || "unknown")}`);
        };

        await chrome.storage.local.set({
          backendUrl,
          accessToken,
          refreshToken,
          tenantId,
          browser: "chrome",
          browserProfile,
          dynamicRuleIds: [],
        });
        await chrome.storage.local.remove(["cachedPolicy", "lastSyncAt"]);

        const syncResponse = await send<{ ok?: boolean; error?: string }>({ type: "SYNC_POLICY_NOW" });
        if (!syncResponse || syncResponse.ok === false) {
          throw new Error(`sync_policy_now_failed:${String(syncResponse?.error || "unknown")}`);
        }
        if (disableDynamicRules) {
          const stored = await chrome.storage.local.get(["dynamicRuleIds"]);
          const dynamicRuleIds = Array.isArray(stored.dynamicRuleIds) ? stored.dynamicRuleIds.filter((v: unknown) => Number.isFinite(Number(v))).map((v: unknown) => Number(v)) : [];
          if (dynamicRuleIds.length > 0) {
            await chrome.declarativeNetRequest.updateDynamicRules({
              removeRuleIds: dynamicRuleIds,
              addRules: [],
            });
          }
          await chrome.storage.local.set({ dynamicRuleIds: [] });
        }
        const healthResponse = await send<{ ok?: boolean; error?: string }>({ type: "REPORT_EXTENSION_HEALTH" });
        if (!healthResponse || healthResponse.ok === false) {
          throw new Error(`extension_health_report_failed:${String(healthResponse?.error || "unknown")}`);
        }

        const started = Date.now();
        let state: any = null;
        while (Date.now() - started < timeoutMs) {
          state = await send<any>({ type: "GET_EXTENSION_STATE" });
          if (state?.lastSyncAt && state?.policy?.policy_version) {
            break;
          }
          await sleepMs(100);
        }
        return {
          lastSyncAt: state?.lastSyncAt || null,
          policyVersion: state?.policy?.policy_version || null,
          platformMode: state?.policy?.platform_mode || null,
          telemetryQueueDepth: Number(state?.telemetryQueueDepth || 0),
          healthStatus: state?.lastHealthReportStatus || null,
        };
      },
      {
        backendUrl: backendBaseUrl,
        accessToken: session.accessToken,
        refreshToken: session.refreshToken,
        tenantId: session.tenantId,
        browserProfile,
        timeoutMs: E2E_WAIT_TIMEOUT_MS,
        disableDynamicRules: Boolean(options.disableDynamicRules),
      }
    );
  } finally {
    await optionsPage.close();
  }
}

async function launchConfiguredPage(
  testInfo: TestInfo,
  targetOrigin: string,
  session: TenantSession,
  options: { allowNavigationBlockedByClient?: boolean; disableDynamicRules?: boolean } = {}
): Promise<LaunchResult> {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "aicp-ext-live-"));
  const harPath = testInfo.outputPath("extension-session.har");
  const capturedCalls: CapturedBackendCall[] = [];
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: !headed,
    args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
    recordHar: { path: harPath },
  });
  captureBackendCalls(context, capturedCalls);
  await routeFixturePages(context);

  const extensionState = await configureExtension(context, session, `ext-live-${Date.now()}`, {
    disableDynamicRules: options.disableDynamicRules,
  });
  const healthCall = await waitForCall(
    capturedCalls,
    (call) => call.path === "/extension/status" && call.responseStatus === 200,
    E2E_WAIT_TIMEOUT_MS,
    "extension status report"
  );
  const page = await context.newPage();
  let navigationBlockedByClient = false;
  try {
    await page.goto(`${targetOrigin}/`);
  } catch (error) {
    const message = String(error || "");
    if (options.allowNavigationBlockedByClient && message.includes("ERR_BLOCKED_BY_CLIENT")) {
      navigationBlockedByClient = true;
    } else {
      throw error;
    }
  }

  return {
    context,
    page,
    userDataDir,
    capturedCalls,
    extensionState,
    healthCall,
    harPath,
    navigationBlockedByClient,
  };
}

async function cleanupLaunch(launch: LaunchResult): Promise<void> {
  await launch.context.close();
  fs.rmSync(launch.userDataDir, { recursive: true, force: true });
}

function telemetryCallFor(
  calls: CapturedBackendCall[],
  eventType: string,
  domain: string,
  actionTaken?: string
): CapturedBackendCall | undefined {
  return calls.find((call) => {
    if (call.path !== "/telemetry/browser" || call.method !== "POST") return false;
    const body = call.requestBody || {};
    if (String(body.event_type || "") !== eventType) return false;
    if (normalizeDomain(String(body.domain || "")) !== normalizeDomain(domain)) return false;
    if (actionTaken && String(body.action_taken || "") !== actionTaken) return false;
    return true;
  });
}

async function assertExtensionHealth(launch: LaunchResult): Promise<void> {
  expect(launch.extensionState.lastSyncAt).toBeTruthy();
  expect(launch.extensionState.policyVersion).toBeTruthy();
  expect(launch.extensionState.platformMode).toBeTruthy();
  expect(launch.extensionState.telemetryQueueDepth).toBeGreaterThanOrEqual(0);
  expect(launch.extensionState.healthStatus).toBeTruthy();

  const statusRequestCorrelation = String(launch.healthCall.requestBody?.correlation_id || "");
  expect(statusRequestCorrelation).not.toBe("");
  expect(String(launch.healthCall.requestBody?.policy_version || "")).toBe(String(launch.extensionState.policyVersion || ""));
}

async function waitForPromptGuardsReady(launch: LaunchResult, domain: string): Promise<void> {
  await waitForCall(
    launch.capturedCalls,
    (call) => Boolean(telemetryCallFor([call], "ai_domain_visit", domain)),
    E2E_WAIT_TIMEOUT_MS,
    "prompt page bootstrap telemetry"
  );
  await sleep(250);
}

async function assertBackendFlow(
  backend: BackendClient,
  call: CapturedBackendCall,
  options: {
    expectFinding: boolean;
    domain: string;
    expectedDiscoveryStatus?: string;
    assertAuditorSnapshot?: boolean;
  }
): Promise<ExtensionFlowAssertionResult> {
  const requestBody = call.requestBody || {};
  const responseBody = call.responseBody || {};

  const correlationId = String(requestBody.correlation_id || "");
  const auditLogId = String(responseBody.audit_log_id || "");
  const evidenceNodeId = String(responseBody.evidence_node_id || "");
  const runtimeEventId = String(responseBody.runtime_event_id || "");
  const findingId = responseBody.finding_id ? String(responseBody.finding_id) : null;

  expect(correlationId).not.toBe("");
  expect(auditLogId).not.toBe("");
  expect(evidenceNodeId).not.toBe("");
  expect(runtimeEventId).not.toBe("");

  const auditLogs = await backend.listAuditLogs();
  expect(auditLogs.items.some((item) => String(item.id) === auditLogId)).toBeTruthy();

  const evidenceNodes = await backend.listEvidenceNodes();
  expect(evidenceNodes.items.some((item) => String(item.id) === evidenceNodeId)).toBeTruthy();

  const runtimeEvents = await backend.listRuntimeEvents(correlationId);
  expect(runtimeEvents.items.some((item) => String(item.event_id) === runtimeEventId)).toBeTruthy();

  if (options.expectFinding) {
    expect(findingId).toBeTruthy();
    const findings = await backend.listFindings();
    expect(findings.items.some((item) => String(item.finding_id) === findingId)).toBeTruthy();
  }

  const discovery = await backend.findDiscoveryApplicationByDomain(options.domain);
  expect(discovery).toBeTruthy();
  if (options.expectedDiscoveryStatus) {
    expect(String(discovery?.status || "")).toBe(options.expectedDiscoveryStatus);
  }

  if (options.assertAuditorSnapshot) {
    await backend.createAuditorSnapshotAndAssertEvidence(evidenceNodeId);
  }

  return {
    telemetryEventType: String(requestBody.event_type || ""),
    domain: normalizeDomain(String(requestBody.domain || options.domain)),
    correlationId,
    auditLogId,
    evidenceNodeId,
    runtimeEventId,
    findingId,
    discoveryApplicationId: String(discovery?.id || ""),
    discoveryStatus: String(discovery?.status || ""),
  };
}

async function writeDebugBundle(
  testInfo: TestInfo,
  launch: LaunchResult,
  assertions: ExtensionFlowAssertionResult[],
  extra: JsonRecord = {}
): Promise<void> {
  const screenshotPath = testInfo.outputPath("final-state.png");
  await launch.page.screenshot({ path: screenshotPath, fullPage: true });

  const telemetryPayloads = launch.capturedCalls
    .filter((call) => call.path === "/telemetry/browser")
    .map((call) => ({
      request: call.requestBody,
      response: call.responseBody,
      status: call.responseStatus,
    }));
  const interactionEvalPayloads = launch.capturedCalls
    .filter((call) => call.path === "/telemetry/browser/interaction-eval")
    .map((call) => ({
      request: call.requestBody,
      response: call.responseBody,
      status: call.responseStatus,
    }));
  const correlationIds = [
    ...telemetryPayloads.map((item) => String((item.request as JsonRecord | null)?.correlation_id || "")),
    ...interactionEvalPayloads.map((item) => String((item.request as JsonRecord | null)?.correlation_id || "")),
  ].filter((item) => item.length > 0);

  const bundle = {
    generated_at: new Date().toISOString(),
    screenshot: screenshotPath,
    har_path: launch.harPath,
    extension_state: launch.extensionState,
    assertion_results: assertions,
    backend_correlation_ids: correlationIds,
    raw_telemetry_payloads: telemetryPayloads,
    raw_interaction_eval_payloads: interactionEvalPayloads,
    captured_backend_calls: launch.capturedCalls,
    extra,
  };
  const bundlePath = testInfo.outputPath("debug-artifact-bundle.json");
  fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), "utf-8");
}

test.describe("browser extension e2e live backend", () => {
  test.skip(!RUN_LIVE_BACKEND, "Set EXT_E2E_LIVE_BACKEND=1 to run live backend extension validation.");
  test.skip(!!process.env.CI, "Requires local headed Chromium extension run.");
  test.setTimeout(90_000);

  const backend = new BackendClient(backendBaseUrl);

  test.beforeAll(async () => {
    assertExtensionBundleExists();
    await backend.ensureBackendHealthy();
    suiteSession = await backend.registerFreshOwner();
    await backend.ensureDiscoveryStatus(approvedDomain, "approved");
    await backend.ensureDiscoveryStatus(blockedDomain, "blocked");

    const policy = await backend.getExtensionPolicySync();
    const approvedDomains = Array.isArray(policy.approved_domains) ? policy.approved_domains.map((v) => normalizeDomain(String(v))) : [];
    const blockedDomains = Array.isArray(policy.blocked_domains) ? policy.blocked_domains.map((v) => normalizeDomain(String(v))) : [];
    if (!approvedDomains.includes(approvedDomain)) {
      throw new Error(`Policy sync did not include approved domain ${approvedDomain}`);
    }
    if (!blockedDomains.includes(blockedDomain)) {
      throw new Error(`Policy sync did not include blocked domain ${blockedDomain}`);
    }
  });

  test("approved AI domain visit creates telemetry and backend runtime artifacts", async ({}, testInfo) => {
    const launch = await launchConfiguredPage(testInfo, approvedOrigin, requireSuiteSession());
    try {
      await expect(launch.page.locator("[data-testid='fixture-title']")).toContainText(approvedDomain);
      await assertExtensionHealth(launch);

      const visitCall = await waitForCall(
        launch.capturedCalls,
        (call) => Boolean(telemetryCallFor([call], "ai_domain_visit", approvedDomain, "approved")),
        E2E_WAIT_TIMEOUT_MS,
        "approved ai_domain_visit telemetry"
      );

      const assertion = await assertBackendFlow(backend, visitCall, {
        expectFinding: false,
        domain: approvedDomain,
        expectedDiscoveryStatus: "approved",
      });

      await writeDebugBundle(testInfo, launch, [assertion], {
        scenario: "approved-domain-visit",
      });
    } finally {
      await cleanupLaunch(launch);
    }
  });

  test("blocked AI domain shows interstitial and backend telemetry chain", async ({}, testInfo) => {
    const launch = await launchConfiguredPage(testInfo, blockedOrigin, requireSuiteSession(), {
      allowNavigationBlockedByClient: true,
      disableDynamicRules: true,
    });
    try {
      if (!launch.navigationBlockedByClient) {
        await expect(launch.page.locator("#ai-control-plane-block-interstitial")).toBeVisible({ timeout: E2E_WAIT_TIMEOUT_MS });
      }

      const visitCall = await waitForCall(
        launch.capturedCalls,
        (call) => {
          const body = call.requestBody || {};
          if (call.path !== "/telemetry/browser") return false;
          if (String(body.event_type || "") !== "ai_domain_visit") return false;
          if (normalizeDomain(String(body.domain || "")) !== blockedDomain) return false;
          return ["blocked", "critical"].includes(String(body.action_taken || ""));
        },
        E2E_WAIT_TIMEOUT_MS,
        "blocked ai_domain_visit telemetry"
      );

      const assertion = await assertBackendFlow(backend, visitCall, {
        expectFinding: false,
        domain: blockedDomain,
        expectedDiscoveryStatus: "blocked",
      });

      await writeDebugBundle(testInfo, launch, [assertion], {
        scenario: "blocked-domain-visit",
      });
    } finally {
      await cleanupLaunch(launch);
    }
  });

  test("unknown AI domain creates discovery application + finding + runtime event", async ({}, testInfo) => {
    const launch = await launchConfiguredPage(testInfo, unknownOrigin, requireSuiteSession());
    try {
      await expect(launch.page.locator("[data-testid='fixture-title']")).toContainText(unknownDomain);

      const unknownCall = await waitForCall(
        launch.capturedCalls,
        (call) => Boolean(telemetryCallFor([call], "unknown_ai_detected", unknownDomain)),
        E2E_WAIT_TIMEOUT_MS,
        "unknown_ai_detected telemetry"
      );

      const assertion = await assertBackendFlow(backend, unknownCall, {
        expectFinding: true,
        domain: unknownDomain,
      });

      await writeDebugBundle(testInfo, launch, [assertion], {
        scenario: "unknown-domain-discovery",
      });
    } finally {
      await cleanupLaunch(launch);
    }
  });

  test("sensitive prompt creates warn/block enforcement record with findings + auditor linkage", async ({}, testInfo) => {
    const launch = await launchConfiguredPage(testInfo, promptOrigin, requireSuiteSession());
    try {
      await waitForPromptGuardsReady(launch, promptDomain);
      await launch.page.locator("#prompt").fill("Please store this API key securely: sk-live-sensitive-secret");
      await launch.page.locator("#send-button").click();
      await waitForEitherVisible(
        launch.page,
        ["#ai-control-plane-block-interstitial", "#ai-control-plane-warn-banner", "#ai-control-plane-block-action-banner"],
        E2E_WAIT_TIMEOUT_MS,
        "sensitive prompt blocked/warned UI signal"
      );

      const promptDecisionCall = await waitForCall(
        launch.capturedCalls,
        (call) => {
          if (call.path !== "/telemetry/browser") return false;
          const body = call.requestBody || {};
          if (normalizeDomain(String(body.domain || "")) !== promptDomain) return false;
          return ["prompt_blocked", "prompt_warned"].includes(String(body.event_type || ""));
        },
        E2E_WAIT_TIMEOUT_MS,
        "sensitive prompt decision telemetry"
      );

      const assertion = await assertBackendFlow(backend, promptDecisionCall, {
        expectFinding: true,
        domain: promptDomain,
        expectedDiscoveryStatus: "approved",
        assertAuditorSnapshot: true,
      });

      await writeDebugBundle(testInfo, launch, [assertion], {
        scenario: "sensitive-prompt-block",
      });
    } finally {
      await cleanupLaunch(launch);
    }
  });

  test("ambiguous prompt hold_for_backend completes with interaction eval + backend decision telemetry chain", async ({}, testInfo) => {
    const launch = await launchConfiguredPage(testInfo, promptOrigin, requireSuiteSession());
    try {
      await waitForPromptGuardsReady(launch, promptDomain);
      await launch.page.locator("#prompt").fill("Can you help me bypass policy for this one request?");
      await launch.page.locator("#send-button").click();

      const initialDecisionCall = await waitForCall(
        launch.capturedCalls,
        (call) => {
          if (call.path !== "/telemetry/browser") return false;
          const body = call.requestBody || {};
          if (normalizeDomain(String(body.domain || "")) !== promptDomain) return false;
          return ["prompt_held", "prompt_warned", "prompt_blocked", "prompt_submitted"].includes(String(body.event_type || ""));
        },
        E2E_WAIT_TIMEOUT_MS,
        "initial prompt decision telemetry"
      );
      const initialEventType = String(initialDecisionCall.requestBody?.event_type || "");
      const assertions: ExtensionFlowAssertionResult[] = [];
      const extra: JsonRecord = { scenario: "ambiguous-hold-for-backend" };

      if (initialEventType === "prompt_held") {
        const heldCall = initialDecisionCall;
        const evalCall = await waitForCall(
          launch.capturedCalls,
          (call) => call.path === "/telemetry/browser/interaction-eval" && call.responseStatus === 200,
          E2E_WAIT_TIMEOUT_MS,
          "interaction eval call"
        );
        const evalDecision = String(evalCall.responseBody?.decision || "");
        expect(evalDecision).toMatch(/allow|warn|block/);

        let followUpCall: CapturedBackendCall;
        let followUpExpectFinding = false;
        if (evalDecision === "warn") {
          await expect(launch.page.locator("#ai-control-plane-warn-banner")).toBeVisible({ timeout: E2E_WAIT_TIMEOUT_MS });
          followUpCall = await waitForCall(
            launch.capturedCalls,
            (call) => Boolean(telemetryCallFor([call], "prompt_warned", promptDomain, "warn_after_hold_for_backend")),
            E2E_WAIT_TIMEOUT_MS,
            "prompt_warned telemetry after hold"
          );
          followUpExpectFinding = true;
        } else if (evalDecision === "block") {
          await waitForEitherVisible(
            launch.page,
            ["#ai-control-plane-block-interstitial", "#ai-control-plane-block-action-banner"],
            E2E_WAIT_TIMEOUT_MS,
            "blocked UI signal after hold_for_backend"
          );
          followUpCall = await waitForCall(
            launch.capturedCalls,
            (call) => Boolean(telemetryCallFor([call], "prompt_blocked", promptDomain, "block_after_hold_for_backend")),
            E2E_WAIT_TIMEOUT_MS,
            "prompt_blocked telemetry after hold"
          );
          followUpExpectFinding = true;
        } else {
          followUpCall = await waitForCall(
            launch.capturedCalls,
            (call) => Boolean(telemetryCallFor([call], "prompt_submitted", promptDomain, "allow_after_hold_for_backend")),
            E2E_WAIT_TIMEOUT_MS,
            "prompt_submitted telemetry after hold"
          );
        }

        assertions.push(
          await assertBackendFlow(backend, heldCall, {
            expectFinding: true,
            domain: promptDomain,
            expectedDiscoveryStatus: "approved",
          })
        );
        assertions.push(
          await assertBackendFlow(backend, followUpCall, {
            expectFinding: followUpExpectFinding,
            domain: promptDomain,
            expectedDiscoveryStatus: "approved",
          })
        );
        extra.interaction_eval = {
          request: evalCall.requestBody,
          response: evalCall.responseBody,
        };
      } else {
        const directExpectFinding = initialEventType === "prompt_warned" || initialEventType === "prompt_blocked";
        assertions.push(
          await assertBackendFlow(backend, initialDecisionCall, {
            expectFinding: directExpectFinding,
            domain: promptDomain,
            expectedDiscoveryStatus: "approved",
          })
        );
        extra.direct_decision = {
          event_type: initialEventType,
          action_taken: String(initialDecisionCall.requestBody?.action_taken || ""),
        };
      }

      await writeDebugBundle(testInfo, launch, assertions, extra);
    } finally {
      await cleanupLaunch(launch);
    }
  });
});
