import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { test, expect, chromium, type BrowserContext, type Page } from "@playwright/test";

type TelemetryPayload = Record<string, unknown>;
type InteractionEvalPayload = Record<string, unknown>;

const currentFilePath = fileURLToPath(import.meta.url);
const currentDir = path.dirname(currentFilePath);
const extensionPath = path.resolve(currentDir, "..", "..");
const extensionManifestVersion = JSON.parse(fs.readFileSync(path.join(extensionPath, "manifest.json"), "utf8")).version as string;
const requiredBundleFiles = [
  path.join(extensionPath, "dist", "service-worker.js"),
  path.join(extensionPath, "dist", "content-script.js"),
  path.join(extensionPath, "dist", "options.js"),
];
const backendPort = Number(process.env.EXT_E2E_BACKEND_PORT || "0");
const extensionSettings = {
  backendUrl: "",
  accessToken: "test-extension-token",
  authEmail: "extension-e2e@example.test",
  tenantId: "test-tenant-id",
  browser: "chrome",
};
const policy = {
  tenant_id: extensionSettings.tenantId,
  platform_mode: "enforce",
  policy_version: "pv-e2e-1",
  approved_domains: ["chat.openai.com", "mail.google.com"],
  blocked_domains: ["claude.ai"],
  warn_domains: [],
  critical_domains: ["claude.ai"],
  unknown_domain_behavior: "discover",
  interaction_rules: {
    input_checks_enabled: true,
    output_checks_enabled: false,
    sensitive_patterns: ["(?i)api[_\\s-]?key", "(?i)private\\s*key"],
    blocked_keywords: ["ignore previous instructions"],
    high_risk_terms: ["bypass policy", "jailbreak"],
    hold_for_backend_on_ambiguous: true,
    backend_allow_confirmation_enabled: false,
  },
};

const telemetryEvents: TelemetryPayload[] = [];
const interactionEvalRequests: InteractionEvalPayload[] = [];
const extensionStatusReports: Record<string, unknown>[] = [];
const dataTransferCheckRequests: Record<string, unknown>[] = [];
const dataTransferJustifyRequests: Record<string, unknown>[] = [];
let backendServer: http.Server | null = null;

function resetCapturedEvents(): void {
  telemetryEvents.length = 0;
  interactionEvalRequests.length = 0;
  extensionStatusReports.length = 0;
  dataTransferCheckRequests.length = 0;
  dataTransferJustifyRequests.length = 0;
}

function readBodyJson(request: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    request.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf-8");
        resolve(raw ? (JSON.parse(raw) as Record<string, unknown>) : {});
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

async function startMockBackend(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const server = http.createServer(async (request, response) => {
      try {
        const method = request.method || "GET";
        const url = request.url || "/";

        if (method === "GET" && url === "/extension/policy-sync") {
          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(JSON.stringify(policy));
          return;
        }

        if (method === "POST" && url === "/telemetry/browser") {
          const payload = await readBodyJson(request);
          telemetryEvents.push(payload);
          const eventType = String(payload.event_type || "");
          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(
            JSON.stringify({
              status: "ok",
              monitoring_signal_id: `sig_${telemetryEvents.length}`,
              audit_log_id: `audit_${telemetryEvents.length}`,
              evidence_node_id: `ev_${telemetryEvents.length}`,
              finding_id: eventType ? `find_${eventType}_${telemetryEvents.length}` : null,
              policy_version: policy.policy_version,
              platform_mode: policy.platform_mode,
            })
          );
          return;
        }

        if (method === "POST" && url === "/telemetry/browser/interaction-eval") {
          const payload = await readBodyJson(request);
          interactionEvalRequests.push(payload);
          const preview = String(payload.prompt_preview_redacted || "").toLowerCase();
          if (preview.includes("bypass policy")) {
            await sleep(1200);
            response.writeHead(200, { "Content-Type": "application/json" });
            response.end(
              JSON.stringify({
                decision: "warn",
                tier: "ambiguous",
                reason_codes: ["high_risk_term"],
                policy_version: policy.policy_version,
                platform_mode: policy.platform_mode,
                correlation_id: String(payload.correlation_id || ""),
                input_signal_types: ["jailbreak"],
                audit_log_id: `audit_eval_${interactionEvalRequests.length}`,
                evidence_node_id: `ev_eval_${interactionEvalRequests.length}`,
                finding_id: `find_eval_${interactionEvalRequests.length}`,
              })
            );
            return;
          }

          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(
            JSON.stringify({
              decision: "allow",
              tier: "clear_negative",
              reason_codes: [],
              policy_version: policy.policy_version,
              platform_mode: policy.platform_mode,
              correlation_id: String(payload.correlation_id || ""),
              input_signal_types: [],
              audit_log_id: `audit_eval_${interactionEvalRequests.length}`,
              evidence_node_id: `ev_eval_${interactionEvalRequests.length}`,
              finding_id: null,
            })
          );
          return;
        }

        if (method === "POST" && url === "/extension/status") {
          const payload = await readBodyJson(request);
          extensionStatusReports.push(payload);
          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(
            JSON.stringify({
              status: "ok",
              monitoring_signal_id: `sig_status_${extensionStatusReports.length}`,
              audit_log_id: `audit_status_${extensionStatusReports.length}`,
              evidence_node_id: `ev_status_${extensionStatusReports.length}`,
              policy_version: policy.policy_version,
              platform_mode: policy.platform_mode,
              runtime_event_id: `rt_status_${extensionStatusReports.length}`,
              finding_id: null,
            })
          );
          return;
        }

        if (method === "POST" && url === "/runtime-control/data-transfer-check") {
          const payload = await readBodyJson(request);
          dataTransferCheckRequests.push(payload);
          const copyContext = (payload.copy_context || {}) as Record<string, unknown>;
          const pasteContext = (payload.paste_context || {}) as Record<string, unknown>;
          const sourceClassification = String(copyContext.source_classification_hint || "unknown");
          const destinationDomain = String(pasteContext.destination_domain || "").toLowerCase();
          const destinationSurface = String(pasteContext.destination_surface_type || "unknown");

          let decision: "allow" | "warn" | "block" | "require_justification" = "allow";
          let reasonCode = "policy_allow";
          let explanation = "Data movement allowed by policy.";
          let recommendation = "monitor";
          let justificationRequired = false;

          if (sourceClassification === "protected" && destinationSurface === "ai_tool") {
            decision = "block";
            reasonCode = "protected_to_public_ai_block";
            explanation = "Sensitive data movement to public AI is blocked.";
            recommendation = "route_to_governance";
          } else if (
            sourceClassification === "protected"
            && (
              destinationSurface === "email"
              || destinationSurface === "slack"
              || destinationDomain.includes("mail.google.com")
              || destinationDomain.includes("slack")
            )
          ) {
            decision = "require_justification";
            reasonCode = "protected_external_requires_justification";
            explanation = "Sensitive data movement requires justification.";
            recommendation = "monitor";
            justificationRequired = true;
          }

          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(
            JSON.stringify({
              decision,
              reason_code: reasonCode,
              explanation,
              recommended_action: recommendation,
              justification_required: justificationRequired,
              audit_log_id: `audit_transfer_${dataTransferCheckRequests.length}`,
              evidence_node_id: `ev_transfer_${dataTransferCheckRequests.length}`,
              finding_id: decision === "allow" ? null : `find_transfer_${dataTransferCheckRequests.length}`,
              runtime_event_id: `rt_transfer_${dataTransferCheckRequests.length}`,
              policy_version: policy.policy_version,
              platform_mode: policy.platform_mode,
              destination_ai_system_id: null,
            })
          );
          return;
        }

        if (method === "POST" && url === "/runtime-control/data-transfer-justify") {
          const payload = await readBodyJson(request);
          dataTransferJustifyRequests.push(payload);
          const justification = String(payload.justification || "");
          const allow = justification.trim().length >= 8;
          response.writeHead(200, { "Content-Type": "application/json" });
          response.end(
            JSON.stringify({
              decision: allow ? "allow" : "block",
              reason_code: allow ? "justification_accepted" : "justification_missing_or_too_short",
              explanation: allow ? "Justification accepted." : "Justification too short.",
              recommended_action: allow ? "monitor" : "route_to_governance",
              audit_log_id: `audit_transfer_justify_${dataTransferJustifyRequests.length}`,
              evidence_node_id: `ev_transfer_justify_${dataTransferJustifyRequests.length}`,
              finding_id: allow ? `find_transfer_justify_${dataTransferJustifyRequests.length}` : null,
              runtime_event_id: `rt_transfer_justify_${dataTransferJustifyRequests.length}`,
              policy_version: policy.policy_version,
              platform_mode: policy.platform_mode,
              destination_ai_system_id: null,
              destination_app_name: null,
            })
          );
          return;
        }

        response.writeHead(404, { "Content-Type": "text/plain" });
        response.end("not found");
      } catch {
        response.writeHead(500, { "Content-Type": "text/plain" });
        response.end("internal error");
      }
    });

    backendServer = server;
    server.once("error", reject);
    server.listen(backendPort, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Mock backend did not receive a loopback port"));
        return;
      }
      extensionSettings.backendUrl = `http://127.0.0.1:${address.port}`;
      console.log(`Extension mock backend listening on 127.0.0.1:${address.port}`);
      resolve();
    });
  });
}

function assertExtensionBundleExists(): void {
  const missing = requiredBundleFiles.filter((filePath) => !fs.existsSync(filePath));
  if (missing.length) {
    throw new Error(`Extension bundle missing. Run 'npm run build' in extension first. Missing: ${missing.join(", ")}`);
  }
}

async function stopMockBackend(): Promise<void> {
  if (!backendServer) return;
  await new Promise<void>((resolve, reject) => {
    backendServer?.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
  backendServer = null;
}

async function waitFor<T>(predicate: () => T | null | undefined, timeoutMs: number): Promise<T> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = predicate();
    if (value) return value;
    await sleep(100);
  }
  throw new Error("Timed out waiting for condition");
}

async function waitForDomainVisit(domain: string, timeoutMs = 10000): Promise<void> {
  await waitFor(
    () =>
      telemetryEvents.find(
        (event) =>
          String(event.event_type) === "ai_domain_visit"
          && String(event.domain) === domain
      ),
    timeoutMs
  );
}

async function waitForExtensionConnected(domain: string, timeoutMs = 10000): Promise<void> {
  await waitFor(
    () => telemetryEvents.find((event) =>
      String(event.event_type) === "extension_connected" && String(event.domain) === domain
    ),
    timeoutMs
  );
}

function capturedEventSummary(): string {
  return JSON.stringify(telemetryEvents.map((event) => ({
    type: event.event_type,
    action: event.action_taken,
    domain: event.domain,
    correlation: event.correlation_id,
  })));
}

async function waitForTransferCheck(): Promise<void> {
  try {
    await waitFor(() => dataTransferCheckRequests[0], 10000);
  } catch {
    throw new Error(`Data-transfer check absent; events=${capturedEventSummary()}`);
  }
}

async function launchWithExtension(): Promise<{ context: BrowserContext; userDataDir: string }> {
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ai-control-plane-ext-"));
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });
  return { context, userDataDir };
}

function testAppHtml(host: string): string {
  return `
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>${host} test app</title></head>
  <body>
    <h1>AI test host: ${host}</h1>
    <textarea id="prompt" rows="5" cols="80" placeholder="Type prompt"></textarea>
    <button id="send-button" type="button">Send</button>
    <script>
      window.__hawkTestSendCount = 0;
      document.getElementById("send-button").addEventListener("click", () => {
        window.__hawkTestSendCount += 1;
      });
    </script>
  </body>
</html>
`.trim();
}

async function routeMockAiApp(context: BrowserContext, origin: string): Promise<void> {
  const host = new URL(origin).hostname;
  await context.route(`${origin}/**`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: testAppHtml(host),
    });
  });
}

async function configureExtension(context: BrowserContext): Promise<void> {
  const worker = context.serviceWorkers()[0] || (await context.waitForEvent("serviceworker"));
  await worker.evaluate(
    async ({ backendUrl, accessToken, authEmail, tenantId, browser, browserProfile, cachedPolicy }) => {
      await chrome.storage.local.set({
        backendUrl,
        accessToken,
        authEmail,
        tenantId,
        browser,
        browserProfile,
        cachedPolicy,
        lastSyncAt: new Date().toISOString(),
        dynamicRuleIds: [],
      });
      await new Promise((resolve) => chrome.runtime.sendMessage({ type: "SYNC_POLICY_NOW" }, () => resolve(null)));
      await new Promise((resolve) => chrome.runtime.sendMessage({ type: "REPORT_EXTENSION_HEALTH" }, () => resolve(null)));
    },
    {
      ...extensionSettings,
      browserProfile: "e2e-profile-a",
      cachedPolicy: policy,
    }
  );
}

async function createConfiguredPage(origin: string): Promise<{ context: BrowserContext; page: Page; userDataDir: string }> {
  const { context, userDataDir } = await launchWithExtension();
  await routeMockAiApp(context, origin);
  await configureExtension(context);
  const page = await context.newPage();
  return { context, page, userDataDir };
}

async function createConfiguredPageForOrigins(origins: string[]): Promise<{ context: BrowserContext; page: Page; userDataDir: string }> {
  const { context, userDataDir } = await launchWithExtension();
  for (const origin of origins) {
    await routeMockAiApp(context, origin);
  }
  await configureExtension(context);
  const page = await context.newPage();
  return { context, page, userDataDir };
}

async function cleanupContext(context: BrowserContext, userDataDir: string): Promise<void> {
  await context.close();
  fs.rmSync(userDataDir, { recursive: true, force: true });
}

test.describe("browser extension e2e (deterministic mock backend)", () => {
  test.skip(!!process.env.CI, "Requires headed Chromium with extension support.");

  test.beforeAll(async () => {
    assertExtensionBundleExists();
    await startMockBackend();
  });

  test.afterAll(async () => {
    await stopMockBackend();
  });

  test.beforeEach(() => {
    resetCapturedEvents();
  });

  test("approved AI domain flow emits visit telemetry", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://chat.openai.com");
    try {
      await page.goto("https://chat.openai.com/");
      await expect(page.locator("h1")).toContainText("chat.openai.com");

      await waitFor(
        () =>
          telemetryEvents.find(
            (event) =>
              String(event.event_type) === "ai_domain_visit" &&
              String(event.domain) === "chat.openai.com" &&
              String(event.action_taken) === "approved"
          ),
        10000
      );
      const visit = telemetryEvents.find((event) => String(event.event_type) === "ai_domain_visit");
      expect(String(visit?.tenant_id || "")).toBe(extensionSettings.tenantId);
      expect(String(visit?.user_email || "")).toBe(extensionSettings.authEmail);
      expect(String(visit?.policy_version || "")).toBe(policy.policy_version);
      expect(String(visit?.browser_profile || "")).toBe("e2e-profile-a");
      expect(String(visit?.correlation_id || "")).not.toBe("");
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("blocked domain shows interstitial", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://claude.ai");
    try {
      await page.goto("https://claude.ai/");
      await expect(page.locator("#ai-control-plane-block-interstitial")).toBeVisible({ timeout: 15000 });
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("unknown AI domain emits unknown_ai_detected telemetry", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://poe.com");
    try {
      await page.goto("https://poe.com/");
      await expect(page.locator("h1")).toContainText("poe.com");

      await waitFor(
        () =>
          telemetryEvents.find(
            (event) =>
              String(event.event_type) === "unknown_ai_detected" &&
              String(event.domain) === "poe.com"
          ),
        10000
      );
      const unknown = telemetryEvents.find((event) => String(event.event_type) === "unknown_ai_detected");
      expect(String(unknown?.action_taken || "")).toBe("discover");
      expect(String(unknown?.policy_version || "")).toBe(policy.policy_version);
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("sensitive prompt is blocked", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://chat.openai.com");
    try {
      await page.goto("https://chat.openai.com/");
      await page.locator("#prompt").pressSequentially("Here is our API key: sk-test-sensitive");
      await page.locator("#send-button").click();
      await expect(page.locator("#ai-control-plane-block-action-banner")).toBeVisible({ timeout: 15000 });
      let promptBlock: TelemetryPayload;
      try {
        promptBlock = await waitFor(() => telemetryEvents.find((event) =>
          String(event.event_type) === "prompt_blocked" && String(event.action_taken).includes("block")
        ), 10000);
      } catch {
        throw new Error(`Prompt block telemetry absent; events=${capturedEventSummary()}`);
      }
      expect(String(promptBlock.correlation_id || "")).not.toBe("");
      await waitFor(() => telemetryEvents.find((event) =>
        String(event.event_type) === "policy_blocked" &&
        String(event.correlation_id || "") === String(promptBlock.correlation_id)
      ), 10000);
      expect(await page.evaluate(() => (window as typeof window & { __hawkTestSendCount: number }).__hawkTestSendCount)).toBe(0);
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("Gmail Send is blocked before submission and emits both block events", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://mail.google.com");
    try {
      await page.goto("https://mail.google.com/");
      await page.locator("#prompt").fill("DEMO_API_KEY=hawk_demo_only_12345678");
      await page.locator("#send-button").click();

      await expect(page.locator("#ai-control-plane-block-action-banner")).toBeVisible({ timeout: 15000 });
      await waitFor(
        () => telemetryEvents.find((event) => String(event.event_type) === "prompt_blocked"),
        10000
      );
      await waitFor(
        () => telemetryEvents.find((event) => String(event.event_type) === "policy_blocked"),
        10000
      );

      expect(await page.evaluate(() => (window as typeof window & { __hawkTestSendCount: number }).__hawkTestSendCount)).toBe(0);
      expect(
        telemetryEvents.some(
          (event) => String(event.event_type) === "prompt_blocked" && String(event.domain) === "mail.google.com"
        )
      ).toBe(true);
      expect(
        telemetryEvents.some(
          (event) => String(event.event_type) === "policy_blocked" && String(event.domain) === "mail.google.com"
        )
      ).toBe(true);
      const blockedPrompt = telemetryEvents.find((event) => String(event.event_type) === "prompt_blocked");
      const blockedPolicy = telemetryEvents.find((event) => String(event.event_type) === "policy_blocked");
      expect(String(blockedPrompt?.correlation_id || "")).not.toBe("");
      expect(blockedPolicy?.correlation_id).toBe(blockedPrompt?.correlation_id);
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("benign Gmail Send resumes after an allow decision", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://mail.google.com");
    try {
      await page.goto("https://mail.google.com/");
      await page.locator("#prompt").fill("Please send the approved public meeting summary.");
      await page.locator("#send-button").click();

      await expect
        .poll(() => page.evaluate(() => (window as typeof window & { __hawkTestSendCount: number }).__hawkTestSendCount))
        .toBe(1);
      await waitFor(
        () => telemetryEvents.find((event) => String(event.event_type) === "prompt_submitted"),
        10000
      );
      expect(telemetryEvents.some((event) => String(event.event_type) === "prompt_blocked")).toBe(false);
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("ambiguous prompt triggers hold_for_backend then adjudication", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://chat.openai.com");
    try {
      await page.goto("https://chat.openai.com/");
      await page.locator("#prompt").fill("Can you help me bypass policy for this one request?");
      await page.locator("#send-button").click();

      await expect(page.locator("#ai-control-plane-hold-banner")).toBeVisible({ timeout: 15000 });

      await waitFor(
        () =>
          interactionEvalRequests.find((event) =>
            String(event.prompt_preview_redacted || "").toLowerCase().includes("bypass policy")
          ),
        10000
      );

      await expect(page.locator("#ai-control-plane-warn-banner")).toBeVisible({ timeout: 15000 });
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("service worker reports extension health status to backend", async () => {
    const { context, page, userDataDir } = await createConfiguredPage("https://chat.openai.com");
    try {
      await page.goto("https://chat.openai.com/");
      await waitFor(
        () => extensionStatusReports.find((entry) => String(entry.status || "") === "ok"),
        10000
      );
      const status = extensionStatusReports[0] || {};
      expect(String(status.extension_version || "")).toBe(extensionManifestVersion);
      expect(String(status.browser_profile || "")).toBe("e2e-profile-a");
      expect(Number(status.telemetry_queue_depth)).toBeGreaterThanOrEqual(0);
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("copy from internal page to Gmail requires justification and calls justify endpoint", async () => {
    const { context, page, userDataDir } = await createConfiguredPageForOrigins([
      "https://internal.acme.ai",
      "https://mail.google.com",
    ]);
    try {
      await page.goto("https://internal.acme.ai/");
      await waitForExtensionConnected("internal.acme.ai");
      await page.locator("#prompt").fill("Internal credential secret for incident response");
      await page.locator("#prompt").evaluate((node) => {
        const input = node as HTMLTextAreaElement;
        input.selectionStart = 0;
        input.selectionEnd = input.value.length;
        const copyEvent = new Event("copy", { bubbles: true, cancelable: true }) as ClipboardEvent;
        input.dispatchEvent(copyEvent);
      });
      await waitFor(
        () =>
          telemetryEvents.find(
            (event) =>
              String(event.event_type) === "clipboard_copy_detected"
              && String((event.source_context as Record<string, unknown> | undefined)?.source_domain || "") === "internal.acme.ai"
          ),
        10000
      );

      await page.goto("https://mail.google.com/");
      await waitForExtensionConnected("mail.google.com");
      await waitForDomainVisit("mail.google.com");
      await page.locator("#prompt").focus();
      await page.locator("#prompt").evaluate((node) => {
        const input = node as HTMLTextAreaElement;
        const clipboardData = new DataTransfer();
        clipboardData.setData("text/plain", "Internal credential secret for incident response");
        const pasteEvent = new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData });
        input.dispatchEvent(pasteEvent);
      });

      await waitForTransferCheck();
      await expect(page.locator("#ai-control-plane-justification-modal")).toBeVisible({ timeout: 15000 });
      await page.locator("#ai-control-plane-justification-modal input[placeholder='Submitter name']").fill("Synthetic Reviewer");
      await page.locator("#ai-control-plane-justification-modal input[placeholder='Submitter email']").fill("reviewer@example.test");
      await page.locator("#ai-control-plane-justification-modal input[placeholder='Role / job title']").fill("Reviewer");
      await page.locator("#ai-control-plane-justification-modal textarea").fill("Required for approved legal escalation workflow.");
      await page.locator("#ai-control-plane-justification-modal button", { hasText: "Submit & Continue" }).click();

      await waitFor(() => dataTransferJustifyRequests[0], 10000);
      expect(
        String(((dataTransferCheckRequests[0]["paste_context"] as Record<string, unknown>)["destination_domain"]) || "")
      ).toContain("mail.google.com");
      expect(String(dataTransferJustifyRequests[0]["justification"] || "")).toContain("legal escalation");
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });

  test("copy from internal page to ChatGPT triggers block decision", async () => {
    const { context, page, userDataDir } = await createConfiguredPageForOrigins([
      "https://internal.acme.ai",
      "https://chat.openai.com",
    ]);
    try {
      await page.goto("https://internal.acme.ai/");
      await waitForExtensionConnected("internal.acme.ai");
      await page.locator("#prompt").fill("Internal protected roadmap with secrets");
      await page.locator("#prompt").evaluate((node) => {
        const input = node as HTMLTextAreaElement;
        input.selectionStart = 0;
        input.selectionEnd = input.value.length;
        const copyEvent = new Event("copy", { bubbles: true, cancelable: true }) as ClipboardEvent;
        input.dispatchEvent(copyEvent);
      });
      await waitFor(
        () =>
          telemetryEvents.find(
            (event) =>
              String(event.event_type) === "clipboard_copy_detected"
              && String((event.source_context as Record<string, unknown> | undefined)?.source_domain || "") === "internal.acme.ai"
          ),
        10000
      );

      await page.goto("https://chat.openai.com/");
      await waitForExtensionConnected("chat.openai.com");
      await waitForDomainVisit("chat.openai.com");
      await page.locator("#prompt").focus();
      await page.locator("#prompt").evaluate((node) => {
        const input = node as HTMLTextAreaElement;
        const clipboardData = new DataTransfer();
        clipboardData.setData("text/plain", "Internal protected roadmap with secrets");
        const pasteEvent = new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData });
        input.dispatchEvent(pasteEvent);
      });

      await waitForTransferCheck();
      await expect(page.locator("#ai-control-plane-block-action-banner")).toBeVisible({ timeout: 15000 });
      const request = dataTransferCheckRequests[0];
      expect(String(((request["paste_context"] as Record<string, unknown>)["destination_surface_type"]) || "")).toBe("ai_tool");
      expect(String(((request["copy_context"] as Record<string, unknown>)["source_classification_hint"]) || "")).toBe("protected");
      await waitFor(() => telemetryEvents.find((event) => String(event.event_type) === "clipboard_paste_detected" && String(event.action_taken).includes("block")), 10000);
      expect(await page.locator("#prompt").inputValue()).toBe("");
      expect(await page.evaluate(() => (window as typeof window & { __hawkTestSendCount: number }).__hawkTestSendCount)).toBe(0);
    } finally {
      await cleanupContext(context, userDataDir);
    }
  });
});
