import { installInputGuard, type InputGuardAction } from "./interactions/input-guard";
import { installDataTransferHooks } from "./interactions/data-transfer-hooks";
import { installOutputGuard } from "./interactions/output-guard";
import { classifyDiscoveryEligibility } from "./discovery-heuristics";
import {
  classifyDomainStatus,
  getSettings,
  SUPPORTED_AI_DOMAINS,
  type BrowserAutomationAction,
  type BrowserAutomationPolicy,
  type ExtensionPolicy,
} from "./policy-sync";
import { detectAgentRuntimeProfile, type AgentRuntimeProfile } from "./agent-runtime-discovery";
import { detectMeetingAiNotetaker, detectMeetingSurface, type MeetingNotetakerDetection } from "./meeting-notetaker";
import { createAppAdapter } from "./app-adapters";
import { detectAppProfile, GENERIC_AI_APP_PROFILE, type AppDetectionConfidence, type AppProfile } from "./app-profiles";
import { buildAiAction, type BrowserAiActionType } from "./ai-action";
import { detectContentSignals } from "./content-signals";
import { ContextValidityStateMachine } from "./context-state-machine";
import { buildBrowserActionContext, type BrowserActionContext } from "./context-builder";
import { getExtensionBuildHash } from "./build-info";
import { evaluatePolicyForAction } from "./policy-evaluation-client";
import {
  clearBlockActionBanner,
  clearHoldBanner,
  clearMeetingNotetakerBanner,
  clearWarnBanner,
  clearJustificationModal,
  clearMonitoringBanner,
  showBlockActionBanner,
  showHoldBanner,
  showJustificationModal,
  showMeetingNotetakerBanner,
  showMonitoringBanner,
  showWarnBanner,
} from "./ui/banner";
import { clearBlockInterstitial, showBlockInterstitial } from "./ui/interstitial";
import { createCorrelationId, getEndpointContext } from "./telemetry";

type DomainStatus = "approved" | "blocked" | "warn" | "critical" | "unknown";
const AGENT_DISCOVERY_SCAN_DEBOUNCE_MS = 900;
const AUTOMATION_SCAN_DEBOUNCE_MS = 900;
const AUTOMATION_REEMIT_INTERVAL_MS = 30_000;
const MEETING_NOTETAKER_SCAN_DEBOUNCE_MS = 900;
const MEETING_NOTETAKER_REEMIT_INTERVAL_MS = 5 * 60_000;
const AUTOMATION_LOCK_STORAGE_KEY = "automationLockState";
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
const CONTENT_SCRIPT_SCOPED_DOMAINS = new Set(
  [...SUPPORTED_AI_DOMAINS, ...POLICY_MANAGED_DOMAINS, ...MEETING_SURFACE_DOMAINS, "app.slack.com", "localhost", "127.0.0.1"]
    .map((value) => value.replace(/^www\./, ""))
);
const AUTOMATION_MARKER_MATCHERS: Array<{ marker: string; indicator: string; confidence: number; suspectedTool?: string }> = [
  {
    marker: "started debugging this browser",
    indicator: "automation_banner_debugging_browser",
    confidence: 0.95,
    suspectedTool: "claude_in_chrome",
  },
  {
    marker: "stop claude",
    indicator: "automation_banner_stop_claude",
    confidence: 0.75,
    suspectedTool: "claude_in_chrome",
  },
  {
    marker: "tool: browser_batch",
    indicator: "automation_tool_browser_batch",
    confidence: 0.9,
    suspectedTool: "claude_in_chrome",
  },
  {
    marker: "ask before acting",
    indicator: "automation_hint_ask_before_acting",
    confidence: 0.5,
  },
  {
    marker: "claude in chrome",
    indicator: "automation_hint_claude_extension",
    confidence: 0.65,
    suspectedTool: "claude_in_chrome",
  },
];
const PURCHASE_ACTION_KEYWORDS = [
  "buy now",
  "buy",
  "purchase",
  "checkout",
  "pay now",
  "place order",
  "complete order",
  "confirm order",
  "order now",
  "book now",
  "subscribe",
  "add to cart",
];
const PURCHASE_PATH_MARKERS = [
  "/checkout",
  "/cart",
  "/payment",
  "/billing",
  "/order",
  "/purchase",
];
const ECOMMERCE_DOMAIN_HINTS = [
  "amazon.",
  "noon.com",
  "ebay.",
  "walmart.",
  "shopify.com",
  "etsy.com",
  "temu.com",
  "aliexpress.com",
];
const PAYMENT_FIELD_HINTS = [
  "card",
  "credit",
  "debit",
  "cvv",
  "cvc",
  "expiry",
  "exp",
  "iban",
  "routing",
  "account",
  "payment",
];
const FORM_SUBMIT_KEYWORDS = ["submit", "confirm", "continue", "next", "save", "apply"];
const ADMIN_ACTION_KEYWORDS = [
  "create token",
  "create api key",
  "generate key",
  "delete",
  "remove",
  "change settings",
  "update permissions",
  "invite user",
  "admin",
];
const COMMUNICATION_ACTION_KEYWORDS = [
  "send email",
  "send message",
  "post",
  "comment",
  "publish",
];
const AI_PROMPT_SUBMIT_HINTS = ["send", "submit", "ask", "prompt", "generate", "reply"];
const EXTERNAL_LINK_HINTS = ["external", "open in new tab", "open link", "visit site"];
const ADMIN_PATH_HINTS = ["/admin", "/settings", "/security", "/permissions", "/tokens", "/apikey", "/api-key"];
const CREDENTIALS_PATH_HINTS = ["/credentials", "/secrets", "/keys", "/token", "/password"];
const PAYMENT_PATH_HINTS = ["/payment", "/billing", "/checkout", "/cart", "/order"];
const AUTOMATION_STOP_COOLDOWN_MS = 8_000;
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
  "/health",
  "/api",
];
const TRUSTED_CONTROL_PLANE_TITLE_HINTS = [
  "ai control plane",
  "enterprise sign in",
  "ai command center",
  "trust center",
  "hawk ai api",
];
const TRUSTED_CONTROL_PLANE_HOSTS = ["localhost", "127.0.0.1", "::1"];
const BEST_EFFORT_MESSAGE_TYPES = new Set([
  "TELEMETRY_EVENT",
  "GET_EXTENSION_STATE",
  "CLEAR_AUTOMATION_LOCK",
  "GET_POLICY",
  "DATA_TRANSFER_CHECK",
  "DATA_TRANSFER_JUSTIFY",
]);

type BrowserAutomationContext = {
  detected: boolean;
  confidence: number;
  suspectedTool: string | null;
  indicators: string[];
};

type AutomationLockState = {
  active: boolean;
  expires_at?: string;
  confidence?: number;
  suspected_tool?: string | null;
  indicators?: string[];
  source_domain?: string | null;
  source_event_type?: string | null;
};

type BrowserActionRisk = "low" | "medium" | "high";
type AutomationSource =
  | "browser_visible"
  | "extension_marker"
  | "scripted_input"
  | "rapid_navigation"
  | "suspected_local_agent"
  | "unknown";
type DecisionBadge =
  | "Allowed Browsing"
  | "Warned Automation"
  | "Blocked Action"
  | "Scope Violation"
  | "Detected-only"
  | "Incomplete";

type ClassifiedBrowserAction = {
  action_type: BrowserAutomationAction;
  action_risk: BrowserActionRisk;
  confidence: number;
  signals: string[];
};

type BrowserAutomationDecision = {
  decision: "allow" | "warn" | "block";
  reason: string;
  decision_badge: DecisionBadge;
  action_type: BrowserAutomationAction;
  action_risk: BrowserActionRisk;
  automation_source: AutomationSource;
  scope_domain: string | null;
  current_domain: string;
  current_url: string;
  finding_type?: string;
  control_ids: string[];
};

type ExtensionIdentityContext = {
  user_id: string;
  email: string;
  machine_id: string;
  os_type: string;
  browser_type: string;
  extension_version: string;
  extension_build_hash: string;
  tab_id: string;
};

type ContextRecoveryHandle = {
  dispose: () => void;
};

const emittedAgentRuntimeFingerprints = new Set<string>();
let lastAutomationFingerprint: string | null = null;
let lastAutomationEmitAtMs = 0;
let lastMeetingNotetakerFingerprint: string | null = null;
let lastMeetingNotetakerEmitAtMs = 0;
let latestAutomationContext: BrowserAutomationContext = {
  detected: false,
  confidence: 0,
  suspectedTool: null,
  indicators: [],
};
let latestAutomationLockState: AutomationLockState | null = null;
let lastAutomationStopAttemptMs = 0;
let lastAutomationActionFingerprint = "";
let lastAutomationActionAtMs = 0;
let activeAppProfile: AppProfile = GENERIC_AI_APP_PROFILE;
let activeAppDetection: AppDetectionConfidence | null = null;
let activeAdapter: ReturnType<typeof createAppAdapter> | null = null;
let extensionIdentityContext: ExtensionIdentityContext = {
  user_id: "",
  email: "",
  machine_id: "",
  os_type: "unknown",
  browser_type: "chrome",
  extension_version: "unknown",
  extension_build_hash: "dev",
  tab_id: "unknown",
};
const contextStateMachine = new ContextValidityStateMachine("UNINITIALIZED");
const sessionId = createCorrelationId();
const sessionStartedAt = new Date().toISOString();
let contextRecoveryHandle: ContextRecoveryHandle | null = null;

function isTopFrameWindow(): boolean {
  try {
    return window.top === window;
  } catch {
    return true;
  }
}

function hasActiveExtensionRuntimeContext(): boolean {
  try {
    return Boolean(chrome?.runtime?.id);
  } catch {
    return false;
  }
}

function isExtensionContextInvalidatedError(error: unknown): boolean {
  const message = String(error instanceof Error ? error.message : error || "").toLowerCase();
  return (
    message.includes("extension context invalidated")
    || message.includes("receiving end does not exist")
    || message.includes("message channel closed")
    || message.includes("message port closed")
    || message.includes("asynchronous response")
    || message.includes("before a response was received")
    || message.includes("context invalidated")
  );
}

function normalizeDomain(raw: string): string {
  return String(raw || "").trim().toLowerCase().replace(/^www\./, "");
}

function domainMatches(candidate: string, expected: string): boolean {
  const left = normalizeDomain(candidate);
  const right = normalizeDomain(expected);
  if (!left || !right) return false;
  return left === right || left.endsWith(`.${right}`);
}

function domainInList(domain: string, values: string[]): boolean {
  return (values || []).some((item) => domainMatches(domain, String(item || "")));
}

function _extractPathname(rawUrl: string): string {
  if (!rawUrl) return "";
  try {
    return new URL(rawUrl).pathname.toLowerCase();
  } catch {
    return "";
  }
}

function _isTrustedControlPlaneSurface(domain: string, rawUrl: string, title: string): boolean {
  const normalizedDomain = normalizeDomain(domain);
  const path = _extractPathname(rawUrl);
  const normalizedTitle = String(title || "").toLowerCase();
  const isLocalControlPlaneHost = TRUSTED_CONTROL_PLANE_HOSTS.some((host) => domainMatches(normalizedDomain, host));
  const isKnownHawkHost = normalizedDomain.includes("hawk");
  const isTrustedHost = isLocalControlPlaneHost || isKnownHawkHost;
  const hasTrustedPath = TRUSTED_CONTROL_PLANE_PATH_PREFIXES.some((prefix) =>
    path === prefix || path.startsWith(`${prefix}/`)
  );
  if (isTrustedHost && hasTrustedPath) return true;
  if (!isTrustedHost) return false;
  return TRUSTED_CONTROL_PLANE_TITLE_HINTS.some((hint) => normalizedTitle.includes(hint));
}

function resolveDomainStatus(domain: string, policy: ExtensionPolicy): DomainStatus {
  return classifyDomainStatus(domain, policy);
}

function detectBrowserAutomationContext(input: {
  domain: string;
  url?: string | null;
  title?: string | null;
  bodyText?: string | null;
}): BrowserAutomationContext {
  const haystack = [input.domain, input.url || "", input.title || "", input.bodyText || ""]
    .join("\n")
    .toLowerCase();
  const indicators = new Set<string>();
  let confidence = 0;
  let suspectedTool: string | null = null;

  for (const matcher of AUTOMATION_MARKER_MATCHERS) {
    if (!haystack.includes(matcher.marker)) continue;
    indicators.add(matcher.indicator);
    confidence = Math.max(confidence, matcher.confidence);
    if (!suspectedTool && matcher.suspectedTool) {
      suspectedTool = matcher.suspectedTool;
    }
  }

  if (!suspectedTool && haystack.includes("claude")) {
    suspectedTool = "claude_in_chrome";
    indicators.add("automation_hint_claude");
    confidence = Math.max(confidence, 0.45);
  }
  if (!suspectedTool && (haystack.includes("atlas") || haystack.includes("chatgpt"))) {
    suspectedTool = "gpt_browser_agent";
    indicators.add("automation_hint_gpt_agent");
    confidence = Math.max(confidence, 0.45);
  }

  const detected = confidence >= 0.7 || indicators.has("automation_banner_debugging_browser");
  return {
    detected,
    confidence: Math.min(1, Math.max(0, confidence)),
    suspectedTool,
    indicators: [...indicators].sort(),
  };
}

function _automationContextFingerprint(context: BrowserAutomationContext, domain: string): string {
  return [
    context.detected ? "1" : "0",
    context.confidence.toFixed(3),
    context.suspectedTool || "",
    context.indicators.join(","),
    normalizeDomain(domain),
  ].join("|");
}

function _signalTypesFromAutomationContext(
  context: BrowserAutomationContext,
  scanSource: "bootstrap" | "dom_update" | "periodic",
): string[] {
  const safeIndicators = Array.isArray(context?.indicators) ? context.indicators : [];
  const safeSuspectedTool = String(context?.suspectedTool || "").trim();
  const indicators = safeIndicators.map((item) => `automation_indicator:${item}`);
  return [
    "automation_suspected",
    `automation_scan:${scanSource}`,
    ...(safeSuspectedTool ? [`suspected_tool:${safeSuspectedTool}`] : []),
    ...indicators,
  ];
}

function _isLikelyEcommerceDomain(domain: string): boolean {
  const normalized = normalizeDomain(domain);
  return ECOMMERCE_DOMAIN_HINTS.some((hint) => normalized.includes(hint));
}

function _isPurchasePath(rawUrl: string): boolean {
  const value = String(rawUrl || "").toLowerCase();
  if (!value) return false;
  return PURCHASE_PATH_MARKERS.some((marker) => value.includes(marker));
}

function _isPurchaseActionLabel(text: string): boolean {
  const normalized = String(text || "").trim().toLowerCase();
  if (!normalized) return false;
  return PURCHASE_ACTION_KEYWORDS.some((keyword) => normalized.includes(keyword));
}

function _isPurchaseActionTarget(target: HTMLElement | null): boolean {
  if (!target) return false;
  const actionNode = target.closest("button, a, [role='button'], input[type='submit']") as HTMLElement | null;
  if (!actionNode) return false;
  const signals = [
    actionNode.innerText || actionNode.textContent || "",
    actionNode.getAttribute("aria-label") || "",
    actionNode.getAttribute("title") || "",
    actionNode.getAttribute("name") || "",
    actionNode.getAttribute("value") || "",
    actionNode.getAttribute("data-testid") || "",
  ].join(" ");
  return _isPurchaseActionLabel(signals);
}

function _isPurchaseFormContext(node: HTMLElement | null): boolean {
  if (!node) return false;
  const form = node.closest("form");
  if (!form) return false;
  const formText = String(form.textContent || "").slice(0, 1200);
  return _isPurchaseActionLabel(formText) || _isPurchasePath(location.href);
}

function _collectActionSignals(target: HTMLElement | null): {
  normalizedLabel: string;
  formAction: string;
  inputType: string;
  role: string;
  href: string;
} {
  const actionNode = target?.closest("button, a, input, textarea, [role='button'], [role='link'], [role='textbox']") as HTMLElement | null;
  const inputNode = target?.closest("input, textarea") as HTMLInputElement | HTMLTextAreaElement | null;
  const form = target?.closest("form");
  const normalizedLabel = String(
    [
      actionNode?.innerText || actionNode?.textContent || "",
      actionNode?.getAttribute("aria-label") || "",
      actionNode?.getAttribute("title") || "",
      actionNode?.getAttribute("name") || "",
      actionNode?.getAttribute("value") || "",
      actionNode?.getAttribute("data-testid") || "",
      form?.getAttribute("aria-label") || "",
      form?.getAttribute("name") || "",
      form?.getAttribute("id") || "",
      target?.getAttribute("data-testid") || "",
    ].join(" ")
  ).toLowerCase();
  return {
    normalizedLabel,
    formAction: String(form?.getAttribute("action") || "").toLowerCase(),
    inputType: String(inputNode?.getAttribute("type") || "").toLowerCase(),
    role: String(actionNode?.getAttribute("role") || "").toLowerCase(),
    href: String((actionNode as HTMLAnchorElement | null)?.getAttribute?.("href") || "").toLowerCase(),
  };
}

function _matchesAnySelector(node: HTMLElement | null, selectors: string[]): boolean {
  if (!node || !Array.isArray(selectors) || selectors.length === 0) return false;
  return selectors.some((selector) => {
    const safe = String(selector || "").trim();
    if (!safe) return false;
    try {
      return Boolean(node.matches(safe) || node.closest(safe));
    } catch {
      return false;
    }
  });
}

function _isPromptInputNode(node: HTMLElement | null): boolean {
  if (!node) return false;
  const promptSelector = [
    "textarea",
    "div[contenteditable='true']",
    "[contenteditable='plaintext-only']",
    "[role='textbox']",
    "input[type='text']",
    "input:not([type])",
  ].join(", ");
  try {
    return Boolean(node.matches(promptSelector) || node.closest(promptSelector));
  } catch {
    return false;
  }
}

function _isKnownAiDomain(domain: string): boolean {
  const normalized = normalizeDomain(domain || location.hostname || "");
  return SUPPORTED_AI_DOMAINS.some((item) => domainMatches(normalized, normalizeDomain(item)));
}

function _hasPromptInputSurface(root: ParentNode = document): boolean {
  const promptSelector = [
    "textarea",
    "div[contenteditable='true']",
    "[contenteditable='plaintext-only']",
    "[role='textbox']",
    "input[type='text']",
    "input:not([type])",
  ].join(", ");
  try {
    return Boolean(root.querySelector(promptSelector));
  } catch {
    return false;
  }
}

function _isLikelyAiPromptSubmitAction(event: Event, target: HTMLElement | null): boolean {
  const domainKnownAi = _isKnownAiDomain(location.hostname);
  const detectedApp = activeAppDetection?.app_detected ? activeAppProfile : null;
  const appId = detectedApp?.app_id || GENERIC_AI_APP_PROFILE.app_id;
  const knownAiApp = (
    appId === "chatgpt"
    || appId === "claude"
    || appId === "gemini"
    || appId === "perplexity"
    || domainKnownAi
  );
  if (!knownAiApp) return false;

  const eventType = String(event.type || "").toLowerCase();
  const submitSelectors = (detectedApp?.submit_selectors || GENERIC_AI_APP_PROFILE.submit_selectors || []);
  const actionNode = target?.closest("button, [role='button'], input[type='submit']") as HTMLElement | null;
  const actionTypeAttr = String(actionNode?.getAttribute("type") || "").toLowerCase();
  const actionTag = String(actionNode?.tagName || "").toLowerCase();
  const promptForm = actionNode?.closest("form") || target?.closest("form");
  const inPromptForm = Boolean(promptForm && _hasPromptInputSurface(promptForm));
  const actionLabel = String(
    [
      actionNode?.innerText || actionNode?.textContent || "",
      actionNode?.getAttribute("aria-label") || "",
      actionNode?.getAttribute("title") || "",
      actionNode?.getAttribute("name") || "",
      actionNode?.getAttribute("value") || "",
      actionNode?.getAttribute("data-testid") || "",
    ].join(" ")
  ).toLowerCase();

  if (eventType === "submit") {
    const form = target?.closest("form");
    if (!form) return false;
    return _hasPromptInputSurface(form);
  }

  if (eventType === "click") {
    if (!actionNode) return false;
    if (_matchesAnySelector(actionNode, submitSelectors) && _hasPromptInputSurface()) return true;
    if (inPromptForm && (actionTypeAttr === "submit" || actionTag === "button")) return true;
    const composerContainer = actionNode.closest(
      "form, [role='form'], [data-testid*='composer'], [data-testid*='prompt'], [class*='composer'], [class*='prompt']",
    );
    if (composerContainer && _hasPromptInputSurface(composerContainer)) return true;
    return AI_PROMPT_SUBMIT_HINTS.some((hint) => actionLabel.includes(hint)) && _hasPromptInputSurface();
  }

  if (eventType === "keydown") {
    const keyEvent = event as KeyboardEvent;
    if (keyEvent.key !== "Enter") return false;
    return _isPromptInputNode(target);
  }

  return false;
}

function _containsAny(text: string, keywords: string[]): boolean {
  const normalized = String(text || "").toLowerCase();
  if (!normalized) return false;
  return keywords.some((keyword) => normalized.includes(keyword));
}

function _wildcardPatternToRegExp(pattern: string): RegExp | null {
  const raw = String(pattern || "").trim();
  if (!raw) return null;
  const escaped = raw.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  try {
    return new RegExp(`^${escaped}$`, "i");
  } catch {
    return null;
  }
}

function _urlMatchesAnyPattern(rawUrl: string, patterns: string[]): boolean {
  const normalizedUrl = String(rawUrl || "").trim().toLowerCase();
  if (!normalizedUrl) return false;
  for (const pattern of patterns || []) {
    const value = String(pattern || "").trim().toLowerCase();
    if (!value) continue;
    if (value.includes("*")) {
      const asRegex = _wildcardPatternToRegExp(value);
      if (asRegex && asRegex.test(normalizedUrl)) return true;
      continue;
    }
    if (normalizedUrl.includes(value)) return true;
  }
  return false;
}

function _classifyBrowserAction(event: Event, target: HTMLElement | null, domain: string): ClassifiedBrowserAction {
  const eventType = String(event.type || "").toLowerCase();
  const currentUrl = String(location.href || "").toLowerCase();
  const signals = _collectActionSignals(target);
  const combinedSignals = `${signals.normalizedLabel} ${signals.formAction} ${signals.href} ${currentUrl}`.trim();
  const actionNode = target?.closest("button, a, input[type='submit'], [role='button']") as HTMLElement | null;

  if (eventType === "scroll") {
    return { action_type: "scroll", action_risk: "low", confidence: 0.9, signals: ["event:scroll"] };
  }
  if (eventType === "change" && signals.inputType === "file") {
    return { action_type: "upload_file", action_risk: "high", confidence: 0.95, signals: ["input:type:file"] };
  }
  if (eventType === "drop") {
    return { action_type: "upload_file", action_risk: "high", confidence: 0.8, signals: ["event:drop"] };
  }
  if (eventType === "copy") {
    return { action_type: "copy_content", action_risk: "medium", confidence: 0.7, signals: ["event:copy"] };
  }
  if (eventType === "submit") {
    if (_isPurchasePath(currentUrl) || _isPurchaseActionLabel(combinedSignals)) {
      return { action_type: "checkout", action_risk: "high", confidence: 0.9, signals: ["event:submit", "purchase:checkout"] };
    }
    return { action_type: "submit_form", action_risk: "high", confidence: 0.85, signals: ["event:submit"] };
  }
  if (_containsAny(combinedSignals, PURCHASE_ACTION_KEYWORDS)) {
    if (_containsAny(combinedSignals, ["add to cart", "add-to-cart"])) {
      return { action_type: "add_to_cart", action_risk: "high", confidence: 0.95, signals: ["keyword:add_to_cart"] };
    }
    if (_containsAny(combinedSignals, ["buy now", "purchase"])) {
      return { action_type: "purchase_now", action_risk: "high", confidence: 0.95, signals: ["keyword:purchase_now"] };
    }
    if (_containsAny(combinedSignals, ["checkout", "place order", "confirm order", "complete order"])) {
      return { action_type: "checkout", action_risk: "high", confidence: 0.9, signals: ["keyword:checkout"] };
    }
    return { action_type: "payment_submit", action_risk: "high", confidence: 0.85, signals: ["keyword:payment_submit"] };
  }
  if ((eventType === "click" || eventType === "submit") && actionNode && _containsAny(combinedSignals, COMMUNICATION_ACTION_KEYWORDS)) {
    if (_containsAny(combinedSignals, ["email"])) {
      return { action_type: "send_email", action_risk: "high", confidence: 0.8, signals: ["keyword:send_email"] };
    }
    return { action_type: "send_message", action_risk: "high", confidence: 0.8, signals: ["keyword:send_message"] };
  }
  if (_containsAny(combinedSignals, ADMIN_ACTION_KEYWORDS) || _containsAny(currentUrl, ADMIN_PATH_HINTS)) {
    if (_containsAny(combinedSignals, ["create token", "create api key", "generate key"]) || _containsAny(currentUrl, ["/apikey", "/api-key", "/token"])) {
      return { action_type: "create_api_key", action_risk: "high", confidence: 0.9, signals: ["keyword:create_api_key"] };
    }
    if (_containsAny(combinedSignals, ["invite user"])) {
      return { action_type: "invite_user", action_risk: "high", confidence: 0.8, signals: ["keyword:invite_user"] };
    }
    if (_containsAny(combinedSignals, ["delete", "remove"])) {
      return { action_type: "delete_item", action_risk: "high", confidence: 0.8, signals: ["keyword:delete_item"] };
    }
    if (_containsAny(combinedSignals, ["settings", "permissions"]) || _containsAny(currentUrl, ["/settings", "/permissions"])) {
      return { action_type: "change_settings", action_risk: "high", confidence: 0.75, signals: ["keyword:change_settings"] };
    }
    return { action_type: "access_admin_console", action_risk: "high", confidence: 0.75, signals: ["path:admin_console"] };
  }
  if (_containsAny(currentUrl, PAYMENT_PATH_HINTS) || _containsAny(combinedSignals, ["payment", "billing", "card", "cvv"])) {
    return { action_type: "access_payment_page", action_risk: "high", confidence: 0.75, signals: ["path:payment"] };
  }
  if (_containsAny(currentUrl, CREDENTIALS_PATH_HINTS)) {
    return { action_type: "access_credentials_page", action_risk: "high", confidence: 0.75, signals: ["path:credentials"] };
  }
  if (_containsAny(combinedSignals, EXTERNAL_LINK_HINTS)) {
    return { action_type: "open_external_link", action_risk: "medium", confidence: 0.65, signals: ["keyword:external_link"] };
  }
  if (eventType === "input" || eventType === "change") {
    return { action_type: "form_fill", action_risk: "medium", confidence: 0.55, signals: [`event:${eventType}`] };
  }
  if (eventType === "click" || eventType === "keydown") {
    const normalizedDomain = normalizeDomain(domain);
    if (_isLikelyEcommerceDomain(normalizedDomain)) {
      return { action_type: "read_content", action_risk: "low", confidence: 0.6, signals: ["domain:ecommerce"] };
    }
    return { action_type: "navigate", action_risk: "low", confidence: 0.55, signals: [`event:${eventType}`] };
  }
  return { action_type: "read_content", action_risk: "low", confidence: 0.4, signals: ["fallback:read_content"] };
}

function _isAutomationLockActive(lock: AutomationLockState | null): boolean {
  if (!lock || !lock.active) return false;
  const expiresAt = String(lock.expires_at || "").trim();
  if (!expiresAt) return false;
  const expiresAtMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMs)) return false;
  return Date.now() < expiresAtMs;
}

function _lockConfidence(lock: AutomationLockState | null): number {
  if (!lock) return 0;
  const parsed = Number(lock.confidence);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(1, parsed));
}

function _lockIndicators(lock: AutomationLockState | null): string[] {
  if (!lock || !Array.isArray(lock.indicators)) return [];
  return Array.from(
    new Set(
      lock.indicators
        .map((item) => String(item || "").trim())
        .filter(Boolean)
    )
  );
}

function _isSensitivePaymentInput(target: HTMLElement | null): boolean {
  if (!target) return false;
  const input = target.closest("input, textarea") as HTMLInputElement | HTMLTextAreaElement | null;
  if (!input) return false;
  const signals = [
    input.getAttribute("name") || "",
    input.getAttribute("id") || "",
    input.getAttribute("autocomplete") || "",
    input.getAttribute("placeholder") || "",
    input.getAttribute("aria-label") || "",
    input.getAttribute("data-testid") || "",
  ].join(" ").toLowerCase();
  if (PAYMENT_FIELD_HINTS.some((hint) => signals.includes(hint))) return true;
  const value = String((input as HTMLInputElement).value || "").replace(/[\s-]/g, "");
  return /^[0-9]{13,19}$/.test(value);
}

function _clearPaymentInput(target: HTMLElement | null): void {
  if (!target) return;
  const input = target.closest("input, textarea") as HTMLInputElement | HTMLTextAreaElement | null;
  if (!input) return;
  if (!String((input as HTMLInputElement).value || "").trim()) return;
  (input as HTMLInputElement).value = "";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function _effectiveAutomationSource(context: BrowserAutomationContext, lock: AutomationLockState | null): AutomationSource {
  const indicatorSet = new Set([...(context.indicators || []), ..._lockIndicators(lock)]);
  if (
    indicatorSet.has("automation_banner_debugging_browser")
    || indicatorSet.has("automation_tool_browser_batch")
    || indicatorSet.has("automation_hint_claude_extension")
  ) {
    return "extension_marker";
  }
  if (context.suspectedTool || lock?.suspected_tool) {
    return "suspected_local_agent";
  }
  if (indicatorSet.size > 0) {
    return "browser_visible";
  }
  return "unknown";
}

function _domainMatchesFromPolicy(candidate: string, expected: string): boolean {
  return domainMatches(normalizeDomain(candidate), normalizeDomain(expected));
}

function _findActionOverride(policy: BrowserAutomationPolicy, domain: string): { allowed: Set<string>; blocked: Set<string> } | null {
  const normalizedDomain = normalizeDomain(domain);
  for (const item of policy.action_overrides || []) {
    const asAny = item as unknown as { domain?: string; domains?: string[] };
    const domainCandidates = Array.from(
      new Set([
        String(asAny.domain || "").trim(),
        ...(Array.isArray(asAny.domains) ? asAny.domains.map((entry) => String(entry || "").trim()) : []),
      ].filter(Boolean))
    );
    if (!domainCandidates.some((candidate) => _domainMatchesFromPolicy(normalizedDomain, candidate))) continue;
    return {
      allowed: new Set((item.allowed_actions || []).map((action) => String(action).trim()).filter(Boolean)),
      blocked: new Set((item.blocked_actions || []).map((action) => String(action).trim()).filter(Boolean)),
    };
  }
  return null;
}

function _decisionBadgeFromDecision(input: {
  decision: "allow" | "warn" | "block";
  scopeViolation: boolean;
  actionRisk: BrowserActionRisk;
  automationDetected: boolean;
}): DecisionBadge {
  if (input.scopeViolation) return "Scope Violation";
  if (input.decision === "block") return "Blocked Action";
  if (input.decision === "warn") return "Warned Automation";
  if (!input.automationDetected) return "Allowed Browsing";
  if (input.actionRisk === "low") return "Allowed Browsing";
  return "Detected-only";
}

function _normalizePolicyOutcome(
  value: unknown,
  fallback: "allow" | "warn" | "block",
): "allow" | "warn" | "block" {
  const normalized = String(value || "").trim().toLowerCase();
  if (normalized === "allow" || normalized === "warn" || normalized === "block") {
    return normalized;
  }
  return fallback;
}

function _browserAutomationUserMessage(
  decision: BrowserAutomationDecision,
  policy: ExtensionPolicy,
  domain: string,
): string {
  const normalizedDomain = normalizeDomain(domain);
  const allowlisted = (policy.browser_automation_control.scope.domains_allowlist || [])
    .some((item) => _domainMatchesFromPolicy(normalizedDomain, String(item || "")));
  const reason = String(decision.reason || "").toLowerCase();
  const actionLabel = String(decision.action_type || "action").replace(/_/g, "-");

  if (reason.includes("suspected_local_agent")) {
    return "Hawk AI detected possible browser automation from a local agent. Browsing is allowed on this site, but high-risk actions are blocked.";
  }
  if (decision.decision === "block" && allowlisted) {
    return `Hawk AI blocked this automated action. Browser automation is allowed on ${normalizedDomain || "this site"} for browsing, but ${actionLabel} is not allowed.`;
  }
  if (decision.decision === "block") {
    return "Hawk AI blocked this automated action because it is outside approved browser-automation scope.";
  }
  if (decision.decision === "warn") {
    return "Hawk AI detected browser automation and applied policy controls. Continue only with low-risk browsing actions.";
  }
  return "Hawk AI allowed this browser action under current automation policy scope.";
}

function _evaluateBrowserAutomationPolicyDecision(input: {
  policy: ExtensionPolicy;
  domain: string;
  classifiedAction: ClassifiedBrowserAction;
  automationContext: BrowserAutomationContext;
  lockState: AutomationLockState | null;
  currentUrl: string;
  hasSensitiveContentSignals: boolean;
}): BrowserAutomationDecision {
  const browserPolicy = input.policy.browser_automation_control;
  const normalizedDomain = normalizeDomain(input.domain);
  const currentUrl = String(input.currentUrl || location.href || "");
  const scope = browserPolicy.scope;
  const allowlist = new Set((scope.domains_allowlist || []).map((item) => normalizeDomain(item)).filter(Boolean));
  const blocklist = new Set((scope.domains_blocklist || []).map((item) => normalizeDomain(item)).filter(Boolean));
  const allowlistPatterns = Array.isArray(scope.url_patterns_allowlist) ? scope.url_patterns_allowlist : [];
  const blocklistPatterns = Array.isArray(scope.url_patterns_blocklist) ? scope.url_patterns_blocklist : [];
  const globalAllowedActions = new Set((browserPolicy.allowed_actions || []).map((item) => String(item).trim()).filter(Boolean));
  const globalBlockedActions = new Set((browserPolicy.blocked_actions || []).map((item) => String(item).trim()).filter(Boolean));
  const override = _findActionOverride(browserPolicy, normalizedDomain);
  const allowedActions = override ? new Set([...globalAllowedActions, ...override.allowed]) : globalAllowedActions;
  const blockedActions = override ? new Set([...globalBlockedActions, ...override.blocked]) : globalBlockedActions;

  const automationDetected = input.automationContext.detected || _isAutomationLockActive(input.lockState);
  const automationSource = _effectiveAutomationSource(input.automationContext, input.lockState);
  const confidence = Math.max(input.automationContext.confidence, _lockConfidence(input.lockState));
  const threshold = Number(browserPolicy.automation?.confidence_threshold ?? 0.6);
  const detectionRequired = Boolean(browserPolicy.automation?.detection_required ?? true);
  const treatAsAutomation = automationDetected && (!detectionRequired || confidence >= threshold);
  const domainBlocked = Array.from(blocklist).some((item) => _domainMatchesFromPolicy(normalizedDomain, item));
  const domainAllowed = Array.from(allowlist).some((item) => _domainMatchesFromPolicy(normalizedDomain, item))
    || _urlMatchesAnyPattern(currentUrl, allowlistPatterns);
  const urlBlocked = _urlMatchesAnyPattern(currentUrl, blocklistPatterns);
  const isLowRisk = input.classifiedAction.action_risk === "low";
  const actionType = String(input.classifiedAction.action_type);
  const isKnownAiDomain = _isKnownAiDomain(normalizedDomain);
  const isAiPromptSubmitAction = isKnownAiDomain && (actionType === "send_message" || actionType === "submit_form");
  const actionExplicitlyAllowed = allowedActions.has(actionType);
  const actionExplicitlyBlocked = blockedActions.has(actionType);

  const scopeDomain = String(input.lockState?.source_domain || "").trim()
    || Array.from(allowlist)[0]
    || (allowlistPatterns[0] ? `url:${allowlistPatterns[0]}` : null);
  const scopeViolation = Boolean(
    treatAsAutomation
    && scopeDomain
    && _domainMatchesFromPolicy(scopeDomain, normalizedDomain) === false
    && domainAllowed === false
    && _urlMatchesAnyPattern(currentUrl, allowlistPatterns) === false
  );
  const hasAnyAllowScope = allowlist.size > 0 || allowlistPatterns.length > 0;
  const configuredDisallowedFallback = browserPolicy.mode === "block" ? "block" : "warn";
  const configuredDecisions = browserPolicy.decisions || {};
  let decision: "allow" | "warn" | "block" = "allow";
  let reason = "allowed_browsing";
  let findingType: string | undefined;

  if (input.hasSensitiveContentSignals) {
    decision = _normalizePolicyOutcome(configuredDecisions.on_sensitive_data_or_secret, "block");
    reason = "sensitive_data_or_secret_triggered";
    findingType = "HIGH_RISK_BROWSER_AUTOMATION_ACTION";
  } else if ((domainBlocked || urlBlocked) && treatAsAutomation) {
    decision = _normalizePolicyOutcome(configuredDecisions.on_blocked_domain, "block");
    reason = "automation_on_blocked_domain";
    findingType = "AUTOMATION_ON_BLOCKED_DOMAIN";
  } else if (automationSource === "suspected_local_agent" && treatAsAutomation) {
    if (scopeViolation) {
      decision = _normalizePolicyOutcome(configuredDecisions.on_scope_violation, "block");
      reason = "browser_agent_scope_violation";
      findingType = "BROWSER_AGENT_SCOPE_VIOLATION";
    } else if (!domainAllowed && hasAnyAllowScope) {
      decision = _normalizePolicyOutcome(configuredDecisions.on_disallowed_domain, configuredDisallowedFallback);
      reason = "suspected_local_agent_non_allowlisted";
      findingType = "LOCAL_AGENT_BROWSER_AUTOMATION_SUSPECTED";
    } else if (!isLowRisk || actionExplicitlyBlocked) {
      decision = _normalizePolicyOutcome(configuredDecisions.on_blocked_action, "block");
      reason = "suspected_local_agent_high_risk";
      findingType = "LOCAL_AGENT_BROWSER_AUTOMATION_SUSPECTED";
    } else {
      decision = _normalizePolicyOutcome(configuredDecisions.on_unknown_automation_source, "warn");
      reason = "suspected_local_agent_low_risk";
      findingType = "LOCAL_AGENT_BROWSER_AUTOMATION_SUSPECTED";
    }
  } else if (scopeViolation) {
    decision = _normalizePolicyOutcome(configuredDecisions.on_scope_violation, "block");
    reason = "browser_agent_scope_violation";
    findingType = "BROWSER_AGENT_SCOPE_VIOLATION";
  } else if (!domainAllowed && treatAsAutomation && hasAnyAllowScope) {
    decision = _normalizePolicyOutcome(configuredDecisions.on_disallowed_domain, configuredDisallowedFallback);
    reason = "domain_outside_allowlist";
    findingType = "BROWSER_AUTOMATION_DETECTED";
  } else if (domainAllowed && actionExplicitlyBlocked) {
    if (isAiPromptSubmitAction && !input.hasSensitiveContentSignals) {
      decision = _normalizePolicyOutcome(configuredDecisions.on_allowed_browsing, "allow");
      reason = "ai_prompt_submit_delegated";
    } else {
      decision = _normalizePolicyOutcome(configuredDecisions.on_blocked_action, "block");
      reason = "blocked_action_on_allowlisted_domain";
      findingType = "HIGH_RISK_BROWSER_AUTOMATION_ACTION";
    }
  } else if (domainAllowed && (isLowRisk || actionExplicitlyAllowed)) {
    decision = _normalizePolicyOutcome(configuredDecisions.on_allowed_browsing, "allow");
    reason = "allowlisted_action";
  } else if (treatAsAutomation && !isLowRisk && hasAnyAllowScope) {
    decision = _normalizePolicyOutcome(configuredDecisions.on_automation_detected, configuredDisallowedFallback);
    reason = "non_low_risk_automation_on_allowlisted_domain";
    if (decision !== "allow") {
      findingType = "BROWSER_AUTOMATION_DETECTED";
    }
  } else if (treatAsAutomation) {
    decision = _normalizePolicyOutcome(configuredDecisions.on_automation_detected, configuredDisallowedFallback);
    reason = "automation_detected";
    if (decision !== "allow") {
      findingType = "BROWSER_AUTOMATION_DETECTED";
    }
  } else {
    decision = "allow";
    reason = "no_automation_confidence";
  }

  if (!browserPolicy.enabled) {
    decision = "allow";
    reason = "policy_disabled";
  }
  if (browserPolicy.mode === "monitor" && decision === "block") {
    decision = "warn";
    reason = "monitor_mode_detect_only";
  }

  const decisionBadge = _decisionBadgeFromDecision({
    decision,
    scopeViolation,
    actionRisk: input.classifiedAction.action_risk,
    automationDetected: treatAsAutomation,
  });

  return {
    decision,
    reason,
    decision_badge: decisionBadge,
    action_type: input.classifiedAction.action_type,
    action_risk: input.classifiedAction.action_risk,
    automation_source: automationSource,
    scope_domain: scopeDomain,
    current_domain: normalizedDomain,
    current_url: input.currentUrl,
    finding_type: findingType,
    control_ids: ["CTRL-BROWSER-AUTOMATION-001"],
  };
}

function attemptStopKnownBrowserAutomation(): void {
  const now = Date.now();
  if (now - lastAutomationStopAttemptMs < AUTOMATION_STOP_COOLDOWN_MS) return;
  lastAutomationStopAttemptMs = now;

  const byText = Array.from(document.querySelectorAll<HTMLElement>("button, [role='button'], a"))
    .find((node) => {
      const label = String(
        [
          node.innerText || node.textContent || "",
          node.getAttribute("aria-label") || "",
          node.getAttribute("title") || "",
        ].join(" ")
      ).trim().toLowerCase();
      return label.includes("stop claude") || label === "cancel" || label.includes("stop automation");
    });
  if (byText) {
    byText.click();
  }
}

async function loadCachedPolicy(): Promise<ExtensionPolicy | null> {
  try {
    const stored = await chrome.storage.local.get(["cachedPolicy"]);
    const policy = stored?.cachedPolicy;
    if (!policy || typeof policy !== "object") return null;
    return policy as ExtensionPolicy;
  } catch {
    return null;
  }
}

async function loadAutomationLockState(): Promise<AutomationLockState | null> {
  try {
    const stored = await chrome.storage.local.get([AUTOMATION_LOCK_STORAGE_KEY]);
    const raw = stored?.[AUTOMATION_LOCK_STORAGE_KEY];
    if (!raw || typeof raw !== "object") return null;
    const candidate = raw as AutomationLockState;
    return _isAutomationLockActive(candidate) ? candidate : null;
  } catch {
    return null;
  }
}

type RuntimeMessageOptions = {
  bestEffortNoAck?: boolean;
};

function postRuntimeMessage<T = any>(
  message: Record<string, unknown>,
  options: RuntimeMessageOptions = {},
): Promise<T> {
  return new Promise((resolve, reject) => {
    const messageType = String(message?.type || "").trim().toUpperCase();
    if (!hasActiveExtensionRuntimeContext()) {
      if (BEST_EFFORT_MESSAGE_TYPES.has(messageType)) {
        resolve({ ok: false, error: "Extension context invalidated" } as T);
        return;
      }
      reject(new Error("Extension context invalidated"));
      return;
    }
    try {
      chrome.runtime.sendMessage(message, (response: T & { ok?: boolean; error?: string }) => {
        if (chrome.runtime.lastError) {
          if (
            BEST_EFFORT_MESSAGE_TYPES.has(messageType)
            && isExtensionContextInvalidatedError(chrome.runtime.lastError.message)
          ) {
            resolve({ ok: false, error: chrome.runtime.lastError.message } as T);
            return;
          }
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (response && (response as any).ok === false) {
          const responseError = String((response as any).error || "Request failed");
          if (
            BEST_EFFORT_MESSAGE_TYPES.has(messageType)
            && isExtensionContextInvalidatedError(responseError)
          ) {
            resolve(response as T);
            return;
          }
          reject(new Error(responseError));
          return;
        }
        resolve(response);
      });
      if (options.bestEffortNoAck && BEST_EFFORT_MESSAGE_TYPES.has(messageType)) {
        resolve({ ok: true, accepted: true, best_effort_no_ack: true } as T);
      }
    } catch (error) {
      if (options.bestEffortNoAck && BEST_EFFORT_MESSAGE_TYPES.has(messageType)) {
        resolve({ ok: false, error: error instanceof Error ? error.message : String(error) } as T);
        return;
      }
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

async function sha256(value: string): Promise<string> {
  const input = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", input);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes).map((item) => item.toString(16).padStart(2, "0")).join("");
}

async function emitTelemetry(payload: Record<string, unknown>): Promise<void> {
  try {
    await postRuntimeMessage({
      type: "TELEMETRY_EVENT",
      payload: buildPilotTelemetryPayload(payload),
    }, { bestEffortNoAck: true });
  } catch (error) {
    if (isExtensionContextInvalidatedError(error)) {
      return;
    }
    throw error;
  }
}

function _uniqueStringList(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  return Array.from(
    new Set(values.map((item) => String(item || "").trim()).filter(Boolean))
  );
}

function buildPilotTelemetryPayload(
  payload: Record<string, unknown>,
  context?: {
    domain?: string;
    url?: string;
    pageTitle?: string;
    sessionId?: string;
    tabId?: string;
    identity?: ExtensionIdentityContext;
  },
): Record<string, unknown> {
  const identity = context?.identity || extensionIdentityContext;
  const resolvedDomain = normalizeDomain(context?.domain || location.hostname);
  const resolvedSessionId = String(payload.session_id || context?.sessionId || sessionId).trim();
  const resolvedTabId = String(payload.tab_id || context?.tabId || identity.tab_id || `${resolvedDomain}:${resolvedSessionId}`).trim();
  const signalTypes = _uniqueStringList([
    ..._uniqueStringList(payload.input_signal_types),
    "session_linked",
    "endpoint_linked",
    "user_linked",
    "browser_linked",
  ]);

  return {
    ...payload,
    url: payload.url || context?.url || location.href,
    page_title: payload.page_title || context?.pageTitle || document.title,
    domain: payload.domain || resolvedDomain,
    source_surface: "browser_extension",
    source_surface_detail: "content_script",
    session_id: resolvedSessionId,
    tab_id: resolvedTabId,
    user_id: payload.user_id || identity.user_id,
    user_email: payload.user_email || identity.email,
    email: payload.email || identity.email,
    machine_id: payload.machine_id || identity.machine_id,
    endpoint_id: payload.endpoint_id || identity.machine_id,
    os_type: payload.os_type || identity.os_type,
    browser: payload.browser || identity.browser_type,
    browser_type: payload.browser_type || identity.browser_type,
    extension_version: payload.extension_version || identity.extension_version,
    extension_build_hash: payload.extension_build_hash || identity.extension_build_hash || getExtensionBuildHash(),
    input_signal_types: signalTypes,
  };
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const value = String(token || "").trim();
  const segments = value.split(".");
  if (segments.length !== 3) return null;
  try {
    const decoded = atob(segments[1].replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function hydrateExtensionIdentityContext(): Promise<void> {
  try {
    const settings = await getSettings();
    const endpoint = await getEndpointContext();
    const jwtPayload = decodeJwtPayload(settings.accessToken);
    const emailFromToken = String(
      jwtPayload?.email
      || jwtPayload?.upn
      || jwtPayload?.preferred_username
      || settings.authEmail
      || ""
    ).trim();
    const userIdFromToken = String(
      jwtPayload?.user_id
      || jwtPayload?.sub
      || jwtPayload?.uid
      || emailFromToken
      || ""
    ).trim();
    extensionIdentityContext = {
      user_id: userIdFromToken || "unknown_user",
      email: emailFromToken || "unknown@unknown.local",
      machine_id: String(endpoint.endpoint_id || "unknown_machine"),
      os_type: String(endpoint.os_type || "unknown"),
      browser_type: String(settings.browser || "chrome"),
      extension_version: chrome.runtime.getManifest().version,
      extension_build_hash: getExtensionBuildHash(),
      tab_id: `${location.hostname}:${sessionId}`,
    };
  } catch {
    extensionIdentityContext = {
      ...extensionIdentityContext,
      extension_version: chrome.runtime.getManifest().version,
      extension_build_hash: getExtensionBuildHash(),
    };
  }
}

async function emitHealthTelemetry(
  eventType:
    | "extension_connected"
    | "policy_sync_success"
    | "policy_sync_failed"
    | "context_invalidated"
    | "context_recovered"
    | "backend_unreachable"
    | "telemetry_queued"
    | "extension_health_status"
    | "extension_error",
  detail: string,
  extra?: Record<string, unknown>,
): Promise<void> {
  await emitTelemetry({
    event_type: eventType,
    action_taken: detail,
    input_signal_types: [
      `context_state:${contextStateMachine.getState()}`,
      ...(extra?.input_signal_types && Array.isArray(extra.input_signal_types)
        ? extra.input_signal_types.map((item) => String(item))
        : []),
    ],
    ...extra,
  });
}

function detectAndBindAppContext(domain: string): AppDetectionConfidence {
  const detection = detectAppProfile({
    domain,
    url: location.href,
    title: document.title,
    root: document,
  });
  activeAppDetection = detection;
  activeAppProfile = detection.profile;
  activeAdapter = createAppAdapter({
    profile: activeAppProfile,
    detect: () =>
      detectAppProfile({
        domain: normalizeDomain(location.hostname),
        url: location.href,
        title: document.title,
        root: document,
      }),
  });
  contextStateMachine.markAppDetected({
    app_id: detection.profile.app_id,
    confidence: detection.confidence,
    signals: detection.signals,
  });
  const boundInputs = activeAdapter.bindInput();
  contextStateMachine.markInputBound({
    input_bindings: boundInputs.length,
    upload_bindings: activeAdapter.detectUpload().length,
    submit_bindings: activeAdapter.detectSubmit().length,
  });
  return detection;
}

function resolveInputMethodFromPromptNode(promptNode: HTMLElement | null): string {
  if (!promptNode) return "unknown";
  if (promptNode instanceof HTMLTextAreaElement) return "textarea";
  if (promptNode instanceof HTMLInputElement) return "input";
  if (promptNode.isContentEditable) return "contenteditable";
  if (String(promptNode.getAttribute("role") || "").toLowerCase() === "textbox") return "textbox";
  return "unknown";
}

function buildActionContextForCurrentPage(input: {
  actionType: BrowserAiActionType;
  promptText: string;
  policy: ExtensionPolicy;
  inputMethod: string;
}): BrowserActionContext {
  return buildBrowserActionContext({
    user_id: extensionIdentityContext.user_id,
    email: extensionIdentityContext.email,
    machine_id: extensionIdentityContext.machine_id,
    os_type: extensionIdentityContext.os_type,
    browser_type: extensionIdentityContext.browser_type,
    extension_version: extensionIdentityContext.extension_version,
    app_profile: activeAppProfile,
    domain: normalizeDomain(location.hostname),
    url: location.href,
    page_title: document.title,
    action_type: input.actionType,
    input_method: input.inputMethod,
    content_length: input.promptText.length,
    session_id: sessionId,
    session_started_at: sessionStartedAt,
    tab_id: extensionIdentityContext.tab_id,
    policy_version: input.policy.policy_version,
    platform_mode: input.policy.platform_mode,
    context_validity_state: contextStateMachine.getState(),
  });
}

async function evaluateContextAwarePolicyDecision(input: {
  policy: ExtensionPolicy;
  promptText: string;
  promptHash: string;
  redactedPreview: string;
  fileMeta: Array<Record<string, unknown>>;
  inputSignalTypes: string[];
  actionType: BrowserAiActionType;
  inputMethod: string;
  timeoutMs?: number;
}): Promise<{
  decision: "allow" | "warn" | "block" | "step_up";
  reasonCodes: string[];
  inputSignalTypes: string[];
  userMessage: string;
}> {
  const contentSignals = detectContentSignals({
    text: input.promptText,
    additionalSignals: input.inputSignalTypes,
  });
  const context = buildActionContextForCurrentPage({
    actionType: input.actionType,
    promptText: input.promptText,
    policy: input.policy,
    inputMethod: input.inputMethod,
  });
  const aiAction = buildAiAction({
    action_id: createCorrelationId(),
    user_id: extensionIdentityContext.user_id,
    machine_id: extensionIdentityContext.machine_id,
    application: activeAppProfile.name,
    action_type: input.actionType,
    input_ref: input.promptHash,
    content_signals: contentSignals.signal_types,
    controls_triggered: input.inputSignalTypes,
    context_validity: contextStateMachine.getState(),
    automation_context: {
      automation_suspected: latestAutomationContext.detected || _isAutomationLockActive(latestAutomationLockState),
      confidence: Math.max(latestAutomationContext.confidence, _lockConfidence(latestAutomationLockState)),
      indicators: Array.from(
        new Set([...latestAutomationContext.indicators, ..._lockIndicators(latestAutomationLockState)]),
      ),
    },
  });

  const result = await evaluatePolicyForAction({
    postRuntimeMessage,
    ai_action: aiAction,
    context,
    content_signals: contentSignals,
    app_profile: activeAppProfile,
    legacy_interaction_payload: {
      correlation_id: createCorrelationId(),
      prompt_hash: input.promptHash,
      raw_prompt: input.promptText,
      prompt_preview_redacted: input.redactedPreview,
      domain: normalizeDomain(location.hostname),
      url: location.href,
      page_title: document.title,
      policy_version: input.policy.policy_version,
      platform_mode: input.policy.platform_mode,
      input_signal_types: Array.from(new Set([...input.inputSignalTypes, ...contentSignals.signal_types])),
      file_meta: input.fileMeta,
      timeout_ms: input.timeoutMs,
    },
  });

  const normalizedReasonCodes = Array.from(
    new Set([
      ...result.reason_codes,
      ...String(result.reason || "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    ]),
  );
  return {
    decision: result.decision,
    reasonCodes: normalizedReasonCodes,
    inputSignalTypes: Array.from(new Set([...input.inputSignalTypes, ...result.input_signal_types])),
    userMessage: result.user_message,
  };
}

function installContextValidityWatchers(domain: string): ContextRecoveryHandle {
  let lastUrl = location.href;
  let disposed = false;
  let routeStaleEmitAt = 0;
  let recoverTimer: number | null = null;

  const markStaleAndRecover = (reason: string): void => {
    if (disposed) return;
    const now = Date.now();
    if (now - routeStaleEmitAt < 500) return;
    routeStaleEmitAt = now;
    contextStateMachine.markStale(reason, { url: location.href, domain });
    void emitHealthTelemetry("context_invalidated", reason, {
      context_validity_state: contextStateMachine.getState(),
    }).catch(() => undefined);
    contextStateMachine.markRecovering(reason, { url: location.href, domain });
    if (recoverTimer) {
      window.clearTimeout(recoverTimer);
      recoverTimer = null;
    }
    recoverTimer = window.setTimeout(() => {
      if (disposed) return;
      detectAndBindAppContext(normalizeDomain(location.hostname));
      contextStateMachine.markRecovered({ url: location.href, domain });
      void emitHealthTelemetry("context_recovered", reason, {
        context_validity_state: contextStateMachine.getState(),
      }).catch(() => undefined);
    }, 300);
  };

  const originalPushState = history.pushState.bind(history);
  const originalReplaceState = history.replaceState.bind(history);

  history.pushState = ((...args: Parameters<typeof history.pushState>) => {
    originalPushState(...args);
    if (lastUrl !== location.href) {
      lastUrl = location.href;
      markStaleAndRecover("spa_route_change");
    }
  }) as typeof history.pushState;

  history.replaceState = ((...args: Parameters<typeof history.replaceState>) => {
    originalReplaceState(...args);
    if (lastUrl !== location.href) {
      lastUrl = location.href;
      markStaleAndRecover("spa_route_replace");
    }
  }) as typeof history.replaceState;

  const popStateListener = (): void => {
    if (lastUrl !== location.href) {
      lastUrl = location.href;
      markStaleAndRecover("tab_restore_or_popstate");
    }
  };
  window.addEventListener("popstate", popStateListener, true);

  const observer = new MutationObserver((records) => {
    const changedInputTree = records.some((record) => {
      if (record.type !== "childList") return false;
      return Array.from(record.addedNodes).some((node) => {
        if (!(node instanceof HTMLElement)) return false;
        return Boolean(
          node.matches("textarea, [contenteditable='true'], [role='textbox'], input[type='file']")
          || node.querySelector("textarea, [contenteditable='true'], [role='textbox'], input[type='file']"),
        );
      });
    });
    if (changedInputTree) {
      markStaleAndRecover("input_node_replaced");
    }
  });
  observer.observe(document.documentElement || document.body, {
    subtree: true,
    childList: true,
  });

  return {
    dispose: () => {
      if (disposed) return;
      disposed = true;
      observer.disconnect();
      window.removeEventListener("popstate", popStateListener, true);
      history.pushState = originalPushState;
      history.replaceState = originalReplaceState;
      if (recoverTimer) {
        window.clearTimeout(recoverTimer);
        recoverTimer = null;
      }
    },
  };
}

function installPromptDraftObserver(policy: ExtensionPolicy, domain: string): () => void {
  let lastEmitAt = 0;
  const onInput = (event: Event): void => {
    const target = event.target as HTMLElement | null;
    if (!target) return;
    const value = activeAdapter?.extractPrompt(target) || "";
    if (!value.trim()) return;
    const now = Date.now();
    if (now - lastEmitAt < 1800) return;
    lastEmitAt = now;
    contextStateMachine.markActionObserved({
      action_type: "prompt_drafted",
      input_method: resolveInputMethodFromPromptNode(target),
    });
    void emitTelemetry({
      event_type: "prompt_drafted",
      action_taken: "draft_observed",
      input_signal_types: [
        `app_profile:${activeAppProfile.app_id}`,
        `context_state:${contextStateMachine.getState()}`,
      ],
      prompt_preview_redacted: detectContentSignals({ text: value }).redacted_snippet,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
      domain,
      url: location.href,
      page_title: document.title,
    }).catch(() => undefined);
  };

  document.addEventListener("input", onInput, true);
  return () => {
    document.removeEventListener("input", onInput, true);
  };
}

function _trimText(value: string | null | undefined, max = 12_000): string {
  return String(value || "").slice(0, max);
}

if (typeof window !== "undefined") {
  window.addEventListener("unhandledrejection", (event) => {
    if (!isExtensionContextInvalidatedError(event.reason)) return;
    contextStateMachine.markInvalid("extension_context_invalidated");
    void emitHealthTelemetry("context_invalidated", "extension_context_invalidated").catch(() => undefined);
    event.preventDefault();
  });

  window.addEventListener("error", (event) => {
    const errorLike = (event as ErrorEvent).error || (event as ErrorEvent).message;
    if (!isExtensionContextInvalidatedError(errorLike)) return;
    contextStateMachine.markInvalid("extension_context_invalidated");
    void emitHealthTelemetry("context_invalidated", "extension_context_invalidated").catch(() => undefined);
    event.preventDefault();
  });
}

function _agentRuntimeFingerprint(profile: AgentRuntimeProfile): string {
  return [
    profile.agent_id,
    profile.agent_name,
    profile.model_name || "",
    profile.runtime_provider || "",
    profile.environment,
    profile.tools.join(","),
    profile.actions.join(","),
    profile.privileges.join(","),
  ]
    .join("|")
    .toLowerCase();
}

function shouldEmitAgentRuntimeDiscovery(seen: Set<string>, fingerprint: string): boolean {
  if (seen.has(fingerprint)) return false;
  seen.add(fingerprint);
  return true;
}

function _agentRuntimeSignalTypes(profile: AgentRuntimeProfile, scanSource: string): string[] {
  const base = [
    "agent_runtime_detected",
    "domain_policy_mismatch",
    "discovery_hint:local_agent_runtime",
    `discovery_scan:${scanSource}`,
  ];
  if (profile.tools.includes("mcp.tools")) {
    base.push("mcp_tooling_detected");
  }
  return base;
}

async function detectAndEmitAgentRuntimeDiscovery(
  policy: ExtensionPolicy,
  domain: string,
  options: { scanSource: "bootstrap" | "dom_update" | "periodic" },
): Promise<void> {
  const scanSource = options.scanSource;
  const profile = detectAgentRuntimeProfile({
    domain,
    url: location.href,
    title: document.title,
    bodyText: _trimText(document.body?.innerText || document.body?.textContent || "", 20_000),
  });
  if (!profile) return;

  const fingerprint = _agentRuntimeFingerprint(profile);
  if (!shouldEmitAgentRuntimeDiscovery(emittedAgentRuntimeFingerprints, fingerprint)) return;

  await emitTelemetry({
    event_type: "agent_runtime_discovered",
    action_taken: "discover",
    input_signal_types: _agentRuntimeSignalTypes(profile, scanSource),
    policy_version: policy.policy_version,
    platform_mode: policy.platform_mode,
    agent_id: profile.agent_id,
    agent_name: profile.agent_name,
    model_name: profile.model_name,
    runtime_provider: profile.runtime_provider,
    detected_tools: profile.tools,
    detected_actions: profile.actions,
    detected_privileges: profile.privileges,
    agent_environment: profile.environment,
  });
}

function installAgentRuntimeDiscoveryMonitor(policy: ExtensionPolicy, domain: string): void {
  if (!isTopFrameWindow()) return;

  let scanTimer: number | null = null;
  const scheduleScan = (scanSource: "dom_update" | "periodic"): void => {
    if (scanTimer) {
      window.clearTimeout(scanTimer);
      scanTimer = null;
    }
    scanTimer = window.setTimeout(() => {
      void detectAndEmitAgentRuntimeDiscovery(policy, domain, { scanSource }).catch(() => undefined);
    }, AGENT_DISCOVERY_SCAN_DEBOUNCE_MS);
  };

  const observer = new MutationObserver(() => {
    scheduleScan("dom_update");
  });
  const root = document.documentElement || document.body;
  if (root) {
    observer.observe(root, {
      subtree: true,
      childList: true,
      characterData: true,
    });
  }

  const periodicId = window.setInterval(() => {
    scheduleScan("periodic");
  }, 12_000);

  window.addEventListener(
    "beforeunload",
    () => {
      observer.disconnect();
      if (scanTimer) {
        window.clearTimeout(scanTimer);
        scanTimer = null;
      }
      window.clearInterval(periodicId);
    },
    { once: true }
  );
}

function _meetingSurfaceLabel(surface: string): string {
  if (surface === "google_meet") return "Google Meet";
  if (surface === "microsoft_teams") return "Microsoft Teams";
  return "meeting";
}

function _meetingNotetakerFingerprint(domain: string, detection: MeetingNotetakerDetection): string {
  return [
    domain,
    location.pathname.slice(0, 96),
    detection.surface,
    detection.provider,
    detection.providerLabel,
  ]
    .join("|")
    .toLowerCase();
}

function _meetingNotetakerSignalTypes(detection: MeetingNotetakerDetection, scanSource: string): string[] {
  return [
    "meeting_ai_notetaker_visible",
    "ai_notetaker_policy_review",
    "external_removal_required",
    `meeting_surface:${detection.surface}`,
    `notetaker_provider:${detection.provider}`,
    `meeting_scan:${scanSource}`,
    ...detection.reasons,
  ];
}

async function emitMeetingNotetakerBlockRequest(
  policy: ExtensionPolicy,
  domain: string,
  detection: MeetingNotetakerDetection,
): Promise<void> {
  await emitTelemetry({
    event_type: "meeting_ai_notetaker_block_requested",
    action_taken: "external_removal_requested",
    severity: "high",
    input_signal_types: [
      ..._meetingNotetakerSignalTypes(detection, "user_action"),
      "user_requested_block",
      "platform_api_or_host_permission_required",
    ],
    detected_tools: [detection.providerLabel],
    detected_actions: ["meeting_notetaker_removal_requested"],
    prompt_preview_redacted: detection.matchedTextRedacted,
    policy_version: policy.policy_version,
    platform_mode: policy.platform_mode,
    meeting_surface: detection.surface,
    notetaker_provider: detection.provider,
    notetaker_label: detection.providerLabel,
    participant_visible: detection.participantVisible,
    control_mode: detection.controlMode,
  });
}

async function detectAndEmitMeetingNotetaker(
  policy: ExtensionPolicy,
  domain: string,
  options: { scanSource: "bootstrap" | "dom_update" | "periodic" },
): Promise<void> {
  const detection = detectMeetingAiNotetaker({
    hostname: domain,
    url: location.href,
    visibleText: _trimText(document.body?.innerText || document.body?.textContent || "", 60_000),
  });
  if (!detection) return;

  const fingerprint = _meetingNotetakerFingerprint(domain, detection);
  const now = Date.now();
  const fingerprintChanged = fingerprint !== lastMeetingNotetakerFingerprint;
  const canReemit = now - lastMeetingNotetakerEmitAtMs >= MEETING_NOTETAKER_REEMIT_INTERVAL_MS;
  if (!fingerprintChanged && !canReemit) return;

  lastMeetingNotetakerFingerprint = fingerprint;
  lastMeetingNotetakerEmitAtMs = now;

  await emitTelemetry({
    event_type: "meeting_ai_notetaker_detected",
    action_taken: "warn_external_removal_required",
    severity: detection.provider === "generic_ai_notetaker" ? "medium" : "high",
    input_signal_types: _meetingNotetakerSignalTypes(detection, options.scanSource),
    detected_tools: [detection.providerLabel],
    detected_actions: ["meeting_ai_notetaker_detected"],
    prompt_preview_redacted: detection.matchedTextRedacted,
    policy_version: policy.policy_version,
    platform_mode: policy.platform_mode,
    meeting_surface: detection.surface,
    notetaker_provider: detection.provider,
    notetaker_label: detection.providerLabel,
    participant_visible: detection.participantVisible,
    control_mode: detection.controlMode,
  });

  showMeetingNotetakerBanner({
    domain,
    surfaceLabel: _meetingSurfaceLabel(detection.surface),
    providerLabel: detection.providerLabel,
    reason: "Review meeting sensitivity before allowing transcription or recording.",
    onRecordBlockRequest: () => emitMeetingNotetakerBlockRequest(policy, domain, detection),
  });
}

function installMeetingNotetakerMonitor(policy: ExtensionPolicy, domain: string): void {
  if (!isTopFrameWindow()) return;

  let scanTimer: number | null = null;
  const scheduleScan = (scanSource: "dom_update" | "periodic"): void => {
    if (scanTimer) {
      window.clearTimeout(scanTimer);
      scanTimer = null;
    }
    scanTimer = window.setTimeout(() => {
      void detectAndEmitMeetingNotetaker(policy, domain, { scanSource }).catch(() => undefined);
    }, MEETING_NOTETAKER_SCAN_DEBOUNCE_MS);
  };

  const observer = new MutationObserver(() => {
    scheduleScan("dom_update");
  });
  const root = document.documentElement || document.body;
  if (root) {
    observer.observe(root, {
      subtree: true,
      childList: true,
      characterData: true,
    });
  }

  const periodicId = window.setInterval(() => {
    scheduleScan("periodic");
  }, 15_000);

  window.addEventListener(
    "beforeunload",
    () => {
      observer.disconnect();
      if (scanTimer) {
        window.clearTimeout(scanTimer);
        scanTimer = null;
      }
      window.clearInterval(periodicId);
      clearMeetingNotetakerBanner();
    },
    { once: true },
  );
}

async function detectAndEmitBrowserAutomation(
  policy: ExtensionPolicy,
  domain: string,
  options: { scanSource: "bootstrap" | "dom_update" | "periodic" },
): Promise<void> {
  const context = detectBrowserAutomationContext({
    domain,
    url: location.href,
    title: document.title,
    bodyText: _trimText(document.body?.innerText || document.body?.textContent || "", 16_000),
  });
  latestAutomationContext = context;
  if (!context.detected) return;

  const fingerprint = _automationContextFingerprint(context, domain);
  const now = Date.now();
  const fingerprintChanged = fingerprint !== lastAutomationFingerprint;
  const canReemit = now - lastAutomationEmitAtMs >= AUTOMATION_REEMIT_INTERVAL_MS;
  if (!fingerprintChanged && !canReemit) return;

  lastAutomationFingerprint = fingerprint;
  lastAutomationEmitAtMs = now;

  await emitTelemetry({
    event_type: "browser_automation_detected",
    action_taken: policy.platform_mode === "enforce" ? "warn_and_restrict" : "observe",
    input_signal_types: _signalTypesFromAutomationContext(context, options.scanSource),
    policy_version: policy.policy_version,
    platform_mode: policy.platform_mode,
    automation_suspected: true,
    automation_confidence: context.confidence,
    suspected_tool: context.suspectedTool,
    automation_indicators: context.indicators,
  });
}

function installBrowserAutomationMonitor(policy: ExtensionPolicy, domain: string): void {
  if (!isTopFrameWindow()) return;

  let scanTimer: number | null = null;
  const scheduleScan = (scanSource: "dom_update" | "periodic"): void => {
    if (scanTimer) {
      window.clearTimeout(scanTimer);
      scanTimer = null;
    }
    scanTimer = window.setTimeout(() => {
      void detectAndEmitBrowserAutomation(policy, domain, { scanSource }).catch(() => undefined);
    }, AUTOMATION_SCAN_DEBOUNCE_MS);
  };

  const observer = new MutationObserver(() => {
    scheduleScan("dom_update");
  });
  const root = document.documentElement || document.body;
  if (root) {
    observer.observe(root, {
      subtree: true,
      childList: true,
      characterData: true,
    });
  }

  const periodicId = window.setInterval(() => {
    scheduleScan("periodic");
  }, 12_000);

  window.addEventListener(
    "beforeunload",
    () => {
      observer.disconnect();
      if (scanTimer) {
        window.clearTimeout(scanTimer);
        scanTimer = null;
      }
      window.clearInterval(periodicId);
    },
    { once: true }
  );
}

function installAutomationPurchaseGuard(policy: ExtensionPolicy, domain: string): void {
  if (!isTopFrameWindow()) return;
  if (_isTrustedControlPlaneSurface(domain, location.href, document.title)) {
    clearBlockActionBanner();
    return;
  }

  void loadAutomationLockState().then((lock) => {
    latestAutomationLockState = lock;
  }).catch(() => undefined);
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== "local") return;
    if (!(AUTOMATION_LOCK_STORAGE_KEY in changes)) return;
    const next = changes[AUTOMATION_LOCK_STORAGE_KEY]?.newValue;
    if (!next || typeof next !== "object") {
      latestAutomationLockState = null;
      return;
    }
    latestAutomationLockState = _isAutomationLockActive(next as AutomationLockState)
      ? (next as AutomationLockState)
      : null;
  });

  const maybeBlockAction = (event: Event, target: HTMLElement | null): void => {
    if (_isTrustedControlPlaneSurface(domain, location.href, document.title)) {
      clearBlockActionBanner();
      return;
    }
    const lockActive = _isAutomationLockActive(latestAutomationLockState);
    const eventTrusted = (event as Event & { isTrusted?: boolean }).isTrusted === true;
    const automationDetected = !eventTrusted && (latestAutomationContext.detected || lockActive);
    const classified = _classifyBrowserAction(event, target, domain);
    const isKnownAiPromptDomain = _isKnownAiDomain(domain);
    const delegatedPromptSubmit = _isLikelyAiPromptSubmitAction(event, target)
      || (
        isKnownAiPromptDomain
        && (classified.action_type === "send_message" || classified.action_type === "submit_form")
      );
    if (delegatedPromptSubmit) {
      const delegatedSignals = Array.from(
        new Set([
          ..._signalTypesFromAutomationContext(latestAutomationContext, "periodic"),
          ...classified.signals.map((item) => `action_signal:${item}`),
          "delegated_to_prompt_guard",
          `action_type:${classified.action_type}`,
        ]),
      );
      if (automationDetected || lockActive) {
        void emitTelemetry({
          event_type: "browser_automation_action",
          action_taken: "allow:delegated_prompt_submission",
          input_signal_types: delegatedSignals,
          prompt_preview_redacted: "Prompt submit delegated to content-aware prompt guard.",
          policy_version: policy.policy_version,
          platform_mode: policy.platform_mode,
          action_type: classified.action_type,
          action_risk: classified.action_risk,
          decision_badge: "Allowed Browsing",
          reason: "delegated_to_prompt_guard",
          automation_suspected: automationDetected,
          automation_confidence: Math.max(latestAutomationContext.confidence, _lockConfidence(latestAutomationLockState)),
          automation_source: _effectiveAutomationSource(latestAutomationContext, latestAutomationLockState),
          suspected_tool: latestAutomationContext.suspectedTool || latestAutomationLockState?.suspected_tool || null,
          automation_indicators: Array.from(new Set([...latestAutomationContext.indicators, ..._lockIndicators(latestAutomationLockState)])),
          scope_domain: normalizeDomain(domain),
          current_domain: normalizeDomain(location.hostname),
          current_url: location.href,
          severity: "low",
        }).catch(() => undefined);
      }
      return;
    }

    const paymentInputContext = _isSensitivePaymentInput(target);
    const hasSensitiveSignal = paymentInputContext || classified.action_type === "payment_submit";
    if (!automationDetected) {
      return;
    }

    const decision = _evaluateBrowserAutomationPolicyDecision({
      policy,
      domain,
      classifiedAction: classified,
      automationContext: latestAutomationContext,
      lockState: latestAutomationLockState,
      currentUrl: location.href,
      hasSensitiveContentSignals: hasSensitiveSignal,
    });

    const fingerprint = [
      decision.decision,
      decision.action_type,
      decision.current_domain,
      decision.current_url,
      decision.reason,
      `${Math.round(Math.max(latestAutomationContext.confidence, _lockConfidence(latestAutomationLockState)) * 100)}`,
    ].join("|");
    const now = Date.now();
    if (fingerprint === lastAutomationActionFingerprint && now - lastAutomationActionAtMs < 800) {
      return;
    }
    lastAutomationActionFingerprint = fingerprint;
    lastAutomationActionAtMs = now;

    const uniqueIndicators = Array.from(
      new Set([
        ...latestAutomationContext.indicators,
        ..._lockIndicators(latestAutomationLockState),
      ])
    );
    const signalTypes = Array.from(
      new Set([
        ..._signalTypesFromAutomationContext(latestAutomationContext, "periodic"),
        ..._lockIndicators(latestAutomationLockState).map((item) => `automation_lock_indicator:${item}`),
        ...(lockActive ? ["automation_lock_active"] : []),
        ...classified.signals.map((item) => `action_signal:${item}`),
        `action_type:${decision.action_type}`,
        `action_risk:${decision.action_risk}`,
        `decision_badge:${decision.decision_badge.replace(/\s+/g, "_").toLowerCase()}`,
        `automation_source:${decision.automation_source}`,
        `reason:${decision.reason}`,
        ...(decision.finding_type ? [`finding_type:${decision.finding_type.toLowerCase()}`] : []),
      ])
    );
    const reasonText = _browserAutomationUserMessage(decision, policy, domain);
    const telemetryEventType = decision.decision === "block" ? "browser_automation_blocked" : "browser_automation_action";
    const telemetryPayload = {
      event_type: telemetryEventType,
      action_taken: `${decision.decision}:${decision.reason}`,
      input_signal_types: signalTypes,
      prompt_preview_redacted: reasonText,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
      action_type: decision.action_type,
      action_risk: decision.action_risk,
      decision_badge: decision.decision_badge,
      reason: decision.reason,
      automation_suspected: automationDetected,
      automation_confidence: Math.max(latestAutomationContext.confidence, _lockConfidence(latestAutomationLockState)),
      automation_source: decision.automation_source,
      suspected_tool: latestAutomationContext.suspectedTool || latestAutomationLockState?.suspected_tool || null,
      automation_indicators: uniqueIndicators,
      scope_domain: decision.scope_domain,
      current_domain: decision.current_domain,
      current_url: decision.current_url,
      severity: decision.decision === "block" ? "critical" : (decision.decision === "warn" ? "high" : "low"),
    };

    if (decision.decision === "block" && policy.platform_mode === "enforce") {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      if (paymentInputContext || decision.action_type === "payment_submit") {
        _clearPaymentInput(target);
      }
      attemptStopKnownBrowserAutomation();
      showNonBlockingBlockedActionNotice(policy, domain, reasonText);
      void emitTelemetry(telemetryPayload).catch(() => undefined);
      return;
    }

    if (decision.decision === "warn") {
      clearBlockInterstitial();
      void showWarnBanner({
        domain,
        reasons: [decision.reason],
        recommendation: reasonText,
        canContinue: true,
      }).catch(() => undefined);
    }
    void emitTelemetry(telemetryPayload).catch(() => undefined);
  };

  const clickListener = (event: MouseEvent): void => {
    maybeBlockAction(event, event.target as HTMLElement | null);
  };
  const submitListener = (event: Event): void => {
    const form = event.target as HTMLFormElement | null;
    maybeBlockAction(event, form as HTMLElement | null);
  };
  const changeListener = (event: Event): void => {
    maybeBlockAction(event, event.target as HTMLElement | null);
  };
  const dropListener = (event: DragEvent): void => {
    maybeBlockAction(event, event.target as HTMLElement | null);
  };

  document.addEventListener("click", clickListener, true);
  document.addEventListener("submit", submitListener, true);
  document.addEventListener("change", changeListener, true);
  document.addEventListener("drop", dropListener, true);

  window.addEventListener(
    "beforeunload",
    () => {
      document.removeEventListener("click", clickListener, true);
      document.removeEventListener("submit", submitListener, true);
      document.removeEventListener("change", changeListener, true);
      document.removeEventListener("drop", dropListener, true);
    },
    { once: true }
  );
}

function enforceBlockedDomain(policy: ExtensionPolicy, domain: string, status: DomainStatus, reason: string): void {
  if (isActionScopedBlockReason(reason)) {
    showNonBlockingBlockedActionNotice(policy, domain, reason);
    return;
  }
  showBlockInterstitial({
    domain,
    reason,
    policyVersion: policy.policy_version,
    onRequestReview: () => {
      void emitTelemetry({
        event_type: "prompt_blocked",
        action_taken: "request_review",
        input_signal_types: ["domain_policy_mismatch"],
        prompt_preview_redacted: "",
      });
      void postRuntimeMessage({ type: "GET_EXTENSION_STATE" }).catch(() => undefined);
    },
  });
}

function isActionScopedBlockReason(reason: string): boolean {
  const value = String(reason || "").toLowerCase();
  return (
    value.includes("file upload")
    || value.includes("clipboard")
    || value.includes("copy/paste")
    || value.includes("paste blocked")
    || value.includes("data transfer")
    || value.includes("transfer blocked")
  );
}

function toUserFacingPolicyMessage(reason: string): string {
  const normalized = String(reason || "").toLowerCase();
  if (!normalized) {
    return "This action was blocked by company policy.";
  }
  if (
    normalized.includes("api key")
    || normalized.includes("secret")
    || normalized.includes("private key")
    || normalized.includes("token")
    || normalized.includes("password")
  ) {
    return "This looks like a secret or credential. Company policy blocks sharing secrets with public AI tools.";
  }
  if (normalized.includes("prompt_injection") || normalized.includes("jailbreak") || normalized.includes("ignore")) {
    return "This prompt looks like a policy bypass/jailbreak attempt and is blocked.";
  }
  if (normalized.includes("sensitive") || normalized.includes("pii") || normalized.includes("emirates")) {
    return "This content appears sensitive and cannot be shared with this AI tool.";
  }
  if (normalized.includes("upload")) {
    return "This file upload is restricted by policy for this destination.";
  }
  if (normalized.includes("purchase") || normalized.includes("payment") || normalized.includes("checkout")) {
    return "Automated purchase/payment actions are blocked for this session.";
  }
  return reason;
}

function showNonBlockingBlockedActionNotice(policy: ExtensionPolicy, domain: string, reason: string): void {
  clearBlockInterstitial();
  clearSelectedFiles();
  const userFacing = toUserFacingPolicyMessage(reason);
  showBlockActionBanner({
    domain,
    reason: `${userFacing} File/text action was removed and you can continue using the application.`,
    policyVersion: policy.policy_version,
    onRequestReview: () => {
      void emitTelemetry({
        event_type: "data_transfer_blocked",
        action_taken: "request_review",
        input_signal_types: ["data_transfer_blocked"],
        prompt_preview_redacted: "",
      });
      void postRuntimeMessage({ type: "GET_EXTENSION_STATE" }).catch(() => undefined);
    },
  });
}

function clearPromptInputs(): void {
  const editableSelectors = [
    "textarea",
    "input[type='text']",
    "input:not([type])",
    "[contenteditable='true']",
    "[contenteditable='plaintext-only']",
    "[role='textbox']",
  ].join(", ");

  const clearTarget = (target: HTMLElement | null): boolean => {
    if (!target) return false;
    if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
      if (!String(target.value || "").trim()) return false;
      target.value = "";
      target.dispatchEvent(new Event("input", { bubbles: true }));
      target.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    }
    if (target.isContentEditable) {
      const existing = String(target.innerText || target.textContent || "").trim();
      if (!existing) return false;
      target.textContent = "";
      target.dispatchEvent(new Event("input", { bubbles: true }));
      target.dispatchEvent(new Event("change", { bubbles: true }));
      return true;
    }
    return false;
  };

  const active = document.activeElement as HTMLElement | null;
  const activeTarget = active?.matches(editableSelectors) ? active : active?.closest<HTMLElement>(editableSelectors) || null;
  if (clearTarget(activeTarget)) return;

  const candidates = Array.from(document.querySelectorAll<HTMLElement>(editableSelectors)).filter((target) => {
    if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
      return Boolean(String(target.value || "").trim());
    }
    return target.isContentEditable && Boolean(String(target.innerText || target.textContent || "").trim());
  });
  if (!candidates.length) return;

  const best = candidates
    .slice()
    .sort((left, right) => {
      const leftSize = left instanceof HTMLTextAreaElement || left instanceof HTMLInputElement
        ? String(left.value || "").length
        : String(left.innerText || left.textContent || "").length;
      const rightSize = right instanceof HTMLTextAreaElement || right instanceof HTMLInputElement
        ? String(right.value || "").length
        : String(right.innerText || right.textContent || "").length;
      return rightSize - leftSize;
    })[0];
  clearTarget(best);
}

function clearSelectedFiles(): void {
  const fileInputs = Array.from(document.querySelectorAll<HTMLInputElement>("input[type='file']"));
  for (const input of fileInputs) {
    if (!input.files || input.files.length === 0) continue;
    try {
      input.value = "";
    } catch {
      continue;
    }
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

function showNonBlockingPromptBlockNotice(policy: ExtensionPolicy, domain: string, reason: string): void {
  clearBlockInterstitial();
  clearPromptInputs();
  const userFacing = toUserFacingPolicyMessage(reason);
  showBlockActionBanner({
    domain,
    reason: `${userFacing} Prompt was removed and you can continue using the application.`,
    policyVersion: policy.policy_version,
    onRequestReview: () => {
      void emitTelemetry({
        event_type: "prompt_blocked",
        action_taken: "request_review",
        input_signal_types: ["prompt_blocked_action_scoped"],
        prompt_preview_redacted: "",
      });
      void postRuntimeMessage({ type: "GET_EXTENSION_STATE" }).catch(() => undefined);
    },
  });
}

function isVerificationFailureOnlyBlock(reasons: string[]): boolean {
  const normalized = reasons
    .map((item) => String(item || "").trim().toLowerCase())
    .filter(Boolean);
  if (!normalized.length) return false;

  const failureMarkers = [
    "fail_secure",
    "fail-secure",
    "fail secure",
    "verification_failed",
    "verification failed",
    "prompt verification failed",
    "enforcement_failure",
    "enforcement failure",
    "backend_unavailable",
    "gateway_enforcement_failure",
    "gateway unavailable",
    "backend timeout",
    "backend_timeout",
    "routing_failure",
    "control_plane_unavailable",
    "browser_enforcement_failed",
  ];

  const explicitRiskMarkers = [
    "sensitive_data_pattern",
    "sensitive_data_detected",
    "prompt_injection",
    "prompt_decomposition",
    "jailbreak",
    "blocked_keyword_match",
    "domain_blocked",
    "uae_sensitive",
    "prompt_risk_forced_block",
    "tool_misuse",
    "exfiltration",
  ];

  const hasFailure = normalized.some((reason) => failureMarkers.some((marker) => reason.includes(marker)));
  if (!hasFailure) return false;
  const hasExplicitRisk = normalized.some((reason) => explicitRiskMarkers.some((marker) => reason.includes(marker)));
  return !hasExplicitRisk;
}

function shouldFailClosedOnBackendVerificationFailure(policy: ExtensionPolicy): boolean {
  return String(policy.platform_mode || "").trim().toLowerCase() === "enforce";
}

function isDetachedSubmissionError(error: unknown): boolean {
  const message = String(error instanceof Error ? error.message : error || "").toLowerCase();
  return message.includes("form") && message.includes("not connected");
}

function safelyResumeSubmission(action: InputGuardAction, domain: string): void {
  try {
    action.resumeSubmission();
  } catch (error) {
    if (!isDetachedSubmissionError(error)) {
      throw error;
    }
    void emitHealthTelemetry("extension_health_status", "submission_resume_failed", {
      status: "submission_resume_failed",
      last_error: "form_not_connected",
    }).catch(() => undefined);
    try {
      showMonitoringBanner({
        domain,
        message: "The page changed before the extension could submit. Please press Send again; monitoring remains active.",
      });
    } catch {
      // Banner rendering must never break the prompt/event path. Detached pages
      // and extension-context reloads are already reported through telemetry.
    }
  }
}

function installBootstrapGuard(): () => void {
  const isEditable = (node: HTMLElement | null): boolean =>
    !!node && !!node.closest("textarea, [contenteditable='true'], [contenteditable='plaintext-only'], [role='textbox']");

  const isSubmitLike = (node: HTMLElement | null): boolean => {
    if (!node) return false;
    const button = node.closest("button, [role='button']") as HTMLElement | null;
    if (!button) return false;
    const text = String(
      [
        button.innerText || button.textContent || "",
        button.getAttribute("aria-label") || "",
        button.getAttribute("data-testid") || "",
        button.getAttribute("name") || "",
        button.getAttribute("id") || "",
      ].join(" ")
    ).toLowerCase();
    return (
      button.getAttribute("type") === "submit"
      || text.includes("send")
      || text.includes("submit")
      || text.includes("prompt")
      || text.includes("message")
    );
  };

  const prevent = (event: Event): void => {
    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();
    showHoldBanner("Applying security policy…");
  };

  const clickListener = (event: MouseEvent): void => {
    const target = event.target as HTMLElement | null;
    if (isSubmitLike(target)) {
      prevent(event);
    }
  };

  const keydownListener = (event: KeyboardEvent): void => {
    const target = event.target as HTMLElement | null;
    if (event.key === "Enter" && !event.shiftKey && isEditable(target)) {
      prevent(event);
    }
  };

  const submitListener = (event: Event): void => {
    const form = event.target as HTMLFormElement | null;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.querySelector("textarea, [contenteditable='true'], [contenteditable='plaintext-only'], [role='textbox']")) {
      prevent(event);
    }
  };

  document.addEventListener("click", clickListener, true);
  document.addEventListener("keydown", keydownListener, true);
  document.addEventListener("submit", submitListener, true);

  return () => {
    document.removeEventListener("click", clickListener, true);
    document.removeEventListener("keydown", keydownListener, true);
    document.removeEventListener("submit", submitListener, true);
  };
}

async function handleDecision(policy: ExtensionPolicy, domain: string, action: InputGuardAction): Promise<void> {
  if (action.fileMeta.length) {
    await emitTelemetry({
      event_type: "file_upload_detected",
      action_taken: "inspect_on_submit",
      input_signal_types: action.inputSignalTypes,
      file_meta: action.fileMeta,
      prompt_preview_redacted: action.redactedPreview,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
    });
  }

  if (action.decision === "allow") {
    const backendAllowConfirmationEnabled =
      policy.platform_mode === "enforce"
      && Boolean(policy.interaction_rules.backend_allow_confirmation_enabled);
    if (backendAllowConfirmationEnabled) {
      const backendCorrelationId = createCorrelationId();
      const promptHash = await sha256(action.promptText);
      const inputMethod = resolveInputMethodFromPromptNode(document.activeElement as HTMLElement | null);
      try {
        contextStateMachine.markActionObserved({
          phase: "pre_submit",
          action_type: "prompt_submitted",
          input_method: inputMethod,
        });
        const evaluation = await evaluateContextAwarePolicyDecision({
          policy,
          promptText: action.promptText,
          promptHash,
          redactedPreview: action.redactedPreview,
          fileMeta: action.fileMeta,
          inputSignalTypes: action.inputSignalTypes,
          actionType: "prompt_submitted",
          inputMethod,
          timeoutMs: 2500,
        });

        if (evaluation.decision === "allow") {
          await emitTelemetry({
            event_type: "prompt_submitted",
            action_taken: "allow_after_backend_confirmation",
            input_signal_types: evaluation.inputSignalTypes,
            prompt_preview_redacted: action.redactedPreview,
            file_meta: action.fileMeta,
            correlation_id: backendCorrelationId,
          });
          await emitTelemetry({
            event_type: "ai_app_opened",
            action_taken: activeAppProfile.app_id,
            input_signal_types: [
              `app_profile:${activeAppProfile.app_id}`,
              `context_state:${contextStateMachine.getState()}`,
            ],
          });
          safelyResumeSubmission(action, domain);
          return;
        }

        if (evaluation.decision === "warn" || evaluation.decision === "step_up") {
          await emitTelemetry({
            event_type: "prompt_warned",
            action_taken: evaluation.decision === "step_up"
              ? "step_up_after_backend_confirmation"
              : "warn_after_backend_confirmation",
            input_signal_types: evaluation.inputSignalTypes,
            prompt_preview_redacted: action.redactedPreview,
            file_meta: action.fileMeta,
            correlation_id: backendCorrelationId,
          });
          await emitTelemetry({
            event_type: "policy_warned",
            action_taken: evaluation.reasonCodes.join(",") || "policy_warned",
            input_signal_types: evaluation.inputSignalTypes,
            prompt_preview_redacted: action.redactedPreview,
            file_meta: action.fileMeta,
            correlation_id: backendCorrelationId,
          });
          const proceed = await showWarnBanner({
            domain,
            reasons: evaluation.reasonCodes.length ? evaluation.reasonCodes : ["policy_warned"],
            recommendation: evaluation.userMessage || "Backend review flagged this interaction.",
            canContinue: evaluation.decision !== "step_up",
          });
          if (proceed === "continue") {
            safelyResumeSubmission(action, domain);
          }
          return;
        }

        if (isVerificationFailureOnlyBlock(evaluation.reasonCodes)) {
          if (shouldFailClosedOnBackendVerificationFailure(policy)) {
            await emitTelemetry({
              event_type: "prompt_blocked",
              action_taken: "backend_verification_failed_block",
              input_signal_types: evaluation.inputSignalTypes,
              prompt_preview_redacted: action.redactedPreview,
              file_meta: action.fileMeta,
              correlation_id: backendCorrelationId,
            });
            await emitTelemetry({
              event_type: "policy_blocked",
              action_taken: evaluation.reasonCodes.join(",") || "backend_verification_failed",
              input_signal_types: evaluation.inputSignalTypes,
              prompt_preview_redacted: action.redactedPreview,
              file_meta: action.fileMeta,
              correlation_id: backendCorrelationId,
            });
            showNonBlockingPromptBlockNotice(policy, domain, "Realtime verification failed closed in enforce mode.");
            return;
          }
          await emitTelemetry({
            event_type: "prompt_warned",
            action_taken: "backend_verification_failed_allow_monitor",
            input_signal_types: evaluation.inputSignalTypes,
            prompt_preview_redacted: action.redactedPreview,
            file_meta: action.fileMeta,
            correlation_id: backendCorrelationId,
          });
          showMonitoringBanner({
            domain,
            message: "Prompt verification degraded to monitoring mode. Prompt allowed while controls recover.",
          });
          safelyResumeSubmission(action, domain);
          return;
        }

        await emitTelemetry({
          event_type: "prompt_blocked",
          action_taken: "block_after_backend_confirmation",
          input_signal_types: evaluation.inputSignalTypes,
          prompt_preview_redacted: action.redactedPreview,
          file_meta: action.fileMeta,
          correlation_id: backendCorrelationId,
        });
        await emitTelemetry({
          event_type: "policy_blocked",
          action_taken: evaluation.reasonCodes.join(",") || "policy_blocked",
          input_signal_types: evaluation.inputSignalTypes,
          prompt_preview_redacted: action.redactedPreview,
          file_meta: action.fileMeta,
          correlation_id: backendCorrelationId,
        });
        showNonBlockingPromptBlockNotice(
          policy,
          domain,
          evaluation.userMessage || evaluation.reasonCodes.join(", ") || "Backend policy denied request"
        );
        return;
      } catch {
        void emitHealthTelemetry("backend_unreachable", "interaction_evaluate_failed").catch(() => undefined);
        if (shouldFailClosedOnBackendVerificationFailure(policy)) {
          await emitTelemetry({
            event_type: "prompt_blocked",
            action_taken: "backend_confirmation_failed_block",
            input_signal_types: action.inputSignalTypes,
            prompt_preview_redacted: action.redactedPreview,
            file_meta: action.fileMeta,
            correlation_id: backendCorrelationId,
          });
          await emitTelemetry({
            event_type: "policy_blocked",
            action_taken: "backend_confirmation_failed_block",
            input_signal_types: action.inputSignalTypes,
            prompt_preview_redacted: action.redactedPreview,
            file_meta: action.fileMeta,
            correlation_id: backendCorrelationId,
          });
          showNonBlockingPromptBlockNotice(
            policy,
            domain,
            "Realtime verification is unavailable. Enforce mode blocks submission until controls recover."
          );
          return;
        }
        await emitTelemetry({
          event_type: "prompt_warned",
          action_taken: "backend_confirmation_failed_allow_monitor",
          input_signal_types: action.inputSignalTypes,
          prompt_preview_redacted: action.redactedPreview,
          file_meta: action.fileMeta,
          correlation_id: backendCorrelationId,
        });
        showMonitoringBanner({
          domain,
          message: "Realtime verification is temporarily unavailable. Prompt allowed under monitoring.",
        });
        safelyResumeSubmission(action, domain);
        return;
      }
    }

    await emitTelemetry({
      event_type: "prompt_submitted",
      action_taken: "allow",
      input_signal_types: action.inputSignalTypes,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
    });
    safelyResumeSubmission(action, domain);
    return;
  }

  if (action.decision === "warn") {
    await emitTelemetry({
      event_type: "prompt_warned",
      action_taken: "warn",
      input_signal_types: action.inputSignalTypes,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
    });
    await emitTelemetry({
      event_type: "policy_warned",
      action_taken: action.reasonCodes.join(",") || "policy_warned",
      input_signal_types: action.inputSignalTypes,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
    });
    const choice = await showWarnBanner({
      domain,
      reasons: action.reasonCodes,
      recommendation: "This interaction may violate policy.",
      canContinue: true,
    });
    if (choice === "continue") {
      await emitTelemetry({
        event_type: "prompt_submitted",
        action_taken: "continue_after_warn",
        input_signal_types: action.inputSignalTypes,
        prompt_preview_redacted: action.redactedPreview,
        file_meta: action.fileMeta,
        policy_version: policy.policy_version,
        platform_mode: policy.platform_mode,
      });
      safelyResumeSubmission(action, domain);
    }
    return;
  }

  if (action.decision === "block") {
    const blockCorrelationId = createCorrelationId();
    await emitTelemetry({
      event_type: "prompt_blocked",
      action_taken: "block",
      input_signal_types: action.inputSignalTypes,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      correlation_id: blockCorrelationId,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
    });
    await emitTelemetry({
      event_type: "policy_blocked",
      action_taken: action.reasonCodes.join(",") || "policy_blocked",
      input_signal_types: action.inputSignalTypes,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      correlation_id: blockCorrelationId,
      policy_version: policy.policy_version,
      platform_mode: policy.platform_mode,
    });
    showNonBlockingPromptBlockNotice(policy, domain, action.reasonCodes.join(", ") || "Policy blocked this action");
    return;
  }

  void emitTelemetry({
    event_type: "prompt_held",
    action_taken: "hold_for_backend",
    input_signal_types: action.inputSignalTypes,
    prompt_preview_redacted: action.redactedPreview,
    file_meta: action.fileMeta,
    policy_version: policy.policy_version,
    platform_mode: policy.platform_mode,
  }).catch(() => undefined);

  const holdCorrelationId = createCorrelationId();
  showHoldBanner("Security review in progress.");
  const holdTimeoutMs = 2500;
  const inputMethod = resolveInputMethodFromPromptNode(document.activeElement as HTMLElement | null);
  const promptHash = await sha256(action.promptText);

  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    window.setTimeout(() => reject(new Error("Hold adjudication timeout")), holdTimeoutMs);
  });

  try {
    const result = await Promise.race([
      evaluateContextAwarePolicyDecision({
        policy,
        promptText: action.promptText,
        promptHash,
        redactedPreview: action.redactedPreview,
        fileMeta: action.fileMeta,
        inputSignalTypes: action.inputSignalTypes,
        actionType: "prompt_submitted",
        inputMethod,
        timeoutMs: holdTimeoutMs,
      }),
      timeoutPromise,
    ]);
    clearHoldBanner();
    const decision = result.decision;
    const reasons = result.reasonCodes || action.reasonCodes;
    const mergedSignals = Array.from(new Set([...(result.inputSignalTypes || []), ...action.inputSignalTypes]));
    if (decision === "allow") {
      await emitTelemetry({
        event_type: "prompt_submitted",
        action_taken: "allow_after_hold_for_backend",
        input_signal_types: mergedSignals,
        prompt_preview_redacted: action.redactedPreview,
        file_meta: action.fileMeta,
        correlation_id: holdCorrelationId,
      });
      safelyResumeSubmission(action, domain);
      return;
    }
    if (decision === "warn" || decision === "step_up") {
      await emitTelemetry({
        event_type: "prompt_warned",
        action_taken: decision === "step_up"
          ? "step_up_after_hold_for_backend"
          : "warn_after_hold_for_backend",
        input_signal_types: mergedSignals,
        prompt_preview_redacted: action.redactedPreview,
        file_meta: action.fileMeta,
        correlation_id: holdCorrelationId,
      });
      await emitTelemetry({
        event_type: "policy_warned",
        action_taken: reasons.join(",") || "policy_warned",
        input_signal_types: mergedSignals,
        prompt_preview_redacted: action.redactedPreview,
        file_meta: action.fileMeta,
        correlation_id: holdCorrelationId,
      });
      const proceed = await showWarnBanner({
        domain,
        reasons,
        recommendation: result.userMessage || "Backend review returned warning.",
        canContinue: decision !== "step_up",
      });
      if (proceed === "continue") {
        safelyResumeSubmission(action, domain);
      }
      return;
    }
    if (isVerificationFailureOnlyBlock(reasons)) {
      if (shouldFailClosedOnBackendVerificationFailure(policy)) {
        await emitTelemetry({
          event_type: "prompt_blocked",
          action_taken: "hold_verification_failed_block",
          input_signal_types: mergedSignals,
          prompt_preview_redacted: action.redactedPreview,
          file_meta: action.fileMeta,
          correlation_id: holdCorrelationId,
        });
        await emitTelemetry({
          event_type: "policy_blocked",
          action_taken: reasons.join(",") || "hold_verification_failed",
          input_signal_types: mergedSignals,
          prompt_preview_redacted: action.redactedPreview,
          file_meta: action.fileMeta,
          correlation_id: holdCorrelationId,
        });
        showNonBlockingPromptBlockNotice(policy, domain, "Realtime verification failed closed in enforce mode.");
        return;
      }
      await emitTelemetry({
        event_type: "prompt_warned",
        action_taken: "hold_verification_failed_allow_monitor",
        input_signal_types: mergedSignals,
        prompt_preview_redacted: action.redactedPreview,
        file_meta: action.fileMeta,
        correlation_id: holdCorrelationId,
      });
      showMonitoringBanner({
        domain,
        message: "Hold verification degraded to monitoring mode. Prompt allowed while controls recover.",
      });
      safelyResumeSubmission(action, domain);
      return;
    }
    await emitTelemetry({
      event_type: "prompt_blocked",
      action_taken: "block_after_hold_for_backend",
      input_signal_types: mergedSignals,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      correlation_id: holdCorrelationId,
    });
    await emitTelemetry({
      event_type: "policy_blocked",
      action_taken: reasons.join(",") || "policy_blocked",
      input_signal_types: mergedSignals,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      correlation_id: holdCorrelationId,
    });
    showNonBlockingPromptBlockNotice(policy, domain, result.userMessage || reasons.join(", ") || "Backend denied request");
  } catch {
    clearHoldBanner();
    void emitHealthTelemetry("backend_unreachable", "hold_for_backend_timeout").catch(() => undefined);
    if (shouldFailClosedOnBackendVerificationFailure(policy)) {
      await emitTelemetry({
        event_type: "prompt_blocked",
        action_taken: "hold_for_backend_timeout_block",
        input_signal_types: action.inputSignalTypes,
        prompt_preview_redacted: action.redactedPreview,
        file_meta: action.fileMeta,
        correlation_id: holdCorrelationId,
      });
      await emitTelemetry({
        event_type: "policy_blocked",
        action_taken: "hold_for_backend_timeout_block",
        input_signal_types: action.inputSignalTypes,
        prompt_preview_redacted: action.redactedPreview,
        file_meta: action.fileMeta,
        correlation_id: holdCorrelationId,
      });
      showNonBlockingPromptBlockNotice(
        policy,
        domain,
        "Realtime verification timed out. Enforce mode blocks submission until controls recover."
      );
      return;
    }
    await emitTelemetry({
      event_type: "prompt_warned",
      action_taken: "hold_for_backend_timeout_warn",
      input_signal_types: action.inputSignalTypes,
      prompt_preview_redacted: action.redactedPreview,
      file_meta: action.fileMeta,
      correlation_id: holdCorrelationId,
    });
    const proceed = await showWarnBanner({
      domain,
      reasons: action.reasonCodes.length ? action.reasonCodes : ["backend_timeout"],
      recommendation: "Security verification timed out. Continue under monitoring or cancel.",
      canContinue: true,
    });
    if (proceed === "continue") {
      safelyResumeSubmission(action, domain);
      showMonitoringBanner({
        domain,
        message: "Prompt submitted with timeout fallback. Monitoring remains active.",
      });
    }
  }
}

async function bootstrap(): Promise<void> {
  const removeBootstrapGuard = installBootstrapGuard();
  try {
    await hydrateExtensionIdentityContext();
    await emitHealthTelemetry("extension_connected", "content_script_bootstrap");
    const isTopFrame = isTopFrameWindow();
    const domain = normalizeDomain(location.hostname);
    if (_isTrustedControlPlaneSurface(domain, location.href, document.title)) {
      contextStateMachine.markDisabled("trusted_control_plane_surface");
      clearWarnBanner();
      clearHoldBanner();
      clearJustificationModal();
      clearBlockActionBanner();
      clearMonitoringBanner();
      clearMeetingNotetakerBanner();
      return;
    }

    const appDetection = detectAndBindAppContext(domain);
    if (appDetection.app_detected) {
      await emitTelemetry({
        event_type: "ai_app_opened",
        action_taken: appDetection.profile.app_id,
        input_signal_types: [
          `app_profile:${appDetection.profile.app_id}`,
          `app_confidence:${appDetection.confidence.toFixed(2)}`,
          ...appDetection.signals.map((item) => `app_signal:${item}`),
        ],
      });
    }

    if (!contextRecoveryHandle && isTopFrame) {
      contextRecoveryHandle = installContextValidityWatchers(domain);
      window.addEventListener(
        "beforeunload",
        () => {
          if (contextRecoveryHandle) {
            contextRecoveryHandle.dispose();
            contextRecoveryHandle = null;
          }
        },
        { once: true },
      );
    }

    const cachedPolicy = await loadCachedPolicy();
    let policy: ExtensionPolicy | null = cachedPolicy;
    let domainStatus: DomainStatus = cachedPolicy ? resolveDomainStatus(domain, cachedPolicy) : "unknown";

    try {
      const policyResponse = await postRuntimeMessage<{ ok: true; policy: ExtensionPolicy; domainStatus: DomainStatus }>({
        type: "GET_POLICY",
        domain,
        forceSync: true,
      });
      policy = policyResponse.policy;
      domainStatus = policyResponse.domainStatus;
      contextStateMachine.markPolicySynced({
        policy_version: policy?.policy_version,
        platform_mode: policy?.platform_mode,
      });
      await emitHealthTelemetry("policy_sync_success", "policy_sync_ok", {
        policy_version: policy?.policy_version,
        platform_mode: policy?.platform_mode,
      });
    } catch {
      await emitHealthTelemetry("policy_sync_failed", "policy_sync_unavailable").catch(() => undefined);
      if (!policy) return;
    }

    if (!policy) return;

    const discoveryEligibility = classifyDiscoveryEligibility(
      {
        domain,
        url: location.href,
        title: document.title,
      },
      {
        policyManagedDomains: POLICY_MANAGED_DOMAINS,
        scopedDomains: CONTENT_SCRIPT_SCOPED_DOMAINS,
      }
    );
    const bootstrapAutomationContext = detectBrowserAutomationContext({
      domain,
      url: location.href,
      title: document.title,
      bodyText: _trimText(document.body?.innerText || document.body?.textContent || "", 16_000),
    });
    latestAutomationContext = bootstrapAutomationContext;
    const meetingSurface = detectMeetingSurface(domain, location.href);
    const isMeetingSurface = meetingSurface !== "unknown";
    const shouldEnforceSurface = discoveryEligibility.eligible || bootstrapAutomationContext.detected || isMeetingSurface;
    contextStateMachine.markValid({
      should_enforce_surface: shouldEnforceSurface,
      discovery_eligible: discoveryEligibility.eligible,
      automation_detected: bootstrapAutomationContext.detected,
      meeting_surface: isMeetingSurface ? meetingSurface : null,
    });

    if (isTopFrame && shouldEnforceSurface) {
      await emitTelemetry({
        event_type: "ai_domain_visit",
        action_taken: domainStatus,
        policy_version: policy.policy_version,
        platform_mode: policy.platform_mode,
        input_signal_types: [
          domainStatus === "unknown" ? "domain_policy_mismatch" : "domain_known",
          ...(discoveryEligibility.hint ? [`discovery_hint:${discoveryEligibility.hint}`] : []),
          ...(isMeetingSurface ? [`meeting_surface:${meetingSurface}`, "meeting_surface_scoped"] : []),
          ...(bootstrapAutomationContext.detected ? ["automation_suspected"] : []),
        ],
      });

      if (domainStatus === "unknown" && !isMeetingSurface) {
        await emitTelemetry({
          event_type: "unknown_ai_detected",
          action_taken: policy.unknown_domain_behavior,
          input_signal_types: [
            "domain_policy_mismatch",
            ...(discoveryEligibility.hint ? [`discovery_hint:${discoveryEligibility.hint}`] : []),
          ],
          policy_version: policy.policy_version,
          platform_mode: policy.platform_mode,
        });
      }
    }

    if (isTopFrame) {
      if (isMeetingSurface) {
        await detectAndEmitMeetingNotetaker(policy, domain, { scanSource: "bootstrap" });
        installMeetingNotetakerMonitor(policy, domain);
      }
      if (shouldEnforceSurface && !isMeetingSurface) {
        await detectAndEmitAgentRuntimeDiscovery(policy, domain, { scanSource: "bootstrap" });
        installAgentRuntimeDiscoveryMonitor(policy, domain);
      }
      if (!isMeetingSurface) {
        installBrowserAutomationMonitor(policy, domain);
        void detectAndEmitBrowserAutomation(policy, domain, { scanSource: "bootstrap" }).catch(() => undefined);
        installAutomationPurchaseGuard(policy, domain);
      }
    }

    if (
      isTopFrame
      && shouldEnforceSurface
      && (domainStatus === "critical"
        || domainStatus === "blocked"
        || (!isMeetingSurface && domainStatus === "unknown" && policy.unknown_domain_behavior === "block"))
    ) {
      enforceBlockedDomain(
        policy,
        domain,
        domainStatus,
        domainStatus === "unknown" ? "Unknown AI domain blocked by policy" : "Domain is blocked by policy"
      );
      return;
    }

    if (!shouldEnforceSurface) {
      contextStateMachine.markDisabled("outside_policy_scope", {
        domain,
        discovery_hint: discoveryEligibility.hint || null,
      });
      return;
    }

    installDataTransferHooks({
      domain,
      policy,
      onTelemetry: async (payload) => {
        const normalizedPayload = {
          ...payload,
          policy_version: policy.policy_version,
          platform_mode: policy.platform_mode,
        };
        await emitTelemetry(normalizedPayload);
        const eventType = String(payload.event_type || "").toLowerCase();
        if (eventType === "clipboard_paste_detected") {
          await emitTelemetry({
            event_type: "paste_into_ai_app",
            action_taken: "paste_observed",
            input_signal_types: Array.isArray(payload.input_signal_types)
              ? payload.input_signal_types
              : [],
            prompt_preview_redacted: String(payload.prompt_preview_redacted || ""),
            policy_version: policy.policy_version,
            platform_mode: policy.platform_mode,
          });
        }
        if (eventType === "file_upload_detected") {
          await emitTelemetry({
            event_type: "file_upload_attempted",
            action_taken: "file_upload_observed",
            input_signal_types: Array.isArray(payload.input_signal_types)
              ? payload.input_signal_types
              : [],
            file_meta: Array.isArray(payload.file_meta)
              ? payload.file_meta
              : [],
            policy_version: policy.policy_version,
            platform_mode: policy.platform_mode,
          });
        }
      },
      onWarn: ({ domain: warnDomain, reasons, recommendation }) =>
        showWarnBanner({
          domain: warnDomain,
          reasons,
          recommendation,
          canContinue: true,
        }),
      onBlock: async ({ domain: blockedDomain, reason }) => {
        showNonBlockingBlockedActionNotice(policy, blockedDomain, reason);
      },
      onRequireJustification: async ({ domain: justificationDomain, reason, recommendation }) => {
        const settings = await getSettings();
        return showJustificationModal({
          domain: justificationDomain,
          reason,
          recommendation,
          defaultEmail: settings.authEmail,
          defaultRole: settings.actorRole,
          defaultDepartment: settings.actorDepartment,
        });
      },
      onDataTransferCheck: async (transferPayload) => {
        const response = await postRuntimeMessage<{
          ok?: boolean;
          result: {
            decision: "allow" | "warn" | "block" | "require_justification";
            reason_code: string;
            explanation: string;
            recommended_action: string;
            justification_required: boolean;
            policy_version: string;
            platform_mode: string;
          };
          error?: string;
        }>({
          type: "DATA_TRANSFER_CHECK",
          payload: {
            ...transferPayload,
            correlation_id: transferPayload.correlation_id || createCorrelationId(),
          },
        });
        if (!response || response.ok === false || !response.result) {
          return {
            decision: "allow",
            reason_code: "extension_context_unavailable",
            explanation: "Extension context unavailable during data-transfer policy check; allowing action.",
            recommended_action: "retry_if_needed",
            justification_required: false,
            policy_version: policy.policy_version,
            platform_mode: policy.platform_mode,
          };
        }
        return response.result;
      },
      onDataTransferJustify: async (transferPayload) => {
        const response = await postRuntimeMessage<{
          ok?: boolean;
          result: {
            decision: "allow" | "block";
            reason_code: string;
            explanation: string;
            recommended_action: string;
          };
          error?: string;
        }>({
          type: "DATA_TRANSFER_JUSTIFY",
          payload: {
            ...transferPayload,
            correlation_id: transferPayload.correlation_id || createCorrelationId(),
          },
        });
        if (!response || response.ok === false || !response.result) {
          return {
            decision: "allow",
            reason_code: "extension_context_unavailable",
            explanation: "Extension context unavailable during justification check; allowing action.",
            recommended_action: "retry_if_needed",
          };
        }
        return response.result;
      },
    });

    const removePromptDraftObserver = installPromptDraftObserver(policy, domain);
    window.addEventListener(
      "beforeunload",
      () => {
        removePromptDraftObserver();
      },
      { once: true },
    );

    if (policy.interaction_rules.input_checks_enabled) {
      installInputGuard({
        domain,
        policy,
        onDecision: (action) => handleDecision(policy, domain, action),
      });
      contextStateMachine.markInputBound({
        source: "input_guard",
      });
    }

    if (policy.interaction_rules.output_checks_enabled) {
      installOutputGuard({
        domain,
        policy,
        onFlag: async ({ reason, preview, inputSignalTypes }) => {
          await emitTelemetry({
            event_type: "output_flagged",
            action_taken: "flagged",
            input_signal_types: inputSignalTypes,
            prompt_preview_redacted: preview,
            policy_version: policy.policy_version,
            platform_mode: policy.platform_mode,
          });
          await showWarnBanner({
            domain,
            reasons: [reason],
            recommendation: "Potential risky output detected.",
            canContinue: false,
          });
        },
      });
    }
  } finally {
    removeBootstrapGuard();
    clearHoldBanner();
  }
}

export const __contentScriptTestHooks = {
  evaluateBrowserAutomationPolicyDecision: _evaluateBrowserAutomationPolicyDecision,
  isTrustedControlPlaneSurface: _isTrustedControlPlaneSurface,
  shouldFailClosedOnBackendVerificationFailure,
  buildPilotTelemetryPayload,
  handleDecision,
  shouldEmitAgentRuntimeDiscovery,
};

if (typeof window !== "undefined" && typeof document !== "undefined" && typeof chrome !== "undefined") {
  void bootstrap().catch(() => undefined);
}
