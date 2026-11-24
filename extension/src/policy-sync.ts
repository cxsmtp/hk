export type PlatformMode = "discovery" | "enforce";
export type UnknownDomainBehavior = "discover" | "warn" | "block";
export type BrowserType = "chrome" | "edge" | "brave";
export type BrowserAutomationMode = "monitor" | "warn" | "block";
export type BrowserAutomationSource =
  | "browser_visible"
  | "extension_marker"
  | "agentic_browser_marker"
  | "scripted_input"
  | "rapid_navigation"
  | "automated_click_cadence"
  | "suspected_local_agent"
  | "unknown";
export type BrowserAutomationAction =
  | "page_view"
  | "search"
  | "scroll"
  | "navigate"
  | "read_content"
  | "form_fill"
  | "copy_content"
  | "download_file"
  | "open_external_link"
  | "submit_form"
  | "upload_file"
  | "add_to_cart"
  | "checkout"
  | "purchase_now"
  | "payment_submit"
  | "send_message"
  | "send_email"
  | "delete_item"
  | "change_settings"
  | "invite_user"
  | "create_api_key"
  | "access_admin_console"
  | "access_payment_page"
  | "access_credentials_page"
  | "credential_submit";

export type BrowserAutomationPolicy = {
  policy_id: string;
  name: string;
  category: "BROWSER_AUTOMATION_CONTROL";
  mode: BrowserAutomationMode;
  enabled: boolean;
  scope: {
    users: string[];
    groups: string[];
    tenant_id: string;
    surfaces: string[];
    source_vendors: string[];
    agentic_browser_assets: string[];
    domains_allowlist: string[];
    domains_blocklist: string[];
    url_patterns_allowlist: string[];
    url_patterns_blocklist: string[];
  };
  automation: {
    detection_required: boolean;
    confidence_threshold: number;
    sources: BrowserAutomationSource[];
  };
  allowed_actions: BrowserAutomationAction[];
  blocked_actions: BrowserAutomationAction[];
  action_overrides: Array<{
    name?: string;
    domain?: string;
    domains?: string[];
    allowed_actions: BrowserAutomationAction[];
    blocked_actions: BrowserAutomationAction[];
  }>;
  decisions: {
    on_allowed_browsing: "allow" | "warn" | "block";
    on_automation_detected: "allow" | "warn" | "block";
    on_blocked_domain: "allow" | "warn" | "block";
    on_disallowed_domain: "allow" | "warn" | "block";
    on_blocked_action: "allow" | "warn" | "block";
    on_scope_violation: "allow" | "warn" | "block";
    on_unknown_automation_source: "allow" | "warn" | "block";
    on_sensitive_data_or_secret: "allow" | "warn" | "block";
  };
};

export type InteractionRules = {
  input_checks_enabled: boolean;
  output_checks_enabled: boolean;
  sensitive_patterns: string[];
  blocked_keywords: string[];
  high_risk_terms: string[];
  hold_for_backend_on_ambiguous: boolean;
  backend_allow_confirmation_enabled: boolean;
};

export type IntentAwareActionControlPolicy = {
  policy_id: string;
  schema_version: string;
  name: string;
  category: "INTENT_AWARE_AI_ACTION_CONTROL";
  mode: "monitor" | "shadow" | "warn" | "block";
  enabled: boolean;
  scope: {
    users: string[];
    groups: string[];
    surfaces: string[];
    applications: string[];
    domains: string[];
    destination_trust_levels: string[];
  };
  allowed_intents: string[];
  blocked_intents: string[];
  intent_action_rules: Array<Record<string, unknown>>;
  copy_export_rules: Array<{
    output_contains: string[];
    output_sensitivity_threshold: string;
    action: "copy_output" | "download_output" | "export_output" | "share_output";
    decision: "allow" | "warn" | "block";
  }>;
  alignment_rules: Array<Record<string, unknown>>;
};

export type ExtensionPolicy = {
  tenant_id: string;
  platform_mode: PlatformMode;
  policy_version: string;
  approved_domains: string[];
  blocked_domains: string[];
  warn_domains: string[];
  critical_domains: string[];
  unknown_domain_behavior: UnknownDomainBehavior;
  interaction_rules: InteractionRules;
  browser_automation_control: BrowserAutomationPolicy;
  intent_aware_action_control: IntentAwareActionControlPolicy;
};

function normalizePolicyPayload(payload: ExtensionPolicy): ExtensionPolicy {
  const rules = payload?.interaction_rules || ({} as Partial<InteractionRules>);
  const browserPolicy = payload?.browser_automation_control || ({} as Partial<BrowserAutomationPolicy>);
  const intentPolicy = payload?.intent_aware_action_control || ({} as Partial<IntentAwareActionControlPolicy>);
  const scope = (browserPolicy.scope || {}) as Partial<BrowserAutomationPolicy["scope"]>;
  const automation = (
    browserPolicy.automation
    || ((browserPolicy as unknown as { automation_detection?: Partial<BrowserAutomationPolicy["automation"]> }).automation_detection || {})
  ) as Partial<BrowserAutomationPolicy["automation"]>;
  const decisions = (browserPolicy.decisions || {}) as Partial<BrowserAutomationPolicy["decisions"]>;
  const normalizeActionList = (values: unknown): BrowserAutomationAction[] =>
    Array.from(new Set(Array.isArray(values) ? values.map((item) => String(item || "").trim()).filter(Boolean) : []))
      .filter(Boolean) as BrowserAutomationAction[];

  return {
    ...payload,
    approved_domains: Array.isArray(payload?.approved_domains) ? payload.approved_domains : [],
    blocked_domains: sanitizeBlockedDomains(Array.isArray(payload?.blocked_domains) ? payload.blocked_domains : []),
    warn_domains: Array.isArray(payload?.warn_domains) ? payload.warn_domains : [],
    critical_domains: sanitizeBlockedDomains(Array.isArray(payload?.critical_domains) ? payload.critical_domains : []),
    interaction_rules: {
      input_checks_enabled: Boolean(rules.input_checks_enabled),
      output_checks_enabled: Boolean(rules.output_checks_enabled),
      sensitive_patterns: Array.isArray(rules.sensitive_patterns) ? rules.sensitive_patterns : [],
      blocked_keywords: Array.isArray(rules.blocked_keywords) ? rules.blocked_keywords : [],
      high_risk_terms: Array.isArray(rules.high_risk_terms) ? rules.high_risk_terms : [],
      hold_for_backend_on_ambiguous: Boolean(rules.hold_for_backend_on_ambiguous),
      backend_allow_confirmation_enabled: Boolean((rules as any).backend_allow_confirmation_enabled),
    },
    browser_automation_control: {
      policy_id: String(browserPolicy.policy_id || "browser_automation_control_default"),
      name: String(browserPolicy.name || "Browser Automation Control"),
      category: "BROWSER_AUTOMATION_CONTROL",
      mode: (["monitor", "warn", "block"].includes(String(browserPolicy.mode || "").toLowerCase())
        ? String(browserPolicy.mode).toLowerCase()
        : "warn") as BrowserAutomationMode,
      enabled: Boolean(browserPolicy.enabled ?? true),
      scope: {
        users: Array.isArray(scope.users) ? scope.users.map((item) => String(item || "").trim()).filter(Boolean) : [],
        groups: Array.isArray(scope.groups) ? scope.groups.map((item) => String(item || "").trim()).filter(Boolean) : [],
        tenant_id: String(scope.tenant_id || payload?.tenant_id || ""),
        surfaces: Array.isArray(scope.surfaces) && scope.surfaces.length
          ? scope.surfaces.map((item) => String(item || "").trim()).filter(Boolean)
          : ["browser_extension"],
        source_vendors: Array.isArray(scope.source_vendors)
          ? scope.source_vendors.map((item) => String(item || "").trim()).filter(Boolean)
          : [],
        agentic_browser_assets: Array.isArray(scope.agentic_browser_assets)
          ? scope.agentic_browser_assets.map((item) => String(item || "").trim()).filter(Boolean)
          : [],
        domains_allowlist: Array.isArray(scope.domains_allowlist)
          ? scope.domains_allowlist.map((item) => normalizeDomain(String(item || ""))).filter(Boolean)
          : [],
        domains_blocklist: sanitizeBlockedDomains(
          Array.isArray(scope.domains_blocklist)
            ? scope.domains_blocklist.map((item) => normalizeDomain(String(item || ""))).filter(Boolean)
            : [],
        ),
        url_patterns_allowlist: Array.isArray(scope.url_patterns_allowlist)
          ? scope.url_patterns_allowlist.map((item) => String(item || "").trim()).filter(Boolean)
          : [],
        url_patterns_blocklist: Array.isArray(scope.url_patterns_blocklist)
          ? scope.url_patterns_blocklist.map((item) => String(item || "").trim()).filter(Boolean)
          : [],
      },
      automation: {
        detection_required: Boolean(automation.detection_required ?? true),
        confidence_threshold: Math.max(0, Math.min(1, Number(automation.confidence_threshold ?? 0.6))),
        sources: Array.from(
          new Set(
            (
              Array.isArray(automation.sources)
                ? automation.sources
                : [
                    "browser_visible",
                    "extension_marker",
                    "agentic_browser_marker",
                    "scripted_input",
                    "rapid_navigation",
                    "automated_click_cadence",
                    "suspected_local_agent",
                    "unknown",
                  ]
            )
              .map((item) => String(item || "").trim())
              .filter(Boolean)
          )
        ) as BrowserAutomationSource[],
      },
      allowed_actions: normalizeActionList(browserPolicy.allowed_actions),
      blocked_actions: normalizeActionList(browserPolicy.blocked_actions),
      action_overrides: Array.isArray(browserPolicy.action_overrides)
        ? browserPolicy.action_overrides
          .map((item) => {
            const domainCandidates = Array.from(
              new Set(
                [
                  String(item?.domain || "").trim(),
                  ...(Array.isArray(item?.domains) ? item.domains.map((entry) => String(entry || "").trim()) : []),
                ]
                  .map((value) => normalizeDomain(value))
                  .filter(Boolean)
              )
            );
            if (!domainCandidates.length) return null;
            return {
              name: String(item?.name || "").trim() || undefined,
              domain: domainCandidates[0],
              domains: domainCandidates,
              allowed_actions: normalizeActionList(item?.allowed_actions),
              blocked_actions: normalizeActionList(item?.blocked_actions),
            };
          })
          .filter((item): item is NonNullable<typeof item> => Boolean(item))
        : [],
      decisions: {
        on_allowed_browsing: (String(decisions.on_allowed_browsing || "allow").toLowerCase() as "allow" | "warn" | "block"),
        on_automation_detected: (String(decisions.on_automation_detected || "warn").toLowerCase() as "allow" | "warn" | "block"),
        on_blocked_domain: (String(decisions.on_blocked_domain || "block").toLowerCase() as "allow" | "warn" | "block"),
        on_disallowed_domain: (String(decisions.on_disallowed_domain || "warn").toLowerCase() as "allow" | "warn" | "block"),
        on_blocked_action: (String(decisions.on_blocked_action || "block").toLowerCase() as "allow" | "warn" | "block"),
        on_scope_violation: (String(decisions.on_scope_violation || "block").toLowerCase() as "allow" | "warn" | "block"),
        on_unknown_automation_source: (String(decisions.on_unknown_automation_source || "warn").toLowerCase() as "allow" | "warn" | "block"),
        on_sensitive_data_or_secret: (String(decisions.on_sensitive_data_or_secret || "block").toLowerCase() as "allow" | "warn" | "block"),
      },
    },
    intent_aware_action_control: {
      policy_id: String(intentPolicy.policy_id || "pilot_intent_aware_ai_action_control"),
      schema_version: String(intentPolicy.schema_version || "intent-aware-ai-action-control/v1"),
      name: String(intentPolicy.name || "Pilot Intent-Aware AI Action Control"),
      category: "INTENT_AWARE_AI_ACTION_CONTROL",
      mode: (["monitor", "shadow", "warn", "block"].includes(String(intentPolicy.mode || "").toLowerCase())
        ? String(intentPolicy.mode).toLowerCase()
        : "block") as IntentAwareActionControlPolicy["mode"],
      enabled: Boolean(intentPolicy.enabled ?? true),
      scope: {
        users: Array.isArray(intentPolicy.scope?.users) ? intentPolicy.scope.users.map(String).filter(Boolean) : [],
        groups: Array.isArray(intentPolicy.scope?.groups) ? intentPolicy.scope.groups.map(String).filter(Boolean) : [],
        surfaces: Array.isArray(intentPolicy.scope?.surfaces) && intentPolicy.scope.surfaces.length
          ? intentPolicy.scope.surfaces.map(String).filter(Boolean)
          : ["browser_extension"],
        applications: Array.isArray(intentPolicy.scope?.applications) ? intentPolicy.scope.applications.map(String).filter(Boolean) : [],
        domains: Array.isArray(intentPolicy.scope?.domains) ? intentPolicy.scope.domains.map((item) => normalizeDomain(String(item || ""))).filter(Boolean) : [],
        destination_trust_levels: Array.isArray(intentPolicy.scope?.destination_trust_levels)
          ? intentPolicy.scope.destination_trust_levels.map(String).filter(Boolean)
          : ["public", "unknown"],
      },
      allowed_intents: Array.isArray(intentPolicy.allowed_intents) ? intentPolicy.allowed_intents.map(String).filter(Boolean) : [],
      blocked_intents: Array.isArray(intentPolicy.blocked_intents) ? intentPolicy.blocked_intents.map(String).filter(Boolean) : [],
      intent_action_rules: Array.isArray(intentPolicy.intent_action_rules) ? intentPolicy.intent_action_rules : [],
      copy_export_rules: Array.isArray(intentPolicy.copy_export_rules)
        ? intentPolicy.copy_export_rules.map((rule) => ({
          output_contains: Array.isArray(rule.output_contains) ? rule.output_contains.map(String).filter(Boolean) : [],
          output_sensitivity_threshold: String(rule.output_sensitivity_threshold || "medium"),
          action: (String(rule.action || "copy_output") as IntentAwareActionControlPolicy["copy_export_rules"][number]["action"]),
          decision: (String(rule.decision || "block").toLowerCase() as "allow" | "warn" | "block"),
        }))
        : [],
      alignment_rules: Array.isArray(intentPolicy.alignment_rules) ? intentPolicy.alignment_rules : [],
    },
  };
}

export type ExtensionSettings = {
  backendUrl: string;
  accessToken: string;
  refreshToken: string;
  tenantId: string;
  browser: BrowserType;
  browserProfile: string;
  authEmail: string;
  actorRole: string;
  actorDepartment: string;
  pilotHostname: string;
  pilotDeviceType: "laptop" | "desktop" | "vm";
  pilotOsVersion: string;
  enterpriseManaged: boolean;
  policyLocked: boolean;
};

type AuthTokensResponse = {
  access_token?: string;
  refresh_token?: string;
  selected_tenant_id?: string;
  token_type?: string;
  expires_in?: number;
  tenants?: Array<{ id?: string; role?: string; name?: string }>;
};

export type SignInResult = {
  tenantId: string;
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  actorRole: string;
};

export const STORAGE_KEYS = {
  backendUrl: "backendUrl",
  accessToken: "accessToken",
  refreshToken: "refreshToken",
  tenantId: "tenantId",
  browser: "browser",
  browserProfile: "browserProfile",
  authEmail: "authEmail",
  actorRole: "actorRole",
  actorDepartment: "actorDepartment",
  pilotHostname: "pilotHostname",
  pilotDeviceType: "pilotDeviceType",
  pilotOsVersion: "pilotOsVersion",
  // Legacy-only keys: retained solely so upgrades can remove old secrets.
  authPassword: "authPassword",
  authPasswordCipher: "authPasswordCipher",
  authPasswordIv: "authPasswordIv",
  cachedPolicy: "cachedPolicy",
  lastSyncAt: "lastSyncAt",
  dynamicRuleIds: "dynamicRuleIds",
} as const;

type AuthTokenPair = {
  accessToken: string;
  refreshToken: string;
};

export const SUPPORTED_AI_DOMAINS = [
  "chat.openai.com",
  "chatgpt.com",
  "platform.openai.com",
  "claude.ai",
  "console.anthropic.com",
  "gemini.google.com",
  "aistudio.google.com",
  "notebooklm.google.com",
  "copilot.microsoft.com",
  "perplexity.ai",
  "www.perplexity.ai",
  "poe.com",
  "grok.com",
  "x.ai",
  "you.com",
  "www.you.com",
];

const PLATFORM_PROTECTED_DOMAINS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
  "host.docker.internal",
]);

let refreshAccessTokenInFlight: { key: string; promise: Promise<ExtensionSettings | null> } | null = null;
let volatileAuthTokens: AuthTokenPair = { accessToken: "", refreshToken: "" };

function normalizeDomain(raw: string): string {
  const trimmed = String(raw || "").trim().toLowerCase();
  if (!trimmed) return "";
  const candidate = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(candidate);
    const host = url.hostname.toLowerCase().replace(/^www\./, "");
    return host;
  } catch {
    return trimmed.replace(/^www\./, "");
  }
}

export function domainMatches(candidate: string, expected: string): boolean {
  const c = normalizeDomain(candidate);
  const e = normalizeDomain(expected);
  if (!c || !e) return false;
  return c === e || c.endsWith(`.${e}`);
}

function isPlatformProtectedDomain(domain: string): boolean {
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;
  if (PLATFORM_PROTECTED_DOMAINS.has(normalized)) return true;
  // Preserve local loopback subdomains when using local split-host setups.
  return normalized.endsWith(".localhost");
}

export function sanitizeBlockedDomains(domains: string[]): string[] {
  return Array.from(
    new Set(
      (domains || [])
        .map((value) => normalizeDomain(value))
        .filter((value) => Boolean(value) && !isPlatformProtectedDomain(value))
    )
  );
}

export function classifyDomainStatus(domain: string, policy: ExtensionPolicy): "approved" | "blocked" | "warn" | "critical" | "unknown" {
  const target = normalizeDomain(domain);
  if (!target) return "unknown";
  if (policy.critical_domains.some((value) => domainMatches(target, value))) return "critical";
  if (policy.blocked_domains.some((value) => domainMatches(target, value))) return "blocked";
  if (policy.warn_domains.some((value) => domainMatches(target, value))) return "warn";
  if (policy.approved_domains.some((value) => domainMatches(target, value))) return "approved";
  return "unknown";
}

function hasLocalStorageApi(): boolean {
  return typeof chrome !== "undefined" && !!chrome.storage?.local;
}

function hasSessionStorageApi(): boolean {
  return typeof chrome !== "undefined" && !!chrome.storage?.session;
}

function hasManagedStorageApi(): boolean {
  return typeof chrome !== "undefined" && !!chrome.storage?.managed;
}

export function normalizeBrowserType(value: unknown): BrowserType {
  const normalized = String(value || "").trim().toLowerCase();
  if (["edge", "msedge", "microsoft_edge", "microsoft-edge"].includes(normalized)) return "edge";
  if (normalized === "brave") return "brave";
  return "chrome";
}

function normalizeManagedBoolean(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  const normalized = String(value || "").trim().toLowerCase();
  return ["1", "true", "yes", "on", "managed", "locked"].includes(normalized);
}

function firstManagedValue(managed: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    const value = managed[key];
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      return value;
    }
  }
  return undefined;
}

async function readManagedSettings(): Promise<Record<string, unknown>> {
  if (!hasManagedStorageApi()) return {};
  try {
    const managed = await chrome.storage.managed.get();
    return managed && typeof managed === "object" ? managed : {};
  } catch {
    return {};
  }
}

async function readSessionTokens(): Promise<AuthTokenPair> {
  if (!hasSessionStorageApi()) {
    return hasLocalStorageApi() ? volatileAuthTokens : { accessToken: "", refreshToken: "" };
  }
  try {
    const stored = await chrome.storage.session.get([
      STORAGE_KEYS.accessToken,
      STORAGE_KEYS.refreshToken,
    ]);
    return {
      accessToken: String(stored[STORAGE_KEYS.accessToken] || ""),
      refreshToken: String(stored[STORAGE_KEYS.refreshToken] || ""),
    };
  } catch {
    return volatileAuthTokens;
  }
}

async function removeLegacyLocalTokens(): Promise<void> {
  if (!hasLocalStorageApi()) return;
  try {
    await chrome.storage.local.remove([STORAGE_KEYS.accessToken, STORAGE_KEYS.refreshToken]);
  } catch {
    // Legacy cleanup is best-effort; callers still avoid writing new tokens to local storage.
  }
}

async function scrubLegacyReusablePasswords(): Promise<void> {
  if (!hasLocalStorageApi()) return;
  try {
    await chrome.storage.local.remove([
      STORAGE_KEYS.authPassword,
      STORAGE_KEYS.authPasswordCipher,
      STORAGE_KEYS.authPasswordIv,
    ]);
  } catch {
    // Best-effort upgrade cleanup; reusable passwords are never read or written.
  }
}

async function writeSessionTokens(tokens: AuthTokenPair): Promise<void> {
  volatileAuthTokens = tokens;
  if (!hasSessionStorageApi()) return;
  await chrome.storage.session.set({
    [STORAGE_KEYS.accessToken]: tokens.accessToken,
    [STORAGE_KEYS.refreshToken]: tokens.refreshToken,
  });
}

export async function getSettings(): Promise<ExtensionSettings> {
  let stored: Record<string, unknown> = {};
  if (hasLocalStorageApi()) {
    try {
      stored = await chrome.storage.local.get([
        STORAGE_KEYS.backendUrl,
        STORAGE_KEYS.accessToken,
        STORAGE_KEYS.refreshToken,
        STORAGE_KEYS.tenantId,
        STORAGE_KEYS.browser,
        STORAGE_KEYS.browserProfile,
        STORAGE_KEYS.authEmail,
        STORAGE_KEYS.actorRole,
        STORAGE_KEYS.actorDepartment,
        STORAGE_KEYS.pilotHostname,
        STORAGE_KEYS.pilotDeviceType,
        STORAGE_KEYS.pilotOsVersion,
      ]);
    } catch {
      stored = {};
    }
  }
  const managed = await readManagedSettings();
  const enterpriseManaged = Object.keys(managed).length > 0
    || normalizeManagedBoolean(firstManagedValue(managed, ["enterprise_managed", "enterpriseManaged"]));
  const policyLocked = normalizeManagedBoolean(
    firstManagedValue(managed, ["policy_locked", "policyLocked", "settings_locked", "settingsLocked"]),
  );
  let tokens = await readSessionTokens();
  const legacyTokens = {
    accessToken: String(stored[STORAGE_KEYS.accessToken] || ""),
    refreshToken: String(stored[STORAGE_KEYS.refreshToken] || ""),
  };
  if ((!tokens.accessToken || !tokens.refreshToken) && (legacyTokens.accessToken || legacyTokens.refreshToken)) {
    tokens = {
      accessToken: tokens.accessToken || legacyTokens.accessToken,
      refreshToken: tokens.refreshToken || legacyTokens.refreshToken,
    };
    await writeSessionTokens(tokens);
  }
  if (legacyTokens.accessToken || legacyTokens.refreshToken) {
    await removeLegacyLocalTokens();
  }
  await scrubLegacyReusablePasswords();
  const managedBackendUrl = firstManagedValue(managed, ["api_base_url", "apiBaseUrl", "backend_url", "backendUrl"]);
  const managedTenantId = firstManagedValue(managed, ["tenant_id", "tenantId"]);
  const managedBrowser = firstManagedValue(managed, ["browser", "browser_type", "browserType"]);
  const managedBrowserProfile = firstManagedValue(managed, ["browser_profile", "browserProfile"]);
  const managedHostname = firstManagedValue(managed, ["hostname", "pilot_hostname", "pilotHostname"]);
  const managedDeviceType = firstManagedValue(managed, ["device_type", "pilot_device_type", "pilotDeviceType"]);
  const managedOsVersion = firstManagedValue(managed, ["os_version", "pilot_os_version", "pilotOsVersion"]);
  const pilotDeviceType = String(managedDeviceType || stored[STORAGE_KEYS.pilotDeviceType] || "laptop").trim().toLowerCase();
  return {
    backendUrl: String(managedBackendUrl || stored[STORAGE_KEYS.backendUrl] || "http://localhost:8000").replace(/\/+$/, ""),
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    tenantId: String(managedTenantId || stored[STORAGE_KEYS.tenantId] || ""),
    browser: normalizeBrowserType(managedBrowser || stored[STORAGE_KEYS.browser]),
    browserProfile: String(managedBrowserProfile || stored[STORAGE_KEYS.browserProfile] || "default"),
    authEmail: String(stored[STORAGE_KEYS.authEmail] || ""),
    actorRole: String(stored[STORAGE_KEYS.actorRole] || "").trim(),
    actorDepartment: String(stored[STORAGE_KEYS.actorDepartment] || "").trim(),
    pilotHostname: String(managedHostname || stored[STORAGE_KEYS.pilotHostname] || "").trim(),
    pilotDeviceType: (["laptop", "desktop", "vm"].includes(pilotDeviceType) ? pilotDeviceType : "laptop") as "laptop" | "desktop" | "vm",
    pilotOsVersion: String(managedOsVersion || stored[STORAGE_KEYS.pilotOsVersion] || "").trim(),
    enterpriseManaged,
    policyLocked,
  };
}

function normalizedApiPath(path: string): string {
  const trimmed = String(path || "").trim();
  if (!trimmed) return "/";
  if (trimmed.startsWith("/")) return trimmed;
  return `/${trimmed}`;
}

async function saveTokens(accessToken: string, refreshToken: string): Promise<void> {
  await writeSessionTokens({ accessToken, refreshToken });
  await removeLegacyLocalTokens();
}

function resolveTenantId(payload: AuthTokensResponse, fallbackTenantId?: string): string {
  const selected = String(payload.selected_tenant_id || "").trim();
  if (selected) return selected;
  const firstTenant = Array.isArray(payload.tenants) ? String(payload.tenants[0]?.id || "").trim() : "";
  if (firstTenant) return firstTenant;
  return String(fallbackTenantId || "").trim();
}

function looksLikeJwt(token: string): boolean {
  const parts = String(token || "").trim().split(".");
  return parts.length === 3 && parts.every((part) => part.length > 0);
}

function refreshTokenRequestKey(settings: ExtensionSettings): string {
  return [settings.backendUrl, settings.tenantId, settings.refreshToken].join("|");
}

async function performRefreshAccessToken(settings: ExtensionSettings): Promise<ExtensionSettings | null> {
  const response = await fetch(`${settings.backendUrl}/auth/refresh`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ refresh_token: settings.refreshToken }),
  });
  if (!response.ok) return null;

  const payload = await response.json() as AuthTokensResponse;
  const accessToken = String(payload.access_token || "").trim();
  const refreshToken = String(payload.refresh_token || settings.refreshToken).trim();
  if (!accessToken || !refreshToken) return null;

  await saveTokens(accessToken, refreshToken);
  return {
    ...settings,
    accessToken,
    refreshToken,
  };
}

export async function refreshAccessToken(settingsOverride?: ExtensionSettings): Promise<ExtensionSettings | null> {
  const settings = settingsOverride || await getSettings();
  if (!settings.backendUrl || !settings.refreshToken || !looksLikeJwt(settings.refreshToken)) return null;

  const key = refreshTokenRequestKey(settings);
  if (refreshAccessTokenInFlight?.key === key) {
    return refreshAccessTokenInFlight.promise;
  }

  const promise = performRefreshAccessToken(settings).finally(() => {
    if (refreshAccessTokenInFlight?.promise === promise) {
      refreshAccessTokenInFlight = null;
    }
  });
  refreshAccessTokenInFlight = { key, promise };
  return promise;
}

export async function fetchWithTenantAuth(
  path: string,
  init?: RequestInit,
  options?: {
    settings?: ExtensionSettings;
    extraHeaders?: Record<string, string>;
  }
): Promise<Response> {
  let settings = options?.settings || await getSettings();
  if (!settings.backendUrl || !settings.tenantId) {
    throw new Error("Extension settings incomplete: backend URL and tenant ID are required.");
  }

  const extraHeaders = options?.extraHeaders || {};
  const method = String(init?.method || "GET").toUpperCase();
  const endpoint = `${settings.backendUrl}${normalizedApiPath(path)}`;

  const doRequest = async (accessToken: string): Promise<Response> => {
    const headers = new Headers(init?.headers || {});
    for (const [name, value] of Object.entries(extraHeaders)) {
      if (String(value || "").trim()) headers.set(name, value);
    }
    headers.set("Authorization", `Bearer ${accessToken}`);
    headers.set("X-Tenant-ID", settings.tenantId);
    if (!headers.has("Content-Type") && method !== "GET" && method !== "HEAD") {
      headers.set("Content-Type", "application/json");
    }
    return await fetch(endpoint, {
      ...init,
      method,
      headers,
    });
  };

  if (!settings.accessToken && settings.refreshToken) {
    const refreshed = await refreshAccessToken(settings);
    if (refreshed) settings = refreshed;
  }

  if (!settings.accessToken) {
    throw new Error("Extension auth session missing. Sign in once in extension options.");
  }

  let response = await doRequest(settings.accessToken);
  if (response.status === 401 && settings.refreshToken) {
    const refreshed = await refreshAccessToken(settings);
    if (refreshed?.accessToken) {
      settings = refreshed;
      response = await doRequest(settings.accessToken);
    }
  }
  return response;
}

export async function signInWithCredentials(input: {
  backendUrl: string;
  email: string;
  password: string;
  tenantId?: string;
}): Promise<SignInResult> {
  const backendUrl = String(input.backendUrl || "").trim().replace(/\/+$/, "");
  const email = String(input.email || "").trim();
  const password = String(input.password || "");
  const requestedTenant = String(input.tenantId || "").trim();
  if (!backendUrl) throw new Error("Backend URL is required");
  if (!email || !password) throw new Error("Email and password are required");

  const response = await fetch(`${backendUrl}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    let detail = "";
    try {
      detail = (await response.text() || "").trim();
    } catch {
      detail = "";
    }
    const suffix = detail ? ` - ${detail.slice(0, 300)}` : "";
    throw new Error(`Sign in failed: ${response.status}${suffix}`);
  }

  const payload = await response.json() as AuthTokensResponse;
  const accessToken = String(payload.access_token || "").trim();
  const refreshToken = String(payload.refresh_token || "").trim();
  const tokenType = String(payload.token_type || "bearer").trim() || "bearer";
  const expiresIn = Number(payload.expires_in || 0) || 0;
  const tenantId = requestedTenant || resolveTenantId(payload, requestedTenant);
  const actorRole = Array.isArray(payload.tenants)
    ? String(payload.tenants.find((tenant) => String(tenant?.id || "").trim() === tenantId)?.role || payload.tenants[0]?.role || "").trim()
    : "";

  if (!accessToken || !refreshToken || !tenantId) {
    throw new Error("Sign in response missing required session fields.");
  }

  await chrome.storage.local.set({
    [STORAGE_KEYS.backendUrl]: backendUrl,
    [STORAGE_KEYS.tenantId]: tenantId,
    [STORAGE_KEYS.authEmail]: email,
    [STORAGE_KEYS.actorRole]: actorRole,
  });
  await saveTokens(accessToken, refreshToken);

  return {
    tenantId,
    accessToken,
    refreshToken,
    tokenType,
    expiresIn,
    actorRole,
  };
}

export async function getCachedPolicy(): Promise<ExtensionPolicy | null> {
  const stored = await chrome.storage.local.get([STORAGE_KEYS.cachedPolicy]);
  const payload = stored[STORAGE_KEYS.cachedPolicy];
  if (!payload || typeof payload !== "object") return null;
  return normalizePolicyPayload(payload as ExtensionPolicy);
}

async function updateDynamicBlockRules(policy: ExtensionPolicy): Promise<void> {
  const normalizedBlocked = sanitizeBlockedDomains(policy.blocked_domains);
  const previous = await chrome.storage.local.get([STORAGE_KEYS.dynamicRuleIds]);
  const previousIds = Array.isArray(previous[STORAGE_KEYS.dynamicRuleIds]) ? previous[STORAGE_KEYS.dynamicRuleIds] as number[] : [];
  // Always clear our managed DNR id range to prevent stale domain blocks from older/corrupted local state.
  const managedRangeIds = Array.from({ length: 1000 }, (_value, idx) => 10000 + idx);
  const removeRuleIds = Array.from(new Set([...previousIds, ...managedRangeIds]));

  const addRules: chrome.declarativeNetRequest.Rule[] = normalizedBlocked.map((domain, index) => ({
    id: 10000 + index,
    priority: 1,
    action: { type: chrome.declarativeNetRequest.RuleActionType.BLOCK },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: [chrome.declarativeNetRequest.ResourceType.MAIN_FRAME],
    },
  }));

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules,
  });
  await chrome.storage.local.set({ [STORAGE_KEYS.dynamicRuleIds]: addRules.map((rule) => rule.id) });
}

export async function syncPolicyNow(): Promise<ExtensionPolicy | null> {
  const settings = await getSettings();
  if (!settings.backendUrl || !settings.tenantId) return null;

  const response = await fetchWithTenantAuth("/extension/policy-sync", {
    method: "GET",
  }, {
    settings,
    extraHeaders: {
      "X-Browser-Profile": settings.browserProfile,
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    let detail = "";
    try {
      detail = (await response.text() || "").trim();
    } catch {
      detail = "";
    }
    const suffix = detail ? ` - ${detail.slice(0, 300)}` : "";
    throw new Error(`Policy sync failed: ${response.status}${suffix}`);
  }

  const payload = normalizePolicyPayload(await response.json() as ExtensionPolicy);
  await chrome.storage.local.set({
    [STORAGE_KEYS.cachedPolicy]: payload,
    [STORAGE_KEYS.lastSyncAt]: new Date().toISOString(),
  });
  await updateDynamicBlockRules(payload);
  return payload;
}
