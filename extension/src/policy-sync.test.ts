import { afterEach, describe, expect, it, vi } from "vitest";

import {
  classifyDomainStatus,
  domainMatches,
  getCachedPolicy,
  getSettings,
  refreshAccessToken,
  sanitizeBlockedDomains,
  signInWithCredentials,
  STORAGE_KEYS,
  type ExtensionPolicy,
  type ExtensionSettings,
} from "./policy-sync";

function createStorage(initial: Record<string, unknown> = {}) {
  const store = new Map<string, unknown>(Object.entries(initial));
  return {
    store,
    get: vi.fn(async (keys?: string | string[]) => {
      if (!keys) return Object.fromEntries(store.entries());
      const normalizedKeys = Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(normalizedKeys.map((key) => [key, store.get(key)]));
    }),
    set: vi.fn(async (values: Record<string, unknown>) => {
      for (const [key, value] of Object.entries(values)) {
        store.set(key, value);
      }
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        store.delete(key);
      }
    }),
  };
}

const policy: ExtensionPolicy = {
  tenant_id: "t1",
  platform_mode: "enforce",
  policy_version: "pv1",
  approved_domains: ["chat.openai.com"],
  blocked_domains: ["blocked.example.ai"],
  warn_domains: ["claude.ai"],
  critical_domains: ["critical.example.ai"],
  unknown_domain_behavior: "warn",
  interaction_rules: {
    input_checks_enabled: true,
    output_checks_enabled: false,
    sensitive_patterns: [],
    blocked_keywords: [],
    high_risk_terms: [],
    hold_for_backend_on_ambiguous: true,
    backend_allow_confirmation_enabled: false,
  },
  browser_automation_control: {
    policy_id: "browser-automation-control-default",
    name: "Browser Automation Control",
    category: "BROWSER_AUTOMATION_CONTROL",
    mode: "block",
    enabled: true,
    scope: {
      users: [],
      groups: [],
      tenant_id: "t1",
      surfaces: ["browser_extension"],
      source_vendors: [],
      agentic_browser_assets: [],
      domains_allowlist: ["chat.openai.com"],
      domains_blocklist: ["blocked.example.ai"],
      url_patterns_allowlist: [],
      url_patterns_blocklist: [],
    },
    automation: {
      detection_required: true,
      confidence_threshold: 0.6,
      sources: ["browser_visible", "extension_marker", "unknown"],
    },
    allowed_actions: ["page_view", "search", "navigate", "read_content"],
    blocked_actions: ["add_to_cart", "checkout", "purchase_now", "payment_submit"],
    action_overrides: [],
    decisions: {
      on_allowed_browsing: "allow",
      on_automation_detected: "warn",
      on_blocked_domain: "block",
      on_disallowed_domain: "warn",
      on_blocked_action: "block",
      on_scope_violation: "block",
      on_unknown_automation_source: "warn",
      on_sensitive_data_or_secret: "block",
    },
  },
  intent_aware_action_control: {
    policy_id: "pilot-intent-aware",
    schema_version: "intent-aware-ai-action-control/v1",
    name: "Pilot Intent-Aware AI Action Control",
    category: "INTENT_AWARE_AI_ACTION_CONTROL",
    mode: "block",
    enabled: true,
    scope: {
      users: [],
      groups: [],
      surfaces: ["browser_extension"],
      applications: [],
      domains: [],
      destination_trust_levels: ["public", "unknown"],
    },
    allowed_intents: ["public_research", "company_lookup"],
    blocked_intents: ["credential_or_secret_handling"],
    intent_action_rules: [],
    copy_export_rules: [],
    alignment_rules: [],
  },
};

describe("policy-sync domain matching", () => {
  it("matches direct and subdomain values", () => {
    expect(domainMatches("chat.openai.com", "chat.openai.com")).toBe(true);
    expect(domainMatches("www.chat.openai.com", "chat.openai.com")).toBe(true);
    expect(domainMatches("foo.bar", "chat.openai.com")).toBe(false);
  });

  it("classifies status using policy lists", () => {
    expect(classifyDomainStatus("chat.openai.com", policy)).toBe("approved");
    expect(classifyDomainStatus("claude.ai", policy)).toBe("warn");
    expect(classifyDomainStatus("blocked.example.ai", policy)).toBe("blocked");
    expect(classifyDomainStatus("critical.example.ai", policy)).toBe("critical");
    expect(classifyDomainStatus("new.unknown.ai", policy)).toBe("unknown");
  });

  it("gives blocked precedence for explicitly blocked collaboration domains", () => {
    const collaborationPolicy: ExtensionPolicy = {
      ...policy,
      approved_domains: ["mail.google.com"],
      blocked_domains: ["mail.google.com"],
      critical_domains: ["mail.google.com"],
    };
    expect(classifyDomainStatus("mail.google.com", collaborationPolicy)).toBe("critical");
  });

  it("never returns local control-plane domains in block rule input", () => {
    expect(
      sanitizeBlockedDomains([
        "hotmail.com",
        "localhost",
        "127.0.0.1",
        "api.localhost",
        "host.docker.internal",
      ])
    ).toEqual(["hotmail.com"]);
  });

  it("normalizes browser automation action scope from cached policy", async () => {
    vi.stubGlobal("chrome", {
      storage: {
        local: {
          get: vi.fn().mockResolvedValue({
            [STORAGE_KEYS.cachedPolicy]: {
              ...policy,
              browser_automation_control: {
                policy_id: "pilot_browser_automation_control",
                name: "Pilot Browser Automation Control",
                category: "BROWSER_AUTOMATION_CONTROL",
                mode: "block",
                enabled: true,
                scope: {
                  tenant_id: "t1",
                  surfaces: ["browser_extension"],
                  domains_allowlist: ["www.amazon.com", "localhost"],
                  domains_blocklist: ["admin.example.com", "127.0.0.1"],
                },
                automation_detection: {
                  confidence_threshold: 0.7,
                  sources: ["suspected_local_agent", "browser_visible", "suspected_local_agent"],
                },
                allowed_actions: ["page_view", "search", "navigate", "read_content"],
                blocked_actions: ["add_to_cart", "checkout", "purchase_now", "payment_submit"],
                action_overrides: [
                  {
                    domain: "www.amazon.com",
                    allowed_actions: ["page_view", "search", "navigate", "read_content"],
                    blocked_actions: ["add_to_cart", "checkout", "purchase_now", "payment_submit"],
                  },
                ],
                decisions: {
                  on_allowed_browsing: "allow",
                  on_automation_detected: "warn",
                  on_blocked_domain: "block",
                  on_disallowed_domain: "warn",
                  on_blocked_action: "block",
                  on_scope_violation: "block",
                  on_unknown_automation_source: "warn",
                  on_sensitive_data_or_secret: "block",
                },
              },
            },
          }),
        },
      },
    });

    const cached = await getCachedPolicy();

    expect(cached?.browser_automation_control.category).toBe("BROWSER_AUTOMATION_CONTROL");
    expect(cached?.browser_automation_control.automation.confidence_threshold).toBe(0.7);
    expect(cached?.browser_automation_control.automation.sources).toEqual(["suspected_local_agent", "browser_visible"]);
    expect(cached?.browser_automation_control.scope.domains_allowlist).toContain("amazon.com");
    expect(cached?.browser_automation_control.scope.domains_blocklist).toEqual(["admin.example.com"]);
    expect(cached?.browser_automation_control.action_overrides[0].domains).toEqual(["amazon.com"]);
    expect(cached?.browser_automation_control.action_overrides[0].allowed_actions).toContain("read_content");
    expect(cached?.browser_automation_control.action_overrides[0].blocked_actions).toEqual([
      "add_to_cart",
      "checkout",
      "purchase_now",
      "payment_submit",
    ]);
    expect(cached?.intent_aware_action_control.category).toBe("INTENT_AWARE_AI_ACTION_CONTROL");
    expect(cached?.intent_aware_action_control.scope.surfaces).toEqual(["browser_extension"]);
  });
});

describe("policy-sync auth refresh", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  function stubChromeStorage() {
    const local = createStorage();
    const session = createStorage();
    vi.stubGlobal("chrome", {
      storage: {
        local,
        session,
      },
    });
    return { local, session };
  }

  function settings(refreshToken = "header.payload.signature"): ExtensionSettings {
    return {
      backendUrl: "http://localhost:8000",
      accessToken: "old-access",
      refreshToken,
      tenantId: "tenant-1",
      browser: "chrome",
      browserProfile: "default",
      authEmail: "",
      actorRole: "",
      actorDepartment: "",
      pilotHostname: "",
      pilotDeviceType: "laptop",
      pilotOsVersion: "",
      enterpriseManaged: false,
      policyLocked: false,
    };
  }

  it("shares one refresh request across concurrent callers", async () => {
    const { local, session } = stubChromeStorage();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: "next-access",
          refresh_token: "next-refresh",
          token_type: "bearer",
          expires_in: 900,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    );
    vi.stubGlobal("fetch", fetchMock);

    const [first, second] = await Promise.all([
      refreshAccessToken(settings()),
      refreshAccessToken(settings()),
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(first?.accessToken).toBe("next-access");
    expect(second?.accessToken).toBe("next-access");
    expect(session.set).toHaveBeenCalledTimes(1);
    expect(local.set).not.toHaveBeenCalledWith(expect.objectContaining({
      [STORAGE_KEYS.accessToken]: expect.any(String),
      [STORAGE_KEYS.refreshToken]: expect.any(String),
    }));
    expect(local.remove).toHaveBeenCalledWith([STORAGE_KEYS.accessToken, STORAGE_KEYS.refreshToken]);
  });

  it("does not send malformed refresh tokens to the API", async () => {
    stubChromeStorage();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const refreshed = await refreshAccessToken(settings("not-a-token"));

    expect(refreshed).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("policy-sync session token storage", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("does not persist sign-in bearer or refresh tokens in chrome.storage.local", async () => {
    const local = createStorage();
    const session = createStorage();
    vi.stubGlobal("chrome", {
      storage: {
        local,
        session,
      },
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: "signed-in-access",
          refresh_token: "signed-in-refresh",
          selected_tenant_id: "tenant-1",
          token_type: "bearer",
          expires_in: 900,
          tenants: [{ id: "tenant-1", role: "viewer", name: "Pilot" }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )
    ));

    await signInWithCredentials({
      backendUrl: "http://127.0.0.1:8000",
      email: "pilot@example.com",
      password: "Password123!",
    });

    expect(local.store.get(STORAGE_KEYS.accessToken)).toBeUndefined();
    expect(local.store.get(STORAGE_KEYS.refreshToken)).toBeUndefined();
    expect(session.store.get(STORAGE_KEYS.accessToken)).toBe("signed-in-access");
    expect(session.store.get(STORAGE_KEYS.refreshToken)).toBe("signed-in-refresh");

    const settings = await getSettings();
    expect(settings.accessToken).toBe("signed-in-access");
    expect(settings.refreshToken).toBe("signed-in-refresh");
  });

  it("migrates legacy local tokens into session storage and removes the local copy", async () => {
    const local = createStorage({
      [STORAGE_KEYS.backendUrl]: "http://127.0.0.1:8000",
      [STORAGE_KEYS.tenantId]: "tenant-1",
      [STORAGE_KEYS.accessToken]: "legacy-access",
      [STORAGE_KEYS.refreshToken]: "legacy-refresh",
    });
    const session = createStorage();
    vi.stubGlobal("chrome", {
      storage: {
        local,
        session,
      },
    });

    const settings = await getSettings();

    expect(settings.accessToken).toBe("legacy-access");
    expect(settings.refreshToken).toBe("legacy-refresh");
    expect(session.store.get(STORAGE_KEYS.accessToken)).toBe("legacy-access");
    expect(session.store.get(STORAGE_KEYS.refreshToken)).toBe("legacy-refresh");
    expect(local.store.get(STORAGE_KEYS.accessToken)).toBeUndefined();
    expect(local.store.get(STORAGE_KEYS.refreshToken)).toBeUndefined();
  });

  it("scrubs legacy reusable passwords instead of recovering a session with them", async () => {
    const local = createStorage({
      [STORAGE_KEYS.authEmail]: "user@example.test",
      [STORAGE_KEYS.authPasswordCipher]: "legacy-cipher",
      [STORAGE_KEYS.authPasswordIv]: "legacy-iv",
      authPassword: "legacy-plaintext-password",
    });
    const session = createStorage();
    vi.stubGlobal("chrome", { storage: { local, session } });

    const settings = await getSettings();

    expect(settings.authEmail).toBe("user@example.test");
    expect(local.store.get(STORAGE_KEYS.authPasswordCipher)).toBeUndefined();
    expect(local.store.get(STORAGE_KEYS.authPasswordIv)).toBeUndefined();
    expect(local.store.get("authPassword")).toBeUndefined();
  });
});

describe("policy-sync settings fallback", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("returns safe defaults when chrome storage is unavailable in a stale content-script context", async () => {
    vi.stubGlobal("chrome", {});

    const settings = await getSettings();

    expect(settings.backendUrl).toBe("http://localhost:8000");
    expect(settings.accessToken).toBe("");
    expect(settings.tenantId).toBe("");
    expect(settings.browser).toBe("chrome");
  });

  it("applies enterprise managed settings over local user-edited settings", async () => {
    const local = createStorage({
      [STORAGE_KEYS.backendUrl]: "http://wrong-local-api:8000",
      [STORAGE_KEYS.tenantId]: "wrong-tenant",
      [STORAGE_KEYS.browser]: "chrome",
      [STORAGE_KEYS.browserProfile]: "user-editable",
      [STORAGE_KEYS.pilotHostname]: "local-host",
    });
    const managed = createStorage({
      api_base_url: "http://10.145.1.44:8000/",
      tenant_id: "managed-tenant",
      browser: "edge",
      browser_profile: "edge-pilot-ring",
      policy_locked: true,
      hostname: "pilot-win-07",
      device_type: "desktop",
      os_version: "10.0.22631",
    });
    vi.stubGlobal("chrome", {
      storage: {
        local,
        managed,
      },
    });

    const settings = await getSettings();

    expect(settings.backendUrl).toBe("http://10.145.1.44:8000");
    expect(settings.tenantId).toBe("managed-tenant");
    expect(settings.browser).toBe("edge");
    expect(settings.browserProfile).toBe("edge-pilot-ring");
    expect(settings.pilotHostname).toBe("pilot-win-07");
    expect(settings.pilotDeviceType).toBe("desktop");
    expect(settings.pilotOsVersion).toBe("10.0.22631");
    expect(settings.enterpriseManaged).toBe(true);
    expect(settings.policyLocked).toBe(true);
  });

  it("treats Brave as a supported Chromium-family browser for pilot telemetry", async () => {
    const local = createStorage({
      [STORAGE_KEYS.backendUrl]: "http://127.0.0.1:8000",
      [STORAGE_KEYS.tenantId]: "tenant-1",
      [STORAGE_KEYS.browser]: "brave",
      [STORAGE_KEYS.browserProfile]: "brave-user",
    });
    vi.stubGlobal("chrome", {
      storage: {
        local,
      },
    });

    const settings = await getSettings();

    expect(settings.browser).toBe("brave");
    expect(settings.browserProfile).toBe("brave-user");
    expect(settings.enterpriseManaged).toBe(false);
    expect(settings.policyLocked).toBe(false);
  });
});
