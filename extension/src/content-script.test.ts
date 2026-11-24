import { afterEach, describe, expect, it, vi } from "vitest";

import { __contentScriptTestHooks } from "./content-script";
import type { ExtensionPolicy } from "./policy-sync";
import type { InputGuardAction } from "./interactions/input-guard";

const basePolicy: ExtensionPolicy = {
  tenant_id: "t1",
  platform_mode: "enforce",
  policy_version: "pv-intent-browser-automation",
  approved_domains: [],
  blocked_domains: [],
  warn_domains: [],
  critical_domains: [],
  unknown_domain_behavior: "warn",
  interaction_rules: {
    input_checks_enabled: true,
    output_checks_enabled: true,
    sensitive_patterns: [],
    blocked_keywords: [],
    high_risk_terms: [],
    hold_for_backend_on_ambiguous: true,
    backend_allow_confirmation_enabled: false,
  },
  browser_automation_control: {
    policy_id: "pilot_browser_automation_control",
    name: "Pilot Browser Automation Control",
    category: "BROWSER_AUTOMATION_CONTROL",
    mode: "block",
    enabled: true,
    scope: {
      users: [],
      groups: [],
      tenant_id: "t1",
      surfaces: ["browser_extension"],
      source_vendors: ["comet", "atlas", "claude", "chatgpt", "gemini", "perplexity", "codex", "custom"],
      agentic_browser_assets: [],
      domains_allowlist: ["docs.example.com", "shop.example.com"],
      domains_blocklist: ["admin.example.com"],
      url_patterns_allowlist: [],
      url_patterns_blocklist: [],
    },
    automation: {
      detection_required: true,
      confidence_threshold: 0.6,
      sources: ["browser_visible", "extension_marker", "suspected_local_agent", "unknown"],
    },
    allowed_actions: ["page_view", "search", "scroll", "navigate", "read_content"],
    blocked_actions: ["add_to_cart", "checkout", "purchase_now", "payment_submit", "submit_form", "upload_file"],
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
    policy_id: "pilot_intent_aware_ai_action_control",
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

function evaluate(input: {
  domain: string;
  url?: string;
  actionType: ExtensionPolicy["browser_automation_control"]["allowed_actions"][number];
  actionRisk: "low" | "medium" | "high";
  detected?: boolean;
  sourceDomain?: string;
  sensitive?: boolean;
}) {
  return __contentScriptTestHooks.evaluateBrowserAutomationPolicyDecision({
    policy: basePolicy,
    domain: input.domain,
    classifiedAction: {
      action_type: input.actionType,
      action_risk: input.actionRisk,
      confidence: 0.9,
      signals: [`test:${input.actionType}`],
    },
    automationContext: {
      detected: input.detected ?? true,
      confidence: input.detected === false ? 0 : 0.9,
      suspectedTool: "custom_local_agent",
      indicators: ["test_local_agent"],
    },
    lockState: input.sourceDomain
      ? {
          active: true,
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          confidence: 0.95,
          suspected_tool: "custom_local_agent",
          indicators: ["automation_lock_active"],
          source_domain: input.sourceDomain,
        }
      : null,
    currentUrl: input.url || `https://${input.domain}/`,
    hasSensitiveContentSignals: Boolean(input.sensitive),
  });
}

describe("content-script browser automation policy", () => {
  it("allows vendor-agnostic low-risk browsing on an approved site", () => {
    const decision = evaluate({
      domain: "docs.example.com",
      actionType: "read_content",
      actionRisk: "low",
    });

    expect(decision.decision).toBe("warn");
    expect(decision.reason).toBe("suspected_local_agent_low_risk");
    expect(decision.automation_source).toBe("suspected_local_agent");
  });

  it("blocks high-risk automated actions on approved sites beyond Amazon", () => {
    const decision = evaluate({
      domain: "shop.example.com",
      url: "https://shop.example.com/products/1",
      actionType: "add_to_cart",
      actionRisk: "high",
    });

    expect(decision.decision).toBe("block");
    expect(decision.reason).toBe("suspected_local_agent_high_risk");
  });

  it("blocks scope overextension when automation leaves its approved domain", () => {
    const decision = evaluate({
      domain: "outside.example.com",
      actionType: "navigate",
      actionRisk: "low",
      sourceDomain: "docs.example.com",
    });

    expect(decision.decision).toBe("block");
    expect(decision.reason).toBe("browser_agent_scope_violation");
    expect(decision.finding_type).toBe("BROWSER_AGENT_SCOPE_VIOLATION");
  });

  it("does not falsely block normal manual browsing", () => {
    const decision = evaluate({
      domain: "docs.example.com",
      actionType: "navigate",
      actionRisk: "low",
      detected: false,
    });

    expect(decision.decision).toBe("allow");
    expect(decision.reason).not.toContain("block");
  });

  it("never treats Hawk control-plane surfaces as governed browser actions", () => {
    expect(
      __contentScriptTestHooks.isTrustedControlPlaneSurface(
        "localhost",
        "http://localhost:3000/command-center",
        "Hawk AI Command Center",
      )
    ).toBe(true);
    expect(
      __contentScriptTestHooks.isTrustedControlPlaneSurface(
        "api.hawk.ai",
        "https://api.hawk.ai/health/schema",
        "Hawk AI API",
      )
    ).toBe(true);
  });
});

describe("content-script backend verification failure handling", () => {
  it("fails closed in enforce mode when prompt verification times out", () => {
    expect(__contentScriptTestHooks.shouldFailClosedOnBackendVerificationFailure(basePolicy)).toBe(true);
  });

  it("does not fail closed in discovery mode", () => {
    expect(
      __contentScriptTestHooks.shouldFailClosedOnBackendVerificationFailure({
        ...basePolicy,
        platform_mode: "discovery",
      }),
    ).toBe(false);
  });
});

describe("agent discovery scan deduplication", () => {
  it("emits each profile once per content session while allowing changed profiles", () => {
    const seen = new Set<string>();
    expect(__contentScriptTestHooks.shouldEmitAgentRuntimeDiscovery(seen, "agent-a")).toBe(true);
    expect(__contentScriptTestHooks.shouldEmitAgentRuntimeDiscovery(seen, "agent-a")).toBe(false);
    expect(__contentScriptTestHooks.shouldEmitAgentRuntimeDiscovery(seen, "agent-b")).toBe(true);
    expect(__contentScriptTestHooks.shouldEmitAgentRuntimeDiscovery(seen, "agent-a")).toBe(false);
  });
});

describe("content-script prompt telemetry handoff", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete (globalThis as any).chrome;
    delete (globalThis as any).location;
    delete (globalThis as any).document;
    delete (globalThis as any).window;
  });

  it("submits allowed prompt telemetry without waiting for a service worker acknowledgement", async () => {
    const sendMessageMock = vi.fn((_message: unknown, callback: (response: { ok: true }) => void) => { void callback; });
    (globalThis as any).chrome = {
      runtime: {
        id: "hawk-extension-test",
        lastError: null,
        sendMessage: sendMessageMock,
      },
    };
    (globalThis as any).location = {
      hostname: "chatgpt.com",
      href: "https://chatgpt.com/",
    };
    (globalThis as any).window = {
      setTimeout: vi.fn(),
    };
    (globalThis as any).document = {
      title: "ChatGPT",
    };

    const resumeSubmission = vi.fn();
    const action: InputGuardAction = {
      tier: "clear_negative",
      decision: "allow",
      reasonCodes: [],
      inputSignalTypes: ["test_prompt_submit"],
      redactedPreview: "Hawk realtime prompt visibility test",
      promptText: "Hawk realtime prompt visibility test",
      fileMeta: [],
      resumeSubmission,
    };

    const handling = __contentScriptTestHooks.handleDecision(
      { ...basePolicy, platform_mode: "discovery" },
      "chatgpt.com",
      action,
    );

    await Promise.resolve();

    expect((globalThis as any).chrome.runtime.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "TELEMETRY_EVENT",
        payload: expect.objectContaining({
          event_type: "prompt_submitted",
          action_taken: "allow",
          prompt_preview_redacted: "Hawk realtime prompt visibility test",
        }),
      }),
      expect.any(Function),
    );
    await handling;
    expect(resumeSubmission).toHaveBeenCalledTimes(1);

    const capturedArgs = sendMessageMock.mock.calls.at(0);
    if (capturedArgs === undefined) throw new Error("expected chrome.runtime.sendMessage to have been called");
    const [, capturedCallback] = capturedArgs;
    capturedCallback({ ok: true });
    await Promise.resolve();

    expect(resumeSubmission).toHaveBeenCalledTimes(1);
  });

  it("does not stall allowed prompt submission when telemetry acknowledgement never returns", async () => {
    (globalThis as any).chrome = {
      runtime: {
        id: "hawk-extension-test",
        lastError: null,
        sendMessage: vi.fn(),
      },
    };
    (globalThis as any).location = {
      hostname: "chatgpt.com",
      href: "https://chatgpt.com/",
    };
    (globalThis as any).window = {
      setTimeout: vi.fn(),
    };
    (globalThis as any).document = {
      title: "ChatGPT",
    };

    const resumeSubmission = vi.fn();
    const action: InputGuardAction = {
      tier: "clear_negative",
      decision: "allow",
      reasonCodes: [],
      inputSignalTypes: ["test_prompt_submit"],
      redactedPreview: "Hawk realtime prompt visibility test",
      promptText: "Hawk realtime prompt visibility test",
      fileMeta: [],
      resumeSubmission,
    };

    await expect(
      __contentScriptTestHooks.handleDecision(
        { ...basePolicy, platform_mode: "discovery" },
        "chatgpt.com",
        action,
      ),
    ).resolves.toBeUndefined();

    expect(resumeSubmission).toHaveBeenCalledTimes(1);
    expect((globalThis as any).chrome.runtime.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "TELEMETRY_EVENT",
        payload: expect.objectContaining({
          event_type: "prompt_submitted",
          action_taken: "allow",
        }),
      }),
      expect.any(Function),
    );
  });

  it("does not break prompt submission when Chrome closes a best-effort telemetry channel", async () => {
    (globalThis as any).chrome = {
      runtime: {
        id: "hawk-extension-test",
        lastError: null,
        sendMessage: vi.fn((_message: unknown, callback: (response: { ok: true } | undefined) => void) => {
          (globalThis as any).chrome.runtime.lastError = {
            message:
              "A listener indicated an asynchronous response by returning true, but the message channel closed before a response was received",
          };
          callback(undefined);
        }),
      },
    };
    (globalThis as any).location = {
      hostname: "chatgpt.com",
      href: "https://chatgpt.com/",
    };
    (globalThis as any).window = {
      setTimeout: vi.fn(),
    };
    (globalThis as any).document = {
      title: "ChatGPT",
    };

    const resumeSubmission = vi.fn();
    const action: InputGuardAction = {
      tier: "clear_negative",
      decision: "allow",
      reasonCodes: [],
      inputSignalTypes: ["test_prompt_submit"],
      redactedPreview: "Hawk realtime prompt visibility test",
      promptText: "Hawk realtime prompt visibility test",
      fileMeta: [],
      resumeSubmission,
    };

    await expect(
      __contentScriptTestHooks.handleDecision(
        { ...basePolicy, platform_mode: "discovery" },
        "chatgpt.com",
        action,
      ),
    ).resolves.toBeUndefined();

    expect(resumeSubmission).toHaveBeenCalledTimes(1);
  });

  it("does not throw when the original prompt form is detached before resume", async () => {
    (globalThis as any).chrome = {
      runtime: {
        id: "hawk-extension-test",
        lastError: null,
        sendMessage: vi.fn((_message: unknown, callback: (response: { ok: true }) => void) => {
          callback({ ok: true });
        }),
      },
    };
    (globalThis as any).location = {
      hostname: "chatgpt.com",
      href: "https://chatgpt.com/",
    };
    (globalThis as any).window = {
      setTimeout: vi.fn(),
    };
    (globalThis as any).document = {
      title: "ChatGPT",
      getElementById: vi.fn(() => null),
      createElement: vi.fn(() => ({
        className: "",
        textContent: "",
        remove: vi.fn(),
        appendChild: vi.fn(),
        style: {},
        setAttribute: vi.fn(),
      })),
      body: {
        appendChild: vi.fn(),
      },
      documentElement: {
        appendChild: vi.fn(),
      },
    };

    const resumeSubmission = vi.fn(() => {
      throw new Error("Form submission canceled because the form is not connected");
    });
    const action: InputGuardAction = {
      tier: "clear_negative",
      decision: "allow",
      reasonCodes: [],
      inputSignalTypes: ["test_prompt_submit"],
      redactedPreview: "Hawk realtime prompt visibility test",
      promptText: "Hawk realtime prompt visibility test",
      fileMeta: [],
      resumeSubmission,
    };

    await expect(
      __contentScriptTestHooks.handleDecision(
        { ...basePolicy, platform_mode: "discovery" },
        "chatgpt.com",
        action,
      ),
    ).resolves.toBeUndefined();

    expect(resumeSubmission).toHaveBeenCalledTimes(1);
    expect((globalThis as any).chrome.runtime.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "TELEMETRY_EVENT",
        payload: expect.objectContaining({
          event_type: "extension_health_status",
          status: "submission_resume_failed",
          last_error: "form_not_connected",
        }),
      }),
      expect.any(Function),
    );
  });
});

describe("content-script pilot signal payload quality", () => {
  it("adds identity, endpoint, browser, tab, and session linkage to AI UI detections", () => {
    const payload = __contentScriptTestHooks.buildPilotTelemetryPayload(
      {
        event_type: "ai_app_opened",
        action_taken: "chatgpt",
        input_signal_types: ["app_profile:chatgpt", "app_signal:known_domain"],
      },
      {
        domain: "chatgpt.com",
        url: "https://chatgpt.com/c/123",
        pageTitle: "ChatGPT",
        sessionId: "sess-page-123",
        tabId: "chatgpt.com:sess-page-123",
        identity: {
          user_id: "user-123",
          email: "analyst@example.com",
          machine_id: "ep_pilot_123",
          os_type: "mac",
          browser_type: "chrome",
          extension_version: "0.1.0",
          tab_id: "chatgpt.com:sess-page-123",
          extension_build_hash: "test-build-hash",
        },
      },
    );

    expect(payload).toMatchObject({
      event_type: "ai_app_opened",
      domain: "chatgpt.com",
      url: "https://chatgpt.com/c/123",
      page_title: "ChatGPT",
      source_surface: "browser_extension",
      source_surface_detail: "content_script",
      session_id: "sess-page-123",
      tab_id: "chatgpt.com:sess-page-123",
      user_id: "user-123",
      user_email: "analyst@example.com",
      machine_id: "ep_pilot_123",
      endpoint_id: "ep_pilot_123",
      browser: "chrome",
      browser_type: "chrome",
      os_type: "mac",
      extension_version: "0.1.0",
    });
    expect(payload.input_signal_types).toContain("session_linked");
    expect(payload.input_signal_types).toContain("endpoint_linked");
    expect(payload.input_signal_types).toContain("user_linked");
  });
});
