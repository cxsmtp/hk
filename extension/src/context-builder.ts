import type { AppProfile } from "./app-profiles";
import type { BrowserAiActionType } from "./ai-action";
import type { ContextValidityState } from "./context-state-machine";

export type BrowserActionContext = {
  user: {
    user_id: string;
    email: string;
  };
  device: {
    machine_id: string;
    os_type: string;
    browser_type: string;
    extension_version: string;
  };
  app_context: {
    app_id: string;
    app_name: string;
    app_domain: string;
    app_risk_level: string;
  };
  page_context: {
    domain: string;
    url: string;
    title: string;
  };
  action_context: {
    action_type: BrowserAiActionType;
    input_method: string;
    content_length: number;
  };
  session_context: {
    session_id: string;
    started_at: string;
    tab_id: string;
  };
  policy_context: {
    policy_version: string;
    platform_mode: string;
  };
  context_validity_state: ContextValidityState;
};

export function buildBrowserActionContext(input: {
  user_id: string;
  email: string;
  machine_id: string;
  os_type?: string;
  browser_type?: string;
  extension_version?: string;
  app_profile: AppProfile;
  domain: string;
  url: string;
  page_title: string;
  action_type: BrowserAiActionType;
  input_method?: string;
  content_length: number;
  session_id: string;
  session_started_at: string;
  tab_id?: string | number | null;
  policy_version?: string;
  platform_mode?: string;
  context_validity_state: ContextValidityState;
}): BrowserActionContext {
  return {
    user: {
      user_id: String(input.user_id || ""),
      email: String(input.email || ""),
    },
    device: {
      machine_id: String(input.machine_id || ""),
      os_type: String(input.os_type || "unknown"),
      browser_type: String(input.browser_type || "chrome"),
      extension_version: String(input.extension_version || "unknown"),
    },
    app_context: {
      app_id: input.app_profile.app_id,
      app_name: input.app_profile.name,
      app_domain: String(input.domain || "").toLowerCase(),
      app_risk_level: input.app_profile.risk_level,
    },
    page_context: {
      domain: String(input.domain || "").toLowerCase(),
      url: String(input.url || ""),
      title: String(input.page_title || ""),
    },
    action_context: {
      action_type: input.action_type,
      input_method: String(input.input_method || "unknown"),
      content_length: Math.max(0, Number(input.content_length || 0)),
    },
    session_context: {
      session_id: String(input.session_id || ""),
      started_at: String(input.session_started_at || new Date().toISOString()),
      tab_id: String(input.tab_id ?? "unknown"),
    },
    policy_context: {
      policy_version: String(input.policy_version || "unknown"),
      platform_mode: String(input.platform_mode || "unknown"),
    },
    context_validity_state: input.context_validity_state,
  };
}
