import type { ContextValidityState } from "./context-state-machine";

export type BrowserAiActionType =
  | "ai_app_opened"
  | "prompt_drafted"
  | "prompt_submitted"
  | "paste_into_ai_app"
  | "file_upload_attempted"
  | "policy_warned"
  | "policy_blocked";

export type AiActionDecision = "allow" | "warn" | "block" | "hold_for_backend" | "step_up" | "observe";

export type BrowserAiAction = {
  action_id: string;
  timestamp: string;
  user_id: string;
  machine_id: string;
  surface: "browser";
  application: string;
  action_type: BrowserAiActionType;
  input_ref?: string;
  content_signals: string[];
  policy_decision?: AiActionDecision;
  controls_triggered: string[];
  context_validity: ContextValidityState;
  automation_context?: {
    automation_suspected: boolean;
    confidence: number;
    indicators: string[];
  };
};

export function buildAiAction(input: {
  action_id: string;
  user_id: string;
  machine_id: string;
  application: string;
  action_type: BrowserAiActionType;
  input_ref?: string;
  content_signals?: string[];
  policy_decision?: AiActionDecision;
  controls_triggered?: string[];
  context_validity: ContextValidityState;
  automation_context?: {
    automation_suspected: boolean;
    confidence: number;
    indicators: string[];
  };
}): BrowserAiAction {
  return {
    action_id: String(input.action_id || ""),
    timestamp: new Date().toISOString(),
    user_id: String(input.user_id || ""),
    machine_id: String(input.machine_id || ""),
    surface: "browser",
    application: String(input.application || "unknown"),
    action_type: input.action_type,
    input_ref: input.input_ref ? String(input.input_ref) : undefined,
    content_signals: Array.from(new Set((input.content_signals || []).map((item) => String(item || "")).filter(Boolean))),
    policy_decision: input.policy_decision,
    controls_triggered: Array.from(
      new Set((input.controls_triggered || []).map((item) => String(item || "")).filter(Boolean)),
    ),
    context_validity: input.context_validity,
    automation_context: input.automation_context
      ? {
        automation_suspected: Boolean(input.automation_context.automation_suspected),
        confidence: Math.max(0, Math.min(1, Number(input.automation_context.confidence) || 0)),
        indicators: Array.from(
          new Set((input.automation_context.indicators || []).map((item) => String(item || "")).filter(Boolean)),
        ),
      }
      : undefined,
  };
}
