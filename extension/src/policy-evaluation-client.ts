import type { AppProfile } from "./app-profiles";
import type { BrowserAiAction } from "./ai-action";
import type { BrowserActionContext } from "./context-builder";

export type PolicyEvaluationDecision = "allow" | "warn" | "block" | "step_up";

export type PolicyEvaluationResponse = {
  decision: PolicyEvaluationDecision;
  reason: string;
  policy_id: string;
  control_ids: string[];
  user_message: string;
  admin_summary: string;
  evidence_required: boolean;
  input_signal_types: string[];
  reason_codes: string[];
};

type RuntimeMessageSender = <T = any>(message: Record<string, unknown>) => Promise<T>;

export async function evaluatePolicyForAction(input: {
  postRuntimeMessage: RuntimeMessageSender;
  ai_action: BrowserAiAction;
  context: BrowserActionContext;
  content_signals: {
    signal_types: string[];
    categories: string[];
    risk_score: number;
    redacted_snippet: string;
  };
  app_profile: AppProfile;
  legacy_interaction_payload: Record<string, unknown>;
}): Promise<PolicyEvaluationResponse> {
  try {
    const v2Result = await input.postRuntimeMessage<{
      ok: true;
      result: PolicyEvaluationResponse;
    }>({
      type: "INTERACTION_EVALUATE",
      payload: {
        ai_action: input.ai_action,
        context: input.context,
        content_signals: input.content_signals,
        app_profile: input.app_profile,
        policy_version: input.context.policy_context.policy_version,
        legacy_interaction_payload: input.legacy_interaction_payload,
      },
    });

    if (v2Result?.result?.decision) {
      return normalizePolicyEvaluationResponse(v2Result.result);
    }
  } catch {
    // Fall through to legacy endpoint path.
  }

  const legacy = await input.postRuntimeMessage<{
    ok: true;
    result: {
      decision: "allow" | "warn" | "block";
      reason_codes?: string[];
      input_signal_types?: string[];
    };
  }>({
    type: "INTERACTION_EVAL",
    payload: input.legacy_interaction_payload,
  });

  const decision = normalizeDecision(legacy?.result?.decision);
  const reasonCodes = Array.isArray(legacy?.result?.reason_codes) ? legacy.result.reason_codes : [];
  const inputSignals = Array.isArray(legacy?.result?.input_signal_types) ? legacy.result.input_signal_types : [];
  const reason = reasonCodes.join(", ") || `${decision}_by_policy`;

  return normalizePolicyEvaluationResponse({
    decision,
    reason,
    policy_id: String(input.context.policy_context.policy_version || "unknown"),
    control_ids: [],
    user_message: defaultUserMessage(decision, reason),
    admin_summary: `Policy decision ${decision} from interaction evaluation.`,
    evidence_required: decision !== "allow",
    input_signal_types: inputSignals,
    reason_codes: reasonCodes,
  });
}

function normalizeDecision(value: unknown): PolicyEvaluationDecision {
  const raw = String(value || "").toLowerCase();
  if (raw === "allow") return "allow";
  if (raw === "block") return "block";
  if (raw === "step_up" || raw === "step-up" || raw === "stepup") return "step_up";
  return "warn";
}

function defaultUserMessage(decision: PolicyEvaluationDecision, reason: string): string {
  if (decision === "allow") {
    return "Action allowed by policy.";
  }
  if (decision === "warn") {
    return `This action may violate policy: ${reason}`;
  }
  if (decision === "step_up") {
    return "This action requires additional approval before it can continue.";
  }
  return `This action was blocked by policy: ${reason}`;
}

function normalizePolicyEvaluationResponse(input: PolicyEvaluationResponse): PolicyEvaluationResponse {
  const decision = normalizeDecision(input.decision);
  return {
    decision,
    reason: String(input.reason || `${decision}_by_policy`),
    policy_id: String(input.policy_id || "unknown"),
    control_ids: Array.from(new Set((input.control_ids || []).map((item) => String(item || "")).filter(Boolean))),
    user_message: String(input.user_message || defaultUserMessage(decision, String(input.reason || ""))),
    admin_summary: String(input.admin_summary || `Policy decision ${decision}.`),
    evidence_required: Boolean(input.evidence_required),
    input_signal_types: Array.from(
      new Set((input.input_signal_types || []).map((item) => String(item || "")).filter(Boolean)),
    ),
    reason_codes: Array.from(new Set((input.reason_codes || []).map((item) => String(item || "")).filter(Boolean))),
  };
}
