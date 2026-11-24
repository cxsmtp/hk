export type RiskTier = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type TenantRole = "owner" | "admin" | "auditor" | "operator" | "viewer";

export type ActorType = "human" | "agent" | "system";

export type Decision = "allow" | "warn" | "block" | "redact" | "hold_for_approval";

export type DetectionConfidenceTier = "clear_negative" | "ambiguous" | "clear_positive";

export type ThreatType =
  | "prompt_injection"
  | "jailbreak"
  | "sensitive_data_leakage"
  | "tool_output_injection"
  | "agent_chain_abuse"
  | "ai_identity_misuse"
  | "action_auth_abuse"
  | "rag_poisoning"
  | "cross_context_leakage"
  | "output_asymmetry";

export type Escalation = "none" | "notify" | "ticket" | "approval_required";

export type Pagination = {
  page: number;
  page_size: number;
  total: number;
};

export type ApiResponse<T> = {
  data: T;
  meta?: Record<string, unknown>;
};
