import { ActorType, Decision, DetectionConfidenceTier, Escalation, RiskTier, ThreatType } from "./core_types";

export type PolicyPackStatus = "draft" | "active" | "retired";

export type ConditionOperator =
  | "contains"
  | "regex"
  | "in"
  | "gt"
  | "lt"
  | "equals"
  | "not_equals";

export type Condition = {
  field: string;
  operator: ConditionOperator;
  value: string | number | boolean | string[];
  case_sensitive?: boolean;
};

export type GuardianTrigger = {
  signal_types: string[];
  conditions: Condition[];
};

export type GuardianEvaluation = {
  method: "rules" | "model_stub" | "hybrid";
  confidence_threshold: number;
};

export type GuardianDecision = {
  on_pass: "allow" | "warn";
  on_fail: "block" | "redact" | "hold_for_approval";
  on_uncertain: "warn" | "hold_for_approval";
};

export type GuardianActions = {
  redact: {
    fields: string[];
    strategy: "mask" | "remove" | "summarize";
  };
  mutate_output: {
    enabled: boolean;
    strategy: "restricted_template" | "safe_completion";
  };
  notify: {
    channels: Array<"email" | "slack" | "teams">;
  };
  create_ticket: {
    system: "jira" | "servicenow";
    severity: "low" | "med" | "high" | "critical";
  };
};

export type GuardianContract = {
  guardian_id: string;
  description: string;
  enabled: boolean;
  trigger: GuardianTrigger;
  evaluation: GuardianEvaluation;
  decision: GuardianDecision;
  actions: GuardianActions;
  evidence: {
    evidence_signal_type: string;
    link_to_controls: string[];
  };
  control_impact: {
    maturity_delta_on_fail: number;
    increase_simulation_frequency: boolean;
    enforcement_strictness_increase: 0 | 1 | 2;
  };
  approval_workflow?: {
    required_roles: Array<"owner" | "admin">;
    sla_minutes: number;
    default_if_timeout: "block" | "warn";
  };
};

export type PolicyPack = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  status: PolicyPackStatus;
};

export type PolicyVersion = {
  id: string;
  pack_id: string;
  version: string;
  created_at: string;
  created_by: string;
  scope: {
    applies_to_risk_tiers: RiskTier[];
    applies_to_ai_system_ids?: string[];
    applies_to_actor_types?: ActorType[];
  };
  enforcement_defaults: {
    default_decision: Decision;
    escalation: Escalation;
  };
  guardian_contracts: GuardianContract[];
};

export type GuardianResult = {
  guardian_id: string;
  decision: Decision;
  confidence: number;
  confidence_tier?: DetectionConfidenceTier;
  arbiter_invoked?: boolean;
  matched_conditions: string[];
  threat_types: ThreatType[];
  actions_taken: Record<string, unknown>;
};

export type EnforcementEvent = {
  id: string;
  tenant_id: string;
  ai_system_id: string;
  actor_type: ActorType;
  actor_id: string;
  request_id: string;
  timestamp: string;
  input: {
    prompt: string;
    context_summary: string;
    attachments_meta: Record<string, unknown>[];
  };
  guardian_results: GuardianResult[];
  final_decision: Decision;
  final_actions: Record<string, unknown>;
  evidence_nodes_created: string[];
  controls_impacted: Array<{ control_id: string; delta: number }>;
  audit_log_id: string;
};

export type GuardianPolicyScope = {
  ai_system_ids: string[];
  agent_ids: string[];
  user_groups: string[];
  environments: Array<"prod" | "staging" | "dev">;
};

export type GuardianPolicyConditions = {
  source: Record<string, unknown>;
  destination: Record<string, unknown>;
  action: Record<string, unknown>;
  data: Record<string, unknown>;
};

export type GuardianPolicyDecision = {
  mode: "allow" | "warn" | "block" | "require_justification" | "require_approval";
  confidence_threshold: number;
  strictness: "low" | "medium" | "high";
};

export type GuardianPolicyEnforcement = {
  fail_mode: "fail_secure" | "fail_open";
  log: boolean;
  create_finding: boolean;
  require_evidence: boolean;
};

export type GuardianPolicyGovernance = {
  risk_level: "low" | "medium" | "high" | "restricted";
  approval_required: boolean;
  policy_owner: string;
  review_cycle_days: number;
};

export type GuardianPolicyFrameworkMapping = {
  nist_ai_rmf: string[];
  iso_42001: string[];
  eu_ai_act: string[];
  owasp_genai: string[];
  mitre_atlas: string[];
  control_ids: string[];
};

export type GuardianPolicyMetadata = {
  created_at?: string;
  updated_at?: string;
  active: boolean;
};

export type GuardianContractCanonical = {
  policy_id: string;
  policy_name: string;
  policy_version: string;
  tenant_id: string;
  scope: GuardianPolicyScope;
  conditions: GuardianPolicyConditions;
  decision: GuardianPolicyDecision;
  enforcement: GuardianPolicyEnforcement;
  governance: GuardianPolicyGovernance;
  framework_mapping: GuardianPolicyFrameworkMapping;
  metadata: GuardianPolicyMetadata;
};
