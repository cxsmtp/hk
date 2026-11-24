export type SimulationCategory =
  | "injection"
  | "leakage"
  | "agent_misuse"
  | "identity_abuse"
  | "rag_poisoning"
  | "output_safety"
  | "resource_abuse"
  | "infra_misconfig"
  | "output_injection";

export type TargetModule =
  | "interaction_security"
  | "shadow_ai"
  | "ai_iam"
  | "monitoring"
  | "auditor";

export type SimulationDef = {
  id: string;
  tenant_id: string;
  name: string;
  category: SimulationCategory;
  target_module: TargetModule;
  version: string;
  safety: {
    requires_sandbox: boolean;
    max_runtime_seconds: number;
    no_external_network: boolean;
  };
  inputs_schema: {
    fields: Array<{
      name: string;
      type: "string" | "number" | "boolean" | "object" | "array";
      required: boolean;
    }>;
  };
  steps: Array<{
    step_id: string;
    kind:
      | "llm_intercept"
      | "mcp_authorize"
      | "shadow_event_ingest"
      | "monitoring_signal"
      | "auditor_snapshot";
    payload_template: Record<string, unknown>;
    variable_bindings: Record<string, unknown>;
  }>;
  assertions: Array<{
    assertion_id: string;
    check: {
      field: string;
      operator: "equals" | "in" | "contains" | "gt" | "lt";
      value: unknown;
    };
    on_fail: {
      result: "fail";
      evidence_signal_type: string;
      severity: "low" | "med" | "high" | "critical";
    };
  }>;
  maps_to_controls: [string, ...string[]];
  deterministic_flag: boolean;
  safe_testing_boundaries: Record<string, unknown>;
  expected_outputs: Record<string, unknown>;
  pass_fail_criteria: {
    pass_conditions: string[];
    fail_conditions: string[];
  };
  evidence_emission_requirements: {
    required_signal_types: string[];
    min_evidence_nodes: number;
    require_audit_log: boolean;
  };
  expected_outcomes: {
    pass_conditions: string[];
    fail_conditions: string[];
  };
};

export type SimulationRun = {
  id: string;
  tenant_id: string;
  simulation_id: string;
  ai_system_id: string;
  started_at: string;
  finished_at?: string;
  mode: "deterministic" | "stochastic";
  inputs_used: Record<string, unknown>;
  results: {
    result: "pass" | "fail";
    failed_assertions: string[];
    failures: string[];
    enforcement_events_linked: string[];
    evidence_nodes_created: string[];
    evidence_node_ids: string[];
    pass_rate: number;
    passes: number;
    iterations: number;
    control_maturity_delta: Array<Record<string, unknown>>;
    enforcement_strictness_delta: Array<Record<string, unknown>>;
    iteration_outputs: Array<Record<string, unknown>>;
  };
  controls_impacted: Array<{
    control_id: string;
    contribution: number;
  }>;
  notes?: string;
};

export type Control = {
  id: string;
  tenant_id?: string;
  name: string;
  category: string;
  description: string;
  mapped_framework_refs: Array<{
    framework: string;
    control_ref: string;
  }>;
};
