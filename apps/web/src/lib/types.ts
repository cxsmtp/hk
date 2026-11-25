import type { ListEnvelope as SharedListEnvelope } from "@shared/schemas/api_envelopes";

export type ListEnvelope<T> = SharedListEnvelope<T>;

export type LoginResponse = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: {
    id: string;
    email: string;
    full_name: string;
  };
  tenants: Array<{ id: string; name: string; role: string }>;
  selected_tenant_id?: string;
  // A temporary password (the first administrator, or after reset_admin): a new one is chosen first.
  must_change_password?: boolean;
};

export type PlatformMode = "discovery" | "enforce";

export type PlatformModeResponse = {
  tenant_id: string;
  platform_mode: PlatformMode;
};

export type AISystem = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  risk_tier: string;
  status: string;
};

export type PolicyPack = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  status: string;
};

export type PolicyPackPlatformTemplate = {
  template_id: string;
  title: string;
  reason: string;
  condition_tree: Record<string, unknown>;
  decision: string;
  applicable_surfaces: string[];
  required_fields: string[];
  required_control_capabilities: string[];
  default_mode: string;
  recommended_mature_mode: string;
  criticality: string;
  override_behavior: string;
  exception_rules: Record<string, unknown>;
  simulation_expectations: Record<string, unknown>;
  evidence_requirements: string[];
  human_explanation: string;
  reference_mappings: Record<string, unknown>;
  non_overridable: boolean;
  explicit_revocation: boolean;
  source_pack?: {
    definition_id?: string | null;
    stable_pack_id: string;
    version: string;
    inherited: boolean;
  };
};

export type PolicyPackPlatformDefinition = {
  id: string;
  stable_pack_id: string;
  version: string;
  name: string;
  description: string;
  vertical: string;
  department_persona: string;
  pack_family: string;
  maturity_status: string;
  package_entitlement: string;
  applicable_jurisdictions: string[];
  framework_mappings: Record<string, unknown>;
  inherited_pack_refs: string[];
  required_signals: string[];
  required_control_capabilities: string[];
  supported_deployment_surfaces: string[];
  default_parameters: Record<string, unknown>;
  customization_schema: Record<string, unknown>;
  simulation_required: boolean;
  default_rollout: string;
  exception_guidance: string;
  known_blind_spots: string[];
  owner_publisher: string;
  release_notes: string;
  state: string;
  templates?: PolicyPackPlatformTemplate[];
  inherited_templates?: PolicyPackPlatformTemplate[];
  definition_lineage?: Array<{
    definition_id: string;
    stable_pack_id: string;
    version: string;
    publisher_ref: string;
    inherited: boolean;
  }>;
};

export type PolicyPackFrameworkAtlasItem = {
  framework_id: string;
  title: string;
  status: string;
  jurisdiction?: string;
  framework_family?: string;
  policy_pack_stable_ids: string[];
  policy_pack_definition_ids: string[];
  policy_pack_names: string[];
  verticals: string[];
  departments: string[];
  surfaces: string[];
  pack_families: string[];
  mapped_control_families?: string[];
  policy_recommendations?: string[];
  control_coverage?: {
    state: string;
    href?: string;
    note?: string;
  };
  simulation_links?: Array<{
    label: string;
    href: string;
  }>;
  evidence_requirements?: string[];
  evidence_href?: string;
  compliance_note?: string;
  recommended_action: string;
  claim_boundary: string;
};

export type PolicyPackFrameworkAtlas = {
  items: PolicyPackFrameworkAtlasItem[];
  count: number;
  disclaimer: string;
};

export type PolicyPackCapabilityCoverage = {
  surfaces: Array<{
    surface: string;
    visibility: string;
    warning: string;
    redaction: string;
    approval: string;
    pre_execution_block: string;
    post_execution_evidence: string;
    independent_verification: string;
    health: string[];
    known_blind_spots: string[];
  }>;
  verified_pre_execution_block_surfaces: string[];
  known_blind_spots: string[];
};

export type AIToolsUsageWorkspace = {
  tenant_id: string;
  generated_at: string;
  window: {
    record_count: number;
    provider_signal_record_count?: number;
    runtime_event_count?: number;
    runtime_projection_count?: number;
    bounded_limit: number;
    last_signal_at?: string | null;
  };
  overview: {
    providers_observed: number;
    active_users: number;
    departments: number;
    clients: number;
    prompts_observed: number;
    mcp_servers: number;
    source_coverage: string[];
    freshness: string;
  };
  providers: Array<{
    provider: string;
    connection_state: string;
    source_types: string[];
    products: string[];
    last_event_at?: string | null;
    freshness: string;
    capabilities: Record<string, string>;
    capability_note: string;
  }>;
  usage: Array<{
    provider: string;
    metric: string;
    unit: string;
    value: number | string;
  }>;
  spend_utilization: {
    totals_by_currency: Record<string, number | string>;
    records: Array<Record<string, unknown>>;
    cost_precedence: string[];
    mixed_currency_total: null;
    productivity_score_generated: false;
    seats: {
      total_licensed_seats: number;
      assigned_seats: number;
      active_seats: number;
      inactive_seats: number;
      never_used_seats: number;
      unknown_activity_seats: number;
      unassigned_seats: number;
      utilization_percent: number | string | null;
      authoritative_snapshot_count: number;
      snapshots: Array<{
        id: string;
        provider: string;
        product: string;
        billing_group?: string | null;
        total_licensed_seats: number;
        assigned_seats: number;
        active_seats: number;
        inactive_seats: number;
        never_used_seats: number;
        unknown_activity_seats: number;
        unassigned_seats: number;
        utilization_percent: number | string | null;
        observed_at: string;
        source_type: string;
        evidence_quality: string;
        completeness: "COMPLETE" | "PARTIAL" | "UNKNOWN";
        freshness: "CURRENT" | "STALE";
        status: "CURRENT" | "PARTIAL" | "STALE" | "UNKNOWN";
      }>;
      unavailable_reason?: string | null;
    };
  };
  mcp_tools: {
    summary: Record<string, number>;
    servers: Array<Record<string, unknown>>;
  };
  prompts_actions: {
    total: number;
    items: Array<Record<string, unknown>>;
    aggregate_only: boolean;
    raw_prompt_stored: false;
    privacy_levels: string[];
  };
  account_devices?: Record<string, unknown>;
  accounts_devices?: {
    source?: string;
    summary?: {
      observed_sessions?: number;
      account_classes?: string[];
      device_assurance?: string[];
      surfaces?: string[];
      clients?: string[];
    };
    items?: Array<{
      provider?: string;
      client?: string;
      account_type?: string;
      device_assurance?: string;
      surface?: string;
      last_event_at?: string | null;
    } & Record<string, unknown>>;
  };
  meeting_ai: Record<string, unknown>;
  data_controls: {
    classifications?: string[];
    classified_prompt_events?: number;
    upload_events?: number;
    download_events?: number;
    raw_values_exposed?: boolean;
  } & Record<string, unknown>;
  authoritative_source_readiness?: {
    overall_status: "AUTHORITATIVE" | "OBSERVED_ONLY" | "MISSING_SOURCE" | string;
    items: Array<{
      label: string;
      status: "AUTHORITATIVE" | "MISSING_SOURCE" | "PARTIAL_EVIDENCE" | string;
      required_sources: string[];
      observed_evidence: string[];
      connect_action: string;
      why_missing: string;
    }>;
    enterprise_denominator?: Record<string, unknown>;
    provider_billed_spend?: Record<string, unknown>;
    provider_admin_seat_utilization?: Record<string, unknown>;
    full_control_coverage?: Record<string, unknown>;
  };
  provider_source_profiles?: Record<string, {
    provider: string;
    overall_status: string;
    source_contract?: string;
    profiles: Array<{
      profile: string;
      status: string;
      cost_label: string;
      source_types: string[];
      required_credential: string;
      notes: string[];
    }>;
    connector_guidance?: Record<string, string>;
  }>;
  coverage_gaps: { status: string; gaps: string[] };
  connector_health: Array<Record<string, unknown>>;
  executive_report: Record<string, unknown>;
  governance: EnterpriseDeveloperAIControl;
};

export type BrowserExtensionHealthInstance = {
  extension_id?: string | null;
  extension_name?: string | null;
  extension_version?: string | null;
  browser?: string | null;
  browser_profile?: string | null;
  endpoint_id?: string | null;
  hostname?: string | null;
  healthy?: boolean | null;
  status?: string | null;
  last_heartbeat_at?: string | null;
  last_sync_at?: string | null;
  telemetry_queue_depth?: number | null;
  policy_version?: string | null;
  platform_mode?: string | null;
  last_error?: string | null;
};

export type BrowserExtensionTamperEvent = {
  classification: string;
  action?: string | null;
  control_state?: string | null;
  extension_id?: string | null;
  browser?: string | null;
  browser_profile?: string | null;
  endpoint_id?: string | null;
  hostname?: string | null;
  severity?: string | null;
  observed_at?: string | null;
};

export type BrowserExtensionHealth = {
  tenant_id: string;
  status: string;
  trusted_extension_id?: string | null;
  trusted_source: string;
  latest_heartbeat_at?: string | null;
  latest_status?: Record<string, unknown> | null;
  duplicate_extension_ids: string[];
  instances: BrowserExtensionHealthInstance[];
  tamper_events: BrowserExtensionTamperEvent[];
  limitations: string[];
};

export type BrowserExtensionRemovalGovernance = {
  tenant_id: string;
  status: string;
  admin_removal_required: boolean;
  hard_prevention_requires_mdm: boolean;
  trusted_extension_id?: string | null;
  trusted_source: string;
  last_heartbeat_at?: string | null;
  duplicate_extension_ids: string[];
  recent_tamper_events: BrowserExtensionTamperEvent[];
  controls: Array<{
    id: string;
    label: string;
    status: string;
    description: string;
    evidence: string[];
    required_owner: string;
  }>;
  mdm_policies: Array<{
    browser: string;
    status: string;
    enforcement_type: string;
    required_policy: string;
    purpose: string;
    trusted_extension_id?: string | null;
    policy_payload: Record<string, unknown>;
    limitations: string[];
  }>;
  admin_workflow: string[];
  audit_events: string[];
  limitations: string[];
};

export type EnterpriseDeveloperAIControl = {
  tenant_id: string;
  package_id: string;
  package_name: string;
  generated_at: string;
  policy: {
    mode: string;
    repository_identity: Record<string, unknown>;
    allowed_operations: string[];
    blocked_operations: string[];
    strict_failure_mode: string;
    full_content_retention: string;
  };
  summary: Record<string, number | string | null>;
  repository_card: Record<string, number | string | boolean | null>;
  repository_inventory?: {
    organizations: number;
    repositories: number;
    access_relations: number;
    direct_access: number;
    team_inherited_access: number;
    unknown_access: number;
    ai_connections: number;
    authoritative_denominator_available: boolean;
    blind_spots: string[];
  };
  developer_ai_setup?: {
    admin_flow: Array<{
      step: number;
      label: string;
      state: string;
      description: string;
    }>;
    approved_repository: GitHubRepositoryProjection | null;
    blocked_repository: {
      id: string | null;
      host?: string;
      full_name: string;
      policy_decision: string;
      reason: string;
      evidence_state: string;
      [key: string]: unknown;
    };
    ai_clients: Array<{
      ai_client: string;
      provider: string;
      model: string;
      repository: string | null;
      repository_id: string;
      tool_call: string;
      action: string;
      policy_decision: string;
      confidence: string;
      source_surface: string;
      evidence_refs: string[];
      action_count: number;
      last_seen_at: string | null;
    }>;
    allowed_actions: string[];
    blocked_actions: string[];
    test_prompts: {
      allow: string;
      block: string;
    };
    config_targets: Array<{
      client: string;
      config_type: string;
      repository_scope: string | null;
      status: string;
    }>;
    latest_decision: {
      repository: string | null;
      ai_client: string;
      provider: string;
      model: string;
      tool_call: string;
      action: string;
      policy_decision: string;
      evidence_refs: string[];
    } | null;
    evidence_state: {
      repositories: number;
      ai_connections: number;
      unauthorized_attempts: number;
      has_approved_repository: boolean;
      has_ai_connection_evidence: boolean;
    };
  };
  developer_counts_definition: Record<string, string>;
  provider_surface_coverage: Record<string, Record<string, string>>;
  provider_capability_manifests: Array<{
    provider: string;
    product: string;
    method: string;
    manifest_id: string;
    catalog_verification: string;
    tenant_state: string;
    validation_tier: string;
    exact_version?: string | null;
    evidence_at?: string | null;
    evidence_age_seconds?: number | null;
    dimensions: Record<string, string>;
    evidence_refs: string[];
    limitations: string[];
    prompt_content_access: string;
  }>;
  provider_usage_summary: Array<{
    provider: string;
    sessions: number;
    actions: number;
    active_users: number;
    models: string[];
    last_activity_at?: string | null;
    spend?: number | null;
    currency?: string | null;
    cost_source: string;
    productivity_score_generated: boolean;
  }>;
  account_device: Record<string, number | string | boolean>;
  control_coverage: Array<{ capability: string; state: string; explanation: string }>;
  unauthorized_attempts: Array<Record<string, unknown>>;
  prompt_visibility: Record<string, unknown>;
  usage_and_cost: Record<string, unknown>;
  meeting_ai: Record<string, unknown>;
  requirement_traceability: Record<string, {
    status: "PASS" | "PARTIAL" | "FAIL" | "UNVERIFIED";
    production_path: string;
    test_evidence: string;
    limitation: string;
  }>;
  limitations: string[];
};

export type GitHubRepositoryProjection = {
  id: string;
  host: string;
  repository_id: string;
  node_id: string | null;
  full_name: string;
  visibility: string;
  lifecycle_state: string;
  default_branch: string | null;
  protection: Record<string, unknown>;
  account_scope_kind: "ORGANIZATION" | "PERSONAL" | "UNKNOWN";
  deny_posture: "BLOCK_CHANGES" | "BLOCK_ALL" | null;
  evidence_state: string;
  governance_state: string;
  governance_version: number;
  approved_scope_ref: string | null;
  policy_mapping_ref: string | null;
  policy_current: boolean;
  read_posture: string;
  operation_controls: Record<"READ" | "EDIT" | "COMMIT" | "PULL" | "PUSH", "ALLOW" | "BLOCK">;
  first_seen_at: string | null;
  last_seen_at: string | null;
  last_verified_at: string | null;
};

export type GitHubRepositoryRuntimeBinding = {
  id: string;
  repository_id: string | null;
  native_integration_id: string;
  canonical_root_sha256: string;
  common_dir_sha256: string;
  scope: "EXACT_FOLDER";
  state: "OBSERVED" | "ACTIVE" | "REVOKED";
  signed_evidence_ref: string;
  actor_id: string | null;
  created_at: string | null;
  updated_at: string | null;
};

export type GitHubRepositoryAccessRelationship = {
  id: string;
  repository_id: string;
  external_principal_id: string;
  principal_type: string;
  permission: string;
  access_path: string;
  source_team_id: string | null;
  mapped_user_id: string | null;
  mapped_group_id: string | null;
  evidence_state: string;
  valid_until: string | null;
};

export type GitHubRepositoryAIConnection = {
  id: string;
  repository_id: string;
  user_id: string | null;
  ai_asset_id: string | null;
  ai_system_id: string | null;
  provider: string | null;
  model: string | null;
  client_name: string | null;
  agent_id: string | null;
  external_capability_id: string | null;
  mcp_server_id: string | null;
  tool_name: string | null;
  tool_schema_fingerprint: string | null;
  source_surface: string;
  relationship_state: string;
  confidence: string;
  evidence_refs: string[];
  action_count: number;
  first_seen_at: string | null;
  last_seen_at: string | null;
};

export type GitHubRepositoryInventoryPage<T = Record<string, unknown>> = {
  items: T[];
  next_cursor: string | null;
  limit: number;
};

export type GitHubRepositoryDetail = {
  repository: GitHubRepositoryProjection;
  access_relationships: GitHubRepositoryInventoryPage<GitHubRepositoryAccessRelationship>;
  ai_connections: GitHubRepositoryInventoryPage<GitHubRepositoryAIConnection>;
  runtime_bindings: GitHubRepositoryInventoryPage<GitHubRepositoryRuntimeBinding>;
};

export type HMAIRSourceConnectionCapability = {
  provider_key: "hmair_github_cloud" | "hmair_github_ghes" | "hmair_microsoft365_copilot";
  state: "not_connected" | "ready" | "partial" | "empty" | "stale" | "permission_denied" | "unsupported" | "failed";
  allowed_capabilities: string[];
  denominator: number | null;
  fresh_at: string | null;
  limitations: string[];
};

export type HMAIRSourceConnection = {
  connection_id: string;
  provider_key: HMAIRSourceConnectionCapability["provider_key"];
  display_name: string;
  status: string;
  account_scope_kind: "ORGANIZATION" | "PERSONAL" | "UNKNOWN";
  target: { target_id: string; target_type: string; environment: string };
  collector: { collector_id: string; collector_type: string; health: string };
  capability: HMAIRSourceConnectionCapability;
};

export type HMAIRSourceConnectionInput = {
  provider_key: HMAIRSourceConnectionCapability["provider_key"];
  display_name: string;
  target_identifier: string;
  environment: string;
  authorization_reference: string;
  requested_capabilities: string[];
  include_entra_account_evidence: boolean;
  metadata: Record<string, unknown>;
  credentials: Record<string, string>;
};

export type SourceConnectionSetupFamily = "github" | "m365_teams" | "identity" | "saas" | "cloud";

export type SourceConnectionSetupFlow = {
  family: SourceConnectionSetupFamily;
  title: string;
  summary: string;
  entrypoint_href: string;
  provider_keys: string[];
  visibility: string[];
  required_authority: string[];
  credential_requirements: string[];
  validation_mode: string;
  limitations: string[];
  status: "setup_required";
};

export type SourceConnectionSetupCatalog = {
  items: SourceConnectionSetupFlow[];
  total: number;
};

export type EnterpriseDenominatorState = "authoritative" | "partial" | "observed_only" | "missing";

export type EnterpriseDenominatorDomain =
  | "users"
  | "devices"
  | "browser"
  | "repositories"
  | "saas_apps"
  | "cloud_runtimes"
  | "models";

export type EnterpriseDenominatorItem = {
  domain: EnterpriseDenominatorDomain;
  label: string;
  state: EnterpriseDenominatorState;
  authoritative: boolean;
  required_source_family: SourceConnectionSetupFamily | null;
  required_source_title: string | null;
  connect_href: string;
  denominator: number | null;
  connection_count: number;
  fresh_at: string | null;
  evidence: string[];
  next_action: string;
  limitation: string;
};

export type EnterpriseDenominatorStatus = {
  overall_state: "authoritative" | "partial_authority" | "observed_only" | "missing_authoritative_sources";
  authoritative_denominator_complete: boolean;
  authoritative_count: number;
  total_domains: number;
  items: EnterpriseDenominatorItem[];
  how_to_get_full_authority: string[];
};

export type GitHubPersonalRepositoryDenyPosture = "BLOCK_CHANGES" | "BLOCK_ALL";

export type PolicyPackPlatformInstance = {
  id: string;
  definition_id: string;
  source_pack_id: string;
  source_pack_version: string;
  selected_vertical: string;
  selected_department_persona: string;
  selected_applications: string[];
  selected_surfaces: string[];
  customer_parameters: Record<string, unknown>;
  local_overrides: Record<string, unknown>;
  disabled_template_ids: string[];
  rollout: Record<string, unknown>;
  runtime_policy_pack_id?: string | null;
  effective_policy_version_id?: string | null;
  previous_effective_policy_version_id?: string | null;
  last_simulation_id?: string | null;
  update_available: boolean;
  owner_ref: string;
  approver_ref?: string | null;
  state: string;
  lineage: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
};

export type PolicyPackSimulation = {
  id: string;
  instance_id: string;
  policy_version_id?: string | null;
  sample_count: number;
  outcome_counts: Record<string, number>;
  scope_breakdown: Record<string, unknown>;
  status: string;
  evidence_refs: string[];
  created_at?: string;
};

export type PolicyVersion = {
  id: string;
  tenant_id: string;
  pack_id: string;
  version: string;
  created_at: string;
  scope: Record<string, unknown>;
  enforcement_defaults: Record<string, unknown>;
  guardian_contracts: Array<Record<string, unknown>>;
};

export type PolicyScopedRule = {
  rule_id: string;
  enabled: boolean;
  priority: number;
  description?: string;
  subjects?: {
    user_ids?: string[];
    roles?: string[];
    departments?: string[];
    actor_types?: string[];
    agent_ids?: string[];
    endpoint_ids?: string[];
    source_surfaces?: string[];
  };
  resources?: {
    ai_system_ids?: string[];
    domains?: string[];
    tools?: string[];
    providers?: string[];
    models?: string[];
  };
  condition_tree?: PolicyConditionTree;
  actions?: {
    types?: string[];
    operations?: string[];
  };
  conditions?: {
    data_classifications?: string[];
    risk_tiers?: string[];
    contains_sensitive?: boolean | null;
  };
  effect?: {
    decision?: "allow" | "warn" | "block" | "redact" | "require_approval" | "require_justification" | "hold_for_approval";
    reason_code?: string;
    explanation?: string;
    recommended_action?: string;
    priority?: number;
  };
  metadata?: Record<string, unknown>;
};

export type PolicyConditionTree =
  | { all: PolicyConditionTree[] }
  | { any: PolicyConditionTree[] }
  | { not: PolicyConditionTree }
  | { field: string; operator: "in" | "eq" | "contains"; value: string[] | string };

export type PolicyScopedRulesResponse = {
  policy_version_id: string;
  scoped_rules: PolicyScopedRule[];
  rule_count: number;
};

export type RunningPolicyStatus = {
  enforced_policy_version_id: string;
  platform_mode: string;
  active_pack_count: number;
  running_versions: Array<{
    id: string;
    pack_id: string;
    pack_name: string;
    pack_status: string;
    version: string;
    created_at: string;
    guardian_count: number;
    default_decision: string;
    escalation: string;
  }>;
};

export type EnforcementEvent = {
  id: string;
  tenant_id?: string;
  request_id: string;
  ai_system_id: string;
  final_decision: string;
  actor_type: string;
  actor_id: string;
  timestamp: string;
  correlation_id?: string | null;
  policy_version_id?: string | null;
  evidence_nodes_created?: string[];
  controls_impacted?: Array<Record<string, unknown>>;
  provider?: string | null;
  model?: string | null;
  model_version?: string | null;
  prompt_hash?: string | null;
  response_hash?: string | null;
  governance_version?: string | null;
  api_endpoint?: string | null;
  tool_name?: string | null;
  tool_category?: string | null;
  data_source?: string | null;
  chain_depth?: number | null;
  document_format?: "pdf" | "docx" | string | null;
  document_block_count?: number | null;
  reversible_masking?: {
    enabled: boolean;
    applied: boolean;
    restored: boolean;
    entity_type_counts: Record<string, number>;
    mapping_destroyed: boolean;
  };
};

export type LLMGatewayDocumentCompleteResponse = {
  file_name: string;
  media_type: string;
  content_base64?: string;
  document: {
    format: "pdf" | "docx";
    page_count: number | null;
    block_count: number;
  };
  hawk: {
    final_decision: string;
    provider_invoked: boolean;
    response_control_coverage: string;
    reversible_masking?: {
      enabled: boolean;
      applied: boolean;
      restored: boolean;
      entity_type_counts: Record<string, number>;
      mapping_destroyed: boolean;
    };
  };
};

export type ExtensionProviderEnforcementHint = {
  provider_id: string;
  provider_name: string;
  provider_type: string;
  trust_level: string;
  default_risk_hint: string;
  known_domains: string[];
  sanctioned_domains: string[];
  blocked_domains: string[];
  suggested_decision: "allow" | "warn" | "block" | "discover";
  browser_message: string;
  surface_policy_mode: string;
};

export type ExtensionPolicySync = {
  tenant_id: string;
  platform_mode: "discovery" | "enforce";
  policy_version: string;
  approved_domains: string[];
  blocked_domains: string[];
  warn_domains: string[];
  critical_domains: string[];
  unknown_domain_behavior: string;
  provider_enforcement_hints: ExtensionProviderEnforcementHint[];
  interaction_rules: {
    input_checks_enabled: boolean;
    output_checks_enabled: boolean;
    sensitive_patterns: string[];
    blocked_keywords: string[];
    high_risk_terms: string[];
    hold_for_backend_on_ambiguous: boolean;
    backend_allow_confirmation_enabled?: boolean;
  };
  browser_automation_control?: {
    policy_id: string;
    name: string;
    category: "BROWSER_AUTOMATION_CONTROL";
    mode: "monitor" | "warn" | "block";
    enabled: boolean;
    scope: {
      users: string[];
      groups: string[];
      tenant_id: string;
      surfaces: string[];
      domains_allowlist: string[];
      domains_blocklist: string[];
      url_patterns_allowlist: string[];
      url_patterns_blocklist: string[];
    };
    automation: {
      detection_required: boolean;
      confidence_threshold: number;
      sources: string[];
    };
    allowed_actions: string[];
    blocked_actions: string[];
    action_overrides: Array<{
      domain: string;
      allowed_actions: string[];
      blocked_actions: string[];
    }>;
    decisions: {
      on_allowed_browsing: string;
      on_automation_detected: string;
      on_blocked_domain: string;
      on_blocked_action: string;
      on_scope_violation: string;
      on_unknown_automation_source: string;
    };
  };
};

export type EvidenceNode = {
  id: string;
  node_type: string;
  signal_type: string;
  label: string;
  created_at: string;
};

export type ApprovalRequest = {
  id: string;
  status: string;
  ai_system_id: string;
  required_roles: string[];
  created_at: string;
  /** Present only on authority-schema V2 requests; required for an optimistic decision. */
  authority_schema_version?: string | null;
  /** Stored request version required by the V2 decision endpoint. */
  expected_version?: number | null;
  request_payload?: { schema_version?: string | null; expected_version?: number | null } | null;
};

export type AguiAction = {
  action_id: string;
  action_type: string;
  title: string;
  description: string;
  source_module: string;
  source_object_type: string;
  source_object_id: string;
  required_role: string[];
  decision_options: string[];
  requires_justification: boolean;
  requires_evidence_display: boolean;
  requires_diff_preview: boolean;
  side_effect_level: "read" | "analyze" | "recommend" | "write" | "enforce" | "export" | "admin";
  created_at: string;
  source_summary: string;
  proof_timeline_url?: string | null;
};

export type AguiDecision = {
  decision_id: string;
  action_id: string;
  decision: string;
  justification?: string | null;
  decided_by?: string | null;
  decided_at: string;
  correlation_id?: string | null;
  evidence_node_ids: string[];
  audit_log_id: string;
  source_module: string;
  source_object_type: string;
  source_object_id: string;
  source_summary: string;
  proof_timeline_url?: string | null;
};

export type AgentIdentity = {
  id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  status: string;
  max_chain_depth: number;
  owner_attested_at?: string | null;
  owner_attestation_expiry?: string | null;
  capability_inheritance?: boolean;
  action_scope?: string[];
  tool_registry?: string[];
  external_system_access?: string[];
  agent_type?: string;
  autonomy_level?: string;
};

export type AgentDetail = {
  id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  status: string;
  owner_attested_at?: string | null;
  owner_attestation_expiry?: string | null;
  max_chain_depth: number;
  capability_inheritance?: boolean;
  action_scope?: string[];
  tool_registry?: string[];
  external_system_access?: string[];
  agent_type?: string;
  autonomy_level?: string;
};

export type AIIAMIdentityProfile = {
  identity_id: string;
  type: "agent" | "user" | "service" | string;
  owner?: string | null;
  model?: string | null;
  environment: string[];
  permissions: {
    tools: string[];
    data: string[];
    actions: string[];
  };
  token_scope: string[];
  expiry?: string | null;
  status: string;
  risk_score: number;
  blast_radius_score: number;
  crq: {
    ALE: number;
    SLE: number;
    ARO: number;
    baseline_ALE: number;
    loss_reduction: number;
    remediation_cost: number;
    decision_impact_score: number;
    control_effectiveness: number;
  };
  risk_components: {
    privilege_score: number;
    behavior_anomaly_score: number;
    control_failure_score: number;
    exposure_score: number;
    simulation_failure_score: number;
  };
  token_control: {
    active_token_count: number;
    kill_switch_ready: boolean;
    rotation_recommended: boolean;
  };
  anomalies: {
    count: number;
    recent_high: number;
  };
  controls: {
    triggered_controls: string[];
    missed_controls: string[];
    failed_controls: number;
    total_controls_evaluated: number;
    effectiveness: number;
  };
  simulation: {
    total_runs: number;
    pass: number;
    fail: number;
    partial: number;
    not_executable: number;
    pass_rate: number;
  };
  exposure_context: Record<string, unknown>;
  graph_summary: Record<string, unknown>;
  owasp_summary: Record<string, unknown>;
  blast_radius?: Record<string, unknown> | null;
  lookback_hours: number;
  updated_at?: string | null;
};

export type RuntimeGraphEdge = {
  edge_id: string;
  relationship_type: string;
  source_node_type: string;
  source_node_id: string;
  target_node_type: string;
  target_node_id: string;
  evidence_node_id?: string | null;
  event_id?: string | null;
  created_at: string;
  payload: Record<string, unknown>;
};

export type RuntimeAgenticChainGraph = {
  chain_id: string;
  nodes: Array<{
    node_type: string;
    node_id: string;
    label?: string | null;
  }>;
  edges: RuntimeGraphEdge[];
  total_edges: number;
  events: Array<{
    id: string;
    event_type: string;
    action_id?: string | null;
    actor_type?: string | null;
    actor_id?: string | null;
    evidence_bundle_id?: string | null;
    created_at?: string | null;
  }>;
};

export type RuntimeAgenticChainEvidence = {
  chain_id: string;
  evidence_bundle_ids: string[];
  evidence: Array<{
    id: string;
    node_type: string;
    signal_type: string;
    label: string;
    payload: Record<string, unknown>;
    created_at?: string | null;
  }>;
};

export type RuntimeAgentGraph = {
  agent_id: string;
  nodes: Array<{
    node_type: string;
    node_id: string;
    label?: string | null;
  }>;
  edges: RuntimeGraphEdge[];
  total_edges: number;
  event_count: number;
  decision_counts: Record<string, number>;
  linked_ai_system_ids: string[];
  max_observed_chain_depth: number;
};

export type AgentTouchpointEdge = {
  id: string;
  source_node_type: string;
  source_node_id: string;
  target_node_type: string;
  target_node_id: string;
  edge_type: string;
  action_id?: string | null;
  chain_id?: string | null;
  risk_level?: string | null;
  control_mode?: string | null;
  evidence_bundle_id?: string | null;
  last_seen_at?: string | null;
};

export type AgentTouchpointNode = {
  id: string;
  node_type: string;
  node_id: string;
  incoming: number;
  outgoing: number;
  risk_levels: string[];
  control_modes: string[];
  evidence_count: number;
};

export type AgentTouchpointRiskBadge = {
  id: string;
  label: string;
  severity: string;
};

export type AgentTouchpointEvidenceSummary = {
  total_edges: number;
  edges_with_evidence: number;
  missing_evidence: number;
  completeness_score: number;
};

export type AgentTouchpointTimelineItem = {
  id: string;
  chain_id?: string | null;
  action_id?: string | null;
  event?: string | null;
  source: { type?: string | null; id?: string | null };
  target: { type?: string | null; id?: string | null };
  control_mode?: string | null;
  risk_level?: string | null;
  evidence_bundle_id?: string | null;
  evidence_linked: boolean;
  last_seen_at?: string | null;
};

export type AgentTouchpoints = {
  agent_id: string;
  edges: AgentTouchpointEdge[];
  nodes?: AgentTouchpointNode[];
  risk_badges?: AgentTouchpointRiskBadge[];
  evidence_summary?: AgentTouchpointEvidenceSummary;
  timeline?: AgentTouchpointTimelineItem[];
  total_edges: number;
};

export type AgentBlastRadius = {
  agent_id: string;
  reachable_tools_count: number;
  reachable_mcp_servers_count: number;
  reachable_saas_apps_count: number;
  reachable_repos_count: number;
  reachable_data_sources_count: number;
  high_risk_actions_count: number;
  persistent_side_effects_count: number;
  external_destinations_count: number;
  delegation_depth_max: number;
  data_access_score: number;
  tool_action_score: number;
  privilege_score: number;
  persistence_score: number;
  external_exfiltration_score: number;
  delegation_score: number;
  overall_blast_radius_score: number;
  snapshot_id?: string | null;
};

export type RuntimeContextNode = {
  id: string;
  type: string;
  entity_id: string;
  metadata: Record<string, unknown>;
  created_at?: string | null;
};

export type RuntimeContextEdge = {
  id: string;
  from_node: string;
  to_node: string;
  relation_type: string;
  chain_id?: string | null;
  parent_action_id?: string | null;
  created_at?: string | null;
};

export type RuntimeChainGraph = {
  nodes: RuntimeContextNode[];
  edges: RuntimeContextEdge[];
  risk_score: number;
};

export type RuntimeAgentChain = RuntimeChainGraph & {
  agent_id: string;
  chain_id?: string | null;
  event_count: number;
};

export type RuntimeTimelineEvent = {
  event_id: string;
  timestamp?: string;
  tenant_id: string;
  source_surface: string;
  ai_surface?: string | null;
  event_type: string;
  action_type?: string;
  ai_system_id?: string | null;
  application?: string | null;
  user_id?: string | null;
  user_email?: string | null;
  machine_id?: string | null;
  device_name?: string | null;
  os_type?: string | null;
  browser_type?: string | null;
  agent_id?: string | null;
  identity_type?: "user" | "agent" | "service" | string;
  provider?: string | null;
  model?: string | null;
  input_ref?: string | null;
  output_ref?: string | null;
  sensitivity_score?: number | null;
  policy_id?: string | null;
  policy_decision?: string;
  decision: string;
  control_triggered?: string[];
  reason_code?: string | null;
  anomaly_score?: number | null;
  finding_id?: string | null;
  related_event_ids?: string[];
  evidence_node_ids: string[];
  correlation_id?: string | null;
  chain_id?: string | null;
  context_id?: string | null;
  tool_name?: string | null;
  tool_category?: string | null;
  api_endpoint?: string | null;
  metadata?: Record<string, unknown> | null;
  risk_score: number;
  created_at: string;
};

export type BankingCoverageStatus =
  | "covered"
  | "not_covered"
  | "unknown"
  | "not_applicable";

export type BankingCoverageDimension = {
  status: BankingCoverageStatus;
  reason: string;
  evidence_refs: string[];
};

export type BankingTimelineEvent = {
  stage: string;
  state: "observed" | "pending" | "blocked" | "unknown";
  occurred_at: string;
  evidence_refs: string[];
};

export type BankingTransactionProjection = {
  tenant_id: string;
  ai_transaction_id: string;
  subject_reference: string;
  subject_type: string;
  agent_chain: string[];
  model: string;
  business_purpose: string;
  action_class: string;
  side_effect_class: string;
  tool_reference: string;
  tool_fingerprint_reference: string;
  policy_version: string;
  control_point_reference: string;
  action_schema: string;
  transport: string;
  target_class: string;
  destination_class: string;
  decision: string;
  selected_controls: string[];
  decision_receipt_ids: string[];
  execution_receipt_ids: string[];
  integrity_status: string;
  drift_flags: string[];
  finding_ids: string[];
  coverage: Record<string, BankingCoverageDimension>;
  coverage_complete: boolean;
  timeline: BankingTimelineEvent[];
};

export type BankingCisoTransactionSummary = {
  ai_transaction_id: string;
  agent_reference: string;
  tool_reference: string;
  transport: string;
  decision: string;
  integrity_status: string;
  coverage_complete: boolean;
};

export type BankingCisoSummary = {
  generated_at: string;
  evidence_window: string;
  scanned_canonical_node_count: number;
  truncated: boolean;
  observed_transaction_count: number;
  customer_facing_agents: string[];
  tool_references: string[];
  data_reach: string[];
  subject_boundary_status: "evidence_backed" | "gaps_present" | "unknown";
  inline_blockable_count: number;
  observe_only_count: number;
  consequential_transaction_count: number;
  execution_verified_count: number;
  consequential_execution_verified_percent: number | null;
  drifted_transaction_count: number;
  control_gaps: string[];
  recent_transactions: BankingCisoTransactionSummary[];
};

export type RuntimeTraceStep = {
  step_number: number;
  event_id: string;
  title: string;
  description: string;
  timestamp: string;
  ai_surface: string;
  action_type: string;
  policy_decision: string;
  controls_triggered: string[];
  user_id?: string | null;
  agent_id?: string | null;
  machine_id?: string | null;
  finding_id?: string | null;
  action_available: boolean;
};

export type RuntimePattern = {
  pattern_id: string;
  type: string;
  frequency: number;
  severity: string;
  affected_entities: Array<{
    entity_type: string;
    entity_id: string;
  }>;
  created_at: string;
  updated_at: string;
};

export type RuntimeRecommendation = {
  recommendation_id: string;
  event_id: string;
  ai_system_id?: string | null;
  recommendation_type: string;
  reason_code: string;
  priority: string;
  payload: Record<string, unknown>;
  status: string;
  created_at: string;
  applied_at?: string | null;
};

export type RuntimeStreamEventType =
  | "runtime.activity.created"
  | "runtime.chain.updated"
  | "runtime.pattern.detected"
  | "runtime.recommendation.created"
  | "runtime.risk.updated"
  | "runtime.stream.connected";

export type RuntimeStreamEvent = {
  event_type: RuntimeStreamEventType | string;
  tenant_id: string;
  created_at: number;
  payload: Record<string, unknown>;
};

export type RuntimeIntelligenceEvent = {
  event_id: string;
  tenant_id: string;
  source_surface: string;
  event_type: string;
  ai_system_id?: string | null;
  app_id?: string | null;
  user_id?: string | null;
  agent_id?: string | null;
  risk_tier?: string | null;
  policy_version_id?: string | null;
  governance_version?: string | null;
  severity?: string | null;
  confidence_tier?: string | null;
  evidence_node_ids: string[];
  correlation_id?: string | null;
  context_id?: string | null;
  chain_id?: string | null;
  parent_action_id?: string | null;
  entity_type?: string | null;
  entity_id?: string | null;
  risk_score: number;
  created_at: string;
  model_provider?: string | null;
  provider?: string | null;
  model_name?: string | null;
  model_version?: string | null;
  tool_name?: string | null;
  tool_category?: string | null;
  api_endpoint?: string | null;
  data_source?: string | null;
  response_size?: number | null;
  chain_depth?: number | null;
  parent_agent_id?: string | null;
  metadata: Record<string, unknown>;
};

export type RuntimeIntelligenceFinding = {
  finding_id: string;
  tenant_id: string;
  source_surface: string;
  ai_tool: string;
  ai_system_id?: string | null;
  user_id?: string | null;
  severity: "low" | "med" | "high" | "critical";
  finding_type: string;
  risk_category: string;
  status: "open" | "reviewing" | "resolved" | "accepted_risk";
  recommended_action: string;
  policy_version_id?: string | null;
  evidence_node_ids: string[];
  related_control_ids: string[];
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
};

export type RuntimeIntelligenceFindingsEnvelope = {
  items: RuntimeIntelligenceFinding[];
  total: number;
  page: number;
  page_size: number;
  recommendation_count: number;
};

export type RuntimeIntelligenceTrigger = {
  trigger_id: string;
  tenant_id: string;
  ai_system_id?: string | null;
  event_id?: string | null;
  reason_code: string;
  target_pack: string;
  related_control_ids: string[];
  evidence_node_ids: string[];
  correlation_id?: string | null;
  recommended_action: string;
  status: string;
  schedule_decision_id?: string | null;
  created_at: string;
  updated_at: string;
};

export type RuntimeIntelligenceRecommendation = {
  recommendation_id: string;
  tenant_id: string;
  event_id: string;
  ai_system_id?: string | null;
  recommendation_type: string;
  reason_code: string;
  priority: string;
  payload: Record<string, unknown>;
  status: string;
  created_at: string;
  applied_at?: string | null;
};

export type RuntimeAISystemGraph = {
  ai_system_id: string;
  nodes: Array<{
    node_type: string;
    node_id: string;
    label?: string | null;
  }>;
  edges: RuntimeGraphEdge[];
  total_edges: number;
};

export type RuntimeActionGraph = {
  action_id: string;
  runtime_event_id: string;
  ai_system_id?: string | null;
  nodes: Array<{
    node_type: string;
    node_id: string;
    label?: string | null;
  }>;
  edges: RuntimeGraphEdge[];
  total_edges: number;
};

export type RuntimeCanonicalAIAction = {
  actor?: {
    identity_id?: string;
    identity_type?: string;
    user_id?: string;
    agent_id?: string;
    session_id?: string;
    runtime_instance_id?: string;
    acting_on_behalf_of?: string;
    delegation_chain?: unknown[];
  };
  authority?: {
    authority_type?: string;
    authority_source?: string;
    authority_owner?: string;
    standing_privilege?: string;
    jit_grant_id?: string;
    permission_scope?: unknown[];
    verified?: boolean | "unknown";
  };
  purpose?: {
    tenant_sector?: string;
    business_function?: string;
    declared_purpose?: string;
    inferred_purpose?: string;
    purpose_confidence?: number | "unknown";
    business_relevance?: string;
    purpose_status?: string;
  };
  surface?: Record<string, unknown>;
  action?: {
    action_type?: string;
    action_category?: string;
    operation?: string;
    risk_level?: string;
    tool_name?: string;
    tool_version?: string;
    tool_fingerprint_id?: string;
    redacted_arguments?: unknown;
    parameter_hash?: string;
    target_resource?: string | null;
    target_resource_hash?: string;
    data_destination?: string | null;
    destination_hash?: string;
    side_effect_class?: string;
    persistent_side_effect?: boolean | "unknown" | null;
  };
  content?: {
    input_sensitivity?: string;
    output_sensitivity?: string;
    code_sensitivity?: string;
    sql_type?: string;
    secret_indicators?: unknown[];
    customer_data_indicators?: unknown[];
    taint_labels?: unknown[];
  };
  approval?: Record<string, unknown>;
  policy?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  [key: string]: unknown;
};

export type ActionIntegrityEvidence = {
  state: "OBSERVED" | "UNKNOWN";
  value: unknown;
  evidence_refs: string[];
  occurred_at: string | null;
  reason_code: string | null;
};

export type ActionIntegrityArrayEvidence = Omit<ActionIntegrityEvidence, "value"> & {
  value: unknown[];
};

export type ActionIntegrityContext = {
  actor_principal: ActionIntegrityEvidence;
  executing_identity: ActionIntegrityEvidence;
  represented_subjects: ActionIntegrityArrayEvidence;
  business_purpose: ActionIntegrityEvidence;
  authority: ActionIntegrityEvidence;
  delegation: ActionIntegrityEvidence;
};

export type ActionIntegrityAction = {
  operation: ActionIntegrityEvidence;
  tool_or_service: ActionIntegrityEvidence;
  safe_parameters: ActionIntegrityEvidence;
  resources: ActionIntegrityArrayEvidence;
  targets: ActionIntegrityArrayEvidence;
  destinations: ActionIntegrityArrayEvidence;
  values_or_quantities: ActionIntegrityArrayEvidence;
  side_effect: ActionIntegrityEvidence;
  persistence: ActionIntegrityEvidence;
  reversibility: ActionIntegrityEvidence;
};

export type ActionIntegrityControl = {
  requirements: ActionIntegrityArrayEvidence;
  control_plan: ActionIntegrityEvidence;
  mandatory_floors: ActionIntegrityArrayEvidence;
  assurance: ActionIntegrityEvidence;
  rejected_controls: ActionIntegrityArrayEvidence;
  blind_spots: ActionIntegrityArrayEvidence;
};

export type ActionIntegrityAuthorisation = {
  policy: ActionIntegrityEvidence;
  decision: ActionIntegrityEvidence;
  approval_request: ActionIntegrityEvidence;
  approval_binding: ActionIntegrityEvidence;
  decision_receipt: ActionIntegrityEvidence;
  execution_permits: ActionIntegrityArrayEvidence;
};

export type ActionIntegrityExecution = {
  observed_semantics: ActionIntegrityEvidence;
  execution_receipts: ActionIntegrityArrayEvidence;
  evidence_quality: ActionIntegrityEvidence;
  material_integrity: ActionIntegrityEvidence;
  execution_state: ActionIntegrityEvidence;
  drift_fields: ActionIntegrityArrayEvidence;
  outcome_integrity: ActionIntegrityEvidence;
};

export type ActionIntegrityDetail = {
  schema_version: string;
  identity: {
    runtime_event_id: string;
    tenant_id: string;
    action_id: string | null;
    canonical_action_id?: string | null;
    chain_id?: string | null;
    decision_receipt_id?: string | null;
    execution_receipt_ids?: string[];
    control_selection_action_id?: string | null;
    control_plan_id?: string | null;
    approval_request_id?: string | null;
    approval_binding_id?: string | null;
    execution_permit_ids?: string[];
    evidence_node_ids?: string[];
    finding_ids?: string[];
  };
  context: ActionIntegrityContext;
  action: ActionIntegrityAction;
  control: ActionIntegrityControl;
  authorisation: ActionIntegrityAuthorisation;
  execution: ActionIntegrityExecution;
  timeline: Array<{
    timeline_event_id: string;
    event_type: string;
    stage_ordinal: number;
    state: "OBSERVED" | "UNKNOWN" | "NOT_APPLICABLE";
    value?: unknown;
    occurred_at: string | null;
    sequence: number;
    source_authority_ref: string;
    evidence_node_ids: string[];
    api_references: Array<Record<string, unknown>>;
    browser_hrefs: Array<Record<string, unknown>>;
    reason_code: string | null;
  }>;
  api_references: Array<Record<string, unknown>>;
  browser_hrefs: Array<Record<string, unknown>>;
};

export type ActivityLineageCertainty = "CONFIRMED" | "CORRELATED" | "INFERRED" | "UNKNOWN";

export type ActivityLineageNode = {
  id: string;
  node_key: string;
  node_type: string;
  authority_type: string;
  authority_id: string;
  label: string;
  certainty: ActivityLineageCertainty;
  evidence_quality: string;
  evidence_refs: string[];
  safe_attributes: Record<string, unknown>;
  ordinal: number;
  occurred_at: string | null;
};

export type ActivityLineageEdge = {
  id: string;
  edge_key: string;
  from_node_id: string;
  to_node_id: string;
  edge_type: string;
  certainty: ActivityLineageCertainty;
  evidence_quality: string;
  evidence_refs: string[];
  safe_attributes: Record<string, unknown>;
  sequence: number;
  occurred_at: string | null;
};

export type ActivityLineageAnswer = {
  state: ActivityLineageCertainty | "UNKNOWN";
  value: unknown;
  evidence_refs: string[];
  reason_code: string | null;
};

export type ActivityLineageProjection = {
  schema_version: string;
  lineage: {
    id: string;
    lineage_key: string;
    source_watermark: string;
    status: "COMPLETE" | "PARTIAL";
    seed_action_id: string;
    seed_runtime_event_id: string;
    root_action_id: string;
    created_at: string | null;
  };
  nodes: ActivityLineageNode[];
  edges: ActivityLineageEdge[];
  authorised_vs_executed: {
    authorised: Record<string, { state: string; value: unknown; evidence_refs: string[]; reason_code: string | null }>;
    executed: Record<string, unknown> & { state?: string; evidence_refs?: string[] };
    result: string;
    drift_fields: string[];
    evidence_refs: string[];
  };
  control_assurance: Array<{
    assertion_id: string;
    capability: string;
    certainty: ActivityLineageCertainty;
    assurance_state?: string;
    last_validation_run_id?: string | null;
    last_validated_at?: string | null;
    fresh_until?: string | null;
  }>;
  findings: Array<{
    id: string;
    investigation_id: string;
    finding_type: string;
    severity: string;
    title: string;
    reason_code: string;
    status: string;
    lineage_node_ids: string[];
    lineage_edge_ids: string[];
    evidence_refs: string[];
  }>;
  questions: Record<string, ActivityLineageAnswer>;
  blind_spots: string[];
  bounds: { limit: number; returned_nodes: number; returned_edges: number; truncated: boolean };
};

export type RuntimeActionTrace = {
  action_id: string;
  runtime_event: Record<string, unknown>;
  ai_action: RuntimeCanonicalAIAction;
  canonical_ai_action?: RuntimeCanonicalAIAction | null;
  canonical_ai_action_status?: "verified" | "unavailable" | "invalid";
  policy_snapshot: Record<string, unknown>;
  decision_explanation: DecisionExplanation & Record<string, unknown>;
  evidence_bundle: Record<string, unknown>;
  decision_receipt: {
    receipt_id?: string;
    chain_id?: string;
    canonical_action_hash?: string;
    actor_hash?: string;
    authority_hash?: string;
    purpose_hash?: string;
    tool_fingerprint?: string;
    parameter_hash?: string;
    target_resource_hash?: string;
    destination_hash?: string;
    side_effect_class?: string;
    approval_binding_id?: string | null;
    approval_binding_status?: string;
    approved_by?: string | null;
    approval_expires_at?: string | null;
    policy_snapshot_id?: string;
    decision?: string;
    control_mode?: string;
    transformations?: unknown[];
    expires_at?: string;
    issued_at?: string;
    collector_id?: string;
    evidence_bundle_id?: string | null;
    evidence_node_id?: string | null;
    signature_present?: boolean;
    signature_verified?: boolean;
    signing_key_id?: string;
  };
  execution_receipt: {
    receipt_id?: string;
    decision_receipt_id?: string;
    execution_attempt_id?: string;
    actual_tool_fingerprint?: string;
    actual_parameter_hash?: string;
    actual_target_resource_hash?: string;
    actual_destination_hash?: string;
    actual_authority_hash?: string;
    actual_side_effect_class?: string;
    downstream_objects?: unknown[];
    execution_status?: string;
    executed_at?: string;
    collector_id?: string;
    evidence_node_id?: string | null;
    signature_present?: boolean;
    signature_verified?: boolean;
    signing_key_id?: string;
  };
  execution_integrity: {
    result_id?: string;
    decision_receipt_id?: string;
    execution_receipt_id?: string | null;
    execution_attempt_id?: string;
    result?: string;
    drift_fields?: string[];
    severity?: string;
    response_action?: string;
    evidence_bundle_id?: string | null;
    evaluated_at?: string;
    signature_present?: boolean;
    signature_verified?: boolean;
    signing_key_id?: string;
  };
  related_findings: Array<{
    finding_id: string;
    finding_type?: string | null;
    severity?: string | null;
    risk_category?: string | null;
    status?: string | null;
    decision?: string | null;
    evidence_status?: string | null;
    related_runtime_event_id?: string | null;
    evidence_node_ids?: string[];
    created_at?: string | null;
    updated_at?: string | null;
  }>;
  graph: {
    nodes: RuntimeActionGraph["nodes"];
    edges: RuntimeGraphEdge[];
    total_edges: number;
  };
  investigation_links: Record<string, string>;
};

export type ActivityAuditUser = {
  user_id: string;
  display_name: string;
  email: string;
  machine_id?: string | null;
  browser_type?: string | null;
  last_seen?: string | null;
  ai_activity_count?: number;
  department?: string | null;
  role?: string | null;
  status: string;
  risk_score: number;
  violation_count: number;
  deployment_surfaces: string[];
  first_seen_at?: string | null;
  last_seen_at?: string | null;
};

export type ActivityAuditEndpoint = {
  endpoint_id: string;
  user_id?: string | null;
  user_email?: string | null;
  user_display_name?: string | null;
  user_department?: string | null;
  user_role?: string | null;
  hostname?: string | null;
  device_type?: string | null;
  os_type?: string | null;
  os_name?: string | null;
  os_version?: string | null;
  browser_type?: string | null;
  browser_name?: string | null;
  browser_version?: string | null;
  extension_name?: string | null;
  extension_version?: string | null;
  ip_address?: string | null;
  location?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  status: string;
  metadata?: Record<string, unknown>;
};

export type ActivityAuditSession = {
  session_id: string;
  user_id?: string | null;
  endpoint_id?: string | null;
  source_surface: string;
  ai_app?: string | null;
  ai_model?: string | null;
  start_time?: string | null;
  end_time?: string | null;
  total_actions: number;
  risk_score: number;
  correlation_id?: string | null;
  metadata?: Record<string, unknown>;
};

export type ActivityAuditAlert = {
  alert_id: string;
  action_id: string;
  session_id?: string | null;
  user_id?: string | null;
  endpoint_id?: string | null;
  finding_id?: string | null;
  alert_type: string;
  severity: string;
  policy_reason?: string | null;
  enforcement_action: string;
  created_at?: string | null;
};

export type UserVisibilityPrompt = {
  content_access_level: "METADATA_ONLY" | "CLASSIFIED_SUMMARY" | "REDACTED_PREVIEW" | "CONTENT_UNAVAILABLE";
  storage_mode?: "full" | "redacted" | "hashed_only" | string | null;
  redacted_preview?: string | null;
  reason?: string | null;
  pii_detected?: boolean;
  sensitive_entities?: string[];
  data_classifications?: string[];
  prompt_hash?: string | null;
  created_at?: string | null;
};

export type ActivityAuditPromptPayload = UserVisibilityPrompt;

export type ActivityAuditAction = {
  action_id: string;
  session_id: string;
  timestamp?: string | null;
  action_type: string;
  ai_app?: string | null;
  ai_model?: string | null;
  data_classification?: string | null;
  sensitivity_score: number;
  policy_triggered?: string | null;
  enforcement_action: string;
  semantic_drift_score: number;
  risk_score: number;
  correlation_id?: string | null;
  runtime_event_id?: string | null;
  monitoring_signal_id?: string | null;
  audit_log_id?: string | null;
  evidence_node_id?: string | null;
  finding_id?: string | null;
  metadata?: Record<string, unknown>;
  prompt_payload?: ActivityAuditPromptPayload | null;
  alerts: ActivityAuditAlert[];
};

export type ActivityAuditTimeline = {
  user?: ActivityAuditUser | null;
  device?: ActivityAuditEndpoint | null;
  devices: ActivityAuditEndpoint[];
  sessions: ActivityAuditSession[];
  actions: ActivityAuditAction[];
  alerts: ActivityAuditAlert[];
  policies_triggered: string[];
  timeline: Array<{
    timestamp?: string | null;
    kind: string;
    action: ActivityAuditAction;
  }>;
  total_actions: number;
  page: number;
  page_size: number;
};

export type ActivityAuditUserDetail = {
  user?: ActivityAuditUser | null;
  machine_id?: string | null;
  browser_type?: string | null;
  last_seen?: string | null;
  ai_activity_count: number;
  recent_actions: ActivityAuditAction[];
};

export type ActivityAuditSearchResponse = {
  items: ActivityAuditAction[];
  total: number;
  page: number;
  page_size: number;
  query: Record<string, string | null | undefined>;
};

export type UserVisibilityAIUsage = {
  applications: string[];
  providers: string[];
  models: string[];
  agents: string[];
  tools: string[];
  account_classes: string[];
  prompt_request_count: number;
  action_count: number;
  sensitive_data_event_count: number;
  warning_approval_block_count: number;
};

export type UserVisibilityUser = {
  user_id: string;
  display_name?: string | null;
  email?: string | null;
  department?: string | null;
  role?: string | null;
  status?: string | null;
  deployment_surfaces: string[];
  last_ai_activity?: string | null;
  ai_usage: UserVisibilityAIUsage;
  maturity_stage: string;
  evidence_quality: string;
};

export type UserVisibilityAction = {
  action_id: string;
  timestamp?: string | null;
  user_id?: string | null;
  user_display_name?: string | null;
  department?: string | null;
  session_id?: string | null;
  action_class?: string | null;
  application?: string | null;
  model?: string | null;
  provider?: string | null;
  source_surface?: string | null;
  account_class?: string | null;
  agent?: string | null;
  tool?: string | null;
  destination?: string | null;
  represented_subject?: string | null;
  resource?: string | null;
  target?: string | null;
  side_effect?: string | null;
  data_classification?: string | null;
  decision?: string | null;
  executing_principal?: string | null;
  approval?: string | null;
  execution_result?: string | null;
  evidence_quality?: string | null;
  policy_pack?: string | null;
  control_point?: string | null;
  drift?: string | null;
  policy_triggered?: string | null;
  integrity?: string | null;
  control_state?: string | null;
  prompt_payload?: UserVisibilityPrompt | null;
  alerts: Array<{ alert_id: string; severity: string; alert_type: string; enforcement_action: string }>;
  receipt_refs: Record<string, string | null | undefined>;
  lineage_refs: Record<string, string | null | undefined>;
  metadata: Record<string, string | number | boolean>;
};

export type UserVisibilityDepartment = {
  department: string;
  user_count: number;
  action_count: number;
  last_ai_activity?: string | null;
};

export type UserVisibilityOrganization = {
  lookback_hours: number;
  user_count: number;
  action_count: number;
  applications: Array<{ name: string; count: number }>;
  evidence_quality: string;
};

export type UserVisibilityDirectorySummary = {
  known_user_count: number;
  active_ai_user_count: number;
  personal_account_user_count: number;
  blocked_action_user_count: number;
  policy_gap_user_count: number | null;
  evidence_quality: string;
  generated_at?: string | null;
};

export type UserVisibilityExperienceSection<T = Record<string, unknown>> = {
  section: string;
  data: T;
};

export type UserVisibilityPolicyStackEntry = {
  assignment_id: string;
  instance_id: string;
  assignment_key: string;
  targets: Record<string, unknown>;
  precedence_layer: number;
  inherited_path: string[];
  active: boolean;
  assignment_kind: "direct" | "inherited" | "pack" | "exception" | string;
  scope_explanation: string;
  requires_action_context: boolean;
  source_pack?: string | null;
  source_pack_version?: string | null;
  pack_instance_state?: string | null;
  selected_surfaces?: string[];
  parameter_override_keys?: string[];
  has_customer_parameters?: boolean;
  update_available?: boolean;
};

export type UserVisibilityPolicyStack = {
  user_id: string;
  group_refs: string[];
  entries: UserVisibilityPolicyStackEntry[];
  effective_policy: Record<string, unknown>;
  final: {
    decision?: string | null;
    source_pack?: string | null;
    assignment_scope?: Record<string, unknown> | null;
    inherited_path?: string[];
    customer_override?: boolean;
    exception?: string | null;
    final_precedence?: string | number | null;
    matched_control_point?: string[] | string | null;
    rule_id?: string | null;
  };
  matched: boolean;
  explanation?: string | null;
  matched_selectors: string[];
};

export type UserVisibilityGroup = {
  group_id: string;
  group_key: string;
  name: string;
  group_type: string;
  source_ref?: string | null;
  active: boolean;
  member_count: number;
  policy_pack_assignments: Array<{ assignment_id: string; assignment_key: string; instance_id: string; active: boolean }>;
};

export type UserVisibilityGroupDetail = UserVisibilityGroup & {
  membership_rule: Record<string, unknown>;
  nested_group_ids: string[];
  member_ids: string[];
  member_count: number;
  member_page: number;
  member_page_size: number;
  audit_refs: Array<{ audit_log_id: string; action: string; actor_user_id?: string | null; created_at?: string | null }>;
};

export type UserVisibilityUser360 = {
  user: Omit<UserVisibilityUser, "ai_usage" | "maturity_stage" | "evidence_quality">;
  ai_usage: {
    action_count: number;
    prompt_request_count?: number;
    applications: Array<{ name: string; count: number }>;
    policy_outcomes: Record<string, number>;
  };
  recent_actions: UserVisibilityAction[];
  recent_actions_total: number;
  identity_groups?: { group_refs: string[]; department?: string | null; deployment_surfaces?: string[] };
  prompt_request_summary?: { prompt_request_count: number; content_access_levels: string[] };
  data_destinations?: { data_classifications: string[]; destinations: string[] };
  policies?: { group_refs: string[]; pack_assignments: Array<Record<string, unknown>>; effective_policy: Record<string, unknown> };
  approvals_exceptions?: { approval_states: string[]; exception_state: string };
  controls_evidence?: { evidence_quality: string; receipt_refs: Array<Record<string, string | null | undefined>> };
  lineage?: { recent_action_refs: Array<Record<string, string | null | undefined>> };
  trends?: { window: string; status: string };
};

export type UserVisibilityRevealGrant = {
  grant_id: string;
  action_id: string;
  purpose: string;
  expires_at: string;
};

export type UserVisibilityAccessGrant = {
  grant_id: string;
  user_id: string;
  capabilities: string[];
  department_scope: string[];
  expires_at?: string | null;
  active: boolean;
};

export type UserVisibilityRevealedPrompt = {
  action_id: string;
  content: string;
  expires_at: string;
};

export type AuditEvidenceExplanation = {
  evidence_id: string;
  decision: string;
  reason: string;
  violated_policy: {
    policy_version_id?: string | null;
    policy_version?: string | null;
    policy_pack_id?: string | null;
    policy_pack_name?: string | null;
  };
  confidence_score: number;
  framework_mapping: Array<{
    framework: string;
    controls: string[];
  }>;
  signal_type: string;
  label: string;
  correlation_id?: string | null;
  created_at: string;
  trace: {
    enforcement_event_id?: string | null;
    runtime_event_id?: string | null;
  };
};

export type Connector = {
  id: string;
  name: string;
  connector_type: string;
  provider_key: string;
  auth_type: string;
  enabled: boolean;
  status: string;
  is_stub: boolean;
  stub_reason: string;
  last_pull_status: string;
  last_pull_error?: string | null;
  last_signal_count: number;
  polling_interval_minutes: number;
  has_secrets: boolean;
  last_run_at?: string | null;
};

export type ConnectorCoverageState = "covered" | "not_covered" | "unknown";

export type ConnectorEvaluation = {
  connector: {
    id: string;
    provider_key: string;
    connector_type: string;
    name: string;
    enabled: boolean;
    status: string;
    is_stub: boolean;
    stub_reason: string;
    last_pull_status: string;
    last_pull_error?: string | null;
    has_secrets: boolean;
  };
  latest_pull: {
    status: string;
    normalized_signal_count: number;
    correlation_id?: string | null;
    evidence_root_id?: string | null;
    error?: string | null;
    created_at: string;
  } | null;
  connector_path: {
    mode: string;
    discovery: ConnectorCoverageState;
    authorization: ConnectorCoverageState;
    prove: ConnectorCoverageState;
  };
  browser_path: {
    canonical_domain?: string | null;
    search_status: "complete" | "truncated";
    mode: string;
    discovery: ConnectorCoverageState;
    authorization: ConnectorCoverageState;
    prove: ConnectorCoverageState;
  };
  latest_browser_action: {
    event_id: string;
    source: string;
    application?: string | null;
    domain?: string | null;
    action_type?: string | null;
    reason?: string | null;
    control_mode: string;
    decision_badge?: string | null;
    decision?: string | null;
    user?: string | null;
    correlation_id?: string | null;
    evidence_node_ids: string[];
    evidence_linked: boolean;
    evidence_link_count: number;
    evidence_integrity_status: string;
    created_at: string;
  } | null;
  evidence: {
    root_id?: string | null;
    integrity_status: string;
    count: number;
    items: Array<{
      id: string;
      node_type: string;
      signal_type: string;
      correlation_id?: string | null;
      created_at: string;
    }>;
  };
  limitations: string[];
};

export type MicrosoftPermissionMode = {
  mode: string;
  label: string;
  description: string;
  application_scopes: string[];
  optional_scopes: string[];
};

export type MicrosoftScopeResolution = {
  provider_key: string;
  permission_mode: string;
  required_scopes: string[];
  optional_scopes: string[];
  selected_scopes: string[];
  security_profile: Record<string, unknown>;
};

export type MicrosoftConsentUrlResponse = {
  consent_url: string;
  tenant_id: string;
  client_id: string;
  redirect_uri: string;
};

export type MicrosoftAppRegistrationTemplate = {
  app_registration_mode: string;
  oauth_supported: string[];
  required_fields: string[];
  credential_options: string[];
  admin_consent_required_for_application_permissions: boolean;
  graph_resource: string;
  security_baseline: Record<string, unknown>;
};

export type ConnectorBootstrapResponse = {
  provider_key: string;
  connector_id?: string | null;
  created: boolean;
  updated: boolean;
  install_url?: string | null;
  consent_url?: string | null;
  required_scopes: string[];
  selected_scopes: string[];
  connector?: Connector | null;
};

export type HmairScanStatus =
  | "queued"
  | "running"
  | "partially_complete"
  | "complete"
  | "failed"
  | "cancelled";

export type HmairDiscoveryScan = {
  scan_id: string;
  name: string;
  scan_type:
    | "full_enterprise"
    | "targeted"
    | "incremental"
    | "verification"
    | "scheduled"
    | "collector_specific";
  status: HmairScanStatus;
  safety_profile: string;
  dry_run: boolean;
  observations_count: number;
  warnings: string[];
  errors: string[];
  coverage_summary: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
};

export type EndpointMetadataInventoryRun = {
  id: string;
  status:
    | "queued"
    | "running"
    | "complete"
    | "partially_complete"
    | "failed"
    | "cancelled"
    | "expired"
    | string;
  endpoint_denominator: number;
  pending_count: number;
  delivered_count: number;
  completed_count: number;
  failed_count: number;
  expired_count: number;
  cancelled_count: number;
  expires_at: string;
  limitations: string[];
};

export type HmairCollectorSummary = {
  collector_id: string;
  collector_type: string;
  version: string;
  health: "healthy" | "warning" | "degraded" | "offline" | "unknown";
  supported_targets: string[];
  active_capabilities: string[];
  passive_capabilities: string[];
  limitations: string[];
  enabled: boolean;
};

export type HmairTargetSummary = {
  target_id: string;
  target_type: string;
  identifier: string;
  environment: string;
  owner_hint: string | null;
  permitted_methods: string[];
  exclusions: string[];
  rate_limit: number;
  active_scan_allowed: boolean;
  sensitive_scope: boolean;
  last_scanned_at: string | null;
};

/** Bounded, metadata-only production Deep Scan selection. */
export type DeepScanPreflightRequest = {
  target_ids: string[];
  collector_ids: string[];
  required_target_ids: string[];
  time_window_minutes: number;
  customer_authorization_reference: string;
  requested_mode: "partial" | "full_enterprise";
};

export type DeepScanSourceReadiness = {
  target_id: string;
  collector_id: string;
  target_type: string;
  required: boolean;
  readiness:
    | "ready"
    | "partial"
    | "not_connected"
    | "unsupported"
    | "permission_denied"
    | "stale"
    | "degraded"
    | "unknown"
    | string;
  observation_mode: "authoritative" | "observed_only" | string;
  expected_count: number | null;
  last_success_at: string | null;
  limitations: string[];
};

export type DeepScanPreflight = {
  profile_digest: string;
  preflight_digest: string;
  mode: "partial" | "full_enterprise" | string;
  sources: DeepScanSourceReadiness[];
  required_gaps: string[];
  ready_assignment_count: number;
  exhaustive_claim_permitted: boolean;
};

export type DeepScanLaunchRequest = {
  name: string;
  preflight: DeepScanPreflightRequest;
  preflight_digest: string;
  dry_run: boolean;
};

export type DeepScanLaunch = {
  scan: HmairDiscoveryScan;
  profile_digest: string;
  preflight_digest: string;
  ready_assignment_count: number;
  exhaustive_claim_permitted: boolean;
};

export type DeepScanCoverageSource = {
  target_id: string;
  collector_id: string;
  target_type: string;
  required: boolean;
  readiness: string;
  observation_mode: string;
  expected_count: number | null;
  coverage_state: string;
  observed_count: number;
  evidence_fresh_at: string | null;
  limitation: string[];
  reason: string | null;
};

export type DeepScanCoverage = {
  scan_id: string;
  status: string;
  mode: "partial" | "full_enterprise" | string;
  profile_digest: string;
  exhaustive_claim_permitted: boolean;
  sources: DeepScanCoverageSource[];
};

export type DiscoveryAssetSummary = {
  asset_id: string;
  asset_type: string;
  canonical_name: string;
  provider: string | null;
  product: string | null;
  framework: string | null;
  version: string | null;
  deployment_family: string | null;
  technical_surface: string | null;
  environment: string | null;
  approved_status: string;
  lifecycle_status: string;
  shadow_ai_status: string;
  resolution_state: "confirmed" | "probable" | "ambiguous" | string;
  resolution_confidence: number;
  resolution_methodology_id: string;
  usage_state: "never_observed" | "historical" | "occasional" | "active" | "high_usage" | "unknown" | string;
  usage_verification_state: string;
  shadow_type: string | null;
  owner_state: string;
  capabilities_count: number;
  identities_count: number;
  reachability_count: number;
  findings_open: number;
  first_seen_at: string;
  last_seen_at: string;
};

export type DiscoveryUsageFact = {
  usage_fact_id: string;
  actor_type: string;
  actor_reference_hash: string | null;
  usage_state: string;
  event_count: number;
  first_observed_at: string | null;
  last_observed_at: string | null;
  source_surface: string;
  evidence_node_id: string;
  confidence: number;
  verification_state: string;
  freshness: string;
  telemetry_complete: boolean;
  methodology_id: string;
  limitations: string[];
};

export type DiscoveryCapability = {
  capability_id: string;
  name: string;
  state: string;
  confidence: number;
  verification_state: string;
  freshness: string;
  observed_usage: boolean;
  declared_only: boolean;
  inferred_only: boolean;
  evidence_claim_id: string;
};

export type DiscoveryReachability = {
  reachability_id: string;
  target_category: string;
  target_reference_hash: string;
  state: string;
  confidence: number;
  verification_state: string;
  freshness: string;
  observed_usage: boolean;
  evidence_node_id: string;
  limitations: string[];
};

export type DiscoveryIdentityLink = {
  identity_link_id: string;
  identity_type: string;
  identity_reference_hash: string;
  access_state: string;
  usage_proven: boolean;
  confidence: number;
  verification_state: string;
  evidence_node_id: string;
};

export type DiscoveryOwnership = {
  ownership_assertion_id: string;
  owner_type: string;
  owner_reference_hash: string | null;
  state: string;
  confidence: number;
  verification_state: string;
  evidence_node_id: string;
};

export type DiscoveryShadowClassification = {
  classification_id: string;
  management_class: string;
  shadow_type: string;
  severity: string;
  confidence: number;
  verification_state: string;
  evidence_node_ids: string[];
  first_observed_at: string;
  last_observed_at: string;
  methodology_id: string;
  limitations: string[];
};

export type DiscoveryIntelligenceFinding = {
  finding_id: string;
  asset_id: string;
  finding_type: string;
  severity: string;
  confidence: number;
  verification_state: string;
  evidence_node_ids: string[];
  first_seen_at: string;
  last_seen_at: string;
  remediation: string;
  verification_action: string;
  coverage_impact: string;
  occurrence_count: number;
  status: string;
};

export type DiscoveryAssetDetail = {
  asset: DiscoveryAssetSummary;
  usage: DiscoveryUsageFact[];
  capabilities: DiscoveryCapability[];
  reachability: DiscoveryReachability[];
  identities: DiscoveryIdentityLink[];
  ownership: DiscoveryOwnership[];
  shadow_classifications: DiscoveryShadowClassification[];
  findings: DiscoveryIntelligenceFinding[];
};

export type DiscoveryAssetEvidence = {
  observation_id: string;
  observed_at: string;
  source_surface: string;
  observation_type: string;
  candidate_asset_type: string;
  observed_state: string;
  evidence_reference: string;
  evidence_hash: string;
  signature_status: string;
  confidence: number;
  freshness: string;
  verification_state: string;
  source_trust: string;
  evidence_mode: string;
  contradiction_state: string;
  link_kind: string;
  link_sequence: number;
};

export type DiscoveryAssetEvidenceList = {
  items: DiscoveryAssetEvidence[];
  total: number;
  next_cursor: string | null;
};

export type DiscoveryAssetHistory = {
  history_event_id: string;
  event_type: string;
  reversal_of_event_id: string | null;
  actor_role: string;
  reason: string;
  evidence_claim_id: string;
  member_role: string;
  member_ordinal: number;
  created_at: string;
};

export type ExposureExtent = "none" | "limited" | "material" | "broad" | "unknown";
export type ExposureVerificationStatus =
  | "verified"
  | "partially_verified"
  | "inferred"
  | "contradicted"
  | "stale"
  | "unknown";
export type ExposureFreshness = "fresh" | "stale" | "expired" | "unknown";
export type ExposureCalculationStatus = "complete" | "partial" | "unavailable";
export type ExposureDimension =
  | "capability"
  | "data"
  | "runtime"
  | "provider"
  | "model"
  | "identity"
  | "permission"
  | "reachability"
  | "usage"
  | "governance"
  | "control_coverage"
  | "ai_action";

export type ExposureFactor = {
  dimension: ExposureDimension;
  source_type: string;
  source_id: string;
  state: string;
  evidence_refs: string[];
  related_source_refs: string[];
  confidence: number | null;
  verification_status: ExposureVerificationStatus;
  freshness: ExposureFreshness;
  observed_at: string | null;
  validated_at: string | null;
  methodology_id: string;
  collector_group: string | null;
  limitations: string[];
};

export type ExposureCoverageDimension = {
  state: "covered" | "not_covered" | "unknown" | "not_applicable";
  path_ids: string[];
  assertion_ids: string[];
  control_mode: string | null;
  external_control_dependency: string | null;
  blind_spots: string[];
  freshness: ExposureFreshness;
};

export type ExposureCoverageProjection = {
  discover: ExposureCoverageDimension;
  authorize: ExposureCoverageDimension;
  prove: ExposureCoverageDimension;
  contain: ExposureCoverageDimension;
};

export type ExposureRecommendation = {
  recommendation_id: string;
  capability: string;
  governance_action: string;
  affected_category_id: string;
  reason: string;
  target_control_path: string;
  prerequisites: string[];
  expected_effect: string;
  product_route: string;
  source_refs: string[];
};

export type ExposureConclusion = {
  category_id: string;
  category_version: string;
  label: string;
  extent: ExposureExtent;
  proven_lower_bound: ExposureExtent | null;
  capability_refs: string[];
  data_refs: string[];
  runtime_refs: string[];
  provider_refs: string[];
  model_refs: string[];
  identity_refs: string[];
  permission_refs: string[];
  reachability_refs: string[];
  usage_refs: string[];
  governance_state: string;
  confidence: number | null;
  evidence_count: number;
  evidence_refs: string[];
  evidence_quality: number | null;
  verification_status: ExposureVerificationStatus;
  collector_diversity: number;
  last_validation: string | null;
  contributors: ExposureFactor[];
  contradictions: ExposureFactor[];
  unknown_dimensions: ExposureDimension[];
  reasoning_trace: string[];
  coverage: ExposureCoverageProjection;
  recommendations: ExposureRecommendation[];
  limitations: string[];
};

export type ExposureProjection = {
  asset_id: string;
  as_of: string;
  calculation_status: ExposureCalculationStatus;
  reasoning_methodology_id: string;
  reasoning_rule_version: string;
  category_catalog_version: string;
  source_input_digest: string;
  exposures: ExposureConclusion[];
  extent_distribution: Record<ExposureExtent, number>;
  unknown_dimensions: ExposureDimension[];
  failed_authorities: string[];
  conflicts: string[];
  limitations: string[];
  truncated: boolean;
};

export type ExposureTimelineEntry = {
  event_id: string;
  event_type:
    | "exposure_increased"
    | "exposure_reduced"
    | "exposure_verified"
    | "exposure_changed"
    | "exposure_coverage_improved"
    | "exposure_coverage_reduced"
    | "recommendation_generated";
  category_id: string;
  occurred_at: string;
  before_extent: ExposureExtent | null;
  after_extent: ExposureExtent | null;
  changed_factors: string[];
  source_event_refs: string[];
  evidence_refs: string[];
  confidence: number | null;
  limitations: string[];
};

export type ExposureTimelineResponse = {
  asset_id: string;
  as_of: string;
  calculation_status: ExposureCalculationStatus;
  reasoning_methodology_id: string;
  reasoning_rule_version: string;
  category_catalog_version: string;
  source_input_digest: string;
  items: ExposureTimelineEntry[];
  total: number;
  page: number;
  page_size: number;
  failed_authorities: string[];
  limitations: string[];
  truncated: boolean;
};

export type ExposureGraphNode = {
  node_id: string;
  node_type: string;
  source_type: string;
  source_id: string;
  label: string;
  verification_status: ExposureVerificationStatus;
  evidence_refs: string[];
  limitations: string[];
};

export type ExposureGraphEdge = {
  edge_id: string;
  edge_type: string;
  source_node_id: string;
  target_node_id: string;
  source_refs: string[];
  evidence_refs: string[];
  verification_status: ExposureVerificationStatus;
  limitations: string[];
};

export type ExposureGraphResponse = {
  asset_id: string;
  category_id: string;
  as_of: string;
  calculation_status: ExposureCalculationStatus;
  reasoning_methodology_id: string;
  reasoning_rule_version: string;
  category_catalog_version: string;
  source_input_digest: string;
  graph: { nodes: ExposureGraphNode[]; edges: ExposureGraphEdge[]; truncated: boolean };
  failed_authorities: string[];
  limitations: string[];
  truncated: boolean;
};

export type DiscoveryEstateSummary = {
  assets_total: number;
  confirmed_assets: number;
  probable_assets: number;
  ambiguous_assets: number;
  active_assets: number;
  shadow_assets: number;
  personal_assets: number;
  unowned_assets: number;
  open_findings: number;
  providers: number;
  environments: number;
  unknown_denominator: boolean;
  denominator_explanation: string;
  generated_at: string;
};

export type DiscoveryEcosystem = {
  ecosystem_id: string;
  provider: string;
  environment: string;
  asset_count: number;
  active_count: number;
  shadow_count: number;
  finding_count: number;
  asset_ids: string[];
  asset_types: string[];
  confidence: number;
  resolution_method: string;
  evidence_refs: string[];
  discovery_sources: string[];
  first_seen_at: string;
  last_seen_at: string;
  limitations: string[];
  enrichment: Record<string, unknown>;
  algorithm_version: string;
};

export type ERGEcosystemSummary = {
  ecosystem_id: string;
  canonical_name: string;
  ecosystem_class: string;
  lifecycle_state: string;
  resolution_state: string;
  confidence: number | null;
  evidence_quality: number | null;
  capability_genome_id: string | null;
  member_count: number;
  outstanding_contradictions: number;
  limitations: string[];
  last_validated_at: string;
  methodology_id: string;
  methodology_version: string;
};

export type ERGEcosystemDetail = ERGEcosystemSummary & {
  why: {
    statement: string;
    confidence: number | null;
    evidence_quality: number | null;
    methodology_id: string;
    methodology_version: string;
    contributors: Array<Record<string, unknown>>;
    limitations: string[];
  };
  members: Array<Record<string, unknown>>;
  relationships: Array<Record<string, unknown>>;
  contradictions: Array<Record<string, unknown>>;
  recent_changes: Array<Record<string, unknown>>;
  recommended_actions: string[];
  verification: Record<string, unknown>;
};

export type ERGTimeline = {
  items: Array<{
    event_id: string;
    event_type: string;
    drift_category: string;
    source_type: string;
    source_reference: string;
    occurred_at: string;
    changed_resolution: boolean;
    ecosystem_ids: string[];
    evidence_references: string[];
    summary: string;
    before: Record<string, unknown>;
    after: Record<string, unknown>;
  }>;
  total: number;
};

export type VerificationOutcome =
  | "verified"
  | "failed"
  | "contradicted"
  | "unsupported"
  | "unknown";

export type DiscoveryVerificationStage =
  | "observed"
  | "candidate"
  | "hypothesis"
  | "verification"
  | "verified"
  | "continuously_validated";

export type EcosystemVerificationProjection = {
  ecosystem_id: string;
  stage: DiscoveryVerificationStage;
  limitations: string[];
  required_outcomes: VerificationOutcome[];
  optional_outcomes: VerificationOutcome[];
  assertion_id: string | null;
  assertion_current: boolean;
  last_validation_at: string | null;
  next_validation_at: string | null;
  verification_coverage: number;
  verification_quality: number | null;
  evidence_quality: number | null;
  collector_diversity: number;
  erg_evaluation_id: string | null;
  confidence: number | null;
};

export type EcosystemVerificationHistory = {
  ecosystem_id: string;
  episodes: Array<{
    episode_id: string;
    sequence: number;
    environment: string;
    trigger: string;
    started_at: string;
    due_at: string;
    expires_at: string;
    limitations: string[];
  }>;
  tasks: Array<{
    task_id: string;
    episode_id: string;
    requirement_record_id: string;
    requirement_id: string;
    required: boolean;
    evidence_class: string;
    task_type: string;
    method: string;
    status: string;
    attempt_count: number;
    expires_at: string;
  }>;
  results: Array<{
    result_id: string;
    episode_id: string;
    requirement_record_id: string;
    requirement_id: string;
    required: boolean;
    evidence_class: string;
    outcome: VerificationOutcome;
    integrity_state: string;
    freshness: string;
    source_identity: string;
    collector_id: string | null;
    validated_at: string;
    expires_at: string;
    limitations: string[];
  }>;
  assertions: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
};

export type VerificationPlanResponse = {
  episode_id: string;
  ecosystem_id: string;
  task_count: number;
  unsupported_result_count: number;
  required_requirement_ids: string[];
  task_requirement_ids: string[];
  unsupported_requirement_ids: string[];
};

export type UnknownAIItem = {
  subject_id: string;
  subject_kind: string;
  label: string;
  probable_type: string;
  confidence: number;
  verification_state: string;
  freshness: string;
  contradiction_state: string;
  evidence_node_id: string;
  required_action: string;
  last_seen_at: string;
};

export type DiscoveryCollectorHealth = {
  collector_id: string;
  collector_type: string;
  version: string;
  status: string;
  last_success_at: string | null;
  last_failure_at: string | null;
  lag_seconds: number | null;
  supported_targets: string[];
  permissions_required: string[];
  limitations: string[];
  data_residency: string;
  control_capability: string;
};

export type DiscoveryCoverageDimension = {
  name: string;
  covered_count: number;
  not_covered_count: number;
  unknown_count: number;
  covered_asset_ids: string[];
  not_covered_asset_ids: string[];
  unknown_asset_ids: string[];
  score: number | null;
  score_withheld_reason: string | null;
  methodology: string;
  evidence_refs: string[];
  missing_evidence: string[];
  improvement_actions: string[];
};

export type DiscoveryCoverageProjection = {
  tenant_id: string;
  methodology_version: string;
  generated_at: string;
  denominator: {
    status: "known" | "inferred" | "inaccessible" | "stale" | "unknown" | string;
    known_assets: number;
    unresolved_hypotheses: number;
    inaccessible_sources: number;
    stale_sources: number;
    unknown_sources: string[];
    unsupported_sources: string[];
    enterprise_denominator_complete: boolean;
    evidence_ref: string | null;
    explanation: string;
  };
  dimensions: Record<string, DiscoveryCoverageDimension>;
  relationships: Array<Record<string, unknown>>;
  gap_candidates: Array<Record<string, unknown>>;
  limitations: string[];
};

export type DiscoveryScanEstimate = {
  target_count: number;
  collector_count: number;
  eligible_assignment_count: number;
  unsupported_pairs: Array<{ target_id: string; collector_id: string }>;
  permission_gaps: Array<Record<string, unknown>>;
  required_permissions: string[];
  safety_profile: string;
  exhaustive_claim_permitted: boolean;
  limitations: string[];
};

export type DiscoveryScanProgress = {
  scan_id: string;
  status: string;
  assignments_total: number;
  assignments_by_state: Record<string, number>;
  completion_percent: number;
  observations_count: number;
  assets_linked: number;
  findings_open: number;
  warnings: string[];
  errors: string[];
};

export type DiscoveryScanResults = {
  scan_id: string;
  status: string;
  asset_ids: string[];
  result_truncated: boolean;
  observations_count: number;
  assets_created: number;
  assets_updated: number;
  assets_unresolved: number;
  findings_open: number;
  completion_confidence: string;
  unsupported_sources: string[];
  unknown_sources: string[];
  exhaustive_claim_permitted: boolean;
  breadth: DiscoveryScanBreadth;
};

export type DiscoveryScanBreadth = {
  total_assets: number;
  active_users: number;
  shadow_ai: number;
  models: number;
  agents: number;
  mcp: number;
  developer_ai: number;
  saas_ai: number;
  ai_enabled_data: number;
  runtimes: number;
  unknown_candidates: number;
  assets_by_type: Record<string, number>;
  assets_by_surface: Record<string, number>;
  findings_by_type: Record<string, number>;
  control_coverage_state: string;
  blind_spots: string[];
};

export type DiscoveryScanSourceDiagnostic = {
  assignment_id: string;
  target_id: string;
  target_type: string;
  collector_id: string;
  collector_type: string;
  collector_health: string;
  assignment_status: string;
  supported: boolean;
  active_scan_allowed: boolean;
  permission_gaps: string[];
  target_exclusions: string[];
  limitations: string[];
  observations_count: number;
  warning: string | null;
  error: string | null;
};

export type DiscoveryScanDiagnostics = {
  scan_id: string;
  assignments_total: number;
  healthy_sources: number;
  warning_sources: number;
  degraded_sources: number;
  unsupported_sources: number;
  permission_denied_sources: number;
  sources: DiscoveryScanSourceDiagnostic[];
  limitations: string[];
};

export type DiscoveryApplication = {
  id: string;
  tenant_id: string;
  tool_key: string;
  tool_name: string;
  vendor: string;
  status: "discovered" | "monitoring" | "approved" | "blocked";
  owner_user_id?: string | null;
  owner_department?: string | null;
  owner_label?: string | null;
  provisional_risk_tier?: string | null;
  ai_system_id?: string | null;
  first_seen_at: string;
  last_seen_at: string;
  risk_score: number;
  findings_total: number;
  findings_open: number;
  recommended_action: string;
  metadata_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type TelemetryImportResult = {
  preview: boolean; total: number; matched: number; imported: number; duplicates: number;
  unmatched: number; outside_window: number; coverage_percent: null; limitations: string[];
  observations: Array<{ tool_name: string; domain: string; process_name: string; observed_at: string;
    observation_state: string; entity_id?: string; signal_id?: string; evidence_id?: string }>;
};

export type ShadowAISignal = {
  id: string;
  tenant_id: string;
  shadow_ai_entity_id?: string | null;
  source_surface: "browser" | "gateway" | "connector" | "aiiam" | "monitoring" | "endpoint" | "dns" | "proxy";
  source_event_id: string;
  domain?: string | null;
  provider?: string | null;
  model_name?: string | null;
  tool_name?: string | null;
  api_endpoint?: string | null;
  user_id?: string | null;
  agent_id?: string | null;
  confidence_signal: Record<string, unknown>;
  raw_fingerprint: Record<string, unknown>;
  created_at: string;
};

export type ShadowAIEntity = {
  id: string;
  tenant_id: string;
  canonical_name: string;
  discovery_status: "discovered" | "reconciled" | "promoted" | "rejected";
  confidence_score: number;
  confidence_level: "low" | "medium" | "high";
  provisional_risk_tier?: string | null;
  source_surfaces: string[];
  vendor?: string | null;
  deployment_type?: string | null;
  ai_type?: string | null;
  first_seen: string;
  last_seen: string;
  linked_ai_system_id?: string | null;
  approved_status: "approved" | "unapproved" | "unknown" | string;
  risk_score: number;
  usage_count: number;
  unique_users: number;
  endpoints_count: number;
  signal_count: number;
  open_findings: number;
  metadata_json: Record<string, unknown>;
  contributing_surfaces?: string[];
  observed_domains?: string[];
  observed_processes?: string[];
  observed_providers?: string[];
  first_seen_by_surface?: Record<string, string>;
  last_seen_by_surface?: Record<string, string>;
  health_status_summary?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type ShadowAIEntityDetail = ShadowAIEntity & {
  signals: ShadowAISignal[];
  linked_findings: string[];
  evidence_node_ids: string[];
  observed_domains: string[];
  observed_providers: string[];
  observed_tools: string[];
  usage_by_user: Array<{
    user_id: string;
    count: number;
    last_seen?: string | null;
    high_sensitivity_events?: number;
  }>;
  usage_by_endpoint: Array<{
    endpoint_id: string;
    count: number;
    last_seen?: string | null;
    high_sensitivity_events?: number;
  }>;
  recent_usage: Array<{
    usage_id: string;
    timestamp?: string | null;
    interaction_type: string;
    user_id?: string | null;
    endpoint_id?: string | null;
    session_id?: string | null;
    sensitivity_detected: boolean;
    policy_triggered?: string | null;
    metadata?: Record<string, unknown>;
  }>;
};

export type DriftAlert = {
  id: string;
  tenant_id: string;
  ai_system_id?: string | null;
  title: string;
  status: string;
  details: string;
  created_at: string;
  updated_at: string;
};

export type Finding = {
  finding_id: string;
  tenant_id: string;
  ai_action_id?: string | null;
  source_surface: string;
  ai_tool: string;
  ai_system_id?: string | null;
  user_id?: string | null;
  agent_id?: string | null;
  machine_id?: string | null;
  department?: string | null;
  severity: "low" | "med" | "high" | "critical";
  finding_type: string;
  risk_category: string;
  data_classification?: string | null;
  browser_type?: string | null;
  application?: string | null;
  decision?: string | null;
  evidence_status?: string | null;
  status: "open" | "reviewing" | "resolved" | "accepted_risk";
  recommended_action: string;
  policy_id?: string | null;
  policy_version_id?: string | null;
  control_mode?: string | null;
  decision_badge?: string | null;
  policy_snapshot?: Record<string, unknown>;
  decision_explanation?: DecisionExplanation | Record<string, unknown>;
  evidence_bundle?: Record<string, unknown>;
  evidence_node_ids: string[];
  related_runtime_event_id?: string | null;
  related_event_ids?: string[];
  related_control_ids: string[];
  related_trace_ids?: string[];
  recommended_actions?: string[];
  action_panel?: FindingActionPanelItem[];
  drilldowns?: FindingDrilldown[];
  chain_replay?: ChainReplay | null;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
};

export type ChainReplayCompleteness = {
  has_finding: boolean;
  has_action: boolean;
  has_policy: boolean;
  has_chain: boolean;
  has_evidence: boolean;
  has_trace: boolean;
};

export type ChainReplayItem = {
  stage: string;
  title: string;
  status: string;
  timestamp?: string | null;
  summary: string;
  references: Record<string, unknown>;
  href?: string | null;
  control_mode?: string | null;
  decision?: string | null;
};

export type ChainReplay = {
  finding_id: string;
  chain_id?: string | null;
  root_action_id?: string | null;
  control_mode?: string | null;
  decision?: string | null;
  integrity_status: string;
  completeness: ChainReplayCompleteness;
  items: ChainReplayItem[];
};

export type FindingDrilldown = {
  type: string;
  label: string;
  href: string;
  enabled?: boolean;
  reason?: string | null;
};

export type FindingActionPanelItem = {
  action: string;
  label: string;
  method: string;
  endpoint?: string | null;
  enabled: boolean;
  context?: Record<string, unknown>;
};

export type RuntimeTrace = {
  trace_key: string;
  trace_key_type: string;
  event_count: number;
  events: RuntimeTimelineEvent[];
  steps?: RuntimeTraceStep[];
};

export type FindingValidationRunItem = {
  simulation_id: string;
  simulation_name: string;
  run_id: string;
  result: "pass" | "fail" | "partial" | "not_executable";
  pass_rate: number;
  evidence_node_ids: string[];
  control_maturity_delta: Array<Record<string, unknown>>;
  enforcement_strictness_delta: Array<Record<string, unknown>>;
};

export type FindingValidationPackResponse = {
  finding_id: string;
  ai_system_id: string;
  total_runs: number;
  runs: FindingValidationRunItem[];
};

export type FindingTicketResponse = {
  finding: Finding;
  ticket_id: string;
  ticket_system: string;
  severity: "low" | "med" | "high" | "critical";
  created_at: string;
};

export type NotetakerPlatformActionRequest = {
  endpoint_id?: string;
  hostname?: string;
  platform: string;
  action: string;
  meeting_id?: string | null;
  participant_id?: string | null;
  organizer_user_id?: string | null;
  notetaker_email?: string | null;
  notetaker_label?: string | null;
};

export type NotetakerPlatformActionResponse = {
  status: string;
  platform: string;
  provider_control_path: string;
  action: string;
  control_mode: string;
  performed: boolean;
  reason: string;
  graph_operation?: Record<string, unknown> | null;
  status_code?: number | null;
  evidence_node_id?: string | null;
  audit_log_id?: string | null;
};

export type FindingTraceability = {
  finding: Finding;
  chain_replay?: ChainReplay | null;
  discovery_application?: {
    id: string;
    tool_key: string;
    tool_name: string;
    vendor: string;
    status: "discovered" | "monitoring" | "approved" | "blocked";
    owner_user_id?: string | null;
    owner_department?: string | null;
    provisional_risk_tier?: string | null;
    ai_system_id?: string | null;
    first_seen_at: string;
    last_seen_at: string;
  } | null;
  policy_version?: {
    id: string;
    version: string;
    pack_id: string;
    pack_name?: string | null;
    created_at: string;
  } | null;
  evidence_nodes: Array<{
    id: string;
    correlation_id?: string | null;
    node_type: string;
    signal_type: string;
    label: string;
    payload: Record<string, unknown>;
    created_at: string;
  }>;
  related_controls: Array<{
    id: string;
    name: string;
    category: string;
    description: string;
    mapped_framework_refs: Array<Record<string, unknown>>;
  }>;
  enforcement_events: Array<{
    id: string;
    correlation_id?: string | null;
    request_id: string;
    timestamp: string;
    final_decision: string;
    policy_version_id?: string | null;
    evidence_nodes_created: string[];
    controls_impacted: Array<Record<string, unknown>>;
    audit_log_id: string;
  }>;
  simulation_runs: Array<{
    id: string;
    simulation_id: string;
    started_at: string;
    finished_at?: string | null;
    mode: string;
    result: "pass" | "fail" | "partial" | "not_executable";
    pass_rate: number;
    evidence_node_ids: string[];
    control_maturity_delta: Array<Record<string, unknown>>;
    enforcement_strictness_delta: Array<Record<string, unknown>>;
  }>;
  maturity_effects: Array<{
    control_id: string;
    maturity_score: number;
    status: string;
    confidence_score: number;
    technical_enforcement_score: number;
    simulation_pass_rate: number;
    coverage_score: number;
    updated_at: string;
  }>;
  auditor_snapshots: Array<{
    id: string;
    ai_system_id?: string | null;
    trigger_type: string;
    artifact_path: string;
    artifact_hash: string;
    created_at: string;
  }>;
  gateway_traces?: Array<Record<string, unknown>>;
  recommended_actions?: string[];
  action_panel?: FindingActionPanelItem[];
  proof_timeline: Array<{
    step: number;
    title: string;
    status: "complete" | "partial" | "missing";
    timestamp?: string | null;
    summary: string;
    references: Record<string, unknown>;
  }>;
};

export type Control = {
  id: string;
  tenant_id: string;
  name: string;
  category: string;
  description: string;
  mapped_framework_refs: Array<Record<string, unknown>>;
  risk_tags?: string[];
  severity?: string;
  enforcement_points?: string[];
  detection_methods?: string[];
  response_actions?: string[];
  evidence_types?: string[];
  remediation_templates?: string[];
  is_global: boolean;
  success_criteria?: Record<string, unknown>;
};

export type ControlExplorerState = {
  tenant_id: string;
  foundation_only?: boolean;
  foundation_control_ids?: string[];
  framework_catalog: Array<{ framework: string; framework_key?: string; domain: string }>;
  legacy_aliases: Record<string, string>;
  total_controls: number;
  category_counts: Record<string, number>;
  framework_counts: Record<string, number>;
  crq_summary?: {
    risk_exposure_usd: number;
    risk_reduced_usd: number;
    at_risk_if_ignored_usd: number;
  };
  controls: Array<{
    control_id: string;
    control_name: string;
    category: string;
    description: string;
    frameworks: Array<Record<string, unknown>>;
    risk_tags: string[];
    severity: string;
    enforcement_points: string[];
    detection_methods: string[];
    response_actions: string[];
    evidence_types: string[];
    remediation_templates: string[];
    simulation_count: number;
    simulation_run_count: number;
    simulation_pass_rate_percent: number;
    runtime_trigger_count?: number;
    runtime_miss_count?: number;
    risk_event?: Record<string, unknown>;
    control_risk_profile?: {
      control_id: string;
      baseline_risk: number;
      current_risk: number;
      risk_reduction: number;
      confidence: number;
    };
    decision_score?: {
      risk_reduction: number;
      cost_to_fix: number;
      priority_score: number;
    };
    financials?: {
      risk_exposure_usd: number;
      risk_reduced_usd: number;
      at_risk_if_ignored_usd: number;
    };
    risk_if_exploited?: number;
    likelihood?: number;
    annualized_loss_expectancy?: number;
    is_global: boolean;
  }>;
};

export type RuntimeControlViewState = {
  tenant_id: string;
  foundation_only?: boolean;
  foundation_control_ids?: string[];
  lookback_hours: number;
  event_count: number;
  control_count: number;
  crq_summary?: {
    risk_exposure_usd: number;
    risk_reduced_usd: number;
    at_risk_if_ignored_usd: number;
  };
  controls: Array<{
    control_id: string;
    control_name: string;
    category: string;
    severity: string;
    trigger_count: number;
    miss_count: number;
    source_surface_counts: Record<string, number>;
    severity_counts: Record<string, number>;
    risk_tag_counts: Record<string, number>;
    risk_event?: Record<string, unknown>;
    control_risk_profile?: {
      control_id: string;
      baseline_risk: number;
      current_risk: number;
      risk_reduction: number;
      confidence: number;
    };
    decision_score?: {
      risk_reduction: number;
      cost_to_fix: number;
      priority_score: number;
    };
    financials?: {
      risk_exposure_usd: number;
      risk_reduced_usd: number;
      at_risk_if_ignored_usd: number;
    };
    risk_if_exploited?: number;
    likelihood?: number;
    annualized_loss_expectancy?: number;
    last_triggered_at?: string | null;
  }>;
};

export type SimulationControlViewState = {
  tenant_id: string;
  foundation_only?: boolean;
  foundation_control_ids?: string[];
  control_count: number;
  crq_summary?: {
    risk_exposure_usd: number;
    risk_reduced_usd: number;
    at_risk_if_ignored_usd: number;
  };
  controls: Array<{
    control_id: string;
    control_name: string;
    category: string;
    severity: string;
    simulation_count: number;
    run_count: number;
    pass_rate_percent: number;
    framework_count: number;
    result_breakdown: {
      pass: number;
      fail: number;
      partial: number;
      not_executable: number;
    };
    crq?: {
      simulation_run_id: string;
      control_ids: string[];
      risk_if_exploited: number;
      likelihood: number;
      frequency: number;
      exposure_factor: number;
      annualized_loss_expectancy: number;
      baseline_ale: number;
      current_ale: number;
      risk_reduction: number;
      increased_exposure: number;
      outcome_impact: string;
    };
    financials?: {
      risk_exposure_usd: number;
      risk_reduced_usd: number;
      at_risk_if_ignored_usd: number;
    };
  }>;
};

export type SimulationDefinition = {
  id: string;
  name: string;
  category: string;
  target_module: string;
  version: string;
  dsl_json?: Record<string, unknown>;
};

export type AgenticChainDefenseMode =
  | "no_defense"
  | "prompt_guardrail_only"
  | "approval_only"
  | "jit_identity_only"
  | "hawk_chain_integrity";

export type AgenticChainScenario = {
  scenario_id: string;
  title: string;
  description: string;
  mapped_research_questions: string[];
  expected_safe_result: string;
  expected_hawk_decision: string;
  expected_findings: string[];
  threat_classes: string[];
  involved_agents: string[];
  involved_tools: string[];
  involved_fake_saas_systems: string[];
  expected_evidence_fields: string[];
  expected_graph_nodes: string[];
  expected_graph_edges: string[];
};

export type AgenticChainScenarioListResponse = {
  items: AgenticChainScenario[];
  total: number;
  defense_modes: AgenticChainDefenseMode[];
};

export type AgenticChainIntegrityReport = {
  scenario_id: string;
  scenario_title: string;
  defense_mode: AgenticChainDefenseMode;
  result: "allowed" | "blocked" | "warned" | "missed" | "escalated";
  expected_result: string;
  pass_fail: "pass" | "fail";
  control_mode: string;
  policy_decision: string;
  chain_id: string;
  chain_risk_score: number;
  approval_drift_result: boolean;
  delegation_risk_result: boolean;
  jit_scope_result: boolean;
  deferred_side_effect_result: boolean;
  taint_tracking_result: boolean;
  findings: string[];
  audit_completeness_score: number;
  policy_latency_ms: number;
  evidence_bundle_link: string;
  graph_timeline_link: string;
};

export type AgenticChainIntegrityMetrics = {
  total_scenarios: number;
  total_runs: number;
  approval_drift_detection_rate: number;
  delegation_risk_detection_rate: number;
  jit_scope_mismatch_detection_rate: number;
  deferred_side_effect_detection_rate: number;
  taint_preservation_accuracy: number;
  false_positive_rate: number;
  false_negative_rate: number;
  audit_completeness_score: number;
  policy_latency_ms: number;
  chain_control_uplift: number;
};

export type AgenticChainRunResponse = {
  total_runs: number;
  reports: AgenticChainIntegrityReport[];
  metrics: AgenticChainIntegrityMetrics;
  persistence?: {
    simulation_definition_id?: string;
    ai_system_id?: string;
    run_ids?: string[];
    evidence_node_ids?: string[];
    finding_ids?: string[];
  };
};

export type SimulationRun = {
  id: string;
  simulation_id: string;
  ai_system_id: string;
  started_at: string;
  finished_at?: string;
  mode: string;
  results: {
    result: "pass" | "fail" | "partial" | "not_executable";
    final_outcome?: "pass" | "fail" | "partial" | "not_executable";
    failed_assertions: string[];
    pass_rate?: number;
    iterations?: number;
    passes?: number;
    expected_controls?: string[];
    triggered_controls?: string[];
    missed_controls?: string[];
    severity?: "low" | "med" | "high" | "critical";
    evaluator_reasoning?: string;
    confidence?: number;
    execution_status?: "executable_now" | "partially_executable" | "not_yet_executable";
    execution_support_matrix?: Array<Record<string, unknown>>;
    step_trace_ids?: string[];
    non_executable_steps?: Array<Record<string, unknown>>;
    enforcement_summary?: Record<string, unknown>;
    iteration_outputs?: Array<Record<string, unknown>>;
    pre_run_policy?: Record<string, unknown>;
    crq?: Record<string, unknown>;
    risk_if_exploited?: number;
    annualized_loss_expectancy?: number;
    likelihood?: number;
    risk_impact?: string;
  };
};

export type SimulationExecutionStep = {
  id: string;
  simulation_run_id: string;
  iteration_index: number;
  step_id: string;
  step_order: number;
  step_type: string;
  title: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  timestamp_started?: string | null;
  timestamp_completed?: string | null;
  actor: string;
  target_surface: string;
  input_payload_ref: Record<string, unknown>;
  output_payload_ref: Record<string, unknown>;
  control_refs: string[];
  decision_ref: Record<string, unknown>;
  evidence_refs: string[];
  notes: string;
};

export type SimulationRunTrace = {
  simulation_run_id: string;
  simulation_id: string;
  ai_system_id: string;
  mode: string;
  started_at?: string | null;
  finished_at?: string | null;
  final_outcome: "pass" | "fail" | "partial" | "not_executable";
  execution_status: "executable_now" | "partially_executable" | "not_yet_executable";
  support_matrix: Array<Record<string, unknown>>;
  steps: SimulationExecutionStep[];
  summary: {
    step_count: number;
    status_counts: Record<string, number>;
    expected_controls: string[];
    triggered_controls: string[];
    missed_controls: string[];
    severity: "low" | "med" | "high" | "critical";
    confidence: number;
    evaluator_reasoning: string;
  };
};

export type SimulationSeedPackBootstrapSummary = {
  seed_pack: string;
  defined_total: number;
  created: number;
  updated: number;
  existing: number;
  definition_ids: string[];
  simulation_ids: string[];
  breakdown: {
    by_category: Record<string, number>;
    by_surface: Record<string, number>;
    by_executable_status: Record<string, number>;
  };
};

export type SimulationStreamEventType =
  | "simulation.run.started"
  | "simulation.step.updated"
  | "simulation.run.completed"
  | "simulation.run.failed"
  | "simulation.stream.connected";

export type SimulationStreamEvent = {
  event_type: SimulationStreamEventType | string;
  tenant_id: string;
  created_at: number;
  payload: {
    run_id?: string;
    simulation_id?: string;
    ai_system_id?: string;
    live_session_id?: string | null;
    timestamp?: string;
    iterations?: number;
    mode?: string;
    step_id?: string;
    step_order?: number;
    step_type?: string;
    title?: string;
    status?: string;
    target_surface?: string;
    target_app?: string | null;
    input_summary?: Record<string, unknown>;
    output_summary?: Record<string, unknown>;
    decision?: string | null;
    reason?: string | null;
    control_ids?: string[];
    evidence_refs?: string[];
    final_outcome?: string;
    result?: string;
    execution_status?: string;
    expected_controls?: string[];
    triggered_controls?: string[];
    missed_controls?: string[];
    control_impact_score?: number;
    evidence_bundle_path?: string;
    risk_if_exploited?: number;
    annualized_loss_expectancy?: number;
    risk_reduction_if_control_passes?: number;
    residual_risk_if_control_fails?: number;
    likelihood?: number;
    baseline_ale?: number;
    current_ale?: number;
    crq?: Record<string, unknown>;
    financials?: Record<string, unknown>;
    [key: string]: unknown;
  };
};

export type SimulationTemplate = {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  status: string;
  category: string;
  target_module: string;
  version_prefix: string;
  parameter_schema: Record<string, unknown>;
  template_body: Record<string, unknown>;
  generation_defaults: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type SimulationPack = {
  pack_id: string;
  name: string;
  description: string;
  categories: string[];
  trigger_reason_codes: string[];
  simulation_count: number;
  run_count: number;
  pass_rate: number;
  latest_run_at?: string | null;
  target_ready: boolean;
};

export type SimulationPackRunResult = {
  pack_id: string;
  ai_system_id: string;
  mode: string;
  stochastic_runs: number;
  total_definitions: number;
  total_runs: number;
  passes: number;
  fails: number;
  pass_rate: number;
  run_ids: string[];
  related_control_ids: string[];
  started_at?: string | null;
  finished_at?: string | null;
  evidence_node_id?: string | null;
};

export type SimulationPolicy = {
  id: string;
  tenant_id: string;
  name: string;
  enabled: boolean;
  enabled_categories: string[];
  enabled_surfaces: string[];
  blocked_categories: string[];
  minimum_severity: string;
  require_approval_for: string[];
  allowed_execution_modes: string[];
  environment_scope: string[];
  tenant_isolation_required: boolean;
  evidence_retention_days: number;
  max_parallel_runs: number;
  notify_on_fail: boolean;
  framework_filters: string[];
  control_filters: string[];
  active: boolean;
  created_at: string;
  updated_at: string;
};

export type SimulationExecutor = {
  id: string;
  tenant_id?: string | null;
  is_global: boolean;
  name: string;
  supported_surfaces: string[];
  supported_categories: string[];
  supported_simulation_ids: string[];
  status: string;
  evidence_types: string[];
  requires: string[];
  created_at: string;
  updated_at: string;
};

export type SimulationCatalogCoverage = {
  tenant_id: string;
  total_required: number;
  total_defined: number;
  total_implemented: number;
  planned_only: number;
  executable_now: number;
  partially_executable: number;
  not_yet_executable: number;
  coverage_ratio: number;
  required_by_category: Record<string, number>;
  by_executable_status: Record<string, number>;
  coverage_by_category: Record<
    string,
    {
      defined: number;
      implemented: number;
      executable_now: number;
      partially_executable: number;
      not_yet_executable: number;
    }
  >;
  coverage_by_framework: Record<
    string,
    {
      simulations: number;
      implemented: number;
      executable_now: number;
      partially_executable: number;
      not_yet_executable: number;
    }
  >;
  coverage_by_control: Record<
    string,
    {
      simulations: number;
      implemented: number;
      executable_now: number;
      partially_executable: number;
      not_yet_executable: number;
    }
  >;
  by_category: Record<
    string,
    {
      defined: number;
      implemented: number;
      executable_now: number;
      partially_executable: number;
      not_yet_executable: number;
    }
  >;
};

export type SimulationCoverageSummary = {
  tenant_id: string;
  generated_at: string;
  totals: {
    simulation_definitions: number;
    simulation_runs: number;
    pack_count: number;
    controls_total: number;
    frameworks_total: number;
  };
  category_coverage: Array<{
    category: string;
    simulation_count: number;
  }>;
  framework_coverage: Array<{
    framework: string;
    simulation_count: number;
    category_breakdown: Record<string, number>;
    mapped_control_count: number;
    controls_missing_simulations: string[];
  }>;
  pack_coverage: SimulationPack[];
  missing_links: {
    simulations_without_controls: number;
    controls_without_simulations: string[];
  };
  trigger_sources: {
    runtime_intelligence: number;
    continuous_monitoring: number;
    governance_changes: number;
  };
  bootstrap?: {
    per_category_target: number;
    generated_total: number;
    generated_by_category: Record<string, number>;
    generated_by_pack: Record<string, number>;
  };
};

export type SimulationHeatmap = {
  tenant_id: string;
  generated_at: string;
  categories: string[];
  rows: Array<{
    framework: string;
    total: number;
    cells: Record<string, number>;
  }>;
};

export type SimulationTrendSeries = {
  tenant_id: string;
  lookback_days: number;
  generated_at: string;
  series: Array<{
    day: string;
    total_runs: number;
    passes: number;
    fails: number;
    pass_rate: number;
    categories: Record<string, number>;
  }>;
  category_series: Array<{
    category: string;
    points: Array<{ day: string; count: number }>;
  }>;
};

export type ControlCoverage = {
  control_id: string;
  control_name: string;
  framework_refs: Array<Record<string, unknown>>;
  mapped_simulations: Array<{
    simulation_id: string;
    name: string;
    category: string;
    target_module: string;
    version: string;
  }>;
  coverage_summary: {
    simulation_count: number;
    run_count: number;
    overall_pass_rate: number;
  };
  pass_rate_trend: Array<{
    run_id: string;
    simulation_id: string;
    started_at: string;
    result: "pass" | "fail" | "partial" | "not_executable";
    pass_rate: number;
    iterations: number;
  }>;
  maturity_impact: Array<{
    ai_system_id: string;
    technical_enforcement_score: number;
    simulation_pass_rate: number;
    coverage_score: number;
    maturity_score: number;
    status: string;
    updated_at: string;
  }>;
};

export type FrameworkCoverage = {
  framework: string;
  tenant_id: string;
  min_simulations: number;
  coverage_percent: number;
  total_controls: number;
  covered_controls: number;
  controls: Array<{
    control_id: string;
    control_name: string;
    simulation_count: number;
    covered: boolean;
  }>;
};

export type ConnectorProviderCatalogItem = {
  provider_key: string;
  display_name: string;
  category: string;
  supports_live_pull: boolean;
  is_stub: boolean;
  stub_reason: string;
  signals: Array<{
    signal_key: string;
    signal_type: string;
    control_id: string;
    evidence_signal_type: string;
  }>;
};

export type MaturityRow = {
  id: string;
  ai_system_id: string;
  control_id: string;
  technical_enforcement_score: number;
  simulation_pass_rate: number;
  coverage_score: number;
  maturity_score: number;
  status: "healthy" | "needs_review" | "contested";
  confidence_score: number;
  confidence_inputs: Record<string, unknown>;
};

export type MaturityCurveStage =
  | "UNKNOWN"
  | "CONNECTED"
  | "MONITORING"
  | "UNDERSTANDING"
  | "POLICY_READY"
  | "CONTROLLED"
  | "ASSURED";

export type MaturityCurveScope = {
  id: string;
  scope_key: string;
  scope_type: string;
  display_name: string;
  filters: Record<string, unknown>;
  active: boolean;
  created_at: string;
  updated_at: string;
};

export type MaturityCurveAssessment = {
  id: string;
  stage: MaturityCurveStage;
  confidence: number;
  source_diversity: number;
  indicators: Record<string, unknown>;
  missing_gates: string[];
  blocking_gaps: string[];
  evidence_refs: string[];
  status: string;
  computed_at: string;
};

export type MaturityCurveBaseline = {
  id: string;
  baseline_version: number;
  sample_count: number;
  source_diversity: number;
  aggregates: Record<string, unknown>;
  status: string;
  created_at: string;
};

export type MaturityCurveRecommendation = {
  id: string;
  title: string;
  category: string;
  status: string;
  review_state: string;
  review_reason?: string | null;
  reviewed_by_ref?: string | null;
  reviewed_at?: string | null;
  policy_draft: Record<string, unknown>;
  evidence_refs: string[];
  assumptions: string[];
  unknowns: string[];
  confidence: number;
  estimated_impact: Record<string, unknown>;
  estimated_friction: Record<string, unknown>;
  candidate_policy_version_id?: string | null;
  created_at: string;
  updated_at: string;
};

export type MaturityCurveSimulation = {
  id: string;
  recommendation_id: string;
  policy_version_id?: string | null;
  sample_count: number;
  outcome_counts: Record<string, number>;
  scope_breakdown: Record<string, Record<string, number>>;
  unknown_count: number;
  passed: boolean;
  evidence_refs: string[];
  created_at: string;
};

export type MaturityCurveRollout = {
  id: string;
  recommendation_id: string;
  policy_version_id?: string | null;
  state: string;
  mode: "monitor" | "shadow" | "enforce";
  rollout_stage: "monitor" | "notify" | "warn" | "require_approval" | "enforce" | "validate" | string;
  requested_by_ref?: string | null;
  approved_by_ref?: string | null;
  approved_at?: string | null;
  effective_at?: string | null;
  rollback_reason?: string | null;
  created_at: string;
  updated_at: string;
};

export type MaturityCurvePattern = {
  id: string;
  dimension: string;
  value_ref: string;
  pattern_type: string;
  approval_state: string;
  risk_state: string;
  control_state: string;
  observation_count: number;
  confidence: number;
  evidence_refs: string[];
  created_at: string;
};

export type MaturityCurveExecutiveReport = {
  report_version: string;
  scope_count: number;
  evidence_summary: {
    observed_actions: number;
    baseline_count: number;
    source_surface_counts: Record<string, number>;
    control_coverage_reference_count: number;
  };
  policy_posture: {
    recommendations_by_state: Record<string, number>;
    rollouts_by_state: Record<string, number>;
    rollouts_by_stage: Record<string, number>;
    effectiveness_by_state: Record<string, number>;
  };
  top_patterns: Array<{
    dimension: string;
    value_ref: string;
    observation_count: number;
    approval_state: string;
    risk_state: string;
    control_state: string;
  }>;
  top_gaps: string[];
  recommended_next_steps: string[];
  risk_trend: { status: string; reason: string };
  known_limitations: string[];
};

export type MaturityCurveEffectiveness = {
  id: string;
  rollout_id: string;
  policy_version_id?: string | null;
  status: "UNKNOWN" | "CURRENT" | "DEGRADED" | "REGRESSED" | "STALE";
  outcome_summary: Record<string, unknown>;
  evidence_refs: string[];
  created_at: string;
};

export type MaturityCurveOverview = {
  entitlement: {
    package_tier: string;
    enabled: boolean;
    custom_attributes_enabled: boolean;
  } | null;
  scopes: MaturityCurveScope[];
  assessments: Array<MaturityCurveAssessment & { scope_id: string }>;
  executive: {
    stage_distribution: Record<string, number>;
    coverage_refs: string[];
    gap_summary: Record<string, number>;
    recommendation_summary: Record<string, number>;
    report: MaturityCurveExecutiveReport;
    computed_at: string;
  } | null;
};

export type MaturityCurveScopeDetail = {
  scope: MaturityCurveScope;
  assessment: MaturityCurveAssessment | null;
  baseline: MaturityCurveBaseline | null;
  patterns: MaturityCurvePattern[];
  recommendations: MaturityCurveRecommendation[];
  simulations: MaturityCurveSimulation[];
  rollouts: MaturityCurveRollout[];
  effectiveness: MaturityCurveEffectiveness[];
};

export type ControlTraceabilityRow = {
  control_id: string;
  control_name: string;
  control_category: string;
  mapped_simulations: Array<{
    simulation_id: string;
    name: string;
    category: string;
    target_module: string;
    version: string;
    last_run: null | {
      run_id: string;
      result: "pass" | "fail" | "partial" | "not_executable";
      pass_rate: number;
      iterations: number;
      started_at: string;
      finished_at?: string;
      contribution: number;
    };
  }>;
  last_run_result: null | {
    run_id: string;
    simulation_id: string;
    result: "pass" | "fail" | "partial" | "not_executable";
    pass_rate: number;
    iterations: number;
    started_at: string;
  };
  maturity_impact: null | {
    technical_enforcement_score: number;
    simulation_pass_rate: number;
    coverage_score: number;
    maturity_score: number;
    updated_at: string;
  };
};

export type MaturityScoreExplanation = {
  tenant_id: string;
  ai_system_id: string;
  control_id: string;
  control_name: string;
  formula: string;
  weights: {
    technical_enforcement_score: number;
    simulation_pass_rate: number;
    coverage_score: number;
  };
  scoring_inputs: {
    technical_enforcement_score: number;
    simulation_pass_rate: number;
    coverage_score: number;
  };
  status: "healthy" | "needs_review" | "contested";
  confidence_score: number;
  confidence_inputs: Record<string, unknown>;
  maturity_score: number;
  recomputed_maturity_score: number;
  score_delta: number;
  evidence_links: {
    policy_guardians: Array<Record<string, unknown>>;
    simulation_runs: Array<Record<string, unknown>>;
    enforcement_events: Array<Record<string, unknown>>;
    evidence_nodes: Array<Record<string, unknown>>;
    monitoring_signals: Array<Record<string, unknown>>;
  };
  recent_history: Array<Record<string, unknown>>;
};

export type ControlConflict = {
  id: string;
  ai_system_id: string;
  control_id: string;
  status: "open" | "resolved";
  reason: string;
  positive_signals: number;
  negative_signals: number;
  detected_at: string;
  resolved_at?: string | null;
  resolution_decision?: string | null;
  resolution_notes?: string;
};

export type AuditorControlPostureRow = {
  group_key: string;
  group_label: string;
  controls_total: number;
  implemented_controls: number;
  partial_controls: number;
  not_implemented_controls: number;
  avg_maturity_score: number;
  avg_confidence_score: number;
  ai_system_count: number;
  control_ids: string[];
};

export type AuditorControlPostureView = {
  group_by: "framework" | "domain" | "ai_system";
  rows: AuditorControlPostureRow[];
};

export type AuditorDashboard = {
  average_maturity: number;
  average_confidence: number;
  maturity_count: number;
  needs_review_count: number;
  contested_count: number;
  healthy_count: number;
  open_conflicts_count: number;
  recent_enforcement_events: Array<Record<string, unknown>>;
  recent_snapshots: Array<Record<string, unknown>>;
  recent_conflicts: ControlConflict[];
};

export type DashboardNotificationItem = {
  notification_id: string;
  notification_type: string;
  severity: "low" | "med" | "high" | "critical";
  title: string;
  summary: string;
  created_at: string;
  source_surface?: string | null;
  actor_user_id?: string | null;
  actor_label?: string | null;
  endpoint_id?: string | null;
  endpoint_label?: string | null;
  finding_id?: string | null;
  action_id?: string | null;
  correlation_id?: string | null;
  request_id?: string | null;
  control_mode?: string | null;
  decision_badge?: string | null;
  drilldowns?: FindingDrilldown[];
  primary_drilldown?: FindingDrilldown | null;
  primary_drilldown_type?: string | null;
  investigation_link?: string | null;
  link: string;
};

export type DashboardNotificationsState = {
  tenant_id: string;
  generated_at: string;
  total: number;
  critical_count: number;
  high_count: number;
  items: DashboardNotificationItem[];
};

export type ScanTriggerResponse = {
  scan_id: string;
  status: string;
};

export type CommandCenterRecommendation = {
  title: string;
  severity: "low" | "med" | "high" | "critical";
  action_type: string;
  affected_system: string;
  reasoning: string;
  priority_score: number;
  module_route?: string;
};

export type CommandCenterCrqSummary = {
  recommendation_count: number;
  scored_recommendation_count: number;
  total_base_risk_usd: number;
  risk_exposure_usd: number;
  total_estimated_risk_reduction_usd: number;
  risk_reduced_usd: number;
  at_risk_if_ignored_usd: number;
  residual_risk_usd: number;
  average_decision_impact_score: number;
  average_base_risk_usd: number;
  average_confidence: number;
  average_impact_value_usd: number;
  average_probability_score: number;
  top_action: string;
  top_recommendation?: {
    recommendation_id: string;
    recommendation_type: string;
    ai_system_id?: string | null;
    action: string;
    decision_impact_score: number;
    estimated_risk_reduction: number;
    base_risk: number;
    confidence: number;
    urgency_multiplier: number;
    control_effectiveness: number;
    impact_value: number;
    probability_score: number;
    reasoning: string[];
    created_at?: string | null;
  } | null;
  financial_impact_explanation: string;
  drilldown: string;
};

export type ExposureScanState = {
  scan_id?: string | null;
  status: "no_data" | "running" | "completed" | "failed" | string;
  scan_type: string;
  scope: string;
  scope_value?: string | null;
  last_scan_time?: string | null;
  started_at?: string | null;
  ended_at?: string | null;
  summary: {
    new_ai_apps_detected: number;
    unknown_apps: number;
    new_users_detected: number;
    new_endpoints_detected: number;
    new_risks_identified: number;
    alerts_generated: number;
    total_ai_apps?: number;
  };
  delta: {
    apps_added: Array<Record<string, unknown>>;
    users_added: Array<Record<string, unknown>>;
    endpoints_added: Array<Record<string, unknown>>;
    risks_added: Array<Record<string, unknown>>;
    alerts_added: Array<Record<string, unknown>>;
  };
  links: {
    new_ai_apps: string;
    unknown_tools: string;
    new_users: string;
    new_endpoints: string;
    new_risks: string;
    alerts: string;
    full_report: string;
  };
  error?: string | null;
  duration_ms?: number | null;
  data_source?: string | null;
  crawl_meta?: {
    mode?: string;
    window_start?: string | null;
    window_end?: string | null;
    lookback_hours?: number;
    max_events?: number;
    runtime_events_considered?: number;
    runtime_events_crawled?: number;
    shadow_discovery_attempts?: number;
    shadow_discovery_upserts?: number;
    source_surfaces?: string[];
    crawl_duration_ms?: number;
    actions_considered?: number;
    actions_in_scope?: number;
    signals_considered?: number;
  } | null;
  snapshot_counts?: {
    apps: number;
    users: number;
    endpoints: number;
    risks: number;
    alerts: number;
    unknown_apps: number;
  } | null;
};

export type AIDiscoveryOverview = {
  window_hours: number;
  apps_detected: number;
  total_usage_events: number;
  shadow_ai_count: number;
  approved_apps: number;
  blocked_apps: number;
  source_breakdown: Record<string, number>;
  risk_breakdown: Record<string, number>;
  usage_trend: Array<{ label: string; count: number }>;
  top_apps: Array<{ app_name: string; usage_count: number }>;
};

export type AIDiscoveryUsageEvent = {
  user_id?: string | null;
  device_id?: string | null;
  browser_type?: string | null;
  app_name: string;
  model?: string | null;
  agent_id?: string | null;
  tool_used?: string | null;
  timestamp: string;
  action_type: string;
  source_surface: string;
  risk_level: "low" | "med" | "high" | "critical";
  risk_score: number;
  metadata: Record<string, unknown>;
};

export type AIDiscoveryGraph = {
  window_hours: number;
  filters: Record<string, unknown>;
  nodes: Array<{
    node_type: string;
    node_id: string;
    label?: string | null;
  }>;
  edges: Array<{
    edge_id: string;
    source_node_type: string;
    source_node_id: string;
    target_node_type: string;
    target_node_id: string;
    relationship_type: string;
    event_id?: string | null;
    created_at?: string | null;
    payload: Record<string, unknown>;
  }>;
  stats: {
    node_count: number;
    edge_count: number;
    event_count: number;
    node_counts: Record<string, number>;
    relationship_counts: Record<string, number>;
  };
};

export type AIDiscoveryIdentityProfile = {
  user_id: string;
  display_name: string;
  email: string;
  devices: string[];
  browsers: string[];
  ai_apps: string[];
  agents: string[];
  tools: string[];
  usage_patterns: Record<string, unknown>;
  risk_score: number;
  anomaly_score: number;
  anomaly_count_7d: number;
};

export type AIDiscoveryAnomalyEvent = {
  id: string;
  signal_type: string;
  anomaly_type: string;
  severity: "low" | "med" | "high" | "critical";
  reason: string;
  confidence: number;
  created_at?: string | null;
  related_entities: Array<{ type: string; id: string }>;
  control_ids: string[];
  runtime_event_id?: string | null;
  monitoring_signal_id?: string | null;
  risk_context: {
    potential_loss_usd: number;
    risk_increase_usd: number;
  };
  owasp_mappings?: Array<{
    risk_id: string;
    framework: string;
    framework_key: string;
    reference: string;
    title: string;
    source_reference_url: string;
    matched_controls: string[];
    risk_tags: string[];
  }>;
  payload: Record<string, unknown>;
};

export type AIDiscoveryAgentEntity = {
  agent_id: string;
  owner?: string | null;
  model?: string | null;
  tools: string[];
  capabilities: string[];
  data_access: string[];
  environment: string[];
  status: string;
  risk_score: number;
  anomaly_score: number;
  event_count: number;
  anomaly_count: number;
  source_surfaces: string[];
  last_seen_at?: string | null;
};

export type AIAgentDiscoveryOverview = {
  window_hours: number;
  discovered_agents: number;
  registered_agents: number;
  unregistered_agents: number;
  high_risk_agents: number;
  agents: AIDiscoveryAgentEntity[];
};

export type AIAgentAttackSurface = {
  agent_id: string;
  window_hours: number;
  live_updated_at: string;
  nodes: Array<{
    node_type: string;
    node_id: string;
    label?: string | null;
  }>;
  edges: Array<{
    edge_id: string;
    source_node_type: string;
    source_node_id: string;
    target_node_type: string;
    target_node_id: string;
    relationship_type: string;
    created_at?: string | null;
    event_id?: string | null;
    risk_weight: number;
    payload: Record<string, unknown>;
  }>;
  stats: Record<string, unknown>;
  owasp_risk_overlays?: Array<{
    risk_id: string;
    framework: string;
    framework_key: string;
    reference: string;
    title: string;
    source_reference_url: string;
    matched_controls: string[];
    risk_tags: string[];
  }>;
  top_connections: Array<{
    entity: string;
    relationship_count: number;
  }>;
};

export type AIAgentBlastRadius = {
  agent_id: string;
  window_hours: number;
  reachable_assets: {
    total: number;
    by_type: Record<string, number>;
    nodes: Record<string, string[]>;
  };
  risk_score: number;
  financial_impact: {
    loss_if_compromised_usd: number;
    loss_prevented_usd: number;
    annualized_loss_expectancy_usd: number;
    baseline_ale_usd: number;
    residual_risk_usd: number;
    likelihood: number;
    confidence: number;
  };
  control_ids: string[];
  owasp_risk_overlays?: Array<{
    risk_id: string;
    framework: string;
    framework_key: string;
    reference: string;
    title: string;
    source_reference_url: string;
    matched_controls: string[];
    risk_tags: string[];
  }>;
  propagation_paths: Array<{
    from: string;
    to: string;
    relation: string;
    depth: number;
  }>;
  attack_surface_stats: Record<string, unknown>;
  updated_at: string;
};

export type AIAgentBehaviorProfile = {
  agent_id: string;
  window_hours: number;
  usage_patterns: {
    usage_time_distribution: Record<string, number>;
    frequency_per_day: Record<string, number>;
    action_type_distribution: Record<string, number>;
    tool_usage_patterns: Record<string, number>;
    data_access_patterns: Record<string, number>;
    source_surface_distribution: Record<string, number>;
    event_count: number;
  };
  chain_depth: {
    max: number;
    average: number;
    samples: number;
  };
  data_volume: {
    total_bytes: number;
    average_bytes: number;
    samples: number;
  };
  baseline: Array<{
    action: string;
    baseline_rate_per_hour: number;
    current_window_count: number;
    window_started_at?: string | null;
    last_seen_at?: string | null;
    last_anomaly_at?: string | null;
  }>;
  anomaly_score: number;
  anomaly_count_7d: number;
  updated_at: string;
};

export type AIAgentEnforcementResult = {
  agent_id: string;
  action: "block_agent" | "restrict_tools" | "require_approval" | "isolate_execution" | string;
  status: string;
  reason: string;
  required_approval: boolean;
  control_ids: string[];
  previous_state: Record<string, unknown>;
  updated_state: Record<string, unknown>;
  revoked_tokens: number;
  revoked_delegations: number;
  impacted_agent_ids: string[];
  owasp_mappings?: Array<{
    risk_id: string;
    framework: string;
    framework_key: string;
    reference: string;
    title: string;
    source_reference_url: string;
    matched_controls: string[];
    risk_tags: string[];
  }>;
  evidence_node_id: string;
  audit_log_id: string;
  runtime_event_id?: string | null;
  enforced_at: string;
};

export type AIAgentSimulationResult = {
  agent_id: string;
  attack_type: string;
  resolved_pack_id: string;
  execution_status: string;
  pack_id: string;
  ai_system_id: string;
  mode: string;
  stochastic_runs: number;
  total_definitions: number;
  total_runs: number;
  passes: number;
  fails: number;
  pass_rate: number;
  run_ids: string[];
  related_control_ids: string[];
  owasp_mappings?: Array<{
    risk_id: string;
    framework: string;
    framework_key: string;
    reference: string;
    title: string;
    source_reference_url: string;
    matched_controls: string[];
    risk_tags: string[];
  }>;
  started_at?: string | null;
  finished_at?: string | null;
  evidence_node_id?: string | null;
};

export type AIAgentOWASPCategoryCoverage = {
  risk_id: string;
  framework: string;
  framework_key: string;
  reference: string;
  title: string;
  source_reference_url: string;
  risk_tags: string[];
  controls: string[];
  matched_controls: string[];
  simulations: string[];
  mapped_catalog_simulations: string[];
  enforcement_actions: string[];
  blast_radius_dimensions: string[];
  remediation_templates: string[];
  extends_llm_risks: string[];
  runtime_event_hits: number;
  anomaly_hits: number;
  simulation_runs: {
    total: number;
    pass: number;
    fail: number;
    partial: number;
    not_executable: number;
  };
  simulation_pass_rate: number;
  defined_simulations: number;
  executable_simulations: number;
  partially_executable_simulations: number;
  not_executable_simulations: number;
  coverage_status: "runtime_active" | "simulation_active" | "mapped_ready" | "mapped_only" | string;
};

export type AIAgentOWASPCoverage = {
  agent_id: string;
  window_hours: number;
  generated_at: string;
  framework_registry: Array<{
    framework: string;
    framework_key: string;
    version: string;
    source_reference_url: string;
  }>;
  categories: AIAgentOWASPCategoryCoverage[];
  summary: {
    total_categories: number;
    framework_counts: Record<string, number>;
    runtime_active_categories: number;
    simulation_active_categories: number;
    controls_observed: string[];
    controls_observed_count: number;
    runtime_events_considered: number;
    anomalies_considered: number;
    simulation_runs_considered: number;
  };
};

export type CommandCenterDashboardState = {
  tenant_id: string;
  generated_at: string;
  view_scope: "full" | "scoped";
  filters_applied: {
    time_window_hours: number;
    ai_system_id?: string | null;
    severity?: string | null;
    intent_category?: string | null;
    input_sensitivity?: string | null;
    output_sensitivity?: string | null;
    action_alignment?: string | null;
  };
  risk_over_time: {
    points: Array<{
      label: string;
      risk_score: number;
      event_count: number;
    }>;
    drilldown: string;
  };
  severity_distribution: {
    counts: Record<string, number>;
    total: number;
    drilldown: string;
  };
  exposure_score: {
    score: number;
    components: Record<string, number>;
    drilldown: string;
  };
  active_incidents: {
    total: number;
    open_findings: number;
    high_critical_findings: number;
    open_drift_alerts: number;
    open_remediation_actions: number;
    drilldown: string;
  };
  runtime_heatmap: {
    rows: Array<{
      surface: string;
      counts: Record<string, number>;
      total: number;
    }>;
    drilldown: string;
  };
  live_activity_feed?: {
    items: Array<{
      event_id: string;
      timestamp?: string | null;
      user_id?: string | null;
      user_email?: string | null;
      agent_id?: string | null;
      machine_id?: string | null;
      ai_surface: string;
      application?: string | null;
      action_type: string;
      tool_name?: string | null;
      policy_decision: string;
      intent_category?: string | null;
      input_sensitivity?: string | null;
      output_sensitivity?: string | null;
      action_alignment?: string | null;
      destination_trust_level?: string | null;
      risk_score: number;
      finding_id?: string | null;
      trace_url: string;
      action_trace_url?: string | null;
      action_graph_url?: string | null;
      finding_url?: string | null;
      finding_traceability_url?: string | null;
      decision_explanation?: DecisionExplanation | null;
    }>;
    total: number;
    drilldown: string;
  };
  ai_action_control?: {
    total_actions: number;
    control_mode_counts: Record<string, number>;
    evidence_status_counts: Record<string, number>;
    high_risk_actions: number;
    review_required: number;
    top_actions: Array<{
      action_id: string;
      timestamp?: string | null;
      user_id?: string | null;
      endpoint_id?: string | null;
      session_id?: string | null;
      ai_app?: string | null;
      action_type?: string | null;
      policy_triggered?: string | null;
      enforcement_action?: string | null;
      control_mode: string;
      evidence_status: string;
      risk_score: number;
      correlation_id?: string | null;
      action_trace_url: string;
      action_graph_url: string;
    }>;
    drilldown: string;
  };
  users_view?: {
    items: Array<{
      user_id: string;
      user_email?: string | null;
      machine_ids: string[];
      browsers: string[];
      connected_apps: string[];
      active_agent_ids: string[];
      ai_activity_count: number;
      risk_score: number;
      last_seen?: string | null;
    }>;
    total: number;
    drilldown: string;
  };
  agents_view?: {
    items: Array<{
      agent_id: string;
      name?: string | null;
      owner?: string | null;
      status: string;
      recent_actions: Array<{
        event_id: string;
        timestamp?: string | null;
        action_type: string;
        application?: string | null;
        tool_name?: string | null;
        policy_decision: string;
        risk_score: number;
        finding_id?: string | null;
      }>;
      tools_used: string[];
      apps_touched: string[];
      risk_score: number;
      anomaly_flag: boolean;
      linked_findings: string[];
    }>;
    total: number;
    registered_agents: number;
    drilldown: string;
  };
  findings_alerts?: {
    items: Array<{
      finding_id: string;
      timestamp?: string | null;
      severity: string;
      finding_type?: string | null;
      user_id?: string | null;
      agent_id?: string | null;
      machine_id?: string | null;
      app: string;
      ai_surface: string;
      policy_id?: string | null;
      control_ids?: string[];
      related_event_ids: string[];
      recommended_actions: string[];
      link: string;
      drilldowns?: FindingDrilldown[];
      primary_drilldown?: FindingDrilldown | null;
      primary_drilldown_type?: string | null;
      investigation_link?: string | null;
    }>;
    total: number;
    drilldown: string;
  };
  attack_trace_view?: {
    trace_key?: string | null;
    trace_key_type?: string | null;
    event_count: number;
    steps: Array<{
      step_number: number;
      event_id: string;
      title: string;
      timestamp?: string | null;
      policy_decision: string;
      user_id?: string | null;
      agent_id?: string | null;
      machine_id?: string | null;
      finding_id?: string | null;
    }>;
    drilldown?: string;
  };
  quick_actions?: Array<{
    action: string;
    label: string;
    api: string;
  }>;
  surface_coverage_summary?: {
    surfaces: Record<string, {
      event_count: number;
      blocked: number;
      warned: number;
      apps: string[];
      agents: string[];
      users: string[];
    }>;
    surface_rows?: Array<{
      id: string;
      label: string;
      surface_type: string;
      coverage: string;
      primary_control: string;
      proof_label: string;
      drilldown: string;
      current_mode: string;
      dominant_control_mode?: string;
      status: string;
      event_count: number;
      blocked: number;
      warned: number;
      inline_prevented: number;
      inline_allowed: number;
      shadow_would_block: number;
      detected_only: number;
      telemetry_only: number;
      external_required: number;
      external_action_triggered: number;
      incomplete: number;
      mode_counts: Record<string, number>;
      apps: string[];
      agents: string[];
      users: string[];
    }>;
    totals?: Record<string, number>;
    drilldown: string;
  };
  mcp_tool_calls?: {
    active_mcp_servers: number;
    shadow_mcp_servers: number;
    active_ai_clients: number;
    tool_calls_today: number;
    blocked_tool_calls: number;
    high_risk_tool_calls: number;
    permission_drift_findings: number;
    unapproved_clients_or_tools: number;
    drilldown: string;
  };
  agentic_browser_activity?: {
    automation_events_today: number;
    blocked_automation_actions: number;
    warned_automation_events: number;
    prevented_events: number;
    allowed_events: number;
    detected_only_events: number;
    incomplete_events: number;
    decision_badge_breakdown: Record<string, number>;
    scope_violations: number;
    high_risk_actions_blocked: number;
    top_domains_with_automation: Array<{
      domain: string;
      count: number;
    }>;
    top_suspected_tools_or_vendors: Array<{
      label: string;
      count: number;
    }>;
    finding_breakdown: Record<string, number>;
    drilldown: string;
  };
  intent_aware_activity?: {
    intent_aware_actions: number;
    allowed_research: number;
    blocked_sensitive_inputs: number;
    blocked_output_copies: number;
    intent_scope_violations: number;
    sales_outreach_data_violations: number;
    shadow_would_block: number;
    top_sensitive_destinations: Array<{
      trust_level: string;
      count: number;
    }>;
    badge_breakdown: Record<string, number>;
    drilldown: string;
  };
  shadow_ai_summary: {
    total_entities: number;
    high_risk_entities: number;
    status_counts: Record<string, number>;
    surface_counts: Record<string, number>;
    signal_breakdown: Record<string, number>;
    top_entities: Array<{
      id: string;
      canonical_name: string;
      confidence_score: number;
      provisional_risk_tier?: string | null;
      discovery_status: string;
      linked_ai_system_id?: string | null;
      last_seen?: string | null;
      source_surfaces: string[];
    }>;
    drilldown: string;
  };
  identity_risk: {
    total_agents: number;
    active_agents: number;
    risky_agents: number;
    top_agents: Array<{
      agent_id: string;
      agent_name?: string;
      status: string;
      max_chain_depth?: number | null;
      actions: number;
      blocked: number;
      warn: number;
      avg_risk_score: number;
    }>;
    drilldown: string;
  };
  control_coverage: {
    average_maturity: number;
    average_technical_enforcement: number;
    average_simulation_pass_rate: number;
    average_coverage_score: number;
    status_counts: Record<string, number>;
    lowest_controls: Array<{
      control_id: string;
      maturity_score: number;
      technical_enforcement_score: number;
      simulation_pass_rate: number;
      coverage_score: number;
      status: string;
    }>;
    drilldown: string;
  };
  violations: {
    count: number;
    open_count: number;
    high_critical_open_count: number;
    items: Array<{
      finding_id: string;
      finding_type: string;
      severity: string;
      status: string;
      ai_tool: string;
      risk_category: string;
      occurrence_count: number;
      last_seen_at?: string | null;
      recommended_action: string;
      source_surface: string;
      ai_system_id?: string | null;
      drilldown: string;
      drilldowns?: FindingDrilldown[];
      primary_drilldown?: FindingDrilldown | null;
      primary_drilldown_type?: string | null;
      investigation_link?: string | null;
    }>;
    drilldown: string;
  };
  simulations: {
    total_runs: number;
    pass_count: number;
    fail_count: number;
    fail_rate_percent: number;
    recent_runs: Array<{
      run_id: string;
      simulation_id: string;
      ai_system_id: string;
      result: string;
      pass_rate: number;
      mode: string;
      started_at?: string | null;
      finished_at?: string | null;
    }>;
    drilldown: string;
  };
  remediation_actions: {
    status_counts: Record<string, number>;
    items: Array<{
      id: string;
      remediation_type: string;
      target_type: string;
      target_id: string;
      source_trigger_type: string;
      status: string;
      risk_level: string;
      action_mode: string;
      requires_approval: boolean;
      created_at?: string | null;
      applied_at?: string | null;
    }>;
    drilldown: string;
  };
  ai_exposure_scan: ExposureScanState;
  crq_summary: CommandCenterCrqSummary;
  sla_metrics: {
    approval_pending: number;
    approval_overdue: number;
    mean_approval_age_minutes: number;
    high_open_findings: number;
    high_overdue_findings: number;
    job_success_rate_24h: number;
    auditor_snapshot_count?: number;
    latest_auditor_snapshot_at?: string | null;
    drilldown: string;
  };
  recommendations: CommandCenterRecommendation[];
  cve_exposure: {
    open_count: number;
    critical: number;
    high: number;
    drilldown: string;
  };
  external_risk_intelligence: {
    critical_risks: number;
    high_or_critical_risks: number;
    known_exploited_items: number;
    affected_assets: number;
    new_risks_since_last_sync: number;
    simulations_recommended: number;
    remediation_pending: number;
    sync_status: string;
    last_sync_at?: string | null;
    source_health: Array<{
      source: string;
      enabled: boolean;
      last_sync_status: string;
      last_sync_at?: string | null;
      last_sync_error?: string | null;
    }>;
    coverage_by_source: Record<string, number>;
    total_ale_usd: number;
    total_residual_risk_usd: number;
    drilldown: string;
  };
  available_filters: {
    time_window_hours: number[];
    severity: string[];
    ai_systems: Array<{
      id: string;
      name: string;
      risk_tier: string;
      status: string;
    }>;
    intent_categories?: string[];
    input_sensitivities?: string[];
    output_sensitivities?: string[];
    action_alignments?: string[];
  };
};

export type DecisionExplanation = {
  explanation_id?: string | null;
  decision_id?: string | null;
  action_id?: string | null;
  tenant_id?: string | null;
  timestamp?: string | null;
  decision_summary?: {
    final_decision?: string | null;
    control_mode?: string | null;
    decision_badge?: string | null;
    plain_english_reason?: string | null;
    recommended_safe_path?: string | null;
    confidence?: string | null;
  };
  evaluated_signals?: Record<string, unknown>;
  matched_policies?: Array<Record<string, unknown>>;
  decision_factors?: Array<{
    factor_type?: string | null;
    label?: string | null;
    value?: unknown;
    severity?: string | null;
    effect?: string | null;
    weight?: number | null;
    explanation?: string | null;
  }>;
  hidden_or_redacted?: Record<string, boolean | string | number | null | undefined>;
  evidence?: {
    evidence_refs?: string[];
    evidence_bundle_id?: string | null;
    trace_id?: string | null;
    event_hash?: string | null;
    finding_id?: string | null;
  };
};

export type PilotHealthState = {
  tenant_id: string;
  generated_at: string;
  overall_status: "ok" | "degraded" | string;
  api_reachable: boolean;
  schema_health: {
    healthy: boolean;
    missing_tables: string[];
    missing_columns: string[];
    pending_migrations: string[];
    notes: string[];
  };
  policy_sync_health: {
    status: "ok" | "stale" | "degraded" | "missing" | string;
    policy_version?: string | null;
    last_sync_at?: string | null;
    telemetry_queue_depth?: number;
    last_error?: string | null;
  };
  telemetry_health: {
    status: "ok" | "stale" | "delayed" | "missing" | string;
    latest_browser_event_at?: string | null;
    lag_seconds?: number | null;
  };
  deployment_hardening?: {
    status: "ok" | "degraded" | "failed" | string;
    summary: {
      ok: number;
      warning: number;
      failed: number;
      manual_required: number;
      total: number;
    };
    checks: Array<{
      id: string;
      label: string;
      status: "ok" | "warning" | "failed" | "manual_required" | string;
      severity: string;
      message: string;
      remediation: string;
    }>;
  };
};

export type AuditorExportArtifacts = {
  json: string;
  csv: string;
  evidence_pack?: string | null;
  pdf_ready_model?: string | null;
  pdf?: string | null;
  artifact_hashes?: Record<string, string>;
  pdf_renderer?: string | null;
  pdf_renderer_available?: boolean;
  hash: string;
};

export type AuditorExportResponse = {
  snapshot_id: string;
  artifact_relative_path: string;
  download_url: string;
  download_urls: Record<string, string>;
  artifacts: AuditorExportArtifacts;
};

export type ScheduledJobRun = {
  id: string;
  job_name: string;
  tenant_id?: string | null;
  started_at: string;
  finished_at: string;
  status: "success" | "fail";
  error_message?: string | null;
};

export type JobStatusItem = {
  job_name: string;
  runs: ScheduledJobRun[];
};

export type JobStatusList = ListEnvelope<JobStatusItem>;

export type DeploymentCoverageSurface = {
  surface: string;
  label: string;
  covered: boolean;
  coverage_percent: number;
  observed_event_count: number;
  policy_enforced_count: number;
  last_seen_at?: string | null;
};

export type DeploymentCoverageSummary = {
  tenant_id: string;
  coverage_percent: number;
  surfaces: DeploymentCoverageSurface[];
  policies_enforced: {
    total_enforcement_events: number;
    policy_bound_enforcement_events: number;
    decision_counts: Record<string, number>;
  };
  connector_posture: {
    total_connectors: number;
    enabled_connectors: number;
  };
  provider_catalog?: {
    supported_provider_counts?: Record<string, number>;
    supported_source_surfaces?: string[];
    enforcement_capable_surfaces?: string[];
    monitoring_only_surfaces?: string[];
  };
  observed_surface_counts?: Record<string, number>;
  observed_provider_category_counts?: Record<string, number>;
  observed_provider_counts?: Record<string, number>;
  provider_surface_mode_counts?: Record<string, Record<string, number>>;
  provider_blind_spots_by_category?: Record<string, string[]>;
  coverage_by_surface_type?: Record<string, number>;
  enforcement_capability?: {
    enforceable_surfaces_observed?: number;
    monitoring_only_surfaces_observed?: number;
    enforcement_surface_gaps?: string[];
    monitoring_surface_gaps?: string[];
  };
  gaps: string[];
};

export type EndpointFloorControlState = {
  status: "inline" | "inline_bound" | "external" | "observe" | "not_covered" | "unavailable" | "unknown";
  verification: "verified" | "experimental" | "unverified";
  health: "healthy" | "degraded" | "unhealthy" | "stale" | "unknown";
  observed_latency_ms?: number | null;
  evidence_refs: string[];
};

export type EndpointFloorLocalPolicy = {
  status: "active" | "disabled" | "invalid" | "unavailable" | "unknown";
  freshness: "fresh" | "stale" | "expired" | "unknown";
  policy_version?: string | null;
  signature_verified: boolean;
  evidence_refs: string[];
};

export type EndpointEnforcementFloorEndpoint = {
  endpoint_id: string;
  hostname: string;
  os_type: string;
  last_seen_at: string;
  health: "healthy" | "degraded" | "stale" | "unknown";
  minimum_floor_satisfied: boolean;
  semantic_control_available: boolean;
  controls: {
    file_control: EndpointFloorControlState;
    process_control: EndpointFloorControlState;
    network_control: EndpointFloorControlState;
    semantic_proxy: EndpointFloorControlState;
  };
  local_policy: EndpointFloorLocalPolicy;
  reason_codes: string[];
  blind_spots: string[];
  evidence_refs: string[];
};

export type EndpointEnforcementFloorSummary = {
  schema_version: string;
  generated_at: string;
  summary: {
    total: number;
    protected: number;
    degraded: number;
    unknown: number;
  };
  endpoints: EndpointEnforcementFloorEndpoint[];
};

export type EndpointHealthDevice = {
  identity_id: string;
  endpoint_id: string;
  assigned_user_id?: string | null;
  status: string;
  key_provider: string;
  key_thumbprint: string;
  scopes: string[];
  last_authenticated_at?: string | null;
  auto_renewal: {
    supported: boolean;
    state: "recent" | "stale" | "not_seen" | "disabled" | string;
    token_ttl_seconds: number;
    explanation: string;
  };
  signed_heartbeat: {
    last_seen_at?: string | null;
    freshness: "fresh" | "stale" | "missing" | string;
    fresh_within_seconds: number;
    evidence_refs: string[];
  };
  policy_freshness: {
    status: string;
    freshness: string;
    policy_version?: string | null;
    signature_verified: boolean;
    evidence_refs: string[];
  };
  command_enforcement_acceptance: {
    state: "accepted" | "not_accepted" | "missing_heartbeat" | "stale_heartbeat" | "identity_not_active" | string;
    minimum_floor_satisfied: boolean;
    semantic_control_available: boolean;
    reason_codes: string[];
    blind_spots: string[];
  };
};

export type EndpointHealthSummary = {
  schema_version: string;
  generated_at: string;
  summary: {
    total: number;
    active: number;
    fresh_signed_heartbeat: number;
    command_enforcement_accepted: number;
    needs_reenrollment: number;
  };
  devices: EndpointHealthDevice[];
};

export type EndpointReenrollmentAuthorization = {
  authorization_id: string;
  enrollment_code: string;
  enrollment_nonce: string;
  expires_at: string;
  scopes: string[];
  endpoint_id: string;
  assigned_user_id?: string | null;
  revoked_identity_id: string;
};

export type ChatGPTCompositeVerification =
  | "verified"
  | "partial"
  | "experimental"
  | "unverified"
  | "unavailable"
  | "unknown";

export type ChatGPTDesktopAction =
  | "chat_prompt"
  | "chat_file_upload"
  | "work_local_file_read"
  | "work_local_file_write"
  | "work_desktop_app"
  | "work_cloud_action"
  | "built_in_browser_navigation"
  | "built_in_browser_upload"
  | "built_in_browser_download"
  | "app_action"
  | "custom_mcp_write"
  | "codex_local_shell"
  | "codex_remote_action"
  | "unknown_action";

export type ChatGPTCompositeCapability = {
  capability: string;
  level: NativeCapabilityLevel;
  verification: ChatGPTCompositeVerification;
  control_role: string;
  evidence_refs: string[];
  blind_spots: string[];
};

export type ChatGPTDesktopCompositeAsset = {
  asset_id: string;
  asset_type: "chatgpt_desktop_composite";
  display_name: string;
  endpoint_id: string;
  last_observed_at: string;
  installation: {
    installed: boolean;
    bundle_path: string | null;
    bundle_id: string | null;
    version: string | null;
    build: string | null;
    team_id: string | null;
    code_directory_hash: string | null;
    signature_verified: boolean;
    hardened_runtime: boolean;
    notarization_verified: boolean;
  };
  process: {
    process_id: number;
    parent_process_id: number | null;
    process_start_time_ns: number | null;
    process_name: string | null;
    executable_path: string | null;
    user: string | null;
    identity_state: string;
  };
  native_hook_available: false;
  account: {
    context: "enterprise" | "business" | "edu" | "personal" | "unknown";
    evidence_source: string;
    authoritative: boolean;
    multiple_workspaces_observed: boolean;
    switch: string | null;
    reason_codes: string[];
  };
  account_history: string[];
  modes_observed: string[];
  runtime_location: "local_endpoint" | "openai_cloud" | "mixed" | "unknown";
  built_in_browser: {
    sub_surface: "chatgpt_built_in_browser";
    observed: boolean;
    inherits_chrome_extension_coverage: false;
    dom_control: "unavailable" | "unknown";
    form_field_semantics: "unavailable" | "unknown";
  };
  endpoint_floor: Omit<EndpointEnforcementFloorEndpoint, "last_seen_at"> & { last_seen_at: string | null };
  capabilities: ChatGPTCompositeCapability[];
  control_coverage: {
    methodology: string;
    total_dimensions: number;
    verified_dimensions: number;
    verified_percent: number;
    counts: Record<ChatGPTCompositeVerification, number>;
    inflation_guard: string;
  };
  compliance_reconciliation: {
    control_role: "evidence_only";
    inline_authorization: false;
    items: Array<{
      correlation_id: string;
      status: "confirmed" | "correlated" | "missing_provider_evidence" | "missing_endpoint_evidence" | "unknown";
      endpoint_action_id: string | null;
      provider_action_id: string | null;
      control_role: "evidence_only";
      inline_authorization: false;
    }>;
    summary: Record<string, number>;
  };
  why_controlled: Record<string, Record<string, string>>;
  blind_spots: string[];
  evidence_refs: string[];
};

export type ChatGPTDesktopAssetResponse = {
  schema_version: string;
  source: "server_projected_evidence";
  generated_at: string;
  total: number;
  items: ChatGPTDesktopCompositeAsset[];
  empty_state: { status: "not_observed"; message: string } | null;
};

export type ChatGPTDesktopControlPlan = {
  schema_version: string;
  source: "server_projected_evidence";
  asset_id: string;
  endpoint_id: string;
  native_hook_available: false;
  context: {
    mode: string;
    runtime_location: string;
    account_context: string;
    account_evidence_source: string;
  };
  requirements: {
    action: ChatGPTDesktopAction;
    mandatory_enforcement_floors: Array<{
      floor_id: string;
      capability: string;
      minimum_level: string;
      allowed_methods: string[];
      maximum_latency_ms: number;
    }>;
    semantic_controls: string[];
    provider_context: string[];
    evidence_sources: string[];
    control_assertion: string;
    reason_codes: string[];
  };
  selection: {
    mandatory_enforcement_floors: Array<[string, string]>;
    semantic_primary_control: string | null;
    unsatisfied_mandatory_floors: string[];
    control_requirement_unsatisfied: boolean;
    reason_codes: string[];
    semantic_controls_required: string[];
    coverage_implications: Record<string, string>;
  };
  why_controlled: Record<string, string>;
  blind_spots: string[];
  evidence_refs: string[];
};

export type CoverageAssertionCounts = {
  covered: number;
  not_covered: number;
  unknown: number;
  not_applicable: number;
  denominator: number;
};

export type CoverageScore = {
  score: number | null;
  counts: CoverageAssertionCounts;
};

export type ControlCoverageDimension = CoverageScore & {
  dimension: string;
  methodology: string;
  missing_reasons: Record<string, number>;
};

export type ControlCoverageBlindSpot = {
  blind_spot_id: string;
  kind: string;
  path_id: string;
  dimensions: string[];
  assertion_ids: string[];
  evidence_refs: string[];
};

export type ControlCoverageImprovement = {
  deployment_type: string;
  addressable_assertion_count: number;
  impacted_path_count: number;
  dimensions: string[];
  path_ids: string[];
  assertion_ids: string[];
  evidence_refs: string[];
  prerequisites: string[];
  conditional: boolean;
};

export type ControlCoverageSummary = {
  tenant_id: string;
  methodology_version: string;
  window_days: number;
  window_start: string;
  window_end: string;
  computed_at: string;
  freshness_status: "current" | "stale" | "failed" | "unknown" | string;
  known_estate_limitation: string;
  headline: CoverageScore;
  dimensions: Record<string, ControlCoverageDimension>;
  surface_summary: {
    protected?: number;
    monitor_only?: number;
    outside_control?: number;
    offline?: number;
    unknown?: number;
    total?: number;
    [key: string]: number | undefined;
  };
  blind_spots: ControlCoverageBlindSpot[];
  deployment_improvements: ControlCoverageImprovement[];
  input_watermarks: Record<string, string>;
  diagnostics: Array<{ code?: string; message?: string; [key: string]: unknown }>;
};

export type ControlCoverageAssertion = {
  assertion_id: string;
  dimension: string;
  state: "covered" | "not_covered" | "unknown" | "not_applicable";
  reason_code: string;
  explanation: string;
  evidence_refs: string[];
  observed_at: string;
  evaluated_at: string;
  valid_until?: string | null;
};

export type ControlCoveragePath = {
  path_id: string;
  path_key: string;
  key_version: string;
  asset_ref: string;
  identity_type: string;
  identity_ref: string;
  runtime_ref: string;
  deployment_surface_ref: string;
  destination_type: string;
  destination_ref: string;
  lifecycle_status: string;
  first_seen_at: string;
  last_seen_at: string;
  source_refs: string[];
  assertions: ControlCoverageAssertion[];
};

export type ControlCoveragePathList = {
  page: number;
  page_size: number;
  total: number;
  items: ControlCoveragePath[];
};

export type ControlCoveragePathDetail = ControlCoveragePath;

export type ExecutiveCoverageState =
  | "covered_current"
  | "covered_stale"
  | "partially_covered"
  | "configured_unvalidated"
  | "regressed"
  | "gap"
  | "unsupported"
  | "unknown"
  | "not_applicable";

export type ExecutiveCoverageDistribution = Record<ExecutiveCoverageState, number>;

export type ExecutiveCoverageGap = {
  gap_id: string;
  assessment_id: string;
  priority: "P0" | "P1" | "P2" | "P3" | string;
  category: string;
  asset_ref: string;
  action_class: string;
  dimension: string;
  surface: string;
  coverage_state: ExecutiveCoverageState;
  cause: string;
  recommended_action: string;
  evidence_refs: string[];
};

export type ExecutiveCoverageSnapshotComparison = {
  current_snapshot_id?: string;
  previous_snapshot_id?: string;
  transitions?: Record<string, number>;
  unchanged?: number;
  introduced?: number;
  removed?: number;
  scope_changed?: boolean;
};

export type ExecutiveControlCoverageSummary = {
  tenant_id: string;
  snapshot_id: string;
  previous_snapshot_id: string | null;
  methodology_version: string;
  computed_at: string;
  scope: {
    scope_id: string;
    scope_type: string;
    scope_key: string;
    display_name: string;
    filters: Record<string, unknown>;
  };
  state_distribution: ExecutiveCoverageDistribution;
  validated_coverage_percent: number | null;
  denominator: number;
  unknown_population: number;
  surface_breakdown: Record<string, ExecutiveCoverageDistribution>;
  dimension_breakdown: Record<string, ExecutiveCoverageDistribution>;
  top_gaps: ExecutiveCoverageGap[];
  change_since_previous: ExecutiveCoverageSnapshotComparison;
  source_versions: Record<string, string>;
  assessment_count: number;
};

export type ExecutiveCoverageAssessmentSummary = {
  assessment_id: string;
  assessment_key: string;
  asset_ref: string;
  action_class: string;
  action_path_ref: string;
  deployment_surface: string;
  dimension: string;
  coverage_state: ExecutiveCoverageState;
  assurance_state: string;
  capability_state: string;
  criticality: string;
  reason_code: string;
  explanation: string;
  evidence_refs: string[];
};

export type ExecutiveCoverageAssessmentList = {
  snapshot_id: string;
  count: number;
  items: ExecutiveCoverageAssessmentSummary[];
  limit: number;
};

export type ExecutiveCoverageAssessmentExplanation = {
  assessment_id: string;
  snapshot_id: string;
  requirement: string;
  applicability: { state: string; reason: string };
  scope: {
    asset_ref: string;
    action_class: string;
    action_path_ref: string;
    deployment_surface: string;
    domain_profile_ref: string | null;
  };
  dimension: string;
  deployment_state: string;
  capability_state: string;
  assurance_state: string;
  evidence_quality: string;
  control_plan_ref: string | null;
  expected_control_points: string[];
  contributing_control_points: string[];
  missing_contributions: string[];
  validation_refs: string[];
  bypass_refs: string[];
  evidence_refs: string[];
  lineage_refs: string[];
  coverage_state: ExecutiveCoverageState;
  reason_code: string;
  explanation: string;
  criticality: string;
  source_versions: Record<string, string>;
  assessed_at: string;
  investigation_links: string[];
};

export type NativeCapabilityLevel =
  | "inline_bound"
  | "inline"
  | "external"
  | "observe"
  | "unavailable"
  | "unknown";

export type NativeVerificationStatus =
  | "verified"
  | "experimental"
  | "unverified"
  | "broken"
  | "removed";

export type NativeCapabilityClaim = {
  level: NativeCapabilityLevel;
  verification_status: NativeVerificationStatus;
  evidence_refs: string[];
};

export type NativeProviderManifest = {
  manifest_id: string;
  manifest_version: string;
  provider: string;
  product: string;
  method: string;
  supported_versions: string[];
  capability_matrix: Record<string, NativeCapabilityClaim>;
  security_properties: {
    pre_execution_capable: boolean;
    post_execution_capable: boolean;
    blocking_strength: number;
    action_fidelity: number;
    identity_quality: number;
    parameter_fidelity: number;
    target_fidelity: number;
    destination_fidelity: number;
    result_fidelity: number;
    bypass_resistance: number;
    tamper_resistance: number;
    expected_latency_ms: number;
    availability_profile: string;
    required_permissions: string[];
    privacy_impact: string;
  };
  verification_status: NativeVerificationStatus;
  verified_at: string | null;
  adapter_version: string;
  verification_evidence: string[];
  official_documentation_reference: string;
  required_permissions: string[];
  deployment_requirements: string[];
  known_blind_spots: string[];
  failure_modes: string[];
  privacy_implications: string[];
  fallback_methods: string[];
  profile_source?: "catalog_only" | "persisted_selector_profile";
  profile_active?: boolean;
  effective_for_selection?: boolean;
  persisted_profile_id?: string | null;
};

export type NativeCapabilityMatrix = {
  matrix_version: string;
  providers: NativeProviderManifest[];
};

export type NativeControlPoint = {
  id: string;
  tenant_id: string;
  display_name: string;
  provider: string;
  product: string;
  method: string;
  deployment_family: "browser" | "endpoint" | "runtime" | "saas_api";
  environment: string;
  state: string;
  mode: "discover" | "monitor" | "enforce";
  health_state: string;
  health_reasons: string[];
  provider_version: string | null;
  adapter_version: string;
  policy_version: string | null;
  policy_fresh_until: string | null;
  degradation_mode: string;
  capabilities: Record<string, NativeCapabilityClaim>;
  known_blind_spots: string[];
  last_validated_at: string | null;
  validation_current: boolean;
  policy_fresh: boolean;
  configuration_integrity_valid: boolean;
  provider_version_compatible: boolean;
  adapter_version_compatible: boolean;
  callback_authenticated: boolean;
  authoritative: boolean;
  route_binding_current: boolean;
  created_at: string;
  updated_at: string;
};

export type NativeControlPointList = {
  items: NativeControlPoint[];
  total: number;
};

export type NativeControlPointHealth = {
  integration_id: string;
  health_state: string;
  reason_codes: string[];
  callback_health: string;
  evidence_flowing: boolean;
  policy_fresh: boolean;
  validation_current: boolean;
  real_acceptance_current: boolean;
  configuration_integrity_valid: boolean;
  provider_version_compatible: boolean;
  adapter_version_compatible: boolean;
  active_for_enforcement: boolean;
  enforcement_feature_active: boolean;
  route_binding_current: boolean;
  profile_active: boolean;
  profile_verification: NativeVerificationStatus;
  adapter_version: string;
  last_health_check_at: string | null;
  last_validated_at: string | null;
  last_action_id: string | null;
  last_selection_reason: string | null;
  current_assurance: number | null;
  expected_latency_ms: number | null;
  observed_latency_ms: number | null;
};

export type NativeControlValidationRun = {
  integration_id: string;
  validation_id: string;
  validation_version: string;
  safe_synthetic: boolean;
  checks: Record<string, boolean>;
  result: "passed" | "failed" | "partial" | "unknown";
  reason_codes: string[];
  evidence_refs: string[];
  validated_at: string;
  observed_latency_ms: number | null;
};

export type NativeControlSelection = {
  selection_id: string;
  action_id: string;
  primary_control_point: string | null;
  secondary_observation_points: string[];
  containment_points: string[];
  rejected_candidates: Array<{ control_point_id: string; reason_codes: string[] }>;
  selection_reason: string;
  required_capabilities: string[];
  satisfied_capabilities: string[];
  unsatisfied_capabilities: string[];
  assurance_level: number;
  coverage_implications: Record<string, string>;
  known_blind_spots: string[];
  selector_version: string;
  matrix_version: string;
  policy_version: string;
  control_profile_version: string | null;
  timestamp: string;
};

export type AIRemediationGuidanceStep = {
  step_order: number;
  action_type: "policy_update" | "restrict_permission" | "review_owner" | "run_simulation" | "ticket" | "investigate" | "rollback";
  title: string;
  description: string;
  requires_approval: boolean;
  estimated_impact: string;
  linked_controls: string[];
  linked_frameworks: string[];
};

export type AIRemediationGuidance = {
  issue_id: string;
  summary: string;
  root_cause_hypothesis: string;
  recommended_steps: AIRemediationGuidanceStep[];
  priority: "low" | "med" | "high" | "critical";
  confidence: number;
  notes: string;
};

export type AIOrchestrationResult = {
  trace_id: string;
  task_type: string;
  provider: string;
  model: string;
  model_version: string;
  prompt_template_id: string;
  routing_policy_id: string;
  policy_route_id: string;
  region_route: string;
  retrieval_refs: Array<Record<string, unknown>>;
  evidence_refs: string[];
  pre_call_guard_results: Record<string, unknown>;
  post_call_guard_results: Record<string, unknown>;
  output_schema_valid: boolean;
  token_usage: Record<string, number>;
  cost_estimate_usd: number;
  status: string;
  rejection_reason?: string | null;
  remediation_guidance?: AIRemediationGuidance | null;
  audit_log_id?: string | null;
  evidence_node_id?: string | null;
};

export type AIReasoningTrace = {
  id: string;
  tenant_id: string;
  issue_type: string;
  issue_id: string;
  task_type: string;
  provider: string;
  model: string;
  model_version: string;
  prompt_template_id: string;
  prompt_variables_json: Record<string, unknown>;
  retrieval_refs_json: Array<Record<string, unknown>>;
  evidence_refs_json: string[];
  routing_policy_id: string;
  policy_route_id: string;
  region_route: string;
  pre_call_guard_results_json: Record<string, unknown>;
  post_call_guard_results_json: Record<string, unknown>;
  output_schema_valid: boolean;
  token_usage_json: Record<string, number>;
  cost_estimate_usd: number;
  status: string;
  output_json: Record<string, unknown>;
  rejection_reason?: string | null;
  correlation_id?: string | null;
};

export type AIReasoningTicketPayload = {
  system: string;
  title: string;
  severity: string;
  description: string;
  trace_id: string;
  issue_type: string;
  issue_id: string;
  provider: string;
  model: string;
  routing_policy_id: string;
  policy_route_id: string;
};
export type OIDCProvider = {
  key: string;
  kind: "entra" | "okta" | string;
  display_name: string;
};

export type OIDCProviderList = { providers: OIDCProvider[] };
