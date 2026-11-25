import type {
  AISystem,
  AguiAction,
  AguiDecision,
  AgentIdentity,
  ApprovalRequest,
  AuditorControlPostureView,
  AuditorDashboard,
  AuditorExportArtifacts,
  Connector,
  ConnectorProviderCatalogItem,
  Control,
  ControlConflict,
  ControlCoverage,
  ControlTraceabilityRow,
  DiscoveryApplication,
  DriftAlert,
  EnforcementEvent,
  EvidenceNode,
  Finding,
  FindingTicketResponse,
  FindingTraceability,
  FindingValidationPackResponse,
  FrameworkCoverage,
  JobStatusItem,
  ListEnvelope,
  LoginResponse,
  MaturityRow,
  MaturityScoreExplanation,
  PolicyPack,
  PolicyScopedRule,
  PolicyVersion,
  SimulationDefinition,
  SimulationRun,
} from "@/lib/types";
import type { Session } from "@/lib/auth";

const DEMO_TENANT_ID = "tenant-acme";
const DEMO_TENANT_NAME = "Acme Enterprise";

const AGUI_ACTION_IDS = [
  "findings.accept_recommendation",
  "findings.reject_recommendation",
  "findings.escalate_to_governance",
  "findings.assign_owner",
  "findings.accept_risk",
  "governance.approve_application",
  "governance.block_application",
  "governance.assign_owner",
  "governance.change_risk_tier",
  "policies.approve_activation",
  "policies.override_enforcement",
  "policies.disable_guardian_binding",
  "simulations.approve_pack_run",
  "simulations.suppress_failure_with_justification",
  "auditor.challenge_assertion",
  "auditor.resolve_contested_control",
  "auditor.approve_export_pack",
  "aiiam.approve_token_mint",
  "aiiam.approve_kill_switch",
  "aiiam.revoke_privilege",
];

const MODULE_DEFAULTS: Record<string, { sourceObjectType: string; url: string; roles: string[] }> = {
  findings: { sourceObjectType: "finding", url: "/discovery/findings", roles: ["owner", "admin", "auditor", "operator"] },
  governance: { sourceObjectType: "discovery_application", url: "/governance", roles: ["owner", "admin", "auditor", "operator"] },
  policies: { sourceObjectType: "policy_pack", url: "/policies", roles: ["owner", "admin", "auditor"] },
  simulations: { sourceObjectType: "simulation_pack", url: "/simulations", roles: ["owner", "admin", "auditor", "operator"] },
  auditor: { sourceObjectType: "control_assertion", url: "/auditor/conflicts", roles: ["owner", "admin", "auditor"] },
  aiiam: { sourceObjectType: "agent_identity", url: "/ai-iam", roles: ["owner", "admin"] },
};

const AGUI_ACTIONS: AguiAction[] = AGUI_ACTION_IDS.map((actionId) => {
  const [module, action] = actionId.split(".");
  const defaults = MODULE_DEFAULTS[module] || MODULE_DEFAULTS.findings;
  const title = action.replaceAll("_", " ");
  return {
    action_id: actionId,
    action_type: action.includes("approve") ? "approval" : action.includes("challenge") ? "challenge" : "decision",
    title: title.charAt(0).toUpperCase() + title.slice(1),
    description: `Human oversight action for ${module}.`,
    source_module: module,
    source_object_type: defaults.sourceObjectType,
    source_object_id: "",
    required_role: defaults.roles,
    decision_options: action.includes("challenge") ? ["challenge", "withdraw"] : ["approve", "deny"],
    requires_justification: true,
    requires_evidence_display: true,
    requires_diff_preview: action.includes("override") || action.includes("change"),
    side_effect_level: action.includes("approve") || action.includes("disable") || action.includes("kill") ? "enforce" : "write",
    created_at: new Date().toISOString(),
    source_summary: `${module} action ${actionId}`,
    proof_timeline_url: defaults.url,
  };
});

type DemoState = {
  policyVersions: PolicyVersion[];
  policyPacks: PolicyPack[];
  aiSystems: AISystem[];
  connectors: Connector[];
  connectorProviders: ConnectorProviderCatalogItem[];
  driftAlerts: DriftAlert[];
  findings: Finding[];
  discoveryApps: DiscoveryApplication[];
  evidenceNodes: EvidenceNode[];
  enforcementEvents: EnforcementEvent[];
  approvals: ApprovalRequest[];
  agents: AgentIdentity[];
  controls: Control[];
  simulationDefinitions: Array<SimulationDefinition & { dsl_json?: Record<string, unknown> }>;
  simulationRuns: SimulationRun[];
  maturity: MaturityRow[];
  conflicts: ControlConflict[];
  aguiActions: AguiAction[];
  aguiDecisions: AguiDecision[];
  jobStatus: JobStatusItem[];
  snapshots: Array<{ id: string; created_at: string; artifact_json: string; artifact_csv: string; hash: string }>;
};

let idCounter = 1000;
let decisionCounter = 10;

function nextId(prefix: string): string {
  idCounter += 1;
  return `${prefix}-${idCounter}`;
}

function minutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60 * 1000).toISOString();
}

function envelope<T>(items: T[], page = 1, pageSize = 200): ListEnvelope<T> {
  return {
    items,
    total: items.length,
    page,
    page_size: pageSize,
  };
}

function buildDemoAuditorControlPosture(
  groupBy: "framework" | "domain" | "ai_system",
  aiSystemId?: string
): AuditorControlPostureView {
  type Bucket = {
    group_key: string;
    group_label: string;
    controls_total: number;
    implemented_controls: number;
    partial_controls: number;
    not_implemented_controls: number;
    maturity_sum: number;
    confidence_sum: number;
    ai_system_ids: Set<string>;
    control_ids: Set<string>;
  };

  const filtered = state.maturity.filter((row) => !aiSystemId || row.ai_system_id === aiSystemId);
  const controlsById = new Map(state.controls.map((item) => [item.id, item]));
  const aiSystemsById = new Map(state.aiSystems.map((item) => [item.id, item]));
  const buckets = new Map<string, Bucket>();

  function classifyState(row: {
    technical_enforcement_score: number;
    simulation_pass_rate: number;
    coverage_score: number;
    maturity_score: number;
    status: string;
  }): "implemented" | "partial" | "not_implemented" {
    if (String(row.status || "").toLowerCase() === "contested") return "partial";
    if (
      row.maturity_score >= 0.75 &&
      row.technical_enforcement_score >= 0.7 &&
      row.simulation_pass_rate >= 0.6 &&
      row.coverage_score >= 0.4
    ) {
      return "implemented";
    }
    if (row.maturity_score >= 0.35 || row.technical_enforcement_score >= 0.4 || row.coverage_score >= 0.25) {
      return "partial";
    }
    return "not_implemented";
  }

  function addToBucket(groupKey: string, groupLabel: string, row: (typeof filtered)[number]) {
    if (!groupKey) return;
    const current =
      buckets.get(groupKey) ||
      ({
        group_key: groupKey,
        group_label: groupLabel,
        controls_total: 0,
        implemented_controls: 0,
        partial_controls: 0,
        not_implemented_controls: 0,
        maturity_sum: 0,
        confidence_sum: 0,
        ai_system_ids: new Set<string>(),
        control_ids: new Set<string>(),
      } satisfies Bucket);

    current.controls_total += 1;
    current.maturity_sum += numberValue(row.maturity_score, 0);
    current.confidence_sum += numberValue(row.confidence_score, 0);
    current.ai_system_ids.add(String(row.ai_system_id || ""));
    current.control_ids.add(String(row.control_id || ""));

    const stateClass = classifyState(row);
    if (stateClass === "implemented") current.implemented_controls += 1;
    else if (stateClass === "partial") current.partial_controls += 1;
    else current.not_implemented_controls += 1;

    buckets.set(groupKey, current);
  }

  for (const row of filtered) {
    const control = controlsById.get(row.control_id);
    const aiSystem = aiSystemsById.get(row.ai_system_id);
    const frameworkMappings = Array.isArray(control?.mapped_framework_refs) ? control.mapped_framework_refs : [];
    const frameworks = frameworkMappings
      .map((item) => (item && typeof item === "object" ? String((item as Record<string, unknown>).framework || "").trim() : ""))
      .filter(Boolean);
    const uniqueFrameworks = frameworks.length ? Array.from(new Set(frameworks)) : ["UNMAPPED"];

    if (groupBy === "framework") {
      uniqueFrameworks.forEach((framework) => addToBucket(framework, framework, row));
      continue;
    }

    if (groupBy === "domain") {
      const domain = String(control?.category || "unknown");
      addToBucket(domain, domain, row);
      continue;
    }

    const aiId = String(row.ai_system_id || "");
    const label = String(aiSystem?.name || aiId || "unknown");
    addToBucket(aiId, label, row);
  }

  const rows = Array.from(buckets.values())
    .map((bucket) => {
      const total = Math.max(1, bucket.controls_total);
      return {
        group_key: bucket.group_key,
        group_label: bucket.group_label,
        controls_total: bucket.controls_total,
        implemented_controls: bucket.implemented_controls,
        partial_controls: bucket.partial_controls,
        not_implemented_controls: bucket.not_implemented_controls,
        avg_maturity_score: bucket.maturity_sum / total,
        avg_confidence_score: bucket.confidence_sum / total,
        ai_system_count: bucket.ai_system_ids.size,
        control_ids: Array.from(bucket.control_ids).sort(),
      };
    })
    .sort((a, b) => a.group_label.localeCompare(b.group_label));

  return {
    group_by: groupBy,
    rows,
  };
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function parseBody(init?: RequestInit): Record<string, unknown> {
  if (!init?.body || typeof init.body !== "string") return {};
  try {
    const parsed = JSON.parse(init.body);
    if (parsed && typeof parsed === "object") return parsed as Record<string, unknown>;
    return {};
  } catch {
    return {};
  }
}

function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

function extractScopedRules(version: PolicyVersion): PolicyScopedRule[] {
  const scope = asRecord(version.scope);
  const raw = scope.scoped_rules;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((item) => item && typeof item === "object" && !Array.isArray(item))
    .map((item) => deepClone(item as PolicyScopedRule));
}

function defaultConnectors(): Connector[] {
  return [
    {
      id: "conn-entra",
      name: "Microsoft Entra ID",
      connector_type: "entra_id",
      provider_key: "entra_id",
      auth_type: "oauth2_client_credentials",
      enabled: true,
      status: "healthy",
      is_stub: false,
      stub_reason: "",
      last_pull_status: "success",
      last_pull_error: null,
      last_signal_count: 37,
      polling_interval_minutes: 15,
      has_secrets: true,
      last_run_at: minutesAgo(18),
    },
    {
      id: "conn-aws",
      name: "AWS IAM + CloudTrail",
      connector_type: "aws",
      provider_key: "aws",
      auth_type: "access_key",
      enabled: true,
      status: "healthy",
      is_stub: false,
      stub_reason: "",
      last_pull_status: "success",
      last_pull_error: null,
      last_signal_count: 22,
      polling_interval_minutes: 15,
      has_secrets: true,
      last_run_at: minutesAgo(7),
    },
    {
      id: "conn-jira",
      name: "Jira",
      connector_type: "jira",
      provider_key: "jira",
      auth_type: "token",
      enabled: true,
      status: "healthy",
      is_stub: false,
      stub_reason: "",
      last_pull_status: "success",
      last_pull_error: null,
      last_signal_count: 12,
      polling_interval_minutes: 15,
      has_secrets: true,
      last_run_at: minutesAgo(25),
    },
  ];
}

function defaultConnectorProviders(): ConnectorProviderCatalogItem[] {
  return [
    {
      provider_key: "entra_id",
      display_name: "Microsoft Entra ID",
      category: "identity",
      supports_live_pull: true,
      is_stub: false,
      stub_reason: "",
      signals: [
        {
          signal_key: "entra.role_change",
          signal_type: "identity.role_change",
          control_id: "CTRL-IDENTITY-001",
          evidence_signal_type: "connector.entra.role_change",
        },
      ],
    },
    {
      provider_key: "aws",
      display_name: "AWS IAM + CloudTrail",
      category: "cloud",
      supports_live_pull: true,
      is_stub: false,
      stub_reason: "",
      signals: [
        {
          signal_key: "aws.public_s3",
          signal_type: "cloud.s3.public_access",
          control_id: "CTRL-CLOUD-001",
          evidence_signal_type: "connector.aws.public_s3",
        },
      ],
    },
    {
      provider_key: "jira",
      display_name: "Jira",
      category: "ticketing",
      supports_live_pull: true,
      is_stub: false,
      stub_reason: "",
      signals: [
        {
          signal_key: "jira.ticket_status",
          signal_type: "ticket.status_change",
          control_id: "CTRL-AUDIT-001",
          evidence_signal_type: "connector.jira.ticket_status",
        },
      ],
    },
  ];
}

function initialState(): DemoState {
  const aiSystems: AISystem[] = [
    {
      id: "ai-sys-1",
      tenant_id: DEMO_TENANT_ID,
      name: "Claims Copilot",
      description: "Insurance claims support model",
      risk_tier: "HIGH",
      status: "active",
    },
    {
      id: "ai-sys-2",
      tenant_id: DEMO_TENANT_ID,
      name: "R&D Assistant",
      description: "Internal research summarization model",
      risk_tier: "CRITICAL",
      status: "approved",
    },
  ];

  const controls: Control[] = [
    {
      id: "CTRL-SEC-001",
      tenant_id: DEMO_TENANT_ID,
      name: "Prompt Injection Guard",
      category: "interaction_security",
      description: "Blocks prompt injection and jailbreak attempts.",
      mapped_framework_refs: [{ framework: "NIST AI RMF", control_ref: "GOV-1" }],
      is_global: false,
      success_criteria: {
        required_sim_pass_rate: 0.8,
        required_evidence_sources: ["telemetry", "simulation", "config"],
        min_maturity: 3,
      },
    },
    {
      id: "CTRL-IAM-001",
      tenant_id: DEMO_TENANT_ID,
      name: "Agent Capability Scoping",
      category: "ai_iam",
      description: "Scopes agent capability tokens and chain depth.",
      mapped_framework_refs: [{ framework: "ISO/IEC 42001", control_ref: "5.2" }],
      is_global: false,
      success_criteria: {
        required_sim_pass_rate: 0.85,
        required_evidence_sources: ["telemetry", "simulation"],
        min_maturity: 3,
      },
    },
  ];

  const simulationDefinitions: Array<SimulationDefinition & { dsl_json?: Record<string, unknown> }> = [
    {
      id: "sim-def-1",
      name: "Prompt Injection Deterministic",
      category: "injection",
      target_module: "interaction_security",
      version: "1.0.0",
      dsl_json: {
        maps_to_controls: ["CTRL-SEC-001"],
        assertions: [{ check: { value: "1" } }],
      },
    },
    {
      id: "sim-def-2",
      name: "Capability Abuse Attempt",
      category: "identity_abuse",
      target_module: "ai_iam",
      version: "1.0.0",
      dsl_json: {
        maps_to_controls: ["CTRL-IAM-001"],
        assertions: [{ check: { value: "never-match" } }],
      },
    },
  ];

  const simulationRuns: SimulationRun[] = [
    {
      id: "sim-run-1",
      simulation_id: "sim-def-1",
      ai_system_id: "ai-sys-1",
      started_at: minutesAgo(180),
      finished_at: minutesAgo(179),
      mode: "deterministic",
      results: {
        result: "pass",
        failed_assertions: [],
        pass_rate: 1,
        iterations: 1,
      },
    },
    {
      id: "sim-run-2",
      simulation_id: "sim-def-2",
      ai_system_id: "ai-sys-1",
      started_at: minutesAgo(120),
      finished_at: minutesAgo(119),
      mode: "deterministic",
      results: {
        result: "fail",
        failed_assertions: ["assertion.block"],
        pass_rate: 0,
        iterations: 1,
      },
    },
  ];

  const maturity: MaturityRow[] = [
    {
      id: "mat-1",
      ai_system_id: "ai-sys-1",
      control_id: "CTRL-SEC-001",
      technical_enforcement_score: 0.75,
      simulation_pass_rate: 0.6,
      coverage_score: 0.8,
      maturity_score: 0.71,
      status: "healthy",
      confidence_score: 0.86,
      confidence_inputs: { telemetry: 4, simulation: 2, conflicts: 0 },
    },
    {
      id: "mat-2",
      ai_system_id: "ai-sys-1",
      control_id: "CTRL-IAM-001",
      technical_enforcement_score: 0.65,
      simulation_pass_rate: 0.4,
      coverage_score: 0.7,
      maturity_score: 0.59,
      status: "needs_review",
      confidence_score: 0.72,
      confidence_inputs: { telemetry: 2, simulation: 2, conflicts: 1 },
    },
  ];

  const evidenceNodes: EvidenceNode[] = [
    {
      id: "ev-1001",
      node_type: "enforcement",
      signal_type: "guardian.prompt_injection.detected",
      label: "Prompt injection detected and held for approval",
      created_at: minutesAgo(90),
    },
    {
      id: "ev-1002",
      node_type: "simulation",
      signal_type: "simulation.fail",
      label: "Identity abuse simulation failed",
      created_at: minutesAgo(70),
    },
    {
      id: "ev-1003",
      node_type: "connector",
      signal_type: "connector.aws.public_s3",
      label: "AWS drift: public access setting changed",
      created_at: minutesAgo(40),
    },
  ];

  const enforcementEvents: EnforcementEvent[] = [
    {
      id: "enf-1",
      request_id: "req-1001",
      ai_system_id: "ai-sys-1",
      final_decision: "hold_for_approval",
      actor_type: "human",
      actor_id: "owner@acme.ai",
      timestamp: minutesAgo(90),
    },
    {
      id: "enf-2",
      request_id: "req-1002",
      ai_system_id: "ai-sys-1",
      final_decision: "warn",
      actor_type: "agent",
      actor_id: "agent-runtime-01",
      timestamp: minutesAgo(35),
    },
  ];

  const approvals: ApprovalRequest[] = [
    {
      id: "apr-1001",
      status: "pending",
      ai_system_id: "ai-sys-1",
      required_roles: ["owner", "admin"],
      created_at: minutesAgo(88),
    },
  ];

  const findings: Finding[] = [
    {
      finding_id: "finding-1001",
      tenant_id: DEMO_TENANT_ID,
      source_surface: "gateway",
      ai_tool: "ChatGPT",
      ai_system_id: "ai-sys-1",
      user_id: "owner-user",
      department: "Claims Ops",
      severity: "critical",
      finding_type: "enforcement_event",
      risk_category: "prompt_injection",
      data_classification: "confidential",
      status: "open",
      recommended_action: "Require approval workflow and escalate to governance for strict policy mode.",
      policy_version_id: "pol-v-1001",
      evidence_node_ids: ["ev-1001"],
      related_control_ids: ["CTRL-SEC-001"],
      occurrence_count: 3,
      first_seen_at: minutesAgo(100),
      last_seen_at: minutesAgo(90),
      created_at: minutesAgo(100),
      updated_at: minutesAgo(90),
    },
    {
      finding_id: "finding-1002",
      tenant_id: DEMO_TENANT_ID,
      source_surface: "browser",
      ai_tool: "Perplexity Pro",
      ai_system_id: null,
      user_id: null,
      department: "Research",
      severity: "high",
      finding_type: "shadow_ai_discovery",
      risk_category: "unsanctioned_tool",
      data_classification: "internal",
      status: "reviewing",
      recommended_action: "Promote to governed app or block domain pending risk review.",
      policy_version_id: "pol-v-1001",
      evidence_node_ids: ["ev-1003"],
      related_control_ids: ["CTRL-SEC-001"],
      occurrence_count: 6,
      first_seen_at: minutesAgo(80),
      last_seen_at: minutesAgo(40),
      created_at: minutesAgo(80),
      updated_at: minutesAgo(40),
    },
    {
      finding_id: "finding-1003",
      tenant_id: DEMO_TENANT_ID,
      source_surface: "aiiam",
      ai_tool: "Internal Agent",
      ai_system_id: "ai-sys-1",
      user_id: "svc-agent-01",
      department: "Platform",
      severity: "med",
      finding_type: "asymmetry_signal",
      risk_category: "agent_misuse",
      data_classification: null,
      status: "open",
      recommended_action: "Run simulation pack and tighten chain depth enforcement.",
      policy_version_id: "pol-v-1001",
      evidence_node_ids: ["ev-1002"],
      related_control_ids: ["CTRL-IAM-001"],
      occurrence_count: 2,
      first_seen_at: minutesAgo(75),
      last_seen_at: minutesAgo(70),
      created_at: minutesAgo(75),
      updated_at: minutesAgo(70),
    },
  ];

  const discoveryApps: DiscoveryApplication[] = [
    {
      id: "disc-1",
      tenant_id: DEMO_TENANT_ID,
      tool_key: "chatgpt",
      tool_name: "ChatGPT",
      vendor: "OpenAI",
      status: "approved",
      owner_user_id: "owner-user",
      owner_department: "Security",
      owner_label: "owner-user",
      provisional_risk_tier: "HIGH",
      ai_system_id: "ai-sys-1",
      first_seen_at: minutesAgo(600),
      last_seen_at: minutesAgo(25),
      risk_score: 82,
      findings_total: 9,
      findings_open: 3,
      recommended_action: "Keep in strict enforcement mode with approval gates.",
      metadata_json: {},
      created_at: minutesAgo(600),
      updated_at: minutesAgo(25),
    },
    {
      id: "disc-2",
      tenant_id: DEMO_TENANT_ID,
      tool_key: "perplexity",
      tool_name: "Perplexity Pro",
      vendor: "Perplexity",
      status: "discovered",
      owner_user_id: null,
      owner_department: "Research",
      owner_label: "Research",
      provisional_risk_tier: "MEDIUM",
      ai_system_id: null,
      first_seen_at: minutesAgo(240),
      last_seen_at: minutesAgo(18),
      risk_score: 71,
      findings_total: 5,
      findings_open: 2,
      recommended_action: "Approve with controls or block immediately.",
      metadata_json: {},
      created_at: minutesAgo(240),
      updated_at: minutesAgo(18),
    },
  ];

  return {
    policyVersions: [
      {
        id: "pol-v-1001",
        tenant_id: DEMO_TENANT_ID,
        pack_id: "pack-1001",
        version: "1.3.0",
        created_at: minutesAgo(180),
        scope: {
          applies_to_risk_tiers: ["HIGH", "CRITICAL"],
          applies_to_actor_types: ["human", "agent"],
        },
        enforcement_defaults: {
          default_decision: "warn",
          escalation: "approval_required",
        },
        guardian_contracts: [],
      },
    ],
    policyPacks: [
      {
        id: "pack-1001",
        tenant_id: DEMO_TENANT_ID,
        name: "Enterprise Runtime Pack",
        description: "Runtime policy pack with guardian matrix and approval escalation.",
        status: "active",
      },
      {
        id: "pack-1002",
        tenant_id: DEMO_TENANT_ID,
        name: "Discovery Observation Pack",
        description: "Monitor-first controls for discovery mode.",
        status: "draft",
      },
    ],
    aiSystems,
    connectors: defaultConnectors(),
    connectorProviders: defaultConnectorProviders(),
    driftAlerts: [
      {
        id: "drift-1",
        tenant_id: DEMO_TENANT_ID,
        ai_system_id: "ai-sys-1",
        title: "MFA disabled for service account",
        status: "open",
        details: "Account svc-runtime has MFA disabled.",
        created_at: minutesAgo(45),
        updated_at: minutesAgo(45),
      },
      {
        id: "drift-2",
        tenant_id: DEMO_TENANT_ID,
        ai_system_id: "ai-sys-2",
        title: "Policy drift in tool scope",
        status: "investigating",
        details: "Allowed tools differ from assigned policy version scope.",
        created_at: minutesAgo(120),
        updated_at: minutesAgo(80),
      },
    ],
    findings,
    discoveryApps,
    evidenceNodes,
    enforcementEvents,
    approvals,
    agents: [
      { id: "agent-1", name: "runtime-agent-1", status: "active", max_chain_depth: 3 },
      { id: "agent-2", name: "audit-agent-1", status: "isolated", max_chain_depth: 2 },
    ],
    controls,
    simulationDefinitions,
    simulationRuns,
    maturity,
    conflicts: [
      {
        id: "conflict-1",
        ai_system_id: "ai-sys-1",
        control_id: "CTRL-SEC-001",
        status: "open",
        reason: "Telemetry and simulation evidence disagree on control health.",
        positive_signals: 3,
        negative_signals: 2,
        detected_at: minutesAgo(55),
        resolved_at: null,
        resolution_decision: null,
      },
      {
        id: "conflict-2",
        ai_system_id: "ai-sys-1",
        control_id: "CTRL-IAM-001",
        status: "resolved",
        reason: "Resolved by auditor adjudication.",
        positive_signals: 1,
        negative_signals: 1,
        detected_at: minutesAgo(180),
        resolved_at: minutesAgo(140),
        resolution_decision: "accept_negative",
      },
    ],
    aguiActions: AGUI_ACTIONS,
    aguiDecisions: [],
    jobStatus: [
      {
        job_name: "approval_sla_timeout",
        runs: [
          {
            id: "jobrun-1",
            job_name: "approval_sla_timeout",
            tenant_id: DEMO_TENANT_ID,
            started_at: minutesAgo(3),
            finished_at: minutesAgo(2),
            status: "success",
            error_message: null,
          },
        ],
      },
      {
        job_name: "connector_pull",
        runs: [
          {
            id: "jobrun-2",
            job_name: "connector_pull",
            tenant_id: DEMO_TENANT_ID,
            started_at: minutesAgo(10),
            finished_at: minutesAgo(9),
            status: "success",
            error_message: null,
          },
        ],
      },
    ],
    snapshots: [],
  };
}

let state: DemoState = initialState();

function recomputeMaturity(aiSystemId: string, controlId: string) {
  const defIds = state.simulationDefinitions
    .filter((def) => ((def.dsl_json?.maps_to_controls as string[] | undefined) || []).includes(controlId))
    .map((def) => def.id);
  const relatedRuns = state.simulationRuns.filter(
    (run) => run.ai_system_id === aiSystemId && defIds.includes(run.simulation_id)
  );
  const passRate = relatedRuns.length
    ? relatedRuns.reduce((acc, run) => acc + numberValue(run.results.pass_rate, run.results.result === "pass" ? 1 : 0), 0) / relatedRuns.length
    : 0.5;
  const existing = state.maturity.find((row) => row.ai_system_id === aiSystemId && row.control_id === controlId);
  const technical = existing?.technical_enforcement_score ?? 0.7;
  const coverage = existing?.coverage_score ?? 0.7;
  const maturityScore = 0.5 * technical + 0.3 * passRate + 0.2 * coverage;
  if (existing) {
    existing.simulation_pass_rate = passRate;
    existing.maturity_score = maturityScore;
    existing.status = maturityScore < 0.6 ? "needs_review" : "healthy";
    existing.confidence_score = Math.max(0.45, Math.min(0.95, 0.55 + relatedRuns.length * 0.05));
    return;
  }
  state.maturity.push({
    id: nextId("mat"),
    ai_system_id: aiSystemId,
    control_id: controlId,
    technical_enforcement_score: technical,
    simulation_pass_rate: passRate,
    coverage_score: coverage,
    maturity_score: maturityScore,
    status: maturityScore < 0.6 ? "needs_review" : "healthy",
    confidence_score: 0.7,
    confidence_inputs: { simulation_runs: relatedRuns.length },
  });
}

function filteredFindings(params: URLSearchParams): Finding[] {
  return state.findings.filter((row) => {
    const statusFilter = params.get("status_filter");
    const severityFilter = params.get("severity_filter");
    const typeFilter = params.get("finding_type_filter");
    const deptFilter = params.get("department_filter");
    const toolFilter = params.get("tool_filter");
    if (statusFilter && row.status !== statusFilter) return false;
    if (severityFilter && row.severity !== severityFilter) return false;
    if (typeFilter && row.finding_type !== typeFilter) return false;
    if (deptFilter && (row.department || "") !== deptFilter) return false;
    if (toolFilter && row.ai_tool !== toolFilter) return false;
    return true;
  });
}

function buildTraceability(finding: Finding): FindingTraceability {
  const application = state.discoveryApps.find((app) => app.tool_name === finding.ai_tool) || null;
  const policyVersion = state.policyVersions.find((policy) => policy.id === finding.policy_version_id) || null;
  const evidence = state.evidenceNodes.filter((node) => finding.evidence_node_ids.includes(node.id)).map((node) => ({
    id: node.id,
    correlation_id: `corr-${node.id}`,
    node_type: node.node_type,
    signal_type: node.signal_type,
    label: node.label,
    payload: {},
    created_at: node.created_at,
  }));
  const relatedControls = state.controls.filter((control) => finding.related_control_ids.includes(control.id));
  const relatedRuns = state.simulationRuns
    .filter((run) =>
      state.simulationDefinitions.some((def) =>
        def.id === run.simulation_id &&
        ((def.dsl_json?.maps_to_controls as string[] | undefined) || []).some((controlId) => finding.related_control_ids.includes(controlId))
      )
    )
    .map((run) => ({
      id: run.id,
      simulation_id: run.simulation_id,
      started_at: run.started_at,
      finished_at: run.finished_at || null,
      mode: run.mode,
      result: run.results.result,
      pass_rate: numberValue(run.results.pass_rate, run.results.result === "pass" ? 1 : 0),
      evidence_node_ids: finding.evidence_node_ids,
      control_maturity_delta: [],
      enforcement_strictness_delta: [],
    }));
  const maturityEffects = state.maturity
    .filter((row) => finding.related_control_ids.includes(row.control_id))
    .map((row) => ({
      control_id: row.control_id,
      maturity_score: row.maturity_score,
      status: row.status,
      confidence_score: row.confidence_score,
      technical_enforcement_score: row.technical_enforcement_score,
      simulation_pass_rate: row.simulation_pass_rate,
      coverage_score: row.coverage_score,
      updated_at: minutesAgo(10),
    }));
  const enforcement = state.enforcementEvents
    .filter((event) => event.ai_system_id === finding.ai_system_id)
    .map((event) => ({
      id: event.id,
      correlation_id: `corr-${event.id}`,
      request_id: event.request_id,
      timestamp: event.timestamp,
      final_decision: event.final_decision,
      policy_version_id: finding.policy_version_id || null,
      evidence_nodes_created: finding.evidence_node_ids,
      controls_impacted: finding.related_control_ids.map((id) => ({ control_id: id, delta: -0.1 })),
      audit_log_id: `audit-${event.id}`,
    }));
  const snapshots = state.snapshots.slice(-3).map((snap) => ({
    id: snap.id,
    ai_system_id: finding.ai_system_id,
    trigger_type: "manual_export",
    artifact_path: snap.artifact_json,
    artifact_hash: snap.hash,
    created_at: snap.created_at,
  }));
  return {
    finding,
    discovery_application: application,
    policy_version: policyVersion
      ? {
          id: policyVersion.id,
          version: policyVersion.version,
          pack_id: policyVersion.pack_id,
          pack_name: state.policyPacks.find((pack) => pack.id === policyVersion.pack_id)?.name || null,
          created_at: minutesAgo(300),
        }
      : null,
    evidence_nodes: evidence,
    related_controls: relatedControls.map((control) => ({
      id: control.id,
      name: control.name,
      category: control.category,
      description: control.description,
      mapped_framework_refs: control.mapped_framework_refs,
    })),
    enforcement_events: enforcement,
    simulation_runs: relatedRuns,
    maturity_effects: maturityEffects,
    auditor_snapshots: snapshots,
    proof_timeline: [
      { step: 1, title: "Detection", status: "complete", timestamp: finding.first_seen_at, summary: "Risk signal detected.", references: { finding_id: finding.finding_id } },
      { step: 2, title: "Policy Evaluated", status: policyVersion ? "complete" : "partial", timestamp: finding.updated_at, summary: "Policy version considered for decision.", references: { policy_version_id: finding.policy_version_id || "-" } },
      { step: 3, title: "Action Taken", status: "complete", timestamp: finding.updated_at, summary: "Status and recommendation captured.", references: { status: finding.status } },
      { step: 4, title: "Evidence Created", status: evidence.length ? "complete" : "missing", timestamp: evidence[0]?.created_at || null, summary: "Evidence nodes linked.", references: { evidence_node_ids: finding.evidence_node_ids } },
      { step: 5, title: "Controls Impacted", status: relatedControls.length ? "complete" : "partial", timestamp: finding.updated_at, summary: "Control mapping resolved.", references: { control_ids: finding.related_control_ids } },
      { step: 6, title: "Simulation Triggered", status: relatedRuns.length ? "complete" : "partial", timestamp: relatedRuns[0]?.started_at || null, summary: "Validation run linkage.", references: { simulation_runs: relatedRuns.map((row) => row.id) } },
      { step: 7, title: "Maturity Effect", status: maturityEffects.length ? "complete" : "partial", timestamp: maturityEffects[0]?.updated_at || null, summary: "Maturity model updated.", references: { maturity: maturityEffects.map((row) => `${row.control_id}:${row.maturity_score.toFixed(2)}`) } },
      { step: 8, title: "Auditor Visibility", status: snapshots.length ? "complete" : "partial", timestamp: snapshots[0]?.created_at || null, summary: "Snapshot/export available for auditor review.", references: { snapshot_ids: snapshots.map((row) => row.id) } },
    ],
  };
}

function auditorDashboard(): AuditorDashboard {
  const averageMaturity =
    state.maturity.length > 0
      ? state.maturity.reduce((acc, item) => acc + item.maturity_score, 0) / state.maturity.length
      : 0;
  const averageConfidence =
    state.maturity.length > 0
      ? state.maturity.reduce((acc, item) => acc + item.confidence_score, 0) / state.maturity.length
      : 0;
  return {
    average_maturity: averageMaturity,
    average_confidence: averageConfidence,
    maturity_count: state.maturity.length,
    needs_review_count: state.maturity.filter((row) => row.status === "needs_review").length,
    contested_count: state.maturity.filter((row) => row.status === "contested").length,
    healthy_count: state.maturity.filter((row) => row.status === "healthy").length,
    open_conflicts_count: state.conflicts.filter((row) => row.status === "open").length,
    recent_enforcement_events: state.enforcementEvents.slice(-5),
    recent_snapshots: state.snapshots.slice(-5),
    recent_conflicts: state.conflicts.slice(-5),
  };
}

function controlTraceability(aiSystemId: string): ControlTraceabilityRow[] {
  return state.controls.map((control) => {
    const mappedSims = state.simulationDefinitions
      .filter((def) => ((def.dsl_json?.maps_to_controls as string[] | undefined) || []).includes(control.id))
      .map((def) => {
        const lastRun = state.simulationRuns
          .filter((run) => run.ai_system_id === aiSystemId && run.simulation_id === def.id)
          .sort((a, b) => (a.started_at < b.started_at ? 1 : -1))[0];
        return {
          simulation_id: def.id,
          name: def.name,
          category: def.category,
          target_module: def.target_module,
          version: def.version,
          last_run: lastRun
            ? {
                run_id: lastRun.id,
                result: lastRun.results.result,
                pass_rate: numberValue(lastRun.results.pass_rate, lastRun.results.result === "pass" ? 1 : 0),
                iterations: numberValue(lastRun.results.iterations, 1),
                started_at: lastRun.started_at,
                finished_at: lastRun.finished_at,
                contribution: lastRun.results.result === "pass" ? 0.1 : -0.1,
              }
            : null,
        };
      });
    const lastRun = mappedSims
      .map((item) => item.last_run)
      .filter(Boolean)
      .sort((a, b) => ((a?.started_at || "") < (b?.started_at || "") ? 1 : -1))[0];
    const mat = state.maturity.find((row) => row.ai_system_id === aiSystemId && row.control_id === control.id);
    return {
      control_id: control.id,
      control_name: control.name,
      control_category: control.category,
      mapped_simulations: mappedSims,
      last_run_result: lastRun
        ? {
            run_id: lastRun.run_id,
            simulation_id: mappedSims.find((item) => item.last_run?.run_id === lastRun.run_id)?.simulation_id || "",
            result: lastRun.result,
            pass_rate: lastRun.pass_rate,
            iterations: lastRun.iterations,
            started_at: lastRun.started_at,
          }
        : null,
      maturity_impact: mat
        ? {
            technical_enforcement_score: mat.technical_enforcement_score,
            simulation_pass_rate: mat.simulation_pass_rate,
            coverage_score: mat.coverage_score,
            maturity_score: mat.maturity_score,
            updated_at: minutesAgo(5),
          }
        : null,
    };
  });
}

function controlCoverage(controlId: string): ControlCoverage {
  const control = state.controls.find((item) => item.id === controlId) || state.controls[0];
  const mappedDefs = state.simulationDefinitions.filter((def) =>
    ((def.dsl_json?.maps_to_controls as string[] | undefined) || []).includes(control.id)
  );
  const runs = state.simulationRuns.filter((run) => mappedDefs.some((def) => def.id === run.simulation_id));
  const overallPassRate = runs.length
    ? runs.reduce((acc, run) => acc + numberValue(run.results.pass_rate, run.results.result === "pass" ? 1 : 0), 0) / runs.length
    : 0;
  return {
    control_id: control.id,
    control_name: control.name,
    framework_refs: control.mapped_framework_refs,
    mapped_simulations: mappedDefs.map((item) => ({
      simulation_id: item.id,
      name: item.name,
      category: item.category,
      target_module: item.target_module,
      version: item.version,
    })),
    coverage_summary: {
      simulation_count: mappedDefs.length,
      run_count: runs.length,
      overall_pass_rate: overallPassRate,
    },
    pass_rate_trend: runs.map((run) => ({
      run_id: run.id,
      simulation_id: run.simulation_id,
      started_at: run.started_at,
      result: run.results.result,
      pass_rate: numberValue(run.results.pass_rate, run.results.result === "pass" ? 1 : 0),
      iterations: numberValue(run.results.iterations, 1),
    })),
    maturity_impact: state.maturity
      .filter((row) => row.control_id === control.id)
      .map((row) => ({
        ai_system_id: row.ai_system_id,
        technical_enforcement_score: row.technical_enforcement_score,
        simulation_pass_rate: row.simulation_pass_rate,
        coverage_score: row.coverage_score,
        maturity_score: row.maturity_score,
        status: row.status,
        updated_at: minutesAgo(3),
      })),
  };
}

function frameworkCoverage(framework: string, minSimulations: number): FrameworkCoverage {
  const controls = state.controls.map((control) => {
    const simulationCount = state.simulationDefinitions.filter((def) =>
      ((def.dsl_json?.maps_to_controls as string[] | undefined) || []).includes(control.id)
    ).length;
    return {
      control_id: control.id,
      control_name: control.name,
      simulation_count: simulationCount,
      covered: simulationCount >= minSimulations,
    };
  });
  const covered = controls.filter((row) => row.covered).length;
  const total = controls.length || 1;
  return {
    framework,
    tenant_id: DEMO_TENANT_ID,
    min_simulations: minSimulations,
    coverage_percent: (covered / total) * 100,
    total_controls: controls.length,
    covered_controls: covered,
    controls,
  };
}

function maturityExplanation(aiSystemId: string, controlId: string): MaturityScoreExplanation {
  const control = state.controls.find((item) => item.id === controlId) || state.controls[0];
  const row = state.maturity.find((item) => item.ai_system_id === aiSystemId && item.control_id === controlId) || state.maturity[0];
  return {
    tenant_id: DEMO_TENANT_ID,
    ai_system_id: aiSystemId,
    control_id: controlId,
    control_name: control?.name || controlId,
    formula: "0.5*technical_enforcement_score + 0.3*simulation_pass_rate + 0.2*coverage_score",
    weights: {
      technical_enforcement_score: 0.5,
      simulation_pass_rate: 0.3,
      coverage_score: 0.2,
    },
    scoring_inputs: {
      technical_enforcement_score: row.technical_enforcement_score,
      simulation_pass_rate: row.simulation_pass_rate,
      coverage_score: row.coverage_score,
    },
    status: row.status,
    confidence_score: row.confidence_score,
    confidence_inputs: row.confidence_inputs,
    maturity_score: row.maturity_score,
    recomputed_maturity_score: row.maturity_score,
    score_delta: 0,
    evidence_links: {
      policy_guardians: [{ policy_version_id: state.policyVersions[0]?.id || "pol-v-1001" }],
      simulation_runs: state.simulationRuns.slice(-5).map((run) => ({ run_id: run.id, result: run.results.result })),
      enforcement_events: state.enforcementEvents.slice(-5).map((event) => ({ event_id: event.id, decision: event.final_decision })),
      evidence_nodes: state.evidenceNodes.slice(-5).map((node) => ({ id: node.id, signal_type: node.signal_type })),
      monitoring_signals: state.driftAlerts.slice(-5).map((alert) => ({ alert_id: alert.id, status: alert.status })),
    },
    recent_history: [
      { at: minutesAgo(180), maturity_score: Math.max(0, row.maturity_score - 0.05) },
      { at: minutesAgo(60), maturity_score: row.maturity_score },
    ],
  };
}

function shouldFailRun(def: SimulationDefinition & { dsl_json?: Record<string, unknown> }): boolean {
  const assertions = (def.dsl_json?.assertions as Array<{ check?: { value?: unknown } }> | undefined) || [];
  return assertions.some((item) => stringValue(item?.check?.value) === "never-match");
}

function auditExportResponse(aiSystemId: string) {
  const snapshotId = nextId("snap");
  const ts = new Date().toISOString().replaceAll(":", "-");
  const artifacts: AuditorExportArtifacts = {
    json: `artifacts/${snapshotId}-${ts}.json`,
    csv: `artifacts/${snapshotId}-${ts}.csv`,
    hash: `hash-${snapshotId}`,
  };
  state.snapshots.push({
    id: snapshotId,
    created_at: new Date().toISOString(),
    artifact_json: artifacts.json,
    artifact_csv: artifacts.csv,
    hash: artifacts.hash,
  });
  state.evidenceNodes.push({
    id: nextId("ev"),
    node_type: "auditor_snapshot",
    signal_type: "auditor.snapshot.exported",
    label: `Auditor snapshot exported for ${aiSystemId}`,
    created_at: new Date().toISOString(),
  });
  return { artifacts, snapshot_id: snapshotId };
}

// Only the demo build (DEMO_BUILD=1, infra/Dockerfile.web.demo) compiles this module in; every other build gets
// demo-fallback-off.ts instead (next.config.mjs). The event name doubles as the marker the production Dockerfile looks
// for in its output (demo-build.mjs DEMO_FALLBACK_MARKER).
const DEMO_DATA_EVENT = "hawk-demo-fallback-data";
let demoDataServed = false;

export function isDemoFallbackEnabled(): boolean {
  if (process.env.NEXT_PUBLIC_HAWK_DEMO_BUILD !== "1") return false;
  const pilotMode = (process.env.NEXT_PUBLIC_PILOT_MODE || "false").toLowerCase() === "true";
  if (pilotMode) return false;
  const demoMode = (process.env.NEXT_PUBLIC_DEMO_MODE || "false").toLowerCase() === "true";
  if (!demoMode) return false;
  return (process.env.NEXT_PUBLIC_DEMO_FALLBACK || "false").toLowerCase() !== "false";
}

/** Whether invented demo data has been shown in this browser tab: the console then says "Demo data" on every view. */
export function demoDataShown(): boolean {
  return demoDataServed;
}

export function subscribeDemoData(listener: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  window.addEventListener(DEMO_DATA_EVENT, listener);
  return () => window.removeEventListener(DEMO_DATA_EVENT, listener);
}

export function demoFallbackRequest(
  path: string,
  init?: RequestInit,
  session?: Session | null
): unknown | null {
  const result = demoFallbackResponse(path, init, session);
  if (result !== null && !demoDataServed) {
    demoDataServed = true;
    if (typeof window !== "undefined") window.dispatchEvent(new Event(DEMO_DATA_EVENT));
  }
  return result;
}

function demoFallbackResponse(
  path: string,
  init?: RequestInit,
  session?: Session | null
): unknown | null {
  if (!isDemoFallbackEnabled()) return null;

  const method = (init?.method || "GET").toUpperCase();
  const url = new URL(path, "http://demo.local");
  const pathname = url.pathname;
  const body = parseBody(init);
  const tenantId = session?.tenantId || DEMO_TENANT_ID;
  const actorId = session?.user?.email || "owner@acme.ai";

  if (pathname === "/auth/login" && method === "POST") {
    const email = stringValue(body.email, "owner@acme.ai");
    const role = email.includes("auditor") ? "auditor" : email.includes("operator") ? "operator" : "owner";
    const response: LoginResponse = {
      access_token: "demo-access-token",
      refresh_token: "demo-refresh-token",
      token_type: "bearer",
      user: {
        id: "demo-user",
        email,
        full_name: role === "auditor" ? "Demo Auditor" : "Demo Owner",
      },
      tenants: [
        {
          id: DEMO_TENANT_ID,
          name: DEMO_TENANT_NAME,
          role,
        },
      ],
      selected_tenant_id: DEMO_TENANT_ID,
    };
    return response;
  }

  if (pathname === "/auth/me" && method === "GET") {
    return {
      id: "demo-user",
      email: actorId,
      full_name: "Demo User",
      tenants: [{ id: DEMO_TENANT_ID, name: DEMO_TENANT_NAME }],
    };
  }

  if (pathname === "/ai-systems" && method === "GET") return envelope(deepClone(state.aiSystems));
  if (pathname === "/ai-systems" && method === "POST") {
    const row: AISystem = {
      id: nextId("ai-sys"),
      tenant_id: tenantId,
      name: stringValue(body.name, "Demo AI System"),
      description: stringValue(body.description, "Demo AI system"),
      risk_tier: stringValue(body.risk_tier, "MEDIUM"),
      status: stringValue(body.status, "draft"),
    };
    state.aiSystems.push(row);
    return deepClone(row);
  }
  const aiSystemMatch = pathname.match(/^\/ai-systems\/([^/]+)$/);
  if (aiSystemMatch && method === "PATCH") {
    const row = state.aiSystems.find((item) => item.id === aiSystemMatch[1]);
    if (!row) return null;
    row.name = stringValue(body.name, row.name);
    row.description = stringValue(body.description, row.description);
    row.risk_tier = stringValue(body.risk_tier, row.risk_tier);
    row.status = stringValue(body.status, row.status);
    return deepClone(row);
  }

  if (pathname === "/policies/packs" && method === "GET") return envelope(deepClone(state.policyPacks));
  if (pathname === "/policies/packs" && method === "POST") {
    const pack: PolicyPack = {
      id: nextId("pack"),
      tenant_id: tenantId,
      name: stringValue(body.name, "Demo Policy Pack"),
      description: stringValue(body.description, ""),
      status: stringValue(body.status, "draft"),
    };
    state.policyPacks.push(pack);
    return { pack: deepClone(pack) };
  }
  const policyPackMatch = pathname.match(/^\/policies\/packs\/([^/]+)$/);
  if (policyPackMatch && method === "PATCH") {
    const row = state.policyPacks.find((item) => item.id === policyPackMatch[1]);
    if (!row) return null;
    row.name = stringValue(body.name, row.name);
    row.description = stringValue(body.description, row.description);
    row.status = stringValue(body.status, row.status);
    return { pack: deepClone(row) };
  }
  const policyVersionListMatch = pathname.match(/^\/policies\/packs\/([^/]+)\/versions$/);
  if (policyVersionListMatch && method === "GET") {
    return envelope(deepClone(state.policyVersions.filter((item) => item.pack_id === policyVersionListMatch[1])));
  }
  if (policyVersionListMatch && method === "POST") {
    const row: PolicyVersion = {
      id: nextId("pol-v"),
      tenant_id: tenantId,
      pack_id: policyVersionListMatch[1],
      version: stringValue(body.version, "1.0.0"),
      created_at: new Date().toISOString(),
      scope: (body.scope as Record<string, unknown>) || {},
      enforcement_defaults: (body.enforcement_defaults as Record<string, unknown>) || {},
      guardian_contracts: (body.guardian_contracts as Array<Record<string, unknown>>) || [],
    };
    state.policyVersions.push(row);
    return deepClone(row);
  }
  const scopedRulesMatch = pathname.match(/^\/policies\/versions\/([^/]+)\/scoped-rules$/);
  if (scopedRulesMatch && method === "GET") {
    const row = state.policyVersions.find((item) => item.id === scopedRulesMatch[1]);
    if (!row) return null;
    const scopedRules = extractScopedRules(row);
    return {
      policy_version_id: row.id,
      scoped_rules: scopedRules,
      rule_count: scopedRules.length,
    };
  }
  if (scopedRulesMatch && method === "PATCH") {
    const row = state.policyVersions.find((item) => item.id === scopedRulesMatch[1]);
    if (!row) return null;
    const scopedRules = Array.isArray(body.scoped_rules)
      ? body.scoped_rules.filter((item) => item && typeof item === "object" && !Array.isArray(item))
      : [];
    const scope = asRecord(row.scope);
    scope.scoped_rules = deepClone(scopedRules);
    row.scope = scope;
    return {
      policy_version_id: row.id,
      scoped_rules: deepClone(scopedRules),
      rule_count: scopedRules.length,
    };
  }
  if (pathname === "/policies/running" && method === "GET") {
    const activePacks = state.policyPacks.filter((item) => String(item.status || "").toLowerCase() === "active");
    const activePackIds = new Set(activePacks.map((item) => item.id));
    const runningVersions = state.policyVersions
      .filter((item) => activePackIds.has(item.pack_id))
      .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
      .map((item) => {
        const pack = activePacks.find((row) => row.id === item.pack_id);
        return {
          id: item.id,
          pack_id: item.pack_id,
          pack_name: pack?.name || item.pack_id,
          pack_status: pack?.status || "active",
          version: item.version,
          created_at: item.created_at,
          guardian_count: (item.guardian_contracts || []).length,
          default_decision: String((item.enforcement_defaults || {}).default_decision || "allow"),
          escalation: String((item.enforcement_defaults || {}).escalation || "notify"),
        };
      });
    return {
      enforced_policy_version_id: runningVersions[0]?.id || "none",
      platform_mode: "enforce",
      active_pack_count: activePacks.length,
      running_versions: runningVersions,
    };
  }

  if (pathname === "/enforcement/events" && method === "GET") {
    const rows = deepClone(state.enforcementEvents).sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
    return envelope(rows);
  }
  if (pathname === "/auditor/control-posture" && method === "GET") {
    const groupByRaw = String(url.searchParams.get("group_by") || "framework").trim().toLowerCase();
    const groupBy = (["framework", "domain", "ai_system"].includes(groupByRaw)
      ? groupByRaw
      : "framework") as "framework" | "domain" | "ai_system";
    const aiSystemId = String(url.searchParams.get("ai_system_id") || "").trim() || undefined;
    return buildDemoAuditorControlPosture(groupBy, aiSystemId);
  }
  if (pathname === "/enforcement/approvals" && method === "GET") {
    const filter = url.searchParams.get("status_filter");
    const rows = state.approvals.filter((row) => !filter || row.status === filter);
    return envelope(deepClone(rows));
  }
  const approvalDecisionMatch = pathname.match(/^\/enforcement\/approvals\/([^/]+)\/decision$/);
  if (approvalDecisionMatch && method === "POST") {
    const row = state.approvals.find((item) => item.id === approvalDecisionMatch[1]);
    if (!row) return null;
    const decision = stringValue(body.decision, "deny");
    row.status = decision === "approve" ? "approved" : "denied";
    return { approval_id: row.id, status: row.status };
  }

  if (pathname === "/gateway/llm/intercept" && method === "POST") {
    const aiSystemId = stringValue(body.ai_system_id, state.aiSystems[0]?.id || "ai-sys-1");
    const prompt = stringValue(body.prompt, "");
    const requestId = nextId("req");
    const eventId = nextId("enf");
    const decision = prompt.toLowerCase().includes("ignore") || prompt.toLowerCase().includes("secret")
      ? "hold_for_approval"
      : "warn";
    const evidenceId = nextId("ev");
    state.evidenceNodes.push({
      id: evidenceId,
      node_type: "enforcement",
      signal_type: "guardian.enforced",
      label: `LLM intercept decision=${decision}`,
      created_at: new Date().toISOString(),
    });
    const event: EnforcementEvent = {
      id: eventId,
      request_id: requestId,
      ai_system_id: aiSystemId,
      final_decision: decision,
      actor_type: stringValue(body.actor_type, "human"),
      actor_id: stringValue(body.actor_id, actorId),
      timestamp: new Date().toISOString(),
    };
    state.enforcementEvents.push(event);

    const approvalIds: string[] = [];
    if (decision === "hold_for_approval") {
      const approval: ApprovalRequest = {
        id: nextId("apr"),
        status: "pending",
        ai_system_id: aiSystemId,
        required_roles: ["owner", "admin"],
        created_at: new Date().toISOString(),
      };
      state.approvals.push(approval);
      approvalIds.push(approval.id);
    }

    const maybeSystem = state.aiSystems.find((item) => item.id === aiSystemId);
    const finding: Finding = {
      finding_id: nextId("finding"),
      tenant_id: tenantId,
      source_surface: "gateway",
      ai_tool: maybeSystem?.name || "Unknown AI Tool",
      ai_system_id: aiSystemId,
      user_id: stringValue(body.actor_id, actorId),
      department: "Security",
      severity: decision === "hold_for_approval" ? "high" : "med",
      finding_type: "enforcement_event",
      risk_category: "runtime_enforcement",
      data_classification: "internal",
      status: "open",
      recommended_action: decision === "hold_for_approval" ? "Review approval and tighten policy." : "Monitor warning outcomes.",
      policy_version_id: state.policyVersions[0]?.id || null,
      evidence_node_ids: [evidenceId],
      related_control_ids: ["CTRL-SEC-001"],
      occurrence_count: 1,
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    state.findings.push(finding);
    return {
      event_id: eventId,
      final_decision: decision,
      approval_request_ids: approvalIds,
      evidence_nodes_created: [evidenceId],
    };
  }

  if (pathname === "/gateway/mcp/authorize" && method === "POST") {
    const token = stringValue(body.capability_token);
    const action = stringValue(body.action);
    const decision = token && token.includes(action) ? "allow" : "block";
    const evidenceId = nextId("ev");
    state.evidenceNodes.push({
      id: evidenceId,
      node_type: "mcp_authorize",
      signal_type: "gateway.mcp.authorize",
      label: `MCP authorize ${decision} for action ${action}`,
      created_at: new Date().toISOString(),
    });
    return { decision, evidence_node_id: evidenceId };
  }

  if (pathname === "/ai-iam/agents" && method === "GET") return envelope(deepClone(state.agents));
  if (pathname === "/ai-iam/agents" && method === "POST") {
    const row: AgentIdentity = {
      id: nextId("agent"),
      name: stringValue(body.name, "runtime-agent"),
      status: "active",
      max_chain_depth: numberValue(body.max_chain_depth, 3),
    };
    state.agents.push(row);
    return deepClone(row);
  }
  if (pathname === "/ai-iam/identities" && method === "GET") {
    const items = state.agents.map((agent) => ({
      identity_id: agent.id,
      type: "agent",
      owner: "owner@acme.ai",
      model: "gpt-4.1-mini",
      environment: ["browser", "gateway"],
      permissions: {
        tools: (agent.tool_registry || []).slice(0, 8),
        data: ["internal"],
        actions: (agent.action_scope || []).slice(0, 8),
      },
      token_scope: (agent.action_scope || []).slice(0, 8),
      expiry: null,
      status: agent.status || "active",
      risk_score: 0.32,
      blast_radius_score: 2.4,
      crq: {
        ALE: 45000,
        SLE: 180000,
        ARO: 0.25,
        baseline_ALE: 120000,
        loss_reduction: 75000,
        remediation_cost: 22000,
        decision_impact_score: 3.41,
        control_effectiveness: 0.62,
      },
      risk_components: {
        privilege_score: 0.41,
        behavior_anomaly_score: 0.16,
        control_failure_score: 0.12,
        exposure_score: 0.34,
        simulation_failure_score: 0.15,
      },
      token_control: {
        active_token_count: 1,
        kill_switch_ready: true,
        rotation_recommended: false,
      },
      anomalies: { count: 0, recent_high: 0 },
      controls: {
        triggered_controls: ["AI_IDENTITY_BINDING"],
        missed_controls: [],
        failed_controls: 0,
        total_controls_evaluated: 12,
        effectiveness: 0.62,
      },
      simulation: {
        total_runs: 3,
        pass: 3,
        fail: 0,
        partial: 0,
        not_executable: 0,
        pass_rate: 1.0,
      },
      exposure_context: {
        allowed_targets: agent.external_system_access || [],
        observed_targets: agent.external_system_access || [],
        internet_exposed_count: 1,
        mcp_connection_count: 0,
      },
      graph_summary: {
        node_count: 12,
        edge_count: 18,
        event_count: 4,
      },
      owasp_summary: {
        total_categories: 5,
        runtime_active_categories: 3,
        simulation_active_categories: 2,
        controls_observed_count: 7,
      },
      blast_radius: null,
      lookback_hours: 720,
      updated_at: new Date().toISOString(),
    }));
    return envelope(items);
  }
  const aiiamIdentityMatch = pathname.match(/^\/ai-iam\/identities\/([^/]+)$/);
  if (aiiamIdentityMatch && method === "GET") {
    const identityId = decodeURIComponent(aiiamIdentityMatch[1]);
    const agent = state.agents.find((item) => item.id === identityId);
    if (!agent) return null;
    return {
      identity_id: agent.id,
      type: "agent",
      owner: "owner@acme.ai",
      model: "gpt-4.1-mini",
      environment: ["browser", "gateway"],
      permissions: {
        tools: (agent.tool_registry || []).slice(0, 8),
        data: ["internal"],
        actions: (agent.action_scope || []).slice(0, 8),
      },
      token_scope: (agent.action_scope || []).slice(0, 8),
      expiry: null,
      status: agent.status || "active",
      risk_score: 0.32,
      blast_radius_score: 2.4,
      crq: {
        ALE: 45000,
        SLE: 180000,
        ARO: 0.25,
        baseline_ALE: 120000,
        loss_reduction: 75000,
        remediation_cost: 22000,
        decision_impact_score: 3.41,
        control_effectiveness: 0.62,
      },
      risk_components: {
        privilege_score: 0.41,
        behavior_anomaly_score: 0.16,
        control_failure_score: 0.12,
        exposure_score: 0.34,
        simulation_failure_score: 0.15,
      },
      token_control: {
        active_token_count: 1,
        kill_switch_ready: true,
        rotation_recommended: false,
      },
      anomalies: { count: 0, recent_high: 0 },
      controls: {
        triggered_controls: ["AI_IDENTITY_BINDING"],
        missed_controls: [],
        failed_controls: 0,
        total_controls_evaluated: 12,
        effectiveness: 0.62,
      },
      simulation: {
        total_runs: 3,
        pass: 3,
        fail: 0,
        partial: 0,
        not_executable: 0,
        pass_rate: 1.0,
      },
      exposure_context: {
        allowed_targets: agent.external_system_access || [],
        observed_targets: agent.external_system_access || [],
        internet_exposed_count: 1,
        mcp_connection_count: 0,
      },
      graph_summary: {
        node_count: 12,
        edge_count: 18,
        event_count: 4,
      },
      owasp_summary: {
        total_categories: 5,
        runtime_active_categories: 3,
        simulation_active_categories: 2,
        controls_observed_count: 7,
      },
      blast_radius: null,
      lookback_hours: 720,
      updated_at: new Date().toISOString(),
    };
  }
  const agentTokenMatch = pathname.match(/^\/ai-iam\/agents\/([^/]+)\/tokens$/);
  if (agentTokenMatch && method === "POST") {
    const scopes = (body.scopes as string[] | undefined) || [];
    return {
      capability_token: `demo-token:${agentTokenMatch[1]}:${scopes.join(",")}`,
      token_id: nextId("tok"),
      scopes,
    };
  }
  const killSwitchMatch = pathname.match(/^\/ai-iam\/agents\/([^/]+)\/kill-switch$/);
  if (killSwitchMatch && method === "POST") {
    const row = state.agents.find((item) => item.id === killSwitchMatch[1]);
    if (row) row.status = "isolated";
    state.evidenceNodes.push({
      id: nextId("ev"),
      node_type: "kill_switch",
      signal_type: "aiiam.kill_switch.executed",
      label: `Kill switch executed for ${killSwitchMatch[1]}`,
      created_at: new Date().toISOString(),
    });
    return { status: "isolated", agent_id: killSwitchMatch[1] };
  }

  if (pathname === "/monitoring/connectors/providers" && method === "GET") return envelope(deepClone(state.connectorProviders));
  if (pathname === "/monitoring/connectors" && method === "GET") return envelope(deepClone(state.connectors));
  if (pathname === "/monitoring/connectors" && method === "POST") {
    const row: Connector = {
      id: nextId("conn"),
      name: stringValue(body.name, "Demo Connector"),
      connector_type: stringValue(body.connector_type, stringValue(body.provider_key, "custom")),
      provider_key: stringValue(body.provider_key, "custom"),
      auth_type: stringValue(body.auth_type, "token"),
      enabled: body.enabled !== false,
      status: "healthy",
      is_stub: false,
      stub_reason: "",
      last_pull_status: "success",
      last_pull_error: null,
      last_signal_count: 0,
      polling_interval_minutes: numberValue(body.polling_interval_minutes, 15),
      has_secrets: true,
      last_run_at: null,
    };
    state.connectors.push(row);
    return deepClone(row);
  }
  const connectorPullMatch = pathname.match(/^\/monitoring\/connectors\/([^/]+)\/pull$/);
  if (connectorPullMatch && method === "POST") {
    const row = state.connectors.find((item) => item.id === connectorPullMatch[1]);
    if (!row) return null;
    row.last_pull_status = "success";
    row.last_signal_count = Math.max(1, row.last_signal_count + 3);
    row.last_run_at = new Date().toISOString();
    state.evidenceNodes.push({
      id: nextId("ev"),
      node_type: "connector_pull",
      signal_type: `connector.${row.provider_key}.pull`,
      label: `${row.name} pulled ${row.last_signal_count} signals`,
      created_at: row.last_run_at,
    });
    return deepClone(row);
  }
  if (pathname === "/monitoring/drift-alerts" && method === "GET") return envelope(deepClone(state.driftAlerts));
  if (pathname === "/monitoring/shadow-events" && method === "POST") {
    const toolName = stringValue(body.ai_tool, "Unknown AI Tool");
    const appId = nextId("disc");
    const app: DiscoveryApplication = {
      id: appId,
      tenant_id: tenantId,
      tool_key: toolName.toLowerCase().replace(/\s+/g, "-"),
      tool_name: toolName || `Shadow Tool ${appId}`,
      vendor: "Unknown",
      status: "discovered",
      owner_user_id: null,
      owner_department: "Unknown",
      owner_label: "Unknown",
      provisional_risk_tier: "MEDIUM",
      ai_system_id: null,
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      risk_score: 66,
      findings_total: 1,
      findings_open: 1,
      recommended_action: "Promote with governance owner or block usage.",
      metadata_json: body.payload as Record<string, unknown>,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    state.discoveryApps.push(app);
    const evidenceId = nextId("ev");
    state.evidenceNodes.push({
      id: evidenceId,
      node_type: "shadow_discovery",
      signal_type: "shadow_ai.detected",
      label: `Shadow AI detected: ${app.tool_name}`,
      created_at: new Date().toISOString(),
    });
    const finding: Finding = {
      finding_id: nextId("finding"),
      tenant_id: tenantId,
      source_surface: "monitoring",
      ai_tool: app.tool_name,
      ai_system_id: null,
      user_id: null,
      department: app.owner_department,
      severity: "high",
      finding_type: "shadow_ai_discovery",
      risk_category: "unsanctioned_tool",
      data_classification: null,
      status: "open",
      recommended_action: "Assign owner and choose approve/monitor/block.",
      policy_version_id: state.policyVersions[0]?.id || null,
      evidence_node_ids: [evidenceId],
      related_control_ids: ["CTRL-SEC-001"],
      occurrence_count: 1,
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    state.findings.push(finding);
    return { id: nextId("shadow"), application_id: app.id, finding_id: finding.finding_id };
  }
  if (pathname === "/monitoring/signals" && method === "POST") {
    const evidenceId = nextId("ev");
    state.evidenceNodes.push({
      id: evidenceId,
      node_type: "monitoring_signal",
      signal_type: stringValue(body.signal_type, "monitoring.signal"),
      label: stringValue(body.title, "Monitoring signal received"),
      created_at: new Date().toISOString(),
    });
    return { id: nextId("signal"), evidence_node_id: evidenceId };
  }

  if (pathname === "/findings" && method === "GET") return envelope(deepClone(filteredFindings(url.searchParams)));
  const findingDetailMatch = pathname.match(/^\/findings\/([^/]+)$/);
  if (findingDetailMatch && method === "GET") {
    const row = state.findings.find((item) => item.finding_id === findingDetailMatch[1]);
    return row ? deepClone(row) : null;
  }
  const findingTraceMatch = pathname.match(/^\/findings\/([^/]+)\/traceability$/);
  if (findingTraceMatch && method === "GET") {
    const row = state.findings.find((item) => item.finding_id === findingTraceMatch[1]);
    return row ? buildTraceability(deepClone(row)) : null;
  }
  const findingStatusMatch = pathname.match(/^\/findings\/([^/]+)\/status$/);
  if (findingStatusMatch && method === "POST") {
    const row = state.findings.find((item) => item.finding_id === findingStatusMatch[1]);
    if (!row) return null;
    row.status = stringValue(body.status, row.status) as Finding["status"];
    row.updated_at = new Date().toISOString();
    return deepClone(row);
  }
  const findingOwnerMatch = pathname.match(/^\/findings\/([^/]+)\/assign-owner$/);
  if (findingOwnerMatch && method === "POST") {
    const row = state.findings.find((item) => item.finding_id === findingOwnerMatch[1]);
    if (!row) return null;
    if (body.owner_user_id) row.user_id = stringValue(body.owner_user_id);
    if (body.owner_department) row.department = stringValue(body.owner_department);
    row.updated_at = new Date().toISOString();
    return deepClone(row);
  }
  const findingEscalateMatch = pathname.match(/^\/findings\/([^/]+)\/escalate$/);
  if (findingEscalateMatch && method === "POST") {
    const row = state.findings.find((item) => item.finding_id === findingEscalateMatch[1]);
    if (!row) return null;
    row.severity = row.severity === "critical" ? "critical" : "high";
    row.status = "reviewing";
    row.updated_at = new Date().toISOString();
    return deepClone(row);
  }
  const findingValidationMatch = pathname.match(/^\/findings\/([^/]+)\/run-validation-pack$/);
  if (findingValidationMatch && method === "POST") {
    const finding = state.findings.find((item) => item.finding_id === findingValidationMatch[1]);
    if (!finding) return null;
    const simDef = state.simulationDefinitions[0];
    const runId = nextId("sim-run");
    const pass = false;
    const evidenceId = nextId("ev");
    state.evidenceNodes.push({
      id: evidenceId,
      node_type: "simulation",
      signal_type: "simulation.validation_pack",
      label: `Validation pack run for ${finding.finding_id}`,
      created_at: new Date().toISOString(),
    });
    const response: FindingValidationPackResponse = {
      finding_id: finding.finding_id,
      ai_system_id: finding.ai_system_id || "ai-sys-1",
      total_runs: 1,
      runs: [
        {
          simulation_id: simDef.id,
          simulation_name: simDef.name,
          run_id: runId,
          result: pass ? "pass" : "fail",
          pass_rate: pass ? 1 : 0,
          evidence_node_ids: [evidenceId],
          control_maturity_delta: finding.related_control_ids.map((id) => ({ control_id: id, delta: pass ? 0.05 : -0.2 })),
          enforcement_strictness_delta: finding.related_control_ids.map((id) => ({ control_id: id, delta: pass ? 0 : 1 })),
        },
      ],
    };
    return response;
  }
  const findingTicketMatch = pathname.match(/^\/findings\/([^/]+)\/create-ticket$/);
  if (findingTicketMatch && method === "POST") {
    const finding = state.findings.find((item) => item.finding_id === findingTicketMatch[1]);
    if (!finding) return null;
    const response: FindingTicketResponse = {
      finding: deepClone(finding),
      ticket_id: nextId("jira"),
      ticket_system: stringValue(body.system, "jira"),
      severity: finding.severity,
      created_at: new Date().toISOString(),
    };
    return response;
  }
  const findingAcceptMatch = pathname.match(/^\/findings\/([^/]+)\/recommendation\/accept$/);
  if (findingAcceptMatch && method === "POST") {
    const finding = state.findings.find((item) => item.finding_id === findingAcceptMatch[1]);
    if (!finding) return null;
    finding.status = "accepted_risk";
    finding.updated_at = new Date().toISOString();
    return deepClone(finding);
  }

  if (pathname === "/discovery/applications" && method === "GET") {
    const statusFilter = url.searchParams.get("status_filter");
    const items = statusFilter ? state.discoveryApps.filter((item) => item.status === statusFilter) : state.discoveryApps;
    return envelope(deepClone(items));
  }
  const discoveryDetailMatch = pathname.match(/^\/discovery\/applications\/([^/]+)$/);
  if (discoveryDetailMatch && method === "GET") {
    const row = state.discoveryApps.find((item) => item.id === discoveryDetailMatch[1]);
    return row ? deepClone(row) : null;
  }
  const discoveryPromoteMatch = pathname.match(/^\/discovery\/applications\/([^/]+)\/promote$/);
  if (discoveryPromoteMatch && method === "POST") {
    const row = state.discoveryApps.find((item) => item.id === discoveryPromoteMatch[1]);
    if (!row) return null;
    const action = stringValue(body.action, "keep_monitoring");
    row.provisional_risk_tier = stringValue(body.provisional_risk_tier, row.provisional_risk_tier || "MEDIUM");
    row.status = action === "approve" ? "approved" : "monitoring";
    if (action === "approve" && !row.ai_system_id) {
      const aiSystem: AISystem = {
        id: nextId("ai-sys"),
        tenant_id: tenantId,
        name: `${row.tool_name} Governed`,
        description: `Promoted from discovery application ${row.id}`,
        risk_tier: row.provisional_risk_tier || "MEDIUM",
        status: "active",
      };
      state.aiSystems.push(aiSystem);
      row.ai_system_id = aiSystem.id;
    }
    row.updated_at = new Date().toISOString();
    return deepClone(row);
  }
  const discoveryBlockMatch = pathname.match(/^\/discovery\/applications\/([^/]+)\/block$/);
  if (discoveryBlockMatch && method === "POST") {
    const row = state.discoveryApps.find((item) => item.id === discoveryBlockMatch[1]);
    if (!row) return null;
    row.status = "blocked";
    row.updated_at = new Date().toISOString();
    return deepClone(row);
  }
  const discoveryOwnerMatch = pathname.match(/^\/discovery\/applications\/([^/]+)\/assign-owner$/);
  if (discoveryOwnerMatch && method === "POST") {
    const row = state.discoveryApps.find((item) => item.id === discoveryOwnerMatch[1]);
    if (!row) return null;
    if (body.owner_user_id) {
      row.owner_user_id = stringValue(body.owner_user_id);
      row.owner_label = row.owner_user_id;
    }
    if (body.owner_department) {
      row.owner_department = stringValue(body.owner_department);
      row.owner_label = row.owner_department;
    }
    row.updated_at = new Date().toISOString();
    return deepClone(row);
  }

  if (pathname === "/simulations/definitions" && method === "GET") {
    return envelope(deepClone(state.simulationDefinitions.map((item) => ({
      id: item.id,
      name: item.name,
      category: item.category,
      target_module: item.target_module,
      version: item.version,
    }))));
  }
  if (pathname === "/simulations/runs" && method === "GET") return envelope(deepClone(state.simulationRuns));
  if (pathname === "/simulations/controls" && method === "GET") return envelope(deepClone(state.controls));
  if (pathname === "/simulations/controls" && method === "POST") {
    const row: Control = {
      id: stringValue(body.id, nextId("CTRL-DEMO")),
      tenant_id: tenantId,
      name: stringValue(body.name, "Demo Control"),
      category: stringValue(body.category, "monitoring"),
      description: stringValue(body.description, ""),
      mapped_framework_refs: (body.mapped_framework_refs as Array<Record<string, unknown>>) || [],
      is_global: Boolean(body.is_global),
      success_criteria: (body.success_criteria as Record<string, unknown>) || {},
    };
    state.controls.push(row);
    return deepClone(row);
  }
  if (pathname === "/simulations/definitions" && method === "POST") {
    const row: SimulationDefinition & { dsl_json?: Record<string, unknown> } = {
      id: nextId("sim-def"),
      name: stringValue(body.name, "Demo Simulation"),
      category: stringValue(body.category, "injection"),
      target_module: stringValue(body.target_module, "interaction_security"),
      version: stringValue(body.version, "1.0.0"),
      dsl_json: (body.dsl_json as Record<string, unknown>) || {},
    };
    state.simulationDefinitions.push(row);
    return { id: row.id, name: row.name, category: row.category, target_module: row.target_module, version: row.version };
  }
  const simulationPatchMatch = pathname.match(/^\/simulations\/definitions\/([^/]+)$/);
  if (simulationPatchMatch && method === "PATCH") {
    const row = state.simulationDefinitions.find((item) => item.id === simulationPatchMatch[1]);
    if (!row) return null;
    row.name = stringValue(body.name, row.name);
    row.category = stringValue(body.category, row.category);
    row.target_module = stringValue(body.target_module, row.target_module);
    row.version = stringValue(body.version, row.version);
    row.dsl_json = (body.dsl_json as Record<string, unknown>) || row.dsl_json;
    return { id: row.id, name: row.name, category: row.category, target_module: row.target_module, version: row.version };
  }
  const simulationRunMatch = pathname.match(/^\/simulations\/definitions\/([^/]+)\/run$/);
  if (simulationRunMatch && method === "POST") {
    const def = state.simulationDefinitions.find((item) => item.id === simulationRunMatch[1]);
    if (!def) return null;
    const aiSystemId = stringValue(body.ai_system_id, state.aiSystems[0]?.id || "ai-sys-1");
    const fail = shouldFailRun(def);
    const run: SimulationRun = {
      id: nextId("sim-run"),
      simulation_id: def.id,
      ai_system_id: aiSystemId,
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      mode: stringValue(body.mode, "deterministic"),
      results: {
        result: fail ? "fail" : "pass",
        failed_assertions: fail ? ["assertion.match"] : [],
        pass_rate: fail ? 0 : 1,
        iterations: numberValue(body.stochastic_runs, 1),
      },
    };
    state.simulationRuns.push(run);
    const mappedControls = ((def.dsl_json?.maps_to_controls as string[] | undefined) || []).filter(Boolean);
    mappedControls.forEach((controlId) => recomputeMaturity(aiSystemId, controlId));
    state.evidenceNodes.push({
      id: nextId("ev"),
      node_type: "simulation_run",
      signal_type: fail ? "simulation.fail" : "simulation.pass",
      label: `${def.name} run result=${run.results.result}`,
      created_at: run.started_at,
    });
    return deepClone(run);
  }
  if (pathname === "/simulations/controls/traceability" && method === "GET") {
    const aiSystemId = url.searchParams.get("ai_system_id") || state.aiSystems[0]?.id || "ai-sys-1";
    return envelope(controlTraceability(aiSystemId));
  }
  const controlCoverageMatch = pathname.match(/^\/controls\/([^/]+)\/coverage$/);
  if (controlCoverageMatch && method === "GET") return controlCoverage(controlCoverageMatch[1]);
  const frameworkCoverageMatch = pathname.match(/^\/frameworks\/([^/]+)\/coverage$/);
  if (frameworkCoverageMatch && method === "GET") {
    return frameworkCoverage(decodeURIComponent(frameworkCoverageMatch[1]), numberValue(url.searchParams.get("min_simulations"), 1));
  }

  if (pathname === "/trust-center/maturity" && method === "GET") return envelope(deepClone(state.maturity));
  const maturityExplainMatch = pathname.match(/^\/trust-center\/maturity\/([^/]+)\/controls\/([^/]+)\/explanation$/);
  if (maturityExplainMatch && method === "GET") return maturityExplanation(maturityExplainMatch[1], maturityExplainMatch[2]);
  if (pathname === "/trust-center/evidence/nodes" && method === "GET") return envelope(deepClone(state.evidenceNodes));

  if (pathname === "/ops/jobs/status" && method === "GET") return envelope(deepClone(state.jobStatus));
  if (pathname === "/auditor/dashboard" && method === "GET") return auditorDashboard();
  if (pathname === "/auditor/conflicts" && method === "GET") {
    const filter = url.searchParams.get("status_filter");
    const rows = filter && filter !== "all" ? state.conflicts.filter((item) => item.status === filter) : state.conflicts;
    return envelope(deepClone(rows));
  }
  const conflictResolveMatch = pathname.match(/^\/auditor\/conflicts\/([^/]+)\/resolve$/);
  if (conflictResolveMatch && method === "POST") {
    const row = state.conflicts.find((item) => item.id === conflictResolveMatch[1]);
    if (!row) return null;
    row.status = "resolved";
    row.resolution_decision = stringValue(body.decision, "inconclusive");
    row.resolution_notes = stringValue(body.notes, "");
    row.resolved_at = new Date().toISOString();
    return deepClone(row);
  }
  if (pathname === "/auditor/export" && method === "POST") {
    return auditExportResponse(stringValue(body.ai_system_id, state.aiSystems[0]?.id || "ai-sys-1"));
  }

  if (pathname === "/agui/actions" && method === "GET") {
    const sourceModule = url.searchParams.get("source_module");
    const actionPrefix = url.searchParams.get("action_prefix");
    let rows = state.aguiActions;
    if (sourceModule) rows = rows.filter((item) => item.source_module === sourceModule);
    if (actionPrefix) rows = rows.filter((item) => item.action_id.startsWith(actionPrefix));
    return envelope(deepClone(rows));
  }
  const aguiActionMatch = pathname.match(/^\/agui\/actions\/([^/]+)$/);
  if (aguiActionMatch && method === "GET") {
    const row = state.aguiActions.find((item) => item.action_id === decodeURIComponent(aguiActionMatch[1]));
    return row ? deepClone(row) : null;
  }
  if (pathname === "/agui/decisions" && method === "GET") {
    const actionId = url.searchParams.get("action_id");
    const sourceModule = url.searchParams.get("source_module");
    let rows = state.aguiDecisions;
    if (actionId) rows = rows.filter((item) => item.action_id === actionId);
    if (sourceModule) rows = rows.filter((item) => item.source_module === sourceModule);
    return envelope(deepClone(rows));
  }
  const aguiDecideMatch = pathname.match(/^\/agui\/actions\/([^/]+)\/decide$/);
  if (aguiDecideMatch && method === "POST") {
    const actionId = decodeURIComponent(aguiDecideMatch[1]);
    const action = state.aguiActions.find((item) => item.action_id === actionId);
    if (!action) return null;
    decisionCounter += 1;
    const decision: AguiDecision = {
      decision_id: `agui-decision-${decisionCounter}`,
      action_id: actionId,
      decision: stringValue(body.decision, action.decision_options[0] || "approve"),
      justification: body.justification ? stringValue(body.justification) : null,
      decided_by: actorId,
      decided_at: new Date().toISOString(),
      correlation_id: `corr-agui-${decisionCounter}`,
      evidence_node_ids: ((body.evidence_node_ids as string[] | undefined) || []).filter(Boolean),
      audit_log_id: `audit-agui-${decisionCounter}`,
      source_module: action.source_module,
      source_object_type: stringValue(body.source_object_type, action.source_object_type),
      source_object_id: stringValue(body.source_object_id, action.source_object_id),
      source_summary: action.source_summary,
      proof_timeline_url: action.proof_timeline_url || null,
    };
    state.aguiDecisions.unshift(decision);
    return deepClone(decision);
  }

  return null;
}

export function resetDemoFallbackState() {
  state = initialState();
  idCounter = 1000;
  decisionCounter = 10;
}
