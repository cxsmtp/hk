from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from .core_types import ActorType, Decision, DetectionConfidenceTier, Escalation, RiskTier, ThreatType


class PolicyPackStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"


class ConditionOperator(str, Enum):
    CONTAINS = "contains"
    REGEX = "regex"
    IN = "in"
    GT = "gt"
    LT = "lt"
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"


class Condition(BaseModel):
    field: str
    operator: ConditionOperator
    value: str | float | int | bool | list[str]
    case_sensitive: bool | None = None


class GuardianTrigger(BaseModel):
    signal_types: list[str]
    conditions: list[Condition]


class GuardianEvaluation(BaseModel):
    method: Literal["rules", "model_stub", "hybrid"]
    confidence_threshold: float = Field(ge=0, le=1)


class GuardianDecision(BaseModel):
    on_pass: Literal["allow", "warn"]
    on_fail: Literal["block", "redact", "hold_for_approval"]
    on_uncertain: Literal["warn", "hold_for_approval"]


class RedactAction(BaseModel):
    fields: list[str]
    strategy: Literal["mask", "remove", "summarize"]


class MutateOutputAction(BaseModel):
    enabled: bool = False
    strategy: Literal["restricted_template", "safe_completion"] = "restricted_template"


class NotifyAction(BaseModel):
    channels: list[Literal["email", "slack", "teams"]] = Field(default_factory=list)


class TicketAction(BaseModel):
    system: Literal["jira", "servicenow"]
    severity: Literal["low", "med", "high", "critical"]


class GuardianActions(BaseModel):
    redact: RedactAction
    mutate_output: MutateOutputAction
    notify: NotifyAction
    create_ticket: TicketAction


class GuardianEvidence(BaseModel):
    evidence_signal_type: str
    link_to_controls: list[str] = Field(default_factory=list)


class GuardianControlImpact(BaseModel):
    maturity_delta_on_fail: float = 0.0
    increase_simulation_frequency: bool = False
    enforcement_strictness_increase: Literal[0, 1, 2] = 0


class ApprovalWorkflow(BaseModel):
    required_roles: list[Literal["owner", "admin"]]
    sla_minutes: int
    default_if_timeout: Literal["block", "warn"]


class GuardianContract(BaseModel):
    guardian_id: str
    description: str
    enabled: bool
    trigger: GuardianTrigger
    evaluation: GuardianEvaluation
    decision: GuardianDecision
    actions: GuardianActions
    evidence: GuardianEvidence
    control_impact: GuardianControlImpact
    approval_workflow: ApprovalWorkflow | None = None


class PolicyScope(BaseModel):
    applies_to_risk_tiers: list[RiskTier]
    applies_to_ai_system_ids: list[str] | None = None
    applies_to_actor_types: list[ActorType] | None = None


class EnforcementDefaults(BaseModel):
    default_decision: Decision
    escalation: Escalation


class PolicyVersionContract(BaseModel):
    id: str
    pack_id: str
    version: str
    created_at: datetime
    created_by: str
    scope: PolicyScope
    enforcement_defaults: EnforcementDefaults
    guardian_contracts: list[GuardianContract]


class PolicyPackContract(BaseModel):
    id: str
    tenant_id: str
    name: str
    description: str
    status: PolicyPackStatus


class GuardianResult(BaseModel):
    guardian_id: str
    decision: Decision
    confidence: float
    confidence_tier: DetectionConfidenceTier | None = None
    arbiter_invoked: bool | None = None
    matched_conditions: list[str]
    threat_types: list[ThreatType] = Field(default_factory=list)
    actions_taken: dict[str, Any] = Field(default_factory=dict)


class ControlImpactItem(BaseModel):
    control_id: str
    delta: float


class EnforcementInput(BaseModel):
    prompt: str
    context_summary: str
    attachments_meta: list[dict[str, Any]] = Field(default_factory=list)


class EnforcementEventContract(BaseModel):
    id: str
    tenant_id: str
    ai_system_id: str
    actor_type: ActorType
    actor_id: str
    request_id: str
    timestamp: datetime
    input: EnforcementInput
    guardian_results: list[GuardianResult]
    final_decision: Decision
    final_actions: dict[str, Any] = Field(default_factory=dict)
    evidence_nodes_created: list[str] = Field(default_factory=list)
    controls_impacted: list[ControlImpactItem] = Field(default_factory=list)
    audit_log_id: str


class GuardianPolicyScope(BaseModel):
    ai_system_ids: list[str] = Field(default_factory=lambda: ["*"])
    agent_ids: list[str] = Field(default_factory=lambda: ["*"])
    user_groups: list[str] = Field(default_factory=lambda: ["*"])
    environments: list[str] = Field(default_factory=lambda: ["prod", "staging", "dev"])


class GuardianPolicyConditions(BaseModel):
    source: dict[str, Any] = Field(default_factory=dict)
    destination: dict[str, Any] = Field(default_factory=dict)
    action: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)


class GuardianPolicyDecision(BaseModel):
    mode: Literal["allow", "warn", "block", "require_justification", "require_approval"] = "warn"
    confidence_threshold: float = Field(default=0.7, ge=0, le=1)
    strictness: Literal["low", "medium", "high"] = "medium"


class GuardianPolicyEnforcement(BaseModel):
    fail_mode: Literal["fail_secure", "fail_open"] = "fail_secure"
    log: bool = True
    create_finding: bool = True
    require_evidence: bool = True


class GuardianPolicyGovernance(BaseModel):
    risk_level: Literal["low", "medium", "high", "restricted"] = "medium"
    approval_required: bool = False
    policy_owner: str = "system"
    review_cycle_days: int = 30


class GuardianPolicyFrameworkMapping(BaseModel):
    nist_ai_rmf: list[str] = Field(default_factory=list)
    iso_42001: list[str] = Field(default_factory=list)
    eu_ai_act: list[str] = Field(default_factory=list)
    owasp_genai: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)


class GuardianPolicyMetadata(BaseModel):
    created_at: datetime | None = None
    updated_at: datetime | None = None
    active: bool = True


class GuardianContractCanonical(BaseModel):
    policy_id: str
    policy_name: str
    policy_version: str
    tenant_id: str
    scope: GuardianPolicyScope
    conditions: GuardianPolicyConditions
    decision: GuardianPolicyDecision
    enforcement: GuardianPolicyEnforcement
    governance: GuardianPolicyGovernance
    framework_mapping: GuardianPolicyFrameworkMapping
    metadata: GuardianPolicyMetadata
