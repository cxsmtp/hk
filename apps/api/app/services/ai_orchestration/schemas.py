from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


TaskType = Literal[
    "remediation_guidance",
    "vulnerability_analysis",
    "control_gap_analysis",
    "simulation_failure_explanation",
    "drift_explanation",
    "audit_summary",
    "questionnaire_answer_draft",
]


class RoutingContext(BaseModel):
    task_type: TaskType
    data_sensitivity: Literal["public", "internal", "sensitive", "restricted"] = "internal"
    risk_tier: str = "medium"
    cost_ceiling_usd: float = Field(default=0.25, ge=0.0)
    region_requirement: str = "global"
    residency_requirement: str = ""
    customer_region: str = "global"
    residency_required: bool = False
    customer_policy_profile: dict[str, Any] = Field(default_factory=dict)


class RemediationStep(BaseModel):
    step_order: int = Field(ge=1)
    action_type: Literal[
        "policy_update",
        "restrict_permission",
        "review_owner",
        "run_simulation",
        "ticket",
        "investigate",
        "rollback",
    ]
    title: str
    description: str
    requires_approval: bool = False
    estimated_impact: str = "medium"
    linked_controls: list[str] = Field(default_factory=list)
    linked_frameworks: list[str] = Field(default_factory=list)


class RiskContext(BaseModel):
    current_ALE: float = 0.0
    potential_ALE: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0


class RemediationImpact(BaseModel):
    estimated_risk_reduction: float = 0.0
    new_ALE: float = 0.0
    priority_score: float = 0.0


class RemediationGuidance(BaseModel):
    issue_id: str
    control_id: str = ""
    summary: str
    root_cause_hypothesis: str
    recommended_steps: list[RemediationStep]
    priority: Literal["low", "med", "high", "critical"] = "med"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    notes: str = ""
    linked_controls: list[str] = Field(default_factory=list)
    linked_frameworks: list[str] = Field(default_factory=list)
    risk_context: RiskContext = Field(default_factory=RiskContext)
    remediation_impact: RemediationImpact = Field(default_factory=RemediationImpact)


class OrchestrationTaskRequest(BaseModel):
    task_type: TaskType
    control_id: str = ""
    issue_type: str
    issue_id: str
    issue_title: str = ""
    issue_summary: str = ""
    severity: str = "medium"
    risk_tier: str = "medium"
    data_sensitivity: Literal["public", "internal", "sensitive", "restricted"] = "internal"
    customer_region: str = "global"
    region_requirement: str = "global"
    residency_requirement: str = ""
    residency_required: bool = False
    cost_ceiling_usd: float = Field(default=0.25, ge=0.0)
    customer_policy_profile: dict[str, Any] = Field(default_factory=dict)
    policy_version: str = ""
    governance_version: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    runtime_event_refs: list[str] = Field(default_factory=list)
    retrieval_refs: list[dict[str, Any]] = Field(default_factory=list)
    control_decision: dict[str, Any] = Field(default_factory=dict)
    simulation_result: dict[str, Any] = Field(default_factory=dict)
    current_controls: list[str] = Field(default_factory=list)
    governance_state: str = "unknown"
    allowed_remediation_types: list[str] = Field(default_factory=list)
    framework_refs: list[str] = Field(default_factory=list)
    context_payload: dict[str, Any] = Field(default_factory=dict)
    route_policy_overrides: dict[str, Any] = Field(default_factory=dict)

    @field_validator("severity", "risk_tier", "governance_state", mode="before")
    @classmethod
    def _normalize_text(cls, value: Any) -> str:
        return str(value or "").strip().lower() or "unknown"

    @field_validator("control_id", mode="before")
    @classmethod
    def _normalize_control_id(cls, value: Any) -> str:
        token = str(value or "").strip()
        return token.upper() if token else ""


class RouteDecision(BaseModel):
    provider: Literal["gpt", "claude", "gemini", "llama"]
    model: str
    model_version: str
    route_id: str
    routing_policy_id: str
    region_route: str
    reasoning: list[str] = Field(default_factory=list)
    estimated_cost_usd: float = 0.0
    route_status: Literal["selected", "fallback", "rejected"] = "selected"
    fallback_provider: str | None = None
    fallback_model: str | None = None
    fail_secure: bool = False
    constraint_failures: list[str] = Field(default_factory=list)
    routing_context: dict[str, Any] = Field(default_factory=dict)


class GuardResult(BaseModel):
    passed: bool
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class OrchestrationResult(BaseModel):
    trace_id: str
    task_type: TaskType
    control_id: str
    provider: str
    model: str
    model_version: str
    prompt_template_id: str
    prompt_template_version: str = "v1"
    prompt_template_status: str = "active"
    routing_policy_id: str
    policy_route_id: str
    region_route: str
    routing_context: dict[str, Any] = Field(default_factory=dict)
    retrieval_refs: list[dict[str, Any]] = Field(default_factory=list)
    retrieval_source_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    runtime_event_refs: list[str] = Field(default_factory=list)
    control_decision: dict[str, Any] = Field(default_factory=dict)
    simulation_result: dict[str, Any] = Field(default_factory=dict)
    policy_version: str = ""
    governance_version: str = ""
    pre_call_guard_results: dict[str, Any] = Field(default_factory=dict)
    post_call_guard_results: dict[str, Any] = Field(default_factory=dict)
    output_schema_valid: bool
    token_usage: dict[str, Any] = Field(default_factory=dict)
    cost_estimate_usd: float = 0.0
    status: str
    rejection_reason: str | None = None
    risk_context: RiskContext = Field(default_factory=RiskContext)
    remediation_impact: RemediationImpact = Field(default_factory=RemediationImpact)
    remediation_guidance: RemediationGuidance | None = None
    audit_log_id: str | None = None
    evidence_node_id: str | None = None
