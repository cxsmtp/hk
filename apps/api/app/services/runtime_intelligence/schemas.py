from __future__ import annotations

from datetime import datetime
import math
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


RuntimeSourceSurface = Literal[
    "browser",
    "gateway",
    "connector",
    "aiiam",
    "monitoring",
    "endpoint",
    "dns",
    "proxy",
    "desktop_app",
    "foundry",
    "copilot",
    "sdk",
    "internal_mcp",
]
RuntimeConfidenceTier = Literal["clear_positive", "ambiguous", "clear_negative"]
RuntimeEntityType = Literal["user", "agent", "tool", "ai_system"]
CanonicalActionSourceSurface = Literal["browser", "api", "connector", "agent"]


class CanonicalAction(BaseModel):
    action_id: str
    source_surface: CanonicalActionSourceSurface
    user_id: str | None = None
    agent_id: str | None = None
    model: str | None = None
    tool: str | None = None
    operation: str
    data_entities: list[str] = Field(default_factory=list)
    timestamp: datetime


class RuntimeEvent(BaseModel):
    event_id: str
    tenant_id: str
    source_surface: RuntimeSourceSurface
    event_type: str
    ai_system_id: str | None = None
    app_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    risk_tier: str | None = None
    policy_version_id: str | None = None
    governance_version: str | None = None
    severity: str | None = None
    confidence_tier: RuntimeConfidenceTier | str | None = None
    evidence_node_ids: list[str] = Field(default_factory=list)
    correlation_id: str | None = None
    context_id: str | None = None
    chain_id: str | None = None
    parent_action_id: str | None = None
    entity_type: RuntimeEntityType | str | None = None
    entity_id: str | None = None
    risk_score: float = 0.0
    created_at: datetime
    model_provider: str | None = None
    provider: str | None = None
    model_name: str | None = None
    model_version: str | None = None
    tool_name: str | None = None
    tool_category: str | None = None
    api_endpoint: str | None = None
    data_source: str | None = None
    response_size: int | None = None
    chain_depth: int | None = None
    parent_agent_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeEventIngestPayload(BaseModel):
    tenant_id: str
    source_surface: RuntimeSourceSurface
    event_type: str
    ai_system_id: str | None = None
    app_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    risk_tier: str | None = None
    policy_version_id: str | None = None
    governance_version: str | None = None
    severity: str | None = None
    confidence_tier: RuntimeConfidenceTier | str | None = None
    evidence_node_ids: list[str] = Field(default_factory=list)
    correlation_id: str | None = None
    context_id: str | None = None
    chain_id: str | None = None
    parent_action_id: str | None = None
    entity_type: RuntimeEntityType | str | None = None
    entity_id: str | None = None
    risk_score: float | None = None
    model_provider: str | None = None
    provider: str | None = None
    model_name: str | None = None
    model_version: str | None = None
    tool_name: str | None = None
    tool_category: str | None = None
    api_endpoint: str | None = None
    data_source: str | None = None
    response_size: int | None = None
    chain_depth: int | None = None
    parent_agent_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("risk_score", mode="before")
    @classmethod
    def validate_finite_risk_score(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, bool):
            raise ValueError("risk_score must be a finite number")
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("risk_score must be a finite number") from exc
        if not math.isfinite(parsed):
            raise ValueError("risk_score must be a finite number")
        return value


class CorrelatedFindingCandidate(BaseModel):
    finding_type: str
    risk_category: str
    severity: str
    reason_code: str
    repeated_count: int = 1
    related_control_ids: list[str] = Field(default_factory=list)
    evidence_node_ids: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    recommendation_types: list[str] = Field(default_factory=list)


class RuntimeRiskScore(BaseModel):
    risk_score: int
    suggested_severity: str
    recommended_action: str
    reasoning: list[str] = Field(default_factory=list)


class GovernanceRecommendation(BaseModel):
    recommendation_type: str
    reason_code: str
    priority: str = "med"
    payload: dict[str, Any] = Field(default_factory=dict)


class TriggerPlan(BaseModel):
    reason_code: str
    target_pack: str
    related_control_ids: list[str] = Field(default_factory=list)
    recommended_action: str = ""
