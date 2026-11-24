from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class GuardOutcome:
    passed: bool
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SecureCallContext:
    task_type: str
    data_sensitivity: str = "internal"
    risk_tier: str = "medium"
    cost_ceiling_usd: float = 0.25
    customer_region: str = "global"
    region_requirement: str = "global"
    residency_requirement: str = ""
    residency_required: bool = False
    customer_policy_profile: dict[str, Any] = field(default_factory=dict)
    policy_applied: str = ""
    policy_version: str = ""
    governance_version: str = ""
    prompt_template_id: str = ""
    prompt_template_version: str = ""
    retrieval_sources: list[str] = field(default_factory=list)
    tool_calls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StoredDecisionSeamAuthority:
    """Server-only route material for reusing one durable V1 decision at a provider seam."""

    decision_receipt_id: str
    action_id: str
    chain_id: str
    actor_principal: str
    parameter_hash: str
    target_ref: str


@dataclass(frozen=True)
class SecureModelCallResult:
    blocked: bool
    block_reason: str | None
    output_text: str | None
    output_json: dict[str, Any] | None
    pre_call_guard: dict[str, Any]
    post_call_guard: dict[str, Any]
    trace: dict[str, Any]
