from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.db.models.policy import PolicyVersion


ALLOWED_WORKFLOW_DECISIONS = {"allow", "warn", "block", "hold"}


@dataclass(frozen=True)
class WorkflowPolicy:
    policy_id: str
    name: str
    applies_to: list[str]
    restricted_tools: list[str]
    required_controls: list[str]
    max_chain_depth: int | None
    allowed_data_classes: list[str]


@dataclass(frozen=True)
class WorkflowPolicyEvaluation:
    decision: str
    workflow_policy_id: str | None
    violation_reason: str | None
    matched_violations: list[str]


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for item in values:
        text = _normalize_text(item)
        if text:
            out.append(text)
    return out


def load_workflow_policy(policy_version: PolicyVersion | None) -> WorkflowPolicy | None:
    if policy_version is None:
        return None
    enforcement_defaults = dict(policy_version.enforcement_defaults or {})
    payload = enforcement_defaults.get("workflow_policy")
    if not isinstance(payload, dict):
        return None

    policy_id = _normalize_text(payload.get("policy_id")) or _normalize_text(policy_version.id)
    name = _normalize_text(payload.get("name")) or "workflow_policy"
    applies_to = _normalize_list(payload.get("applies_to")) or ["*"]
    restricted_tools = [item.lower() for item in _normalize_list(payload.get("restricted_tools"))]
    required_controls = _normalize_list(payload.get("required_controls"))
    max_chain_depth_raw = payload.get("max_chain_depth")
    max_chain_depth: int | None = None
    if max_chain_depth_raw is not None:
        try:
            parsed = int(max_chain_depth_raw)
            if parsed > 0:
                max_chain_depth = parsed
        except (TypeError, ValueError):
            max_chain_depth = None
    allowed_data_classes = [item.lower() for item in _normalize_list(payload.get("allowed_data_classes"))]
    if not allowed_data_classes:
        allowed_data_classes = ["public", "internal", "unknown", "sensitive"]

    return WorkflowPolicy(
        policy_id=policy_id,
        name=name,
        applies_to=applies_to,
        restricted_tools=restricted_tools,
        required_controls=required_controls,
        max_chain_depth=max_chain_depth,
        allowed_data_classes=allowed_data_classes,
    )


def evaluate_workflow_policy(
    policy: WorkflowPolicy | None,
    *,
    agent_id: str | None,
    tool_name: str | None,
    chain_depth: int | None,
    data_classification: str | None,
    available_control_ids: list[str] | None = None,
) -> WorkflowPolicyEvaluation:
    if policy is None:
        return WorkflowPolicyEvaluation(
            decision="allow",
            workflow_policy_id=None,
            violation_reason=None,
            matched_violations=[],
        )

    applies_to = {item.strip() for item in policy.applies_to if item.strip()}
    if applies_to and "*" not in applies_to:
        if not agent_id or agent_id not in applies_to:
            return WorkflowPolicyEvaluation(
                decision="allow",
                workflow_policy_id=policy.policy_id,
                violation_reason=None,
                matched_violations=[],
            )

    violations: list[str] = []
    normalized_tool = _normalize_text(tool_name).lower()
    normalized_data_class = (_normalize_text(data_classification).lower() or "unknown")

    if policy.max_chain_depth is not None and chain_depth is not None and int(chain_depth) > int(policy.max_chain_depth):
        violations.append("chain_depth_exceeded")

    if normalized_tool and normalized_tool in set(policy.restricted_tools):
        violations.append("restricted_tool")

    if normalized_data_class not in set(policy.allowed_data_classes):
        violations.append("data_class_not_allowed")

    required_controls = {item for item in policy.required_controls if item}
    if required_controls:
        observed_controls = {str(item).strip() for item in (available_control_ids or []) if str(item).strip()}
        if not required_controls.issubset(observed_controls):
            violations.append("required_controls_missing")

    if not violations:
        return WorkflowPolicyEvaluation(
            decision="allow",
            workflow_policy_id=policy.policy_id,
            violation_reason=None,
            matched_violations=[],
        )

    if "chain_depth_exceeded" in violations or "restricted_tool" in violations:
        decision = "block"
    elif "data_class_not_allowed" in violations:
        decision = "hold"
    elif "required_controls_missing" in violations:
        decision = "warn"
    else:
        decision = "warn"

    if decision not in ALLOWED_WORKFLOW_DECISIONS:
        decision = "warn"
    violation_reason = ",".join(violations)
    return WorkflowPolicyEvaluation(
        decision=decision,
        workflow_policy_id=policy.policy_id,
        violation_reason=violation_reason,
        matched_violations=violations,
    )
