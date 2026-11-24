from __future__ import annotations

import re
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.policy import GuardianContractBindingV2, GuardianContractV2
from app.services.guardian_policy_engine import canonical_policy_from_v2_binding
from app.services.guardians.confidence_tiering import (
    CONFIDENCE_TIER_AMBIGUOUS,
    CONFIDENCE_TIER_CLEAR_NEGATIVE,
    classify_confidence_tier,
    run_ambiguous_arbiter,
)
from app.services.guardians.threat_registry import guardian_contract_to_threat_types


AGGREGATION_PRECEDENCE = [
    "block",
    "hold_for_approval",
    "redact",
    "warn",
    "allow",
]


def _get_value(payload: dict[str, Any], field: str) -> Any:
    current: Any = payload
    for part in str(field).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _match_condition(payload: dict[str, Any], condition: dict[str, Any]) -> bool:
    operator = str(condition.get("operator") or "").strip().lower()
    expected = condition.get("value")
    case_sensitive = bool(condition.get("case_sensitive", False))
    actual = _get_value(payload, str(condition.get("field") or ""))

    if operator == "contains":
        actual_s = _as_text(actual)
        expected_s = _as_text(expected)
        if not case_sensitive:
            actual_s = actual_s.lower()
            expected_s = expected_s.lower()
        return expected_s in actual_s

    if operator == "regex":
        actual_s = _as_text(actual)
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.search(str(expected), actual_s, flags=flags) is not None
        except re.error:
            return False

    if operator == "in":
        return isinstance(expected, list) and actual in expected

    if operator == "gt":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False

    if operator == "lt":
        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False

    if operator == "equals":
        return actual == expected

    if operator == "not_equals":
        return actual != expected

    return False


def _normalize_conditions(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        conditions = value.get("conditions")
        if isinstance(conditions, list):
            return [item for item in conditions if isinstance(item, dict)]
    return []


def _all_match(payload: dict[str, Any], conditions: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    if not conditions:
        return False, []
    matched_fields: list[str] = []
    for condition in conditions:
        if not _match_condition(payload, condition):
            return False, []
        matched_fields.append(str(condition.get("field") or "unknown"))
    return True, matched_fields


def _aggregate_guardian_decisions(decisions: list[str]) -> str:
    observed = set(decisions)
    for decision in AGGREGATION_PRECEDENCE:
        if decision in observed:
            return decision
    return "allow"


def load_applicable_v2_bindings(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    policy_version_id: str | None,
) -> list[dict[str, Any]]:
    query = (
        select(GuardianContractBindingV2, GuardianContractV2)
        .join(
            GuardianContractV2,
            (GuardianContractV2.id == GuardianContractBindingV2.guardian_contract_id)
            & (GuardianContractV2.tenant_id == GuardianContractBindingV2.tenant_id),
        )
        .where(
            GuardianContractV2.tenant_id == tenant_id,
            GuardianContractBindingV2.tenant_id == tenant_id,
            GuardianContractBindingV2.enabled.is_(True),
            or_(
                GuardianContractBindingV2.ai_system_id.is_(None),
                GuardianContractBindingV2.ai_system_id == ai_system_id,
            ),
        )
    )
    if policy_version_id:
        query = query.where(
            or_(
                GuardianContractBindingV2.policy_version_id.is_(None),
                GuardianContractBindingV2.policy_version_id == policy_version_id,
            )
        )

    rows = db.execute(query).all()
    items: list[dict[str, Any]] = []
    for binding, contract in rows:
        items.append(
            {
                "binding_id": binding.id,
                "guardian_contract_id": contract.id,
                "version": contract.version,
                "name": contract.name,
                "trigger_conditions": contract.trigger_conditions or [],
                "block_conditions": contract.block_conditions or [],
                "mandatory_actions": contract.mandatory_actions or {},
                "escalation_path": contract.escalation_path or {},
                "evidence_requirements": contract.evidence_requirements or {},
                "framework_mappings": contract.framework_mappings or {},
                "canonical_policy": (
                    contract.canonical_policy
                    or canonical_policy_from_v2_binding(
                        binding={
                            "guardian_contract_id": contract.id,
                            "version": contract.version,
                            "name": contract.name,
                            "trigger_conditions": contract.trigger_conditions or [],
                            "block_conditions": contract.block_conditions or [],
                            "mandatory_actions": contract.mandatory_actions or {},
                            "escalation_path": contract.escalation_path or {},
                            "evidence_requirements": contract.evidence_requirements or {},
                            "framework_mappings": contract.framework_mappings or {},
                            "enforcement_strength": binding.enforcement_strength,
                            "enabled": binding.enabled,
                            "ai_system_id": binding.ai_system_id,
                        },
                        tenant_id=tenant_id,
                    )
                ),
                "enforcement_strength": str(binding.enforcement_strength or "baseline").strip().lower(),
                "enabled": bool(binding.enabled),
                "ai_system_id": binding.ai_system_id,
                "policy_version_id": binding.policy_version_id,
            }
        )

    items.sort(
        key=lambda row: (
            str(row["guardian_contract_id"]),
            str(row.get("ai_system_id") or ""),
            str(row.get("policy_version_id") or ""),
            str(row["binding_id"]),
        )
    )
    return items


def evaluate_v2_guardians(
    *,
    payload: dict[str, Any],
    bindings: list[dict[str, Any]],
    strictness_level: int,
) -> tuple[list[dict[str, Any]], str, dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    guardian_results: list[dict[str, Any]] = []
    final_actions: dict[str, Any] = {}
    control_impacts: list[dict[str, Any]] = []
    approval_requirements: list[dict[str, Any]] = []

    for binding in bindings:
        contract_id = str(binding["guardian_contract_id"])
        canonical_policy = dict(binding.get("canonical_policy") or {})
        metadata = dict(canonical_policy.get("metadata") or {})
        trigger_conditions = _normalize_conditions(metadata.get("legacy_trigger_conditions") or binding.get("trigger_conditions"))
        block_conditions = _normalize_conditions(metadata.get("legacy_block_conditions") or binding.get("block_conditions"))
        mandatory_actions = metadata.get("legacy_mandatory_actions") or binding.get("mandatory_actions") or {}
        escalation_path = metadata.get("legacy_escalation_path") or binding.get("escalation_path") or {}
        evidence_requirements = metadata.get("legacy_evidence_requirements") or binding.get("evidence_requirements") or {}
        framework_mappings = dict(canonical_policy.get("framework_mapping") or binding.get("framework_mappings") or {})
        strength = str(binding.get("enforcement_strength") or "baseline").strip().lower()
        canonical_decision_mode = str((canonical_policy.get("decision") or {}).get("mode") or "").strip().lower()

        trigger_match, trigger_fields = _all_match(payload, trigger_conditions)
        block_match, block_fields = _all_match(payload, block_conditions)

        reasons: list[str] = []
        decision = "allow"
        matched_fields: list[str] = []
        confidence_threshold = float((evidence_requirements or {}).get("confidence_threshold", 0.7))
        if block_match:
            decision = "block"
            reasons.append("block_conditions_matched")
            matched_fields.extend(block_fields)
            base_confidence = 0.99
        elif trigger_match:
            matched_fields.extend(trigger_fields)
            if canonical_decision_mode in {"require_approval"}:
                decision = "hold_for_approval"
                reasons.append("trigger_matched_canonical_require_approval")
            elif canonical_decision_mode in {"require_justification"}:
                decision = "warn"
                reasons.append("trigger_matched_canonical_require_justification")
            elif strictness_level >= 2 or strength in {"strict", "maximum"} or canonical_decision_mode == "block":
                decision = "block"
                reasons.append("trigger_matched_strict_enforcement")
            elif canonical_decision_mode == "warn":
                decision = "warn"
                reasons.append("trigger_matched_canonical_warn")
            else:
                decision = "warn"
                reasons.append("trigger_matched")
            base_confidence = 0.78
        else:
            reasons.append("no_conditions_matched")
            base_confidence = 0.2

        confidence_tier = classify_confidence_tier(
            confidence=base_confidence,
            threshold=confidence_threshold,
            trigger_matched=trigger_match,
            block_matched=block_match,
        )
        confidence = base_confidence
        arbiter_invoked = False
        arbiter_reason = None
        if confidence_tier == CONFIDENCE_TIER_AMBIGUOUS:
            arbiter_invoked = True
            arbiter_result = run_ambiguous_arbiter(
                payload=payload,
                guardian_contract_id=contract_id,
                matched_conditions=matched_fields,
                threshold=confidence_threshold,
            )
            confidence_tier = str(arbiter_result.get("tier") or CONFIDENCE_TIER_AMBIGUOUS)
            confidence = float(arbiter_result.get("confidence") or base_confidence)
            arbiter_reason = str(arbiter_result.get("reason") or "arbiter_unknown")
            reasons.append("arbiter_invoked")
            reasons.append(arbiter_reason)
            if confidence_tier == CONFIDENCE_TIER_CLEAR_NEGATIVE:
                decision = "allow"
                reasons.append("arbiter_clear_negative")
            else:
                if block_match or strictness_level >= 2 or strength in {"strict", "maximum"}:
                    decision = "block"
                elif trigger_match:
                    decision = "warn"

        actions_taken: dict[str, Any] = {}
        if decision in {"warn", "redact", "hold_for_approval", "block"}:
            actions_taken = mandatory_actions
            if actions_taken:
                final_actions[contract_id] = actions_taken

        workflow = escalation_path.get("approval_workflow") if isinstance(escalation_path, dict) else None
        if decision in {"warn", "block"} and isinstance(workflow, dict) and workflow:
            if str(workflow.get("mode", "")).lower() == "approval_required":
                decision = "hold_for_approval"
                reasons.append("approval_workflow_required")
                approval_requirements.append(
                    {
                        "guardian_contract_id": contract_id,
                        "guardian_id": contract_id,
                        "required_roles": workflow.get("required_roles", ["owner", "admin"]),
                        "sla_minutes": int(workflow.get("sla_minutes", 30)),
                        "default_if_timeout": str(workflow.get("default_if_timeout", "block")),
                    }
                )

        linked_controls = list(evidence_requirements.get("link_to_controls") or framework_mappings.get("control_ids") or [])
        if decision in {"warn", "redact", "hold_for_approval", "block"}:
            for control_id in linked_controls:
                control_impacts.append({"control_id": str(control_id), "delta": -0.1 if decision == "block" else -0.05})

        guardian_results.append(
            {
                "guardian_contract_id": contract_id,
                "guardian_id": contract_id,
                "version": str(binding.get("version") or "2.0"),
                "decision": decision,
                "confidence": round(float(confidence), 4),
                "confidence_tier": confidence_tier,
                "arbiter_invoked": arbiter_invoked,
                "arbiter_reason": arbiter_reason,
                "matched_conditions": matched_fields,
                "actions_taken": actions_taken,
                "reasons": reasons,
                "enforcement_strength": strength,
                "evidence_node_type": "guardian_enforcement_v2",
                "threat_types": guardian_contract_to_threat_types(contract_id),
            }
        )

    final_decision = _aggregate_guardian_decisions([row["decision"] for row in guardian_results])
    return guardian_results, final_decision, final_actions, control_impacts, approval_requirements
