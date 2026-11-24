"""Bounded declarative condition trees for the existing policy evaluator.

The interpreter is deliberately data-only.  It accepts no expressions,
regular expressions, code, dynamic imports, or arbitrary attribute paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


MAX_CONDITION_DEPTH = 8
MAX_CONDITION_NODES = 64
MAX_LIST_VALUES = 64

ALLOWED_FIELDS = {
    # Identity and account boundary (all values are already tenant-scoped
    # normalized context, never prompt text or arbitrary user attributes).
    "actor_type",
    "actor_user_id",
    "actor_group",
    "actor_role",
    "actor_department",
    "business_unit",
    "legal_entity",
    "tenant_id",
    "service_account",
    "workload_identity",
    "account_class",
    "account_workspace",
    "account_assurance",
    # Endpoint/device context.
    "agent_id",
    "endpoint_id",
    "device_managed",
    "device_group",
    "device_os",
    "endpoint_health",
    "tamper_state",
    # Application/provider/model context.
    "source_surface",
    "application",
    "ai_system_id",
    "provider",
    "provider_workspace",
    "model",
    "model_family",
    "model_risk_class",
    "model_status",
    # Agent, tool, and MCP context.
    "agent_owner",
    "agent_framework",
    "executing_principal",
    "delegation_root",
    "delegation_depth",
    "agent_capability",
    "tool_name",
    "mcp_server",
    "tool_id",
    "tool_fingerprint",
    "schema_fingerprint",
    "tool_trust_state",
    "tool_lifecycle_state",
    "tool_publisher",
    "tool_capability_type",
    # Canonical action, subject/resource, authority, and data context.
    "domain",
    "destination",
    "destination_class",
    "destination_region",
    "operation",
    "action_type",
    "action_class",
    "action_risk",
    "side_effect",
    "persistence",
    "reversibility",
    "represented_subject",
    "subject_type",
    "resource_ref",
    "resource_class",
    "target_system",
    "target_object",
    "target_environment",
    "target_tenant",
    "authority_type",
    "authority_scope",
    "authority_expiry",
    "privilege_class",
    "data_classification",
    "sensitivity_score",
    "contains_sensitive",
    "credential_present",
    "personal_data_present",
    "regulated_data_present",
    "source_code_present",
    "value_amount",
    "record_count",
    "file_size",
    "recipient_count",
    # Policy/control/pattern context.
    "risk_tier",
    "business_purpose",
    "purpose_category",
    "purpose_confidence",
    "purpose_missing",
    "environment",
    "control_health",
    "evidence_quality",
    "policy_decision",
    "control_response",
    "first_seen",
    "new_for_user",
    "new_for_team",
    "new_destination",
    "volume_spike",
    "repeated_failure",
    "repeated_warning",
    "repeated_block",
    "account_switch",
    "unusual_tool",
    "unusual_action",
}
ALLOWED_OPERATORS = {"equals", "in", "contains", "exists", "gte", "lte"}


@dataclass(frozen=True)
class ConditionMatch:
    matched: bool
    specificity: int
    matched_fields: tuple[str, ...]


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _scalar(value: Any, *, field: str) -> str | float | int | bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and len(value.strip()) <= 255:
        return value.strip()
    raise ValueError(f"condition field {field} has an invalid value")


def _validate_atomic(node: Mapping[str, Any]) -> dict[str, Any]:
    if set(node) != {"field", "operator", "value"}:
        raise ValueError("condition atom must contain only field, operator, and value")
    field = _normalize_text(node.get("field"))
    operator = _normalize_text(node.get("operator"))
    if field not in ALLOWED_FIELDS:
        raise ValueError(f"unsupported condition field: {field or 'blank'}")
    if operator not in ALLOWED_OPERATORS:
        raise ValueError(f"unsupported condition operator: {operator or 'blank'}")
    raw_value = node.get("value")
    if operator == "in":
        if not isinstance(raw_value, list) or not raw_value or len(raw_value) > MAX_LIST_VALUES:
            raise ValueError("condition in requires a non-empty bounded list")
        value: Any = [_scalar(item, field=field) for item in raw_value]
    elif operator == "exists":
        if not isinstance(raw_value, bool):
            raise ValueError("condition exists requires a boolean")
        value = raw_value
    elif operator in {"gte", "lte"}:
        if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
            raise ValueError(f"condition {operator} requires a numeric value")
        value = raw_value
    else:
        value = _scalar(raw_value, field=field)
    return {"field": field, "operator": operator, "value": value}


def normalize_condition_tree(tree: Any) -> dict[str, Any]:
    """Validate and canonicalize a small typed policy condition tree."""

    node_count = 0

    def normalize(node: Any, depth: int) -> dict[str, Any]:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_CONDITION_NODES:
            raise ValueError("condition tree exceeds the maximum node count")
        if depth > MAX_CONDITION_DEPTH:
            raise ValueError("condition tree exceeds the maximum depth")
        if not isinstance(node, Mapping):
            raise ValueError("condition tree nodes must be objects")
        keys = set(node)
        if keys == {"all"} or keys == {"any"}:
            operator = "all" if "all" in node else "any"
            children = node[operator]
            if not isinstance(children, list) or not children or len(children) > MAX_LIST_VALUES:
                raise ValueError(f"condition {operator} requires a non-empty bounded list")
            return {operator: [normalize(child, depth + 1) for child in children]}
        if keys == {"not"}:
            return {"not": normalize(node["not"], depth + 1)}
        return _validate_atomic(node)

    return normalize(tree, 1)


def _context_value(context: Mapping[str, Any], field: str) -> Any:
    return context.get(field)


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return float(left) == float(right)
    return _normalize_text(left) == _normalize_text(right)


def _match_atom(node: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    candidate = _context_value(context, str(node["field"]))
    operator = str(node["operator"])
    value = node["value"]
    if operator == "exists":
        return (candidate is not None and str(candidate).strip() != "") is bool(value)
    if operator == "equals":
        return _same(candidate, value)
    if operator == "in":
        return any(_same(candidate, item) for item in value)
    if operator == "contains":
        if isinstance(candidate, (list, tuple, set)):
            return any(_same(item, value) for item in candidate)
        return _normalize_text(value) in _normalize_text(candidate)
    if operator == "gte":
        try:
            return float(candidate) >= float(value)
        except (TypeError, ValueError):
            return False
    if operator == "lte":
        try:
            return float(candidate) <= float(value)
        except (TypeError, ValueError):
            return False
    return False


def evaluate_condition_tree(tree: Any, context: Mapping[str, Any]) -> ConditionMatch:
    """Evaluate a validated tree and return matching evidence for precedence."""

    normalized = normalize_condition_tree(tree)

    def evaluate(node: Mapping[str, Any]) -> tuple[bool, int, list[str]]:
        if "all" in node:
            results = [evaluate(child) for child in node["all"]]
            if not all(item[0] for item in results):
                return False, 0, []
            return True, sum(item[1] for item in results), [field for item in results for field in item[2]]
        if "any" in node:
            results = [evaluate(child) for child in node["any"]]
            matches = [item for item in results if item[0]]
            if not matches:
                return False, 0, []
            best = max(matches, key=lambda item: item[1])
            return True, best[1], best[2]
        if "not" in node:
            matched, _specificity, _fields = evaluate(node["not"])
            return (not matched), 1, [f"not:{_condition_field(node['not'])}"]
        field = str(node["field"])
        return _match_atom(node, context), 1, [field]

    matched, specificity, fields = evaluate(normalized)
    return ConditionMatch(
        matched=matched,
        specificity=specificity if matched else 0,
        matched_fields=tuple(fields if matched else ()),
    )


def _condition_field(node: Mapping[str, Any]) -> str:
    if "field" in node:
        return str(node["field"])
    if "not" in node and isinstance(node["not"], Mapping):
        return _condition_field(node["not"])
    return "condition"
