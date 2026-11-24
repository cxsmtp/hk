from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import UserRegistry
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.user import UserTenantRole
from app.services.maturity_curve.policy_conditions import evaluate_condition_tree, normalize_condition_tree


CANONICAL_DECISIONS = {
    "allow",
    "warn",
    "block",
    "redact",
    "require_approval",
    "require_justification",
    "hold_for_approval",
}

DECISION_RANK = {
    "allow": 0,
    "warn": 1,
    "redact": 2,
    "require_justification": 3,
    "require_approval": 4,
    "hold_for_approval": 4,
    "block": 5,
}


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _normalize_domain(value: Any) -> str:
    raw = _normalize_lower(value)
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.netloc or parsed.path
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host.strip(".")


def _decision_rank(value: str) -> int:
    return DECISION_RANK.get(_normalize_lower(value), -1)


def _normalize_decision(value: Any) -> str:
    normalized = _normalize_lower(value)
    aliases = {
        "deny": "block",
        "alert": "warn",
        "step_up": "require_approval",
        "step-up": "require_approval",
        "hold": "hold_for_approval",
        "require-review": "require_approval",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in CANONICAL_DECISIONS:
        return "allow"
    return normalized


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _non_empty_list(value: Any) -> list[str]:
    return [_normalize_text(item) for item in _as_list(value) if _normalize_text(item)]


def _lower_list(value: Any) -> list[str]:
    return [_normalize_lower(item) for item in _as_list(value) if _normalize_lower(item)]


def _matches_selector(
    *,
    raw_values: Any,
    candidate: Any,
    case_insensitive: bool = True,
) -> bool:
    values = _non_empty_list(raw_values)
    if not values or "*" in values:
        return True
    token = _normalize_text(candidate)
    if not token:
        return False
    if case_insensitive:
        token = token.lower()
        normalized = [item.lower() for item in values]
    else:
        normalized = values
    return token in normalized


def _matches_domain_selector(
    *,
    raw_values: Any,
    candidate: Any,
) -> bool:
    values = [_normalize_domain(item) for item in _as_list(raw_values) if _normalize_domain(item)]
    if not values or "*" in values:
        return True
    domain = _normalize_domain(candidate)
    if not domain:
        return False
    for value in values:
        if value.startswith("*."):
            suffix = value[2:]
            if domain == suffix or domain.endswith(f".{suffix}"):
                return True
            continue
        if domain == value or domain.endswith(f".{value}"):
            return True
    return False


def _matches_bool_selector(raw_value: Any, candidate: Any) -> bool:
    if raw_value is None:
        return True
    return bool(raw_value) == bool(candidate)


def _extract_scoped_rules(policy_version: PolicyVersion | None) -> list[dict[str, Any]]:
    if policy_version is None:
        return []

    out: list[dict[str, Any]] = []
    containers = [
        policy_version.scope if isinstance(policy_version.scope, dict) else {},
        policy_version.contract_json if isinstance(policy_version.contract_json, dict) else {},
        policy_version.enforcement_defaults if isinstance(policy_version.enforcement_defaults, dict) else {},
    ]

    for container in containers:
        scoped = container.get("scoped_rules")
        if not isinstance(scoped, list):
            scope_obj = container.get("scope")
            if isinstance(scope_obj, dict):
                scoped = scope_obj.get("scoped_rules")
        if not isinstance(scoped, list):
            continue
        for rule in scoped:
            if isinstance(rule, dict):
                out.append(dict(rule))
    return out


def _resolve_policy_versions(
    db: Session,
    *,
    tenant_id: str,
    policy_version_id: str | None = None,
) -> list[PolicyVersion]:
    if policy_version_id and _normalize_lower(policy_version_id) != "none":
        row = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.id == policy_version_id,
                PolicyVersion.tenant_id == tenant_id,
            )
        )
        return [row] if row is not None else []

    rows = db.execute(
        select(PolicyPack.id, PolicyVersion)
        .join(PolicyVersion, PolicyVersion.pack_id == PolicyPack.id)
        .where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyPack.tenant_id == tenant_id,
            PolicyPack.status == "active",
        )
        .order_by(PolicyVersion.created_at.desc(), PolicyVersion.id.desc())
    ).all()
    platform_pack_ids = {
        str(pack_id)
        for pack_id, version in rows
        if isinstance(version.contract_json, dict)
        and _normalize_lower(version.contract_json.get("profile")) == "policy_pack_platform"
    }
    active_platform_versions: dict[str, str] = {}
    if platform_pack_ids:
        from app.services.policy_pack_platform.service import active_runtime_policy_version_ids_by_pack

        active_platform_versions = active_runtime_policy_version_ids_by_pack(db, tenant_id=tenant_id)
    versions: list[PolicyVersion] = []
    seen_pack_ids: set[str] = set()
    legacy_version_selected = False
    for pack_id, version in rows:
        normalized_pack_id = str(pack_id)
        if normalized_pack_id in platform_pack_ids:
            if str(version.id) != active_platform_versions.get(normalized_pack_id):
                continue
        elif legacy_version_selected:
            continue
        if normalized_pack_id in seen_pack_ids:
            continue
        seen_pack_ids.add(normalized_pack_id)
        versions.append(version)
        if normalized_pack_id not in platform_pack_ids:
            legacy_version_selected = True
    return versions


def _rules_with_source_versions(policy_versions: list[PolicyVersion]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for policy_version in policy_versions:
        for raw_rule in _extract_scoped_rules(policy_version):
            rule = dict(raw_rule)
            rule["_hawk_source_policy_version_id"] = str(policy_version.id)
            rules.append(rule)
    return rules


def _resolve_actor_role(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    role_hint: str | None = None,
) -> str | None:
    role = _normalize_text(role_hint)
    if role:
        return role
    user_id = _normalize_text(actor_user_id)
    if not user_id:
        return None
    row = db.scalar(
        select(UserTenantRole).where(
            UserTenantRole.tenant_id == tenant_id,
            UserTenantRole.user_id == user_id,
        )
    )
    return _normalize_text(row.role) if row is not None else None


def _resolve_actor_department(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    department_hint: str | None = None,
) -> str | None:
    department = _normalize_text(department_hint)
    if department:
        return department
    user_id = _normalize_text(actor_user_id)
    if not user_id:
        return None
    row = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id == user_id,
        )
    )
    return _normalize_text(row.department) if row is not None else None


@dataclass
class ScopedPolicyResolution:
    matched: bool
    decision: str | None
    reason_code: str | None
    explanation: str | None
    recommended_action: str | None
    policy_version_id: str | None
    rule_id: str | None
    priority: int
    specificity: int
    matched_selectors: list[str]
    raw_rule: dict[str, Any] | None
    actor_role: str | None
    actor_department: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "decision": self.decision,
            "reason_code": self.reason_code,
            "explanation": self.explanation,
            "recommended_action": self.recommended_action,
            "policy_version_id": self.policy_version_id,
            "rule_id": self.rule_id,
            "priority": self.priority,
            "specificity": self.specificity,
            "matched_selectors": list(self.matched_selectors or []),
            "actor_role": self.actor_role,
            "actor_department": self.actor_department,
        }


def _empty_resolution(
    *,
    policy_version_id: str | None,
    actor_role: str | None,
    actor_department: str | None,
) -> ScopedPolicyResolution:
    return ScopedPolicyResolution(
        matched=False,
        decision=None,
        reason_code=None,
        explanation=None,
        recommended_action=None,
        policy_version_id=policy_version_id,
        rule_id=None,
        priority=0,
        specificity=0,
        matched_selectors=[],
        raw_rule=None,
        actor_role=actor_role,
        actor_department=actor_department,
    )


def _evaluate_rule(
    *,
    rule: dict[str, Any],
    context: dict[str, Any],
) -> tuple[bool, int, list[str]]:
    matched_fields: list[str] = []
    specificity = 0

    subjects = rule.get("subjects") if isinstance(rule.get("subjects"), dict) else {}
    resources = rule.get("resources") if isinstance(rule.get("resources"), dict) else {}
    actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
    conditions = rule.get("conditions") if isinstance(rule.get("conditions"), dict) else {}

    checks: list[tuple[str, bool, bool]] = []

    checks.append(
        (
            "subjects.user_ids",
            _matches_selector(raw_values=subjects.get("user_ids"), candidate=context.get("actor_user_id"), case_insensitive=False),
            bool(_non_empty_list(subjects.get("user_ids"))),
        )
    )
    checks.append(
        (
            "subjects.roles",
            _matches_selector(raw_values=subjects.get("roles"), candidate=context.get("actor_role"), case_insensitive=True),
            bool(_non_empty_list(subjects.get("roles"))),
        )
    )
    checks.append(
        (
            "subjects.departments",
            _matches_selector(
                raw_values=subjects.get("departments"),
                candidate=context.get("actor_department"),
                case_insensitive=True,
            ),
            bool(_non_empty_list(subjects.get("departments"))),
        )
    )
    checks.append(
        (
            "subjects.actor_types",
            _matches_selector(raw_values=subjects.get("actor_types"), candidate=context.get("actor_type"), case_insensitive=True),
            bool(_non_empty_list(subjects.get("actor_types"))),
        )
    )
    checks.append(
        (
            "subjects.agent_ids",
            _matches_selector(raw_values=subjects.get("agent_ids"), candidate=context.get("agent_id"), case_insensitive=False),
            bool(_non_empty_list(subjects.get("agent_ids"))),
        )
    )
    checks.append(
        (
            "subjects.endpoint_ids",
            _matches_selector(raw_values=subjects.get("endpoint_ids"), candidate=context.get("endpoint_id"), case_insensitive=False),
            bool(_non_empty_list(subjects.get("endpoint_ids"))),
        )
    )
    checks.append(
        (
            "subjects.source_surfaces",
            _matches_selector(
                raw_values=subjects.get("source_surfaces"),
                candidate=context.get("source_surface"),
                case_insensitive=True,
            ),
            bool(_non_empty_list(subjects.get("source_surfaces"))),
        )
    )

    checks.append(
        (
            "resources.ai_system_ids",
            _matches_selector(
                raw_values=resources.get("ai_system_ids"),
                candidate=context.get("ai_system_id"),
                case_insensitive=False,
            ),
            bool(_non_empty_list(resources.get("ai_system_ids"))),
        )
    )
    checks.append(
        (
            "resources.domains",
            _matches_domain_selector(raw_values=resources.get("domains"), candidate=context.get("domain")),
            bool(_non_empty_list(resources.get("domains"))),
        )
    )
    checks.append(
        (
            "resources.tools",
            _matches_selector(raw_values=resources.get("tools"), candidate=context.get("tool_name"), case_insensitive=True),
            bool(_non_empty_list(resources.get("tools"))),
        )
    )
    checks.append(
        (
            "resources.providers",
            _matches_selector(raw_values=resources.get("providers"), candidate=context.get("provider"), case_insensitive=True),
            bool(_non_empty_list(resources.get("providers"))),
        )
    )
    checks.append(
        (
            "resources.models",
            _matches_selector(raw_values=resources.get("models"), candidate=context.get("model"), case_insensitive=True),
            bool(_non_empty_list(resources.get("models"))),
        )
    )

    checks.append(
        (
            "actions.types",
            _matches_selector(raw_values=actions.get("types"), candidate=context.get("action_type"), case_insensitive=True),
            bool(_non_empty_list(actions.get("types"))),
        )
    )
    checks.append(
        (
            "actions.operations",
            _matches_selector(raw_values=actions.get("operations"), candidate=context.get("operation"), case_insensitive=True),
            bool(_non_empty_list(actions.get("operations"))),
        )
    )

    checks.append(
        (
            "conditions.data_classifications",
            _matches_selector(
                raw_values=conditions.get("data_classifications"),
                candidate=context.get("data_classification"),
                case_insensitive=True,
            ),
            bool(_non_empty_list(conditions.get("data_classifications"))),
        )
    )
    checks.append(
        (
            "conditions.risk_tiers",
            _matches_selector(raw_values=conditions.get("risk_tiers"), candidate=context.get("risk_tier"), case_insensitive=True),
            bool(_non_empty_list(conditions.get("risk_tiers"))),
        )
    )

    condition_contains_sensitive_configured = conditions.get("contains_sensitive") is not None
    checks.append(
        (
            "conditions.contains_sensitive",
            _matches_bool_selector(conditions.get("contains_sensitive"), context.get("contains_sensitive")),
            bool(condition_contains_sensitive_configured),
        )
    )

    for field, matched, configured in checks:
        if not configured:
            continue
        specificity += 1
        if not matched:
            return False, 0, []
        matched_fields.append(field)

    condition_tree = rule.get("condition_tree")
    if condition_tree is not None:
        try:
            condition_match = evaluate_condition_tree(condition_tree, context)
        except ValueError:
            return False, 0, []
        if not condition_match.matched:
            return False, 0, []
        specificity += condition_match.specificity
        matched_fields.extend(f"condition_tree.{field}" for field in condition_match.matched_fields)

    if not bool(rule.get("enabled", True)):
        return False, 0, []

    effect = rule.get("effect") if isinstance(rule.get("effect"), dict) else {}
    decision = _normalize_decision(effect.get("decision") or rule.get("decision"))
    if decision not in CANONICAL_DECISIONS:
        return False, 0, []

    return True, specificity, matched_fields


def _build_scoped_eval_context(
    context: dict[str, Any],
    *,
    actor_user_id: str | None,
    actor_role: str | None,
    actor_department: str | None,
    tenant_id: str | None = None,
    actor_groups: list[str] | None = None,
) -> dict[str, Any]:
    """Normalize the only context shape accepted by scoped policy matching."""

    return {
        "tenant_id": _normalize_text(tenant_id or context.get("tenant_id")) or None,
        "actor_type": _normalize_lower(context.get("actor_type") or "human"),
        "actor_user_id": actor_user_id,
        "actor_role": _normalize_text(actor_role),
        "actor_department": _normalize_text(actor_department),
        "actor_group": [_normalize_text(item) for item in (actor_groups or _as_list(context.get("actor_group"))) if _normalize_text(item)],
        "legal_entity": _normalize_lower(context.get("legal_entity") or ""),
        "business_unit": _normalize_lower(context.get("business_unit") or ""),
        "account_class": _normalize_lower(context.get("account_class") or ""),
        "agent_id": _normalize_text(context.get("agent_id") or "") or None,
        "endpoint_id": _normalize_text(context.get("endpoint_id") or "") or None,
        "source_surface": _normalize_lower(context.get("source_surface") or ""),
        "action_type": _normalize_lower(context.get("action_type") or ""),
        "operation": _normalize_lower(context.get("operation") or context.get("action_type") or ""),
        "domain": _normalize_domain(context.get("domain")),
        "tool_name": _normalize_lower(context.get("tool_name") or context.get("domain") or ""),
        "provider": _normalize_lower(context.get("provider") or ""),
        "model": _normalize_lower(context.get("model") or ""),
        "ai_system_id": _normalize_text(context.get("ai_system_id") or "") or None,
        "data_classification": _normalize_lower(context.get("data_classification") or ""),
        "destination_class": _normalize_lower(context.get("destination_class") or ""),
        "tool_trust_state": _normalize_lower(context.get("tool_trust_state") or ""),
        "contains_sensitive": bool(context.get("contains_sensitive")),
        "risk_tier": _normalize_lower(context.get("risk_tier") or ""),
        "application": _normalize_lower(context.get("application") or context.get("ai_app") or ""),
        "mcp_server": _normalize_lower(context.get("mcp_server") or context.get("mcp_server_id") or ""),
        "destination": _normalize_lower(context.get("destination") or context.get("destination_ref") or context.get("domain") or ""),
        "action_class": _normalize_lower(context.get("action_class") or context.get("action_type") or ""),
        "business_purpose": _normalize_lower(context.get("business_purpose") or context.get("purpose") or ""),
        "environment": _normalize_lower(context.get("environment") or ""),
        "sensitivity_score": context.get("sensitivity_score", 0),
    }


def resolve_scoped_policy_rules(
    db: Session,
    *,
    tenant_id: str,
    policy_version_id: str | None,
    context: dict[str, Any],
    rules: list[dict[str, Any]] | None,
) -> ScopedPolicyResolution:
    actor_user_id = _normalize_text(context.get("actor_user_id") or context.get("user_id")) or None
    actor_role = _resolve_actor_role(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        role_hint=_normalize_text(context.get("actor_role")) or None,
    )
    actor_department = _resolve_actor_department(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        department_hint=_normalize_text(context.get("actor_department")) or None,
    )

    # Dynamic policy-pack groups are configuration context, never a second
    # policy evaluator. The lazy import avoids a startup cycle because the pack
    # compiler itself uses this canonical resolver.
    actor_groups = [_normalize_text(item) for item in _as_list(context.get("actor_group")) if _normalize_text(item)]
    if actor_user_id:
        try:
            from app.services.policy_pack_platform.service import resolve_group_refs_for_user

            actor_groups.extend(resolve_group_refs_for_user(db, tenant_id=tenant_id, user_id=actor_user_id))
        except (ImportError, RuntimeError):
            # The resolver remains available when the optional platform module
            # has not been installed yet; caller-provided scoped context still
            # evaluates normally.
            pass

    resolved_policy_version_id = policy_version_id or None
    if not rules:
        return _empty_resolution(
            policy_version_id=resolved_policy_version_id,
            actor_role=actor_role,
            actor_department=actor_department,
        )

    eval_context = _build_scoped_eval_context(
        context,
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        actor_department=actor_department,
        tenant_id=tenant_id,
        actor_groups=sorted(set(actor_groups)),
    )

    matches: list[tuple[int, int, int, dict[str, Any], list[str]]] = []
    for index, rule in enumerate(rules):
        is_match, specificity, matched_fields = _evaluate_rule(rule=rule, context=eval_context)
        if not is_match:
            continue

        effect = rule.get("effect") if isinstance(rule.get("effect"), dict) else {}
        decision = _normalize_decision(effect.get("decision") or rule.get("decision"))
        priority_value = effect.get("priority", rule.get("priority", 100))
        try:
            priority = int(priority_value)
        except (TypeError, ValueError):
            priority = 100
        matches.append((priority, specificity, _decision_rank(decision), {**rule, "_rule_index": index}, matched_fields))

    if not matches:
        return _empty_resolution(
            policy_version_id=resolved_policy_version_id,
            actor_role=actor_role,
            actor_department=actor_department,
        )

    # Tenant safety and explicit revocation rules form hard floors. A later,
    # more-specific allow must never select around them merely through a larger
    # priority or specificity number.
    hard_floor_matches = [
        item
        for item in matches
        if isinstance(item[3].get("metadata"), dict)
        and isinstance(item[3]["metadata"].get("policy_pack_platform"), dict)
        and bool(
            item[3]["metadata"]["policy_pack_platform"].get("non_overridable")
            or item[3]["metadata"]["policy_pack_platform"].get("explicit_revocation")
        )
    ]
    if hard_floor_matches:
        matches = hard_floor_matches

    matches.sort(key=lambda item: (item[0], item[1], item[2], -int(item[3].get("_rule_index", 0))), reverse=True)
    priority, specificity, _rank, chosen, matched_fields = matches[0]
    effect = chosen.get("effect") if isinstance(chosen.get("effect"), dict) else {}

    rule_id = _normalize_text(chosen.get("rule_id")) or f"scoped_rule_{int(chosen.get('_rule_index', 0)) + 1}"
    decision = _normalize_decision(effect.get("decision") or chosen.get("decision"))
    reason_code = _normalize_text(effect.get("reason_code")) or f"scoped_policy_{rule_id}"
    explanation = _normalize_text(effect.get("explanation")) or "Scoped policy rule matched request context."
    recommended_action = _normalize_text(effect.get("recommended_action")) or (
        "route_to_governance" if decision in {"block", "require_approval", "hold_for_approval", "require_justification"} else "monitor"
    )

    source_policy_version_id = _normalize_text(chosen.get("_hawk_source_policy_version_id")) or policy_version_id
    return ScopedPolicyResolution(
        matched=True,
        decision=decision,
        reason_code=reason_code,
        explanation=explanation,
        recommended_action=recommended_action,
        policy_version_id=source_policy_version_id,
        rule_id=rule_id,
        priority=priority,
        specificity=specificity,
        matched_selectors=matched_fields,
        raw_rule={k: v for k, v in chosen.items() if k not in {"_rule_index", "_hawk_source_policy_version_id"}},
        actor_role=actor_role,
        actor_department=actor_department,
    )


def resolve_scoped_policy_decision(
    db: Session,
    *,
    tenant_id: str,
    policy_version_id: str | None,
    context: dict[str, Any],
) -> ScopedPolicyResolution:
    """Resolve a stored policy version through the canonical scoped-rule evaluator.

    Historical simulations call ``resolve_scoped_policy_rules`` with a proposed
    rule set. Keeping matching and precedence in one evaluator prevents a
    simulation-only policy engine from drifting away from live enforcement.
    """

    policy_versions = _resolve_policy_versions(
        db,
        tenant_id=tenant_id,
        policy_version_id=policy_version_id,
    )
    primary_policy_version = policy_versions[0] if policy_versions else None
    resolved_policy_version_id = str(primary_policy_version.id) if primary_policy_version is not None else (policy_version_id or None)
    rules = _rules_with_source_versions(policy_versions)
    has_explicit_policy_version = bool(policy_version_id and _normalize_lower(policy_version_id) != "none")
    if not has_explicit_policy_version and any(
        isinstance(version.contract_json, dict)
        and _normalize_lower(version.contract_json.get("profile")) == "policy_pack_platform"
        for version in policy_versions
    ):
        from app.services.policy_pack_platform.service import active_policy_pack_exception_rules_for_runtime

        rules.extend(active_policy_pack_exception_rules_for_runtime(db, tenant_id=tenant_id))
    resolution = resolve_scoped_policy_rules(
        db,
        tenant_id=tenant_id,
        policy_version_id=resolved_policy_version_id,
        context=context,
        rules=rules,
    )
    # Maturity exceptions apply only to a policy version explicitly created by
    # the Maturity Curve lifecycle. They are still evaluated through this
    # canonical policy resolver and cannot bypass unrelated policy packs.
    selected_policy_version = next(
        (version for version in policy_versions if str(version.id) == str(resolution.policy_version_id or "")),
        primary_policy_version,
    )
    contract = (
        selected_policy_version.contract_json
        if selected_policy_version is not None and isinstance(selected_policy_version.contract_json, dict)
        else {}
    )
    selected_policy_version_id = str(selected_policy_version.id) if selected_policy_version is not None else None
    maturity_metadata = contract.get("maturity_curve") if isinstance(contract.get("maturity_curve"), dict) else None
    if (
        not resolution.matched
        or resolution.decision not in {"block", "require_approval", "hold_for_approval", "require_justification"}
        or (
            str(contract.get("profile") or "").strip().lower() != "maturity_curve"
            and maturity_metadata is None
        )
        or not selected_policy_version_id
    ):
        return resolution
    from app.services.maturity_curve.exceptions import find_matching_active_policy_exception

    actor_user_id = _normalize_text(context.get("actor_user_id") or context.get("user_id")) or None
    exception = find_matching_active_policy_exception(
        db,
        tenant_id=tenant_id,
        policy_version_id=selected_policy_version_id,
        context=_build_scoped_eval_context(
            context,
            actor_user_id=actor_user_id,
            actor_role=resolution.actor_role,
            actor_department=resolution.actor_department,
            tenant_id=tenant_id,
        ),
    )
    if exception is None:
        return resolution
    return ScopedPolicyResolution(
        matched=True,
        decision="allow",
        reason_code=f"maturity_exception:{exception.id}",
        explanation="A time-bound, exact-scope maturity policy exception is active.",
        recommended_action="monitor_exception_expiry",
        policy_version_id=selected_policy_version_id,
        rule_id=f"maturity_exception:{exception.id}",
        priority=resolution.priority + 1,
        specificity=resolution.specificity + 1,
        matched_selectors=[*resolution.matched_selectors, "maturity_exception"],
        raw_rule={
            "maturity_exception_id": exception.id,
            "base_rule_id": resolution.rule_id,
            "expires_at": exception.expires_at.isoformat(),
        },
        actor_role=resolution.actor_role,
        actor_department=resolution.actor_department,
    )


def normalize_scoped_rule_list(payload_rules: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(payload_rules or []):
        if not isinstance(raw_rule, dict):
            continue
        rule = dict(raw_rule)
        rule_id = _normalize_text(rule.get("rule_id")) or f"scoped_rule_{index + 1}"
        subjects = dict(rule.get("subjects") or {})
        resources = dict(rule.get("resources") or {})
        actions = dict(rule.get("actions") or {})
        conditions = dict(rule.get("conditions") or {})
        effect = dict(rule.get("effect") or {})

        normalized_rule = {
            "rule_id": rule_id,
            "enabled": bool(rule.get("enabled", True)),
            "priority": int(effect.get("priority", rule.get("priority", 100)) or 100),
            "description": _normalize_text(rule.get("description")),
            "subjects": {
                "user_ids": _non_empty_list(subjects.get("user_ids")),
                "roles": _lower_list(subjects.get("roles")),
                "departments": _lower_list(subjects.get("departments")),
                "actor_types": _lower_list(subjects.get("actor_types")),
                "agent_ids": _non_empty_list(subjects.get("agent_ids")),
                "endpoint_ids": _non_empty_list(subjects.get("endpoint_ids")),
                "source_surfaces": _lower_list(subjects.get("source_surfaces")),
            },
            "resources": {
                "ai_system_ids": _non_empty_list(resources.get("ai_system_ids")),
                "domains": [_normalize_domain(item) for item in _as_list(resources.get("domains")) if _normalize_domain(item)],
                "tools": _lower_list(resources.get("tools")),
                "providers": _lower_list(resources.get("providers")),
                "models": _lower_list(resources.get("models")),
            },
            "actions": {
                "types": _lower_list(actions.get("types")),
                "operations": _lower_list(actions.get("operations")),
            },
            "conditions": {
                "data_classifications": _lower_list(conditions.get("data_classifications")),
                "risk_tiers": [value.upper() for value in _lower_list(conditions.get("risk_tiers"))],
                "contains_sensitive": (
                    bool(conditions.get("contains_sensitive"))
                    if conditions.get("contains_sensitive") is not None
                    else None
                ),
            },
            "effect": {
                "decision": _normalize_decision(effect.get("decision") or rule.get("decision")),
                "reason_code": _normalize_text(effect.get("reason_code")),
                "explanation": _normalize_text(effect.get("explanation")),
                "recommended_action": _normalize_text(effect.get("recommended_action")),
                "priority": int(effect.get("priority", rule.get("priority", 100)) or 100),
            },
            "metadata": dict(rule.get("metadata") or {}),
        }
        if rule.get("condition_tree") is not None:
            normalized_rule["condition_tree"] = normalize_condition_tree(rule.get("condition_tree"))
        normalized.append(normalized_rule)
    return normalized


def validate_scoped_rule_list(payload_rules: list[dict[str, Any]] | None) -> list[str]:
    errors: list[str] = []
    seen_rule_ids: set[str] = set()
    for index, raw_rule in enumerate(payload_rules or []):
        if not isinstance(raw_rule, dict) or raw_rule.get("condition_tree") is None:
            continue
        try:
            normalize_condition_tree(raw_rule.get("condition_tree"))
        except ValueError as exc:
            errors.append(f"rule[{index}] invalid condition_tree: {exc}")
    if errors:
        return errors
    for index, rule in enumerate(normalize_scoped_rule_list(payload_rules)):
        rule_id = str(rule.get("rule_id") or "")
        if not rule_id:
            errors.append(f"rule[{index}] missing rule_id")
        if rule_id in seen_rule_ids:
            errors.append(f"duplicate rule_id: {rule_id}")
        seen_rule_ids.add(rule_id)

        decision = str(((rule.get("effect") or {}).get("decision")) or "")
        if decision not in CANONICAL_DECISIONS:
            errors.append(f"rule[{rule_id}] invalid decision: {decision}")

        has_scope = False
        for section_key in ("subjects", "resources", "actions", "conditions"):
            section = rule.get(section_key)
            if not isinstance(section, dict):
                continue
            for value in section.values():
                if isinstance(value, list) and value:
                    has_scope = True
                elif isinstance(value, bool):
                    has_scope = True
        if isinstance(rule.get("condition_tree"), dict):
            has_scope = True
        if not has_scope:
            errors.append(f"rule[{rule_id}] must define at least one selector in subjects/resources/actions/conditions")

    return errors
