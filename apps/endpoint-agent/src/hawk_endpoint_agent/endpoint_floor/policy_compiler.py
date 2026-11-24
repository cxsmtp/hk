from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from .contracts import EndpointPrimitive
from .local_policy import FastPathAction


_SUPPORTED_PREDICATES = frozenset(
    {
        "primitives",
        "resource_classifications",
        "destination_classifications",
        "binary_identities",
        "users",
        "business_purposes",
        "application_assets",
        "ai_assets",
    }
)

_EXECUTABLE_POLICY_KEYS = frozenset(
    {
        "script",
        "scripts",
        "command",
        "commands",
        "shell",
        "powershell",
        "plugin_url",
        "plugin_urls",
        "executable",
        "executable_module",
        "executable_url",
        "module_url",
        "binary_url",
        "payload",
    }
)

_DEFAULT_DEGRADATION = {
    "low_risk_read": "allow_with_evidence",
    "sensitive_file_read": "fail_closed",
    "file_write": "local_policy_only",
    "process_exec": "local_policy_only",
    "known_approved_destination": "allow_with_evidence",
    "unknown_external_destination": "require_exception",
    "sensitive_external_transfer": "fail_closed",
    "mcp_local_connection": "require_exception",
}

_DECISION_ALIASES = {
    "allow": FastPathAction.ALLOW,
    "allow_with_evidence": FastPathAction.ALLOW_WITH_EVIDENCE,
    "block": FastPathAction.BLOCK,
    "deny": FastPathAction.BLOCK,
    "require_preauthorized_permit": FastPathAction.REQUIRE_PREAUTHORIZED_PERMIT,
    "require_remote_decision": FastPathAction.REQUIRE_REMOTE_DECISION,
    "remote_evaluation_required": FastPathAction.REQUIRE_REMOTE_DECISION,
    "require_approval": FastPathAction.REQUIRE_USER_RETRY_AFTER_APPROVAL,
    "require_user_retry_after_approval": FastPathAction.REQUIRE_USER_RETRY_AFTER_APPROVAL,
    "local_escalation_required": FastPathAction.REQUIRE_USER_RETRY_AFTER_APPROVAL,
    "remote_enrichment_allowed": FastPathAction.ALLOW_WITH_EVIDENCE,
}


def _utc_iso(value: str) -> str:
    rendered = str(value or "").strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(rendered)
    if parsed.tzinfo is None:
        raise ValueError("policy timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sorted_strings(values: object, *, field: str, maximum: int = 4096) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError(f"{field} must be a bounded list")
    if len(values) > maximum:
        raise ValueError(f"{field} exceeds the supported limit")
    normalized = {str(value).strip() for value in values if str(value).strip()}
    return sorted(normalized)


def _reject_executable_material(value: object, *, path: str = "policy") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in _EXECUTABLE_POLICY_KEYS:
                raise ValueError(f"executable policy material is prohibited at {path}.{normalized}")
            _reject_executable_material(nested, path=f"{path}.{normalized}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, nested in enumerate(value):
            _reject_executable_material(nested, path=f"{path}[{index}]")


class EndpointPolicyCompiler:
    """Compile Hawk policy's bounded deterministic subset for endpoint use.

    The compiler does not invent a second policy language. It accepts the
    normalized Hawk rule projection, emits only data, and explicitly routes
    unsupported predicates to the authoritative remote policy path.
    """

    def compile(
        self,
        source_policy: Mapping[str, Any],
        *,
        tenant_id: str,
        device_id: str,
        policy_version: str,
        policy_epoch: int,
        issued_at: str,
        expires_at: str,
        rollback_version: str | None,
        platform_capability_requirements: Sequence[str],
    ) -> dict[str, Any]:
        source = deepcopy(dict(source_policy))
        _reject_executable_material(source)
        if not tenant_id.strip() or not device_id.strip() or not policy_version.strip():
            raise ValueError("tenant, device, and policy version are required")
        if type(policy_epoch) is not int or policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")

        issued = _utc_iso(issued_at)
        expires = _utc_iso(expires_at)
        if expires <= issued:
            raise ValueError("policy expiration must follow issuance")

        source_rules = source.get("rules")
        if not isinstance(source_rules, list) or len(source_rules) > 4096:
            raise ValueError("source policy rules must be a bounded list")

        omitted_predicates: set[str] = set()
        compiled_rules: list[dict[str, Any]] = []
        supported_primitives: set[str] = set()
        classification_rules: set[str] = set()
        destination_rules: set[str] = set()
        seen_rule_ids: set[str] = set()

        for index, source_rule in enumerate(source_rules):
            if not isinstance(source_rule, Mapping):
                raise ValueError("source policy rule must be an object")
            rule_id = str(source_rule.get("rule_id") or "").strip()
            if not rule_id or rule_id in seen_rule_ids:
                raise ValueError("source policy rule IDs must be unique and non-empty")
            seen_rule_ids.add(rule_id)
            try:
                priority = int(source_rule.get("priority"))
            except (TypeError, ValueError) as error:
                raise ValueError(f"rule {rule_id} priority is invalid") from error
            if not 0 <= priority <= 1_000_000:
                raise ValueError(f"rule {rule_id} priority is outside the supported range")

            conditions = source_rule.get("conditions", source_rule.get("match", {}))
            if not isinstance(conditions, Mapping):
                raise ValueError(f"rule {rule_id} conditions must be an object")
            unsupported = {str(key) for key in conditions if str(key) not in _SUPPORTED_PREDICATES}
            omitted_predicates.update(unsupported)

            match: dict[str, list[str]] = {}
            for predicate in sorted(_SUPPORTED_PREDICATES.intersection(map(str, conditions))):
                values = _sorted_strings(
                    conditions[predicate],
                    field=f"rules[{index}].conditions.{predicate}",
                    maximum=1024,
                )
                if predicate == "primitives":
                    try:
                        values = sorted({EndpointPrimitive(value.lower()).value for value in values})
                    except ValueError as error:
                        raise ValueError(f"rule {rule_id} contains an unsupported primitive") from error
                    supported_primitives.update(values)
                elif predicate == "resource_classifications":
                    classification_rules.update(values)
                elif predicate == "destination_classifications":
                    destination_rules.update(values)
                match[predicate] = values

            decision_value = str(
                source_rule.get("decision", source_rule.get("action", "")) or ""
            ).strip().lower()
            action = _DECISION_ALIASES.get(decision_value)
            if action is None:
                raise ValueError(f"rule {rule_id} decision is unsupported")
            compiled_rules.append(
                {
                    "rule_id": rule_id,
                    "priority": priority,
                    "match": match,
                    "action": action.value,
                }
            )

        if omitted_predicates:
            compiled_rules.append(
                {
                    "rule_id": "compiler-remote-evaluation-required",
                    "priority": 0,
                    "match": {},
                    "action": FastPathAction.REQUIRE_REMOTE_DECISION.value,
                }
            )

        compiled_rules.sort(key=lambda row: (int(row["priority"]), str(row["rule_id"])))
        source_scope = source.get("user_group_scope") or {}
        if not isinstance(source_scope, Mapping):
            raise ValueError("user_group_scope must be an object")
        user_group_scope = {
            "users": _sorted_strings(source_scope.get("users", []), field="user_group_scope.users"),
            "groups": _sorted_strings(source_scope.get("groups", []), field="user_group_scope.groups"),
        }
        degradation = dict(_DEFAULT_DEGRADATION)
        supplied_degradation = source.get("degradation")
        if supplied_degradation is not None:
            if not isinstance(supplied_degradation, Mapping):
                raise ValueError("degradation must be an object")
            if set(supplied_degradation) != set(_DEFAULT_DEGRADATION):
                raise ValueError("degradation must define every supported action class")
            degradation = {str(key): str(value) for key, value in supplied_degradation.items()}

        required_remote_context = sorted(omitted_predicates)
        return {
            "schema": "hawk.endpoint-fast-path-policy",
            "version": 2,
            "tenant_id": tenant_id.strip(),
            "device_id": device_id.strip(),
            "policy_version": policy_version.strip(),
            "policy_sequence": policy_epoch,
            "policy_epoch": policy_epoch,
            "rollback_version": rollback_version.strip() if rollback_version else None,
            "issued_at": issued,
            "expires_at": expires,
            "rules": compiled_rules,
            "degradation": degradation,
            "user_group_scope": user_group_scope,
            "supported_primitives": sorted(supported_primitives),
            "classification_rules": sorted(classification_rules),
            "destination_rules": sorted(destination_rules),
            "business_purpose_references": _sorted_strings(
                source.get("business_purpose_references", []),
                field="business_purpose_references",
            ),
            "exception_references": _sorted_strings(
                source.get("exception_references", []),
                field="exception_references",
            ),
            "supported_predicates": sorted(_SUPPORTED_PREDICATES),
            "omitted_predicates": sorted(omitted_predicates),
            "required_remote_context": required_remote_context,
            "platform_capability_requirements": _sorted_strings(
                platform_capability_requirements,
                field="platform_capability_requirements",
                maximum=256,
            ),
        }
