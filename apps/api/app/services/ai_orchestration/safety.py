from __future__ import annotations

import copy
import re
from typing import Any

from app.services.ai_orchestration.prompts import PromptTemplateSpec
from app.services.ai_orchestration.schemas import GuardResult, OrchestrationTaskRequest, RouteDecision
from app.services.sensitive_data_detection_service import (
    API_KEY_PATTERN,
    CC_PATTERN,
    EMAIL_PATTERN,
    EMIRATES_ID_CONTEXT_PATTERN,
    EMIRATES_ID_STRICT_PATTERN,
    PHONE_PATTERN,
    detect_sensitive_data,
)


SENSITIVE_REDACTION_PATTERNS = [
    EMAIL_PATTERN,
    PHONE_PATTERN,
    CC_PATTERN,
    API_KEY_PATTERN,
    EMIRATES_ID_STRICT_PATTERN,
    EMIRATES_ID_CONTEXT_PATTERN,
]


def _redact_text(value: str) -> str:
    redacted = str(value or "")
    for pattern in SENSITIVE_REDACTION_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _redact_variables(variables: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    out = copy.deepcopy(variables)
    redacted_fields: list[str] = []
    for key, value in list(out.items()):
        if isinstance(value, str):
            redacted = _redact_text(value)
            if redacted != value:
                redacted_fields.append(key)
                out[key] = redacted
        elif isinstance(value, list):
            new_list: list[Any] = []
            changed = False
            for item in value:
                if isinstance(item, str):
                    redacted_item = _redact_text(item)
                    changed = changed or redacted_item != item
                    new_list.append(redacted_item)
                else:
                    new_list.append(item)
            if changed:
                redacted_fields.append(key)
                out[key] = new_list
        elif isinstance(value, dict):
            nested_text = str(value)
            redacted_nested = _redact_text(nested_text)
            if redacted_nested != nested_text:
                redacted_fields.append(key)
                out[key] = {"redacted": True}
    return out, sorted(set(redacted_fields))


def apply_pre_call_guards(
    *,
    task: OrchestrationTaskRequest,
    route: RouteDecision,
    prompt_variables: dict[str, Any],
    template: PromptTemplateSpec | None = None,
) -> tuple[dict[str, Any], GuardResult]:
    checks: list[str] = []
    violations: list[str] = []

    if task.residency_required and task.customer_region and task.customer_region != "global":
        checks.append("residency_required")
        if route.region_route not in {"global", task.customer_region}:
            violations.append("region_route_mismatch")

    if task.data_sensitivity in {"sensitive", "restricted"}:
        checks.append("sensitive_route_guard")
        if route.provider not in {"gpt", "claude", "llama"}:
            violations.append("provider_not_allowed_for_sensitive")

    if route.fail_secure or route.route_status == "rejected":
        checks.append("route_fail_secure")
        violations.append("routing_constraints_unmet")

    if template is not None and template.allowed_models:
        checks.append("template_model_compatibility")
        if str(route.provider or "").strip().lower() not in {str(item).strip().lower() for item in template.allowed_models}:
            violations.append("route_provider_not_allowed_by_template")

    text_sources = [task.issue_summary, task.issue_title, str(task.context_payload)]
    detection = detect_sensitive_data(text_inputs=text_sources, correlation_id="orchestration-precall")
    sensitive_detected = bool(detection.get("contains_sensitive"))
    checks.append("sensitive_detection")

    redacted_variables, redacted_fields = _redact_variables(prompt_variables)

    if task.data_sensitivity == "restricted" and sensitive_detected and route.provider not in {"gpt", "claude", "llama"}:
        violations.append("restricted_data_route_violation")

    if violations:
        return redacted_variables, GuardResult(
            passed=False,
            reason="pre_call_policy_rejected",
            details={
                "checks": checks,
                "violations": violations,
                "sensitive_detected": sensitive_detected,
                "redacted_fields": redacted_fields,
                "detection": detection,
            },
        )

    return redacted_variables, GuardResult(
        passed=True,
        reason="ok",
        details={
            "checks": checks,
            "violations": [],
            "sensitive_detected": sensitive_detected,
            "redacted_fields": redacted_fields,
            "detection": detection,
        },
    )


_UNSAFE_RECOMMENDATION_PATTERNS = [
    re.compile(r"(?i)\b(auto\s*apply|auto-apply|enforce\s+immediately|execute\s+automatically)\b"),
    re.compile(r"(?i)\b(run\s+shell|bash\s+-c|powershell\b|curl\s+http)\b"),
]

_UNSAFE_EXECUTION_KEYS = {
    "execute_now",
    "apply_immediately",
    "autonomous_enforce",
    "auto_apply",
    "enforcement_action",
    "direct_enforcement_payload",
}


def apply_post_call_guards(*, raw_output: dict[str, Any]) -> GuardResult:
    serialized = str(raw_output)
    violations: list[str] = []
    for pattern in _UNSAFE_RECOMMENDATION_PATTERNS:
        if pattern.search(serialized):
            violations.append(f"unsafe_pattern:{pattern.pattern}")

    if isinstance(raw_output, dict):
        for key in _UNSAFE_EXECUTION_KEYS:
            if key in raw_output:
                violations.append(f"unsafe_key:{key}")

    if violations:
        return GuardResult(
            passed=False,
            reason="post_call_policy_rejected",
            details={"violations": violations},
        )

    return GuardResult(
        passed=True,
        reason="ok",
        details={"violations": []},
    )
