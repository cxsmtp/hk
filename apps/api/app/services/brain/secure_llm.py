from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.services.brain.providers.base import LLMProvider
from app.services.llm_gateway_secure.gateway import secure_generate_json
from app.services.llm_gateway_secure.schemas import SecureCallContext


def _data_sensitivity(tenant_policy: dict[str, Any] | None) -> str:
    policy = dict(tenant_policy or {})
    value = str(policy.get("data_sensitivity") or policy.get("default_data_sensitivity") or "internal").strip().lower()
    if value in {"public", "internal", "sensitive", "restricted"}:
        return value
    return "internal"


def _policy_profile(tenant_policy: dict[str, Any] | None) -> dict[str, Any]:
    policy = dict(tenant_policy or {})
    profile = dict(policy.get("llm_gateway_security") or {}) if isinstance(policy.get("llm_gateway_security"), dict) else {}
    for key in [
        "provider_allowlist",
        "allowed_regions",
        "minimization_mode",
        "post_call_sensitive_action",
        "require_tls_1_3",
        "allow_insecure_localhost_http",
        "allow_high_risk_tools",
    ]:
        if key in policy and key not in profile:
            profile[key] = policy.get(key)
    return profile


def secure_brain_generate_json(
    *,
    provider: LLMProvider,
    system_prompt: str,
    user_prompt: str,
    json_schema: dict[str, Any],
    task_type: str,
    risk_tier: str | None,
    tenant_policy: dict[str, Any] | None,
    tenant_id: str | None,
    actor_user_id: str | None,
    db: Session | None,
    correlation_id: str | None,
    prompt_template_id: str,
    prompt_template_version: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = secure_generate_json(
        delegate=provider,
        provider=str(getattr(provider, "name", "") or "openai"),
        model=str(getattr(provider, "model", "") or ""),
        model_version=str(getattr(provider, "model", "") or ""),
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        json_schema=json_schema,
        context=SecureCallContext(
            task_type=str(task_type or "brain_task"),
            data_sensitivity=_data_sensitivity(tenant_policy),
            risk_tier=str(risk_tier or "medium").strip().lower() or "medium",
            cost_ceiling_usd=float(dict(tenant_policy or {}).get("cost_ceiling_usd") or 0.25),
            customer_region=str(dict(tenant_policy or {}).get("customer_region") or "global"),
            region_requirement=str(dict(tenant_policy or {}).get("region_requirement") or "global"),
            residency_requirement=str(dict(tenant_policy or {}).get("residency_requirement") or ""),
            residency_required=bool(dict(tenant_policy or {}).get("residency_required")),
            customer_policy_profile=_policy_profile(tenant_policy),
            policy_applied=str(dict(tenant_policy or {}).get("policy_version") or "brain-policy"),
            policy_version=str(dict(tenant_policy or {}).get("policy_version") or ""),
            governance_version=str(dict(tenant_policy or {}).get("governance_version") or ""),
            prompt_template_id=prompt_template_id,
            prompt_template_version=prompt_template_version,
            retrieval_sources=[],
            tool_calls=[],
        ),
        db=db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        correlation_id=correlation_id,
    )

    if result.blocked:
        raise RuntimeError(f"secure_gateway_blocked:{result.block_reason or 'blocked'}")
    output = dict(result.output_json or {})
    if not output:
        raise RuntimeError("secure_gateway_empty_output")
    return output, dict(result.trace or {})
