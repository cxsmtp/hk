from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings
from app.services.ai_orchestration.schemas import OrchestrationTaskRequest, RouteDecision


_PROVIDER_ORDER_BY_TASK: dict[str, list[str]] = {
    "remediation_guidance": ["gpt", "claude", "gemini", "llama"],
    "vulnerability_analysis": ["gpt", "claude", "gemini", "llama"],
    "control_gap_analysis": ["gpt", "claude", "gemini", "llama"],
    "simulation_failure_explanation": ["gpt", "claude", "gemini", "llama"],
    "drift_explanation": ["claude", "gpt", "gemini", "llama"],
    "audit_summary": ["gemini", "gpt", "claude", "llama"],
    "questionnaire_answer_draft": ["gemini", "gpt", "claude", "llama"],
}

_PROVIDER_COST_PER_1K_EST: dict[str, float] = {
    "gpt": 0.02,
    "claude": 0.018,
    "gemini": 0.01,
    "llama": 0.006,
}

_PROVIDER_REGIONS: dict[str, set[str]] = {
    "gpt": {"global", "us", "eu", "uae", "gcc"},
    "claude": {"global", "us", "eu"},
    "gemini": {"global", "us", "eu", "asia", "uae", "gcc"},
    "llama": {"global", "us", "eu", "asia", "uae", "gcc"},
}


@dataclass(frozen=True)
class ProviderModel:
    provider: str
    model: str
    model_version: str


def _provider_model(provider: str) -> ProviderModel:
    normalized = provider.strip().lower()
    if normalized == "gpt":
        model = settings.openai_model or settings.llm_model or "gpt-4.1-mini"
        return ProviderModel(provider="gpt", model=model, model_version=str(model))
    if normalized == "claude":
        model = settings.anthropic_model or "claude-3-5-sonnet"
        return ProviderModel(provider="claude", model=model, model_version=str(model))
    if normalized == "gemini":
        model = settings.gemini_model or "gemini-1.5-pro"
        return ProviderModel(provider="gemini", model=model, model_version=str(model))
    model = settings.llm_model or "llama-3.1-70b-instruct"
    return ProviderModel(provider="llama", model=model, model_version=str(model))


def _normalized_region(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized or "global"


def _effective_cost_ceiling(task: OrchestrationTaskRequest) -> float:
    if task.cost_ceiling_usd > 0:
        return float(task.cost_ceiling_usd)
    return 0.25


def _policy_profile(task: OrchestrationTaskRequest) -> dict[str, object]:
    profile = dict(task.customer_policy_profile or {})
    if not profile and isinstance(task.route_policy_overrides.get("customer_policy_profile"), dict):
        profile = dict(task.route_policy_overrides["customer_policy_profile"])
    return profile


def _safe_provider_route(
    *,
    task: OrchestrationTaskRequest,
    region: str,
    sensitivity: str,
    risk_tier: str,
    candidates: list[str],
    failures: list[str],
    reasoning: list[str],
) -> RouteDecision:
    policy_profile = _policy_profile(task)
    routing_context = {
        "task_type": task.task_type,
        "data_sensitivity": sensitivity,
        "risk_tier": risk_tier,
        "cost_ceiling_usd": _effective_cost_ceiling(task),
        "region_requirement": _normalized_region(task.region_requirement or task.customer_region),
        "residency_requirement": str(task.residency_requirement or "").strip().lower(),
        "customer_region": region,
        "residency_required": bool(task.residency_required),
        "customer_policy_profile": policy_profile,
    }

    if not candidates:
        fallback = _provider_model("llama")
        return RouteDecision(
            provider=fallback.provider,
            model=fallback.model,
            model_version=fallback.model_version,
            route_id=f"{task.task_type}:rejected:{region}:{risk_tier}:{sensitivity}",
            routing_policy_id="orchestration-routing-policy-v2",
            region_route=region,
            reasoning=reasoning,
            estimated_cost_usd=_PROVIDER_COST_PER_1K_EST.get(fallback.provider, 0.03),
            route_status="rejected",
            fallback_provider=fallback.provider,
            fallback_model=fallback.model,
            fail_secure=True,
            constraint_failures=failures,
            routing_context=routing_context,
        )

    selected = candidates[0]
    model = _provider_model(selected)
    est_cost = _PROVIDER_COST_PER_1K_EST.get(selected, 0.03)
    return RouteDecision(
        provider=model.provider,
        model=model.model,
        model_version=model.model_version,
        route_id=f"{task.task_type}:{selected}:{region}:{risk_tier}:{sensitivity}",
        routing_policy_id="orchestration-routing-policy-v2",
        region_route=region,
        reasoning=reasoning,
        estimated_cost_usd=round(est_cost, 6),
        route_status="selected",
        fallback_provider=None,
        fallback_model=None,
        fail_secure=False,
        constraint_failures=failures,
        routing_context=routing_context,
    )


def choose_route(task: OrchestrationTaskRequest) -> RouteDecision:
    region = _normalized_region(task.customer_region)
    sensitivity = str(task.data_sensitivity or "internal").strip().lower()
    risk_tier = str(task.risk_tier or "medium").strip().lower()

    region_requirement = _normalized_region(task.region_requirement or region)
    residency_requirement = str(task.residency_requirement or "").strip().lower()

    candidates = list(_PROVIDER_ORDER_BY_TASK.get(task.task_type, ["gpt", "claude", "gemini", "llama"]))
    failures: list[str] = []
    reasoning: list[str] = []

    policy_profile = _policy_profile(task)
    allowlist = policy_profile.get("provider_allowlist")
    if isinstance(allowlist, list) and allowlist:
        allow = {str(item).strip().lower() for item in allowlist if str(item).strip()}
        before = list(candidates)
        candidates = [provider for provider in candidates if provider in allow]
        if candidates != before:
            reasoning.append("customer policy provider allowlist applied")

    blocked = policy_profile.get("blocked_providers")
    if isinstance(blocked, list) and blocked:
        deny = {str(item).strip().lower() for item in blocked if str(item).strip()}
        before = list(candidates)
        candidates = [provider for provider in candidates if provider not in deny]
        if candidates != before:
            reasoning.append("customer policy blocked providers applied")

    override_allowlist = task.route_policy_overrides.get("provider_allowlist")
    if isinstance(override_allowlist, list) and override_allowlist:
        allow = {str(item).strip().lower() for item in override_allowlist if str(item).strip()}
        before = list(candidates)
        candidates = [provider for provider in candidates if provider in allow]
        if candidates != before:
            reasoning.append("route override provider allowlist applied")

    if sensitivity in {"sensitive", "restricted"}:
        before = list(candidates)
        candidates = [provider for provider in candidates if provider in {"gpt", "claude", "llama"}]
        if candidates != before:
            reasoning.append("sensitivity route excluded low-assurance providers")

    if risk_tier in {"high", "critical", "restricted", "prohibited"}:
        before = list(candidates)
        candidates = [provider for provider in candidates if provider in {"gpt", "claude", "llama"}]
        if candidates != before:
            reasoning.append("high risk tier routed to high-capability models")

    if task.residency_required:
        before = list(candidates)
        candidates = [
            provider
            for provider in candidates
            if region in _PROVIDER_REGIONS.get(provider, {"global"})
            and region_requirement in _PROVIDER_REGIONS.get(provider, {"global"})
        ]
        if candidates != before:
            reasoning.append("residency requirement constrained provider region")

    if residency_requirement:
        before = list(candidates)
        candidates = [
            provider
            for provider in candidates
            if residency_requirement in _PROVIDER_REGIONS.get(provider, {"global"})
        ]
        if candidates != before:
            reasoning.append("residency requirement profile constrained provider region")

    if not candidates:
        failures.append("no_provider_matches_policy_residency_constraints")

    ceiling = _effective_cost_ceiling(task)
    if ceiling > 0 and candidates:
        cost_filtered = [provider for provider in candidates if _PROVIDER_COST_PER_1K_EST.get(provider, 1.0) <= ceiling]
        if cost_filtered:
            candidates = cost_filtered
            reasoning.append("cost ceiling applied")
        else:
            lowest = min(candidates, key=lambda provider: _PROVIDER_COST_PER_1K_EST.get(provider, 1.0))
            if _PROVIDER_COST_PER_1K_EST.get(lowest, 1.0) > ceiling:
                failures.append("cost_ceiling_exceeded_for_all_candidates")
                candidates = []
            else:
                candidates = [lowest]
                reasoning.append("selected lowest-cost fallback provider")

    return _safe_provider_route(
        task=task,
        region=region,
        sensitivity=sensitivity,
        risk_tier=risk_tier,
        candidates=candidates,
        failures=failures,
        reasoning=reasoning,
    )
