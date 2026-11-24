from __future__ import annotations

from typing import Any

from app.services.ai_orchestration.routing import choose_route
from app.services.ai_orchestration.schemas import OrchestrationTaskRequest, RouteDecision, RoutingContext
from app.services.brain.providers.provider_factory import available_providers
from app.services.brain.router import ModelRouter


def build_routing_context(task: OrchestrationTaskRequest) -> RoutingContext:
    region_requirement = str(task.region_requirement or task.customer_region or "global").strip().lower() or "global"
    return RoutingContext(
        task_type=task.task_type,
        data_sensitivity=task.data_sensitivity,
        risk_tier=task.risk_tier,
        cost_ceiling_usd=float(task.cost_ceiling_usd or 0.0),
        region_requirement=region_requirement,
        residency_requirement=str(task.residency_requirement or "").strip().lower(),
        customer_region=str(task.customer_region or "global").strip().lower() or "global",
        residency_required=bool(task.residency_required),
        customer_policy_profile=dict(task.customer_policy_profile or {}),
    )


def _provider_hints_for_task(task: OrchestrationTaskRequest) -> dict[str, Any]:
    router = ModelRouter()
    active = router.active_config()
    # Keep this deterministic and reference-safe: only provider names, no payload data.
    configured = [
        str(name).strip().lower()
        for name in (active.get("planner_models") if task.task_type == "questionnaire_answer_draft" else active.get("summarizer_models"))
        or []
        if str(name).strip()
    ]
    normalized = {
        "openai": "gpt",
        "chatgpt": "gpt",
        "claude": "claude",
        "anthropic": "claude",
        "gemini": "gemini",
        "llama": "llama",
    }
    hints = []
    for name in configured:
        mapped = normalized.get(name)
        if mapped and mapped not in hints:
            hints.append(mapped)
    return {
        "brain_router_mode": active.get("router_mode"),
        "brain_provider_hints": hints,
        "registered_providers": list(available_providers()),
    }


def resolve_route(task: OrchestrationTaskRequest) -> tuple[RouteDecision, RoutingContext]:
    routing_context = build_routing_context(task)
    # Single routing entrypoint for orchestration reasoning tasks.
    route = choose_route(task)

    merged_context = {
        **dict(route.routing_context or {}),
        **routing_context.model_dump(),
        **_provider_hints_for_task(task),
    }
    route = route.model_copy(update={"routing_context": merged_context})
    return route, routing_context
