from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.services.brain.providers.base import LLMProvider
from app.services.brain.providers.provider_factory import get_provider


class ModelRouter:
    def __init__(self, *, mode: str | None = None) -> None:
        self.mode = (mode or settings.llm_router_mode or "council").strip().lower()

    def _default_selection(self, task_type: str) -> list[str]:
        if self.mode != "council":
            return [settings.llm_provider or "openai"]
        if task_type == "planner":
            return ["openai", "claude"]
        if task_type == "summarizer":
            return ["openai", "claude", "gemini"]
        return [settings.llm_provider or "openai"]

    def choose_models(
        self,
        task_type: str,
        risk_tier: str | None,
        tenant_policy: dict[str, Any] | None,
    ) -> list[LLMProvider]:
        selected = self._default_selection(task_type)
        policy = tenant_policy or {}
        if isinstance(policy, dict):
            override_key = f"{task_type}_models"
            override = policy.get(override_key)
            if isinstance(override, list) and override:
                selected = [str(item) for item in override]

        providers: list[LLMProvider] = []
        errors: list[str] = []
        seen: set[str] = set()
        for name in selected:
            normalized_name = str(name).strip().lower()
            if not normalized_name or normalized_name in seen:
                continue
            seen.add(normalized_name)
            try:
                providers.append(get_provider(normalized_name))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{normalized_name}: {exc}")

        if not providers:
            raise ValueError(f"No configured providers available for task '{task_type}'. Errors: {'; '.join(errors)}")

        # Ignore risk_tier in phase 0 selection logic, but keep signature for future policies.
        _ = risk_tier
        return providers

    def active_config(self) -> dict[str, Any]:
        return {
            "router_mode": self.mode,
            "planner_models": self._default_selection("planner"),
            "summarizer_models": self._default_selection("summarizer"),
            "default_provider": settings.llm_provider or "openai",
        }
