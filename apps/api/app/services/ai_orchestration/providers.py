from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.services.llm_gateway_secure import SecureCallContext, SecureModelCallResult, secure_generate_json
from app.services.ai_orchestration.schemas import RouteDecision
from app.services.brain.providers.base import LLMProvider
from app.services.brain.providers.openai_provider import OpenAIProvider
from app.services.brain.providers.provider_factory import get_provider


class OrchestrationProviderAdapter:
    def __init__(
        self,
        *,
        provider_name: str,
        model: str,
        model_version: str,
        delegate: LLMProvider,
    ) -> None:
        self.provider_name = provider_name
        self.model = model
        self.model_version = model_version
        self._delegate = delegate

    def generate_json(self, *, system_prompt: str, user_prompt: str, json_schema: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError(
            "Direct provider invocation is disabled. Use secure_generate_json with SecureCallContext."
        )

    def secure_generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any],
        context: SecureCallContext,
        db: Session | None,
        tenant_id: str | None,
        actor_user_id: str | None,
        correlation_id: str | None,
    ) -> SecureModelCallResult:
        return secure_generate_json(
            delegate=self._delegate,
            provider=self.provider_name,
            model=self.model,
            model_version=self.model_version,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=json_schema,
            context=context,
            db=db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
        )


def _llama_provider(route: RouteDecision) -> LLMProvider:
    api_key = (settings.llm_api_key or settings.openai_api_key or "").strip()
    base_url = (settings.llm_base_url or settings.openai_base_url or "").strip() or None
    if not api_key:
        raise ValueError("LLAMA route requires LLM_API_KEY/OPENAI_API_KEY")
    if not base_url:
        raise ValueError("LLAMA route requires LLM_BASE_URL/OPENAI_BASE_URL")

    return OpenAIProvider(
        api_key=api_key,
        model=route.model,
        base_url=base_url,
        api_version=settings.llm_api_version,
        timeout_secs=settings.llm_timeout_secs,
        temperature=settings.llm_temperature,
        max_tokens=settings.llm_max_tokens,
        reasoning_effort=settings.openai_reasoning_effort,
    )


def get_orchestration_provider(route: RouteDecision) -> OrchestrationProviderAdapter:
    provider = route.provider
    if provider == "gpt":
        delegate = get_provider("openai")
    elif provider == "claude":
        delegate = get_provider("claude")
    elif provider == "gemini":
        delegate = get_provider("gemini")
    elif provider == "llama":
        delegate = _llama_provider(route)
    else:
        raise ValueError(f"Unsupported orchestration provider '{provider}'")

    return OrchestrationProviderAdapter(
        provider_name=provider,
        model=route.model,
        model_version=route.model_version,
        delegate=delegate,
    )
