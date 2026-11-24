from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.services.brain.providers.anthropic_provider import AnthropicProvider
from app.services.brain.providers.base import LLMProvider
from app.services.brain.providers.gemini_provider import GeminiProvider
from app.services.brain.providers.openai_provider import OpenAIProvider


ALIASES = {
    "openai": "openai",
    "chatgpt": "openai",
    "anthropic": "claude",
    "claude": "claude",
    "gemini": "gemini",
}


def available_providers() -> list[str]:
    return ["openai", "claude", "gemini"]


def _normalize_provider_name(provider_name: str | None) -> str:
    selected = (provider_name or settings.llm_provider or "openai").strip().lower()
    normalized = ALIASES.get(selected)
    if normalized is None:
        raise ValueError(f"Unsupported LLM provider '{selected}'. Available: {', '.join(available_providers())}")
    return normalized


def _require(value: str | None, env_name: str, provider_name: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise ValueError(f"{env_name} is required when provider={provider_name}")
    return normalized


def _openai_api_key() -> str:
    return _require(settings.openai_api_key or settings.llm_api_key, "OPENAI_API_KEY", "openai")


def _openai_model() -> str:
    return _require(settings.openai_model or settings.llm_model, "OPENAI_MODEL", "openai")


def _openai_base_url() -> str | None:
    return settings.openai_base_url or settings.llm_base_url


def _build_provider(provider_name: str) -> LLMProvider:
    if provider_name == "openai":
        return OpenAIProvider(
            api_key=_openai_api_key(),
            model=_openai_model(),
            base_url=_openai_base_url(),
            api_version=settings.llm_api_version,
            timeout_secs=settings.llm_timeout_secs,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
            reasoning_effort=settings.openai_reasoning_effort,
        )

    if provider_name == "claude":
        return AnthropicProvider(
            api_key=_require(settings.anthropic_api_key, "ANTHROPIC_API_KEY", "claude"),
            model=_require(settings.anthropic_model, "ANTHROPIC_MODEL", "claude"),
            timeout_secs=settings.llm_timeout_secs,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )

    if provider_name == "gemini":
        return GeminiProvider(
            api_key=_require(settings.gemini_api_key, "GEMINI_API_KEY", "gemini"),
            model=_require(settings.gemini_model, "GEMINI_MODEL", "gemini"),
            timeout_secs=settings.llm_timeout_secs,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
        )

    raise ValueError(f"Provider '{provider_name}' is not implemented")


def get_provider(provider_name: str | None = None) -> LLMProvider:
    normalized = _normalize_provider_name(provider_name)
    return _build_provider(normalized)


def provider_health(provider_name: str) -> dict[str, Any]:
    normalized = _normalize_provider_name(provider_name)
    try:
        return _build_provider(normalized).health()
    except Exception as exc:  # noqa: BLE001
        return {
            "name": normalized,
            "ok": False,
            "model": "",
            "error": str(exc),
        }


def get_provider_health_map() -> list[dict[str, Any]]:
    return [provider_health(name) for name in available_providers()]
