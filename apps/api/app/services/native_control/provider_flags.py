from __future__ import annotations

from app.services.native_control.providers import canonical_provider


PROVIDER_ENFORCE_FLAGS = {
    "anthropic": "native_control_anthropic",
    "cursor": "native_control_cursor",
    "openai": "native_control_openai",
    "google": "native_control_google",
    "microsoft": "native_control_microsoft",
    "azure": "native_control_azure",
    "aws": "native_control_aws",
    "meta": "native_control_meta",
    "moonshot_kimi": "native_control_kimi",
    "alibaba_qwen": "native_control_qwen",
    "deepseek": "native_control_deepseek",
}


def provider_enforcement_enabled(settings_obj: object, provider: str) -> bool:
    flag = PROVIDER_ENFORCE_FLAGS.get(canonical_provider(provider))
    return bool(flag and getattr(settings_obj, flag, False))
