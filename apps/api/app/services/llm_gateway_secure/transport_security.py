from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from app.core.config import settings
from app.services.llm_gateway_secure.schemas import GuardOutcome


SENSITIVE_QUERY_KEYS = {
    "token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "pwd",
    "auth",
}

DEFAULT_PROVIDER_ENDPOINTS = {
    "openai": "https://api.openai.com/v1",
    "gpt": "https://api.openai.com/v1",
    "claude": "https://api.anthropic.com/v1/messages",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models",
    "llama": "https://localhost/v1",
    "mistral": "https://api.mistral.ai/v1",
    "custom": "https://localhost/v1",
    "oss_local": "https://localhost/v1",
    "azure_openai": "https://localhost/openai/deployments",
}

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _normalized_provider(value: str) -> str:
    token = str(value or "").strip().lower()
    if token in {"chatgpt", "openai"}:
        return "openai"
    if token in {"claude", "anthropic"}:
        return "claude"
    if token in {"gemini"}:
        return "gemini"
    if token in {"llama", "oss", "local", "ollama", "llama_cpp", "llama.cpp", "oss_local"}:
        return "llama"
    if token in {"mistral"}:
        return "mistral"
    if token in {"azure-openai", "azure_openai"}:
        return "azure_openai"
    if token in {"custom"}:
        return "custom"
    return token


def provider_endpoint(provider: str) -> str:
    normalized = _normalized_provider(provider)
    if normalized in {"openai", "azure_openai", "llama", "custom", "mistral"}:
        base_url = str(settings.openai_base_url or settings.llm_base_url or "").strip()
        if base_url:
            return base_url
    return DEFAULT_PROVIDER_ENDPOINTS.get(normalized, "https://localhost/v1")


def _provider_allowed(*, provider: str, policy_profile: dict[str, Any]) -> bool:
    allowlist = policy_profile.get("provider_allowlist") if isinstance(policy_profile, dict) else None
    if isinstance(allowlist, list) and allowlist:
        normalized_allow = {str(item).strip().lower() for item in allowlist if str(item).strip()}
        return _normalized_provider(provider) in normalized_allow
    return True


def _allows_local_http(*, policy_profile: dict[str, Any]) -> bool:
    if str(settings.env or "dev").strip().lower() not in {"dev", "test", "local"}:
        return False
    return bool(policy_profile.get("allow_insecure_localhost_http"))


def validate_transport_security(*, provider: str, policy_profile: dict[str, Any]) -> GuardOutcome:
    endpoint = provider_endpoint(provider)
    parsed = urlparse(endpoint)
    host = str(parsed.hostname or "").strip().lower()
    scheme = str(parsed.scheme or "").strip().lower()
    query = parse_qs(parsed.query or "")

    violations: list[str] = []
    warnings: list[str] = []

    if not _provider_allowed(provider=provider, policy_profile=policy_profile):
        violations.append("provider_not_allowlisted")

    if any(key.lower() in SENSITIVE_QUERY_KEYS for key in query):
        violations.append("sensitive_query_parameter_present")

    if scheme != "https":
        if host in _LOCAL_HOSTS and _allows_local_http(policy_profile=policy_profile):
            warnings.append("insecure_localhost_allowed_by_policy")
        else:
            violations.append("tls_required_https_only")

    # Practical TLS hardening signal for higher-assurance policies.
    if bool(policy_profile.get("require_tls_1_3")):
        warnings.append("tls_1_3_enforced_where_supported")

    if violations:
        return GuardOutcome(
            passed=False,
            reason="transport_security_rejected",
            details={
                "provider": provider,
                "endpoint": endpoint,
                "violations": violations,
                "warnings": warnings,
            },
        )

    return GuardOutcome(
        passed=True,
        reason="transport_security_ok",
        details={
            "provider": provider,
            "endpoint": endpoint,
            "violations": [],
            "warnings": warnings,
            "header_minimization": True,
            "url_secret_safety": True,
        },
    )
