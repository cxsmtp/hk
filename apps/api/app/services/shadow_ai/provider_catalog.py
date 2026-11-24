from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from app.services.provider_catalog import list_catalog as list_canonical_catalog
from app.services.provider_catalog import resolve_provider


def _norm(value: str | None) -> str:
    return str(value or "").strip().lower()


def _extract_domain(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = parsed.netloc or parsed.path
        host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in host:
            host = host.split(":", 1)[0]
        host = host.lower().strip().strip(".")
        return host or None
    except Exception:
        return None


def _matches(pattern: str, domain: str) -> bool:
    normalized_pattern = _norm(pattern)
    normalized_domain = _norm(domain)
    if not normalized_pattern or not normalized_domain:
        return False
    if normalized_pattern.startswith("*."):
        suffix = normalized_pattern[1:]  # keep leading "."
        return normalized_domain.endswith(suffix)
    return normalized_domain == normalized_pattern


def _provider_label(name: str | None, provider_id: str | None = None) -> str | None:
    text = str(name or "").strip()
    if text and text.lower() != "unknown provider":
        return text.split(" ", 1)[0]
    pid = _norm(provider_id)
    if not pid:
        return None
    first = pid.split("_", 1)[0]
    return first.replace("-", " ").title()


def _fallback_key(signal: dict[str, Any], domain: str | None) -> str:
    for value in [
        signal.get("canonical_key"),
        signal.get("tool_name"),
        signal.get("app_name"),
        signal.get("provider"),
        signal.get("model_provider"),
        signal.get("model_name"),
        signal.get("api_endpoint"),
        signal.get("full_url"),
        signal.get("app_id"),
        domain,
    ]:
        candidate = _norm(str(value or ""))
        if candidate:
            return candidate
    return "unknown_ai_entity"


def match_domain(domain: str | None) -> dict[str, Any] | None:
    inferred = infer_from_signal({"domain": domain, "source_surface": "dns"})
    if not bool(inferred.get("catalog_match")):
        return None
    normalized = _extract_domain(domain)
    return {
        "matched_domain": normalized,
        "provider": inferred.get("provider"),
        "tool_name": inferred.get("tool_name"),
        "category": inferred.get("category"),
        "canonical_key": inferred.get("canonical_key"),
        "confidence_hint": inferred.get("confidence_hint"),
        "catalog_match": True,
    }


def infer_from_signal(signal: dict[str, Any]) -> dict[str, Any]:
    source_surface = str(signal.get("source_surface") or "").strip().lower() or None
    resolved = resolve_provider(signal, source_surface=source_surface)
    domain = _extract_domain(
        str(
            resolved.get("domain")
            or signal.get("domain")
            or signal.get("destination_domain")
            or signal.get("request_domain")
            or signal.get("queried_domain")
            or signal.get("api_endpoint")
            or signal.get("full_url")
            or signal.get("app_id")
            or ""
        )
    )
    provider_name = str(
        signal.get("provider")
        or signal.get("model_provider")
        or resolved.get("provider_name")
        or ""
    ).strip()
    provider_id = str(resolved.get("provider_id") or "").strip()
    provider = _provider_label(provider_name, provider_id) or provider_name or None
    tool_name = str(
        signal.get("tool_name")
        or signal.get("app_name")
        or resolved.get("canonical_tool_name")
        or provider_name
        or domain
        or "Unknown AI Tool"
    ).strip()
    tool_category = str(
        signal.get("tool_category")
        or signal.get("app_category")
        or resolved.get("provider_type")
        or "unknown"
    ).strip()
    catalog_match = bool(resolved.get("catalog_match"))
    matched_on = [str(item).strip() for item in (resolved.get("matched_on") or []) if str(item).strip()]
    confidence_hint = str(resolved.get("confidence_hint") or "low").strip() or "low"
    strong_match_reasons = {"domain_match", "api_endpoint_match", "process_match", "tool_match"}
    strong_catalog_identity = (
        catalog_match
        and provider_id
        and provider_id != "unknown_provider"
        and (
            confidence_hint in {"high", "medium"}
            and any(reason in strong_match_reasons for reason in matched_on)
        )
    )
    canonical_key = (
        provider_id
        if strong_catalog_identity
        else _fallback_key(signal, domain)
    )
    return {
        "domain": domain,
        "provider": provider,
        "provider_id": provider_id or None,
        "provider_name": str(resolved.get("provider_name") or provider_name or "").strip() or None,
        "provider_type": str(resolved.get("provider_type") or tool_category or "").strip() or None,
        "tool_name": tool_name or None,
        "tool_category": tool_category or None,
        "category": tool_category or None,
        "canonical_key": canonical_key,
        "confidence_hint": confidence_hint,
        "catalog_match": catalog_match,
        "normalized_model_family": str(resolved.get("normalized_model_family") or "").strip() or None,
        "default_risk_hint": str(resolved.get("default_risk_hint") or "").strip() or None,
        "trust_level": str(resolved.get("trust_level") or "").strip() or None,
        "source_surface": str(resolved.get("source_surface") or source_surface or "").strip() or None,
        "matched_on": matched_on,
    }


def canonical_tool_key(signal: dict[str, Any]) -> str:
    inferred = infer_from_signal(signal)
    key = str(inferred.get("canonical_key") or "").strip().lower()
    if key:
        return key
    for value in [
        signal.get("tool_name"),
        signal.get("domain"),
        signal.get("provider"),
        signal.get("model_name"),
        signal.get("api_endpoint"),
        signal.get("app_id"),
    ]:
        text = _norm(str(value or ""))
        if text:
            return text
    return "unknown_ai_entity"


def list_catalog() -> list[dict[str, Any]]:
    rows = list_canonical_catalog()
    out: list[dict[str, Any]] = []
    for row in rows:
        known_domains = [str(item) for item in (row.get("known_domains") or []) if str(item).strip()]
        known_tools = [str(item) for item in (row.get("known_tool_names") or []) if str(item).strip()]
        provider_id = str(row.get("provider_id") or "").strip()
        canonical_name = str(row.get("canonical_name") or "").strip()
        provider = _provider_label(canonical_name, provider_id) or canonical_name
        provider_type = str(row.get("provider_type") or "").strip() or "unknown"
        trust_level = str(row.get("trust_level") or "").strip().lower()
        out.append(
            {
                # Backward-compatible shadow catalog shape.
                "pattern": known_domains[0] if known_domains else "",
                "provider": provider,
                "tool_name": known_tools[0] if known_tools else canonical_name,
                "category": provider_type,
                "canonical_key": provider_id or "unknown_provider",
                "confidence_hint": "high" if trust_level == "trusted" else "medium",
                # Canonical catalog fields.
                "provider_id": provider_id or "unknown_provider",
                "canonical_name": canonical_name,
                "provider_type": provider_type,
                "deployment_surfaces": list(row.get("deployment_surfaces") or []),
                "known_domains": known_domains,
                "known_api_endpoints": list(row.get("known_api_endpoints") or []),
                "known_process_names": list(row.get("known_process_names") or []),
                "known_model_names": list(row.get("known_model_names") or []),
                "known_tool_names": known_tools,
                "aliases": list(row.get("aliases") or []),
                "trust_level": str(row.get("trust_level") or "").strip() or None,
                "default_risk_hint": str(row.get("default_risk_hint") or "").strip() or None,
            }
        )
    return out
