from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.shadow_ai import ShadowAISignal


@dataclass
class ConfidenceScoreResult:
    confidence_score: float
    confidence_level: str
    confidence_reasoning: list[str]


def _normalize_text(value: str | None) -> str:
    return str(value or "").strip().lower()


def score_shadow_confidence(
    db: Session,
    *,
    tenant_id: str,
    shadow_ai_entity_id: str,
) -> ConfidenceScoreResult:
    signals = db.scalars(
        select(ShadowAISignal).where(
            ShadowAISignal.tenant_id == tenant_id,
            ShadowAISignal.shadow_ai_entity_id == shadow_ai_entity_id,
        )
    ).all()

    if not signals:
        return ConfidenceScoreResult(
            confidence_score=0.1,
            confidence_level="low",
            confidence_reasoning=["no_attributed_signals"],
        )

    signal_count = len(signals)
    surfaces = sorted(
        {
            _normalize_text(row.source_surface)
            for row in signals
            if _normalize_text(row.source_surface)
        }
    )
    providers = sorted(
        {
            _normalize_text(row.provider)
            for row in signals
            if _normalize_text(row.provider)
        }
    )
    domains = sorted(
        {
            _normalize_text(row.domain)
            for row in signals
            if _normalize_text(row.domain)
        }
    )
    tools = sorted(
        {
            _normalize_text(row.tool_name)
            for row in signals
            if _normalize_text(row.tool_name)
        }
    )
    has_user_attribution = any(_normalize_text(row.user_id) for row in signals)
    has_host_attribution = any(_normalize_text((row.raw_fingerprint or {}).get("host_id")) for row in signals if isinstance(row.raw_fingerprint, dict))
    has_process_attribution = any(_normalize_text((row.raw_fingerprint or {}).get("process_name")) for row in signals if isinstance(row.raw_fingerprint, dict))
    has_model_or_provider = any(_normalize_text(row.model_name) or _normalize_text(row.provider) for row in signals)
    connector_confirmation = any(
        bool((row.confidence_signal or {}).get("connector_confirmed"))
        for row in signals
        if isinstance(row.confidence_signal, dict)
    )
    catalog_confirmed = any(
        bool((row.confidence_signal or {}).get("catalog_match"))
        for row in signals
        if isinstance(row.confidence_signal, dict)
    )
    endpoint_dns_proxy = {"endpoint", "dns", "proxy"}
    network_surface_count = len(endpoint_dns_proxy.intersection(set(surfaces)))

    score = 0.10
    reasons: list[str] = []

    if signal_count >= 2:
        score += 0.15
        reasons.append(f"same_entity_observed_{signal_count}_times")
    if signal_count >= 5:
        score += 0.10
        reasons.append("repeated_observation_over_threshold")

    if len(surfaces) >= 2:
        score += 0.25
        reasons.append(f"seen_across_{len(surfaces)}_surfaces")
    elif len(surfaces) == 1:
        score += 0.08
        reasons.append("single_surface_observation")

    consistency_signals = 0
    if len(providers) <= 1 and providers:
        consistency_signals += 1
    if len(domains) <= 1 and domains:
        consistency_signals += 1
    if len(tools) <= 1 and tools:
        consistency_signals += 1
    if consistency_signals >= 2:
        score += 0.18
        reasons.append("consistent_provider_domain_tool")
    elif consistency_signals == 1:
        score += 0.10
        reasons.append("partially_consistent_identity_metadata")

    if has_user_attribution:
        score += 0.08
        reasons.append("user_attribution_present")
    if has_host_attribution:
        score += 0.05
        reasons.append("host_attribution_present")
    if has_process_attribution:
        score += 0.05
        reasons.append("process_attribution_present")
    if has_model_or_provider:
        score += 0.08
        reasons.append("provider_or_model_metadata_present")
    if network_surface_count >= 2:
        score += 0.14
        reasons.append("network_surface_agreement")
    if catalog_confirmed:
        score += 0.10
        reasons.append("provider_catalog_match")
    if connector_confirmation:
        score += 0.12
        reasons.append("sanctioned_connector_confirmation")

    if set(surfaces) == {"dns"} and signal_count <= 1:
        score = min(score, 0.35)
        reasons.append("single_dns_signal_low_confidence")

    bounded_score = round(max(0.0, min(score, 0.99)), 2)
    if bounded_score >= 0.8:
        level = "high"
    elif bounded_score >= 0.5:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("insufficient_signal_quality")

    return ConfidenceScoreResult(
        confidence_score=bounded_score,
        confidence_level=level,
        confidence_reasoning=reasons,
    )
