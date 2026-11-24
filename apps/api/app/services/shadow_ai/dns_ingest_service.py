from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.observability import log_structured
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.runtime_intelligence.runtime_event_normalizer import ingest_runtime_event
from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload
from app.services.shadow_ai.confidence_scoring import score_shadow_confidence
from app.services.shadow_ai.provider_catalog import infer_from_signal


@dataclass
class DNSIngestResult:
    source_signal_id: str
    runtime_event_id: str | None
    shadow_ai_entity_id: str | None
    finding_id: str | None
    confidence_level: str
    promoted_to_runtime: bool


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    raw = str(value or "").strip()
    if raw:
        try:
            out = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return out if out.tzinfo else out.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def ingest_dns_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    actor_user_id: str | None,
) -> DNSIngestResult:
    observed_at = _parse_ts(payload.get("query_time"))
    correlation_id = str(payload.get("correlation_id") or "").strip() or str(uuid4())
    source_event_id = str(payload.get("source_event_id") or f"dns:{uuid4()}").strip()
    query_count = max(1, _to_int(payload.get("query_count"), 1))

    inferred = infer_from_signal(
        {
            "queried_domain": payload.get("queried_domain"),
            "provider": payload.get("provider"),
            "tool_name": payload.get("tool_name"),
            "api_endpoint": payload.get("api_endpoint"),
            "full_url": payload.get("full_url"),
        }
    )
    domain = str(inferred.get("domain") or payload.get("queried_domain") or "").strip() or None

    signal = ShadowAISignal(
        tenant_id=tenant_id,
        shadow_ai_entity_id=None,
        source_surface="dns",
        source_event_id=source_event_id,
        domain=domain,
        provider=str(inferred.get("provider") or payload.get("provider") or "").strip() or None,
        model_name=str(payload.get("model_name") or "").strip() or None,
        tool_name=str(inferred.get("tool_name") or payload.get("tool_name") or domain or "").strip() or None,
        api_endpoint=str(payload.get("api_endpoint") or "").strip() or None,
        user_id=str(payload.get("user_id") or "").strip() or None,
        agent_id=str(payload.get("agent_id") or "").strip() or None,
        confidence_signal={
            "source_surface": "dns",
            "catalog_match": bool(inferred.get("catalog_match")),
            "confidence_hint": inferred.get("confidence_hint"),
            "query_count": query_count,
        },
        raw_fingerprint={
            "queried_domain": payload.get("queried_domain"),
            "resolved_ip": payload.get("resolved_ip"),
            "source_system": payload.get("source_system"),
            "host_id": payload.get("host_id"),
            "query_time": observed_at.isoformat(),
            "query_count": query_count,
        },
    )
    db.add(signal)
    db.flush()

    source_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_source_signal",
        signal_type="shadow_ai.dns.signal",
        label=f"DNS AI signal {domain or signal.id}",
        payload={
            "shadow_ai_signal_id": signal.id,
            "source_surface": "dns",
            "queried_domain": payload.get("queried_domain"),
            "resolved_ip": payload.get("resolved_ip"),
            "query_count": query_count,
            "source_system": payload.get("source_system"),
            "host_id": payload.get("host_id"),
        },
        correlation_id=correlation_id,
    )

    same_domain_count = len(
        db.scalars(
            select(ShadowAISignal).where(
                ShadowAISignal.tenant_id == tenant_id,
                ShadowAISignal.source_surface == "dns",
                ShadowAISignal.domain == domain,
            )
        ).all()
    )

    catalog_match = bool(inferred.get("catalog_match"))
    strong_catalog = catalog_match and str(inferred.get("confidence_hint") or "").lower() in {"high", "medium"}
    has_attribution = bool(str(payload.get("user_id") or "").strip() or str(payload.get("host_id") or "").strip())
    promote_to_runtime = bool(payload.get("force_runtime")) or same_domain_count >= 3 or (strong_catalog and query_count >= 2) or (
        strong_catalog and has_attribution and query_count >= 1
    )

    runtime_event_id: str | None = None
    shadow_ai_entity_id: str | None = None
    finding_id: str | None = None
    confidence_level = "low" if not promote_to_runtime else "medium"

    if promote_to_runtime:
        try:
            runtime_event = ingest_runtime_event(
                db,
                payload=RuntimeEventIngestPayload(
                    tenant_id=tenant_id,
                    source_surface="dns",
                    event_type="shadow_ai.dns_discovered",
                    ai_system_id=str(payload.get("ai_system_id") or "").strip() or None,
                    app_id=domain,
                    user_id=str(payload.get("user_id") or "").strip() or None,
                    agent_id=str(payload.get("agent_id") or "").strip() or None,
                    risk_tier=None,
                    policy_version_id=None,
                    governance_version=None,
                    severity=str(payload.get("severity") or "med"),
                    confidence_tier=None,
                    evidence_node_ids=[source_node.id],
                    correlation_id=correlation_id,
                    model_provider=str(payload.get("model_provider") or inferred.get("provider") or "").strip() or None,
                    provider=str(inferred.get("provider") or payload.get("provider") or "").strip() or None,
                    model_name=str(payload.get("model_name") or "").strip() or None,
                    tool_name=str(inferred.get("tool_name") or payload.get("tool_name") or domain or "").strip() or None,
                    tool_category=str(inferred.get("tool_category") or "dns_observation").strip() or None,
                    api_endpoint=str(payload.get("api_endpoint") or "").strip() or None,
                    data_source="dns",
                    response_size=None,
                    chain_depth=None,
                    parent_agent_id=None,
                    metadata={
                        "source_surface": "dns",
                        "risk_category": "shadow_ai",
                        "governance_state": "unknown",
                        "domain": domain,
                        "queried_domain": payload.get("queried_domain"),
                        "resolved_ip": payload.get("resolved_ip"),
                        "source_system": payload.get("source_system"),
                        "host_id": payload.get("host_id"),
                        "query_count": query_count,
                        "catalog_match": catalog_match,
                        "confidence_hint": inferred.get("confidence_hint"),
                        "timestamp": observed_at.isoformat(),
                    },
                ),
            )
            if runtime_event is not None:
                runtime_event_id = runtime_event.event_id
                metadata = dict(runtime_event.metadata_json or {})
                shadow_ai_entity_id = str(metadata.get("shadow_ai_entity_id") or "").strip() or None
                finding_id = str(metadata.get("shadow_ai_finding_id") or "").strip() or None
                confidence_level = str(metadata.get("shadow_ai_confidence_level") or confidence_level)
                if shadow_ai_entity_id:
                    signal.shadow_ai_entity_id = shadow_ai_entity_id
                    unresolved = db.scalars(
                        select(ShadowAISignal).where(
                            ShadowAISignal.tenant_id == tenant_id,
                            ShadowAISignal.source_surface == "dns",
                            ShadowAISignal.domain == domain,
                            ShadowAISignal.shadow_ai_entity_id.is_(None),
                        )
                    ).all()
                    for row in unresolved:
                        row.shadow_ai_entity_id = shadow_ai_entity_id
                    db.flush()
                    entity = db.scalar(
                        select(ShadowAIEntity).where(
                            ShadowAIEntity.tenant_id == tenant_id,
                            ShadowAIEntity.id == shadow_ai_entity_id,
                        )
                    )
                    if entity is not None:
                        score = score_shadow_confidence(
                            db,
                            tenant_id=tenant_id,
                            shadow_ai_entity_id=shadow_ai_entity_id,
                        )
                        entity.confidence_score = score.confidence_score
                        metadata_json = dict(entity.metadata_json or {})
                        metadata_json["confidence_reasoning"] = score.confidence_reasoning
                        entity.metadata_json = metadata_json
                        db.flush()
                        confidence_level = score.confidence_level
        except Exception as exc:  # pragma: no cover - defensive non-blocking guard
            if isinstance(exc, CanonicalProjectionError):
                raise
            log_structured(
                "shadow_ai_dns_runtime_ingest_failed",
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                source_signal_id=signal.id,
                error=str(exc),
            )

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="system" if actor_user_id is None else "human",
        action="shadow_ai.dns.ingest",
        resource_type="shadow_ai_signal",
        resource_id=signal.id,
        payload={
            "runtime_event_id": runtime_event_id,
            "shadow_ai_entity_id": shadow_ai_entity_id,
            "finding_id": finding_id,
            "promoted_to_runtime": promote_to_runtime,
            "same_domain_count": same_domain_count,
        },
        correlation_id=correlation_id,
    )

    return DNSIngestResult(
        source_signal_id=signal.id,
        runtime_event_id=runtime_event_id,
        shadow_ai_entity_id=shadow_ai_entity_id,
        finding_id=finding_id,
        confidence_level=confidence_level,
        promoted_to_runtime=promote_to_runtime,
    )
