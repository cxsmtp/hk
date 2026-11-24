from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.observability import log_structured
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.db.models.shadow_ai import ShadowAISignal
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.runtime_intelligence.runtime_event_normalizer import ingest_runtime_event
from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload
from app.services.shadow_ai.provider_catalog import infer_from_signal


@dataclass
class ProxyIngestResult:
    source_signal_id: str
    runtime_event_id: str | None
    shadow_ai_entity_id: str | None
    finding_id: str | None
    confidence_level: str


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


def ingest_proxy_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    actor_user_id: str | None,
) -> ProxyIngestResult:
    observed_at = _parse_ts(payload.get("timestamp"))
    correlation_id = str(payload.get("correlation_id") or "").strip() or str(uuid4())
    source_event_id = str(payload.get("source_event_id") or f"proxy:{uuid4()}").strip()
    inferred = infer_from_signal(
        {
            "request_domain": payload.get("request_domain"),
            "full_url": payload.get("full_url"),
            "provider": payload.get("provider"),
            "tool_name": payload.get("tool_name"),
            "api_endpoint": payload.get("api_endpoint") or payload.get("full_url"),
            "app_name": payload.get("app_category"),
        }
    )

    signal = ShadowAISignal(
        tenant_id=tenant_id,
        shadow_ai_entity_id=None,
        source_surface="proxy",
        source_event_id=source_event_id,
        domain=str(inferred.get("domain") or payload.get("request_domain") or "").strip() or None,
        provider=str(inferred.get("provider") or payload.get("provider") or "").strip() or None,
        model_name=str(payload.get("model_name") or "").strip() or None,
        tool_name=str(inferred.get("tool_name") or payload.get("tool_name") or payload.get("app_category") or "").strip() or None,
        api_endpoint=str(payload.get("full_url") or payload.get("api_endpoint") or "").strip() or None,
        user_id=str(payload.get("user_id") or "").strip() or None,
        agent_id=str(payload.get("agent_id") or "").strip() or None,
        confidence_signal={
            "source_surface": "proxy",
            "catalog_match": bool(inferred.get("catalog_match")),
            "confidence_hint": inferred.get("confidence_hint"),
            "response_code": payload.get("response_code"),
        },
        raw_fingerprint={
            "request_domain": payload.get("request_domain"),
            "full_url": payload.get("full_url"),
            "method": payload.get("method"),
            "response_code": payload.get("response_code"),
            "bytes_sent": payload.get("bytes_sent"),
            "bytes_received": payload.get("bytes_received"),
            "host_id": payload.get("host_id"),
            "app_category": payload.get("app_category"),
            "timestamp": observed_at.isoformat(),
        },
    )
    db.add(signal)
    db.flush()

    source_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_source_signal",
        signal_type="shadow_ai.proxy.signal",
        label=f"Proxy AI signal {signal.tool_name or signal.domain or signal.id}",
        payload={
            "shadow_ai_signal_id": signal.id,
            "source_surface": "proxy",
            "request_domain": payload.get("request_domain"),
            "full_url": payload.get("full_url"),
            "response_code": payload.get("response_code"),
            "bytes_sent": payload.get("bytes_sent"),
            "bytes_received": payload.get("bytes_received"),
        },
        correlation_id=correlation_id,
    )

    runtime_event_id: str | None = None
    shadow_ai_entity_id: str | None = None
    finding_id: str | None = None
    confidence_level = str(inferred.get("confidence_hint") or "medium")

    try:
        runtime_event = ingest_runtime_event(
            db,
            payload=RuntimeEventIngestPayload(
                tenant_id=tenant_id,
                source_surface="proxy",
                event_type="shadow_ai.proxy_discovered",
                ai_system_id=str(payload.get("ai_system_id") or "").strip() or None,
                app_id=str(inferred.get("domain") or payload.get("request_domain") or "").strip() or None,
                user_id=str(payload.get("user_id") or "").strip() or None,
                agent_id=str(payload.get("agent_id") or "").strip() or None,
                risk_tier=None,
                policy_version_id=None,
                governance_version=None,
                severity=str(payload.get("severity") or "high"),
                confidence_tier=None,
                evidence_node_ids=[source_node.id],
                correlation_id=correlation_id,
                model_provider=str(payload.get("model_provider") or inferred.get("provider") or "").strip() or None,
                provider=str(inferred.get("provider") or payload.get("provider") or "").strip() or None,
                model_name=str(payload.get("model_name") or "").strip() or None,
                tool_name=str(inferred.get("tool_name") or payload.get("tool_name") or payload.get("app_category") or "").strip() or None,
                tool_category=str(inferred.get("tool_category") or payload.get("app_category") or "proxy_traffic").strip() or None,
                api_endpoint=str(payload.get("full_url") or payload.get("api_endpoint") or "").strip() or None,
                data_source="proxy",
                response_size=None,
                chain_depth=None,
                parent_agent_id=None,
                metadata={
                    "source_surface": "proxy",
                    "risk_category": "shadow_ai",
                    "governance_state": "unknown",
                    "domain": inferred.get("domain") or payload.get("request_domain"),
                    "request_domain": payload.get("request_domain"),
                    "full_url": payload.get("full_url"),
                    "method": payload.get("method"),
                    "response_code": payload.get("response_code"),
                    "bytes_sent": payload.get("bytes_sent"),
                    "bytes_received": payload.get("bytes_received"),
                    "host_id": payload.get("host_id"),
                    "app_category": payload.get("app_category"),
                    "catalog_match": bool(inferred.get("catalog_match")),
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
                db.flush()
    except Exception as exc:  # pragma: no cover - defensive non-blocking guard
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "shadow_ai_proxy_runtime_ingest_failed",
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
        action="shadow_ai.proxy.ingest",
        resource_type="shadow_ai_signal",
        resource_id=signal.id,
        payload={
            "runtime_event_id": runtime_event_id,
            "shadow_ai_entity_id": shadow_ai_entity_id,
            "finding_id": finding_id,
            "source_surface": "proxy",
        },
        correlation_id=correlation_id,
    )

    return ProxyIngestResult(
        source_signal_id=signal.id,
        runtime_event_id=runtime_event_id,
        shadow_ai_entity_id=shadow_ai_entity_id,
        finding_id=finding_id,
        confidence_level=confidence_level,
    )
