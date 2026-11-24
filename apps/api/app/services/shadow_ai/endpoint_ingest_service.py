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
class EndpointIngestResult:
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


def ingest_endpoint_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    actor_user_id: str | None,
) -> EndpointIngestResult:
    inferred = infer_from_signal(payload)
    observed_at = _parse_ts(payload.get("timestamp"))
    correlation_id = str(payload.get("correlation_id") or "").strip() or str(uuid4())
    source_event_id = str(payload.get("source_event_id") or f"endpoint:{uuid4()}").strip()

    source_signal = ShadowAISignal(
        tenant_id=tenant_id,
        shadow_ai_entity_id=None,
        source_surface="endpoint",
        source_event_id=source_event_id,
        domain=str(inferred.get("domain") or payload.get("destination_domain") or "").strip() or None,
        provider=str(inferred.get("provider") or payload.get("provider") or payload.get("model_provider") or "").strip() or None,
        model_name=str(payload.get("model_name") or "").strip() or None,
        tool_name=str(inferred.get("tool_name") or payload.get("process_name") or payload.get("tool_name") or "").strip() or None,
        api_endpoint=str(payload.get("api_endpoint") or "").strip() or None,
        user_id=str(payload.get("user_id") or "").strip() or None,
        agent_id=str(payload.get("agent_id") or "").strip() or None,
        confidence_signal={
            "source_surface": "endpoint",
            "catalog_match": bool(inferred.get("catalog_match")),
            "confidence_hint": inferred.get("confidence_hint"),
            "host_id": str(payload.get("host_id") or "").strip() or None,
        },
        raw_fingerprint={
            "process_name": str(payload.get("process_name") or "").strip() or None,
            "executable_path": str(payload.get("executable_path") or "").strip() or None,
            "command_line": str(payload.get("command_line") or "").strip() or None,
            "destination_domain": str(payload.get("destination_domain") or "").strip() or None,
            "destination_ip": str(payload.get("destination_ip") or "").strip() or None,
            "host_id": str(payload.get("host_id") or "").strip() or None,
            "bytes_sent": payload.get("bytes_sent"),
            "bytes_received": payload.get("bytes_received"),
            "timestamp": observed_at.isoformat(),
        },
    )
    db.add(source_signal)
    db.flush()

    source_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_source_signal",
        signal_type="shadow_ai.endpoint.signal",
        label=f"Endpoint AI signal {source_signal.tool_name or source_signal.domain or source_signal.id}",
        payload={
            "shadow_ai_signal_id": source_signal.id,
            "source_surface": "endpoint",
            "process_name": payload.get("process_name"),
            "host_id": payload.get("host_id"),
            "destination_domain": payload.get("destination_domain"),
            "destination_ip": payload.get("destination_ip"),
        },
        correlation_id=correlation_id,
    )

    runtime_event_id: str | None = None
    shadow_ai_entity_id: str | None = None
    finding_id: str | None = None
    confidence_level = str(inferred.get("confidence_hint") or "low")

    try:
        runtime_event = ingest_runtime_event(
            db,
            payload=RuntimeEventIngestPayload(
                tenant_id=tenant_id,
                source_surface="endpoint",
                event_type="shadow_ai.endpoint_discovered",
                ai_system_id=str(payload.get("ai_system_id") or "").strip() or None,
                app_id=str(inferred.get("domain") or payload.get("destination_domain") or "").strip() or None,
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
                tool_name=str(inferred.get("tool_name") or payload.get("process_name") or "").strip() or None,
                tool_category=str(inferred.get("tool_category") or payload.get("tool_category") or "endpoint_process").strip() or None,
                api_endpoint=str(payload.get("api_endpoint") or "").strip() or None,
                data_source="endpoint",
                response_size=None,
                chain_depth=None,
                parent_agent_id=None,
                metadata={
                    "source_surface": "endpoint",
                    "risk_category": "shadow_ai",
                    "governance_state": "unknown",
                    "domain": inferred.get("domain") or payload.get("destination_domain"),
                    "destination_domain": payload.get("destination_domain"),
                    "destination_ip": payload.get("destination_ip"),
                    "process_name": payload.get("process_name"),
                    "executable_path": payload.get("executable_path"),
                    "command_line": payload.get("command_line"),
                    "host_id": payload.get("host_id"),
                    "host_sensitivity": payload.get("host_sensitivity"),
                    "bytes_sent": payload.get("bytes_sent"),
                    "bytes_received": payload.get("bytes_received"),
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
                source_signal.shadow_ai_entity_id = shadow_ai_entity_id
                db.flush()
    except Exception as exc:  # pragma: no cover - endpoint ingest remains non-blocking to platform enforcement
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "shadow_ai_endpoint_runtime_ingest_failed",
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            source_signal_id=source_signal.id,
            error=str(exc),
        )

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="system" if actor_user_id is None else "human",
        action="shadow_ai.endpoint.ingest",
        resource_type="shadow_ai_signal",
        resource_id=source_signal.id,
        payload={
            "runtime_event_id": runtime_event_id,
            "shadow_ai_entity_id": shadow_ai_entity_id,
            "finding_id": finding_id,
            "source_surface": "endpoint",
        },
        correlation_id=correlation_id,
    )

    return EndpointIngestResult(
        source_signal_id=source_signal.id,
        runtime_event_id=runtime_event_id,
        shadow_ai_entity_id=shadow_ai_entity_id,
        finding_id=finding_id,
        confidence_level=confidence_level,
    )
