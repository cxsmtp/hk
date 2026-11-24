from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.observability import log_structured
from app.db.models.activity_audit import AISession, DeploymentEndpoint
from app.db.models.ai_system import AISystem
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal, ShadowAIUsage
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.findings_service import generate_shadow_ai_entity_finding
from app.services.shadow_ai.confidence_scoring import score_shadow_confidence
from app.services.shadow_ai.identity_resolution_service import resolve_identity
from app.services.shadow_ai.reconciliation_service import reconcile_to_trust_center_candidate
from app.services.shadow_ai.risk_assignment import assign_provisional_risk, is_risk_escalation


ALLOWED_SIGNAL_SURFACES = {"browser", "gateway", "connector", "aiiam", "monitoring", "endpoint", "dns", "proxy"}
IGNORED_EVENT_TYPES = {"extension_health_status"}
SHADOW_EVENT_HINTS = {"unknown", "shadow", "discovery", "unsanctioned", "unregistered"}
APPROVED_GOVERNANCE_STATES = {"approved", "active", "live"}
RISK_TO_SEVERITY = {"LOW": "low", "MEDIUM": "med", "HIGH": "high", "CRITICAL": "critical"}
APPROVED_STATUSES = {"approved", "active", "live"}


@dataclass
class ShadowDiscoveryResult:
    entity_id: str
    signal_id: str
    finding_id: str | None
    ai_system_id: str | None
    confidence_score: float
    confidence_level: str
    risk_tier: str


def _norm(value: str | None) -> str:
    return str(value or "").strip().lower()


def _safe_max_dt(left: datetime, right: datetime) -> datetime:
    left_utc = left if left.tzinfo else left.replace(tzinfo=timezone.utc)
    right_utc = right if right.tzinfo else right.replace(tzinfo=timezone.utc)
    return left_utc if left_utc >= right_utc else right_utc


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


def _configured_hawk_hosts() -> set[str]:
    hosts = {"localhost", "127.0.0.1", "::1"}
    for key in ("API_BASE_URL", "WEB_ORIGIN", "FRONTEND_URL"):
        host = _extract_domain(os.getenv(key))
        if host:
            hosts.add(host)
    for origin in str(os.getenv("CORS_ORIGINS") or "").split(","):
        host = _extract_domain(origin)
        if host:
            hosts.add(host)
    return hosts


def _is_hawk_internal_signal(event: RuntimeEvent, metadata: dict[str, Any]) -> bool:
    candidates = [
        metadata.get("domain"),
        metadata.get("destination_domain"),
        metadata.get("request_domain"),
        metadata.get("queried_domain"),
        metadata.get("api_endpoint"),
        metadata.get("url"),
        metadata.get("page_url"),
        event.app_id,
    ]
    domains = {_extract_domain(str(item)) for item in candidates if str(item or "").strip()}
    domains.discard(None)
    if domains & _configured_hawk_hosts():
        return True
    for item in candidates:
        raw = str(item or "").strip().lower()
        if raw.startswith(("chrome-extension://", "moz-extension://", "edge-extension://")):
            return True
    return False


def _event_metadata(event: RuntimeEvent) -> dict[str, Any]:
    return dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}


def _signal_surface_for_event(event: RuntimeEvent, metadata: dict[str, Any]) -> str:
    source = _norm(event.source_surface)
    if source in ALLOWED_SIGNAL_SURFACES:
        return source
    source_hint = _norm(metadata.get("source_surface"))
    if source_hint in ALLOWED_SIGNAL_SURFACES:
        return source_hint
    event_type = _norm(event.event_type)
    if event_type.startswith("shadow_ai.") or event_type.startswith("monitoring."):
        return "monitoring"
    return "connector"


def _is_shadow_candidate(event: RuntimeEvent, metadata: dict[str, Any]) -> bool:
    event_type = _norm(event.event_type)
    if event_type in IGNORED_EVENT_TYPES:
        return False
    if _is_hawk_internal_signal(event, metadata):
        return False

    if any(hint in event_type for hint in SHADOW_EVENT_HINTS):
        return True

    if _norm(metadata.get("risk_category")) == "shadow_ai":
        return True

    governance_state = _norm(metadata.get("governance_state"))
    if governance_state and governance_state not in APPROVED_GOVERNANCE_STATES:
        return True

    if event.ai_system_id is None:
        signal_fields = [
            metadata.get("provider"),
            metadata.get("model_provider"),
            metadata.get("tool_name"),
            metadata.get("api_endpoint"),
            metadata.get("domain"),
            event.app_id,
        ]
        if any(str(item or "").strip() for item in signal_fields):
            return True

    return False


def _build_signal_payload(event: RuntimeEvent, metadata: dict[str, Any]) -> dict[str, Any]:
    domain = (
        _extract_domain(metadata.get("domain"))
        or _extract_domain(metadata.get("destination_domain"))
        or _extract_domain(metadata.get("request_domain"))
        or _extract_domain(metadata.get("queried_domain"))
        or _extract_domain(event.app_id)
        or _extract_domain(metadata.get("api_endpoint"))
    )
    tool_name = (
        str(
            metadata.get("tool_name")
            or metadata.get("process_name")
            or metadata.get("app_name")
            or event.app_id
            or ""
        ).strip()
        or None
    )
    provider = str(metadata.get("provider") or metadata.get("model_provider") or "").strip() or None
    model_name = str(metadata.get("model_name") or "").strip() or None
    api_endpoint = str(metadata.get("api_endpoint") or "").strip() or None
    profile = dict(metadata.get("agent_runtime_profile") or {}) if isinstance(metadata.get("agent_runtime_profile"), dict) else {}
    return {
        "domain": domain,
        "provider": provider,
        "model_name": model_name,
        "tool_name": tool_name,
        "api_endpoint": api_endpoint,
        "deployment_type": str(metadata.get("deployment_type") or "").strip() or None,
        "ai_type": str(metadata.get("ai_type") or "").strip() or None,
        "app_id": event.app_id,
        "canonical_key": str(profile.get("agent_id") or metadata.get("agent_id") or "").strip() or None,
        "agent_runtime_id": str(profile.get("agent_id") or metadata.get("agent_id") or "").strip() or None,
    }


def _select_shadow_finding_type(
    *,
    source_surface: str,
    entity_created: bool,
    risk_escalation: bool,
    repeated_count: int,
    confidence_level: str,
    event_type: str,
    api_endpoint: str | None,
    provider_type: str | None,
    provider_id: str | None,
) -> str:
    if entity_created:
        if source_surface == "endpoint":
            return "shadow_ai_endpoint_discovered"
        if source_surface in {"dns", "proxy"}:
            return "shadow_ai_network_discovered"
        return "shadow_ai_discovered"
    if risk_escalation:
        return "shadow_ai_risk_escalation"
    provider_type_norm = _norm(provider_type)
    provider_id_norm = _norm(provider_id)
    if source_surface in {"dns", "proxy"} and repeated_count >= 3:
        return "repeated_unknown_ai_network_usage"
    endpoint_tokens = {"api", "model", "responses", "/v1/"}
    if source_surface in {"endpoint", "proxy", "gateway", "connector"}:
        lowered_endpoint = f"{event_type} {api_endpoint or ''}".lower()
        if provider_type_norm in {"model_api", "local_model"} or any(token in lowered_endpoint for token in endpoint_tokens):
            return "unsanctioned_model_api_usage"
    if source_surface in {"connector", "gateway", "proxy"} and provider_id_norm in {
        "openai_chatgpt",
        "anthropic_claude",
        "google_gemini",
        "microsoft_copilot",
        "perplexity",
    }:
        return "shadow_ai_network_discovered"
    if confidence_level == "high":
        return "cross_surface_shadow_ai_confirmation"
    return "shadow_ai_discovered"


def _create_shadow_signal_evidence(
    db: Session,
    *,
    tenant_id: str,
    signal: ShadowAISignal,
    correlation_id: str | None,
) -> str:
    node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_signal",
        signal_type=f"shadow_ai.signal.{signal.source_surface}",
        label=f"Shadow AI signal from {signal.source_surface}",
        payload={
            "shadow_ai_signal_id": signal.id,
            "source_event_id": signal.source_event_id,
            "domain": signal.domain,
            "provider": signal.provider,
            "tool_name": signal.tool_name,
            "api_endpoint": signal.api_endpoint,
        },
        correlation_id=correlation_id,
    )
    return node.id


def _create_shadow_entity_evidence(
    db: Session,
    *,
    tenant_id: str,
    entity: ShadowAIEntity,
    correlation_id: str | None,
) -> str:
    node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_entity",
        signal_type="shadow_ai.entity",
        label=f"Shadow AI entity {entity.canonical_name}",
        payload={
            "shadow_ai_entity_id": entity.id,
            "canonical_name": entity.canonical_name,
            "discovery_status": entity.discovery_status,
            "confidence_score": entity.confidence_score,
            "provisional_risk_tier": entity.provisional_risk_tier,
            "approved_status": entity.approved_status,
            "risk_score": entity.risk_score,
            "usage_count": entity.usage_count,
            "unique_users": entity.unique_users,
            "endpoints_count": entity.endpoints_count,
            "linked_ai_system_id": entity.linked_ai_system_id,
            "source_surfaces": list(entity.source_surfaces or []),
        },
        correlation_id=correlation_id,
    )
    return node.id


def _safe_link_evidence(
    db: Session,
    *,
    tenant_id: str,
    from_node_id: str | None,
    to_node_id: str | None,
    edge_type: str,
    payload: dict[str, Any] | None = None,
) -> None:
    if not from_node_id or not to_node_id:
        return
    try:
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=from_node_id,
            to_node_id=to_node_id,
            edge_type=edge_type,
            payload=payload or {},
        )
    except Exception:
        return


def _derive_interaction_type(*, event_type: str, metadata: dict[str, Any], source_surface: str) -> str:
    normalized_type = _norm(event_type)
    if "upload" in normalized_type:
        return "upload"
    if "prompt" in normalized_type:
        return "prompt"
    if "tool" in normalized_type:
        return "tool_call"
    operation = _norm(str(metadata.get("operation") or ""))
    if operation in {"upload", "prompt", "tool_call", "browse"}:
        return operation
    if source_surface in {"dns", "proxy"}:
        return "browse"
    return "prompt"


def _compute_approved_status(db: Session, *, entity: ShadowAIEntity) -> str:
    if not str(entity.linked_ai_system_id or "").strip():
        return "unknown"
    linked = db.scalar(
        select(AISystem).where(
            AISystem.tenant_id == entity.tenant_id,
            AISystem.id == entity.linked_ai_system_id,
        )
    )
    if linked is None:
        return "unknown"
    status = _norm(linked.status)
    if status in APPROVED_STATUSES:
        return "approved"
    return "unapproved"


def _compute_entity_risk_score(
    *,
    risk_tier: str,
    confidence_score: float,
    repeated_count: int,
    sensitivity_detected: bool,
    policy_triggered: bool,
) -> float:
    base = {
        "LOW": 0.2,
        "MEDIUM": 0.45,
        "HIGH": 0.72,
        "CRITICAL": 0.9,
    }.get(str(risk_tier or "MEDIUM").strip().upper(), 0.45)
    repeat_boost = min(0.2, max(0.0, repeated_count) * 0.02)
    confidence_boost = min(0.15, max(0.0, confidence_score) * 0.15)
    sensitivity_boost = 0.15 if sensitivity_detected else 0.0
    policy_boost = 0.1 if policy_triggered else 0.0
    return round(min(1.0, base + repeat_boost + confidence_boost + sensitivity_boost + policy_boost), 4)


def _record_shadow_usage(
    db: Session,
    *,
    event: RuntimeEvent,
    metadata: dict[str, Any],
    entity: ShadowAIEntity,
    source_surface: str,
) -> ShadowAIUsage:
    reason_codes = metadata.get("reason_codes")
    policy_triggered = None
    if isinstance(reason_codes, list):
        policy_triggered = ",".join(str(item).strip() for item in reason_codes if str(item).strip()) or None
    elif str(metadata.get("policy_triggered") or "").strip():
        policy_triggered = str(metadata.get("policy_triggered")).strip()

    session_id = str(metadata.get("session_id") or event.context_id or "").strip() or None
    if session_id is not None and db.get(AISession, session_id) is None:
        session_id = None
    reported_endpoint_id = str(metadata.get("endpoint_id") or "").strip() or None
    endpoint_id = None
    endpoint_binding_state = "not_reported"
    if reported_endpoint_id:
        endpoint = db.get(DeploymentEndpoint, reported_endpoint_id)
        if endpoint is not None and endpoint.tenant_id == event.tenant_id:
            endpoint_id = endpoint.endpoint_id
            endpoint_binding_state = "bound"
        else:
            endpoint_binding_state = "unresolved"

    usage = ShadowAIUsage(
        tenant_id=event.tenant_id,
        asset_id=entity.id,
        user_id=event.user_id,
        endpoint_id=endpoint_id,
        session_id=session_id,
        timestamp=event.created_at,
        interaction_type=_derive_interaction_type(
            event_type=str(event.event_type or ""),
            metadata=metadata,
            source_surface=source_surface,
        ),
        sensitivity_detected=bool(
            metadata.get("contains_sensitive")
            or metadata.get("sensitivity_detected")
            or metadata.get("sensitive_confidence_score")
        ),
        policy_triggered=policy_triggered,
        metadata_json={
            "event_id": event.event_id,
            "source_surface": source_surface,
            "domain": metadata.get("domain") or event.app_id,
            "api_endpoint": metadata.get("api_endpoint"),
            "tool_name": metadata.get("tool_name"),
            "operation": metadata.get("operation"),
            "correlation_id": event.correlation_id,
            "reported_endpoint_id": reported_endpoint_id,
            "endpoint_binding_state": endpoint_binding_state,
        },
    )
    db.add(usage)
    db.flush()
    return usage


def _refresh_entity_usage_rollups(db: Session, *, entity: ShadowAIEntity) -> tuple[int, int, int]:
    usage_count = int(
        db.scalar(
            select(func.count())
            .select_from(ShadowAIUsage)
            .where(
                ShadowAIUsage.tenant_id == entity.tenant_id,
                ShadowAIUsage.asset_id == entity.id,
            )
        )
        or 0
    )
    unique_users = int(
        db.scalar(
            select(func.count(func.distinct(ShadowAIUsage.user_id)))
            .where(
                ShadowAIUsage.tenant_id == entity.tenant_id,
                ShadowAIUsage.asset_id == entity.id,
                ShadowAIUsage.user_id.is_not(None),
            )
        )
        or 0
    )
    endpoints_count = int(
        db.scalar(
            select(func.count(func.distinct(ShadowAIUsage.endpoint_id)))
            .where(
                ShadowAIUsage.tenant_id == entity.tenant_id,
                ShadowAIUsage.asset_id == entity.id,
                ShadowAIUsage.endpoint_id.is_not(None),
            )
        )
        or 0
    )
    return usage_count, unique_users, endpoints_count


def process_runtime_event_for_shadow_discovery(
    db: Session,
    *,
    event: RuntimeEvent,
) -> ShadowDiscoveryResult | None:
    metadata = _event_metadata(event)
    if not _is_shadow_candidate(event, metadata):
        return None

    source_surface = _signal_surface_for_event(event, metadata)
    signal_payload = _build_signal_payload(event, metadata)

    existing_signal = db.scalar(
        select(ShadowAISignal).where(
            ShadowAISignal.tenant_id == event.tenant_id,
            ShadowAISignal.source_surface == source_surface,
            ShadowAISignal.source_event_id == event.event_id,
        )
    )
    if existing_signal:
        entity = db.scalar(
            select(ShadowAIEntity).where(
                ShadowAIEntity.tenant_id == event.tenant_id,
                ShadowAIEntity.id == existing_signal.shadow_ai_entity_id,
            )
        )
        if not entity:
            return None
        return ShadowDiscoveryResult(
            entity_id=entity.id,
            signal_id=existing_signal.id,
            finding_id=None,
            ai_system_id=entity.linked_ai_system_id,
            confidence_score=float(entity.confidence_score or 0.0),
            confidence_level="high" if float(entity.confidence_score or 0.0) >= 0.8 else "medium",
            risk_tier=str(entity.provisional_risk_tier or "MEDIUM"),
        )

    resolution = resolve_identity(
        db,
        tenant_id=event.tenant_id,
        signal=signal_payload,
        explicit_ai_system_id=event.ai_system_id,
        source_surface=source_surface,
        first_seen_at=event.created_at,
    )
    entity = db.scalar(
        select(ShadowAIEntity).where(
            ShadowAIEntity.tenant_id == event.tenant_id,
            ShadowAIEntity.id == resolution.shadow_ai_entity_id,
        )
    )
    if entity is None:
        return None

    signal = ShadowAISignal(
        tenant_id=event.tenant_id,
        shadow_ai_entity_id=entity.id,
        source_surface=source_surface,
        source_event_id=event.event_id,
        domain=signal_payload.get("domain"),
        provider=signal_payload.get("provider"),
        model_name=signal_payload.get("model_name"),
        tool_name=signal_payload.get("tool_name"),
        api_endpoint=signal_payload.get("api_endpoint"),
        user_id=event.user_id,
        agent_id=event.agent_id,
        confidence_signal={
            "source_surface": source_surface,
            "governance_state": _norm(metadata.get("governance_state")) or "unknown",
            "connector_confirmed": bool(metadata.get("connector_confirmed")),
            "provider_id": metadata.get("provider_id"),
            "provider_type": metadata.get("provider_type"),
            "provider_confidence_hint": (metadata.get("provider_catalog") or {}).get("confidence_hint")
            if isinstance(metadata.get("provider_catalog"), dict)
            else None,
            "catalog_match": bool(metadata.get("catalog_match")),
        },
        raw_fingerprint={
            "event_type": event.event_type,
            "app_id": event.app_id,
            "metadata_keys": sorted(metadata.keys()),
            "process_name": metadata.get("process_name"),
            "command_line": metadata.get("command_line"),
            "host_id": metadata.get("host_id"),
            "api_endpoint": metadata.get("api_endpoint"),
            "active_integration_transport": metadata.get("active_integration_transport"),
            "evidence_basis": metadata.get("evidence_basis"),
            "control_binding_state": metadata.get("control_binding_state"),
        },
    )
    db.add(signal)
    db.flush()

    signal_node_id = _create_shadow_signal_evidence(
        db,
        tenant_id=event.tenant_id,
        signal=signal,
        correlation_id=event.correlation_id,
    )

    repeat_count = int(
        db.scalar(
            select(func.count())
            .select_from(ShadowAISignal)
            .where(
                ShadowAISignal.tenant_id == event.tenant_id,
                ShadowAISignal.shadow_ai_entity_id == entity.id,
            )
        )
        or 0
    )
    usage = _record_shadow_usage(
        db,
        event=event,
        metadata=metadata,
        entity=entity,
        source_surface=source_surface,
    )
    usage_count, unique_users, endpoints_count = _refresh_entity_usage_rollups(db, entity=entity)

    confidence = score_shadow_confidence(
        db,
        tenant_id=event.tenant_id,
        shadow_ai_entity_id=entity.id,
    )
    previous_risk = str(entity.provisional_risk_tier or "").strip().upper() or None
    risk = assign_provisional_risk(
        entity=entity,
        confidence_score=confidence.confidence_score,
        confidence_level=confidence.confidence_level,
        repeated_count=repeat_count,
        event_metadata=metadata | {"event_type": event.event_type},
    )

    entity.confidence_score = confidence.confidence_score
    entity.provisional_risk_tier = risk.provisional_risk_tier
    entity.last_seen = _safe_max_dt(entity.last_seen, event.created_at)
    entity.usage_count = usage_count
    entity.unique_users = unique_users
    entity.endpoints_count = endpoints_count
    entity.risk_score = _compute_entity_risk_score(
        risk_tier=risk.provisional_risk_tier,
        confidence_score=confidence.confidence_score,
        repeated_count=repeat_count,
        sensitivity_detected=bool(usage.sensitivity_detected),
        policy_triggered=bool(usage.policy_triggered),
    )
    if signal.provider and not entity.vendor:
        entity.vendor = signal.provider
    if resolution.matched_ai_system_id and not entity.linked_ai_system_id:
        entity.linked_ai_system_id = resolution.matched_ai_system_id
        entity.discovery_status = "reconciled"
    elif entity.linked_ai_system_id:
        if str(entity.discovery_status or "").strip().lower() not in {"promoted", "reconciled"}:
            entity.discovery_status = "reconciled"
    elif entity.discovery_status == "rejected":
        entity.discovery_status = "rejected"
    else:
        entity.discovery_status = "discovered"
    entity.approved_status = _compute_approved_status(db, entity=entity)

    entity.metadata_json = {
        **dict(entity.metadata_json or {}),
        "confidence_reasoning": confidence.confidence_reasoning,
        "risk_reasoning": risk.risk_reasoning,
        "last_runtime_event_id": event.event_id,
        "last_source_surface": source_surface,
        "usage_count": usage_count,
        "unique_users": unique_users,
        "endpoints_count": endpoints_count,
        "agent_runtime_profile": (
            dict(metadata.get("agent_runtime_profile") or {})
            if isinstance(metadata.get("agent_runtime_profile"), dict)
            else dict((entity.metadata_json or {}).get("agent_runtime_profile") or {})
        ),
        "active_integration_transport": str(
            metadata.get("active_integration_transport")
            or (entity.metadata_json or {}).get("active_integration_transport")
            or "unknown"
        ),
        "control_binding_state": str(
            metadata.get("control_binding_state")
            or (entity.metadata_json or {}).get("control_binding_state")
            or "unknown"
        ),
        "evidence_basis": str(
            metadata.get("evidence_basis")
            or (entity.metadata_json or {}).get("evidence_basis")
            or "unknown"
        ),
    }
    db.flush()

    entity_node_id = _create_shadow_entity_evidence(
        db,
        tenant_id=event.tenant_id,
        entity=entity,
        correlation_id=event.correlation_id,
    )
    _safe_link_evidence(
        db,
        tenant_id=event.tenant_id,
        from_node_id=signal_node_id,
        to_node_id=entity_node_id,
        edge_type="shadow_ai.signal_to_entity",
        payload={"shadow_ai_signal_id": signal.id, "shadow_ai_entity_id": entity.id},
    )
    for node_id in event.evidence_node_ids or []:
        _safe_link_evidence(
            db,
            tenant_id=event.tenant_id,
            from_node_id=str(node_id),
            to_node_id=entity_node_id,
            edge_type="shadow_ai.runtime_evidence_to_entity",
            payload={"runtime_event_id": event.event_id},
        )

    finding_type = _select_shadow_finding_type(
        source_surface=source_surface,
        entity_created=resolution.entity_created,
        risk_escalation=is_risk_escalation(previous_risk, risk.provisional_risk_tier),
        repeated_count=repeat_count,
        confidence_level=confidence.confidence_level,
        event_type=str(event.event_type or ""),
        api_endpoint=signal_payload.get("api_endpoint"),
        provider_type=str(metadata.get("provider_type") or ""),
        provider_id=str(metadata.get("provider_id") or ""),
    )

    should_emit_finding = resolution.entity_created or is_risk_escalation(previous_risk, risk.provisional_risk_tier) or finding_type in {
        "repeated_unknown_ai_network_usage",
        "unsanctioned_model_api_usage",
        "cross_surface_shadow_ai_confirmation",
    }
    finding = (
        generate_shadow_ai_entity_finding(
            db,
            tenant_id=event.tenant_id,
            entity=entity,
            finding_type=finding_type,
            severity=RISK_TO_SEVERITY.get(risk.provisional_risk_tier, "med"),
            source_surface=source_surface,
            evidence_node_ids=[
                signal_node_id,
                entity_node_id,
                *[str(node_id) for node_id in (event.evidence_node_ids or []) if str(node_id).strip()],
            ],
            related_control_ids=["CTRL-TENANT-ISO-001"],
            recommended_action={
                "shadow_ai_discovered": "review",
                "shadow_ai_endpoint_discovered": "investigate_endpoint_process",
                "shadow_ai_network_discovered": "monitor_only",
                "shadow_ai_risk_escalation": "route_to_governance",
                "repeated_unknown_ai_network_usage": "block_via_proxy_policy",
                "unsanctioned_model_api_usage": "investigate_endpoint_process",
                "cross_surface_shadow_ai_confirmation": "promote_to_trust_center",
            }.get(finding_type, "review"),
            ai_system_id=entity.linked_ai_system_id,
        )
        if should_emit_finding
        else None
    )
    finding_id = finding.finding_id if finding else None

    finding_node_id: str | None = None
    if finding is not None:
        finding_node = create_evidence_node(
            db,
            tenant_id=event.tenant_id,
            node_type="shadow_ai_finding",
            signal_type=f"shadow_ai.finding.{finding_type}",
            label=f"Shadow AI finding {finding_type}",
            payload={"finding_id": finding.finding_id, "shadow_ai_entity_id": entity.id},
            correlation_id=event.correlation_id,
        )
        finding_node_id = finding_node.id
        _safe_link_evidence(
            db,
            tenant_id=event.tenant_id,
            from_node_id=entity_node_id,
            to_node_id=finding_node.id,
            edge_type="shadow_ai.entity_to_finding",
            payload={"finding_id": finding.finding_id},
        )

    reconciliation = reconcile_to_trust_center_candidate(
        db,
        tenant_id=event.tenant_id,
        entity=entity,
        confidence_score=confidence.confidence_score,
        confidence_level=confidence.confidence_level,
        evidence_node_ids=[signal_node_id, entity_node_id, *([finding_node_id] if finding_node_id else [])],
        actor_user_id=None,
        force_promote=False,
    )

    write_audit_log(
        db,
        tenant_id=event.tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="shadow_ai.runtime_event_processed",
        resource_type="runtime_event",
        resource_id=event.event_id,
        payload={
            "shadow_ai_entity_id": entity.id,
            "shadow_ai_signal_id": signal.id,
            "confidence_score": confidence.confidence_score,
            "confidence_level": confidence.confidence_level,
            "risk_tier": risk.provisional_risk_tier,
            "finding_id": finding_id,
            "reconciliation": reconciliation.reason,
            "promoted": reconciliation.promoted,
            "ai_system_id": reconciliation.ai_system_id or entity.linked_ai_system_id,
        },
        correlation_id=event.correlation_id,
    )

    return ShadowDiscoveryResult(
        entity_id=entity.id,
        signal_id=signal.id,
        finding_id=finding_id,
        ai_system_id=reconciliation.ai_system_id or entity.linked_ai_system_id,
        confidence_score=confidence.confidence_score,
        confidence_level=confidence.confidence_level,
        risk_tier=risk.provisional_risk_tier,
    )


def safe_process_runtime_event_for_shadow_discovery(
    db: Session,
    *,
    event: RuntimeEvent,
) -> ShadowDiscoveryResult | None:
    try:
        return process_runtime_event_for_shadow_discovery(db, event=event)
    except Exception as exc:  # pragma: no cover - defensive non-blocking guard
        log_structured(
            "shadow_ai_discovery_processing_failed",
            tenant_id=event.tenant_id,
            runtime_event_id=event.event_id,
            source_surface=event.source_surface,
            event_type=event.event_type,
            correlation_id=event.correlation_id,
            error=str(exc),
        )
        return None
