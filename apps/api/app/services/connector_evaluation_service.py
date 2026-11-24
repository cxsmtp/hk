from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.monitoring import Connector
from app.db.models.runtime_intelligence import RuntimeEvent


MAX_EVIDENCE_ITEMS = 25
MAX_ERROR_LENGTH = 512
LEGACY_URL_SCAN_LIMIT = 250

_PROVIDER_DOMAINS = {
    "gmail": "mail.google.com",
}
_INLINE_AUTHORIZATION_MODES = {
    "inline_allowed",
    "inline_prevented",
}
_KNOWN_CONTROL_MODES = _INLINE_AUTHORIZATION_MODES | {
    "detected_only",
    "external_action_triggered",
    "external_required",
    "incomplete",
    "shadow_would_block",
    "telemetry_only",
}
_DECISION_BADGES = {
    "inline_allowed": "Pre-Action Allowed",
    "inline_prevented": "Pre-Action Blocked",
    "review_required": "Review Required",
    "warned": "Warning Issued",
    "telemetry_only": "Detected-Only",
}


def _safe_text(value: Any, *, maximum: int = 128) -> str | None:
    text = str(value or "").strip()
    return text[:maximum] or None


def _safe_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _normalized_connector_status(connector: Connector) -> tuple[str, bool]:
    raw_status = str(connector.status or "").strip().lower()
    last_pull_status = str(connector.last_pull_status or "").strip().lower()
    if raw_status == "revoked":
        normalized_status = "revoked"
    elif bool(connector.is_stub):
        normalized_status = "stub"
    elif not bool(connector.enabled) or raw_status in {"disabled", "inactive"}:
        normalized_status = "disabled"
    elif raw_status in {"degraded", "error", "failed"} or last_pull_status == "error":
        normalized_status = "degraded"
    else:
        normalized_status = "active"
    normalized_enabled = bool(connector.enabled) and normalized_status not in {"disabled", "revoked", "stub"}
    return normalized_status, normalized_enabled


def _url_matches_domain(event: RuntimeEvent, canonical_domain: str) -> bool:
    metadata = dict(event.metadata_json or {})
    url = str(metadata.get("url") or "").strip()
    if not url:
        return False
    try:
        return str(urlsplit(url).hostname or "").lower() == canonical_domain
    except ValueError:
        return False


def _event_matches_domain(event: RuntimeEvent, canonical_domain: str) -> bool:
    metadata = dict(event.metadata_json or {})
    return (
        str(event.app_id or "").strip().lower() == canonical_domain
        or str(metadata.get("domain") or "").strip().lower() == canonical_domain
        or _url_matches_domain(event, canonical_domain)
    )


def _event_order_key(event: RuntimeEvent) -> tuple[Any, str]:
    return event.created_at, event.event_id


def _control_mode(event: RuntimeEvent) -> str:
    candidate_mode = _safe_text(dict(event.metadata_json or {}).get("control_mode"), maximum=32)
    return candidate_mode if candidate_mode in _KNOWN_CONTROL_MODES else "incomplete"


def _bounded_reason(metadata: dict[str, Any]) -> str | None:
    for key in ("reason", "decision_reason", "reason_code"):
        reason = _safe_text(metadata.get(key), maximum=128)
        if reason:
            return reason
    input_signal_types = metadata.get("input_signal_types")
    if isinstance(input_signal_types, list) and input_signal_types:
        return _safe_text(input_signal_types[0], maximum=128)
    return None


def _latest_pull(db: Session, *, tenant_id: str, connector_id: str) -> tuple[dict[str, Any] | None, str | None]:
    audit = db.scalar(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action == "monitoring.connector.pull",
            AuditLog.resource_type == "connector",
            AuditLog.resource_id == connector_id,
        )
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
    )
    if audit is None:
        return None, None

    payload = dict(audit.payload or {})
    status = _safe_text(payload.get("status"), maximum=32) or "unknown"
    correlation_id = _safe_text(audit.correlation_id, maximum=64)
    evidence_root_id = _safe_text(payload.get("evidence_root_id"), maximum=36)
    error = None
    if status == "error" and payload.get("error"):
        error = "Connector pull failed; consult server diagnostics."[:MAX_ERROR_LENGTH]

    return (
        {
            "status": status,
            "normalized_signal_count": _safe_int(payload.get("normalized_signal_count")),
            "correlation_id": correlation_id,
            "evidence_root_id": evidence_root_id,
            "error": error,
            "created_at": audit.created_at,
        },
        evidence_root_id,
    )


def _latest_browser_action(
    db: Session,
    *,
    tenant_id: str,
    canonical_domain: str | None,
) -> tuple[dict[str, Any] | None, bool]:
    if canonical_domain is None:
        return None, False

    managed_conditions = (
        RuntimeEvent.tenant_id == tenant_id,
        RuntimeEvent.source_surface.in_(("browser", "browser_extension")),
        func.lower(func.coalesce(RuntimeEvent.browser_type, "")) == "chrome",
        func.lower(func.coalesce(RuntimeEvent.metadata_json["source_surface"].as_string(), ""))
        == "browser_extension",
        func.coalesce(RuntimeEvent.metadata_json["extension_version"].as_string(), "") != "",
        or_(
            func.coalesce(RuntimeEvent.metadata_json["endpoint_id"].as_string(), "") != "",
            func.coalesce(RuntimeEvent.machine_id, "") != "",
        ),
    )
    structured_event = db.scalar(
        select(RuntimeEvent)
        .where(
            *managed_conditions,
            or_(
                func.lower(func.coalesce(RuntimeEvent.app_id, "")) == canonical_domain,
                func.lower(func.coalesce(RuntimeEvent.metadata_json["domain"].as_string(), ""))
                == canonical_domain,
            ),
        )
        .order_by(RuntimeEvent.created_at.desc(), RuntimeEvent.event_id.desc())
        .limit(1)
    )

    legacy_url_candidates = db.scalars(
        select(RuntimeEvent)
        .where(
            *managed_conditions,
            func.coalesce(RuntimeEvent.metadata_json["url"].as_string(), "") != "",
        )
        .order_by(RuntimeEvent.created_at.desc(), RuntimeEvent.event_id.desc())
        .limit(LEGACY_URL_SCAN_LIMIT + 1)
    ).all()
    legacy_search_truncated = len(legacy_url_candidates) > LEGACY_URL_SCAN_LIMIT
    url_event = next(
        (
            candidate
            for candidate in legacy_url_candidates[:LEGACY_URL_SCAN_LIMIT]
            if _url_matches_domain(candidate, canonical_domain)
        ),
        None,
    )
    if url_event is None and legacy_search_truncated:
        return None, True

    matching_latest = [candidate for candidate in (structured_event, url_event) if candidate is not None]
    if not matching_latest:
        return None, False

    event = max(matching_latest, key=_event_order_key)
    if event.event_type == "policy_blocked" and event.correlation_id and _control_mode(event) not in _INLINE_AUTHORIZATION_MODES:
        correlated_candidates = db.scalars(
            select(RuntimeEvent)
            .where(
                *managed_conditions,
                RuntimeEvent.correlation_id == event.correlation_id,
            )
            .order_by(RuntimeEvent.created_at.desc(), RuntimeEvent.event_id.desc())
        ).all()
        correlated_inline = next(
            (
                candidate
                for candidate in correlated_candidates
                if candidate.event_id != event.event_id
                and _event_matches_domain(candidate, canonical_domain)
                and _control_mode(candidate) in _INLINE_AUTHORIZATION_MODES
            ),
            None,
        )
        if correlated_inline is not None:
            event = correlated_inline

    metadata = dict(event.metadata_json or {})
    control_mode = _control_mode(event)
    decision = str(event.decision or "").strip().lower()
    event_type = str(event.event_type or "").strip().lower()
    authorization_observed = (
        control_mode == "inline_prevented"
        and decision in {"block", "deny"}
        and "blocked" in event_type
    ) or (
        control_mode == "inline_allowed"
        and decision == "allow"
        and "allowed" in event_type
    )
    expected_badge = _DECISION_BADGES.get(control_mode)
    candidate_badge = _safe_text(metadata.get("decision_badge"), maximum=64)
    decision_badge = candidate_badge if candidate_badge == expected_badge else expected_badge
    evidence_node_ids = [
        node_id
        for node_id in (_safe_text(item, maximum=36) for item in list(event.evidence_node_ids or [])[:MAX_EVIDENCE_ITEMS])
        if node_id is not None
    ]
    linked_evidence_ids = set(
        db.scalars(
            select(EvidenceNode.id).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id.in_(evidence_node_ids),
            )
        ).all()
    ) if evidence_node_ids else set()
    if not evidence_node_ids:
        evidence_integrity_status = "unknown"
    elif len(linked_evidence_ids) == len(evidence_node_ids):
        evidence_integrity_status = "valid"
    else:
        evidence_integrity_status = "invalid"

    return (
        {
            "event_id": event.event_id,
            "source": "browser",
            "application": "Gmail" if canonical_domain == "mail.google.com" else canonical_domain,
            "action_type": _safe_text(metadata.get("action_type"), maximum=128),
            "reason": _bounded_reason(metadata),
            "control_mode": control_mode,
            "decision_badge": decision_badge,
            "decision": _safe_text(event.decision, maximum=32),
            "domain": canonical_domain,
            "user": _safe_text(event.user_id, maximum=64),
            "correlation_id": _safe_text(event.correlation_id, maximum=64),
            "evidence_node_ids": evidence_node_ids,
            "evidence_linked": bool(evidence_node_ids) and len(linked_evidence_ids) == len(evidence_node_ids),
            "evidence_link_count": len(linked_evidence_ids),
            "evidence_integrity_status": evidence_integrity_status,
            "created_at": event.created_at,
            "_authorization_observed": authorization_observed,
        },
        False,
    )


def _evidence_summary(
    db: Session,
    *,
    tenant_id: str,
    root_id: str | None,
    correlation_id: str | None,
) -> dict[str, Any]:
    if root_id is None:
        return {
            "root_id": None,
            "integrity_status": "unknown",
            "count": 0,
            "items": [],
        }

    ordered_ids: list[str] = [root_id]
    if correlation_id:
        correlated_ids = db.scalars(
            select(EvidenceNode.id)
            .where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.correlation_id == correlation_id,
            )
            .order_by(EvidenceNode.created_at.asc(), EvidenceNode.id.asc())
            .limit(MAX_EVIDENCE_ITEMS)
        ).all()
        ordered_ids.extend(correlated_ids)

    linked_edges = db.scalars(
        select(EvidenceEdge)
        .where(
            EvidenceEdge.tenant_id == tenant_id,
            or_(EvidenceEdge.from_node_id == root_id, EvidenceEdge.to_node_id == root_id),
        )
        .order_by(EvidenceEdge.created_at.asc(), EvidenceEdge.id.asc())
        .limit(MAX_EVIDENCE_ITEMS)
    ).all()
    for edge in linked_edges:
        ordered_ids.append(edge.to_node_id if edge.from_node_id == root_id else edge.from_node_id)

    bounded_ids = list(dict.fromkeys(ordered_ids))[:MAX_EVIDENCE_ITEMS]
    rows = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id.in_(bounded_ids),
        )
    ).all()
    rows_by_id = {row.id: row for row in rows}
    items = [
        {
            "id": row.id,
            "node_type": row.node_type,
            "signal_type": row.signal_type,
            "correlation_id": row.correlation_id,
            "created_at": row.created_at,
        }
        for node_id in bounded_ids
        if (row := rows_by_id.get(node_id)) is not None
    ]

    return {
        "root_id": root_id,
        "integrity_status": "valid" if root_id in rows_by_id else "invalid",
        "count": len(items),
        "items": items,
    }


def connector_evaluation(db: Session, *, tenant_id: str, connector_id: str) -> dict[str, Any] | None:
    connector = db.scalar(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == tenant_id,
        )
    )
    if connector is None:
        return None

    provider_key = str(connector.provider_key or connector.connector_type or "").strip().lower()
    canonical_domain = _PROVIDER_DOMAINS.get(provider_key)
    latest_pull, evidence_root_id = _latest_pull(
        db,
        tenant_id=tenant_id,
        connector_id=connector.id,
    )
    latest_browser_action, browser_search_truncated = _latest_browser_action(
        db,
        tenant_id=tenant_id,
        canonical_domain=canonical_domain,
    )
    authorization_observed = bool(
        latest_browser_action.pop("_authorization_observed", False)
        if latest_browser_action is not None
        else False
    )
    control_mode = latest_browser_action.get("control_mode") if latest_browser_action else None
    evidence = _evidence_summary(
        db,
        tenant_id=tenant_id,
        root_id=evidence_root_id,
        correlation_id=(latest_pull or {}).get("correlation_id"),
    )
    normalized_status, normalized_enabled = _normalized_connector_status(connector)
    latest_pull_status = (latest_pull or {}).get("status")
    connector_operational = normalized_status not in {"disabled", "revoked", "stub"}
    if not connector_operational:
        connector_discovery = "not_covered"
    elif latest_pull_status == "success":
        connector_discovery = "covered"
    elif latest_pull is None:
        connector_discovery = "not_covered"
    else:
        connector_discovery = "unknown"
    if browser_search_truncated:
        browser_authorization = "unknown"
    elif latest_browser_action is None:
        browser_authorization = "not_covered"
    elif control_mode in _INLINE_AUTHORIZATION_MODES and authorization_observed:
        browser_authorization = "covered"
    else:
        browser_authorization = "unknown"
    if browser_search_truncated:
        browser_prove = "unknown"
    elif latest_browser_action is None:
        browser_prove = "not_covered"
    elif (
        latest_browser_action.get("evidence_linked") is True
        and latest_browser_action.get("evidence_integrity_status") == "valid"
    ):
        browser_prove = "covered"
    else:
        browser_prove = "unknown"

    return {
        "connector": {
            "id": connector.id,
            "provider_key": provider_key,
            "connector_type": connector.connector_type,
            "name": _safe_text(connector.name, maximum=255) or "Unnamed connector",
            "enabled": normalized_enabled,
            "status": normalized_status,
            "is_stub": bool(connector.is_stub),
            "stub_reason": _safe_text(connector.stub_reason, maximum=256) or "",
            "last_pull_status": _safe_text(connector.last_pull_status, maximum=32) or "unknown",
            "last_pull_error": (
                "Connector pull failed; consult server diagnostics."
                if connector.last_pull_error
                else None
            ),
            "has_secrets": bool(connector.encrypted_secrets),
        },
        "latest_pull": latest_pull,
        "connector_path": {
            "mode": "monitor_only",
            "discovery": connector_discovery,
            "authorization": "not_covered",
            "prove": (
                "covered"
                if connector_operational
                and latest_pull_status == "success"
                and evidence.get("integrity_status") == "valid"
                else "unknown"
            ),
        },
        "browser_path": {
            "canonical_domain": canonical_domain,
            "search_status": "truncated" if browser_search_truncated else "complete",
            "mode": "unknown" if browser_search_truncated else (control_mode or "not_observed"),
            "discovery": (
                "unknown"
                if browser_search_truncated
                else ("covered" if latest_browser_action is not None else "not_covered")
            ),
            "authorization": browser_authorization,
            "prove": browser_prove,
        },
        "latest_browser_action": latest_browser_action,
        "evidence": evidence,
        "limitations": [
            "Connector pulls observe provider metadata after the fact and do not authorize browser actions.",
            "Browser authorization is based only on the latest matching runtime control event.",
            "Unmanaged browsers may not emit runtime control evidence.",
            "Gmail mobile and desktop clients are outside browser-path coverage.",
            "Direct Gmail API actions are outside browser-path coverage unless separately instrumented.",
        ],
    }
