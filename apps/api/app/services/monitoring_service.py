from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import case, desc, func, select
from sqlalchemy.orm import Session

from app.core.observability import log_structured
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.knowledge_base import KBControl, KBFramework
from app.db.models.monitoring import Connector, DriftAlert, MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeGovernanceRecommendation, RuntimeSimulationTrigger
from app.services.audit_service import write_audit_log
from app.services.connector_secret_service import decrypt_connector_secrets
from app.services.enforcement_routing_service import route_enforcement
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.findings_service import (
    generate_from_drift_alert,
    generate_from_shadow_event,
    generate_unregistered_ai_system_finding,
)
from app.services.integration_connector_service import (
    list_connector_signal_coverage,
    list_provider_catalog,
    run_provider_pull,
    validate_monitoring_connector_destination,
)
from app.services.outbound_destination_policy import OutboundDestinationPolicy
from app.services.runtime_intelligence import RUNTIME_FINDING_TYPES


SAAS_APP_BY_PROVIDER: dict[str, str] = {
    "slack": "slack",
    "gmail": "gmail",
    "google_workspace": "google_workspace",
    "outlook": "outlook",
    "microsoft_365": "microsoft_365",
    "office365": "microsoft_365",
    "o365": "microsoft_365",
    "teams": "teams",
    "onedrive_sharepoint": "sharepoint",
    "office_apps": "office_apps",
    "microsoft_defender": "microsoft_defender",
    "azure_openai": "azure_openai",
    "power_platform": "power_platform",
}


def _validate_ai_system_tenant(db: Session, *, tenant_id: str, ai_system_id: str | None) -> None:
    if not ai_system_id:
        return
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if not ai_system:
        raise ValueError("AI system not found for tenant")


def _normalized_severity(value: str | None) -> str:
    severity = str(value or "low").strip().lower()
    if severity == "medium":
        return "med"
    if severity not in {"low", "med", "high", "critical"}:
        return "low"
    return severity


def _severity_rank(value: str | None) -> int:
    order = {"low": 1, "med": 2, "high": 3, "critical": 4}
    return int(order.get(_normalized_severity(value), 1))


def _extract_ai_tool_hint(payload: dict[str, Any]) -> str:
    record = payload.get("record") if isinstance(payload.get("record"), dict) else {}
    source_metadata = payload.get("source_metadata") if isinstance(payload.get("source_metadata"), dict) else {}
    return (
        str(
            record.get("domain")
            or record.get("host")
            or record.get("tool_name")
            or record.get("appDisplayName")
            or record.get("clientAppUsed")
            or record.get("resourceDisplayName")
            or ""
        ).strip()
        or str(payload.get("ai_tool") or payload.get("tool_name") or payload.get("provider_key") or "").strip()
        or str(source_metadata.get("provider_name") or source_metadata.get("provider_key") or "connector_ai_usage").strip()
    )


def _first_non_empty(*values: Any) -> str:
    for value in values:
        token = str(value or "").strip()
        if token:
            return token
    return ""


def _provider_from_signal_type(signal_type: str) -> str:
    parts = [part.strip().lower() for part in str(signal_type or "").split(".") if part.strip()]
    if len(parts) >= 2:
        if parts[0] == "saas":
            return parts[1]
        if parts[0] == "ai":
            return parts[1]
    return ""


def _build_surface_event_from_monitoring_signal(
    *,
    signal_type: str,
    severity: str,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    signal_norm = str(signal_type or "").strip().lower()
    if ".ai_usage" not in signal_norm:
        return None

    record = payload.get("record") if isinstance(payload.get("record"), dict) else {}
    source_metadata = payload.get("source_metadata") if isinstance(payload.get("source_metadata"), dict) else {}
    retroactive_policy = payload.get("retroactive_policy") if isinstance(payload.get("retroactive_policy"), dict) else {}

    provider_key = _first_non_empty(payload.get("provider_key"), source_metadata.get("provider_key"), _provider_from_signal_type(signal_norm)).lower()
    app = SAAS_APP_BY_PROVIDER.get(provider_key, provider_key or "saas_ai")

    content = _first_non_empty(
        payload.get("prompt_or_content"),
        payload.get("content"),
        payload.get("prompt"),
        record.get("prompt"),
        record.get("message"),
        record.get("text"),
        record.get("query"),
        record.get("summary"),
    )

    user_id = _first_non_empty(
        payload.get("user_id"),
        payload.get("user"),
        record.get("user_id"),
        record.get("user"),
        record.get("userPrincipalName"),
        record.get("actor"),
    )
    user_principal_name = _first_non_empty(
        payload.get("user_principal_name"),
        record.get("userPrincipalName"),
    )
    entra_user_id = _first_non_empty(
        payload.get("entra_user_id"),
        record.get("userId"),
        (record.get("initiatedBy") or {}).get("user", {}).get("id")
        if isinstance((record.get("initiatedBy") or {}).get("user"), dict)
        else "",
    )
    hostname = _first_non_empty(payload.get("hostname"), record.get("hostname"), record.get("device"))
    endpoint_id = _first_non_empty(payload.get("endpoint_id"), payload.get("device_id"), record.get("device_id"), hostname)
    app_domain = _first_non_empty(payload.get("domain"), record.get("domain"), record.get("host"), record.get("app_domain"))
    url = _first_non_empty(payload.get("url"), record.get("url"))
    model = _first_non_empty(payload.get("model"), record.get("model"))
    decision_hint = _first_non_empty(retroactive_policy.get("decision"), payload.get("decision_hint"))
    reason_code = _first_non_empty(retroactive_policy.get("reason_code"), payload.get("reason_code"))

    input_signal_types: list[str] = []
    for token in [signal_norm, _first_non_empty(payload.get("reason_code")), _first_non_empty(retroactive_policy.get("reason_code"))]:
        if token:
            input_signal_types.append(token)

    return {
        "surface": "saas",
        "app": app,
        "action_type": "prompt_input" if content else "activity",
        "event_type": signal_norm,
        "user_id": user_id or None,
        "device_id": endpoint_id or None,
        "endpoint_id": endpoint_id or None,
        "hostname": hostname or None,
        "app_domain": app_domain or None,
        "url": url or None,
        "model": model or None,
        "prompt_or_content": content or None,
        "prompt_preview_redacted": _first_non_empty(payload.get("prompt_preview_redacted")),
        "gateway_routed": True,
        "data_classification": _first_non_empty(payload.get("data_classification")) or None,
        "risk_tier": str(severity or "low").strip().lower(),
        "decision_hint": decision_hint or None,
        "reason_code": reason_code or None,
        "input_signal_types": input_signal_types,
        "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        "metadata": {
            "source": (
                "microsoft"
                if provider_key in {"entra_id", "microsoft_365", "outlook", "teams", "onedrive_sharepoint", "office_apps", "microsoft_defender", "power_platform"}
                else "connector_signal"
            ),
            "monitoring_signal_type": signal_norm,
            "provider_key": provider_key,
            "entra_user_id": entra_user_id or None,
            "user_principal_name": user_principal_name or None,
            "source_metadata": source_metadata,
        },
    }


def _is_drift_signal(*, signal_type: str, payload: dict[str, Any]) -> bool:
    signal_norm = str(signal_type or "").strip().lower()
    reason_code = str(payload.get("reason_code") or "").strip().lower()
    return bool(payload.get("control_drift_detected")) or "drift" in signal_norm or "drift" in reason_code


def _is_connector_risk_signal(*, signal_type: str, severity: str, payload: dict[str, Any]) -> bool:
    if bool(payload.get("connector_risk_exposed")):
        return True
    signal_norm = str(signal_type or "").strip().lower()
    reason_code = str(payload.get("reason_code") or "").strip().lower()
    pull_status = str(payload.get("pull_status") or "").strip().lower()
    high_severity = _severity_rank(severity) >= _severity_rank("high")
    if signal_norm.startswith("integration.health.") and pull_status in {"error", "degraded"} and high_severity:
        return True
    return "connector_risk" in reason_code and high_severity


def _is_missing_evidence_signal(*, signal_type: str, payload: dict[str, Any]) -> bool:
    if bool(payload.get("missing_evidence_detected")) or bool(payload.get("evidence_missing")):
        return True
    signal_norm = str(signal_type or "").strip().lower()
    if "evidence" in signal_norm and "gap" in signal_norm:
        return True
    coverage = payload.get("coverage")
    if isinstance(coverage, dict):
        control_map = coverage.get("control_signal_map")
        if isinstance(control_map, list):
            for row in control_map:
                if not isinstance(row, dict):
                    continue
                if int(row.get("live_evidence_count") or 0) <= 0:
                    return True
    return False


def _mark_ai_system_non_compliant(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    signal_type: str,
    severity: str,
    controls: list[str],
    control_drift_detected: bool,
    missing_evidence_detected: bool,
) -> None:
    row = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if row is None:
        return
    metadata = dict(row.metadata_json or {})
    metadata["compliance_state"] = "non_compliant"
    metadata["remediation_required"] = True
    metadata["non_compliance_reason"] = (
        "control_drift_detected"
        if control_drift_detected
        else "evidence_gap_detected"
        if missing_evidence_detected
        else str(metadata.get("non_compliance_reason") or "monitoring_signal")
    )
    metadata["non_compliance_last_signal_type"] = signal_type
    metadata["non_compliance_last_seen_at"] = datetime.now(timezone.utc).isoformat()
    metadata["non_compliance_severity"] = _normalized_severity(severity)
    metadata["non_compliance_controls"] = sorted(
        {
            *[str(item).strip() for item in (metadata.get("non_compliance_controls") or []) if str(item).strip()],
            *[str(control_id).strip() for control_id in (controls or []) if str(control_id).strip()],
        }
    )
    metadata["requires_revalidation"] = bool(metadata.get("requires_revalidation")) or missing_evidence_detected
    metadata["control_drift_detected"] = bool(metadata.get("control_drift_detected")) or control_drift_detected
    metadata["missing_evidence_detected"] = bool(metadata.get("missing_evidence_detected")) or missing_evidence_detected
    row.metadata_json = metadata
    db.flush()


def _parse_iso_datetime(value: str | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _retroactive_connector_policy(
    *,
    signal_type: str,
    severity: str,
    payload: dict[str, Any],
    ai_system_id: str | None,
) -> dict[str, Any] | None:
    signal_type_norm = str(signal_type or "").strip().lower()
    if not signal_type_norm:
        return None
    if ".ai_usage" not in signal_type_norm and not signal_type_norm.startswith("ai."):
        return None

    ai_tool = _extract_ai_tool_hint(payload)
    contains_sensitive = bool(payload.get("contains_sensitive")) or _severity_rank(severity) >= _severity_rank("high")
    sanctioned = bool(str(ai_system_id or "").strip())
    source_metadata = payload.get("source_metadata") if isinstance(payload.get("source_metadata"), dict) else {}
    provider_key = str(payload.get("provider_key") or "").strip() or str(source_metadata.get("provider_key") or "").strip()

    if sanctioned:
        decision = "allow"
        reason_code = "sanctioned_ai_usage_observed"
        recommended_action = "monitor_usage_trend"
        explanation = "Connector detected AI usage on a governed system; monitoring only."
    elif contains_sensitive:
        decision = "block"
        reason_code = "unsanctioned_sensitive_ai_usage"
        recommended_action = "route_to_governance_and_block"
        explanation = "Connector detected sensitive unsanctioned AI usage; governance escalation required."
    else:
        decision = "block"
        reason_code = "unsanctioned_unknown_ai_from_connector"
        recommended_action = "block_and_register_discovered_ai"
        explanation = "Connector detected unsanctioned AI usage; usage is blocked until Trust Center review."

    return {
        "decision": decision,
        "reason_code": reason_code,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "ai_tool": ai_tool,
        "provider_key": provider_key,
        "is_sanctioned": sanctioned,
        "policy_id": "connector_retroactive_policy_v1",
        "policy_version": "1.0.0",
        "register_shadow_candidate": not sanctioned,
    }


def _extract_related_control_ids(payload: dict[str, Any], related_control_ids: list[str] | None) -> list[str]:
    provided = [str(control_id).strip() for control_id in (related_control_ids or []) if str(control_id).strip()]
    if provided:
        return sorted(set(provided))
    payload_controls = [
        str(control_id).strip()
        for control_id in (payload.get("related_control_ids") or [])
        if str(control_id).strip()
    ]
    return sorted(set(payload_controls))


def _active_jira_connector(db: Session, *, tenant_id: str) -> Connector | None:
    return db.scalar(
        select(Connector)
        .where(
            Connector.tenant_id == tenant_id,
            Connector.enabled.is_(True),
            Connector.provider_key == "jira",
            Connector.status.in_(["active", "stub", "degraded"]),
        )
        .order_by(desc(Connector.updated_at))
        .limit(1)
    )


def _build_remediation_candidates(
    db: Session,
    *,
    tenant_id: str,
    signal_type: str,
    severity: str,
    provider_key: str | None = None,
    control_ids: list[str] | None = None,
    context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    severity_norm = _normalized_severity(severity)
    controls = [str(control_id).strip() for control_id in (control_ids or []) if str(control_id).strip()]
    candidates: list[dict[str, Any]] = []
    if _severity_rank(severity_norm) >= _severity_rank("med"):
        candidates.append(
            {
                "type": "policy_tune_candidate",
                "priority": "high" if _severity_rank(severity_norm) >= _severity_rank("high") else "med",
                "action": "review_control_mapping",
                "signal_type": signal_type,
                "related_control_ids": controls,
                "provider_key": provider_key,
            }
        )
    if _severity_rank(severity_norm) >= _severity_rank("high"):
        candidates.append(
            {
                "type": "simulation_validation_candidate",
                "priority": "high",
                "action": "run_targeted_validation_pack",
                "signal_type": signal_type,
                "related_control_ids": controls,
                "provider_key": provider_key,
            }
        )

    jira_connector = _active_jira_connector(db, tenant_id=tenant_id)
    if jira_connector and _severity_rank(severity_norm) >= _severity_rank("high"):
        jira_config = dict(jira_connector.config or {})
        candidates.append(
            {
                "type": "external_ticket_candidate",
                "provider": "jira",
                "connector_id": jira_connector.id,
                "status": "candidate",
                "payload": {
                    "project_key": str(jira_config.get("project_key") or "SEC"),
                    "issue_type": str(jira_config.get("issue_type") or "Task"),
                    "summary": f"[{severity_norm.upper()}] {signal_type} remediation candidate",
                    "description": (
                        f"Signal '{signal_type}' requires remediation review. "
                        f"Provider={provider_key or 'n/a'} controls={controls or []} context={dict(context or {})}"
                    ),
                    "labels": ["hawk-ai", "monitoring", "remediation-candidate"],
                    "related_control_ids": controls,
                },
            }
        )
    return candidates


def _priority_to_severity(priority: str | None) -> str:
    normalized = str(priority or "med").strip().lower()
    if normalized in {"critical", "p0"}:
        return "critical"
    if normalized in {"high", "p1"}:
        return "high"
    if normalized in {"med", "medium", "p2"}:
        return "med"
    return "low"


def ingest_shadow_event(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    event_type: str,
    payload: dict[str, Any],
    actor_user_id: str | None,
) -> MonitoringSignal:
    _validate_ai_system_tenant(db, tenant_id=tenant_id, ai_system_id=ai_system_id)
    routing = route_enforcement(
        {
            "policy_id": "connector_shadow_monitoring",
            "policy_version": str((payload or {}).get("policy_version") or "none"),
        },
        {
            "event_id": str((payload or {}).get("event_id") or ""),
            "tenant_id": tenant_id,
            "source_surface": str((payload or {}).get("source_surface") or "connector"),
            "action_type": str(event_type or "shadow_event"),
            "ai_system_id": ai_system_id,
            "agent_id": (payload or {}).get("agent_id"),
            "data_classification": (payload or {}).get("data_classification"),
            "correlation_id": (payload or {}).get("correlation_id"),
        },
    )
    payload_with_routing = dict(payload or {})
    payload_with_routing["enforcement_routing"] = routing

    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        signal_type=f"shadow_ai.{event_type}",
        severity=payload.get("severity", "med"),
        payload=payload_with_routing,
    )
    db.add(signal)
    db.flush()
    shadow_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_signal",
        signal_type=signal.signal_type,
        label=f"Shadow AI signal: {event_type}",
        payload={
            "monitoring_signal_id": signal.id,
            "ai_system_id": ai_system_id,
            "event_type": event_type,
            "severity": signal.severity,
        },
    )
    updated_payload = dict(payload_with_routing or {})
    existing_ids = [str(node_id) for node_id in (updated_payload.get("evidence_node_ids") or []) if str(node_id).strip()]
    updated_payload["evidence_node_ids"] = sorted({*existing_ids, shadow_node.id})
    signal.payload = updated_payload

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="system",
        action="shadow_ai.ingest_event",
        resource_type="monitoring_signal",
        resource_id=signal.id,
        payload={"event_type": event_type, "ai_system_id": ai_system_id, "evidence_node_id": shadow_node.id},
    )
    generate_from_shadow_event(db, signal=signal)
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_connector_signal

        ingest_from_connector_signal(db, signal=signal, evidence_node_id=shadow_node.id)
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="monitoring_service",
            tenant_id=tenant_id,
            signal_type=signal.signal_type,
            correlation_id=None,
            error=str(exc),
        )
    return signal


def ingest_monitoring_signal(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    signal_type: str,
    severity: str,
    payload: dict[str, Any],
    actor_user_id: str | None,
    create_default_drift_alert: bool = True,
    drift_title: str | None = None,
    drift_ai_tool: str | None = None,
    related_control_ids: list[str] | None = None,
    forward_to_runtime_intelligence: bool = True,
) -> MonitoringSignal:
    _validate_ai_system_tenant(db, tenant_id=tenant_id, ai_system_id=ai_system_id)
    severity_norm = _normalized_severity(severity)
    controls = _extract_related_control_ids(payload, related_control_ids)
    payload_dict = dict(payload or {})
    retroactive_policy = _retroactive_connector_policy(
        signal_type=signal_type,
        severity=severity_norm,
        payload=payload_dict,
        ai_system_id=ai_system_id,
    )
    if retroactive_policy is not None:
        payload_dict["retroactive_policy"] = retroactive_policy
    control_drift_detected = _is_drift_signal(signal_type=signal_type, payload=payload_dict)
    connector_risk_exposed = _is_connector_risk_signal(signal_type=signal_type, severity=severity_norm, payload=payload_dict)
    missing_evidence_detected = _is_missing_evidence_signal(signal_type=signal_type, payload=payload_dict)
    if control_drift_detected:
        payload_dict["control_drift_detected"] = True
    if connector_risk_exposed:
        payload_dict["connector_risk_exposed"] = True
        payload_dict["disable_high_risk_actions"] = True
    if missing_evidence_detected:
        payload_dict["missing_evidence_detected"] = True
        payload_dict["require_revalidation"] = True
    if ai_system_id and (control_drift_detected or missing_evidence_detected):
        _mark_ai_system_non_compliant(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            signal_type=signal_type,
            severity=severity_norm,
            controls=controls,
            control_drift_detected=control_drift_detected,
            missing_evidence_detected=missing_evidence_detected,
        )
    routing = route_enforcement(
        {
            "policy_id": "connector_monitoring_policy",
            "policy_version": str(payload_dict.get("policy_version") or "none"),
        },
        {
            "event_id": str(payload_dict.get("event_id") or ""),
            "tenant_id": tenant_id,
            "source_surface": str(payload_dict.get("source_surface") or "connector"),
            "action_type": str(signal_type or "monitoring_signal"),
            "ai_system_id": ai_system_id,
            "agent_id": payload_dict.get("agent_id"),
            "data_classification": payload_dict.get("data_classification"),
            "correlation_id": payload_dict.get("correlation_id"),
        },
    )
    payload_dict["enforcement_routing"] = routing
    remediation_candidates = payload_dict.get("remediation_candidates")
    if not isinstance(remediation_candidates, list):
        remediation_candidates = _build_remediation_candidates(
            db,
            tenant_id=tenant_id,
            signal_type=signal_type,
            severity=severity_norm,
            provider_key=str(payload_dict.get("provider_key") or ""),
            control_ids=controls,
            context={
                "ai_system_id": ai_system_id,
                "signal_type": signal_type,
            },
        )
    payload_dict["related_control_ids"] = controls
    payload_dict["remediation_candidates"] = remediation_candidates

    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        signal_type=signal_type,
        severity=severity_norm,
        payload=payload_dict,
    )
    db.add(signal)
    db.flush()
    signal_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="monitoring_signal",
        signal_type=signal_type,
        label=f"Monitoring signal: {signal_type}",
        payload={
            "monitoring_signal_id": signal.id,
            "ai_system_id": ai_system_id,
            "severity": severity_norm,
            "related_control_ids": controls,
        },
    )
    normalized_payload = dict(payload_dict or {})
    existing_ids = [str(node_id) for node_id in (normalized_payload.get("evidence_node_ids") or []) if str(node_id).strip()]
    normalized_payload["evidence_node_ids"] = sorted({*existing_ids, signal_node.id})
    signal.payload = normalized_payload

    retroactive_policy_payload = dict(normalized_payload.get("retroactive_policy") or {})
    retro_decision = str(retroactive_policy_payload.get("decision") or "").strip().lower()
    if retroactive_policy_payload and retro_decision in {"warn", "block"} and not ai_system_id:
        governance_finding = generate_unregistered_ai_system_finding(
            db,
            tenant_id=tenant_id,
            source_surface="connector",
            ai_tool=str(retroactive_policy_payload.get("ai_tool") or "connector_ai_usage"),
            requested_ai_system_id=None,
            policy_version_id=str(payload_dict.get("policy_version") or "") or None,
            evidence_node_ids=[signal_node.id],
            related_control_ids=controls or ["CTRL-TENANT-ISO-001", "CTRL-INPUT-001"],
            recommended_action=str(retroactive_policy_payload.get("recommended_action") or "route_to_governance_review"),
        )
        if governance_finding is not None:
            retroactive_policy_payload["finding_id"] = governance_finding.finding_id
        normalized_payload["retroactive_policy"] = retroactive_policy_payload
        signal.payload = normalized_payload

    if remediation_candidates:
        remediation_node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="remediation_candidate",
            signal_type=f"{signal_type}.remediation",
            label=f"Remediation candidates for {signal_type}",
            payload={
                "monitoring_signal_id": signal.id,
                "related_control_ids": controls,
                "candidates": remediation_candidates,
            },
        )
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=signal_node.id,
            to_node_id=remediation_node.id,
            edge_type="remediation_candidate",
            payload={"monitoring_signal_id": signal.id},
        )
        normalized_payload["evidence_node_ids"] = sorted({*normalized_payload["evidence_node_ids"], remediation_node.id})
        signal.payload = normalized_payload

    if create_default_drift_alert and severity_norm in {"high", "critical"}:
        alert = DriftAlert(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            title=drift_title or f"Drift alert: {signal_type}",
            status="open",
            details=(
                f"Monitoring signal {signal.id} severity={severity_norm}. "
                f"Remediation candidates: {len(remediation_candidates or [])}"
            ),
        )
        db.add(alert)
        db.flush()
        generate_from_drift_alert(
            db,
            alert=alert,
            severity=severity_norm,
            ai_tool=drift_ai_tool or "monitoring_signal_ingest",
            evidence_node_ids=[signal_node.id],
            related_control_ids=controls,
        )
        from app.services.simulation_scheduler_service import schedule_for_connector_drift_event

        schedule_for_connector_drift_event(
            db,
            tenant_id=tenant_id,
            ai_system_id=alert.ai_system_id,
            related_control_ids=controls,
            drift_alert_id=alert.id,
            actor_user_id=actor_user_id,
        )

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="system",
        action="monitoring.signal.ingest",
        resource_type="monitoring_signal",
        resource_id=signal.id,
        payload={
            "signal_type": signal_type,
            "severity": severity_norm,
            "ai_system_id": ai_system_id,
            "evidence_node_id": signal_node.id,
            "related_control_ids": controls,
            "remediation_candidates": remediation_candidates,
        },
    )

    try:
        from app.services.remediation import propose_remediation_from_monitoring_signal

        remediation_source_trigger: str | None = None
        signal_type_norm = str(signal_type or "").strip().lower()
        if retroactive_policy_payload and not ai_system_id and ".ai_usage" in signal_type_norm:
            remediation_source_trigger = "shadow_ai_detection"
        elif control_drift_detected or connector_risk_exposed:
            remediation_source_trigger = "drift_alert"
        propose_remediation_from_monitoring_signal(
            db,
            signal=signal,
            source_trigger_type=remediation_source_trigger,
            context={
                "reason_code": str(payload_dict.get("reason_code") or signal_type),
                "related_control_ids": controls,
                "evidence_node_ids": list((signal.payload or {}).get("evidence_node_ids") or []),
                "connector_id": str(payload_dict.get("connector_id") or ""),
                "ticket_system": str((payload_dict.get("ticket") or {}).get("system") or payload_dict.get("ticket_system") or "jira"),
                "ai_tool": str(retroactive_policy_payload.get("ai_tool") or payload_dict.get("ai_tool") or ""),
                "provider_key": str(retroactive_policy_payload.get("provider_key") or payload_dict.get("provider_key") or ""),
                "source_surfaces": [str(payload_dict.get("source_surface") or "connector")],
                "control_drift_detected": control_drift_detected,
                "connector_risk_exposed": connector_risk_exposed,
                "missing_evidence_detected": missing_evidence_detected,
                "require_revalidation": missing_evidence_detected,
                "disable_high_risk_actions": connector_risk_exposed,
            },
        )
    except Exception as exc:  # pragma: no cover - remediation layer must not block monitoring ingestion
        log_structured(
            "monitoring_remediation_proposal_failed",
            module="monitoring_service",
            tenant_id=tenant_id,
            signal_id=signal.id,
            signal_type=signal_type,
            error=str(exc),
        )

    if forward_to_runtime_intelligence:
        try:
            from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_connector_signal

            ingest_from_connector_signal(db, signal=signal, evidence_node_id=signal_node.id)
        except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
            if isinstance(exc, CanonicalProjectionError):
                raise
            log_structured(
                "runtime_intelligence_ingest_failed",
                module="monitoring_service",
                tenant_id=tenant_id,
                signal_type=signal_type,
                correlation_id=None,
                error=str(exc),
            )

    try:
        from app.services.surface_control_plane_service import ingest_surface_event

        surface_event = _build_surface_event_from_monitoring_signal(
            signal_type=signal_type,
            severity=severity_norm,
            payload=normalized_payload,
        )
        if surface_event is not None:
            surface_out = ingest_surface_event(
                db,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                event=surface_event,
            )
            surface_payload = dict(normalized_payload)
            surface_payload["surface_control_plane"] = {
                "ingested": True,
                "runtime_event_id": surface_out.get("runtime_event_id"),
                "audit_action_id": surface_out.get("audit_action_id"),
                "alert_id": surface_out.get("alert_id"),
                "decision": surface_out.get("decision"),
                "policy_triggered": surface_out.get("policy_triggered"),
            }
            signal.payload = surface_payload
            db.flush()
    except Exception as exc:  # pragma: no cover - surface control enrichment must not break monitoring ingestion
        log_structured(
            "monitoring_surface_control_forward_failed",
            module="monitoring_service",
            tenant_id=tenant_id,
            signal_id=signal.id,
            signal_type=signal_type,
            error=str(exc),
        )

    return signal


def evaluate_scheduled_monitoring_remediation(
    db: Session,
    *,
    tenant_id: str,
    lookback_minutes: int = 120,
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(minutes=max(15, int(lookback_minutes)))
    rows = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.created_at >= since,
            MonitoringSignal.signal_type.notilike("remediation.lifecycle.%"),
        )
        .order_by(desc(MonitoringSignal.created_at))
    ).all()

    evaluated = 0
    remediations_evaluated = 0
    last_evaluated_signal_id: str | None = None
    now = datetime.now(timezone.utc)
    cooldown_minutes = max(15, int(max(lookback_minutes // 2, 30)))

    for signal in rows:
        signal_type_norm = str(signal.signal_type or "").strip().lower()
        if signal_type_norm.startswith("remediation.lifecycle."):
            continue

        payload = dict(signal.payload or {}) if isinstance(signal.payload, dict) else {}
        retroactive_policy_payload = dict(payload.get("retroactive_policy") or {})
        retroactive_unknown_ai = bool(retroactive_policy_payload) and not bool(signal.ai_system_id) and ".ai_usage" in signal_type_norm
        control_drift_detected = _is_drift_signal(signal_type=signal.signal_type, payload=payload)
        connector_risk_exposed = _is_connector_risk_signal(signal_type=signal.signal_type, severity=signal.severity, payload=payload)
        missing_evidence_detected = _is_missing_evidence_signal(signal_type=signal.signal_type, payload=payload)

        should_evaluate = retroactive_unknown_ai or control_drift_detected or connector_risk_exposed or missing_evidence_detected
        if not should_evaluate:
            continue

        last_eval_at = _parse_iso_datetime(payload.get("last_remediation_evaluated_at"))
        if last_eval_at and (now - last_eval_at) < timedelta(minutes=cooldown_minutes):
            continue

        evaluated += 1
        last_evaluated_signal_id = signal.id
        try:
            from app.services.remediation import propose_remediation_from_monitoring_signal

            trigger_override: str | None = None
            if retroactive_unknown_ai:
                trigger_override = "shadow_ai_detection"
            elif control_drift_detected or connector_risk_exposed:
                trigger_override = "drift_alert"

            propose_remediation_from_monitoring_signal(
                db,
                signal=signal,
                source_trigger_type=trigger_override,
                context={
                    "reason_code": str(payload.get("reason_code") or signal.signal_type),
                    "related_control_ids": list(payload.get("related_control_ids") or []),
                    "evidence_node_ids": list(payload.get("evidence_node_ids") or []),
                    "connector_id": str(payload.get("connector_id") or ""),
                    "ticket_system": str((payload.get("ticket") or {}).get("system") or payload.get("ticket_system") or "jira"),
                    "ai_tool": str(retroactive_policy_payload.get("ai_tool") or payload.get("ai_tool") or ""),
                    "provider_key": str(retroactive_policy_payload.get("provider_key") or payload.get("provider_key") or ""),
                    "source_surfaces": [str(payload.get("source_surface") or "connector")],
                    "control_drift_detected": control_drift_detected,
                    "connector_risk_exposed": connector_risk_exposed,
                    "missing_evidence_detected": missing_evidence_detected,
                    "require_revalidation": missing_evidence_detected,
                    "disable_high_risk_actions": connector_risk_exposed,
                    "scheduled_recheck": True,
                },
            )
            remediations_evaluated += 1
            payload["last_remediation_evaluated_at"] = now.isoformat()
            signal.payload = payload
        except Exception as exc:  # pragma: no cover - periodic remediation evaluation is non-blocking
            log_structured(
                "monitoring_remediation_evaluation_failed",
                module="monitoring_service",
                tenant_id=tenant_id,
                signal_id=signal.id,
                signal_type=signal.signal_type,
                error=str(exc),
            )

    if remediations_evaluated > 0:
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="system",
            action="monitoring.remediation.evaluate",
            resource_type="monitoring_signal",
            resource_id=str(last_evaluated_signal_id or "scheduled_remediation_evaluation"),
            payload={
                "lookback_minutes": int(max(15, lookback_minutes)),
                "signals_evaluated": evaluated,
                "remediations_evaluated": remediations_evaluated,
            },
        )

    return {
        "lookback_minutes": int(max(15, lookback_minutes)),
        "signals_scanned": len(rows),
        "signals_evaluated": evaluated,
        "remediations_evaluated": remediations_evaluated,
    }


def run_connector_once(
    db: Session,
    *,
    tenant_id: str,
    connector: Connector,
    destination_policy: OutboundDestinationPolicy | None = None,
) -> list[MonitoringSignal]:
    if connector.tenant_id != tenant_id:
        raise ValueError("Connector not found for tenant")

    now = datetime.now(timezone.utc)
    connector.last_run_at = now
    generated: list[MonitoringSignal] = []
    connector_config = dict(connector.config or {})
    provider_key = connector.provider_key or connector.connector_type
    policy = validate_monitoring_connector_destination(
        provider_key=provider_key,
        connector_config=connector_config,
        destination_policy=destination_policy,
    )
    secrets = decrypt_connector_secrets(connector.encrypted_secrets)

    from app.services.connector_activity import connector_scope

    with connector_scope(tenant_id=tenant_id, connector=connector.name or provider_key, connector_id=connector.id):
        pull_result = run_provider_pull(
            provider_key=provider_key,
            connector_config=connector_config,
            secrets=secrets,
            destination_policy=policy,
        )

    pull_root = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="connector_pull",
        signal_type=f"connector.{provider_key}.pull",
        label=f"Connector pull {connector.name}",
        payload={
            "connector_id": connector.id,
            "connector_name": connector.name,
            "provider_key": provider_key,
            "started_at": now.isoformat(),
            "pull_status": pull_result.status,
        },
    )

    connector.is_stub = bool(pull_result.is_stub)
    connector.stub_reason = pull_result.stub_reason or ""
    connector.last_pull_status = pull_result.status
    connector.last_pull_error = pull_result.error
    connector.last_signal_count = len(pull_result.normalized_signals)

    if pull_result.status == "success":
        connector.status = "active"
    elif pull_result.status == "stub":
        connector.status = "stub"
    else:
        connector.status = "degraded"

    health_severity = (
        "low"
        if pull_result.status == "success"
        else ("med" if pull_result.status == "stub" else "high")
    )
    health_signal = ingest_monitoring_signal(
        db,
        tenant_id=tenant_id,
        ai_system_id=None,
        signal_type=f"integration.health.{provider_key}",
        severity=health_severity,
        payload={
            "provider_key": provider_key,
            "connector_id": connector.id,
            "connector_name": connector.name,
            "pull_status": pull_result.status,
            "is_stub": bool(pull_result.is_stub),
            "stub_reason": pull_result.stub_reason or "",
            "pull_error": pull_result.error,
            "normalized_signal_count": len(pull_result.normalized_signals),
            "observed_at": now.isoformat(),
        },
        actor_user_id=None,
        create_default_drift_alert=pull_result.status == "error",
        drift_title=f"Connector health degraded: {connector.name}",
        related_control_ids=[],
        forward_to_runtime_intelligence=True,
    )
    generated.append(health_signal)

    for normalized in pull_result.normalized_signals:
        signal = ingest_monitoring_signal(
            db,
            tenant_id=tenant_id,
            ai_system_id=None,
            signal_type=normalized.signal_type,
            severity=normalized.severity,
            payload={
                **normalized.payload,
                "connector_id": connector.id,
                "connector_name": connector.name,
            },
            actor_user_id=None,
            create_default_drift_alert=False,
        )
        generated.append(signal)

        node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="integration_signal",
            signal_type=normalized.evidence_signal_type,
            label=f"{connector.name}: {normalized.signal_type}",
            payload={
                "connector_id": connector.id,
                "monitoring_signal_id": signal.id,
                "control_id": normalized.control_id,
                "severity": normalized.severity,
                "provider_key": provider_key,
                "source_metadata": normalized.payload.get("source_metadata", {}),
                "observed_at": normalized.payload.get("observed_at"),
            },
        )
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=pull_root.id,
            to_node_id=node.id,
            edge_type="generated",
            payload={"monitoring_signal_id": signal.id},
        )

        drift = DriftAlert(
            tenant_id=tenant_id,
            ai_system_id=None,
            title=normalized.drift_title,
            status="open",
            details=f"Connector {connector.name} generated {normalized.signal_type} mapped to {normalized.control_id}",
        )
        db.add(drift)
        db.flush()
        generate_from_drift_alert(
            db,
            alert=drift,
            severity=normalized.severity,
            ai_tool=provider_key,
            evidence_node_ids=[node.id],
            related_control_ids=[normalized.control_id],
        )
        from app.services.simulation_scheduler_service import schedule_for_connector_drift_event

        schedule_for_connector_drift_event(
            db,
            tenant_id=tenant_id,
            ai_system_id=drift.ai_system_id,
            related_control_ids=[normalized.control_id],
            drift_alert_id=drift.id,
            actor_user_id=None,
        )

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="monitoring.connector.pull",
        resource_type="connector",
        resource_id=connector.id,
        payload={
            "provider_key": provider_key,
            "status": pull_result.status,
            "is_stub": pull_result.is_stub,
            "stub_reason": pull_result.stub_reason,
            "error": pull_result.error,
            "pulled_count": pull_result.pulled_count,
            "normalized_signal_count": len(pull_result.normalized_signals),
            "evidence_root_id": pull_root.id,
        },
    )

    db.flush()
    return generated


def list_active_connectors(db: Session, *, tenant_id: str) -> list[Connector]:
    return db.scalars(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.enabled.is_(True),
            Connector.status.in_(["active", "stub", "degraded"]),
        )
    ).all()


def connector_catalog() -> list[dict[str, Any]]:
    return list_provider_catalog()


def consume_runtime_intelligence_outputs(
    db: Session,
    *,
    tenant_id: str,
    lookback_minutes: int = 75,
    actor_user_id: str | None = None,
) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(minutes=max(5, int(lookback_minutes)))

    existing_runtime_signals = db.scalars(
        select(MonitoringSignal).where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("runtime_intelligence.%"),
            MonitoringSignal.created_at >= since,
        )
    ).all()
    seen_finding_ids: set[str] = set()
    seen_trigger_ids: set[str] = set()
    seen_recommendation_ids: set[str] = set()
    for signal in existing_runtime_signals:
        payload = dict(signal.payload or {}) if isinstance(signal.payload, dict) else {}
        finding_id = str(payload.get("runtime_finding_id") or "").strip()
        trigger_id = str(payload.get("runtime_trigger_id") or "").strip()
        recommendation_id = str(payload.get("runtime_recommendation_id") or "").strip()
        if finding_id:
            seen_finding_ids.add(finding_id)
        if trigger_id:
            seen_trigger_ids.add(trigger_id)
        if recommendation_id:
            seen_recommendation_ids.add(recommendation_id)

    finding_rows = db.scalars(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.finding_type.in_(sorted(RUNTIME_FINDING_TYPES)),
            Finding.updated_at >= since,
        )
    ).all()
    trigger_rows = db.scalars(
        select(RuntimeSimulationTrigger).where(
            RuntimeSimulationTrigger.tenant_id == tenant_id,
            RuntimeSimulationTrigger.updated_at >= since,
        )
    ).all()
    recommendation_rows = db.scalars(
        select(RuntimeGovernanceRecommendation).where(
            RuntimeGovernanceRecommendation.tenant_id == tenant_id,
            RuntimeGovernanceRecommendation.created_at >= since,
        )
    ).all()

    ingested_findings = 0
    ingested_triggers = 0
    ingested_recommendations = 0

    for finding in finding_rows:
        finding_id = str(finding.finding_id or "").strip()
        if not finding_id or finding_id in seen_finding_ids:
            continue
        signal = ingest_monitoring_signal(
            db,
            tenant_id=tenant_id,
            ai_system_id=finding.ai_system_id,
            signal_type=f"runtime_intelligence.finding.{finding.finding_type}",
            severity=_normalized_severity(finding.severity),
            payload={
                "source": "runtime_intelligence",
                "runtime_finding_id": finding.finding_id,
                "finding_type": finding.finding_type,
                "reason_code": finding.finding_type,
                "risk_category": finding.risk_category,
                "status": finding.status,
                "occurrence_count": finding.occurrence_count,
                "recommended_action": finding.recommended_action,
                "related_control_ids": list(finding.related_control_ids or []),
                "evidence_node_ids": list(finding.evidence_node_ids or []),
                "last_seen_at": finding.last_seen_at.isoformat() if finding.last_seen_at else None,
            },
            actor_user_id=actor_user_id,
            create_default_drift_alert=_severity_rank(finding.severity) >= _severity_rank("high"),
            drift_title=f"Runtime finding: {finding.finding_type}",
            drift_ai_tool=finding.ai_tool or "runtime_intelligence",
            related_control_ids=list(finding.related_control_ids or []),
            forward_to_runtime_intelligence=False,
        )
        seen_finding_ids.add(finding_id)
        ingested_findings += 1
        log_structured(
            "monitoring_runtime_finding_consumed",
            module="monitoring_service",
            tenant_id=tenant_id,
            signal_type=signal.signal_type,
            correlation_id=None,
            runtime_finding_id=finding_id,
        )

    for trigger in trigger_rows:
        trigger_id = str(trigger.trigger_id or "").strip()
        if not trigger_id or trigger_id in seen_trigger_ids:
            continue
        ingest_monitoring_signal(
            db,
            tenant_id=tenant_id,
            ai_system_id=trigger.ai_system_id,
            signal_type=f"runtime_intelligence.trigger.{trigger.reason_code}",
            severity="high" if str(trigger.status or "").lower() in {"pending", "scheduled"} else "med",
            payload={
                "source": "runtime_intelligence",
                "runtime_trigger_id": trigger.trigger_id,
                "reason_code": trigger.reason_code,
                "target_pack": trigger.target_pack,
                "status": trigger.status,
                "recommended_action": trigger.recommended_action,
                "related_control_ids": list(trigger.related_control_ids or []),
                "evidence_node_ids": list(trigger.evidence_node_ids or []),
                "schedule_decision_id": trigger.schedule_decision_id,
            },
            actor_user_id=actor_user_id,
            create_default_drift_alert=False,
            related_control_ids=list(trigger.related_control_ids or []),
            forward_to_runtime_intelligence=False,
        )
        seen_trigger_ids.add(trigger_id)
        ingested_triggers += 1

    for recommendation in recommendation_rows:
        recommendation_id = str(recommendation.recommendation_id or "").strip()
        if not recommendation_id or recommendation_id in seen_recommendation_ids:
            continue
        rec_payload = dict(recommendation.payload or {})
        rec_controls = [str(control_id).strip() for control_id in (rec_payload.get("related_control_ids") or []) if str(control_id).strip()]
        rec_evidence = [str(node_id).strip() for node_id in (rec_payload.get("evidence_node_ids") or []) if str(node_id).strip()]
        severity = _priority_to_severity(recommendation.priority)
        ingest_monitoring_signal(
            db,
            tenant_id=tenant_id,
            ai_system_id=recommendation.ai_system_id,
            signal_type=f"runtime_intelligence.recommendation.{recommendation.recommendation_type}",
            severity=severity,
            payload={
                "source": "runtime_intelligence",
                "runtime_recommendation_id": recommendation.recommendation_id,
                "event_id": recommendation.event_id,
                "recommendation_type": recommendation.recommendation_type,
                "reason_code": recommendation.reason_code,
                "priority": recommendation.priority,
                "status": recommendation.status,
                "related_control_ids": rec_controls,
                "evidence_node_ids": rec_evidence,
                "payload": rec_payload,
            },
            actor_user_id=actor_user_id,
            create_default_drift_alert=severity in {"high", "critical"},
            drift_title=f"Runtime recommendation: {recommendation.recommendation_type}",
            related_control_ids=rec_controls,
            forward_to_runtime_intelligence=False,
        )
        seen_recommendation_ids.add(recommendation_id)
        ingested_recommendations += 1

    db.flush()
    return {
        "lookback_minutes": int(max(5, lookback_minutes)),
        "runtime_findings_scanned": len(finding_rows),
        "runtime_triggers_scanned": len(trigger_rows),
        "runtime_recommendations_scanned": len(recommendation_rows),
        "ingested_runtime_findings": ingested_findings,
        "ingested_runtime_triggers": ingested_triggers,
        "ingested_runtime_recommendations": ingested_recommendations,
    }


def connector_control_coverage(
    db: Session,
    *,
    tenant_id: str,
    provider_key: str | None = None,
) -> list[dict[str, Any]]:
    coverage_rows = list_connector_signal_coverage(provider_key=provider_key)
    if not coverage_rows:
        return []

    mapped_signal_types = sorted(
        {
            str(row.get("signal_type") or "").strip()
            for row in coverage_rows
            if str(row.get("signal_type") or "").strip()
        }
    )
    # Coverage needs counts and timestamps, not the potentially large JSON payloads.
    # Keep this aggregation in SQL so API requests and scheduled workers cannot
    # hydrate the complete telemetry/evidence history into process memory.
    signal_rows = db.execute(
        select(
            MonitoringSignal.signal_type,
            func.count(MonitoringSignal.id),
            func.max(MonitoringSignal.created_at),
        )
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.in_(mapped_signal_types),
        )
        .group_by(MonitoringSignal.signal_type)
    ).all()
    signal_stats: dict[str, dict[str, Any]] = {
        str(signal_type): {"count": int(count or 0), "last_seen_at": last_seen_at}
        for signal_type, count, last_seen_at in signal_rows
    }

    connector_key = func.coalesce(
        func.nullif(Connector.provider_key, ""),
        Connector.connector_type,
    )
    connector_rows = db.execute(
        select(
            connector_key.label("provider_key"),
            func.count(Connector.id),
            func.sum(case((Connector.enabled.is_(True), 1), else_=0)),
        )
        .where(Connector.tenant_id == tenant_id)
        .group_by(connector_key)
    ).all()
    connector_stats: dict[str, dict[str, int]] = {
        str(provider_key): {
            "connector_count": int(connector_count or 0),
            "enabled_connector_count": int(enabled_count or 0),
        }
        for provider_key, connector_count, enabled_count in connector_rows
    }

    control_ids = sorted({str(row.get("control_id") or "").strip() for row in coverage_rows if str(row.get("control_id") or "").strip()})
    frameworks_by_control: dict[str, list[str]] = {}
    if control_ids:
        framework_rows = db.execute(
            select(KBControl.id, KBFramework.name)
            .join(KBFramework, KBFramework.id == KBControl.framework_id)
            .where(KBControl.id.in_(control_ids))
        ).all()
        for control_id, framework_name in framework_rows:
            frameworks_by_control.setdefault(str(control_id), [])
            frameworks_by_control[str(control_id)].append(str(framework_name))
        for control_id, names in frameworks_by_control.items():
            frameworks_by_control[control_id] = sorted({name.strip() for name in names if name.strip()})

    evidence_signal_types = sorted(
        {
            str(row.get("evidence_signal_type") or "").strip()
            for row in coverage_rows
            if str(row.get("evidence_signal_type") or "").strip()
        }
    )
    evidence_stats: dict[str, dict[str, Any]] = {}
    if evidence_signal_types:
        evidence_rows = db.execute(
            select(
                EvidenceNode.signal_type,
                func.count(EvidenceNode.id),
                func.max(EvidenceNode.created_at),
            ).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.signal_type.in_(evidence_signal_types),
            ).group_by(EvidenceNode.signal_type)
        ).all()
        evidence_stats = {
            str(signal_type): {"count": int(count or 0), "last_seen_at": last_seen_at}
            for signal_type, count, last_seen_at in evidence_rows
        }

    enriched: list[dict[str, Any]] = []
    for row in coverage_rows:
        stats = signal_stats.get(row["signal_type"], {"count": 0, "last_seen_at": None})
        provider_stats = connector_stats.get(row["provider_key"], {"connector_count": 0, "enabled_connector_count": 0})
        framework_names = frameworks_by_control.get(str(row.get("control_id") or "").strip(), [])
        evidence = evidence_stats.get(str(row.get("evidence_signal_type") or "").strip(), {"count": 0, "last_seen_at": None})
        enriched.append(
            {
                **row,
                "observed_count": int(stats["count"]),
                "last_seen_at": stats["last_seen_at"],
                "connector_count": int(provider_stats["connector_count"]),
                "enabled_connector_count": int(provider_stats["enabled_connector_count"]),
                "framework_names": framework_names,
                "live_evidence_count": int(evidence["count"]),
                "live_evidence_last_seen_at": evidence["last_seen_at"],
                "has_live_evidence": bool(int(evidence["count"]) > 0),
            }
        )
    return enriched


def connector_coverage_summary(
    db: Session,
    *,
    tenant_id: str,
    provider_key: str | None = None,
) -> dict[str, Any]:
    rows = connector_control_coverage(db, tenant_id=tenant_id, provider_key=provider_key)
    if not rows:
        return {
            "total_signal_rows": 0,
            "controls_covered": 0,
            "frameworks_with_live_evidence": 0,
            "signals_with_live_evidence": 0,
            "control_signal_map": [],
            "framework_live_evidence": [],
        }

    controls: dict[str, dict[str, Any]] = {}
    frameworks: dict[str, dict[str, Any]] = {}
    signals_with_live_evidence = 0

    for row in rows:
        control_id = str(row.get("control_id") or "").strip()
        signal_type = str(row.get("signal_type") or "").strip()
        provider = str(row.get("provider_key") or "").strip()
        live_count = int(row.get("live_evidence_count") or 0)
        live_last_seen = row.get("live_evidence_last_seen_at")
        framework_names = [str(name).strip() for name in (row.get("framework_names") or []) if str(name).strip()]

        if live_count > 0:
            signals_with_live_evidence += 1

        if control_id:
            control_bucket = controls.setdefault(
                control_id,
                {
                    "control_id": control_id,
                    "framework_names": set(),
                    "signal_types": set(),
                    "providers": set(),
                    "live_evidence_count": 0,
                    "last_evidence_at": None,
                },
            )
            control_bucket["signal_types"].add(signal_type)
            control_bucket["providers"].add(provider)
            control_bucket["live_evidence_count"] += live_count
            if live_last_seen and (
                control_bucket["last_evidence_at"] is None
                or live_last_seen > control_bucket["last_evidence_at"]
            ):
                control_bucket["last_evidence_at"] = live_last_seen
            for name in framework_names:
                control_bucket["framework_names"].add(name)

        for name in framework_names:
            framework_bucket = frameworks.setdefault(
                name,
                {
                    "framework_name": name,
                    "control_ids": set(),
                    "signal_types": set(),
                    "live_evidence_count": 0,
                    "last_evidence_at": None,
                },
            )
            if control_id:
                framework_bucket["control_ids"].add(control_id)
            framework_bucket["signal_types"].add(signal_type)
            framework_bucket["live_evidence_count"] += live_count
            if live_last_seen and (
                framework_bucket["last_evidence_at"] is None
                or live_last_seen > framework_bucket["last_evidence_at"]
            ):
                framework_bucket["last_evidence_at"] = live_last_seen

    control_signal_map = sorted(
        [
            {
                "control_id": bucket["control_id"],
                "framework_names": sorted(bucket["framework_names"]),
                "signal_types": sorted(bucket["signal_types"]),
                "providers": sorted(bucket["providers"]),
                "live_evidence_count": int(bucket["live_evidence_count"]),
                "last_evidence_at": bucket["last_evidence_at"],
            }
            for bucket in controls.values()
        ],
        key=lambda row: row["control_id"],
    )
    framework_live_evidence = sorted(
        [
            {
                "framework_name": bucket["framework_name"],
                "control_count": len(bucket["control_ids"]),
                "signal_count": len(bucket["signal_types"]),
                "live_evidence_count": int(bucket["live_evidence_count"]),
                "last_evidence_at": bucket["last_evidence_at"],
            }
            for bucket in frameworks.values()
        ],
        key=lambda row: row["framework_name"],
    )

    return {
        "total_signal_rows": len(rows),
        "controls_covered": len(controls),
        "frameworks_with_live_evidence": len([row for row in framework_live_evidence if int(row["live_evidence_count"]) > 0]),
        "signals_with_live_evidence": signals_with_live_evidence,
        "control_signal_map": control_signal_map,
        "framework_live_evidence": framework_live_evidence,
    }
