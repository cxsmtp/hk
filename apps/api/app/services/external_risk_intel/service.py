from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db.models.external_risk import (
    ExternalRiskAssetMapping,
    ExternalRiskImpact,
    ExternalRiskRecord,
    ExternalRiskSource,
    ExternalRiskSyncRun,
    RiskTriggeredSimulationRecommendation,
)
from app.db.models.monitoring import MonitoringSignal
from app.services.audit_service import write_audit_log
from app.services.external_risk_intel.correlation_engine import correlate_risk_record
from app.services.external_risk_intel.normalization import normalize_source_records
from app.services.external_risk_intel.simulation_triggering import recommend_simulations
from app.services.external_risk_intel.source_connector import (
    DEFAULT_SOURCE_ENDPOINTS,
    ExternalFeedFetchError,
    fetch_source_records,
)
from app.services.outbound_destination_policy import canonical_origin
from app.services.external_risk_intel.transport_security import validate_transport_security
from app.services.monitoring_service import ingest_monitoring_signal


SOURCE_LABELS: dict[str, str] = {
    "nvd": "NVD",
    "mitre": "MITRE CVE",
    "cisa_kev": "CISA KEV",
    "github": "GitHub Advisory Database",
    "osv": "OSV",
}
DEFAULT_SOURCE_FETCH_TIMEOUT_SECONDS = 8.0
STALE_SYNC_TIMEOUT_MINUTES = 15


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _mark_stale_running_syncs(
    db: Session,
    *,
    tenant_id: str,
    stale_after_minutes: int = STALE_SYNC_TIMEOUT_MINUTES,
) -> int:
    stale_after = max(1, int(stale_after_minutes))
    now = _utcnow()
    cutoff = now - timedelta(minutes=stale_after)
    rows = db.scalars(
        select(ExternalRiskSyncRun).where(
            ExternalRiskSyncRun.tenant_id == tenant_id,
            ExternalRiskSyncRun.status == "running",
            ExternalRiskSyncRun.started_at <= cutoff,
        )
    ).all()

    for row in rows:
        trace_payload = dict(row.trace_payload or {})
        trace_payload["stale_marked_at"] = now.isoformat()
        trace_payload["stale_timeout_minutes"] = stale_after
        row.status = "failed"
        row.completed_at = row.completed_at or now
        row.error_message = row.error_message or "stale_running_sync_timeout"
        row.trace_payload = trace_payload

    if rows:
        db.flush()
    return len(rows)


def _severity_rank(value: str | None) -> int:
    token = str(value or "med").strip().lower()
    order = {"low": 1, "med": 2, "medium": 2, "high": 3, "critical": 4}
    return int(order.get(token, 2))


def _normalize_severity(value: str | None) -> str:
    token = str(value or "med").strip().lower()
    if token == "medium":
        return "med"
    if token in {"low", "med", "high", "critical"}:
        return token
    return "med"


def _default_transport_policy(host: str) -> dict[str, Any]:
    return {
        "minimum_tls_version": "TLSv1.3",
        "allow_tls12_fallback": True,
        "allow_system_trust_store_fallback": True,
        "require_mtls": False,
        "pinned_certificate_sha256": [],
        "host": host,
    }


def ensure_default_sources(db: Session, *, tenant_id: str) -> list[ExternalRiskSource]:
    existing = db.scalars(select(ExternalRiskSource).where(ExternalRiskSource.tenant_id == tenant_id)).all()
    existing_by_source = {str(row.source).strip().lower(): row for row in existing}

    created = False
    for source, endpoint in DEFAULT_SOURCE_ENDPOINTS.items():
        if source in existing_by_source:
            continue
        host = endpoint.split("//", 1)[-1].split("/", 1)[0]
        row = ExternalRiskSource(
            tenant_id=tenant_id,
            source=source,
            display_name=SOURCE_LABELS.get(source, source.upper()),
            enabled=True,
            endpoint_url=endpoint,
            auth_mode="none",
            auth_config={},
            source_trust_policy={"require_integrity_signature": False},
            egress_policy={"allowed_hosts": [host.lower()]},
            redaction_policy={"send_raw_payloads": False, "redact_fields": ["tenant_id", "user_id", "prompt", "secret"]},
            routing_policy={"external_analysis_mode": "summary_only"},
            transport_policy=_default_transport_policy(host),
            sync_schedule="0 */6 * * *",
            last_sync_status="never",
        )
        db.add(row)
        created = True

    if created:
        db.flush()
    return db.scalars(select(ExternalRiskSource).where(ExternalRiskSource.tenant_id == tenant_id).order_by(ExternalRiskSource.source)).all()


def list_sources(db: Session, *, tenant_id: str) -> list[ExternalRiskSource]:
    ensure_default_sources(db, tenant_id=tenant_id)
    return db.scalars(
        select(ExternalRiskSource)
        .where(ExternalRiskSource.tenant_id == tenant_id)
        .order_by(ExternalRiskSource.source)
    ).all()


def upsert_source(db: Session, *, tenant_id: str, payload: dict[str, Any]) -> ExternalRiskSource:
    source = str(payload.get("source") or "").strip().lower()
    if not source:
        raise ValueError("source_required")

    endpoint = str(payload.get("endpoint_url") or "").strip()
    if not endpoint:
        endpoint = DEFAULT_SOURCE_ENDPOINTS.get(source, "")
    if not endpoint:
        raise ValueError("endpoint_url_required")

    existing = db.scalar(
        select(ExternalRiskSource).where(
            ExternalRiskSource.tenant_id == tenant_id,
            ExternalRiskSource.source == source,
        )
    )
    endpoint_origin_changed = bool(
        existing is not None
        and canonical_origin(str(existing.endpoint_url)) != canonical_origin(endpoint)
    )
    explicitly_rebound_auth = "auth_config" in payload and bool(payload.get("auth_config"))

    row = existing or ExternalRiskSource(
        tenant_id=tenant_id,
        source=source,
        display_name=SOURCE_LABELS.get(source, source.upper()),
        endpoint_url=endpoint,
        auth_mode="none",
        auth_config={},
        source_trust_policy={},
        egress_policy={},
        redaction_policy={},
        routing_policy={},
        transport_policy={},
        sync_schedule="0 */6 * * *",
        enabled=True,
    )

    row.display_name = str(payload.get("display_name") or row.display_name or SOURCE_LABELS.get(source, source.upper()))
    row.enabled = bool(payload.get("enabled", row.enabled))
    row.endpoint_url = endpoint
    row.auth_mode = str(payload.get("auth_mode") or row.auth_mode or "none").strip().lower()
    row.auth_config = dict(payload.get("auth_config") or row.auth_config or {})
    if endpoint_origin_changed and not explicitly_rebound_auth:
        row.auth_mode = "none"
        row.auth_config = {}
    row.source_trust_policy = dict(payload.get("source_trust_policy") or row.source_trust_policy or {})
    row.egress_policy = dict(payload.get("egress_policy") or row.egress_policy or {})
    row.redaction_policy = dict(payload.get("redaction_policy") or row.redaction_policy or {})
    row.routing_policy = dict(payload.get("routing_policy") or row.routing_policy or {})

    host = endpoint.split("//", 1)[-1].split("/", 1)[0]
    merged_transport = dict(_default_transport_policy(host))
    merged_transport.update(dict(row.transport_policy or {}))
    merged_transport.update(dict(payload.get("transport_policy") or {}))
    row.transport_policy = merged_transport

    if "sync_schedule" in payload:
        row.sync_schedule = str(payload.get("sync_schedule") or row.sync_schedule or "0 */6 * * *")

    policy_check = validate_transport_security(
        endpoint_url=row.endpoint_url,
        transport_policy=row.transport_policy,
        egress_policy=row.egress_policy,
    )
    if not policy_check.allowed:
        raise ValueError(f"transport_policy_failed:{policy_check.reason}")

    if existing is None:
        db.add(row)

    db.flush()
    return row


def _upsert_risk_record(
    db: Session,
    *,
    tenant_id: str,
    source_id: str,
    source: str,
    normalized: dict[str, Any],
) -> tuple[ExternalRiskRecord, bool]:
    row = db.scalar(
        select(ExternalRiskRecord).where(
            ExternalRiskRecord.tenant_id == tenant_id,
            ExternalRiskRecord.source == source,
            ExternalRiskRecord.source_record_id == str(normalized.get("source_record_id") or "").strip(),
        )
    )
    created = row is None
    if row is None:
        row = ExternalRiskRecord(
            tenant_id=tenant_id,
            source_id=source_id,
            source=source,
            source_record_id=str(normalized.get("source_record_id") or "").strip(),
            title=str(normalized.get("title") or "").strip()[:512] or str(normalized.get("source_record_id") or "risk_record"),
            description=str(normalized.get("description") or ""),
            severity=_normalize_severity(normalized.get("severity")),
            cvss_score=normalized.get("cvss_score"),
            exploit_status=str(normalized.get("exploit_status") or "unknown"),
            affected_components=list(normalized.get("affected_components") or []),
            affected_versions=list(normalized.get("affected_versions") or []),
            references=list(normalized.get("references") or []),
            published_at=normalized.get("published_at"),
            source_updated_at=normalized.get("source_updated_at"),
            integrity_status=str(normalized.get("integrity_status") or "partial"),
            ingestion_trace_id=str(normalized.get("ingestion_trace_id") or ""),
            raw_artifact_ref=str(normalized.get("raw_artifact_ref") or "") or None,
            raw_payload_ref=dict(normalized.get("raw_payload_ref") or {}),
        )
        db.add(row)
        db.flush()
        return row, created

    row.source_id = source_id
    row.title = str(normalized.get("title") or row.title)[:512]
    row.description = str(normalized.get("description") or row.description)
    row.severity = _normalize_severity(normalized.get("severity") or row.severity)
    row.cvss_score = normalized.get("cvss_score")
    row.exploit_status = str(normalized.get("exploit_status") or row.exploit_status)
    row.affected_components = list(normalized.get("affected_components") or [])
    row.affected_versions = list(normalized.get("affected_versions") or [])
    row.references = list(normalized.get("references") or [])
    row.published_at = normalized.get("published_at")
    row.source_updated_at = normalized.get("source_updated_at")
    row.integrity_status = str(normalized.get("integrity_status") or row.integrity_status)
    row.ingestion_trace_id = str(normalized.get("ingestion_trace_id") or row.ingestion_trace_id or "")
    row.raw_artifact_ref = str(normalized.get("raw_artifact_ref") or row.raw_artifact_ref or "") or None
    row.raw_payload_ref = dict(normalized.get("raw_payload_ref") or {})
    db.flush()
    return row, created


def _upsert_mapping(
    db: Session,
    *,
    tenant_id: str,
    risk_record_id: str,
    mapping: dict[str, Any],
) -> ExternalRiskAssetMapping:
    row = db.scalar(
        select(ExternalRiskAssetMapping).where(
            ExternalRiskAssetMapping.tenant_id == tenant_id,
            ExternalRiskAssetMapping.risk_record_id == risk_record_id,
            ExternalRiskAssetMapping.asset_type == str(mapping.get("asset_type") or ""),
            ExternalRiskAssetMapping.asset_id == str(mapping.get("asset_id") or ""),
            ExternalRiskAssetMapping.environment == str(mapping.get("environment") or "unknown"),
        )
    )
    if row is None:
        row = ExternalRiskAssetMapping(
            tenant_id=tenant_id,
            risk_record_id=risk_record_id,
            asset_type=str(mapping.get("asset_type") or "unknown"),
            asset_id=str(mapping.get("asset_id") or "unknown"),
            environment=str(mapping.get("environment") or "unknown"),
            confidence=float(mapping.get("confidence") or 0.0),
            mapping_reason=str(mapping.get("mapping_reason") or ""),
            control_ids=list(mapping.get("control_ids") or []),
            simulation_ids=list(mapping.get("simulation_ids") or []),
            mapping_status="auto",
        )
        db.add(row)
        db.flush()
        return row

    row.confidence = float(mapping.get("confidence") or row.confidence or 0.0)
    row.mapping_reason = str(mapping.get("mapping_reason") or row.mapping_reason)
    row.control_ids = sorted({str(item).strip() for item in (mapping.get("control_ids") or row.control_ids or []) if str(item).strip()})
    row.simulation_ids = sorted({str(item).strip() for item in (mapping.get("simulation_ids") or row.simulation_ids or []) if str(item).strip()})
    db.flush()
    return row


def _impact_baseline(asset_type: str, environment: str) -> float:
    base = {
        "ai_system": 260000.0,
        "model_endpoint": 240000.0,
        "connector": 210000.0,
        "agent_runtime": 190000.0,
        "tenant_surface": 175000.0,
    }.get(asset_type, 150000.0)
    env = str(environment or "").lower()
    if env in {"prod", "production"}:
        return base * 1.35
    if env in {"staging", "sandbox"}:
        return base * 0.75
    return base


def _exploit_multiplier(exploit_status: str) -> float:
    token = str(exploit_status or "unknown").strip().lower()
    if token == "known_exploited":
        return 1.6
    if token == "publicly_exploitable":
        return 1.25
    return 1.0


def _likelihood_from_record(*, cvss_score: float | None, exploit_status: str, severity: str, confidence: float) -> float:
    cvss_component = min(max(float(cvss_score or 0.0) / 10.0, 0.0), 1.0)
    exploit_component = {
        "known_exploited": 0.35,
        "publicly_exploitable": 0.22,
        "unknown": 0.1,
    }.get(str(exploit_status or "unknown").strip().lower(), 0.1)
    severity_component = {"critical": 0.25, "high": 0.18, "med": 0.1, "low": 0.05}.get(_normalize_severity(severity), 0.1)
    confidence_component = min(max(float(confidence or 0.0), 0.0), 1.0) * 0.2
    return min(cvss_component * 0.45 + exploit_component + severity_component + confidence_component, 1.0)


def _upsert_impact(
    db: Session,
    *,
    tenant_id: str,
    risk_record: ExternalRiskRecord,
    mapping: ExternalRiskAssetMapping,
) -> ExternalRiskImpact:
    row = db.scalar(
        select(ExternalRiskImpact).where(
            ExternalRiskImpact.tenant_id == tenant_id,
            ExternalRiskImpact.risk_record_id == risk_record.id,
            ExternalRiskImpact.asset_type == mapping.asset_type,
            ExternalRiskImpact.asset_id == mapping.asset_id,
        )
    )

    likelihood = _likelihood_from_record(
        cvss_score=risk_record.cvss_score,
        exploit_status=risk_record.exploit_status,
        severity=risk_record.severity,
        confidence=mapping.confidence,
    )
    impact = _impact_baseline(mapping.asset_type, mapping.environment) * _exploit_multiplier(risk_record.exploit_status)
    frequency = 2.0 if str(risk_record.exploit_status).lower() == "known_exploited" else 1.0
    ale = likelihood * impact * frequency
    residual = max(ale * (1.0 - min(max(mapping.confidence, 0.0), 0.95) * 0.45), 0.0)

    context = {
        "cvss_score": risk_record.cvss_score,
        "severity": risk_record.severity,
        "exploit_status": risk_record.exploit_status,
        "mapping_confidence": mapping.confidence,
        "frequency": frequency,
    }

    if row is None:
        row = ExternalRiskImpact(
            tenant_id=tenant_id,
            risk_record_id=risk_record.id,
            asset_type=mapping.asset_type,
            asset_id=mapping.asset_id,
            likelihood=likelihood,
            impact=impact,
            annualized_loss_expectancy=ale,
            residual_risk=residual,
            rationale="cvss+exploit_status+asset_criticality",
            calculation_context=context,
        )
        db.add(row)
        db.flush()
        return row

    row.likelihood = likelihood
    row.impact = impact
    row.annualized_loss_expectancy = ale
    row.residual_risk = residual
    row.rationale = "cvss+exploit_status+asset_criticality"
    row.calculation_context = context
    db.flush()
    return row


def _upsert_sim_recommendation(
    db: Session,
    *,
    tenant_id: str,
    risk_record: ExternalRiskRecord,
    recommendation: dict[str, Any],
) -> RiskTriggeredSimulationRecommendation:
    row = db.scalar(
        select(RiskTriggeredSimulationRecommendation).where(
            RiskTriggeredSimulationRecommendation.tenant_id == tenant_id,
            RiskTriggeredSimulationRecommendation.risk_record_id == risk_record.id,
        )
    )

    payload = {
        "risk_record_id": risk_record.id,
        "source_record_id": risk_record.source_record_id,
        "severity": risk_record.severity,
        "exploit_status": risk_record.exploit_status,
        "details": recommendation.get("details") or [],
    }

    if row is None:
        row = RiskTriggeredSimulationRecommendation(
            tenant_id=tenant_id,
            risk_record_id=risk_record.id,
            priority=str(recommendation.get("priority") or "high"),
            reason=str(recommendation.get("reason") or ""),
            control_ids=list(recommendation.get("control_ids") or []),
            simulation_ids=list(recommendation.get("simulation_ids") or []),
            status="recommended",
            run_mode="manual",
            approval_required=True,
            recommendation_payload=payload,
        )
        db.add(row)
        db.flush()
        return row

    row.priority = str(recommendation.get("priority") or row.priority)
    row.reason = str(recommendation.get("reason") or row.reason)
    row.control_ids = sorted({str(item).strip() for item in (recommendation.get("control_ids") or row.control_ids or []) if str(item).strip()})
    row.simulation_ids = sorted({str(item).strip() for item in (recommendation.get("simulation_ids") or row.simulation_ids or []) if str(item).strip()})
    row.recommendation_payload = payload
    db.flush()
    return row


def _recent_alert_keys(db: Session, *, tenant_id: str, lookback_hours: int = 72) -> set[tuple[str, str]]:
    since = _utcnow() - timedelta(hours=max(1, int(lookback_hours)))
    rows = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type == "external_risk.risk_record",
            MonitoringSignal.created_at >= since,
        )
        .order_by(desc(MonitoringSignal.created_at))
        .limit(4000)
    ).all()
    keys: set[tuple[str, str]] = set()
    for row in rows:
        payload = dict(row.payload or {}) if isinstance(row.payload, dict) else {}
        key = (str(payload.get("risk_record_id") or ""), str(payload.get("source_updated_at") or ""))
        if key[0]:
            keys.add(key)
    return keys


def _ingest_risk_alert(
    db: Session,
    *,
    tenant_id: str,
    risk_record: ExternalRiskRecord,
    mapping_rows: list[ExternalRiskAssetMapping],
    source: ExternalRiskSource,
    actor_user_id: str | None,
) -> None:
    primary_mapping = max(mapping_rows, key=lambda row: float(row.confidence or 0.0)) if mapping_rows else None
    ai_system_id = primary_mapping.asset_id if primary_mapping and primary_mapping.asset_type == "ai_system" else None
    related_control_ids = sorted(
        {
            str(control_id).strip()
            for mapping in mapping_rows
            for control_id in (mapping.control_ids or [])
            if str(control_id).strip()
        }
    )

    payload = {
        "risk_record_id": risk_record.id,
        "source": risk_record.source,
        "source_record_id": risk_record.source_record_id,
        "exploit_status": risk_record.exploit_status,
        "cvss_score": risk_record.cvss_score,
        "asset_mappings": [
            {
                "asset_type": row.asset_type,
                "asset_id": row.asset_id,
                "environment": row.environment,
                "confidence": row.confidence,
            }
            for row in mapping_rows
        ],
        "source_endpoint": source.endpoint_url,
        "source_updated_at": risk_record.source_updated_at.isoformat() if risk_record.source_updated_at else None,
        "reason_code": "external_risk_correlated",
        "source_surface": "external_risk_intel",
        "provider_key": source.source,
        "related_control_ids": related_control_ids,
    }

    ingest_monitoring_signal(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        signal_type="external_risk.risk_record",
        severity=risk_record.severity,
        payload=payload,
        actor_user_id=actor_user_id,
        create_default_drift_alert=_severity_rank(risk_record.severity) >= _severity_rank("high"),
        drift_title=f"External risk: {risk_record.source_record_id}",
        drift_ai_tool=str(primary_mapping.asset_type if primary_mapping else "external_asset"),
        related_control_ids=related_control_ids,
        forward_to_runtime_intelligence=True,
    )


def _ingest_transport_failure_signal(
    db: Session,
    *,
    tenant_id: str,
    source: ExternalRiskSource,
    reason: str,
    actor_user_id: str | None,
) -> None:
    ingest_monitoring_signal(
        db,
        tenant_id=tenant_id,
        ai_system_id=None,
        signal_type="external_risk.feed_failure",
        severity="high",
        payload={
            "source": source.source,
            "source_id": source.id,
            "reason_code": reason,
            "source_surface": "external_risk_intel",
            "endpoint": source.endpoint_url,
            "transport_policy": source.transport_policy,
            "egress_policy": source.egress_policy,
            "provider_key": source.source,
            "related_control_ids": ["POLICY_ENFORCEMENT_CONTROL", "AI_SYSTEM_INVENTORY_CONTROL"],
        },
        actor_user_id=actor_user_id,
        create_default_drift_alert=True,
        drift_title=f"External risk feed failure: {source.source}",
        drift_ai_tool="external_risk_intel",
        related_control_ids=["POLICY_ENFORCEMENT_CONTROL", "AI_SYSTEM_INVENTORY_CONTROL"],
        forward_to_runtime_intelligence=False,
    )


def run_sync(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    fetcher: Callable[[ExternalRiskSource], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _mark_stale_running_syncs(db, tenant_id=tenant_id)
    sources = [row for row in ensure_default_sources(db, tenant_id=tenant_id) if row.enabled]

    run = ExternalRiskSyncRun(
        tenant_id=tenant_id,
        status="running",
        trace_payload={
            "trigger": "manual",
            "source_count": len(sources),
        },
    )
    db.add(run)
    db.flush()

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="external_risk.sync.start",
        resource_type="external_risk_sync",
        resource_id=run.id,
        payload={"source_count": len(sources)},
    )
    db.flush()
    # Release early write lock (important for SQLite/local demo usage) before external fetch.
    db.commit()
    run = db.get(ExternalRiskSyncRun, run.id) or run

    records_ingested = 0
    mappings_created = 0
    alerts_created = 0
    recommendations_created = 0
    transport_failures = 0
    source_summaries: list[dict[str, Any]] = []
    alert_keys = _recent_alert_keys(db, tenant_id=tenant_id)

    for source in sources:
        run.source_id = source.id
        source_trace_id = f"{run.id}:{source.source}"

        check = validate_transport_security(
            endpoint_url=source.endpoint_url,
            transport_policy=source.transport_policy,
            egress_policy=source.egress_policy,
        )
        if not check.allowed:
            transport_failures += 1
            source.last_sync_status = "failed"
            source.last_sync_error = check.reason
            _ingest_transport_failure_signal(
                db,
                tenant_id=tenant_id,
                source=source,
                reason=check.reason,
                actor_user_id=actor_user_id,
            )
            source_summaries.append(
                {
                    "source": source.source,
                    "status": "failed",
                    "reason": check.reason,
                    "record_count": 0,
                }
            )
            continue

        try:
            feed = fetch_source_records(
                source,
                timeout_seconds=DEFAULT_SOURCE_FETCH_TIMEOUT_SECONDS,
                fetcher=fetcher,
            )
            normalized_rows = normalize_source_records(
                source=source.source,
                records=feed.records,
                ingestion_trace_id=source_trace_id,
            )
            source_record_count = 0

            for normalized in normalized_rows:
                record, _created = _upsert_risk_record(
                    db,
                    tenant_id=tenant_id,
                    source_id=source.id,
                    source=source.source,
                    normalized=normalized,
                )
                source_record_count += 1

                mappings = correlate_risk_record(
                    db,
                    tenant_id=tenant_id,
                    record={
                        "title": record.title,
                        "description": record.description,
                        "affected_components": record.affected_components,
                        "references": record.references,
                    },
                )

                mapping_rows: list[ExternalRiskAssetMapping] = []
                control_ids_union: set[str] = set()
                for mapping in mappings:
                    row = _upsert_mapping(
                        db,
                        tenant_id=tenant_id,
                        risk_record_id=record.id,
                        mapping=mapping,
                    )
                    mapping_rows.append(row)
                    control_ids_union.update(str(item).strip() for item in (row.control_ids or []) if str(item).strip())
                    _upsert_impact(
                        db,
                        tenant_id=tenant_id,
                        risk_record=record,
                        mapping=row,
                    )
                mappings_created += len(mapping_rows)

                recommendation = recommend_simulations(
                    db,
                    tenant_id=tenant_id,
                    control_ids=sorted(control_ids_union),
                    severity=record.severity,
                    exploit_status=record.exploit_status,
                )
                recommendation["control_ids"] = sorted(control_ids_union)
                _upsert_sim_recommendation(
                    db,
                    tenant_id=tenant_id,
                    risk_record=record,
                    recommendation=recommendation,
                )
                recommendations_created += 1

                if _severity_rank(record.severity) >= _severity_rank("high"):
                    alert_key = (
                        record.id,
                        record.source_updated_at.isoformat() if record.source_updated_at else "",
                    )
                    if alert_key not in alert_keys:
                        _ingest_risk_alert(
                            db,
                            tenant_id=tenant_id,
                            risk_record=record,
                            mapping_rows=mapping_rows,
                            source=source,
                            actor_user_id=actor_user_id,
                        )
                        alert_keys.add(alert_key)
                        alerts_created += 1

            records_ingested += source_record_count
            source.last_sync_status = "success"
            source.last_sync_error = None
            source.last_sync_at = _utcnow()
            source_summaries.append(
                {
                    "source": source.source,
                    "status": "success",
                    "reason": "ok",
                    "record_count": source_record_count,
                }
            )
            db.flush()
            db.commit()
        except ExternalFeedFetchError as exc:
            transport_failures += 1
            source.last_sync_status = "failed"
            source.last_sync_error = str(exc)
            _ingest_transport_failure_signal(
                db,
                tenant_id=tenant_id,
                source=source,
                reason=str(exc),
                actor_user_id=actor_user_id,
            )
            source_summaries.append(
                {
                    "source": source.source,
                    "status": "failed",
                    "reason": str(exc),
                    "record_count": 0,
                }
            )
            db.flush()
            db.commit()
        except Exception as exc:  # noqa: BLE001
            # Never fail the full sync on a single-source processing issue.
            transport_failures += 1
            source.last_sync_status = "failed"
            source.last_sync_error = f"source_processing_failed:{type(exc).__name__}:{exc}"
            _ingest_transport_failure_signal(
                db,
                tenant_id=tenant_id,
                source=source,
                reason=f"source_processing_failed:{type(exc).__name__}",
                actor_user_id=actor_user_id,
            )
            source_summaries.append(
                {
                    "source": source.source,
                    "status": "failed",
                    "reason": source.last_sync_error,
                    "record_count": 0,
                }
            )
            db.flush()
            db.commit()

    run.completed_at = _utcnow()
    run.status = "failed" if transport_failures and records_ingested == 0 else "completed"
    run.records_ingested = records_ingested
    run.mappings_created = mappings_created
    run.alerts_created = alerts_created
    run.simulation_recommendations_created = recommendations_created
    run.transport_failures = transport_failures
    run.error_message = "all_sources_failed" if run.status == "failed" else None
    run.trace_payload = {
        "source_summaries": source_summaries,
        "records_ingested": records_ingested,
        "mappings_created": mappings_created,
        "alerts_created": alerts_created,
        "simulation_recommendations_created": recommendations_created,
        "transport_failures": transport_failures,
    }

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="external_risk.sync.complete",
        resource_type="external_risk_sync",
        resource_id=run.id,
        payload=run.trace_payload,
    )

    db.flush()
    db.commit()

    return {
        "sync_id": run.id,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "records_ingested": records_ingested,
        "mappings_created": mappings_created,
        "alerts_created": alerts_created,
        "simulation_recommendations_created": recommendations_created,
        "transport_failures": transport_failures,
        "source_summaries": source_summaries,
    }


def list_records(
    db: Session,
    *,
    tenant_id: str,
    severity: str | None = None,
    limit: int = 200,
) -> list[ExternalRiskRecord]:
    stmt = select(ExternalRiskRecord).where(ExternalRiskRecord.tenant_id == tenant_id)
    if severity:
        stmt = stmt.where(ExternalRiskRecord.severity == _normalize_severity(severity))
    return db.scalars(stmt.order_by(desc(ExternalRiskRecord.source_updated_at), desc(ExternalRiskRecord.updated_at)).limit(max(1, min(limit, 1000)))).all()


def get_record_mappings(db: Session, *, tenant_id: str, risk_record_id: str) -> list[ExternalRiskAssetMapping]:
    return db.scalars(
        select(ExternalRiskAssetMapping)
        .where(
            ExternalRiskAssetMapping.tenant_id == tenant_id,
            ExternalRiskAssetMapping.risk_record_id == risk_record_id,
        )
        .order_by(desc(ExternalRiskAssetMapping.confidence), ExternalRiskAssetMapping.asset_type)
    ).all()


def get_asset_records(db: Session, *, tenant_id: str, asset_id: str) -> list[dict[str, Any]]:
    mappings = db.scalars(
        select(ExternalRiskAssetMapping)
        .where(
            ExternalRiskAssetMapping.tenant_id == tenant_id,
            ExternalRiskAssetMapping.asset_id == asset_id,
        )
        .order_by(desc(ExternalRiskAssetMapping.updated_at))
    ).all()
    risk_ids = [row.risk_record_id for row in mappings]
    if not risk_ids:
        return []
    records = {
        row.id: row
        for row in db.scalars(
            select(ExternalRiskRecord).where(
                ExternalRiskRecord.tenant_id == tenant_id,
                ExternalRiskRecord.id.in_(risk_ids),
            )
        ).all()
    }
    impacts = {
        (row.risk_record_id, row.asset_type, row.asset_id): row
        for row in db.scalars(
            select(ExternalRiskImpact).where(
                ExternalRiskImpact.tenant_id == tenant_id,
                ExternalRiskImpact.asset_id == asset_id,
            )
        ).all()
    }

    out: list[dict[str, Any]] = []
    for mapping in mappings:
        record = records.get(mapping.risk_record_id)
        if not record:
            continue
        impact = impacts.get((mapping.risk_record_id, mapping.asset_type, mapping.asset_id))
        out.append(
            {
                "risk_record_id": record.id,
                "source": record.source,
                "source_record_id": record.source_record_id,
                "title": record.title,
                "severity": record.severity,
                "exploit_status": record.exploit_status,
                "asset_type": mapping.asset_type,
                "asset_id": mapping.asset_id,
                "confidence": mapping.confidence,
                "control_ids": mapping.control_ids,
                "simulation_ids": mapping.simulation_ids,
                "annualized_loss_expectancy": float(impact.annualized_loss_expectancy) if impact else 0.0,
                "residual_risk": float(impact.residual_risk) if impact else 0.0,
                "updated_at": record.source_updated_at.isoformat() if record.source_updated_at else None,
            }
        )
    return out


def get_summary(db: Session, *, tenant_id: str, lookback_hours: int = 24 * 7) -> dict[str, Any]:
    _mark_stale_running_syncs(db, tenant_id=tenant_id)
    ensure_default_sources(db, tenant_id=tenant_id)
    since = _utcnow() - timedelta(hours=max(1, int(lookback_hours)))
    severity_lower = func.lower(ExternalRiskRecord.severity)
    exploit_lower = func.lower(ExternalRiskRecord.exploit_status)
    rec_status_lower = func.lower(RiskTriggeredSimulationRecommendation.status)
    critical_count = int(
        db.scalar(
            select(func.count(ExternalRiskRecord.id)).where(
                ExternalRiskRecord.tenant_id == tenant_id,
                ExternalRiskRecord.updated_at >= since,
                severity_lower == "critical",
            )
        )
        or 0
    )
    high_or_critical_count = int(
        db.scalar(
            select(func.count(ExternalRiskRecord.id)).where(
                ExternalRiskRecord.tenant_id == tenant_id,
                ExternalRiskRecord.updated_at >= since,
                severity_lower.in_(("high", "critical")),
            )
        )
        or 0
    )
    known_exploited_count = int(
        db.scalar(
            select(func.count(ExternalRiskRecord.id)).where(
                ExternalRiskRecord.tenant_id == tenant_id,
                ExternalRiskRecord.updated_at >= since,
                exploit_lower == "known_exploited",
            )
        )
        or 0
    )
    affected_assets_subquery = (
        select(
            ExternalRiskAssetMapping.asset_type,
            ExternalRiskAssetMapping.asset_id,
        )
        .where(ExternalRiskAssetMapping.tenant_id == tenant_id)
        .distinct()
        .subquery()
    )
    affected_assets_count = int(
        db.scalar(select(func.count()).select_from(affected_assets_subquery))
        or 0
    )
    pending_sim_recs_count = int(
        db.scalar(
            select(func.count(RiskTriggeredSimulationRecommendation.id)).where(
                RiskTriggeredSimulationRecommendation.tenant_id == tenant_id,
                RiskTriggeredSimulationRecommendation.updated_at >= since,
                rec_status_lower.in_(("recommended", "pending")),
            )
        )
        or 0
    )
    total_ale = float(
        db.scalar(
            select(func.coalesce(func.sum(ExternalRiskImpact.annualized_loss_expectancy), 0.0)).where(
                ExternalRiskImpact.tenant_id == tenant_id
            )
        )
        or 0.0
    )
    total_residual = float(
        db.scalar(
            select(func.coalesce(func.sum(ExternalRiskImpact.residual_risk), 0.0)).where(
                ExternalRiskImpact.tenant_id == tenant_id
            )
        )
        or 0.0
    )
    latest_sync = db.scalar(
        select(ExternalRiskSyncRun)
        .where(ExternalRiskSyncRun.tenant_id == tenant_id)
        .order_by(desc(ExternalRiskSyncRun.started_at))
        .limit(1)
    )
    latest_completed_sync = db.scalar(
        select(ExternalRiskSyncRun)
        .where(
            ExternalRiskSyncRun.tenant_id == tenant_id,
            ExternalRiskSyncRun.completed_at.is_not(None),
        )
        .order_by(desc(ExternalRiskSyncRun.completed_at), desc(ExternalRiskSyncRun.started_at))
        .limit(1)
    )
    latest_successful_sync = db.scalar(
        select(ExternalRiskSyncRun)
        .where(
            ExternalRiskSyncRun.tenant_id == tenant_id,
            ExternalRiskSyncRun.status == "completed",
            ExternalRiskSyncRun.completed_at.is_not(None),
        )
        .order_by(desc(ExternalRiskSyncRun.completed_at), desc(ExternalRiskSyncRun.started_at))
        .limit(1)
    )

    by_source = {
        source: count
        for source, count in db.execute(
            select(ExternalRiskRecord.source, func.count(ExternalRiskRecord.id))
            .where(ExternalRiskRecord.tenant_id == tenant_id)
            .group_by(ExternalRiskRecord.source)
        )
    }

    return {
        "critical_risks": critical_count,
        "high_or_critical_risks": high_or_critical_count,
        "known_exploited_items": known_exploited_count,
        "affected_assets": affected_assets_count,
        "new_risks_since_last_sync": int(latest_successful_sync.records_ingested if latest_successful_sync else 0),
        "simulations_recommended": pending_sim_recs_count,
        "remediation_pending": pending_sim_recs_count,
        "sync_status": str(latest_sync.status if latest_sync else "no_data"),
        "last_sync_at": (
            latest_successful_sync.completed_at.isoformat()
            if latest_successful_sync and latest_successful_sync.completed_at
            else (latest_completed_sync.completed_at.isoformat() if latest_completed_sync and latest_completed_sync.completed_at else None)
        ),
        "source_health": [
            {
                "source": row.source,
                "enabled": row.enabled,
                "last_sync_status": row.last_sync_status,
                "last_sync_at": row.last_sync_at.isoformat() if row.last_sync_at else None,
                "last_sync_error": row.last_sync_error,
            }
            for row in db.scalars(
                select(ExternalRiskSource)
                .where(ExternalRiskSource.tenant_id == tenant_id)
                .order_by(ExternalRiskSource.source)
            ).all()
        ],
        "coverage_by_source": by_source,
        "total_ale_usd": round(total_ale, 2),
        "total_residual_risk_usd": round(total_residual, 2),
        "drilldown": "/monitoring?focus=external-risk",
    }
