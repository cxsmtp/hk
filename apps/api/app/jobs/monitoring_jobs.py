from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.config import settings
from app.core.observability import log_structured
from app.db.models.monitoring import Connector
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.job_run_service import tracked_scheduled_job
from app.services.monitoring_service import (
    connector_coverage_summary,
    consume_runtime_intelligence_outputs,
    evaluate_scheduled_monitoring_remediation,
    ingest_monitoring_signal,
    run_connector_once,
)
from app.services.simulation_pack_service import evaluate_simulation_coverage_remediation


logger = logging.getLogger(__name__)

_DETERMINISTIC_CONNECTOR_CONFIGURATION_ERRORS = frozenset(
    {
        "Missing base_url configuration.",
        "Unresolved base_url template.",
    }
)


def _is_deterministic_connector_configuration_error(exc: ValueError) -> bool:
    return str(exc).strip() in _DETERMINISTIC_CONNECTOR_CONFIGURATION_ERRORS


@celery_app.task(name="app.jobs.monitoring_jobs.run_all_connectors")
def run_all_connectors(tenant_id: str) -> dict:
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        connectors = db.scalars(
            select(Connector).where(
                Connector.tenant_id == tenant_id,
                Connector.enabled.is_(True),
                Connector.status.in_(["active", "stub", "degraded"]),
            )
        ).all()
        generated = 0
        executed = 0
        configuration_errors: list[dict[str, str]] = []
        for connector in connectors:
            interval_minutes = max(1, int(connector.polling_interval_minutes or 15))
            if connector.last_run_at is not None and (now - connector.last_run_at) < timedelta(minutes=interval_minutes):
                continue
            connector_id = connector.id
            try:
                signals = run_connector_once(db, tenant_id=tenant_id, connector=connector)
                executed += 1
                generated += len(signals)
                db.commit()
            except ValueError as exc:
                if not _is_deterministic_connector_configuration_error(exc):
                    raise

                db.rollback()
                persisted = db.get(Connector, connector_id)
                if persisted is None or persisted.tenant_id != tenant_id:
                    raise
                reason = str(exc).strip()
                logger.warning(
                    "Connector not run: its configuration is invalid (%s)",
                    reason,
                    extra={"connector_id": connector_id, "tenant_id": tenant_id, "reason_code": "connector_configuration_invalid"},
                )
                persisted.last_run_at = datetime.now(timezone.utc)
                persisted.status = "degraded"
                persisted.last_pull_status = "error"
                persisted.last_pull_error = reason[:512]
                persisted.last_signal_count = 0
                persisted.is_stub = False
                persisted.stub_reason = ""
                db.commit()
                executed += 1
                configuration_errors.append(
                    {
                        "connector_id": connector_id,
                        "reason_code": "connector_configuration_invalid",
                    }
                )
        if executed:
            logger.info(
                "Connectors run: %d of %d, %d signal(s)",
                executed,
                len(connectors),
                generated,
                extra={"tenant_id": tenant_id, "configuration_errors": len(configuration_errors)},
            )
        return {
            "tenant_id": tenant_id,
            "connectors": len(connectors),
            "executed_connectors": executed,
            "signals_generated": generated,
            "configuration_error_count": len(configuration_errors),
            "configuration_errors": configuration_errors,
        }
    finally:
        db.close()


@celery_app.task(name="app.jobs.monitoring_jobs.run_scheduled_monitoring_checks")
def run_scheduled_monitoring_checks() -> dict:
    return run_monitoring_15m_checks()


def _list_active_tenants() -> list[Tenant]:
    db = SessionLocal()
    try:
        return db.scalars(select(Tenant).where(Tenant.is_active.is_(True))).all()
    finally:
        db.close()


def _run_monitoring_cycle(
    *,
    cadence_key: str,
    lookback_minutes: int,
    emit_coverage_snapshot: bool,
    run_connectors: bool,
) -> dict:
    with tracked_scheduled_job(f"monitoring_cycle_{cadence_key}", tenant_id=None):
        tenants = _list_active_tenants()
        per_tenant: list[dict] = []
        total_connectors = 0
        total_signals = 0
        total_runtime_findings = 0
        total_runtime_triggers = 0
        total_runtime_recommendations = 0
        total_remediation_signals_evaluated = 0
        total_remediations_evaluated = 0
        total_simulation_coverage_remediations = 0

        for tenant in tenants:
            connector_result = (
                run_all_connectors(tenant.id)
                if run_connectors
                else {
                    "tenant_id": tenant.id,
                    "connectors": 0,
                    "executed_connectors": 0,
                    "signals_generated": 0,
                }
            )
            total_connectors += int(connector_result.get("connectors", 0))
            total_signals += int(connector_result.get("signals_generated", 0))

            db = SessionLocal()
            try:
                runtime_summary = consume_runtime_intelligence_outputs(
                    db,
                    tenant_id=tenant.id,
                    lookback_minutes=lookback_minutes,
                    actor_user_id=None,
                )
                remediation_summary = evaluate_scheduled_monitoring_remediation(
                    db,
                    tenant_id=tenant.id,
                    lookback_minutes=max(60, int(lookback_minutes)),
                    actor_user_id=None,
                )
                simulation_coverage_summary = (
                    evaluate_simulation_coverage_remediation(
                        db,
                        tenant_id=tenant.id,
                        actor_user_id=None,
                    )
                    if emit_coverage_snapshot
                    else {
                        "coverage_gap_detected": False,
                        "controls_without_simulations": [],
                        "simulations_without_controls": 0,
                        "recommendation_count": 0,
                        "recommended_simulations": [],
                        "monitoring_signal_id": None,
                    }
                )
                coverage_summary = connector_coverage_summary(db, tenant_id=tenant.id) if emit_coverage_snapshot else None
                if coverage_summary is not None:
                    missing_evidence_count = sum(
                        1
                        for row in (coverage_summary.get("control_signal_map") or [])
                        if isinstance(row, dict) and int(row.get("live_evidence_count") or 0) <= 0
                    )
                    coverage_severity = "high" if int(missing_evidence_count) > 0 else "low"
                    ingest_monitoring_signal(
                        db,
                        tenant_id=tenant.id,
                        ai_system_id=None,
                        signal_type=f"monitoring.cadence.{cadence_key}.coverage",
                        severity=coverage_severity,
                        payload={
                            "cadence": cadence_key,
                            "source": "continuous_monitoring",
                            "coverage": coverage_summary,
                            "runtime_consumption": runtime_summary,
                            "missing_evidence_detected": int(missing_evidence_count) > 0,
                            "missing_evidence_count": int(missing_evidence_count),
                            "require_revalidation": int(missing_evidence_count) > 0,
                            "simulation_coverage_remediation": simulation_coverage_summary,
                            "reason_code": (
                                "monitoring_evidence_gap_detected"
                                if int(missing_evidence_count) > 0
                                else "monitoring_coverage_healthy"
                            ),
                            "remediation_summary": remediation_summary,
                        },
                        actor_user_id=None,
                        create_default_drift_alert=False,
                        forward_to_runtime_intelligence=False,
                    )
                db.commit()
            except Exception as exc:
                db.rollback()
                runtime_summary = {
                    "lookback_minutes": lookback_minutes,
                    "runtime_findings_scanned": 0,
                    "runtime_triggers_scanned": 0,
                    "runtime_recommendations_scanned": 0,
                    "ingested_runtime_findings": 0,
                    "ingested_runtime_triggers": 0,
                    "ingested_runtime_recommendations": 0,
                    "error": str(exc),
                }
                remediation_summary = {
                    "lookback_minutes": int(max(60, lookback_minutes)),
                    "signals_scanned": 0,
                    "signals_evaluated": 0,
                    "remediations_evaluated": 0,
                    "error": str(exc),
                }
                simulation_coverage_summary = {
                    "coverage_gap_detected": False,
                    "controls_without_simulations": [],
                    "simulations_without_controls": 0,
                    "recommendation_count": 0,
                    "recommended_simulations": [],
                    "monitoring_signal_id": None,
                    "error": str(exc),
                }
                log_structured(
                    "monitoring_runtime_consumption_failed",
                    module="monitoring_jobs",
                    tenant_id=tenant.id,
                    signal_type=f"monitoring.cadence.{cadence_key}",
                    correlation_id=None,
                    error=str(exc),
                )
            finally:
                db.close()

            total_runtime_findings += int(runtime_summary.get("ingested_runtime_findings", 0))
            total_runtime_triggers += int(runtime_summary.get("ingested_runtime_triggers", 0))
            total_runtime_recommendations += int(runtime_summary.get("ingested_runtime_recommendations", 0))
            total_remediation_signals_evaluated += int(remediation_summary.get("signals_evaluated", 0))
            total_remediations_evaluated += int(remediation_summary.get("remediations_evaluated", 0))
            total_simulation_coverage_remediations += int(simulation_coverage_summary.get("recommendation_count", 0))

            per_tenant.append(
                {
                    **connector_result,
                    "runtime_consumption": runtime_summary,
                    "remediation_evaluation": remediation_summary,
                    "simulation_coverage_remediation": simulation_coverage_summary,
                }
            )

        return {
            "cadence": cadence_key,
            "lookback_minutes": lookback_minutes,
            "tenants_processed": len(tenants),
            "total_connectors": total_connectors,
            "total_signals_generated": total_signals,
            "runtime_findings_ingested": total_runtime_findings,
            "runtime_triggers_ingested": total_runtime_triggers,
            "runtime_recommendations_ingested": total_runtime_recommendations,
            "remediation_signals_evaluated": total_remediation_signals_evaluated,
            "remediations_evaluated": total_remediations_evaluated,
            "simulation_coverage_recommendations": total_simulation_coverage_remediations,
            "per_tenant": per_tenant,
        }


@celery_app.task(name="app.jobs.monitoring_jobs.run_monitoring_15m_checks")
def run_monitoring_15m_checks() -> dict:
    return _run_monitoring_cycle(
        cadence_key="15m",
        lookback_minutes=20,
        emit_coverage_snapshot=False,
        run_connectors=True,
    )


@celery_app.task(name="app.jobs.monitoring_jobs.run_monitoring_hourly_checks")
def run_monitoring_hourly_checks() -> dict:
    if not settings.monitoring_hourly_coverage_enabled:
        return {
            "cadence": "hourly",
            "status": "deferred",
            "reason_code": "hourly_coverage_disabled",
        }
    return _run_monitoring_cycle(
        cadence_key="hourly",
        lookback_minutes=75,
        emit_coverage_snapshot=True,
        run_connectors=False,
    )


@celery_app.task(name="app.jobs.monitoring_jobs.run_monitoring_daily_checks")
def run_monitoring_daily_checks() -> dict:
    return _run_monitoring_cycle(
        cadence_key="daily",
        lookback_minutes=24 * 60,
        emit_coverage_snapshot=True,
        run_connectors=False,
    )
