from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import get_correlation_id, reset_correlation_id, set_correlation_id
from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.simulation import SimulationDefinition, SimulationRun, SimulationScheduleDecision
from app.services.audit_service import write_audit_log
from app.services.control_graph_service import normalize_control_ids
from app.services.evidence_service import create_evidence_node
from app.services.governance_resolution import resolve_ai_system_status
from app.services.simulation_pack_service import select_pack_simulations


APPROVED_STATUSES = {"approved", "active"}
HIGH_RISK_TIERS = {"HIGH", "CRITICAL", "RESTRICTED"}
DEFAULT_CONTROL_IDS = [
    "CTRL-INPUT-001",
    "CTRL-DLP-001",
    "CTRL-TOOL-001",
    "CTRL-AI-IAM-001",
    "CTRL-RAG-001",
    "CTRL-TENANT-ISO-001",
]
ASYMMETRY_LABEL_TO_CONTROL = {
    "output_asymmetry": "CTRL-TOOL-001",
    "agent_chain_abuse": "CTRL-AI-IAM-001",
    "potential_data_exfiltration": "CTRL-DLP-001",
    "prompt_injection_like": "CTRL-INPUT-001",
}
REPEATED_BLOCK_LOOKBACK_MINUTES = 30
REPEATED_BLOCK_THRESHOLD = 3


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _unique_strings(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        item = str(raw or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _is_high_risk_tier(risk_tier: str | None) -> bool:
    return str(risk_tier or "").strip().upper() in HIGH_RISK_TIERS


def _control_ids_from_simulations(db: Session, *, tenant_id: str) -> list[str]:
    rows = db.scalars(
        select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)
    ).all()
    controls: list[str] = []
    for row in rows:
        controls.extend(str(control_id) for control_id in ((row.dsl_json or {}).get("maps_to_controls") or []))
    return _unique_strings(controls)


def _matching_simulations(
    db: Session,
    *,
    tenant_id: str,
    target_control_ids: list[str],
    target_pack: str | None = None,
) -> list[SimulationDefinition]:
    if target_pack:
        selected = select_pack_simulations(
            db,
            tenant_id=tenant_id,
            pack_id=target_pack,
            target_control_ids=target_control_ids,
        )
        if selected:
            return selected

    rows = db.scalars(
        select(SimulationDefinition)
        .where(SimulationDefinition.tenant_id == tenant_id)
        .order_by(SimulationDefinition.created_at.asc(), SimulationDefinition.id.asc())
    ).all()
    if not target_control_ids:
        return rows

    target = set(normalize_control_ids(target_control_ids))
    matched: list[SimulationDefinition] = []
    for row in rows:
        mapped_controls = set(normalize_control_ids([str(control_id) for control_id in ((row.dsl_json or {}).get("maps_to_controls") or [])]))
        if mapped_controls.intersection(target):
            matched.append(row)
    return matched


def _summarize_runs(db: Session, *, tenant_id: str, run_ids: list[str]) -> dict[str, Any]:
    if not run_ids:
        return {"total_runs": 0, "passes": 0, "fails": 0, "results": []}

    rows = db.scalars(
        select(SimulationRun).where(
            SimulationRun.tenant_id == tenant_id,
            SimulationRun.id.in_(run_ids),
        )
    ).all()
    by_id = {row.id: row for row in rows}
    ordered_rows = [by_id[row_id] for row_id in run_ids if row_id in by_id]

    results = []
    passes = 0
    fails = 0
    for row in ordered_rows:
        result = str((row.results or {}).get("result") or "fail")
        if result == "pass":
            passes += 1
        else:
            fails += 1
        results.append(
            {
                "run_id": row.id,
                "simulation_id": row.simulation_id,
                "result": result,
                "pass_rate": float((row.results or {}).get("pass_rate") or 0.0),
            }
        )
    return {
        "total_runs": len(ordered_rows),
        "passes": passes,
        "fails": fails,
        "results": results,
    }


def _with_scheduler_correlation() -> tuple[str, Any | None]:
    correlation_id = get_correlation_id()
    if correlation_id:
        return correlation_id, None
    generated = str(uuid4())
    token = set_correlation_id(generated)
    return generated, token


def _finalize_scheduler_correlation(token: Any | None) -> None:
    if token is None:
        return
    reset_correlation_id(token)


def schedule_simulation_pack(
    db: Session,
    *,
    tenant_id: str,
    reason_code: str,
    target_ai_system_id: str | None,
    target_control_ids: list[str] | None,
    target_pack: str | None = None,
    trigger_payload: dict[str, Any] | None = None,
    actor_user_id: str | None = None,
) -> SimulationScheduleDecision:
    trigger_payload = dict(trigger_payload or {})
    resolved_pack = str(target_pack or trigger_payload.get("target_pack") or "").strip() or None
    if resolved_pack:
        trigger_payload["target_pack"] = resolved_pack
    raw_controls = [str(control_id) for control_id in (target_control_ids or [])]
    resolved_controls = normalize_control_ids(_unique_strings(raw_controls))
    if not resolved_controls:
        resolved_controls = _control_ids_from_simulations(db, tenant_id=tenant_id)
    if not resolved_controls:
        resolved_controls = normalize_control_ids(_unique_strings(DEFAULT_CONTROL_IDS))

    decision = SimulationScheduleDecision(
        tenant_id=tenant_id,
        reason_code=reason_code,
        target_ai_system_id=target_ai_system_id,
        target_control_ids=resolved_controls,
        trigger_payload=trigger_payload,
        status="scheduled",
        scheduled_simulation_ids=[],
        simulation_run_ids=[],
        execution_summary={},
    )
    db.add(decision)
    db.flush()

    correlation_id, correlation_token = _with_scheduler_correlation()
    try:
        audit_created = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="system",
            action="simulation.scheduler.scheduled",
            resource_type="simulation_schedule_decision",
            resource_id=decision.id,
            payload={
                "reason_code": reason_code,
                "target_ai_system_id": target_ai_system_id,
                "target_control_ids": resolved_controls,
                "target_pack": resolved_pack,
                "trigger_payload": trigger_payload,
            },
            correlation_id=correlation_id,
        )
        evidence_created = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="simulation_schedule_decision",
            signal_type="simulation.scheduler.scheduled",
            label=f"Simulation schedule decision {reason_code}",
            payload={
                "decision_id": decision.id,
                "reason_code": reason_code,
                "target_ai_system_id": target_ai_system_id,
                "target_control_ids": resolved_controls,
                "audit_log_id": audit_created.id,
                "trigger_payload": trigger_payload,
            },
            correlation_id=correlation_id,
        )

        governance_status = resolve_ai_system_status(
            target_ai_system_id,
            {
                "db": db,
                "tenant_id": tenant_id,
                "route": "simulation.scheduler",
                "module": "simulation_scheduler",
                "source_hint": "trust_center",
            },
        )

        if governance_status.get("status") == "UNKNOWN":
            runtime_evidence_ids = [evidence_created.id]
            runtime_event_id: str | None = None
            try:
                from app.services.runtime_intelligence.runtime_event_normalizer import ingest_runtime_event
                from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

                runtime_row = ingest_runtime_event(
                    db,
                    payload=RuntimeEventIngestPayload(
                        tenant_id=tenant_id,
                        source_surface="monitoring",
                        event_type="simulation_scheduler_unknown_ai_system",
                        ai_system_id=None,
                        app_id=(target_ai_system_id or "unknown_ai_system"),
                        user_id=None,
                        agent_id=None,
                        risk_tier="HIGH",
                        policy_version_id=None,
                        governance_version="g1",
                        severity="high",
                        confidence_tier="clear_positive",
                        evidence_node_ids=[evidence_created.id],
                        correlation_id=correlation_id,
                        metadata={
                            "reason_code": reason_code,
                            "requested_ai_system_id": target_ai_system_id,
                            "governance_state": "UNKNOWN",
                            "governance_reason": governance_status.get("reason"),
                        },
                    ),
                )
                if runtime_row is not None:
                    runtime_event_id = runtime_row.event_id
                    runtime_evidence_ids = [str(node_id) for node_id in (runtime_row.evidence_node_ids or []) if str(node_id).strip()]
            except Exception:
                runtime_event_id = None

            from app.services.findings_service import generate_unregistered_ai_system_finding

            generate_unregistered_ai_system_finding(
                db,
                tenant_id=tenant_id,
                source_surface="monitoring",
                ai_tool=(target_ai_system_id or "unknown_ai_system"),
                requested_ai_system_id=target_ai_system_id,
                policy_version_id=None,
                evidence_node_ids=runtime_evidence_ids,
                related_control_ids=["CTRL-TENANT-ISO-001"],
                recommended_action=(
                    "Simulation scheduling received an unknown AI system. Register the system in Trust Center before scheduling validation."
                ),
            )

            decision.status = "failed" if settings.governance_strict_mode else "skipped"
            decision.started_at = _utcnow()
            decision.finished_at = _utcnow()
            decision.error_message = "Unknown AI system is not registered in Trust Center"
            decision.execution_summary = {
                "status": decision.status,
                "reason": "unknown_ai_system",
                "requested_ai_system_id": target_ai_system_id,
                "governance_status": governance_status,
                "runtime_event_id": runtime_event_id,
                "evidence_node_id": evidence_created.id,
            }
            return decision

        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.id == target_ai_system_id,
                AISystem.tenant_id == tenant_id,
            )
        )
        if ai_system is None:
            decision.status = "failed"
            decision.started_at = _utcnow()
            decision.finished_at = _utcnow()
            decision.error_message = "AI system not found for tenant"
            decision.execution_summary = {
                "status": "failed",
                "reason": "ai_system_not_found",
                "target_ai_system_id": target_ai_system_id,
            }
            return decision

        simulations = _matching_simulations(
            db,
            tenant_id=tenant_id,
            target_control_ids=resolved_controls,
            target_pack=resolved_pack,
        )
        decision.scheduled_simulation_ids = [row.id for row in simulations]
        decision.started_at = _utcnow()
        decision.status = "running"
        db.flush()

        if not simulations:
            decision.status = "no_simulations"
            decision.finished_at = _utcnow()
            decision.execution_summary = {
                "status": "no_simulations",
                "target_control_ids": resolved_controls,
                "target_ai_system_id": target_ai_system_id,
                "target_pack": resolved_pack,
            }
            return decision

        run_ids: list[str] = []
        run_errors: list[str] = []
        from app.services.simulation_service import run_simulation

        for simulation in simulations:
            try:
                run = run_simulation(
                    db,
                    tenant_id=tenant_id,
                    simulation=simulation,
                    ai_system_id=target_ai_system_id,
                    mode="deterministic",
                    stochastic_runs=1,
                    inputs_used={
                        "scheduler_reason_code": reason_code,
                        "scheduler_decision_id": decision.id,
                        "scheduler_trigger_payload": trigger_payload,
                    },
                    actor_user_id=actor_user_id,
                    execution_mode="scheduled",
                    execution_environment=str(trigger_payload.get("execution_environment") or "staging"),
                )
                run_ids.append(run.id)
            except Exception as exc:  # pragma: no cover - protected by integration tests
                run_errors.append(f"{simulation.id}:{exc}")

        decision.simulation_run_ids = run_ids
        decision.finished_at = _utcnow()
        summary = _summarize_runs(db, tenant_id=tenant_id, run_ids=run_ids)
        summary["target_control_ids"] = resolved_controls
        summary["target_ai_system_id"] = target_ai_system_id
        summary["target_pack"] = resolved_pack
        summary["reason_code"] = reason_code
        summary["run_errors"] = run_errors
        decision.execution_summary = summary

        if run_errors:
            decision.status = "failed"
            decision.error_message = "; ".join(run_errors)[:4000]
        else:
            decision.status = "completed"

        audit_result = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="system",
            action="simulation.scheduler.executed",
            resource_type="simulation_schedule_decision",
            resource_id=decision.id,
            payload={
                "status": decision.status,
                "reason_code": reason_code,
                "target_ai_system_id": target_ai_system_id,
                "target_pack": resolved_pack,
                "scheduled_simulation_ids": decision.scheduled_simulation_ids,
                "simulation_run_ids": run_ids,
                "execution_summary": summary,
            },
            correlation_id=correlation_id,
        )
        create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="simulation_schedule_result",
            signal_type="simulation.scheduler.executed",
            label=f"Simulation scheduler executed {reason_code}",
            payload={
                "decision_id": decision.id,
                "status": decision.status,
                "reason_code": reason_code,
                "target_ai_system_id": target_ai_system_id,
                "simulation_run_ids": run_ids,
                "audit_log_id": audit_result.id,
                "execution_summary": summary,
            },
            correlation_id=correlation_id,
        )
        return decision
    finally:
        _finalize_scheduler_correlation(correlation_token)


def schedule_for_ai_system_approved(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_user_id: str | None = None,
) -> SimulationScheduleDecision:
    return schedule_simulation_pack(
        db,
        tenant_id=tenant_id,
        reason_code="ai_system_approved",
        target_ai_system_id=ai_system_id,
        target_control_ids=DEFAULT_CONTROL_IDS,
        target_pack="governance_discovery_validation_pack",
        trigger_payload={"trigger_type": "governance_approval"},
        actor_user_id=actor_user_id,
    )


def schedule_for_high_risk_tier(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    risk_tier: str | None,
    actor_user_id: str | None = None,
) -> SimulationScheduleDecision | None:
    if not _is_high_risk_tier(risk_tier):
        return None
    return schedule_simulation_pack(
        db,
        tenant_id=tenant_id,
        reason_code="high_risk_tier",
        target_ai_system_id=ai_system_id,
        target_control_ids=DEFAULT_CONTROL_IDS,
        target_pack="data_leakage_pack",
        trigger_payload={"trigger_type": "risk_tier_high_or_above", "risk_tier": risk_tier},
        actor_user_id=actor_user_id,
    )


def schedule_for_asymmetry_spike(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    evidence_node_id: str,
    risk_labels: list[str] | None,
    actor_user_id: str | None = None,
) -> SimulationScheduleDecision:
    labels = _unique_strings([str(label) for label in (risk_labels or [])])
    controls = [ASYMMETRY_LABEL_TO_CONTROL[label] for label in labels if label in ASYMMETRY_LABEL_TO_CONTROL]
    if not controls:
        controls = ["CTRL-TOOL-001"]
    return schedule_simulation_pack(
        db,
        tenant_id=tenant_id,
        reason_code="asymmetry_spike",
        target_ai_system_id=ai_system_id,
        target_control_ids=controls,
        target_pack="data_leakage_pack",
        trigger_payload={
            "trigger_type": "asymmetry_heuristic_spike",
            "evidence_node_id": evidence_node_id,
            "risk_labels": labels,
        },
        actor_user_id=actor_user_id,
    )


def schedule_for_repeated_enforcement_blocks(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_user_id: str | None = None,
) -> SimulationScheduleDecision | None:
    cutoff = _utcnow() - timedelta(minutes=REPEATED_BLOCK_LOOKBACK_MINUTES)
    events = db.scalars(
        select(EnforcementEvent)
        .where(
            EnforcementEvent.tenant_id == tenant_id,
            EnforcementEvent.ai_system_id == ai_system_id,
            EnforcementEvent.final_decision == "block",
            EnforcementEvent.timestamp >= cutoff,
            EnforcementEvent.request_id.not_like("sim-%"),
        )
        .order_by(EnforcementEvent.timestamp.desc())
    ).all()
    if len(events) < REPEATED_BLOCK_THRESHOLD:
        return None

    controls: list[str] = []
    for event in events:
        for impact in (event.controls_impacted or []):
            if isinstance(impact, dict) and impact.get("control_id"):
                controls.append(str(impact["control_id"]))
    controls = _unique_strings(controls)
    if not controls:
        controls = ["CTRL-INPUT-001", "CTRL-TOOL-001"]

    return schedule_simulation_pack(
        db,
        tenant_id=tenant_id,
        reason_code="repeated_enforcement_blocks",
        target_ai_system_id=ai_system_id,
        target_control_ids=controls,
        target_pack="prompt_attack_pack",
        trigger_payload={
            "trigger_type": "repeated_enforcement_blocks",
            "threshold": REPEATED_BLOCK_THRESHOLD,
            "lookback_minutes": REPEATED_BLOCK_LOOKBACK_MINUTES,
            "recent_block_count": len(events),
            "event_ids": [event.id for event in events[:10]],
        },
        actor_user_id=actor_user_id,
    )


def schedule_for_connector_drift_event(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    related_control_ids: list[str] | None,
    drift_alert_id: str,
    actor_user_id: str | None = None,
) -> list[SimulationScheduleDecision]:
    controls = _unique_strings([str(control_id) for control_id in (related_control_ids or [])])
    decisions: list[SimulationScheduleDecision] = []

    target_ids: list[str | None]
    if ai_system_id:
        target_ids = [ai_system_id]
    else:
        rows = db.scalars(
            select(AISystem).where(
                AISystem.tenant_id == tenant_id,
                AISystem.status != "prohibited",
            )
        ).all()
        target_ids = [row.id for row in rows] or [None]

    for target in target_ids:
        decisions.append(
            schedule_simulation_pack(
                db,
                tenant_id=tenant_id,
                reason_code="connector_drift_event",
                target_ai_system_id=target,
                target_control_ids=controls,
                target_pack="governance_discovery_validation_pack",
                trigger_payload={
                    "trigger_type": "connector_drift_event",
                    "drift_alert_id": drift_alert_id,
                    "related_control_ids": controls,
                },
                actor_user_id=actor_user_id,
            )
        )
    return decisions
