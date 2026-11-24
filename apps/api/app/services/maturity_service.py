from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.enforcement import EnforcementEvent
from app.db.models.knowledge_base import KBControl, KBFramework
from app.db.models.maturity import ConflictResolution, ControlConflict, ControlMaturity, ControlMaturityHistory
from app.db.models.monitoring import MonitoringSignal
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node


CONFIDENCE_THRESHOLD = 0.65

EVIDENCE_PRECEDENCE: dict[str, int] = {
    "telemetry": 1,
    "simulation": 2,
    "configuration": 3,
    "documentation": 4,
}


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def _to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _evidence_source(signal_type: str | None, node_type: str | None) -> str:
    signal = str(signal_type or "").lower()
    node = str(node_type or "").lower()

    telemetry_markers = (
        "telemetry",
        "monitoring",
        "connector.",
        "integration_signal",
        "runtime",
        "usage",
        "gateway.",
    )
    simulation_markers = (
        "simulation",
        "sim_",
        "sim.",
    )
    configuration_markers = (
        "config",
        "configuration",
        "policy",
        "guardian",
        "iam",
        "mcp",
    )

    # The explicit signal namespace is authoritative. A simulation event can
    # be persisted through a runtime-shaped evidence node; classifying from
    # the combined strings made source precedence depend on creation timing.
    for source, markers in (
        ("simulation", simulation_markers),
        ("telemetry", telemetry_markers),
        ("configuration", configuration_markers),
    ):
        if any(marker in signal for marker in markers):
            return source
    for source, markers in (
        ("simulation", simulation_markers),
        ("telemetry", telemetry_markers),
        ("configuration", configuration_markers),
    ):
        if any(marker in node for marker in markers):
            return source
    return "documentation"


def _evidence_precedence(source: str) -> int:
    return EVIDENCE_PRECEDENCE.get(source, EVIDENCE_PRECEDENCE["documentation"])


def _run_pass_metrics(run: SimulationRun) -> tuple[float, int, float]:
    payload = run.results or {}
    run_result = str(payload.get("result", "fail")).lower()

    iterations = max(1, _to_int(payload.get("iterations", 1), 1))
    if "pass_rate" in payload:
        pass_rate = _clamp(_to_float(payload.get("pass_rate", 0.0), 0.0))
    else:
        pass_rate = 1.0 if run_result == "pass" else 0.0

    passes = pass_rate * float(iterations)
    return passes, iterations, pass_rate


def _normalize_dt(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _merge_latest(ts_a: datetime | None, ts_b: datetime | None) -> datetime | None:
    if ts_a is None:
        return ts_b
    if ts_b is None:
        return ts_a
    return ts_a if ts_a >= ts_b else ts_b


def _freshness_score(latest_signal_at: datetime | None, now: datetime) -> float:
    if latest_signal_at is None:
        return 0.0
    age_hours = max(0.0, (now - latest_signal_at).total_seconds() / 3600.0)
    if age_hours <= 24:
        return 1.0
    if age_hours <= 24 * 7:
        return 0.8
    if age_hours <= 24 * 30:
        return 0.5
    return 0.2


def _compute_confidence_inputs(
    *,
    evidence_count: int,
    positive_signals: int,
    negative_signals: int,
    telemetry_evidence_count: int,
    simulation_evidence_count: int,
    has_conflict: bool,
    latest_signal_at: datetime | None,
    now: datetime,
) -> tuple[float, dict[str, Any]]:
    total_signals = max(0, positive_signals + negative_signals)
    evidence_count_score = _clamp(min(1.0, evidence_count / 8.0))
    consistency_score = _clamp((abs(positive_signals - negative_signals) / total_signals) if total_signals else 0.0)
    freshness = _freshness_score(latest_signal_at, now)

    base_score = _clamp(
        (0.2 * evidence_count_score)
        + (0.5 * consistency_score)
        + (0.3 * freshness)
    )
    telemetry_bonus = 0.1 * max(0, telemetry_evidence_count)
    simulation_bonus = 0.05 * max(0, simulation_evidence_count)
    conflict_penalty = -0.2 if has_conflict else 0.0
    confidence_score = _clamp(base_score + telemetry_bonus + simulation_bonus + conflict_penalty)

    return confidence_score, {
        "threshold": CONFIDENCE_THRESHOLD,
        "evidence_count": evidence_count,
        "evidence_count_score": evidence_count_score,
        "consistency": consistency_score,
        "signal_freshness": freshness,
        "base_score": base_score,
        "telemetry_evidence_count": telemetry_evidence_count,
        "simulation_evidence_count": simulation_evidence_count,
        "telemetry_bonus": telemetry_bonus,
        "simulation_bonus": simulation_bonus,
        "conflict_penalty": conflict_penalty,
        "positive_signals": positive_signals,
        "negative_signals": negative_signals,
        "latest_signal_at": latest_signal_at.isoformat() if latest_signal_at else None,
        "confidence_score": confidence_score,
    }


def _implementation_state(
    *,
    technical: float,
    simulation_pass_rate: float,
    coverage: float,
    maturity: float,
    status: str,
) -> str:
    normalized_status = str(status or "").strip().lower()
    if normalized_status == "contested":
        return "partial"
    if maturity >= 0.75 and technical >= 0.7 and simulation_pass_rate >= 0.6 and coverage >= 0.4:
        return "implemented"
    if maturity >= 0.35 or technical >= 0.4 or coverage >= 0.25:
        return "partial"
    return "not_implemented"


def _implementation_reasoning(
    *,
    technical: float,
    simulation_pass_rate: float,
    coverage: float,
    maturity: float,
    status: str,
) -> list[str]:
    state = _implementation_state(
        technical=technical,
        simulation_pass_rate=simulation_pass_rate,
        coverage=coverage,
        maturity=maturity,
        status=status,
    )
    reasons = [
        f"technical_enforcement_score={technical:.2f}",
        f"simulation_pass_rate={simulation_pass_rate:.2f}",
        f"coverage_score={coverage:.2f}",
        f"maturity_score={maturity:.2f}",
    ]
    if str(status or "").strip().lower() == "contested":
        reasons.append("status=contested indicates contradictory evidence requiring review")
    reasons.append(f"posture={state}")
    return reasons


def _extract_conflict_stats(
    *,
    db: Session,
    tenant_id: str,
    control_id: str,
    recent_runs: list[SimulationRun],
    recent_events: list[EnforcementEvent],
) -> dict[str, Any]:
    positive_signals = 0
    negative_signals = 0
    evidence_node_ids: set[str] = set()
    latest_signal_at: datetime | None = None

    for run in recent_runs:
        run_time = _normalize_dt(run.finished_at or run.started_at)
        for item in (run.controls_impacted or []):
            if item.get("control_id") != control_id:
                continue
            contribution = _to_float(item.get("contribution", 0.0), 0.0)
            if contribution > 0:
                positive_signals += 1
            elif contribution < 0:
                negative_signals += 1
            else:
                run_result = str((run.results or {}).get("result", "fail")).lower()
                if run_result == "pass":
                    positive_signals += 1
                else:
                    negative_signals += 1
            latest_signal_at = _merge_latest(latest_signal_at, run_time)
            for node_id in ((run.results or {}).get("evidence_nodes_created") or []):
                if node_id:
                    evidence_node_ids.add(str(node_id))

    for event in recent_events:
        event_time = _normalize_dt(event.timestamp)
        for item in (event.controls_impacted or []):
            if item.get("control_id") != control_id:
                continue
            delta = _to_float(item.get("delta", 0.0), 0.0)
            if delta > 0:
                positive_signals += 1
            elif delta < 0:
                negative_signals += 1
            latest_signal_at = _merge_latest(latest_signal_at, event_time)
            for node_id in (event.evidence_nodes_created or []):
                if node_id:
                    evidence_node_ids.add(str(node_id))

    return {
        "positive_signals": positive_signals,
        "negative_signals": negative_signals,
        "evidence_node_ids": sorted(evidence_node_ids),
        "latest_signal_at": latest_signal_at,
        "evidence_source_counts": {},
    }


def _with_evidence_sources(
    db: Session,
    *,
    tenant_id: str,
    stats: dict[str, Any],
) -> dict[str, Any]:
    evidence_ids = list(stats.get("evidence_node_ids") or [])
    if not evidence_ids:
        return {
            **stats,
            "evidence_source_counts": {
                "telemetry": 0,
                "simulation": 0,
                "configuration": 0,
                "documentation": 0,
            },
        }

    nodes = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id.in_(evidence_ids),
        )
    ).all()
    node_by_id = {node.id: node for node in nodes}

    source_counts = {
        "telemetry": 0,
        "simulation": 0,
        "configuration": 0,
        "documentation": 0,
    }
    ordered_sources: list[dict[str, Any]] = []
    for node_id in evidence_ids:
        node = node_by_id.get(node_id)
        if not node:
            continue
        source = _evidence_source(node.signal_type, node.node_type)
        source_counts[source] += 1
        ordered_sources.append(
            {
                "node_id": node.id,
                "source": source,
                "precedence": _evidence_precedence(source),
                "created_at": _normalize_dt(node.created_at),
            }
        )

    ordered_sources.sort(
        key=lambda row: (
            row["precedence"],
            -(row["created_at"].timestamp() if isinstance(row["created_at"], datetime) else 0.0),
            row["node_id"],
        )
    )
    chosen = ordered_sources[0]["node_id"] if ordered_sources else None
    discarded = [row["node_id"] for row in ordered_sources[1:]]

    if ordered_sources:
        chosen_source = ordered_sources[0]["source"]
        reason = (
            f"chose {chosen} ({chosen_source}) using precedence "
            "telemetry>simulation>configuration>documentation"
        )
    else:
        reason = "no evidence available to resolve conflict"

    return {
        **stats,
        "evidence_source_counts": source_counts,
        "resolution_candidate": {
            "chosen_evidence_id": chosen,
            "discarded_evidence_ids": discarded,
            "reason": reason,
        },
    }


def _record_conflict_resolution(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_id: str,
    conflict_id: str | None,
    chosen_evidence_id: str | None,
    discarded_evidence_ids: list[str],
    reason: str,
) -> ConflictResolution:
    resolution = ConflictResolution(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_id=control_id,
        conflict_id=conflict_id,
        chosen_evidence_id=chosen_evidence_id,
        discarded_evidence_ids=discarded_evidence_ids,
        reason=reason,
    )
    db.add(resolution)
    db.flush()
    return resolution


def _sync_control_conflict(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_id: str,
    stats: dict[str, Any],
) -> bool:
    positive = int(stats.get("positive_signals", 0))
    negative = int(stats.get("negative_signals", 0))
    latest_signal_at = stats.get("latest_signal_at")
    evidence_node_ids = list(stats.get("evidence_node_ids", []))
    resolution_candidate = stats.get("resolution_candidate") or {}
    chosen_evidence_id = resolution_candidate.get("chosen_evidence_id")
    discarded_evidence_ids = list(resolution_candidate.get("discarded_evidence_ids") or [])
    resolution_reason = str(resolution_candidate.get("reason") or "no resolution reason")
    source_counts = dict(stats.get("evidence_source_counts") or {})

    open_conflict = db.scalar(
        select(ControlConflict)
        .where(
            ControlConflict.tenant_id == tenant_id,
            ControlConflict.ai_system_id == ai_system_id,
            ControlConflict.control_id == control_id,
            ControlConflict.status == "open",
        )
        .order_by(desc(ControlConflict.detected_at))
    )

    if positive > 0 and negative > 0:
        if open_conflict:
            open_conflict.positive_signals = positive
            open_conflict.negative_signals = negative
            open_conflict.latest_signal_at = latest_signal_at
            open_conflict.evidence_node_ids = evidence_node_ids
            open_conflict.details = {
                "reason": "contradictory_evidence",
                "detector": "automatic",
                "positive_signals": positive,
                "negative_signals": negative,
                "evidence_source_counts": source_counts,
                "chosen_evidence_id": chosen_evidence_id,
                "discarded_evidence_ids": discarded_evidence_ids,
                "resolution_reason": resolution_reason,
            }
            _record_conflict_resolution(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                control_id=control_id,
                conflict_id=open_conflict.id,
                chosen_evidence_id=chosen_evidence_id,
                discarded_evidence_ids=discarded_evidence_ids,
                reason=resolution_reason,
            )
            write_audit_log(
                db,
                tenant_id=tenant_id,
                actor_user_id=None,
                actor_type="system",
                action="control.conflict.resolution",
                resource_type="control_conflict",
                resource_id=open_conflict.id,
                payload={
                    "control_id": control_id,
                    "ai_system_id": ai_system_id,
                    "chosen_evidence_id": chosen_evidence_id,
                    "discarded_evidence_ids": discarded_evidence_ids,
                    "reason": resolution_reason,
                    "evidence_source_counts": source_counts,
                },
            )
            return True

        latest_resolved = db.scalar(
            select(ControlConflict)
            .where(
                ControlConflict.tenant_id == tenant_id,
                ControlConflict.ai_system_id == ai_system_id,
                ControlConflict.control_id == control_id,
                ControlConflict.status == "resolved",
            )
            .order_by(desc(ControlConflict.resolved_at), desc(ControlConflict.detected_at))
        )

        latest_resolved_signal = _normalize_dt(latest_resolved.latest_signal_at) if latest_resolved else None
        latest_signal_at_norm = _normalize_dt(latest_signal_at)
        if latest_resolved and latest_resolved_signal and latest_signal_at_norm and latest_signal_at_norm <= latest_resolved_signal:
            return False

        conflict_node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="control_conflict",
            signal_type="control.conflict.detected",
            label=f"Control conflict detected for {control_id}",
            payload={
                "ai_system_id": ai_system_id,
                "control_id": control_id,
                "positive_signals": positive,
                "negative_signals": negative,
                "chosen_evidence_id": chosen_evidence_id,
            },
        )

        audit = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action="control.conflict.detected",
            resource_type="control_conflict",
            resource_id=control_id,
            payload={
                "ai_system_id": ai_system_id,
                "control_id": control_id,
                "positive_signals": positive,
                "negative_signals": negative,
                "chosen_evidence_id": chosen_evidence_id,
                "discarded_evidence_ids": discarded_evidence_ids,
                "resolution_reason": resolution_reason,
            },
        )

        conflict = ControlConflict(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_id=control_id,
            status="open",
            reason="contradictory_evidence",
            positive_signals=positive,
            negative_signals=negative,
            latest_signal_at=latest_signal_at,
            evidence_node_ids=[*evidence_node_ids, conflict_node.id],
            details={
                "reason": "contradictory_evidence",
                "detector": "automatic",
                "positive_signals": positive,
                "negative_signals": negative,
                "evidence_source_counts": source_counts,
                "chosen_evidence_id": chosen_evidence_id,
                "discarded_evidence_ids": discarded_evidence_ids,
                "resolution_reason": resolution_reason,
            },
            audit_log_id=audit.id,
        )
        db.add(conflict)
        db.flush()
        _record_conflict_resolution(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_id=control_id,
            conflict_id=conflict.id,
            chosen_evidence_id=chosen_evidence_id,
            discarded_evidence_ids=discarded_evidence_ids,
            reason=resolution_reason,
        )
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action="control.conflict.resolution",
            resource_type="control_conflict",
            resource_id=conflict.id,
            payload={
                "control_id": control_id,
                "ai_system_id": ai_system_id,
                "chosen_evidence_id": chosen_evidence_id,
                "discarded_evidence_ids": discarded_evidence_ids,
                "reason": resolution_reason,
                "evidence_source_counts": source_counts,
            },
        )
        return True

    return open_conflict is not None


def recalculate_control_maturity(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_ids: list[str] | None = None,
    reason: str = "recalculation",
) -> list[ControlMaturity]:
    ai_system = db.scalar(select(AISystem).where(AISystem.id == ai_system_id, AISystem.tenant_id == tenant_id))
    if not ai_system:
        return []

    controls_query = select(Control).where(Control.tenant_id == tenant_id)
    if control_ids:
        controls_query = controls_query.where(Control.id.in_(control_ids))
    controls = db.scalars(controls_query).all()

    policy_versions = db.scalars(
        select(PolicyVersion)
        .join(PolicyPack, PolicyPack.id == PolicyVersion.pack_id)
        .where(PolicyVersion.tenant_id == tenant_id, PolicyPack.status == "active")
        .order_by(desc(PolicyVersion.created_at))
    ).all()

    monitoring_exists = db.scalar(
        select(MonitoringSignal.id).where(MonitoringSignal.tenant_id == tenant_id, MonitoringSignal.ai_system_id == ai_system_id).limit(1)
    )
    monitoring_score = 1.0 if monitoring_exists else 0.0

    mapped_defs = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()
    control_to_sim_defs: dict[str, set[str]] = defaultdict(set)
    for sim_def in mapped_defs:
        for cid in (sim_def.dsl_json.get("maps_to_controls") or []):
            control_to_sim_defs[cid].add(sim_def.id)

    recent_runs = db.scalars(
        select(SimulationRun)
        .where(SimulationRun.tenant_id == tenant_id, SimulationRun.ai_system_id == ai_system_id)
        .order_by(desc(SimulationRun.started_at))
        .limit(200)
    ).all()

    recent_events = db.scalars(
        select(EnforcementEvent)
        .where(EnforcementEvent.tenant_id == tenant_id, EnforcementEvent.ai_system_id == ai_system_id)
        .order_by(desc(EnforcementEvent.timestamp))
        .limit(300)
    ).all()

    control_pass_counts: dict[str, tuple[float, int]] = defaultdict(lambda: (0.0, 0))
    for run in recent_runs:
        pass_total, iteration_total, _pass_rate = _run_pass_metrics(run)
        impacted = run.controls_impacted or []
        for item in impacted:
            cid = item.get("control_id")
            if not cid:
                continue
            passed, total = control_pass_counts[cid]
            passed += pass_total
            total += iteration_total
            control_pass_counts[cid] = (passed, total)

    changed_rows: list[ControlMaturity] = []
    now = datetime.now(timezone.utc)

    for control in controls:
        policy_present = 0.0
        enforcement_enabled = 0.0

        for pv in policy_versions:
            guardians = pv.guardian_contracts or []
            for guardian in guardians:
                links = ((guardian.get("evidence") or {}).get("link_to_controls") or [])
                if control.id in links:
                    policy_present = 1.0
                    if guardian.get("enabled"):
                        enforcement_enabled = 1.0
                    break

        technical = _clamp((policy_present + enforcement_enabled + monitoring_score) / 3.0)

        passed, total = control_pass_counts.get(control.id, (0.0, 0))
        simulation_pass_rate = _clamp((passed / total) if total else 0.0)

        mapped_count = len(control_to_sim_defs.get(control.id, set()))
        total_defs = max(1, len(mapped_defs))
        coverage = _clamp(mapped_count / total_defs)

        maturity = _clamp(0.5 * technical + 0.3 * simulation_pass_rate + 0.2 * coverage)

        signal_stats_raw = _extract_conflict_stats(
            control_id=control.id,
            db=db,
            tenant_id=tenant_id,
            recent_runs=recent_runs,
            recent_events=recent_events,
        )
        signal_stats = _with_evidence_sources(db, tenant_id=tenant_id, stats=signal_stats_raw)
        has_open_conflict = _sync_control_conflict(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_id=control.id,
            stats=signal_stats,
        )

        confidence_score, confidence_inputs = _compute_confidence_inputs(
            evidence_count=len(signal_stats["evidence_node_ids"]),
            positive_signals=signal_stats["positive_signals"],
            negative_signals=signal_stats["negative_signals"],
            telemetry_evidence_count=int((signal_stats.get("evidence_source_counts") or {}).get("telemetry", 0)),
            simulation_evidence_count=int((signal_stats.get("evidence_source_counts") or {}).get("simulation", 0)),
            has_conflict=has_open_conflict,
            latest_signal_at=signal_stats["latest_signal_at"],
            now=now,
        )
        status = "contested" if has_open_conflict else ("needs_review" if confidence_score < CONFIDENCE_THRESHOLD else "healthy")

        row = db.scalar(
            select(ControlMaturity).where(
                ControlMaturity.tenant_id == tenant_id,
                ControlMaturity.ai_system_id == ai_system_id,
                ControlMaturity.control_id == control.id,
            )
        )

        if not row:
            row = ControlMaturity(
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                control_id=control.id,
                technical_enforcement_score=technical,
                simulation_pass_rate=simulation_pass_rate,
                coverage_score=coverage,
                maturity_score=maturity,
                status=status,
                confidence_score=confidence_score,
                confidence_inputs=confidence_inputs,
            )
            db.add(row)
        else:
            row.technical_enforcement_score = technical
            row.simulation_pass_rate = simulation_pass_rate
            row.coverage_score = coverage
            row.maturity_score = maturity
            row.status = status
            row.confidence_score = confidence_score
            row.confidence_inputs = confidence_inputs
            row.updated_at = datetime.now(timezone.utc)

        hist = ControlMaturityHistory(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_id=control.id,
            technical_enforcement_score=technical,
            simulation_pass_rate=simulation_pass_rate,
            coverage_score=coverage,
            maturity_score=maturity,
            status=status,
            confidence_score=confidence_score,
            confidence_inputs=confidence_inputs,
            reason=reason,
        )
        db.add(hist)
        changed_rows.append(row)

    db.flush()
    return changed_rows


def get_control_traceability(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
) -> list[dict[str, Any]]:
    ai_system = db.scalar(select(AISystem).where(AISystem.id == ai_system_id, AISystem.tenant_id == tenant_id))
    if not ai_system:
        raise ValueError("AI system not found for tenant")

    controls = db.scalars(select(Control).where(Control.tenant_id == tenant_id)).all()
    definitions = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()

    runs = db.scalars(
        select(SimulationRun)
        .where(SimulationRun.tenant_id == tenant_id, SimulationRun.ai_system_id == ai_system_id)
        .order_by(desc(SimulationRun.started_at))
    ).all()
    latest_by_sim_id: dict[str, SimulationRun] = {}
    for run in runs:
        if run.simulation_id not in latest_by_sim_id:
            latest_by_sim_id[run.simulation_id] = run

    maturity_rows = db.scalars(
        select(ControlMaturity).where(ControlMaturity.tenant_id == tenant_id, ControlMaturity.ai_system_id == ai_system_id)
    ).all()
    maturity_by_control = {row.control_id: row for row in maturity_rows}

    traces: list[dict[str, Any]] = []
    for control in controls:
        mapped_simulations: list[dict[str, Any]] = []
        latest_control_run: SimulationRun | None = None

        for sim in definitions:
            mapped_controls = sim.dsl_json.get("maps_to_controls") or []
            if control.id not in mapped_controls:
                continue

            run = latest_by_sim_id.get(sim.id)
            run_summary = None
            if run:
                if not latest_control_run or (run.started_at and run.started_at > latest_control_run.started_at):
                    latest_control_run = run

                _passes, iterations, pass_rate = _run_pass_metrics(run)
                contribution = 0.0
                for item in (run.controls_impacted or []):
                    if item.get("control_id") == control.id:
                        contribution = _to_float(item.get("contribution", 0.0), 0.0)
                        break

                run_summary = {
                    "run_id": run.id,
                    "result": (run.results or {}).get("result", "fail"),
                    "pass_rate": pass_rate,
                    "iterations": iterations,
                    "started_at": run.started_at,
                    "finished_at": run.finished_at,
                    "contribution": contribution,
                }

            mapped_simulations.append(
                {
                    "simulation_id": sim.id,
                    "name": sim.name,
                    "category": sim.category,
                    "target_module": sim.target_module,
                    "version": sim.version,
                    "last_run": run_summary,
                }
            )

        mapped_simulations.sort(key=lambda row: row["name"])

        maturity = maturity_by_control.get(control.id)
        maturity_impact = None
        if maturity:
            maturity_impact = {
                "technical_enforcement_score": maturity.technical_enforcement_score,
                "simulation_pass_rate": maturity.simulation_pass_rate,
                "coverage_score": maturity.coverage_score,
                "maturity_score": maturity.maturity_score,
                "status": maturity.status,
                "confidence_score": maturity.confidence_score,
                "updated_at": maturity.updated_at,
            }

        last_run_result = None
        if latest_control_run:
            _passes, iterations, pass_rate = _run_pass_metrics(latest_control_run)
            last_run_result = {
                "run_id": latest_control_run.id,
                "simulation_id": latest_control_run.simulation_id,
                "result": (latest_control_run.results or {}).get("result", "fail"),
                "pass_rate": pass_rate,
                "iterations": iterations,
                "started_at": latest_control_run.started_at,
            }

        traces.append(
            {
                "control_id": control.id,
                "control_name": control.name,
                "control_category": control.category,
                "mapped_simulations": mapped_simulations,
                "last_run_result": last_run_result,
                "maturity_impact": maturity_impact,
            }
        )

    traces.sort(key=lambda row: row["control_id"])
    return traces


def get_maturity_score_explanation(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_id: str,
) -> dict[str, Any]:
    ai_system = db.scalar(select(AISystem).where(AISystem.id == ai_system_id, AISystem.tenant_id == tenant_id))
    if not ai_system:
        raise ValueError("AI system not found for tenant")

    maturity = db.scalar(
        select(ControlMaturity).where(
            ControlMaturity.tenant_id == tenant_id,
            ControlMaturity.ai_system_id == ai_system_id,
            ControlMaturity.control_id == control_id,
        )
    )
    if not maturity:
        raise ValueError("Control maturity not found for tenant and ai_system")

    control = db.scalar(
        select(Control).where(
            Control.id == control_id,
            Control.tenant_id == tenant_id,
        )
    )
    if not control:
        raise ValueError("Control not found for tenant")

    framework_names: set[str] = set()
    for item in (control.mapped_framework_refs or []):
        if isinstance(item, dict):
            value = str(item.get("framework") or "").strip()
            if value:
                framework_names.add(value)
        else:
            text = str(item).strip()
            if text:
                framework_names.add(text)
    kb_framework_rows = db.execute(
        select(KBFramework.name)
        .join(KBControl, KBControl.framework_id == KBFramework.id)
        .where(KBControl.id == control_id)
    ).all()
    for (name,) in kb_framework_rows:
        cleaned = str(name or "").strip()
        if cleaned:
            framework_names.add(cleaned)
    frameworks = sorted(framework_names) or ["UNMAPPED"]
    domain = str(control.category or "").strip() or "unknown"

    weights = {
        "technical_enforcement_score": 0.5,
        "simulation_pass_rate": 0.3,
        "coverage_score": 0.2,
    }

    recomputed_score = _clamp(
        (weights["technical_enforcement_score"] * maturity.technical_enforcement_score)
        + (weights["simulation_pass_rate"] * maturity.simulation_pass_rate)
        + (weights["coverage_score"] * maturity.coverage_score)
    )

    active_policy_versions = db.scalars(
        select(PolicyVersion)
        .join(PolicyPack, PolicyPack.id == PolicyVersion.pack_id)
        .where(PolicyVersion.tenant_id == tenant_id, PolicyPack.status == "active")
        .order_by(desc(PolicyVersion.created_at))
    ).all()

    policy_links: list[dict[str, Any]] = []
    for policy_version in active_policy_versions:
        for guardian in (policy_version.guardian_contracts or []):
            linked_controls = ((guardian.get("evidence") or {}).get("link_to_controls") or [])
            if control_id not in linked_controls:
                continue
            policy_links.append(
                {
                    "policy_version_id": policy_version.id,
                    "policy_pack_id": policy_version.pack_id,
                    "guardian_id": guardian.get("guardian_id"),
                    "guardian_enabled": bool(guardian.get("enabled", False)),
                    "path": f"/policies/packs/{policy_version.pack_id}/versions",
                }
            )

    all_sim_defs = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()
    mapped_sim_defs = [row for row in all_sim_defs if control_id in (row.dsl_json.get("maps_to_controls") or [])]
    mapped_sim_ids = [row.id for row in mapped_sim_defs]

    simulation_runs: list[SimulationRun] = []
    if mapped_sim_ids:
        simulation_runs = db.scalars(
            select(SimulationRun)
            .where(
                SimulationRun.tenant_id == tenant_id,
                SimulationRun.ai_system_id == ai_system_id,
                SimulationRun.simulation_id.in_(mapped_sim_ids),
            )
            .order_by(desc(SimulationRun.started_at))
            .limit(30)
        ).all()

    run_links: list[dict[str, Any]] = []
    linked_event_ids: list[str] = []
    linked_evidence_ids: list[str] = []

    for run in simulation_runs:
        _passes, iterations, pass_rate = _run_pass_metrics(run)
        payload = run.results or {}
        run_links.append(
            {
                "run_id": run.id,
                "simulation_id": run.simulation_id,
                "result": payload.get("result", "fail"),
                "pass_rate": pass_rate,
                "iterations": iterations,
                "started_at": run.started_at,
                "finished_at": run.finished_at,
                "failed_assertions": payload.get("failed_assertions", []),
                "path": "/simulations/runs",
            }
        )
        linked_event_ids.extend(payload.get("enforcement_events_linked", []))
        linked_evidence_ids.extend(payload.get("evidence_nodes_created", []))

    enforcement_events: list[EnforcementEvent] = []
    if linked_event_ids:
        enforcement_events = db.scalars(
            select(EnforcementEvent).where(
                EnforcementEvent.tenant_id == tenant_id,
                EnforcementEvent.id.in_(linked_event_ids),
            )
        ).all()

    event_links: list[dict[str, Any]] = []
    for event in enforcement_events:
        event_links.append(
            {
                "event_id": event.id,
                "request_id": event.request_id,
                "final_decision": event.final_decision,
                "timestamp": event.timestamp,
                "policy_version_id": event.policy_version_id,
                "path": "/enforcement/events",
            }
        )
        linked_evidence_ids.extend(event.evidence_nodes_created or [])

    monitoring_signals = db.scalars(
        select(MonitoringSignal)
        .where(MonitoringSignal.tenant_id == tenant_id, MonitoringSignal.ai_system_id == ai_system_id)
        .order_by(desc(MonitoringSignal.created_at))
        .limit(20)
    ).all()

    unique_evidence_ids: list[str] = []
    seen_evidence = set()
    for node_id in linked_evidence_ids:
        if not node_id or node_id in seen_evidence:
            continue
        seen_evidence.add(node_id)
        unique_evidence_ids.append(node_id)

    evidence_nodes = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id.in_(unique_evidence_ids) if unique_evidence_ids else EvidenceNode.id == "__none__",
        )
    ).all()
    evidence_by_id = {node.id: node for node in evidence_nodes}

    history = db.scalars(
        select(ControlMaturityHistory)
        .where(
            ControlMaturityHistory.tenant_id == tenant_id,
            ControlMaturityHistory.ai_system_id == ai_system_id,
            ControlMaturityHistory.control_id == control_id,
        )
        .order_by(desc(ControlMaturityHistory.created_at))
        .limit(10)
    ).all()

    conflicts = db.scalars(
        select(ControlConflict)
        .where(
            ControlConflict.tenant_id == tenant_id,
            ControlConflict.ai_system_id == ai_system_id,
            ControlConflict.control_id == control_id,
        )
        .order_by(desc(ControlConflict.detected_at))
        .limit(5)
    ).all()
    resolutions = db.scalars(
        select(ConflictResolution)
        .where(
            ConflictResolution.tenant_id == tenant_id,
            ConflictResolution.ai_system_id == ai_system_id,
            ConflictResolution.control_id == control_id,
        )
        .order_by(desc(ConflictResolution.created_at))
        .limit(5)
    ).all()

    implementation_state = _implementation_state(
        technical=float(maturity.technical_enforcement_score),
        simulation_pass_rate=float(maturity.simulation_pass_rate),
        coverage=float(maturity.coverage_score),
        maturity=float(maturity.maturity_score),
        status=str(maturity.status or ""),
    )
    implementation_reasoning = _implementation_reasoning(
        technical=float(maturity.technical_enforcement_score),
        simulation_pass_rate=float(maturity.simulation_pass_rate),
        coverage=float(maturity.coverage_score),
        maturity=float(maturity.maturity_score),
        status=str(maturity.status or ""),
    )

    confidence_inputs = dict(maturity.confidence_inputs or {})
    process_evidence_score = _clamp(
        (0.5 * _to_float(confidence_inputs.get("evidence_count_score"), 0.0))
        + (0.5 * _to_float(confidence_inputs.get("signal_freshness"), 0.0))
    )
    process_evidence_reasoning = [
        f"evidence_count_score={_to_float(confidence_inputs.get('evidence_count_score'), 0.0):.2f}",
        f"signal_freshness={_to_float(confidence_inputs.get('signal_freshness'), 0.0):.2f}",
        f"conflict_penalty={_to_float(confidence_inputs.get('conflict_penalty'), 0.0):.2f}",
        f"derived_process_evidence_score={process_evidence_score:.2f}",
    ]

    direct_evidence_links = [
        {
            "node_id": node_id,
            "signal_type": evidence_by_id[node_id].signal_type if node_id in evidence_by_id else None,
            "created_at": evidence_by_id[node_id].created_at if node_id in evidence_by_id else None,
            "path": "/trust-center/evidence/nodes",
        }
        for node_id in unique_evidence_ids
    ]
    evidence_influence = {
        "policy_guardian_links": len(policy_links),
        "simulation_runs": len(run_links),
        "enforcement_events": len(event_links),
        "monitoring_signals": len(monitoring_signals),
        "direct_evidence_nodes": len(direct_evidence_links),
        "open_conflicts": len([row for row in conflicts if str(row.status) == "open"]),
    }

    return {
        "tenant_id": tenant_id,
        "ai_system_id": ai_system_id,
        "control_id": control.id,
        "control_name": control.name,
        "domain": domain,
        "frameworks": frameworks,
        "implementation_state": implementation_state,
        "implementation_reasoning": implementation_reasoning,
        "formula": "maturity_score = 0.5*technical_enforcement_score + 0.3*simulation_pass_rate + 0.2*coverage_score",
        "weights": weights,
        "scoring_inputs": {
            "technical_enforcement_score": maturity.technical_enforcement_score,
            "simulation_pass_rate": maturity.simulation_pass_rate,
            "coverage_score": maturity.coverage_score,
        },
        "status": maturity.status,
        "confidence_score": maturity.confidence_score,
        "confidence_inputs": maturity.confidence_inputs,
        "maturity_score": maturity.maturity_score,
        "recomputed_maturity_score": recomputed_score,
        "score_delta": round(maturity.maturity_score - recomputed_score, 8),
        "control_posture_explanation": {
            "status": implementation_state,
            "why": implementation_reasoning,
            "evidence_influence": evidence_influence,
            "direct_evidence_links": direct_evidence_links[:50],
        },
        "maturity_component_explanation": {
            "technical_enforcement": {
                "score": maturity.technical_enforcement_score,
                "why": [
                    f"policy_guardian_links={len(policy_links)}",
                    f"enforcement_events={len(event_links)}",
                    f"monitoring_signals={len(monitoring_signals)}",
                ],
            },
            "coverage": {
                "score": maturity.coverage_score,
                "why": [
                    f"mapped_simulations={len(mapped_sim_defs)}",
                    f"total_simulation_runs_considered={len(simulation_runs)}",
                ],
            },
            "process_evidence": {
                "score": process_evidence_score,
                "why": process_evidence_reasoning,
            },
        },
        "evidence_links": {
            "policy_guardians": policy_links,
            "simulation_runs": run_links,
            "enforcement_events": event_links,
            "evidence_nodes": direct_evidence_links,
            "monitoring_signals": [
                {"signal_id": signal.id, "created_at": signal.created_at, "path": "/monitoring/signals"} for signal in monitoring_signals
            ],
        },
        "conflicts": [
            {
                "conflict_id": conflict.id,
                "status": conflict.status,
                "reason": conflict.reason,
                "positive_signals": conflict.positive_signals,
                "negative_signals": conflict.negative_signals,
                "detected_at": conflict.detected_at,
                "resolved_at": conflict.resolved_at,
                "resolution_decision": conflict.resolution_decision,
            }
            for conflict in conflicts
        ],
        "conflict_resolutions": [
            {
                "resolution_id": row.id,
                "conflict_id": row.conflict_id,
                "chosen_evidence_id": row.chosen_evidence_id,
                "discarded_evidence_ids": row.discarded_evidence_ids,
                "reason": row.reason,
                "created_at": row.created_at,
            }
            for row in resolutions
        ],
        "evidence_precedence": [
            {"source": "telemetry", "rank": 1},
            {"source": "simulation", "rank": 2},
            {"source": "configuration", "rank": 3},
            {"source": "documentation", "rank": 4},
        ],
        "recent_history": [
            {
                "history_id": row.id,
                "reason": row.reason,
                "technical_enforcement_score": row.technical_enforcement_score,
                "simulation_pass_rate": row.simulation_pass_rate,
                "coverage_score": row.coverage_score,
                "maturity_score": row.maturity_score,
                "status": row.status,
                "confidence_score": row.confidence_score,
                "confidence_inputs": row.confidence_inputs,
                "created_at": row.created_at,
            }
            for row in history
        ],
    }
