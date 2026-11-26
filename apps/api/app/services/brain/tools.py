from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.observability import get_correlation_id
from app.core.rbac import ROLE_ORDER, roles_meeting
from app.db.models.ai_system import AISystem
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.finding import Finding
from app.db.models.job_run import ScheduledJobRun
from app.services.self_recovery import plain_job_failure
from app.db.models.maturity import ControlConflict
from app.db.models.monitoring import Connector
from app.db.models.policy import ApprovalRequest, PolicyPack, PolicyVersion
from app.db.models.simulation import SimulationDefinition, SimulationRun
from app.db.models.snapshot import AuditorSnapshot
from app.services.ai_iam_service import mint_capability_token, revoke_capability_token
from app.services.brain.finding_analyzer import analyze_finding
from app.services.mcp.context import MCPExecutionContext
from app.services.mcp.contracts import ToolContract, ToolRegistration
from app.services.mcp.registry import get_mcp_registry
from app.services.monitoring_service import connector_catalog, connector_control_coverage, run_connector_once
from app.services.platform_mode_service import get_tenant_platform_mode
from app.services.simulation_service import run_simulation
from app.services.snapshot_service import (
    artifact_download_url,
    artifact_relative_path,
    create_auditor_snapshot,
    export_audit_artifacts,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _parse_limit(value: Any, default: int = 20, max_limit: int = 200) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(max_limit, parsed))


def _parse_cursor(value: Any) -> int:
    try:
        parsed = int(str(value or "0"))
    except (TypeError, ValueError):
        parsed = 0
    return max(0, parsed)


def _next_cursor(offset: int, limit: int, total: int) -> str | None:
    next_offset = offset + limit
    if next_offset >= total:
        return None
    return str(next_offset)


@dataclass
class ToolContext:
    db: Session
    tenant_id: str
    user_id: str
    user_role: str


def _roles_at_or_above(min_role: str) -> list[str]:
    threshold = ROLE_ORDER.get(min_role, 999)
    return [role for role, order in ROLE_ORDER.items() if order >= threshold]


def _roles_for_changes(min_role: str) -> list[str]:
    """Roles that may run a tool that writes or enforces: never a read-only role such as the auditor (app/core/rbac.py)."""

    return roles_meeting(min_role, write=True)


def _normalize_ai_system_row(row: AISystem) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "description": row.description,
        "risk_tier": row.risk_tier,
        "status": row.status,
        "metadata_json": row.metadata_json,
    }


def _tool_governance_list_ai_systems(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    filters = args.get("filters") or {}
    limit = _parse_limit(args.get("limit"), default=20, max_limit=200)
    offset = _parse_cursor(args.get("cursor"))

    query = select(AISystem).where(AISystem.tenant_id == ctx.tenant_id).order_by(AISystem.created_at.desc())
    rows = ctx.db.scalars(query).all()

    if isinstance(filters, dict):
        risk_tier = filters.get("risk_tier")
        status = filters.get("status")
        name_contains = filters.get("name_contains")
        if risk_tier:
            rows = [row for row in rows if row.risk_tier == risk_tier]
        if status:
            rows = [row for row in rows if row.status == status]
        if name_contains:
            needle = str(name_contains).lower()
            rows = [row for row in rows if needle in row.name.lower()]

    total = len(rows)
    sliced = rows[offset : offset + limit]
    return {
        "items": [_normalize_ai_system_row(row) for row in sliced],
        "total": total,
        "cursor": _next_cursor(offset, limit, total),
    }


def _tool_governance_get_ai_system(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ai_system_id = str(args.get("id") or args.get("ai_system_id") or "").strip()
    if not ai_system_id:
        raise ValueError("governance.get_ai_system requires 'id'")

    row = ctx.db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == ctx.tenant_id,
        )
    )
    if not row:
        raise ValueError("AI system not found for tenant")
    return {"ai_system": _normalize_ai_system_row(row)}


def _tool_policies_get_policy_version(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    policy_version_id = str(args.get("policy_version_id") or "").strip()
    if not policy_version_id:
        raise ValueError("policies.get_policy_version requires 'policy_version_id'")

    row = ctx.db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant_id,
        )
    )
    if not row:
        raise ValueError("Policy version not found for tenant")

    return {
        "policy_version": {
            "id": row.id,
            "pack_id": row.pack_id,
            "version": row.version,
            "scope": row.scope,
            "enforcement_defaults": row.enforcement_defaults,
            "guardian_contracts": row.guardian_contracts,
            "contract_json": row.contract_json,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
    }


def _tool_policies_get_guardian_matrix(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    policy_version_id = str(args.get("policy_version_id") or "").strip()
    if not policy_version_id:
        raise ValueError("policies.get_guardian_matrix requires 'policy_version_id'")

    row = ctx.db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant_id,
        )
    )
    if not row:
        raise ValueError("Policy version not found for tenant")

    guardians: list[dict[str, Any]] = []
    for guardian in row.guardian_contracts or []:
        impact = guardian.get("control_impact") or {}
        guardians.append(
            {
                "guardian_id": guardian.get("guardian_id"),
                "description": guardian.get("description", ""),
                "enabled": bool(guardian.get("enabled", False)),
                "triggers": guardian.get("trigger") or {"signal_types": [], "conditions": []},
                "thresholds": guardian.get("evaluation") or {"method": "rules", "confidence_threshold": 0.0},
                "actions": guardian.get("actions") or {},
                "mapped_controls": ((guardian.get("evidence") or {}).get("link_to_controls") or []),
                "control_impact_deltas": {
                    "maturity_delta_on_fail": float(impact.get("maturity_delta_on_fail", 0.0)),
                    "enforcement_strictness_increase": int(impact.get("enforcement_strictness_increase", 0)),
                    "increase_simulation_frequency": bool(impact.get("increase_simulation_frequency", False)),
                },
            }
        )

    return {
        "policy_version_id": row.id,
        "guardians": guardians,
    }


def _tool_evidence_query(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    filters = args.get("filters") or {}
    time_range = args.get("time_range") or {}
    limit = _parse_limit(args.get("limit"), default=50, max_limit=500)
    offset = _parse_cursor(args.get("cursor"))

    query = select(EvidenceNode).where(EvidenceNode.tenant_id == ctx.tenant_id).order_by(EvidenceNode.created_at.desc())
    rows = ctx.db.scalars(query).all()

    if isinstance(time_range, dict):
        start_at = _parse_iso_datetime(time_range.get("start"))
        end_at = _parse_iso_datetime(time_range.get("end"))
        if start_at:
            rows = [row for row in rows if row.created_at and row.created_at >= start_at]
        if end_at:
            rows = [row for row in rows if row.created_at and row.created_at <= end_at]

    if isinstance(filters, dict):
        signal_type = filters.get("signal_type")
        node_type = filters.get("node_type")
        correlation_id = filters.get("correlation_id")
        if signal_type:
            rows = [row for row in rows if row.signal_type == signal_type]
        if node_type:
            rows = [row for row in rows if row.node_type == node_type]
        if correlation_id:
            rows = [row for row in rows if row.correlation_id == correlation_id]

    total = len(rows)
    sliced = rows[offset : offset + limit]
    evidence_ids = [row.id for row in sliced]
    return {
        "items": [
            {
                "id": row.id,
                "node_type": row.node_type,
                "signal_type": row.signal_type,
                "label": row.label,
                "payload": row.payload,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in sliced
        ],
        "total": total,
        "cursor": _next_cursor(offset, limit, total),
        "evidence_node_ids": evidence_ids,
    }


def _tool_enforcement_list_events(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    filters = args.get("filters") or {}
    limit = _parse_limit(args.get("limit"), default=50, max_limit=500)
    offset = _parse_cursor(args.get("cursor"))

    query = select(EnforcementEvent).where(EnforcementEvent.tenant_id == ctx.tenant_id).order_by(EnforcementEvent.timestamp.desc())
    rows = ctx.db.scalars(query).all()

    if isinstance(filters, dict):
        ai_system_id = filters.get("ai_system_id")
        final_decision = filters.get("final_decision")
        policy_version_id = filters.get("policy_version_id")
        if ai_system_id:
            rows = [row for row in rows if row.ai_system_id == ai_system_id]
        if final_decision:
            rows = [row for row in rows if row.final_decision == final_decision]
        if policy_version_id:
            rows = [row for row in rows if row.policy_version_id == policy_version_id]

    total = len(rows)
    sliced = rows[offset : offset + limit]
    evidence_ids: list[str] = []
    for row in sliced:
        for node_id in row.evidence_nodes_created or []:
            if node_id and node_id not in evidence_ids:
                evidence_ids.append(str(node_id))

    return {
        "items": [
            {
                "id": row.id,
                "ai_system_id": row.ai_system_id,
                "request_id": row.request_id,
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "final_decision": row.final_decision,
                "policy_version_id": row.policy_version_id,
                "evidence_nodes_created": row.evidence_nodes_created or [],
                "controls_impacted": row.controls_impacted or [],
            }
            for row in sliced
        ],
        "total": total,
        "cursor": _next_cursor(offset, limit, total),
        "evidence_node_ids": evidence_ids,
    }


def _tool_simulations_list_for_control(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    control_id = str(args.get("control_id") or "").strip()
    ai_system_id = str(args.get("ai_system_id") or "").strip() or None
    if not control_id:
        raise ValueError("simulations.list_for_control requires 'control_id'")

    sims = ctx.db.scalars(
        select(SimulationDefinition)
        .where(SimulationDefinition.tenant_id == ctx.tenant_id)
        .order_by(SimulationDefinition.created_at.desc())
    ).all()
    mapped = [row for row in sims if control_id in (((row.dsl_json or {}).get("maps_to_controls")) or [])]

    items: list[dict[str, Any]] = []
    for sim in mapped:
        run_query = (
            select(SimulationRun)
            .where(
                SimulationRun.tenant_id == ctx.tenant_id,
                SimulationRun.simulation_id == sim.id,
            )
            .order_by(SimulationRun.started_at.desc())
        )
        if ai_system_id:
            run_query = run_query.where(SimulationRun.ai_system_id == ai_system_id)
        latest_run = ctx.db.scalar(run_query.limit(1))

        items.append(
            {
                "simulation_id": sim.id,
                "name": sim.name,
                "version": sim.version,
                "category": sim.category,
                "target_module": sim.target_module,
                "last_run_result": ((latest_run.results or {}).get("result") if latest_run else None),
                "last_run_at": (latest_run.started_at.isoformat() if latest_run and latest_run.started_at else None),
            }
        )

    return {
        "control_id": control_id,
        "ai_system_id": ai_system_id,
        "items": items,
        "total": len(items),
    }


def _tool_simulations_run(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    simulation_id = str(args.get("simulation_id") or "").strip()
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    if not simulation_id:
        raise ValueError("simulations.run requires 'simulation_id'")
    if not ai_system_id:
        raise ValueError("simulations.run requires 'ai_system_id'")

    simulation = ctx.db.scalar(
        select(SimulationDefinition).where(
            SimulationDefinition.id == simulation_id,
            SimulationDefinition.tenant_id == ctx.tenant_id,
        )
    )
    if not simulation:
        raise ValueError("Simulation definition not found for tenant")

    run = run_simulation(
        ctx.db,
        tenant_id=ctx.tenant_id,
        simulation=simulation,
        ai_system_id=ai_system_id,
        mode=str(args.get("mode") or "deterministic"),
        stochastic_runs=_parse_limit(args.get("stochastic_runs"), default=5, max_limit=50),
        inputs_used=(args.get("inputs_used") or {}),
        actor_user_id=ctx.user_id,
    )
    results = run.results or {}
    return {
        "simulation_run_id": run.id,
        "result": results.get("result"),
        "pass_rate": results.get("pass_rate"),
        "failed_assertions": results.get("failed_assertions", []),
        "evidence_node_ids": results.get("evidence_nodes_created", []),
        "enforcement_event_ids": results.get("enforcement_events_linked", []),
    }


def _tool_auditor_create_snapshot(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    snapshot = create_auditor_snapshot(
        ctx.db,
        tenant_id=ctx.tenant_id,
        ai_system_id=args.get("ai_system_id"),
        trigger_type="brain",
        payload={
            "framework": args.get("framework"),
            "period": args.get("period"),
            "source": "brain",
        },
        actor_user_id=ctx.user_id,
    )
    return {
        "snapshot_id": snapshot.id,
        "artifact_path": snapshot.artifact_path,
        "artifact_hash": snapshot.artifact_hash,
        "download_url": artifact_download_url(snapshot.id),
        "snapshot_ids": [snapshot.id],
    }


def _tool_auditor_export_snapshot(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    snapshot_id = str(args.get("snapshot_id") or "").strip()
    export_format = str(args.get("format") or "json").strip().lower()
    if not snapshot_id:
        raise ValueError("auditor.export_snapshot requires 'snapshot_id'")
    if export_format not in {"json", "csv"}:
        raise ValueError("auditor.export_snapshot format must be json|csv")

    snapshot = ctx.db.scalar(
        select(AuditorSnapshot).where(
            AuditorSnapshot.id == snapshot_id,
            AuditorSnapshot.tenant_id == ctx.tenant_id,
        )
    )
    if not snapshot:
        raise ValueError("Snapshot not found for tenant")

    if export_format == "json":
        return {
            "snapshot_id": snapshot.id,
            "format": "json",
            "artifact_path": snapshot.artifact_path,
            "artifact_relative_path": artifact_relative_path(snapshot.artifact_path),
            "download_url": artifact_download_url(snapshot.id),
            "snapshot_ids": [snapshot.id],
        }

    now = _utcnow()
    period_start = (
        ((snapshot.payload or {}).get("period") or {}).get("start")
        or (now - timedelta(days=30)).isoformat()
    )
    period_end = (
        ((snapshot.payload or {}).get("period") or {}).get("end")
        or now.isoformat()
    )
    out = export_audit_artifacts(
        ctx.db,
        tenant_id=ctx.tenant_id,
        ai_system_id=snapshot.ai_system_id,
        period_start=period_start,
        period_end=period_end,
    )
    return {
        "snapshot_id": snapshot.id,
        "format": "csv",
        "csv_artifact": out["csv"],
        "csv_relative_path": out["csv_relative_path"],
        "hash": out["hash"],
        "snapshot_ids": [snapshot.id],
    }


def _tool_ops_jobs_status(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    limit = _parse_limit(args.get("limit"), default=5, max_limit=50)
    rows = ctx.db.scalars(
        select(ScheduledJobRun)
        .where(or_(ScheduledJobRun.tenant_id == ctx.tenant_id, ScheduledJobRun.tenant_id.is_(None)))
        .order_by(ScheduledJobRun.started_at.desc())
        .limit(1000)
    ).all()

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        bucket = grouped.setdefault(row.job_name, [])
        if len(bucket) >= limit:
            continue
        bucket.append(
            {
                "id": row.id,
                "status": row.status,
                "tenant_id": row.tenant_id,
                "started_at": row.started_at.isoformat() if row.started_at else None,
                "finished_at": row.finished_at.isoformat() if row.finished_at else None,
                # A job of the whole installation: when and its reference, never its error's text (self_recovery.py).
                "error_message": plain_job_failure(row) if row.tenant_id is None and row.status != "success" else row.error_message,
            }
        )

    items = [{"job_name": name, "runs": runs} for name, runs in sorted(grouped.items())]
    return {"items": items, "total": len(items)}


def _tool_governance_update_ai_system_state(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    status = str(args.get("status") or "").strip()
    if not ai_system_id or not status:
        raise ValueError("governance.update_ai_system_state requires ai_system_id and status")
    row = ctx.db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("AI system not found for tenant")
    row.status = status
    metadata = dict(row.metadata_json or {})
    governance_state = str(args.get("governance_state") or "").strip()
    lifecycle_state = str(args.get("lifecycle_state") or "").strip()
    if governance_state:
        metadata["governance_state"] = governance_state.upper()
    if lifecycle_state:
        metadata["lifecycle_state"] = lifecycle_state.upper()
    row.metadata_json = metadata
    ctx.db.flush()
    return {"ai_system": _normalize_ai_system_row(row)}


def _tool_governance_assign_owner(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    owner_user_id = str(args.get("owner_user_id") or "").strip() or None
    owner_department = str(args.get("owner_department") or "").strip() or None
    if not ai_system_id:
        raise ValueError("governance.assign_owner requires ai_system_id")
    if not owner_user_id and not owner_department:
        raise ValueError("governance.assign_owner requires owner_user_id or owner_department")
    row = ctx.db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("AI system not found for tenant")
    metadata = dict(row.metadata_json or {})
    if owner_user_id:
        metadata["owner_user_id"] = owner_user_id
    if owner_department:
        metadata["owner_department"] = owner_department
    row.metadata_json = metadata
    ctx.db.flush()
    return {"ai_system": _normalize_ai_system_row(row)}


def _tool_governance_set_risk_tier(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    risk_tier = str(args.get("risk_tier") or "").strip().upper()
    if not ai_system_id or not risk_tier:
        raise ValueError("governance.set_risk_tier requires ai_system_id and risk_tier")
    row = ctx.db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("AI system not found for tenant")
    row.risk_tier = risk_tier
    ctx.db.flush()
    return {"ai_system": _normalize_ai_system_row(row)}


def _normalize_finding_row(row: Finding) -> dict[str, Any]:
    return {
        "finding_id": row.finding_id,
        "tenant_id": row.tenant_id,
        "source_surface": row.source_surface,
        "ai_tool": row.ai_tool,
        "ai_system_id": row.ai_system_id,
        "user_id": row.user_id,
        "department": row.department,
        "severity": row.severity,
        "finding_type": row.finding_type,
        "risk_category": row.risk_category,
        "status": row.status,
        "recommended_action": row.recommended_action,
        "policy_version_id": row.policy_version_id,
        "evidence_node_ids": row.evidence_node_ids or [],
        "related_control_ids": row.related_control_ids or [],
        "occurrence_count": int(row.occurrence_count or 0),
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


def _tool_findings_list(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    filters = args.get("filters") or {}
    limit = _parse_limit(args.get("limit"), default=50, max_limit=500)
    offset = _parse_cursor(args.get("cursor"))
    rows = ctx.db.scalars(
        select(Finding).where(Finding.tenant_id == ctx.tenant_id).order_by(Finding.updated_at.desc())
    ).all()
    if isinstance(filters, dict):
        if filters.get("severity"):
            rows = [row for row in rows if row.severity == filters.get("severity")]
        if filters.get("status"):
            rows = [row for row in rows if row.status == filters.get("status")]
        if filters.get("finding_type"):
            rows = [row for row in rows if row.finding_type == filters.get("finding_type")]
        if filters.get("department"):
            rows = [row for row in rows if row.department == filters.get("department")]
        if filters.get("ai_tool"):
            rows = [row for row in rows if row.ai_tool == filters.get("ai_tool")]
    total = len(rows)
    sliced = rows[offset : offset + limit]
    evidence_ids: list[str] = []
    for row in sliced:
        for node_id in row.evidence_node_ids or []:
            node = str(node_id).strip()
            if node and node not in evidence_ids:
                evidence_ids.append(node)
    return {
        "items": [_normalize_finding_row(row) for row in sliced],
        "total": total,
        "cursor": _next_cursor(offset, limit, total),
        "evidence_node_ids": evidence_ids,
    }


def _tool_findings_get(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(args.get("finding_id") or args.get("id") or "").strip()
    if not finding_id:
        raise ValueError("findings.get requires finding_id")
    row = ctx.db.scalar(
        select(Finding).where(
            Finding.finding_id == finding_id,
            Finding.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Finding not found for tenant")
    return {
        "finding": _normalize_finding_row(row),
        "evidence_node_ids": [str(node_id) for node_id in (row.evidence_node_ids or []) if str(node_id).strip()],
    }


def _tool_findings_update_status(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(args.get("finding_id") or "").strip()
    new_status = str(args.get("status") or "").strip().lower()
    if not finding_id or not new_status:
        raise ValueError("findings.update_status requires finding_id and status")
    row = ctx.db.scalar(
        select(Finding).where(
            Finding.finding_id == finding_id,
            Finding.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Finding not found for tenant")
    row.status = new_status
    ctx.db.flush()
    return {"finding": _normalize_finding_row(row)}


def _tool_findings_analyze(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(args.get("finding_id") or "").strip()
    if not finding_id:
        raise ValueError("findings.analyze requires finding_id")
    result = analyze_finding(
        ctx.db,
        tenant_id=ctx.tenant_id,
        finding_id=finding_id,
        actor_user_id=ctx.user_id,
        correlation_id=get_correlation_id(),
    )
    return result.model_dump()


def _tool_policies_activate_policy_version(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    policy_version_id = str(args.get("policy_version_id") or "").strip()
    if not policy_version_id:
        raise ValueError("policies.activate_policy_version requires policy_version_id")
    row = ctx.db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Policy version not found for tenant")
    pack = ctx.db.scalar(
        select(PolicyPack).where(
            PolicyPack.id == row.pack_id,
            PolicyPack.tenant_id == ctx.tenant_id,
        )
    )
    if pack is None:
        raise ValueError("Policy pack not found for tenant")
    pack.status = "active"
    ctx.db.flush()
    return {
        "policy_version_id": row.id,
        "pack_id": pack.id,
        "pack_status": pack.status,
        "version": row.version,
    }


def _tool_evidence_get_node(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    node_id = str(args.get("node_id") or args.get("id") or "").strip()
    if not node_id:
        raise ValueError("evidence.get_node requires node_id")
    row = ctx.db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == node_id,
            EvidenceNode.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Evidence node not found for tenant")
    return {
        "node": {
            "id": row.id,
            "correlation_id": row.correlation_id,
            "node_type": row.node_type,
            "signal_type": row.signal_type,
            "label": row.label,
            "payload": row.payload,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        },
        "evidence_node_ids": [row.id],
    }


def _tool_evidence_get_trace(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    node_id = str(args.get("node_id") or "").strip()
    max_depth = _parse_limit(args.get("depth"), default=2, max_limit=5)
    if not node_id:
        raise ValueError("evidence.get_trace requires node_id")
    root = ctx.db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == node_id,
            EvidenceNode.tenant_id == ctx.tenant_id,
        )
    )
    if root is None:
        raise ValueError("Evidence node not found for tenant")

    visited_nodes: dict[str, EvidenceNode] = {root.id: root}
    visited_edges: dict[str, EvidenceEdge] = {}
    frontier = {root.id}
    depth = 0
    while frontier and depth < max_depth:
        depth += 1
        edges = ctx.db.scalars(
            select(EvidenceEdge).where(
                EvidenceEdge.tenant_id == ctx.tenant_id,
                or_(EvidenceEdge.from_node_id.in_(list(frontier)), EvidenceEdge.to_node_id.in_(list(frontier))),
            )
        ).all()
        next_frontier: set[str] = set()
        for edge in edges:
            visited_edges[edge.id] = edge
            for candidate in [edge.from_node_id, edge.to_node_id]:
                if candidate not in visited_nodes:
                    node = ctx.db.scalar(
                        select(EvidenceNode).where(
                            EvidenceNode.id == candidate,
                            EvidenceNode.tenant_id == ctx.tenant_id,
                        )
                    )
                    if node is not None:
                        visited_nodes[node.id] = node
                        next_frontier.add(node.id)
        frontier = next_frontier

    return {
        "root_node_id": root.id,
        "nodes": [
            {
                "id": row.id,
                "node_type": row.node_type,
                "signal_type": row.signal_type,
                "label": row.label,
                "payload": row.payload,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in visited_nodes.values()
        ],
        "edges": [
            {
                "id": row.id,
                "from_node_id": row.from_node_id,
                "to_node_id": row.to_node_id,
                "edge_type": row.edge_type,
                "payload": row.payload,
            }
            for row in visited_edges.values()
        ],
        "evidence_node_ids": sorted(visited_nodes.keys()),
    }


def _tool_simulations_run_pack(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    if not ai_system_id:
        raise ValueError("simulations.run_pack requires ai_system_id")
    simulation_ids = [str(item).strip() for item in (args.get("simulation_ids") or []) if str(item).strip()]
    control_id = str(args.get("control_id") or "").strip()
    if not simulation_ids and control_id:
        sims = ctx.db.scalars(
            select(SimulationDefinition).where(SimulationDefinition.tenant_id == ctx.tenant_id)
        ).all()
        simulation_ids = [
            row.id
            for row in sims
            if control_id in (((row.dsl_json or {}).get("maps_to_controls")) or [])
        ]
    if not simulation_ids:
        raise ValueError("simulations.run_pack requires simulation_ids or control_id with mapped simulations")

    mode = str(args.get("mode") or "deterministic")
    stochastic_runs = _parse_limit(args.get("stochastic_runs"), default=5, max_limit=50)
    inputs_used = args.get("inputs_used") or {}
    runs: list[dict[str, Any]] = []
    evidence_node_ids: list[str] = []
    pass_count = 0
    for simulation_id in simulation_ids:
        simulation = ctx.db.scalar(
            select(SimulationDefinition).where(
                SimulationDefinition.id == simulation_id,
                SimulationDefinition.tenant_id == ctx.tenant_id,
            )
        )
        if simulation is None:
            continue
        run = run_simulation(
            ctx.db,
            tenant_id=ctx.tenant_id,
            simulation=simulation,
            ai_system_id=ai_system_id,
            mode=mode,
            stochastic_runs=stochastic_runs,
            inputs_used=inputs_used,
            actor_user_id=ctx.user_id,
        )
        result = str((run.results or {}).get("result") or "").strip().lower()
        if result == "pass":
            pass_count += 1
        run_evidence = [str(item) for item in ((run.results or {}).get("evidence_nodes_created") or []) if str(item).strip()]
        for node_id in run_evidence:
            if node_id not in evidence_node_ids:
                evidence_node_ids.append(node_id)
        runs.append(
            {
                "simulation_id": simulation.id,
                "simulation_run_id": run.id,
                "result": (run.results or {}).get("result"),
                "pass_rate": (run.results or {}).get("pass_rate"),
                "failed_assertions": (run.results or {}).get("failed_assertions", []),
                "evidence_node_ids": run_evidence,
            }
        )
    total = len(runs)
    pack_result = "pass" if total and pass_count == total else "fail"
    return {
        "ai_system_id": ai_system_id,
        "total_runs": total,
        "passed_runs": pass_count,
        "result": pack_result,
        "runs": runs,
        "evidence_node_ids": evidence_node_ids,
    }


def _tool_simulations_get_result(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    simulation_run_id = str(args.get("simulation_run_id") or args.get("run_id") or "").strip()
    if not simulation_run_id:
        raise ValueError("simulations.get_result requires simulation_run_id")
    row = ctx.db.scalar(
        select(SimulationRun).where(
            SimulationRun.id == simulation_run_id,
            SimulationRun.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Simulation run not found for tenant")
    results = row.results or {}
    return {
        "simulation_run_id": row.id,
        "simulation_id": row.simulation_id,
        "ai_system_id": row.ai_system_id,
        "result": results.get("result"),
        "pass_rate": results.get("pass_rate"),
        "failed_assertions": results.get("failed_assertions", []),
        "evidence_node_ids": results.get("evidence_nodes_created", []),
        "controls_impacted": row.controls_impacted or [],
    }


def _tool_auditor_get_snapshot(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    snapshot_id = str(args.get("snapshot_id") or "").strip()
    if not snapshot_id:
        raise ValueError("auditor.get_snapshot requires snapshot_id")
    row = ctx.db.scalar(
        select(AuditorSnapshot).where(
            AuditorSnapshot.id == snapshot_id,
            AuditorSnapshot.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Snapshot not found for tenant")
    return {
        "snapshot": {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "ai_system_id": row.ai_system_id,
            "trigger_type": row.trigger_type,
            "artifact_path": row.artifact_path,
            "artifact_hash": row.artifact_hash,
            "payload": row.payload,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "download_url": artifact_download_url(row.id),
        },
        "snapshot_ids": [row.id],
    }


def _tool_auditor_challenge_control(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    control_id = str(args.get("control_id") or "").strip()
    challenge_reason = str(args.get("challenge_reason") or "").strip()
    if not ai_system_id or not control_id or not challenge_reason:
        raise ValueError("auditor.challenge_control requires ai_system_id, control_id, challenge_reason")
    evidence_node_ids = [str(item).strip() for item in (args.get("evidence_node_ids") or []) if str(item).strip()]
    conflict = ControlConflict(
        tenant_id=ctx.tenant_id,
        ai_system_id=ai_system_id,
        control_id=control_id,
        status="open",
        reason="mcp_auditor_challenge",
        positive_signals=0,
        negative_signals=0,
        latest_signal_at=_utcnow(),
        evidence_node_ids=evidence_node_ids,
        details={
            "challenge_reason": challenge_reason,
            "requested_by": ctx.user_id,
            "source": "mcp",
        },
        audit_log_id=None,
    )
    ctx.db.add(conflict)
    ctx.db.flush()
    return {
        "conflict_id": conflict.id,
        "status": conflict.status,
        "ai_system_id": ai_system_id,
        "control_id": control_id,
        "evidence_node_ids": evidence_node_ids,
    }


def _tool_aiiam_get_agent(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    agent_id = str(args.get("agent_id") or args.get("id") or "").strip()
    if not agent_id:
        raise ValueError("aiiam.get_agent requires agent_id")
    row = ctx.db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Agent not found for tenant")
    return {
        "agent": {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "name": row.name,
            "description": row.description,
            "status": row.status,
            "owner_attested_at": row.owner_attested_at.isoformat() if row.owner_attested_at else None,
            "owner_attestation_expiry": row.owner_attestation_expiry.isoformat() if row.owner_attestation_expiry else None,
            "max_chain_depth": row.max_chain_depth,
            "capability_inheritance": row.capability_inheritance,
        }
    }


def _tool_aiiam_mint_token(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    agent_id = str(args.get("agent_id") or "").strip()
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    scopes = [str(item).strip() for item in (args.get("scopes") or []) if str(item).strip()]
    if not agent_id or not ai_system_id or not scopes:
        raise ValueError("aiiam.mint_token requires agent_id, ai_system_id, scopes")

    agent = ctx.db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == ctx.tenant_id,
        )
    )
    if agent is None:
        raise ValueError("Agent not found for tenant")
    ai_system = ctx.db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == ctx.tenant_id,
        )
    )
    if ai_system is None:
        raise ValueError("AI system not found for tenant")

    approval_request_id = str(args.get("approval_request_id") or "").strip() or None
    high_risk = str(ai_system.risk_tier or "").strip().upper() in {"HIGH", "CRITICAL", "RESTRICTED", "PROHIBITED"}
    if high_risk and not approval_request_id:
        raise ValueError("aiiam.mint_token requires approval_request_id for HIGH+ risk tier")
    if approval_request_id:
        req = ctx.db.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.id == approval_request_id,
                ApprovalRequest.tenant_id == ctx.tenant_id,
                ApprovalRequest.ai_system_id == ai_system_id,
            )
        )
        if req is None or req.status != "approved":
            raise ValueError("approval_request_id is not approved for this ai_system_id")

    raw_token = secrets.token_urlsafe(32)
    row = mint_capability_token(
        ctx.db,
        tenant_id=ctx.tenant_id,
        ai_system_id=ai_system_id,
        agent_identity_id=agent_id,
        raw_token=raw_token,
        scopes=scopes,
        expires_minutes=_parse_limit(args.get("expires_minutes"), default=120, max_limit=24 * 60),
        chain_depth=_parse_limit(args.get("chain_depth"), default=1, max_limit=agent.max_chain_depth),
        issued_by_user_id=ctx.user_id,
    )
    ctx.db.flush()
    return {
        "token_id": row.id,
        "capability_token": raw_token,
        "agent_id": agent_id,
        "ai_system_id": ai_system_id,
        "scopes": row.scopes,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
    }


def _tool_aiiam_revoke_token(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    token_id = str(args.get("token_id") or "").strip()
    if not token_id:
        raise ValueError("aiiam.revoke_token requires token_id")
    row = revoke_capability_token(ctx.db, tenant_id=ctx.tenant_id, token_id=token_id)
    if row is None:
        raise ValueError("Token not found for tenant")
    return {
        "token_id": row.id,
        "status": "revoked",
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
    }


def _tool_aiiam_kill_switch(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    agent_id = str(args.get("agent_id") or "").strip()
    if not agent_id:
        raise ValueError("aiiam.kill_switch requires agent_id")
    agent = ctx.db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == ctx.tenant_id,
        )
    )
    if agent is None:
        raise ValueError("Agent not found for tenant")
    agent.status = "isolated"
    now = _utcnow()
    tokens = ctx.db.scalars(
        select(CapabilityToken).where(
            CapabilityToken.tenant_id == ctx.tenant_id,
            CapabilityToken.agent_identity_id == agent_id,
        )
    ).all()
    revoked_tokens = 0
    for token in tokens:
        if token.revoked_at is None:
            token.revoked_at = now
            revoked_tokens += 1
    snap = create_auditor_snapshot(
        ctx.db,
        tenant_id=ctx.tenant_id,
        ai_system_id=None,
        trigger_type="kill_switch",
        payload={"agent_id": agent_id, "revoked_tokens": revoked_tokens, "source": "mcp"},
        actor_user_id=ctx.user_id,
    )
    ctx.db.flush()
    return {
        "agent_id": agent.id,
        "status": "isolated",
        "revoked_tokens": revoked_tokens,
        "snapshot_id": snap.id,
        "snapshot_ids": [snap.id],
    }


def _tool_integrations_list(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    status_filter = str(args.get("status") or "").strip().lower()
    limit = _parse_limit(args.get("limit"), default=100, max_limit=500)
    offset = _parse_cursor(args.get("cursor"))
    rows = ctx.db.scalars(
        select(Connector).where(Connector.tenant_id == ctx.tenant_id).order_by(Connector.updated_at.desc())
    ).all()
    if status_filter:
        rows = [row for row in rows if str(row.status or "").strip().lower() == status_filter]
    total = len(rows)
    sliced = rows[offset : offset + limit]
    return {
        "items": [
            {
                "id": row.id,
                "name": row.name,
                "provider_key": row.provider_key,
                "status": row.status,
                "enabled": row.enabled,
                "last_pull_status": row.last_pull_status,
                "last_signal_count": row.last_signal_count,
                "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
                "is_stub": row.is_stub,
                "stub_reason": row.stub_reason,
            }
            for row in sliced
        ],
        "total": total,
        "cursor": _next_cursor(offset, limit, total),
    }


def _tool_integrations_pull_signals(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    connector_id = str(args.get("connector_id") or "").strip()
    if not connector_id:
        raise ValueError("integrations.pull_signals requires connector_id")
    row = ctx.db.scalar(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("Connector not found for tenant")
    signals = run_connector_once(ctx.db, tenant_id=ctx.tenant_id, connector=row)
    signal_ids = [item.id for item in signals]
    evidence_node_ids: list[str] = []
    for signal in signals:
        payload = signal.payload or {}
        for node_id in payload.get("evidence_node_ids") or []:
            normalized = str(node_id).strip()
            if normalized and normalized not in evidence_node_ids:
                evidence_node_ids.append(normalized)
    ctx.db.flush()
    return {
        "connector_id": row.id,
        "status": row.status,
        "last_pull_status": row.last_pull_status,
        "signal_count": len(signals),
        "signal_ids": signal_ids,
        "evidence_node_ids": evidence_node_ids,
    }


def _tool_integrations_get_health(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    del args
    rows = ctx.db.scalars(select(Connector).where(Connector.tenant_id == ctx.tenant_id)).all()
    by_status: dict[str, int] = {}
    for row in rows:
        key = str(row.status or "unknown").strip().lower() or "unknown"
        by_status[key] = by_status.get(key, 0) + 1
    health = "healthy"
    if by_status.get("degraded", 0) > 0:
        health = "degraded"
    if by_status.get("failed", 0) > 0:
        health = "unhealthy"
    return {
        "health": health,
        "total_connectors": len(rows),
        "status_counts": by_status,
        "catalog_size": len(connector_catalog()),
        "coverage_rows": len(connector_control_coverage(ctx.db, tenant_id=ctx.tenant_id)),
    }


def _tool_tickets_create_jira(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    summary = str(args.get("summary") or "").strip()
    if not summary:
        raise ValueError("tickets.create_jira requires summary")
    ticket_id = f"JIRA-{secrets.token_hex(4).upper()}"
    return {
        "ticket_id": ticket_id,
        "system": "jira",
        "summary": summary,
        "description": str(args.get("description") or "").strip(),
        "severity": str(args.get("severity") or "med").strip().lower(),
        "finding_id": str(args.get("finding_id") or "").strip() or None,
        "status": "created",
    }


def _tool_workflows_request_approval(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    ai_system_id = str(args.get("ai_system_id") or "").strip()
    if not ai_system_id:
        raise ValueError("workflows.request_approval requires ai_system_id")
    required_roles = [str(item).strip() for item in (args.get("required_roles") or []) if str(item).strip()]
    if not required_roles:
        required_roles = ["owner", "admin"]
    req = ApprovalRequest(
        tenant_id=ctx.tenant_id,
        enforcement_event_id=str(args.get("enforcement_event_id") or "").strip() or None,
        ai_system_id=ai_system_id,
        request_payload=args.get("request_payload") or {},
        required_roles=required_roles,
        sla_minutes=_parse_limit(args.get("sla_minutes"), default=60, max_limit=7 * 24 * 60),
        default_if_timeout=str(args.get("default_if_timeout") or "block"),
        status="pending",
        decision=None,
    )
    ctx.db.add(req)
    ctx.db.flush()
    return {
        "approval_request_id": req.id,
        "status": req.status,
        "ai_system_id": req.ai_system_id,
        "required_roles": req.required_roles,
        "sla_minutes": req.sla_minutes,
        "default_if_timeout": req.default_if_timeout,
    }


def _make_executor(handler):
    def _executor(db: Session, context: MCPExecutionContext, args: dict[str, Any]) -> dict[str, Any]:
        tool_ctx = ToolContext(
            db=db,
            tenant_id=context.tenant_id,
            user_id=context.user_id,
            user_role=context.user_role,
        )
        return handler(tool_ctx, args)

    return _executor


def _register_brain_tools() -> None:
    registry = get_mcp_registry()
    if registry.get("workflows.request_approval"):
        return

    tool_definitions: list[tuple[ToolContract, Any]] = [
        (
            ToolContract(
                tool_name="governance.list_ai_systems",
                module="governance",
                version="1.0.0",
                description="List governed AI systems for the current tenant",
                input_schema={
                    "type": "object",
                    "properties": {
                        "filters": {"type": "object"},
                        "limit": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                    },
                    "required": ["items", "total"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_governance_list_ai_systems,
        ),
        (
            ToolContract(
                tool_name="governance.get_ai_system",
                module="governance",
                version="1.0.0",
                description="Fetch a governed AI system by ID",
                input_schema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "ai_system_id": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "ai_system": {"type": "object"},
                    },
                    "required": ["ai_system"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=True,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_governance_get_ai_system,
        ),
        (
            ToolContract(
                tool_name="policies.get_policy_version",
                module="policies",
                version="1.0.0",
                description="Retrieve a policy version contract",
                input_schema={
                    "type": "object",
                    "properties": {
                        "policy_version_id": {"type": "string", "minLength": 1},
                    },
                    "required": ["policy_version_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "policy_version": {"type": "object"},
                    },
                    "required": ["policy_version"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_policies_get_policy_version,
        ),
        (
            ToolContract(
                tool_name="policies.get_guardian_matrix",
                module="policies",
                version="1.0.0",
                description="Fetch guardian enforcement matrix for a policy version",
                input_schema={
                    "type": "object",
                    "properties": {
                        "policy_version_id": {"type": "string", "minLength": 1},
                    },
                    "required": ["policy_version_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "policy_version_id": {"type": "string"},
                        "guardians": {"type": "array"},
                    },
                    "required": ["policy_version_id", "guardians"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_policies_get_guardian_matrix,
        ),
        (
            ToolContract(
                tool_name="evidence.query",
                module="evidence",
                version="1.0.0",
                description="Query evidence nodes for proof and traceability",
                input_schema={
                    "type": "object",
                    "properties": {
                        "time_range": {"type": "object"},
                        "filters": {"type": "object"},
                        "limit": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["items", "total", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_evidence_query,
        ),
        (
            ToolContract(
                tool_name="enforcement.list_events",
                module="enforcement",
                version="1.0.0",
                description="List enforcement events for AI interactions",
                input_schema={
                    "type": "object",
                    "properties": {
                        "filters": {"type": "object"},
                        "limit": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["items", "total", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("auditor"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_enforcement_list_events,
        ),
        (
            ToolContract(
                tool_name="simulations.list_for_control",
                module="simulations",
                version="1.0.0",
                description="List simulations mapped to a control",
                input_schema={
                    "type": "object",
                    "properties": {
                        "control_id": {"type": "string", "minLength": 1},
                        "ai_system_id": {"type": ["string", "null"]},
                    },
                    "required": ["control_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "control_id": {"type": "string"},
                        "ai_system_id": {"type": ["string", "null"]},
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                    },
                    "required": ["control_id", "items", "total"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="analyze",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_simulations_list_for_control,
        ),
        (
            ToolContract(
                tool_name="simulations.run",
                module="simulations",
                version="1.0.0",
                description="Execute a simulation run with deterministic result recording",
                input_schema={
                    "type": "object",
                    "properties": {
                        "simulation_id": {"type": "string", "minLength": 1},
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "mode": {"type": "string"},
                        "stochastic_runs": {"type": "integer"},
                        "inputs_used": {"type": "object"},
                    },
                    "required": ["simulation_id", "ai_system_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "simulation_run_id": {"type": "string"},
                        "result": {"type": "string"},
                        "pass_rate": {"type": "number"},
                        "failed_assertions": {"type": "array"},
                        "evidence_node_ids": {"type": "array"},
                        "enforcement_event_ids": {"type": "array"},
                    },
                    "required": ["simulation_run_id", "result", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_for_changes("operator"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="enforce",
                citations_supported=True,
                governance_scope_required=True,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=20000,
            ),
            _tool_simulations_run,
        ),
        (
            ToolContract(
                tool_name="auditor.create_snapshot",
                module="auditor",
                version="1.0.0",
                description="Create an auditor snapshot artifact for the tenant or AI system scope",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": ["string", "null"]},
                        "framework": {"type": "string"},
                        "period": {"type": "object"},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "snapshot_id": {"type": "string"},
                        "artifact_path": {"type": "string"},
                        "artifact_hash": {"type": "string"},
                        "download_url": {"type": "string"},
                        "snapshot_ids": {"type": "array"},
                    },
                    "required": ["snapshot_id", "artifact_path", "download_url", "snapshot_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("operator"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="export",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=20000,
            ),
            _tool_auditor_create_snapshot,
        ),
        (
            ToolContract(
                tool_name="auditor.export_snapshot",
                module="auditor",
                version="1.0.0",
                description="Export snapshot artifacts in json or csv format",
                input_schema={
                    "type": "object",
                    "properties": {
                        "snapshot_id": {"type": "string", "minLength": 1},
                        "format": {"type": "string"},
                    },
                    "required": ["snapshot_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "snapshot_id": {"type": "string"},
                        "format": {"type": "string"},
                    },
                    "required": ["snapshot_id", "format"],
                    "additionalProperties": True,
                },
                required_role=_roles_at_or_above("operator"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="export",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=30000,
            ),
            _tool_auditor_export_snapshot,
        ),
        (
            ToolContract(
                tool_name="ops.jobs_status",
                module="ops",
                version="1.0.0",
                description="Fetch scheduled job execution status",
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer"},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                    },
                    "required": ["items", "total"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("auditor"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_ops_jobs_status,
        ),
        (
            ToolContract(
                tool_name="governance.update_ai_system_state",
                module="governance",
                version="1.0.0",
                description="Update AI system lifecycle/governance state",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "status": {"type": "string", "minLength": 1},
                        "governance_state": {"type": ["string", "null"]},
                        "lifecycle_state": {"type": ["string", "null"]},
                    },
                    "required": ["ai_system_id", "status"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ai_system": {"type": "object"}},
                    "required": ["ai_system"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="write",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_governance_update_ai_system_state,
        ),
        (
            ToolContract(
                tool_name="governance.assign_owner",
                module="governance",
                version="1.0.0",
                description="Assign owner metadata to governed AI system",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "owner_user_id": {"type": ["string", "null"]},
                        "owner_department": {"type": ["string", "null"]},
                    },
                    "required": ["ai_system_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ai_system": {"type": "object"}},
                    "required": ["ai_system"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="write",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_governance_assign_owner,
        ),
        (
            ToolContract(
                tool_name="governance.set_risk_tier",
                module="governance",
                version="1.0.0",
                description="Set governed AI system risk tier",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "risk_tier": {"type": "string", "minLength": 1},
                    },
                    "required": ["ai_system_id", "risk_tier"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ai_system": {"type": "object"}},
                    "required": ["ai_system"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="enforce",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_governance_set_risk_tier,
        ),
        (
            ToolContract(
                tool_name="findings.list",
                module="findings",
                version="1.0.0",
                description="List findings for tenant",
                input_schema={
                    "type": "object",
                    "properties": {
                        "filters": {"type": "object"},
                        "limit": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["items", "total", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_findings_list,
        ),
        (
            ToolContract(
                tool_name="findings.get",
                module="findings",
                version="1.0.0",
                description="Get finding by ID",
                input_schema={
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "id": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "finding": {"type": "object"},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["finding", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_findings_get,
        ),
        (
            ToolContract(
                tool_name="findings.update_status",
                module="findings",
                version="1.0.0",
                description="Update finding workflow status",
                input_schema={
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string", "minLength": 1},
                        "status": {"type": "string", "minLength": 1},
                    },
                    "required": ["finding_id", "status"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"finding": {"type": "object"}},
                    "required": ["finding"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("auditor"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="write",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_findings_update_status,
        ),
        (
            ToolContract(
                tool_name="findings.analyze",
                module="findings",
                version="1.0.0",
                description="Analyze a finding and return evidence-backed recommendations",
                input_schema={
                    "type": "object",
                    "properties": {"finding_id": {"type": "string", "minLength": 1}},
                    "required": ["finding_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "answer": {"type": "string"},
                        "summary": {"type": "string"},
                        "citations": {"type": "array"},
                        "controls": {"type": "array"},
                    },
                    "required": ["answer", "summary", "citations", "controls"],
                    "additionalProperties": True,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="analyze",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=10000,
            ),
            _tool_findings_analyze,
        ),
        (
            ToolContract(
                tool_name="policies.activate_policy_version",
                module="policies",
                version="1.0.0",
                description="Activate a policy version through its policy pack",
                input_schema={
                    "type": "object",
                    "properties": {"policy_version_id": {"type": "string", "minLength": 1}},
                    "required": ["policy_version_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "policy_version_id": {"type": "string"},
                        "pack_id": {"type": "string"},
                        "pack_status": {"type": "string"},
                        "version": {"type": "string"},
                    },
                    "required": ["policy_version_id", "pack_id", "pack_status", "version"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="enforce",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_policies_activate_policy_version,
        ),
        (
            ToolContract(
                tool_name="evidence.get_node",
                module="evidence",
                version="1.0.0",
                description="Fetch a single evidence node by ID",
                input_schema={
                    "type": "object",
                    "properties": {
                        "node_id": {"type": "string"},
                        "id": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "node": {"type": "object"},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["node", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_evidence_get_node,
        ),
        (
            ToolContract(
                tool_name="evidence.get_trace",
                module="evidence",
                version="1.0.0",
                description="Get evidence trace graph from a root node",
                input_schema={
                    "type": "object",
                    "properties": {
                        "node_id": {"type": "string", "minLength": 1},
                        "depth": {"type": "integer"},
                    },
                    "required": ["node_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "root_node_id": {"type": "string"},
                        "nodes": {"type": "array"},
                        "edges": {"type": "array"},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["root_node_id", "nodes", "edges", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=8000,
            ),
            _tool_evidence_get_trace,
        ),
        (
            ToolContract(
                tool_name="simulations.run_pack",
                module="simulations",
                version="1.0.0",
                description="Run a simulation pack and aggregate outcomes",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "simulation_ids": {"type": "array"},
                        "control_id": {"type": "string"},
                        "mode": {"type": "string"},
                        "stochastic_runs": {"type": "integer"},
                        "inputs_used": {"type": "object"},
                    },
                    "required": ["ai_system_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string"},
                        "total_runs": {"type": "integer"},
                        "passed_runs": {"type": "integer"},
                        "result": {"type": "string"},
                        "runs": {"type": "array"},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["ai_system_id", "total_runs", "passed_runs", "result", "runs", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_for_changes("operator"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="enforce",
                citations_supported=True,
                governance_scope_required=True,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=40000,
            ),
            _tool_simulations_run_pack,
        ),
        (
            ToolContract(
                tool_name="simulations.get_result",
                module="simulations",
                version="1.0.0",
                description="Get simulation run result by run ID",
                input_schema={
                    "type": "object",
                    "properties": {
                        "simulation_run_id": {"type": "string"},
                        "run_id": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "simulation_run_id": {"type": "string"},
                        "simulation_id": {"type": "string"},
                        "ai_system_id": {"type": "string"},
                        "result": {"type": "string"},
                        "pass_rate": {"type": "number"},
                        "failed_assertions": {"type": "array"},
                        "evidence_node_ids": {"type": "array"},
                        "controls_impacted": {"type": "array"},
                    },
                    "required": ["simulation_run_id", "simulation_id", "ai_system_id", "result", "evidence_node_ids", "controls_impacted"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_simulations_get_result,
        ),
        (
            ToolContract(
                tool_name="auditor.challenge_control",
                module="auditor",
                version="1.0.0",
                description="Create an auditor challenge against a control",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "control_id": {"type": "string", "minLength": 1},
                        "challenge_reason": {"type": "string", "minLength": 3},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["ai_system_id", "control_id", "challenge_reason"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "conflict_id": {"type": "string"},
                        "status": {"type": "string"},
                        "ai_system_id": {"type": "string"},
                        "control_id": {"type": "string"},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["conflict_id", "status", "ai_system_id", "control_id", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin", "auditor"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="enforce",
                citations_supported=True,
                governance_scope_required=True,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=10000,
            ),
            _tool_auditor_challenge_control,
        ),
        (
            ToolContract(
                tool_name="auditor.get_snapshot",
                module="auditor",
                version="1.0.0",
                description="Get auditor snapshot metadata and download URL",
                input_schema={
                    "type": "object",
                    "properties": {"snapshot_id": {"type": "string", "minLength": 1}},
                    "required": ["snapshot_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "snapshot": {"type": "object"},
                        "snapshot_ids": {"type": "array"},
                    },
                    "required": ["snapshot", "snapshot_ids"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("auditor"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_auditor_get_snapshot,
        ),
        (
            ToolContract(
                tool_name="aiiam.get_agent",
                module="ai_iam",
                version="1.0.0",
                description="Get AI IAM agent identity",
                input_schema={
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "id": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"agent": {"type": "object"}},
                    "required": ["agent"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_aiiam_get_agent,
        ),
        (
            ToolContract(
                tool_name="aiiam.mint_token",
                module="ai_iam",
                version="1.0.0",
                description="Mint capability token for AI IAM agent",
                input_schema={
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string", "minLength": 1},
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "scopes": {"type": "array"},
                        "expires_minutes": {"type": "integer"},
                        "chain_depth": {"type": "integer"},
                        "approval_request_id": {"type": ["string", "null"]},
                    },
                    "required": ["agent_id", "ai_system_id", "scopes"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "token_id": {"type": "string"},
                        "capability_token": {"type": "string"},
                        "agent_id": {"type": "string"},
                        "ai_system_id": {"type": "string"},
                        "scopes": {"type": "array"},
                        "expires_at": {"type": "string"},
                    },
                    "required": ["token_id", "capability_token", "agent_id", "ai_system_id", "scopes", "expires_at"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="enforce",
                citations_supported=False,
                governance_scope_required=True,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=10000,
            ),
            _tool_aiiam_mint_token,
        ),
        (
            ToolContract(
                tool_name="aiiam.revoke_token",
                module="ai_iam",
                version="1.0.0",
                description="Revoke AI IAM capability token",
                input_schema={
                    "type": "object",
                    "properties": {"token_id": {"type": "string", "minLength": 1}},
                    "required": ["token_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "token_id": {"type": "string"},
                        "status": {"type": "string"},
                        "revoked_at": {"type": ["string", "null"]},
                    },
                    "required": ["token_id", "status", "revoked_at"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="enforce",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_aiiam_revoke_token,
        ),
        (
            ToolContract(
                tool_name="aiiam.kill_switch",
                module="ai_iam",
                version="1.0.0",
                description="Isolate agent and revoke all capability tokens",
                input_schema={
                    "type": "object",
                    "properties": {"agent_id": {"type": "string", "minLength": 1}},
                    "required": ["agent_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "status": {"type": "string"},
                        "revoked_tokens": {"type": "integer"},
                        "snapshot_id": {"type": "string"},
                        "snapshot_ids": {"type": "array"},
                    },
                    "required": ["agent_id", "status", "revoked_tokens", "snapshot_id", "snapshot_ids"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="admin",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=15000,
            ),
            _tool_aiiam_kill_switch,
        ),
        (
            ToolContract(
                tool_name="integrations.list",
                module="monitoring",
                version="1.0.0",
                description="List configured integration connectors",
                input_schema={
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "limit": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "items": {"type": "array"},
                        "total": {"type": "integer"},
                        "cursor": {"type": ["string", "null"]},
                    },
                    "required": ["items", "total"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_integrations_list,
        ),
        (
            ToolContract(
                tool_name="integrations.pull_signals",
                module="monitoring",
                version="1.0.0",
                description="Pull signals now from a configured integration connector",
                input_schema={
                    "type": "object",
                    "properties": {"connector_id": {"type": "string", "minLength": 1}},
                    "required": ["connector_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "connector_id": {"type": "string"},
                        "status": {"type": "string"},
                        "last_pull_status": {"type": "string"},
                        "signal_count": {"type": "integer"},
                        "signal_ids": {"type": "array"},
                        "evidence_node_ids": {"type": "array"},
                    },
                    "required": ["connector_id", "status", "last_pull_status", "signal_count", "signal_ids", "evidence_node_ids"],
                    "additionalProperties": False,
                },
                required_role=["owner", "admin"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="write",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=30000,
            ),
            _tool_integrations_pull_signals,
        ),
        (
            ToolContract(
                tool_name="integrations.get_health",
                module="monitoring",
                version="1.0.0",
                description="Get integration health summary",
                input_schema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "health": {"type": "string"},
                        "total_connectors": {"type": "integer"},
                        "status_counts": {"type": "object"},
                        "catalog_size": {"type": "integer"},
                        "coverage_rows": {"type": "integer"},
                    },
                    "required": ["health", "total_connectors", "status_counts", "catalog_size", "coverage_rows"],
                    "additionalProperties": False,
                },
                required_role=_roles_at_or_above("viewer"),
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            _tool_integrations_get_health,
        ),
        (
            ToolContract(
                tool_name="tickets.create_jira",
                module="tickets",
                version="1.0.0",
                description="Create Jira ticket from finding/workflow context",
                input_schema={
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string", "minLength": 1},
                        "description": {"type": "string"},
                        "severity": {"type": "string"},
                        "finding_id": {"type": ["string", "null"]},
                        "ai_system_id": {"type": ["string", "null"]},
                    },
                    "required": ["summary"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "ticket_id": {"type": "string"},
                        "system": {"type": "string"},
                        "summary": {"type": "string"},
                        "description": {"type": "string"},
                        "severity": {"type": "string"},
                        "finding_id": {"type": ["string", "null"]},
                        "status": {"type": "string"},
                    },
                    "required": ["ticket_id", "system", "summary", "description", "severity", "finding_id", "status"],
                    "additionalProperties": False,
                },
                required_role=_roles_for_changes("operator"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="write",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_tickets_create_jira,
        ),
        (
            ToolContract(
                tool_name="workflows.request_approval",
                module="workflows",
                version="1.0.0",
                description="Create approval request for governed action execution",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string", "minLength": 1},
                        "request_payload": {"type": "object"},
                        "required_roles": {"type": "array"},
                        "sla_minutes": {"type": "integer"},
                        "default_if_timeout": {"type": "string"},
                        "enforcement_event_id": {"type": ["string", "null"]},
                    },
                    "required": ["ai_system_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "approval_request_id": {"type": "string"},
                        "status": {"type": "string"},
                        "ai_system_id": {"type": "string"},
                        "required_roles": {"type": "array"},
                        "sla_minutes": {"type": "integer"},
                        "default_if_timeout": {"type": "string"},
                    },
                    "required": ["approval_request_id", "status", "ai_system_id", "required_roles", "sla_minutes", "default_if_timeout"],
                    "additionalProperties": False,
                },
                required_role=_roles_for_changes("operator"),
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="write",
                citations_supported=False,
                governance_scope_required=True,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            _tool_workflows_request_approval,
        ),
    ]

    for contract, handler in tool_definitions:
        if registry.get(contract.tool_name):
            continue
        registry.register(
            ToolRegistration(
                contract=contract,
                executor=_make_executor(handler),
            )
        )


def list_tools() -> list[dict[str, Any]]:
    _register_brain_tools()
    registry = get_mcp_registry()
    return [
        {
            "name": row["tool_name"],
            "required_role": row["required_role"],
            "side_effect_level": row["side_effect_level"],
        }
        for row in registry.list()
    ]


def execute_tool(
    *,
    db: Session,
    tenant_id: str,
    user_id: str,
    user_role: str,
    tool_name: str,
    args: dict[str, Any],
    platform_mode: str | None = None,
    correlation_id: str | None = None,
    ai_system_id: str | None = None,
    risk_tier: str | None = None,
    governance_version: str | None = None,
    policy_version_id: str | None = None,
    brain_session_id: str | None = None,
    brain_plan_id: str | None = None,
) -> dict[str, Any]:
    _register_brain_tools()

    effective_ai_system_id = ai_system_id or str(args.get("ai_system_id") or "").strip() or None
    effective_risk_tier = risk_tier
    if effective_ai_system_id and not effective_risk_tier:
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.id == effective_ai_system_id,
                AISystem.tenant_id == tenant_id,
            )
        )
        if ai_system is not None:
            effective_risk_tier = ai_system.risk_tier

    context = MCPExecutionContext(
        tenant_id=tenant_id,
        user_id=user_id,
        user_role=user_role,
        platform_mode=platform_mode or get_tenant_platform_mode(db, tenant_id=tenant_id),
        correlation_id=correlation_id or get_correlation_id(),
        ai_system_id=effective_ai_system_id,
        risk_tier=effective_risk_tier,
        governance_version=governance_version or "v1",
        policy_version_id=policy_version_id or str(args.get("policy_version_id") or "").strip() or None,
        brain_session_id=brain_session_id,
        brain_plan_id=brain_plan_id,
    )
    return get_mcp_registry().execute(
        db=db,
        context=context,
        tool_name=tool_name,
        args=args,
    )


def get_tool_contract(tool_name: str) -> ToolContract | None:
    _register_brain_tools()
    registration = get_mcp_registry().get(tool_name)
    if registration is None:
        return None
    return registration.contract


def tool_exists(tool_name: str) -> bool:
    return get_tool_contract(tool_name) is not None
