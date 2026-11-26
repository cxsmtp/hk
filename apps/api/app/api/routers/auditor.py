from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.deps_control_plane import require_control_plane_healthy
from app.core.deps_governance import governance_payload_dependency
from app.core.config import settings
from app.core.observability import get_correlation_id
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.audit import AuditLog
from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.finding import Finding
from app.db.models.maturity import ConflictResolution, ControlConflict, ControlMaturity
from app.db.models.monitoring import MonitoringSignal
from app.db.models.remediation import RemediationAction
from app.db.models.runtime_intelligence import RuntimeEvent, RuntimeGovernanceRecommendation, RuntimeSimulationTrigger
from app.db.models.simulation import Control
from app.db.models.simulation import SimulationRun
from app.db.models.snapshot import AuditorSnapshot
from app.db.models.user import User
from app.db.session import get_db
from app.services import evidence_signing
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError
from app.services.maturity_service import recalculate_control_maturity
from app.services.control_graph_service import normalize_control_ids
from app.services.snapshot_service import (
    artifact_download_url,
    artifact_named_download_url,
    artifact_relative_path,
    build_control_posture_views,
    create_auditor_snapshot,
    export_audit_artifacts,
    resolve_artifact_file_path,
)


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auditor",
    tags=["auditor"],
    dependencies=[Depends(require_control_plane_healthy(module="auditor"))],
)


class SnapshotRequest(BaseModel):
    ai_system_id: str | None = None
    tenant_scope: bool = False
    frameworks_in_scope: list[str] = Field(default_factory=list)
    controls_in_scope: list[str] = Field(default_factory=list)
    time_range: dict[str, str] | None = None
    risk_tier: str | None = None
    lifecycle_state: str | None = None
    include_systems: list[str] = Field(default_factory=list)
    trigger_type: str = "manual"
    payload: dict = Field(default_factory=dict)


class ExportRequest(BaseModel):
    ai_system_id: str | None = None
    period_start: str | None = None
    period_end: str | None = None


class ConflictResolveRequest(BaseModel):
    decision: Literal["accept_positive", "accept_negative", "inconclusive"]
    notes: str = Field(default="", max_length=2000)


class AuditorChallengeRequest(BaseModel):
    ai_system_id: str
    control_id: str
    challenge_reason: str = Field(min_length=3, max_length=2000)
    evidence_node_ids: list[str] = Field(default_factory=list)


class EnforcementEventSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    ai_system_id: str
    request_id: str
    final_decision: str
    actor_type: str
    actor_id: str
    timestamp: datetime


class AuditorSnapshotResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    ai_system_id: str | None = None
    trigger_type: str
    artifact_path: str
    artifact_hash: str
    payload: dict
    created_at: datetime


class ControlConflictResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    ai_system_id: str
    control_id: str
    status: str
    reason: str
    positive_signals: int
    negative_signals: int
    latest_signal_at: datetime | None = None
    evidence_node_ids: list
    details: dict
    detected_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution_decision: str | None = None
    resolution_notes: str
    audit_log_id: str | None = None


class AuditorDashboardResponse(BaseModel):
    average_maturity: float
    average_confidence: float
    maturity_count: int
    needs_review_count: int
    contested_count: int
    healthy_count: int
    open_conflicts_count: int
    recent_enforcement_events: list[EnforcementEventSummaryResponse]
    recent_snapshots: list[AuditorSnapshotResponse]
    recent_conflicts: list[ControlConflictResponse]


class AuditorExportArtifactsResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    json_artifact: str = Field(alias="json")
    csv: str
    evidence_pack: str | None = None
    pdf_ready_model: str | None = None
    pdf: str | None = None
    signature_manifest: str | None = None
    evidence_signature: dict[str, Any] | None = None
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    pdf_renderer: str | None = None
    pdf_renderer_available: bool = False
    hash: str


class AuditorExportResponse(BaseModel):
    snapshot_id: str
    artifact_relative_path: str
    download_url: str
    download_urls: dict[str, str] = Field(default_factory=dict)
    artifacts: AuditorExportArtifactsResponse


class ControlPostureRow(BaseModel):
    group_key: str
    group_label: str
    controls_total: int
    implemented_controls: int
    partial_controls: int
    not_implemented_controls: int
    avg_maturity_score: float
    avg_confidence_score: float
    ai_system_count: int
    control_ids: list[str]


class ControlPostureResponse(BaseModel):
    group_by: Literal["framework", "domain", "ai_system"]
    rows: list[ControlPostureRow]


class DataFlowTraceResponse(BaseModel):
    correlation_id: str
    summary: dict
    source_destination: list[dict]
    enforcement_events: list[dict]
    runtime_events: list[dict]
    monitoring_signals: list[dict]
    audit_logs: list[dict]
    evidence_nodes: list[dict]
    evidence_edges: list[dict]
    findings: list[dict]
    simulation_runs: list[dict]
    runtime_triggers: list[dict]
    runtime_recommendations: list[dict]


class RemediationTraceResponse(BaseModel):
    remediation_id: str
    remediation: dict
    trigger: dict
    approver: dict | None = None
    stages: list[dict]
    evidence_linkage: dict
    evidence_nodes: list[dict]
    evidence_edges: list[dict]
    audit_logs: list[dict]
    tickets: list[dict]
    affected_controls: list[dict]
    framework_mappings: list[dict]
    compliance_impact: dict
    timeline: list[dict]


def _normalize_scope_list(values: list[str]) -> list[str]:
    cleaned = [str(value).strip() for value in values if str(value).strip()]
    return sorted(dict.fromkeys(cleaned))


def _write_snapshot_scope_block(
    *,
    db: Session,
    tenant_id: str,
    route: str,
    module: str,
    reason_code: str,
    message: str,
    status_code: int,
    request: Request,
) -> None:
    correlation_id = getattr(request.state, "correlation_id", None)
    payload = {
        "reason_code": reason_code,
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "ai_system_id": None,
        "route": route,
        "module": module,
        "governance_action": "auditor.snapshot.create",
        "governance_version": "g1",
    }
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="governance.context.blocked",
        resource_type="tenant",
        resource_id=tenant_id,
        payload=payload,
        correlation_id=correlation_id,
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="governance_context_block",
        signal_type="governance.context.blocked",
        label="Governance context blocked for auditor snapshot",
        payload=payload,
        correlation_id=correlation_id,
    )
    db.commit()
    raise HTTPException(
        status_code=status_code,
        detail={
            "code": message,
            "reason_code": reason_code,
            "message": message.replace("_", " "),
        },
    )


def _parse_time_range_or_raise(*, payload: SnapshotRequest, db: Session, ctx: TenantContext, request: Request) -> dict[str, str]:
    if payload.time_range is None:
        _write_snapshot_scope_block(
            db=db,
            tenant_id=ctx.tenant.id,
            route="/auditor/snapshot",
            module="auditor",
            reason_code="TENANT_SCOPE_TIME_RANGE_REQUIRED",
            message="TENANT_SCOPE_TIME_RANGE_REQUIRED",
            status_code=status.HTTP_400_BAD_REQUEST,
            request=request,
        )

    start = str(payload.time_range.get("start", "")).strip()
    end = str(payload.time_range.get("end", "")).strip()
    if not start or not end:
        _write_snapshot_scope_block(
            db=db,
            tenant_id=ctx.tenant.id,
            route="/auditor/snapshot",
            module="auditor",
            reason_code="TENANT_SCOPE_TIME_RANGE_REQUIRED",
            message="TENANT_SCOPE_TIME_RANGE_REQUIRED",
            status_code=status.HTTP_400_BAD_REQUEST,
            request=request,
        )

    def _parse_iso(value: str) -> datetime:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)

    try:
        start_dt = _parse_iso(start)
        end_dt = _parse_iso(end)
    except ValueError:
        _write_snapshot_scope_block(
            db=db,
            tenant_id=ctx.tenant.id,
            route="/auditor/snapshot",
            module="auditor",
            reason_code="TENANT_SCOPE_TIME_RANGE_INVALID",
            message="TENANT_SCOPE_TIME_RANGE_INVALID",
            status_code=status.HTTP_400_BAD_REQUEST,
            request=request,
        )

    if start_dt > end_dt:
        _write_snapshot_scope_block(
            db=db,
            tenant_id=ctx.tenant.id,
            route="/auditor/snapshot",
            module="auditor",
            reason_code="TENANT_SCOPE_TIME_RANGE_INVALID",
            message="TENANT_SCOPE_TIME_RANGE_INVALID",
            status_code=status.HTTP_400_BAD_REQUEST,
            request=request,
        )
    return {"start": start, "end": end}


def _scope_hash(scope: dict) -> str:
    serialized = json.dumps(scope, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()



def _storage_failure(exc: RuntimeError) -> HTTPException:
    """A 500 for an artifact that could not be written or read: a plain sentence and the request id; the error itself
    (it names the server's folders and the operating system's message) goes to the server log only."""

    request_id = get_correlation_id() or ""
    logger.error("Auditor artifact storage failed", exc_info=exc, extra={"request_id": request_id, "reason_code": "artifact_storage_failed"})
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"The evidence files could not be written or read on the server.{f' Request id: {request_id}.' if request_id else ''}",
    )

@router.get("/dashboard", response_model=AuditorDashboardResponse)
def dashboard(
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    maturities = db.scalars(select(ControlMaturity).where(ControlMaturity.tenant_id == ctx.tenant.id)).all()
    events = db.scalars(
        select(EnforcementEvent).where(EnforcementEvent.tenant_id == ctx.tenant.id).order_by(EnforcementEvent.timestamp.desc()).limit(25)
    ).all()
    snapshots = db.scalars(
        select(AuditorSnapshot).where(AuditorSnapshot.tenant_id == ctx.tenant.id).order_by(AuditorSnapshot.created_at.desc()).limit(10)
    ).all()
    conflicts = db.scalars(
        select(ControlConflict)
        .where(ControlConflict.tenant_id == ctx.tenant.id)
        .order_by(ControlConflict.detected_at.desc())
        .limit(50)
    ).all()

    avg_maturity = (sum(m.maturity_score for m in maturities) / len(maturities)) if maturities else 0.0
    avg_confidence = (sum(m.confidence_score for m in maturities) / len(maturities)) if maturities else 0.0
    needs_review_count = sum(1 for m in maturities if m.status == "needs_review")
    contested_count = sum(1 for m in maturities if m.status == "contested")
    healthy_count = sum(1 for m in maturities if m.status == "healthy")
    open_conflicts = [row for row in conflicts if row.status == "open"]

    return AuditorDashboardResponse(
        average_maturity=avg_maturity,
        average_confidence=avg_confidence,
        maturity_count=len(maturities),
        needs_review_count=needs_review_count,
        contested_count=contested_count,
        healthy_count=healthy_count,
        open_conflicts_count=len(open_conflicts),
        recent_enforcement_events=[EnforcementEventSummaryResponse.model_validate(row) for row in events],
        recent_snapshots=[AuditorSnapshotResponse.model_validate(row) for row in snapshots],
        recent_conflicts=[ControlConflictResponse.model_validate(row) for row in conflicts[:10]],
    )


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).isoformat()
    return value.astimezone(timezone.utc).isoformat()


def _state_delta(before: dict, after: dict) -> list[dict]:
    keys = sorted(set(before.keys()) | set(after.keys()))
    delta: list[dict] = []
    for key in keys:
        left = before.get(key)
        right = after.get(key)
        if left != right:
            delta.append({"path": key, "before": left, "after": right})
    return delta


def _canonical_framework_refs(remediation_type: str) -> list[dict]:
    normalized = str(remediation_type or "").strip().lower()
    # Canonical remediation-to-framework hints used for consistent auditor explainability.
    baseline = [
        {"framework": "iso_27001", "reference": "A.5.36", "rationale": "Remediation and corrective action governance"},
        {"framework": "nist_ai_rmf", "reference": "GV-4", "rationale": "Governance response and accountability"},
        {"framework": "eu_ai_act", "reference": "risk_management", "rationale": "Risk treatment and controls"},
    ]
    if normalized in {"kill_switch", "agent_suspend", "permission_reduce"}:
        baseline.extend(
            [
                {"framework": "iso_27001", "reference": "A.8.2", "rationale": "Privileged access restriction"},
                {"framework": "nist_ai_rmf", "reference": "MP-3", "rationale": "Operational controls and safeguards"},
                {"framework": "eu_ai_act", "reference": "technical_robustness", "rationale": "Operational safety response"},
            ]
        )
    if normalized in {"policy_tighten", "trust_center_escalation", "require_step_up"}:
        baseline.extend(
            [
                {"framework": "iso_27001", "reference": "A.5.1", "rationale": "Policy governance and updates"},
                {"framework": "nist_ai_rmf", "reference": "GV-1", "rationale": "Policies aligned to AI risk posture"},
                {"framework": "eu_ai_act", "reference": "governance", "rationale": "Risk governance and oversight"},
            ]
        )
    dedup: list[dict] = []
    seen: set[str] = set()
    for item in baseline:
        token = json.dumps(item, sort_keys=True)
        if token in seen:
            continue
        seen.add(token)
        dedup.append(item)
    return dedup


@router.get("/data-flow-trace/{correlation_id}", response_model=DataFlowTraceResponse)
def data_flow_trace(
    correlation_id: str,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    normalized_correlation = str(correlation_id or "").strip()
    if not normalized_correlation:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="correlation_id is required")

    audits = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == ctx.tenant.id,
            AuditLog.correlation_id == normalized_correlation,
        )
        .order_by(AuditLog.created_at.asc())
    ).all()
    enforcement_events = db.scalars(
        select(EnforcementEvent)
        .where(
            EnforcementEvent.tenant_id == ctx.tenant.id,
            EnforcementEvent.correlation_id == normalized_correlation,
        )
        .order_by(EnforcementEvent.timestamp.asc())
    ).all()
    runtime_events = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.correlation_id == normalized_correlation,
        )
        .order_by(RuntimeEvent.created_at.asc())
    ).all()
    simulation_runs = db.scalars(
        select(SimulationRun)
        .where(
            SimulationRun.tenant_id == ctx.tenant.id,
            SimulationRun.correlation_id == normalized_correlation,
        )
        .order_by(SimulationRun.started_at.asc())
    ).all()
    runtime_triggers = db.scalars(
        select(RuntimeSimulationTrigger)
        .where(
            RuntimeSimulationTrigger.tenant_id == ctx.tenant.id,
            RuntimeSimulationTrigger.correlation_id == normalized_correlation,
        )
        .order_by(RuntimeSimulationTrigger.created_at.asc())
    ).all()
    runtime_recommendations = db.scalars(
        select(RuntimeGovernanceRecommendation)
        .join(RuntimeEvent, RuntimeEvent.event_id == RuntimeGovernanceRecommendation.event_id)
        .where(
            RuntimeGovernanceRecommendation.tenant_id == ctx.tenant.id,
            RuntimeEvent.correlation_id == normalized_correlation,
        )
        .order_by(RuntimeGovernanceRecommendation.created_at.asc())
    ).all()

    monitoring_candidates = db.scalars(
        select(MonitoringSignal)
        .where(MonitoringSignal.tenant_id == ctx.tenant.id)
        .order_by(MonitoringSignal.created_at.desc())
        .limit(500)
    ).all()
    monitoring_signals = [
        row
        for row in monitoring_candidates
        if str((row.payload or {}).get("correlation_id") or "").strip() == normalized_correlation
    ]
    monitoring_signals.reverse()

    evidence_seed_ids: set[str] = set()
    for event in enforcement_events:
        evidence_seed_ids.update(str(node_id) for node_id in (event.evidence_nodes_created or []) if str(node_id).strip())
    for row in runtime_events:
        evidence_seed_ids.update(str(node_id) for node_id in (row.evidence_node_ids or []) if str(node_id).strip())

    evidence_nodes = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == ctx.tenant.id,
            (EvidenceNode.correlation_id == normalized_correlation)
            | (EvidenceNode.id.in_(sorted(evidence_seed_ids)) if evidence_seed_ids else EvidenceNode.id == "__none__"),
        )
    ).all()
    evidence_node_ids = {row.id for row in evidence_nodes}

    evidence_edges = db.scalars(
        select(EvidenceEdge).where(
            EvidenceEdge.tenant_id == ctx.tenant.id,
            (
                (EvidenceEdge.from_node_id.in_(sorted(evidence_node_ids)))
                | (EvidenceEdge.to_node_id.in_(sorted(evidence_node_ids)))
            )
            if evidence_node_ids
            else EvidenceEdge.id == "__none__",
        )
    ).all()

    findings = db.scalars(
        select(Finding).where(Finding.tenant_id == ctx.tenant.id).order_by(Finding.updated_at.desc()).limit(500)
    ).all()
    findings_for_trace = [
        row
        for row in findings
        if bool({str(node_id) for node_id in (row.evidence_node_ids or []) if str(node_id).strip()} & evidence_node_ids)
    ]

    source_destination: list[dict] = []
    for row in monitoring_signals:
        payload = dict(row.payload or {})
        source_domain = str(payload.get("source_domain") or "").strip()
        destination_domain = str(payload.get("destination_domain") or payload.get("target_resource") or "").strip()
        if not source_domain and not destination_domain:
            continue
        source_destination.append(
            {
                "source": source_domain or payload.get("source_surface_type") or payload.get("agent_id"),
                "destination": destination_domain or payload.get("destination_surface_type") or payload.get("tool_name"),
                "decision": payload.get("action_taken") or payload.get("decision"),
                "reason_code": payload.get("reason_code"),
                "event_type": payload.get("event_type"),
            }
        )

    users = sorted(
        {
            *(str(item.actor_user_id) for item in audits if item.actor_user_id),
            *(str(item.user_id) for item in runtime_events if item.user_id),
        }
    )
    agents = sorted(
        {
            *(str(item.agent_id) for item in runtime_events if item.agent_id),
            *(str(item.actor_id) for item in enforcement_events if str(item.actor_type).lower() == "agent"),
        }
    )
    decisions = sorted(
        {
            *(str(item.final_decision) for item in enforcement_events if item.final_decision),
            *(
                str((signal.payload or {}).get("action_taken") or (signal.payload or {}).get("decision"))
                for signal in monitoring_signals
                if (signal.payload or {}).get("action_taken") or (signal.payload or {}).get("decision")
            ),
        }
    )
    policy_versions = sorted(
        {
            *(str(item.policy_version_id) for item in enforcement_events if item.policy_version_id),
            *(str(item.policy_version_id) for item in runtime_events if item.policy_version_id),
            *(
                str((signal.payload or {}).get("policy_version"))
                for signal in monitoring_signals
                if (signal.payload or {}).get("policy_version")
            ),
        }
    )

    summary = {
        "users": users,
        "agents": agents,
        "decision_set": decisions,
        "policy_versions": policy_versions,
        "counts": {
            "audits": len(audits),
            "enforcement_events": len(enforcement_events),
            "runtime_events": len(runtime_events),
            "monitoring_signals": len(monitoring_signals),
            "evidence_nodes": len(evidence_nodes),
            "evidence_edges": len(evidence_edges),
            "findings": len(findings_for_trace),
            "simulation_runs": len(simulation_runs),
            "runtime_triggers": len(runtime_triggers),
            "runtime_recommendations": len(runtime_recommendations),
        },
    }

    return DataFlowTraceResponse(
        correlation_id=normalized_correlation,
        summary=summary,
        source_destination=source_destination,
        enforcement_events=[
            {
                "id": row.id,
                "request_id": row.request_id,
                "ai_system_id": row.ai_system_id,
                "actor_type": row.actor_type,
                "actor_id": row.actor_id,
                "decision": row.final_decision,
                "policy_version_id": row.policy_version_id,
                "timestamp": _iso(row.timestamp),
                "controls_impacted": list(row.controls_impacted or []),
            }
            for row in enforcement_events
        ],
        runtime_events=[
            {
                "event_id": row.event_id,
                "source_surface": row.source_surface,
                "event_type": row.event_type,
                "ai_system_id": row.ai_system_id,
                "user_id": row.user_id,
                "agent_id": row.agent_id,
                "severity": row.severity,
                "policy_version_id": row.policy_version_id,
                "evidence_node_ids": list(row.evidence_node_ids or []),
                "metadata": dict(row.metadata_json or {}),
                "created_at": _iso(row.created_at),
            }
            for row in runtime_events
        ],
        monitoring_signals=[
            {
                "id": row.id,
                "signal_type": row.signal_type,
                "severity": row.severity,
                "payload": dict(row.payload or {}),
                "created_at": _iso(row.created_at),
            }
            for row in monitoring_signals
        ],
        audit_logs=[
            {
                "id": row.id,
                "actor_user_id": row.actor_user_id,
                "actor_type": row.actor_type,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "payload": dict(row.payload or {}),
                "created_at": _iso(row.created_at),
            }
            for row in audits
        ],
        evidence_nodes=[
            {
                "id": row.id,
                "node_type": row.node_type,
                "signal_type": row.signal_type,
                "label": row.label,
                "payload": dict(row.payload or {}),
                "correlation_id": row.correlation_id,
                "created_at": _iso(row.created_at),
            }
            for row in evidence_nodes
        ],
        evidence_edges=[
            {
                "id": row.id,
                "from_node_id": row.from_node_id,
                "to_node_id": row.to_node_id,
                "edge_type": row.edge_type,
                "payload": dict(row.payload or {}),
            }
            for row in evidence_edges
        ],
        findings=[
            {
                "finding_id": row.finding_id,
                "finding_type": row.finding_type,
                "severity": row.severity,
                "status": row.status,
                "recommended_action": row.recommended_action,
                "evidence_node_ids": list(row.evidence_node_ids or []),
                "related_control_ids": list(row.related_control_ids or []),
                "policy_version_id": row.policy_version_id,
                "occurrence_count": int(row.occurrence_count),
            }
            for row in findings_for_trace
        ],
        simulation_runs=[
            {
                "id": row.id,
                "simulation_id": row.simulation_id,
                "ai_system_id": row.ai_system_id,
                "mode": row.mode,
                "controls_impacted": list(row.controls_impacted or []),
                "results": dict(row.results or {}),
                "started_at": _iso(row.started_at),
                "finished_at": _iso(row.finished_at),
            }
            for row in simulation_runs
        ],
        runtime_triggers=[
            {
                "trigger_id": row.trigger_id,
                "event_id": row.event_id,
                "ai_system_id": row.ai_system_id,
                "reason_code": row.reason_code,
                "target_pack": row.target_pack,
                "related_control_ids": list(row.related_control_ids or []),
                "status": row.status,
                "created_at": _iso(row.created_at),
            }
            for row in runtime_triggers
        ],
        runtime_recommendations=[
            {
                "recommendation_id": row.recommendation_id,
                "event_id": row.event_id,
                "ai_system_id": row.ai_system_id,
                "recommendation_type": row.recommendation_type,
                "reason_code": row.reason_code,
                "priority": row.priority,
                "status": row.status,
                "payload": dict(row.payload or {}),
                "created_at": _iso(row.created_at),
                "applied_at": _iso(row.applied_at),
            }
            for row in runtime_recommendations
        ],
    )


@router.get("/remediation-trace/{remediation_id}", response_model=RemediationTraceResponse)
def remediation_trace(
    remediation_id: str,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    remediation = db.scalar(
        select(RemediationAction).where(
            RemediationAction.tenant_id == ctx.tenant.id,
            RemediationAction.id == remediation_id,
        )
    )
    if remediation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Remediation action not found")

    source_trigger_type = str(remediation.source_trigger_type or "").strip().lower()
    trigger_details: dict = {
        "source_trigger_type": source_trigger_type,
        "source_trigger_id": remediation.source_trigger_id,
        "summary": remediation.recommendation_text,
    }
    trigger_created_at: datetime | None = None
    related_control_ids: set[str] = set()

    if source_trigger_type in {"guardian_violation", "shadow_ai_detection"}:
        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == ctx.tenant.id,
                Finding.finding_id == remediation.source_trigger_id,
            )
        )
        if finding is not None:
            trigger_created_at = finding.created_at
            related_control_ids.update(str(item) for item in (finding.related_control_ids or []) if str(item).strip())
            trigger_details.update(
                {
                    "finding_id": finding.finding_id,
                    "finding_type": finding.finding_type,
                    "severity": finding.severity,
                    "status": finding.status,
                }
            )
    elif source_trigger_type == "simulation_failure":
        run = db.scalar(
            select(SimulationRun).where(
                SimulationRun.tenant_id == ctx.tenant.id,
                SimulationRun.id == remediation.source_trigger_id,
            )
        )
        if run is not None:
            trigger_created_at = run.started_at
            related_control_ids.update(
                str(item.get("control_id"))
                for item in (run.controls_impacted or [])
                if isinstance(item, dict) and str(item.get("control_id") or "").strip()
            )
            trigger_details.update(
                {
                    "simulation_run_id": run.id,
                    "simulation_id": run.simulation_id,
                    "mode": run.mode,
                    "result": str((run.results or {}).get("result") or ""),
                }
            )
    elif source_trigger_type in {"drift_alert", "model_integrity_failure", "ingestion_poisoning_indicator"}:
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == ctx.tenant.id,
                MonitoringSignal.id == remediation.source_trigger_id,
            )
        )
        if signal is not None:
            trigger_created_at = signal.created_at
            payload = dict(signal.payload or {})
            related_control_ids.update(str(item) for item in (payload.get("related_control_ids") or []) if str(item).strip())
            trigger_details.update(
                {
                    "monitoring_signal_id": signal.id,
                    "signal_type": signal.signal_type,
                    "severity": signal.severity,
                }
            )
    elif source_trigger_type == "runtime_pattern":
        recommendation = db.scalar(
            select(RuntimeGovernanceRecommendation).where(
                RuntimeGovernanceRecommendation.tenant_id == ctx.tenant.id,
                RuntimeGovernanceRecommendation.recommendation_id == remediation.source_trigger_id,
            )
        )
        if recommendation is not None:
            trigger_created_at = recommendation.created_at
            payload = dict(recommendation.payload or {})
            related_control_ids.update(str(item) for item in (payload.get("related_control_ids") or []) if str(item).strip())
            trigger_details.update(
                {
                    "recommendation_id": recommendation.recommendation_id,
                    "recommendation_type": recommendation.recommendation_type,
                    "priority": recommendation.priority,
                    "status": recommendation.status,
                }
            )

    rollback_details = dict(remediation.rollback_payload or {}).get("details") or {}
    if isinstance(rollback_details, dict):
        related_control_ids.update(str(item) for item in (rollback_details.get("related_control_ids") or []) if str(item).strip())

    normalized_related_control_ids = normalize_control_ids(sorted(related_control_ids))
    controls = (
        db.scalars(
            select(Control).where(
                Control.tenant_id == ctx.tenant.id,
                Control.id.in_(normalized_related_control_ids),
            )
        ).all()
        if normalized_related_control_ids
        else []
    )
    affected_controls = [
        {
            "id": row.id,
            "name": row.name,
            "category": row.category,
            "mapped_framework_refs": list(row.mapped_framework_refs or []),
        }
        for row in controls
    ]
    framework_mappings: list[dict] = []
    seen_framework_refs: set[str] = set()
    for row in controls:
        for mapping in row.mapped_framework_refs or []:
            serialized = json.dumps(mapping, sort_keys=True, default=str)
            if serialized in seen_framework_refs:
                continue
            seen_framework_refs.add(serialized)
            framework_mappings.append(mapping if isinstance(mapping, dict) else {"reference": str(mapping)})
    for mapping in _canonical_framework_refs(remediation.remediation_type):
        serialized = json.dumps(mapping, sort_keys=True, default=str)
        if serialized in seen_framework_refs:
            continue
        seen_framework_refs.add(serialized)
        framework_mappings.append(mapping)

    audit_logs = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == ctx.tenant.id,
            AuditLog.correlation_id == remediation.id,
        )
        .order_by(AuditLog.created_at.asc())
    ).all()

    remediation_nodes = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == ctx.tenant.id,
            EvidenceNode.correlation_id == remediation.id,
        )
        .order_by(EvidenceNode.created_at.asc())
    ).all()
    remediation_node_ids = {row.id for row in remediation_nodes}
    evidence_edges = (
        db.scalars(
            select(EvidenceEdge).where(
                EvidenceEdge.tenant_id == ctx.tenant.id,
                (EvidenceEdge.from_node_id.in_(sorted(remediation_node_ids)))
                | (EvidenceEdge.to_node_id.in_(sorted(remediation_node_ids))),
            )
        ).all()
        if remediation_node_ids
        else []
    )
    connected_node_ids = set(remediation_node_ids)
    connected_node_ids.update(edge.from_node_id for edge in evidence_edges)
    connected_node_ids.update(edge.to_node_id for edge in evidence_edges)
    evidence_nodes = (
        db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == ctx.tenant.id,
                EvidenceNode.id.in_(sorted(connected_node_ids)),
            )
        ).all()
        if connected_node_ids
        else remediation_nodes
    )

    approver = None
    if remediation.approved_by:
        user = db.scalar(select(User).where(User.id == remediation.approved_by))
        approver = {
            "user_id": remediation.approved_by,
            "email": getattr(user, "email", None) if user else None,
            "full_name": getattr(user, "full_name", None) if user else None,
        }

    timeline: list[dict] = []
    if trigger_created_at is not None:
        timeline.append(
            {
                "timestamp": _iso(trigger_created_at),
                "kind": "trigger",
                "label": source_trigger_type,
                "details": trigger_details,
            }
        )
    for row in audit_logs:
        timeline.append(
            {
                "timestamp": _iso(row.created_at),
                "kind": "audit",
                "label": row.action,
                "details": {"resource_type": row.resource_type, "resource_id": row.resource_id, "payload": dict(row.payload or {})},
            }
        )
    for row in evidence_nodes:
        timeline.append(
            {
                "timestamp": _iso(row.created_at),
                "kind": "evidence",
                "label": row.signal_type,
                "details": {"node_id": row.id, "node_type": row.node_type},
            }
        )
    timeline = sorted(timeline, key=lambda item: str(item.get("timestamp") or ""))

    rollback_payload = dict(remediation.rollback_payload or {})
    rollback_context = dict(rollback_payload.get("context") or {})
    remediation_crq = dict(rollback_context.get("crq") or {})
    if not remediation_crq and isinstance(rollback_payload.get("details"), dict):
        remediation_crq = dict((rollback_payload.get("details") or {}).get("crq") or {})

    def _safe_float(value: object, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    baseline_ale = _safe_float(remediation_crq.get("baseline_ale") or remediation_crq.get("at_risk_if_ignored_usd"))
    current_ale = _safe_float(remediation_crq.get("current_ale") or remediation_crq.get("annualized_loss_expectancy"))
    new_ale = _safe_float(remediation_crq.get("new_ALE"))
    estimated_risk_reduction = _safe_float(remediation_crq.get("estimated_risk_reduction"))
    if baseline_ale <= 0.0:
        baseline_ale = max(current_ale, new_ale, estimated_risk_reduction)
    if current_ale <= 0.0:
        current_ale = max(new_ale, 0.0)
    if new_ale <= 0.0:
        new_ale = max(0.0, current_ale - estimated_risk_reduction)

    before_state = dict(rollback_payload.get("before") or {})
    after_state = dict(rollback_payload.get("after") or {})
    state_delta = _state_delta(before_state, after_state)

    trigger_node_ids: set[str] = set()
    target_node_ids: set[str] = set()
    for edge in evidence_edges:
        if edge.edge_type == "triggers_remediation":
            trigger_node_ids.add(edge.from_node_id)
        if edge.edge_type == "remediation_affects_target":
            target_node_ids.add(edge.to_node_id)

    remediation_execution_audits = [row for row in audit_logs if row.action in {"remediation.applied", "remediation.failed", "remediation.rolled_back"}]
    execution_status = remediation_execution_audits[-1].action if remediation_execution_audits else "pending_execution"
    execution_timestamp = _iso(remediation_execution_audits[-1].created_at) if remediation_execution_audits else _iso(remediation.applied_at)
    outcome_status = remediation.status
    outcome_timestamp = _iso(remediation.applied_at)
    if outcome_timestamp is None and audit_logs:
        outcome_timestamp = _iso(audit_logs[-1].created_at)

    stages = [
        {
            "stage": "trigger",
            "status": "observed" if trigger_created_at else "unknown",
            "timestamp": _iso(trigger_created_at),
            "details": trigger_details,
        },
        {
            "stage": "decision",
            "status": "approved" if remediation.approved_by else "proposed",
            "timestamp": _iso(remediation.created_at),
            "details": {
                "remediation_type": remediation.remediation_type,
                "action_mode": remediation.action_mode,
                "risk_level": remediation.risk_level,
                "requires_approval": remediation.requires_approval,
                "approved_by": remediation.approved_by,
                "justification": remediation.justification,
                "recommendation_text": remediation.recommendation_text,
            },
        },
        {
            "stage": "execution",
            "status": execution_status,
            "timestamp": execution_timestamp,
            "details": {
                "audit_event_count": len(remediation_execution_audits),
                "rollback_supported": remediation.rollback_supported,
            },
        },
        {
            "stage": "outcome",
            "status": outcome_status,
            "timestamp": outcome_timestamp,
            "details": {
                "resolved": outcome_status == "applied",
                "rolled_back": outcome_status == "rolled_back",
                "failed": outcome_status == "failed",
            },
        },
    ]

    ticket_refs: list[dict] = []
    seen_tickets: set[str] = set()
    details = dict(rollback_payload.get("details") or {})
    candidate_tickets = []
    if isinstance(details, dict):
        if isinstance(details.get("tickets"), list):
            candidate_tickets.extend(item for item in details.get("tickets") if isinstance(item, dict))
        if isinstance(details.get("ticket_id"), str):
            candidate_tickets.append(
                {
                    "ticket_id": details.get("ticket_id"),
                    "ticket_system": details.get("ticket_system"),
                    "severity": details.get("severity"),
                    "title": details.get("title"),
                    "description": details.get("description"),
                    "created_at": details.get("created_at"),
                }
            )
    for row in audit_logs:
        payload = dict(row.payload or {})
        if row.action == "remediation.ticket.created" and str(payload.get("ticket_id") or "").strip():
            candidate_tickets.append(payload)
    for row in evidence_nodes:
        payload = dict(row.payload or {})
        if row.signal_type == "remediation.ticket.created" and str(payload.get("ticket_id") or "").strip():
            candidate_tickets.append(payload)
    for ticket in candidate_tickets:
        ticket_id = str(ticket.get("ticket_id") or "").strip()
        ticket_system = str(ticket.get("ticket_system") or "").strip().lower()
        if not ticket_id:
            continue
        token = f"{ticket_system}:{ticket_id}"
        if token in seen_tickets:
            continue
        seen_tickets.add(token)
        ticket_refs.append(
            {
                "ticket_id": ticket_id,
                "ticket_system": ticket_system or "jira",
                "severity": str(ticket.get("severity") or remediation.risk_level or "").lower(),
                "title": ticket.get("title"),
                "description": ticket.get("description"),
                "created_at": str(ticket.get("created_at") or ""),
                "status": str(ticket.get("status") or "open").lower(),
            }
        )

    remaining_gaps: list[str] = []
    if remediation.requires_approval and not remediation.approved_by:
        remaining_gaps.append("approval_pending")
    if remediation.status in {"proposed", "failed", "rejected"}:
        remaining_gaps.append("remediation_not_effective")
    if remediation.status == "rolled_back":
        remaining_gaps.append("rollback_completed_revalidation_required")
    if not framework_mappings:
        remaining_gaps.append("framework_mapping_missing")
    remediation_risk_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(remediation.risk_level or "").lower(), 2)
    if not ticket_refs and remediation_risk_rank >= 3:
        remaining_gaps.append("ticket_not_created_for_high_risk")

    framework_names = sorted(
        {
            str(item.get("framework") or "").strip()
            for item in framework_mappings
            if isinstance(item, dict) and str(item.get("framework") or "").strip()
        }
    )
    framework_financial_risk: list[dict] = []
    if framework_names:
        per_framework_current = current_ale / float(len(framework_names)) if current_ale > 0 else 0.0
        per_framework_reduction = estimated_risk_reduction / float(len(framework_names)) if estimated_risk_reduction > 0 else 0.0
        per_framework_baseline = baseline_ale / float(len(framework_names)) if baseline_ale > 0 else 0.0
        for name in framework_names:
            framework_financial_risk.append(
                {
                    "framework": name,
                    "baseline_ale": round(per_framework_baseline, 2),
                    "current_ale": round(per_framework_current, 2),
                    "risk_reduction_usd": round(per_framework_reduction, 2),
                }
            )

    related_control_ids = [str(item) for item in (remediation_crq.get("related_control_ids") or []) if str(item).strip()]
    control_effectiveness_usd: list[dict] = []
    if affected_controls:
        reduction_pool = estimated_risk_reduction
        if reduction_pool <= 0.0 and current_ale > new_ale:
            reduction_pool = current_ale - new_ale
        per_control_reduction = reduction_pool / float(len(affected_controls)) if reduction_pool > 0 else 0.0
        for row in affected_controls:
            control_effectiveness_usd.append(
                {
                    "control_id": row.get("id"),
                    "control_name": row.get("name"),
                    "mapped": (not related_control_ids) or (str(row.get("id")) in related_control_ids),
                    "estimated_risk_reduction_usd": round(per_control_reduction, 2),
                }
            )

    compliance_impact = {
        "resolved_risk": remediation.status == "applied" and bool(state_delta or remediation.applied_at),
        "remaining_gaps": remaining_gaps,
        "maturity_signal": "improving" if remediation.status == "applied" else "attention_required",
        "frameworks_covered": sorted({str(item.get("framework") or "").strip().lower() for item in framework_mappings if str(item.get("framework") or "").strip()}),
        "ticket_count": len(ticket_refs),
        "financial_risk": {
            "baseline_ale": round(baseline_ale, 2),
            "current_ale": round(current_ale, 2),
            "new_ale": round(new_ale, 2),
            "estimated_risk_reduction_usd": round(estimated_risk_reduction, 2),
            "at_risk_if_ignored_usd": round(max(baseline_ale, current_ale), 2),
        },
        "framework_financial_risk": framework_financial_risk,
        "control_effectiveness_usd": control_effectiveness_usd,
    }

    evidence_linkage = {
        "before_state": before_state,
        "after_state": after_state,
        "state_delta": state_delta,
        "trigger_evidence_node_ids": sorted(trigger_node_ids),
        "remediation_evidence_node_ids": sorted(remediation_node_ids),
        "target_evidence_node_ids": sorted(target_node_ids),
    }

    return RemediationTraceResponse(
        remediation_id=remediation.id,
        remediation={
            "id": remediation.id,
            "remediation_type": remediation.remediation_type,
            "target_type": remediation.target_type,
            "target_id": remediation.target_id,
            "action_mode": remediation.action_mode,
            "status": remediation.status,
            "risk_level": remediation.risk_level,
            "requires_approval": remediation.requires_approval,
            "approved_by": remediation.approved_by,
            "justification": remediation.justification,
            "rollback_supported": remediation.rollback_supported,
            "rollback_payload": dict(remediation.rollback_payload or {}),
            "crq": remediation_crq,
            "created_at": _iso(remediation.created_at),
            "applied_at": _iso(remediation.applied_at),
        },
        trigger=trigger_details,
        approver=approver,
        stages=stages,
        evidence_linkage=evidence_linkage,
        evidence_nodes=[
            {
                "id": row.id,
                "node_type": row.node_type,
                "signal_type": row.signal_type,
                "label": row.label,
                "payload": dict(row.payload or {}),
                "correlation_id": row.correlation_id,
                "created_at": _iso(row.created_at),
            }
            for row in sorted(evidence_nodes, key=lambda item: item.created_at)
        ],
        evidence_edges=[
            {
                "id": row.id,
                "from_node_id": row.from_node_id,
                "to_node_id": row.to_node_id,
                "edge_type": row.edge_type,
                "payload": dict(row.payload or {}),
            }
            for row in evidence_edges
        ],
        audit_logs=[
            {
                "id": row.id,
                "action": row.action,
                "actor_user_id": row.actor_user_id,
                "actor_type": row.actor_type,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "payload": dict(row.payload or {}),
                "created_at": _iso(row.created_at),
            }
            for row in audit_logs
        ],
        tickets=ticket_refs,
        affected_controls=affected_controls,
        framework_mappings=framework_mappings,
        compliance_impact=compliance_impact,
        timeline=timeline,
    )


@router.post(
    "/snapshot",
    response_model=AuditorSnapshotResponse,
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="auditor.snapshot.create",
                route="/auditor/snapshot",
                module="auditor",
                missing_ai_reason_code="AI_SYSTEM_ID_MISSING_FOR_SNAPSHOT",
                missing_ai_message="ai_system_id is required unless tenant_scope=true",
                missing_ai_response_code="AI_SYSTEM_ID_REQUIRED",
            )
        )
    ],
)
def snapshot(
    payload: SnapshotRequest,
    request: Request,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    snapshot_payload = dict(payload.payload or {})
    if payload.tenant_scope:
        if not settings.auditor_tenant_snapshot_enabled:
            _write_snapshot_scope_block(
                db=db,
                tenant_id=ctx.tenant.id,
                route="/auditor/snapshot",
                module="auditor",
                reason_code="TENANT_SNAPSHOT_DISABLED",
                message="TENANT_SNAPSHOT_DISABLED",
                status_code=status.HTTP_403_FORBIDDEN,
                request=request,
            )

        frameworks_in_scope = _normalize_scope_list(payload.frameworks_in_scope)
        controls_in_scope = _normalize_scope_list(payload.controls_in_scope)
        if not frameworks_in_scope and not controls_in_scope:
            _write_snapshot_scope_block(
                db=db,
                tenant_id=ctx.tenant.id,
                route="/auditor/snapshot",
                module="auditor",
                reason_code="TENANT_SCOPE_TARGET_REQUIRED",
                message="TENANT_SCOPE_TARGET_REQUIRED",
                status_code=status.HTTP_400_BAD_REQUEST,
                request=request,
            )

        time_range = _parse_time_range_or_raise(payload=payload, db=db, ctx=ctx, request=request)
        include_systems = _normalize_scope_list(payload.include_systems)

        query = select(AISystem.id).where(AISystem.tenant_id == ctx.tenant.id)
        if include_systems:
            query = query.where(AISystem.id.in_(include_systems))
        if payload.risk_tier:
            query = query.where(func.upper(AISystem.risk_tier) == payload.risk_tier.strip().upper())
        if payload.lifecycle_state:
            query = query.where(func.upper(AISystem.status) == payload.lifecycle_state.strip().upper())

        ai_systems_included = sorted(db.scalars(query).all())
        scope_descriptor = {
            "snapshot_scope": "tenant",
            "frameworks_in_scope": frameworks_in_scope,
            "controls_in_scope": controls_in_scope,
            "time_range": time_range,
            "risk_tier": payload.risk_tier.strip().upper() if payload.risk_tier else None,
            "lifecycle_state": payload.lifecycle_state.strip().upper() if payload.lifecycle_state else None,
            "include_systems": include_systems,
            "ai_systems_included": ai_systems_included,
        }
        snapshot_payload.update(
            {
                "snapshot_scope": "tenant",
                "scope_hash": _scope_hash(scope_descriptor),
                "ai_systems_included": ai_systems_included,
                "frameworks_in_scope": frameworks_in_scope,
                "controls_in_scope": controls_in_scope,
                "time_range": time_range,
                "risk_tier": scope_descriptor["risk_tier"],
                "lifecycle_state": scope_descriptor["lifecycle_state"],
                "include_systems": include_systems,
            }
        )

    try:
        row = create_auditor_snapshot(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            trigger_type=payload.trigger_type,
            payload=snapshot_payload,
            actor_user_id=None,
        )
        db.commit()
        db.refresh(row)
        return AuditorSnapshotResponse.model_validate(row)
    except RuntimeError as exc:
        db.rollback()
        raise _storage_failure(exc) from exc
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/export", response_model=AuditorExportResponse)
def export(
    payload: ExportRequest,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    end = payload.period_end or datetime.now(timezone.utc).isoformat()
    start = payload.period_start or (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    try:
        out = export_audit_artifacts(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            period_start=start,
            period_end=end,
        )

        snap = create_auditor_snapshot(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            trigger_type="export",
            payload={"period_start": start, "period_end": end, "artifacts": out},
            actor_user_id=None,
            artifact_hash=out.get("hash"),
            artifact_relative_path=out.get("json_relative_path"),
        )

        db.commit()
        relative_path = artifact_relative_path(snap.artifact_path)
        return AuditorExportResponse(
            snapshot_id=snap.id,
            artifact_relative_path=relative_path,
            download_url=artifact_download_url(snap.id),
            download_urls={
                "json": artifact_named_download_url(snap.id, "json"),
                "csv": artifact_named_download_url(snap.id, "csv"),
                "evidence_pack": artifact_named_download_url(snap.id, "evidence_pack"),
                "pdf_ready_model": artifact_named_download_url(snap.id, "pdf_ready_model"),
                "pdf": artifact_named_download_url(snap.id, "pdf"),
                "signature_manifest": artifact_named_download_url(snap.id, "signature_manifest"),
            },
            artifacts=AuditorExportArtifactsResponse(**out),
        )
    except RuntimeError as exc:
        db.rollback()
        raise _storage_failure(exc) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/snapshots/{snapshot_id}/download")
def download_snapshot(
    snapshot_id: str,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    snapshot = db.scalar(
        select(AuditorSnapshot).where(
            AuditorSnapshot.id == snapshot_id,
            AuditorSnapshot.tenant_id == ctx.tenant.id,
        )
    )
    if not snapshot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found")

    try:
        artifact_path = resolve_artifact_file_path(snapshot.artifact_path)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise _storage_failure(exc) from exc

    if not artifact_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot artifact not found")

    return FileResponse(
        path=artifact_path,
        filename=artifact_path.name,
        media_type="application/octet-stream",
        headers=evidence_signing.service().header_for(artifact_path.read_bytes(), artifact="auditor.snapshot"),
    )


@router.get("/snapshots/{snapshot_id}/artifacts/{artifact_name}")
def download_snapshot_artifact(
    snapshot_id: str,
    artifact_name: Literal["json", "csv", "evidence_pack", "pdf_ready_model", "pdf", "signature_manifest"],
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    snapshot = db.scalar(
        select(AuditorSnapshot).where(
            AuditorSnapshot.id == snapshot_id,
            AuditorSnapshot.tenant_id == ctx.tenant.id,
        )
    )
    if not snapshot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found")

    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
    artifact_value = artifacts.get(artifact_name)
    if not isinstance(artifact_value, str) or not artifact_value.strip():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Artifact '{artifact_name}' not found")

    try:
        artifact_path = resolve_artifact_file_path(artifact_value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise _storage_failure(exc) from exc

    if not artifact_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot artifact not found")

    media_type = {
        "json": "application/json",
        "csv": "text/csv",
        "evidence_pack": "application/json",
        "pdf_ready_model": "application/json",
        "pdf": "application/pdf",
        "signature_manifest": "application/json",
    }[artifact_name]
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        action="auditor.snapshot.artifact_download",
        resource_type="auditor_snapshot",
        resource_id=snapshot.id,
        actor_user_id=None,
        actor_type="user",
        payload={"artifact_name": artifact_name, "artifact_path": artifact_relative_path(str(artifact_path))},
    )
    db.commit()
    # Each file also carries its own detached evidence signature (app/services/evidence_signing.py), so it can be
    # checked on its own, offline (tools/verify_evidence.py --signature).
    return FileResponse(
        path=artifact_path,
        filename=artifact_path.name,
        media_type=media_type,
        headers=evidence_signing.service().header_for(artifact_path.read_bytes(), artifact=f"auditor.{artifact_name}"),
    )


@router.get("/conflicts", response_model=ListEnvelope[ControlConflictResponse])
def list_conflicts(
    status_filter: str = "open",
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    query = select(ControlConflict).where(ControlConflict.tenant_id == ctx.tenant.id)
    if status_filter != "all":
        query = query.where(ControlConflict.status == status_filter)
    rows = db.scalars(query.order_by(ControlConflict.detected_at.desc())).all()
    dto_rows = [ControlConflictResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ControlConflictResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/challenge", response_model=ControlConflictResponse)
def create_challenge(
    payload: AuditorChallengeRequest,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == payload.ai_system_id,
            AISystem.tenant_id == ctx.tenant.id,
        )
    )
    if not ai_system:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")

    control = db.scalar(
        select(Control).where(
            Control.id == payload.control_id,
            Control.tenant_id == ctx.tenant.id,
        )
    )
    if not control:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control not found")

    referenced_nodes = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == ctx.tenant.id,
            EvidenceNode.id.in_(payload.evidence_node_ids) if payload.evidence_node_ids else EvidenceNode.id == "__none__",
        )
    ).all()
    found_ids = {row.id for row in referenced_nodes}
    missing_ids = [node_id for node_id in payload.evidence_node_ids if node_id not in found_ids]
    if missing_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown evidence_node_ids for tenant: {', '.join(missing_ids)}",
        )

    challenge_node = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="auditor_challenge",
        signal_type="control.challenge.created",
        label=f"Auditor challenge for {payload.control_id}",
        payload={
            "ai_system_id": payload.ai_system_id,
            "control_id": payload.control_id,
            "challenge_reason": payload.challenge_reason.strip(),
            "evidence_node_ids": payload.evidence_node_ids,
        },
    )

    conflict = ControlConflict(
        tenant_id=ctx.tenant.id,
        ai_system_id=payload.ai_system_id,
        control_id=payload.control_id,
        status="open",
        reason="auditor_challenge",
        positive_signals=0,
        negative_signals=0,
        latest_signal_at=datetime.now(timezone.utc),
        evidence_node_ids=[*payload.evidence_node_ids, challenge_node.id],
        details={
            "challenge_reason": payload.challenge_reason.strip(),
            "requires_human_resolution": True,
            "challenge_node_id": challenge_node.id,
            "lineage_preserved": True,
        },
        audit_log_id=None,
    )
    db.add(conflict)
    db.flush()

    for node_id in payload.evidence_node_ids:
        link_evidence_nodes(
            db,
            tenant_id=ctx.tenant.id,
            from_node_id=node_id,
            to_node_id=challenge_node.id,
            edge_type="challenged_by",
            payload={"conflict_id": conflict.id, "control_id": payload.control_id},
        )

    audit = write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="auditor.challenge.create",
        resource_type="control_conflict",
        resource_id=conflict.id,
        payload={
            "ai_system_id": payload.ai_system_id,
            "control_id": payload.control_id,
            "challenge_reason": payload.challenge_reason.strip(),
            "evidence_node_ids": payload.evidence_node_ids,
            "requires_human_resolution": True,
        },
    )
    conflict.audit_log_id = audit.id

    recalculate_control_maturity(
        db,
        tenant_id=ctx.tenant.id,
        ai_system_id=payload.ai_system_id,
        control_ids=[payload.control_id],
        reason=f"auditor_challenge:{conflict.id}",
    )

    db.commit()
    db.refresh(conflict)
    return ControlConflictResponse.model_validate(conflict)


@router.post("/conflicts/{conflict_id}/resolve", response_model=ControlConflictResponse)
def resolve_conflict(
    conflict_id: str,
    payload: ConflictResolveRequest,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    conflict = db.scalar(
        select(ControlConflict).where(
            ControlConflict.id == conflict_id,
            ControlConflict.tenant_id == ctx.tenant.id,
        )
    )
    if not conflict:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conflict not found")
    if conflict.status != "open":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Conflict is not open")

    now = datetime.now(timezone.utc)
    conflict.status = "resolved"
    conflict.resolved_at = now
    conflict.resolution_decision = payload.decision
    conflict.resolution_notes = payload.notes.strip()
    conflict.resolved_by = None

    audit = write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="auditor.conflict.resolve",
        resource_type="control_conflict",
        resource_id=conflict.id,
        payload={
            "decision": payload.decision,
            "notes": conflict.resolution_notes,
            "control_id": conflict.control_id,
            "ai_system_id": conflict.ai_system_id,
        },
    )
    conflict.audit_log_id = audit.id

    chosen_evidence_id = (conflict.details or {}).get("chosen_evidence_id")
    if not chosen_evidence_id and conflict.evidence_node_ids:
        chosen_evidence_id = conflict.evidence_node_ids[0]
    discarded_evidence_ids = [node_id for node_id in (conflict.evidence_node_ids or []) if node_id != chosen_evidence_id]
    db.add(
        ConflictResolution(
            tenant_id=ctx.tenant.id,
            ai_system_id=conflict.ai_system_id,
            control_id=conflict.control_id,
            conflict_id=conflict.id,
            chosen_evidence_id=chosen_evidence_id,
            discarded_evidence_ids=discarded_evidence_ids,
            reason=f"human_resolution:{payload.decision}",
        )
    )

    resolution_node = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="control_conflict_resolution",
        signal_type="control.conflict.resolved",
        label=f"Control conflict resolved for {conflict.control_id}",
        payload={
            "conflict_id": conflict.id,
            "control_id": conflict.control_id,
            "ai_system_id": conflict.ai_system_id,
            "decision": payload.decision,
            "notes": conflict.resolution_notes,
        },
    )

    existing_node_ids = list(conflict.evidence_node_ids or [])
    if existing_node_ids:
        try:
            link_evidence_nodes(
                db,
                tenant_id=ctx.tenant.id,
                from_node_id=existing_node_ids[0],
                to_node_id=resolution_node.id,
                edge_type="adjudicated",
                payload={"conflict_id": conflict.id},
            )
        except ValueError:
            pass
    conflict.evidence_node_ids = [*existing_node_ids, resolution_node.id]

    recalculate_control_maturity(
        db,
        tenant_id=ctx.tenant.id,
        ai_system_id=conflict.ai_system_id,
        control_ids=[conflict.control_id],
        reason=f"conflict_resolved:{conflict.id}:{payload.decision}",
    )

    db.commit()
    db.refresh(conflict)
    return ControlConflictResponse.model_validate(conflict)


@router.get("/control-posture", response_model=ControlPostureResponse)
def control_posture_view(
    group_by: Literal["framework", "domain", "ai_system"] = "framework",
    ai_system_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("evidence.export")),
    db: Session = Depends(get_db),
):
    if ai_system_id:
        row = db.scalar(
            select(AISystem).where(
                AISystem.id == ai_system_id,
                AISystem.tenant_id == ctx.tenant.id,
            )
        )
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")

    views = build_control_posture_views(
        db,
        tenant_id=ctx.tenant.id,
        ai_system_id=ai_system_id,
    )
    rows = views.get(group_by, [])
    return ControlPostureResponse(
        group_by=group_by,
        rows=[ControlPostureRow.model_validate(item) for item in rows],
    )
