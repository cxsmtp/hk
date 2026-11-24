from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryEcosystemMembership,
    DiscoveryEcosystemResolutionEvent,
    DiscoveryHypothesisEvaluation,
)
from app.db.session import get_db
from app.services.hmair.erg.evidence_timeline import EvidenceTimeline
from app.services.hmair.erg.pipeline import EvidenceResolutionPipeline
from app.services.hmair.adv.projection import (
    VerificationProjectionConflict,
    VerificationProjectionService,
)
from app.services.hmair.erg.resolution_history import (
    ResolutionAuthorizationError,
    ResolutionConflict,
    ResolutionHistory,
)
from app.services.hmair.resolution_explainability_service import (
    confidence_band,
    explain_resolution,
    public_evidence_state,
)


router = APIRouter(
    prefix="/discovery/evidence-resolution",
    tags=["discovery-evidence-resolution"],
)


class EcosystemSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem_id: str
    canonical_name: str
    ecosystem_class: str
    lifecycle_state: str
    resolution_state: str
    confidence: float | None
    evidence_quality: float | None
    capability_genome_id: str | None
    member_count: int
    outstanding_contradictions: int
    limitations: list[str]
    last_validated_at: datetime
    methodology_id: str
    methodology_version: str


class EcosystemDetailResponse(EcosystemSummaryResponse):
    why: dict
    members: list[dict]
    relationships: list[dict]
    contradictions: list[dict]
    recent_changes: list[dict]
    recommended_actions: list[str]
    verification: dict


class TimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[dict]
    total: int


class GraphResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[dict]
    edges: list[dict]
    methodology: str
    limitations: list[str]


class MergeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ecosystem_ids: list[str] = Field(min_length=2, max_length=32)
    canonical_name: str = Field(min_length=1, max_length=255)
    ecosystem_class: str = Field(min_length=1, max_length=128)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=128)


class AttachRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    graph_node_id: str = Field(min_length=1, max_length=36)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=128)


class DispositionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Literal["reject", "manual_review", "unknown"]
    subject_reference: str = Field(min_length=1, max_length=255)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=128)


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_ids: list[str] = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=80)
    verification_environment: str = Field(default="production", min_length=1, max_length=64)


class ResolveResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inference_run_id: str
    evidence_node_id: str
    graph_edge_ids: list[str]
    evaluation_ids: list[str]
    outcomes: list[dict]
    verification_episode_ids: list[str]
    verification_limitations: list[str]


class SplitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groups: list[list[str]] = Field(min_length=2, max_length=32)
    canonical_names: list[str] = Field(min_length=2, max_length=32)
    ecosystem_classes: list[str] = Field(min_length=2, max_length=32)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=128)


class ReverseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_node_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=1, max_length=128)


class MutationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    action: str
    ecosystem_ids: list[str]
    before_memberships: list[dict]
    after_memberships: list[dict]


def _require_erg() -> None:
    if not settings.cie_core:
        raise HTTPException(status_code=404, detail="Evidence Resolution Graph is not enabled")


def _latest_records(db: Session, tenant_id: str) -> tuple[DiscoveryAIEcosystem, ...]:
    rows = tuple(db.scalars(select(DiscoveryAIEcosystem).where(
        DiscoveryAIEcosystem.tenant_id == tenant_id
    ).order_by(DiscoveryAIEcosystem.ecosystem_id, DiscoveryAIEcosystem.resolution_version.desc())))
    latest: dict[str, DiscoveryAIEcosystem] = {}
    for row in rows:
        latest.setdefault(row.ecosystem_id, row)
    return tuple(sorted(
        (row for row in latest.values() if row.lifecycle_state == "active"),
        key=lambda row: (row.canonical_name.lower(), row.ecosystem_id),
    ))


def _members(db: Session, tenant_id: str, ecosystem_id: str) -> tuple[DiscoveryEcosystemMembership, ...]:
    rows = tuple(db.scalars(select(DiscoveryEcosystemMembership).where(
        DiscoveryEcosystemMembership.tenant_id == tenant_id,
        DiscoveryEcosystemMembership.ecosystem_id == ecosystem_id,
    ).order_by(DiscoveryEcosystemMembership.membership_sequence.desc())))
    latest: dict[str, DiscoveryEcosystemMembership] = {}
    for row in rows:
        latest.setdefault(row.graph_node_id, row)
    return tuple(sorted(
        (row for row in latest.values() if row.membership_state == "active"),
        key=lambda row: row.graph_node_id,
    ))


def _summary(db: Session, row: DiscoveryAIEcosystem) -> EcosystemSummaryResponse:
    return EcosystemSummaryResponse(
        ecosystem_id=row.ecosystem_id, canonical_name=row.canonical_name,
        ecosystem_class=row.ecosystem_class, lifecycle_state=row.lifecycle_state,
        resolution_state=row.resolution_state, confidence=row.confidence,
        evidence_quality=row.evidence_quality,
        capability_genome_id=row.capability_genome_id,
        member_count=len(_members(db, row.tenant_id, row.ecosystem_id)),
        outstanding_contradictions=row.outstanding_contradictions,
        limitations=list(row.limitations_json), last_validated_at=row.last_validated_at,
        methodology_id=row.methodology_id, methodology_version=row.methodology_version,
    )


def _ecosystem(db: Session, tenant_id: str, ecosystem_id: str) -> DiscoveryAIEcosystem:
    row = next((item for item in _latest_records(db, tenant_id) if item.ecosystem_id == ecosystem_id), None)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI ecosystem not found")
    return row


@router.get("/ecosystems", response_model=list[EcosystemSummaryResponse])
def list_ecosystems(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> list[EcosystemSummaryResponse]:
    _require_erg()
    return [_summary(db, row) for row in _latest_records(db, ctx.tenant.id)]


@router.get("/ecosystems/{ecosystem_id}", response_model=EcosystemDetailResponse)
def get_ecosystem(
    ecosystem_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> EcosystemDetailResponse:
    _require_erg()
    row = _ecosystem(db, ctx.tenant.id, ecosystem_id)
    member_rows = _members(db, ctx.tenant.id, ecosystem_id)
    node_ids = tuple(item.graph_node_id for item in member_rows)
    nodes = {item.graph_node_id: item for item in db.scalars(select(DiscoveryResolutionGraphNode).where(
        DiscoveryResolutionGraphNode.tenant_id == ctx.tenant.id,
        DiscoveryResolutionGraphNode.graph_node_id.in_(node_ids),
    ))} if node_ids else {}
    edges = tuple(db.scalars(select(DiscoveryResolutionGraphEdge).where(
        DiscoveryResolutionGraphEdge.tenant_id == ctx.tenant.id,
        DiscoveryResolutionGraphEdge.from_node_id.in_(node_ids),
        DiscoveryResolutionGraphEdge.to_node_id.in_(node_ids),
    ))) if node_ids else ()
    historical = {item.predecessor_edge_id for item in edges if item.predecessor_edge_id}
    current_edges = tuple(item for item in edges if item.edge_id not in historical)
    contradictions = [
        {"edge_id": item.edge_id, "type": item.edge_type,
         "state": item.contradiction_state, "evidence_node_id": item.evidence_node_id}
        for item in current_edges if item.contradiction_state in {"possible", "confirmed", "unknown"}
    ]
    events = tuple(db.scalars(select(DiscoveryEcosystemResolutionEvent).where(
        DiscoveryEcosystemResolutionEvent.tenant_id == ctx.tenant.id
    ).order_by(DiscoveryEcosystemResolutionEvent.occurred_at.desc()).limit(100)))
    changes = [
        {"event_id": item.resolution_event_id, "action": item.action,
         "reason": item.reason, "operator_role": item.operator_role,
         "occurred_at": item.occurred_at}
        for item in events
        if ecosystem_id in set(item.source_ecosystem_ids_json + item.result_ecosystem_ids_json)
    ][:20]
    summary = _summary(db, row)
    limitations = list(row.limitations_json)
    recommendations = []
    if contradictions:
        recommendations.append("Review outstanding contradictory evidence before merging.")
    if row.evidence_quality is None:
        recommendations.append("Collect validated evidence from another independent surface.")
    if not recommendations:
        recommendations.append("Continue validation to keep evidence fresh.")
    explanation = explain_resolution(
        confidence=row.confidence,
        evidence_quality=row.evidence_quality,
        evidence_categories=tuple(item.edge_type for item in current_edges),
        source_surfaces=tuple(item.source_surface for item in current_edges),
        collector_ids=tuple(item.collector_id or "" for item in current_edges),
        # Current ERG rows retain collector identity and surface diversity but
        # do not yet store an attested independence group. Do not infer one.
        independent_source_groups=(),
        conflicts=tuple(
            f"{item.edge_type}:{item.contradiction_state}"
            for item in current_edges
            if item.contradiction_state
            in {"possible", "confirmed", "unknown", "unresolved"}
        ),
        limitations=tuple(limitations),
        methodology_id=row.methodology_id,
        methodology_version=row.methodology_version,
    )
    try:
        verification = VerificationProjectionService().get(
            db,
            tenant_id=ctx.tenant.id,
            ecosystem_id=ecosystem_id,
            evaluated_at=datetime.now(timezone.utc),
        )
        verification_projection = {
            "stage": verification.stage.value,
            "assertion_current": verification.assertion_current,
            "verification_coverage": verification.verification_coverage,
            "verification_quality": verification.verification_quality,
            "collector_diversity": verification.collector_diversity,
            "last_validation_at": verification.last_validation_at,
            "next_validation_at": verification.next_validation_at,
            "limitations": list(verification.limitations),
        }
    except VerificationProjectionConflict:
        verification_projection = {
            "stage": "hypothesis",
            "assertion_current": False,
            "verification_coverage": 0.0,
            "verification_quality": None,
            "collector_diversity": 0,
            "last_validation_at": None,
            "next_validation_at": None,
            "limitations": ["verification_projection_unavailable"],
        }
    return EcosystemDetailResponse(
        **summary.model_dump(),
        why={
            "statement": "Hawk resolved this ecosystem from versioned supporting evidence and explicit relationship rules.",
            **explanation.model_dump(mode="json"),
            "contributors": [
                {"graph_node_id": member.graph_node_id,
                 "node_class": nodes[member.graph_node_id].node_class,
                 "subject_reference": nodes[member.graph_node_id].subject_reference,
                 "confidence": member.confidence,
                 "verification_state": member.verification_state,
                 "evidence_node_id": member.evidence_node_id}
                for member in member_rows
            ],
            "limitations": limitations,
        },
        members=[
            {"graph_node_id": member.graph_node_id,
             "node_class": nodes[member.graph_node_id].node_class,
             "subject_reference": nodes[member.graph_node_id].subject_reference,
             "confidence": member.confidence,
             "verification_state": member.verification_state}
            for member in member_rows
        ],
        relationships=[
            {"edge_id": item.edge_id, "from_node_id": item.from_node_id,
             "to_node_id": item.to_node_id, "edge_type": item.edge_type,
             "confidence": item.confidence,
             "confidence_band": confidence_band(item.confidence),
             "evidence_state": public_evidence_state(
                 freshness=item.freshness,
                 verification_state=item.verification_state,
                 contradiction_state=item.contradiction_state,
             ),
             "freshness": item.freshness,
             "validation_state": item.verification_state,
             "rule_id": item.relationship_rule_id,
             "rule_version": item.relationship_rule_version,
             "collector_id": item.collector_id,
             "source_surface": item.source_surface,
             "evidence_node_id": item.evidence_node_id}
            for item in current_edges
        ],
        contradictions=contradictions, recent_changes=changes,
        recommended_actions=recommendations,
        verification=verification_projection,
    )


@router.get("/ecosystems/{ecosystem_id}/timeline", response_model=TimelineResponse)
def get_timeline(
    ecosystem_id: str,
    limit: int = Query(default=200, ge=1, le=1000),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> TimelineResponse:
    _require_erg()
    _ecosystem(db, ctx.tenant.id, ecosystem_id)
    items = [item.model_dump() for item in EvidenceTimeline().list(
        db, tenant_id=ctx.tenant.id, limit=limit
    ) if ecosystem_id in item.ecosystem_ids]
    return TimelineResponse(items=items, total=len(items))


@router.get("/ecosystems/{ecosystem_id}/graph", response_model=GraphResponse)
def get_graph(
    ecosystem_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> GraphResponse:
    detail = get_ecosystem(ecosystem_id=ecosystem_id, ctx=ctx, db=db)
    return GraphResponse(
        nodes=detail.members, edges=detail.relationships,
        methodology="Current append-only edge projection; predecessor edges remain available in history.",
        limitations=detail.limitations,
    )


def _mutation_response(result) -> MutationResponse:
    return MutationResponse(
        event_id=result.event_id, action=result.action,
        ecosystem_ids=list(result.ecosystem_ids),
        before_memberships=list(result.before_memberships),
        after_memberships=list(result.after_memberships),
    )


@router.post("/resolve", response_model=ResolveResponse)
def resolve_observations(
    request: ResolveRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
) -> ResolveResponse:
    _require_erg()
    try:
        result = EvidenceResolutionPipeline().run(
            db,
            tenant_id=ctx.tenant.id,
            observation_ids=tuple(request.observation_ids),
            evaluated_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
            verification_environment=request.verification_environment,
        )
        db.commit()
        return ResolveResponse(
            inference_run_id=result.inference_run_id,
            evidence_node_id=result.evidence_node_id,
            graph_edge_ids=list(result.graph_edge_ids),
            evaluation_ids=list(result.evaluation_ids),
            outcomes=list(result.outcomes),
            verification_episode_ids=list(result.verification_episode_ids),
            verification_limitations=list(result.verification_limitations),
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Evidence resolution conflicted with current tenant evidence",
        ) from exc


@router.post(
    "/ecosystems/{ecosystem_id}/observations",
    response_model=MutationResponse,
)
def attach_observation(
    ecosystem_id: str,
    request: AttachRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
) -> MutationResponse:
    _require_erg()
    try:
        result = ResolutionHistory().attach_observation(
            db,
            tenant_id=ctx.tenant.id,
            ecosystem_id=ecosystem_id,
            graph_node_id=request.graph_node_id,
            evidence_node_id=request.evidence_node_id,
            confidence=request.confidence,
            evidence_quality=request.evidence_quality,
            operator_id=ctx.user.id if ctx.user else "unknown",
            operator_role=ctx.role,
            reason=request.reason,
            occurred_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _mutation_response(result)
    except ResolutionAuthorizationError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ResolutionConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/dispositions", response_model=MutationResponse)
def record_disposition(
    request: DispositionRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
) -> MutationResponse:
    _require_erg()
    try:
        result = ResolutionHistory().record_disposition(
            db,
            tenant_id=ctx.tenant.id,
            action=request.action,
            subject_reference=request.subject_reference,
            evidence_node_id=request.evidence_node_id,
            confidence=request.confidence,
            operator_id=ctx.user.id if ctx.user else "unknown",
            operator_role=ctx.role,
            reason=request.reason,
            occurred_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _mutation_response(result)
    except ResolutionAuthorizationError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ResolutionConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/ecosystems/merge", response_model=MutationResponse)
def merge_ecosystems(
    request: MergeRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
) -> MutationResponse:
    _require_erg()
    try:
        result = ResolutionHistory().merge(
            db, tenant_id=ctx.tenant.id,
            source_ecosystem_ids=tuple(request.source_ecosystem_ids),
            canonical_name=request.canonical_name, ecosystem_class=request.ecosystem_class,
            evidence_node_id=request.evidence_node_id,
            operator_id=ctx.user.id if ctx.user else "unknown", operator_role=ctx.role,
            reason=request.reason, occurred_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _mutation_response(result)
    except ResolutionConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/ecosystems/{ecosystem_id}/split", response_model=MutationResponse)
def split_ecosystem(
    ecosystem_id: str, request: SplitRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
) -> MutationResponse:
    _require_erg()
    try:
        result = ResolutionHistory().split(
            db, tenant_id=ctx.tenant.id, source_ecosystem_id=ecosystem_id,
            groups=tuple(tuple(group) for group in request.groups),
            canonical_names=tuple(request.canonical_names),
            ecosystem_classes=tuple(request.ecosystem_classes),
            evidence_node_id=request.evidence_node_id,
            operator_id=ctx.user.id if ctx.user else "unknown", operator_role=ctx.role,
            reason=request.reason, occurred_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _mutation_response(result)
    except ResolutionConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/resolution-events/{event_id}/reverse", response_model=MutationResponse)
def reverse_resolution(
    event_id: str, request: ReverseRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
) -> MutationResponse:
    _require_erg()
    try:
        result = ResolutionHistory().reverse(
            db, tenant_id=ctx.tenant.id, resolution_event_id=event_id,
            evidence_node_id=request.evidence_node_id,
            operator_id=ctx.user.id if ctx.user else "unknown", operator_role=ctx.role,
            reason=request.reason, occurred_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _mutation_response(result)
    except ResolutionConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


__all__ = ["router"]
