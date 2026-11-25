from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.discovery_resolution import DiscoveryVerificationTask
from app.db.models.discovery_verification import (
    DiscoveryVerificationAssertion,
    DiscoveryVerificationEpisode,
    DiscoveryVerificationEvent,
    DiscoveryVerificationPolicy,
    DiscoveryVerificationPolicyRequirement,
    DiscoveryVerificationResult,
)
from app.db.models.evidence_resolution import DiscoveryAIEcosystem
from app.db.session import get_db
from app.services.hmair.adv.assertions import (
    VerificationAssertionConflict,
    VerificationAssertionEngine,
    stored_utc,
)
from app.services.hmair.adv.planner import (
    VerificationPlan,
    VerificationPlanner,
    VerificationPlanningConflict,
)
from app.services.hmair.adv.policy import (
    VerificationPolicyConflict,
    create_verification_policy,
)
from app.services.hmair.adv.projection import (
    EcosystemVerificationProjection,
    VerificationProjectionConflict,
    VerificationProjectionService,
)
from app.services.hmair.contracts import canonical_json_bytes


router = APIRouter(
    prefix="/discovery/evidence-resolution",
    tags=["discovery-verification"],
)


class VerificationProjectionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem_id: str
    stage: str
    limitations: list[str]
    required_outcomes: list[str]
    optional_outcomes: list[str]
    assertion_id: str | None
    assertion_current: bool
    last_validation_at: datetime | None
    next_validation_at: datetime | None
    verification_coverage: float
    verification_quality: float | None
    evidence_quality: float | None
    collector_diversity: int
    erg_evaluation_id: str | None
    confidence: float | None


class StartVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_evaluation_id: str = Field(min_length=1, max_length=36)
    environment: str = Field(min_length=1, max_length=64)
    trigger: str = Field(min_length=1, max_length=64)
    idempotency_key: str = Field(min_length=1, max_length=128)


class StartVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode_id: str
    ecosystem_id: str
    task_count: int
    unsupported_result_count: int
    required_requirement_ids: list[str]
    task_requirement_ids: list[str]
    unsupported_requirement_ids: list[str]


class EvaluateVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)


class RetryVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)


class CancelVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)


class CancelVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode_id: str
    event_id: str
    cancelled_task_count: int


class VerificationRequirementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requirement_id: str = Field(min_length=1, max_length=128)
    task_type: str = Field(min_length=1, max_length=64)
    accepted_methods: list[str] = Field(min_length=1, max_length=16)
    evidence_class: str = Field(min_length=1, max_length=64)
    independence_group: str = Field(min_length=1, max_length=128)
    required: bool
    minimum_result_count: int = Field(ge=1, le=32)
    maximum_age_seconds: int = Field(ge=60, le=31_536_000)
    applicability: dict[str, list[str]]


class VerificationPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(min_length=1, max_length=128)
    version: int = Field(ge=1)
    ecosystem_classes: list[str] = Field(min_length=1, max_length=64)
    environments: list[str] = Field(min_length=1, max_length=64)
    minimum_evidence_quality: float = Field(ge=0.0, le=1.0)
    minimum_confidence: float = Field(ge=0.0, le=1.0)
    minimum_source_diversity: int = Field(ge=1, le=64)
    assertion_ttl_seconds: int = Field(ge=60, le=31_536_000)
    rescan_interval_seconds: int = Field(ge=60, le=31_536_000)
    effective_from: datetime
    effective_until: datetime | None = None
    requirements: list[VerificationRequirementRequest] = Field(min_length=1, max_length=64)
    idempotency_key: str = Field(min_length=1, max_length=128)


class VerificationPolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_record_id: str
    policy_id: str
    version: int
    ecosystem_classes: list[str]
    environments: list[str]
    minimum_evidence_quality: float
    minimum_confidence: float
    minimum_source_diversity: int
    assertion_ttl_seconds: int
    rescan_interval_seconds: int
    effective_from: datetime
    effective_until: datetime | None
    methodology_version: str
    requirement_count: int


class EpisodeSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode_id: str
    ecosystem_id: str
    sequence: int
    environment: str
    trigger: str
    started_at: datetime
    due_at: datetime
    expires_at: datetime
    limitations: list[str]


class EpisodeDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    episode: EpisodeSummaryResponse
    tasks: list[dict]
    results: list[dict]
    assertions: list[dict]
    events: list[dict]


class AssertionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assertion_id: str
    ecosystem_id: str
    episode_id: str
    conclusion: str
    required_requirement_count: int
    required_verified_count: int
    optional_requirement_count: int
    optional_verified_count: int
    source_diversity: int
    evidence_quality: float | None
    verification_quality: float | None
    issued_at: datetime
    valid_from: datetime
    valid_until: datetime
    limitations: list[str]
    contradictions: list[str]


class VerificationHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem_id: str
    episodes: list[dict]
    tasks: list[dict]
    results: list[dict]
    assertions: list[dict]
    events: list[dict]


def _require_adv() -> None:
    if not settings.cie_core:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Autonomous Discovery Verification is not enabled",
        )


def _ensure_ecosystem(db: Session, *, tenant_id: str, ecosystem_id: str) -> None:
    exists = db.scalar(
        select(DiscoveryAIEcosystem.ecosystem_record_id).where(
            DiscoveryAIEcosystem.tenant_id == tenant_id,
            DiscoveryAIEcosystem.ecosystem_id == ecosystem_id,
        )
    )
    if exists is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI ecosystem not found",
        )


def _episode(
    db: Session, *, tenant_id: str, episode_id: str
) -> DiscoveryVerificationEpisode:
    row = db.scalar(
        select(DiscoveryVerificationEpisode).where(
            DiscoveryVerificationEpisode.tenant_id == tenant_id,
            DiscoveryVerificationEpisode.episode_id == episode_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Verification episode not found")
    return row


def _episode_summary(row: DiscoveryVerificationEpisode) -> EpisodeSummaryResponse:
    return EpisodeSummaryResponse(
        episode_id=row.episode_id,
        ecosystem_id=row.ecosystem_id,
        sequence=row.episode_sequence,
        environment=row.environment,
        trigger=row.trigger,
        started_at=stored_utc(row.started_at),
        due_at=stored_utc(row.due_at),
        expires_at=stored_utc(row.expires_at),
        limitations=list(row.limitations_json),
    )


def _policy_response(
    db: Session, row: DiscoveryVerificationPolicy
) -> VerificationPolicyResponse:
    # The safe response exposes only the count, never worker or credential material.
    count = len(row.requirements)
    return VerificationPolicyResponse(
        policy_record_id=row.policy_record_id,
        policy_id=row.policy_id,
        version=row.version,
        ecosystem_classes=list(row.ecosystem_classes_json),
        environments=list(row.environments_json),
        minimum_evidence_quality=row.minimum_evidence_quality,
        minimum_confidence=row.minimum_confidence,
        minimum_source_diversity=row.minimum_source_diversity,
        assertion_ttl_seconds=row.assertion_ttl_seconds,
        rescan_interval_seconds=row.rescan_interval_seconds,
        effective_from=stored_utc(row.effective_from),
        effective_until=(stored_utc(row.effective_until) if row.effective_until else None),
        methodology_version=row.methodology_version,
        requirement_count=count,
    )


def _projection_response(
    projection: EcosystemVerificationProjection,
) -> VerificationProjectionResponse:
    return VerificationProjectionResponse(
        ecosystem_id=projection.ecosystem_id,
        stage=projection.stage.value,
        limitations=list(projection.limitations),
        required_outcomes=[item.value for item in projection.required_outcomes],
        optional_outcomes=[item.value for item in projection.optional_outcomes],
        assertion_id=projection.assertion_id,
        assertion_current=projection.assertion_current,
        last_validation_at=projection.last_validation_at,
        next_validation_at=projection.next_validation_at,
        verification_coverage=projection.verification_coverage,
        verification_quality=projection.verification_quality,
        evidence_quality=projection.evidence_quality,
        collector_diversity=projection.collector_diversity,
        erg_evaluation_id=projection.erg_evaluation_id,
        confidence=projection.confidence,
    )


def _plan_response(plan: VerificationPlan) -> StartVerificationResponse:
    return StartVerificationResponse(
        episode_id=plan.episode.episode_id,
        ecosystem_id=plan.episode.ecosystem_id,
        task_count=len(plan.tasks),
        unsupported_result_count=len(plan.unsupported_results),
        required_requirement_ids=list(plan.required_requirement_ids),
        task_requirement_ids=list(plan.task_requirement_ids),
        unsupported_requirement_ids=list(plan.unsupported_requirement_ids),
    )


def _existing_plan(
    db: Session, *, tenant_id: str, idempotency_key: str
) -> VerificationPlan | None:
    episode = db.scalar(
        select(DiscoveryVerificationEpisode).where(
            DiscoveryVerificationEpisode.tenant_id == tenant_id,
            DiscoveryVerificationEpisode.idempotency_key == idempotency_key,
        )
    )
    if episode is None:
        return None
    requirements = tuple(
        db.scalars(
            select(DiscoveryVerificationPolicyRequirement).where(
                DiscoveryVerificationPolicyRequirement.tenant_id == tenant_id,
                DiscoveryVerificationPolicyRequirement.policy_record_id
                == episode.policy_record_id,
            )
        ).all()
    )
    return VerificationPlanner._projection(
        db,
        episode,
        tuple(sorted(item.requirement_id for item in requirements if item.required)),
    )


def _assertion_response(row: DiscoveryVerificationAssertion) -> AssertionResponse:
    return AssertionResponse(
        assertion_id=row.assertion_id,
        ecosystem_id=row.ecosystem_id,
        episode_id=row.episode_id,
        conclusion=row.conclusion,
        required_requirement_count=row.required_requirement_count,
        required_verified_count=row.required_verified_count,
        optional_requirement_count=row.optional_requirement_count,
        optional_verified_count=row.optional_verified_count,
        source_diversity=row.source_diversity,
        evidence_quality=row.evidence_quality,
        verification_quality=row.verification_quality,
        issued_at=stored_utc(row.issued_at),
        valid_from=stored_utc(row.valid_from),
        valid_until=stored_utc(row.valid_until),
        limitations=list(row.limitations_json),
        contradictions=list(row.contradictions_json),
    )


@router.get(
    "/ecosystems/{ecosystem_id}/verification", response_model=VerificationProjectionResponse
)
def get_verification_projection(
    ecosystem_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> VerificationProjectionResponse:
    _require_adv()
    try:
        projection = VerificationProjectionService().get(
            db,
            tenant_id=ctx.tenant.id,
            ecosystem_id=ecosystem_id,
            evaluated_at=datetime.now(timezone.utc),
        )
        return _projection_response(projection)
    except VerificationProjectionConflict as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/ecosystems/{ecosystem_id}/verification/history", response_model=VerificationHistoryResponse
)
def get_verification_history(
    ecosystem_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> VerificationHistoryResponse:
    _require_adv()
    tenant_id = ctx.tenant.id
    _ensure_ecosystem(db, tenant_id=tenant_id, ecosystem_id=ecosystem_id)
    episodes = tuple(
        db.scalars(
            select(DiscoveryVerificationEpisode)
            .where(
                DiscoveryVerificationEpisode.tenant_id == tenant_id,
                DiscoveryVerificationEpisode.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryVerificationEpisode.episode_sequence.desc())
        ).all()
    )
    episode_ids = tuple(item.episode_id for item in episodes)
    policy_record_ids = tuple({item.policy_record_id for item in episodes})
    requirement_rows = tuple(
        db.scalars(
            select(DiscoveryVerificationPolicyRequirement).where(
                DiscoveryVerificationPolicyRequirement.tenant_id == tenant_id,
                DiscoveryVerificationPolicyRequirement.policy_record_id.in_(
                    policy_record_ids
                ),
            )
        ).all()
    ) if policy_record_ids else ()
    requirements = {
        item.requirement_record_id: item for item in requirement_rows
    }
    tasks = tuple(
        db.scalars(
            select(DiscoveryVerificationTask).where(
                DiscoveryVerificationTask.tenant_id == tenant_id,
                DiscoveryVerificationTask.verification_episode_id.in_(episode_ids),
            )
        ).all()
    ) if episode_ids else ()
    results = tuple(
        db.scalars(
            select(DiscoveryVerificationResult)
            .where(
                DiscoveryVerificationResult.tenant_id == tenant_id,
                DiscoveryVerificationResult.episode_id.in_(episode_ids),
            )
            .order_by(DiscoveryVerificationResult.validated_at.desc())
        ).all()
    ) if episode_ids else ()
    assertions = tuple(
        db.scalars(
            select(DiscoveryVerificationAssertion)
            .where(
                DiscoveryVerificationAssertion.tenant_id == tenant_id,
                DiscoveryVerificationAssertion.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryVerificationAssertion.assertion_sequence.desc())
        ).all()
    )
    events = tuple(
        db.scalars(
            select(DiscoveryVerificationEvent)
            .where(
                DiscoveryVerificationEvent.tenant_id == tenant_id,
                DiscoveryVerificationEvent.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryVerificationEvent.occurred_at.desc())
        ).all()
    )
    return VerificationHistoryResponse(
        ecosystem_id=ecosystem_id,
        episodes=[
            {
                "episode_id": item.episode_id,
                "sequence": item.episode_sequence,
                "environment": item.environment,
                "trigger": item.trigger,
                "started_at": item.started_at,
                "due_at": item.due_at,
                "expires_at": item.expires_at,
                "limitations": list(item.limitations_json),
            }
            for item in episodes
        ],
        tasks=[
            {
                "task_id": item.task_id,
                "episode_id": item.verification_episode_id,
                "requirement_record_id": item.verification_requirement_id,
                "requirement_id": (
                    requirements[item.verification_requirement_id].requirement_id
                    if item.verification_requirement_id in requirements else "unknown"
                ),
                "required": (
                    requirements[item.verification_requirement_id].required
                    if item.verification_requirement_id in requirements else False
                ),
                "evidence_class": (
                    requirements[item.verification_requirement_id].evidence_class
                    if item.verification_requirement_id in requirements else "unknown"
                ),
                "task_type": item.task_type,
                "method": item.method,
                "status": item.status,
                "attempt_count": item.attempt_count,
                "expires_at": item.expires_at,
            }
            for item in tasks
        ],
        results=[
            {
                "result_id": item.result_id,
                "episode_id": item.episode_id,
                "requirement_record_id": item.requirement_record_id,
                "requirement_id": requirements[item.requirement_record_id].requirement_id,
                "required": requirements[item.requirement_record_id].required,
                "evidence_class": requirements[item.requirement_record_id].evidence_class,
                "outcome": item.outcome,
                "integrity_state": item.integrity_state,
                "freshness": item.freshness,
                "source_identity": item.source_identity,
                "collector_id": item.collector_id,
                "validated_at": item.validated_at,
                "expires_at": item.expires_at,
                "limitations": list(item.limitations_json),
            }
            for item in results
        ],
        assertions=[
            _assertion_response(item).model_dump()
            for item in assertions
        ],
        events=[
            {
                "event_id": item.event_id,
                "episode_id": item.episode_id,
                "assertion_id": item.assertion_id,
                "event_type": item.event_type,
                "occurred_at": item.occurred_at,
                "actor_type": item.actor_type,
                "reason": item.reason,
                "evidence_node_ids": list(item.evidence_node_ids_json),
            }
            for item in events
        ],
    )


@router.get(
    "/ecosystems/{ecosystem_id}/verification/episodes",
    response_model=list[EpisodeSummaryResponse],
)
def list_verification_episodes(
    ecosystem_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> list[EpisodeSummaryResponse]:
    _require_adv()
    _ensure_ecosystem(db, tenant_id=ctx.tenant.id, ecosystem_id=ecosystem_id)
    rows = db.scalars(
        select(DiscoveryVerificationEpisode)
        .where(
            DiscoveryVerificationEpisode.tenant_id == ctx.tenant.id,
            DiscoveryVerificationEpisode.ecosystem_id == ecosystem_id,
        )
        .order_by(DiscoveryVerificationEpisode.episode_sequence.desc())
    ).all()
    return [_episode_summary(item) for item in rows]


@router.get(
    "/verification/episodes/{episode_id}",
    response_model=EpisodeDetailResponse,
)
def get_verification_episode(
    episode_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> EpisodeDetailResponse:
    _require_adv()
    row = _episode(db, tenant_id=ctx.tenant.id, episode_id=episode_id)
    history = get_verification_history(
        row.ecosystem_id, ctx=ctx, db=db
    )
    return EpisodeDetailResponse(
        episode=_episode_summary(row),
        tasks=[item for item in history.tasks if item["episode_id"] == episode_id],
        results=[item for item in history.results if item["episode_id"] == episode_id],
        assertions=[
            item for item in history.assertions if item["episode_id"] == episode_id
        ],
        events=[item for item in history.events if item["episode_id"] == episode_id],
    )


@router.get(
    "/verification/policies", response_model=list[VerificationPolicyResponse]
)
def list_verification_policies(
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> list[VerificationPolicyResponse]:
    _require_adv()
    rows = db.scalars(
        select(DiscoveryVerificationPolicy)
        .where(DiscoveryVerificationPolicy.tenant_id == ctx.tenant.id)
        .order_by(
            DiscoveryVerificationPolicy.policy_id,
            DiscoveryVerificationPolicy.version.desc(),
        )
    ).all()
    return [_policy_response(db, item) for item in rows]


@router.post(
    "/verification/policies", response_model=VerificationPolicyResponse
)
def create_policy(
    request: VerificationPolicyRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> VerificationPolicyResponse:
    _require_adv()
    try:
        row = create_verification_policy(
            db,
            tenant_id=ctx.tenant.id,
            policy_id=request.policy_id,
            version=request.version,
            ecosystem_classes=tuple(request.ecosystem_classes),
            environments=tuple(request.environments),
            minimum_evidence_quality=request.minimum_evidence_quality,
            minimum_confidence=request.minimum_confidence,
            minimum_source_diversity=request.minimum_source_diversity,
            assertion_ttl_seconds=request.assertion_ttl_seconds,
            rescan_interval_seconds=request.rescan_interval_seconds,
            effective_from=request.effective_from,
            effective_until=request.effective_until,
            requirements=tuple(item.model_dump() for item in request.requirements),
            actor_id=ctx.user.id if ctx.user else "unknown",
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _policy_response(db, row)
    except VerificationPolicyConflict as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/ecosystems/{ecosystem_id}/verification/start", response_model=StartVerificationResponse
)
def start_verification(
    ecosystem_id: str,
    request: StartVerificationRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> StartVerificationResponse:
    _require_adv()
    _ensure_ecosystem(db, tenant_id=ctx.tenant.id, ecosystem_id=ecosystem_id)
    try:
        existing = _existing_plan(
            db, tenant_id=ctx.tenant.id, idempotency_key=request.idempotency_key
        )
        if existing is not None:
            if existing.episode.ecosystem_id != ecosystem_id:
                raise VerificationPlanningConflict(
                    "verification episode idempotency conflict"
                )
            return _plan_response(existing)
        plan = VerificationPlanner().start(
            db,
            tenant_id=ctx.tenant.id,
            ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=request.hypothesis_evaluation_id,
            environment=request.environment,
            trigger=request.trigger,
            triggered_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _plan_response(plan)
    except (VerificationPlanningConflict, VerificationPolicyConflict) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/verification/episodes/{episode_id}/evaluate", response_model=AssertionResponse
)
def evaluate_verification(
    episode_id: str,
    request: EvaluateVerificationRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> AssertionResponse:
    _require_adv()
    try:
        existing = db.scalar(
            select(DiscoveryVerificationAssertion).where(
                DiscoveryVerificationAssertion.tenant_id == ctx.tenant.id,
                DiscoveryVerificationAssertion.idempotency_key
                == request.idempotency_key,
            )
        )
        if existing is not None:
            if existing.episode_id != episode_id:
                raise VerificationAssertionConflict(
                    "verification assertion idempotency conflict"
                )
            return _assertion_response(existing)
        row = VerificationAssertionEngine().evaluate(
            db,
            tenant_id=ctx.tenant.id,
            episode_id=episode_id,
            evaluated_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _assertion_response(row)
    except VerificationAssertionConflict as exc:
        db.rollback()
        detail = str(exc)
        code = 404 if "unavailable" in detail else 409
        raise HTTPException(status_code=code, detail=detail) from exc


@router.post(
    "/verification/episodes/{episode_id}/retry",
    response_model=StartVerificationResponse,
)
def retry_verification(
    episode_id: str,
    request: RetryVerificationRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> StartVerificationResponse:
    _require_adv()
    source = _episode(db, tenant_id=ctx.tenant.id, episode_id=episode_id)
    try:
        existing = _existing_plan(
            db, tenant_id=ctx.tenant.id, idempotency_key=request.idempotency_key
        )
        if existing is not None:
            if existing.episode.predecessor_episode_id != episode_id:
                raise VerificationPlanningConflict(
                    "verification retry idempotency conflict"
                )
            return _plan_response(existing)
        plan = VerificationPlanner().start(
            db,
            tenant_id=ctx.tenant.id,
            ecosystem_id=source.ecosystem_id,
            hypothesis_evaluation_id=source.hypothesis_evaluation_id,
            environment=source.environment,
            trigger="manual_retry",
            trigger_event_id=None,
            triggered_at=datetime.now(timezone.utc),
            idempotency_key=request.idempotency_key,
        )
        db.commit()
        return _plan_response(plan)
    except (VerificationPlanningConflict, VerificationPolicyConflict) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "/verification/episodes/{episode_id}/cancel",
    response_model=CancelVerificationResponse,
)
def cancel_verification(
    episode_id: str,
    request: CancelVerificationRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> CancelVerificationResponse:
    _require_adv()
    episode = _episode(db, tenant_id=ctx.tenant.id, episode_id=episode_id)
    existing = db.scalar(
        select(DiscoveryVerificationEvent).where(
            DiscoveryVerificationEvent.tenant_id == ctx.tenant.id,
            DiscoveryVerificationEvent.idempotency_key == request.idempotency_key,
        )
    )
    if existing is not None:
        if existing.episode_id != episode_id or existing.event_type != "verification_updated":
            raise HTTPException(status_code=409, detail="verification cancellation idempotency conflict")
        return CancelVerificationResponse(
            episode_id=episode_id,
            event_id=existing.event_id,
            cancelled_task_count=int(existing.after_json.get("cancelled_task_count", 0)),
        )
    now = datetime.now(timezone.utc)
    rows = tuple(
        db.scalars(
            select(DiscoveryVerificationTask).where(
                DiscoveryVerificationTask.tenant_id == ctx.tenant.id,
                DiscoveryVerificationTask.verification_episode_id == episode_id,
                DiscoveryVerificationTask.status.in_(("pending", "claimed")),
            )
        ).all()
    )
    before = {item.task_id: item.status for item in rows}
    for item in rows:
        item.status = "cancelled"
        item.completed_at = now
        item.limitations_json = sorted(
            set(item.limitations_json or ()) | {"cancelled_by_authorized_operator"}
        )
    event_material: dict[str, object] = {
        "tenant_id": ctx.tenant.id,
        "episode_id": episode_id,
        "cancelled_task_ids": sorted(before),
        "reason": request.reason,
        "actor_id": ctx.user.id if ctx.user else "unknown",
    }
    event = DiscoveryVerificationEvent(
        event_id=str(uuid4()), tenant_id=ctx.tenant.id,
        ecosystem_id=episode.ecosystem_id,
        ecosystem_record_id=episode.ecosystem_record_id,
        episode_id=episode_id, assertion_id=None,
        event_type="verification_updated", occurred_at=now,
        actor_id=ctx.user.id if ctx.user else "unknown",
        actor_type="admin" if ctx.role == "admin" else "operator",
        evidence_node_ids_json=[], before_json={"task_statuses": before},
        after_json={
            "cancelled_task_count": len(rows),
            "cancelled_task_ids": sorted(before),
        },
        reason=request.reason, idempotency_key=request.idempotency_key,
        input_digest=hashlib.sha256(
            b"hawk:discovery:verification-cancel:v1"
            + canonical_json_bytes(event_material)
        ).hexdigest(),
    )
    db.add(event)
    db.commit()
    return CancelVerificationResponse(
        episode_id=episode_id,
        event_id=event.event_id,
        cancelled_task_count=len(rows),
    )


__all__ = ["router"]
