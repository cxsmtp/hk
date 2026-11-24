"""RBAC-protected Maturity Curve and policy-intelligence product API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import parse_maturity_curve_rollout, settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.maturity_curve import (
    MaturityAssessment,
    MaturityExecutiveSnapshot,
    MaturityObservedUsagePattern,
    MaturityPolicyEffectivenessSnapshot,
    MaturityPolicyException,
    MaturityPolicyRecommendation,
    MaturityPolicyRollout,
    MaturityPolicySimulation,
    MaturityScope,
    MaturityUsageBaseline,
    TenantMaturityEntitlement,
)
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.maturity_curve.effectiveness import materialize_policy_effectiveness
from app.services.maturity_curve.entitlements import MaturityEntitlementError
from app.services.maturity_curve.exceptions import create_policy_exception
from app.services.maturity_curve.executive import materialize_executive_snapshot
from app.services.maturity_curve.recommendations import generate_policy_recommendations
from app.services.maturity_curve.recommendations import review_policy_recommendation
from app.services.maturity_curve.rollouts import create_policy_rollout, transition_policy_rollout
from app.services.maturity_curve.service import create_maturity_scope, materialize_maturity_scope
from app.services.maturity_curve.simulation import simulate_policy_recommendation


def _require_maturity_curve_enabled(ctx: TenantContext = Depends(require_role(min_role="viewer"))) -> None:
    rollout = parse_maturity_curve_rollout(settings.maturity_curve_policy_intelligence_rollout)
    if not settings.maturity_curve_policy_intelligence or rollout.get(str(ctx.tenant.id)) is not True:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


router = APIRouter(
    prefix="/maturity-curve",
    tags=["maturity-curve"],
    dependencies=[Depends(_require_maturity_curve_enabled)],
)


class ScopeCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_key: str = Field(min_length=1, max_length=255)
    scope_type: str = Field(min_length=1, max_length=32)
    display_name: str = Field(min_length=1, max_length=255)
    filters: dict[str, Any] = Field(default_factory=dict)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_days: int = Field(default=30, ge=1, le=365)


class RolloutTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_state: str = Field(min_length=3, max_length=32)
    reason: str = Field(min_length=3, max_length=2_000)
    rollout_stage: str | None = Field(default=None, min_length=3, max_length=32)


class PolicyExceptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: dict[str, Any]
    reason: str = Field(min_length=3, max_length=2_000)
    expires_at: datetime


class RecommendationReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=3, max_length=32)
    reason: str = Field(min_length=3, max_length=2_000)


def _actor_ref(ctx: TenantContext) -> str:
    return f"user:{ctx.user.id}"


def _service_error(exc: Exception) -> HTTPException:
    if isinstance(exc, MaturityEntitlementError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    detail = str(exc)
    code = status.HTTP_404_NOT_FOUND if detail.endswith("_not_found") else status.HTTP_422_UNPROCESSABLE_ENTITY
    return HTTPException(status_code=code, detail=detail)


def _scope_payload(scope: MaturityScope) -> dict[str, Any]:
    return {
        "id": scope.id,
        "scope_key": scope.scope_key,
        "scope_type": scope.scope_type,
        "display_name": scope.display_name,
        "filters": scope.filters or {},
        "active": scope.active,
        "created_at": scope.created_at,
        "updated_at": scope.updated_at,
    }


def _assessment_payload(row: MaturityAssessment | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": row.id,
        "stage": row.stage,
        "confidence": row.confidence,
        "source_diversity": row.source_diversity,
        "indicators": row.indicators or {},
        "missing_gates": row.missing_gates or [],
        "blocking_gaps": row.blocking_gaps or [],
        "evidence_refs": row.evidence_refs or [],
        "status": row.status,
        "computed_at": row.computed_at,
    }


def _baseline_payload(row: MaturityUsageBaseline | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": row.id,
        "baseline_version": row.baseline_version,
        "sample_count": row.sample_count,
        "source_diversity": row.source_diversity,
        "aggregates": row.aggregates or {},
        "status": row.status,
        "created_at": row.created_at,
    }


def _recommendation_payload(row: MaturityPolicyRecommendation) -> dict[str, Any]:
    return {
        "id": row.id,
        "title": row.title,
        "category": row.category,
        "status": row.status,
        "review_state": row.review_state,
        "review_reason": row.review_reason,
        "reviewed_by_ref": row.reviewed_by_ref,
        "reviewed_at": row.reviewed_at,
        "policy_draft": row.policy_draft or {},
        "evidence_refs": row.evidence_refs or [],
        "assumptions": row.assumptions or [],
        "unknowns": row.unknowns or [],
        "confidence": row.confidence,
        "estimated_impact": row.estimated_impact or {},
        "estimated_friction": row.estimated_friction or {},
        "candidate_policy_version_id": row.candidate_policy_version_id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _simulation_payload(row: MaturityPolicySimulation) -> dict[str, Any]:
    return {
        "id": row.id,
        "recommendation_id": row.recommendation_id,
        "policy_version_id": row.policy_version_id,
        "sample_count": row.sample_count,
        "outcome_counts": row.outcome_counts or {},
        "scope_breakdown": row.scope_breakdown or {},
        "unknown_count": row.unknown_count,
        "passed": row.passed,
        "evidence_refs": row.evidence_refs or [],
        "created_at": row.created_at,
    }


def _rollout_payload(row: MaturityPolicyRollout) -> dict[str, Any]:
    return {
        "id": row.id,
        "recommendation_id": row.recommendation_id,
        "policy_version_id": row.policy_version_id,
        "state": row.state,
        "mode": row.mode,
        "rollout_stage": row.rollout_stage,
        "requested_by_ref": row.requested_by_ref,
        "approved_by_ref": row.approved_by_ref,
        "approved_at": row.approved_at,
        "effective_at": row.effective_at,
        "rollback_reason": row.rollback_reason,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _effectiveness_payload(row: MaturityPolicyEffectivenessSnapshot) -> dict[str, Any]:
    return {
        "id": row.id,
        "rollout_id": row.rollout_id,
        "policy_version_id": row.policy_version_id,
        "status": row.status,
        "outcome_summary": row.outcome_summary or {},
        "evidence_refs": row.evidence_refs or [],
        "created_at": row.created_at,
    }


def _pattern_payload(row: MaturityObservedUsagePattern) -> dict[str, Any]:
    return {
        "id": row.id,
        "dimension": row.dimension,
        "value_ref": row.value_ref,
        "pattern_type": row.pattern_type,
        "approval_state": row.approval_state,
        "risk_state": row.risk_state,
        "control_state": row.control_state,
        "observation_count": row.observation_count,
        "confidence": row.confidence,
        "evidence_refs": row.evidence_refs or [],
        "created_at": row.created_at,
    }


@router.get("/entitlement")
def get_entitlement(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(TenantMaturityEntitlement).where(TenantMaturityEntitlement.tenant_id == ctx.tenant.id)
    )
    if row is None:
        return {"configured": False, "package_tier": None, "enabled": False, "custom_attributes_enabled": False}
    return {
        "configured": True,
        "package_tier": row.package_tier,
        "enabled": row.enabled,
        "custom_attributes_enabled": row.custom_attributes_enabled,
    }


@router.get("/overview")
def overview(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scopes = list(
        db.scalars(
            select(MaturityScope)
            .where(MaturityScope.tenant_id == ctx.tenant.id, MaturityScope.active.is_(True))
            .order_by(MaturityScope.scope_type.asc(), MaturityScope.display_name.asc())
        ).all()
    )
    latest_assessments: list[dict[str, Any]] = []
    for scope in scopes:
        latest = db.scalar(
            select(MaturityAssessment)
            .where(MaturityAssessment.tenant_id == ctx.tenant.id, MaturityAssessment.scope_id == scope.id)
            .order_by(MaturityAssessment.computed_at.desc(), MaturityAssessment.id.desc())
        )
        if latest is not None:
            latest_assessments.append({"scope_id": scope.id, **(_assessment_payload(latest) or {})})
    entitlement = db.scalar(
        select(TenantMaturityEntitlement).where(TenantMaturityEntitlement.tenant_id == ctx.tenant.id)
    )
    executive = db.scalar(
        select(MaturityExecutiveSnapshot)
        .where(MaturityExecutiveSnapshot.tenant_id == ctx.tenant.id)
        .order_by(MaturityExecutiveSnapshot.computed_at.desc(), MaturityExecutiveSnapshot.id.desc())
    )
    return {
        "entitlement": (
            {
                "package_tier": entitlement.package_tier,
                "enabled": entitlement.enabled,
                "custom_attributes_enabled": entitlement.custom_attributes_enabled,
            }
            if entitlement is not None
            else None
        ),
        "scopes": [_scope_payload(scope) for scope in scopes],
        "assessments": latest_assessments,
        "executive": (
            {
                "stage_distribution": executive.stage_distribution or {},
                "coverage_refs": executive.coverage_refs or [],
                "gap_summary": executive.gap_summary or {},
                "recommendation_summary": executive.recommendation_summary or {},
                "report": executive.report or {},
                "computed_at": executive.computed_at,
            }
            if executive is not None
            else None
        ),
    }


@router.get("/scopes")
def list_scopes(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = list(
        db.scalars(
            select(MaturityScope)
            .where(MaturityScope.tenant_id == ctx.tenant.id)
            .order_by(MaturityScope.scope_type.asc(), MaturityScope.display_name.asc())
        ).all()
    )
    return {"items": [_scope_payload(row) for row in rows], "total": len(rows)}


@router.post("/scopes", status_code=status.HTTP_201_CREATED)
def create_scope(
    payload: ScopeCreateRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        scope = create_maturity_scope(
            db,
            tenant_id=ctx.tenant.id,
            scope_key=payload.scope_key,
            scope_type=payload.scope_type,
            display_name=payload.display_name,
            filters=payload.filters,
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_scope.create",
            resource_type="maturity_scope",
            resource_id=scope.id,
            payload={"scope_key": scope.scope_key, "scope_type": scope.scope_type},
        )
        db.commit()
        db.refresh(scope)
        return _scope_payload(scope)
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.get("/scopes/{scope_id}")
def scope_detail(
    scope_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scope = db.scalar(select(MaturityScope).where(MaturityScope.tenant_id == ctx.tenant.id, MaturityScope.id == scope_id))
    if scope is None:
        raise HTTPException(status_code=404, detail="maturity_scope_not_found")
    assessment = db.scalar(
        select(MaturityAssessment)
        .where(MaturityAssessment.tenant_id == ctx.tenant.id, MaturityAssessment.scope_id == scope.id)
        .order_by(MaturityAssessment.computed_at.desc(), MaturityAssessment.id.desc())
    )
    baseline = db.scalar(
        select(MaturityUsageBaseline)
        .where(MaturityUsageBaseline.tenant_id == ctx.tenant.id, MaturityUsageBaseline.scope_id == scope.id)
        .order_by(MaturityUsageBaseline.created_at.desc(), MaturityUsageBaseline.id.desc())
    )
    recommendations = list(
        db.scalars(
            select(MaturityPolicyRecommendation)
            .where(MaturityPolicyRecommendation.tenant_id == ctx.tenant.id, MaturityPolicyRecommendation.scope_id == scope.id)
            .order_by(MaturityPolicyRecommendation.updated_at.desc(), MaturityPolicyRecommendation.id.desc())
        ).all()
    )
    rollouts = list(
        db.scalars(
            select(MaturityPolicyRollout)
            .where(MaturityPolicyRollout.tenant_id == ctx.tenant.id, MaturityPolicyRollout.scope_id == scope.id)
            .order_by(MaturityPolicyRollout.updated_at.desc(), MaturityPolicyRollout.id.desc())
        ).all()
    )
    simulations = list(
        db.scalars(
            select(MaturityPolicySimulation)
            .where(MaturityPolicySimulation.tenant_id == ctx.tenant.id, MaturityPolicySimulation.scope_id == scope.id)
            .order_by(MaturityPolicySimulation.created_at.desc(), MaturityPolicySimulation.id.desc())
        ).all()
    )
    effectiveness = list(
        db.scalars(
            select(MaturityPolicyEffectivenessSnapshot)
            .where(MaturityPolicyEffectivenessSnapshot.tenant_id == ctx.tenant.id, MaturityPolicyEffectivenessSnapshot.scope_id == scope.id)
            .order_by(MaturityPolicyEffectivenessSnapshot.created_at.desc(), MaturityPolicyEffectivenessSnapshot.id.desc())
        ).all()
    )
    patterns = list(
        db.scalars(
            select(MaturityObservedUsagePattern)
            .where(MaturityObservedUsagePattern.tenant_id == ctx.tenant.id, MaturityObservedUsagePattern.scope_id == scope.id)
            .order_by(
                MaturityObservedUsagePattern.observation_count.desc(),
                MaturityObservedUsagePattern.dimension.asc(),
                MaturityObservedUsagePattern.id.asc(),
            )
        ).all()
    )
    return {
        "scope": _scope_payload(scope),
        "assessment": _assessment_payload(assessment),
        "baseline": _baseline_payload(baseline),
        "patterns": [_pattern_payload(item) for item in patterns],
        "recommendations": [_recommendation_payload(item) for item in recommendations],
        "simulations": [_simulation_payload(item) for item in simulations],
        "rollouts": [_rollout_payload(item) for item in rollouts],
        "effectiveness": [_effectiveness_payload(item) for item in effectiveness],
    }


@router.get("/scopes/{scope_id}/patterns")
def list_scope_patterns(
    scope_id: str,
    dimension: str | None = Query(default=None, max_length=64),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(MaturityObservedUsagePattern).where(
        MaturityObservedUsagePattern.tenant_id == ctx.tenant.id,
        MaturityObservedUsagePattern.scope_id == scope_id,
    )
    if dimension:
        query = query.where(MaturityObservedUsagePattern.dimension == dimension.strip().lower())
    rows = list(
        db.scalars(
            query.order_by(
                MaturityObservedUsagePattern.observation_count.desc(),
                MaturityObservedUsagePattern.id.desc(),
            )
        ).all()
    )
    return {"items": [_pattern_payload(row) for row in rows], "total": len(rows)}


@router.post("/scopes/{scope_id}/refresh")
def refresh_scope(
    scope_id: str,
    payload: RefreshRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        materialized = materialize_maturity_scope(
            db,
            tenant_id=ctx.tenant.id,
            scope_id=scope_id,
            window_days=payload.window_days,
        )
        recommendations = generate_policy_recommendations(
            db,
            tenant_id=ctx.tenant.id,
            scope_id=scope_id,
            assessment_id=materialized.assessment.id,
            baseline_id=materialized.baseline.id,
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_scope.refresh",
            resource_type="maturity_scope",
            resource_id=scope_id,
            payload={"window_days": payload.window_days, "recommendation_count": len(recommendations)},
        )
        db.commit()
        return {
            "scope": _scope_payload(materialized.scope),
            "assessment": _assessment_payload(materialized.assessment),
            "baseline": _baseline_payload(materialized.baseline),
            "recommendations": [_recommendation_payload(row) for row in recommendations],
        }
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.get("/recommendations")
def list_recommendations(
    scope_id: str | None = Query(default=None, max_length=36),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(MaturityPolicyRecommendation).where(MaturityPolicyRecommendation.tenant_id == ctx.tenant.id)
    if scope_id:
        query = query.where(MaturityPolicyRecommendation.scope_id == scope_id)
    rows = list(db.scalars(query.order_by(MaturityPolicyRecommendation.updated_at.desc(), MaturityPolicyRecommendation.id.desc())).all())
    return {"items": [_recommendation_payload(row) for row in rows], "total": len(rows)}


@router.get("/recommendations/{recommendation_id}")
def get_recommendation(
    recommendation_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(MaturityPolicyRecommendation).where(
            MaturityPolicyRecommendation.tenant_id == ctx.tenant.id,
            MaturityPolicyRecommendation.id == recommendation_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="maturity_recommendation_not_found")
    return _recommendation_payload(row)


@router.post("/recommendations/{recommendation_id}/review")
def review_recommendation(
    recommendation_id: str,
    payload: RecommendationReviewRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if payload.action.strip().upper() == "APPROVE" and ctx.role not in {"admin", "owner"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin approval is required for this recommendation.")
    try:
        recommendation = review_policy_recommendation(
            db,
            tenant_id=ctx.tenant.id,
            recommendation_id=recommendation_id,
            action=payload.action,
            actor_ref=_actor_ref(ctx),
            reason=payload.reason,
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_recommendation.review",
            resource_type="maturity_policy_recommendation",
            resource_id=recommendation.id,
            payload={"review_action": payload.action.strip().upper(), "review_state": recommendation.review_state},
        )
        db.commit()
        return _recommendation_payload(recommendation)
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.post("/recommendations/{recommendation_id}/simulate")
def simulate_recommendation(
    recommendation_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        simulation = simulate_policy_recommendation(db, tenant_id=ctx.tenant.id, recommendation_id=recommendation_id)
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_recommendation.simulate",
            resource_type="maturity_policy_recommendation",
            resource_id=recommendation_id,
            payload={"simulation_id": simulation.id, "passed": simulation.passed},
        )
        db.commit()
        return _simulation_payload(simulation)
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.post("/recommendations/{recommendation_id}/rollouts", status_code=status.HTTP_201_CREATED)
def start_rollout(
    recommendation_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        rollout = create_policy_rollout(
            db,
            tenant_id=ctx.tenant.id,
            recommendation_id=recommendation_id,
            actor_ref=_actor_ref(ctx),
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_rollout.create",
            resource_type="maturity_policy_rollout",
            resource_id=rollout.id,
            payload={"recommendation_id": recommendation_id},
        )
        db.commit()
        return _rollout_payload(rollout)
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.post("/rollouts/{rollout_id}/transition")
def transition_rollout(
    rollout_id: str,
    payload: RolloutTransitionRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if str(payload.target_state or "").upper() != "REVIEW" and ctx.role not in {"admin", "owner"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin approval is required for this rollout transition.")
    try:
        rollout = transition_policy_rollout(
            db,
            tenant_id=ctx.tenant.id,
            rollout_id=rollout_id,
            target_state=payload.target_state,
            actor_ref=_actor_ref(ctx),
            reason=payload.reason,
            rollout_stage=payload.rollout_stage,
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_rollout.transition",
            resource_type="maturity_policy_rollout",
            resource_id=rollout.id,
            payload={"target_state": rollout.state, "rollout_stage": rollout.rollout_stage, "reason": payload.reason},
        )
        db.commit()
        return _rollout_payload(rollout)
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.post("/rollouts/{rollout_id}/effectiveness")
def refresh_effectiveness(
    rollout_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        snapshot = materialize_policy_effectiveness(db, tenant_id=ctx.tenant.id, rollout_id=rollout_id)
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_rollout.effectiveness.refresh",
            resource_type="maturity_policy_rollout",
            resource_id=rollout_id,
            payload={"effectiveness_snapshot_id": snapshot.id, "status": snapshot.status},
        )
        db.commit()
        return _effectiveness_payload(snapshot)
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.post("/rollouts/{rollout_id}/exceptions", status_code=status.HTTP_201_CREATED)
def approve_exception(
    rollout_id: str,
    payload: PolicyExceptionRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rollout = db.scalar(
        select(MaturityPolicyRollout).where(
            MaturityPolicyRollout.tenant_id == ctx.tenant.id,
            MaturityPolicyRollout.id == rollout_id,
        )
    )
    if rollout is None or not rollout.policy_version_id:
        raise HTTPException(status_code=404, detail="maturity_rollout_not_found")
    try:
        exception = create_policy_exception(
            db,
            tenant_id=ctx.tenant.id,
            rollout_id=rollout.id,
            policy_version_id=rollout.policy_version_id,
            scope=payload.scope,
            reason=payload.reason,
            requested_by_ref=_actor_ref(ctx),
            approved_by_ref=_actor_ref(ctx),
            expires_at=payload.expires_at,
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_policy_exception.approve",
            resource_type="maturity_policy_exception",
            resource_id=exception.id,
            payload={"rollout_id": rollout.id, "expires_at": exception.expires_at.isoformat()},
        )
        db.commit()
        return {
            "id": exception.id,
            "rollout_id": exception.rollout_id,
            "policy_version_id": exception.policy_version_id,
            "scope": exception.scope,
            "status": exception.status,
            "expires_at": exception.expires_at,
            "audit_ref": exception.audit_ref,
        }
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc


@router.post("/scopes/{scope_id}/executive")
def refresh_executive(
    scope_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        snapshot = materialize_executive_snapshot(db, tenant_id=ctx.tenant.id, scope_id=scope_id)
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            actor_type="human",
            action="maturity_executive.refresh",
            resource_type="maturity_scope",
            resource_id=scope_id,
            payload={"snapshot_id": snapshot.id},
        )
        db.commit()
        return {
            "id": snapshot.id,
            "scope_id": snapshot.scope_id,
            "stage_distribution": snapshot.stage_distribution or {},
            "coverage_refs": snapshot.coverage_refs or [],
            "gap_summary": snapshot.gap_summary or {},
            "recommendation_summary": snapshot.recommendation_summary or {},
            "report": snapshot.report or {},
            "computed_at": snapshot.computed_at,
        }
    except Exception as exc:
        db.rollback()
        raise _service_error(exc) from exc
