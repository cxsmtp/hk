from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.deps_control_plane import require_control_plane_healthy
from app.core.observability import get_correlation_id
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.user import User
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.brain.council import ModelCouncil
from app.services.brain.executor import execute_plan
from app.services.brain.finding_analyzer import FindingAnalysisResult, analyze_finding
from app.services.brain.planner import create_plan
from app.services.brain.providers.provider_factory import available_providers, get_provider_health_map
from app.services.brain.router import ModelRouter
from app.services.brain.schemas import BrainAnswer, BrainExecutionResult, BrainPlan
from app.services.brain.summarizer import summarize
from app.services.evidence_service import create_evidence_node


router = APIRouter(
    prefix="/brain",
    tags=["brain"],
    dependencies=[Depends(require_control_plane_healthy(module="brain"))],
)


class BrainHealthResponse(BaseModel):
    status: str
    router_mode: str
    providers: list[dict[str, Any]]


class BrainProvidersResponse(BaseModel):
    available_providers: list[str]
    active_config: dict[str, Any]


class BrainPlanRequest(BaseModel):
    question: str
    context: dict[str, Any] = Field(default_factory=dict)


class BrainExecuteRequest(BaseModel):
    plan_id: str


class BrainAskRequest(BaseModel):
    question: str
    context: dict[str, Any] = Field(default_factory=dict)


class BrainFindingAnalyzeRequest(BaseModel):
    context: dict[str, Any] = Field(default_factory=dict)


def _log_brain_request(
    db: Session,
    *,
    endpoint: str,
    tenant_id: str,
    user_id: str,
    correlation_id: str,
) -> None:
    action = f"brain.{endpoint}"
    resource_id = f"/brain/{endpoint}"
    summary = f"Brain endpoint {resource_id} called with correlation_id={correlation_id}"
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=user_id,
        actor_type="human",
        action=action,
        resource_type="brain_endpoint",
        resource_id=resource_id,
        payload={"endpoint": resource_id, "correlation_id": correlation_id},
        correlation_id=correlation_id,
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="brain_request",
        signal_type=action,
        label=summary,
        payload={
            "source": "brain",
            "summary": summary,
            "endpoint": resource_id,
            "correlation_id": correlation_id,
            "audit_log_id": audit.id,
        },
        correlation_id=correlation_id,
    )
    db.commit()


@router.get("/health", response_model=BrainHealthResponse)
def brain_health(
    request: Request,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    correlation_id = getattr(request.state, "correlation_id", None) or get_correlation_id() or "unknown"
    try:
        _log_brain_request(
            db,
            endpoint="health",
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to write brain audit/evidence: {exc}") from exc

    model_router = ModelRouter()
    providers = get_provider_health_map()
    overall_status = "ok" if any(bool(row.get("ok")) for row in providers) else "degraded"
    return BrainHealthResponse(
        status=overall_status,
        router_mode=model_router.mode,
        providers=providers,
    )


@router.get("/providers", response_model=BrainProvidersResponse)
def brain_providers(
    request: Request,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    correlation_id = getattr(request.state, "correlation_id", None) or get_correlation_id() or "unknown"
    try:
        _log_brain_request(
            db,
            endpoint="providers",
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to write brain audit/evidence: {exc}") from exc

    model_router = ModelRouter()
    return BrainProvidersResponse(
        available_providers=available_providers(),
        active_config=model_router.active_config(),
    )


@router.post("/plan", response_model=BrainPlan)
def brain_plan(
    payload: BrainPlanRequest,
    request: Request,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    correlation_id = getattr(request.state, "correlation_id", None) or get_correlation_id() or "unknown"
    try:
        _log_brain_request(
            db,
            endpoint="plan",
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to write brain audit/evidence: {exc}") from exc

    try:
        model_router = ModelRouter()
        model_council = ModelCouncil(
            db=db,
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
        plan = create_plan(
            db,
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            user_role=ctx.role,
            question=payload.question,
            context=payload.context,
            model_router=model_router,
            model_council=model_council,
        )
        db.commit()
        return plan
    except ValueError as exc:
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to persist brain plan: {exc}") from exc


@router.post("/execute", response_model=BrainExecutionResult)
def brain_execute(
    payload: BrainExecuteRequest,
    request: Request,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    correlation_id = getattr(request.state, "correlation_id", None) or get_correlation_id() or "unknown"
    try:
        _log_brain_request(
            db,
            endpoint="execute",
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to write brain audit/evidence: {exc}") from exc

    try:
        result = execute_plan(
            db,
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            user_role=ctx.role,
            plan_id=payload.plan_id,
            correlation_id=correlation_id,
        )
        db.commit()
        return result
    except PermissionError as exc:
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Brain execute persistence failed: {exc}") from exc


@router.post("/ask", response_model=BrainAnswer)
def brain_ask(
    payload: BrainAskRequest,
    request: Request,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    correlation_id = getattr(request.state, "correlation_id", None) or get_correlation_id() or "unknown"
    try:
        _log_brain_request(
            db,
            endpoint="ask",
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to write brain audit/evidence: {exc}") from exc

    try:
        model_router = ModelRouter()
        model_council = ModelCouncil(
            db=db,
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
        plan = create_plan(
            db,
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            user_role=ctx.role,
            question=payload.question,
            context=payload.context,
            model_router=model_router,
            model_council=model_council,
        )
        execution = execute_plan(
            db,
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            user_role=ctx.role,
            plan_id=plan.plan_id,
            correlation_id=correlation_id,
        )
        answer = summarize(
            question=payload.question,
            execution_result=execution,
            model_router=model_router,
            model_council=model_council,
        )
        db.commit()
        return answer
    except PermissionError as exc:
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        try:
            db.commit()
        except SQLAlchemyError:
            db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Brain ask persistence failed: {exc}") from exc


@router.post("/findings/{finding_id}/analyze", response_model=FindingAnalysisResult)
def brain_analyze_finding(
    finding_id: str,
    payload: BrainFindingAnalyzeRequest,
    request: Request,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    del payload
    correlation_id = getattr(request.state, "correlation_id", None) or get_correlation_id() or "unknown"
    try:
        _log_brain_request(
            db,
            endpoint=f"findings.{finding_id}.analyze",
            tenant_id=ctx.tenant.id,
            user_id=current_user.id,
            correlation_id=correlation_id,
        )
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to write brain audit/evidence: {exc}") from exc

    try:
        result = analyze_finding(
            db,
            tenant_id=ctx.tenant.id,
            finding_id=finding_id,
            actor_user_id=current_user.id,
            correlation_id=correlation_id,
        )
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Brain finding analysis failed: {exc}") from exc
