from __future__ import annotations

from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.observability import banking_runtime_metrics
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.user import User
from app.db.session import get_db
from app.services.banking_subject_context_service import BankingSubjectContextError
from app.services.banking_transaction_projection_service import (
    BankingCisoSummary,
    BankingTransactionProjection,
    build_banking_ciso_summary,
    build_banking_transaction_projection,
)
from app.services.banking_transaction_integrity_service import (
    BankingActionPayload,
    BankingAuthorizationResult,
    BankingExecutionPayload,
    BankingExecutionResult,
    BankingModelAuthorizationResult,
    BankingModelRequestPayload,
    BankingModelResponsePayload,
    BankingModelResponseResult,
    BankingPreExecutionPayload,
    BankingPreExecutionResult,
    BankingStructuredResponsePayload,
    BankingStructuredResponseResult,
    assure_banking_structured_response,
    authorize_banking_action,
    authorize_banking_model_request,
    report_banking_execution,
    validate_banking_model_response,
    validate_banking_pre_execution,
)


router = APIRouter(
    prefix="/runtime-control",
    tags=["runtime-control"],
)

_ACTION_AUTHORIZE_PATH = "/runtime-control/banking-actions/authorize"
_PRE_EXECUTION_PATH = "/runtime-control/banking-actions/pre-execution"
_EXECUTION_PATH = "/runtime-control/banking-actions/execution"
_MODEL_AUTHORIZE_PATH = "/runtime-control/banking-models/authorize"
_MODEL_RESPONSE_PATH = "/runtime-control/banking-models/response"
_STRUCTURED_RESPONSE_PATH = "/runtime-control/banking-responses/assure"


def _observe_latency(
    *,
    tenant_id: str,
    path: str,
    started: float,
    status_code: int,
    transport: str | None = None,
) -> None:
    latency_ms = max(0.0, (perf_counter() - started) * 1000.0)
    banking_runtime_metrics.observe_latency(
        tenant_id,
        path,
        latency_ms,
        status_code=status_code,
    )
    if transport is not None:
        banking_runtime_metrics.observe_transport_latency(
            tenant_id,
            transport,
            latency_ms,
            status_code=status_code,
        )


def _record_decision(tenant_id: str, decision: str) -> None:
    banking_runtime_metrics.increment(tenant_id, "decisions")
    if decision == "block":
        banking_runtime_metrics.increment(tenant_id, "blocked")
    if decision in {"require_approval", "require_second_approval"}:
        banking_runtime_metrics.increment(tenant_id, "approvals")


def _record_failure(tenant_id: str, exc: Exception) -> None:
    reason = str(exc).lower()
    if "policy" in reason:
        banking_runtime_metrics.increment(tenant_id, "policy_errors")
    if any(token in reason for token in ("subject", "customer", "account")):
        banking_runtime_metrics.increment(tenant_id, "subject_violations")
    if any(token in reason for token in ("target", "resource", "destination")):
        banking_runtime_metrics.increment(tenant_id, "target_violations")
    if any(token in reason for token in ("receipt", "evidence", "integrity")):
        banking_runtime_metrics.increment(tenant_id, "receipt_failures")
    if "selector" in reason:
        banking_runtime_metrics.increment(tenant_id, "selector_failures")


def _unprocessable(db: Session, exc: ValueError) -> HTTPException:
    db.rollback()
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail=str(exc),
    )


@router.post("/banking-actions/authorize", response_model=BankingAuthorizationResult)
def authorize_action(
    payload: BankingActionPayload,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    started = perf_counter()
    transport = (
        payload.transport_binding.transport
        if payload.transport_binding is not None
        else "function"
    )
    banking_runtime_metrics.increment(ctx.tenant.id, "actions")
    try:
        result = authorize_banking_action(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            payload=payload,
            settings_obj=settings,
        )
        _record_decision(ctx.tenant.id, result.decision)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_ACTION_AUTHORIZE_PATH,
            started=started,
            status_code=200,
            transport=transport,
        )
        return result
    except (BankingSubjectContextError, ValueError) as exc:
        _record_failure(ctx.tenant.id, exc)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_ACTION_AUTHORIZE_PATH,
            started=started,
            status_code=422,
            transport=transport,
        )
        raise _unprocessable(db, exc) from exc


@router.post("/banking-actions/pre-execution", response_model=BankingPreExecutionResult)
def pre_execution(
    payload: BankingPreExecutionPayload,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    started = perf_counter()
    transport = (
        payload.final_action.transport_binding.transport
        if payload.final_action.transport_binding is not None
        else "function"
    )
    try:
        result = validate_banking_pre_execution(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            payload=payload,
            settings_obj=settings,
        )
        banking_runtime_metrics.increment(ctx.tenant.id, "enforcements")
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_PRE_EXECUTION_PATH,
            started=started,
            status_code=200,
            transport=transport,
        )
        return result
    except ValueError as exc:
        _record_failure(ctx.tenant.id, exc)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_PRE_EXECUTION_PATH,
            started=started,
            status_code=422,
            transport=transport,
        )
        raise _unprocessable(db, exc) from exc


@router.post("/banking-actions/execution", response_model=BankingExecutionResult)
def execution(
    payload: BankingExecutionPayload,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    started = perf_counter()
    try:
        result = report_banking_execution(
            db,
            tenant_id=ctx.tenant.id,
            payload=payload,
            settings_obj=settings,
        )
        if result.integrity != "matched" or result.drift_fields:
            banking_runtime_metrics.increment(ctx.tenant.id, "action_drift")
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_EXECUTION_PATH,
            started=started,
            status_code=200,
        )
        return result
    except ValueError as exc:
        _record_failure(ctx.tenant.id, exc)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_EXECUTION_PATH,
            started=started,
            status_code=422,
        )
        raise _unprocessable(db, exc) from exc


@router.post(
    "/banking-models/authorize",
    response_model=BankingModelAuthorizationResult,
)
def authorize_model_request(
    payload: BankingModelRequestPayload,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    started = perf_counter()
    banking_runtime_metrics.increment(ctx.tenant.id, "actions")
    try:
        result = authorize_banking_model_request(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            payload=payload,
            settings_obj=settings,
        )
        _record_decision(ctx.tenant.id, result.decision)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_MODEL_AUTHORIZE_PATH,
            started=started,
            status_code=200,
        )
        return result
    except (BankingSubjectContextError, ValueError) as exc:
        _record_failure(ctx.tenant.id, exc)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_MODEL_AUTHORIZE_PATH,
            started=started,
            status_code=422,
        )
        raise _unprocessable(db, exc) from exc


@router.post(
    "/banking-models/response",
    response_model=BankingModelResponseResult,
)
def validate_model_response(
    payload: BankingModelResponsePayload,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    started = perf_counter()
    try:
        result = validate_banking_model_response(
            db,
            tenant_id=ctx.tenant.id,
            payload=payload,
            settings_obj=settings,
        )
        if result.decision != "allow":
            banking_runtime_metrics.increment(ctx.tenant.id, "response_mismatches")
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_MODEL_RESPONSE_PATH,
            started=started,
            status_code=200,
        )
        return result
    except ValueError as exc:
        _record_failure(ctx.tenant.id, exc)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_MODEL_RESPONSE_PATH,
            started=started,
            status_code=422,
        )
        raise _unprocessable(db, exc) from exc


@router.post(
    "/banking-responses/assure",
    response_model=BankingStructuredResponseResult,
)
def assure_structured_response(
    payload: BankingStructuredResponsePayload,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    started = perf_counter()
    try:
        result = assure_banking_structured_response(
            db,
            tenant_id=ctx.tenant.id,
            payload=payload,
            settings_obj=settings,
        )
        if result.decision != "allow":
            banking_runtime_metrics.increment(ctx.tenant.id, "response_mismatches")
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_STRUCTURED_RESPONSE_PATH,
            started=started,
            status_code=200,
        )
        return result
    except ValueError as exc:
        _record_failure(ctx.tenant.id, exc)
        _observe_latency(
            tenant_id=ctx.tenant.id,
            path=_STRUCTURED_RESPONSE_PATH,
            started=started,
            status_code=422,
        )
        raise _unprocessable(db, exc) from exc


@router.get(
    "/banking-transactions/summary/ciso",
    response_model=BankingCisoSummary,
)
def get_banking_ciso_summary(
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    return build_banking_ciso_summary(db, tenant_id=ctx.tenant.id)


@router.get(
    "/banking-transactions/{ai_transaction_id}",
    response_model=BankingTransactionProjection,
)
def get_banking_transaction(
    ai_transaction_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    projection = build_banking_transaction_projection(
        db,
        tenant_id=ctx.tenant.id,
        ai_transaction_id=ai_transaction_id,
    )
    if projection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="banking transaction not found",
        )
    if not projection.coverage_complete:
        banking_runtime_metrics.increment(ctx.tenant.id, "coverage_degradation")
    return projection
