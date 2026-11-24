from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.enterprise_developer_ai_control import (
    build_enterprise_developer_ai_control_from_db,
)
from app.services.provider_signals import (
    ProviderSeatSnapshotEnvelope,
    ProviderSignalEnvelope,
    build_provider_signal_workspace,
    ingest_provider_seat_snapshot,
    ingest_provider_signal,
)


router = APIRouter(tags=["ai-tools-usage"])


class ProviderSignalIngestResponse(BaseModel):
    id: str
    created: bool
    provider: str
    product: str
    record_kind: str
    occurred_at: datetime


class ProviderSeatSnapshotIngestResponse(BaseModel):
    id: str
    created: bool
    provider: str
    product: str
    total_licensed_seats: int
    assigned_seats: int
    active_seats: int
    inactive_seats: int
    never_used_seats: int
    unknown_activity_seats: int
    completeness: str
    observed_at: datetime


@router.get("/ai-tools-usage")
def get_ai_tools_usage(
    window_days: int = Query(default=30, ge=1, le=366),
    limit: int = Query(default=250, ge=1, le=5000),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict:
    provider_workspace = build_provider_signal_workspace(
        db,
        tenant_id=ctx.tenant.id,
        now=datetime.now(UTC),
        window_days=window_days,
        limit=limit,
        role=ctx.role,
    )
    return {
        **provider_workspace,
        "governance": build_enterprise_developer_ai_control_from_db(
            db, tenant_id=ctx.tenant.id
        ),
    }


@router.post(
    "/ai-tools-usage/signals",
    response_model=ProviderSignalIngestResponse,
    status_code=status.HTTP_201_CREATED,
)
def post_provider_signal(
    payload: ProviderSignalEnvelope,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
) -> ProviderSignalIngestResponse:
    try:
        result = ingest_provider_signal(
            db, tenant_id=ctx.tenant.id, envelope=payload
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    db.commit()
    db.refresh(result.record)
    return ProviderSignalIngestResponse(
        id=result.record.id,
        created=result.created,
        provider=result.record.provider,
        product=result.record.product,
        record_kind=result.record.record_kind,
        occurred_at=result.record.occurred_at,
    )


@router.post(
    "/ai-tools-usage/seats",
    response_model=ProviderSeatSnapshotIngestResponse,
    status_code=status.HTTP_201_CREATED,
)
def post_provider_seat_snapshot(
    payload: ProviderSeatSnapshotEnvelope,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
) -> ProviderSeatSnapshotIngestResponse:
    try:
        result = ingest_provider_seat_snapshot(
            db, tenant_id=ctx.tenant.id, envelope=payload
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    db.commit()
    db.refresh(result.record)
    return ProviderSeatSnapshotIngestResponse(
        id=result.record.id,
        created=result.created,
        provider=result.record.provider,
        product=result.record.product,
        total_licensed_seats=result.record.total_licensed_seats,
        assigned_seats=result.record.assigned_seats,
        active_seats=result.record.active_seats,
        inactive_seats=result.record.inactive_seats,
        never_used_seats=result.record.never_used_seats,
        unknown_activity_seats=result.record.unknown_activity_seats,
        completeness=result.record.completeness,
        observed_at=result.record.observed_at,
    )
