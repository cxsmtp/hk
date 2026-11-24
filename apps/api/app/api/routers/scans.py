from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.user import User
from app.db.session import get_db
from app.services.scan_service import (
    get_latest_scan,
    get_scan_by_id,
    launch_scan_worker,
    serialize_scan_result,
    trigger_scan,
)


router = APIRouter(prefix="/scans", tags=["scans"])


class ScanTriggerRequest(BaseModel):
    scan_type: str = Field(default="discovery")
    scope: str = Field(default="global")
    parameters: dict[str, Any] = Field(default_factory=dict)


class ScanTriggerResponse(BaseModel):
    scan_id: str
    status: str


class ScanResultResponse(BaseModel):
    scan_id: str | None = None
    status: str
    scan_type: str
    scope: str
    scope_value: str | None = None
    last_scan_time: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    summary: dict[str, Any]
    delta: dict[str, Any]
    links: dict[str, str]
    error: str | None = None
    duration_ms: int | None = None
    data_source: str | None = None
    crawl_meta: dict[str, Any] | None = None
    snapshot_counts: dict[str, int] | None = None


@router.post("/trigger", response_model=ScanTriggerResponse, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan_route(
    payload: ScanTriggerRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor", "operator"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        row, created_new = trigger_scan(
            db,
            tenant_id=ctx.tenant.id,
            scan_type=payload.scan_type,
            scope=payload.scope,
            parameters=payload.parameters,
            triggered_by=current_user.id,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    if created_new and str(row.status or "").strip().lower() == "running":
        launch_scan_worker(row.scan_id, db=db)
    response_status = "running" if created_new else str(row.status or "running")
    return ScanTriggerResponse(scan_id=row.scan_id, status=response_status)


@router.get("/latest", response_model=ScanResultResponse)
def latest_scan_route(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = get_latest_scan(db, tenant_id=ctx.tenant.id)
    payload = serialize_scan_result(row)
    return ScanResultResponse.model_validate(payload)


@router.get("/{scan_id}", response_model=ScanResultResponse)
def get_scan_route(
    scan_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = get_scan_by_id(db, tenant_id=ctx.tenant.id, scan_id=scan_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return ScanResultResponse.model_validate(serialize_scan_result(row))
