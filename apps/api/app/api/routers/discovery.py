from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.auth import get_current_user
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.discovery import DiscoveryApplication
from app.db.models.finding import Finding
from app.db.models.user import User
from app.db.session import get_db
from app.services.discovery_service import (
    assign_discovery_application_owner,
    block_discovery_application,
    get_discovery_application,
    promote_discovery_application,
    tool_key_for_name,
)


router = APIRouter(prefix="/discovery", tags=["discovery"])


class DiscoveryApplicationResponse(BaseModel):
    id: str
    tenant_id: str
    tool_key: str
    tool_name: str
    vendor: str
    status: str
    owner_user_id: str | None = None
    owner_department: str | None = None
    owner_label: str | None = None
    provisional_risk_tier: str | None = None
    ai_system_id: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    risk_score: int
    findings_total: int
    findings_open: int
    recommended_action: str
    metadata_json: dict
    created_at: datetime
    updated_at: datetime


class DiscoveryApplicationPromoteRequest(BaseModel):
    action: Literal["approve", "keep_monitoring"] = "approve"
    provisional_risk_tier: str | None = None


class DiscoveryApplicationBlockRequest(BaseModel):
    reason: str | None = None


class DiscoveryApplicationAssignOwnerRequest(BaseModel):
    owner_user_id: str | None = None
    owner_department: str | None = None


def _severity_weight(value: str) -> int:
    normalized = str(value or "").strip().lower()
    if normalized == "critical":
        return 40
    if normalized == "high":
        return 25
    if normalized in {"med", "medium"}:
        return 12
    return 5


def _build_finding_map(findings: list[Finding]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for finding in findings:
        key = tool_key_for_name(finding.ai_tool or "unknown")
        bucket = out.setdefault(
            key,
            {
                "total": 0,
                "open": 0,
                "risk_score": 0,
                "latest_recommended_action": "",
                "latest_updated_at": datetime.min.replace(tzinfo=finding.updated_at.tzinfo if finding.updated_at else None),
            },
        )
        bucket["total"] += 1
        if finding.status in {"open", "reviewing"}:
            bucket["open"] += 1
            bucket["risk_score"] += _severity_weight(finding.severity) + 4
        else:
            bucket["risk_score"] += _severity_weight(finding.severity)
        if finding.updated_at and finding.updated_at >= bucket["latest_updated_at"]:
            bucket["latest_updated_at"] = finding.updated_at
            bucket["latest_recommended_action"] = finding.recommended_action
    return out


def _to_response(row: DiscoveryApplication, finding_map: dict[str, dict]) -> DiscoveryApplicationResponse:
    metrics = finding_map.get(row.tool_key, {})
    owner_label = row.owner_department or row.owner_user_id
    recommended = metrics.get("latest_recommended_action") or "Continue monitoring until governance decision is finalized."
    risk_score = min(100, int(metrics.get("risk_score", 0)))
    return DiscoveryApplicationResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        tool_key=row.tool_key,
        tool_name=row.tool_name,
        vendor=row.vendor,
        status=row.status,
        owner_user_id=row.owner_user_id,
        owner_department=row.owner_department,
        owner_label=owner_label,
        provisional_risk_tier=row.provisional_risk_tier,
        ai_system_id=row.ai_system_id,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        risk_score=risk_score,
        findings_total=int(metrics.get("total", 0)),
        findings_open=int(metrics.get("open", 0)),
        recommended_action=recommended,
        metadata_json=row.metadata_json or {},
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


@router.get("/applications", response_model=ListEnvelope[DiscoveryApplicationResponse])
def list_discovery_applications(
    status_filter: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    query = select(DiscoveryApplication).where(DiscoveryApplication.tenant_id == ctx.tenant.id)
    if status_filter:
        query = query.where(DiscoveryApplication.status == status_filter)
    rows = db.scalars(query.order_by(DiscoveryApplication.last_seen_at.desc())).all()
    finding_rows = db.scalars(select(Finding).where(Finding.tenant_id == ctx.tenant.id)).all()
    finding_map = _build_finding_map(finding_rows)
    dto_rows = [_to_response(row, finding_map) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[DiscoveryApplicationResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/applications/{application_id}", response_model=DiscoveryApplicationResponse)
def get_discovery_application_by_id(
    application_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = get_discovery_application(db, tenant_id=ctx.tenant.id, application_id=application_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery application not found")
    finding_rows = db.scalars(
        select(Finding).where(
            Finding.tenant_id == ctx.tenant.id,
            Finding.ai_tool == row.tool_name,
        )
    ).all()
    return _to_response(row, _build_finding_map(finding_rows))


@router.post("/applications/{application_id}/promote", response_model=DiscoveryApplicationResponse)
def promote_discovery_application_endpoint(
    application_id: str,
    payload: DiscoveryApplicationPromoteRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = get_discovery_application(db, tenant_id=ctx.tenant.id, application_id=application_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery application not found")
    try:
        promote_discovery_application(
            db,
            tenant_id=ctx.tenant.id,
            application=row,
            action=payload.action,
            provisional_risk_tier=payload.provisional_risk_tier,
            actor_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    db.refresh(row)
    findings = db.scalars(select(Finding).where(Finding.tenant_id == ctx.tenant.id, Finding.ai_tool == row.tool_name)).all()
    return _to_response(row, _build_finding_map(findings))


@router.post("/applications/{application_id}/block", response_model=DiscoveryApplicationResponse)
def block_discovery_application_endpoint(
    application_id: str,
    payload: DiscoveryApplicationBlockRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = get_discovery_application(db, tenant_id=ctx.tenant.id, application_id=application_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery application not found")
    block_discovery_application(
        db,
        tenant_id=ctx.tenant.id,
        application=row,
        reason=payload.reason,
        actor_user_id=current_user.id,
    )
    db.commit()
    db.refresh(row)
    findings = db.scalars(select(Finding).where(Finding.tenant_id == ctx.tenant.id, Finding.ai_tool == row.tool_name)).all()
    return _to_response(row, _build_finding_map(findings))


@router.post("/applications/{application_id}/assign-owner", response_model=DiscoveryApplicationResponse)
def assign_discovery_application_owner_endpoint(
    application_id: str,
    payload: DiscoveryApplicationAssignOwnerRequest,
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not payload.owner_user_id and not payload.owner_department:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide owner_user_id or owner_department",
        )

    row = get_discovery_application(db, tenant_id=ctx.tenant.id, application_id=application_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Discovery application not found")

    try:
        assign_discovery_application_owner(
            db,
            tenant_id=ctx.tenant.id,
            application=row,
            owner_user_id=payload.owner_user_id,
            owner_department=payload.owner_department,
            actor_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    db.commit()
    db.refresh(row)
    findings = db.scalars(select(Finding).where(Finding.tenant_id == ctx.tenant.id, Finding.ai_tool == row.tool_name)).all()
    return _to_response(row, _build_finding_map(findings))
