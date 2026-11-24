from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.auth import get_current_user
from app.core.deps_control_plane import require_control_plane_healthy
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.user import User
from app.db.models.external_risk import ExternalRiskRecord, ExternalRiskSource
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.external_risk_intel import (
    get_asset_records,
    get_record_mappings,
    get_summary,
    list_records,
    list_sources,
    run_sync,
    upsert_source,
)


router = APIRouter(
    prefix="/external-risk",
    tags=["external-risk"],
    dependencies=[Depends(require_control_plane_healthy(module="monitoring"))],
)


class ExternalRiskSourcePayload(BaseModel):
    source: str
    display_name: str | None = None
    enabled: bool = True
    endpoint_url: str | None = None
    auth_mode: str = "none"
    auth_config: dict[str, Any] = Field(default_factory=dict)
    source_trust_policy: dict[str, Any] = Field(default_factory=dict)
    egress_policy: dict[str, Any] = Field(default_factory=dict)
    redaction_policy: dict[str, Any] = Field(default_factory=dict)
    routing_policy: dict[str, Any] = Field(default_factory=dict)
    transport_policy: dict[str, Any] = Field(default_factory=dict)
    sync_schedule: str | None = None


class ExternalRiskSourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    source: str
    display_name: str
    enabled: bool
    endpoint_url: str
    auth_mode: str
    source_trust_policy: dict[str, Any]
    egress_policy: dict[str, Any]
    redaction_policy: dict[str, Any]
    routing_policy: dict[str, Any]
    transport_policy: dict[str, Any]
    sync_schedule: str
    last_sync_at: datetime | None = None
    last_sync_status: str
    last_sync_error: str | None = None
    created_at: datetime
    updated_at: datetime


class ExternalRiskRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    source: str
    source_record_id: str
    title: str
    description: str
    severity: str
    cvss_score: float | None = None
    exploit_status: str
    affected_components: list[str]
    affected_versions: list[str]
    references: list[str]
    published_at: datetime | None = None
    source_updated_at: datetime | None = None
    integrity_status: str
    ingestion_trace_id: str | None = None
    raw_artifact_ref: str | None = None
    created_at: datetime
    updated_at: datetime


@router.get("/sources", response_model=ListEnvelope[ExternalRiskSourceResponse])
def get_sources(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = list_sources(db, tenant_id=ctx.tenant.id)
    db.commit()
    dto = [ExternalRiskSourceResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto, page=page, page_size=page_size)
    return ListEnvelope[ExternalRiskSourceResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/sources", response_model=ExternalRiskSourceResponse)
def post_source(
    payload: ExternalRiskSourcePayload,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        row = upsert_source(db, tenant_id=ctx.tenant.id, payload=payload.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="external_risk.source.upsert",
        resource_type="external_risk_source",
        resource_id=row.id,
        payload={"source": row.source, "enabled": row.enabled, "endpoint_url": row.endpoint_url},
    )
    db.commit()
    db.refresh(row)
    return ExternalRiskSourceResponse.model_validate(row)


@router.get("/records", response_model=ListEnvelope[ExternalRiskRecordResponse])
def get_records(
    severity: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows: list[ExternalRiskRecord] = list_records(
        db,
        tenant_id=ctx.tenant.id,
        severity=severity,
        limit=limit,
    )
    db.commit()
    dto = [ExternalRiskRecordResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto, page=page, page_size=page_size)
    return ListEnvelope[ExternalRiskRecordResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/assets/{asset_id}")
def get_asset_view(
    asset_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = get_asset_records(db, tenant_id=ctx.tenant.id, asset_id=asset_id)
    db.commit()
    return {
        "tenant_id": ctx.tenant.id,
        "asset_id": asset_id,
        "records": payload,
    }


@router.get("/mappings/{risk_record_id}")
def get_mappings_view(
    risk_record_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = get_record_mappings(db, tenant_id=ctx.tenant.id, risk_record_id=risk_record_id)
    db.commit()
    return {
        "tenant_id": ctx.tenant.id,
        "risk_record_id": risk_record_id,
        "mappings": [
            {
                "mapping_id": row.id,
                "asset_type": row.asset_type,
                "asset_id": row.asset_id,
                "environment": row.environment,
                "confidence": row.confidence,
                "mapping_reason": row.mapping_reason,
                "control_ids": row.control_ids,
                "simulation_ids": row.simulation_ids,
                "mapping_status": row.mapping_status,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }
            for row in rows
        ],
    }


@router.post("/sync")
def post_sync(
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        summary = run_sync(db, tenant_id=ctx.tenant.id, actor_user_id=current_user.id)
        db.commit()
        return summary
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"external_risk_sync_failed:{type(exc).__name__}",
        ) from exc


@router.get("/summary")
def get_external_risk_summary(
    lookback_hours: int = Query(default=24 * 7, ge=1, le=24 * 90),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = get_summary(db, tenant_id=ctx.tenant.id, lookback_hours=lookback_hours)
    db.commit()
    return payload
