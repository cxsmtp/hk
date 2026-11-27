from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_permission
from app.core.tenant import TenantContext, require_tenant
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.control_plane_health_service import control_plane_module_status, evaluate_control_plane_health
from app.services.evidence_service import create_evidence_node
from app.services.platform_mode_service import (
    PLATFORM_MODES,
    get_tenant_platform_mode,
    normalize_platform_mode,
    set_tenant_platform_mode,
)


router = APIRouter(prefix="/system", tags=["system"])


class ControlPlaneHealthResponse(BaseModel):
    governance_status: str
    enforcement_status: str
    iam_status: str
    auditor_status: str
    healthy: bool
    strict_mode: bool
    required_checks: list[str]
    checks: dict[str, dict]


class PlatformModeResponse(BaseModel):
    tenant_id: str
    platform_mode: str


class PlatformModeUpdateRequest(BaseModel):
    platform_mode: str


@router.get("/control-plane-health", response_model=ControlPlaneHealthResponse)
def control_plane_health(
    ai_system_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("monitoring.view")),
    db: Session = Depends(get_db),
):
    del ai_system_id, ctx
    report = evaluate_control_plane_health(db)
    status_payload = control_plane_module_status(report)
    return ControlPlaneHealthResponse(
        **status_payload,
        healthy=report.healthy,
        strict_mode=report.strict_mode,
        required_checks=report.required_checks,
        checks=report.to_dict()["checks"],
    )


@router.get("/platform-mode", response_model=PlatformModeResponse)
def get_platform_mode(
    ctx: TenantContext = Depends(require_permission("monitoring.view")),
    db: Session = Depends(get_db),
):
    return PlatformModeResponse(
        tenant_id=ctx.tenant.id,
        platform_mode=get_tenant_platform_mode(db, tenant_id=ctx.tenant.id),
    )


@router.post("/platform-mode", response_model=PlatformModeResponse)
def update_platform_mode(
    payload: PlatformModeUpdateRequest,
    ctx: TenantContext = Depends(require_permission("settings.manage")),
    db: Session = Depends(get_db),
):
    requested = str(payload.platform_mode or "").strip().lower()
    if requested not in PLATFORM_MODES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="platform_mode must be one of: discovery, enforce",
        )
    mode = normalize_platform_mode(requested)

    row = set_tenant_platform_mode(
        db,
        tenant_id=ctx.tenant.id,
        platform_mode=mode,
    )

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="system.platform_mode.update",
        resource_type="tenant",
        resource_id=ctx.tenant.id,
        payload={"platform_mode": row.platform_mode},
    )
    create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="platform_mode_change",
        signal_type="system.platform_mode.updated",
        label=f"Platform mode set to {row.platform_mode}",
        payload={"tenant_id": ctx.tenant.id, "platform_mode": row.platform_mode},
    )
    db.commit()
    return PlatformModeResponse(
        tenant_id=ctx.tenant.id,
        platform_mode=row.platform_mode,
    )


class FeaturesResponse(BaseModel):
    # Control Coverage (app/api/routers/control_coverage.py), off unless CONTROL_COVERAGE_API_ENABLED: the console
    # leaves its panels out instead of reporting it unavailable.
    control_coverage: bool


@router.get("/features", response_model=FeaturesResponse)
def get_features(ctx: TenantContext = Depends(require_tenant)):
    del ctx
    return FeaturesResponse(control_coverage=bool(settings.control_coverage_api_enabled))
