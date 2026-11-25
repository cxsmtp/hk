from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.api.routers.discovery_scans import SanitizedHmairRoute, require_hmair_core
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.hmair.surface_source_registration_service import (
    SurfaceSourceRegistrationInput,
    register_surface_source,
)


class SurfaceSourceRegistrationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    collector_id: str
    target_type: str
    collector_health: str
    expected_count: int
    baseline_expires_at: str
    ready: bool
    limitations: list[str]


router = APIRouter(
    prefix="/discovery/surface-sources",
    tags=["discovery"],
    dependencies=[Depends(require_hmair_core)],
    route_class=SanitizedHmairRoute,
)


@router.post("", response_model=SurfaceSourceRegistrationResponse, status_code=status.HTTP_201_CREATED)
def register_h2_surface_source(
    payload: SurfaceSourceRegistrationInput,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
) -> SurfaceSourceRegistrationResponse:
    """Register a source prerequisite; evidence can only be proved by preflight."""

    try:
        record = register_surface_source(
            db,
            tenant_id=ctx.tenant.id,
            input=payload,
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=(ctx.user.id if ctx.user is not None else None),
            actor_type="human",
            action="discovery.surface_source.registered",
            resource_type="discovery_target",
            resource_id=record.target.target_id,
            payload={
                "source_kind": payload.source_kind,
                "target_type": record.target.target_type,
                "collector_id": record.collector.collector_id,
                "expected_count": payload.expected_count,
                "baseline_expires_at": payload.baseline_expires_at.isoformat(),
                "created": record.created,
            },
        )
        db.commit()
    except ValueError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid HMAIR surface source registration",
        ) from None

    baseline = record.target.coverage_baseline_json
    return SurfaceSourceRegistrationResponse(
        target_id=record.target.target_id,
        collector_id=record.collector.collector_id,
        target_type=record.target.target_type,
        collector_health=record.collector.health,
        expected_count=int(baseline["expected_count"]),
        baseline_expires_at=str(baseline["expires_at"]),
        # Registration records authorization and denominator only. It never
        # upgrades a source to ready before a fresh evidence-bound preflight.
        ready=False,
        limitations=list(record.collector.limitations_json),
    )


__all__ = ["SurfaceSourceRegistrationResponse", "register_h2_surface_source", "router"]
