from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.routers.discovery_scans import (
    SanitizedHmairRoute,
    _bounded_safe_scalar,
    _bounded_safe_strings,
    require_hmair_core,
)
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.discovery_canonical import DiscoveryTarget
from app.db.session import get_db


class DiscoveryTargetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    target_type: str
    identifier: str
    environment: str
    owner_hint: str | None
    permitted_methods: list[str]
    exclusions: list[str]
    rate_limit: int
    active_scan_allowed: bool
    sensitive_scope: bool
    last_scanned_at: str | None


class DiscoveryTargetListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DiscoveryTargetResponse]
    total: int


router = APIRouter(
    prefix="/discovery/targets",
    tags=["discovery"],
    dependencies=[Depends(require_hmair_core)],
    route_class=SanitizedHmairRoute,
)


def _target_response(row: DiscoveryTarget) -> DiscoveryTargetResponse:
    identifier = _bounded_safe_scalar(row.identifier, max_chars=256)
    owner_hint = (
        _bounded_safe_scalar(row.owner_hint, max_chars=128)
        if row.owner_hint is not None
        else None
    )
    return DiscoveryTargetResponse(
        target_id=row.target_id,
        target_type=row.target_type,
        identifier=identifier or "Restricted target",
        environment=row.environment,
        owner_hint=owner_hint,
        permitted_methods=_bounded_safe_strings(
            row.permitted_methods_json, max_items=64, max_chars=128
        ),
        exclusions=_bounded_safe_strings(
            row.exclusions_json, max_items=64, max_chars=128
        ),
        rate_limit=row.rate_limit,
        active_scan_allowed=row.active_scan_allowed,
        sensitive_scope=row.sensitive_scope,
        last_scanned_at=(
            row.last_scanned_at.isoformat() if row.last_scanned_at else None
        ),
    )


@router.get("", response_model=DiscoveryTargetListResponse)
def list_targets(
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DiscoveryTargetListResponse:
    rows = list(
        db.scalars(
            select(DiscoveryTarget)
            .where(DiscoveryTarget.tenant_id == ctx.tenant.id)
            .order_by(DiscoveryTarget.target_type, DiscoveryTarget.target_id)
        )
    )
    total = int(
        db.scalar(
            select(func.count(DiscoveryTarget.target_id)).where(
                DiscoveryTarget.tenant_id == ctx.tenant.id
            )
        )
        or 0
    )
    return DiscoveryTargetListResponse(
        items=[_target_response(row) for row in rows], total=total
    )


__all__ = ["DiscoveryTargetListResponse", "DiscoveryTargetResponse", "list_targets", "router"]
