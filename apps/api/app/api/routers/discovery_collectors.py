from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.routers.discovery_scans import (
    SanitizedHmairRoute,
    _bounded_redacted_strings,
    _bounded_safe_strings,
    _flag_enabled,
    _surface_enabled,
    require_hmair_core,
)
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.discovery_canonical import DiscoveryCollector
from app.db.session import get_db


_OMITTED_LIMITATION_NOTICE = (
    "Additional limitation detail was omitted for privacy."
)


class DiscoveryCollectorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    collector_type: str
    version: str
    health: str
    supported_targets: list[str]
    active_capabilities: list[str]
    passive_capabilities: list[str]
    limitations: list[str]
    enabled: bool


class DiscoveryCollectorListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DiscoveryCollectorResponse]
    total: int


router = APIRouter(
    prefix="/discovery/collectors",
    tags=["discovery"],
    dependencies=[Depends(require_hmair_core)],
    route_class=SanitizedHmairRoute,
)


def _collector_enabled(row: DiscoveryCollector) -> bool:
    surface_available = any(
        _surface_enabled(str(target_type))
        for target_type in (row.supported_targets_json or [])
        if type(target_type) is str
    )
    active_available = (
        not row.active_capabilities_json or _flag_enabled("hmair_active_scan")
    )
    return surface_available and active_available


def _collector_response(row: DiscoveryCollector) -> DiscoveryCollectorResponse:
    return DiscoveryCollectorResponse(
        collector_id=row.collector_id,
        collector_type=row.collector_type,
        version=row.version,
        health=row.health,
        supported_targets=_bounded_safe_strings(
            row.supported_targets_json,
            max_items=32,
            max_chars=64,
        ),
        active_capabilities=_bounded_safe_strings(
            row.active_capabilities_json,
            max_items=64,
            max_chars=128,
        ),
        passive_capabilities=_bounded_safe_strings(
            row.passive_capabilities_json,
            max_items=64,
            max_chars=128,
        ),
        limitations=_bounded_redacted_strings(
            row.limitations_json,
            max_items=64,
            max_chars=500,
            omitted_notice=_OMITTED_LIMITATION_NOTICE,
        ),
        enabled=_collector_enabled(row),
    )


@router.get("", response_model=DiscoveryCollectorListResponse)
def list_collectors(
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DiscoveryCollectorListResponse:
    rows = list(
        db.scalars(
            select(DiscoveryCollector)
            .where(DiscoveryCollector.tenant_id == ctx.tenant.id)
            .order_by(DiscoveryCollector.collector_id)
        )
    )
    total = int(
        db.scalar(
            select(func.count(DiscoveryCollector.collector_id)).where(
                DiscoveryCollector.tenant_id == ctx.tenant.id
            )
        )
        or 0
    )
    return DiscoveryCollectorListResponse(
        items=[_collector_response(row) for row in rows],
        total=total,
    )


@router.get("/{collector_id}/health", response_model=DiscoveryCollectorResponse)
def get_collector_health(
    collector_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
) -> DiscoveryCollectorResponse:
    row = db.scalar(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == ctx.tenant.id,
            DiscoveryCollector.collector_id == collector_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return _collector_response(row)


__all__ = ["router"]
