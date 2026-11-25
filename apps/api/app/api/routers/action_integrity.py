"""Tenant-scoped Phase 5 Action Detail read projection."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.action_integrity.action_detail import materialize_action_detail


router = APIRouter(prefix="/action-integrity", tags=["action-integrity"])


def validate_runtime_event_id(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or "/" in value:
        raise ValueError("runtime_event_id must be one bounded path segment")
    return value


@router.get("/actions/{runtime_event_id}")
def action_detail(
    runtime_event_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        event_id = validate_runtime_event_id(runtime_event_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # This is a derived read model only; every value is rebuilt from its
    # tenant-scoped durable source records before the projection is stored.
    detail = materialize_action_detail(db, tenant_id=ctx.tenant.id, runtime_event_id=event_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="action detail not found")
    db.commit()
    return detail
