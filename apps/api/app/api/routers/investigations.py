"""Bounded tenant-scoped Phase 7 AI action investigation API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import get_db
from app.services.activity_lineage import (
    LineageQuery,
    add_investigation_finding,
    create_investigation,
    get_activity_lineage_projection,
    get_investigation,
    materialize_lineage_projection,
    search_lineages,
    traverse_lineage,
)


router = APIRouter(prefix="/investigations", tags=["investigations"])


class InvestigationCreateRequest(BaseModel):
    lineage_id: str = Field(min_length=1, max_length=36)
    title: str = Field(min_length=1, max_length=255)
    scope: dict[str, Any] = Field(default_factory=dict)
    saved_query: dict[str, Any] = Field(default_factory=dict)
    time_from: datetime | None = None
    time_to: datetime | None = None


class FindingCreateRequest(BaseModel):
    finding_type: str = Field(min_length=1, max_length=64)
    severity: str = Field(pattern="^(info|low|medium|high|critical)$")
    title: str = Field(min_length=1, max_length=255)
    reason_code: str = Field(min_length=1, max_length=128)
    lineage_node_ids: list[str] = Field(default_factory=list, max_length=100)
    lineage_edge_ids: list[str] = Field(default_factory=list, max_length=100)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)


def _bounded_path(value: str, *, name: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or "/" in value:
        raise HTTPException(status_code=422, detail=f"{name} must be one bounded path segment")
    return value


def _value_error(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


@router.get("/runtime-events/{runtime_event_id}")
def lineage_for_runtime_event(
    runtime_event_id: str,
    depth: int = Query(default=3, ge=0, le=6),
    limit: int = Query(default=100, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    event_id = _bounded_path(runtime_event_id, name="runtime_event_id")
    try:
        result = materialize_lineage_projection(
            db, tenant_id=ctx.tenant.id, runtime_event_id=event_id, depth=depth, limit=limit,
        )
    except ValueError as exc:
        raise _value_error(exc) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    db.commit()
    return result


@router.get("/actions/{action_id}")
def lineage_for_action(
    action_id: str,
    depth: int = Query(default=3, ge=0, le=6),
    limit: int = Query(default=100, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    action_ref = _bounded_path(action_id, name="action_id")
    event = db.scalar(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.entity_type.in_(("action", "canonical_action")),
            RuntimeEvent.entity_id == action_ref,
        )
        .order_by(RuntimeEvent.created_at.desc(), RuntimeEvent.event_id.desc())
        .limit(1)
    )
    if event is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    try:
        result = materialize_lineage_projection(
            db, tenant_id=ctx.tenant.id, runtime_event_id=event.event_id, depth=depth, limit=limit,
        )
    except ValueError as exc:
        raise _value_error(exc) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    db.commit()
    return result


@router.get("/lineages/{lineage_id}")
def lineage_detail(
    lineage_id: str,
    limit: int = Query(default=100, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    result = get_activity_lineage_projection(
        db, tenant_id=ctx.tenant.id, lineage_id=_bounded_path(lineage_id, name="lineage_id", maximum=36), limit=limit,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    return result


@router.get("/lineages/{lineage_id}/traverse")
def lineage_traversal(
    lineage_id: str,
    seed_node_id: str = Query(min_length=1, max_length=36),
    direction: str = Query(default="both", pattern="^(upstream|downstream|both)$"),
    depth: int = Query(default=3, ge=0, le=6),
    limit: int = Query(default=100, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        result = traverse_lineage(
            db, tenant_id=ctx.tenant.id,
            lineage_id=_bounded_path(lineage_id, name="lineage_id", maximum=36),
            seed_node_id=seed_node_id, direction=direction, depth=depth, limit=limit,
        )
    except ValueError as exc:
        raise _value_error(exc) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    return result


@router.get("/search")
def lineage_search(
    action_id: str | None = Query(default=None, max_length=255),
    authority_type: str | None = Query(default=None, max_length=255),
    authority_id: str | None = Query(default=None, max_length=255),
    node_type: str | None = Query(default=None, max_length=32),
    certainty: str | None = Query(default=None, pattern="^(CONFIRMED|CORRELATED|INFERRED|UNKNOWN)$"),
    actor: str | None = Query(default=None, max_length=255),
    executing_principal: str | None = Query(default=None, max_length=255),
    represented_subject: str | None = Query(default=None, max_length=255),
    agent: str | None = Query(default=None, max_length=255),
    tool: str | None = Query(default=None, max_length=255),
    mcp_server: str | None = Query(default=None, max_length=255),
    mcp_tool: str | None = Query(default=None, max_length=255),
    resource: str | None = Query(default=None, max_length=255),
    target: str | None = Query(default=None, max_length=255),
    destination: str | None = Query(default=None, max_length=255),
    provider: str | None = Query(default=None, max_length=255),
    decision: str | None = Query(default=None, max_length=32),
    integrity_status: str | None = Query(default=None, max_length=32),
    drift_type: str | None = Query(default=None, max_length=64),
    control_point: str | None = Query(default=None, max_length=255),
    validation_state: str | None = Query(default=None, max_length=32),
    time_from: datetime | None = Query(default=None),
    time_to: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        items = search_lineages(db, tenant_id=ctx.tenant.id, query=LineageQuery(
            action_id=action_id, authority_type=authority_type, authority_id=authority_id,
            node_type=node_type, certainty=certainty, time_from=time_from, time_to=time_to, limit=limit,
            actor=actor, executing_principal=executing_principal, represented_subject=represented_subject,
            agent=agent, tool=tool, mcp_server=mcp_server, mcp_tool=mcp_tool,
            resource=resource, target=target, destination=destination, provider=provider,
            decision=decision, integrity_status=integrity_status, drift_type=drift_type,
            control_point=control_point, validation_state=validation_state,
        ))
    except ValueError as exc:
        raise _value_error(exc) from exc
    return {"count": len(items), "items": items, "bounds": {"limit": limit}}


@router.post("")
def investigation_create(
    payload: InvestigationCreateRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = create_investigation(
            db, tenant_id=ctx.tenant.id, lineage_id=payload.lineage_id, title=payload.title,
            owner_ref=f"user:{ctx.user.id}" if ctx.user is not None else "operator:unknown",
            scope=payload.scope, saved_query=payload.saved_query,
            time_from=payload.time_from, time_to=payload.time_to,
        )
    except ValueError as exc:
        raise _value_error(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    db.commit()
    result = get_investigation(db, tenant_id=ctx.tenant.id, investigation_id=row.id)
    assert result is not None
    return result


@router.get("/{investigation_id}")
def investigation_detail(
    investigation_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    result = get_investigation(
        db, tenant_id=ctx.tenant.id,
        investigation_id=_bounded_path(investigation_id, name="investigation_id", maximum=36),
    )
    if result is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    return result


@router.post("/{investigation_id}/findings")
def investigation_finding_create(
    investigation_id: str,
    payload: FindingCreateRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = add_investigation_finding(
            db, tenant_id=ctx.tenant.id,
            investigation_id=_bounded_path(investigation_id, name="investigation_id", maximum=36),
            finding_type=payload.finding_type, severity=payload.severity, title=payload.title,
            reason_code=payload.reason_code, lineage_node_ids=payload.lineage_node_ids,
            lineage_edge_ids=payload.lineage_edge_ids, evidence_refs=payload.evidence_refs,
        )
    except ValueError as exc:
        raise _value_error(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="AI action investigation not found")
    db.commit()
    return {
        "id": row.id, "investigation_id": row.investigation_id, "finding_type": row.finding_type,
        "severity": row.severity, "title": row.title, "reason_code": row.reason_code,
        "status": row.status, "lineage_node_ids": list(row.lineage_node_ids or []),
        "lineage_edge_ids": list(row.lineage_edge_ids or []), "evidence_refs": list(row.evidence_refs or []),
    }
