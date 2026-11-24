from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.executive_mcp_service import (
    ExecutiveQuery,
    build_executive_mcp_summary,
    create_executive_mcp_presentation,
    query_executive_mcp_metrics,
)


router = APIRouter(prefix="/executive-mcp", tags=["executive-mcp"])


class ExecutiveQueryRequest(BaseModel):
    metric: Literal[
        "actions",
        "blocked",
        "top_violations",
        "violations_by_framework",
        "providers",
        "mcp_tools",
        "github_repositories",
        "control_coverage",
        "spend",
        "tokens",
    ]
    window_days: int = Field(default=30, ge=1, le=366)
    group_by: str | None = Field(default=None, max_length=64)
    limit: int = Field(default=10, ge=1, le=100)
    include_named_users: bool = False


class ExecutivePresentationRequest(BaseModel):
    title: str = Field(default="Executive AI Governance Brief", min_length=1, max_length=120)
    window_days: int = Field(default=30, ge=1, le=366)


@router.get("/summary")
def executive_mcp_summary(
    window_days: int = Query(default=30, ge=1, le=366),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    result = build_executive_mcp_summary(
        db,
        tenant_id=ctx.tenant.id,
        role=ctx.role,
        window_days=window_days,
    )
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="executive_mcp.summary.view",
        resource_type="executive_mcp",
        resource_id="summary",
        payload={"window_days": window_days, "raw_prompt_content_included": False},
    )
    db.commit()
    return result


@router.post("/query")
def executive_mcp_query(
    payload: ExecutiveQueryRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    result = query_executive_mcp_metrics(
        db,
        tenant_id=ctx.tenant.id,
        role=ctx.role,
        query=ExecutiveQuery(
            metric=payload.metric,
            window_days=payload.window_days,
            group_by=payload.group_by,
            limit=payload.limit,
            include_named_users=payload.include_named_users,
        ),
    )
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="executive_mcp.query",
        resource_type="executive_mcp",
        resource_id=payload.metric,
        payload={
            "metric": payload.metric,
            "window_days": payload.window_days,
            "group_by": payload.group_by,
            "include_named_users": bool(payload.include_named_users),
            "raw_prompt_content_included": False,
        },
    )
    db.commit()
    return result


@router.post("/presentations")
def executive_mcp_presentation(
    payload: ExecutivePresentationRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    result = create_executive_mcp_presentation(
        db,
        tenant_id=ctx.tenant.id,
        role=ctx.role,
        title=payload.title,
        window_days=payload.window_days,
    )
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="executive_mcp.presentation.create",
        resource_type="executive_mcp_presentation",
        resource_id=result["artifact_id"],
        payload={
            "filename": result["filename"],
            "window_days": payload.window_days,
            "slide_count": result["slide_count"],
            "raw_prompt_content_included": False,
        },
    )
    db.commit()
    return result
