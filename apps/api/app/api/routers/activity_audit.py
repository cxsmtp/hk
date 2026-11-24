from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope
from app.core.auth import get_current_user
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.activity_audit import UserRegistry
from app.db.models.user import User
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.activity_audit_service import (
    get_endpoint_timeline,
    get_user_registry_entry,
    get_user_timeline,
    list_deployment_endpoints,
    list_user_registry,
    search_activity_audit,
)
from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_ai_iam_event


router = APIRouter(tags=["activity-audit"])


class ActivityTimelineResponse(BaseModel):
    user: dict[str, Any] | None = None
    device: dict[str, Any] | None = None
    devices: list[dict[str, Any]] = Field(default_factory=list)
    sessions: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    policies_triggered: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    total_actions: int
    page: int
    page_size: int


class ActivitySearchResponse(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int
    page: int
    page_size: int
    query: dict[str, Any] = Field(default_factory=dict)


class UserRegistryDetailResponse(BaseModel):
    user: dict[str, Any] | None = None
    machine_id: str | None = None
    browser_type: str | None = None
    last_seen: str | None = None
    ai_activity_count: int = 0
    recent_actions: list[dict[str, Any]] = Field(default_factory=list)


class UserEnforcementRequest(BaseModel):
    reason: str | None = None


@router.get("/users", response_model=ListEnvelope[dict[str, Any]])
def list_users_registry(
    q: str | None = None,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = list_user_registry(
        db,
        tenant_id=ctx.tenant.id,
        q=q,
        page=page,
        page_size=page_size,
    )
    return ListEnvelope[dict[str, Any]](
        items=list(payload.get("items") or []),
        total=int(payload.get("total") or 0),
        page=int(payload.get("page") or page),
        page_size=int(payload.get("page_size") or page_size),
    )


@router.get("/users/{user_id}", response_model=UserRegistryDetailResponse)
def get_user_registry(
    user_id: str,
    action_limit: int = 20,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = get_user_registry_entry(
        db,
        tenant_id=ctx.tenant.id,
        user_id=user_id,
        action_limit=action_limit,
    )
    if payload is None:
        return UserRegistryDetailResponse()
    return UserRegistryDetailResponse.model_validate(payload)


@router.post("/users/{user_id}/block", response_model=UserRegistryDetailResponse)
def block_user_registry(
    user_id: str,
    payload: UserEnforcementRequest | None = None,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == ctx.tenant.id,
            UserRegistry.user_id == user_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Use an independent administrator to contain the current user",
        )

    user = db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active user account not found")

    row.status = "blocked"
    row.violation_count = int(row.violation_count or 0) + 1
    row.last_seen_at = datetime.now(timezone.utc)
    user.is_active = False

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="activity_audit.user.block",
        resource_type="user_registry",
        resource_id=user_id,
        payload={
            "reason": (payload.reason if payload else None),
            "account_disabled": True,
            "existing_access_tokens_rejected_on_next_request": True,
        },
    )
    try:
        ingest_from_ai_iam_event(
            db,
            tenant_id=ctx.tenant.id,
            event_type="aiiam.user_blocked",
            ai_system_id=None,
            user_id=user_id,
            agent_id=None,
            severity="high",
            evidence_node_ids=[],
            correlation_id=str(current_user.id),
            metadata={
                "action": "block_user",
                "reason": (payload.reason if payload else None),
                "machine_id": None,
            },
        )
    except Exception:
        pass

    db.commit()
    detail = get_user_registry_entry(db, tenant_id=ctx.tenant.id, user_id=user_id, action_limit=20) or {}
    return UserRegistryDetailResponse.model_validate(detail)


@router.post("/users/{user_id}/enforce-policy", response_model=UserRegistryDetailResponse)
def enforce_policy_for_user(
    user_id: str,
    payload: UserEnforcementRequest | None = None,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == ctx.tenant.id,
            UserRegistry.user_id == user_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    surfaces = [str(item).strip() for item in list(row.deployment_surfaces or []) if str(item).strip()]
    if "strict_policy_enforced" not in surfaces:
        surfaces.append("strict_policy_enforced")
    row.deployment_surfaces = sorted(set(surfaces))
    row.last_seen_at = datetime.now(timezone.utc)

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="activity_audit.user.enforce_policy",
        resource_type="user_registry",
        resource_id=user_id,
        payload={"reason": (payload.reason if payload else None)},
    )
    try:
        ingest_from_ai_iam_event(
            db,
            tenant_id=ctx.tenant.id,
            event_type="aiiam.user_policy_enforced",
            ai_system_id=None,
            user_id=user_id,
            agent_id=None,
            severity="med",
            evidence_node_ids=[],
            correlation_id=str(current_user.id),
            metadata={
                "action": "enforce_policy",
                "reason": (payload.reason if payload else None),
            },
        )
    except Exception:
        pass

    db.commit()
    detail = get_user_registry_entry(db, tenant_id=ctx.tenant.id, user_id=user_id, action_limit=20) or {}
    return UserRegistryDetailResponse.model_validate(detail)


@router.get("/endpoints", response_model=ListEnvelope[dict[str, Any]])
def list_endpoints_registry(
    q: str | None = None,
    user_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = list_deployment_endpoints(
        db,
        tenant_id=ctx.tenant.id,
        q=q,
        user_id=user_id,
        page=page,
        page_size=page_size,
    )
    return ListEnvelope[dict[str, Any]](
        items=list(payload.get("items") or []),
        total=int(payload.get("total") or 0),
        page=int(payload.get("page") or page),
        page_size=int(payload.get("page_size") or page_size),
    )


@router.get("/users/{user_id}/timeline", response_model=ActivityTimelineResponse)
def user_timeline(
    user_id: str,
    action_type: str | None = None,
    enforcement_action: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 200,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = get_user_timeline(
        db,
        tenant_id=ctx.tenant.id,
        user_id=user_id,
        action_type=action_type,
        enforcement_action=enforcement_action,
        severity=severity,
        page=page,
        page_size=page_size,
    )
    return ActivityTimelineResponse.model_validate(payload)


@router.get("/endpoints/{endpoint_id}/timeline", response_model=ActivityTimelineResponse)
def endpoint_timeline(
    endpoint_id: str,
    action_type: str | None = None,
    enforcement_action: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 200,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = get_endpoint_timeline(
        db,
        tenant_id=ctx.tenant.id,
        endpoint_id=endpoint_id,
        action_type=action_type,
        enforcement_action=enforcement_action,
        severity=severity,
        page=page,
        page_size=page_size,
    )
    return ActivityTimelineResponse.model_validate(payload)


@router.get("/activity-audit/search", response_model=ActivitySearchResponse)
def search_activity(
    user: str | None = None,
    device: str | None = None,
    ai_app: str | None = None,
    prompt_keyword: str | None = None,
    alert_type: str | None = None,
    runtime_event_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = search_activity_audit(
        db,
        tenant_id=ctx.tenant.id,
        user=user,
        device=device,
        ai_app=ai_app,
        prompt_keyword=prompt_keyword,
        alert_type=alert_type,
        runtime_event_id=runtime_event_id,
        page=page,
        page_size=page_size,
    )
    return ActivitySearchResponse.model_validate(payload)
