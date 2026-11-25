"""Bounded, tenant-safe User Visibility API contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.user_visibility_service import (
    UserVisibilityError,
    create_visibility_access_grant,
    consume_prompt_reveal,
    directory_summary,
    get_user_360,
    get_user_360_section,
    get_effective_policy_stack,
    get_effective_policy_references,
    get_group_detail,
    get_privacy_settings,
    list_actions,
    list_departments,
    list_groups,
    list_users,
    list_visibility_access_grants,
    organization_summary,
    request_prompt_reveal,
    update_privacy_settings,
    require_visibility_capability,
)
from app.services.policy_pack_platform.service import PolicyPackPlatformError, update_policy_pack_group_memberships


router = APIRouter(prefix="/user-visibility", tags=["user-visibility"])


class AccessGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=36)
    capabilities: list[str] = Field(min_length=1, max_length=8)
    department_scope: list[str] = Field(default_factory=list, max_length=64)
    expires_at: datetime | None = None
    reason: str = Field(min_length=3, max_length=1_000)


class PromptRevealRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: Literal["security_investigation", "audit", "incident_response", "privacy_review"]
    reason: str = Field(min_length=3, max_length=1_000)


class BulkMembershipRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    add_user_ids: list[str] = Field(default_factory=list, max_length=1_000)
    remove_user_ids: list[str] = Field(default_factory=list, max_length=1_000)


class PrivacySettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_content_reveal_enabled: bool
    retention_days: int = Field(ge=0, le=3_650)


def _error(exc: UserVisibilityError) -> HTTPException:
    detail = str(exc)
    if detail.endswith("_not_found"):
        code = status.HTTP_404_NOT_FOUND
    elif detail in {"visibility_content_grant_consumed", "visibility_content_grant_expired"}:
        code = status.HTTP_409_CONFLICT
    elif detail.endswith("_invalid") or detail.endswith("_reason_invalid") or detail.endswith("_unavailable") or detail.endswith("_disabled") or detail.endswith("_expired"):
        code = status.HTTP_422_UNPROCESSABLE_CONTENT
    else:
        code = status.HTTP_403_FORBIDDEN
    return HTTPException(status_code=code, detail=detail)


def _policy_pack_error(exc: PolicyPackPlatformError) -> HTTPException:
    detail = str(exc)
    if detail.endswith("_not_found"):
        code = status.HTTP_404_NOT_FOUND
    elif detail.endswith("_source_managed") or detail.endswith("_conflict"):
        code = status.HTTP_409_CONFLICT
    elif detail.endswith("_invalid") or detail.endswith("_not_allowed") or detail.endswith("_user_not_found"):
        code = status.HTTP_422_UNPROCESSABLE_CONTENT
    else:
        code = status.HTTP_403_FORBIDDEN
    return HTTPException(status_code=code, detail=detail)


@router.post("/access-grants", status_code=status.HTTP_201_CREATED)
def create_access_grant(
    payload: AccessGrantRequest,
    ctx: TenantContext = Depends(require_permission("identities.manage")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        grant = create_visibility_access_grant(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            user_id=payload.user_id,
            capabilities=payload.capabilities,
            department_scope=payload.department_scope,
            reason=payload.reason,
            expires_at=payload.expires_at,
        )
        db.commit()
        db.refresh(grant)
        return {
            "grant_id": grant.id,
            "user_id": grant.user_id,
            "capabilities": list(grant.capabilities or []),
            "department_scope": list(grant.department_scope or []),
            "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
            "active": bool(grant.active),
        }
    except UserVisibilityError as exc:
        db.rollback()
        raise _error(exc) from exc


@router.get("/access-grants", response_model=ListEnvelope[dict[str, Any]])
def get_access_grants(
    ctx: TenantContext = Depends(require_permission("identities.manage")),
    db: Session = Depends(get_db),
):
    items = list_visibility_access_grants(db, tenant_id=ctx.tenant.id)
    return ListEnvelope[dict[str, Any]](items=items, total=len(items), page=1, page_size=len(items) or 1)


@router.get("/privacy-settings")
def get_tenant_privacy_settings(
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="manage_privacy",
        )
        return get_privacy_settings(db, tenant_id=ctx.tenant.id)
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.put("/privacy-settings")
def put_tenant_privacy_settings(
    payload: PrivacySettingsRequest,
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        result = update_privacy_settings(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            full_content_reveal_enabled=payload.full_content_reveal_enabled,
            retention_days=payload.retention_days,
        )
        db.commit()
        return result
    except UserVisibilityError as exc:
        db.rollback()
        raise _error(exc) from exc


@router.post("/prompts/{action_id}/reveal-grants", status_code=status.HTTP_201_CREATED)
def create_prompt_reveal_grant(
    action_id: str,
    payload: PromptRevealRequest,
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        grant = request_prompt_reveal(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            action_id=action_id,
            purpose=payload.purpose,
            reason=payload.reason,
        )
        db.commit()
        db.refresh(grant)
        return {
            "grant_id": grant.id,
            "action_id": grant.action_id,
            "purpose": grant.purpose,
            "expires_at": grant.expires_at.isoformat(),
        }
    except UserVisibilityError as exc:
        db.rollback()
        raise _error(exc) from exc


@router.post("/prompt-reveal/{grant_id}")
def consume_prompt_reveal_grant(
    grant_id: str,
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        payload = consume_prompt_reveal(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            grant_id=grant_id,
        )
        db.commit()
        return payload
    except UserVisibilityError as exc:
        db.rollback()
        raise _error(exc) from exc


@router.get("/users", response_model=ListEnvelope[dict[str, Any]])
def get_users(
    q: str | None = Query(default=None, max_length=255),
    department: str | None = Query(default=None, max_length=128),
    status_value: str | None = Query(default=None, alias="status", max_length=32),
    role: str | None = Query(default=None, max_length=64),
    group_id: str | None = Query(default=None, max_length=36),
    application: str | None = Query(default=None, max_length=255),
    account_class: str | None = Query(default=None, max_length=128),
    provider: str | None = Query(default=None, max_length=255),
    model: str | None = Query(default=None, max_length=255),
    last_activity_after: datetime | None = None,
    sort_by: str | None = Query(default=None, max_length=32),
    sort_direction: Literal["asc", "desc"] | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
):
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_user_metadata",
            target_department=department,
        )
        payload = list_users(
            db,
            tenant_id=ctx.tenant.id,
            actor_scope=scope,
            q=q,
            department=department,
            status_value=status_value,
            role=role,
            group_id=group_id,
            application=application,
            account_class=account_class,
            provider=provider,
            model=model,
            last_activity_after=last_activity_after,
            page=page,
            page_size=page_size,
            sort_by=sort_by,
            sort_direction=sort_direction,
        )
        return ListEnvelope[dict[str, Any]](**payload)
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/users/summary")
def get_user_directory_summary(
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_aggregates",
        )
        return directory_summary(db, tenant_id=ctx.tenant.id, actor_scope=scope)
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/users/{user_id}")
def get_user_detail(
    user_id: str,
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_user_metadata",
        )
        require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_action_details",
        )
        return get_user_360(db, tenant_id=ctx.tenant.id, actor_scope=scope, user_id=user_id)
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/users/{user_id}/experience/{section}")
def get_user_experience_section(
    user_id: str,
    section: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        required_capability = "view_user_metadata" if section in {"overview", "usage", "accounts", "policies", "maturity"} else "view_action_details"
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability=required_capability,
        )
        return get_user_360_section(
            db,
            tenant_id=ctx.tenant.id,
            actor_scope=scope,
            user_id=user_id,
            section=section,
            page=page,
            page_size=page_size,
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/departments", response_model=ListEnvelope[dict[str, Any]])
def get_departments(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
):
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_aggregates",
        )
        return ListEnvelope[dict[str, Any]](
            **list_departments(db, tenant_id=ctx.tenant.id, actor_scope=scope, page=page, page_size=page_size)
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/organization")
def get_organization(
    lookback_hours: int = Query(default=24 * 30, ge=1, le=24 * 90),
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_aggregates",
        )
        return organization_summary(
            db,
            tenant_id=ctx.tenant.id,
            actor_scope=scope,
            lookback_hours=lookback_hours,
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/actions", response_model=ListEnvelope[dict[str, Any]])
def get_actions(
    user_id: str | None = Query(default=None, max_length=36),
    group_id: str | None = Query(default=None, max_length=36),
    department: str | None = Query(default=None, max_length=128),
    application: str | None = Query(default=None, max_length=255),
    account_class: str | None = Query(default=None, max_length=128),
    provider: str | None = Query(default=None, max_length=255),
    model: str | None = Query(default=None, max_length=255),
    agent: str | None = Query(default=None, max_length=255),
    tool: str | None = Query(default=None, max_length=255),
    action_class: str | None = Query(default=None, max_length=64),
    resource: str | None = Query(default=None, max_length=255),
    target: str | None = Query(default=None, max_length=255),
    destination: str | None = Query(default=None, max_length=255),
    data_class: str | None = Query(default=None, max_length=64),
    side_effect: str | None = Query(default=None, max_length=128),
    decision: str | None = Query(default=None, max_length=32),
    integrity: str | None = Query(default=None, max_length=64),
    control_state: str | None = Query(default=None, max_length=64),
    surface: str | None = Query(default=None, max_length=32),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
):
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_action_details",
            target_department=department,
        )
        return ListEnvelope[dict[str, Any]](
            **list_actions(
                db,
                tenant_id=ctx.tenant.id,
                actor_scope=scope,
                user_id=user_id,
                group_id=group_id,
                department=department,
                application=application,
                account_class=account_class,
                provider=provider,
                model=model,
                agent=agent,
                tool=tool,
                action_class=action_class,
                resource=resource,
                target=target,
                destination=destination,
                data_class=data_class,
                side_effect=side_effect,
                decision=decision,
                integrity=integrity,
                control_state=control_state,
                surface=surface,
                start_time=start_time,
                end_time=end_time,
                page=page,
                page_size=page_size,
            )
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/groups", response_model=ListEnvelope[dict[str, Any]])
def get_groups(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
):
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_user_metadata",
        )
        return ListEnvelope[dict[str, Any]](
            **list_groups(db, tenant_id=ctx.tenant.id, actor_scope=scope, page=page, page_size=page_size)
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/groups/{group_id}")
def get_group(
    group_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_user_metadata",
        )
        return get_group_detail(
            db,
            tenant_id=ctx.tenant.id,
            actor_scope=scope,
            group_id=group_id,
            page=page,
            page_size=page_size,
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.post("/groups/{group_id}/memberships")
def update_group_memberships(
    group_id: str,
    payload: BulkMembershipRequest,
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, list[str]]:
    try:
        require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="manage_groups",
        )
        result = update_policy_pack_group_memberships(
            db,
            tenant_id=ctx.tenant.id,
            group_id=group_id,
            add_user_ids=payload.add_user_ids,
            remove_user_ids=payload.remove_user_ids,
            actor_user_id=ctx.user.id,
        )
        db.commit()
        return result
    except UserVisibilityError as exc:
        db.rollback()
        raise _error(exc) from exc
    except PolicyPackPlatformError as exc:
        db.rollback()
        raise _policy_pack_error(exc) from exc


@router.get("/users/{user_id}/effective-policies")
def get_effective_policies(
    user_id: str,
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_user_metadata",
        )
        return get_effective_policy_references(
            db,
            tenant_id=ctx.tenant.id,
            actor_scope=scope,
            user_id=user_id,
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc


@router.get("/users/{user_id}/policy-stack")
def get_user_policy_stack(
    user_id: str,
    ctx: TenantContext = Depends(require_permission("identities.view")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        scope = require_visibility_capability(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tenant_role=ctx.role,
            capability="view_user_metadata",
        )
        return get_effective_policy_stack(
            db,
            tenant_id=ctx.tenant.id,
            actor_scope=scope,
            user_id=user_id,
        )
    except UserVisibilityError as exc:
        raise _error(exc) from exc
