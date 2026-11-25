from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, oauth2_scheme
from app.db.models.user import User, UserTenantRole
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal, get_db


class TenantContext:
    """Who is asking, in which tenant, and what they may do there.

    ``permissions``: what their role holds in this tenant (app/services/iam_service.py). ``role_key``: the role their
    membership carries (a built-in id, or a role someone made). ``role``: the highest built-in role their permissions
    cover, for code that still reasons in role names (for the built-in roles, unchanged: the role itself)."""

    def __init__(
        self,
        tenant: Tenant,
        role: str,
        user: User | None = None,
        *,
        permissions: frozenset[str] | None = None,
        role_key: str | None = None,
        membership: UserTenantRole | None = None,
    ):
        self.tenant = tenant
        self.role = role
        self.user = user
        self.role_key = role_key if role_key is not None else role
        if permissions is None:
            from app.core.permissions import default_permissions

            permissions = default_permissions(role)
        self.permissions = frozenset(permissions)
        self.membership = membership


def _tenant_context_for_user(*, tenant_id: str | None, db: Session, current_user: User) -> TenantContext:
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing X-Tenant-ID header")

    membership = db.scalar(
        select(UserTenantRole).where(
            UserTenantRole.user_id == current_user.id,
            UserTenantRole.tenant_id == tenant_id,
        )
    )
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User not in tenant")

    tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    if not tenant.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant is inactive")

    from app.services import iam_service

    permissions, floor = iam_service.resolve(db, tenant.id, membership.role)
    return TenantContext(tenant=tenant, role=floor, user=current_user, permissions=permissions, role_key=membership.role, membership=membership)


def require_tenant(
    request: Request,
    x_tenant_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TenantContext:
    context = _tenant_context_for_user(tenant_id=x_tenant_id, db=db, current_user=current_user)
    # Who made this request, for the user activity log (app/services/user_activity.py), read once it is answered.
    try:
        request.state.activity_actor = {
            "tenant_id": context.tenant.id,
            "user_id": current_user.id,
            "user": current_user.email or "",
            "name": current_user.full_name or "",
            "role": context.role_key or "",
        }
    except Exception:  # noqa: BLE001 - never stands in the way of the request
        pass
    return context


def require_stream_tenant(
    request: Request = None,  # type: ignore[assignment]  # FastAPI fills it; direct callers may pass it
    x_tenant_id: str | None = Header(default=None),
    token: str = Depends(oauth2_scheme),
) -> TenantContext:
    with SessionLocal() as db:
        current_user = get_current_user(request=request, token=token, db=db)
        context = _tenant_context_for_user(tenant_id=x_tenant_id, db=db, current_user=current_user)
    return context
