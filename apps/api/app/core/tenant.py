from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import get_current_user, oauth2_scheme
from app.db.models.user import User, UserTenantRole
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal, get_db


class TenantContext:
    def __init__(self, tenant: Tenant, role: str, user: User | None = None):
        self.tenant = tenant
        self.role = role
        self.user = user


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

    return TenantContext(tenant=tenant, role=membership.role, user=current_user)


def require_tenant(
    x_tenant_id: str | None = Header(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TenantContext:
    return _tenant_context_for_user(tenant_id=x_tenant_id, db=db, current_user=current_user)


def require_stream_tenant(
    request: Request = None,  # type: ignore[assignment]  # FastAPI fills it; direct callers may pass it
    x_tenant_id: str | None = Header(default=None),
    token: str = Depends(oauth2_scheme),
) -> TenantContext:
    with SessionLocal() as db:
        current_user = get_current_user(request=request, token=token, db=db)
        context = _tenant_context_for_user(tenant_id=x_tenant_id, db=db, current_user=current_user)
    return context
