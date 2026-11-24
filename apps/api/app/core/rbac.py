from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, status

from app.core.tenant import TenantContext, require_tenant


ROLE_ORDER = {
    "viewer": 0,
    "operator": 1,
    "auditor": 2,
    "admin": 3,
    "owner": 4,
}


def require_role(min_role: str | None = None, allow_list: list[str] | None = None) -> Callable[[TenantContext], TenantContext]:
    def checker(ctx: TenantContext = Depends(require_tenant)) -> TenantContext:
        role = ctx.role
        if allow_list and role in allow_list:
            return ctx
        if min_role and ROLE_ORDER.get(role, -1) >= ROLE_ORDER.get(min_role, 99):
            return ctx
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    return checker
