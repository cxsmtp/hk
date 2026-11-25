from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from app.core.tenant import TenantContext, require_tenant


ROLE_ORDER = {
    "viewer": 0,
    "operator": 1,
    "auditor": 2,
    "admin": 3,
    "owner": 4,
}

#: Roles that read and never change anything. The auditor ranks above the operator, so that it reads what auditors
#: read (min_role="auditor" routes), but it must never pass an operator's checks for changing things: on routes that
#: need at least an operator it only reads (GET, HEAD, OPTIONS). Routes that name it in allow_list are unaffected.
READ_ONLY_ROLES = frozenset({"auditor"})
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def role_meets(role: str, min_role: str, *, write: bool) -> bool:
    """Whether ``role`` passes a ``min_role`` check. A read-only role passes checks at or below its own rank only for
    reading, except checks for its own rank or for viewers (what it is for)."""

    if ROLE_ORDER.get(role, -1) < ROLE_ORDER.get(min_role, 99):
        return False
    if role in READ_ONLY_ROLES and write and ROLE_ORDER.get(min_role, 99) > ROLE_ORDER["viewer"] and min_role not in READ_ONLY_ROLES:
        return False
    return True


def roles_meeting(min_role: str, *, write: bool) -> list[str]:
    """Every role that passes a ``min_role`` check (for checks made outside a request, such as the brain's tools)."""

    return [role for role in ROLE_ORDER if role_meets(role, min_role, write=write)]


def require_role(min_role: str | None = None, allow_list: list[str] | None = None) -> Callable[..., TenantContext]:
    def checker(request: Request, ctx: TenantContext = Depends(require_tenant)) -> TenantContext:
        role = ctx.role
        if allow_list and role in allow_list:
            return ctx
        write = str(request.method or "GET").upper() not in _READ_METHODS
        if min_role and role_meets(role, min_role, write=write):
            return ctx
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    return checker
