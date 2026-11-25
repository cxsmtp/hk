"""Who may do what in a tenant: permission checks (FTR Command Center's server/rbac.js ``need``; CxMissionZero's
``requirePermission``).

Every route names the permission it needs with ``require_permission("discovery.view")``. What a person holds comes from
their role in the tenant (app/services/iam_service.py, resolved once per request in app/core/tenant.py), and the
built-in roles hold exactly what the old fixed role order let them do (app/core/permissions.py).

``require_role(min_role=..., allow_list=...)`` is kept as a thin compatibility wrapper for code written against the old
fixed roles: it asks for every permission of the matching level (a Viewer's, an Operator's, an Auditor's, an Admin's),
so a built-in role passes it exactly when it passed before, and a role someone made passes it only when it holds all of
that level. ``ROLE_ORDER``, ``role_meets`` and ``roles_meeting`` remain for code that still reasons in role names (the
assistant's tools, the MCP bridges), which is told the highest built-in role a person's permissions cover
(``TenantContext.role``).
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from app.core.permissions import INSPECT, LEVEL_ROLES, MANAGE, OPERATE, PERMISSION_BY_ID, PERMISSIONS, REVIEW, VIEW
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

REFUSED = "Your role does not allow that."


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


def legacy_level(min_role: str | None, allow_list: list[str] | None, *, write: bool) -> str | None:
    """The permission level an old role check stood for (app/core/permissions.py), or None when no role passes it."""

    if allow_list:
        wanted = frozenset(allow_list)
        for level, roles in LEVEL_ROLES.items():
            if roles == wanted:
                return level
        return None
    if not min_role:
        return None
    passing = frozenset(role for role in ROLE_ORDER if role_meets(role, min_role, write=write))
    for level, roles in LEVEL_ROLES.items():
        if roles == passing:
            return level
    return None


#: Every permission of each level: what require_role asks for.
LEVEL_PERMISSIONS: dict[str, frozenset[str]] = {
    level: frozenset(p.id for p in PERMISSIONS if p.level == level) for level in (VIEW, INSPECT, OPERATE, REVIEW, MANAGE)
}


def holds(ctx: TenantContext, *permission_ids: str) -> bool:
    held = getattr(ctx, "permissions", None)
    if held is None:
        # A context made without permissions (tests and bridges that build one by hand): its built-in role's.
        from app.core.permissions import default_permissions

        held = default_permissions(str(getattr(ctx, "role", "") or ""))
    return all(pid in held for pid in permission_ids)


def require_permission(*permission_ids: str) -> Callable[..., TenantContext]:
    """A dependency: the tenant context, when the person's role holds every one of these permissions; 403 otherwise."""

    unknown = [pid for pid in permission_ids if pid not in PERMISSION_BY_ID]
    if unknown or not permission_ids:
        raise ValueError(f"Unknown permission: {', '.join(unknown) or '(none)'}")

    def permission_checker(ctx: TenantContext = Depends(require_tenant)) -> TenantContext:
        if holds(ctx, *permission_ids):
            return ctx
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=REFUSED)

    permission_checker.permissions = tuple(permission_ids)  # type: ignore[attr-defined]  # read by tests
    return permission_checker


def require_role(min_role: str | None = None, allow_list: list[str] | None = None) -> Callable[..., TenantContext]:
    """Compatibility: an old role check, made as a permission check (every permission of the matching level)."""

    def checker(request: Request, ctx: TenantContext = Depends(require_tenant)) -> TenantContext:
        write = str(request.method or "GET").upper() not in _READ_METHODS
        level = legacy_level(min_role, allow_list, write=write)
        if level is not None:
            if holds(ctx, *LEVEL_PERMISSIONS[level]):
                return ctx
        # A check that is no level (allow_list=["owner"], min_role="owner"): judged on the built-in role the person's
        # permissions cover, as before.
        elif (allow_list and ctx.role in allow_list) or (min_role and role_meets(ctx.role, min_role, write=write)):
            return ctx
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    return checker
