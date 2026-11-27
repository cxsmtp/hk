"""Who may change what applies to the whole server: the installation's administrators.

Roles are per tenant (app/core/permissions.py), but some settings are kept once for the whole server: the password
rule, idle sign-out and sign-in notice, the compliance settings, the email server, HTTPS, the network and its trusted
certificates, updates, backups, hands-off, branding, the licence and the evidence signing key. A tenant's owners
and admins may read them (shown read-only in the console), but only the installation's administrators may change them:
the owners and admins (those who hold system.update) of the installation's first tenant, the one cases about the server
itself are raised in (app/services/self_check.py), as for the diagnostics bundle.

On a server with one tenant, its owners and admins are the installation's administrators: nothing changes for them.

``require_installation_admin("settings.manage")`` is a dependency: the tenant context when the person holds those
permissions (as ``require_permission``, 403 otherwise) and is an installation administrator; 403 with a plain sentence
otherwise, recorded in the audit log as refused.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.rbac import holds, require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db

#: The sentence a refused change answers with (the console shows it as is).
INSTALLATION_ONLY = (
    "This setting applies to the whole server: only the server's administrators (the owners and admins of its first "
    "workspace) can change it."
)
#: The note the console shows beside these settings for everyone else.
SET_BY_SERVER = "Set by the server's administrators."


def default_tenant(db: Any) -> str | None:
    from app.services.self_check import SelfCheck

    return SelfCheck.default_tenant(db)


def is_installation_admin(db: Any, ctx: Any) -> bool:
    """The owners and admins (those who hold system.update) of the installation's first tenant."""

    return holds(ctx, "system.update") and bool(getattr(ctx, "tenant", None)) and ctx.tenant.id == default_tenant(db)


def refuse(db: Session, ctx: TenantContext, *, what: str, method: str = "") -> HTTPException:
    """Record the refusal in the audit log (committed) and return the 403 to raise."""

    from app.services.audit_service import write_audit_log

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="settings.installation.refused",
        resource_type="installation_setting",
        resource_id=(what or "-")[:128],
        payload={
            "outcome": "refused",
            "reason": f"{(ctx.user.email if ctx.user else 'Someone')} tried to change a setting of the whole server ({method} {what}); only the server's administrators may.".strip(),
            "method": method,
            "path": what,
        },
    )
    db.commit()
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=INSTALLATION_ONLY)


def require_installation_admin(*permission_ids: str) -> Callable[..., TenantContext]:
    """A dependency: the tenant context when the person holds these permissions and is one of the installation's
    administrators; 403 otherwise (recorded in the audit log when only the second fails)."""

    permitted = require_permission(*permission_ids)

    def installation_admin_checker(request: Request, ctx: TenantContext = Depends(permitted), db: Session = Depends(get_db)) -> TenantContext:
        if is_installation_admin(db, ctx):
            return ctx
        raise refuse(db, ctx, what=str(request.url.path), method=str(request.method or "").upper())

    installation_admin_checker.permissions = tuple(permission_ids)  # type: ignore[attr-defined]  # read by tests
    installation_admin_checker.installation = True  # type: ignore[attr-defined]  # read by tests
    return installation_admin_checker


__all__ = ["INSTALLATION_ONLY", "SET_BY_SERVER", "default_tenant", "is_installation_admin", "refuse", "require_installation_admin"]
