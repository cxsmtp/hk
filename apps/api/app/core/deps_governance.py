from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.tenant import TenantContext, require_tenant
from app.db.session import get_db
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError, enforce


def require_governance(
    *,
    db: Session,
    tenant_id: str,
    ai_system_id: str | None,
    action: str,
    route: str,
    module: str,
    tenant_scope: bool = False,
    commit_logs: bool = False,
    missing_ai_reason_code: str = "ai_system_id_missing",
    missing_ai_message: str = "ai_system_id is required",
    missing_ai_response_code: str = "governance_context_blocked",
):
    try:
        return enforce(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            action=action,
            route=route,
            module=module,
            tenant_scope=tenant_scope,
            commit_logs=commit_logs,
            missing_ai_reason_code=missing_ai_reason_code,
            missing_ai_message=missing_ai_message,
        )
    except GovernanceViolationError as exc:
        response_code = (
            missing_ai_response_code
            if exc.reason_code == missing_ai_reason_code
            else "governance_context_blocked"
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "code": response_code,
                "reason_code": exc.reason_code,
                "message": exc.message,
            },
        ) from exc
    except GovernanceFailSecureError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "governance_fail_secure",
                "reason_code": exc.reason_code,
                "message": exc.message,
            },
        ) from exc


def governance_payload_dependency(
    *,
    action: str,
    route: str,
    module: str,
    missing_ai_reason_code: str = "ai_system_id_missing",
    missing_ai_message: str = "ai_system_id is required",
    missing_ai_response_code: str = "governance_context_blocked",
) -> Callable[..., Any]:
    async def _dependency(
        request: Request,
        ctx: TenantContext = Depends(require_tenant),
        db: Session = Depends(get_db),
    ):
        body: dict[str, Any] = {}
        try:
            parsed = await request.json()
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            body = {}

        ai_system_id = body.get("ai_system_id")
        tenant_scope = bool(body.get("tenant_scope", False))
        return require_governance(
            db=db,
            tenant_id=ctx.tenant.id,
            ai_system_id=ai_system_id,
            action=action,
            route=route,
            module=module,
            tenant_scope=tenant_scope,
            commit_logs=True,
            missing_ai_reason_code=missing_ai_reason_code,
            missing_ai_message=missing_ai_message,
            missing_ai_response_code=missing_ai_response_code,
        )

    return _dependency
