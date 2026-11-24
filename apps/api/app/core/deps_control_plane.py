from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.tenant import TenantContext, require_tenant
from app.db.session import SessionLocal, get_db
from app.services.audit_service import write_audit_log
from app.services.control_plane_health_service import ControlPlaneHealthReport, evaluate_control_plane_health
from app.services.evidence_service import create_evidence_node


def _extract_ai_system_id(request: Request) -> str | None:
    from_query = request.query_params.get("ai_system_id")
    if from_query:
        return str(from_query)

    from_path = request.path_params.get("ai_system_id")
    if isinstance(from_path, str) and from_path:
        return from_path
    return None


async def _extract_ai_system_id_from_payload(request: Request) -> str | None:
    in_request = _extract_ai_system_id(request)
    if in_request:
        return in_request

    content_type = str(request.headers.get("content-type", "")).lower()
    if "application/json" not in content_type:
        return None

    try:
        body = await request.json()
    except Exception:
        return None
    if isinstance(body, dict):
        value = body.get("ai_system_id")
        if value:
            return str(value)
    return None


def _write_fail_secure_event(
    *,
    db: Session,
    tenant_id: str,
    ai_system_id: str | None,
    module: str,
    route: str,
    correlation_id: str | None,
    report: ControlPlaneHealthReport,
) -> tuple[str | None, str | None]:
    payload: dict[str, Any] = {
        "reason_code": "control_plane_unhealthy",
        "tenant_id": tenant_id,
        "ai_system_id": ai_system_id,
        "route": route,
        "module": module,
        "correlation_id": correlation_id,
        "failed_checks": report.failing_required_checks(),
        "required_checks": report.required_checks,
        "checks": report.to_dict()["checks"],
    }

    def _write(session: Session) -> tuple[str, str]:
        audit = write_audit_log(
            session,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action="governance.fail_secure.blocked",
            resource_type="control_plane_module",
            resource_id=module,
            payload=payload,
            correlation_id=correlation_id,
        )
        evidence = create_evidence_node(
            session,
            tenant_id=tenant_id,
            node_type="control_plane_fail_secure",
            signal_type="governance.fail_secure.blocked",
            label=f"Control plane fail-secure block for {module}",
            payload=payload,
            correlation_id=correlation_id,
        )
        session.commit()
        return audit.id, evidence.id

    try:
        return _write(db)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    try:
        with SessionLocal() as fallback_db:
            return _write(fallback_db)
    except Exception:
        return None, None


def require_control_plane_healthy(*, module: str) -> Callable[..., Any]:
    async def _dependency(
        request: Request,
        ctx: TenantContext = Depends(require_tenant),
        db: Session = Depends(get_db),
    ) -> None:
        if settings.gateway_intercept_minimal_mode and request.url.path in {
            "/gateway/llm/intercept",
            "/gateway/mcp/authorize",
        }:
            return

        report = evaluate_control_plane_health(db)
        if report.healthy:
            return

        ai_system_id = await _extract_ai_system_id_from_payload(request)
        correlation_id = getattr(request.state, "correlation_id", None)
        audit_log_id, evidence_node_id = _write_fail_secure_event(
            db=db,
            tenant_id=ctx.tenant.id,
            ai_system_id=ai_system_id,
            module=module,
            route=request.url.path,
            correlation_id=correlation_id,
            report=report,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "governance_fail_secure",
                "message": "Governance unavailable - fail secure",
                "module": module,
                "failed_checks": report.failing_required_checks(),
                "audit_log_id": audit_log_id,
                "evidence_node_id": evidence_node_id,
            },
        )

    return _dependency
