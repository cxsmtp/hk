from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.ai_system import AISystem
from app.services.audit_service import write_audit_log
from app.services.control_plane_health_service import control_plane_module_status, evaluate_control_plane_health
from app.services.evidence_service import create_evidence_node
from app.services.job_run_service import write_scheduled_job_run


BLOCKED_LIFECYCLE_STATES = {"prohibited", "blocked"}


def check_db_connectivity(db: Session) -> None:
    db.execute(text("SELECT 1"))


#: Documented reasons a route may run the fail-secure check without an AI-system context. Missing context is denied
#: (fail closed) unless the call site names one of these explicitly: there is no global allow.
#: - ``tenant_registry``: reading or administering the tenant's AI IAM registry (agents, identities, users, purpose
#:   sessions) is not an action of any one AI system; the database check still applies.
#: - ``containment``: revoking a token or using an agent's kill switch must stay possible whichever AI system the
#:   agent served; the database check still applies.
NO_AI_SYSTEM_CONTEXT_REASONS = frozenset({"tenant_registry", "containment"})


class UnregisteredAISystemBlock(Exception):
    """The fail-secure check denied because the tenant has no such AI system.

    That is a governance decision, not an outage. ``enforce_fail_secure_or_raise`` raises this instead of the 503 only
    when the call site asks with ``unknown_ai_system_is_governance_block``, and the caller must turn it into a denial
    (see ``enforce_gateway_fail_secure_or_raise``). Left uncaught it is still a denial, never an allow."""

    def __init__(self, ai_system_id: str | None) -> None:
        super().__init__("ai_system_not_found")
        self.ai_system_id = ai_system_id


def validate_governance_context(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    no_ai_system_context_reason: str | None = None,
) -> tuple[bool, str]:
    """Whether the governance context lets the action go ahead: ``(ok, reason)``.

    Fails closed: no AI system given, or one this tenant does not have, is a denial. A route that genuinely acts
    without an AI system passes ``no_ai_system_context_reason`` (one of NO_AI_SYSTEM_CONTEXT_REASONS); should it
    give an ``ai_system_id`` all the same, that AI system is checked like any other."""

    if not ai_system_id:
        if no_ai_system_context_reason is None:
            return False, "no_ai_system_context"
        if no_ai_system_context_reason not in NO_AI_SYSTEM_CONTEXT_REASONS:
            return False, "invalid_no_ai_system_context_reason"
        return True, f"not_ai_system_scoped:{no_ai_system_context_reason}"

    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if ai_system is None:
        return False, "ai_system_not_found"

    if not ai_system.risk_tier:
        return False, "risk_tier_missing"

    if str(ai_system.risk_tier).upper() == "PROHIBITED":
        return False, "risk_tier_prohibited"

    lifecycle = (ai_system.status or "").strip().lower()
    if lifecycle in BLOCKED_LIFECYCLE_STATES:
        return False, f"lifecycle_{lifecycle}"

    return True, "ok"


def queue_auditor_fail_secure_job(
    *,
    tenant_id: str,
    ai_system_id: str | None,
    module: str,
    reason: str,
    request_id: str | None,
) -> dict[str, Any]:
    queued = False
    queue_error: str | None = None

    try:
        from app.jobs.auditor_jobs import export_audit_snapshot

        export_audit_snapshot.apply_async(
            kwargs={"tenant_id": tenant_id, "ai_system_id": ai_system_id},
            queue="auditor",
        )
        queued = True
    except Exception as exc:  # pragma: no cover - broker availability varies by environment
        queue_error = str(exc)

    started = datetime.now(timezone.utc)
    try:
        write_scheduled_job_run(
            job_name="fail_secure_auditor_snapshot",
            tenant_id=tenant_id,
            started_at=started,
            finished_at=started,
            status="queued" if queued else "fail",
            error_message=queue_error,
        )
    except Exception:  # pragma: no cover - best effort tracking
        pass

    return {"queued": queued, "error": queue_error}


def _module_fail_secure_message(module: str) -> str:
    if module == "gateway":
        return "Governance unavailable - fail secure"
    if module == "ai_iam":
        return "AI IAM unavailable - fail secure"
    if module == "simulations":
        return "Simulations suspended - fail secure"
    return "Control plane unavailable - fail secure"


def _best_effort_record_fail_secure_event(
    db: Session,
    *,
    tenant_id: str,
    module: str,
    reason: str,
    request_id: str | None,
    ai_system_id: str | None,
) -> tuple[str | None, str | None]:
    try:
        audit = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action="governance.fail_secure.blocked",
            resource_type="control_plane_module",
            resource_id=module,
            payload={
                "module": module,
                "reason": reason,
                "request_id": request_id,
                "ai_system_id": ai_system_id,
            },
        )
        node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="control_plane_fail_secure",
            signal_type="governance.fail_secure.blocked",
            label=f"Fail-secure block for {module}",
            payload={
                "module": module,
                "reason": reason,
                "request_id": request_id,
                "ai_system_id": ai_system_id,
            },
        )
        db.commit()
        return audit.id, node.id
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None, None


def _raise_fail_secure(
    *,
    db: Session,
    tenant_id: str,
    module: str,
    reason: str,
    request_id: str | None,
    ai_system_id: str | None,
) -> None:
    queue_info = queue_auditor_fail_secure_job(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        module=module,
        reason=reason,
        request_id=request_id,
    )
    audit_log_id, evidence_node_id = _best_effort_record_fail_secure_event(
        db,
        tenant_id=tenant_id,
        module=module,
        reason=reason,
        request_id=request_id,
        ai_system_id=ai_system_id,
    )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "code": "fail_secure_block",
            "message": _module_fail_secure_message(module),
            "module": module,
            "reason": reason,
            "request_id": request_id,
            "auditor_job_queued": bool(queue_info.get("queued")),
            "audit_log_id": audit_log_id,
            "evidence_node_id": evidence_node_id,
        },
    )


def enforce_fail_secure_or_raise(
    db: Session,
    *,
    tenant_id: str,
    module: str,
    ai_system_id: str | None = None,
    request_id: str | None = None,
    no_ai_system_context_reason: str | None = None,
    unknown_ai_system_is_governance_block: bool = False,
) -> None:
    """Raise 503 ``fail_secure_block`` unless the database answers and the governance context is valid.

    With ``unknown_ai_system_is_governance_block`` an AI system the tenant does not have raises
    ``UnregisteredAISystemBlock`` instead of the 503, so the caller can answer with its governance 403; it is denied
    either way.

    Without an AI system this denies (``governance_context_failed:no_ai_system_context``) unless the call site states
    why it has none with ``no_ai_system_context_reason`` (see NO_AI_SYSTEM_CONTEXT_REASONS)."""

    if not settings.fail_secure_mode:
        return

    try:
        check_db_connectivity(db)
    except SQLAlchemyError:
        _raise_fail_secure(
            db=db,
            tenant_id=tenant_id,
            module=module,
            reason="db_unavailable",
            request_id=request_id,
            ai_system_id=ai_system_id,
        )

    try:
        governance_ok, governance_reason = validate_governance_context(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            no_ai_system_context_reason=no_ai_system_context_reason,
        )
    except SQLAlchemyError:
        _raise_fail_secure(
            db=db,
            tenant_id=tenant_id,
            module=module,
            reason="governance_query_failed",
            request_id=request_id,
            ai_system_id=ai_system_id,
        )
        return

    if not governance_ok:
        if unknown_ai_system_is_governance_block and governance_reason == "ai_system_not_found":
            raise UnregisteredAISystemBlock(ai_system_id)
        _raise_fail_secure(
            db=db,
            tenant_id=tenant_id,
            module=module,
            reason=f"governance_context_failed:{governance_reason}",
            request_id=request_id,
            ai_system_id=ai_system_id,
        )


def enforce_gateway_fail_secure_or_raise(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    request_id: str | None,
    governance_route: str,
    governance_action: str,
    module: str = "gateway",
) -> None:
    """The fail-secure check for gateway and LLM-gateway routes.

    Genuine governance-unavailable reasons (database down, governance query failed, no AI-system context, missing risk
    tier, blocked lifecycle) stay a 503 ``fail_secure_block``. An AI system the tenant does not have is a governance
    decision: the governance guard records it as shadow-AI usage and the route answers with the guard's 403
    ``governance_context_blocked`` contract (``reason_code`` ``ai_system_not_registered``). Every path denies; should
    the guard not block, the 403 is raised all the same."""

    try:
        enforce_fail_secure_or_raise(
            db,
            tenant_id=tenant_id,
            module=module,
            ai_system_id=ai_system_id,
            request_id=request_id,
            unknown_ai_system_is_governance_block=True,
        )
    except UnregisteredAISystemBlock:
        _raise_unregistered_ai_system_block(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            governance_route=governance_route,
            governance_action=governance_action,
        )


def _raise_unregistered_ai_system_block(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    governance_route: str,
    governance_action: str,
) -> None:
    from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError
    from app.services.governance_guard import enforce as enforce_governance

    reason_code = "ai_system_not_registered"
    message = "Governance context blocked"
    try:
        enforce_governance(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            action=governance_action,
            route=governance_route,
            module="gateway_service",
            commit_logs=True,
        )
    except GovernanceViolationError as exc:
        reason_code = exc.reason_code or reason_code
        message = exc.message or message
    except GovernanceFailSecureError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except Exception:
        # Recording the shadow usage failed: still a denial, with the registration contract.
        try:
            db.rollback()
        except Exception:
            pass
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "governance_context_blocked", "reason_code": reason_code, "message": message},
    )


def get_control_plane_health(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None = None,
) -> dict[str, str]:
    del tenant_id, ai_system_id
    report = evaluate_control_plane_health(db)
    return control_plane_module_status(report)
