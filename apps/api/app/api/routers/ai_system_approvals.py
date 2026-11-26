"""The approval workflow for AI systems (app/services/ai_system_approval_service.py).

- GET /settings/ai-system-approvals: the tenant's policy by risk tier, the defaults and the roles that exist. Anyone
  who sees the inventory may read it (to know what an approval needs). PUT: owners and admins (settings.manage).
- POST /ai-systems/{id}/approval-requests (app/api/routers/ai_systems.py): ask for an approval.
- GET /ai-system-approvals: the requests (pending by default); each says whether the person asking may approve it.
- POST /ai-system-approvals/{id}/decision: approve (choosing the scope within the policy, on the first approval) or
  deny. The route is open to everyone who sees the inventory; the policy's approver roles, the distinct-approver count
  and the self-approval rule decide.
- GET /ai-system-approvals/grants and POST /ai-system-approvals/grants/{id}/revoke: standing approvals, and revoking
  one (the tier's approvers, or owners and admins).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac import holds, require_permission
from app.core.tenant import TenantContext
from app.db.models.ai_system import AISystem
from app.db.models.ai_system_approval import AISystemApprovalGrant
from app.db.models.policy import ApprovalRequest
from app.db.session import get_db
from app.services import ai_system_approval_service as approvals
from app.services.audit_service import write_audit_log


router = APIRouter(tags=["ai-system-approvals"])

REQUEST_STATUSES = ("pending", "approved", "denied", "expired")
GRANT_STATES = ("ACTIVE", "CONSUMED", "EXPIRED", "REVOKED", "SUPERSEDED")


class ApprovalDecisionBody(BaseModel):
    decision: str = Field(pattern="^(approve|deny)$")
    scope: str | None = Field(default=None, max_length=16)
    duration_hours: int | None = Field(default=None, ge=1, le=approvals.MAX_DURATION_HOURS)
    reason: str | None = Field(default=None, max_length=500)


class RevokeBody(BaseModel):
    reason: str | None = Field(default=None, max_length=255)


def refused(error: approvals.ApprovalWorkflowError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={"error": error.message, "detail": {"code": error.code, "message": error.message}},
    )


def _user_id(ctx: TenantContext) -> str | None:
    user = getattr(ctx, "user", None)
    return str(user.id) if user is not None and getattr(user, "id", None) else None


def _role(ctx: TenantContext) -> str:
    return str(getattr(ctx, "role_key", None) or getattr(ctx, "role", "") or "")


# ---- The policy -----------------------------------------------------------------------------------------------------


@router.get("/settings/ai-system-approvals")
def get_policy(ctx: TenantContext = Depends(require_permission("discovery.view")), db: Session = Depends(get_db)):
    view = approvals.policy_view(db, ctx.tenant.id)
    view["may_manage"] = holds(ctx, "settings.manage")
    return view


@router.put("/settings/ai-system-approvals")
def put_policy(
    body: dict[str, Any] | None = Body(default=None),
    ctx: TenantContext = Depends(require_permission("settings.manage")),
    db: Session = Depends(get_db),
):
    user = getattr(ctx, "user", None)
    try:
        saved = approvals.save_policy(db, ctx.tenant.id, body or {}, by=(getattr(user, "email", "") or "") if user else "")
    except approvals.ApprovalWorkflowError as error:
        db.rollback()
        return refused(error)
    after = saved["view"]["policy"]
    changed = sorted(tier for tier in approvals.TIERS if saved["before"]["tiers"][tier] != after["tiers"][tier])
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=_user_id(ctx),
        actor_type="human",
        action="settings.ai_system_approvals",
        resource_type="settings",
        resource_id="ai_system_approvals",
        payload={
            "outcome": "changed",
            "reason": "AI system approval policy: " + (", ".join(changed) + " changed" if changed else "no tier changed") + ".",
            "changed_tiers": changed,
            "before": {tier: saved["before"]["tiers"][tier] for tier in changed},
            "after": {tier: after["tiers"][tier] for tier in changed},
            "request_ttl_hours": after["request_ttl_hours"],
            "revision": saved["view"]["revision"],
        },
    )
    db.commit()
    view = approvals.policy_view(db, ctx.tenant.id)
    view["may_manage"] = True
    return view


# ---- Requests and decisions -----------------------------------------------------------------------------------------


def _systems(db: Session, tenant_id: str, ids: set[str]) -> dict[str, AISystem]:
    if not ids:
        return {}
    return {row.id: row for row in db.scalars(select(AISystem).where(AISystem.tenant_id == tenant_id, AISystem.id.in_(ids)))}


@router.get("/ai-system-approvals")
def list_requests(
    status: str = "pending",
    ai_system_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    wanted = REQUEST_STATUSES if status == "all" else (status,)
    if any(item not in REQUEST_STATUSES for item in wanted):
        return refused(approvals.ApprovalWorkflowError("status is pending, approved, denied, expired or all.", status_code=400, code="invalid_status"))
    query = select(ApprovalRequest).where(ApprovalRequest.tenant_id == ctx.tenant.id, ApprovalRequest.status.in_(wanted))
    if ai_system_id:
        query = query.where(ApprovalRequest.ai_system_id == ai_system_id)
    rows = [row for row in db.scalars(query.order_by(ApprovalRequest.created_at.desc()).limit(500)) if approvals.is_ai_system_approval_request(row)]
    systems = _systems(db, ctx.tenant.id, {row.ai_system_id for row in rows})
    items = [
        approvals.request_view(row, system=systems.get(row.ai_system_id), actor_user_id=_user_id(ctx), actor_role=_role(ctx))
        for row in rows
    ]
    return {"items": items, "total": len(items)}


@router.post("/ai-system-approvals/{request_id}/decision")
def decide_request(
    request_id: str,
    body: ApprovalDecisionBody,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    actor = _user_id(ctx)
    try:
        request, grant = approvals.decide(
            db,
            tenant_id=ctx.tenant.id,
            request_id=request_id,
            actor_user_id=actor,
            actor_role=_role(ctx),
            decision=body.decision,
            scope=body.scope,
            duration_hours=body.duration_hours,
            reason=body.reason,
        )
    except approvals.ApprovalWorkflowError as error:
        if error.code == "request_expired":
            # The expiry is a decision of its own: kept, not rolled back with the refused approval.
            db.commit()
            return refused(error)
        db.rollback()
        if error.code != "not_found":
            row = db.scalar(select(ApprovalRequest).where(ApprovalRequest.tenant_id == ctx.tenant.id, ApprovalRequest.id == request_id))
            if row is not None:
                approvals.record_refusal(
                    db,
                    tenant_id=ctx.tenant.id,
                    actor_user_id=actor,
                    ai_system_id=row.ai_system_id,
                    error=error,
                    step=f"decision.{body.decision}",
                    extra={"approval_request_id": request_id},
                )
                db.commit()
        return refused(error)
    db.commit()
    system = db.scalar(select(AISystem).where(AISystem.tenant_id == ctx.tenant.id, AISystem.id == request.ai_system_id))
    return {
        "request": approvals.request_view(request, system=system, actor_user_id=actor, actor_role=_role(ctx)),
        "grant": approvals.grant_view(grant, system=system) if grant is not None else None,
        "ai_system_status": system.status if system is not None else None,
    }


# ---- Standing approvals -------------------------------------------------------------------------------------------


@router.get("/ai-system-approvals/grants")
def list_grants(
    state: str = "ACTIVE",
    ai_system_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    wanted = GRANT_STATES if state.lower() == "all" else (state.upper(),)
    if any(item not in GRANT_STATES for item in wanted):
        return refused(approvals.ApprovalWorkflowError("state is ACTIVE, CONSUMED, EXPIRED, REVOKED, SUPERSEDED or all.", status_code=400, code="invalid_state"))
    query = select(AISystemApprovalGrant).where(AISystemApprovalGrant.tenant_id == ctx.tenant.id, AISystemApprovalGrant.state.in_(wanted))
    if ai_system_id:
        query = query.where(AISystemApprovalGrant.ai_system_id == ai_system_id)
    rows = list(db.scalars(query.order_by(AISystemApprovalGrant.created_at.desc()).limit(500)))
    systems = _systems(db, ctx.tenant.id, {row.ai_system_id for row in rows})
    items = [approvals.grant_view(row, system=systems.get(row.ai_system_id)) for row in rows]
    return {"items": items, "total": len(items)}


@router.post("/ai-system-approvals/grants/{grant_id}/revoke")
def revoke(
    grant_id: str,
    body: RevokeBody | None = None,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    actor = _user_id(ctx)
    try:
        grant = approvals.revoke_grant(
            db,
            tenant_id=ctx.tenant.id,
            grant_id=grant_id,
            actor_user_id=actor,
            actor_role=_role(ctx),
            may_manage=holds(ctx, "settings.manage"),
            reason=(body.reason if body else None),
        )
    except approvals.ApprovalWorkflowError as error:
        db.rollback()
        if error.code != "not_found":
            row = db.scalar(select(AISystemApprovalGrant).where(AISystemApprovalGrant.tenant_id == ctx.tenant.id, AISystemApprovalGrant.id == grant_id))
            if row is not None:
                approvals.record_refusal(db, tenant_id=ctx.tenant.id, actor_user_id=actor, ai_system_id=row.ai_system_id, error=error, step="revoke", extra={"grant_id": grant_id})
                db.commit()
        return refused(error)
    db.commit()
    system = db.scalar(select(AISystem).where(AISystem.tenant_id == ctx.tenant.id, AISystem.id == grant.ai_system_id))
    return {"grant": approvals.grant_view(grant, system=system), "ai_system_status": system.status if system is not None else None}
