"""Bounded, feature-gated Maturity Curve materialization jobs."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from app.core.config import parse_maturity_curve_rollout, settings
from app.db.models.maturity_curve import MaturityPolicyRollout, MaturityScope, TenantMaturityEntitlement
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.job_run_service import tracked_scheduled_job
from app.services.maturity_curve.effectiveness import materialize_policy_effectiveness
from app.services.maturity_curve.entitlements import MaturityEntitlementError
from app.services.maturity_curve.executive import materialize_executive_snapshot
from app.services.maturity_curve.recommendations import generate_policy_recommendations
from app.services.maturity_curve.service import materialize_maturity_scope


MAX_SCOPES_PER_REFRESH = 100


def maturity_curve_enabled_for_tenant(tenant_id: str) -> bool:
    if not settings.maturity_curve_policy_intelligence:
        return False
    rollout = parse_maturity_curve_rollout(settings.maturity_curve_policy_intelligence_rollout)
    return rollout.get(str(tenant_id or "").strip()) is True


@celery_app.task(name="app.jobs.maturity_curve_jobs.refresh_maturity_curve")
def refresh_maturity_curve(tenant_id: str) -> dict[str, object]:
    if not maturity_curve_enabled_for_tenant(tenant_id):
        return {"tenant_id": tenant_id, "status": "disabled", "scopes": 0}
    with tracked_scheduled_job("maturity_curve_refresh", tenant_id=tenant_id):
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active.is_(True)))
            entitlement = db.scalar(
                select(TenantMaturityEntitlement).where(TenantMaturityEntitlement.tenant_id == tenant_id)
            )
            if tenant is None:
                return {"tenant_id": tenant_id, "status": "tenant_not_found", "scopes": 0}
            if entitlement is None or not entitlement.enabled:
                return {"tenant_id": tenant_id, "status": "not_entitled", "scopes": 0}
            scopes = list(
                db.scalars(
                    select(MaturityScope)
                    .where(MaturityScope.tenant_id == tenant_id, MaturityScope.active.is_(True))
                    .order_by(MaturityScope.scope_type.asc(), MaturityScope.id.asc())
                    .limit(MAX_SCOPES_PER_REFRESH)
                ).all()
            )
            results: dict[str, int] = {"scopes": 0, "recommendations": 0, "effectiveness": 0}
            try:
                for scope in scopes:
                    materialized = materialize_maturity_scope(
                        db,
                        tenant_id=tenant_id,
                        scope_id=scope.id,
                        now=datetime.now(timezone.utc),
                    )
                    results["scopes"] += 1
                    recommendations = generate_policy_recommendations(
                        db,
                        tenant_id=tenant_id,
                        scope_id=scope.id,
                        assessment_id=materialized.assessment.id,
                        baseline_id=materialized.baseline.id,
                    )
                    results["recommendations"] += len(recommendations)
                rollouts = list(
                    db.scalars(
                        select(MaturityPolicyRollout).where(
                            MaturityPolicyRollout.tenant_id == tenant_id,
                            MaturityPolicyRollout.state.in_(("ENFORCE", "MONITOR")),
                        )
                    ).all()
                )
                for rollout in rollouts:
                    try:
                        materialize_policy_effectiveness(
                            db,
                            tenant_id=tenant_id,
                            rollout_id=rollout.id,
                            now=datetime.now(timezone.utc),
                        )
                        results["effectiveness"] += 1
                    except MaturityEntitlementError:
                        # Secure/Control tenants retain visibility and drafts;
                        # Assurance-only evidence is simply not materialized.
                        break
                organization_scope = next((scope for scope in scopes if scope.scope_type == "organization"), None)
                if organization_scope is not None:
                    materialize_executive_snapshot(db, tenant_id=tenant_id, scope_id=organization_scope.id)
                db.commit()
            except Exception:
                db.rollback()
                raise
            return {"tenant_id": tenant_id, "status": "success", **results}


@celery_app.task(name="app.jobs.maturity_curve_jobs.enqueue_maturity_curve_refreshes")
def enqueue_maturity_curve_refreshes() -> dict[str, object]:
    if not settings.maturity_curve_policy_intelligence:
        return {"status": "disabled", "enqueued": 0, "tenant_ids": []}
    rollout = parse_maturity_curve_rollout(settings.maturity_curve_policy_intelligence_rollout)
    enabled_ids = sorted(tenant_id for tenant_id, enabled in rollout.items() if enabled)
    if not enabled_ids:
        return {"status": "disabled", "enqueued": 0, "tenant_ids": []}
    with SessionLocal() as db:
        tenant_ids = sorted(
            db.scalars(
                select(Tenant.id).where(Tenant.id.in_(enabled_ids), Tenant.is_active.is_(True))
            ).all()
        )
    for tenant_id in tenant_ids:
        refresh_maturity_curve.delay(tenant_id)
    return {"status": "enqueued", "enqueued": len(tenant_ids), "tenant_ids": tenant_ids}
