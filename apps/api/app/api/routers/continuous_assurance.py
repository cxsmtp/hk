"""Read-only, tenant-scoped Phase 6 continuous-assurance API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.continuous_assurance import (
    ControlAssertion,
    DriftSignal,
    ValidationEvidenceBundle,
    ValidationRemediation,
    ValidationRun,
)
from app.db.session import get_db


router = APIRouter(prefix="/continuous-assurance", tags=["continuous-assurance"])


def _run_projection(db: Session, *, tenant_id: str, assertion_id: str) -> dict[str, object] | None:
    run = db.scalar(
        select(ValidationRun)
        .where(
            ValidationRun.tenant_id == tenant_id,
            ValidationRun.assertion_id == assertion_id,
        )
        .order_by(ValidationRun.started_at.desc(), ValidationRun.id.desc())
    )
    if run is None:
        return None
    evidence = (
        db.scalar(
            select(ValidationEvidenceBundle).where(
                ValidationEvidenceBundle.tenant_id == tenant_id,
                ValidationEvidenceBundle.id == run.evidence_bundle_id,
            )
        )
        if run.evidence_bundle_id
        else None
    )
    return {
        "run_id": run.id,
        "status": run.status,
        "outcome": run.outcome,
        "reason_codes": list(run.reason_codes or []),
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "evidence_quality": evidence.evidence_quality if evidence is not None else None,
        "evidence_refs": list(evidence.evidence_refs or []) if evidence is not None else [],
    }


def _assertion_projection(db: Session, *, assertion: ControlAssertion) -> dict[str, object]:
    tenant_id = assertion.tenant_id
    drift_rows = tuple(
        row
        for row in db.scalars(
            select(DriftSignal)
            .where(DriftSignal.tenant_id == tenant_id)
            .order_by(DriftSignal.observed_at.desc(), DriftSignal.id.desc())
        ).all()
        if assertion.id in set(row.affected_assertion_ids or [])
    )
    remediation_rows = tuple(
        db.scalars(
            select(ValidationRemediation)
            .where(
                ValidationRemediation.tenant_id == tenant_id,
                ValidationRemediation.assertion_id == assertion.id,
            )
            .order_by(ValidationRemediation.created_at.desc(), ValidationRemediation.id.desc())
        ).all()
    )
    return {
        "assertion_id": assertion.id,
        "assertion_key": assertion.assertion_key,
        "assertion_type": assertion.assertion_type,
        "asset_ref": assertion.asset_ref,
        "action_class": assertion.action_class,
        "required_capability": assertion.required_capability,
        "expected_outcome": assertion.expected_outcome,
        "required_evidence_level": assertion.required_evidence_level,
        "assurance_state": assertion.assurance_state,
        "assurance_version": assertion.assurance_version,
        "last_validated_at": assertion.last_validated_at,
        "fresh_until": assertion.fresh_until,
        "dependencies": [
            {
                "category": item.dependency_category,
                "key": item.dependency_key,
                "current_digest": item.current_digest,
            }
            for item in assertion.dependencies
        ],
        "last_validation": _run_projection(
            db, tenant_id=tenant_id, assertion_id=assertion.id
        ),
        "drift": [
            {
                "signal_id": row.id,
                "category": row.category,
                "dependency_key": row.dependency_key,
                "source_ref": row.source_ref,
                "status": row.status,
                "observed_at": row.observed_at,
            }
            for row in drift_rows
        ],
        "remediation": [
            {
                "remediation_id": row.id,
                "state": row.state,
                "reason": row.reason,
                "revalidation_required": row.revalidation_required,
                "resolved_validation_run_id": row.resolved_validation_run_id,
            }
            for row in remediation_rows
        ],
    }


@router.get("/assertions")
def assertions(
    state: str | None = Query(default=None),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    query = select(ControlAssertion).where(ControlAssertion.tenant_id == ctx.tenant.id)
    if state:
        normalized = state.strip().upper()
        if normalized not in {"UNKNOWN", "CURRENT", "STALE", "REGRESSED"}:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid assurance state")
        query = query.where(ControlAssertion.assurance_state == normalized)
    rows = tuple(db.scalars(query.order_by(ControlAssertion.updated_at.desc())).all())
    return {
        "tenant_id": ctx.tenant.id,
        "count": len(rows),
        "items": [_assertion_projection(db, assertion=row) for row in rows],
    }


@router.get("/assertions/{assertion_id}")
def assertion_detail(
    assertion_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    row = db.scalar(
        select(ControlAssertion).where(
            ControlAssertion.tenant_id == ctx.tenant.id,
            ControlAssertion.id == assertion_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assurance assertion not found")
    return _assertion_projection(db, assertion=row)
