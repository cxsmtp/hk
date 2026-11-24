"""Derived effectiveness evidence for an already-enforced maturity rollout."""

from __future__ import annotations

from collections import Counter
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.maturity_curve import (
    MaturityPolicyEffectivenessSnapshot,
    MaturityPolicyRollout,
    MaturityScope,
)
from app.db.models.policy import PolicyVersion
from app.services.maturity_curve.entitlements import require_maturity_capability
from app.services.maturity_curve.service import _bounded_refs, _canonical_digest, materialize_maturity_scope
from app.services.maturity_curve.simulation import _policy_context
from app.services.policy_scope_service import resolve_scoped_policy_decision


_PROTECTED_DECISIONS = {"block", "require_approval", "hold_for_approval", "require_justification"}
_NON_PREVENTIVE_OBSERVED = {"", "allow", "allowed", "warn", "warning", "monitor"}


def materialize_policy_effectiveness(
    db: Session,
    *,
    tenant_id: str,
    rollout_id: str,
    now: datetime | None = None,
) -> MaturityPolicyEffectivenessSnapshot:
    """Compare the current policy's expected result with action metadata.

    ``REGRESSED`` is evidence of an expected high-assurance decision that was
    observed as non-preventive.  The service records the discrepancy; it never
    relaxes a policy or silently changes a rollout.
    """

    require_maturity_capability(db, tenant_id=tenant_id, capability="effectiveness")
    rollout = db.scalar(
        select(MaturityPolicyRollout).where(
            MaturityPolicyRollout.tenant_id == tenant_id,
            MaturityPolicyRollout.id == rollout_id,
        )
    )
    if rollout is None:
        raise ValueError("maturity_rollout_not_found")
    if str(rollout.state or "").upper() not in {"ENFORCE", "MONITOR"} or not rollout.policy_version_id:
        raise ValueError("maturity_effectiveness_requires_enforced_rollout")
    scope = db.scalar(
        select(MaturityScope).where(
            MaturityScope.tenant_id == tenant_id,
            MaturityScope.id == rollout.scope_id,
        )
    )
    version = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyVersion.id == rollout.policy_version_id,
        )
    )
    if scope is None or version is None:
        raise ValueError("maturity_effectiveness_policy_context_not_found")

    materialized = materialize_maturity_scope(db, tenant_id=tenant_id, scope_id=scope.id, now=now)
    from app.services.maturity_curve.recommendations import _scoped_window_projections

    projections = _scoped_window_projections(
        db,
        tenant_id=tenant_id,
        scope=scope,
        window=materialized.observation_window,
    )
    expected_counts: Counter[str] = Counter()
    observed_counts: Counter[str] = Counter()
    mismatch_count = 0
    unknown_count = 0
    action_rows: list[tuple[str, str, str]] = []
    for projection in projections:
        resolution = resolve_scoped_policy_decision(
            db,
            tenant_id=tenant_id,
            policy_version_id=version.id,
            context=_policy_context(projection),
        )
        expected = resolution.decision if resolution.matched else "unknown"
        observed = str(projection.get("decision") or "unknown").strip().lower()
        expected_counts[expected] += 1
        observed_counts[observed] += 1
        if expected == "unknown":
            unknown_count += 1
        if expected in _PROTECTED_DECISIONS and observed in _NON_PREVENTIVE_OBSERVED:
            mismatch_count += 1
        action_rows.append((str(projection["action_id"]), expected, observed))

    input_digest = _canonical_digest(
        {
            "rollout_id": rollout.id,
            "policy_version_id": version.id,
            "window_id": materialized.observation_window.id,
            "action_results": action_rows,
        }
    )
    existing = db.scalar(
        select(MaturityPolicyEffectivenessSnapshot).where(
            MaturityPolicyEffectivenessSnapshot.tenant_id == tenant_id,
            MaturityPolicyEffectivenessSnapshot.rollout_id == rollout.id,
            MaturityPolicyEffectivenessSnapshot.observation_window_id == materialized.observation_window.id,
            MaturityPolicyEffectivenessSnapshot.input_digest == input_digest,
        )
    )
    if existing is not None:
        return existing

    if mismatch_count:
        status = "REGRESSED"
    elif not projections:
        status = "UNKNOWN"
    elif unknown_count:
        status = "DEGRADED"
    else:
        status = "CURRENT"
    snapshot = MaturityPolicyEffectivenessSnapshot(
        tenant_id=tenant_id,
        scope_id=scope.id,
        rollout_id=rollout.id,
        policy_version_id=version.id,
        observation_window_id=materialized.observation_window.id,
        status=status,
        outcome_summary={
            "sample_count": len(projections),
            "expected_decisions": dict(sorted(expected_counts.items())),
            "observed_decisions": dict(sorted(observed_counts.items())),
            "enforcement_mismatches": mismatch_count,
            "unknown_evaluations": unknown_count,
        },
        evidence_refs=_bounded_refs(
            [
                f"maturity_policy_rollout:{rollout.id}",
                f"policy_version:{version.id}",
                f"maturity_observation_window:{materialized.observation_window.id}",
                *(f"ai_action:{action_id}" for action_id, _expected, _observed in action_rows),
            ],
            maximum=500,
        ),
        input_digest=input_digest,
    )
    db.add(snapshot)
    db.flush()
    return snapshot
