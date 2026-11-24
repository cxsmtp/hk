"""Historical policy simulation using the live scoped-policy evaluator.

This module intentionally does not implement policy matching.  A candidate
draft is replayed through ``resolve_scoped_policy_rules`` so simulation and
live policy evaluation have identical selector, typed-condition, precedence,
and explanation semantics.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.maturity_curve import (
    MaturityObservationWindow,
    MaturityPolicyRecommendation,
    MaturityPolicySimulation,
    MaturityScope,
)
from app.services.maturity_curve.entitlements import require_maturity_capability
from app.services.maturity_curve.recommendations import _scoped_window_projections
from app.services.maturity_curve.service import _bounded_refs, _canonical_digest
from app.services.policy_scope_service import resolve_scoped_policy_rules


def _policy_context(projection: dict[str, Any]) -> dict[str, Any]:
    sensitivity = float(projection.get("sensitivity_score") or 0.0)
    return {
        "source_surface": projection.get("source_surface"),
        "application": projection.get("application"),
        "provider": projection.get("provider"),
        "model": projection.get("model"),
        "agent_id": projection.get("agent_id"),
        "tool_name": projection.get("tool_name"),
        "mcp_server": projection.get("mcp_server"),
        "action_type": projection.get("action_type"),
        "operation": projection.get("action_type"),
        "action_class": projection.get("action_type"),
        "environment": projection.get("environment"),
        "business_purpose": projection.get("business_purpose"),
        "data_classification": projection.get("data_classification"),
        "sensitivity_score": sensitivity,
        "contains_sensitive": sensitivity > 0.0,
    }


def simulate_policy_recommendation(
    db: Session,
    *,
    tenant_id: str,
    recommendation_id: str,
    now: datetime | None = None,
) -> MaturityPolicySimulation:
    """Replay one candidate draft against its frozen observation window.

    A passed result means the bounded historical metadata was completely
    evaluable through the existing matcher.  It is not proof that a policy is
    safe to enforce in every future environment.
    """

    require_maturity_capability(db, tenant_id=tenant_id, capability="simulations")
    recommendation = db.scalar(
        select(MaturityPolicyRecommendation).where(
            MaturityPolicyRecommendation.tenant_id == tenant_id,
            MaturityPolicyRecommendation.id == recommendation_id,
        )
    )
    if recommendation is None:
        raise ValueError("maturity_recommendation_not_found")
    scope = db.scalar(
        select(MaturityScope).where(
            MaturityScope.tenant_id == tenant_id,
            MaturityScope.id == recommendation.scope_id,
        )
    )
    if scope is None:
        raise ValueError("maturity_recommendation_scope_not_found")
    # Retrieve through the assessment's window with explicit tenant/scope checks.
    from app.db.models.maturity_curve import MaturityAssessment

    assessment = db.scalar(
        select(MaturityAssessment).where(
            MaturityAssessment.tenant_id == tenant_id,
            MaturityAssessment.id == recommendation.assessment_id,
            MaturityAssessment.scope_id == scope.id,
        )
    )
    if assessment is None:
        raise ValueError("maturity_recommendation_assessment_not_found")
    window = db.scalar(
        select(MaturityObservationWindow).where(
            MaturityObservationWindow.tenant_id == tenant_id,
            MaturityObservationWindow.id == assessment.observation_window_id,
            MaturityObservationWindow.scope_id == scope.id,
        )
    )
    if window is None:
        raise ValueError("maturity_recommendation_window_not_found")

    policy_draft = recommendation.policy_draft if isinstance(recommendation.policy_draft, dict) else {}
    rules = policy_draft.get("scoped_rules") if isinstance(policy_draft.get("scoped_rules"), list) else []
    if not rules:
        raise ValueError("maturity_recommendation_has_no_scoped_rules")
    projections = _scoped_window_projections(db, tenant_id=tenant_id, scope=scope, window=window)
    input_digest = _canonical_digest(
        {
            "recommendation_id": recommendation.id,
            "recommendation_digest": recommendation.recommendation_digest,
            "window_id": window.id,
            "actions": [(item["action_id"], item.get("timestamp")) for item in projections],
            "rules": rules,
        }
    )
    existing = db.scalar(
        select(MaturityPolicySimulation).where(
            MaturityPolicySimulation.tenant_id == tenant_id,
            MaturityPolicySimulation.recommendation_id == recommendation.id,
            MaturityPolicySimulation.input_digest == input_digest,
        )
    )
    if existing is not None:
        return existing

    counts: Counter[str] = Counter()
    breakdown: dict[str, Counter[str]] = defaultdict(Counter)
    unknown_count = 0
    evidence_refs: list[str] = [
        f"maturity_policy_recommendation:{recommendation.id}",
        f"maturity_observation_window:{window.id}",
    ]
    for projection in projections:
        resolution = resolve_scoped_policy_rules(
            db,
            tenant_id=tenant_id,
            policy_version_id=recommendation.candidate_policy_version_id,
            context=_policy_context(projection),
            rules=rules,
        )
        surface = str(projection.get("source_surface") or "unknown")
        if not resolution.matched:
            decision = "unknown"
            unknown_count += 1
        else:
            decision = resolution.decision
        counts[decision] += 1
        breakdown[surface][decision] += 1
        evidence_refs.append(f"ai_action:{projection['action_id']}")

    # Empty windows do not pass merely because there were no unmatched rows.
    passed = bool(projections) and unknown_count == 0
    simulation = MaturityPolicySimulation(
        tenant_id=tenant_id,
        scope_id=scope.id,
        recommendation_id=recommendation.id,
        policy_version_id=recommendation.candidate_policy_version_id,
        input_digest=input_digest,
        sample_count=len(projections),
        outcome_counts=dict(sorted(counts.items())),
        scope_breakdown={key: dict(sorted(value.items())) for key, value in sorted(breakdown.items())},
        unknown_count=unknown_count,
        passed=passed,
        evidence_refs=_bounded_refs(evidence_refs, maximum=500),
    )
    db.add(simulation)
    db.flush()
    return simulation
