"""Evidence-backed maturity policy recommendations.

Recommendations are intentionally conservative: they turn only a sufficiently
diverse, complete observation baseline into a *draft*.  They do not authorize,
publish, or enforce policy.  The existing PolicyVersion and scoped-policy
evaluator remain the authority once an administrator approves a rollout.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction
from app.db.models.control_coverage import DeploymentSurface
from app.db.models.maturity_curve import (
    MaturityAssessment,
    MaturityObservationWindow,
    MaturityPolicyRecommendation,
    MaturityRecommendationReview,
    MaturityScope,
    MaturityUsageBaseline,
)
from app.services.maturity_curve.entitlements import require_maturity_capability
from app.services.maturity_curve.service import (
    _action_projection,
    _bounded_refs,
    _canonical_digest,
    _load_sessions,
    _matches_scope,
    _normalize_token,
)


MINIMUM_RECOMMENDATION_SAMPLE = 5
MINIMUM_SOURCE_DIVERSITY = 1
MINIMUM_HIGH_SENSITIVITY = 0.7
RECOMMENDABLE_STAGES = {"UNDERSTANDING", "POLICY_READY", "CONTROLLED", "ASSURED"}


def _scoped_window_projections(
    db: Session,
    *,
    tenant_id: str,
    scope: MaturityScope,
    window: MaturityObservationWindow,
) -> list[dict[str, Any]]:
    actions = list(
        db.scalars(
            select(AIAction)
            .where(
                AIAction.tenant_id == tenant_id,
                AIAction.timestamp >= window.window_start,
                AIAction.timestamp <= window.window_end,
            )
            .order_by(AIAction.timestamp.asc(), AIAction.action_id.asc())
        ).all()
    )
    sessions = _load_sessions(
        db,
        tenant_id=tenant_id,
        session_ids=sorted({str(action.session_id) for action in actions if action.session_id}),
    )
    return [
        projection
        for projection in (_action_projection(action, sessions.get(str(action.session_id))) for action in actions)
        if _matches_scope(scope, projection)
    ]


def _recommendable_action_type(projections: list[dict[str, Any]], baseline: MaturityUsageBaseline) -> str | None:
    counts = baseline.aggregates.get("action_type_counts", {}) if isinstance(baseline.aggregates, dict) else {}
    if not isinstance(counts, dict):
        return None
    observed = Counter(_normalize_token(projection.get("action_type")) for projection in projections)
    candidates = [
        action_type
        for action_type, count in counts.items()
        if _normalize_token(action_type) and int(count or 0) >= MINIMUM_RECOMMENDATION_SAMPLE
        and observed[_normalize_token(action_type)] >= MINIMUM_RECOMMENDATION_SAMPLE
    ]
    if not candidates:
        return None
    # Tool actions are consequential but retain exact, pre-existing canonical
    # matching semantics; otherwise choose the most frequently observed type.
    if "tool_call" in {_normalize_token(value) for value in candidates}:
        return "tool_call"
    return sorted(candidates, key=lambda value: (-observed[_normalize_token(value)], _normalize_token(value)))[0]


def _matches_personal_sensitive_upload(item: dict[str, Any]) -> bool:
    account = _normalize_token(item.get("account_class"))
    action_type = _normalize_token(item.get("action_type"))
    sensitive = float(item.get("sensitivity_score") or 0.0) >= MINIMUM_HIGH_SENSITIVITY
    classified = _normalize_token(item.get("data_classification")) in {"confidential", "restricted", "sensitive"}
    return "personal" in account and ("upload" in action_type or action_type in {"file_transfer", "external_transfer"}) and (sensitive or classified)


def _matches_untrusted_external_tool(item: dict[str, Any]) -> bool:
    trust = _normalize_token(item.get("tool_trust_state"))
    destination = _normalize_token(item.get("destination_class"))
    return bool(item.get("tool_name")) and trust in {"unknown", "unapproved", "stale", "revoked"} and destination in {"external", "public", "unknown"}


def _matches_unapproved_provider_or_model(item: dict[str, Any]) -> bool:
    return _normalize_token(item.get("model_status")) in {"unapproved", "revoked", "stale"} or _normalize_token(
        item.get("provider_status")
    ) in {"unapproved", "revoked", "stale"}


def _matches_policy_friction(item: dict[str, Any]) -> bool:
    return _normalize_token(item.get("policy_decision")) in {"warn", "warning", "block", "blocked"}


def _candidate_sets(projections: list[dict[str, Any]], baseline: MaturityUsageBaseline) -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Return deterministic, evidence-only candidate groups in safety order."""

    candidates = [
        (
            "personal_account_sensitive_upload",
            "Block sensitive uploads to personal AI accounts",
            [item for item in projections if _matches_personal_sensitive_upload(item)],
        ),
        (
            "untrusted_tool_external_destination",
            "Review untrusted tool use toward external destinations",
            [item for item in projections if _matches_untrusted_external_tool(item)],
        ),
        (
            "unapproved_provider_or_model",
            "Review unapproved provider or model use",
            [item for item in projections if _matches_unapproved_provider_or_model(item)],
        ),
        (
            "policy_friction",
            "Review repeated policy friction",
            [item for item in projections if _matches_policy_friction(item)],
        ),
    ]
    complete = [item for item in candidates if len(item[2]) >= MINIMUM_RECOMMENDATION_SAMPLE]
    if complete:
        return complete
    action_type = _recommendable_action_type(projections, baseline)
    if action_type is None:
        return []
    return [
        (
            "consequential_usage",
            f"Review observed {action_type.replace('_', ' ')} activity",
            [item for item in projections if _normalize_token(item.get("action_type")) == action_type],
        )
    ]


def _surface_capability_summary(
    db: Session,
    *,
    tenant_id: str,
    source_surfaces: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Return supported, partial, and unsupported observed source surfaces."""

    rows = list(
        db.scalars(
            select(DeploymentSurface).where(
                DeploymentSurface.tenant_id == tenant_id,
                DeploymentSurface.deployment_family.in_(source_surfaces),
            )
        ).all()
    )
    supported: set[str] = set()
    partial: set[str] = set()
    for row in rows:
        family = _normalize_token(row.deployment_family)
        if _normalize_token(row.health_status) not in {"healthy", "warning"}:
            continue
        if _normalize_token(row.control_capability) == "inline":
            supported.add(family)
        elif _normalize_token(row.control_capability) in {"warn_only", "monitor_only", "external_required"}:
            partial.add(family)
    unsupported = sorted(set(source_surfaces) - supported - partial)
    return sorted(supported), sorted(partial), unsupported


def _unique_values(items: list[dict[str, Any]], field: str) -> list[str]:
    return sorted({_normalize_token(item.get(field)) for item in items if _normalize_token(item.get(field))})


def _draft_for_candidate(
    *,
    category: str,
    candidate_items: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    sources = _unique_values(candidate_items, "source_surface")
    action_types = _unique_values(candidate_items, "action_type")
    providers = _unique_values(candidate_items, "provider")
    account_classes = _unique_values(candidate_items, "account_class")
    data_classes = _unique_values(candidate_items, "data_classification")
    tool_names = _unique_values(candidate_items, "tool_name")
    model_statuses = _unique_values(candidate_items, "model_status")
    destination_classes = _unique_values(candidate_items, "destination_class")
    conditions: list[dict[str, Any]] = []
    if action_types:
        conditions.append({"field": "action_type", "operator": "in", "value": action_types})
    if sources:
        conditions.append({"field": "source_surface", "operator": "in", "value": sources})
    if providers:
        conditions.append({"field": "provider", "operator": "in", "value": providers})

    decision = "warn"
    reason_code = "maturity_observed_consequential_usage"
    if category == "personal_account_sensitive_upload":
        conditions.extend(
            [
                {"field": "account_class", "operator": "in", "value": account_classes},
                {"field": "data_classification", "operator": "in", "value": data_classes or ["confidential", "restricted"]},
            ]
        )
        decision = "block"
        reason_code = "maturity_personal_account_sensitive_upload"
    elif category == "untrusted_tool_external_destination":
        conditions.extend(
            [
                {"field": "tool_name", "operator": "in", "value": tool_names},
                {"field": "tool_trust_state", "operator": "in", "value": ["unknown", "unapproved", "stale", "revoked"]},
                {"field": "destination_class", "operator": "in", "value": destination_classes or ["external", "public", "unknown"]},
            ]
        )
        decision = "require_approval"
        reason_code = "maturity_untrusted_tool_external_destination"
    elif category == "unapproved_provider_or_model":
        conditions.append(
            {"field": "model_status", "operator": "in", "value": model_statuses or ["unapproved", "revoked", "stale"]}
        )
        decision = "require_approval"
        reason_code = "maturity_unapproved_provider_or_model"
    elif category == "policy_friction":
        # A friction recommendation never relaxes a block automatically. It
        # asks for a staged approval rule that must still be simulated/reviewed.
        decision = "require_approval"
        reason_code = "maturity_repeated_policy_friction"
    elif max((float(item.get("sensitivity_score") or 0.0) for item in candidate_items), default=0.0) >= MINIMUM_HIGH_SENSITIVITY:
        conditions.append({"field": "sensitivity_score", "operator": "gte", "value": MINIMUM_HIGH_SENSITIVITY})
        decision = "require_approval"

    rule_id = f"maturity_{category}_{_canonical_digest({'sources': sources, 'providers': providers, 'actions': action_types})[:12]}"
    return (
        {
            "source": "maturity_curve",
            "version": "maturity-draft-v1",
            "scoped_rules": [
                {
                    "rule_id": rule_id,
                    "enabled": True,
                    "priority": 100,
                    "description": "Evidence-backed Maturity Curve draft; it remains non-enforcing until a human-approved rollout activates the existing policy runtime.",
                    "condition_tree": {"all": conditions},
                    "effect": {
                        "decision": decision,
                        "reason_code": reason_code,
                        "explanation": "This typed draft is limited to observed normalized action context and requires review before activation.",
                        "recommended_action": "request_approval" if decision == "require_approval" else "monitor",
                        "priority": 100,
                    },
                }
            ],
        },
        decision,
    )


def generate_policy_recommendations(
    db: Session,
    *,
    tenant_id: str,
    scope_id: str,
    assessment_id: str,
    baseline_id: str,
) -> list[MaturityPolicyRecommendation]:
    """Return idempotent, evidence-backed policy *drafts* for one scope.

    A weak, partial, stale, single-source, contradicted, or otherwise
    incomplete baseline returns no recommendation.  Absence is not treated as
    negative evidence and never becomes a blanket policy.
    """

    require_maturity_capability(db, tenant_id=tenant_id, capability="recommendations")
    scope = db.scalar(
        select(MaturityScope).where(MaturityScope.tenant_id == tenant_id, MaturityScope.id == scope_id)
    )
    assessment = db.scalar(
        select(MaturityAssessment).where(MaturityAssessment.tenant_id == tenant_id, MaturityAssessment.id == assessment_id)
    )
    baseline = db.scalar(
        select(MaturityUsageBaseline).where(MaturityUsageBaseline.tenant_id == tenant_id, MaturityUsageBaseline.id == baseline_id)
    )
    if scope is None or assessment is None or baseline is None:
        raise ValueError("maturity_recommendation_context_not_found")
    if assessment.scope_id != scope.id or baseline.scope_id != scope.id:
        raise ValueError("maturity_recommendation_scope_mismatch")
    if assessment.observation_window_id != baseline.observation_window_id:
        raise ValueError("maturity_recommendation_window_mismatch")
    if (
        baseline.status != "COMPLETE"
        or baseline.sample_count < MINIMUM_RECOMMENDATION_SAMPLE
        or baseline.source_diversity < MINIMUM_SOURCE_DIVERSITY
        or assessment.stage not in RECOMMENDABLE_STAGES
        or assessment.blocking_gaps
    ):
        return []

    window = db.scalar(
        select(MaturityObservationWindow).where(
            MaturityObservationWindow.tenant_id == tenant_id,
            MaturityObservationWindow.id == baseline.observation_window_id,
        )
    )
    if window is None:
        raise ValueError("maturity_recommendation_window_not_found")
    projections = _scoped_window_projections(db, tenant_id=tenant_id, scope=scope, window=window)
    created: list[MaturityPolicyRecommendation] = []
    for category, title, candidate_items in _candidate_sets(projections, baseline):
        sources = _unique_values(candidate_items, "source_surface")
        if len(candidate_items) < MINIMUM_RECOMMENDATION_SAMPLE or len(sources) < MINIMUM_SOURCE_DIVERSITY:
            continue
        policy_draft, decision = _draft_for_candidate(category=category, candidate_items=candidate_items)
        supported, partial, unsupported = _surface_capability_summary(
            db,
            tenant_id=tenant_id,
            source_surfaces=sources,
        )
        recommendation_key = f"{scope.scope_key}:{category}"
        digest_material = {
            "scope_id": scope.id,
            "assessment_id": assessment.id,
            "baseline_id": baseline.id,
            "policy_draft": policy_draft,
            "action_refs": [item["action_id"] for item in candidate_items],
            "control_capability": {"supported": supported, "partial": partial, "unsupported": unsupported},
        }
        recommendation_digest = _canonical_digest(digest_material)
        existing = db.scalar(
            select(MaturityPolicyRecommendation).where(
                MaturityPolicyRecommendation.tenant_id == tenant_id,
                MaturityPolicyRecommendation.scope_id == scope.id,
                MaturityPolicyRecommendation.recommendation_key == recommendation_key,
                MaturityPolicyRecommendation.recommendation_digest == recommendation_digest,
            )
        )
        if existing is not None:
            created.append(existing)
            continue

        # One category has one active current recommendation.  New evidence
        # supersedes the old draft without silently deleting its audit trail.
        active_prior = list(
            db.scalars(
                select(MaturityPolicyRecommendation).where(
                    MaturityPolicyRecommendation.tenant_id == tenant_id,
                    MaturityPolicyRecommendation.scope_id == scope.id,
                    MaturityPolicyRecommendation.recommendation_key == recommendation_key,
                    MaturityPolicyRecommendation.status.in_(("DRAFT", "REVIEW", "APPROVED")),
                )
            ).all()
        )
        for prior in active_prior:
            prior.status = "EXPIRED"
            prior.review_state = "SUPERSEDED"

        confidence_factors = {
            "evidence_volume": len(candidate_items),
            "baseline_sample_count": baseline.sample_count,
            "source_diversity": len(sources),
            "assessment_confidence": float(assessment.confidence),
            "supported_surfaces": supported,
            "partial_surfaces": partial,
            "unsupported_surfaces": unsupported,
        }
        implementation_confidence = 1.0 if supported and not unsupported else 0.6 if supported or partial else 0.3
        confidence = min(
            1.0,
            float(assessment.confidence),
            len(candidate_items) / max(baseline.sample_count, 1),
            implementation_confidence,
        )
        unknowns = ["No raw prompt, document, credential, or tool output was used to create this recommendation."]
        if unsupported:
            unknowns.append("Some observed surfaces lack a current pre-execution enforcement capability for this draft.")
        recommendation = MaturityPolicyRecommendation(
            tenant_id=tenant_id,
            scope_id=scope.id,
            assessment_id=assessment.id,
            recommendation_key=recommendation_key,
            title=title,
            category=category,
            status="DRAFT",
            review_state="PENDING",
            policy_draft=policy_draft,
            evidence_refs=_bounded_refs(
                [
                    f"maturity_assessment:{assessment.id}",
                    f"maturity_usage_baseline:{baseline.id}",
                    f"maturity_observation_window:{window.id}",
                    *(f"ai_action:{item['action_id']}" for item in candidate_items),
                ],
                maximum=100,
            ),
            assumptions=["Observed normalized metadata remains representative until the next materialization."],
            unknowns=unknowns,
            confidence=confidence,
            estimated_impact={
                "matched_historical_actions": len(candidate_items),
                "users_affected": len(_unique_values(candidate_items, "actor_user_id")),
                "applications_affected": _unique_values(candidate_items, "application"),
                "agents_affected": _unique_values(candidate_items, "agent_id"),
                "tools_affected": _unique_values(candidate_items, "tool_name"),
                "destinations_affected": _unique_values(candidate_items, "destination"),
                "decision": decision,
                "supported_surfaces": supported,
                "partial_surfaces": partial,
                "unsupported_surfaces": unsupported,
                "confidence_factors": confidence_factors,
            },
            estimated_friction={
                "requires_human_approval": decision == "require_approval",
                "possible_exception_candidates": len(_unique_values(candidate_items, "actor_group")),
            },
            recommendation_digest=recommendation_digest,
        )
        db.add(recommendation)
        db.flush()
        created.append(recommendation)
    return created


_REVIEW_ACTIONS = {"REVIEW", "APPROVE", "REJECT", "DEFER", "ACCEPT_RISK"}


def review_policy_recommendation(
    db: Session,
    *,
    tenant_id: str,
    recommendation_id: str,
    action: str,
    actor_ref: str,
    reason: str,
    now: datetime | None = None,
) -> MaturityPolicyRecommendation:
    """Record a human decision without mutating policy authority or evidence."""

    normalized_action = str(action or "").strip().upper()
    normalized_reason = str(reason or "").strip()
    if normalized_action not in _REVIEW_ACTIONS or len(normalized_reason) < 3 or not str(actor_ref or "").strip():
        raise ValueError("invalid_maturity_recommendation_review")
    capability = "approval_workflow" if normalized_action == "APPROVE" else "recommendations"
    require_maturity_capability(db, tenant_id=tenant_id, capability=capability)
    recommendation = db.scalar(
        select(MaturityPolicyRecommendation).where(
            MaturityPolicyRecommendation.tenant_id == tenant_id,
            MaturityPolicyRecommendation.id == recommendation_id,
        )
    )
    if recommendation is None:
        raise ValueError("maturity_recommendation_not_found")
    if recommendation.status in {"REJECTED", "DISMISSED", "EXPIRED"}:
        raise ValueError("maturity_recommendation_not_reviewable")

    timestamp = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    status_map = {
        "REVIEW": "REVIEW",
        "APPROVE": "APPROVED",
        "REJECT": "REJECTED",
        "DEFER": "DISMISSED",
        "ACCEPT_RISK": "DISMISSED",
    }
    state_map = {
        "REVIEW": "IN_REVIEW",
        "APPROVE": "APPROVED",
        "REJECT": "REJECTED",
        "DEFER": "DEFERRED",
        "ACCEPT_RISK": "ACCEPTED_RISK",
    }
    recommendation.status = status_map[normalized_action]
    recommendation.review_state = state_map[normalized_action]
    recommendation.review_reason = normalized_reason[:2_000]
    recommendation.reviewed_by_ref = str(actor_ref).strip()[:255]
    recommendation.reviewed_at = timestamp
    db.add(
        MaturityRecommendationReview(
            tenant_id=tenant_id,
            recommendation_id=recommendation.id,
            action=normalized_action,
            actor_ref=str(actor_ref).strip()[:255],
            reason=normalized_reason[:2_000],
        )
    )
    db.flush()
    return recommendation
