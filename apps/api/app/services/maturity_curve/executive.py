"""Tenant-scoped executive projection for evidence-backed Maturity Curve data."""

from __future__ import annotations

from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.maturity_curve import (
    MaturityAssessment,
    MaturityExecutiveSnapshot,
    MaturityObservedUsagePattern,
    MaturityPolicyEffectivenessSnapshot,
    MaturityPolicyRecommendation,
    MaturityPolicyRollout,
    MaturityScope,
    MaturityUsageBaseline,
)
from app.services.maturity_curve.entitlements import require_maturity_capability
from app.services.maturity_curve.service import _bounded_refs, _canonical_digest


_EXECUTIVE_PATTERN_DIMENSIONS = {
    "source_surface",
    "application",
    "provider",
    "model",
    "agent_id",
    "tool_name",
    "mcp_server",
    "action_type",
    "data_classification",
    "destination_class",
    "account_class",
}
_EXECUTIVE_REPORT_VERSION = "maturity-executive-v2"
_CANONICAL_LIMITATION = (
    "Only canonical AI Action and AI Session metadata were used; raw prompts and action payloads were not retained."
)


def _latest_baselines(
    db: Session,
    *,
    tenant_id: str,
    scopes: list[MaturityScope],
) -> list[MaturityUsageBaseline]:
    baselines: list[MaturityUsageBaseline] = []
    for candidate in scopes:
        baseline = db.scalar(
            select(MaturityUsageBaseline)
            .where(
                MaturityUsageBaseline.tenant_id == tenant_id,
                MaturityUsageBaseline.scope_id == candidate.id,
            )
            .order_by(MaturityUsageBaseline.created_at.desc(), MaturityUsageBaseline.id.desc())
        )
        if baseline is not None:
            baselines.append(baseline)
    return baselines


def _bounded_counter(values: list[str], *, maximum: int = 8) -> dict[str, int]:
    return dict(sorted(Counter(value for value in values if value).items(), key=lambda item: (-item[1], item[0]))[:maximum])


def _executive_report(
    *,
    baselines: list[MaturityUsageBaseline],
    patterns: list[MaturityObservedUsagePattern],
    assessments: list[MaturityAssessment],
    recommendations: list[MaturityPolicyRecommendation],
    rollouts: list[MaturityPolicyRollout],
    effectiveness: list[MaturityPolicyEffectivenessSnapshot],
    coverage_refs: list[str],
) -> dict:
    """Build a bounded, non-identifying executive projection.

    The report intentionally contains summary counts, approved reference types,
    and explicit unknowns. It never copies user identifiers, action payloads,
    prompts, documents, credentials, or tool results from canonical sources.
    """

    aggregate_counts: Counter[str] = Counter()
    source_surfaces: Counter[str] = Counter()
    for baseline in baselines:
        aggregates = baseline.aggregates if isinstance(baseline.aggregates, dict) else {}
        aggregate_counts["observed_actions"] += int(baseline.sample_count or 0)
        surfaces = aggregates.get("source_surface_counts")
        if isinstance(surfaces, dict):
            source_surfaces.update(
                {
                    str(surface): int(count or 0)
                    for surface, count in surfaces.items()
                    if str(surface) and isinstance(count, (int, float))
                }
            )

    safe_patterns = [
        pattern
        for pattern in patterns
        if str(pattern.dimension or "").strip().lower() in _EXECUTIVE_PATTERN_DIMENSIONS
    ]
    top_patterns = [
        {
            "dimension": pattern.dimension,
            "value_ref": pattern.value_ref,
            "observation_count": pattern.observation_count,
            "approval_state": pattern.approval_state,
            "risk_state": pattern.risk_state,
            "control_state": pattern.control_state,
        }
        for pattern in sorted(
            safe_patterns,
            key=lambda item: (-int(item.observation_count or 0), str(item.dimension), str(item.value_ref)),
        )[:10]
    ]
    top_gaps = list(
        dict.fromkeys(
            str(gap)
            for assessment in assessments
            for gap in [*(assessment.blocking_gaps or []), *(assessment.missing_gates or [])]
            if str(gap)
        )
    )[:12]
    active_recommendations = [item for item in recommendations if item.status in {"DRAFT", "REVIEW", "APPROVED"}]
    next_steps: list[str] = []
    if top_gaps:
        next_steps.append("Resolve the highest-priority blocking evidence gap before advancing maturity.")
    if active_recommendations:
        next_steps.append("Review evidence-backed policy recommendations before publishing any policy version.")
    if any(item.status in {"REGRESSED", "DEGRADED", "UNKNOWN"} for item in effectiveness):
        next_steps.append("Investigate effectiveness evidence before expanding an active rollout.")
    if not next_steps:
        next_steps.append("Continue monitoring the current evidence window; no automatic policy change is proposed.")

    return {
        "report_version": _EXECUTIVE_REPORT_VERSION,
        "scope_count": len(assessments),
        "evidence_summary": {
            "observed_actions": aggregate_counts["observed_actions"],
            "baseline_count": len(baselines),
            "source_surface_counts": dict(sorted(source_surfaces.items())),
            "control_coverage_reference_count": len(coverage_refs),
        },
        "policy_posture": {
            "recommendations_by_state": dict(sorted(Counter(item.status for item in recommendations).items())),
            "rollouts_by_state": dict(sorted(Counter(item.state for item in rollouts).items())),
            "rollouts_by_stage": dict(sorted(Counter(item.rollout_stage for item in rollouts).items())),
            "effectiveness_by_state": dict(sorted(Counter(item.status for item in effectiveness).items())),
        },
        "top_patterns": top_patterns,
        "top_gaps": top_gaps,
        "recommended_next_steps": next_steps,
        "risk_trend": {
            "status": "UNKNOWN",
            "reason": "A comparable historical executive window is required before Hawk reports a trend.",
        },
        "known_limitations": [_CANONICAL_LIMITATION],
    }


def materialize_executive_snapshot(
    db: Session,
    *,
    tenant_id: str,
    scope_id: str,
) -> MaturityExecutiveSnapshot:
    """Persist an idempotent executive projection without inventing a score."""

    require_maturity_capability(db, tenant_id=tenant_id, capability="executive_reporting")
    scope = db.scalar(
        select(MaturityScope).where(MaturityScope.tenant_id == tenant_id, MaturityScope.id == scope_id)
    )
    if scope is None:
        raise ValueError("maturity_scope_not_found")
    scopes = [scope]
    if scope.scope_type == "organization":
        scopes = list(
            db.scalars(
                select(MaturityScope).where(
                    MaturityScope.tenant_id == tenant_id,
                    MaturityScope.active.is_(True),
                )
            ).all()
        )
    latest: list[MaturityAssessment] = []
    for candidate in scopes:
        assessment = db.scalar(
            select(MaturityAssessment)
            .where(
                MaturityAssessment.tenant_id == tenant_id,
                MaturityAssessment.scope_id == candidate.id,
            )
            .order_by(MaturityAssessment.computed_at.desc(), MaturityAssessment.id.desc())
        )
        if assessment is not None:
            latest.append(assessment)
    recommendations = list(
        db.scalars(
            select(MaturityPolicyRecommendation).where(
                MaturityPolicyRecommendation.tenant_id == tenant_id,
                MaturityPolicyRecommendation.scope_id.in_([item.id for item in scopes]),
            )
        ).all()
    ) if scopes else []
    scope_ids = [item.id for item in scopes]
    baselines = _latest_baselines(db, tenant_id=tenant_id, scopes=scopes)
    patterns = list(
        db.scalars(
            select(MaturityObservedUsagePattern).where(
                MaturityObservedUsagePattern.tenant_id == tenant_id,
                MaturityObservedUsagePattern.scope_id.in_(scope_ids),
            )
        ).all()
    ) if scope_ids else []
    rollouts = list(
        db.scalars(
            select(MaturityPolicyRollout).where(
                MaturityPolicyRollout.tenant_id == tenant_id,
                MaturityPolicyRollout.scope_id.in_(scope_ids),
            )
        ).all()
    ) if scope_ids else []
    effectiveness = list(
        db.scalars(
            select(MaturityPolicyEffectivenessSnapshot).where(
                MaturityPolicyEffectivenessSnapshot.tenant_id == tenant_id,
                MaturityPolicyEffectivenessSnapshot.scope_id.in_(scope_ids),
            )
        ).all()
    ) if scope_ids else []
    stage_distribution = dict(sorted(Counter(item.stage for item in latest).items()))
    gap_summary = {
        "scopes_total": len(scopes),
        "scopes_with_assessment": len(latest),
        "blocking_gaps": sum(len(item.blocking_gaps or []) for item in latest),
        "missing_gates": sum(len(item.missing_gates or []) for item in latest),
        "unknown_or_stale": sum(1 for item in latest if item.status != "CURRENT" or item.stage == "UNKNOWN"),
    }
    recommendation_summary = dict(sorted(Counter(item.status for item in recommendations).items()))
    coverage_refs = _bounded_refs(
        [reference for assessment in latest for reference in (assessment.evidence_refs or []) if str(reference).startswith("control_coverage:")],
        maximum=100,
    )
    report = _executive_report(
        baselines=baselines,
        patterns=patterns,
        assessments=latest,
        recommendations=recommendations,
        rollouts=rollouts,
        effectiveness=effectiveness,
        coverage_refs=coverage_refs,
    )
    digest = _canonical_digest(
        {
            "report_version": _EXECUTIVE_REPORT_VERSION,
            "scope_id": scope.id,
            "assessments": [(item.id, item.stage, item.status, item.computed_at) for item in latest],
            "recommendations": [(item.id, item.status, item.recommendation_digest) for item in recommendations],
            "baselines": [(item.id, item.baseline_digest, item.status) for item in baselines],
            "patterns": [
                (item.id, item.dimension, item.value_ref, item.observation_count, item.risk_state, item.approval_state)
                for item in patterns
            ],
            "rollouts": [(item.id, item.state, item.rollout_stage, item.policy_version_id) for item in rollouts],
            "effectiveness": [(item.id, item.status, item.input_digest) for item in effectiveness],
            "coverage_refs": coverage_refs,
        }
    )
    existing = db.scalar(
        select(MaturityExecutiveSnapshot).where(
            MaturityExecutiveSnapshot.tenant_id == tenant_id,
            MaturityExecutiveSnapshot.scope_id == scope.id,
            MaturityExecutiveSnapshot.input_digest == digest,
        )
    )
    if existing is not None:
        return existing
    snapshot = MaturityExecutiveSnapshot(
        tenant_id=tenant_id,
        scope_id=scope.id,
        input_digest=digest,
        stage_distribution=stage_distribution,
        coverage_refs=coverage_refs,
        gap_summary=gap_summary,
        recommendation_summary=recommendation_summary,
        report=report,
    )
    db.add(snapshot)
    db.flush()
    return snapshot
