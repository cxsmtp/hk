"""Phase 8 evidence-backed, tenant-scoped executive Control Coverage."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Mapping, Sequence
from uuid import uuid4

from sqlalchemy import case, func, insert, select
from sqlalchemy.orm import Session

from app.core.control_coverage import (
    PHASE8_METHODOLOGY_VERSION,
    CoverageDimension,
    CoverageApplicability,
    ExecutiveCoverageFacts,
    ExecutiveCoverageState,
    derive_executive_coverage,
)
from app.db.models.control_coverage import (
    ControlCoverageAssessment,
    ControlCoverageGap,
    ControlCoverageSnapshot,
    CoverageScope,
)


PHASE8_SNAPSHOT_KIND = "executive_coverage"
MAX_EXECUTIVE_PATH_INPUTS = 10_000
MAX_EXECUTIVE_ASSESSMENT_INPUTS = MAX_EXECUTIVE_PATH_INPUTS * len(CoverageDimension)
EXECUTIVE_WRITE_BATCH_SIZE = 250
_STATE_ORDER = tuple(state.value for state in ExecutiveCoverageState)
_SURFACES = ("browser", "endpoint", "runtime", "saas_api", "unknown")
_GAP_STATES = frozenset(_STATE_ORDER) - {
    ExecutiveCoverageState.COVERED_CURRENT.value,
    ExecutiveCoverageState.NOT_APPLICABLE.value,
}


@dataclass(frozen=True)
class CoverageAssessmentInput:
    assessment_key: str
    asset_ref: str
    action_class: str
    action_path_ref: str
    deployment_surface: str
    dimension: str
    requirement_ref: str
    applicability_reason: str
    facts: ExecutiveCoverageFacts
    control_plan_ref: str | None = None
    validation_refs: tuple[str, ...] = ()
    lineage_refs: tuple[str, ...] = ()
    bypass_refs: tuple[str, ...] = ()
    domain_profile_ref: str | None = None
    criticality: str = "medium"
    source_versions: Mapping[str, str] | None = None


def _validate_executive_input_count(input_count: int) -> None:
    """Keep the snapshot bound aligned with the bounded path projection."""

    if input_count > MAX_EXECUTIVE_ASSESSMENT_INPUTS:
        raise ValueError("coverage assessment input exceeds the bounded P0 limit")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_values(values: Sequence[str], *, maximum: int = 100) -> list[str]:
    result: list[str] = []
    for value in values[:maximum]:
        normalized = str(value or "").strip()
        if normalized and len(normalized) <= 255 and not any(token in normalized for token in ("\r", "\n", "\x00")):
            result.append(normalized)
    return sorted(set(result))


def _scope(
    db: Session,
    *,
    tenant_id: str,
    scope_type: str,
    scope_key: str,
    display_name: str,
    filters: Mapping[str, object] | None = None,
) -> CoverageScope:
    row = db.scalar(
        select(CoverageScope).where(
            CoverageScope.tenant_id == tenant_id,
            CoverageScope.scope_type == scope_type,
            CoverageScope.scope_key == scope_key,
        )
    )
    if row is None:
        row = CoverageScope(
            tenant_id=tenant_id,
            scope_type=scope_type,
            scope_key=scope_key,
            display_name=display_name,
            filters=dict(filters or {}),
            active=True,
        )
        db.add(row)
        db.flush()
    else:
        row.display_name = display_name
        row.filters = dict(filters or row.filters or {})
        row.active = True
    return row


def _input_digest(
    *, inputs: Sequence[CoverageAssessmentInput], source_versions: Mapping[str, str]
) -> str:
    hasher = hashlib.sha256()
    header = {
        "methodology": PHASE8_METHODOLOGY_VERSION,
        "source_versions": dict(sorted(source_versions.items())),
    }
    hasher.update(json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    hasher.update(b"\n")
    for item in sorted(inputs, key=lambda value: value.assessment_key):
        assessment = {
            "key": item.assessment_key,
            "asset": item.asset_ref,
            "action": item.action_class,
            "path": item.action_path_ref,
            "surface": item.deployment_surface,
            "dimension": item.dimension,
            "requirement": item.requirement_ref,
            "facts": {
                "applicability": item.facts.applicability.value,
                "deployment": item.facts.deployment.value,
                "capability": item.facts.capability.value,
                "assurance": item.facts.assurance.value,
                "evidence_quality": item.facts.evidence_quality,
                "evidence_refs": sorted(item.facts.evidence_refs),
                "expected": sorted(item.facts.expected_control_points),
                "contributing": sorted(item.facts.contributing_control_points),
                "missing": sorted(item.facts.missing_contributions),
                "bypass": item.facts.bypass_reachable,
                "compensating": item.facts.compensating_bypass_control,
                "previously_validated": item.facts.previously_validated,
                "regression": item.facts.unresolved_regression,
            },
        }
        hasher.update(
            json.dumps(assessment, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        )
        hasher.update(b"\n")
    return hasher.hexdigest()


def _priority(*, state: str, criticality: str, reason_code: str) -> str:
    high_impact = criticality in {"critical", "high"}
    if state == "regressed" and high_impact:
        return "P0"
    if state == "gap" and high_impact:
        return "P0"
    if reason_code == "reachable_bypass_uncontrolled":
        return "P0" if high_impact else "P1"
    if state in {"regressed", "gap", "unsupported", "unknown", "covered_stale"}:
        return "P1" if high_impact else "P2"
    if state == "partially_covered":
        return "P1" if high_impact else "P2"
    return "P2" if high_impact else "P3"


def _gap_category(*, state: str, reason_code: str) -> str:
    if reason_code == "reachable_bypass_uncontrolled":
        return "bypass_path"
    return {
        "regressed": "regressed_control",
        "covered_stale": "stale_validation",
        "configured_unvalidated": "configured_unvalidated",
        "partially_covered": "partial_control_plan",
        "unsupported": "unsupported_surface",
        "unknown": "evidence_quality_gap",
        "gap": "missing_control",
    }.get(state, "control_gap")


def _recommended_action(*, state: str, reason_code: str) -> str:
    if state == "regressed":
        return "Remediate the failed control and complete current revalidation before restoring coverage."
    if state == "covered_stale":
        return "Revalidate the affected control against the current dependency and deployment state."
    if reason_code == "reachable_bypass_uncontrolled":
        return "Close the reachable bypass or verify an independent compensating control on that route."
    if state == "configured_unvalidated":
        return "Run bounded validation and attach current evidence for the required capability."
    if state == "unsupported":
        return "Deploy a control point that supports this capability or keep the limitation explicit."
    if state == "unknown":
        return "Collect the missing applicability, deployment, capability, or assurance evidence."
    if state == "partially_covered":
        return "Add or validate the missing composed-control contribution shown in this assessment."
    return "Deploy and validate the required control for this action path."


def _distribution(counts: Mapping[str, int]) -> dict[str, int]:
    return {state: counts.get(state, 0) for state in _STATE_ORDER}


def _breakdown(grouped: Mapping[str, Mapping[str, int]]) -> dict[str, dict[str, int]]:
    return {key: _distribution(values) for key, values in sorted(grouped.items())}


def refresh_executive_coverage_snapshot(
    db: Session,
    *,
    tenant_id: str,
    scope_type: str,
    scope_key: str,
    display_name: str,
    inputs: Sequence[CoverageAssessmentInput],
    source_versions: Mapping[str, str],
    assessed_at: datetime,
    filters: Mapping[str, object] | None = None,
) -> ControlCoverageSnapshot:
    """Persist one bounded point-in-time view over already-authoritative facts."""

    _validate_executive_input_count(len(inputs))
    assessed_at = _utc(assessed_at)
    scope = _scope(
        db,
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_key=scope_key,
        display_name=display_name,
        filters=filters,
    )
    previous = db.scalar(
        select(ControlCoverageSnapshot)
        .where(
            ControlCoverageSnapshot.tenant_id == tenant_id,
            ControlCoverageSnapshot.scope_id == scope.id,
            ControlCoverageSnapshot.snapshot_kind == PHASE8_SNAPSHOT_KIND,
        )
        .order_by(ControlCoverageSnapshot.computed_at.desc(), ControlCoverageSnapshot.id.desc())
        .limit(1)
    )
    snapshot = ControlCoverageSnapshot(
        tenant_id=tenant_id,
        methodology_version=PHASE8_METHODOLOGY_VERSION,
        window_start=assessed_at,
        window_end=assessed_at,
        input_digest=_input_digest(inputs=inputs, source_versions=source_versions),
        headline_counts={},
        headline_score=None,
        dimension_summaries={},
        input_watermarks=dict(source_versions),
        diagnostics=[],
        freshness_status="current",
        scope_id=scope.id,
        previous_snapshot_id=previous.id if previous else None,
        snapshot_kind=PHASE8_SNAPSHOT_KIND,
        source_versions=dict(source_versions),
        assessment_totals={},
        applicable_requirement_count=0,
        unknown_population=0,
        gap_summary={},
        comparison_summary={},
        computed_at=assessed_at,
    )
    db.add(snapshot)
    db.flush()

    assessment_batch: list[dict[str, object]] = []
    gap_batch: list[dict[str, object]] = []
    distribution_counts: Counter[str] = Counter()
    dimension_counts: dict[str, Counter[str]] = defaultdict(Counter)
    gap_priority_counts: Counter[str] = Counter()
    applicable = 0

    def flush_batches() -> None:
        if assessment_batch:
            db.execute(insert(ControlCoverageAssessment), assessment_batch)
            assessment_batch.clear()
        if gap_batch:
            db.execute(insert(ControlCoverageGap), gap_batch)
            gap_batch.clear()

    for item in sorted(inputs, key=lambda value: value.assessment_key):
        derived = derive_executive_coverage(item.facts)
        surface = item.deployment_surface if item.deployment_surface in _SURFACES else "unknown"
        assessment_id = str(uuid4())
        criticality = item.criticality if item.criticality in {"info", "low", "medium", "high", "critical"} else "medium"
        coverage_state = derived.state.value
        evidence_refs = _safe_values(item.facts.evidence_refs)
        assessment_batch.append(
            {
                "id": assessment_id,
                "tenant_id": tenant_id,
                "scope_id": scope.id,
                "snapshot_id": snapshot.id,
                "assessment_key": item.assessment_key,
                "asset_ref": item.asset_ref,
                "action_class": item.action_class,
                "action_path_ref": item.action_path_ref,
                "domain_profile_ref": item.domain_profile_ref,
                "deployment_surface": surface,
                "dimension": item.dimension,
                "requirement_ref": item.requirement_ref,
                "applicability_state": item.facts.applicability.value,
                "applicability_reason": item.applicability_reason,
                "deployment_state": item.facts.deployment.value,
                "capability_state": item.facts.capability.value,
                "assurance_state": item.facts.assurance.value,
                "evidence_quality": item.facts.evidence_quality or "unknown",
                "coverage_state": coverage_state,
                "reason_code": derived.reason_code,
                "explanation": derived.explanation,
                "control_plan_ref": item.control_plan_ref,
                "expected_control_points": _safe_values(item.facts.expected_control_points),
                "contributing_control_points": _safe_values(item.facts.contributing_control_points),
                "missing_contributions": _safe_values(item.facts.missing_contributions),
                "bypass_refs": _safe_values(item.bypass_refs),
                "evidence_refs": evidence_refs,
                "validation_refs": _safe_values(item.validation_refs),
                "lineage_refs": _safe_values(item.lineage_refs),
                "source_versions": dict(item.source_versions or {}),
                "criticality": criticality,
                "assessed_at": assessed_at,
            }
        )
        distribution_counts[coverage_state] += 1
        dimension_counts[item.dimension][coverage_state] += 1
        if item.facts.applicability is not CoverageApplicability.NOT_APPLICABLE:
            applicable += 1
        if coverage_state in _GAP_STATES:
            priority = _priority(
                state=coverage_state,
                criticality=criticality,
                reason_code=derived.reason_code,
            )
            gap_priority_counts[priority] += 1
            gap_batch.append(
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "scope_id": scope.id,
                    "snapshot_id": snapshot.id,
                    "assessment_id": assessment_id,
                    "category": _gap_category(
                        state=coverage_state,
                        reason_code=derived.reason_code,
                    ),
                    "priority": priority,
                    "cause": derived.explanation,
                    "recommended_action": _recommended_action(
                        state=coverage_state,
                        reason_code=derived.reason_code,
                    ),
                    "evidence_refs": evidence_refs,
                    "status": "open",
                }
            )
        if len(assessment_batch) >= EXECUTIVE_WRITE_BATCH_SIZE:
            flush_batches()

    flush_batches()
    distribution = _distribution(distribution_counts)
    current = distribution[ExecutiveCoverageState.COVERED_CURRENT.value]
    snapshot.headline_counts = distribution
    snapshot.headline_score = round(current / applicable * 100.0, 2) if applicable else None
    snapshot.dimension_summaries = _breakdown(dimension_counts)
    snapshot.assessment_totals = distribution
    snapshot.applicable_requirement_count = applicable
    snapshot.unknown_population = distribution[ExecutiveCoverageState.UNKNOWN.value]
    snapshot.gap_summary = dict(gap_priority_counts)
    if previous is not None:
        snapshot.comparison_summary = compare_coverage_snapshots(
            db,
            tenant_id=tenant_id,
            current_snapshot_id=snapshot.id,
            previous_snapshot_id=previous.id,
        ) or {}
    db.flush()
    return snapshot


def compare_coverage_snapshots(
    db: Session,
    *,
    tenant_id: str,
    current_snapshot_id: str,
    previous_snapshot_id: str,
) -> dict[str, object] | None:
    snapshots = db.scalars(
        select(ControlCoverageSnapshot).where(
            ControlCoverageSnapshot.tenant_id == tenant_id,
            ControlCoverageSnapshot.id.in_((current_snapshot_id, previous_snapshot_id)),
            ControlCoverageSnapshot.snapshot_kind == PHASE8_SNAPSHOT_KIND,
        )
    ).all()
    by_id = {row.id: row for row in snapshots}
    current = by_id.get(current_snapshot_id)
    previous = by_id.get(previous_snapshot_id)
    if current is None or previous is None or current.scope_id != previous.scope_id:
        return None
    rows = db.execute(
        select(
            ControlCoverageAssessment.snapshot_id,
            ControlCoverageAssessment.assessment_key,
            ControlCoverageAssessment.coverage_state,
        ).where(
            ControlCoverageAssessment.tenant_id == tenant_id,
            ControlCoverageAssessment.snapshot_id.in_((current_snapshot_id, previous_snapshot_id)),
        )
    ).all()
    current_rows = {row.assessment_key: row.coverage_state for row in rows if row.snapshot_id == current_snapshot_id}
    previous_rows = {row.assessment_key: row.coverage_state for row in rows if row.snapshot_id == previous_snapshot_id}
    transitions: Counter[str] = Counter()
    unchanged = 0
    for key in sorted(current_rows.keys() & previous_rows.keys()):
        before, after = previous_rows[key], current_rows[key]
        if before == after:
            unchanged += 1
        else:
            transitions[f"{before}_to_{after}"] += 1
    return {
        "current_snapshot_id": current_snapshot_id,
        "previous_snapshot_id": previous_snapshot_id,
        "transitions": dict(sorted(transitions.items())),
        "unchanged": unchanged,
        "introduced": len(current_rows.keys() - previous_rows.keys()),
        "removed": len(previous_rows.keys() - current_rows.keys()),
        "scope_changed": False,
    }


def _top_gaps(
    db: Session, *, tenant_id: str, snapshot_id: str, limit: int = 10
) -> list[dict[str, object]]:
    priority_rank = case(
        (ControlCoverageGap.priority == "P0", 0),
        (ControlCoverageGap.priority == "P1", 1),
        (ControlCoverageGap.priority == "P2", 2),
        (ControlCoverageGap.priority == "P3", 3),
        else_=9,
    )
    pairs = db.execute(
        select(ControlCoverageGap, ControlCoverageAssessment)
        .join(
            ControlCoverageAssessment,
            (ControlCoverageAssessment.tenant_id == ControlCoverageGap.tenant_id)
            & (ControlCoverageAssessment.id == ControlCoverageGap.assessment_id),
        )
        .where(
            ControlCoverageGap.tenant_id == tenant_id,
            ControlCoverageGap.snapshot_id == snapshot_id,
            ControlCoverageGap.status == "open",
            ControlCoverageAssessment.tenant_id == tenant_id,
            ControlCoverageAssessment.snapshot_id == snapshot_id,
        )
        .order_by(priority_rank, ControlCoverageGap.created_at, ControlCoverageGap.id)
        .limit(limit)
    ).all()
    result = []
    for gap, assessment in pairs:
        result.append(
            {
                "gap_id": gap.id,
                "assessment_id": assessment.id,
                "priority": gap.priority,
                "category": gap.category,
                "asset_ref": assessment.asset_ref,
                "action_class": assessment.action_class,
                "dimension": assessment.dimension,
                "surface": assessment.deployment_surface,
                "coverage_state": assessment.coverage_state,
                "cause": gap.cause,
                "recommended_action": gap.recommended_action,
                "evidence_refs": list(gap.evidence_refs or []),
            }
        )
    return result


def _aggregate_distribution(
    db: Session, *, tenant_id: str, snapshot_id: str
) -> dict[str, int]:
    counts = dict(
        db.execute(
            select(ControlCoverageAssessment.coverage_state, func.count(ControlCoverageAssessment.id))
            .where(
                ControlCoverageAssessment.tenant_id == tenant_id,
                ControlCoverageAssessment.snapshot_id == snapshot_id,
            )
            .group_by(ControlCoverageAssessment.coverage_state)
        ).all()
    )
    return {state: int(counts.get(state, 0)) for state in _STATE_ORDER}


def _aggregate_breakdown(
    db: Session,
    *,
    tenant_id: str,
    snapshot_id: str,
    field,
) -> dict[str, dict[str, int]]:
    grouped: dict[str, dict[str, int]] = {}
    rows = db.execute(
        select(field, ControlCoverageAssessment.coverage_state, func.count(ControlCoverageAssessment.id))
        .where(
            ControlCoverageAssessment.tenant_id == tenant_id,
            ControlCoverageAssessment.snapshot_id == snapshot_id,
        )
        .group_by(field, ControlCoverageAssessment.coverage_state)
    ).all()
    for group, state, count in rows:
        key = str(group or "unknown")
        grouped.setdefault(key, {item: 0 for item in _STATE_ORDER})[state] = int(count)
    return dict(sorted(grouped.items()))


def get_executive_coverage_summary(
    db: Session,
    *,
    tenant_id: str,
    snapshot_id: str | None = None,
    scope_type: str = "tenant",
    scope_key: str = "all",
) -> dict[str, object] | None:
    statement = (
        select(ControlCoverageSnapshot, CoverageScope)
        .join(
            CoverageScope,
            (CoverageScope.tenant_id == ControlCoverageSnapshot.tenant_id)
            & (CoverageScope.id == ControlCoverageSnapshot.scope_id),
        )
        .where(
            ControlCoverageSnapshot.tenant_id == tenant_id,
            ControlCoverageSnapshot.snapshot_kind == PHASE8_SNAPSHOT_KIND,
        )
    )
    if snapshot_id is not None:
        statement = statement.where(ControlCoverageSnapshot.id == snapshot_id)
    else:
        statement = statement.where(
            CoverageScope.scope_type == scope_type,
            CoverageScope.scope_key == scope_key,
        ).order_by(ControlCoverageSnapshot.computed_at.desc(), ControlCoverageSnapshot.id.desc())
    pair = db.execute(statement.limit(1)).first()
    if pair is None:
        return None
    snapshot, scope = pair
    distribution = _aggregate_distribution(db, tenant_id=tenant_id, snapshot_id=snapshot.id)
    return {
        "tenant_id": tenant_id,
        "snapshot_id": snapshot.id,
        "previous_snapshot_id": snapshot.previous_snapshot_id,
        "methodology_version": snapshot.methodology_version,
        "computed_at": snapshot.computed_at,
        "scope": {
            "scope_id": scope.id,
            "scope_type": scope.scope_type,
            "scope_key": scope.scope_key,
            "display_name": scope.display_name,
            "filters": dict(scope.filters or {}),
        },
        "state_distribution": distribution,
        "validated_coverage_percent": snapshot.headline_score,
        "denominator": snapshot.applicable_requirement_count,
        "unknown_population": snapshot.unknown_population,
        "surface_breakdown": _aggregate_breakdown(
            db,
            tenant_id=tenant_id,
            snapshot_id=snapshot.id,
            field=ControlCoverageAssessment.deployment_surface,
        ),
        "dimension_breakdown": _aggregate_breakdown(
            db,
            tenant_id=tenant_id,
            snapshot_id=snapshot.id,
            field=ControlCoverageAssessment.dimension,
        ),
        "top_gaps": _top_gaps(db, tenant_id=tenant_id, snapshot_id=snapshot.id),
        "change_since_previous": dict(snapshot.comparison_summary or {}),
        "source_versions": dict(snapshot.source_versions or {}),
        "assessment_count": sum(distribution.values()),
    }


def get_coverage_assessment_explanation(
    db: Session, *, tenant_id: str, assessment_id: str
) -> dict[str, object] | None:
    row = db.scalar(
        select(ControlCoverageAssessment).where(
            ControlCoverageAssessment.tenant_id == tenant_id,
            ControlCoverageAssessment.id == assessment_id,
        )
    )
    if row is None:
        return None
    return {
        "assessment_id": row.id,
        "snapshot_id": row.snapshot_id,
        "requirement": row.requirement_ref,
        "applicability": {"state": row.applicability_state, "reason": row.applicability_reason},
        "scope": {
            "asset_ref": row.asset_ref,
            "action_class": row.action_class,
            "action_path_ref": row.action_path_ref,
            "deployment_surface": row.deployment_surface,
            "domain_profile_ref": row.domain_profile_ref,
        },
        "dimension": row.dimension,
        "deployment_state": row.deployment_state,
        "capability_state": row.capability_state,
        "assurance_state": row.assurance_state,
        "evidence_quality": row.evidence_quality,
        "control_plan_ref": row.control_plan_ref,
        "expected_control_points": list(row.expected_control_points or []),
        "contributing_control_points": list(row.contributing_control_points or []),
        "missing_contributions": list(row.missing_contributions or []),
        "validation_refs": list(row.validation_refs or []),
        "bypass_refs": list(row.bypass_refs or []),
        "evidence_refs": list(row.evidence_refs or []),
        "lineage_refs": list(row.lineage_refs or []),
        "coverage_state": row.coverage_state,
        "reason_code": row.reason_code,
        "explanation": row.explanation,
        "criticality": row.criticality,
        "source_versions": dict(row.source_versions or {}),
        "assessed_at": row.assessed_at,
        "investigation_links": [f"/runtime-intelligence/action-trace/{ref.split(':', 1)[1]}" for ref in (row.lineage_refs or []) if str(ref).startswith("lineage:")],
    }


def list_coverage_assessments(
    db: Session,
    *,
    tenant_id: str,
    snapshot_id: str,
    state: str | None = None,
    surface: str | None = None,
    dimension: str | None = None,
    asset_ref: str | None = None,
    action_class: str | None = None,
    limit: int = 200,
) -> list[dict[str, object]]:
    snapshot = db.scalar(
        select(ControlCoverageSnapshot).where(
            ControlCoverageSnapshot.tenant_id == tenant_id,
            ControlCoverageSnapshot.id == snapshot_id,
            ControlCoverageSnapshot.snapshot_kind == PHASE8_SNAPSHOT_KIND,
        )
    )
    if snapshot is None:
        return []
    statement = select(ControlCoverageAssessment).where(
        ControlCoverageAssessment.tenant_id == tenant_id,
        ControlCoverageAssessment.snapshot_id == snapshot_id,
    )
    for field, value in (
        (ControlCoverageAssessment.coverage_state, state),
        (ControlCoverageAssessment.deployment_surface, surface),
        (ControlCoverageAssessment.dimension, dimension),
        (ControlCoverageAssessment.asset_ref, asset_ref),
        (ControlCoverageAssessment.action_class, action_class),
    ):
        if value:
            statement = statement.where(field == value)
    rows = db.scalars(
        statement.order_by(
            ControlCoverageAssessment.criticality.desc(),
            ControlCoverageAssessment.asset_ref,
            ControlCoverageAssessment.dimension,
        ).limit(min(max(limit, 1), 200))
    ).all()
    return [
        {
            "assessment_id": row.id,
            "assessment_key": row.assessment_key,
            "asset_ref": row.asset_ref,
            "action_class": row.action_class,
            "action_path_ref": row.action_path_ref,
            "deployment_surface": row.deployment_surface,
            "dimension": row.dimension,
            "coverage_state": row.coverage_state,
            "assurance_state": row.assurance_state,
            "capability_state": row.capability_state,
            "criticality": row.criticality,
            "reason_code": row.reason_code,
            "explanation": row.explanation,
            "evidence_refs": list(row.evidence_refs or []),
        }
        for row in rows
    ]
