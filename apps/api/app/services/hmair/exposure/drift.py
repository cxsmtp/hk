from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, field_validator

from app.services.hmair.contracts import StrictContract
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    ExposureTimelineEventType,
    VerificationStatus,
)
from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult


_EXTENT_RANK = {
    ExposureExtent.NONE: 0,
    ExposureExtent.LIMITED: 1,
    ExposureExtent.MATERIAL: 2,
    ExposureExtent.BROAD: 3,
    ExposureExtent.UNKNOWN: -1,
}
_VERIFICATION_RANK = {
    VerificationStatus.CONTRADICTED: 0,
    VerificationStatus.UNKNOWN: 1,
    VerificationStatus.STALE: 2,
    VerificationStatus.INFERRED: 3,
    VerificationStatus.PARTIALLY_VERIFIED: 4,
    VerificationStatus.VERIFIED: 5,
}


class ExposureDrift(StrictContract):
    event_type: ExposureTimelineEventType
    category_id: str = Field(min_length=1, max_length=64)
    occurred_at: datetime
    before_extent: ExposureExtent | None = None
    after_extent: ExposureExtent | None = None
    changed_factors: tuple[str, ...] = Field(default=(), max_length=64)
    source_event_refs: tuple[str, ...] = Field(min_length=1, max_length=64)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=64)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("occurred_at")
    @classmethod
    def occurred_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("exposure drift timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("changed_factors", "source_event_refs", "evidence_refs", "limitations")
    @classmethod
    def collections_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(item.strip() for item in value)))
        if any(not item or len(item) > 255 for item in normalized):
            raise ValueError("exposure drift references must be bounded")
        return normalized


def _factor_marker(factor: ExposureFactor) -> str:
    return ":".join(
        (
            factor.dimension.value,
            factor.source_type,
            factor.source_id,
            factor.state,
        )
    )[:255]


def _coverage_rank(factors: tuple[ExposureFactor, ...]) -> int | None:
    states = {
        item.state.casefold().rsplit(":", maxsplit=1)[-1]
        for item in factors
        if item.dimension is ExposureDimension.CONTROL_COVERAGE
    }
    if not states:
        return None
    ranks = {
        "not_covered": 0,
        "unknown": 1,
        "not_applicable": 1,
        "covered": 2,
    }
    known = [ranks[state] for state in states if state in ranks]
    return min(known) if known else None


def _bounded_limitations(
    values: set[str], *, required_markers: set[str]
) -> tuple[str, ...]:
    ordered = tuple(sorted(values))
    if len(ordered) <= 32:
        return ordered
    markers = tuple(sorted(required_markers.intersection(values)))[:32]
    remaining = tuple(item for item in ordered if item not in markers)
    return tuple(sorted((*remaining[: 32 - len(markers)], *markers)))


def compare_exposure_states(
    *,
    before: ExposureRuleResult,
    after: ExposureRuleResult,
    before_factors: tuple[ExposureFactor, ...],
    after_factors: tuple[ExposureFactor, ...],
    source_event_refs: tuple[str, ...],
    occurred_at: datetime,
) -> ExposureDrift:
    if before.category_id != after.category_id:
        raise ValueError("exposure drift requires one exact category")

    before_markers = {_factor_marker(item) for item in before_factors}
    after_markers = {_factor_marker(item) for item in after_factors}
    all_changed = tuple(sorted(before_markers ^ after_markers))
    changed = all_changed[:64]
    all_source_event_refs = tuple(sorted(set(source_event_refs)))
    if not all_source_event_refs:
        raise ValueError("exposure drift requires at least one source event")
    bounded_source_event_refs = all_source_event_refs[:64]
    all_evidence_refs = tuple(sorted(set(before.evidence_refs + after.evidence_refs)))
    limitation_markers: set[str] = set()
    if len(all_changed) > len(changed):
        limitation_markers.add("changed_factors_truncated")
    if len(all_source_event_refs) > len(bounded_source_event_refs):
        limitation_markers.add("source_event_refs_truncated")
    if len(all_evidence_refs) > 64:
        limitation_markers.add("evidence_refs_truncated")
    before_coverage = _coverage_rank(before_factors)
    after_coverage = _coverage_rank(after_factors)

    if before_coverage is not None and after_coverage is not None and after_coverage > before_coverage:
        event_type = ExposureTimelineEventType.EXPOSURE_COVERAGE_IMPROVED
    elif before_coverage is not None and after_coverage is not None and after_coverage < before_coverage:
        event_type = ExposureTimelineEventType.EXPOSURE_COVERAGE_REDUCED
    elif ExposureExtent.UNKNOWN in {before.extent, after.extent}:
        event_type = ExposureTimelineEventType.EXPOSURE_CHANGED
    elif _EXTENT_RANK[after.extent] > _EXTENT_RANK[before.extent]:
        event_type = ExposureTimelineEventType.EXPOSURE_INCREASED
    elif _EXTENT_RANK[after.extent] < _EXTENT_RANK[before.extent]:
        event_type = ExposureTimelineEventType.EXPOSURE_REDUCED
    elif (
        after.verification_status is VerificationStatus.VERIFIED
        and _VERIFICATION_RANK[after.verification_status]
        > _VERIFICATION_RANK[before.verification_status]
    ):
        event_type = ExposureTimelineEventType.EXPOSURE_VERIFIED
    else:
        event_type = ExposureTimelineEventType.EXPOSURE_CHANGED

    return ExposureDrift(
        event_type=event_type,
        category_id=after.category_id,
        occurred_at=occurred_at,
        before_extent=before.extent,
        after_extent=after.extent,
        changed_factors=changed,
        source_event_refs=bounded_source_event_refs,
        evidence_refs=all_evidence_refs[:64],
        confidence=after.confidence,
        limitations=_bounded_limitations(
            set(before.limitations + after.limitations) | limitation_markers,
            required_markers=limitation_markers,
        ),
    )


def recommendation_generated_drift(
    *,
    category_id: str,
    recommendation_id: str,
    source_event_refs: tuple[str, ...],
    occurred_at: datetime,
    confidence: float | None,
) -> ExposureDrift:
    return ExposureDrift(
        event_type=ExposureTimelineEventType.RECOMMENDATION_GENERATED,
        category_id=category_id,
        occurred_at=occurred_at,
        changed_factors=(f"recommendation:{recommendation_id}",),
        source_event_refs=source_event_refs,
        evidence_refs=(),
        confidence=confidence,
        limitations=("recommendation_is_deterministic_projection",),
    )


__all__ = [
    "ExposureDrift",
    "compare_exposure_states",
    "recommendation_generated_drift",
]
