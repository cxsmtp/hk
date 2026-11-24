from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect

from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    ExposureTimelineEventType,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.drift import (
    compare_exposure_states,
    recommendation_generated_drift,
)
from app.services.hmair.exposure.exposure_timeline import (
    build_exposure_timeline,
    build_timeline_entry,
)
from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


def _factor(
    dimension: ExposureDimension,
    state: str,
    index: int,
    *,
    verification: VerificationStatus = VerificationStatus.VERIFIED,
) -> ExposureFactor:
    return ExposureFactor(
        dimension=dimension,
        source_type=f"authority_{dimension.value}",
        source_id=f"source-{dimension.value}-{index}",
        state=state,
        evidence_refs=(f"evidence-{dimension.value}-{index}",),
        confidence=0.9,
        verification_status=verification,
        freshness=FreshnessState.FRESH,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="timeline-test/1.0",
        collector_group=dimension.value,
    )


def _result(
    extent: ExposureExtent,
    *,
    verification: VerificationStatus = VerificationStatus.VERIFIED,
) -> ExposureRuleResult:
    return ExposureRuleResult(
        category_id="coding_exposure",
        category_version="1.0.0",
        methodology_version="1.0.0",
        extent=extent,
        proven_lower_bound=None if extent is ExposureExtent.UNKNOWN else extent,
        contributors=(),
        contradictions=(),
        unknown_dimensions=(),
        confidence=0.9,
        verification_status=verification,
        evidence_quality=None,
        collector_diversity=1,
        evidence_refs=(),
        reasoning_trace=("timeline_fixture",),
        limitations=("evidence_quality_authority_unavailable",),
    )


def _compare(
    before: ExposureRuleResult,
    after: ExposureRuleResult,
    *,
    before_factors: tuple[ExposureFactor, ...] = (),
    after_factors: tuple[ExposureFactor, ...] = (),
    event: str = "event-1",
    occurred_at: datetime = NOW,
):
    return compare_exposure_states(
        before=before,
        after=after,
        before_factors=before_factors,
        after_factors=after_factors,
        source_event_refs=(event,),
        occurred_at=occurred_at,
    )


def test_drift_maps_all_approved_event_types_without_risk_scoring() -> None:
    increased = _compare(_result(ExposureExtent.LIMITED), _result(ExposureExtent.MATERIAL))
    reduced = _compare(_result(ExposureExtent.BROAD), _result(ExposureExtent.LIMITED))
    verified = _compare(
        _result(ExposureExtent.MATERIAL, verification=VerificationStatus.INFERRED),
        _result(ExposureExtent.MATERIAL),
    )
    changed = _compare(
        _result(ExposureExtent.MATERIAL),
        _result(ExposureExtent.MATERIAL),
        before_factors=(_factor(ExposureDimension.PROVIDER, "provider_a", 1),),
        after_factors=(_factor(ExposureDimension.PROVIDER, "provider_b", 2),),
    )
    coverage_improved = _compare(
        _result(ExposureExtent.MATERIAL),
        _result(ExposureExtent.MATERIAL),
        before_factors=(_factor(ExposureDimension.CONTROL_COVERAGE, "authorization:not_covered", 1),),
        after_factors=(_factor(ExposureDimension.CONTROL_COVERAGE, "authorization:covered", 2),),
    )
    coverage_reduced = _compare(
        _result(ExposureExtent.MATERIAL),
        _result(ExposureExtent.MATERIAL),
        before_factors=(_factor(ExposureDimension.CONTROL_COVERAGE, "authorization:covered", 1),),
        after_factors=(_factor(ExposureDimension.CONTROL_COVERAGE, "authorization:not_covered", 2),),
    )
    recommendation = recommendation_generated_drift(
        category_id="coding_exposure",
        recommendation_id="a" * 64,
        source_event_refs=("recommendation-source",),
        occurred_at=NOW,
        confidence=0.9,
    )

    assert {
        increased.event_type,
        reduced.event_type,
        verified.event_type,
        changed.event_type,
        coverage_improved.event_type,
        coverage_reduced.event_type,
        recommendation.event_type,
    } == set(ExposureTimelineEventType)
    assert "risk_score" not in inspect.signature(compare_exposure_states).parameters


def test_timeline_ids_and_order_are_deterministic_and_bounded() -> None:
    changes = tuple(
        _compare(
            _result(ExposureExtent.LIMITED),
            _result(ExposureExtent.MATERIAL),
            event=f"event-{index}",
            occurred_at=NOW - timedelta(days=index),
        )
        for index in range(5)
    )
    first = build_exposure_timeline(
        changes=tuple(reversed(changes)),
        rule_version="1.0.0",
        as_of=NOW,
        lookback_days=3,
        limit=2,
    )
    second = build_exposure_timeline(
        changes=changes,
        rule_version="1.0.0",
        as_of=NOW,
        lookback_days=3,
        limit=2,
    )

    assert first == second
    assert len(first) == 2
    assert [item.occurred_at for item in first] == sorted(
        (item.occurred_at for item in first), reverse=True
    )
    assert [item.source_event_refs for item in first] == [("event-0",), ("event-1",)]
    assert all(len(item.event_id) == 64 for item in first)


def test_event_id_uses_only_sorted_source_events_category_and_rule_version() -> None:
    drift = compare_exposure_states(
        before=_result(ExposureExtent.LIMITED),
        after=_result(ExposureExtent.MATERIAL),
        before_factors=(),
        after_factors=(),
        source_event_refs=("source-b", "source-a"),
        occurred_at=NOW,
    )
    first = build_timeline_entry(drift=drift, rule_version="1.0.0")
    reordered = drift.model_copy(update={"source_event_refs": ("source-a", "source-b")})
    second = build_timeline_entry(drift=reordered, rule_version="1.0.0")
    changed_rule = build_timeline_entry(drift=drift, rule_version="1.0.1")

    assert first.event_id == second.event_id
    assert first.event_id != changed_rule.event_id
    assert first.source_event_refs == ("source-a", "source-b")


def test_unknown_transition_is_changed_not_increased_or_reduced() -> None:
    became_unknown = _compare(
        _result(ExposureExtent.MATERIAL),
        _result(ExposureExtent.UNKNOWN, verification=VerificationStatus.UNKNOWN),
    )
    became_known = _compare(
        _result(ExposureExtent.UNKNOWN, verification=VerificationStatus.UNKNOWN),
        _result(ExposureExtent.LIMITED),
    )
    assert became_unknown.event_type is ExposureTimelineEventType.EXPOSURE_CHANGED
    assert became_known.event_type is ExposureTimelineEventType.EXPOSURE_CHANGED


def test_distinct_extent_changes_have_distinct_event_ids() -> None:
    material = build_timeline_entry(
        drift=_compare(_result(ExposureExtent.LIMITED), _result(ExposureExtent.MATERIAL)),
        rule_version="1.0.0",
    )
    broad = build_timeline_entry(
        drift=_compare(_result(ExposureExtent.LIMITED), _result(ExposureExtent.BROAD)),
        rule_version="1.0.0",
    )
    assert material.event_id != broad.event_id


def test_timeline_projection_has_no_database_write_surface() -> None:
    assert "db" not in inspect.signature(build_exposure_timeline).parameters
    source = inspect.getsource(build_exposure_timeline)
    assert "add(" not in source
    assert "commit(" not in source
    assert "execute(" not in source


def test_drift_bounds_large_change_sets_and_marks_truncation() -> None:
    before_factors = tuple(
        _factor(ExposureDimension.RUNTIME, f"runtime-before-{index:03d}", index)
        for index in range(70)
    )
    after_factors = tuple(
        _factor(ExposureDimension.RUNTIME, f"runtime-after-{index:03d}", index + 100)
        for index in range(70)
    )

    drift = _compare(
        _result(ExposureExtent.MATERIAL),
        _result(ExposureExtent.MATERIAL),
        before_factors=before_factors,
        after_factors=after_factors,
    )

    assert len(drift.changed_factors) == 64
    assert "changed_factors_truncated" in drift.limitations
