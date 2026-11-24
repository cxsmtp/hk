from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.hmair.erg.confidence_engine import (
    DEFAULT_DECAY_POLICIES,
    ConfidenceEngine,
)
from app.services.hmair.erg.contracts import EdgeConfidenceInput


NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)


def _edge(
    edge_id: str,
    *,
    source: str,
    base: float = 1.0,
    observation_quality: float | None = 1.0,
    collector_quality: float | None = 1.0,
    age_days: int = 1,
    contradiction_state: str = "none",
    validation_state: str = "verified",
    weight: float = 1.0,
) -> EdgeConfidenceInput:
    return EdgeConfidenceInput(
        edge_id=edge_id,
        signal_class="runtime",
        source_surface=source,
        collector_id=f"collector-{source}",
        base_confidence=base,
        relationship_weight=weight,
        observation_quality=observation_quality,
        collector_quality=collector_quality,
        observed_at=NOW - timedelta(days=age_days),
        last_validated_at=NOW - timedelta(days=age_days),
        validation_state=validation_state,
        contradiction_state=contradiction_state,
        declared_freshness="fresh" if age_days <= 30 else "unknown",
        relationship_rule_id="relationship-runtime-v1",
        relationship_rule_version="1.0.0",
    )


def test_edge_evaluation_exposes_every_factor_and_keeps_weight_separate() -> None:
    result = ConfidenceEngine().evaluate_edge(
        edge=_edge(
            "edge-a",
            source="endpoint",
            base=0.9,
            observation_quality=0.8,
            collector_quality=0.9,
            weight=2.0,
        ),
        evaluated_at=NOW,
    )
    assert result.base_confidence == 0.9
    assert result.observation_quality_factor == 0.8
    assert result.collector_quality_factor == 0.9
    assert result.decay_factor == 1.0
    assert result.effective_confidence == pytest.approx(0.648)
    assert result.edge_quality == pytest.approx(0.72)
    assert result.relationship_weight == 2.0


def test_decay_is_versioned_utc_and_never_mutates_base_confidence() -> None:
    engine = ConfidenceEngine()
    fresh = engine.evaluate_edge(edge=_edge("fresh", source="endpoint", age_days=30), evaluated_at=NOW)
    stale = engine.evaluate_edge(edge=_edge("stale", source="endpoint", age_days=31), evaluated_at=NOW)
    expired = engine.evaluate_edge(edge=_edge("expired", source="endpoint", age_days=91), evaluated_at=NOW)
    assert fresh.decay_factor == 1.0
    assert stale.decay_factor == 0.65
    assert expired.decay_factor == 0.25
    assert expired.base_confidence == 1.0
    assert expired.decay_policy_version == "1.0.0"
    with pytest.raises(ValueError, match="timezone-aware"):
        engine.evaluate_edge(
            edge=_edge("naive", source="endpoint"),
            evaluated_at=datetime(2026, 8, 16, 12, 0),
        )


def test_missing_quality_or_decay_policy_is_unknown_not_perfect() -> None:
    engine = ConfidenceEngine(decay_policies={})
    result = engine.evaluate_edge(
        edge=_edge(
            "edge-unknown",
            source="endpoint",
            observation_quality=None,
        ),
        evaluated_at=NOW,
    )
    assert result.effective_confidence is None
    assert result.edge_quality is None
    assert result.freshness == "unknown"
    assert result.automatic_resolution_eligible is False
    assert {"observation_quality_unknown", "decay_policy_unknown"} <= set(result.limitations)


def test_weighted_evidence_quality_is_exact_and_reproducible() -> None:
    engine = ConfidenceEngine()
    first = engine.evaluate_edge(
        edge=_edge("first", source="endpoint", observation_quality=0.8, collector_quality=1.0, weight=1.0),
        evaluated_at=NOW,
    )
    second = engine.evaluate_edge(
        edge=_edge("second", source="network", observation_quality=0.6, collector_quality=1.0, weight=3.0),
        evaluated_at=NOW,
    )
    quality = engine.aggregate_evidence_quality(edges=(first, second))
    assert quality.evidence_quality == pytest.approx(0.65)
    assert quality.total_weight == 4.0
    assert quality.unknown_edge_ids == ()


def test_source_diversity_caps_and_create_threshold_are_exact() -> None:
    engine = ConfidenceEngine()
    one = tuple(
        engine.evaluate_edge(edge=_edge("one", source="endpoint"), evaluated_at=NOW)
        for _ in range(1)
    )
    two = (
        engine.evaluate_edge(edge=_edge("two-a", source="endpoint"), evaluated_at=NOW),
        engine.evaluate_edge(edge=_edge("two-b", source="network"), evaluated_at=NOW),
    )
    three = two + (
        engine.evaluate_edge(edge=_edge("three", source="repository"), evaluated_at=NOW),
    )
    assert engine.evaluate_resolution(edges=one, rule_cap=0.98, anchor_confidences=(1.0,), anchors_satisfied=True, strong_relationship=True).confidence == 0.70
    two_result = engine.evaluate_resolution(edges=two, rule_cap=0.98, anchor_confidences=(1.0,), anchors_satisfied=True, strong_relationship=True)
    assert two_result.confidence == 0.90
    assert two_result.create_eligible is True
    assert two_result.attach_eligible is False
    three_result = engine.evaluate_resolution(edges=three, rule_cap=0.98, anchor_confidences=(1.0,), anchors_satisfied=True, strong_relationship=True)
    assert three_result.confidence == 0.98
    assert three_result.create_eligible is True
    assert three_result.attach_eligible is True


def test_confirmed_contradiction_or_missing_anchor_prohibits_automatic_resolution() -> None:
    engine = ConfidenceEngine()
    edges = (
        engine.evaluate_edge(edge=_edge("a", source="endpoint"), evaluated_at=NOW),
        engine.evaluate_edge(edge=_edge("b", source="network", contradiction_state="confirmed"), evaluated_at=NOW),
        engine.evaluate_edge(edge=_edge("c", source="repository"), evaluated_at=NOW),
    )
    contradicted = engine.evaluate_resolution(
        edges=edges,
        rule_cap=0.98,
        anchor_confidences=(1.0,),
        anchors_satisfied=True,
        strong_relationship=True,
    )
    assert contradicted.create_eligible is False
    assert contradicted.attach_eligible is False
    assert contradicted.recommended_action == "manual_review"
    assert "unresolved_confirmed_contradiction" in contradicted.limitations

    clean_edges = tuple(
        engine.evaluate_edge(edge=_edge(f"clean-{index}", source=source), evaluated_at=NOW)
        for index, source in enumerate(("endpoint", "network", "repository"))
    )
    missing_anchor = engine.evaluate_resolution(
        edges=clean_edges,
        rule_cap=0.98,
        anchor_confidences=(),
        anchors_satisfied=False,
        strong_relationship=True,
    )
    assert missing_anchor.create_eligible is False
    assert missing_anchor.recommended_action == "manual_review"
    assert "required_anchor_missing" in missing_anchor.limitations


def test_default_decay_policy_is_visible_and_not_hidden() -> None:
    policy = DEFAULT_DECAY_POLICIES["runtime"]
    assert policy.policy_id == "erg-decay-runtime"
    assert policy.version == "1.0.0"
    assert policy.fresh_days == 30
    assert policy.stale_days == 90
    assert policy.fresh_factor == 1.0
    assert policy.stale_factor == 0.65
    assert policy.expired_factor == 0.25

