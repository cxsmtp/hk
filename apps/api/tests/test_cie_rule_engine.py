from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.hmair.cie.contracts import CIESignalType, NormalizedCapabilitySignal
from app.services.hmair.cie.rule_engine import CapabilityRuleEngine


NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


def _signal(
    signal_id: str,
    *,
    facts: tuple[str, ...],
    source: str = "endpoint",
    confidence: float = 0.96,
    freshness: str = "fresh",
    verification_state: str = "partially_verified",
    contradiction_state: str = "none",
) -> NormalizedCapabilitySignal:
    return NormalizedCapabilitySignal(
        signal_id=signal_id,
        tenant_id="tenant-a",
        observation_id=f"obs-{signal_id}",
        collector_id=f"collector-{source}",
        source=source,
        signal_type=CIESignalType.PROCESS,
        timestamp=NOW,
        confidence=confidence,
        attributes={},
        facts=facts,
        relationship_hints=(),
        evidence_reference=f"evidence://{signal_id}",
        evidence_hash="a" * 64,
        freshness=freshness,
        verification_state=verification_state,
        source_trust="medium",
        contradiction_state=contradiction_state,
        product_hint=None,
    )


def _coding(signals: tuple[NormalizedCapabilitySignal, ...]):
    result = CapabilityRuleEngine().evaluate(signals=signals, validated_at=NOW)
    return next(item for item in result if item.rule_id == "coding-composition-v1")


def test_product_name_alone_never_matches_coding_rule() -> None:
    signals = (_signal("product", facts=("product:cursor",)),)
    assert CapabilityRuleEngine().evaluate(signals=signals, validated_at=NOW) == ()


def test_required_product_neutral_signals_match_coding_rule() -> None:
    signals = (
        _signal("repo", facts=("repository_context",), source="source_code"),
        _signal("exec", facts=("execution_context",), source="endpoint"),
        _signal("model", facts=("model_context",), source="network"),
    )
    coding = _coding(signals)
    assert coding.confidence == pytest.approx(0.96)
    assert coding.supporting_signal_ids == ("exec", "model", "repo")
    assert coding.source_diversity == 3


def test_single_source_confidence_is_capped_at_point_seven() -> None:
    signals = (
        _signal("repo", facts=("repository_context",)),
        _signal("exec", facts=("execution_context",)),
        _signal("model", facts=("model_context",)),
    )
    coding = _coding(signals)
    assert coding.confidence == 0.70
    assert "single_source_only" in coding.limitations


def test_stale_evidence_and_contradiction_caps_are_explained() -> None:
    signals = (
        _signal("repo", facts=("repository_context",), source="source_code"),
        _signal(
            "exec",
            facts=("execution_context",),
            source="endpoint",
            freshness="stale",
        ),
        _signal(
            "model",
            facts=("model_context", "explicitly_disabled"),
            source="network",
            contradiction_state="contradicted",
        ),
    )
    coding = _coding(signals)
    assert coding.confidence <= 0.40
    assert coding.conflicting_signal_ids == ("model",)
    assert {"contains_stale_evidence", "contains_contradiction"} <= set(
        coding.limitations
    )


def test_missing_optional_predicates_are_reported_as_unknowns() -> None:
    signals = (
        _signal("repo", facts=("repository_context",), source="source_code"),
        _signal("exec", facts=("execution_context",), source="endpoint"),
        _signal("model", facts=("model_context",), source="network"),
    )
    coding = _coding(signals)
    assert "usage_context" in coding.unknown_predicates


def test_expired_or_inferred_only_evidence_is_never_promoted_as_verified() -> None:
    signals = (
        _signal(
            "repo",
            facts=("repository_context",),
            source="source_code",
            freshness="expired",
            verification_state="inferred",
        ),
        _signal("exec", facts=("execution_context",), source="endpoint"),
        _signal("model", facts=("model_context",), source="network"),
    )
    coding = _coding(signals)
    assert coding.confidence == 0.25
    assert coding.verification_state == "inferred"
    assert "contains_expired_evidence" in coding.limitations


def test_rule_output_is_deterministic_across_input_order() -> None:
    signals = (
        _signal("repo", facts=("repository_context",), source="source_code"),
        _signal("exec", facts=("execution_context",), source="endpoint"),
        _signal("model", facts=("model_context",), source="network"),
    )
    engine = CapabilityRuleEngine()
    assert engine.evaluate(signals=signals, validated_at=NOW) == engine.evaluate(
        signals=tuple(reversed(signals)), validated_at=NOW
    )


def test_cross_tenant_signal_bundle_is_rejected() -> None:
    first = _signal("one", facts=("repository_context",))
    second = _signal("two", facts=("execution_context",)).model_copy(
        update={"tenant_id": "tenant-b"}
    )
    with pytest.raises(ValueError, match="one tenant"):
        CapabilityRuleEngine().evaluate(signals=(first, second), validated_at=NOW)


def test_validation_timestamp_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        CapabilityRuleEngine().evaluate(
            signals=(_signal("one", facts=("repository_context",)),),
            validated_at=datetime(2026, 8, 16, 9, 0),
        )
