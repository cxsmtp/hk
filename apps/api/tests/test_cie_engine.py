from __future__ import annotations

from datetime import datetime, timezone

from app.services.hmair.cie.contracts import CIESignalType, NormalizedCapabilitySignal
from app.services.hmair.cie.service import CapabilityInferenceEngine


NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


def _signal(signal_id: str, fact: str, source: str) -> NormalizedCapabilitySignal:
    return NormalizedCapabilitySignal(
        signal_id=signal_id,
        tenant_id="tenant-a",
        observation_id=f"obs-{signal_id}",
        collector_id=f"collector-{source}",
        source=source,
        signal_type=CIESignalType.PROCESS,
        timestamp=NOW,
        confidence=0.96,
        attributes={},
        facts=(fact,),
        relationship_hints=(),
        evidence_reference=f"evidence://{signal_id}",
        evidence_hash="a" * 64,
        freshness="fresh",
        verification_state="partially_verified",
        source_trust="medium",
        contradiction_state="none",
        product_hint=None,
    )


def test_inference_result_is_pre_asset_explainable_and_deterministic() -> None:
    signals = (
        _signal("repo", "repository_context", "source_code"),
        _signal("exec", "execution_context", "endpoint"),
        _signal("model", "model_context", "network"),
    )
    engine = CapabilityInferenceEngine()
    first = engine.infer_signals(signals=signals, validated_at=NOW)
    second = engine.infer_signals(signals=tuple(reversed(signals)), validated_at=NOW)
    assert first == second
    assert first.subject_reference_hash == second.subject_reference_hash
    assert first.recommended_asset_type == "agent"
    assert first.recommended_ecosystem == "coding"
    assert any(item.rule_id == "coding-composition-v1" for item in first.evaluations)
    assert first.observation_ids == ("obs-exec", "obs-model", "obs-repo")


def test_no_matching_evidence_remains_unknown() -> None:
    result = CapabilityInferenceEngine().infer_signals(
        signals=(_signal("unknown", "product:renamed-ai", "endpoint"),),
        validated_at=NOW,
    )
    assert result.evaluations == ()
    assert result.recommended_asset_type == "unknown_ai_candidate"
    assert result.recommended_ecosystem == "unknown"
    assert "no_capability_rule_matched" in result.limitations


def test_optional_features_are_explicitly_reported_when_disabled() -> None:
    result = CapabilityInferenceEngine().infer_signals(
        signals=(_signal("read", "capability:filesystem_read", "endpoint"),),
        validated_at=NOW,
    )
    assert {
        "genome_disabled",
        "marketplace_disabled",
        "dependency_graph_disabled",
        "drift_disabled",
    } <= set(result.limitations)

