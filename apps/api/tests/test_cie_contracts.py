from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.services.hmair.cie.contracts import (
    CIESignalType,
    CapabilityEvaluation,
    CapabilityFamily,
    NormalizedCapabilitySignal,
)


NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


def _signal(**overrides: object) -> NormalizedCapabilitySignal:
    material: dict[str, object] = {
        "signal_id": "signal-a",
        "tenant_id": "tenant-a",
        "observation_id": "observation-a",
        "collector_id": "collector-a",
        "source": "endpoint",
        "signal_type": "process",
        "timestamp": NOW,
        "confidence": 0.9,
        "attributes": {"runtime": "python"},
        "facts": ("runtime:python", "execution_context"),
        "relationship_hints": (),
        "evidence_reference": "evidence://signal-a",
        "evidence_hash": "a" * 64,
        "freshness": "fresh",
        "verification_state": "partially_verified",
        "source_trust": "medium",
        "contradiction_state": "none",
        "product_hint": None,
    }
    material.update(overrides)
    return NormalizedCapabilitySignal.model_validate(material)


def test_signal_and_family_taxonomies_are_complete() -> None:
    assert {item.value for item in CIESignalType} == {
        "executable", "package", "dependency", "runtime", "configuration",
        "repository", "sdk", "api", "provider", "network", "dns",
        "identity", "process", "filesystem", "marketplace", "extension",
        "model", "mcp", "tool", "database", "vector_store", "prompt_store",
        "memory", "usage",
    }
    assert {item.value for item in CapabilityFamily} == {
        "coding", "research", "customer_support", "office_productivity",
        "content", "analytics", "devops", "infrastructure", "data_science",
        "rag", "memory", "workflow_automation", "model_hosting", "security",
        "cloud_administration", "custom", "unknown",
    }


def test_signal_requires_timezone_hash_and_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _signal(timestamp=datetime(2026, 8, 16, 9, 0))
    with pytest.raises(ValidationError):
        _signal(evidence_hash="not-a-hash")
    with pytest.raises(ValidationError):
        _signal(unexpected="forbidden")


def test_capability_evaluation_retains_truth_dimensions() -> None:
    evaluation = CapabilityEvaluation(
        capability_id="code_execution",
        family="coding",
        rule_id="coding-composition-v1",
        rule_version="1.0.0",
        calibration_version="conservative-caps-v1",
        confidence=0.91,
        supporting_signal_ids=("signal-a", "signal-b"),
        conflicting_signal_ids=(),
        unknown_predicates=("usage_context",),
        source_diversity=2,
        freshness="fresh",
        verification_state="inferred",
        last_validated_at=NOW,
        explanation="Repository, execution, and model context support coding.",
        limitations=("usage_not_observed",),
        recommended_asset_type="unknown_ai_candidate",
        recommended_ecosystem="coding",
    )
    assert evaluation.confidence == 0.91
    assert evaluation.unknown_predicates == ("usage_context",)

