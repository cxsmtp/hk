from __future__ import annotations

from datetime import datetime, timezone

from app.db.models.discovery_canonical import DiscoveryObservation
from app.services.hmair.cie.contracts import CIESignalType
from app.services.hmair.cie.signal_normalizer import SignalNormalizer


NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


def _observation(**overrides: object) -> DiscoveryObservation:
    material: dict[str, object] = {
        "observation_id": "observation-a",
        "tenant_id": "tenant-a",
        "assignment_id": "assignment-a",
        "scan_id": "scan-a",
        "collector_id": "collector-a",
        "collector_type": "repository_metadata",
        "collector_version": "1.0.0",
        "target_id": "target-a",
        "source_surface": "source_code",
        "subject_reference": "subject:opaque-a",
        "normalized_signal_json": {"runtime": "python", "model_provider": "openai"},
        "observed_at": NOW,
        "received_at": NOW,
        "observation_type": "repository",
        "candidate_asset_type": "unknown_ai_candidate",
        "observed_state": "observed",
        "identifiers_json": {"product": "Cursor", "repository_root": "/opaque/repo"},
        "attributes_json": {"execution_context": True},
        "configuration_summary_json": {"model": {"provider": "openai"}},
        "usage_summary_json": {},
        "capability_hints_json": ["shell_execution", "MCP_client", "not_supported"],
        "identity_hints_json": [],
        "relationship_hints_json": [{"relationship": "uses", "target": "model"}],
        "evidence_reference": "evidence://observation-a",
        "evidence_hash": "a" * 64,
        "signature_status": "valid",
        "confidence": 0.94,
        "freshness": "fresh",
        "verification_state": "partially_verified",
        "source_trust": "strong",
        "collection_scope_json": {},
        "parser_version": "1.0.0",
        "schema_version": "1.0.0",
        "evidence_mode": "direct",
        "evidence_mutability": "immutable",
        "contradiction_state": "none",
        "contradiction_references_json": [],
        "sensitivity": "metadata_only",
        "redaction_status": "redacted",
        "idempotency_key": "b" * 64,
        "payload_digest": "c" * 64,
    }
    material.update(overrides)
    return DiscoveryObservation(**material)


def test_normalizer_preserves_evidence_and_derives_product_neutral_facts() -> None:
    signal = SignalNormalizer().normalize(_observation())
    assert signal.signal_type is CIESignalType.REPOSITORY
    assert signal.evidence_hash == "a" * 64
    assert signal.product_hint == "cursor"
    assert {
        "repository_context",
        "execution_context",
        "model_context",
        "runtime_context",
        "capability:terminal_execution",
        "capability:mcp_client",
    } <= set(signal.facts)
    assert "capability:not_supported" not in signal.facts


def test_product_name_remains_explanatory_and_not_a_capability_fact() -> None:
    signal = SignalNormalizer().normalize(
        _observation(
            normalized_signal_json={},
            attributes_json={},
            configuration_summary_json={},
            capability_hints_json=[],
            identifiers_json={"product": "Cursor"},
            observation_type="application",
            source_surface="endpoint",
        )
    )
    assert signal.product_hint == "cursor"
    assert not any(item.startswith("capability:") for item in signal.facts)


def test_normalization_is_deterministic() -> None:
    normalizer = SignalNormalizer()
    assert normalizer.normalize(_observation()) == normalizer.normalize(_observation())

