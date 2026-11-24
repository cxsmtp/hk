from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services.hmair.collector_registry import CollectorRegistry
from app.services.hmair.collector_sdk import DiscoveryTargetView
from app.services.hmair.collectors.aws_gcp import (
    AWSAIDiscoveryCollector,
    GCPAIDiscoveryCollector,
)
from app.services.hmair.collectors.azure import AzureAIDiscoveryCollector
from app.services.hmair.collectors.data import DataAIDiscoveryCollector
from app.services.hmair.collectors.network import NetworkAIDiscoveryCollector
from app.services.hmair.collectors.path_native import (
    PathNativeSignal,
    register_controlled_breadth_collectors,
)
from app.services.hmair.collectors.repository_ci import (
    RepositoryAIDiscoveryCollector,
)
from app.services.hmair.collectors.saas_identity import (
    IdentityAIDiscoveryCollector,
    SaaSAIDiscoveryCollector,
)


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def _signal(**updates: object) -> PathNativeSignal:
    values: dict[str, object] = {
        "observation_id": "breadth-observation-a",
        "scan_id": "00000000-0000-0000-0000-000000000001",
        "target_id": "breadth-target-a",
        "subject_reference": "resource:fingerprint-a",
        "raw_signal_type": "unknown_ai_signal",
        "asset_candidate_type": "unknown_ai_candidate",
        "observed_state": "observed",
        "normalized_signal": {"resource_class": "unknown_ai_resource"},
        "identifiers": {"resource_ref": "resource:fingerprint-a"},
        "configuration_summary": {},
        "usage_summary": {},
        "capability_hints": (),
        "identity_hints": (),
        "relationship_hints": (),
        "evidence_reference": "evidence://breadth-a",
        "evidence_hash": "a" * 64,
        "observed_at": NOW,
        "confidence": 0.55,
        "freshness": "fresh",
        "verification_state": "partially_verified",
        "source_trust": "medium",
        "collection_scope": {"scope_type": "provider_metadata"},
        "evidence_mode": "direct",
        "evidence_mutability": "immutable",
        "contradiction_state": "none",
        "contradiction_references": (),
    }
    values.update(updates)
    return PathNativeSignal(**values)


def test_controlled_breadth_registration_is_explicit_default_off() -> None:
    registry = CollectorRegistry()
    register_controlled_breadth_collectors(registry, enabled=False)
    assert registry.list_declarations() == ()

    register_controlled_breadth_collectors(registry, enabled=True)
    declarations = registry.list_declarations()
    assert {item.collector_type for item in declarations} == {
        "phase2_aws_ai",
        "phase2_azure_ai",
        "phase2_data_ai",
        "phase2_gcp_ai",
        "phase2_identity_ai",
        "phase2_network_ai",
        "phase2_repository_ai",
        "phase2_saas_ai",
    }
    assert all(item.active_capabilities == () for item in declarations)
    assert all(item.control_capability == "monitor_only" for item in declarations)
    assert all(item.health == "unknown" for item in declarations)
    assert all(item.permissions_required for item in declarations)
    assert all(item.limitations for item in declarations)


def test_cloud_metadata_preserves_resource_identity_and_unknown_usage() -> None:
    foundry = _signal(
        raw_signal_type="agent_resource",
        asset_candidate_type="ai_agent",
        observed_state="configured",
        normalized_signal={
            "provider": "azure",
            "resource_type": "foundry_agent",
            "region": "uaenorth",
        },
        identifiers={"provider_resource_id_hash": "b" * 64},
        configuration_summary={"identity_mode": "managed_identity"},
        relationship_hints=(
            {"relationship": "uses_model", "target_ref": "model:hash-b"},
            {"relationship": "exposed_by", "target_ref": "apim:hash-c"},
        ),
        capability_hints=("agent_orchestration", "tool_use"),
        usage_summary={},
        verification_state="verified",
        source_trust="strong",
        confidence=0.95,
    )
    collector = AzureAIDiscoveryCollector(signals=(foundry,))
    observation = collector.emit_observations()[0]
    assert observation.observed_state.value == "configured"
    assert dict(observation.usage_summary) == {}
    assert dict(observation.normalized_signal)["resource_type"] == "foundry_agent"
    assert collector.collect_usage(
        collector.enumerate_scope(
            DiscoveryTargetView(
                target_id="azure-a",
                target_type="cloud_subscription",
                identifier="subscription:fingerprint-a",
                environment="production",
                permitted_methods=("metadata",),
                exclusions=(),
                rate_limit=60,
                active_scan_allowed=False,
                sensitive_scope=False,
            )
        )[0]
    ) == ()

    for adapter in (AWSAIDiscoveryCollector(), GCPAIDiscoveryCollector()):
        assert adapter.declaration.health == "unknown"
        assert "usage" in " ".join(adapter.report_limitations()).casefold()


def test_saas_license_and_identity_assignment_never_become_usage() -> None:
    license_signal = _signal(
        observation_id="saas-license-a",
        raw_signal_type="license_assignment",
        asset_candidate_type="ai_saas",
        observed_state="enabled",
        normalized_signal={"product_family": "enterprise_copilot"},
        configuration_summary={"license_count": 20},
        usage_summary={},
    )
    identity_signal = _signal(
        observation_id="identity-assignment-a",
        raw_signal_type="service_principal",
        asset_candidate_type="ai_identity",
        observed_state="configured",
        normalized_signal={"identity_type": "service_principal"},
        identity_hints=(
            {"identity_type": "service_principal", "identity_ref": "sp:hash-a"},
        ),
        usage_summary={},
    )
    saas = SaaSAIDiscoveryCollector(signals=(license_signal,))
    identity = IdentityAIDiscoveryCollector(signals=(identity_signal,))
    assert saas.emit_observations()[0].observed_state.value == "enabled"
    assert dict(saas.emit_observations()[0].usage_summary) == {}
    assert identity.emit_observations()[0].observed_state.value == "configured"
    assert dict(identity.emit_observations()[0].usage_summary) == {}


def test_repository_network_and_data_collectors_keep_evidence_bounded() -> None:
    repository = RepositoryAIDiscoveryCollector(
        signals=(
            _signal(
                observation_id="repo-reference-a",
                raw_signal_type="sdk_dependency",
                asset_candidate_type="ai_application",
                observed_state="configured",
                normalized_signal={
                    "dependency_family": "model_sdk",
                    "path_hash": "c" * 64,
                    "commit_hash": "d" * 64,
                },
                usage_summary={},
            ),
        )
    )
    network = NetworkAIDiscoveryCollector(
        signals=(
            _signal(
                observation_id="network-flow-a",
                raw_signal_type="network_flow",
                asset_candidate_type="unknown_ai_candidate",
                observed_state="observed",
                normalized_signal={
                    "destination_class": "model_provider",
                    "transport": "tls",
                },
                identity_hints=(),
                usage_summary={"flow_count": 1, "actor_class": "unknown"},
                confidence=0.4,
                verification_state="inferred",
                source_trust="weak",
            ),
        )
    )
    data = DataAIDiscoveryCollector(
        signals=(
            _signal(
                observation_id="vector-index-a",
                raw_signal_type="vector_db_reference",
                asset_candidate_type="vector_store",
                observed_state="configured",
                normalized_signal={
                    "engine_family": "pgvector",
                    "index_ref": "index:hash-a",
                },
                usage_summary={},
            ),
        )
    )

    assert repository.emit_observations()[0].observed_state.value == "configured"
    network_observation = network.emit_observations()[0]
    assert network_observation.verification_state.value == "inferred"
    assert network_observation.source_trust.value == "weak"
    assert data.emit_observations()[0].raw_signal_type.value == "vector_db_reference"

    with pytest.raises(ValueError):
        _signal(normalized_signal={"database_row": {"secret": "private"}})
    with pytest.raises(ValueError):
        _signal(normalized_signal={"file_content": "proprietary source"})
