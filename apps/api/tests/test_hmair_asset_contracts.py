from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import FrozenInstanceError, fields, is_dataclass
from datetime import datetime, timedelta, timezone
import json
import math
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import app.services.hmair as hmair


C = hmair.contracts

REQUIRED_H1B_EXPORTS = {
    "AIAssetType",
    "AICapabilityType",
    "AICapabilityState",
    "ResolutionAction",
    "ShadowAIStatus",
    "FingerprintComponentCategory",
    "ResolutionSignalCategory",
    "ResolutionActorRole",
    "ResolutionSignal",
    "AIAssetCreate",
    "AIAssetContract",
    "EvidenceClaimCreate",
    "AssetFingerprintCreate",
    "AIAssetFingerprintContract",
    "AICapabilityAssertionCreate",
    "AICapabilityContract",
    "ResolutionActor",
    "ResolutionRequest",
    "AssetMergeRequest",
    "SplitPartition",
    "AssetSplitRequest",
    "HistoryReversalRequest",
    "ResolutionDecisionContract",
    "ResolutionResult",
    "ResolutionOperationResult",
}

OUTWARD_DTO_NAMES = {
    "ResolutionSignal",
    "AIAssetCreate",
    "AIAssetContract",
    "EvidenceClaimCreate",
    "AssetFingerprintCreate",
    "AIAssetFingerprintContract",
    "AICapabilityAssertionCreate",
    "AICapabilityContract",
    "ResolutionActor",
    "ResolutionRequest",
    "AssetMergeRequest",
    "SplitPartition",
    "AssetSplitRequest",
    "HistoryReversalRequest",
    "ResolutionDecisionContract",
    "ResolutionResult",
    "ResolutionOperationResult",
}

ACCEPTED_H1A_EXPORTS = {
    "CollectorDeclaration",
    "CollectorRunStatus",
    "DiscoveryObservationInput",
    "DiscoveryScanCreate",
    "DiscoveryScanStatus",
    "DiscoveryScanType",
    "DiscoveryTargetInput",
    "DiscoveryTargetType",
    "ObservationFreshness",
    "StrictContract",
}

PRIVATE_CANONICAL_NAMES = {
    "_canonicalize_evidence_claim_input",
    "_canonicalize_asset_fingerprint_input",
    "_canonicalize_ai_capability_input",
    "_canonicalize_resolution_request",
    "_canonicalize_merge_request",
    "_canonicalize_split_request",
    "_canonicalize_reversal_request",
    "_resolution_child_material_digest",
}


def test_h1b_contract_surface_is_exported() -> None:
    missing_contracts = sorted(
        name for name in REQUIRED_H1B_EXPORTS if not hasattr(C, name)
    )
    missing_package = sorted(
        name for name in REQUIRED_H1B_EXPORTS if not hasattr(hmair, name)
    )
    assert missing_contracts == [], f"missing H1B contract symbols: {missing_contracts}"
    assert missing_package == [], f"missing H1B package exports: {missing_package}"
    assert set(hmair.__all__) == ACCEPTED_H1A_EXPORTS | REQUIRED_H1B_EXPORTS
    for name in REQUIRED_H1B_EXPORTS:
        assert getattr(hmair, name) is getattr(C, name)


def test_canonicalization_surface_is_module_visible_or_private_not_root_public() -> None:
    assert callable(C.canonical_json_bytes)
    assert not hasattr(hmair, "canonical_json_bytes")
    assert "canonical_json_bytes" not in hmair.__all__
    for name in PRIVATE_CANONICAL_NAMES:
        assert callable(getattr(C, name))
        assert not hasattr(hmair, name)
        assert name not in hmair.__all__
    assert not any("Canonical" in name for name in hmair.__all__)


def test_every_outward_h1b_dto_is_a_strict_contract_subclass() -> None:
    assert OUTWARD_DTO_NAMES < REQUIRED_H1B_EXPORTS
    for name in OUTWARD_DTO_NAMES:
        assert issubclass(getattr(C, name), C.StrictContract)


@pytest.fixture(autouse=True)
def _require_h1b_surface(request: pytest.FixtureRequest) -> None:
    """Keep RED attributable to the absent surface, not collection failures."""
    if request.node.name == "test_h1b_contract_surface_is_exported":
        return
    if any(not hasattr(C, name) for name in REQUIRED_H1B_EXPORTS):
        pytest.skip("H1B production contract surface is not implemented yet")


ASSET_TYPES = {
    "ai_application",
    "ai_saas",
    "ai_feature",
    "model",
    "model_endpoint",
    "agent",
    "agent_framework",
    "runtime",
    "llm_gateway",
    "mcp_server",
    "mcp_client",
    "mcp_tool",
    "ide",
    "cli",
    "browser_extension",
    "endpoint_application",
    "sdk",
    "api",
    "workflow",
    "plugin",
    "vector_database",
    "knowledge_base",
    "prompt_store",
    "memory_store",
    "data_connector",
    "identity",
    "service_account",
    "oauth_application",
    "unknown_ai_candidate",
}

CAPABILITY_TYPES = {
    "model_inference",
    "embeddings",
    "file_upload",
    "file_download",
    "source_code_access",
    "terminal_execution",
    "process_execution",
    "filesystem_read",
    "filesystem_write",
    "browser_automation",
    "email_send",
    "messaging_send",
    "database_read",
    "database_write",
    "vector_search",
    "MCP_client",
    "MCP_server",
    "tool_execution",
    "external_network",
    "secret_access",
    "cloud_admin",
    "identity_change",
    "memory_write",
    "persistent_side_effect",
    "code_change",
    "CI_CD",
    "customer_data_access",
}

CAPABILITY_STATES = {
    "declared",
    "configured",
    "observed",
    "inferred",
    "denied",
    "unknown",
}

RESOLUTION_ACTIONS = {"create", "merge", "attach", "reject", "manual_review"}

SHADOW_STATES = {
    "approved",
    "approved_but_uncontrolled",
    "known_unapproved",
    "suspected_shadow",
    "confirmed_shadow",
    "personal_account",
    "owner_unknown",
    "unknown",
}

FINGERPRINT_COMPONENTS = {
    "executable",
    "package",
    "dependency",
    "configuration",
    "provider",
    "model",
    "protocol",
    "runtime",
    "network",
    "capability",
    "identity",
    "behavior",
}

SIGNAL_CATEGORIES = {
    "exact provider IDs",
    "tenant IDs",
    "app registration IDs",
    "endpoint device IDs",
    "process and executable hashes",
    "package lockfiles",
    "repository origin",
    "API endpoint",
    "model deployment ID",
    "MCP server URL",
    "MCP schema fingerprint",
    "service principal",
    "Kubernetes workload UID",
    "SaaS tenant ID",
    "user identity",
    "network destination",
    "configuration path",
    "tool fingerprint",
}

UTC_TIME = datetime(2026, 8, 2, 8, 30, 45, 123456, tzinfo=timezone.utc)
OFFSET_TIME = datetime(
    2026,
    8,
    2,
    12,
    30,
    45,
    123456,
    tzinfo=timezone(timedelta(hours=4)),
)


def _signal(category: str = "API endpoint") -> dict[str, Any]:
    return {"category": category}


def _new_asset(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "asset_type": "ai_application",
        "canonical_name": "Caf\u00e9 Assistant",
        "provider": "Example AI",
        "product": "Assistant",
        "framework": None,
        "version": "1.0",
        "deployment_family": "saas",
        "technical_surface": "browser",
        "environment": "production",
    }
    data.update(updates)
    return data


def _claim(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "claim_type": "asset_identity",
        "subject_observation_id": "obs-1",
        "subject_asset_id": None,
        "source_observation_id": "obs-1",
        "evidence_node_id": "node-1",
        "claim_method": "exact provider metadata",
        "limitations": ("second limitation", "first limitation"),
        "confidence": 0.5,
        "freshness": "fresh",
        "observed_at": OFFSET_TIME,
        "idempotency_key": "claim-request-1",
    }
    data.update(updates)
    return data


def _fingerprint(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "asset_id": "asset-1",
        "source_observation_id": "obs-1",
        "evidence_claim_id": "claim-1",
        "fingerprint_version": "hmair-fp-v1",
        "component_hashes": {"provider": "b" * 64, "behavior": "a" * 64},
        "detected_products": ("Zulu", "Alpha"),
        "detected_frameworks": ("framework-z", "framework-a"),
        "detected_models": ("model-z", "model-a"),
        "detected_protocols": ("https", "grpc"),
        "detected_capabilities": ("model_inference", "MCP_client"),
        "observed_destinations": ("z-destination", "a-destination"),
        "confidence": 0.5,
        "supersedes_fingerprint_id": None,
        "drift_summary": {},
    }
    data.update(updates)
    return data


def _capability(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "asset_id": "asset-1",
        "source_observation_id": "obs-1",
        "evidence_claim_id": "claim-1",
        "name": "MCP_client",
        "state": "observed",
        "confidence": 0.5,
        "first_observed_at": OFFSET_TIME,
        "last_observed_at": datetime(
            2026,
            8,
            2,
            13,
            30,
            45,
            654321,
            tzinfo=timezone(timedelta(hours=4)),
        ),
        "extractor_version": "extractor-v1",
        "supersedes_capability_id": None,
    }
    data.update(updates)
    return data


def _actor(**updates: Any) -> Any:
    data: dict[str, Any] = {"actor_id": "op\u00e9rateur-1", "actor_role": "owner"}
    data.update(updates)
    return C.ResolutionActor(**data)


def _resolution_request(**updates: Any) -> Any:
    data: dict[str, Any] = {
        "candidate_observation_ids": ("obs-2", "obs-1"),
        "new_asset": None,
        "existing_asset_id": None,
        "matched_signals": (_signal("API endpoint"),),
        "conflicting_signals": (),
        "confidence": 0.5,
        "algorithm_version": "hmair-h1b-v1",
        "evidence_claim_id": "claim-1",
        "evidence_node_id": "node-1",
        "idempotency_key": "resolution-request-1",
        "reason": None,
    }
    data.update(updates)
    return C.ResolutionRequest(**data)


def _merge_request(**updates: Any) -> Any:
    data: dict[str, Any] = {
        "source_asset_ids": ("asset-source-2", "asset-source-1"),
        "result_asset_id": "asset-result-1",
        "candidate_observation_ids": ("obs-2", "obs-1"),
        "matched_signals": (_signal("exact provider IDs"),),
        "conflicting_signals": (),
        "confidence": 0.75,
        "algorithm_version": "hmair-merge-v1",
        "evidence_claim_id": "claim-merge-1",
        "evidence_node_id": "node-merge-1",
        "idempotency_key": "merge-request-1",
        "reason": "operator approved merge",
    }
    data.update(updates)
    return C.AssetMergeRequest(**data)


def _partition_attach(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "candidate_observation_ids": ("obs-2",),
        "new_asset": None,
        "existing_asset_id": "asset-result-2",
        "matched_signals": (_signal("MCP server URL"),),
        "conflicting_signals": (),
        "confidence": 0.6,
        "algorithm_version": "split-attach-v1",
        "evidence_claim_id": "claim-child-2",
        "evidence_node_id": "node-child-2",
    }
    data.update(updates)
    return data


def _partition_create(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "candidate_observation_ids": ("obs-1",),
        "new_asset": _new_asset(canonical_name="Caf\u00e9 Split"),
        "existing_asset_id": None,
        "matched_signals": (_signal("repository origin"),),
        "conflicting_signals": (),
        "confidence": 0.4,
        "algorithm_version": "split-create-v1",
        "evidence_claim_id": "claim-child-1",
        "evidence_node_id": "node-child-1",
    }
    data.update(updates)
    return data


def _split_request(**updates: Any) -> Any:
    data: dict[str, Any] = {
        "idempotency_key": "split-request-1",
        "source_asset_id": "asset-source-1",
        "reason": "operator approved split",
        "event_evidence_claim_id": "claim-event-1",
        "event_evidence_node_id": "node-event-1",
        # Deliberately opposite canonical digest order.
        "partitions": (_partition_attach(), _partition_create()),
    }
    data.update(updates)
    return C.AssetSplitRequest(**data)


def _observation_ids(count: int) -> tuple[str, ...]:
    return tuple(f"obs-{index:03d}" for index in range(count))


def _asset_ids(count: int) -> tuple[str, ...]:
    return tuple(f"asset-{index:03d}" for index in range(count))


def _distinct_attach_partitions(count: int) -> tuple[dict[str, Any], ...]:
    return tuple(
        _partition_attach(
            candidate_observation_ids=(f"obs-{index:03d}",),
            existing_asset_id=f"asset-{index:03d}",
            evidence_claim_id=f"claim-{index:03d}",
            evidence_node_id=f"node-{index:03d}",
        )
        for index in range(count)
    )


def _reversal_request(**updates: Any) -> Any:
    data: dict[str, Any] = {
        "idempotency_key": "reversal-request-1",
        "reversal_of_event_id": "history-event-1",
        "reason": "operator approved reversal",
        "evidence_claim_id": "claim-reversal-1",
        "evidence_node_id": "node-reversal-1",
    }
    data.update(updates)
    return C.HistoryReversalRequest(**data)


def test_exact_h1b_vocabularies() -> None:
    assert {item.value for item in C.AIAssetType} == ASSET_TYPES
    assert {item.value for item in C.AICapabilityType} == CAPABILITY_TYPES
    assert {item.value for item in C.AICapabilityState} == CAPABILITY_STATES
    assert {item.value for item in C.ResolutionAction} == RESOLUTION_ACTIONS
    assert {item.value for item in C.ShadowAIStatus} == SHADOW_STATES
    assert {
        item.value for item in C.FingerprintComponentCategory
    } == FINGERPRINT_COMPONENTS
    assert {item.value for item in C.ResolutionSignalCategory} == SIGNAL_CATEGORIES
    assert {item.value for item in C.ResolutionActorRole} == {
        "system",
        "owner",
        "admin",
    }


def test_capability_names_preserve_source_case() -> None:
    values = {item.value for item in C.AICapabilityType}
    assert {"MCP_client", "MCP_server", "CI_CD"} <= values
    assert {"mcp_client", "mcp_server", "ci_cd"}.isdisjoint(values)


def test_contract_field_sets_are_exact() -> None:
    assert set(C.ResolutionSignal.model_fields) == {"category"}
    assert set(C.AIAssetCreate.model_fields) == {
        "asset_type",
        "canonical_name",
        "provider",
        "product",
        "framework",
        "version",
        "deployment_family",
        "technical_surface",
        "environment",
    }
    assert set(C.AIAssetContract.model_fields) == {
        "asset_id",
        "tenant_id",
        "asset_type",
        "canonical_name",
        "provider",
        "product",
        "framework",
        "version",
        "deployment_family",
        "technical_surface",
        "environment",
        "owner",
        "business_unit",
        "approved_status",
        "shadow_ai_status",
        "lifecycle_status",
        "first_seen_at",
        "last_seen_at",
        "last_used_at",
        "identity_ids",
        "runtime_ids",
        "model_ids",
        "tool_ids",
        "data_source_ids",
        "capability_profile_id",
        "fingerprint_id",
        "usage_profile_id",
        "control_coverage_ref",
        "resolution_confidence",
        "source_observation_ids",
        "unresolved_conflicts",
        "evidence_bundle_id",
    }
    assert set(C.EvidenceClaimCreate.model_fields) == {
        "claim_type",
        "subject_observation_id",
        "subject_asset_id",
        "source_observation_id",
        "evidence_node_id",
        "claim_result",
        "claim_method",
        "limitations",
        "confidence",
        "freshness",
        "observed_at",
        "idempotency_key",
    }
    assert set(C.AssetFingerprintCreate.model_fields) == {
        "asset_id",
        "source_observation_id",
        "evidence_claim_id",
        "fingerprint_version",
        "component_hashes",
        "detected_products",
        "detected_frameworks",
        "detected_models",
        "detected_protocols",
        "detected_capabilities",
        "observed_destinations",
        "confidence",
        "supersedes_fingerprint_id",
        "drift_summary",
    }
    assert set(C.AIAssetFingerprintContract.model_fields) == {
        "fingerprint_id",
        "asset_id",
        "fingerprint_version",
        "component_hashes",
        "detected_products",
        "detected_frameworks",
        "detected_models",
        "detected_protocols",
        "detected_capabilities",
        "observed_destinations",
        "evidence_sources",
        "confidence",
        "created_at",
        "supersedes_fingerprint_id",
        "drift_summary",
    }
    assert set(C.AICapabilityAssertionCreate.model_fields) == {
        "asset_id",
        "source_observation_id",
        "evidence_claim_id",
        "name",
        "state",
        "confidence",
        "first_observed_at",
        "last_observed_at",
        "extractor_version",
        "supersedes_capability_id",
    }
    assert set(C.AICapabilityContract.model_fields) == {
        "name",
        "state",
        "evidence",
        "confidence",
        "first_observed_at",
        "last_observed_at",
        "extractor_version",
    }
    assert set(C.ResolutionDecisionContract.model_fields) == {
        "decision_id",
        "candidate_observation_ids",
        "canonical_asset_id",
        "action",
        "matched_signals",
        "conflicting_signals",
        "confidence",
        "algorithm_version",
        "created_at",
    }


def test_mutation_request_field_sets_are_exact() -> None:
    assert set(C.ResolutionActor.model_fields) == {"actor_id", "actor_role"}
    assert set(C.ResolutionRequest.model_fields) == {
        "candidate_observation_ids",
        "new_asset",
        "existing_asset_id",
        "matched_signals",
        "conflicting_signals",
        "confidence",
        "algorithm_version",
        "evidence_claim_id",
        "evidence_node_id",
        "idempotency_key",
        "reason",
    }
    assert set(C.AssetMergeRequest.model_fields) == {
        "source_asset_ids",
        "result_asset_id",
        "candidate_observation_ids",
        "matched_signals",
        "conflicting_signals",
        "confidence",
        "algorithm_version",
        "evidence_claim_id",
        "evidence_node_id",
        "idempotency_key",
        "reason",
    }
    assert set(C.SplitPartition.model_fields) == {
        "candidate_observation_ids",
        "new_asset",
        "existing_asset_id",
        "matched_signals",
        "conflicting_signals",
        "confidence",
        "algorithm_version",
        "evidence_claim_id",
        "evidence_node_id",
    }
    assert set(C.AssetSplitRequest.model_fields) == {
        "idempotency_key",
        "source_asset_id",
        "reason",
        "event_evidence_claim_id",
        "event_evidence_node_id",
        "partitions",
    }
    assert set(C.HistoryReversalRequest.model_fields) == {
        "idempotency_key",
        "reversal_of_event_id",
        "reason",
        "evidence_claim_id",
        "evidence_node_id",
    }
    assert set(C.ResolutionResult.model_fields) == {"decision", "asset"}
    assert set(C.ResolutionOperationResult.model_fields) == {
        "history_event_id",
        "results",
    }


def test_private_canonical_material_carriers_are_frozen_slotted_dataclasses() -> None:
    claim = C._canonicalize_evidence_claim_input(
        tenant_id="tenant-1",
        payload=C.EvidenceClaimCreate(**_claim()),
    )
    resolution = C._canonicalize_resolution_request(
        tenant_id="tenant-1",
        actor=_actor(),
        action=C.ResolutionAction("reject"),
        payload=_resolution_request(),
    )
    for carrier in (claim, resolution, resolution.decisions[0]):
        assert is_dataclass(carrier)
        assert type(carrier).__name__.startswith("_")
        assert type(carrier).__dataclass_params__.frozen is True
        assert not hasattr(carrier, "__dict__")
        assert not isinstance(carrier, BaseModel)
        real_field_name = fields(carrier)[0].name
        with pytest.raises(FrozenInstanceError):
            setattr(carrier, real_field_name, getattr(carrier, real_field_name))


def _valid_contract_instances() -> tuple[Any, ...]:
    asset = C.AIAssetContract(
        asset_id="asset-1",
        tenant_id="tenant-1",
        **_new_asset(),
        owner=None,
        business_unit=None,
        approved_status="unknown",
        shadow_ai_status="unknown",
        lifecycle_status="unknown",
        first_seen_at=OFFSET_TIME,
        last_seen_at=OFFSET_TIME,
        last_used_at=None,
        identity_ids=(),
        runtime_ids=(),
        model_ids=(),
        tool_ids=(),
        data_source_ids=(),
        capability_profile_id=None,
        fingerprint_id=None,
        usage_profile_id=None,
        control_coverage_ref=None,
        resolution_confidence=0.5,
        source_observation_ids=("obs-1",),
        unresolved_conflicts=(),
        evidence_bundle_id="node-1",
    )
    fingerprint = C.AIAssetFingerprintContract(
        fingerprint_id="fingerprint-1",
        asset_id="asset-1",
        fingerprint_version="hmair-fp-v1",
        component_hashes={"provider": "b" * 64},
        detected_products=("Assistant",),
        detected_frameworks=(),
        detected_models=("model-1",),
        detected_protocols=("https",),
        detected_capabilities=("model_inference",),
        observed_destinations=("provider-destination",),
        evidence_sources=("claim-1",),
        confidence=0.5,
        created_at=OFFSET_TIME,
        supersedes_fingerprint_id=None,
        drift_summary={},
    )
    capability = C.AICapabilityContract(
        name="model_inference",
        state="observed",
        evidence=("claim-1",),
        confidence=0.5,
        first_observed_at=OFFSET_TIME,
        last_observed_at=OFFSET_TIME,
        extractor_version="extractor-v1",
    )
    decision = C.ResolutionDecisionContract(
        decision_id="decision-1",
        candidate_observation_ids=("obs-1",),
        canonical_asset_id=None,
        action="manual_review",
        matched_signals=(_signal(),),
        conflicting_signals=(),
        confidence=0.5,
        algorithm_version="hmair-h1b-v1",
        created_at=OFFSET_TIME,
    )
    return (
        C.ResolutionSignal(**_signal()),
        C.AIAssetCreate(**_new_asset()),
        asset,
        C.EvidenceClaimCreate(**_claim()),
        C.AssetFingerprintCreate(**_fingerprint()),
        fingerprint,
        C.AICapabilityAssertionCreate(**_capability()),
        capability,
        _actor(),
        _resolution_request(),
        _merge_request(),
        C.SplitPartition(**_partition_create()),
        _split_request(),
        _reversal_request(),
        decision,
        C.ResolutionResult(decision=decision, asset=None),
        C.ResolutionOperationResult(
            history_event_id="history-1",
            results=(C.ResolutionResult(decision=decision, asset=None),),
        ),
    )


def test_h1b_asset_contract_enforces_owned_null_and_empty_boundaries() -> None:
    asset = _valid_contract_instances()[2]
    data = asset.model_dump(mode="json")
    for field_name in (
        "owner",
        "business_unit",
        "last_used_at",
        "capability_profile_id",
        "usage_profile_id",
        "control_coverage_ref",
    ):
        assert data[field_name] is None
        with pytest.raises(ValidationError):
            C.AIAssetContract(**{**data, field_name: "not-h1b-authoritative"})
    for field_name in (
        "identity_ids",
        "runtime_ids",
        "model_ids",
        "tool_ids",
        "data_source_ids",
    ):
        assert data[field_name] == []
        with pytest.raises(ValidationError):
            C.AIAssetContract(**{**data, field_name: ("unverified-id",)})
    conflicted = C.AIAssetContract(
        **{
            **data,
            "unresolved_conflicts": (
                _signal("API endpoint"),
                _signal("repository origin"),
            ),
        }
    )
    assert tuple(
        signal.category.value for signal in conflicted.unresolved_conflicts
    ) == ("API endpoint", "repository origin")


def test_all_h1b_contracts_are_frozen_strict_and_json_round_trip_safe() -> None:
    for instance in _valid_contract_instances():
        with pytest.raises(ValidationError):
            type(instance)(**{**instance.model_dump(mode="json"), "extra": "forbidden"})
        with pytest.raises(ValidationError):
            instance.model_copy(update={"extra": "forbidden"})
        with pytest.raises(ValidationError):
            instance.__class__.model_validate(
                {**instance.model_dump(mode="json"), "extra": "forbidden"}
            )
        with pytest.raises(ValidationError):
            instance.unexpected = "blocked"
        restored = type(instance).model_validate_json(instance.model_dump_json())
        assert restored.model_dump(mode="json") == instance.model_dump(mode="json")


@pytest.mark.parametrize(
    "entrypoint",
    ("constructor", "model_validate", "model_validate_json"),
)
def test_every_outward_dto_entrypoint_sanitizes_submitted_markers(
    entrypoint: str,
) -> None:
    marker = "RAW-H1B-DTO-MARKER-DO-NOT-RETAIN"
    instances = _valid_contract_instances()
    assert {type(instance).__name__ for instance in instances} == OUTWARD_DTO_NAMES
    for instance in instances:
        model = type(instance)
        material = {**instance.model_dump(mode="json"), marker: marker}
        with pytest.raises(ValidationError) as captured:
            if entrypoint == "constructor":
                model(**material)
            elif entrypoint == "model_validate":
                model.model_validate(material)
            else:
                model.model_validate_json(json.dumps(material, ensure_ascii=False))
        rendered = f"{captured.value}\n{captured.value.errors()!r}"
        assert marker not in rendered
        assert all(
            detail.get("input") is None and "ctx" not in detail
            for detail in captured.value.errors()
        )


def test_scalar_only_model_validate_strings_sanitizes_submitted_marker() -> None:
    marker = "RAW-H1B-STRING-MARKER-DO-NOT-RETAIN"
    with pytest.raises(ValidationError) as captured:
        C.ResolutionActor.model_validate_strings(
            {
                "actor_id": "operator-1",
                "actor_role": "owner",
                "unexpected": marker,
            }
        )
    rendered = f"{captured.value}\n{captured.value.errors()!r}"
    assert marker not in rendered
    assert all(
        detail.get("input") is None and "ctx" not in detail
        for detail in captured.value.errors()
    )


def test_resolution_results_preserve_exact_decision_asset_association_and_order() -> None:
    asset = _valid_contract_instances()[2]
    decision_data = _valid_contract_instances()[14].model_dump(mode="json")
    first_decision = C.ResolutionDecisionContract(
        **{
            **decision_data,
            "decision_id": "decision-1",
            "canonical_asset_id": "asset-1",
            "action": "attach",
        }
    )
    second_decision = C.ResolutionDecisionContract(
        **{
            **decision_data,
            "decision_id": "decision-2",
            "canonical_asset_id": "asset-1",
            "action": "merge",
        }
    )
    third_decision = C.ResolutionDecisionContract(
        **{
            **decision_data,
            "decision_id": "decision-3",
            "canonical_asset_id": "asset-1",
            "action": "create",
        }
    )
    first = C.ResolutionResult(decision=first_decision, asset=asset)
    second = C.ResolutionResult(decision=second_decision, asset=asset)
    third = C.ResolutionResult(decision=third_decision, asset=asset)
    operation = C.ResolutionOperationResult(
        history_event_id="history-1",
        results=(third, second, first),
    )
    assert tuple(result.decision.decision_id for result in operation.results) == (
        "decision-3",
        "decision-2",
        "decision-1",
    )
    result_schema = C.ResolutionOperationResult.model_json_schema()["properties"][
        "results"
    ]
    assert "minItems" not in result_schema
    assert "maxItems" not in result_schema
    assert C.ResolutionOperationResult(
        history_event_id="history-reversal",
        results=(),
    ).results == ()
    with pytest.raises(ValidationError):
        C.ResolutionResult(decision=first_decision, asset=None)
    wrong_asset = asset.model_copy(update={"asset_id": "asset-2"})
    with pytest.raises(ValidationError):
        C.ResolutionResult(decision=first_decision, asset=wrong_asset)
    manual = _valid_contract_instances()[14]
    with pytest.raises(ValidationError):
        C.ResolutionResult(decision=manual, asset=asset)


def test_nested_contract_inputs_are_detached_and_deeply_immutable() -> None:
    signal = {"category": "repository origin"}
    matched = [signal, _signal("API endpoint")]
    payload = _resolution_request(matched_signals=matched)
    signal["category"] = "tenant IDs"
    matched.append(_signal("tool fingerprint"))

    assert payload.matched_signals[0].category.value == "API endpoint"
    assert payload.matched_signals[1].category.value == "repository origin"
    with pytest.raises(ValidationError):
        payload.matched_signals[0].category = C.ResolutionSignalCategory("tenant IDs")

    components = {"provider": "b" * 64}
    fingerprint = C.AssetFingerprintCreate(**_fingerprint(component_hashes=components))
    components["model"] = "c" * 64
    assert fingerprint.component_hashes == MappingProxyType({"provider": "b" * 64})
    with pytest.raises(TypeError):
        fingerprint.component_hashes["model"] = "c" * 64


@pytest.mark.parametrize(
    ("factory", "field_name"),
    [
        (_claim, "observed_at"),
        (_capability, "first_observed_at"),
        (_capability, "last_observed_at"),
    ],
)
def test_create_contract_times_require_timezone_and_normalize_to_utc(
    factory: Any,
    field_name: str,
) -> None:
    model = C.EvidenceClaimCreate if factory is _claim else C.AICapabilityAssertionCreate
    instance = model(**factory(**{field_name: OFFSET_TIME}))
    assert getattr(instance, field_name) == UTC_TIME
    assert getattr(instance, field_name).tzinfo is timezone.utc
    with pytest.raises(ValidationError):
        model(**factory(**{field_name: datetime(2026, 8, 2, 8, 30)}))


def test_response_times_require_timezone_and_normalize_to_utc() -> None:
    asset, fingerprint, capability, decision = (
        _valid_contract_instances()[2],
        _valid_contract_instances()[5],
        _valid_contract_instances()[7],
        _valid_contract_instances()[14],
    )
    assert asset.first_seen_at == UTC_TIME
    assert asset.last_seen_at == UTC_TIME
    assert fingerprint.created_at == UTC_TIME
    assert capability.first_observed_at == UTC_TIME
    assert capability.last_observed_at == UTC_TIME
    assert decision.created_at == UTC_TIME


@pytest.mark.parametrize(
    ("model", "factory", "field_name"),
    [
        ("EvidenceClaimCreate", _claim, "confidence"),
        ("AssetFingerprintCreate", _fingerprint, "confidence"),
        ("AICapabilityAssertionCreate", _capability, "confidence"),
    ],
)
@pytest.mark.parametrize("confidence", [0.0, 1.0])
def test_all_assertion_confidences_accept_exact_float_boundaries(
    model: str,
    factory: Any,
    field_name: str,
    confidence: float,
) -> None:
    instance = getattr(C, model)(**factory(**{field_name: confidence}))
    assert getattr(instance, field_name) == confidence
    assert type(getattr(instance, field_name)) is float


@pytest.mark.parametrize(
    ("model", "factory"),
    [
        ("EvidenceClaimCreate", _claim),
        ("AssetFingerprintCreate", _fingerprint),
        ("AICapabilityAssertionCreate", _capability),
    ],
)
@pytest.mark.parametrize(
    "confidence",
    [-0.0, -0.01, 1.01, math.nan, math.inf, -math.inf, 0, 1, True, "0.5"],
)
def test_all_assertion_confidences_reject_noncanonical_values(
    model: str,
    factory: Any,
    confidence: Any,
) -> None:
    with pytest.raises(ValidationError):
        getattr(C, model)(**factory(confidence=confidence))


@pytest.mark.parametrize(
    "confidence",
    [-0.0, -0.01, 1.01, math.nan, math.inf, -math.inf, 0, 1, True, "0.5"],
)
def test_resolution_confidence_is_a_finite_nonnegative_zero_python_float(
    confidence: Any,
) -> None:
    with pytest.raises(ValidationError):
        _resolution_request(confidence=confidence)
    with pytest.raises(ValidationError):
        _merge_request(confidence=confidence)
    with pytest.raises(ValidationError):
        C.SplitPartition(**_partition_create(confidence=confidence))


@pytest.mark.parametrize(
    ("model_name", "field_name"),
    (
        ("AIAssetContract", "resolution_confidence"),
        ("AIAssetFingerprintContract", "confidence"),
        ("AICapabilityContract", "confidence"),
        ("ResolutionDecisionContract", "confidence"),
    ),
)
@pytest.mark.parametrize(
    "invalid",
    (-0.0, -0.01, 1.01, math.nan, math.inf, -math.inf, 0, 1, True, "0.5"),
)
def test_response_confidences_reject_noncanonical_values(
    model_name: str,
    field_name: str,
    invalid: Any,
) -> None:
    instance = next(
        item for item in _valid_contract_instances() if type(item).__name__ == model_name
    )
    with pytest.raises(ValidationError):
        type(instance)(**{**instance.model_dump(mode="json"), field_name: invalid})


@pytest.mark.parametrize("boundary", (0.0, 1.0))
def test_all_response_confidences_accept_float_boundaries(boundary: float) -> None:
    for model_name, field_name in (
        ("AIAssetContract", "resolution_confidence"),
        ("AIAssetFingerprintContract", "confidence"),
        ("AICapabilityContract", "confidence"),
        ("ResolutionDecisionContract", "confidence"),
    ):
        instance = next(
            item
            for item in _valid_contract_instances()
            if type(item).__name__ == model_name
        )
        updated = type(instance)(
            **{**instance.model_dump(mode="json"), field_name: boundary}
        )
        assert getattr(updated, field_name) == boundary
        assert type(getattr(updated, field_name)) is float


def test_assertion_dtos_never_accept_a_caller_input_digest() -> None:
    for model, data in (
        (C.EvidenceClaimCreate, _claim()),
        (C.AssetFingerprintCreate, _fingerprint()),
        (C.AICapabilityAssertionCreate, _capability()),
    ):
        with pytest.raises(ValidationError):
            model(**{**data, "input_digest": "a" * 64})


def test_evidence_claim_requires_exactly_one_typed_subject() -> None:
    assert C.EvidenceClaimCreate(**_claim()).subject_observation_id == "obs-1"
    assert C.EvidenceClaimCreate(
        **_claim(subject_observation_id=None, subject_asset_id="asset-1")
    ).subject_asset_id == "asset-1"
    with pytest.raises(ValidationError):
        C.EvidenceClaimCreate(
            **_claim(subject_observation_id=None, subject_asset_id=None)
        )
    with pytest.raises(ValidationError):
        C.EvidenceClaimCreate(**_claim(subject_asset_id="asset-1"))


def test_claim_strings_idempotency_and_limitations_are_bounded() -> None:
    claim = C.EvidenceClaimCreate(**_claim())
    assert claim.claim_result == "unknown"
    assert claim.limitations == ("second limitation", "first limitation")
    with pytest.raises(ValidationError):
        C.EvidenceClaimCreate(**_claim(claim_result=None))
    for field_name, limit in (
        ("claim_type", 64),
        ("claim_result", 500),
        ("claim_method", 500),
        ("idempotency_key", 128),
    ):
        with pytest.raises(ValidationError):
            C.EvidenceClaimCreate(**_claim(**{field_name: "x" * (limit + 1)}))
        with pytest.raises(ValidationError):
            C.EvidenceClaimCreate(**_claim(**{field_name: "   "}))
    with pytest.raises(ValidationError):
        C.EvidenceClaimCreate(**_claim(limitations=("x" * 513,)))
    with pytest.raises(ValidationError):
        C.EvidenceClaimCreate(**_claim(limitations=tuple("x" for _ in range(129))))
    assert len(
        C.EvidenceClaimCreate(
            **_claim(limitations=tuple(f"limit-{index}" for index in range(128)))
        ).limitations
    ) == 128
    oversized_limitations = tuple(
        f"limitation-{index}-" + ("x" * 480) for index in range(9)
    )
    with pytest.raises(ValidationError):
        C.EvidenceClaimCreate(**_claim(limitations=oversized_limitations))


def test_fingerprint_categories_hashes_collections_and_h1b_drift_are_exact() -> None:
    all_components = {name: "a" * 64 for name in FINGERPRINT_COMPONENTS}
    fingerprint = C.AssetFingerprintCreate(
        **_fingerprint(component_hashes=all_components)
    )
    assert {item.value for item in fingerprint.component_hashes} == FINGERPRINT_COMPONENTS
    with pytest.raises(ValidationError):
        C.AssetFingerprintCreate(
            **_fingerprint(component_hashes={"invented": "a" * 64})
        )
    with pytest.raises(ValidationError):
        C.AssetFingerprintCreate(
            **_fingerprint(component_hashes={"provider": "A" * 64})
        )
    with pytest.raises(ValidationError):
        C.AssetFingerprintCreate(**_fingerprint(drift_summary={"status": "changed"}))
    with pytest.raises(ValidationError):
        C.AssetFingerprintCreate(
            **_fingerprint(detected_products=("Assistant", "Assistant"))
        )


def test_six_fingerprint_set_tuples_are_unique_and_canonical_byte_sorted() -> None:
    fingerprint = C.AssetFingerprintCreate(**_fingerprint())
    assert fingerprint.detected_products == ("Alpha", "Zulu")
    assert fingerprint.detected_frameworks == ("framework-a", "framework-z")
    assert fingerprint.detected_models == ("model-a", "model-z")
    assert fingerprint.detected_protocols == ("grpc", "https")
    assert fingerprint.detected_capabilities == ("MCP_client", "model_inference")
    assert fingerprint.observed_destinations == ("a-destination", "z-destination")
    for field_name in (
        "detected_products",
        "detected_frameworks",
        "detected_models",
        "detected_protocols",
        "observed_destinations",
    ):
        with pytest.raises(ValidationError):
            C.AssetFingerprintCreate(
                **_fingerprint(**{field_name: ("duplicate", "duplicate")})
            )
    with pytest.raises(ValidationError):
        C.AssetFingerprintCreate(
            **_fingerprint(
                detected_capabilities=("model_inference", "model_inference")
            )
        )


@pytest.mark.parametrize(
    "field_name",
    (
        "detected_products",
        "detected_frameworks",
        "detected_models",
        "detected_protocols",
        "observed_destinations",
    ),
)
def test_each_fingerprint_tuple_enforces_count_and_8192_byte_budgets(
    field_name: str,
) -> None:
    too_many = tuple(f"item-{index:03d}" for index in range(129))
    boundary = tuple(f"item-{index:03d}" for index in range(128))
    assert len(
        getattr(
            C.AssetFingerprintCreate(**_fingerprint(**{field_name: boundary})),
            field_name,
        )
    ) == 128
    with pytest.raises(ValidationError):
        C.AssetFingerprintCreate(**_fingerprint(**{field_name: too_many}))
    oversized = tuple(
        f"item-{index:02d}-" + ("x" * 490) for index in range(17)
    )
    with pytest.raises(ValidationError):
        C.AssetFingerprintCreate(**_fingerprint(**{field_name: oversized}))


def test_detected_capabilities_effective_maximum_is_exact_enum_universe() -> None:
    exact_capabilities = tuple(item.value for item in C.AICapabilityType)
    assert len(exact_capabilities) == 27
    fingerprint = C.AssetFingerprintCreate(
        **_fingerprint(detected_capabilities=exact_capabilities)
    )
    assert len(fingerprint.detected_capabilities) == 27
    assert set(fingerprint.detected_capabilities) == CAPABILITY_TYPES

    # The public collection ceiling remains 128, while enum membership plus
    # uniqueness makes the effective accepted maximum the 27 exact values.
    field_schema = C.AssetFingerprintCreate.model_json_schema()["properties"][
        "detected_capabilities"
    ]
    assert field_schema["maxItems"] == 128


def test_exact_one_evidence_references_accept_only_trimmed_nfc_boundaries() -> None:
    fingerprint = _valid_contract_instances()[5]
    capability = _valid_contract_instances()[7]
    assert fingerprint.evidence_sources == ("claim-1",)
    assert capability.evidence == ("claim-1",)
    for model, data, field_name in (
        (
            C.AIAssetFingerprintContract,
            fingerprint.model_dump(mode="json"),
            "evidence_sources",
        ),
        (C.AICapabilityContract, capability.model_dump(mode="json"), "evidence"),
    ):
        assert getattr(model(**{**data, field_name: ("x",)}), field_name) == ("x",)
        assert getattr(
            model(**{**data, field_name: ("x" * 36,)}), field_name
        ) == ("x" * 36,)
        for invalid in (
            None,
            (),
            ("",),
            (0,),
            ("   ",),
            (" claim-1 ",),
            ("Cafe\u0301",),
            ("x" * 37,),
            ("claim-1", "claim-1"),
            ("claim-1", "claim-2"),
        ):
            with pytest.raises(ValidationError):
                model(**{**data, field_name: invalid})
        field_schema = model.model_json_schema()["properties"][field_name]
        assert field_schema["minItems"] == 1
        assert field_schema["maxItems"] == 1


def test_capability_times_are_ordered_and_exact_names_states_are_enforced() -> None:
    with pytest.raises(ValidationError):
        C.AICapabilityAssertionCreate(**_capability(name="mcp_client"))
    with pytest.raises(ValidationError):
        C.AICapabilityAssertionCreate(**_capability(state="confirmed"))
    with pytest.raises(ValidationError):
        C.AICapabilityAssertionCreate(
            **_capability(
                first_observed_at=UTC_TIME + timedelta(seconds=1),
                last_observed_at=UTC_TIME,
            )
        )


def test_resolution_request_candidate_ids_have_exact_boundaries() -> None:
    assert _resolution_request(candidate_observation_ids=("o",)).candidate_observation_ids == (
        "o",
    )
    assert len(
        _resolution_request(
            candidate_observation_ids=_observation_ids(128)
        ).candidate_observation_ids
    ) == 128
    assert _resolution_request(
        candidate_observation_ids=("o" * 128,)
    ).candidate_observation_ids == ("o" * 128,)
    for invalid in (
        (),
        _observation_ids(129),
        ("obs-1", "obs-1"),
        ("o" * 129,),
    ):
        with pytest.raises(ValidationError):
            _resolution_request(candidate_observation_ids=invalid)


def test_merge_candidate_and_source_ids_have_exact_boundaries() -> None:
    assert _merge_request(candidate_observation_ids=("o",)).candidate_observation_ids == (
        "o",
    )
    assert len(
        _merge_request(
            candidate_observation_ids=_observation_ids(128)
        ).candidate_observation_ids
    ) == 128
    assert _merge_request(
        candidate_observation_ids=("o" * 128,)
    ).candidate_observation_ids == ("o" * 128,)
    for invalid in (
        (),
        _observation_ids(129),
        ("obs-1", "obs-1"),
        ("o" * 129,),
    ):
        with pytest.raises(ValidationError):
            _merge_request(candidate_observation_ids=invalid)

    assert _merge_request(source_asset_ids=("a", "b")).source_asset_ids == (
        "a",
        "b",
    )
    assert len(_merge_request(source_asset_ids=_asset_ids(128)).source_asset_ids) == 128
    assert _merge_request(
        source_asset_ids=("a" * 36, "b")
    ).source_asset_ids == ("a" * 36, "b")
    for invalid in (
        (),
        ("asset-1",),
        _asset_ids(129),
        ("asset-1", "asset-1"),
        ("a" * 37, "b"),
    ):
        with pytest.raises(ValidationError):
            _merge_request(source_asset_ids=invalid)


def test_split_partition_candidate_and_asset_ids_have_exact_boundaries() -> None:
    assert C.SplitPartition(
        **_partition_attach(candidate_observation_ids=("o",))
    ).candidate_observation_ids == ("o",)
    assert len(
        C.SplitPartition(
            **_partition_attach(candidate_observation_ids=_observation_ids(128))
        ).candidate_observation_ids
    ) == 128
    assert C.SplitPartition(
        **_partition_attach(candidate_observation_ids=("o" * 128,))
    ).candidate_observation_ids == ("o" * 128,)
    for invalid in (
        (),
        _observation_ids(129),
        ("obs-1", "obs-1"),
        ("o" * 129,),
    ):
        with pytest.raises(ValidationError):
            C.SplitPartition(
                **_partition_attach(candidate_observation_ids=invalid)
            )
    assert C.SplitPartition(
        **_partition_attach(existing_asset_id="a" * 36)
    ).existing_asset_id == "a" * 36
    with pytest.raises(ValidationError):
        C.SplitPartition(**_partition_attach(existing_asset_id="a" * 37))


def test_split_request_partitions_have_exact_boundaries() -> None:
    assert len(_split_request(partitions=_distinct_attach_partitions(1)).partitions) == 1
    assert len(
        _split_request(partitions=_distinct_attach_partitions(128)).partitions
    ) == 128
    with pytest.raises(ValidationError):
        _split_request(partitions=())
    with pytest.raises(ValidationError):
        _split_request(partitions=_distinct_attach_partitions(129))
    duplicate = _partition_attach()
    with pytest.raises(ValidationError):
        _split_request(partitions=(duplicate, duplicate))
    assert _split_request(source_asset_id="a" * 36).source_asset_id == "a" * 36
    with pytest.raises(ValidationError):
        _split_request(source_asset_id="a" * 37)


def test_split_upper_bound_topology_with_all_signal_categories_validates() -> None:
    categories = tuple(sorted(SIGNAL_CATEGORIES))
    assert len(categories) == 18
    partitions = tuple(
        _partition_attach(
            candidate_observation_ids=(f"obs-{index:03d}",),
            existing_asset_id=f"asset-{index:03d}",
            matched_signals=tuple(_signal(category) for category in categories),
            conflicting_signals=tuple(_signal(category) for category in categories),
            evidence_claim_id=f"claim-{index:03d}",
            evidence_node_id=f"node-{index:03d}",
        )
        for index in range(128)
    )

    request = _split_request(partitions=partitions)

    assert len(request.partitions) == 128
    for partition in request.partitions:
        assert len(partition.matched_signals) == 18
        assert len(partition.conflicting_signals) == 18
        assert {
            signal.category.value for signal in partition.matched_signals
        } == SIGNAL_CATEGORIES
        assert {
            signal.category.value for signal in partition.conflicting_signals
        } == SIGNAL_CATEGORIES


def test_asset_source_observation_preview_has_exact_conservative_boundaries() -> None:
    asset = _valid_contract_instances()[2]
    data = asset.model_dump(mode="json")
    assert C.AIAssetContract(
        **{**data, "source_observation_ids": ()}
    ).source_observation_ids == ()
    assert len(
        C.AIAssetContract(
            **{**data, "source_observation_ids": _observation_ids(128)}
        ).source_observation_ids
    ) == 128
    assert C.AIAssetContract(
        **{**data, "source_observation_ids": ("o" * 128,)}
    ).source_observation_ids == ("o" * 128,)
    for invalid in (
        _observation_ids(129),
        ("obs-1", "obs-1"),
        ("o" * 129,),
        ("obs-z", "obs-a"),
    ):
        with pytest.raises(ValidationError):
            C.AIAssetContract(**{**data, "source_observation_ids": invalid})

    field_schema = C.AIAssetContract.model_json_schema()["properties"][
        "source_observation_ids"
    ]
    description = field_schema.get("description", "").lower()
    assert "preview" in description
    assert "ascending" in description
    assert "non-exhaustive" in description or "not exhaustive" in description
    assert not any("source_observation" in name and "count" in name for name in data)


def test_resolution_decision_candidate_ids_have_exact_boundaries() -> None:
    decision = _valid_contract_instances()[14]
    data = decision.model_dump(mode="json")
    assert C.ResolutionDecisionContract(
        **{**data, "candidate_observation_ids": ("o",)}
    ).candidate_observation_ids == ("o",)
    assert len(
        C.ResolutionDecisionContract(
            **{**data, "candidate_observation_ids": _observation_ids(128)}
        ).candidate_observation_ids
    ) == 128
    assert C.ResolutionDecisionContract(
        **{**data, "candidate_observation_ids": ("o" * 128,)}
    ).candidate_observation_ids == ("o" * 128,)
    for invalid in (
        (),
        _observation_ids(129),
        ("obs-1", "obs-1"),
        ("o" * 129,),
    ):
        with pytest.raises(ValidationError):
            C.ResolutionDecisionContract(
                **{**data, "candidate_observation_ids": invalid}
            )


def test_resolution_decision_asset_actions_reject_empty_canonical_asset_id() -> None:
    decision = _valid_contract_instances()[14]
    data = decision.model_dump(mode="json")
    accepted_empty_ids: list[str] = []

    for action in ("create", "attach", "merge"):
        valid = C.ResolutionDecisionContract(
            **{**data, "action": action, "canonical_asset_id": "asset-1"}
        )
        assert valid.canonical_asset_id == "asset-1"
        try:
            C.ResolutionDecisionContract(
                **{**data, "action": action, "canonical_asset_id": ""}
            )
        except ValidationError:
            pass
        else:
            accepted_empty_ids.append(action)

    for action in ("reject", "manual_review"):
        nonasset_decision = C.ResolutionDecisionContract(
            **{**data, "action": action, "canonical_asset_id": None}
        )
        assert nonasset_decision.canonical_asset_id is None

    assert accepted_empty_ids == []


def test_dto_order_is_retained_and_private_canonicalizers_sort_only_frozen_sets() -> None:
    reversed_candidates = ("obs-z", "obs-a")
    resolution = _resolution_request(
        candidate_observation_ids=reversed_candidates
    )
    merge = _merge_request(
        source_asset_ids=("asset-z", "asset-a"),
        candidate_observation_ids=reversed_candidates,
    )
    partition = C.SplitPartition(
        **_partition_attach(candidate_observation_ids=reversed_candidates)
    )
    decision_data = _valid_contract_instances()[14].model_dump(mode="json")
    decision = C.ResolutionDecisionContract(
        **{**decision_data, "candidate_observation_ids": reversed_candidates}
    )
    split = _split_request(
        partitions=(
            _partition_attach(
                candidate_observation_ids=("obs-d", "obs-c"),
                existing_asset_id="asset-z",
                evidence_claim_id="claim-z",
                evidence_node_id="node-z",
            ),
            _partition_attach(
                candidate_observation_ids=("obs-b", "obs-a"),
                existing_asset_id="asset-a",
                evidence_claim_id="claim-a",
                evidence_node_id="node-a",
            ),
        )
    )

    assert resolution.candidate_observation_ids == reversed_candidates
    assert merge.source_asset_ids == ("asset-z", "asset-a")
    assert merge.candidate_observation_ids == reversed_candidates
    assert partition.candidate_observation_ids == reversed_candidates
    assert decision.candidate_observation_ids == reversed_candidates
    assert tuple(item.existing_asset_id for item in split.partitions) == (
        "asset-z",
        "asset-a",
    )

    resolution_material = C._canonicalize_resolution_request(
        tenant_id="tenant-1",
        actor=_actor(),
        action=C.ResolutionAction("manual_review"),
        payload=resolution,
    )
    assert resolution_material.decisions[0].nonhistory_object[
        "candidate_observation_ids"
    ] == ("obs-a", "obs-z")

    merge_material = C._canonicalize_merge_request(
        tenant_id="tenant-1", actor=_actor(), payload=merge
    )
    assert merge_material.event_object["source_asset_ids"] == (
        "asset-a",
        "asset-z",
    )
    assert merge_material.decisions[0].child_object[
        "candidate_observation_ids"
    ] == ("obs-a", "obs-z")

    split_material = C._canonicalize_split_request(
        tenant_id="tenant-1", actor=_actor(), payload=split
    )
    assert tuple(
        child.child_material_digest for child in split_material.decisions
    ) == tuple(
        sorted(child.child_material_digest for child in split_material.decisions)
    )
    assert all(
        child.child_object["candidate_observation_ids"]
        == tuple(sorted(child.child_object["candidate_observation_ids"]))
        for child in split_material.decisions
    )


def test_resolution_target_shape_is_at_most_one_and_action_specific() -> None:
    with pytest.raises(ValidationError):
        _resolution_request(new_asset=_new_asset(), existing_asset_id="asset-1")
    create_without_reason = _resolution_request(new_asset=_new_asset(), reason=None)
    attach_without_reason = _resolution_request(
        existing_asset_id="asset-1",
        reason=None,
    )
    assert create_without_reason.new_asset is not None
    assert create_without_reason.existing_asset_id is None
    assert attach_without_reason.new_asset is None
    assert attach_without_reason.existing_asset_id == "asset-1"
    with pytest.raises(ValueError):
        C._canonicalize_resolution_request(
            tenant_id="tenant-1",
            actor=_actor(),
            action=C.ResolutionAction("create"),
            payload=create_without_reason,
        )
    with pytest.raises(ValueError):
        C._canonicalize_resolution_request(
            tenant_id="tenant-1",
            actor=_actor(),
            action=C.ResolutionAction("attach"),
            payload=attach_without_reason,
        )

    reject_with_forbidden_target = _resolution_request(
        new_asset=_new_asset(),
        reason=None,
    )
    manual_with_forbidden_target = _resolution_request(
        existing_asset_id="asset-1",
        reason=None,
    )
    with pytest.raises(ValueError):
        C._canonicalize_resolution_request(
            tenant_id="tenant-1",
            actor=_actor(),
            action=C.ResolutionAction("reject"),
            payload=reject_with_forbidden_target,
        )
    with pytest.raises(ValueError):
        C._canonicalize_resolution_request(
            tenant_id="tenant-1",
            actor=_actor(),
            action=C.ResolutionAction("manual_review"),
            payload=manual_with_forbidden_target,
        )


def test_all_resolution_mutations_require_claim_node_reason_and_bounded_key() -> None:
    cases = (
        (C.AssetMergeRequest, _merge_request().model_dump(mode="json")),
        (C.HistoryReversalRequest, _reversal_request().model_dump(mode="json")),
    )
    for model, data in cases:
        for field_name in (
            "evidence_claim_id",
            "evidence_node_id",
            "idempotency_key",
            "reason",
        ):
            missing = dict(data)
            missing.pop(field_name)
            with pytest.raises(ValidationError):
                model(**missing)
        with pytest.raises(ValidationError):
            model(**{**data, "idempotency_key": "x" * 129})
        with pytest.raises(ValidationError):
            model(**{**data, "reason": "x" * 501})
    resolution = _resolution_request()
    assert resolution.reason is None
    missing_reason = resolution.model_dump(mode="json")
    missing_reason.pop("reason")
    assert C.ResolutionRequest(**missing_reason).reason is None
    for field_name in ("evidence_claim_id", "evidence_node_id", "idempotency_key"):
        missing = resolution.model_dump(mode="json")
        missing.pop(field_name)
        with pytest.raises(ValidationError):
            C.ResolutionRequest(**missing)


def test_split_partition_exact_target_claim_and_decision_fields_are_required() -> None:
    valid = _partition_create()
    for field_name in (
        "candidate_observation_ids",
        "matched_signals",
        "conflicting_signals",
        "confidence",
        "algorithm_version",
        "evidence_claim_id",
        "evidence_node_id",
    ):
        missing = dict(valid)
        missing.pop(field_name)
        with pytest.raises(ValidationError):
            C.SplitPartition(**missing)
    with pytest.raises(ValidationError):
        C.SplitPartition(**{**valid, "new_asset": None, "existing_asset_id": None})
    with pytest.raises(ValidationError):
        C.SplitPartition(**{**valid, "existing_asset_id": "asset-result-1"})
    with pytest.raises(ValidationError):
        C.SplitPartition(**_partition_create(candidate_observation_ids=()))


def test_split_requires_event_claim_and_distinct_child_claims_and_targets() -> None:
    valid = _split_request().model_dump(mode="json")
    for field_name in (
        "idempotency_key",
        "source_asset_id",
        "reason",
        "event_evidence_claim_id",
        "event_evidence_node_id",
        "partitions",
    ):
        missing = dict(valid)
        missing.pop(field_name)
        with pytest.raises(ValidationError):
            C.AssetSplitRequest(**missing)
    with pytest.raises(ValidationError):
        _split_request(partitions=())
    with pytest.raises(ValidationError):
        _split_request(
            event_evidence_claim_id="claim-child-1",
        )
    with pytest.raises(ValidationError):
        _split_request(
            partitions=(
                _partition_create(),
                _partition_attach(evidence_claim_id="claim-child-1"),
            )
        )
    with pytest.raises(ValidationError):
        _split_request(
            partitions=(
                _partition_attach(),
                _partition_attach(
                    candidate_observation_ids=("obs-3",),
                    evidence_claim_id="claim-child-3",
                    evidence_node_id="node-child-3",
                ),
            )
        )


def test_split_rejects_overlapping_candidates() -> None:
    with pytest.raises(ValidationError):
        _split_request(
            partitions=(
                _partition_create(candidate_observation_ids=("obs-1", "obs-2")),
                _partition_attach(candidate_observation_ids=("obs-2",)),
            )
        )


@pytest.mark.parametrize(
    "category",
    sorted(SIGNAL_CATEGORIES),
)
def test_signal_category_allowlist_is_exact(category: str) -> None:
    signal = C.ResolutionSignal(**_signal(category))
    assert signal.category.value == category


def test_signal_tuples_are_category_only_unique_sorted_and_cross_tuple_repeatable() -> None:
    duplicate = _signal("API endpoint")
    with pytest.raises(ValidationError):
        _resolution_request(matched_signals=(duplicate, duplicate))
    all_signals = tuple(_signal(category) for category in reversed(sorted(SIGNAL_CATEGORIES)))
    request = _resolution_request(
        matched_signals=all_signals,
        conflicting_signals=(
            _signal("tool fingerprint"),
            _signal("API endpoint"),
        ),
    )
    assert tuple(signal.category.value for signal in request.matched_signals) == tuple(
        sorted(SIGNAL_CATEGORIES)
    )
    assert tuple(
        signal.category.value for signal in request.conflicting_signals
    ) == ("API endpoint", "tool fingerprint")
    with pytest.raises(ValidationError):
        _resolution_request(
            conflicting_signals=(
                _signal("API endpoint"),
                _signal("API endpoint"),
            )
        )
    with pytest.raises(ValidationError):
        C.ResolutionSignal(category="API endpoint", summary="forbidden")
    with pytest.raises(ValidationError):
        C.ResolutionSignal(category="API endpoint", identifier="private-id")


def test_validation_errors_are_sanitized_for_every_h1b_entrypoint() -> None:
    marker = "RAW-SUBMITTED-MARKER-DO-NOT-RETAIN"
    with pytest.raises(ValidationError) as captured:
        C.ResolutionSignal(category="API endpoint", summary=marker)
    rendered = f"{captured.value}\n{captured.value.errors()!r}"
    assert marker not in rendered
    assert "raw_prompt" not in rendered
    assert all(
        detail.get("input") is None and "ctx" not in detail
        for detail in captured.value.errors()
    )


def _depth_2000_list(marker: str) -> list[Any]:
    nested: Any = marker
    for _ in range(2000):
        nested = [nested]
    return nested


class _ExplodingChildMapping(Mapping[str, object]):
    def __init__(self, marker: str) -> None:
        self.marker = marker
        self.touched = False

    def __getitem__(self, key: str) -> object:
        self.touched = True
        raise AssertionError("oversized-container child access")

    def __iter__(self) -> Iterator[str]:
        self.touched = True
        raise AssertionError("oversized-container child iteration")

    def __len__(self) -> int:
        return 1

    def __repr__(self) -> str:
        return self.marker


def _fail_deep_input(message: str) -> None:
    raise AssertionError(message) from None


def _assert_deep_validation_error_is_sanitized(
    captured: ValidationError,
    marker: str,
) -> None:
    try:
        details = captured.errors()
        rendered = f"{captured}\n{details!r}"
    except RecursionError:
        _fail_deep_input("sanitized validation error rendering leaked recursion")
    if marker in rendered:
        _fail_deep_input(
            "sanitized validation error retained deep untrusted material"
        )
    if "recursionerror" in rendered.casefold():
        _fail_deep_input("sanitized validation error exposed a raw RecursionError")
    if not all(
        detail.get("input") is None and "ctx" not in detail for detail in details
    ):
        _fail_deep_input("sanitized validation error retained input or context")


def test_oversized_candidate_container_rejects_before_child_traversal() -> None:
    marker = "RAW-OVERSIZED-CHILD-BOMB-DO-NOT-RETAIN"
    bomb = _ExplodingChildMapping(marker)
    oversized: tuple[object, ...] = (*_observation_ids(128), bomb)

    try:
        _resolution_request(candidate_observation_ids=oversized)
    except AssertionError:
        _fail_deep_input("oversized candidate container traversed its child bomb")
    except ValidationError as captured:
        if bomb.touched:
            _fail_deep_input("oversized candidate container touched its child bomb")
        _assert_deep_validation_error_is_sanitized(captured, marker)
    else:
        _fail_deep_input("oversized candidate container was accepted")


def test_resolution_signal_constructor_rejects_depth_2000_extra_safely() -> None:
    marker = "RAW-DEEP-CONSTRUCTOR-MARKER-DO-NOT-RETAIN"
    try:
        C.ResolutionSignal(
            category="API endpoint",
            unexpected=_depth_2000_list(marker),
        )
    except RecursionError:
        _fail_deep_input("constructor exposed a raw RecursionError")
    except ValidationError as captured:
        _assert_deep_validation_error_is_sanitized(captured, marker)
    else:
        _fail_deep_input("constructor accepted a depth-2000 unexpected value")


def test_resolution_signal_model_validate_rejects_depth_2000_extra_safely() -> None:
    marker = "RAW-DEEP-MAPPING-MARKER-DO-NOT-RETAIN"
    try:
        C.ResolutionSignal.model_validate(
            {
                "category": "API endpoint",
                "unexpected": _depth_2000_list(marker),
            }
        )
    except RecursionError:
        _fail_deep_input("model_validate exposed a raw RecursionError")
    except ValidationError as captured:
        _assert_deep_validation_error_is_sanitized(captured, marker)
    else:
        _fail_deep_input("model_validate accepted a depth-2000 unexpected value")


def test_resolution_signal_model_validate_json_rejects_depth_2000_safely() -> None:
    marker = "RAW-DEEP-JSON-MARKER-DO-NOT-RETAIN"
    deep_json = (
        '{"category":"API endpoint","unexpected":'
        + ("[" * 2000)
        + f'"{marker}"'
        + ("]" * 2000)
        + "}"
    )
    try:
        C.ResolutionSignal.model_validate_json(deep_json)
    except RecursionError:
        _fail_deep_input("model_validate_json exposed a raw RecursionError")
    except ValidationError as captured:
        _assert_deep_validation_error_is_sanitized(captured, marker)
    else:
        _fail_deep_input("model_validate_json accepted depth-2000 JSON")


def test_canonical_json_bytes_rejects_depth_2000_with_fixed_safe_error() -> None:
    marker = "RAW-DEEP-CANONICAL-MARKER-DO-NOT-RETAIN"
    with pytest.raises(ValueError) as baseline:
        C.canonical_json_bytes({"value": object()})
    expected_message = str(baseline.value)

    try:
        C.canonical_json_bytes(_depth_2000_list(marker))
    except RecursionError:
        _fail_deep_input("canonical_json_bytes exposed a raw RecursionError")
    except ValueError as captured:
        rendered = str(captured)
        if marker in rendered:
            _fail_deep_input(
                "canonical_json_bytes retained deep untrusted material"
            )
        if "recursionerror" in rendered.casefold():
            _fail_deep_input("canonical_json_bytes exposed a raw RecursionError")
        if rendered != expected_message:
            _fail_deep_input("canonical_json_bytes did not use its fixed safe error")
    else:
        _fail_deep_input("canonical_json_bytes accepted a depth-2000 value")


def test_nfc_is_required_and_never_silently_normalized() -> None:
    decomposed = "Cafe\u0301"
    with pytest.raises(ValidationError):
        C.AIAssetCreate(**_new_asset(canonical_name=decomposed))
    with pytest.raises(ValidationError):
        _resolution_request(algorithm_version=decomposed)
    with pytest.raises(ValueError):
        C.canonical_json_bytes({"label": decomposed})
    with pytest.raises(ValueError):
        C.canonical_json_bytes({decomposed: "value"})


def test_algorithm_version_is_nfc_trimmed_nonempty_and_bounded() -> None:
    for version in ("", "   ", "x" * 65, "Cafe\u0301"):
        with pytest.raises(ValidationError):
            C.SplitPartition(**_partition_create(algorithm_version=version))
    partition = C.SplitPartition(**_partition_create(algorithm_version=" valid-v1 "))
    assert partition.algorithm_version == "valid-v1"


def test_canonical_json_bytes_freezes_exact_utf8_rules() -> None:
    value = {"z": [2, 1], "a": "Caf\u00e9"}
    assert C.canonical_json_bytes(value) == b'{"a":"Caf\xc3\xa9","z":[2,1]}'
    assert C.canonical_json_bytes({"one": 1.0}) == b'{"one":1.0}'
    for invalid in (
        {"value": math.nan},
        {"value": math.inf},
        {"value": -math.inf},
        {"confidence": -0.0},
        {"value": 1 << 63},
        {1: "not-a-string-key"},
    ):
        with pytest.raises(ValueError):
            C.canonical_json_bytes(invalid)


def test_canonical_json_failures_use_one_fixed_sanitized_message() -> None:
    marker = "RAW-CANONICAL-MARKER-DO-NOT-RETAIN"
    messages: set[str] = set()
    for invalid in (
        {"value": marker + "e\u0301"},
        {"value": object()},
        {marker + "e\u0301": "value"},
    ):
        with pytest.raises(ValueError) as captured:
            C.canonical_json_bytes(invalid)
        messages.add(str(captured.value))
        assert marker not in str(captured.value)
    assert len(messages) == 1


# Literal, independently frozen G15 input vectors. No expected value below is
# produced by a production serializer or digest helper under test.
CLAIM_INPUT_BYTES = (
    b'{"claim_method":"exact provider metadata","claim_result":"unknown",'
    b'"claim_type":"asset_identity","confidence":0.5,"evidence_node_id":'
    b'"node-1","freshness":"fresh","limitations":["second limitation",'
    b'"first limitation"],"observed_at":"2026-08-02T08:30:45.123456Z",'
    b'"schema_version":"hmair-h1b-evidence-claim-v1",'
    b'"source_observation_id":"obs-1","subject_asset_id":null,'
    b'"subject_observation_id":"obs-1","tenant_id":"tenant-1"}'
)
CLAIM_INPUT_DIGEST = "ea5c35b6a2fa836a3ed9768d9249e0536ab697bfc29aa3923a5a9b792a2d96e8"

FINGERPRINT_INPUT_BYTES = (
    b'{"asset_id":"asset-1","component_hashes":{"behavior":'
    b'"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    b'"provider":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},'
    b'"confidence":0.5,"detected_capabilities":["MCP_client","model_inference"],'
    b'"detected_frameworks":["framework-a","framework-z"],'
    b'"detected_models":["model-a","model-z"],"detected_products":'
    b'["Alpha","Zulu"],"detected_protocols":["grpc","https"],'
    b'"drift_summary":{},"evidence_claim_id":"claim-1","fingerprint_version":'
    b'"hmair-fp-v1","observed_destinations":["a-destination","z-destination"],'
    b'"schema_version":"hmair-h1b-asset-fingerprint-v1",'
    b'"source_observation_id":"obs-1","supersedes_fingerprint_id":null,'
    b'"tenant_id":"tenant-1"}'
)
FINGERPRINT_INPUT_DIGEST = (
    "02738d8515436923f29f2dde629f98be4bd5ffacc9888c618668841055b25784"
)

CAPABILITY_INPUT_BYTES = (
    b'{"asset_id":"asset-1","confidence":0.5,"evidence_claim_id":"claim-1",'
    b'"extractor_version":"extractor-v1","first_observed_at":'
    b'"2026-08-02T08:30:45.123456Z","last_observed_at":'
    b'"2026-08-02T09:30:45.654321Z","name":"MCP_client","schema_version":'
    b'"hmair-h1b-ai-capability-v1","source_observation_id":"obs-1",'
    b'"state":"observed","supersedes_capability_id":null,"tenant_id":"tenant-1"}'
)
CAPABILITY_INPUT_DIGEST = (
    "370e6c68a323f737ed0f72b6293783bd8f1910cc3ab9a5af58aa8209d526645b"
)


def test_evidence_claim_input_object_bytes_and_digest_are_exact_literals() -> None:
    material = C._canonicalize_evidence_claim_input(
        tenant_id="tenant-1",
        payload=C.EvidenceClaimCreate(**_claim()),
    )
    assert set(material.canonical_object) == {
        "claim_method",
        "claim_result",
        "claim_type",
        "confidence",
        "evidence_node_id",
        "freshness",
        "limitations",
        "observed_at",
        "schema_version",
        "source_observation_id",
        "subject_asset_id",
        "subject_observation_id",
        "tenant_id",
    }
    assert material.canonical_object["limitations"] == (
        "second limitation",
        "first limitation",
    )
    assert material.canonical_object["subject_asset_id"] is None
    assert material.canonical_object["observed_at"] == "2026-08-02T08:30:45.123456Z"
    assert material.canonical_bytes == CLAIM_INPUT_BYTES
    assert material.input_digest == CLAIM_INPUT_DIGEST
    changed_key = C._canonicalize_evidence_claim_input(
        tenant_id="tenant-1",
        payload=C.EvidenceClaimCreate(
            **_claim(idempotency_key="different-claim-request")
        ),
    )
    assert changed_key == material


def test_fingerprint_input_object_bytes_and_digest_are_exact_literals() -> None:
    material = C._canonicalize_asset_fingerprint_input(
        tenant_id="tenant-1",
        payload=C.AssetFingerprintCreate(**_fingerprint()),
    )
    assert set(material.canonical_object) == {
        "asset_id",
        "component_hashes",
        "confidence",
        "detected_capabilities",
        "detected_frameworks",
        "detected_models",
        "detected_products",
        "detected_protocols",
        "drift_summary",
        "evidence_claim_id",
        "fingerprint_version",
        "observed_destinations",
        "schema_version",
        "source_observation_id",
        "supersedes_fingerprint_id",
        "tenant_id",
    }
    assert material.canonical_object["supersedes_fingerprint_id"] is None
    assert material.canonical_object["detected_products"] == ("Alpha", "Zulu")
    assert material.canonical_bytes == FINGERPRINT_INPUT_BYTES
    assert material.input_digest == FINGERPRINT_INPUT_DIGEST


def test_capability_input_object_bytes_and_digest_are_exact_literals() -> None:
    material = C._canonicalize_ai_capability_input(
        tenant_id="tenant-1",
        payload=C.AICapabilityAssertionCreate(**_capability()),
    )
    assert set(material.canonical_object) == {
        "asset_id",
        "confidence",
        "evidence_claim_id",
        "extractor_version",
        "first_observed_at",
        "last_observed_at",
        "name",
        "schema_version",
        "source_observation_id",
        "state",
        "supersedes_capability_id",
        "tenant_id",
    }
    assert material.canonical_object["supersedes_capability_id"] is None
    assert material.canonical_object["first_observed_at"] == (
        "2026-08-02T08:30:45.123456Z"
    )
    assert material.canonical_object["last_observed_at"] == (
        "2026-08-02T09:30:45.654321Z"
    )
    assert material.canonical_bytes == CAPABILITY_INPUT_BYTES
    assert material.input_digest == CAPABILITY_INPUT_DIGEST


@pytest.mark.parametrize(
    ("field_name", "tenant_id", "updates"),
    (
        ("tenant_id", "tenant-2", {}),
        ("claim_method", "tenant-1", {"claim_method": "different method"}),
        ("claim_result", "tenant-1", {"claim_result": "different result"}),
        ("claim_type", "tenant-1", {"claim_type": "different_claim_type"}),
        ("confidence", "tenant-1", {"confidence": 0.6}),
        ("evidence_node_id", "tenant-1", {"evidence_node_id": "node-2"}),
        ("freshness", "tenant-1", {"freshness": "stale"}),
        (
            "limitations",
            "tenant-1",
            {"limitations": ("first limitation", "second limitation")},
        ),
        (
            "observed_at",
            "tenant-1",
            {"observed_at": OFFSET_TIME + timedelta(seconds=1)},
        ),
        (
            "source_observation_id",
            "tenant-1",
            {"source_observation_id": "obs-2"},
        ),
        (
            "subject_observation_id/subject_asset_id nullable flip",
            "tenant-1",
            {"subject_observation_id": None, "subject_asset_id": "asset-1"},
        ),
    ),
)
def test_claim_digest_changes_for_every_persisted_caller_field(
    field_name: str,
    tenant_id: str,
    updates: dict[str, Any],
) -> None:
    baseline = C._canonicalize_evidence_claim_input(
        tenant_id="tenant-1", payload=C.EvidenceClaimCreate(**_claim())
    )
    changed = C._canonicalize_evidence_claim_input(
        tenant_id=tenant_id,
        payload=C.EvidenceClaimCreate(**_claim(**updates)),
    )
    assert changed.input_digest != baseline.input_digest, field_name


def test_claim_idempotency_key_is_explicitly_excluded_from_input_digest() -> None:
    baseline = C._canonicalize_evidence_claim_input(
        tenant_id="tenant-1", payload=C.EvidenceClaimCreate(**_claim())
    )
    changed_key = C._canonicalize_evidence_claim_input(
        tenant_id="tenant-1",
        payload=C.EvidenceClaimCreate(
            **_claim(idempotency_key="different-claim-request")
        ),
    )
    assert changed_key == baseline


@pytest.mark.parametrize(
    ("field_name", "tenant_id", "updates"),
    (
        ("tenant_id", "tenant-2", {}),
        ("asset_id", "tenant-1", {"asset_id": "asset-2"}),
        (
            "component_hashes",
            "tenant-1",
            {
                "component_hashes": {
                    "behavior": "a" * 64,
                    "provider": "c" * 64,
                }
            },
        ),
        ("confidence", "tenant-1", {"confidence": 0.6}),
        (
            "detected_capabilities",
            "tenant-1",
            {"detected_capabilities": ("MCP_server", "model_inference")},
        ),
        (
            "detected_frameworks",
            "tenant-1",
            {"detected_frameworks": ("framework-a", "framework-b")},
        ),
        (
            "detected_models",
            "tenant-1",
            {"detected_models": ("model-a", "model-b")},
        ),
        (
            "detected_products",
            "tenant-1",
            {"detected_products": ("Alpha", "Beta")},
        ),
        (
            "detected_protocols",
            "tenant-1",
            {"detected_protocols": ("grpc", "websocket")},
        ),
        (
            "evidence_claim_id",
            "tenant-1",
            {"evidence_claim_id": "claim-2"},
        ),
        (
            "fingerprint_version",
            "tenant-1",
            {"fingerprint_version": "hmair-fp-v2"},
        ),
        (
            "observed_destinations",
            "tenant-1",
            {"observed_destinations": ("a-destination", "b-destination")},
        ),
        (
            "source_observation_id",
            "tenant-1",
            {"source_observation_id": "obs-2"},
        ),
        (
            "supersedes_fingerprint_id nullable flip",
            "tenant-1",
            {"supersedes_fingerprint_id": "fingerprint-0"},
        ),
    ),
)
def test_fingerprint_digest_changes_for_every_persisted_caller_field(
    field_name: str,
    tenant_id: str,
    updates: dict[str, Any],
) -> None:
    baseline = C._canonicalize_asset_fingerprint_input(
        tenant_id="tenant-1", payload=C.AssetFingerprintCreate(**_fingerprint())
    )
    changed = C._canonicalize_asset_fingerprint_input(
        tenant_id=tenant_id,
        payload=C.AssetFingerprintCreate(**_fingerprint(**updates)),
    )
    assert changed.input_digest != baseline.input_digest, field_name


@pytest.mark.parametrize(
    ("field_name", "tenant_id", "updates"),
    (
        ("tenant_id", "tenant-2", {}),
        ("asset_id", "tenant-1", {"asset_id": "asset-2"}),
        ("confidence", "tenant-1", {"confidence": 0.6}),
        (
            "evidence_claim_id",
            "tenant-1",
            {"evidence_claim_id": "claim-2"},
        ),
        (
            "extractor_version",
            "tenant-1",
            {"extractor_version": "extractor-v2"},
        ),
        (
            "first_observed_at",
            "tenant-1",
            {"first_observed_at": OFFSET_TIME - timedelta(seconds=1)},
        ),
        (
            "last_observed_at",
            "tenant-1",
            {
                "last_observed_at": datetime(
                    2026,
                    8,
                    2,
                    13,
                    30,
                    46,
                    654321,
                    tzinfo=timezone(timedelta(hours=4)),
                )
            },
        ),
        ("name", "tenant-1", {"name": "MCP_server"}),
        (
            "source_observation_id",
            "tenant-1",
            {"source_observation_id": "obs-2"},
        ),
        ("state", "tenant-1", {"state": "configured"}),
        (
            "supersedes_capability_id nullable flip",
            "tenant-1",
            {"supersedes_capability_id": "capability-0"},
        ),
    ),
)
def test_capability_digest_changes_for_every_persisted_caller_field(
    field_name: str,
    tenant_id: str,
    updates: dict[str, Any],
) -> None:
    baseline = C._canonicalize_ai_capability_input(
        tenant_id="tenant-1",
        payload=C.AICapabilityAssertionCreate(**_capability()),
    )
    changed = C._canonicalize_ai_capability_input(
        tenant_id=tenant_id,
        payload=C.AICapabilityAssertionCreate(**_capability(**updates)),
    )
    assert changed.input_digest != baseline.input_digest, field_name


# Literal, independently frozen resolution vectors. No expected value below is
# produced by the production serializer or digest helpers under test.
GOLDEN: dict[str, dict[str, Any]] = {
    "create": {
        "event_bytes": (
            b'{"actor_id":"op\xc3\xa9rateur-1","actor_role":"owner","children":'
            b'[{"child":{"action":"create","algorithm_version":"hmair-h1b-v1",'
            b'"candidate_observation_ids":["obs-1","obs-2"],"confidence":0.5,'
            b'"conflicting_signals":[],"evidence_claim_id":"claim-1",'
            b'"evidence_node_id":"node-1","matched_signals":[{"category":'
            b'"API endpoint"}],"new_asset":'
            b'{"asset_type":"ai_application","canonical_name":"Caf\xc3\xa9 Assistant",'
            b'"deployment_family":"saas","environment":"production","framework":null,'
            b'"product":"Assistant","provider":"Example AI","technical_surface":'
            b'"browser","version":"1.0"},"result_asset_id":null,"schema_version":'
            b'"hmair-h1b-decision-child-v1"},"child_material_digest":'
            b'"4d53a823e5ba17ecfd36ba0a58153f4c3d1b9b42709d24e359c6de3d85bbd142",'
            b'"operation_index":0}],"event_evidence_claim_id":"claim-1",'
            b'"event_evidence_node_id":"node-1","event_type":"create","reason":'
            b'"cr\xc3\xa9er asset","reversal_of_event_id":null,"schema_version":'
            b'"hmair-h1b-event-v1","source_asset_ids":[],"tenant_id":"tenant-1"}'
        ),
        "event_input_digest": "d5b3184ff5c02ef2744d97af4de6dbc614738c43a165a48be682e79855d4b61f",
        "decisions": (
            {
                "operation_index": 0,
                "child_bytes": (
                    b'{"action":"create","algorithm_version":"hmair-h1b-v1",'
                    b'"candidate_observation_ids":["obs-1","obs-2"],"confidence":0.5,'
                    b'"conflicting_signals":[],"evidence_claim_id":"claim-1",'
                    b'"evidence_node_id":"node-1","matched_signals":[{"category":'
                    b'"API endpoint"}],'
                    b'"new_asset":{"asset_type":"ai_application","canonical_name":'
                    b'"Caf\xc3\xa9 Assistant","deployment_family":"saas","environment":'
                    b'"production","framework":null,"product":"Assistant","provider":'
                    b'"Example AI","technical_surface":"browser","version":"1.0"},'
                    b'"result_asset_id":null,"schema_version":'
                    b'"hmair-h1b-decision-child-v1"}'
                ),
                "child_material_digest": "4d53a823e5ba17ecfd36ba0a58153f4c3d1b9b42709d24e359c6de3d85bbd142",
                "nonhistory_bytes": None,
                "decision_idempotency_key": "dbfc9349a1e20d570522c11c34bc374466ce38c2e41d7d5ecd6429412676fc7c",
                "decision_input_digest": "1bf2c5482e5a61d14ad20624322990c9b41eab821c5e1663453359caa2cde379",
            },
        ),
    },
    "attach": {
        "event_bytes": (
            b'{"actor_id":"op\xc3\xa9rateur-1","actor_role":"owner","children":'
            b'[{"child":{"action":"attach","algorithm_version":"hmair-h1b-v1",'
            b'"candidate_observation_ids":["obs-1","obs-2"],"confidence":0.5,'
            b'"conflicting_signals":[],"evidence_claim_id":"claim-1",'
            b'"evidence_node_id":"node-1","matched_signals":[{"category":'
            b'"API endpoint"}],"new_asset":null,'
            b'"result_asset_id":"asset-result-1","schema_version":'
            b'"hmair-h1b-decision-child-v1"},"child_material_digest":'
            b'"4bfc0eb9c115351280b40dfdc06cbc5da26671c6294b1ccd88b19a753f214a83",'
            b'"operation_index":0}],"event_evidence_claim_id":"claim-1",'
            b'"event_evidence_node_id":"node-1","event_type":"attach","reason":'
            b'"operator approved","reversal_of_event_id":null,"schema_version":'
            b'"hmair-h1b-event-v1","source_asset_ids":[],"tenant_id":"tenant-1"}'
        ),
        "event_input_digest": "1357a9cca810b555c8f0f7cbf6b2858e39e0efa6ec638251c6084b96c6cc7acd",
        "decisions": (
            {
                "operation_index": 0,
                "child_bytes": (
                    b'{"action":"attach","algorithm_version":"hmair-h1b-v1",'
                    b'"candidate_observation_ids":["obs-1","obs-2"],"confidence":0.5,'
                    b'"conflicting_signals":[],"evidence_claim_id":"claim-1",'
                    b'"evidence_node_id":"node-1","matched_signals":[{"category":'
                    b'"API endpoint"}],'
                    b'"new_asset":null,"result_asset_id":"asset-result-1",'
                    b'"schema_version":"hmair-h1b-decision-child-v1"}'
                ),
                "child_material_digest": "4bfc0eb9c115351280b40dfdc06cbc5da26671c6294b1ccd88b19a753f214a83",
                "nonhistory_bytes": None,
                "decision_idempotency_key": "dbfc9349a1e20d570522c11c34bc374466ce38c2e41d7d5ecd6429412676fc7c",
                "decision_input_digest": "f21c4de1864a5810848d49e7bbdb6638ab309eef325269c4cca9153e66d803e5",
            },
        ),
    },
    "merge": {
        "event_bytes": (
            b'{"actor_id":"op\xc3\xa9rateur-1","actor_role":"owner","children":'
            b'[{"child":{"action":"merge","algorithm_version":"hmair-merge-v1",'
            b'"candidate_observation_ids":["obs-1","obs-2"],"confidence":0.75,'
            b'"conflicting_signals":[],"evidence_claim_id":"claim-merge-1",'
            b'"evidence_node_id":"node-merge-1","matched_signals":[{"category":'
            b'"exact provider IDs"}],'
            b'"new_asset":null,"result_asset_id":"asset-result-1","schema_version":'
            b'"hmair-h1b-decision-child-v1"},"child_material_digest":'
            b'"afed2b6c1f1e9df2beb458e49fe799bbab8278a00f0cb9d17a28b97f3773a329",'
            b'"operation_index":0}],"event_evidence_claim_id":"claim-merge-1",'
            b'"event_evidence_node_id":"node-merge-1","event_type":"merge","reason":'
            b'"operator approved merge","reversal_of_event_id":null,"schema_version":'
            b'"hmair-h1b-event-v1","source_asset_ids":["asset-source-1",'
            b'"asset-source-2"],"tenant_id":"tenant-1"}'
        ),
        "event_input_digest": "b59aac7532eb1ded0879c577771d6c2efec72c0b94e4cfc56acfb6aa3d2162b6",
        "decisions": (
            {
                "operation_index": 0,
                "child_bytes": (
                    b'{"action":"merge","algorithm_version":"hmair-merge-v1",'
                    b'"candidate_observation_ids":["obs-1","obs-2"],"confidence":0.75,'
                    b'"conflicting_signals":[],"evidence_claim_id":"claim-merge-1",'
                    b'"evidence_node_id":"node-merge-1","matched_signals":[{"category":'
                    b'"exact provider IDs"}],'
                    b'"new_asset":null,"result_asset_id":"asset-result-1",'
                    b'"schema_version":"hmair-h1b-decision-child-v1"}'
                ),
                "child_material_digest": "afed2b6c1f1e9df2beb458e49fe799bbab8278a00f0cb9d17a28b97f3773a329",
                "nonhistory_bytes": None,
                "decision_idempotency_key": "d9484c02c8bf61dfeff78c63a64001fd88a708741ab4cba047b621113e4ebd4f",
                "decision_input_digest": "b66fadf676e1d3dfd4b6707267573982d25799992b10eaad8a8c090c31a96ca5",
            },
        ),
    },
    "split": {
        "event_bytes": (
            b'{"actor_id":"op\xc3\xa9rateur-1","actor_role":"owner","children":'
            b'[{"child":{"action":"attach","algorithm_version":"split-attach-v1",'
            b'"candidate_observation_ids":["obs-2"],"confidence":0.6,'
            b'"conflicting_signals":[],"evidence_claim_id":"claim-child-2",'
            b'"evidence_node_id":"node-child-2","matched_signals":[{"category":'
            b'"MCP server URL"}],'
            b'"new_asset":null,"result_asset_id":"asset-result-2","schema_version":'
            b'"hmair-h1b-decision-child-v1"},"child_material_digest":'
            b'"35174b7f7e11fd79a74ad858b1c0085087e6a9765be76b43eecb4d3abd3fda5a",'
            b'"operation_index":0},{"child":{"action":"create","algorithm_version":'
            b'"split-create-v1","candidate_observation_ids":["obs-1"],'
            b'"confidence":0.4,"conflicting_signals":[],"evidence_claim_id":'
            b'"claim-child-1","evidence_node_id":"node-child-1","matched_signals":'
            b'[{"category":"repository origin"}],'
            b'"new_asset":{"asset_type":"ai_application","canonical_name":'
            b'"Caf\xc3\xa9 Split","deployment_family":"saas","environment":"production",'
            b'"framework":null,"product":"Assistant","provider":"Example AI",'
            b'"technical_surface":"browser","version":"1.0"},"result_asset_id":null,'
            b'"schema_version":"hmair-h1b-decision-child-v1"},'
            b'"child_material_digest":'
            b'"f951ea81cffe1eef741eda2828a32349cf7466d67ec125bf32a752c3e78d8328",'
            b'"operation_index":1}],"event_evidence_claim_id":"claim-event-1",'
            b'"event_evidence_node_id":"node-event-1","event_type":"split","reason":'
            b'"operator approved split","reversal_of_event_id":null,"schema_version":'
            b'"hmair-h1b-event-v1","source_asset_ids":["asset-source-1"],'
            b'"tenant_id":"tenant-1"}'
        ),
        "event_input_digest": "ad393d6f9cb9e4e14caeb2df3a1885adb3fb44c23a1ad630b1f9363013713d81",
        "decisions": (
            {
                "operation_index": 0,
                "child_bytes": (
                    b'{"action":"attach","algorithm_version":"split-attach-v1",'
                    b'"candidate_observation_ids":["obs-2"],"confidence":0.6,'
                    b'"conflicting_signals":[],"evidence_claim_id":"claim-child-2",'
                    b'"evidence_node_id":"node-child-2","matched_signals":[{"category":'
                    b'"MCP server URL"}],'
                    b'"new_asset":null,"result_asset_id":"asset-result-2",'
                    b'"schema_version":"hmair-h1b-decision-child-v1"}'
                ),
                "child_material_digest": "35174b7f7e11fd79a74ad858b1c0085087e6a9765be76b43eecb4d3abd3fda5a",
                "nonhistory_bytes": None,
                "decision_idempotency_key": "2e7c107d6740ab99e510fa827570d581ce8c9702f4d5c6328c3589cffbbff0da",
                "decision_input_digest": "d8ee6689ccc580541657ca1648623693b46cfbc80112356abacdf2a9ca3207d8",
            },
            {
                "operation_index": 1,
                "child_bytes": (
                    b'{"action":"create","algorithm_version":"split-create-v1",'
                    b'"candidate_observation_ids":["obs-1"],"confidence":0.4,'
                    b'"conflicting_signals":[],"evidence_claim_id":"claim-child-1",'
                    b'"evidence_node_id":"node-child-1","matched_signals":[{"category":'
                    b'"repository origin"}],'
                    b'"new_asset":{"asset_type":"ai_application","canonical_name":'
                    b'"Caf\xc3\xa9 Split","deployment_family":"saas","environment":'
                    b'"production","framework":null,"product":"Assistant","provider":'
                    b'"Example AI","technical_surface":"browser","version":"1.0"},'
                    b'"result_asset_id":null,"schema_version":'
                    b'"hmair-h1b-decision-child-v1"}'
                ),
                "child_material_digest": "f951ea81cffe1eef741eda2828a32349cf7466d67ec125bf32a752c3e78d8328",
                "nonhistory_bytes": None,
                "decision_idempotency_key": "2f2c301477b06e8036a524eb0b016ee56eae3492b6ca1825b2ad12cc9e11a28a",
                "decision_input_digest": "d79680532388f121fba09105f9e58655222ccdd046f90f854c15310e5b57229f",
            },
        ),
    },
    "reversal": {
        "event_bytes": (
            b'{"actor_id":"op\xc3\xa9rateur-1","actor_role":"owner","children":[],'
            b'"event_evidence_claim_id":"claim-reversal-1",'
            b'"event_evidence_node_id":"node-reversal-1","event_type":"reversal",'
            b'"reason":"operator approved reversal","reversal_of_event_id":'
            b'"history-event-1","schema_version":"hmair-h1b-event-v1",'
            b'"source_asset_ids":[],"tenant_id":"tenant-1"}'
        ),
        "event_input_digest": "bb4e4217cc63e651f298008f157d457dcc3ec4fedf3154dcc9a2c2c8eb9b146d",
        "decisions": (),
    },
    "reject": {
        "event_bytes": None,
        "event_input_digest": None,
        "decisions": (
            {
                "operation_index": 0,
                "child_bytes": None,
                "child_material_digest": None,
                "nonhistory_bytes": (
                    b'{"action":"reject","actor_id":"op\xc3\xa9rateur-1",'
                    b'"actor_role":"owner","algorithm_version":"hmair-h1b-v1",'
                    b'"candidate_observation_ids":["obs-1","obs-2"],'
                    b'"canonical_asset_id":null,"confidence":0.5,'
                    b'"conflicting_signals":[],"evidence_claim_id":"claim-1",'
                    b'"evidence_node_id":"node-1","matched_signals":[{"category":'
                    b'"API endpoint"}],'
                    b'"schema_version":"hmair-h1b-nonhistory-decision-v1",'
                    b'"tenant_id":"tenant-1"}'
                ),
                "decision_idempotency_key": "dbfc9349a1e20d570522c11c34bc374466ce38c2e41d7d5ecd6429412676fc7c",
                "decision_input_digest": "45b5848b56e808a6989a3672d76308d0cbda26d2212d7e99856013112fd7091e",
            },
        ),
    },
    "manual_review": {
        "event_bytes": None,
        "event_input_digest": None,
        "decisions": (
            {
                "operation_index": 0,
                "child_bytes": None,
                "child_material_digest": None,
                "nonhistory_bytes": (
                    b'{"action":"manual_review","actor_id":"op\xc3\xa9rateur-1",'
                    b'"actor_role":"owner","algorithm_version":"hmair-h1b-v1",'
                    b'"candidate_observation_ids":["obs-1","obs-2"],'
                    b'"canonical_asset_id":null,"confidence":0.5,'
                    b'"conflicting_signals":[{"category":"API endpoint"}],'
                    b'"evidence_claim_id":"claim-1",'
                    b'"evidence_node_id":"node-1","matched_signals":[{"category":'
                    b'"API endpoint"}],'
                    b'"schema_version":"hmair-h1b-nonhistory-decision-v1",'
                    b'"tenant_id":"tenant-1"}'
                ),
                "decision_idempotency_key": "dbfc9349a1e20d570522c11c34bc374466ce38c2e41d7d5ecd6429412676fc7c",
                "decision_input_digest": "405cdff6865d0c1fb158a02fa1d0ef6b2465313a656d8d329428f652972d28fc",
            },
        ),
    },
}


def _canonical_for_action(action: str) -> Any:
    if action == "create":
        return C._canonicalize_resolution_request(
            tenant_id="tenant-1",
            actor=_actor(),
            action=C.ResolutionAction("create"),
            payload=_resolution_request(
                candidate_observation_ids=("obs-2", "obs-1"),
                new_asset=_new_asset(),
                reason="cr\u00e9er asset",
            ),
        )
    if action == "attach":
        return C._canonicalize_resolution_request(
            tenant_id="tenant-1",
            actor=_actor(),
            action=C.ResolutionAction("attach"),
            payload=_resolution_request(
                existing_asset_id="asset-result-1",
                reason="operator approved",
            ),
        )
    if action == "merge":
        return C._canonicalize_merge_request(
            tenant_id="tenant-1", actor=_actor(), payload=_merge_request()
        )
    if action == "split":
        return C._canonicalize_split_request(
            tenant_id="tenant-1", actor=_actor(), payload=_split_request()
        )
    if action == "reversal":
        return C._canonicalize_reversal_request(
            tenant_id="tenant-1", actor=_actor(), payload=_reversal_request()
        )
    if action in {"reject", "manual_review"}:
        return C._canonicalize_resolution_request(
            tenant_id="tenant-1",
            actor=_actor(),
            action=C.ResolutionAction(action),
            payload=_resolution_request(
                conflicting_signals=(
                    (_signal("API endpoint"),) if action == "manual_review" else ()
                )
            ),
        )
    raise AssertionError(action)


@pytest.mark.parametrize(
    "action",
    ["create", "attach", "merge", "split", "reversal", "reject", "manual_review"],
)
def test_all_actions_match_independent_canonical_byte_and_digest_vectors(
    action: str,
) -> None:
    expected = GOLDEN[action]
    material = _canonical_for_action(action)
    assert material.event_bytes == expected["event_bytes"]
    assert material.event_input_digest == expected["event_input_digest"]
    assert len(material.decisions) == len(expected["decisions"])
    for actual, frozen in zip(material.decisions, expected["decisions"], strict=True):
        assert actual.operation_index == frozen["operation_index"]
        assert actual.child_bytes == frozen["child_bytes"]
        assert actual.child_material_digest == frozen["child_material_digest"]
        assert actual.nonhistory_bytes == frozen["nonhistory_bytes"]
        assert actual.decision_idempotency_key == frozen["decision_idempotency_key"]
        assert actual.decision_input_digest == frozen["decision_input_digest"]


def test_category_only_nonempty_conflicting_signal_vector_is_literal() -> None:
    material = _canonical_for_action("manual_review")
    decision = material.decisions[0]
    assert tuple(
        dict(item) for item in decision.nonhistory_object["matched_signals"]
    ) == ({"category": "API endpoint"},)
    assert tuple(
        dict(item) for item in decision.nonhistory_object["conflicting_signals"]
    ) == ({"category": "API endpoint"},)
    assert decision.nonhistory_bytes == GOLDEN["manual_review"]["decisions"][0][
        "nonhistory_bytes"
    ]


def test_split_canonicalizes_children_before_whole_event_hashing() -> None:
    original = _canonical_for_action("split")
    reordered = C._canonicalize_split_request(
        tenant_id="tenant-1",
        actor=_actor(),
        payload=_split_request(
            partitions=(
                _partition_create(candidate_observation_ids=("obs-1",)),
                _partition_attach(candidate_observation_ids=("obs-2",)),
            )
        ),
    )
    assert reordered == original
    assert [item.operation_index for item in original.decisions] == [0, 1]
    assert [item.child_material_digest for item in original.decisions] == sorted(
        item.child_material_digest for item in original.decisions
    )


def test_split_rejects_distinct_children_with_duplicate_material_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        C,
        "_resolution_child_material_digest",
        lambda canonical_child_bytes: "0" * 64,
    )
    with pytest.raises(ValueError):
        C._canonicalize_split_request(
            tenant_id="tenant-1",
            actor=_actor(),
            payload=_split_request(),
        )


def test_signal_order_is_canonical_and_duplicate_entries_reject() -> None:
    first = _signal("repository origin")
    second = _signal("API endpoint")
    left = C._canonicalize_resolution_request(
        tenant_id="tenant-1",
        actor=_actor(),
        action=C.ResolutionAction("manual_review"),
        payload=_resolution_request(matched_signals=(first, second)),
    )
    right = C._canonicalize_resolution_request(
        tenant_id="tenant-1",
        actor=_actor(),
        action=C.ResolutionAction("manual_review"),
        payload=_resolution_request(matched_signals=(second, first)),
    )
    assert left == right
    with pytest.raises(ValidationError):
        _resolution_request(matched_signals=(first, first))


def test_altered_replay_changes_input_digest_but_not_derived_key() -> None:
    original = _canonical_for_action("attach")
    altered = C._canonicalize_resolution_request(
        tenant_id="tenant-1",
        actor=_actor(),
        action=C.ResolutionAction("attach"),
        payload=_resolution_request(
            existing_asset_id="asset-result-1",
            reason="different approved reason",
        ),
    )
    assert altered.event_input_digest != original.event_input_digest
    assert (
        altered.decisions[0].decision_input_digest
        != original.decisions[0].decision_input_digest
    )
    assert (
        altered.decisions[0].decision_idempotency_key
        == original.decisions[0].decision_idempotency_key
    )


def test_request_key_changes_derived_key_not_canonical_input_digest() -> None:
    original = _canonical_for_action("merge")
    changed_key = C._canonicalize_merge_request(
        tenant_id="tenant-1",
        actor=_actor(),
        payload=_merge_request(idempotency_key="merge-request-2"),
    )
    assert changed_key.event_input_digest == original.event_input_digest
    assert (
        changed_key.decisions[0].decision_input_digest
        == original.decisions[0].decision_input_digest
    )
    assert (
        changed_key.decisions[0].decision_idempotency_key
        != original.decisions[0].decision_idempotency_key
    )


def test_nonhistory_material_has_no_event_input_or_child_material() -> None:
    for action in ("reject", "manual_review"):
        material = _canonical_for_action(action)
        assert material.event_object is None
        assert material.event_bytes is None
        assert material.event_input_digest is None
        assert len(material.decisions) == 1
        decision = material.decisions[0]
        assert decision.child_object is None
        assert decision.child_bytes is None
        assert decision.child_material_digest is None
        assert decision.nonhistory_object is not None
        assert decision.nonhistory_bytes is not None


def test_reversal_has_event_material_and_no_decision_material() -> None:
    reversal = _canonical_for_action("reversal")
    assert reversal.event_object["event_type"] == "reversal"
    assert reversal.event_object["source_asset_ids"] == ()
    assert reversal.event_object["children"] == ()
    assert reversal.event_object["reversal_of_event_id"] == "history-event-1"
    assert reversal.decisions == ()


def test_canonical_objects_have_exact_schema_keys_and_explicit_nulls() -> None:
    create = _canonical_for_action("create")
    child = create.decisions[0].child_object
    assert set(child) == {
        "action",
        "algorithm_version",
        "candidate_observation_ids",
        "confidence",
        "conflicting_signals",
        "evidence_claim_id",
        "evidence_node_id",
        "matched_signals",
        "new_asset",
        "result_asset_id",
        "schema_version",
    }
    assert child["result_asset_id"] is None
    assert set(child["new_asset"]) == {
        "asset_type",
        "canonical_name",
        "provider",
        "product",
        "framework",
        "version",
        "deployment_family",
        "technical_surface",
        "environment",
    }
    assert child["new_asset"]["framework"] is None
    assert set(create.event_object) == {
        "actor_id",
        "actor_role",
        "children",
        "event_evidence_claim_id",
        "event_evidence_node_id",
        "event_type",
        "reason",
        "reversal_of_event_id",
        "schema_version",
        "source_asset_ids",
        "tenant_id",
    }
    assert create.event_object["reversal_of_event_id"] is None


def test_missing_or_extra_fixed_schema_keys_reject() -> None:
    data = _partition_create()
    data.pop("algorithm_version")
    with pytest.raises(ValidationError):
        C.SplitPartition(**data)
    with pytest.raises(ValidationError):
        C.SplitPartition(**{**_partition_create(), "invented": "not allowed"})


def test_golden_canonical_bytes_exclude_private_and_ambient_material() -> None:
    for vector in GOLDEN.values():
        chunks = [vector["event_bytes"]]
        chunks.extend(item["child_bytes"] for item in vector["decisions"])
        chunks.extend(item["nonhistory_bytes"] for item in vector["decisions"])
        rendered = b"\n".join(item for item in chunks if item is not None)
        assert b"idempotency_key" not in rendered
        assert b"resolution-request-1" not in rendered
        assert b"raw" not in rendered.lower()
        assert b"prompt" not in rendered.lower()
        assert b"secret" not in rendered.lower()
        assert b"timestamp" not in rendered.lower()
        assert b"generated" not in rendered.lower()
