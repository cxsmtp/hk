from __future__ import annotations

from importlib import import_module

import pytest
from pydantic import ValidationError

from app.db.models.discovery_canonical import DiscoveryObservation


CONTRACTS = import_module("app.services.hmair.contracts")


def test_phase2_source_surface_taxonomy_is_complete() -> None:
    source_surface = getattr(CONTRACTS, "SourceSurface", None)

    assert source_surface is not None
    assert {item.value for item in source_surface} == {
        "endpoint",
        "browser",
        "cloud",
        "saas",
        "identity",
        "source_code",
        "ci_cd",
        "network",
        "dns",
        "api_gateway",
        "service_mesh",
        "mcp",
        "database",
        "vector_store",
        "model_endpoint",
        "runtime",
        "kubernetes",
        "container",
        "unknown",
    }


def test_phase2_observation_type_taxonomy_is_complete() -> None:
    observation_type = getattr(CONTRACTS, "ObservationType", None)

    assert observation_type is not None
    assert {item.value for item in observation_type} == {
        "installed_application",
        "running_process",
        "browser_extension",
        "web_ai_usage",
        "sdk_dependency",
        "package_reference",
        "ai_endpoint_reference",
        "model_deployment",
        "agent_resource",
        "mcp_client",
        "mcp_server",
        "mcp_tool",
        "oauth_app",
        "service_principal",
        "managed_identity",
        "license_assignment",
        "network_flow",
        "dns_lookup",
        "api_call",
        "vector_db_reference",
        "rag_index",
        "prompt_config",
        "agent_config",
        "tool_config",
        "model_config",
        "ai_saas_feature",
        "active_user",
        "token_usage",
        "request_usage",
        "unknown_ai_signal",
    }


def test_phase2_fact_truth_taxonomies_are_explicit() -> None:
    fact_state = getattr(CONTRACTS, "ObservedFactState", None)
    verification = getattr(CONTRACTS, "FactVerificationState", None)
    source_trust = getattr(CONTRACTS, "SourceTrust", None)

    assert fact_state is not None
    assert verification is not None
    assert source_trust is not None
    assert {item.value for item in fact_state} == {
        "installed",
        "configured",
        "enabled",
        "reachable",
        "observed",
        "actively_used",
        "inferred",
        "unknown",
    }
    assert {item.value for item in verification} == {
        "verified",
        "partially_verified",
        "inferred",
        "contradicted",
        "stale",
        "unknown",
    }
    assert {item.value for item in source_trust} == {
        "strong",
        "medium",
        "weak",
        "unknown",
    }


def test_phase2_observation_contract_requires_evidence_metadata() -> None:
    fields = CONTRACTS.DiscoveryObservationInput.model_fields
    required = {
        "source_surface",
        "subject_reference",
        "raw_signal_type",
        "normalized_signal",
        "asset_candidate_type",
        "observed_state",
        "verification_state",
        "source_trust",
        "collection_scope",
        "parser_version",
        "schema_version",
        "evidence_mode",
        "evidence_mutability",
        "contradiction_state",
        "contradiction_references",
    }

    assert required <= set(fields)
    assert all(fields[name].is_required() for name in required)
    assert "received_at" not in fields
    assert "allow" not in fields
    assert "block" not in fields


def test_phase2_observation_model_persists_server_owned_truth() -> None:
    columns = set(DiscoveryObservation.__table__.columns.keys())

    assert {
        "source_surface",
        "subject_reference",
        "normalized_signal_json",
        "received_at",
        "observed_state",
        "verification_state",
        "source_trust",
        "collection_scope_json",
        "parser_version",
        "schema_version",
        "evidence_mode",
        "evidence_mutability",
        "contradiction_state",
        "contradiction_references_json",
    } <= columns


def test_phase2_observation_rejects_missing_new_truth_fields() -> None:
    with pytest.raises(ValidationError):
        CONTRACTS.DiscoveryObservationInput.model_validate(
            {
                "observation_id": "obs-phase2",
                "scan_id": "00000000-0000-0000-0000-000000000001",
                "collector_id": "collector-phase2",
                "collector_type": "endpoint",
                "collector_version": "2.0.0",
                "target_id": "target-phase2",
                "observed_at": "2026-08-15T08:00:00Z",
                "observation_type": "running_process",
                "candidate_asset_type": "runtime",
                "identifiers": {},
                "attributes": {},
                "configuration_summary": {},
                "usage_summary": {},
                "capability_hints": [],
                "identity_hints": [],
                "relationship_hints": [],
                "evidence_reference": "evidence://phase2",
                "evidence_hash": "a" * 64,
                "signature_status": "verified",
                "confidence": 0.8,
                "freshness": "fresh",
                "sensitivity": "metadata",
                "redaction_status": "redacted",
            }
        )
