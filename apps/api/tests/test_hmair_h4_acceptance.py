from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api.routers.discovery_scans import _SURFACE_FLAGS as API_SURFACE_FLAGS
from app.jobs.hmair_discovery_jobs import _SURFACE_FLAGS as JOB_SURFACE_FLAGS
from app.services.hmair.collector_registry import CollectorRegistry
from app.services.hmair.collector_sdk import DiscoveryTargetView
from app.services.hmair.collectors.path_native import PathNativeSignal


NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[3]

EXPECTED_PROFILES = {
    "azure_managed_ai",
    "aws_managed_ai",
    "gcp_managed_ai",
    "kubernetes_ai_workloads",
    "microsoft365_ai",
    "github_ai",
    "google_workspace_ai",
    "slack_ai",
    "salesforce_ai",
    "servicenow_ai",
    "atlassian_ai",
    "notion_ai",
    "zoom_ai",
    "entra_ai_identity",
    "okta_ai_identity",
    "google_ai_identity",
    "repository_ai_metadata",
    "cicd_ai_metadata",
    "dns_ai_metadata",
    "swg_ai_metadata",
    "proxy_ai_metadata",
    "firewall_ai_metadata",
    "flow_ai_metadata",
    "api_gateway_ai_metadata",
    "service_mesh_ai_metadata",
    "api_catalog_ai_metadata",
    "database_ai_metadata",
    "vector_store_ai_metadata",
    "search_rag_knowledge_metadata",
    "prompt_registry_metadata",
    "memory_store_metadata",
}
EXPECTED_FAMILIES = {
    "managed_ai",
    "kubernetes",
    "saas",
    "identity",
    "repository_ci",
    "network",
    "api_catalog",
    "data_platform",
}
H4_TARGET_FLAGS = {
    "cloud_subscription": "hmair_cloud",
    "cloud_project": "hmair_cloud",
    "kubernetes_cluster": "hmair_cloud",
    "saas_tenant": "hmair_saas",
    "identity_tenant": "hmair_identity",
    "repository_org": "hmair_repository",
    "repository": "hmair_repository",
    "network_range": "hmair_network",
    "dns_domain": "hmair_network",
    "api_gateway": "hmair_network",
    "database_platform": "hmair_database",
    "ai_provider_account": "hmair_saas",
}


def _h4_modules():
    try:
        from app.services.hmair.collectors.h4_catalog import (
            H4_COLLECTOR_PROFILES,
            get_h4_collector_profile,
        )
        from app.services.hmair.collectors.h4_metadata import H4MetadataCollector
        from app.services.hmair.collectors.path_native import (
            register_h4_profile_collectors,
        )
    except ModuleNotFoundError as error:
        pytest.fail(f"H4 implementation is unavailable: {error}")
    return (
        H4_COLLECTOR_PROFILES,
        get_h4_collector_profile,
        H4MetadataCollector,
        register_h4_profile_collectors,
    )


def _signal(profile, *, observed_state: str = "configured") -> PathNativeSignal:
    return PathNativeSignal(
        observation_id=f"h4-{profile.profile_id}",
        scan_id="00000000-0000-4000-8000-000000000404",
        target_id=f"target-{profile.profile_id}",
        subject_reference=f"{profile.family}:{profile.profile_id}",
        raw_signal_type=profile.observation_types[0],
        asset_candidate_type="unknown_ai_candidate",
        observed_state=observed_state,
        normalized_signal={
            "provider": profile.provider,
            "resource_ref_hash": "a" * 64,
        },
        identifiers={"resource_ref_hash": "a" * 64},
        configuration_summary={"mode": "metadata_only"},
        usage_summary=(
            {"event_count": 1} if observed_state == "actively_used" else {}
        ),
        capability_hints=(),
        identity_hints=(),
        relationship_hints=(),
        evidence_reference=f"h4://{profile.profile_id}/safe-metadata",
        evidence_hash="b" * 64,
        observed_at=NOW,
        confidence=0.75,
        freshness="fresh",
        verification_state="partially_verified",
        source_trust="medium",
        collection_scope={
            "profile_id": profile.profile_id,
            "connection_mode": profile.supported_connection_modes[0],
            "target_type": profile.target_type.value,
            "source_surface": profile.source_surface.value,
        },
        evidence_mode="direct",
        evidence_mutability="mutable",
        contradiction_state="none",
        contradiction_references=(),
    )


def test_h4_catalog_has_exact_stable_profiles_and_families() -> None:
    profiles, lookup, _, _ = _h4_modules()
    assert len(profiles) == len(EXPECTED_PROFILES)
    assert {item.profile_id for item in profiles} == EXPECTED_PROFILES
    assert {item.family for item in profiles} == EXPECTED_FAMILIES
    assert len({item.profile_id for item in profiles}) == len(profiles)
    assert all(lookup(item.profile_id) is item for item in profiles)
    with pytest.raises(LookupError):
        lookup("unknown_provider")


def test_h4_profiles_are_metadata_only_and_operationally_complete() -> None:
    profiles, _, _, _ = _h4_modules()
    forbidden = {"credential", "password", "private_key", "secret", "token"}
    for profile in profiles:
        payload = profile.model_dump(mode="json")
        assert profile.observation_types
        assert profile.passive_capabilities
        assert profile.permissions_required
        assert profile.privacy_exclusions
        assert profile.limitations
        assert profile.denominator_behavior
        assert profile.data_residency
        assert profile.supported_connection_modes
        assert profile.active_capabilities == ()
        assert profile.control_capability == "monitor_only"
        assert not any(callable(value) for value in payload.values())
        assert not forbidden & set(payload)
        assert all("@" not in value for value in profile.permissions_required)


def test_every_h4_profile_uses_one_canonical_catalog_backed_adapter() -> None:
    profiles, _, adapter_type, _ = _h4_modules()
    for profile in profiles:
        signal = _signal(profile)
        collector = adapter_type(profile=profile, signals=(signal,))
        emitted = collector.emit_observations()
        assert len(emitted) == 1
        assert emitted[0].collector_type == f"hmair_h4_{profile.profile_id}"
        assert emitted[0].source_surface == profile.source_surface
        assert emitted[0].raw_signal_type in profile.observation_types
        scope = collector.enumerate_scope(
            DiscoveryTargetView(
                target_id=signal.target_id,
                target_type=profile.target_type,
                identifier=f"{profile.profile_id}:opaque",
                environment="production",
                permitted_methods=("metadata",),
                exclusions=tuple(profile.privacy_exclusions),
                rate_limit=100,
                active_scan_allowed=False,
                sensitive_scope=False,
            )
        )[0]
        assert collector.collect_usage(scope) == ()


def test_h4_adapter_rejects_cross_profile_and_raw_content() -> None:
    profiles, lookup, adapter_type, _ = _h4_modules()
    azure = lookup("azure_managed_ai")
    slack = lookup("slack_ai")
    with pytest.raises(ValueError):
        adapter_type(profile=azure, signals=(_signal(slack),))
    with pytest.raises(ValidationError):
        PathNativeSignal(
            **{
                **_signal(profiles[0]).model_dump(mode="python"),
                "normalized_signal": {"file_content": "private source"},
            }
        )


def test_h4_profile_registry_is_explicit_and_non_evidence_bearing() -> None:
    profiles, _, _, register = _h4_modules()
    registry = CollectorRegistry()
    register(registry, enabled=False)
    assert registry.list_declarations() == ()
    register(registry, enabled=True)
    declarations = registry.list_declarations()
    assert len(declarations) == len(profiles)
    assert {item.collector_type for item in declarations} == {
        f"hmair_h4_{profile.profile_id}" for profile in profiles
    }
    assert all(item.health == "unknown" for item in declarations)
    assert all(item.active_capabilities == () for item in declarations)
    assert all(item.control_capability == "monitor_only" for item in declarations)
    assert len({item.declaration_hash for item in declarations}) == len(declarations)


def test_h4_target_flags_are_complete_and_identical_in_api_and_worker() -> None:
    for target_type, flag in H4_TARGET_FLAGS.items():
        assert API_SURFACE_FLAGS[target_type] == flag
        assert JOB_SURFACE_FLAGS[target_type] == flag


def test_h4_connection_modes_never_imply_live_coverage() -> None:
    profiles, lookup, _, _ = _h4_modules()
    assert "typed_direct" in lookup("microsoft365_ai").supported_connection_modes
    assert "typed_direct" in lookup("github_ai").supported_connection_modes
    for profile in profiles:
        assert set(profile.supported_connection_modes) <= {
            "typed_direct",
            "existing_connector",
            "attested_metadata_feed",
        }
        assert "adapter_presence_is_not_coverage" in profile.limitations
        assert "customer_owned_connection_required" in profile.limitations


def test_h4_cross_family_fixtures_cover_every_profile_without_content() -> None:
    profiles, _, _, _ = _h4_modules()
    fixture_paths = (
        ROOT / "apps/api/tests/fixtures/hmair/h4-cloud-kubernetes.json",
        ROOT / "apps/api/tests/fixtures/hmair/h4-saas-identity.json",
        ROOT / "apps/api/tests/fixtures/hmair/h4-repository-network-data.json",
    )
    rows = tuple(
        row
        for path in fixture_paths
        for row in json.loads(path.read_text(encoding="utf-8"))["profiles"]
    )
    assert {row["profile_id"] for row in rows} == {
        item.profile_id for item in profiles
    }
    rendered = json.dumps(rows, sort_keys=True).casefold()
    for forbidden in (
        "prompt_content",
        "response_content",
        "source_code",
        "file_content",
        "database_row",
        "vector_content",
        "credential",
        "private_key",
    ):
        assert forbidden not in rendered
