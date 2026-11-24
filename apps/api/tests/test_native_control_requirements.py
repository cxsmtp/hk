from __future__ import annotations

import pytest

from app.core.control_engine.authorization import AuthorizationRequest
from app.services.native_control.contracts import (
    AssuranceLevel,
    CapabilityDimension,
    DegradationMode,
)
from app.services.native_control.requirements import derive_control_requirements
from app.services.native_control.providers import canonical_provider


def _request(**changes: object) -> AuthorizationRequest:
    payload: dict[str, object] = {
        "tenant_id": "tenant-1",
        "environment": "production",
        "collector_id": "mcp-gateway",
        "action_id": "action-1",
        "chain_id": "chain-1",
        "surface": "mcp_gateway",
        "actor": {"identity_id": "user-1"},
        "authority": {"verified": True},
        "action": {"action_type": "tool_execution", "risk_level": "high"},
        "tool": {"name": "github.create_pull_request", "fingerprint_id": "tool-1"},
        "parameters": {"parameter_hash": "p" * 64},
        "target": {
            "resource_hash": "r" * 64,
            "destination": "github.com",
            "destination_hash": "d" * 64,
        },
        "side_effect_context": {"persistent_side_effect": True},
        "discovery_context": {"provider": "openai", "product": "direct_api"},
        "policy_snapshot_id": "policy-7",
        "policy_profile": {
            "dependencies_healthy": True,
            "degraded_behavior": "block",
            "minimum_control_assurance": "A5",
            "maximum_control_latency_ms": 120,
        },
        "path_evidence": {},
    }
    payload.update(changes)
    return AuthorizationRequest.model_validate(payload)


def test_existing_policy_context_derives_exact_selector_requirements() -> None:
    requirement = derive_control_requirements(_request())

    assert requirement.action_class == "persistent_side_effect"
    assert requirement.requires_pre_execution is True
    assert requirement.pre_execution_capability is CapabilityDimension.MCP_CONTROL
    assert requirement.requires_identity is True
    assert requirement.requires_parameter_binding is True
    assert requirement.requires_target_binding is True
    assert requirement.requires_destination_binding is True
    assert requirement.requires_post_execution is True
    assert requirement.requires_persistence_detection is True
    assert requirement.minimum_assurance is AssuranceLevel.A5_VERIFIED
    assert requirement.maximum_latency_ms == 120
    assert requirement.acceptable_degradation_modes == (DegradationMode.FAIL_CLOSED,)


def test_prompt_without_side_effect_does_not_invent_binding_requirements() -> None:
    request = _request(
        action={"action_type": "prompt", "risk_level": "low"},
        tool={},
        parameters={},
        target={},
        side_effect_context={},
        policy_profile={"dependencies_healthy": True, "degraded_behavior": "monitor"},
    )

    requirement = derive_control_requirements(request)

    assert requirement.action_class == "model_interaction"
    assert requirement.pre_execution_capability is CapabilityDimension.PROMPT_CONTROL
    assert requirement.requires_parameter_binding is False
    assert requirement.requires_target_binding is False
    assert requirement.requires_destination_binding is False
    assert requirement.requires_post_execution is False
    assert requirement.minimum_assurance is AssuranceLevel.A3_INLINE
    assert requirement.acceptable_degradation_modes == (DegradationMode.MONITOR_ONLY,)


def test_local_file_read_requires_file_capability_without_destination_binding() -> None:
    request = _request(
        surface="runtime_control",
        action={"action_type": "file_read", "risk_level": "low"},
        target={"destination": "local", "destination_hash": "d" * 64},
        side_effect_context={},
    )

    requirement = derive_control_requirements(request)

    assert requirement.pre_execution_capability is CapabilityDimension.FILE_READ_CONTROL
    assert requirement.requires_destination_binding is False


def test_remote_file_read_still_requires_destination_binding() -> None:
    request = _request(
        surface="runtime_control",
        action={"action_type": "file_read", "risk_level": "low"},
        target={"destination": "github.com", "destination_hash": "d" * 64},
        side_effect_context={},
    )

    assert derive_control_requirements(request).requires_destination_binding is True


def test_unknown_minimum_assurance_fails_to_stronger_derived_requirement() -> None:
    request = _request(policy_profile={"minimum_control_assurance": "marketing-grade"})

    requirement = derive_control_requirements(request)

    assert requirement.minimum_assurance is AssuranceLevel.A5_VERIFIED


@pytest.mark.parametrize(
    ("surface", "action_type", "expected"),
    (
        ("sdk", "prompt", CapabilityDimension.PROMPT_CONTROL),
        ("sdk", "response", CapabilityDimension.RESPONSE_CONTROL),
        ("mcp_gateway", "tool_execution", CapabilityDimension.MCP_CONTROL),
        ("runtime_control", "command_execution", CapabilityDimension.COMMAND_CONTROL),
        ("runtime_control", "file_read", CapabilityDimension.FILE_READ_CONTROL),
        ("runtime_control", "file_write", CapabilityDimension.FILE_WRITE_CONTROL),
        ("runtime_control", "network_request", CapabilityDimension.NETWORK_CONTROL),
        ("sdk", "agent_action", CapabilityDimension.TOOL_CONTROL),
    ),
)
def test_pre_execution_capability_tracks_the_actual_action_surface(
    surface: str,
    action_type: str,
    expected: CapabilityDimension,
) -> None:
    request = _request(
        surface=surface,
        action={"action_type": action_type, "risk_level": "high"},
        side_effect_context={},
    )

    assert derive_control_requirements(request).pre_execution_capability is expected


@pytest.mark.parametrize(
    ("alias", "expected"),
    (("gemini", "google"), ("azure_openai", "azure"), ("bedrock", "aws"), ("llama", "meta")),
)
def test_live_provider_aliases_normalize_to_native_manifest_namespace(alias: str, expected: str) -> None:
    assert canonical_provider(alias) == expected
