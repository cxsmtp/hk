from __future__ import annotations

from dataclasses import replace

import pytest

from app.services.native_control.adapter_contract import AdapterResolutionState
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.claude_adapter import ClaudeAdapter
from app.services.native_control.contracts import ActionClass
from app.services.native_control.live_adapter_dispatch import (
    ExactAdapterDispatchError,
    dispatch_live_callback_adapter,
)
from app.services.native_control.openai_adapters import OpenAIDirectAPIControlAdapter


def _dispatch(
    registry: NativeControlAdapterRegistry,
    *,
    provider_version: str = "2.1.183",
    adapter_version: str = "1.2.0",
    provider: str = "anthropic",
    product: str = "claude_code",
    integration_method: str = "native_hook",
    deployment_family: str = "endpoint",
    runtime: str = "claude_code_native_hook",
    model_provider: str = "anthropic",
    model: str = "claude-3-7-sonnet",
    provider_event_type: str = "before_tool",
    raw_payload: dict[str, object] | None = None,
):
    return dispatch_live_callback_adapter(
        registry=registry,
        tenant_id="tenant-1",
        integration_id="integration-1",
        instance_key="claude-code-mac",
        provider=provider,
        product=product,
        provider_version=provider_version,
        adapter_version=adapter_version,
        environment="production",
        deployment_family=deployment_family,
        integration_method=integration_method,
        runtime=runtime,
        model_provider=model_provider,
        model=model,
        credential_id="credential-1",
        event_id="event-1",
        provider_event_id="provider-tool-1",
        provider_event_type=provider_event_type,
        nonce="nonce-1",
        correlation_id="correlation-1",
        session_id="session-1",
        chain_id="chain-1",
        received_at="2026-08-20T00:00:00+00:00",
        policy_snapshot_id="policy-1",
        policy_profile={"base_decision": "allow", "dependencies_healthy": True},
        resolved_actor={
            "identity_id": "credential-1",
            "identity_type": "workload",
            "authority_type": "signed_workload_identity",
            "authority_source": "native_control_credential",
        },
        raw_payload=raw_payload or {
            "callback_schema": "hawk-native-hash-envelope/v1",
            "action_type": "tool_execution",
            "tool_name": "Read",
            "tool_class": "file_read",
            "tool_fingerprint_id": "f" * 64,
            "parameter_hash": "a" * 64,
            "target_resource": "README.md",
            "target_resource_hash": "b" * 64,
            "destination": "local",
            "destination_hash": "c" * 64,
            "persistent_side_effect": False,
            "data_classifications": [],
        },
    )


def test_live_callback_dispatch_uses_the_exact_provider_adapter() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    dispatch = _dispatch(registry)

    assert dispatch.is_exact is True
    assert dispatch.adapter_id == "anthropic.claude-code.command-hooks"
    assert dispatch.resolution.state is AdapterResolutionState.EXACT_MATCH
    assert dispatch.normalized_event.provider == "anthropic"
    assert dispatch.normalized_event.product == "claude_code"
    assert dispatch.normalized_event.raw_provider_event_type == "PreToolUse"
    assert dispatch.normalized_event.action["parameter_hash"] == "a" * 64
    assert dispatch.normalized_event.target["resource_hash"] == "b" * 64
    assert dispatch.normalized_event.destination["destination_hash"] == "c" * 64
    assert dispatch.authorization_request.collector_id == "native-adapter:integration-1"
    assert dispatch.authorization_request.discovery_context["asset_status"] == "unknown"
    binding = dispatch.authorization_request.path_evidence["native_control_route_binding"]
    assert binding["verified"] is False
    assert binding.get("runtime_context_verified") is not True
    assert "lifecycle_stage" not in binding


def test_hash_only_endpoint_callbacks_preserve_distinct_signed_material_without_raw_rehashing() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())
    first = _dispatch(
        registry,
        raw_payload={
            "callback_schema": "hawk-native-hash-envelope/v1",
            "action_type": "FILE_READ",
            "tool_name": "Read",
            "tool_class": "file_read",
            "tool_fingerprint_id": "f" * 64,
            "parameter_hash": "a" * 64,
            "target_resource_hash": "b" * 64,
            "destination_hash": "c" * 64,
            "persistent_side_effect": False,
        },
    )
    second = _dispatch(
        registry,
        raw_payload={
            "callback_schema": "hawk-native-hash-envelope/v1",
            "action_type": "FILE_READ",
            "tool_name": "Read",
            "tool_class": "file_read",
            "tool_fingerprint_id": "f" * 64,
            "parameter_hash": "z" * 64,
            "target_resource_hash": "y" * 64,
            "destination_hash": "x" * 64,
            "persistent_side_effect": False,
        },
    )

    assert first.normalized_event.action["parameter_hash"] == "a" * 64
    assert second.normalized_event.action["parameter_hash"] == "z" * 64
    assert first.authorization_request.parameters != second.authorization_request.parameters
    assert first.authorization_request.target != second.authorization_request.target
    assert first.authorization_request.parameters["parameter_hash"] != "{}"


@pytest.mark.parametrize("action_type,tool_class,expected", [
    ("FILE_READ", "unknown_tool", ActionClass.FILE_READ),
    ("FILE_READ", "local_shell", ActionClass.FILE_READ),
    ("COMMAND_EXECUTION", "local_shell", ActionClass.COMMAND),
    ("COMMAND_EXECUTION", "file_read", ActionClass.COMMAND),
    ("UNKNOWN_TOOL_ACTION", "file_read", ActionClass.UNKNOWN_ACTION),
    ("UNKNOWN_TOOL_ACTION", "mcp", ActionClass.UNKNOWN_ACTION),
])
def test_hash_only_action_class_uses_signed_action_type_without_tool_label_authority(action_type, tool_class, expected) -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())
    dispatch = _dispatch(registry, raw_payload={
        "callback_schema": "hawk-native-hash-envelope/v1", "action_type": action_type,
        "tool_name": "Read", "tool_class": tool_class, "tool_fingerprint_id": "f" * 64,
        "parameter_hash": "a" * 64, "target_resource_hash": "b" * 64,
        "destination_hash": "c" * 64, "persistent_side_effect": False,
    })
    assert dispatch.normalized_event.action["action_class"] == expected.value
    assert dispatch.runtime_context.action_class == expected
    assert dispatch.normalized_event.action["parameter_hash"] == "a" * 64
    assert dispatch.normalized_event.target["resource_hash"] == "b" * 64
    assert dispatch.normalized_event.destination["destination_hash"] == "c" * 64


def test_hash_only_endpoint_callback_accepts_unknown_delegation_sentinel_without_claiming_depth() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    dispatch = _dispatch(
        registry,
        provider_event_type="before_model",
        raw_payload={
            "callback_schema": "hawk-native-hash-envelope/v1",
            "action_type": "MODEL_REQUEST",
            "tool_name": "unknown",
            "tool_class": "unknown_tool",
            "tool_fingerprint_id": "f" * 64,
            "parameter_hash": "a" * 64,
            "target_resource_hash": "b" * 64,
            "destination_hash": "c" * 64,
            "persistent_side_effect": False,
            "data_classifications": [],
            # The endpoint uses -1 only when the provider supplied no depth.
            "delegation_depth": -1,
        },
    )

    assert dispatch.is_exact is True
    assert "delegation_depth" not in dispatch.normalized_event.runtime


@pytest.mark.parametrize("bad_depth", [-2, 65, True, "1"])
def test_hash_only_endpoint_callback_rejects_invalid_delegation_depth(bad_depth: object) -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    with pytest.raises(ExactAdapterDispatchError, match="provider_event_schema_invalid_field_type"):
        _dispatch(
            registry,
            raw_payload={
                "callback_schema": "hawk-native-hash-envelope/v1",
                "action_type": "MODEL_REQUEST",
                "tool_name": "unknown",
                "tool_fingerprint_id": "f" * 64,
                "parameter_hash": "a" * 64,
                "target_resource_hash": "b" * 64,
                "destination_hash": "c" * 64,
                "delegation_depth": bad_depth,
            },
        )


@pytest.mark.parametrize(
    "raw_payload, reason",
    [
        (
            {
                "callback_schema": "hawk-native-hash-envelope/v1",
                "action_type": "FILE_READ",
                "tool_name": "Read",
                "tool_fingerprint_id": "f" * 64,
                "parameter_hash": "a" * 64,
                "target_resource_hash": "b" * 64,
                "destination_hash": "c" * 64,
                "tool_input": {"path": "README.md"},
            },
            "provider_event_schema_mixed_raw_and_hash_only",
        ),
        (
            {
                "action_type": "FILE_READ",
                "tool_name": "Read",
                "tool_fingerprint_id": "f" * 64,
                "parameter_hash": "a" * 64,
                "target_resource_hash": "b" * 64,
                "destination_hash": "c" * 64,
            },
            "provider_event_schema_marker_required",
        ),
        (
            {
                "callback_schema": "hawk-native-hash-envelope/v1",
                "action_type": "FILE_READ",
                "tool_name": "Read",
                "tool_fingerprint_id": "f" * 64,
                "parameter_hash": "a" * 64,
                "target_resource_hash": "b" * 64,
                "destination_hash": "c" * 64,
                "unreviewed": "field",
            },
            "provider_event_schema_unknown_field",
        ),
    ],
)
def test_hash_only_endpoint_callback_schema_rejects_ambiguous_or_unbounded_input(
    raw_payload: dict[str, object], reason: str
) -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    with pytest.raises(ExactAdapterDispatchError, match=reason):
        _dispatch(registry, raw_payload=raw_payload)


def test_live_callback_dispatch_keeps_authenticated_model_identity_distinct_from_application_provider() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    dispatch = _dispatch(
        registry,
        model_provider="aws_bedrock",
        model="anthropic.claude-3-7-sonnet-v1",
    )

    assert dispatch.runtime_context.provider == "anthropic"
    assert dispatch.runtime_context.product == "claude_code"
    assert dispatch.runtime_context.model_provider == "aws_bedrock"
    assert dispatch.runtime_context.model == "anthropic.claude-3-7-sonnet-v1"


def test_exact_match_without_enforcement_eligibility_has_no_verified_route_binding() -> None:
    registry = NativeControlAdapterRegistry(environment="development")
    registry.register(ClaudeAdapter())

    dispatch = _dispatch(registry)

    assert dispatch.resolution.state is AdapterResolutionState.EXACT_MATCH
    assert dispatch.resolution.enforcement_eligible is False
    assert (
        dispatch.authorization_request.path_evidence["native_control_route_binding"]["verified"]
        is False
    )
    binding = dispatch.authorization_request.path_evidence["native_control_route_binding"]
    assert binding.get("runtime_context_verified") is not True
    assert "lifecycle_stage" not in binding


def test_dispatch_derives_acceptance_action_class_from_normalized_event_not_raw_tool_class() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    dispatch = _dispatch(
        registry,
        raw_payload={
            "tool_name": "Write",
            # Deliberately adversarial: this untrusted raw label must not
            # widen the reviewed acceptance scope before adapter normalization.
            "tool_class": "mcp",
            "parameters": {"file_path": "README.md"},
            "persistent_side_effect": True,
        },
    )

    assert dispatch.normalized_event.action["action_type"] == "FILE_WRITE"
    assert dispatch.normalized_event.action["action_class"] == "file_write"
    assert dispatch.runtime_context.action_class is ActionClass.FILE_WRITE
    assert dispatch.runtime_context.action_class is not ActionClass.MCP


def test_dispatch_rejects_control_method_not_supported_by_selected_adapter() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    with pytest.raises(ExactAdapterDispatchError, match="adapter_control_method_unsupported"):
        _dispatch(registry, integration_method="gateway_inline")


def test_dispatch_rejects_deployment_family_not_supported_by_selected_adapter() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    with pytest.raises(ExactAdapterDispatchError, match="adapter_deployment_family_unsupported"):
        _dispatch(registry, deployment_family="saas_api")


def test_dispatch_converts_adapter_schema_errors_to_safe_exact_dispatch_error() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(OpenAIDirectAPIControlAdapter())

    with pytest.raises(ExactAdapterDispatchError, match="provider_event_schema_too_large"):
        _dispatch(
            registry,
            provider="openai",
            product="direct_api",
            provider_version="1.0.0",
            adapter_version="1.0.0",
            integration_method="api_intercept",
            deployment_family="saas_api",
            runtime="customer_api",
            provider_event_type="before_model",
            raw_payload={"arguments": {"oversized": "x" * 66_000}},
        )


def test_live_callback_dispatch_rejects_an_unverified_newer_known_provider_version() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    with pytest.raises(ExactAdapterDispatchError, match="provider_version_unverified_newer"):
        _dispatch(registry, provider_version="2.1.184")


def test_live_callback_dispatch_rejects_ambiguous_provider_adapter_matches() -> None:
    first = ClaudeAdapter()
    second = ClaudeAdapter()
    second.descriptor = replace(second.descriptor, adapter_id="anthropic.claude-code.command-hooks-shadow")
    second.manifest = replace(  # type: ignore[assignment]
        second.manifest,
        descriptor_id=second.descriptor.adapter_id,
    )
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(first)
    registry.register(second)

    with pytest.raises(ExactAdapterDispatchError, match="adapter_ambiguous"):
        _dispatch(registry)


def test_live_callback_dispatch_rejects_a_broken_provider_adapter() -> None:
    adapter = ClaudeAdapter()
    adapter.manifest = replace(  # type: ignore[assignment]
        adapter.manifest,
        verification_status=adapter.manifest.verification_status.BROKEN,
    )
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(adapter)

    with pytest.raises(ExactAdapterDispatchError, match="provider_version_broken"):
        _dispatch(registry)


def test_unknown_provider_dispatch_is_explicitly_non_exact_for_observation_fallback() -> None:
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(ClaudeAdapter())

    dispatch = _dispatch(registry, provider="alibaba_qwen", product="self_hosted")

    assert dispatch.is_exact is False
    assert dispatch.adapter_id is None
    assert dispatch.resolution.state is AdapterResolutionState.UNKNOWN
