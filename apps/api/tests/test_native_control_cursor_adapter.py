from __future__ import annotations

from dataclasses import replace

from app.core.control_engine.authorization import authorize_ai_action
from app.services.native_control.adapter_contract import (
    AdapterMaturity,
    AdapterPipelineContext,
)
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    HealthState,
    VerificationStatus,
)
from app.services.native_control.cursor_adapter import CursorAdapter
from app.services.native_control.adapters import HawkCursorControlAdapter, ProviderEventContext


def _context(*, decision: str = "allow") -> AdapterPipelineContext:
    base = AdapterPipelineContext.reference(
        tenant_id="tenant-bank",
        integration_instance_id="cursor-hook-1",
        provider_event_id="cursor-event-1",
        policy_profile={"base_decision": decision, "dependencies_healthy": True},
    )
    return replace(
        base,
        provider_version="9.9.9",
        correlation_id="cursor-event-1",
        session_id="cursor-session",
        chain_id="cursor-session",
    )


def test_cursor_adapter_promotes_only_exact_release_capabilities_with_reviewed_evidence() -> None:
    adapter = CursorAdapter()

    assert adapter.descriptor.provider_family == "cursor"
    assert adapter.descriptor.product_family == "cursor"
    assert adapter.descriptor.maturity is AdapterMaturity.EXPERIMENTAL
    assert adapter.manifest.verification_status is VerificationStatus.EXPERIMENTAL
    assert adapter.manifest.exact_verified_versions == ("2026.08.11-e8db854",)
    assert adapter.version_assurance("2026.08.11-e8db854") == "exact_verified"
    assert adapter.version_assurance("9.9.9") == "unsupported"
    assert adapter.validate_environment(
        {"available": True, "provider_version": "2026.08.11-e8db854"}
    ) is True
    assert adapter.validate_environment({"available": True, "provider_version": "9.9.9"}) is False
    assert adapter.health().state is HealthState.UNVERIFIED
    verified = {
        CapabilityDimension.PROMPT_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.COMMAND_CONTROL,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.DESTINATION_BINDING,
        CapabilityDimension.POST_EXECUTION_VISIBILITY,
        CapabilityDimension.EXECUTION_CORRELATION,
        CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL,
        CapabilityDimension.PERSISTENT_SIDE_EFFECT_VISIBILITY,
        CapabilityDimension.BYPASS_DETECTION,
        CapabilityDimension.CONFIG_INTEGRITY,
    }
    assert all(
        adapter.manifest.capabilities[dimension].verification_status
        is VerificationStatus.VERIFIED
        for dimension in verified
    )
    assert adapter.manifest.capabilities[CapabilityDimension.DELEGATION_CONTROL].verification_status is VerificationStatus.EXPERIMENTAL
    assert adapter.manifest.capabilities[CapabilityDimension.FILE_WRITE_CONTROL].verification_status is VerificationStatus.EXPERIMENTAL
    assert adapter.manifest.capabilities[CapabilityDimension.POST_EXECUTION_VERIFICATION].level is CapabilityLevel.UNAVAILABLE

    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(adapter)
    assert registry.eligible_adapters() == ()
    assert registry.eligible_adapters(include_experimental=True) == (adapter,)


def test_cursor_adapter_exposes_documented_lifecycle_without_claiming_verified_execution() -> None:
    adapter = CursorAdapter()
    semantics = adapter.lifecycle_semantics()

    assert semantics["beforeShellExecution"] == "pre_execution_authorization"
    assert semantics["beforeMCPExecution"] == "pre_execution_authorization"
    assert semantics["beforeReadFile"] == "pre_execution_authorization"
    assert semantics["beforeSubmitPrompt"] == "prompt_context_and_control"
    assert semantics["subagentStart"] == "delegation_authorization"
    assert semantics["afterAgentThought"] == "metadata_only_never_thought_content"
    assert semantics["workspaceOpen"] == "workspace_context"
    assert adapter.manifest.capabilities[CapabilityDimension.POST_EXECUTION_VERIFICATION].level is CapabilityLevel.UNAVAILABLE


def test_cursor_adapter_normalizes_one_canonical_action_with_secondary_surface_observations() -> None:
    adapter = CursorAdapter()
    event = adapter.normalize_event(
        {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "github_create_pull_request",
            "tool_input": {"owner": "hawk", "repo": "private", "title": "private"},
            "conversation_id": "provider-private",
            "generation_id": "generation-private",
            "workspace_roots": ["/private/repo"],
            "user_email": "private@example.com",
            "cursor_version": "9.9.9",
            "model": "claude-opus-test",
            "endpoint_observation_id": "endpoint-observation-1",
            "mcp_observation_id": "mcp-observation-1",
        },
        _context(decision="block"),
    )

    assert event.provider == "cursor"
    assert event.product == "cursor"
    assert event.lifecycle_stage == "before_tool"
    assert event.action["action_type"] == "MCP_TOOL_CALL"
    assert event.mcp["tool_name"] == "github_create_pull_request"
    assert event.runtime["primary_control_point"] == "cursor_native_hook"
    assert [row["source"] for row in event.runtime["secondary_observations"]] == ["endpoint", "mcp"]
    assert all(row["verified"] is False for row in event.runtime["secondary_observations"])
    assert all(len(row["observation_id_hash"]) == 64 for row in event.runtime["secondary_observations"])
    exported = str(event)
    assert "private@example.com" not in exported
    assert "/private/repo" not in exported
    assert '"title": "private"' not in exported
    assert "endpoint-observation-1" not in exported
    assert "mcp-observation-1" not in exported

    response = authorize_ai_action(event.to_authorization_request())
    output = adapter.format_decision_response(response)
    assert output["continue"] is False
    assert output["permission"] == "deny"


def test_cursor_install_preserves_customer_hooks_and_uses_enterprise_priority_truth() -> None:
    adapter = CursorAdapter(helper_path="/Library/Hawk/bin/hawk-native-hook")
    customer = {"command": "/opt/customer/audit", "timeout": 30}
    existing = {"version": 1, "theme": "dark", "hooks": {"beforeShellExecution": [customer]}}

    first = adapter.install(adapter.install_plan(existing), existing)
    second = adapter.install(adapter.install_plan(first.configuration), first.configuration)

    assert first.configuration["theme"] == "dark"
    assert first.configuration["hooks"]["beforeShellExecution"][1] == customer
    assert first.configuration["hooks"]["beforeShellExecution"][0]["failClosed"] is True
    assert first.configuration["hooks"]["preToolUse"][0]["matcher"] == "^(?!Shell$|Read$|Task$|MCP:).*"
    assert first.fingerprint.hawk_owned_content_hash == second.fingerprint.hawk_owned_content_hash
    assert first.fingerprint.ordering == "enterprise_source_has_highest_merge_priority"
    assert adapter.detect_drift(first.configuration) == ()
    assert adapter.uninstall(first.configuration) == existing


def test_cursor_endpoint_callback_fields_cross_the_generic_api_boundary_without_raw_material() -> None:
    request = HawkCursorControlAdapter(product="cursor").normalize_event(
        context=ProviderEventContext.minimum_for_test(),
        event={
            "provider_event_type": "before_mcp",
            "action_type": "MCP_TOOL_CALL",
            "tool_name": "github_create_pull_request",
            "tool_fingerprint_id": "f" * 64,
            "parameter_hash": "a" * 64,
            "target_resource": "mcp",
            "target_resource_hash": "b" * 64,
            "destination": "mcp",
            "destination_hash": "c" * 64,
            "persistent_side_effect": True,
            "side_effect_class": "persistent",
            "prompt_hash": "d" * 64,
            "response_hash": "unknown",
            "data_classifications": [],
            "mcp_server_id": "unknown",
            "mcp_tool_name": "github_create_pull_request",
            "provider_session_hash": "e" * 64,
            "provider_tool_use_hash": "9" * 64,
            "provider_generation_hash": "8" * 64,
            "provider_account_hash": "7" * 64,
            "provider_app_version": "9.9.9",
            "workspace_hash": "6" * 64,
            "branch_hash": "5" * 64,
            "subagent_id_hash": "4" * 64,
            "parent_session_hash": "3" * 64,
            "subagent_type": "unknown",
            "is_parallel_worker": False,
            "execution_location": "local",
            "delegation_depth": 2,
            "permission_mode": "unknown",
            "agent_id_hash": "2" * 64,
            "agent_type": "unknown",
            "run_in_background": False,
            "execution_status": "pending",
            "evidence_quality": "none",
            "failure_hash": "unknown",
        },
    )

    assert request.runtime["provider_app_version"] == "9.9.9"
    assert request.runtime["execution_location"] == "local"
    assert request.runtime["delegation_depth"] == 2
    assert request.path_evidence["inline_pre_execution"] is True
    assert request.action["action_type"] == "MCP_TOOL_CALL"


def test_cursor_specific_signed_callback_lifecycles_are_server_allowlisted() -> None:
    from app.api.routers.native_controls import (
        _NATIVE_CALLBACK_EVENTS,
        _NATIVE_POST_ACTION_EVENTS,
        _NATIVE_PRE_ACTION_EVENTS,
    )

    assert {
        "before_shell",
        "before_mcp",
        "before_file_read",
        "subagent_start",
    } <= _NATIVE_PRE_ACTION_EVENTS
    assert {"after_shell", "after_mcp", "after_file_edit"} <= _NATIVE_POST_ACTION_EVENTS
    assert {
        "subagent_stop",
        "pre_compact",
        "stop",
        "after_agent_response",
        "after_agent_thought",
        "workspace_open",
    } <= _NATIVE_CALLBACK_EVENTS
