from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

from app.core.control_engine.authorization import authorize_ai_action
from app.services.native_control.adapter_contract import (
    AdapterMaturity,
    AdapterPipelineContext,
    EvidenceQuality,
)
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.claude_adapter import ClaudeAdapter
from app.services.native_control.claude_acceptance_registry import (
    load_claude_acceptance_registry,
)
from app.services.native_control.conformance import NativeControlAdapterConformanceSuite
from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    VerificationStatus,
)


def _context(*, decision: str = "allow") -> AdapterPipelineContext:
    base = AdapterPipelineContext.reference(
        tenant_id="tenant-bank",
        integration_instance_id="claude-hook-1",
        provider_event_id="toolu_01Hawk",
        policy_profile={"base_decision": decision, "dependencies_healthy": True},
    )
    return replace(
        base,
        provider_version="2.1.183",
        correlation_id="toolu_01Hawk",
        session_id="session-claude",
        chain_id="session-claude",
    )


def _pre_event(command: str = "git status") -> dict[str, object]:
    return {
        "session_id": "provider-session-must-not-be-authority",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "toolu_01Hawk",
    }


def _with_verified_discovery_asset(request):
    """Mirror the trusted router enrichment; callback payloads cannot supply these facts."""

    return request.model_copy(
        deep=True,
        update={
            "discovery_context": {
                **dict(request.discovery_context),
                "asset_status": "verified",
            },
            "target": {
                **dict(request.target),
                "resource_hash": "a" * 64,
                "destination": "internal",
                "destination_hash": "b" * 64,
            },
            "tool": {
                **dict(request.tool),
                "fingerprint_id": "c" * 64,
            },
        },
    )


def test_claude_adapter_promotes_only_the_exact_real_binary_version() -> None:
    adapter = ClaudeAdapter()

    assert adapter.descriptor.provider_family == "anthropic"
    assert adapter.descriptor.product_family == "claude_code"
    assert adapter.descriptor.maturity is AdapterMaturity.PRODUCTION
    assert adapter.manifest.verification_status is VerificationStatus.VERIFIED
    assert adapter.manifest.exact_verified_versions == ("2.1.183",)
    assert adapter.supported_versions() == ("2.1.183", "2.1.183")
    assert adapter.version_assurance("2.1.183") == "exact_verified"
    assert adapter.version_assurance("2.1.184") == "unsupported"
    assert adapter.version_assurance("future") == "unsupported"
    assert adapter.validate_environment({"available": True, "provider_version": "2.1.184"}) is False
    assert adapter.validate_environment({"available": True, "provider_version": "future"}) is False

    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(adapter)
    assert registry.eligible_adapters() == (adapter,)


def test_claude_exact_version_registry_requires_reviewed_adapter_bound_evidence() -> None:
    registry = load_claude_acceptance_registry()

    assert registry.accepted_versions(adapter_version="1.2.0") == ("2.1.183",)
    assert registry.assurance("2.1.183", adapter_version="1.2.0") == "exact_verified"
    assert registry.assurance("2.1.183", adapter_version="1.1.0") == "unsupported"
    assert registry.assurance("2.1.184", adapter_version="1.2.0") == "unsupported"
    entry = registry.entry("2.1.183", adapter_version="1.2.0")
    assert entry is not None
    assert entry.reviewed is True
    assert len(entry.report_sha256) == 64
    assert {"PreToolUse", "PermissionRequest", "UserPromptSubmit", "SubagentStart", "SubagentStop"} <= set(entry.tested_events)
    assert {"tool_control", "mcp_control", "prompt_control", "delegation_control"} <= set(entry.accepted_capabilities)


def test_claude_capability_profile_is_partial_and_does_not_overclaim_binding_or_execution_proof() -> None:
    capabilities = ClaudeAdapter.manifest.capabilities

    assert capabilities[CapabilityDimension.TOOL_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert capabilities[CapabilityDimension.COMMAND_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert capabilities[CapabilityDimension.FILE_WRITE_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert capabilities[CapabilityDimension.PROMPT_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert capabilities[CapabilityDimension.MCP_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert capabilities[CapabilityDimension.MCP_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert capabilities[CapabilityDimension.DELEGATION_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert capabilities[CapabilityDimension.DELEGATION_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert capabilities[CapabilityDimension.PARAMETER_BINDING].level is CapabilityLevel.INLINE_BOUND
    assert capabilities[CapabilityDimension.TARGET_BINDING].level is CapabilityLevel.OBSERVE
    assert capabilities[CapabilityDimension.POST_EXECUTION_VISIBILITY].level is CapabilityLevel.OBSERVE
    assert capabilities[CapabilityDimension.POST_EXECUTION_VERIFICATION].level is CapabilityLevel.UNAVAILABLE
    assert capabilities[CapabilityDimension.PROVIDER_PERMISSION_CONTEXT].level is CapabilityLevel.OBSERVE
    assert capabilities[CapabilityDimension.PROVIDER_PERMISSION_CONTEXT].verification_status is VerificationStatus.VERIFIED
    assert capabilities[CapabilityDimension.HAWK_APPROVAL_BINDING].level is CapabilityLevel.EXTERNAL
    assert capabilities[CapabilityDimension.APPROVAL_CORRELATION].verification_status is VerificationStatus.VERIFIED
    assert capabilities[CapabilityDimension.TOOL_FAILURE_VISIBILITY].verification_status is VerificationStatus.VERIFIED
    assert capabilities[CapabilityDimension.EXECUTION_CORRELATION].verification_status is VerificationStatus.VERIFIED
    assert capabilities[CapabilityDimension.CONFIG_CHANGE_VISIBILITY].verification_status is VerificationStatus.EXPERIMENTAL
    blind_spot_ids = {row.id for row in ClaudeAdapter.manifest.known_blind_spots}
    assert "anthropic.claude-code.version-mismatch" in blind_spot_ids
    assert "anthropic.claude-code.provider-permission-not-authorization" in blind_spot_ids


def test_claude_lifecycle_classification_separates_enforcement_approval_evidence_and_context() -> None:
    adapter = ClaudeAdapter()

    assert adapter.supported_tool_events() == (
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PostToolUseFailure",
    )
    assert adapter.lifecycle_semantics() == {
        "PreToolUse": "pre_execution_authorization",
        "PermissionRequest": "approval_context",
        "PostToolUse": "provider_reported_execution",
        "PostToolUseFailure": "provider_reported_failure",
        "UserPromptSubmit": "prompt_context_and_control",
        "SessionStart": "session_context",
        "SessionEnd": "session_context",
        "ConfigChange": "configuration_integrity_signal",
        "SubagentStart": "provider_reported_delegation_context",
        "SubagentStop": "provider_reported_delegation_context",
    }


def test_claude_subagent_context_callbacks_are_server_allowlisted_as_observation() -> None:
    from app.api.routers.native_controls import (
        _NATIVE_CALLBACK_EVENTS,
        _NATIVE_POST_ACTION_EVENTS,
        _NATIVE_PRE_ACTION_EVENTS,
    )

    context_events = {"subagent_context_start", "subagent_context_stop"}
    assert context_events <= _NATIVE_CALLBACK_EVENTS
    assert context_events.isdisjoint(_NATIVE_PRE_ACTION_EVENTS)
    assert context_events.isdisjoint(_NATIVE_POST_ACTION_EVENTS)


def test_claude_adapter_normalizes_real_pre_tool_use_without_trusting_provider_identity() -> None:
    adapter = ClaudeAdapter()
    event = adapter.normalize_event(_pre_event("git push origin main"), _context())

    assert event.tenant_id == "tenant-bank"
    assert event.integration_instance_id == "claude-hook-1"
    assert event.raw_provider_event_type == "PreToolUse"
    assert event.lifecycle_stage == "before_tool"
    assert event.tool["name"] == "Bash"
    assert event.action["canonical_parameters"] == {"command": "git push origin main"}
    assert len(event.action["parameter_hash"]) == 64
    assert event.provider_correlation["tool_use_id"] == "toolu_01Hawk"
    assert event.provider_correlation["correlation_id"] == "toolu_01Hawk"
    assert event.actor["identity_id"] == "reference-user"
    assert "provider-session-must-not-be-authority" not in str(event.actor)


def test_claude_normalizes_known_tool_families_unknown_tools_mcp_and_subagent_context() -> None:
    adapter = ClaudeAdapter()
    context = _context()
    bash = adapter.normalize_event(
        {
            **_pre_event("git status"),
            "cwd": "/tmp/hawk-workspace",
            "permission_mode": "default",
            "agent_id": "agent-123",
            "agent_type": "Explore",
            "tool_input": {
                "command": "git status",
                "description": "read repository state",
                "timeout": 30,
                "run_in_background": False,
            },
        },
        context,
    )
    file_write = adapter.normalize_event(
        {**_pre_event(), "tool_name": "Write", "tool_input": {"file_path": "/tmp/demo.txt", "content": "demo"}},
        context,
    )
    mcp = adapter.normalize_event(
        {**_pre_event(), "tool_name": "mcp__github__create_pull_request", "tool_input": {"owner": "hawk", "repo": "demo"}},
        context,
    )
    unknown = adapter.normalize_event(
        {**_pre_event(), "tool_name": "VendorMagic", "tool_input": {"opaque": True}},
        context,
    )
    subagent = adapter.normalize_event(
        {
            "hook_event_name": "SubagentStart",
            "session_id": "private-parent",
            "agent_id": "private-child",
            "agent_type": "Explore",
            "prompt": "raw delegated task",
        },
        context,
    )

    assert bash.action["action_type"] == "COMMAND_EXECUTION"
    assert bash.target["canonical_target"] == "/tmp/hawk-workspace"
    assert bash.session["permission_mode"] == "default"
    assert bash.provider_correlation["agent_id"] == "agent-123"
    assert bash.provider_correlation["agent_type"] == "Explore"
    assert file_write.action["action_type"] == "FILE_WRITE"
    assert file_write.target["canonical_target"] == "/tmp/demo.txt"
    assert mcp.action["action_type"] == "MCP_TOOL_CALL"
    assert mcp.mcp == {"server_id": "github", "tool_name": "create_pull_request"}
    assert unknown.action["action_type"] == "UNKNOWN_TOOL_ACTION"
    assert unknown.tool["name"] == "VendorMagic"
    assert subagent.lifecycle_stage == "subagent_context_start"
    assert subagent.action["action_type"] == "SESSION_CONTEXT"
    assert subagent.timing["pre_execution"] is False
    assert len(subagent.provider_correlation["agent_id_hash"]) == 64
    assert "private-child" not in str(subagent)
    assert "raw delegated task" not in str(subagent)


def test_claude_decision_translation_is_native_and_never_weakens_block() -> None:
    adapter = ClaudeAdapter()
    event = adapter.normalize_event(_pre_event(), _context(decision="block"))
    response = authorize_ai_action(event.to_authorization_request())

    assert response.decision == "block"
    assert adapter.format_decision_response(response) == {
        "decision": "block",
        "continue": False,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": response.reason,
        },
    }


def test_claude_decision_translation_fails_closed_for_unknown_assets_and_never_weakens_restrictive_policy() -> None:
    adapter = ClaudeAdapter()

    unknown_request = adapter.normalize_event(_pre_event(), _context(decision="allow")).to_authorization_request()
    unknown_response = authorize_ai_action(unknown_request)
    assert unknown_response.decision == "block"
    assert adapter.format_decision_response(unknown_response)["hookSpecificOutput"]["permissionDecision"] == "deny"

    outputs = {}
    for decision in ("allow", "warn", "require_approval", "require_second_approval", "redact"):
        event = adapter.normalize_event(_pre_event(), _context(decision=decision))
        response = authorize_ai_action(_with_verified_discovery_asset(event.to_authorization_request()))
        outputs[decision] = adapter.format_decision_response(response)

    assert outputs["allow"]["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert outputs["warn"]["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert outputs["require_approval"]["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert outputs["require_second_approval"]["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert outputs["redact"]["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert all(
        "updatedInput" not in output["hookSpecificOutput"]
        for output in outputs.values()
    )
    assert adapter.supports_input_mutation() is False


def test_claude_post_tool_use_correlates_result_without_claiming_external_verification() -> None:
    adapter = ClaudeAdapter()
    result = adapter.capture_execution_result(
        {
            "hook_event_name": "PostToolUse",
            "tool_use_id": "toolu_01Hawk",
            "tool_input": {"command": "git status"},
            "tool_response": {"stdout": "clean", "stderr": "", "interrupted": False},
        }
    )

    assert result["quality"] == EvidenceQuality.PROVIDER_REPORTED.value
    assert result["tool_use_id"] == "toolu_01Hawk"
    assert len(result["parameter_hash"]) == 64
    assert len(result["result_hash"]) == 64
    assert "clean" not in str(result)


def test_claude_install_is_idempotent_detects_tamper_and_uninstalls_only_hawk() -> None:
    adapter = ClaudeAdapter(helper_path="/Library/Hawk/bin/hawk-native-hook")
    customer_hook = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "/opt/customer/hook", "timeout": 30}],
    }
    existing = {"theme": "dark", "hooks": {"PreToolUse": [customer_hook]}}
    plan = adapter.install_plan(existing)

    first = adapter.install(plan, existing)
    second = adapter.install(plan, first.configuration)
    installed = first.configuration

    assert installed["theme"] == "dark"
    assert installed["hooks"]["PreToolUse"][0]["hooks"][0]["command"].startswith(
        "/Library/Hawk/bin/hawk-native-hook --hawk-managed-hook"
    )
    assert installed["hooks"]["PreToolUse"][1] == customer_hook
    assert first.fingerprint.hawk_owned_content_hash == second.fingerprint.hawk_owned_content_hash
    assert adapter.validate_installation(installed) is True
    assert adapter.detect_drift(installed) == ()

    tampered = deepcopy(installed)
    tampered["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 5000
    assert adapter.validate_installation(tampered) is False
    assert "hawk_hook_changed:PreToolUse" in adapter.detect_drift(tampered)
    assert adapter.uninstall(installed) == existing


def test_claude_timeout_and_conformance_are_bounded_without_false_ordering_claim() -> None:
    adapter = ClaudeAdapter(acceptance_probes={name: True for name in ClaudeAdapter.REQUIRED_PROBES})

    assert adapter.timeout_budget().response_deadline_ms == 5_000
    assert adapter.timeout_budget().remaining_network_budget_ms == 500
    assert adapter.manifest.event_semantics.ordering_guaranteed is False
    assert adapter.manifest.event_semantics.runs_before_untrusted_mutators is False
    result = NativeControlAdapterConformanceSuite().run(adapter)
    assert result.passed is True, result.failures
