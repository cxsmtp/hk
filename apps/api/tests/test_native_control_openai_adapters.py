from __future__ import annotations

import hashlib

from app.core.control_engine.authorization import AuthorizationResponse
from app.services.native_control.adapter_contract import (
    AdapterMaturity,
    AdapterPipelineContext,
    AdapterError,
    AdapterErrorCode,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    RuntimeLocation,
    VerificationStatus,
)
from app.services.native_control.manifests import build_default_registry
from app.services.native_control.openai_adapters import (
    CodexNativeControlAdapter,
    OpenAIAgentsSDKControlAdapter,
    OpenAIDirectAPIControlAdapter,
)


def _response(decision: str) -> AuthorizationResponse:
    mode = {
        "allow": "inline_allowed",
        "warn": "warned",
        "block": "inline_prevented",
        "require_approval": "review_required",
        "require_second_approval": "review_required",
    }[decision]
    return AuthorizationResponse(
        decision=decision,
        control_mode=mode,
        reason=f"hawk_{decision}",
        policy_snapshot_id="policy-1",
        policy_profile_hash="p" * 64,
        response_hash="r" * 64,
    )


def test_openai_provider_family_has_three_separate_product_adapters() -> None:
    agents = OpenAIAgentsSDKControlAdapter()
    codex = CodexNativeControlAdapter()
    direct = OpenAIDirectAPIControlAdapter()

    assert {row.descriptor.adapter_id for row in (agents, codex, direct)} == {
        "openai.agents-sdk.control",
        "openai.codex.native-hooks",
        "openai.direct-api.control",
    }
    assert {row.descriptor.product_family for row in (agents, codex, direct)} == {
        "agents_sdk",
        "codex",
        "direct_api",
    }
    assert agents.descriptor.enforcement_methods_supported == (
        ControlMethod.SDK_MIDDLEWARE,
        ControlMethod.AGENT_MIDDLEWARE,
    )
    assert codex.descriptor.enforcement_methods_supported == (ControlMethod.NATIVE_HOOK,)
    assert direct.descriptor.enforcement_methods_supported == (
        ControlMethod.GATEWAY_INLINE,
        ControlMethod.API_INTERCEPT,
        ControlMethod.TOOL_LOOP_INTERCEPT,
    )
    assert not any("universal" in row.descriptor.adapter_id for row in (agents, codex, direct))


def test_agents_remains_experimental_while_hash_bound_codex_is_production() -> None:
    agents = OpenAIAgentsSDKControlAdapter()
    codex = CodexNativeControlAdapter()

    assert agents.descriptor.maturity is AdapterMaturity.EXPERIMENTAL
    assert agents.manifest.verification_status is VerificationStatus.EXPERIMENTAL
    assert codex.descriptor.maturity is AdapterMaturity.PRODUCTION
    assert codex.manifest.verification_status is VerificationStatus.VERIFIED


def test_codex_promotes_only_the_events_and_capabilities_in_the_acceptance_artifact() -> None:
    codex = CodexNativeControlAdapter()

    assert codex.descriptor.event_schema_version == "codex-hooks/0.154.0"
    assert codex.manifest.provider_version_min == "0.154.0"
    assert codex.manifest.provider_version_max == "0.154.0"
    assert codex.manifest.exact_verified_versions == ("0.154.0",)
    assert set(codex.manifest.supported_lifecycle_events) == {
        "session_start",
        "before_model",
    }
    verified = {
        dimension
        for dimension, claim in codex.manifest.capabilities.items()
        if claim.verification_status is VerificationStatus.VERIFIED
    }
    assert verified == {
        CapabilityDimension.DISCOVERY,
        CapabilityDimension.IDENTITY,
        CapabilityDimension.PROMPT_CONTROL,
    }
    assert codex.manifest.supported_action_classes == (ActionClass.MODEL_REQUEST,)
    assert codex.manifest.supported_runtime_locations == (RuntimeLocation.LOCAL_ENDPOINT,)
    assert codex.manifest.is_reviewed_contract is True
    assert "Hosted tools do not traverse" in codex.manifest.known_blind_spots[0].impact


def test_codex_0154_detection_requires_the_registered_binary_hash(monkeypatch, tmp_path) -> None:
    import app.services.native_control.openai_adapters as adapters

    binary = tmp_path / "codex"
    binary.write_bytes(b"accepted-codex-binary")
    binary.chmod(0o700)
    monkeypatch.setattr(adapters.shutil, "which", lambda _command: str(binary))

    class VersionResult:
        returncode = 0
        stdout = "codex-cli 0.154.0\n"

    monkeypatch.setattr(adapters.subprocess, "run", lambda *_args, **_kwargs: VersionResult())
    codex = CodexNativeControlAdapter()

    assert codex.detect_environment()["version"] == "0.154.0"
    assert codex.detect_environment()["exact_version_accepted"] is False
    assert codex.validation_probe()["installation"] is False

    class Accepted:
        provider_version = "0.154.0"
        binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    monkeypatch.setattr(adapters, "_CODEX_ACCEPTANCE", Accepted())
    assert codex.detect_environment()["exact_version_accepted"] is True
    assert codex.validation_probe()["installation"] is True
    assert codex.manifest.exact_verified_versions == ("0.154.0",)


def test_codex_normalizes_interrupt_as_evidence_only_session_context() -> None:
    codex = CodexNativeControlAdapter()
    event = codex.normalize_event(
        {"hook_event_name": "Interrupt"},
        AdapterPipelineContext.reference(
            tenant_id="tenant-1",
            integration_instance_id="codex-1",
            provider_event_id="interrupt-1",
        ),
    )

    assert event.lifecycle_stage == "session_interrupt"
    assert event.timing["pre_execution"] is False


def test_codex_callback_router_can_parse_unverified_events_without_promoting_them() -> None:
    import ast
    from pathlib import Path

    router_path = Path(__file__).resolve().parents[1] / "app/api/routers/native_controls.py"
    tree = ast.parse(router_path.read_text(encoding="utf-8"))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_NATIVE_CALLBACK_EVENTS"
            for target in node.targets
        )
    )
    callback_events = ast.literal_eval(assignment.value)

    assert "post_compact" in callback_events
    assert "interrupt" in callback_events
    assert set(CodexNativeControlAdapter().manifest.supported_lifecycle_events) == {
        "session_start",
        "before_model",
    }


def test_agents_sdk_promotes_only_exact_function_tool_capabilities() -> None:
    adapter = OpenAIAgentsSDKControlAdapter()
    function = adapter.action_profile("function_tool")
    hosted = adapter.action_profile("hosted_web_search")

    assert adapter.manifest.exact_verified_versions == ("0.20.0",)
    assert function.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert function.capabilities[CapabilityDimension.HITL_APPROVAL].verification_status is VerificationStatus.EXPERIMENTAL
    assert hosted.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL].level is CapabilityLevel.UNAVAILABLE
    assert hosted.claim(CapabilityDimension.TOOL_CONTROL).verification_status is not VerificationStatus.VERIFIED


def test_agents_function_tool_normalization_binds_exact_action_without_raw_secret_export() -> None:
    adapter = OpenAIAgentsSDKControlAdapter()
    context = AdapterPipelineContext.reference(
        tenant_id="tenant-1",
        integration_instance_id="openai-agents-1",
        provider_event_id="tool-call-1",
    )
    event = adapter.normalize_event(
        {
            "event_type": "function_tool_input",
            "tool_class": "function_tool",
            "tool_name": "delete_customer_record",
            "tool_call_id": "call-1",
            "arguments": {"customer_id": "customer-7", "api_key": "must-not-persist"},
            "target": "customer-7",
            "destination": "crm.internal",
            "agent_id": "billing-agent",
            "business_purpose": "approved account closure",
            "persistent_side_effect": True,
        },
        context,
    )

    assert event.product == "agents_sdk"
    assert event.lifecycle_stage == "before_tool"
    assert event.action["action_class"] == "function_tool"
    assert event.action["parameter_hash"] != "unknown"
    assert event.target["resource"] == "customer-7"
    assert event.destination["destination"] == "crm.internal"
    assert "must-not-persist" not in repr(event)


def test_agents_decision_mapping_never_approximates_approval_as_allow() -> None:
    adapter = OpenAIAgentsSDKControlAdapter()

    assert adapter.format_decision_response(_response("allow"))["behavior"] == "allow"
    assert adapter.format_decision_response(_response("block"))["behavior"] == "raise_exception"
    with pytest.raises(AdapterError) as error:
        adapter.format_decision_response(_response("require_approval"))
    assert error.value.code is AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE


def test_direct_api_is_never_described_as_native_hook() -> None:
    adapter = OpenAIDirectAPIControlAdapter()

    assert ControlMethod.NATIVE_HOOK not in adapter.descriptor.enforcement_methods_supported
    assert "native hook" not in adapter.descriptor.description.lower()


def test_default_registry_exposes_three_product_specific_openai_manifests() -> None:
    registry = build_default_registry()
    agents = registry.get("openai", "agents_sdk", ControlMethod.SDK_MIDDLEWARE)
    codex = registry.get("openai", "codex", ControlMethod.NATIVE_HOOK)
    direct = registry.get("openai", "direct_api", ControlMethod.GATEWAY_INLINE)

    assert agents.verification_status is VerificationStatus.EXPERIMENTAL
    assert codex.verification_status is VerificationStatus.VERIFIED
    assert codex.supported_versions == ("0.154.0",)
    assert direct.verification_status is VerificationStatus.VERIFIED
    assert direct.supported_versions == ("hawk-openai-compatible-v1",)
    assert agents.capability_matrix[CapabilityDimension.TOOL_CONTROL].level in {
        CapabilityLevel.UNKNOWN,
        CapabilityLevel.UNAVAILABLE,
    }
    assert codex.capability_matrix[CapabilityDimension.PROMPT_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert codex.capability_matrix[CapabilityDimension.CODEX_COMMAND_CONTROL].verification_status is not VerificationStatus.VERIFIED
    assert direct.capability_matrix[CapabilityDimension.DIRECT_API_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert all("universal" not in row.manifest_id for row in registry.for_provider("openai"))


import pytest
