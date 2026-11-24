from __future__ import annotations

from dataclasses import replace
import hashlib
import json

from app.core.control_engine.authorization import authorize_ai_action
from app.services.native_control.adapter_contract import (
    AdapterMaturity,
    AdapterPipelineContext,
    EvidenceQuality,
)
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.conformance import NativeControlAdapterConformanceSuite
from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    VerificationStatus,
)
from app.services.native_control.gemini_acceptance_registry import (
    load_gemini_acceptance_registry,
)
from app.services.native_control.gemini_cli_adapter import GeminiCliAdapter
from app.services.native_control.findings import FINDING_PROFILES


def _context(*, decision: str = "allow") -> AdapterPipelineContext:
    base = AdapterPipelineContext.reference(
        tenant_id="tenant-bank",
        integration_instance_id="gemini-hook-1",
        provider_event_id="gemini-event-1",
        policy_profile={"base_decision": decision, "dependencies_healthy": True},
    )
    return replace(
        base,
        provider_version="0.54.4",
        correlation_id="gemini-tool-1",
        session_id="gemini-session-1",
        chain_id="gemini-session-1",
    )


def _before_tool(tool_name: str = "run_shell_command") -> dict[str, object]:
    return {
        "hook_event_name": "BeforeTool",
        "session_id": "provider-session-is-not-authority",
        "tool_name": tool_name,
        "tool_input": {"command": "git status"},
        "original_request_name": "tail_origin",
    }


def _with_verified_discovery_asset(request):
    """Mirror trusted router enrichment; provider callback data cannot approve an asset."""

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


def test_gemini_adapter_is_exact_version_and_reviewed_evidence_bound() -> None:
    adapter = GeminiCliAdapter()

    assert adapter.descriptor.provider_family == "google"
    assert adapter.descriptor.product_family == "gemini_cli"
    assert adapter.descriptor.maturity is AdapterMaturity.EXPERIMENTAL
    assert adapter.manifest.verification_status is VerificationStatus.EXPERIMENTAL
    assert adapter.manifest.exact_verified_versions == ("0.54.4", "0.55.1")
    assert adapter.supported_versions() == ("0.54.4", "0.55.1")
    assert adapter.version_assurance("0.54.4") == "exact_verified"
    assert adapter.version_assurance("0.55.1") == "exact_verified"
    assert adapter.version_assurance("0.55.2") == "unsupported"
    assert adapter.validate_environment({"available": True, "provider_version": "0.55.2"}) is False

    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(adapter)
    assert registry.eligible_adapters() == ()


def test_gemini_file_read_is_verified_observation_not_an_inline_file_gate() -> None:
    claim = GeminiCliAdapter.manifest.capabilities[CapabilityDimension.FILE_READ_CONTROL]

    assert claim.level is CapabilityLevel.OBSERVE
    assert claim.verification_status is VerificationStatus.VERIFIED


def test_gemini_acceptance_registry_rejects_unreviewed_wrong_hash_and_wrong_adapter(tmp_path) -> None:
    artifact = tmp_path / "docs/evidence/report.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        json.dumps({
            "provider": "google",
            "product": "gemini_cli",
            "provider_version": "0.54.4",
            "adapter_version": "1.0.0",
            "maturity": "experimental",
            "passed": False,
            "tested_events": ["BeforeTool", "AfterTool"],
            "accepted_capabilities": ["tool_control"],
        }) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    registry_path = tmp_path / "docs/evidence/gemini-cli-acceptance-registry.json"

    def write(*, reviewed: bool = True, report_sha256: str = digest, adapter_version: str = "1.0.0") -> None:
        registry_path.write_text(
            json.dumps(
                {
                    "schema_version": "gemini-cli-acceptance-registry/1.0",
                    "entries": [
                        {
                            "provider": "google",
                            "product": "gemini_cli",
                            "provider_version": "0.54.4",
                            "adapter_version": adapter_version,
                            "report_sha256": report_sha256,
                            "evidence_artifact": "docs/evidence/report.json",
                            "evidence_timestamp": "2026-08-12T00:00:00+00:00",
                            "tested_events": ["BeforeTool", "AfterTool"],
                            "accepted_capabilities": ["tool_control"],
                            "measured_callback_p95_ms": 5.0,
                            "reviewed": reviewed,
                            "review_status": "reviewed_by_acceptance_gate",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    write(reviewed=False)
    assert load_gemini_acceptance_registry(registry_path).entries == ()
    write(report_sha256="0" * 64)
    assert load_gemini_acceptance_registry(registry_path).entries == ()
    write(adapter_version="9.9.9")
    registry = load_gemini_acceptance_registry(registry_path)
    assert registry.accepted_versions(adapter_version="1.0.0") == ()
    assert registry.accepted_versions(adapter_version="9.9.9") == ()


def test_gemini_lifecycle_semantics_are_capability_specific() -> None:
    adapter = GeminiCliAdapter()

    assert adapter.supported_tool_events() == ("BeforeTool", "AfterTool")
    assert adapter.lifecycle_semantics() == {
        "SessionStart": "advisory_session_context",
        "SessionEnd": "best_effort_session_evidence",
        "BeforeAgent": "pre_agent_turn_control",
        "AfterAgent": "provider_reported_agent_response",
        "BeforeModel": "pre_model_request_control",
        "AfterModel": "streaming_response_boundary",
        "BeforeToolSelection": "tool_filtering_only",
        "BeforeTool": "pre_execution_authorization",
        "AfterTool": "provider_reported_execution",
        "PreCompress": "advisory_compression_context",
        "Notification": "provider_notification_observation",
    }
    assert adapter.supports_input_mutation() is False


def test_gemini_enterprise_admin_controls_require_tenant_bound_verified_receipt() -> None:
    adapter = GeminiCliAdapter()
    assert adapter.enterprise_admin_controls_status(
        tenant_id="tenant-bank", evidence=None
    )["status"] == "unverified:tenant_evidence_not_supplied"

    evidence = {
        "schema_version": "google-gemini-admin-controls-evidence/1.0",
        "tenant_id": "tenant-bank",
        "provider": "google",
        "product": "gemini_cli",
        "source": "google_enterprise_admin_controls",
        "observed_at": "2026-08-12T08:00:00+00:00",
        "controls": {
            "strict_mode": True,
            "yolo_mode_disabled": True,
            "mcp_allowlist_enforced": True,
            "required_mcp_servers_enforced": True,
        },
        "evidence_refs": ["evidence:google-admin:tenant-bank:receipt-1"],
        "signed_receipt": {"receipt_id": "receipt-1"},
    }
    assert adapter.enterprise_admin_controls_status(
        tenant_id="tenant-bank", evidence=evidence
    )["status"] == "unverified:tenant_receipt_verifier_not_supplied"
    assert adapter.enterprise_admin_controls_status(
        tenant_id="tenant-other", evidence=evidence, verify_receipt=lambda _row: True
    )["status"] == "failed:tenant_binding_mismatch"

    verified = adapter.enterprise_admin_controls_status(
        tenant_id="tenant-bank", evidence=evidence, verify_receipt=lambda _row: True
    )
    assert verified["status"] == "verified:tenant_admin_controls_enforced"
    assert verified["enterprise_controls_claimed"] is True
    assert verified["evidence_refs"] == evidence["evidence_refs"]


def test_gemini_managed_launcher_deployment_requires_mdm_endpoint_receipt() -> None:
    adapter = GeminiCliAdapter()
    assert adapter.managed_launcher_deployment_status(
        tenant_id="tenant-bank", endpoint_id="endpoint-1", evidence=None
    )["status"] == "unverified:mdm_deployment_evidence_not_supplied"

    evidence = {
        "schema_version": "google-gemini-managed-launcher-evidence/1.0",
        "tenant_id": "tenant-bank",
        "endpoint_id": "endpoint-1",
        "provider": "google",
        "product": "gemini_cli",
        "source": "enterprise_mdm",
        "provider_version": "0.54.4",
        "observed_at": "2026-08-12T08:00:00+00:00",
        "mdm_profile_id_hash": "a" * 64,
        "checks": {
            "launcher_hash_verified": True,
            "binary_hash_verified": True,
            "runtime_hash_verified": True,
            "settings_hash_verified": True,
            "helper_hash_verified": True,
            "runtime_config_hash_verified": True,
            "system_settings_override_enforced": True,
        },
        "evidence_refs": ["evidence:mdm:endpoint-1:receipt-1"],
        "signed_receipt": {"receipt_id": "receipt-1"},
    }
    assert adapter.managed_launcher_deployment_status(
        tenant_id="tenant-bank", endpoint_id="endpoint-1", evidence=evidence
    )["status"] == "unverified:mdm_receipt_verifier_not_supplied"
    undated = dict(evidence)
    undated.pop("observed_at")
    assert adapter.managed_launcher_deployment_status(
        tenant_id="tenant-bank",
        endpoint_id="endpoint-1",
        evidence=undated,
        verify_receipt=lambda _row: True,
    )["status"] == "failed:mdm_receipt_contract_invalid"
    verified = adapter.managed_launcher_deployment_status(
        tenant_id="tenant-bank",
        endpoint_id="endpoint-1",
        evidence=evidence,
        verify_receipt=lambda _row: True,
    )
    assert verified["status"] == "verified:mdm_deployed_and_enforced"
    assert verified["managed_launcher_claimed"] is True


def test_gemini_security_degradation_has_structured_finding_profiles() -> None:
    assert {
        "PROVIDER_POLICY_INVALID",
        "HOOK_OUTPUT_INTEGRITY_FAILURE",
        "PROJECT_HOOK_CONFLICT",
        "TOOL_SELECTION_CONTROL_WEAKENED",
    }.issubset(FINDING_PROFILES)


def test_gemini_normalizes_tool_families_mcp_and_tail_calls_without_provider_identity_authority() -> None:
    adapter = GeminiCliAdapter()
    shell = adapter.normalize_event(_before_tool(), _context())
    file_read = adapter.normalize_event(
        {**_before_tool("read_file"), "tool_input": {"file_path": "/private/demo.txt"}},
        _context(),
    )
    file_write = adapter.normalize_event(
        {**_before_tool("write_file"), "tool_input": {"file_path": "/private/demo.txt", "content": "secret"}},
        _context(),
    )
    mcp = adapter.normalize_event(
        {**_before_tool("mcp_github_create_pull_request"), "tool_input": {"owner": "hawk", "repo": "demo"}},
        _context(),
    )

    assert shell.action["action_type"] == "COMMAND_EXECUTION"
    assert file_read.action["action_type"] == "FILE_READ"
    assert file_write.action["action_type"] == "FILE_WRITE"
    assert mcp.action["action_type"] == "MCP_TOOL_CALL"
    assert mcp.mcp == {"server_id": "github", "tool_name": "create_pull_request"}
    assert mcp.provider_correlation["tail_call"] is True
    assert len(mcp.provider_correlation["original_request_name_hash"]) == 64
    assert shell.actor["identity_id"] == "reference-user"
    assert "provider-session-is-not-authority" not in str(shell.actor)
    assert "tail_origin" not in str(mcp)


def test_gemini_decision_translation_fails_closed_for_unknown_assets_and_never_mutates_input() -> None:
    adapter = GeminiCliAdapter()
    unknown_request = adapter.normalize_event(_before_tool(), _context(decision="allow")).to_authorization_request()
    unknown_response = authorize_ai_action(unknown_request)
    assert unknown_response.decision == "block"
    assert adapter.format_decision_response(unknown_response)["decision"] == "deny"

    outputs = {}
    for decision in ("allow", "warn", "review", "require_approval", "require_second_approval", "redact", "block"):
        event = adapter.normalize_event(_before_tool(), _context(decision=decision))
        response = authorize_ai_action(_with_verified_discovery_asset(event.to_authorization_request()))
        outputs[decision] = adapter.format_decision_response(response)

    assert outputs["allow"]["decision"] == "allow"
    assert outputs["allow"]["continue"] is True
    for restrictive in ("warn", "review", "require_approval", "require_second_approval", "redact", "block"):
        assert outputs[restrictive]["decision"] == "deny"
        assert outputs[restrictive]["continue"] is False
    assert all("tool_input" not in json.dumps(output) for output in outputs.values())


def test_gemini_post_tool_evidence_is_provider_reported_not_execution_proof() -> None:
    result = GeminiCliAdapter().capture_execution_result(
        {
            "hook_event_name": "AfterTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git status"},
            "tool_response": {"llmContent": "private", "returnDisplay": "private"},
        }
    )

    assert result["quality"] == EvidenceQuality.PROVIDER_REPORTED.value
    assert len(result["parameter_hash"]) == 64
    assert len(result["result_hash"]) == 64
    assert "private" not in str(result)
    assert GeminiCliAdapter.manifest.capabilities[CapabilityDimension.POST_EXECUTION_VERIFICATION].level is CapabilityLevel.UNAVAILABLE


def test_gemini_install_is_idempotent_detects_disable_tamper_and_preserves_customer_hooks() -> None:
    adapter = GeminiCliAdapter(helper_path="/Library/Hawk/bin/hawk-native-hook")
    customer = {
        "matcher": "write_file",
        "hooks": [{"name": "customer", "type": "command", "command": "/opt/customer/hook", "timeout": 3000}],
    }
    existing = {"theme": "dark", "hooks": {"BeforeTool": [customer]}}

    first = adapter.install(adapter.install_plan(existing), existing)
    second = adapter.install(adapter.install_plan(first.configuration), first.configuration)
    assert first.configuration == second.configuration
    assert first.configuration["hooks"]["BeforeTool"][1] == customer
    assert adapter.validate_installation(first.configuration) is True

    tampered = json.loads(json.dumps(first.configuration))
    tampered["hooksConfig"] = {"enabled": False, "disabled": ["hawk-native-control"]}
    assert adapter.validate_installation(tampered) is False
    assert "native_control_disabled:hooksConfig.enabled" in adapter.detect_drift(tampered)
    assert adapter.uninstall(first.configuration) == existing
    assert adapter.security_conflicts(first.configuration) == ("competing_hook:BeforeTool",)
    assert adapter.verify_integrity(first.configuration) is False


def test_gemini_timeout_conformance_and_manifest_never_claim_false_ordering_or_response_proof() -> None:
    adapter = GeminiCliAdapter(acceptance_probes={name: True for name in GeminiCliAdapter.REQUIRED_PROBES})

    assert adapter.timeout_budget().response_deadline_ms == 5_000
    assert adapter.timeout_budget().remaining_network_budget_ms == 500
    assert adapter.manifest.event_semantics.ordering_guaranteed is False
    assert adapter.manifest.event_semantics.runs_before_untrusted_mutators is False
    assert adapter.manifest.capabilities[CapabilityDimension.RESPONSE_CONTROL].verification_status is VerificationStatus.EXPERIMENTAL
    result = NativeControlAdapterConformanceSuite().run(adapter)
    assert result.passed is True, result.failures
