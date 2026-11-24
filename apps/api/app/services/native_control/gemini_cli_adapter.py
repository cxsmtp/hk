from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import subprocess
from typing import Any, Callable, Mapping

from app.core.control_engine.authorization import AuthorizationResponse
from app.services.native_control.adapter_contract import (
    AdapterDescriptor,
    AdapterError,
    AdapterErrorCode,
    AdapterMaturity,
    AdapterPipelineContext,
    CapabilityManifest,
    ControlConfigFingerprint,
    DeploymentFamily,
    EventSemantics,
    EvidenceQuality,
    InstallationPlan,
    InstallationResult,
    NativeControlEvent,
    SelectionCharacteristics,
    StructuredBlindSpot,
    TimeoutBudget,
    stable_hash,
)
from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ControlPointHealth,
    DegradationMode,
    HealthState,
    SecurityProperties,
    VerificationStatus,
)
from app.services.native_control.gemini_acceptance_registry import load_gemini_acceptance_registry


_MARKER = "--hawk-managed-hook"
_ADAPTER_VERSION = "1.0.0"
_REGISTRY = load_gemini_acceptance_registry()
_EXACT_VERSIONS = _REGISTRY.accepted_versions(adapter_version=_ADAPTER_VERSION)
_LATEST = _REGISTRY.entry(_EXACT_VERSIONS[-1], adapter_version=_ADAPTER_VERSION) if _EXACT_VERSIONS else None
_ACCEPTED = frozenset(_LATEST.accepted_capabilities if _LATEST else ())
_PRODUCTION_ELIGIBLE = bool(_LATEST and _LATEST.production_eligible)
_VERSION_MIN = _EXACT_VERSIONS[0] if _EXACT_VERSIONS else "0.54.4"
_VERSION_MAX = _EXACT_VERSIONS[-1] if _EXACT_VERSIONS else "0.54.4"
_EVENTS = {
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "BeforeAgent": "before_agent",
    "AfterAgent": "after_agent",
    "BeforeModel": "before_model",
    "AfterModel": "after_model",
    "BeforeToolSelection": "before_tool_selection",
    "BeforeTool": "before_tool",
    "AfterTool": "after_tool",
    "PreCompress": "pre_compress",
    "Notification": "notification",
}
_WRITE_TOKENS = frozenset({"create", "delete", "edit", "execute", "merge", "post", "push", "send", "update", "upload", "write"})


def _claim(level: CapabilityLevel, capability: str) -> CapabilityClaim:
    status = VerificationStatus.VERIFIED if capability in _ACCEPTED else VerificationStatus.EXPERIMENTAL
    return CapabilityClaim(
        level=level,
        verification_status=status,
        evidence_refs=(
            "repo:apps/endpoint-agent/tests/test_gemini_binary_acceptance.py",
            "repo:apps/api/tests/test_native_control_gemini_adapter.py",
        ) if status is VerificationStatus.VERIFIED else (),
    )


def _managed(row: object) -> bool:
    return isinstance(row, Mapping) and any(
        isinstance(handler, Mapping) and _MARKER in str(handler.get("command") or "")
        for handler in row.get("hooks") or []
    )


class GeminiCliAdapter:
    """Google Gemini CLI command-hook mechanics over Hawk's shared control plane."""

    REQUIRED_PROBES = (
        "environment",
        "installation",
        "authentication",
        "replay_defense",
        "event_delivery",
        "normalization",
        "safe_allow",
        "safe_deny",
        "policy_callback",
        "configuration_integrity",
        "privacy",
    )
    descriptor = AdapterDescriptor(
        adapter_id="google.gemini-cli.command-hooks",
        provider_family="google",
        product_family="gemini_cli",
        adapter_version=_ADAPTER_VERSION,
        deployment_families_supported=(DeploymentFamily.ENDPOINT, DeploymentFamily.RUNTIME),
        enforcement_methods_supported=(ControlMethod.NATIVE_HOOK,),
        event_schema_version="gemini-cli-hooks/runtime-validated-v1",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.PRODUCTION if _PRODUCTION_ELIGIBLE else AdapterMaturity.EXPERIMENTAL,
        description="Gemini CLI command-hook adapter with signed Hawk lifecycle callbacks.",
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider="google",
        product="gemini_cli",
        provider_version_min=_VERSION_MIN,
        provider_version_max=_VERSION_MAX,
        exact_verified_versions=_EXACT_VERSIONS,
        adapter_version=_ADAPTER_VERSION,
        verification_status=(
            VerificationStatus.VERIFIED if _PRODUCTION_ELIGIBLE else VerificationStatus.EXPERIMENTAL
        ),
        verified_at=_LATEST.evidence_timestamp if _LATEST else None,
        source_reference="repo:docs/evidence/gemini-cli-acceptance-registry.json",
        capabilities={
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE, "discovery"),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.OBSERVE, "identity"),
            CapabilityDimension.PROMPT_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "prompt_control"),
            CapabilityDimension.RESPONSE_CONTROL: _claim(CapabilityLevel.INLINE, "response_control"),
            CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "tool_control"),
            CapabilityDimension.MCP_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "mcp_control"),
            CapabilityDimension.COMMAND_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "command_control"),
            # The accepted hook reports a read_file action before the provider
            # tool dispatch. It does not prove an OS file-open denial, so retain
            # the reviewed evidence as visibility rather than an inline file
            # authorization claim.
            CapabilityDimension.FILE_READ_CONTROL: _claim(CapabilityLevel.OBSERVE, "file_read_control"),
            CapabilityDimension.FILE_WRITE_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "file_write_control"),
            CapabilityDimension.APPROVAL_CONTROL: _claim(CapabilityLevel.EXTERNAL, "approval_control"),
            CapabilityDimension.PROVIDER_PERMISSION_CONTEXT: _claim(CapabilityLevel.OBSERVE, "provider_permission_context"),
            CapabilityDimension.HAWK_APPROVAL_BINDING: _claim(CapabilityLevel.EXTERNAL, "hawk_approval_binding"),
            CapabilityDimension.APPROVAL_CORRELATION: _claim(CapabilityLevel.OBSERVE, "approval_correlation"),
            CapabilityDimension.PARAMETER_BINDING: _claim(CapabilityLevel.INLINE_BOUND, "parameter_binding"),
            CapabilityDimension.TARGET_BINDING: _claim(CapabilityLevel.INLINE_BOUND, "target_binding"),
            CapabilityDimension.DESTINATION_BINDING: _claim(CapabilityLevel.INLINE_BOUND, "destination_binding"),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE, "post_execution_visibility"),
            CapabilityDimension.TOOL_FAILURE_VISIBILITY: _claim(CapabilityLevel.OBSERVE, "tool_failure_visibility"),
            CapabilityDimension.EXECUTION_CORRELATION: _claim(CapabilityLevel.OBSERVE, "execution_correlation"),
            CapabilityDimension.POST_EXECUTION_VERIFICATION: _claim(CapabilityLevel.UNAVAILABLE, "post_execution_absence_verified"),
            CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "persistent_side_effect_control"),
            CapabilityDimension.PERSISTENT_SIDE_EFFECT_VISIBILITY: _claim(CapabilityLevel.OBSERVE, "persistent_side_effect_visibility"),
            CapabilityDimension.DELEGATION_CONTROL: _claim(CapabilityLevel.UNKNOWN, "delegation_control"),
            CapabilityDimension.CONTAINMENT: _claim(CapabilityLevel.UNAVAILABLE, "containment_absence_verified"),
            CapabilityDimension.BYPASS_DETECTION: _claim(CapabilityLevel.OBSERVE, "bypass_detection"),
            CapabilityDimension.CONFIG_INTEGRITY: _claim(CapabilityLevel.INLINE_BOUND, "config_integrity"),
        },
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=90,
            action_fidelity=95,
            identity_quality=65,
            parameter_fidelity=95,
            target_fidelity=90,
            destination_fidelity=85,
            result_fidelity=60,
            bypass_resistance=60,
            tamper_resistance=80,
            expected_latency_ms=int(_LATEST.measured_callback_p95_ms) if _LATEST else 5_000,
            availability_profile="synchronous_local_command_hook",
            required_permissions=("gemini.settings.write", "hawk.callback.send"),
            privacy_impact="bounded metadata and stable hashes; no raw prompt, result, or secret export",
        ),
        required_permissions=("gemini.settings.write", "hawk.callback.send"),
        event_semantics=EventSemantics(
            pre_execution_events=("BeforeAgent", "BeforeModel", "BeforeTool"),
            post_execution_events=("AfterAgent", "AfterModel", "AfterTool"),
            normalized_fields=(
                "canonical_parameters", "parameter_hash", "canonical_target", "target_hash",
                "destination_hash", "action_correlation", "execution_result",
            ),
            synchronous_decision_mechanism="Gemini CLI command-hook JSON deny or provider exit code 2",
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(
            StructuredBlindSpot(
                id="google.gemini-cli.version-mismatch",
                control_dimension=CapabilityDimension.BYPASS_DETECTION,
                scope="Gemini CLI binary version",
                condition="The detected version lacks a reviewed exact-version acceptance entry.",
                impact="The adapter is ineligible for Enforce and contributes no protected coverage.",
                detection_method="Local binary version and signed callback binding",
                mitigation="Pin a reviewed version or run the real-binary acceptance gate.",
                evidence=("repo:apps/endpoint-agent/tests/test_gemini_binary_acceptance.py",),
            ),
            StructuredBlindSpot(
                id="google.gemini-cli.alternate-surface-bypass",
                control_dimension=CapabilityDimension.BYPASS_DETECTION,
                scope="Google AI activity outside configured Gemini CLI hooks",
                condition="A caller uses direct APIs, another client, or disables/removes hooks.",
                impact="The action does not traverse this adapter.",
                detection_method="Endpoint discovery and settings integrity monitoring",
                mitigation="Use gateway, endpoint runtime, managed settings, and admin policy for alternate paths.",
                evidence=("https://geminicli.com/docs/hooks/reference/",),
            ),
            StructuredBlindSpot(
                id="google.gemini-cli.hook-composition",
                control_dimension=CapabilityDimension.PARAMETER_BINDING,
                scope="Multiple provider hooks",
                condition="Another hook mutates tool input or filters tools in the same lifecycle.",
                impact="Hawk does not claim an unproven global ordering guarantee.",
                detection_method="Settings fingerprint and real-binary composition tests",
                mitigation="Disable Hawk input mutation and reauthorize any future mutated action.",
                evidence=("https://geminicli.com/docs/hooks/reference/",),
            ),
        ),
        failure_modes=(
            "callback unavailable at a pre-action event",
            "hook output malformed or stdout polluted",
            "hook disabled, removed, timed out, or version mismatched",
            "provider policy blocks before Hawk hook execution",
        ),
        supported_installation_modes=("user_settings", "project_settings", "system_settings"),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED,),
        execution_evidence_quality=EvidenceQuality.PROVIDER_REPORTED,
        selection_characteristics=SelectionCharacteristics(35, 35, 30, 20, 30),
    )

    def __init__(
        self,
        *,
        helper_path: str = "/Library/Hawk/bin/hawk-native-hook",
        runtime_config_path: str = "/Library/Hawk/etc/native-control.json",
        binary_path: str = "gemini",
        integration_instance_id: str = "gemini-native-hook",
        acceptance_probes: Mapping[str, bool] | None = None,
    ) -> None:
        self.helper_path = str(helper_path)
        self.runtime_config_path = str(runtime_config_path)
        self.binary_path = str(binary_path)
        self.integration_instance_id = str(integration_instance_id)
        self._acceptance_probes = {name: bool((acceptance_probes or {}).get(name)) for name in self.REQUIRED_PROBES}

    def limitations(self) -> tuple[StructuredBlindSpot, ...]:
        return self.manifest.known_blind_spots

    def supported_versions(self) -> tuple[str, str]:
        return self.manifest.provider_version_min, self.manifest.provider_version_max

    def version_assurance(self, provider_version: str) -> str:
        return "exact_verified" if str(provider_version or "").strip() in self.manifest.exact_verified_versions else "unsupported"

    def supported_tool_events(self) -> tuple[str, ...]:
        return ("BeforeTool", "AfterTool")

    def lifecycle_semantics(self) -> dict[str, str]:
        return {
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

    def enterprise_admin_controls_status(
        self,
        *,
        tenant_id: str,
        evidence: Mapping[str, Any] | None,
        verify_receipt: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> dict[str, Any]:
        """Evaluate tenant-backed Google Admin evidence without self-attestation.

        The adapter cannot verify a Google tenant by trusting a boolean in the
        payload. A caller must supply the platform's receipt verifier, which is
        responsible for validating the signed receipt against the tenant's
        authoritative integration identity.
        """

        unclaimed = {
            "status": "unverified:tenant_evidence_not_supplied",
            "enterprise_controls_claimed": False,
            "controls": {},
            "evidence_refs": [],
        }
        if evidence is None:
            return unclaimed
        if verify_receipt is None:
            return {
                **unclaimed,
                "status": "unverified:tenant_receipt_verifier_not_supplied",
            }
        expected_tenant = str(tenant_id or "").strip()
        if not expected_tenant or str(evidence.get("tenant_id") or "").strip() != expected_tenant:
            return {**unclaimed, "status": "failed:tenant_binding_mismatch"}
        if (
            evidence.get("schema_version") != "google-gemini-admin-controls-evidence/1.0"
            or evidence.get("provider") != "google"
            or evidence.get("product") != "gemini_cli"
            or evidence.get("source") != "google_enterprise_admin_controls"
        ):
            return {**unclaimed, "status": "failed:authoritative_source_invalid"}
        try:
            observed_at = datetime.fromisoformat(str(evidence.get("observed_at") or ""))
        except ValueError:
            return {**unclaimed, "status": "failed:evidence_timestamp_invalid"}
        if observed_at.tzinfo is None:
            return {**unclaimed, "status": "failed:evidence_timestamp_invalid"}
        refs = [
            str(value)
            for value in evidence.get("evidence_refs") or []
            if isinstance(value, str) and value.startswith("evidence:")
        ]
        receipt = evidence.get("signed_receipt")
        if not refs or not isinstance(receipt, Mapping):
            return {**unclaimed, "status": "failed:signed_evidence_missing"}
        try:
            receipt_verified = verify_receipt(evidence) is True
        except Exception:
            receipt_verified = False
        if not receipt_verified:
            return {**unclaimed, "status": "failed:tenant_receipt_invalid"}
        required = (
            "strict_mode",
            "yolo_mode_disabled",
            "mcp_allowlist_enforced",
            "required_mcp_servers_enforced",
        )
        source_controls = evidence.get("controls")
        controls = {
            name: bool(source_controls.get(name))
            for name in required
        } if isinstance(source_controls, Mapping) else {}
        fully_enforced = bool(controls) and all(controls.values())
        return {
            "status": (
                "verified:tenant_admin_controls_enforced"
                if fully_enforced
                else "verified:tenant_admin_controls_observed_not_fully_enforced"
            ),
            "enterprise_controls_claimed": fully_enforced,
            "controls": controls,
            "evidence_refs": refs,
            "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
        }

    def managed_launcher_deployment_status(
        self,
        *,
        tenant_id: str,
        endpoint_id: str,
        evidence: Mapping[str, Any] | None,
        verify_receipt: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> dict[str, Any]:
        """Require an endpoint- and tenant-bound MDM receipt before coverage."""

        unclaimed = {
            "status": "unverified:mdm_deployment_evidence_not_supplied",
            "managed_launcher_claimed": False,
            "checks": {},
            "evidence_refs": [],
        }
        if evidence is None:
            return unclaimed
        if verify_receipt is None:
            return {**unclaimed, "status": "unverified:mdm_receipt_verifier_not_supplied"}
        expected_tenant = str(tenant_id or "").strip()
        expected_endpoint = str(endpoint_id or "").strip()
        if (
            not expected_tenant
            or not expected_endpoint
            or str(evidence.get("tenant_id") or "").strip() != expected_tenant
            or str(evidence.get("endpoint_id") or "").strip() != expected_endpoint
        ):
            return {**unclaimed, "status": "failed:mdm_receipt_binding_mismatch"}
        version = str(evidence.get("provider_version") or "")
        if (
            evidence.get("schema_version")
            != "google-gemini-managed-launcher-evidence/1.0"
            or evidence.get("provider") != "google"
            or evidence.get("product") != "gemini_cli"
            or evidence.get("source") != "enterprise_mdm"
            or self.version_assurance(version) != "exact_verified"
            or not re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("mdm_profile_id_hash") or ""))
        ):
            return {**unclaimed, "status": "failed:mdm_receipt_contract_invalid"}
        try:
            observed_at = datetime.fromisoformat(str(evidence.get("observed_at") or ""))
        except ValueError:
            return {**unclaimed, "status": "failed:mdm_receipt_contract_invalid"}
        if observed_at.tzinfo is None:
            return {**unclaimed, "status": "failed:mdm_receipt_contract_invalid"}
        refs = [
            str(value)
            for value in evidence.get("evidence_refs") or []
            if isinstance(value, str) and value.startswith("evidence:")
        ]
        receipt = evidence.get("signed_receipt")
        if not refs or not isinstance(receipt, Mapping):
            return {**unclaimed, "status": "failed:mdm_signed_evidence_missing"}
        try:
            receipt_verified = verify_receipt(evidence) is True
        except Exception:
            receipt_verified = False
        if not receipt_verified:
            return {**unclaimed, "status": "failed:mdm_receipt_invalid"}
        required = (
            "launcher_hash_verified",
            "binary_hash_verified",
            "runtime_hash_verified",
            "settings_hash_verified",
            "helper_hash_verified",
            "runtime_config_hash_verified",
            "system_settings_override_enforced",
        )
        source_checks = evidence.get("checks")
        checks = {
            name: bool(source_checks.get(name))
            for name in required
        } if isinstance(source_checks, Mapping) else {}
        enforced = bool(checks) and all(checks.values())
        return {
            "status": (
                "verified:mdm_deployed_and_enforced"
                if enforced
                else "failed:mdm_deployment_checks_incomplete"
            ),
            "managed_launcher_claimed": enforced,
            "checks": checks,
            "evidence_refs": refs,
            "provider_version": version,
            "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
        }

    def supported_mcp_events(self) -> tuple[str, ...]:
        return ("BeforeTool:mcp_.*", "AfterTool:mcp_.*")

    def supported_command_events(self) -> tuple[str, ...]:
        return ("BeforeTool:run_shell_command", "AfterTool:run_shell_command")

    def supported_file_events(self) -> tuple[str, ...]:
        return ("BeforeTool:read_file|write_file|replace", "AfterTool:read_file|write_file|replace")

    def supports_input_mutation(self) -> bool:
        return False

    def decision_deadline_ms(self) -> int:
        return 5_000

    def timeout_budget(self) -> TimeoutBudget:
        return TimeoutBudget(provider_timeout_ms=4_000, hawk_processing_budget_ms=500, response_deadline_ms=5_000)

    def validation_probe(self) -> dict[str, bool]:
        return dict(self._acceptance_probes)

    def detect_environment(self) -> dict[str, Any]:
        binary = Path(self.binary_path).expanduser()
        if not binary.is_absolute():
            from shutil import which
            resolved = which(self.binary_path)
            binary = Path(resolved) if resolved else binary
        version = "unknown"
        available = binary.is_file() and not binary.is_symlink()
        if available:
            try:
                result = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=5, check=False)
                match = re.search(r"\b(\d+\.\d+\.\d+)\b", result.stdout)
                version = match.group(1) if result.returncode == 0 and match else "unknown"
            except (OSError, subprocess.SubprocessError):
                available = False
        return {"available": available, "binary_path": str(binary), "provider_version": version}

    def validate_environment(self, detected: Mapping[str, Any]) -> bool:
        return detected.get("available") is True and self.version_assurance(str(detected.get("provider_version") or "")) == "exact_verified"

    def _entry(self, provider_event: str) -> dict[str, object]:
        command = " ".join((
            shlex.quote(self.helper_path), _MARKER, "--provider", "gemini_cli", "--event",
            _EVENTS[provider_event], "--config", shlex.quote(self.runtime_config_path),
        ))
        matcher = ".*" if provider_event in {"BeforeTool", "AfterTool"} else "*"
        return {
            "matcher": matcher,
            "hooks": [{
                "type": "command", "command": command, "timeout": 5000,
                "name": "hawk-native-control",
                "description": "Hawk signed native lifecycle governance callback",
            }],
        }

    def install_plan(self, existing_configuration: Mapping[str, Any]) -> InstallationPlan:
        return InstallationPlan(
            adapter_id=self.descriptor.adapter_id,
            files_or_settings_affected=("~/.gemini/settings.json",),
            permissions_required=("gemini.settings.write",),
            existing_configuration_detected=bool(existing_configuration),
            hawk_owned_fragment_key=_MARKER,
            rollback_strategy="remove only command handlers containing the Hawk managed marker",
            restart_required=True,
            estimated_coverage_effect=("Gemini CLI prompt, model, tool, command, file and MCP lifecycle",),
            known_risks=("provider hook composition does not establish a universal ordering guarantee",),
        )

    def _without_hawk(self, configuration: Mapping[str, Any]) -> dict[str, Any]:
        result = deepcopy(dict(configuration))
        hooks = result.get("hooks")
        if not isinstance(hooks, dict):
            return result
        for provider_event in _EVENTS:
            rows = hooks.get(provider_event)
            if not isinstance(rows, list):
                continue
            remaining = [row for row in rows if not _managed(row)]
            if remaining:
                hooks[provider_event] = remaining
            else:
                hooks.pop(provider_event, None)
        if not hooks:
            result.pop("hooks", None)
        return result

    def install(self, plan: InstallationPlan, existing_configuration: Mapping[str, Any]) -> InstallationResult:
        if plan.adapter_id != self.descriptor.adapter_id or plan.hawk_owned_fragment_key != _MARKER:
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        base = self._without_hawk(existing_configuration)
        configuration = deepcopy(base)
        hooks = configuration.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        fragments: dict[str, object] = {}
        for provider_event in _EVENTS:
            existing = hooks.setdefault(provider_event, [])
            if not isinstance(existing, list):
                raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
            entry = self._entry(provider_event)
            hooks[provider_event] = [entry, *existing]
            fragments[provider_event] = entry
        fingerprint = ControlConfigFingerprint(
            integration_instance_id=self.integration_instance_id,
            provider="google",
            config_location="~/.gemini/settings.json",
            hawk_owned_content_hash=stable_hash(fragments),
            surrounding_context_hash=stable_hash(base),
            ordering="listed_first_without_universal_provider_ordering_claim",
            callback_identity="signed_hawk_native_callback",
            helper_identity=stable_hash(self.helper_path),
            event_subscriptions=tuple(_EVENTS),
            blocking_semantics="BeforeTool/BeforeAgent/BeforeModel JSON deny or exit code 2",
            version=self.descriptor.adapter_version,
            last_verified=datetime.now(timezone.utc).isoformat(),
        )
        if not self.validate_installation(configuration):
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        return InstallationResult(configuration=configuration, fingerprint=fingerprint)

    def detect_drift(self, configuration: Mapping[str, Any]) -> tuple[str, ...]:
        reasons: list[str] = []
        hooks_config = configuration.get("hooksConfig")
        if isinstance(hooks_config, Mapping):
            if hooks_config.get("enabled") is False:
                reasons.append("native_control_disabled:hooksConfig.enabled")
            disabled = hooks_config.get("disabled")
            if isinstance(disabled, list) and "hawk-native-control" in disabled:
                reasons.append("native_control_disabled:hawk-native-control")
        hooks = configuration.get("hooks")
        if not isinstance(hooks, Mapping):
            reasons.append("gemini_hooks_missing")
            return tuple(reasons)
        for provider_event in _EVENTS:
            rows = hooks.get(provider_event)
            if not isinstance(rows, list) or not rows or rows[0] != self._entry(provider_event):
                reasons.append(f"hawk_hook_changed:{provider_event}")
            elif sum(1 for row in rows if _managed(row)) != 1:
                reasons.append(f"hawk_hook_count_invalid:{provider_event}")
        return tuple(reasons)

    def validate_installation(self, configuration: Mapping[str, Any]) -> bool:
        return not self.detect_drift(configuration)

    def security_conflicts(self, configuration: Mapping[str, Any]) -> tuple[str, ...]:
        hooks = configuration.get("hooks")
        if not isinstance(hooks, Mapping):
            return ("gemini_hooks_missing",)
        sensitive_events = (
            "BeforeTool", "AfterTool", "BeforeToolSelection", "BeforeModel", "AfterModel",
        )
        return tuple(
            f"competing_hook:{event}"
            for event in sensitive_events
            if isinstance(hooks.get(event), list)
            and any(not _managed(row) for row in hooks[event])
        )

    def configure(self, configuration: Mapping[str, Any]) -> InstallationResult:
        return self.install(self.install_plan(configuration), configuration)

    def verify_integrity(self, configuration: Mapping[str, Any]) -> bool:
        return self.validate_installation(configuration) and not self.security_conflicts(configuration)

    def uninstall(self, configuration: Mapping[str, Any]) -> dict[str, Any]:
        return self._without_hawk(configuration)

    def normalize_event(self, raw_payload: Mapping[str, Any], context: AdapterPipelineContext) -> NativeControlEvent:
        if not isinstance(raw_payload, Mapping):
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        provider_event = str(raw_payload.get("hook_event_name") or raw_payload.get("event_type") or "")
        if provider_event == "tool_call":
            provider_event = "BeforeTool"
        if provider_event not in _EVENTS:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        lifecycle = _EVENTS[provider_event]
        tool_name = str(raw_payload.get("tool_name") or provider_event)
        raw_input = raw_payload.get("tool_input")
        if not isinstance(raw_input, Mapping):
            raw_input = raw_payload.get("parameters")
        parameters = deepcopy(dict(raw_input)) if isinstance(raw_input, Mapping) else {}
        cwd = str(raw_payload.get("cwd") or "unknown")
        mcp_match = re.match(r"^mcp_([^_]+)_(.+)$", tool_name)
        mcp_server = mcp_match.group(1) if mcp_match else ""
        mcp_tool = mcp_match.group(2) if mcp_match else ""
        normalized_tool = tool_name.strip().lower()
        if mcp_match:
            action_type = "MCP_TOOL_CALL"
        else:
            action_type = {
                "run_shell_command": "COMMAND_EXECUTION",
                "read_file": "FILE_READ",
                "write_file": "FILE_WRITE",
                "replace": "FILE_WRITE",
                "glob": "FILE_SEARCH",
                "search_file_content": "FILE_SEARCH",
                "google_web_search": "WEB_SEARCH",
                "web_fetch": "WEB_FETCH",
            }.get(normalized_tool, "UNKNOWN_TOOL_ACTION")
        if provider_event in {"BeforeModel", "BeforeToolSelection"}:
            action_type = "MODEL_REQUEST"
        elif provider_event == "BeforeAgent":
            action_type = "AGENT_TURN"
        elif provider_event in {"SessionStart", "SessionEnd", "AfterAgent", "AfterModel", "PreCompress", "Notification"}:
            action_type = "SESSION_CONTEXT"
        target_parts = [str(parameters[key]) for key in ("owner", "repo", "path", "file_path", "url", "resource", "id") if isinstance(parameters.get(key), (str, int))]
        if action_type == "COMMAND_EXECUTION":
            target = cwd
        elif action_type in {"FILE_READ", "FILE_WRITE", "FILE_SEARCH"}:
            target = str(parameters.get("file_path") or parameters.get("path") or cwd)
        else:
            target = str(raw_payload.get("target") or ("/".join(target_parts) if target_parts else tool_name))
        tokens = set(re.split(r"[^a-z0-9]+", f"{tool_name} {json.dumps(parameters, default=str)}".lower()))
        persistent = lifecycle not in {"session_start", "session_end", "after_agent", "after_model", "before_tool_selection", "pre_compress", "notification"} and bool(
            action_type in {"COMMAND_EXECUTION", "FILE_WRITE", "UNKNOWN_TOOL_ACTION"} or tokens & _WRITE_TOKENS
        )
        original_request_name = raw_payload.get("original_request_name")
        model_request = raw_payload.get("llm_request") if isinstance(raw_payload.get("llm_request"), Mapping) else {}
        return NativeControlEvent(
            tenant_id=context.tenant_id,
            integration_instance_id=context.integration_instance_id,
            provider="google",
            product="gemini_cli",
            raw_provider_event_type=provider_event,
            provider_event_id=context.provider_event_id,
            provider_version=context.provider_version,
            adapter_version=self.descriptor.adapter_version,
            lifecycle_stage=lifecycle,
            actor=dict(context.resolved_actor),
            session={"session_id": context.session_id, "cwd_hash": stable_hash(cwd), "permission_mode": str(raw_payload.get("approval_mode") or "unknown")},
            runtime={"environment": context.environment, "credential_id": context.credential_id, "correlation_id": context.correlation_id},
            tool={"name": tool_name, "version": context.provider_version, "fingerprint_id": stable_hash(tool_name)},
            model={"name": str(model_request.get("model") or raw_payload.get("model") or "unknown")},
            mcp={"server_id": mcp_server, "tool_name": mcp_tool} if mcp_server else {},
            action={"action_type": action_type, "canonical_parameters": parameters, "parameter_hash": stable_hash(parameters)},
            target={"resource": target, "canonical_target": target, "resource_hash": stable_hash(target)},
            destination={"destination": mcp_server or "local", "destination_hash": stable_hash(mcp_server or "local")},
            side_effect_class="persistent_external_write" if persistent else "read_or_unknown",
            persistence={"persistent_side_effect": persistent},
            provider_correlation={
                "chain_id": context.chain_id,
                "correlation_id": context.correlation_id,
                "tail_call": bool(original_request_name),
                "original_request_name_hash": stable_hash(original_request_name) if original_request_name else "unknown",
            },
            timing={"received_at": context.received_at, "pre_execution": lifecycle in {"before_agent", "before_model", "before_tool"}},
            integrity={"transport": context.transport.value, "signature_valid": context.signature_valid},
            policy_snapshot_id=context.policy_snapshot_id,
            policy_profile=dict(context.policy_profile),
        )

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision == "allow":
            return {"decision": "allow", "continue": True, "reason": response.reason}
        return {"decision": "deny", "continue": False, "reason": response.reason}

    def capture_execution_result(self, provider_result: Mapping[str, Any]) -> dict[str, Any]:
        parameters = dict(provider_result.get("tool_input")) if isinstance(provider_result.get("tool_input"), Mapping) else {}
        result = dict(provider_result.get("tool_response")) if isinstance(provider_result.get("tool_response"), Mapping) else {"status": "unknown"}
        return {
            "quality": EvidenceQuality.PROVIDER_REPORTED.value,
            "provider_event_type": str(provider_result.get("hook_event_name") or "AfterTool"),
            "parameter_hash": stable_hash(parameters),
            "result_hash": stable_hash(result),
            "original_request_name_hash": stable_hash(provider_result.get("original_request_name")) if provider_result.get("original_request_name") else "unknown",
        }

    def health(self) -> ControlPointHealth:
        passed = all(self._acceptance_probes.values())
        return ControlPointHealth(
            state=HealthState.HEALTHY if passed else HealthState.UNVERIFIED,
            callback_authenticated=self._acceptance_probes["authentication"],
            validation_current=passed,
            evidence_flowing=self._acceptance_probes["event_delivery"],
            configuration_integrity_valid=self._acceptance_probes["configuration_integrity"],
            policy_fresh=self._acceptance_probes["policy_callback"],
            observed_latency_ms=self.manifest.security_properties.expected_latency_ms if passed else None,
            reason_codes=() if passed else tuple(name for name, value in self._acceptance_probes.items() if not value),
        )
