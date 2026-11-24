from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shlex
import subprocess
from typing import Any, Mapping

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
    stable_hash,
)
from app.services.native_control.claude_adapter import ClaudeAdapter
from app.services.native_control.cursor_acceptance_registry import (
    load_cursor_acceptance_registry,
)
from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ControlPointHealth,
    DegradationMode,
    SecurityProperties,
    VerificationStatus,
)


_MARKER = "--hawk-managed-hook"
_ADAPTER_VERSION = "0.2.0"
_ACCEPTANCE_REGISTRY = load_cursor_acceptance_registry()
_EXACT_VERIFIED_VERSIONS = _ACCEPTANCE_REGISTRY.accepted_versions(
    adapter_version=_ADAPTER_VERSION
)
_LATEST_ACCEPTANCE = (
    _ACCEPTANCE_REGISTRY.entry(
        _EXACT_VERIFIED_VERSIONS[-1],
        adapter_version=_ADAPTER_VERSION,
    )
    if _EXACT_VERIFIED_VERSIONS
    else None
)
_ACCEPTED_CAPABILITIES = frozenset(
    _LATEST_ACCEPTANCE.accepted_capabilities if _LATEST_ACCEPTANCE else ()
)
_EVENTS = {
    "sessionStart": "session_start",
    "sessionEnd": "session_end",
    "preToolUse": "before_tool",
    "postToolUse": "after_tool",
    "postToolUseFailure": "after_tool_failure",
    "subagentStart": "subagent_start",
    "subagentStop": "subagent_stop",
    "beforeShellExecution": "before_tool",
    "afterShellExecution": "after_tool",
    "beforeMCPExecution": "before_tool",
    "afterMCPExecution": "after_tool",
    "beforeReadFile": "before_tool",
    "afterFileEdit": "after_tool",
    "beforeSubmitPrompt": "before_model",
    "preCompact": "session_context",
    "stop": "session_context",
    "afterAgentResponse": "after_model",
    "afterAgentThought": "session_context",
    "beforeTabFileRead": "before_tool",
    "afterTabFileEdit": "after_tool",
    "workspaceOpen": "session_context",
}
_FAIL_CLOSED_EVENTS = frozenset(
    {
        "preToolUse",
        "subagentStart",
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
        "beforeSubmitPrompt",
        "beforeTabFileRead",
    }
)
_RUNTIME_PROFILES = frozenset(
    {
        "cursor_ide_local",
        "cursor_cli_local",
        "cursor_cloud_agent",
        "cursor_remote_machine",
        "cursor_automation",
        "cursor_unknown_runtime",
    }
)


def _runtime_facts(raw_payload: Mapping[str, Any]) -> tuple[str, str, bool]:
    """Classify the execution boundary without projecting local coverage remote.

    A callback from a local Cursor installation can describe a cloud or remote
    action.  A caller may provide a reviewed runtime-profile value, but absent
    that evidence Hawk records only the narrow runtime fact observable here.
    """

    profile = str(raw_payload.get("runtime_profile") or "").strip().lower()
    location = str(raw_payload.get("execution_location") or "").strip().lower()
    if profile not in _RUNTIME_PROFILES:
        if raw_payload.get("is_automation") is True:
            profile = "cursor_automation"
        elif raw_payload.get("is_cloud_agent") is True or location in {
            "cloud",
            "cloud_agent",
            "provider_hosted",
        }:
            profile = "cursor_cloud_agent"
        elif location in {"remote", "remote_agent", "remote_machine"}:
            profile = "cursor_remote_machine"
        else:
            profile = "cursor_unknown_runtime"
    normalized_location = (
        "cloud"
        if profile == "cursor_cloud_agent"
        else "local"
        if location == "local" and profile in {"cursor_ide_local", "cursor_cli_local"}
        else "unknown"
    )
    endpoint_execution_authority = (
        normalized_location == "local"
        and profile in {"cursor_ide_local", "cursor_cli_local"}
    )
    return profile, normalized_location, endpoint_execution_authority


def _claim(level: CapabilityLevel, capability: str) -> CapabilityClaim:
    verified = capability in _ACCEPTED_CAPABILITIES
    return CapabilityClaim(
        level=level,
        verification_status=(
            VerificationStatus.VERIFIED
            if verified
            else VerificationStatus.EXPERIMENTAL
        ),
        evidence_refs=(
            "repo:docs/evidence/cursor-2026.08.11-e8db854-acceptance-result.json",
            "repo:apps/endpoint-agent/tests/test_cursor_binary_acceptance.py",
            "repo:apps/api/tests/test_native_control_cursor_adapter.py",
        ) if verified else (),
    )


def _managed(row: object) -> bool:
    return isinstance(row, Mapping) and _MARKER in str(row.get("command") or "")


class CursorAdapter(ClaudeAdapter):
    """Cursor hook adapter with exact-release, capability-level evidence."""

    descriptor = AdapterDescriptor(
        adapter_id="cursor.cursor.command-hooks",
        provider_family="cursor",
        product_family="cursor",
        adapter_version=_ADAPTER_VERSION,
        deployment_families_supported=(DeploymentFamily.ENDPOINT, DeploymentFamily.RUNTIME),
        enforcement_methods_supported=(ControlMethod.NATIVE_HOOK,),
        event_schema_version="cursor-hooks/documented-unverified-v1",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.EXPERIMENTAL,
        description="Cursor command-hook adapter with signed exact-version local CLI acceptance; managed deployment remains unverified.",
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider="cursor",
        product="cursor",
        provider_version_min=(
            _EXACT_VERIFIED_VERSIONS[0]
            if _EXACT_VERIFIED_VERSIONS
            else "0.0.0"
        ),
        provider_version_max=(
            _EXACT_VERIFIED_VERSIONS[-1]
            if _EXACT_VERIFIED_VERSIONS
            else "0.0.0"
        ),
        exact_verified_versions=_EXACT_VERIFIED_VERSIONS,
        adapter_version=descriptor.adapter_version,
        verification_status=VerificationStatus.EXPERIMENTAL,
        verified_at=(
            _LATEST_ACCEPTANCE.evidence_timestamp
            if _LATEST_ACCEPTANCE
            else None
        ),
        source_reference="repo:docs/evidence/cursor-acceptance-registry.json",
        capabilities={
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE, "discovery"),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.OBSERVE, "identity"),
            CapabilityDimension.PROMPT_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "prompt_control"),
            CapabilityDimension.RESPONSE_CONTROL: _claim(CapabilityLevel.UNAVAILABLE, "response_control"),
            CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "tool_control"),
            CapabilityDimension.MCP_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "mcp_control"),
            CapabilityDimension.COMMAND_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "command_control"),
            CapabilityDimension.FILE_READ_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "file_read_control"),
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
            CapabilityDimension.POST_EXECUTION_VERIFICATION: _claim(CapabilityLevel.UNAVAILABLE, "post_execution_verification"),
            CapabilityDimension.CONFIG_CHANGE_VISIBILITY: _claim(CapabilityLevel.OBSERVE, "config_change_visibility"),
            CapabilityDimension.BACKGROUND_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE, "background_execution_visibility"),
            CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "persistent_side_effect_control"),
            CapabilityDimension.PERSISTENT_SIDE_EFFECT_VISIBILITY: _claim(CapabilityLevel.OBSERVE, "persistent_side_effect_visibility"),
            CapabilityDimension.DELEGATION_CONTROL: _claim(CapabilityLevel.INLINE_BOUND, "delegation_control"),
            CapabilityDimension.CONTAINMENT: _claim(CapabilityLevel.UNAVAILABLE, "containment"),
            CapabilityDimension.BYPASS_DETECTION: _claim(CapabilityLevel.OBSERVE, "bypass_detection"),
            CapabilityDimension.CONFIG_INTEGRITY: _claim(CapabilityLevel.INLINE_BOUND, "config_integrity"),
        },
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=90,
            action_fidelity=90,
            identity_quality=45,
            parameter_fidelity=90,
            target_fidelity=85,
            destination_fidelity=85,
            result_fidelity=50,
            bypass_resistance=55,
            tamper_resistance=75,
            expected_latency_ms=int(
                _LATEST_ACCEPTANCE.measured_callback_p95_ms
                if _LATEST_ACCEPTANCE
                else 4_000
            ),
            availability_profile="exact_version_local_cli_user_hook; enterprise_managed_source_unverified",
            required_permissions=("cursor.hooks.write", "hawk.callback.send"),
            privacy_impact="bounded metadata and stable hashes; no raw prompt, source, result, secret, transcript, or agent thought export",
        ),
        required_permissions=("cursor.hooks.write", "hawk.callback.send"),
        event_semantics=EventSemantics(
            pre_execution_events=(
                "preToolUse",
                "subagentStart",
                "beforeShellExecution",
                "beforeMCPExecution",
                "beforeReadFile",
                "beforeSubmitPrompt",
                "beforeTabFileRead",
            ),
            post_execution_events=(
                "postToolUse",
                "postToolUseFailure",
                "afterShellExecution",
                "afterMCPExecution",
                "afterFileEdit",
                "afterTabFileEdit",
            ),
            normalized_fields=(
                "identity",
                "canonical_parameters",
                "parameter_hash",
                "canonical_target",
                "target_hash",
                "destination_hash",
                "action_correlation",
                "workspace_hash",
                "repository_context",
                "delegation_lineage",
                "secondary_observations",
            ),
            synchronous_decision_mechanism="Cursor command-hook JSON with failClosed security events and real-binary deny precedence",
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(
            StructuredBlindSpot(
                id="cursor.version-mismatch",
                control_dimension=CapabilityDimension.BYPASS_DETECTION,
                scope="Cursor IDE and CLI product versions",
                condition="The detected Cursor Agent CLI version is not exactly 2026.08.11-e8db854",
                impact="Exact-version verified capability claims do not apply and Enforce is ineligible.",
                detection_method="Local signed binary/version inventory and acceptance report",
                mitigation="Pin a reviewed release or run the exact-version acceptance gate.",
                evidence=("repo:docs/evidence/cursor-acceptance-registry.json",),
            ),
            StructuredBlindSpot(
                id="cursor.cloud-partial-hooks",
                control_dimension=CapabilityDimension.BACKGROUND_EXECUTION_VISIBILITY,
                scope="Cursor cloud agents",
                condition="Cloud agents omit session, MCP, Tab and workspace hooks and may begin read-only before hooks load",
                impact="Local native-hook coverage cannot be projected onto cloud execution.",
                detection_method="Execution-location classification and hook heartbeat comparison",
                mitigation="Use enterprise/team cloud hooks and a separate gateway or provider control for missing paths.",
                evidence=("https://cursor.com/docs/hooks#cloud-agent-support",),
            ),
            StructuredBlindSpot(
                id="cursor.project-hook-attacker-control",
                control_dimension=CapabilityDimension.CONFIG_INTEGRITY,
                scope="Project .cursor/hooks.json configuration",
                condition="Repository content can modify project hooks",
                impact="Project configuration cannot establish Hawk root authority.",
                detection_method="Enterprise hook fingerprint, source priority and event heartbeat monitoring",
                mitigation="Deploy the Hawk hook from the enterprise system path using MDM.",
                evidence=("https://cursor.com/docs/hooks#configuration",),
            ),
            StructuredBlindSpot(
                id="cursor-native-endpoint-mcp-noncompositional",
                control_dimension=CapabilityDimension.EXECUTION_CORRELATION,
                scope="Overlapping native, endpoint and MCP telemetry",
                condition="Secondary observations cannot be correlated to the same canonical action",
                impact="Duplicate evaluations or inflated protection claims are possible.",
                detection_method="Canonical correlation and endpoint/MCP observation IDs",
                mitigation="Use Cursor native as action-specific primary and attach endpoint/MCP as secondary observations only.",
                evidence=("repo:apps/api/tests/test_native_control_cursor_adapter.py",),
            ),
            StructuredBlindSpot(
                id="cursor.desktop-and-tab-not-accepted",
                control_dimension=CapabilityDimension.BYPASS_DETECTION,
                scope="Cursor desktop Agent Chat, Tab and application lifecycle",
                condition="The signed desktop package was verified but those interactive runtime paths were not exercised",
                impact="CLI hook evidence cannot be projected onto desktop, Tab or workspace lifecycle actions.",
                detection_method="Surface-specific runtime heartbeat and exact-version acceptance",
                mitigation="Run separate desktop Agent Chat, Tab and workspaceOpen acceptance before promotion.",
                evidence=("repo:docs/evidence/cursor-2026.08.11-e8db854-acceptance-result.json",),
            ),
        ),
        failure_modes=(
            "Cursor binary/version unavailable or unaccepted",
            "Hawk helper removed or changed",
            "signed callback unavailable",
            "hook timeout or invalid JSON",
            "event set reduction or configuration-source drift",
        ),
        supported_installation_modes=(
            "enterprise_mdm",
            "team_cloud_distribution",
            "project_hooks",
            "user_hooks",
        ),
        supported_degradation_modes=(DegradationMode.MONITOR_ONLY, DegradationMode.FAIL_CLOSED),
        execution_evidence_quality=EvidenceQuality.PROVIDER_REPORTED,
        selection_characteristics=SelectionCharacteristics(50, 45, 45, 25, 45),
    )

    def __init__(
        self,
        *,
        helper_path: str = "/Library/Hawk/bin/hawk-native-hook",
        runtime_config_path: str = "/Library/Hawk/etc/native-control.json",
        binary_path: str = "cursor",
        integration_instance_id: str = "cursor-native-hook",
        acceptance_probes: Mapping[str, bool] | None = None,
    ) -> None:
        super().__init__(
            helper_path=helper_path,
            runtime_config_path=runtime_config_path,
            binary_path=binary_path,
            integration_instance_id=integration_instance_id,
            acceptance_probes=acceptance_probes,
        )

    def version_assurance(self, provider_version: str) -> str:
        return _ACCEPTANCE_REGISTRY.assurance(
            str(provider_version or "").strip(),
            adapter_version=self.descriptor.adapter_version,
        )

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
                result = subprocess.run(
                    [str(binary), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                match = re.search(
                    r"\b(\d{4}\.\d{2}\.\d{2}-[0-9A-Za-z]+)\b",
                    f"{result.stdout}\n{result.stderr}",
                )
                version = match.group(1) if result.returncode == 0 and match else "unknown"
            except (OSError, subprocess.SubprocessError):
                available = False
        return {
            "available": available,
            "binary_path": str(binary),
            "provider_version": version,
        }

    def validate_environment(self, detected: Mapping[str, Any]) -> bool:
        return (
            detected.get("available") is True
            and self.version_assurance(
                str(detected.get("provider_version") or "")
            ) == "exact_verified"
        )

    def supported_tool_events(self) -> tuple[str, ...]:
        return ("preToolUse", "postToolUse", "postToolUseFailure")

    def lifecycle_semantics(self) -> dict[str, str]:
        values = {
            "sessionStart": "session_context",
            "sessionEnd": "session_context",
            "preToolUse": "pre_execution_authorization",
            "postToolUse": "provider_reported_execution",
            "postToolUseFailure": "provider_reported_failure",
            "subagentStart": "delegation_authorization",
            "subagentStop": "delegation_context",
            "beforeShellExecution": "pre_execution_authorization",
            "afterShellExecution": "provider_reported_execution",
            "beforeMCPExecution": "pre_execution_authorization",
            "afterMCPExecution": "provider_reported_execution",
            "beforeReadFile": "pre_execution_authorization",
            "afterFileEdit": "provider_reported_execution",
            "beforeSubmitPrompt": "prompt_context_and_control",
            "preCompact": "session_context",
            "stop": "session_context",
            "afterAgentResponse": "provider_reported_response_metadata",
            "afterAgentThought": "metadata_only_never_thought_content",
            "beforeTabFileRead": "pre_execution_authorization",
            "afterTabFileEdit": "provider_reported_execution",
            "workspaceOpen": "workspace_context",
        }
        return values

    def supported_mcp_events(self) -> tuple[str, ...]:
        return ("beforeMCPExecution", "afterMCPExecution", "preToolUse:MCP:*")

    def supported_command_events(self) -> tuple[str, ...]:
        return ("beforeShellExecution", "afterShellExecution", "preToolUse:Shell")

    def supported_file_events(self) -> tuple[str, ...]:
        return ("beforeReadFile", "afterFileEdit", "beforeTabFileRead", "afterTabFileEdit")

    def supports_input_mutation(self) -> bool:
        return False

    def install_plan(self, existing_configuration: Mapping[str, Any]) -> InstallationPlan:
        return InstallationPlan(
            adapter_id=self.descriptor.adapter_id,
            files_or_settings_affected=("/Library/Application Support/Cursor/hooks.json",),
            permissions_required=("cursor.enterprise_hooks.write",),
            existing_configuration_detected=bool(existing_configuration),
            hawk_owned_fragment_key=_MARKER,
            rollback_strategy="remove only command handlers containing the Hawk managed marker",
            restart_required=False,
            estimated_coverage_effect=("Exact-version verified local CLI command, prompt, file-read and MCP controls",),
            known_risks=("Cursor hook failures are fail-open unless failClosed is set per security event",),
        )

    def _entry(self, provider_event: str) -> dict[str, object]:
        command = " ".join(
            (
                shlex.quote(self.helper_path),
                _MARKER,
                "--provider",
                "cursor",
                "--event",
                _EVENTS[provider_event],
                "--config",
                shlex.quote(self.runtime_config_path),
            )
        )
        entry: dict[str, object] = {"command": command, "timeout": 5}
        if provider_event == "preToolUse":
            entry["matcher"] = "^(?!Shell$|Read$|Task$|MCP:).*"
        elif provider_event in {"postToolUse", "postToolUseFailure"}:
            entry["matcher"] = "^(?!Shell$|Read$|Write$|Delete$|Task$|MCP:).*"
        if provider_event in _FAIL_CLOSED_EVENTS:
            entry["failClosed"] = True
        return entry

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

    def install(
        self,
        plan: InstallationPlan,
        existing_configuration: Mapping[str, Any],
    ) -> InstallationResult:
        if plan.adapter_id != self.descriptor.adapter_id or plan.hawk_owned_fragment_key != _MARKER:
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        base = self._without_hawk(existing_configuration)
        configuration = deepcopy(base)
        if configuration.setdefault("version", 1) != 1:
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        hooks = configuration.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        managed: dict[str, object] = {}
        for provider_event in _EVENTS:
            rows = hooks.setdefault(provider_event, [])
            if not isinstance(rows, list):
                raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
            entry = self._entry(provider_event)
            hooks[provider_event] = [entry, *rows]
            managed[provider_event] = entry
        fingerprint = ControlConfigFingerprint(
            integration_instance_id=self.integration_instance_id,
            provider="cursor",
            config_location="/Library/Application Support/Cursor/hooks.json",
            hawk_owned_content_hash=stable_hash(managed),
            surrounding_context_hash=stable_hash(base),
            ordering="enterprise_source_has_highest_merge_priority",
            callback_identity="signed_hawk_native_callback",
            helper_identity=stable_hash(self.helper_path),
            event_subscriptions=tuple(_EVENTS),
            blocking_semantics="failClosed pre-actions with exact-version verified deny precedence",
            version=self.descriptor.adapter_version,
            last_verified=datetime.now(timezone.utc).isoformat(),
        )
        if not self.validate_installation(configuration):
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        return InstallationResult(configuration=configuration, fingerprint=fingerprint)

    def validate_installation(self, configuration: Mapping[str, Any]) -> bool:
        if configuration.get("version") != 1:
            return False
        hooks = configuration.get("hooks")
        if not isinstance(hooks, Mapping):
            return False
        return all(
            isinstance(hooks.get(event), list)
            and bool(hooks[event])
            and hooks[event][0] == self._entry(event)
            and sum(1 for row in hooks[event] if _managed(row)) == 1
            for event in _EVENTS
        )

    def detect_drift(self, configuration: Mapping[str, Any]) -> tuple[str, ...]:
        reasons: list[str] = []
        if configuration.get("version") != 1:
            reasons.append("cursor_hooks_schema_version_invalid")
        hooks = configuration.get("hooks")
        if not isinstance(hooks, Mapping):
            return (*reasons, "cursor_hooks_missing")
        for event in _EVENTS:
            rows = hooks.get(event)
            if not isinstance(rows, list) or not rows or rows[0] != self._entry(event):
                reasons.append(f"hawk_hook_changed:{event}")
            elif sum(1 for row in rows if _managed(row)) != 1:
                reasons.append(f"hawk_hook_count_invalid:{event}")
        return tuple(reasons)

    def normalize_event(
        self,
        raw_payload: Mapping[str, Any],
        context: AdapterPipelineContext,
    ) -> NativeControlEvent:
        if not isinstance(raw_payload, Mapping):
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        provider_event = str(raw_payload.get("hook_event_name") or raw_payload.get("event_type") or "")
        if provider_event == "tool_call":
            provider_event = "preToolUse"
        if provider_event not in _EVENTS:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        tool_name = str(raw_payload.get("tool_name") or provider_event)
        raw_input = raw_payload.get("tool_input")
        if isinstance(raw_input, str):
            try:
                raw_input = json.loads(raw_input)
            except json.JSONDecodeError:
                raw_input = {}
        parameters = dict(raw_input) if isinstance(raw_input, Mapping) else {}
        if provider_event in {"beforeShellExecution", "afterShellExecution"}:
            tool_name = "Shell"
            parameters = {"command": raw_payload.get("command") or parameters.get("command") or ""}
        if provider_event == "subagentStart":
            tool_name = "Task"
        if provider_event in {"beforeReadFile", "beforeTabFileRead"}:
            tool_name = "Read"
            parameters = {"file_path": raw_payload.get("file_path") or ""}
        if provider_event in {"afterFileEdit", "afterTabFileEdit"}:
            tool_name = "Write"
            parameters = {"file_path": raw_payload.get("file_path") or ""}
        normalized_tool = tool_name.strip().lower()
        if provider_event in {"beforeMCPExecution", "afterMCPExecution"} or normalized_tool.startswith("mcp:"):
            action_type = "MCP_TOOL_CALL"
        elif provider_event == "subagentStart":
            action_type = "AGENT_INVOCATION"
        elif provider_event == "beforeSubmitPrompt":
            action_type = "MODEL_REQUEST"
        else:
            action_type = {
                "shell": "COMMAND_EXECUTION",
                "read": "FILE_READ",
                "write": "FILE_WRITE",
                "grep": "FILE_SEARCH",
                "delete": "FILE_WRITE",
                "task": "AGENT_INVOCATION",
            }.get(normalized_tool, "UNKNOWN_TOOL_ACTION")
        parameter_hash = stable_hash(parameters)
        workspace_hash = stable_hash(raw_payload.get("workspace_roots") or [])
        target_hash = stable_hash(
            parameters.get("file_path")
            or parameters.get("path")
            or parameters.get("repo")
            or raw_payload.get("url")
            or raw_payload.get("command")
            or "unknown"
        )
        lifecycle = _EVENTS[provider_event]
        secondary = [
            {
                "source": source,
                "observation_id_hash": stable_hash(raw_payload[key]),
                # Provider payload references are correlation hints only. A
                # Hawk-owned resolver must verify them before coverage use.
                "verified": False,
            }
            for source, key in (
                ("endpoint", "endpoint_observation_id"),
                ("mcp", "mcp_observation_id"),
            )
            if str(raw_payload.get(key) or "").strip()
        ]
        persistent = action_type in {"COMMAND_EXECUTION", "FILE_WRITE", "MCP_TOOL_CALL", "UNKNOWN_TOOL_ACTION"}
        runtime_profile, execution_location, endpoint_execution_authority = _runtime_facts(raw_payload)
        return NativeControlEvent(
            tenant_id=context.tenant_id,
            integration_instance_id=context.integration_instance_id,
            provider="cursor",
            product="cursor",
            raw_provider_event_type=provider_event,
            provider_event_id=context.provider_event_id,
            provider_version=context.provider_version,
            adapter_version=self.descriptor.adapter_version,
            lifecycle_stage=lifecycle,
            actor=dict(context.resolved_actor),
            session={
                "session_id": context.session_id,
                "provider_session_hash": stable_hash(raw_payload.get("conversation_id") or "unknown"),
                "generation_hash": stable_hash(raw_payload.get("generation_id") or "unknown"),
                "workspace_hash": workspace_hash,
                "branch_hash": stable_hash(raw_payload.get("git_branch") or "unknown"),
            },
            runtime={
                "environment": context.environment,
                "credential_id": context.credential_id,
                "correlation_id": context.correlation_id,
                "primary_control_point": "cursor_native_hook",
                "secondary_observations": secondary,
                "runtime_profile": runtime_profile,
                "execution_location": execution_location,
                "endpoint_execution_authority": endpoint_execution_authority,
            },
            tool={"name": tool_name, "version": context.provider_version, "fingerprint_id": stable_hash(tool_name)},
            model={"model_id": str(raw_payload.get("model_id") or raw_payload.get("model") or "unknown")[:255]},
            mcp={"server_id": "unknown", "tool_name": tool_name} if action_type == "MCP_TOOL_CALL" else {},
            action={
                "action_type": action_type,
                "canonical_parameters": {"parameter_hash": parameter_hash},
                "parameter_hash": parameter_hash,
            },
            target={"resource": "hashed_target", "canonical_target": target_hash, "resource_hash": target_hash},
            destination={
                "destination": "mcp" if action_type == "MCP_TOOL_CALL" else "local",
                "destination_hash": stable_hash(raw_payload.get("url") or "local"),
            },
            side_effect_class="persistent_or_external" if persistent else "read_or_context",
            persistence={"persistent_side_effect": persistent},
            provider_correlation={
                "tool_use_hash": stable_hash(raw_payload.get("tool_use_id") or context.correlation_id),
                "chain_id": context.chain_id,
                "correlation_id": context.correlation_id,
                "subagent_id_hash": stable_hash(raw_payload.get("subagent_id") or "unknown"),
                "parent_session_hash": stable_hash(raw_payload.get("parent_conversation_id") or "unknown"),
                "delegation_depth": (
                    int(raw_payload.get("delegation_depth"))
                    if isinstance(raw_payload.get("delegation_depth"), int)
                    and 0 <= int(raw_payload.get("delegation_depth")) <= 64
                    else -1
                ),
            },
            timing={"received_at": context.received_at, "pre_execution": provider_event in _FAIL_CLOSED_EVENTS},
            integrity={
                "transport": context.transport.value,
                "signature_valid": context.signature_valid,
                "provider_account_hash": stable_hash(raw_payload.get("user_email") or "unknown"),
            },
            policy_snapshot_id=context.policy_snapshot_id,
            policy_profile=dict(context.policy_profile),
        )

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision in {"block", "require_second_approval", "redact"}:
            permission = "deny"
            continues = False
        elif response.decision in {"warn", "review", "require_approval"}:
            permission = "ask"
            continues = False
        else:
            permission = "allow"
            continues = True
        return {
            "decision": response.decision,
            "continue": continues,
            "permission": permission,
            **({"user_message": response.reason, "agent_message": response.reason} if permission != "allow" else {}),
        }

    def capture_execution_result(self, provider_result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "quality": EvidenceQuality.PROVIDER_REPORTED.value,
            "tool_use_hash": stable_hash(provider_result.get("tool_use_id") or "unknown"),
            "parameter_hash": stable_hash(provider_result.get("tool_input") or {}),
            "result_hash": stable_hash(provider_result.get("tool_output") or provider_result.get("result") or {}),
            "provider_event_type": str(provider_result.get("hook_event_name") or "postToolUse"),
        }

    def health(self) -> ControlPointHealth:
        return super().health()
