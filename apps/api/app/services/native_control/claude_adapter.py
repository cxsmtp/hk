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
    TimeoutBudget,
    stable_hash,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ControlPointHealth,
    DegradationMode,
    HealthState,
    RuntimeLocation,
    SecurityProperties,
    VerificationStatus,
)
from app.services.native_control.claude_acceptance_registry import (
    load_claude_acceptance_registry,
)


_MARKER = "--hawk-managed-hook"
_ADAPTER_VERSION = "1.2.0"
_ACCEPTANCE_REGISTRY = load_claude_acceptance_registry()
_EXACT_VERIFIED_VERSIONS = _ACCEPTANCE_REGISTRY.accepted_versions(
    adapter_version=_ADAPTER_VERSION
)
_SUPPORTED_VERSION_MIN = _EXACT_VERIFIED_VERSIONS[0] if _EXACT_VERIFIED_VERSIONS else "0.0.0"
_SUPPORTED_VERSION_MAX = _EXACT_VERIFIED_VERSIONS[-1] if _EXACT_VERIFIED_VERSIONS else "0.0.0"
_LATEST_ACCEPTANCE = (
    _ACCEPTANCE_REGISTRY.entry(
        _SUPPORTED_VERSION_MAX,
        adapter_version=_ADAPTER_VERSION,
    )
    if _EXACT_VERIFIED_VERSIONS
    else None
)
_EVENTS = {
    "PreToolUse": "before_tool",
    "PermissionRequest": "approval_context",
    "PostToolUse": "after_tool",
    "PostToolUseFailure": "after_tool_failure",
    "UserPromptSubmit": "before_model",
    "SubagentStart": "subagent_context_start",
    "SubagentStop": "subagent_context_stop",
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "ConfigChange": "config_change",
}
_WRITE_TOKENS = frozenset(
    {"create", "delete", "edit", "execute", "merge", "post", "push", "send", "update", "upload", "write"}
)


def _claim(
    level: CapabilityLevel,
    verification_status: VerificationStatus = VerificationStatus.VERIFIED,
) -> CapabilityClaim:
    return CapabilityClaim(
        level=level,
        verification_status=verification_status,
        evidence_refs=(
            "repo:apps/api/tests/test_native_control_claude_adapter.py",
            "repo:apps/endpoint-agent/tests/test_native_hook_installer.py",
            "repo:apps/endpoint-agent/tests/test_native_hook_callback.py",
        ),
    )


def _managed(row: object) -> bool:
    if not isinstance(row, Mapping):
        return False
    return any(
        isinstance(handler, Mapping) and _MARKER in str(handler.get("command") or "")
        for handler in row.get("hooks") or []
    )


class ClaudeAdapter:
    """Claude Code provider adapter over documented command hooks.

    This class owns only provider mechanics. Hawk's callback boundary, policy,
    replay, evidence and control-point selection remain outside the adapter.
    """

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
        adapter_id="anthropic.claude-code.command-hooks",
        provider_family="anthropic",
        product_family="claude_code",
        adapter_version=_ADAPTER_VERSION,
        deployment_families_supported=(DeploymentFamily.ENDPOINT, DeploymentFamily.RUNTIME),
        enforcement_methods_supported=(ControlMethod.NATIVE_HOOK,),
        event_schema_version="claude-code-hooks/runtime-validated-v1",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.PRODUCTION,
        description="Claude Code command-hook adapter with signed Hawk pre/post action callbacks.",
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider="anthropic",
        product="claude_code",
        provider_version_min=_SUPPORTED_VERSION_MIN,
        provider_version_max=_SUPPORTED_VERSION_MAX,
        exact_verified_versions=_EXACT_VERIFIED_VERSIONS,
        adapter_version=descriptor.adapter_version,
        verification_status=VerificationStatus.VERIFIED,
        verified_at=(
            _LATEST_ACCEPTANCE.evidence_timestamp
            if _LATEST_ACCEPTANCE is not None
            else "1970-01-01T00:00:00+00:00"
        ),
        source_reference="repo:docs/evidence/claude-code-acceptance-registry.json",
        capabilities={
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.PROMPT_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.MCP_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.COMMAND_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.FILE_READ_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.FILE_WRITE_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.APPROVAL_CONTROL: _claim(
                CapabilityLevel.EXTERNAL,
                VerificationStatus.EXPERIMENTAL,
            ),
            CapabilityDimension.PROVIDER_PERMISSION_CONTEXT: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.HAWK_APPROVAL_BINDING: _claim(CapabilityLevel.EXTERNAL),
            CapabilityDimension.APPROVAL_CORRELATION: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.PARAMETER_BINDING: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.TARGET_BINDING: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.TOOL_FAILURE_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.EXECUTION_CORRELATION: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.POST_EXECUTION_VERIFICATION: _claim(CapabilityLevel.UNAVAILABLE),
            CapabilityDimension.CONFIG_CHANGE_VISIBILITY: _claim(
                CapabilityLevel.OBSERVE,
                VerificationStatus.EXPERIMENTAL,
            ),
            CapabilityDimension.BACKGROUND_EXECUTION_VISIBILITY: _claim(
                CapabilityLevel.OBSERVE,
                VerificationStatus.EXPERIMENTAL,
            ),
            CapabilityDimension.PERSISTENT_SIDE_EFFECT_VISIBILITY: _claim(
                CapabilityLevel.OBSERVE,
                VerificationStatus.EXPERIMENTAL,
            ),
            CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL: _claim(
                CapabilityLevel.INLINE,
                VerificationStatus.EXPERIMENTAL,
            ),
            CapabilityDimension.DELEGATION_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.CONTAINMENT: _claim(CapabilityLevel.UNAVAILABLE),
            CapabilityDimension.BYPASS_DETECTION: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.CONFIG_INTEGRITY: _claim(CapabilityLevel.INLINE_BOUND),
        },
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=90,
            action_fidelity=95,
            identity_quality=70,
            parameter_fidelity=95,
            target_fidelity=85,
            destination_fidelity=80,
            result_fidelity=65,
            bypass_resistance=65,
            tamper_resistance=85,
            expected_latency_ms=5_000,
            availability_profile="synchronous_local_command_hook",
            required_permissions=("claude.settings.write", "hawk.callback.send"),
            privacy_impact="bounded metadata and stable hashes; no raw prompt, result, or secret export",
        ),
        required_permissions=("claude.settings.write", "hawk.callback.send"),
        event_semantics=EventSemantics(
            pre_execution_events=("PreToolUse", "UserPromptSubmit"),
            post_execution_events=("PostToolUse", "PostToolUseFailure"),
            normalized_fields=(
                "identity",
                "canonical_parameters",
                "parameter_hash",
                "canonical_target",
                "target_hash",
                "destination_hash",
                "action_correlation",
                "execution_result",
            ),
            synchronous_decision_mechanism="Claude Code command hook JSON permissionDecision",
            # Claude runs all matching handlers in parallel. Security comes
            # from documented deny precedence, not an invented first-hook claim.
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(
            StructuredBlindSpot(
                id="anthropic.claude-code.version-mismatch",
                control_dimension=CapabilityDimension.BYPASS_DETECTION,
                scope="Claude Code binary version",
                condition="The detected version is not exactly 2.1.183",
                impact="The adapter is ineligible for Enforce and contributes no protected coverage.",
                detection_method="Signed callback version binding and local binary detection",
                mitigation="Pin 2.1.183 or ship a reviewed exact-version manifest and acceptance report.",
                evidence=("repo:apps/endpoint-agent/tests/test_claude_binary_acceptance.py",),
            ),
            StructuredBlindSpot(
                id="anthropic.claude-code.direct-api-bypass",
                control_dimension=CapabilityDimension.BYPASS_DETECTION,
                scope="Claude activity outside the configured local Claude Code hook runtime",
                condition="A caller uses a direct API, web session, bare/safe mode, or removes user-scoped hooks",
                impact="The action does not traverse this adapter.",
                detection_method="Endpoint discovery and configuration-integrity monitoring",
                mitigation="Use managed settings/MDM plus endpoint or gateway coverage for alternate paths.",
                evidence=("https://code.claude.com/docs/en/hooks",),
            ),
            StructuredBlindSpot(
                id="anthropic.claude-code.parallel-hook-order",
                control_dimension=CapabilityDimension.CONFIG_INTEGRITY,
                scope="Multiple matching PreToolUse handlers",
                condition="Claude executes matching handlers in parallel",
                impact="Hawk cannot claim it executes before another mutating handler.",
                detection_method="Pre/post parameter-hash correlation and managed-fragment fingerprinting",
                mitigation="Rely on deny precedence; alert on input mutation and configuration drift.",
                evidence=("https://code.claude.com/docs/en/hooks",),
            ),
            StructuredBlindSpot(
                id="anthropic.claude-code.provider-permission-not-authorization",
                control_dimension=CapabilityDimension.APPROVAL_CONTROL,
                scope="Interactive PermissionRequest approval lifecycle",
                condition="Claude emits provider permission context independently from Hawk approval state",
                impact="A provider-side allow must never be interpreted as Hawk authorization.",
                detection_method="Exact action-hash correlation across real interactive PreToolUse and PermissionRequest callbacks",
                mitigation="Enforce Hawk approval gates as PreToolUse deny; approve out of band and require an exact-action retry.",
                evidence=("repo:apps/endpoint-agent/tests/test_claude_binary_acceptance.py",),
            ),
        ),
        failure_modes=(
            "Hawk helper removed or modified",
            "signed callback unavailable",
            "settings hook removed or shadowed by safe/bare mode",
            "provider timeout before helper fail-closed response",
        ),
        supported_installation_modes=("user_settings", "project_settings", "managed_settings"),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED,),
        execution_evidence_quality=EvidenceQuality.PROVIDER_REPORTED,
        selection_characteristics=SelectionCharacteristics(45, 35, 30, 25, 35),
        # These are the reviewed static contract bounds. They are deliberately
        # separate from a customer integration's immutable real acceptance,
        # which the signed callback router verifies from persisted evidence.
        supported_action_classes=(
            ActionClass.MODEL_REQUEST,
            ActionClass.COMMAND,
            ActionClass.FILE_READ,
            ActionClass.FILE_WRITE,
            ActionClass.MCP,
            ActionClass.DELEGATION,
        ),
        supported_runtime_locations=(
            RuntimeLocation.LOCAL_ENDPOINT,
            RuntimeLocation.CUSTOMER_RUNTIME,
        ),
        supported_deployment_families=(
            DeploymentFamily.ENDPOINT,
            DeploymentFamily.RUNTIME,
        ),
        supported_runtimes=("claude_code_native_hook",),
        supported_control_methods=(ControlMethod.NATIVE_HOOK,),
        supported_lifecycle_events=(
            "before_tool",
            "approval_context",
            "after_tool",
            "after_tool_failure",
            "before_model",
            "subagent_context_start",
            "subagent_context_stop",
            "session_start",
            "session_end",
            "config_change",
        ),
        reviewed_by="hawk-provider-contract-review",
        reviewed_at="2026-08-20T00:00:00+00:00",
        reviewed_evidence_refs=(
            "repo:apps/api/tests/test_native_control_claude_adapter.py",
            "repo:apps/endpoint-agent/tests/test_native_hook_callback.py",
        ),
    )

    def __init__(
        self,
        *,
        helper_path: str = "/Library/Hawk/bin/hawk-native-hook",
        runtime_config_path: str = "/Library/Hawk/etc/native-control.json",
        binary_path: str = "claude",
        integration_instance_id: str = "claude-native-hook",
        acceptance_probes: Mapping[str, bool] | None = None,
    ) -> None:
        self.helper_path = str(helper_path)
        self.runtime_config_path = str(runtime_config_path)
        self.binary_path = str(binary_path)
        self.integration_instance_id = str(integration_instance_id)
        self._acceptance_probes = {
            name: bool((acceptance_probes or {}).get(name)) for name in self.REQUIRED_PROBES
        }

    def limitations(self) -> tuple[StructuredBlindSpot, ...]:
        return self.manifest.known_blind_spots

    def supported_versions(self) -> tuple[str, str]:
        return self.manifest.provider_version_min, self.manifest.provider_version_max

    def version_assurance(self, provider_version: str) -> str:
        version = str(provider_version or "").strip()
        if version in self.manifest.exact_verified_versions:
            return "exact_verified"
        return "unsupported"

    def supported_tool_events(self) -> tuple[str, ...]:
        return ("PreToolUse", "PermissionRequest", "PostToolUse", "PostToolUseFailure")

    def lifecycle_semantics(self) -> dict[str, str]:
        return {
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

    def supported_mcp_events(self) -> tuple[str, ...]:
        return (
            "PreToolUse:mcp__.*",
            "PermissionRequest:mcp__.*",
            "PostToolUse:mcp__.*",
            "PostToolUseFailure:mcp__.*",
        )

    def supported_command_events(self) -> tuple[str, ...]:
        return ("PreToolUse:Bash", "PostToolUse:Bash")

    def supported_file_events(self) -> tuple[str, ...]:
        return ("PreToolUse:Read|Write|Edit", "PostToolUse:Read|Write|Edit")

    def supports_input_mutation(self) -> bool:
        """Verified v1 never emits updatedInput; mutation cannot be bound safely across parallel hooks."""
        return False

    def decision_deadline_ms(self) -> int:
        return 5_000

    def timeout_budget(self) -> TimeoutBudget:
        return TimeoutBudget(
            provider_timeout_ms=4_000,
            hawk_processing_budget_ms=500,
            response_deadline_ms=5_000,
        )

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
                result = subprocess.run(
                    [str(binary), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                match = re.search(r"\b(\d+\.\d+\.\d+)\b", result.stdout)
                version = match.group(1) if result.returncode == 0 and match else "unknown"
            except (OSError, subprocess.SubprocessError):
                available = False
        return {"available": available, "binary_path": str(binary), "provider_version": version}

    def validate_environment(self, detected: Mapping[str, Any]) -> bool:
        return (
            detected.get("available") is True
            and self.version_assurance(str(detected.get("provider_version") or "")) != "unsupported"
        )

    def _entry(self, provider_event: str) -> dict[str, object]:
        command = " ".join(
            (
                shlex.quote(self.helper_path),
                _MARKER,
                "--provider",
                "claude_code",
                "--event",
                _EVENTS[provider_event],
                "--config",
                shlex.quote(self.runtime_config_path),
            )
        )
        return {
            "matcher": ".*",
            "hooks": [{"type": "command", "command": command, "timeout": 5}],
        }

    def install_plan(self, existing_configuration: Mapping[str, Any]) -> InstallationPlan:
        return InstallationPlan(
            adapter_id=self.descriptor.adapter_id,
            files_or_settings_affected=("~/.claude/settings.json",),
            permissions_required=("claude.settings.write",),
            existing_configuration_detected=bool(existing_configuration),
            hawk_owned_fragment_key=_MARKER,
            rollback_strategy="remove only command handlers containing the Hawk managed marker",
            restart_required=True,
            estimated_coverage_effect=("Claude Code prompt, tool, command, file and MCP lifecycle",),
            known_risks=("matching Claude hooks run in parallel; configuration order is not execution order",),
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

    def install(
        self,
        plan: InstallationPlan,
        existing_configuration: Mapping[str, Any],
    ) -> InstallationResult:
        if plan.adapter_id != self.descriptor.adapter_id or plan.hawk_owned_fragment_key != _MARKER:
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        base = self._without_hawk(existing_configuration)
        configuration = deepcopy(base)
        hooks = configuration.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        managed_fragments: dict[str, object] = {}
        for provider_event in _EVENTS:
            existing = hooks.setdefault(provider_event, [])
            if not isinstance(existing, list):
                raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
            entry = self._entry(provider_event)
            hooks[provider_event] = [entry, *existing]
            managed_fragments[provider_event] = entry
        fingerprint = ControlConfigFingerprint(
            integration_instance_id=self.integration_instance_id,
            provider="anthropic",
            config_location="~/.claude/settings.json",
            hawk_owned_content_hash=stable_hash(managed_fragments),
            surrounding_context_hash=stable_hash(base),
            ordering="listed_first_but_provider_executes_matching_hooks_in_parallel",
            callback_identity="signed_hawk_native_callback",
            helper_identity=stable_hash(self.helper_path),
            event_subscriptions=tuple(_EVENTS),
            blocking_semantics="PreToolUse permissionDecision deny; deny precedence",
            version=self.descriptor.adapter_version,
            last_verified=datetime.now(timezone.utc).isoformat(),
        )
        if not self.validate_installation(configuration):
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        return InstallationResult(configuration=configuration, fingerprint=fingerprint)

    def validate_installation(self, configuration: Mapping[str, Any]) -> bool:
        hooks = configuration.get("hooks")
        if not isinstance(hooks, Mapping):
            return False
        for provider_event in _EVENTS:
            rows = hooks.get(provider_event)
            if not isinstance(rows, list) or not rows or rows[0] != self._entry(provider_event):
                return False
            if sum(1 for row in rows if _managed(row)) != 1:
                return False
        return True

    def configure(self, configuration: Mapping[str, Any]) -> InstallationResult:
        return self.install(self.install_plan(configuration), configuration)

    def verify_integrity(self, configuration: Mapping[str, Any]) -> bool:
        return self.validate_installation(configuration)

    def detect_drift(self, configuration: Mapping[str, Any]) -> tuple[str, ...]:
        hooks = configuration.get("hooks")
        if not isinstance(hooks, Mapping):
            return ("claude_hooks_missing",)
        reasons: list[str] = []
        for provider_event in _EVENTS:
            rows = hooks.get(provider_event)
            if not isinstance(rows, list) or not rows or rows[0] != self._entry(provider_event):
                reasons.append(f"hawk_hook_changed:{provider_event}")
            elif sum(1 for row in rows if _managed(row)) != 1:
                reasons.append(f"hawk_hook_count_invalid:{provider_event}")
        return tuple(reasons)

    def uninstall(self, configuration: Mapping[str, Any]) -> dict[str, Any]:
        return self._without_hawk(configuration)

    def normalize_event(
        self,
        raw_payload: Mapping[str, Any],
        context: AdapterPipelineContext,
    ) -> NativeControlEvent:
        if not isinstance(raw_payload, Mapping):
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        provider_event = str(raw_payload.get("hook_event_name") or raw_payload.get("event_type") or "")
        if provider_event == "tool_call":
            provider_event = "PreToolUse"
        if provider_event not in _EVENTS:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        tool_name = str(raw_payload.get("tool_name") or provider_event)
        tool_input = raw_payload.get("tool_input")
        if not isinstance(tool_input, Mapping):
            tool_input = raw_payload.get("parameters")
        parameters = deepcopy(dict(tool_input)) if isinstance(tool_input, Mapping) else {}
        tool_use_id = str(raw_payload.get("tool_use_id") or context.correlation_id)
        cwd = str(raw_payload.get("cwd") or "unknown")
        permission_mode = str(raw_payload.get("permission_mode") or "unknown")
        target_parts = [
            str(parameters[key])
            for key in ("owner", "repo", "path", "file_path", "url", "resource", "id")
            if key in parameters and isinstance(parameters[key], (str, int))
        ]
        normalized_tool = tool_name.strip().lower()
        mcp_match = re.match(r"^mcp__(.+?)__(.+)$", tool_name)
        mcp_server = mcp_match.group(1) if mcp_match else ""
        mcp_tool = mcp_match.group(2) if mcp_match else ""
        if mcp_match:
            action_type = "MCP_TOOL_CALL"
        else:
            action_type = {
                "bash": "COMMAND_EXECUTION",
                "read": "FILE_READ",
                "write": "FILE_WRITE",
                "edit": "FILE_WRITE",
                "glob": "FILE_SEARCH",
                "grep": "FILE_SEARCH",
                "webfetch": "WEB_FETCH",
                "websearch": "WEB_SEARCH",
                "agent": "AGENT_INVOCATION",
            }.get(normalized_tool, "UNKNOWN_TOOL_ACTION")
        if provider_event == "UserPromptSubmit":
            action_type = "MODEL_REQUEST"
        elif provider_event in {
            "SessionStart",
            "SessionEnd",
            "ConfigChange",
            "SubagentStart",
            "SubagentStop",
        }:
            action_type = "SESSION_CONTEXT"
        if action_type == "COMMAND_EXECUTION":
            target = cwd
        elif action_type in {"FILE_READ", "FILE_WRITE", "FILE_SEARCH"}:
            target = str(parameters.get("file_path") or parameters.get("path") or parameters.get("notebook_path") or cwd)
        else:
            target = str(raw_payload.get("target") or ("/".join(target_parts) if target_parts else tool_name))
        prompt_material = raw_payload.get("prompt")
        if prompt_material is None:
            prompt_material = raw_payload.get("input")
        if prompt_material is None:
            prompt_material = raw_payload.get("messages")
        prompt_hash = str(raw_payload.get("prompt_hash") or "unknown")
        if (
            provider_event == "UserPromptSubmit"
            and prompt_hash.lower() == "unknown"
            and prompt_material is not None
        ):
            prompt_hash = stable_hash(prompt_material)
        tokens = set(re.split(r"[^a-z0-9]+", f"{tool_name} {json.dumps(parameters, default=str)}".lower()))
        persistent = bool(
            action_type in {"COMMAND_EXECUTION", "FILE_WRITE"}
            or tokens & _WRITE_TOKENS
        )
        lifecycle = _EVENTS[provider_event]
        if provider_event in {"SubagentStart", "SubagentStop"}:
            agent_id = str(raw_payload.get("agent_id") or "unknown")
            parent_session = str(raw_payload.get("session_id") or "unknown")
            provider_correlation = {
                "agent_id_hash": str(raw_payload.get("agent_id_hash") or stable_hash(agent_id)),
                "parent_session_hash": str(
                    raw_payload.get("parent_session_hash") or stable_hash(parent_session)
                ),
                "agent_type": str(raw_payload.get("agent_type") or "unknown")[:128],
                "chain_id": context.chain_id,
                "correlation_id": context.correlation_id,
            }
        else:
            provider_correlation = {
                "tool_use_id": tool_use_id,
                "chain_id": context.chain_id,
                "correlation_id": context.correlation_id,
                "agent_id": str(raw_payload.get("agent_id") or "unknown"),
                "agent_type": str(raw_payload.get("agent_type") or "unknown"),
            }
        return NativeControlEvent(
            tenant_id=context.tenant_id,
            integration_instance_id=context.integration_instance_id,
            provider="anthropic",
            product="claude_code",
            raw_provider_event_type=provider_event,
            provider_event_id=context.provider_event_id,
            provider_version=context.provider_version,
            adapter_version=self.descriptor.adapter_version,
            lifecycle_stage=lifecycle,
            actor=dict(context.resolved_actor),
            session={
                "session_id": context.session_id,
                "cwd": cwd,
                "permission_mode": permission_mode,
            },
            runtime={
                "environment": context.environment,
                "credential_id": context.credential_id,
                "correlation_id": context.correlation_id,
            },
            tool={"name": tool_name, "version": context.provider_version, "fingerprint_id": stable_hash(tool_name)},
            model={},
            mcp={"server_id": mcp_server, "tool_name": mcp_tool} if mcp_server else {},
            action={
                "action_type": action_type,
                "canonical_parameters": parameters,
                "parameter_hash": stable_hash(parameters),
                "prompt_hash": prompt_hash,
            },
            target={"resource": target, "canonical_target": target, "resource_hash": stable_hash(target)},
            destination={
                "destination": mcp_server or "local",
                "destination_hash": stable_hash(mcp_server or "local"),
            },
            side_effect_class="persistent_external_write" if persistent else "read_or_unknown",
            persistence={"persistent_side_effect": persistent},
            provider_correlation=provider_correlation,
            timing={"received_at": context.received_at, "pre_execution": lifecycle.startswith("before_")},
            integrity={"transport": context.transport.value, "signature_valid": context.signature_valid},
            policy_snapshot_id=context.policy_snapshot_id,
            policy_profile=dict(context.policy_profile),
        )

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision == "block":
            return {
                "decision": "block",
                "continue": False,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": response.reason,
                },
            }
        if response.decision in {"require_second_approval", "redact"}:
            return {
                "decision": response.decision,
                "continue": False,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": response.reason,
                },
            }
        if response.decision in {"warn", "review", "require_approval"}:
            return {
                "decision": response.decision,
                "continue": False,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": response.reason,
                },
            }
        return {
            "decision": response.decision,
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": response.reason,
            },
        }

    def capture_execution_result(self, provider_result: Mapping[str, Any]) -> dict[str, Any]:
        tool_input = provider_result.get("tool_input")
        parameters = dict(tool_input) if isinstance(tool_input, Mapping) else {}
        response = provider_result.get("tool_response")
        bounded_response = dict(response) if isinstance(response, Mapping) else {"status": "unknown"}
        return {
            "quality": EvidenceQuality.PROVIDER_REPORTED.value,
            "tool_use_id": str(provider_result.get("tool_use_id") or "unknown"),
            "parameter_hash": stable_hash(parameters),
            "result_hash": stable_hash(bounded_response),
            "provider_event_type": str(provider_result.get("hook_event_name") or "PostToolUse"),
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
