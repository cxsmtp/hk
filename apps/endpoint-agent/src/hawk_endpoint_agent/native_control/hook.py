from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from hawk_endpoint_agent.auth.device_key import DEVICE_KEY_ERROR_CODES, DeviceKeyError, build_device_key_provider
from hawk_endpoint_agent.native_control.gemini_serializer import render_gemini_runtime_result
from hawk_endpoint_agent.native_control.repository_guard import classify_file_operation, classify_repository_command


_WRITE_TOKENS = {
    "admin", "create", "delete", "edit", "execute", "insert", "merge", "post",
    "purchase", "remove", "run", "send", "shell", "submit", "update", "upload", "write",
}
_SECRET_PATTERN = re.compile(r"(?:api[_-]?key|password|private[_-]?key|secret|token|sk-[A-Za-z0-9_-]{8,})", re.IGNORECASE)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _repository_event_fields(
    provider: str,
    event: str,
    raw: dict[str, Any],
    tool_name: str,
    tool_input: dict[str, Any],
) -> dict[str, str]:
    normalized_event = str(event or "").strip().lower()
    normalized_tool = str(tool_name or "").strip().lower()
    cwd = str(raw.get("cwd") or tool_input.get("workdir") or os.getcwd())
    decision = None
    evidence_only = normalized_event == "after_file_edit"

    if normalized_event in {"before_shell", "after_shell"}:
        command = raw.get("command") or tool_input.get("command")
        if command:
            decision = classify_repository_command(str(command), cwd)
            evidence_only = normalized_event == "after_shell"
    elif normalized_event == "before_file_read":
        target = raw.get("file_path") or tool_input.get("file_path") or tool_input.get("path")
        decision = classify_file_operation(str(target or ""), cwd, write=False)
    elif normalized_event == "after_file_edit":
        target = raw.get("file_path") or tool_input.get("file_path") or tool_input.get("path")
        decision = classify_file_operation(str(target or ""), cwd, write=True)
    elif normalized_event in {"before_tool", "after_tool", "after_tool_failure"}:
        if normalized_tool in {"bash", "shell", "powershell", "run_shell_command", "run_terminal_command", "exec_command"}:
            command = raw.get("command") or tool_input.get("command") or tool_input.get("cmd")
            if command:
                decision = classify_repository_command(str(command), cwd)
                evidence_only = normalized_event != "before_tool"
        elif normalized_tool in {"read", "read_file", "open_file"}:
            target = tool_input.get("file_path") or tool_input.get("path")
            decision = classify_file_operation(str(target or ""), cwd, write=False)
            evidence_only = normalized_event != "before_tool"
        elif normalized_tool in {"write", "write_file", "edit", "replace", "apply_patch"}:
            target = tool_input.get("file_path") or tool_input.get("path")
            if normalized_tool == "apply_patch" and not target:
                patch_text = tool_input.get("patch") or tool_input.get("input") or tool_input.get("content")
                if isinstance(patch_text, str):
                    matches = re.findall(r"^\*\*\* (?:Update|Add|Delete) File: ([^\r\n]+)$", patch_text, re.MULTILINE)
                    if len(matches) == 1 and "*** Move to:" not in patch_text and "*** Copy to:" not in patch_text:
                        target = matches[0].strip()
            decision = classify_file_operation(str(target or ""), cwd, write=True)
            evidence_only = normalized_event != "before_tool"

    if decision is None:
        return {}
    fields = decision.signed_fields()
    if evidence_only:
        fields["repository_control_resolution"] = "evidence_only"
        fields["repository_operation"] = "UNKNOWN"
    return fields


def _bounded(value: object, maximum: int = 255) -> str:
    return str(value or "")[:maximum]


def normalize_provider_event(provider: str, event: str, raw: dict[str, Any]) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ValueError("provider hook input must be an object")
    normalized_event = str(event or "").strip().lower()
    normalized_provider = str(provider or "").strip().lower()
    tool_name = _bounded(raw.get("tool_name") or raw.get("toolName") or "unknown")
    raw_tool_input = raw.get("tool_input")
    if normalized_provider == "cursor" and isinstance(raw_tool_input, str):
        try:
            decoded_tool_input = json.loads(raw_tool_input)
        except json.JSONDecodeError:
            decoded_tool_input = {}
        tool_input = decoded_tool_input if isinstance(decoded_tool_input, dict) else {}
    else:
        tool_input = raw_tool_input if isinstance(raw_tool_input, dict) else {}
    if normalized_provider == "cursor":
        if normalized_event in {"before_shell", "after_shell"}:
            tool_name = "Shell"
            tool_input = {
                "command": raw.get("command") or tool_input.get("command") or "",
                "working_directory": raw.get("cwd") or tool_input.get("working_directory") or "",
            }
        elif normalized_event in {"before_mcp", "after_mcp"}:
            tool_name = _bounded(raw.get("tool_name") or "MCP")
        elif normalized_event == "before_file_read":
            tool_name = "Read"
            tool_input = {"file_path": raw.get("file_path") or ""}
        elif normalized_event == "after_file_edit":
            tool_name = "Write"
            tool_input = {"file_path": raw.get("file_path") or ""}
        elif normalized_event == "subagent_start":
            tool_name = "Task"
            tool_input = {
                "subagent_type": raw.get("subagent_type") or "unknown",
                "is_parallel_worker": raw.get("is_parallel_worker") is True,
                "task_hash": _hash(raw.get("task") or "unknown"),
            }
    prompt_material = raw.get("prompt") or raw.get("llm_request") or {}
    provider_session = _bounded(
        raw.get("conversation_id")
        or raw.get("session_id")
        or raw.get("sessionId")
        or "unknown",
        512,
    )
    provider_tool_use = _bounded(
        raw.get("tool_use_id") or raw.get("toolUseId") or raw.get("tool_call_id") or "",
        512,
    )
    raw_tool_response = raw.get("tool_response") or raw.get("tool_output") or raw.get("result")
    tool_response = raw_tool_response if raw_tool_response not in (None, "") else {}
    serialized_for_classification = json.dumps(
        {"tool_name": tool_name, "tool_input": tool_input, "prompt": prompt_material},
        sort_keys=True,
        default=str,
    )
    name_tokens = set(re.split(r"[^a-z0-9]+", tool_name.lower()))
    material_tokens = set(re.split(r"[^a-z0-9]+", serialized_for_classification.lower()))
    mcp_match = re.match(r"^mcp__(.+?)__(.+)$", tool_name)
    if normalized_provider == "gemini_cli" and not mcp_match:
        mcp_match = re.match(r"^mcp_([^_]+)_(.+)$", tool_name)
    mcp_server = _bounded(mcp_match.group(1) if mcp_match else "", 255)
    mcp_tool = _bounded(mcp_match.group(2) if mcp_match else "", 255)
    normalized_tool = tool_name.strip().lower()
    if normalized_provider == "cursor" and normalized_event in {"before_mcp", "after_mcp"}:
        canonical_action_type = "MCP_TOOL_CALL"
        mcp_tool = tool_name
    elif mcp_match:
        canonical_action_type = "MCP_TOOL_CALL"
    else:
        canonical_action_type = {
            "bash": "COMMAND_EXECUTION",
            "shell": "COMMAND_EXECUTION",
            "powershell": "COMMAND_EXECUTION",
            "exec_command": "COMMAND_EXECUTION",
            "run_shell_command": "COMMAND_EXECUTION",
            "read": "FILE_READ",
            "read_file": "FILE_READ",
            "write": "FILE_WRITE",
            "write_file": "FILE_WRITE",
            "apply_patch": "FILE_WRITE",
            "edit": "FILE_WRITE",
            "replace": "FILE_WRITE",
            "glob": "FILE_SEARCH",
            "glob_files": "FILE_SEARCH",
            "grep": "FILE_SEARCH",
            "search_file_content": "FILE_SEARCH",
            "webfetch": "WEB_FETCH",
            "web_fetch": "WEB_FETCH",
            "websearch": "WEB_SEARCH",
            "google_web_search": "WEB_SEARCH",
            "agent": "AGENT_INVOCATION",
            "spawn_agent": "AGENT_INVOCATION",
        }.get(normalized_tool, "UNKNOWN_TOOL_ACTION")
    if normalized_event in {"before_model", "before_tool_selection"}:
        canonical_action_type = "MODEL_REQUEST"
    elif normalized_event == "before_agent":
        canonical_action_type = "AGENT_TURN"
    elif normalized_event == "subagent_start":
        canonical_action_type = "AGENT_INVOCATION"
    elif normalized_event in {
        "session_start",
        "session_end",
        "config_change",
        "subagent_context_start",
        "subagent_context_stop",
        "subagent_stop",
        "pre_compact",
        "stop",
        "after_agent_response",
        "after_agent_thought",
        "workspace_open",
        "after_agent",
        "after_model",
        "notification",
        "pre_compress",
        "post_compact",
        "interrupt",
    }:
        canonical_action_type = "SESSION_CONTEXT"
    # Arbitrary command tools are conservatively treated as side-effecting.
    # A remote policy may allow a known read-only command, but the endpoint
    # must never under-classify Bash/PowerShell before authorization.
    observation_only = normalized_event in {
        "session_start",
        "session_end",
        "after_agent",
        "after_model",
        "before_tool_selection",
        "notification",
        "pre_compress",
        "interrupt",
    }
    persistent = False if observation_only else bool(
        canonical_action_type == "UNKNOWN_TOOL_ACTION"
        or name_tokens.intersection({"bash", "powershell", "shell"})
        or canonical_action_type == "FILE_WRITE"
        or name_tokens.intersection(_WRITE_TOKENS)
        or material_tokens.intersection(_WRITE_TOKENS)
    )
    classifications = ["secret"] if _SECRET_PATTERN.search(serialized_for_classification) else []
    cwd = _bounded(raw.get("cwd") or "unknown", 1_024)
    permission_mode = _bounded(raw.get("permission_mode") or "unknown", 64)
    agent_id = _bounded(raw.get("agent_id") or "unknown", 512)
    agent_type = _bounded(raw.get("agent_type") or "unknown", 255)
    # Never synthesize a provider tool-use identifier from session/tool input.
    # That would turn distinct provider lifecycle events into a reusable
    # correlation authority.  If the provider does not expose an exact ID,
    # Hawk binds only the individual signed envelope and requires a fresh
    # authorization for a later PermissionRequest/Post callback.
    execution_status = (
        "failed" if normalized_event == "after_tool_failure"
        else "succeeded" if normalized_event in {
            "after_tool", "after_shell", "after_mcp", "after_file_edit", "after_agent", "after_model"
        }
        else "pending"
    )
    side_effect_class = (
        "unknown" if canonical_action_type == "UNKNOWN_TOOL_ACTION"
        else "persistent" if persistent
        else "read_only_or_unknown"
    )
    tool_class = (
        "local_mcp"
        if canonical_action_type == "MCP_TOOL_CALL"
        else "local_shell"
        if canonical_action_type == "COMMAND_EXECUTION"
        else "apply_patch"
        if normalized_tool == "apply_patch"
        else "agent_as_tool"
        if canonical_action_type == "AGENT_INVOCATION"
        else "codex_tool"
        if normalized_provider == "codex" and canonical_action_type not in {
            "MODEL_REQUEST",
            "SESSION_CONTEXT",
            "UNKNOWN_TOOL_ACTION",
        }
        else "unknown_tool"
    )
    tool_fingerprint_id = _hash({"provider": provider, "tool_name": tool_name})
    parameter_hash = _hash(tool_input)
    target_material = (
        tool_input.get("file_path")
        or tool_input.get("path")
        or tool_input.get("url")
        or tool_input.get("query")
        or cwd
    )
    if normalized_event in {"before_mcp", "after_mcp"}:
        target_material = raw.get("url") or raw.get("command") or tool_name
    target_resource_hash = _hash(target_material)
    repository_fields = _repository_event_fields(
        normalized_provider, normalized_event, raw, tool_name, tool_input
    )
    provider_session_hash = _hash(provider_session)
    provider_tool_use_hash = _hash(provider_tool_use) if provider_tool_use else "unknown"
    # Some native clients do not provide an exact per-prompt/per-tool
    # invocation identifier.  In that case, the callback must not reuse a
    # stable session+tool+parameter hash forever: a previous interrupted
    # pre-execution callback can otherwise leave the API with a pending durable
    # binding and cause every later retry of the same prompt to fail closed.
    #
    # When the provider gives an exact tool_use_id we keep that deterministic
    # binding.  Otherwise we mint a one-callback correlation nonce.  Session,
    # prompt, parameter and resource hashes still preserve audit correlation,
    # but the authority claim is fresh for this signed callback.
    provider_invocation_hash = (
        provider_tool_use_hash
        if provider_tool_use
        else _hash(
            {
                "event": normalized_event,
                "provider": normalized_provider,
                "session": provider_session_hash,
                "nonce": raw.get("event_id") or raw.get("hook_event_id") or secrets.token_urlsafe(24),
            }
        )
    )
    approval_action_hash = _hash(
        {
            "provider_session_hash": provider_session_hash,
            "provider_invocation_hash": provider_invocation_hash,
            # Claude's tool lifecycle describes one invocation. Keep its
            # binding across stages only when an exact tool ID is present;
            # missing IDs retain fresh callback identity and reauthorization.
            "event": (
                "tool_invocation"
                if normalized_provider == "claude_code"
                and provider_tool_use
                and normalized_event in {
                    "before_tool", "permission_request", "after_tool", "after_tool_failure"
                }
                else normalized_event
            ),
            "tool_fingerprint_id": tool_fingerprint_id,
            "parameter_hash": parameter_hash,
            "target_resource_hash": target_resource_hash,
        }
    )
    permission_suggestions = (
        raw.get("permission_suggestions")
        if isinstance(raw.get("permission_suggestions"), list)
        else []
    )
    config_source = (
        _bounded(raw.get("source") or "unknown", 128)
        if normalized_event == "config_change"
        else "unknown"
    )
    config_file_path_hash = (
        _hash(raw.get("file_path") or "unknown")
        if normalized_event == "config_change"
        else "unknown"
    )
    provider_generation = _bounded(raw.get("generation_id") or "unknown", 512)
    workspace_roots = raw.get("workspace_roots") if isinstance(raw.get("workspace_roots"), list) else []
    provider_account = _bounded(raw.get("user_email") or "unknown", 512)
    branch = _bounded(raw.get("git_branch") or "unknown", 1_024)
    subagent_id = _bounded(raw.get("subagent_id") or "unknown", 512)
    parent_session = _bounded(raw.get("parent_conversation_id") or "unknown", 512)
    provider_version = _bounded(raw.get("cursor_version") or raw.get("provider_version") or "unknown", 64)
    llm_request = raw.get("llm_request") if isinstance(raw.get("llm_request"), dict) else {}
    model = _bounded(raw.get("model_id") or raw.get("model") or llm_request.get("model") or "unknown", 255)
    location_hint = str(raw.get("execution_location") or "").strip().lower()
    execution_location = (
        "cloud"
        if raw.get("is_cloud_agent") is True or location_hint == "cloud"
        else "local" if location_hint == "local"
        else "unknown"
    )
    try:
        delegation_depth = int(raw.get("delegation_depth"))
    except (TypeError, ValueError):
        delegation_depth = -1
    if delegation_depth < 0 or delegation_depth > 64:
        delegation_depth = -1
    destination_material = (
        raw.get("url") or raw.get("command") or mcp_server or "local"
        if normalized_event in {"before_mcp", "after_mcp"}
        else mcp_server or "local"
    )
    prompt_hash = _hash(prompt_material)
    if normalized_event == "after_agent_thought":
        # Cursor exposes private reasoning text. It is deliberately reduced to
        # a one-way integrity hash and is never copied into Hawk evidence.
        prompt_hash = _hash(raw.get("text") or raw.get("thought") or "")
    response_material = (
        tool_response
        or raw.get("prompt_response")
        or raw.get("llm_response")
        or raw.get("message")
        or raw.get("details")
        or {}
    )
    original_request_name = raw.get("original_request_name")
    return {
        # This is a privacy-safe endpoint wire schema, not raw provider hook
        # input.  The API must preserve the signed hashes exactly and must not
        # send this payload through an adapter that rehashes missing arguments.
        "callback_schema": "hawk-native-hash-envelope/v1",
        "provider_event_type": normalized_event,
        "action_type": canonical_action_type,
        "tool_class": tool_class,
        "tool_name": tool_name,
        "tool_fingerprint_id": tool_fingerprint_id,
        "parameter_hash": parameter_hash,
        "target_resource": "workspace" if canonical_action_type.startswith("FILE_") else tool_name,
        "target_resource_hash": target_resource_hash,
        "destination": "mcp" if normalized_event in {"before_mcp", "after_mcp"} else (mcp_server or "local"),
        "destination_hash": _hash(destination_material),
        "mcp_server_id": mcp_server or "unknown",
        "mcp_tool_name": mcp_tool or "unknown",
        "tail_call": bool(original_request_name),
        "original_request_name_hash": _hash(original_request_name) if original_request_name else "unknown",
        "persistent_side_effect": persistent,
        "side_effect_class": side_effect_class,
        "prompt_hash": prompt_hash,
        "response_hash": _hash(response_material) if response_material else "unknown",
        "data_classifications": classifications,
        # Provider identifiers are correlation material, never authority. Raw
        # session/tool IDs stay on the endpoint and only stable hashes leave it.
        "provider_session_hash": provider_session_hash,
        # An absent provider tool-use identifier is not an identifier.  Do
        # not export the stable digest of an empty string because it would
        # make unrelated actions appear to share one exact invocation.
        "provider_tool_use_hash": provider_tool_use_hash,
        "approval_action_hash": approval_action_hash,
        "permission_context_present": normalized_event == "permission_request",
        "permission_suggestions_hash": (
            _hash(permission_suggestions)
            if normalized_event == "permission_request"
            else "unknown"
        ),
        # ConfigChange is secondary provider telemetry. The provider source is
        # retained, while the local file path is exported only as a hash.
        "config_source": config_source,
        "config_file_path_hash": config_file_path_hash,
        "workspace_hash": _hash(workspace_roots or cwd),
        **repository_fields,
        "provider_generation_hash": _hash(provider_generation),
        "provider_account_hash": _hash(provider_account),
        "provider_app_version": provider_version,
        "model": model,
        "branch_hash": _hash(branch),
        "subagent_id_hash": _hash(subagent_id),
        "parent_session_hash": _hash(parent_session),
        "subagent_type": _bounded(raw.get("subagent_type") or "unknown", 128),
        "is_parallel_worker": raw.get("is_parallel_worker") is True,
        "execution_location": execution_location,
        "delegation_depth": delegation_depth,
        "permission_mode": permission_mode,
        "agent_id_hash": _hash(agent_id),
        "agent_type": agent_type,
        "run_in_background": tool_input.get("run_in_background") is True,
        "execution_status": execution_status,
        "evidence_quality": "provider_reported" if normalized_event in {
            "after_tool", "after_tool_failure", "after_shell", "after_mcp", "after_file_edit",
            "subagent_context_start", "subagent_context_stop",
            "session_start", "session_end", "after_agent", "after_model",
            "before_tool_selection", "notification", "pre_compress",
            "post_compact",
        } else "none",
        "failure_hash": _hash(raw.get("error")) if normalized_event == "after_tool_failure" else "unknown",
    }


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _configuration(config_path: str | None = None, *, use_environment: bool = True) -> dict[str, object]:
    file_values: dict[str, object] = {}
    if config_path:
        path = Path(config_path).expanduser()
        if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
            raise ValueError("native hook runtime configuration is unavailable or insecure")
        decoded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("native hook runtime configuration is invalid")
        forbidden = [key for key in decoded if "private" in str(key).lower() or "access_token" in str(key).lower()]
        if forbidden:
            raise ValueError("native hook runtime configuration contains forbidden secret material")
        file_values = decoded
        if decoded.get("transport") == "endpoint":
            from .endpoint_broker import endpoint_configuration
            return endpoint_configuration(decoded)
    def value(env_name: str, config_name: str, default: object = "") -> object:
        environment_value = os.environ.get(env_name) if use_environment else None
        return environment_value if environment_value is not None else file_values.get(config_name, default)

    required = {
        "api_url": value("HAWK_NATIVE_API_URL", "api_url"),
        "tenant_id": value("HAWK_NATIVE_TENANT_ID", "tenant_id"),
        "integration_id": value("HAWK_NATIVE_INTEGRATION_ID", "integration_id"),
        "credential_id": value("HAWK_NATIVE_CREDENTIAL_ID", "credential_id"),
        "provider": value("HAWK_NATIVE_PROVIDER", "provider"),
        "product": value("HAWK_NATIVE_PRODUCT", "product"),
        "provider_version": value("HAWK_NATIVE_PROVIDER_VERSION", "provider_version"),
        "adapter_version": value("HAWK_NATIVE_ADAPTER_VERSION", "adapter_version", "1.0.0"),
    }
    missing = sorted(key for key, value in required.items() if not str(value).strip())
    if missing:
        raise ValueError(f"native hook configuration missing: {missing[0]}")
    api_url = str(required["api_url"]).rstrip("/")
    parsed = urlparse(api_url)
    if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("native hook API transport must use HTTPS")
    return {
        **required,
        "api_url": api_url,
        "credential_epoch": int(value("HAWK_NATIVE_CREDENTIAL_EPOCH", "credential_epoch", 1)),
        "environment": value("HAWK_NATIVE_ENVIRONMENT", "environment", "production"),
        "key_provider": value("HAWK_NATIVE_KEY_PROVIDER", "key_provider", "kms_hsm_helper"),
        "security_profile": value("HAWK_AGENT_SECURITY_PROFILE", "security_profile", "bank"),
        "kms_hsm_helper_path": value(
            "HAWK_NATIVE_KMS_HELPER_PATH",
            "kms_hsm_helper_path",
            "unix:///var/run/hawk/kms-signer.sock",
        ),
        "kms_hsm_key_reference": value("HAWK_NATIVE_KMS_KEY_REFERENCE", "kms_hsm_key_reference"),
        "secure_enclave_helper_path": value(
            "HAWK_AGENT_IDENTITY_HELPER_PATH", "secure_enclave_helper_path",
            "~/Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity",
        ),
        "secure_enclave_key_tag": value("HAWK_AGENT_KEY_TAG", "secure_enclave_key_tag", "com.hawk.endpoint-agent.device-key"),
        "gemini_block_transport": value(
            "HAWK_GEMINI_BLOCK_TRANSPORT", "gemini_block_transport", "json"
        ),
    }


def _signed_callback(config: dict[str, object], event: str, provider_event: dict[str, object]) -> dict[str, str]:
    provider = build_device_key_provider(
        provider_name=str(config["key_provider"]),
        security_profile=str(config["security_profile"]),
        helper_path=str(config["secure_enclave_helper_path"]),
        key_tag=str(config["secure_enclave_key_tag"]),
        kms_hsm_helper_path=str(config["kms_hsm_helper_path"]),
        kms_hsm_key_reference=str(config["kms_hsm_key_reference"]),
    )
    now = datetime.now(timezone.utc)
    payload = _canonical(provider_event)
    event_id = secrets.token_urlsafe(24)
    provider_tool_use_hash = str(provider_event.get("provider_tool_use_hash") or "")
    provider_session_hash = str(provider_event.get("provider_session_hash") or "")
    approval_action_hash = str(provider_event.get("approval_action_hash") or "")
    correlation_id = approval_action_hash or provider_tool_use_hash or event_id
    session_id = provider_session_hash or secrets.token_urlsafe(18)
    envelope: dict[str, object] = {
        "event_id": event_id,
        "integration_instance_id": str(config["integration_id"]),
        "tenant_binding": str(config["tenant_id"]),
        "provider": str(config["provider"]),
        "product": str(config["product"]),
        "provider_event_id": correlation_id,
        "provider_event_type": event,
        "provider_version": str(config["provider_version"]),
        "adapter_version": str(config["adapter_version"]),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=30)).isoformat(),
        "nonce": secrets.token_urlsafe(24),
        "session_id": session_id,
        "chain_id": session_id,
        "correlation_id": correlation_id,
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "canonical_action_hash": None,
        "credential_id": str(config["credential_id"]),
        "credential_epoch": int(config["credential_epoch"]),
        "signature_algorithm": "ES256",
    }
    envelope["signature"] = _b64url(provider.sign(_canonical(envelope)))
    return {
        "envelope_base64": base64.b64encode(_canonical(envelope)).decode("ascii"),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }


def _post_callback(config: dict[str, object], body: dict[str, str]) -> dict[str, Any]:
    target = f"{config['api_url']}/native-controls/callbacks/{config['integration_id']}"
    outgoing = urlrequest.Request(
        target,
        data=_canonical(body),
        headers={"Content-Type": "application/json", "User-Agent": "hawk-native-hook/1.0"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(outgoing, timeout=4.0) as response:
            decoded = json.loads(response.read(65_536).decode("utf-8"))
    except (OSError, urlerror.URLError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("Hawk native callback unavailable") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("Hawk native callback returned an invalid response")
    return decoded


def provider_hook_output(provider: str, event: str, decision: dict[str, Any]) -> dict[str, Any]:
    normalized_provider = str(provider or "").strip().lower()
    normalized_event = str(event or "").strip().lower()
    hawk_decision = str(decision.get("decision") or "allow").strip().lower()
    enforced = decision.get("enforced") is True
    blocked = hawk_decision == "block" and enforced
    reason = str(decision.get("reason") or "Blocked by Hawk policy")
    if normalized_event not in {
        "before_tool",
        "before_agent",
        "permission_request",
        "before_model",
        "config_change",
        "before_shell",
        "before_mcp",
        "before_file_read",
        "subagent_start",
    }:
        return {}
    if normalized_provider == "gemini_cli":
        restrictive = enforced and hawk_decision in {
            "block",
            "review",
            "require_approval",
            "require_second_approval",
            "redact",
        }
        if normalized_event not in {"before_tool", "before_agent", "before_model"}:
            return {}
        if restrictive:
            return {
                "decision": "deny",
                "reason": reason,
                "systemMessage": "Hawk blocked this action before execution.",
            }
        return {"decision": "allow", "systemMessage": "Hawk governed this action."}
    if normalized_provider == "claude_code":
        if normalized_event == "permission_request":
            denied = enforced and hawk_decision in {
                "block",
                "review",
                "require_approval",
                "require_second_approval",
                "redact",
            }
            payload: dict[str, Any] = {"behavior": "deny" if denied else "allow"}
            if denied:
                payload["message"] = reason
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": payload,
                }
            }
        if normalized_event == "before_tool":
            if blocked:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }
            if enforced and hawk_decision in {
                "review",
                "require_approval",
                "require_second_approval",
                "redact",
            }:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }
            if enforced and hawk_decision == "warn":
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": reason,
                    }
                }
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": "Allowed by Hawk policy",
                }
            }
        return {"decision": "block", "reason": reason} if blocked else {}
    if normalized_provider == "codex":
        restrictive = enforced and hawk_decision in {
            "block",
            "review",
            "require_approval",
            "require_second_approval",
            "redact",
        }
        if normalized_event == "permission_request":
            payload: dict[str, Any] = {"behavior": "deny" if restrictive else "allow"}
            if restrictive:
                payload["message"] = reason
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": payload,
                }
            }
        if normalized_event == "before_tool":
            if restrictive:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }
            output: dict[str, Any] = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                }
            }
            if enforced and hawk_decision == "warn":
                output["hookSpecificOutput"]["additionalContext"] = reason
            return output
        if normalized_event == "before_model":
            return {"decision": "block", "reason": reason} if restrictive else {}
        # SubagentStart cannot be stopped by its hook contract, and post hooks
        # cannot undo an action. They remain evidence-only.
        return {}
    if normalized_provider == "cursor":
        restrictive = enforced and hawk_decision in {
            "block",
            "review",
            "require_approval",
            "require_second_approval",
            "redact",
        }
        if normalized_event == "before_model":
            return {
                "continue": not restrictive,
                **({"user_message": reason} if restrictive else {}),
            }
        if normalized_event in {"before_tool", "before_file_read", "subagent_start"}:
            # Cursor documents that ask is accepted but is not enforced for
            # preToolUse, while file-read and subagent contracts document only
            # allow/deny. Approval-strength decisions therefore remain deny.
            permission = "deny" if restrictive else "allow"
        elif restrictive and hawk_decision == "block":
            permission = "deny"
        elif restrictive:
            permission = "ask"
        elif enforced and hawk_decision == "warn":
            permission = "ask"
        else:
            permission = "allow"
        output: dict[str, Any] = {"permission": permission}
        if permission != "allow":
            output["user_message"] = reason
            if normalized_event not in {"before_file_read", "subagent_start"}:
                output["agent_message"] = reason
        return output
    raise ValueError("unsupported_native_hook_provider")


def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--hawk-managed-hook", action="store_true")
    parser.add_argument(
        "--provider",
        required=True,
        choices=("gemini_cli", "claude_code", "cursor", "codex"),
    )
    parser.add_argument(
        "--event",
        required=True,
        choices=(
            "before_tool",
            "before_agent",
            "permission_request",
            "after_tool",
            "after_tool_failure",
            "after_agent",
            "before_model",
            "after_model",
            "before_tool_selection",
            "session_start",
            "session_end",
            "config_change",
            "before_shell",
            "after_shell",
            "before_mcp",
            "after_mcp",
            "before_file_read",
            "after_file_edit",
            "subagent_start",
            "subagent_stop",
            "subagent_context_start",
            "subagent_context_stop",
            "pre_compact",
            "stop",
            "after_agent_response",
            "after_agent_thought",
            "workspace_open",
            "pre_compress",
            "post_compact",
            "notification",
            "interrupt",
        ),
    )
    parser.add_argument("--config")
    args = parser.parse_args()
    diagnostic = ""
    block_transport = os.environ.get("HAWK_GEMINI_BLOCK_TRANSPORT", "json")
    try:
        raw_bytes = sys.stdin.buffer.read(1_048_577)
        if len(raw_bytes) > 1_048_576:
            raise ValueError("provider hook input too large")
        raw = json.loads(raw_bytes.decode("utf-8"))
        config = _configuration(args.config)
        expected_provider = {
            "gemini_cli": "google",
            "claude_code": "anthropic",
            "cursor": "cursor",
            "codex": "openai",
        }[args.provider]
        if str(config["provider"]).strip().lower() != expected_provider:
            raise ValueError("native hook provider binding mismatch")
        block_transport = str(config.get("gemini_block_transport") or block_transport)
        if config.get("transport") == "endpoint":
            from .endpoint_broker import query_endpoint, hook_output
            decision = query_endpoint(config, args.provider, args.event, raw)
            output = hook_output(args.provider, args.event, decision)
        else:
            provider_event = normalize_provider_event(args.provider, args.event, raw)
            decision = _post_callback(config, _signed_callback(config, args.event, provider_event))
            output = provider_hook_output(args.provider, args.event, decision)
    except Exception as exc:
        diagnostic = "Hawk native control failed closed"
        if os.environ.get("HAWK_NATIVE_ACCEPTANCE_DEBUG") == "1":
            diagnostic = f"{diagnostic}:{type(exc).__name__}"
            if isinstance(exc, DeviceKeyError) and exc.code in DEVICE_KEY_ERROR_CODES:
                diagnostic = f"{diagnostic}:{exc.code}"
        if args.event in {
            "before_tool",
            "before_agent",
            "permission_request",
            "before_model",
            "config_change",
            "before_shell",
            "before_mcp",
            "before_file_read",
            "subagent_start",
        }:
            output = provider_hook_output(
                args.provider,
                args.event,
                {"decision": "block", "reason": "Hawk policy service unavailable (fail closed)", "enforced": True},
            )
        else:
            output = {}
    if args.provider == "gemini_cli":
        result = render_gemini_runtime_result(
            args.event,
            output,
            diagnostic=diagnostic,
            block_transport=block_transport,
        )
        if result.stderr:
            sys.stderr.write(result.stderr)
            sys.stderr.flush()
        if result.stdout:
            sys.stdout.write(result.stdout)
            sys.stdout.flush()
        if result.exit_code:
            raise SystemExit(result.exit_code)
        return
    if diagnostic and os.environ.get("HAWK_NATIVE_ACCEPTANCE_DEBUG") == "1":
        sys.stderr.write(f"{diagnostic}\n")
        sys.stderr.flush()
    sys.stdout.write(json.dumps(output, sort_keys=True, separators=(",", ":")))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
