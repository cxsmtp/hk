from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any


_MARKER = "--hawk-managed-hook"
_EVENTS = {
    "gemini_cli": (
        ("SessionStart", "session_start"),
        ("SessionEnd", "session_end"),
        ("BeforeAgent", "before_agent"),
        ("AfterAgent", "after_agent"),
        ("BeforeTool", "before_tool"),
        ("AfterTool", "after_tool"),
        ("BeforeModel", "before_model"),
        ("AfterModel", "after_model"),
        ("BeforeToolSelection", "before_tool_selection"),
        ("PreCompress", "pre_compress"),
        ("Notification", "notification"),
    ),
    "claude_code": (
        ("PreToolUse", "before_tool"),
        ("PermissionRequest", "permission_request"),
        ("PostToolUse", "after_tool"),
        ("PostToolUseFailure", "after_tool_failure"),
        ("UserPromptSubmit", "before_model"),
        ("SubagentStart", "subagent_context_start"),
        ("SubagentStop", "subagent_context_stop"),
        ("SessionStart", "session_start"),
        ("SessionEnd", "session_end"),
        ("ConfigChange", "config_change"),
    ),
    "cursor": (
        ("sessionStart", "session_start"),
        ("sessionEnd", "session_end"),
        ("preToolUse", "before_tool"),
        ("postToolUse", "after_tool"),
        ("postToolUseFailure", "after_tool_failure"),
        ("subagentStart", "subagent_start"),
        ("subagentStop", "subagent_stop"),
        ("beforeShellExecution", "before_shell"),
        ("afterShellExecution", "after_shell"),
        ("beforeMCPExecution", "before_mcp"),
        ("afterMCPExecution", "after_mcp"),
        ("beforeReadFile", "before_file_read"),
        ("afterFileEdit", "after_file_edit"),
        ("beforeSubmitPrompt", "before_model"),
        ("preCompact", "pre_compact"),
        ("stop", "stop"),
        ("afterAgentResponse", "after_agent_response"),
        ("afterAgentThought", "after_agent_thought"),
        ("beforeTabFileRead", "before_file_read"),
        ("afterTabFileEdit", "after_file_edit"),
        ("workspaceOpen", "workspace_open"),
    ),
    "codex": (
        ("SessionStart", "session_start"),
        ("SessionEnd", "session_end"),
        ("PreToolUse", "before_tool"),
        ("PermissionRequest", "permission_request"),
        ("PostToolUse", "after_tool"),
        ("PreCompact", "pre_compact"),
        ("PostCompact", "post_compact"),
        ("UserPromptSubmit", "before_model"),
        ("SubagentStart", "subagent_start"),
        ("SubagentStop", "subagent_stop"),
        ("Stop", "stop"),
        # Codex only allows a 1–3 second timeout for Interrupt. This remains
        # evidence-only: the lifecycle contract cannot cancel the interrupt.
        ("Interrupt", "interrupt"),
    ),
}

_CURSOR_FAIL_CLOSED_EVENTS = frozenset(
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
_CURSOR_CLOUD_EVENTS = frozenset(
    {
        "beforeShellExecution",
        "afterShellExecution",
        "beforeReadFile",
        "afterFileEdit",
        "preToolUse",
        "postToolUse",
        "postToolUseFailure",
        "subagentStart",
        "subagentStop",
        "beforeSubmitPrompt",
        "preCompact",
        "afterAgentResponse",
        "afterAgentThought",
        "stop",
    }
)


@dataclass(frozen=True, slots=True)
class InstallResult:
    provider: str
    settings_path: str
    changed: bool
    fingerprint: str
    events: tuple[str, ...]


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _managed(row: object) -> bool:
    if not isinstance(row, dict):
        return False
    if _MARKER in str(row.get("command") or ""):
        return True
    for hook in row.get("hooks") or []:
        if isinstance(hook, dict) and _MARKER in str(hook.get("command") or ""):
            return True
    return False


def cursor_settings_path(
    scope: str,
    *,
    platform: str | None = None,
    home: Path | str | None = None,
    project_root: Path | str | None = None,
) -> Path:
    """Return only paths documented by Cursor for hook configuration."""

    normalized_scope = str(scope or "").strip().lower()
    platform_name = str(platform or sys.platform).strip().lower()
    if normalized_scope == "user":
        return Path(home or Path.home()).expanduser() / ".cursor" / "hooks.json"
    if normalized_scope == "project":
        if project_root is None:
            raise ValueError("cursor_project_root_required")
        return Path(project_root).expanduser().resolve() / ".cursor" / "hooks.json"
    if normalized_scope not in {"enterprise", "managed"}:
        raise ValueError("cursor_settings_scope_unsupported")
    if platform_name.startswith("darwin"):
        return Path("/Library/Application Support/Cursor/hooks.json")
    if platform_name.startswith("linux"):
        return Path("/etc/cursor/hooks.json")
    if platform_name.startswith(("win", "cygwin")):
        return Path(r"C:\ProgramData\Cursor\hooks.json")
    raise ValueError("cursor_enterprise_settings_platform_unsupported")


def cursor_hook_surface_coverage(event: str, *, cloud_agent: bool) -> dict[str, object]:
    normalized = str(event or "").strip()
    known = {provider_event for provider_event, _ in _EVENTS["cursor"]}
    if normalized not in known:
        return {"native_hook_covered": False, "reason": "cursor_hook_unknown"}
    if cloud_agent and normalized not in _CURSOR_CLOUD_EVENTS:
        return {"native_hook_covered": False, "reason": "cursor_cloud_hook_unsupported"}
    return {
        "native_hook_covered": True,
        "reason": "cursor_cloud_hook_supported" if cloud_agent else "cursor_local_hook_supported",
    }


def claude_settings_path(
    scope: str,
    *,
    platform: str | None = None,
    home: Path | str | None = None,
    project_root: Path | str | None = None,
) -> Path:
    normalized_scope = str(scope or "").strip().lower()
    platform_name = str(platform or sys.platform).strip().lower()
    if normalized_scope == "user":
        return Path(home or Path.home()).expanduser() / ".claude" / "settings.json"
    if normalized_scope in {"project", "local_project"}:
        if project_root is None:
            raise ValueError("claude_project_root_required")
        filename = "settings.local.json" if normalized_scope == "local_project" else "settings.json"
        return Path(project_root).expanduser().resolve() / ".claude" / filename
    if normalized_scope != "managed":
        raise ValueError("claude_settings_scope_unsupported")
    if platform_name.startswith("darwin"):
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    if platform_name.startswith("linux"):
        return Path("/etc/claude-code/managed-settings.json")
    if platform_name.startswith(("win", "cygwin")):
        return Path(r"C:\Program Files\ClaudeCode\managed-settings.json")
    raise ValueError("claude_managed_settings_platform_unsupported")


def gemini_settings_path(
    scope: str,
    *,
    platform: str | None = None,
    home: Path | str | None = None,
    project_root: Path | str | None = None,
) -> Path:
    """Return documented Gemini CLI user, workspace, or system settings paths."""

    normalized_scope = str(scope or "").strip().lower()
    platform_name = str(platform or sys.platform).strip().lower()
    if normalized_scope == "user":
        return Path(home or Path.home()).expanduser() / ".gemini" / "settings.json"
    if normalized_scope == "project":
        if project_root is None:
            raise ValueError("gemini_project_root_required")
        return Path(project_root).expanduser().resolve() / ".gemini" / "settings.json"
    if normalized_scope not in {"managed", "enterprise"}:
        raise ValueError("gemini_settings_scope_unsupported")
    if platform_name.startswith("darwin"):
        return Path("/Library/Application Support/GeminiCli/settings.json")
    if platform_name.startswith("linux"):
        return Path("/etc/gemini-cli/settings.json")
    if platform_name.startswith(("win", "cygwin")):
        return Path(r"C:\ProgramData\gemini-cli\settings.json")
    raise ValueError("gemini_managed_settings_platform_unsupported")


def gemini_managed_launcher_script(
    *,
    binary_path: Path | str,
    system_settings_path: Path | str,
    helper_path: Path | str,
    runtime_config_path: Path | str,
    expected_version: str,
    runtime_path: Path | str | None = None,
) -> str:
    """Render a macOS/Linux MDM launcher with immutable artifact pins.

    The function only renders a deployment artifact. An enterprise MDM remains
    responsible for placing it and the referenced files under administrator
    ownership. Every executable or control file is hash-checked again before
    each launch, and the provider's system-settings override is replaced with
    the exact managed path.
    """

    version = str(expected_version or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("gemini_managed_expected_version_invalid")

    def controlled_file(value: Path | str, label: str, *, executable: bool) -> tuple[Path, str]:
        candidate = Path(value).expanduser()
        if candidate.is_symlink():
            raise ValueError(f"gemini_managed_{label}_symlink")
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError(f"gemini_managed_{label}_unavailable") from exc
        if not resolved.is_file():
            raise ValueError(f"gemini_managed_{label}_unavailable")
        mode = resolved.stat().st_mode
        if mode & 0o022:
            raise ValueError(f"gemini_managed_{label}_writable")
        if executable and not mode & 0o111:
            raise ValueError(f"gemini_managed_{label}_not_executable")
        return resolved, hashlib.sha256(resolved.read_bytes()).hexdigest()

    binary, binary_digest = controlled_file(binary_path, "binary", executable=True)
    if binary.read_bytes()[:128].startswith(b"#!/usr/bin/env ") and runtime_path is None:
        raise ValueError("gemini_managed_runtime_required")
    settings, settings_digest = controlled_file(
        system_settings_path, "system_settings", executable=False
    )
    helper, helper_digest = controlled_file(helper_path, "helper", executable=True)
    config, config_digest = controlled_file(
        runtime_config_path, "runtime_config", executable=False
    )
    runtime: Path | None = None
    runtime_digest = ""
    if runtime_path is not None:
        runtime, runtime_digest = controlled_file(runtime_path, "runtime", executable=True)

    version_command = (
        [str(runtime), str(binary), "--version"]
        if runtime is not None
        else [str(binary), "--version"]
    )
    try:
        with tempfile.TemporaryDirectory(prefix="hawk-gemini-version-") as version_home:
            version_result = subprocess.run(
                version_command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env={
                    "HOME": version_home,
                    "PATH": "/usr/bin:/bin",
                    "NO_COLOR": "1",
                    "CI": "true",
                },
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("gemini_managed_binary_version_unavailable") from exc
    observed_version = re.search(r"\b(\d+\.\d+\.\d+)\b", version_result.stdout)
    if (
        version_result.returncode != 0
        or observed_version is None
        or observed_version.group(1) != version
    ):
        raise ValueError("gemini_managed_binary_version_mismatch")

    assignments = [
        ("HAWK_GEMINI_BINARY", binary, binary_digest),
        ("HAWK_GEMINI_SETTINGS", settings, settings_digest),
        ("HAWK_GEMINI_HELPER", helper, helper_digest),
        ("HAWK_GEMINI_CONFIG", config, config_digest),
    ]
    if runtime is not None:
        assignments.append(("HAWK_GEMINI_RUNTIME", runtime, runtime_digest))
    lines = [
        "#!/bin/sh",
        "# Hawk managed Gemini CLI launcher",
        "# Deploy as administrator-owned mode 0555 through the approved MDM profile.",
        "set -eu",
        f"HAWK_GEMINI_EXPECTED_VERSION={shlex.quote(version)}",
    ]
    for variable, path, digest in assignments:
        lines.extend(
            (
                f"{variable}={shlex.quote(str(path))}",
                f"{variable}_SHA256={shlex.quote(digest)}",
            )
        )
    lines.extend(
        (
            "",
            "hawk_verify_managed_file() {",
            '  hawk_path="$1"',
            '  hawk_expected="$2"',
            '  [ -f "$hawk_path" ] && [ ! -L "$hawk_path" ] || exit 78',
            "  hawk_actual=$(/usr/bin/shasum -a 256 \"$hawk_path\" | /usr/bin/awk '{print $1}')",
            '  [ "$hawk_actual" = "$hawk_expected" ] || exit 78',
            "}",
            "",
        )
    )
    for variable, _path, _digest in assignments:
        lines.append(
            f'hawk_verify_managed_file "${variable}" "${variable}_SHA256"'
        )
    lines.extend(
        (
            "unset GEMINI_CLI_SYSTEM_SETTINGS_PATH",
            'export GEMINI_CLI_SYSTEM_SETTINGS_PATH="$HAWK_GEMINI_SETTINGS"',
        )
    )
    if runtime is None:
        lines.append('exec "$HAWK_GEMINI_BINARY" "$@"')
    else:
        lines.append('exec "$HAWK_GEMINI_RUNTIME" "$HAWK_GEMINI_BINARY" "$@"')
    return "\n".join(lines) + "\n"


def codex_settings_path(
    scope: str,
    *,
    platform: str | None = None,
    home: Path | str | None = None,
    project_root: Path | str | None = None,
) -> Path:
    """Return documented Codex hook or managed-requirements locations."""

    normalized_scope = str(scope or "").strip().lower()
    platform_name = str(platform or sys.platform).strip().lower()
    if normalized_scope == "user":
        return Path(home or Path.home()).expanduser() / ".codex" / "hooks.json"
    if normalized_scope == "project":
        if project_root is None:
            raise ValueError("codex_project_root_required")
        return Path(project_root).expanduser().resolve() / ".codex" / "hooks.json"
    if normalized_scope not in {"managed", "enterprise"}:
        raise ValueError("codex_settings_scope_unsupported")
    if platform_name.startswith(("darwin", "linux")):
        return Path("/etc/codex/requirements.toml")
    if platform_name.startswith(("win", "cygwin")):
        return Path(r"C:\ProgramData\OpenAI\Codex\requirements.toml")
    raise ValueError("codex_managed_settings_platform_unsupported")


def codex_managed_requirements_toml(
    *,
    helper_path: Path | str,
    runtime_config_path: Path | str,
) -> str:
    """Render the bank-safe managed-only Codex requirements fragment.

    This returns a deployment artifact instead of mutating a machine-wide
    requirements file. The enterprise MDM layer remains the authority that
    merges and signs the final administrator configuration.
    """

    helper = Path(helper_path).expanduser().resolve()
    config = Path(runtime_config_path).expanduser().resolve()
    for path, label in ((helper, "helper"), (config, "runtime_config")):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"codex_managed_{label}_unavailable")
        if path.stat().st_mode & 0o022:
            raise ValueError(f"codex_managed_{label}_writable")
    lines = [
        "# Hawk managed Codex native-control requirements",
        "allow_managed_hooks_only = true",
        "",
        "[features]",
        "hooks = true",
        "",
        "[hooks]",
        f"managed_dir = {json.dumps(str(helper.parent))}",
    ]
    matcher_events = {"PreToolUse", "PermissionRequest", "PostToolUse"}
    for provider_event, hawk_event in _EVENTS["codex"]:
        lines.extend(("", f"[[hooks.{provider_event}]]"))
        if provider_event in matcher_events:
            lines.append('matcher = ".*"')
        command = " ".join(
            (
                shlex.quote(str(helper)),
                _MARKER,
                "--provider",
                "codex",
                "--event",
                hawk_event,
                "--config",
                shlex.quote(str(config)),
            )
        )
        lines.extend(
            (
                f"[[hooks.{provider_event}.hooks]]",
                'type = "command"',
                f"command = {json.dumps(command)}",
                f"timeout = {1 if provider_event == 'Interrupt' else 5}",
                'statusMessage = "Checking Hawk AI policy"',
            )
        )
    return "\n".join(lines) + "\n"


def claude_launch_coverage(
    arguments: list[str] | tuple[str, ...],
    *,
    managed_hook_present: bool,
) -> dict[str, object]:
    flags = {str(value).strip() for value in arguments}
    if "--bare" in flags:
        return {"native_hook_covered": False, "reason": "bare_mode_skips_hooks"}
    if "--safe-mode" in flags and not managed_hook_present:
        return {"native_hook_covered": False, "reason": "safe_mode_requires_managed_hook"}
    if "--safe-mode" in flags:
        return {"native_hook_covered": True, "reason": "safe_mode_managed_hook"}
    return {"native_hook_covered": True, "reason": "standard_hook_discovery"}


class NativeHookInstaller:
    def __init__(
        self,
        *,
        provider: str,
        helper_path: Path | str,
        runtime_config_path: Path | str | None = None,
    ) -> None:
        normalized = str(provider or "").strip().lower()
        if normalized not in _EVENTS:
            raise ValueError("unsupported_native_hook_provider")
        helper = Path(helper_path).expanduser().resolve()
        if not helper.is_file() or helper.is_symlink():
            raise ValueError("native_hook_helper_unavailable")
        if helper.stat().st_mode & 0o022:
            raise ValueError("native_hook_helper_is_group_or_world_writable")
        self.provider = normalized
        self.helper_path = helper
        self.runtime_config_path = (
            Path(runtime_config_path).expanduser().resolve() if runtime_config_path else None
        )

    def _entry(self, event: str, provider_event: str | None = None) -> dict[str, object]:
        parts = [
                shlex.quote(str(self.helper_path)),
                _MARKER,
                "--provider",
                self.provider,
                "--event",
                event,
        ]
        if self.runtime_config_path:
            parts.extend(("--config", shlex.quote(str(self.runtime_config_path))))
        command = " ".join(parts)
        if self.provider == "cursor":
            handler: dict[str, object] = {"command": command, "timeout": 5}
            provider_event = next(
                provider_name
                for provider_name, hawk_name in _EVENTS["cursor"]
                if hawk_name == event
            )
            # Several Cursor events share a normalized Hawk lifecycle name.
            # The caller patches the precise provider event below where needed.
            if provider_event in _CURSOR_FAIL_CLOSED_EVENTS:
                handler["failClosed"] = True
            return handler
        handler: dict[str, object] = {
            "type": "command",
            "command": command,
            # Claude uses seconds; Gemini's documented command timeout is ms.
            # Both leave four seconds for Hawk's local callback and a final
            # second to emit the provider-native fail-closed result.
            "timeout": (
                5000
                if self.provider == "gemini_cli"
                else 1
                if self.provider == "codex" and provider_event == "Interrupt"
                else 5
            ),
        }
        if self.provider == "gemini_cli":
            handler.update(
                {
                    "name": "hawk-native-control",
                    "description": "Hawk signed pre/post action governance callback",
                }
            )
        if self.provider == "codex" and provider_event not in {
            "PreToolUse",
            "PermissionRequest",
            "PostToolUse",
        }:
            return {"hooks": [handler]}
        matcher = (
            ".*"
            if self.provider != "gemini_cli" or provider_event in {"BeforeTool", "AfterTool"}
            else "*"
        )
        return {"matcher": matcher, "hooks": [handler]}

    def _cursor_entry(self, provider_event: str, hawk_event: str) -> dict[str, object]:
        parts = [
            shlex.quote(str(self.helper_path)),
            _MARKER,
            "--provider",
            "cursor",
            "--event",
            hawk_event,
        ]
        if self.runtime_config_path:
            parts.extend(("--config", shlex.quote(str(self.runtime_config_path))))
        handler: dict[str, object] = {
            "command": " ".join(parts),
            "timeout": 5,
        }
        # Cursor emits generic tool hooks in addition to action-specific
        # shell/MCP/read/subagent hooks. Partition the known tool families so
        # one action has one pre-action authorization path. Unknown tools stay
        # on preToolUse and remain conservatively classed by Hawk.
        if provider_event == "preToolUse":
            handler["matcher"] = "^(?!Shell$|Read$|Task$|MCP:).*"
        elif provider_event in {"postToolUse", "postToolUseFailure"}:
            handler["matcher"] = "^(?!Shell$|Read$|Write$|Delete$|Task$|MCP:).*"
        if provider_event in _CURSOR_FAIL_CLOSED_EVENTS:
            handler["failClosed"] = True
        return handler

    def _load(self, path: Path) -> tuple[dict[str, Any], int]:
        if path.is_symlink():
            raise ValueError("native_hook_settings_symlink_refused")
        if not path.exists():
            return {}, 0o600
        if not path.is_file():
            raise ValueError("native_hook_settings_not_a_file")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("native_hook_settings_invalid_json") from exc
        if not isinstance(payload, dict):
            raise ValueError("native_hook_settings_invalid_shape")
        return payload, path.stat().st_mode & 0o777

    @staticmethod
    def _write(path: Path, payload: dict[str, Any], mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        encoded = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.hawk-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode & 0o700 or 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _desired(self, current: dict[str, Any]) -> dict[str, Any]:
        desired = json.loads(json.dumps(current))
        if self.provider == "cursor":
            version = desired.setdefault("version", 1)
            if version != 1:
                raise ValueError("cursor_hooks_schema_version_unsupported")
        hooks = desired.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError("native_hook_settings_hooks_invalid")
        for provider_event, hawk_event in _EVENTS[self.provider]:
            existing = hooks.setdefault(provider_event, [])
            if not isinstance(existing, list):
                raise ValueError("native_hook_settings_event_invalid")
            entry = (
                self._cursor_entry(provider_event, hawk_event)
                if self.provider == "cursor"
                else self._entry(hawk_event, provider_event)
            )
            hooks[provider_event] = [entry] + [row for row in existing if not _managed(row)]
        return desired

    def detect_drift(
        self,
        settings_path: Path | str,
        *,
        expected_fingerprint: str | None = None,
    ) -> tuple[str, ...]:
        path = Path(settings_path).expanduser()
        try:
            current, _mode = self._load(path)
        except ValueError as exc:
            return (str(exc),)
        reasons: list[str] = []
        if self.provider == "gemini_cli":
            hooks_config = current.get("hooksConfig")
            if isinstance(hooks_config, dict):
                if hooks_config.get("enabled") is False:
                    reasons.append("native_control_disabled:hooksConfig.enabled")
                disabled = hooks_config.get("disabled")
                if isinstance(disabled, list) and "hawk-native-control" in disabled:
                    reasons.append("native_control_disabled:hawk-native-control")
        if self.provider == "claude_code" and current.get("disableAllHooks") is True:
            reasons.append("native_control_disabled:disableAllHooks")
        if self.provider == "cursor" and current.get("version") != 1:
            reasons.append("cursor_hooks_schema_version_invalid")
        hooks = current.get("hooks")
        if not isinstance(hooks, dict):
            reasons.append("settings_hooks_missing")
        else:
            for provider_event, hawk_event in _EVENTS[self.provider]:
                rows = hooks.get(provider_event)
                expected = (
                    self._cursor_entry(provider_event, hawk_event)
                    if self.provider == "cursor"
                    else self._entry(hawk_event, provider_event)
                )
                managed = [row for row in rows or [] if _managed(row)] if isinstance(rows, list) else []
                if len(managed) != 1:
                    reasons.append(f"hawk_hook_count_invalid:{provider_event}")
                    continue
                if not rows or rows[0] != expected or managed[0] != expected:
                    reasons.append(f"hawk_hook_changed:{provider_event}")
        current_fingerprint = hashlib.sha256(_canonical(current)).hexdigest()
        if expected_fingerprint and current_fingerprint != expected_fingerprint:
            reasons.append("settings_fingerprint_changed")
        return tuple(dict.fromkeys(reasons))

    def validate_installation(
        self,
        settings_path: Path | str,
        *,
        expected_fingerprint: str | None = None,
    ) -> bool:
        return not self.detect_drift(
            settings_path,
            expected_fingerprint=expected_fingerprint,
        )

    def security_conflicts(self, settings_path: Path | str) -> tuple[str, ...]:
        """Report preserved non-Hawk hooks that can alter Gemini security semantics."""

        if self.provider != "gemini_cli":
            return ()
        try:
            current, _mode = self._load(Path(settings_path).expanduser())
        except ValueError as exc:
            return (str(exc),)
        hooks = current.get("hooks")
        if not isinstance(hooks, dict):
            return ("settings_hooks_missing",)
        sensitive_events = (
            "BeforeTool", "AfterTool", "BeforeToolSelection", "BeforeModel", "AfterModel",
        )
        return tuple(
            f"competing_hook:{event}"
            for event in sensitive_events
            if isinstance(hooks.get(event), list)
            and any(not _managed(row) for row in hooks[event])
        )

    def install(self, settings_path: Path | str) -> InstallResult:
        path = Path(settings_path).expanduser()
        current, mode = self._load(path)
        desired = self._desired(current)
        changed = _canonical(current) != _canonical(desired)
        if changed:
            self._write(path, desired, mode)
        return InstallResult(
            provider=self.provider,
            settings_path=str(path),
            changed=changed,
            fingerprint=hashlib.sha256(_canonical(desired)).hexdigest(),
            events=tuple(event for event, _ in _EVENTS[self.provider]),
        )

    def uninstall(self, settings_path: Path | str) -> InstallResult:
        path = Path(settings_path).expanduser()
        current, mode = self._load(path)
        desired = json.loads(json.dumps(current))
        hooks = desired.get("hooks")
        if isinstance(hooks, dict):
            for provider_event, _ in _EVENTS[self.provider]:
                existing = hooks.get(provider_event)
                if not isinstance(existing, list):
                    continue
                remaining = [row for row in existing if not _managed(row)]
                if remaining:
                    hooks[provider_event] = remaining
                else:
                    hooks.pop(provider_event, None)
            if not hooks:
                desired.pop("hooks", None)
        changed = _canonical(current) != _canonical(desired)
        if changed:
            self._write(path, desired, mode)
        return InstallResult(
            provider=self.provider,
            settings_path=str(path),
            changed=changed,
            fingerprint=hashlib.sha256(_canonical(desired)).hexdigest(),
            events=tuple(event for event, _ in _EVENTS[self.provider]),
        )
