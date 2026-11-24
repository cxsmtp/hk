from __future__ import annotations

import json
from pathlib import Path
import subprocess

from hawk_endpoint_agent.native_control.installer import (
    NativeHookInstaller,
    claude_launch_coverage,
    claude_settings_path,
    gemini_managed_launcher_script,
    gemini_settings_path,
)


def test_claude_scope_paths_and_bypass_truth_are_explicit(tmp_path: Path) -> None:
    assert claude_settings_path("user", platform="darwin", home=tmp_path) == tmp_path / ".claude/settings.json"
    assert claude_settings_path("project", platform="darwin", project_root=tmp_path) == tmp_path / ".claude/settings.json"
    assert claude_settings_path("local_project", platform="darwin", project_root=tmp_path) == tmp_path / ".claude/settings.local.json"
    assert str(claude_settings_path("managed", platform="darwin")) == "/Library/Application Support/ClaudeCode/managed-settings.json"
    assert str(claude_settings_path("managed", platform="linux")) == "/etc/claude-code/managed-settings.json"
    assert str(claude_settings_path("managed", platform="win32")) == "C:\\Program Files\\ClaudeCode\\managed-settings.json"

    assert claude_launch_coverage([], managed_hook_present=False) == {
        "native_hook_covered": True,
        "reason": "standard_hook_discovery",
    }
    assert claude_launch_coverage(["--safe-mode"], managed_hook_present=True)["native_hook_covered"] is True
    assert claude_launch_coverage(["--safe-mode"], managed_hook_present=False) == {
        "native_hook_covered": False,
        "reason": "safe_mode_requires_managed_hook",
    }
    assert claude_launch_coverage(["--bare"], managed_hook_present=True) == {
        "native_hook_covered": False,
        "reason": "bare_mode_skips_hooks",
    }


def test_gemini_installer_is_atomic_idempotent_and_preserves_other_hooks(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"theme": "dark", "hooks": {"BeforeTool": [{"matcher": "read_file", "hooks": [{"type": "command", "command": "other-hook"}]}]}}),
        encoding="utf-8",
    )
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    installer = NativeHookInstaller(provider="gemini_cli", helper_path=helper)

    first = installer.install(settings)
    second = installer.install(settings)
    payload = json.loads(settings.read_text(encoding="utf-8"))

    assert first.fingerprint == second.fingerprint
    assert payload["theme"] == "dark"
    assert sum("--hawk-managed-hook" in str(row) for row in payload["hooks"]["BeforeTool"]) == 1
    assert any(row.get("matcher") == "read_file" for row in payload["hooks"]["BeforeTool"])
    assert {
        "SessionStart",
        "SessionEnd",
        "BeforeAgent",
        "AfterAgent",
        "BeforeModel",
        "AfterModel",
        "BeforeToolSelection",
        "BeforeTool",
        "AfterTool",
        "PreCompress",
        "Notification",
    } == set(payload["hooks"])
    assert payload["hooks"]["BeforeTool"][0]["matcher"] == ".*"
    assert payload["hooks"]["AfterTool"][0]["matcher"] == ".*"
    assert payload["hooks"]["SessionStart"][0]["matcher"] == "*"
    assert payload["hooks"]["BeforeTool"][0]["hooks"][0]["timeout"] == 5000

    installer.uninstall(settings)
    restored = json.loads(settings.read_text(encoding="utf-8"))
    assert restored["theme"] == "dark"
    assert restored["hooks"]["BeforeTool"] == payload["hooks"]["BeforeTool"][1:]
    assert "AfterTool" not in restored["hooks"]


def test_gemini_documented_user_project_and_system_paths_are_explicit(tmp_path: Path) -> None:
    assert gemini_settings_path("user", platform="darwin", home=tmp_path) == tmp_path / ".gemini/settings.json"
    assert gemini_settings_path("project", platform="darwin", project_root=tmp_path) == tmp_path / ".gemini/settings.json"
    assert str(gemini_settings_path("managed", platform="darwin")) == "/Library/Application Support/GeminiCli/settings.json"
    assert str(gemini_settings_path("enterprise", platform="linux")) == "/etc/gemini-cli/settings.json"
    assert str(gemini_settings_path("managed", platform="win32")) == "C:\\ProgramData\\gemini-cli\\settings.json"


def test_gemini_managed_launcher_pins_every_executable_control_artifact(tmp_path: Path) -> None:
    binary = tmp_path / "gemini-0.54.4"
    helper = tmp_path / "hawk-native-hook"
    settings = tmp_path / "settings.json"
    runtime = tmp_path / "runtime.json"
    binary.write_text("#!/bin/sh\necho 0.54.4\n", encoding="utf-8")
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    settings.write_text("{}\n", encoding="utf-8")
    runtime.write_text("{}\n", encoding="utf-8")
    binary.chmod(0o500)
    helper.chmod(0o500)
    settings.chmod(0o600)
    runtime.chmod(0o600)

    rendered = gemini_managed_launcher_script(
        binary_path=binary,
        system_settings_path=settings,
        helper_path=helper,
        runtime_config_path=runtime,
        expected_version="0.54.4",
    )

    assert rendered.startswith("#!/bin/sh\n# Hawk managed Gemini CLI launcher")
    assert 'export GEMINI_CLI_SYSTEM_SETTINGS_PATH="$HAWK_GEMINI_SETTINGS"' in rendered
    assert 'exec "$HAWK_GEMINI_BINARY" "$@"' in rendered
    assert "sha256" in rendered.lower()
    assert str(binary.resolve()) in rendered
    assert "command -v gemini" not in rendered
    assert "${PATH}" not in rendered


def test_gemini_managed_launcher_refuses_symlink_or_writable_control_artifact(tmp_path: Path) -> None:
    binary = tmp_path / "gemini"
    helper = tmp_path / "helper"
    settings = tmp_path / "settings.json"
    runtime = tmp_path / "runtime.json"
    for path in (binary, helper, settings, runtime):
        path.write_text("safe", encoding="utf-8")
        path.chmod(0o600)
    binary.chmod(0o500)
    helper.chmod(0o622)

    import pytest

    with pytest.raises(ValueError, match="gemini_managed_helper_writable"):
        gemini_managed_launcher_script(
            binary_path=binary,
            system_settings_path=settings,
            helper_path=helper,
            runtime_config_path=runtime,
            expected_version="0.54.4",
        )


def test_gemini_managed_launcher_executes_pinned_binary_and_stops_on_tamper(tmp_path: Path) -> None:
    binary = tmp_path / "gemini"
    helper = tmp_path / "helper"
    settings = tmp_path / "settings.json"
    runtime = tmp_path / "runtime.json"
    launcher = tmp_path / "hawk-gemini"
    binary.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then echo 0.54.4; exit 0; fi\n"
        "printf 'managed:%s' \"$1\"\n",
        encoding="utf-8",
    )
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    settings.write_text("{}\n", encoding="utf-8")
    runtime.write_text("{}\n", encoding="utf-8")
    binary.chmod(0o500)
    helper.chmod(0o500)
    settings.chmod(0o600)
    runtime.chmod(0o600)
    launcher.write_text(
        gemini_managed_launcher_script(
            binary_path=binary,
            system_settings_path=settings,
            helper_path=helper,
            runtime_config_path=runtime,
            expected_version="0.54.4",
        ),
        encoding="utf-8",
    )
    launcher.chmod(0o500)

    allowed = subprocess.run(
        [str(launcher), "argument"], capture_output=True, text=True, check=False
    )
    assert allowed.returncode == 0
    assert allowed.stdout == "managed:argument"

    settings.write_text('{"tampered":true}\n', encoding="utf-8")
    settings.chmod(0o600)
    refused = subprocess.run(
        [str(launcher), "argument"], capture_output=True, text=True, check=False
    )
    assert refused.returncode == 78


def test_gemini_managed_launcher_requires_pinned_runtime_for_env_shebang(tmp_path: Path) -> None:
    binary = tmp_path / "gemini.js"
    helper = tmp_path / "helper"
    settings = tmp_path / "settings.json"
    runtime = tmp_path / "runtime.json"
    binary.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    settings.write_text("{}\n", encoding="utf-8")
    runtime.write_text("{}\n", encoding="utf-8")
    binary.chmod(0o500)
    helper.chmod(0o500)
    settings.chmod(0o600)
    runtime.chmod(0o600)

    import pytest

    with pytest.raises(ValueError, match="gemini_managed_runtime_required"):
        gemini_managed_launcher_script(
            binary_path=binary,
            system_settings_path=settings,
            helper_path=helper,
            runtime_config_path=runtime,
            expected_version="0.54.4",
        )


def test_gemini_managed_launcher_rejects_mislabeled_binary_version(tmp_path: Path) -> None:
    binary = tmp_path / "gemini"
    helper = tmp_path / "helper"
    settings = tmp_path / "settings.json"
    runtime = tmp_path / "runtime.json"
    binary.write_text("#!/bin/sh\necho 0.54.5\n", encoding="utf-8")
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    settings.write_text("{}\n", encoding="utf-8")
    runtime.write_text("{}\n", encoding="utf-8")
    binary.chmod(0o500)
    helper.chmod(0o500)
    settings.chmod(0o600)
    runtime.chmod(0o600)

    import pytest

    with pytest.raises(ValueError, match="gemini_managed_binary_version_mismatch"):
        gemini_managed_launcher_script(
            binary_path=binary,
            system_settings_path=settings,
            helper_path=helper,
            runtime_config_path=runtime,
            expected_version="0.54.4",
        )


def test_gemini_installer_detects_global_and_named_hook_disable(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    installer = NativeHookInstaller(provider="gemini_cli", helper_path=helper)
    installer.install(settings)

    payload = json.loads(settings.read_text(encoding="utf-8"))
    payload["hooksConfig"] = {"enabled": False, "disabled": ["hawk-native-control"]}
    settings.write_text(json.dumps(payload), encoding="utf-8")

    reasons = installer.detect_drift(settings)
    assert "native_control_disabled:hooksConfig.enabled" in reasons
    assert "native_control_disabled:hawk-native-control" in reasons


def test_gemini_installer_detects_event_tamper_and_uninstalls_only_hawk(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    customer = {
        "matcher": "write_file",
        "hooks": [{"name": "customer", "type": "command", "command": "/opt/customer/hook", "timeout": 3000}],
    }
    settings.write_text(json.dumps({"hooks": {"BeforeTool": [customer]}}), encoding="utf-8")
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    installer = NativeHookInstaller(provider="gemini_cli", helper_path=helper)
    installed = installer.install(settings)

    payload = json.loads(settings.read_text(encoding="utf-8"))
    payload["hooks"]["BeforeTool"][0]["hooks"][0]["timeout"] = 60000
    settings.write_text(json.dumps(payload), encoding="utf-8")
    assert "hawk_hook_changed:BeforeTool" in installer.detect_drift(
        settings, expected_fingerprint=installed.fingerprint
    )

    installer.install(settings)
    installer.uninstall(settings)
    restored = json.loads(settings.read_text(encoding="utf-8"))
    assert restored == {"hooks": {"BeforeTool": [customer]}}


def test_gemini_installer_flags_competing_security_hooks_without_deleting_them(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    customer = {
        "matcher": ".*",
        "hooks": [{"name": "customer", "type": "command", "command": "/opt/customer/hook", "timeout": 3000}],
    }
    settings.write_text(json.dumps({"hooks": {"BeforeTool": [customer]}}), encoding="utf-8")
    installer = NativeHookInstaller(provider="gemini_cli", helper_path=helper)
    installer.install(settings)

    assert installer.security_conflicts(settings) == ("competing_hook:BeforeTool",)
    installer.uninstall(settings)
    assert json.loads(settings.read_text(encoding="utf-8"))["hooks"]["BeforeTool"] == [customer]


def test_claude_installer_uses_documented_authorization_evidence_context_and_integrity_hooks(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)

    result = NativeHookInstaller(provider="claude_code", helper_path=helper).install(settings)
    payload = json.loads(settings.read_text(encoding="utf-8"))

    assert result.changed is True
    assert {
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PostToolUseFailure",
        "UserPromptSubmit",
        "SubagentStart",
        "SubagentStop",
        "SessionStart",
        "SessionEnd",
        "ConfigChange",
    } == set(payload["hooks"])
    assert payload["hooks"]["PreToolUse"][0]["matcher"] == ".*"
    assert "--event before_tool" in payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "--event subagent_context_start" in payload["hooks"]["SubagentStart"][0]["hooks"][0]["command"]
    assert "--event subagent_context_stop" in payload["hooks"]["SubagentStop"][0]["hooks"][0]["command"]
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == 5


def test_claude_installer_detects_global_hook_disable_as_bypass(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    installer = NativeHookInstaller(provider="claude_code", helper_path=helper)
    installer.install(settings)
    payload = json.loads(settings.read_text(encoding="utf-8"))
    payload["disableAllHooks"] = True
    settings.write_text(json.dumps(payload), encoding="utf-8")

    assert "native_control_disabled:disableAllHooks" in installer.detect_drift(settings)
    assert installer.validate_installation(settings) is False


def test_claude_installer_places_hawk_first_detects_tamper_and_preserves_customer_uninstall(
    tmp_path: Path,
) -> None:
    settings = tmp_path / "settings.json"
    customer = {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "/opt/customer/hook", "timeout": 30}],
    }
    settings.write_text(json.dumps({"theme": "dark", "hooks": {"PreToolUse": [customer]}}), encoding="utf-8")
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    installer = NativeHookInstaller(provider="claude_code", helper_path=helper)

    installed = installer.install(settings)
    payload = json.loads(settings.read_text(encoding="utf-8"))

    assert "--hawk-managed-hook" in str(payload["hooks"]["PreToolUse"][0])
    assert payload["hooks"]["PreToolUse"][1] == customer
    assert installer.validate_installation(settings, expected_fingerprint=installed.fingerprint) is True
    assert installer.detect_drift(settings, expected_fingerprint=installed.fingerprint) == ()

    tampered = json.loads(json.dumps(payload))
    tampered["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "/tmp/tampered"
    settings.write_text(json.dumps(tampered), encoding="utf-8")
    assert installer.validate_installation(settings, expected_fingerprint=installed.fingerprint) is False
    assert "settings_fingerprint_changed" in installer.detect_drift(
        settings, expected_fingerprint=installed.fingerprint
    )

    settings.write_text(json.dumps(payload), encoding="utf-8")
    installer.uninstall(settings)
    restored = json.loads(settings.read_text(encoding="utf-8"))
    assert restored == {"theme": "dark", "hooks": {"PreToolUse": [customer]}}
