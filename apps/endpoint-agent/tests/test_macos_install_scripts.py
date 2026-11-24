from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_installer_is_per_user_local_and_monitor_first() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert "Library/Application Support/Hawk/EndpointAgent" in script
    assert "python3 -m venv" in script
    assert '"cryptography>=42"' in script
    assert "--no-input" in script
    assert "--no-cache-dir" in script
    assert "src/hawk_endpoint_agent" in script
    assert "PYTHONPATH" in script
    assert "com.hawk.endpoint-agent.plist" in script
    assert 'HAWK_ENDPOINT_MODE="monitor"' in script
    assert "networksetup" not in script
    assert "add-trusted-cert" not in script


def test_installer_uses_stdin_only_secretless_enrollment() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert "--enrollment-bundle-stdin" in script
    assert "--ai-system-id" in script
    assert '[[ -z "$HAWK_API_URL" || -z "$HAWK_TENANT_ID" || -z "$HAWK_AI_SYSTEM_ID" ]]' in script
    assert "--security-profile" in script
    assert 'HAWK_SECURITY_PROFILE="bank"' in script
    assert "build_macos_identity_helper.sh" in script
    assert "hawk-device-identity" in script
    assert "--identity-helper" in script
    assert "--agent-token" not in script
    assert "--operator-token" not in script
    assert "HAWK_AGENT_TOKEN" not in script
    assert "HAWK_AGENT_OPERATOR_TOKEN" not in script
    assert '"agent-token" "operator-token" "tenant-id"' in script
    assert '[[ -f "$HAWK_LEGACY_FILE" && ! -L "$HAWK_LEGACY_FILE" ]]' in script
    assert '/bin/rm -f "$HAWK_LEGACY_FILE"' in script


def test_installer_requires_explicit_development_profile_for_adhoc_helper() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert '"$HAWK_SECURITY_PROFILE" == "development"' in script
    assert "--codesign-identity" in script
    assert "--options runtime" in script
    assert "Signature=adhoc" in script
    assert "TeamIdentifier=not set" in script


def test_bank_installer_requires_hashed_offline_dependency_bundle() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert "--wheelhouse" in script
    assert "--requirements-lock" in script
    assert "bank security profile requires an offline wheelhouse and hashed requirements lock" in script
    assert '--no-index' in script
    assert '--find-links "$HAWK_WHEELHOUSE"' in script
    assert '--require-hashes' in script
    assert '-r "$HAWK_REQUIREMENTS_LOCK"' in script
    assert 'if [[ "$HAWK_SECURITY_PROFILE" == "bank" ]]; then' in script
    assert 'else\n  "$HAWK_RUNTIME/venv/bin/python" -m pip install' in script
    assert '"cryptography>=42"' in script


def test_installer_preserves_existing_state_and_evidence() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert 'rsync -a --delete' in script
    assert '"$HAWK_RUNTIME/app/hawk_endpoint_agent/"' in script
    assert 'rm -rf "$HAWK_STATE"' not in script
    assert 'rm -f "$HAWK_STATE/' not in script
    assert "evidence-queue.json" not in script
    assert "baseline.json" not in script


def test_installer_writes_restricted_chrome_native_messaging_host() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert 'HAWK_NATIVE_HOST_NAME="com.hawk.endpoint_agent"' in script
    assert "Google/Chrome/NativeMessagingHosts" in script
    assert '! "$HAWK_EXTENSION_ID_VALUE" =~ ^[a-p]{32}$' in script
    assert "--install-bridge --extension-id" in script
    assert 'HAWK_AGENT_CONFIG=' in script
    assert 'PYTHONPATH=' in script
    assert '"$HAWK_RUNTIME/venv/bin/python"' in script
    assert "hawk_endpoint_agent.bridge" in script
    assert 'chmod 755 "$HAWK_NATIVE_HOST_WRAPPER"' in script
    assert 'chmod 644 "$HAWK_NATIVE_HOST_MANIFEST"' in script


def test_installer_uses_bash_printf_for_portable_shell_quoting() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert "/usr/bin/printf '#!/usr/bin/env bash\\nexport HAWK_AGENT_CONFIG=%q" not in script
    assert "\n  printf '#!/usr/bin/env bash\\nexport HAWK_AGENT_CONFIG=%q" in script


def test_installer_validates_and_passes_versioned_device_key_tag() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert '--device-key-tag) HAWK_DEVICE_KEY_TAG="$2"; shift 2 ;;' in script
    assert 'HAWK_DEVICE_KEY_TAG="com.hawk.endpoint-agent.device-key"' in script
    assert '! "$HAWK_DEVICE_KEY_TAG" =~ ^[A-Za-z0-9._-]{1,200}$' in script
    assert '--device-key-tag "$HAWK_DEVICE_KEY_TAG"' in script


def test_installer_verifies_enrolled_identity_before_starting_service() -> None:
    script = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    verification = '"$HAWK_RUNTIME/bin/hawk-endpoint-agent" --config "$HAWK_CONFIG" --verify-device-identity'
    launch = 'launchctl bootstrap "gui/$(id -u)" "$HAWK_PLIST"'
    assert verification in script
    assert script.index(verification) < script.index(launch)


def test_runtime_wrappers_use_only_private_venv_and_copied_package() -> None:
    agent = (ROOT / "scripts" / "hawk-endpoint-agent-wrapper.sh").read_text(encoding="utf-8")
    control = (ROOT / "scripts" / "hawk-endpoint-control-wrapper.sh").read_text(encoding="utf-8")
    native_hook = (ROOT / "scripts" / "hawk-native-hook-wrapper.sh").read_text(encoding="utf-8")
    installer = (ROOT / "scripts" / "install_macos_user.sh").read_text(encoding="utf-8")

    assert 'PYTHONPATH="$HAWK_RUNTIME/app"' in agent
    assert '"$HAWK_RUNTIME/venv/bin/python" -m hawk_endpoint_agent' in agent
    assert 'PYTHONPATH="$HAWK_RUNTIME/app"' in control
    assert '"$HAWK_RUNTIME/venv/bin/python" -m hawk_endpoint_agent.operator_cli' in control
    assert 'PYTHONPATH="$HAWK_RUNTIME/app"' in native_hook
    assert (
        '"$HAWK_RUNTIME/venv/bin/python" -m '
        'hawk_endpoint_agent.native_control.hook' in native_hook
    )
    assert 'hawk-native-hook-wrapper.sh' in installer
    assert '"$HAWK_RUNTIME/bin/hawk-native-hook"' in installer


def test_uninstaller_preserves_state_without_explicit_purge() -> None:
    script = (ROOT / "scripts" / "uninstall_macos_user.sh").read_text(encoding="utf-8")

    assert "com.hawk.endpoint-agent.plist" in script
    assert "--purge-data" in script
    assert 'if [[ "$HAWK_PURGE" == "1" ]]' in script
    assert "launchctl bootout" in script
