from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infra" / "scripts" / "enroll_gemini_demo.py"


def load_enrollment_module():
    spec = importlib.util.spec_from_file_location("enroll_gemini_demo", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runtime_validation_accepts_confined_virtualenv_python_symlink(tmp_path: Path) -> None:
    module = load_enrollment_module()
    runtime_bin = tmp_path / "runtime" / "venv" / "bin"
    runtime_bin.mkdir(parents=True)
    python_target = runtime_bin / "python3.12"
    python_target.write_bytes(b"trusted runtime")
    python_target.chmod(0o700)
    python_link = runtime_bin / "python"
    python_link.symlink_to(python_target.name)

    validated = module.require_regular_file(
        python_link,
        "Hawk private Python runtime",
        executable=True,
        allowed_symlink_root=runtime_bin,
    )

    assert validated == python_target.resolve(strict=True)


def test_runtime_validation_rejects_symlink_outside_explicit_root(tmp_path: Path) -> None:
    module = load_enrollment_module()
    runtime_bin = tmp_path / "runtime" / "venv" / "bin"
    runtime_bin.mkdir(parents=True)
    outside_target = tmp_path / "untrusted-python"
    outside_target.write_bytes(b"untrusted runtime")
    outside_target.chmod(0o700)
    python_link = runtime_bin / "python"
    python_link.symlink_to(outside_target)

    with pytest.raises(module.EnrollmentError, match="escapes its trusted runtime"):
        module.require_regular_file(
            python_link,
            "Hawk private Python runtime",
            executable=True,
            allowed_symlink_root=runtime_bin,
        )


def test_enrollment_binds_runtime_callbacks_to_registered_gemini_key(tmp_path: Path) -> None:
    module = load_enrollment_module()
    runtime_config = tmp_path / "gemini-cli.json"
    module.secure_atomic_json(
        runtime_config,
        {
            "key_provider": "macos_secure_enclave",
            "kms_hsm_key_reference": (
                "secure-enclave://com.hawk.endpoint-agent.native-control.gemini.v1"
            ),
        },
    )

    module.bind_secure_enclave_runtime_config(
        runtime_config,
        key_tag="com.hawk.endpoint-agent.native-control.gemini.v1",
    )

    payload = module.load_json(runtime_config)
    assert payload["secure_enclave_key_tag"] == (
        "com.hawk.endpoint-agent.native-control.gemini.v1"
    )


def test_enrollment_rejects_conflicting_runtime_key_binding(tmp_path: Path) -> None:
    module = load_enrollment_module()
    runtime_config = tmp_path / "gemini-cli.json"
    module.secure_atomic_json(
        runtime_config,
        {
            "key_provider": "macos_secure_enclave",
            "kms_hsm_key_reference": "secure-enclave://registered-key",
            "secure_enclave_key_tag": "different-key",
        },
    )

    with pytest.raises(module.EnrollmentError, match="key binding is inconsistent"):
        module.bind_secure_enclave_runtime_config(
            runtime_config,
            key_tag="registered-key",
        )


def test_gemini_demo_enrollment_is_isolated_resume_safe_and_secretless() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "os.umask(0o077)" in script
    assert 'GEMINI_VERSION = "0.54.4"' in script
    assert 'GEMINI_ROOT = Path.home() / f"Library/Application Support/Hawk/Gemini/{GEMINI_VERSION}"' in script
    assert 'GEMINI_SETTINGS = GEMINI_ROOT / "settings.json"' in script
    assert 'GEMINI_BINARY = GEMINI_ROOT / "node_modules/@google/gemini-cli/bundle/gemini.js"' in script
    assert "MemoryTokenVault" in script
    assert "gemini-demo-enrollment.json" in script
    assert "credential_registered" in script
    assert "macos_secure_enclave" in script
    assert '"NATIVE_CONTROL_GOOGLE": "true"' in script
    assert "NATIVE_CONTROL_ROUTE_BINDINGS_JSON" in script
    assert 'row.get("provider") != "google"' in script
    assert 'row.get("provider") != "anthropic"' not in script
    assert '"--provider", "gemini_cli"' in script
    assert '"--settings", str(GEMINI_SETTINGS)' in script
    assert '"--provider-family", "google"' in script
    assert '"--product", "gemini_cli"' in script
    assert '"--provider-version", GEMINI_VERSION' in script
    assert '"--adapter-version", ADAPTER_VERSION' in script
    assert "render-gemini-managed" in script
    assert "GEMINI_CLI_SYSTEM_SETTINGS_PATH" not in script
    assert "Password123!" not in script
    assert "rm -rf" not in script

    state_start = script.index("state_payload = {")
    state_end = script.index("secure_atomic_json(STATE_FILE, state_payload)", state_start)
    state_payload = script[state_start:state_end]
    assert "access_token" not in state_payload
    assert "refresh_token" not in state_payload
    assert "token" not in state_payload.lower()


def test_gemini_demo_enrollment_registers_full_lifecycle_and_preserves_global_install() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    for event in (
        "session_start",
        "session_end",
        "before_agent",
        "after_agent",
        "before_model",
        "after_model",
        "before_tool_selection",
        "before_tool",
        "after_tool",
        "pre_compress",
        "notification",
    ):
        assert f'"{event}"' in script

    assert 'global_gemini_before = shutil.which("gemini")' in script
    assert 'global_gemini_after = shutil.which("gemini")' in script
    assert 'Global Gemini launcher changed during isolated enrollment.' in script
    assert 'f"{GEMINI_SETTINGS.name}.hawk-backup-{timestamp}"' in script
    assert "uninstall" not in script
