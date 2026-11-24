from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from hawk_endpoint_agent.native_control.cursor_acceptance import (
    _run_agent_interactive,
    _write_helper,
    run_cursor_binary_acceptance,
)


def test_generated_cursor_helper_imports_endpoint_package_from_src(tmp_path: Path) -> None:
    helper = tmp_path / "hawk-native-hook"
    _write_helper(helper)

    result = subprocess.run(
        [
            str(helper),
            "--provider",
            "cursor",
            "--event",
            "before_shell",
            "--config",
            str(tmp_path / "missing-runtime.json"),
        ],
        input="{}",
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0
    assert '"permission":"deny"' in result.stdout.replace(" ", "")
    assert "No module named 'hawk_endpoint_agent'" not in result.stderr


def test_cursor_interactive_runner_submits_through_a_real_tty(tmp_path: Path) -> None:
    binary = tmp_path / "fake-cursor-agent"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('Cursor Agent', flush=True)\n"
        "prompt = sys.stdin.readline().strip()\n"
        "print('accepted:' + prompt, flush=True)\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)

    output = _run_agent_interactive(
        binary=binary,
        acceptance_home=tmp_path,
        workspace=tmp_path,
        prompt="hawk-interactive-probe",
        expected_output="accepted:hawk-interactive-probe",
        timeout=10,
    )

    assert "accepted:hawk-interactive-probe" in output


def test_cursor_interactive_runner_retries_enter_after_keyboard_protocol_startup(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fake-cursor-agent"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('Cursor Agent', flush=True)\n"
        "prompt = sys.stdin.readline().strip()\n"
        "sys.stdin.readline()\n"
        "print('accepted:' + prompt, flush=True)\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)

    output = _run_agent_interactive(
        binary=binary,
        acceptance_home=tmp_path,
        workspace=tmp_path,
        prompt="hawk-retry-probe",
        expected_output="accepted:hawk-retry-probe",
        timeout=10,
    )

    assert "accepted:hawk-retry-probe" in output


def test_missing_cursor_binary_is_a_non_promotable_acceptance_result(tmp_path: Path) -> None:
    report = run_cursor_binary_acceptance(tmp_path / "cursor-not-installed")

    assert report.binary_available is False
    assert report.provider_version == "unknown"
    assert report.exact_version_verified is False
    assert report.signed_allow is False
    assert report.signed_block is False
    assert report.blocked_action_executed is None
    assert report.passed is False
    assert "cursor_binary_unavailable" in report.diagnostics


def test_exact_cursor_release_runs_signed_capability_level_acceptance() -> None:
    binary_value = os.environ.get("HAWK_CURSOR_ACCEPTANCE_BINARY")
    home_value = os.environ.get("HAWK_CURSOR_ACCEPTANCE_HOME")
    app_value = os.environ.get("HAWK_CURSOR_ACCEPTANCE_APP")
    if not binary_value or not home_value or not app_value:
        pytest.skip("exact Cursor acceptance installation is not configured")

    report = run_cursor_binary_acceptance(
        Path(binary_value),
        acceptance_home=Path(home_value),
        desktop_app=Path(app_value),
    )

    assert report.provider_version == "2026.08.11-e8db854"
    assert report.desktop_version == "3.15.6"
    assert report.desktop_commit == "a1f686545fd0ce8917bbd2449f733551a9bce420"
    assert report.exact_version_verified is True
    assert report.signed_allow is True
    assert report.allowed_action_executed is True
    assert report.signed_block is True
    assert report.blocked_action_executed is False
    assert report.shell_pre_action_verified is True
    assert report.file_read_pre_action_verified is True
    assert report.prompt_pre_action_verified is True
    assert report.interactive_prompt_allowed is True
    assert report.interactive_prompt_blocked is True
    assert report.interactive_prompt_block_prevented_backend is True
    assert report.post_action_correlated is True
    assert report.timeout_failed_closed is True
    assert report.config_tamper_detected is True
    assert report.customer_hooks_preserved is True
    assert report.hook_ordering_verified is True
    assert report.input_mutation_verified is True
    assert report.measured_callback_sample_count > 0
    assert report.measured_callback_p95_ms < 4_000
    assert report.input_mutation_status in {
        "verified:mutation_attempt_cannot_override_deny",
        "unverified:not_emitted",
    }
    assert report.mcp_status in {
        "verified:read_and_blocked_write",
        "unverified:model_did_not_call_fixture",
    }
    assert report.endpoint_correlation_verified is False
    assert (
        report.endpoint_correlation_status
        == "unverified:external_endpoint_observation_not_in_fixture"
    )
    assert report.managed_hook_status in {
        "verified:enterprise_source_loaded",
        "unverified:system_write_requires_mdm_or_admin",
    }
    assert report.passed is True
