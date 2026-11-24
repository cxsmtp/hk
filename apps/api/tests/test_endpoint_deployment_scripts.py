from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "relative_script",
    [
        "infra/scripts/endpoint_agent.py",
        "infra/scripts/endpoint_proxy_guard.py",
        "infra/scripts/connector_bootstrap.py",
    ],
)
def test_deployment_scripts_have_help(relative_script: str) -> None:
    script_path = REPO_ROOT / relative_script
    assert script_path.exists(), f"Missing script: {script_path}"
    run = subprocess.run(
        [sys.executable, str(script_path), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    assert "usage:" in run.stdout.lower()


def test_proxy_guard_conflicting_macos_proxy_flags_fail_fast() -> None:
    script_path = REPO_ROOT / "infra/scripts/endpoint_proxy_guard.py"
    run = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--allow-local-http-api",
            "--apply-macos-proxy",
            "--clear-macos-proxy",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert run.returncode == 2
    assert "either --apply-macos-proxy or --clear-macos-proxy" in run.stdout.lower()

