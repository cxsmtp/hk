from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_claude_debug_emits_only_redacted_failure_class() -> None:
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "HAWK_NATIVE_ACCEPTANCE_DEBUG": "1",
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hawk_endpoint_agent.native_control.hook",
            "--hawk-managed-hook",
            "--provider",
            "claude_code",
            "--event",
            "before_model",
            "--config",
            "/private/demo-secret-path.json",
        ],
        input="{}",
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=ROOT,
    )

    assert result.returncode == 0
    assert result.stderr == "Hawk native control failed closed:ValueError\n"
    assert "demo-secret-path" not in result.stderr
    assert "private" not in result.stderr
    assert "Hawk policy service unavailable" in result.stdout


def test_claude_default_failure_keeps_diagnostics_suppressed() -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    env.pop("HAWK_NATIVE_ACCEPTANCE_DEBUG", None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hawk_endpoint_agent.native_control.hook",
            "--hawk-managed-hook",
            "--provider",
            "claude_code",
            "--event",
            "before_model",
            "--config",
            "/private/demo-secret-path.json",
        ],
        input="{}",
        text=True,
        capture_output=True,
        check=False,
        env=env,
        cwd=ROOT,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Hawk policy service unavailable" in result.stdout


def test_device_key_debug_exposes_only_allowlisted_code(monkeypatch, capsys):
    import io
    from hawk_endpoint_agent.auth.device_key import DeviceKeyError
    from hawk_endpoint_agent.native_control import hook
    monkeypatch.setenv('HAWK_NATIVE_ACCEPTANCE_DEBUG','1')
    monkeypatch.setattr(sys,'argv',['hook','--hawk-managed-hook','--provider','codex','--event','before_tool'])
    monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(b'{}')))
    def configuration(_):raise DeviceKeyError('private/path token=supersecret',code='device_key_helper_unsigned')
    monkeypatch.setattr(hook,'_configuration',configuration)
    hook.main()
    captured=capsys.readouterr()
    assert captured.err=='Hawk native control failed closed:DeviceKeyError:device_key_helper_unsigned\n'
    assert 'supersecret' not in captured.out+captured.err
