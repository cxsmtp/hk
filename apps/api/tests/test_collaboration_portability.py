import os
from pathlib import Path
import subprocess
import sys


def test_isolated_lab_uses_the_invoking_python_without_creating_services():
    from infra.scripts import isolated_hawk_lab

    assert isolated_hawk_lab.PYTHON == Path(sys.executable)


def test_boundary_test_wrapper_honors_a_quoted_explicit_interpreter(tmp_path):
    root = Path(__file__).resolve().parents[3]
    interpreter = tmp_path / "test python"
    capture = tmp_path / "calls"
    interpreter.write_text('#!/bin/sh\nprintf "%s\\n" "$PWD:$*" >> "$HAWK_TEST_CAPTURE"\n')
    interpreter.chmod(0o700)
    result = subprocess.run(
        ["/bin/bash", str(root / "infra/scripts/test-claude-enterprise-boundary.sh")],
        cwd=tmp_path,
        env={"PATH": os.defpath, "HOME": str(tmp_path), "TEST_PYTHON": str(interpreter), "HAWK_TEST_CAPTURE": str(capture)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert capture.read_text().splitlines() == [
        f"{root}/apps/endpoint-agent:-m pytest -q tests/test_claude_enterprise_boundary.py",
        f"{root}/apps/api:-m pytest -q tests/test_claude_enterprise_inference.py",
    ]
