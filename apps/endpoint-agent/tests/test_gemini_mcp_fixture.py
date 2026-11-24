from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


def _exchange(process: subprocess.Popen[str], payload: dict[str, object]) -> dict[str, object]:
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline())


def test_gemini_mcp_fixture_exposes_read_and_write_without_network(tmp_path: Path) -> None:
    marker = tmp_path / "fixture.marker"
    process = subprocess.Popen(
        [sys.executable, "-m", "hawk_endpoint_agent.native_control.gemini_mcp_fixture", "--marker", str(marker)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    try:
        initialized = _exchange(process, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        })
        tools = _exchange(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        written = _exchange(process, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "write_marker", "arguments": {"value": "accepted"}},
        })
        read = _exchange(process, {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "read_marker", "arguments": {}},
        })

        assert initialized["result"]["serverInfo"]["name"] == "hawk-gemini-acceptance"
        assert {row["name"] for row in tools["result"]["tools"]} == {"read_marker", "write_marker"}
        assert written["result"]["content"][0]["text"] == "written"
        assert read["result"]["content"][0]["text"] == "present"
        assert marker.read_text(encoding="utf-8") == "accepted"
    finally:
        process.terminate()
        process.wait(timeout=5)


def test_gemini_mcp_fixture_exits_after_acceptance_idle_timeout(tmp_path: Path) -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hawk_endpoint_agent.native_control.gemini_mcp_fixture",
            "--marker",
            str(tmp_path / "fixture.marker"),
            "--idle-timeout-seconds",
            "0.2",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )

    assert process.wait(timeout=2) == 0
