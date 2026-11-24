from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any


@dataclass(slots=True)
class FixtureState:
    marker_path: Path
    call_log_path: Path | None = None
    read_calls: int = 0
    write_calls: int = 0

    def record(self, tool_name: str) -> None:
        if tool_name == "read_fixture":
            self.read_calls += 1
        elif tool_name == "write_marker":
            self.write_calls += 1
        if self.call_log_path is not None:
            with self.call_log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"{tool_name}\n")


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "read_fixture",
            "description": "Return a fixed synthetic Hawk acceptance value.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "write_marker",
            "description": "Write a bounded synthetic note to the temporary acceptance marker.",
            "inputSchema": {
                "type": "object",
                "properties": {"note": {"type": "string", "maxLength": 256}},
                "required": ["note"],
                "additionalProperties": False,
            },
        },
    ]


def _response(request_id: object, result: object) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def handle_request(state: FixtureState, request: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        raise ValueError("mcp_fixture_request_invalid")
    method = str(request.get("method") or "")
    request_id = request.get("id")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    if method.startswith("notifications/"):
        return None
    if method == "initialize":
        requested_version = str(params.get("protocolVersion") or "2025-06-18")
        return _response(
            request_id,
            {
                "protocolVersion": requested_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "hawk-claude-acceptance", "version": "1.0.0"},
            },
        )
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(request_id, {"tools": _tools()})
    if method == "resources/list":
        return _response(request_id, {"resources": []})
    if method == "prompts/list":
        return _response(request_id, {"prompts": []})
    if method != "tools/call":
        raise ValueError("mcp_fixture_method_unknown")
    tool_name = str(params.get("name") or "")
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    if tool_name == "read_fixture":
        state.record(tool_name)
        return _response(
            request_id,
            {"content": [{"type": "text", "text": "hawk-fixture-ok"}], "isError": False},
        )
    if tool_name == "write_marker":
        note = arguments.get("note")
        if not isinstance(note, str):
            raise ValueError("mcp_fixture_note_required")
        if len(note) > 256:
            raise ValueError("mcp_fixture_note_too_large")
        state.marker_path.write_text(note + "\n", encoding="utf-8")
        state.record(tool_name)
        return _response(
            request_id,
            {"content": [{"type": "text", "text": "marker-written"}], "isError": False},
        )
    raise ValueError("mcp_fixture_tool_unknown")


def _error(request_id: object, exc: Exception) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32602, "message": str(exc)[:160]},
    }


def run_stdio(state: FixtureState) -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        request_id: object = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("mcp_fixture_request_invalid")
            request_id = request.get("id")
            response = handle_request(state, request)
        except (ValueError, json.JSONDecodeError) as exc:
            response = _error(request_id, exc)
        if response is not None:
            sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
            sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", required=True)
    parser.add_argument("--call-log", required=True)
    args = parser.parse_args()
    marker_path = Path(args.marker).expanduser().resolve()
    call_log_path = Path(args.call_log).expanduser().resolve()
    if marker_path == call_log_path:
        raise ValueError("mcp_fixture_paths_must_differ")
    run_stdio(FixtureState(marker_path=marker_path, call_log_path=call_log_path))


if __name__ == "__main__":
    main()
