from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any


_PROTOCOL_VERSION = "2025-06-18"


def _result(request_id: object, value: object) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def _error(request_id: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tools() -> list[dict[str, object]]:
    return [
        {
            "name": "read_marker",
            "description": "Read only whether the harmless local acceptance marker exists.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "annotations": {"readOnlyHint": True, "destructiveHint": False},
        },
        {
            "name": "write_marker",
            "description": "Write a harmless marker inside the isolated acceptance directory.",
            "inputSchema": {
                "type": "object",
                "properties": {"value": {"type": "string", "maxLength": 64}},
                "required": ["value"],
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": False, "destructiveHint": False},
        },
    ]


def _handle(payload: dict[str, Any], marker: Path) -> dict[str, object] | None:
    request_id = payload.get("id")
    method = payload.get("method")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "hawk-gemini-acceptance", "version": "1.0.0"},
        })
    if method == "tools/list":
        return _result(request_id, {"tools": _tools()})
    if method == "tools/call":
        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
        name = params.get("name")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        if name == "read_marker":
            return _result(request_id, {"content": [{"type": "text", "text": "present" if marker.exists() else "absent"}]})
        if name == "write_marker":
            value = arguments.get("value")
            if not isinstance(value, str) or not value or len(value) > 64:
                return _error(request_id, -32602, "invalid value")
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(value, encoding="utf-8")
            marker.chmod(0o600)
            return _result(request_id, {"content": [{"type": "text", "text": "written"}]})
        return _error(request_id, -32602, "unknown tool")
    if method == "ping":
        return _result(request_id, {})
    return _error(request_id, -32601, "method not found") if request_id is not None else None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", required=True)
    parser.add_argument("--idle-timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if not 0 < args.idle_timeout_seconds <= 300:
        parser.error("idle timeout must be between 0 and 300 seconds")
    marker = Path(args.marker).expanduser().resolve()
    activity_lock = threading.Lock()
    last_activity = [time.monotonic()]
    stopped = threading.Event()

    def idle_watchdog() -> None:
        interval = min(1.0, max(0.05, args.idle_timeout_seconds / 4))
        while not stopped.wait(interval):
            with activity_lock:
                idle_for = time.monotonic() - last_activity[0]
            if idle_for >= args.idle_timeout_seconds:
                # The fixture has no durable state. A hard process exit is
                # intentional so a provider client that leaves stdin open
                # cannot leak an acceptance subprocess.
                os._exit(0)

    threading.Thread(target=idle_watchdog, daemon=True).start()
    try:
        for line in sys.stdin:
            with activity_lock:
                last_activity[0] = time.monotonic()
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    raise ValueError("request must be an object")
                response = _handle(payload, marker)
            except (json.JSONDecodeError, ValueError) as exc:
                response = _error(None, -32700, type(exc).__name__)
            if response is not None:
                sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
                sys.stdout.flush()
    finally:
        stopped.set()


if __name__ == "__main__":
    main()
