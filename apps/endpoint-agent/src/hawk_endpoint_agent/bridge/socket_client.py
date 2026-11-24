"""Thin client to the agent's local control socket."""

from __future__ import annotations

import json
import socket
from typing import Any

from ..local_broker_auth import (
    LocalBrokerAuthenticationError,
    verify_local_broker_response,
)


def query_agent(
    socket_path: str,
    request: dict[str, Any],
    *,
    timeout: float = 5.0,
    expected_thumbprint: str = "",
) -> dict[str, Any]:
    """Send one request to the control socket and return the decision.

    On any transport failure returns a fail-secure-shaped response (``warn``) so a
    browser integration surfaces risk rather than silently allowing.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        with sock.makefile("r", encoding="utf-8") as stream:
            line = stream.readline(262_145)
        if len(line) > 262_144 or not line.endswith("\n"):
            return {"ok": False, "error": "invalid_response_frame"}
    except (OSError, UnicodeError) as exc:
        return {"ok": False, "error": f"agent_unavailable:{exc}", "action": "warn", "control_mode": "warned"}
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if not line:
        return {"ok": False, "error": "no_response", "action": "warn", "control_mode": "warned"}
    try:
        decoded = json.loads(line)
    except json.JSONDecodeError:
        return {"ok": False, "error": "bad_response", "action": "warn", "control_mode": "warned"}
    if not expected_thumbprint:
        return {"ok": False, "error": "broker_auth_pin_missing", "action": "warn", "control_mode": "warned"}
    try:
        return verify_local_broker_response(
            decoded,
            expected_thumbprint=expected_thumbprint,
        )
    except LocalBrokerAuthenticationError:
        return {"ok": False, "error": "broker_auth_failed", "action": "warn", "control_mode": "warned"}
