"""Native-messaging host loop.

Reads framed messages from the browser (stdin), forwards each to the agent control
socket for a decision, and writes the framed decision back (stdout). Injectable
reader/writer make the loop unit-testable without a real browser.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, BinaryIO

from ..config import AgentConfig
from .framing import encode_message, read_messages
from .socket_client import query_agent

PROTOCOL_VERSION = 1
_UNAVAILABLE_ERRORS = {
    "no_response",
    "bad_response",
    "broker_auth_failed",
    "broker_auth_pin_missing",
}


def _to_request(message: dict[str, Any]) -> dict[str, Any]:
    """Normalize a browser event into a dispatcher request (default surface=browser)."""
    if "protocol_version" in message:
        if message.get("protocol_version") != PROTOCOL_VERSION:
            raise ValueError("unsupported_protocol_version")
        op = message.get("op")
        if op not in {"evaluate", "identity"}:
            raise ValueError("unsupported_operation")
        if op == "identity":
            return {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": str(message.get("request_id") or "")[:128],
                "op": "identity",
            }
        payload = message.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("invalid_payload")
        request = dict(payload)
        request["request_id"] = str(message.get("request_id") or "")[:128]
    else:
        request = dict(message)
        request.pop("op", None)  # legacy browser events are never control ops

    # Only the two browser-owned endpoint paths are accepted from this host.
    # Payload content can never self-assert MCP/SDK/Foundry coverage.
    declared_surface = str(message.get("surface") or "browser")
    request["surface"] = "data_transfer" if declared_surface == "data_transfer" else "browser"
    request["protocol_version"] = PROTOCOL_VERSION
    request["op"] = "evaluate"
    return request


def _is_unavailable(decision: dict[str, Any]) -> bool:
    error = str(decision.get("error") or "")
    return error.startswith("agent_unavailable:") or error in _UNAVAILABLE_ERRORS


def _native_response(message: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    unavailable = _is_unavailable(decision)
    if message.get("op") == "identity":
        broker_auth = decision.get("broker_auth")
        broker_endpoint_id = (
            str(broker_auth.get("endpoint_id") or "").strip()
            if isinstance(broker_auth, dict)
            else ""
        )
        endpoint_id = str(decision.get("endpoint_id") or "").strip()
        identity_verified = bool(
            decision.get("ok")
            and not unavailable
            and endpoint_id
            and endpoint_id == broker_endpoint_id
        )
        safe_decision = dict(decision)
        if not identity_verified:
            safe_decision.pop("endpoint_id", None)
            safe_decision.pop("user_id", None)
            safe_decision.pop("user_email", None)
            safe_decision["ok"] = False
            if not unavailable:
                safe_decision["error"] = "endpoint_identity_mismatch"
        return {
            **safe_decision,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": str(message.get("request_id") or "")[:128],
            "endpoint_available": not unavailable,
            "endpoint_authorized": False,
            "endpoint_identity_verified": identity_verified,
        }
    monitor_only = str(decision.get("control_mode") or "").startswith("monitor_would_")
    authorized = bool(decision.get("ok")) and not unavailable and not monitor_only
    return {
        **decision,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": str(message.get("request_id") or "")[:128],
        "endpoint_available": not unavailable,
        "endpoint_authorized": authorized,
    }


def run_host(
    config: AgentConfig,
    *,
    reader: BinaryIO | None = None,
    writer: BinaryIO | None = None,
) -> int:
    socket_path = str(Path(config.ipc_socket_path).expanduser())
    reader = reader or sys.stdin.buffer
    writer = writer or sys.stdout.buffer
    for message in read_messages(reader.read):
        if not isinstance(message, dict):
            continue
        try:
            request = _to_request(message)
        except ValueError as exc:
            decision = {"ok": False, "error": str(exc)}
        else:
            decision = query_agent(
                socket_path,
                request,
                timeout=config.http_timeout_seconds,
                expected_thumbprint=config.ipc_trusted_device_thumbprint,
            )
        writer.write(encode_message(_native_response(message, decision)))
        try:
            writer.flush()
        except (OSError, ValueError):
            return 0
    return 0
