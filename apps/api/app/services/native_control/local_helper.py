from __future__ import annotations

from dataclasses import dataclass
import json


MAX_HELPER_MESSAGE_BYTES = 32_768
ALLOWED_OPERATIONS = {
    "event.emit",
    "decision.receive",
    "policy.refresh",
    "health.report",
    "integrity.report",
    "configuration.receive",
    "policy.install",
    "configuration.apply",
    "decision.cache",
    "metadata.sync",
}
OPERATION_PAYLOAD_KEYS = {
    "event.emit": {"event_hash", "event_type"},
    "decision.receive": {"action_hash", "decision", "expires_at"},
    "policy.refresh": {"policy_version", "policy_hash", "expires_at", "key_id", "signature"},
    "health.report": {"state", "observed_at"},
    "integrity.report": {"config_hash", "observed_at"},
    "configuration.receive": {
        "configuration_version", "configuration_hash", "expires_at", "key_id", "signature"
    },
    "policy.install": {
        "policy_version",
        "policy_hash",
        "expires_at",
        "key_id",
        "signature",
    },
    "configuration.apply": {
        "configuration_version",
        "configuration_hash",
        "mode",
        "policy_endpoint",
        "telemetry_endpoint",
        "poll_interval_seconds",
        "allowed_surfaces",
        "tenant_binding",
        "integration_instance_id",
    },
    "decision.cache": {
        "action_hash",
        "decision",
        "expires_at",
        "policy_version",
    },
    "metadata.sync": {
        "metadata_version",
        "asset_ids",
        "capability_hashes",
        "observed_at",
        "cursor",
    },
}
PROHIBITED_KEYS = {
    "command",
    "shell",
    "script",
    "exec",
    "executable",
    "binary",
    "plugin",
    "module",
    "dynamic_import",
    "native_extension",
    "download_url",
    "update_artifact",
    "program",
    "arguments",
    "process",
    "argv",
    "interpreter",
    "launch",
    "spawn",
}


@dataclass(frozen=True, slots=True)
class LocalHelperMessage:
    operation: str
    payload: dict[str, object]


class HawkNativeControlHelper:
    """Narrow declarative helper. It cannot execute commands, plugins, or processes."""

    def __init__(self, sink) -> None:
        if not callable(sink):
            raise ValueError("helper_sink_required")
        self._sink = sink

    def _send(self, operation: str, payload: dict[str, object]) -> LocalHelperMessage:
        message = validate_local_helper_message({"operation": operation, "payload": payload})
        self._sink({"operation": message.operation, "payload": dict(message.payload)})
        return message

    def emit_event(self, *, event_hash: str, event_type: str) -> LocalHelperMessage:
        return self._send("event.emit", {"event_hash": event_hash, "event_type": event_type})

    def receive_decision(
        self, *, action_hash: str, decision: str, expires_at: str
    ) -> LocalHelperMessage:
        return self._send(
            "decision.receive",
            {"action_hash": action_hash, "decision": decision, "expires_at": expires_at},
        )

    def refresh_signed_policy(
        self,
        *,
        policy_version: str,
        policy_hash: str,
        expires_at: str,
        key_id: str,
        signature: str,
    ) -> LocalHelperMessage:
        return self._send(
            "policy.refresh",
            {
                "policy_version": policy_version,
                "policy_hash": policy_hash,
                "expires_at": expires_at,
                "key_id": key_id,
                "signature": signature,
            },
        )

    def report_health(self, *, state: str, observed_at: str) -> LocalHelperMessage:
        return self._send("health.report", {"state": state, "observed_at": observed_at})

    def report_integrity(self, *, config_hash: str, observed_at: str) -> LocalHelperMessage:
        return self._send("integrity.report", {"config_hash": config_hash, "observed_at": observed_at})

    def receive_signed_configuration(
        self,
        *,
        configuration_version: str,
        configuration_hash: str,
        expires_at: str,
        key_id: str,
        signature: str,
    ) -> LocalHelperMessage:
        return self._send(
            "configuration.receive",
            {
                "configuration_version": configuration_version,
                "configuration_hash": configuration_hash,
                "expires_at": expires_at,
                "key_id": key_id,
                "signature": signature,
            },
        )


def _inspect(value: object, *, depth: int = 0) -> None:
    if depth > 6:
        raise ValueError("helper_message_too_deep")
    if isinstance(value, dict):
        if set(str(key).lower() for key in value) & PROHIBITED_KEYS:
            raise ValueError("helper_executable_material_forbidden")
        for child in value.values():
            _inspect(child, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 256:
            raise ValueError("helper_message_too_many_items")
        for child in value:
            _inspect(child, depth=depth + 1)
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise ValueError("helper_message_not_json")


def validate_local_helper_message(raw: dict[str, object]) -> LocalHelperMessage:
    if not isinstance(raw, dict) or set(raw) != {"operation", "payload"}:
        raise ValueError("helper_message_schema_invalid")
    operation = str(raw.get("operation") or "")
    if operation not in ALLOWED_OPERATIONS:
        raise ValueError("helper_operation_not_allowed")
    payload = raw.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("helper_payload_invalid")
    if not payload or not set(payload) <= OPERATION_PAYLOAD_KEYS[operation]:
        raise ValueError("helper_payload_schema_invalid")
    _inspect(payload)
    try:
        encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("helper_message_not_json") from exc
    if len(encoded) > MAX_HELPER_MESSAGE_BYTES:
        raise ValueError("helper_message_too_large")
    return LocalHelperMessage(operation=operation, payload=dict(payload))
