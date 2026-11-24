"""Bounded, secret-free registration for locally bound agent runtimes.

Registration is discovery evidence, not authorization evidence. The caller is a
same-user SDK peer and its manifest remains explicitly self-attested until Hawk
observes signed pre-action decisions for the same client path.
"""

from __future__ import annotations

import re
from typing import Any


class AgentRegistrationError(ValueError):
    pass


_TRANSPORTS = {"composio", "google_direct", "tavily_direct", "local_ollama", "unknown"}
_EVIDENCE_BASES = {"runtime_configuration", "supported_binding", "observed_action"}
_SURFACES = {"llm", "sdk", "developer_agent", "foundry", "data_transfer"}
_TOP_LEVEL_KEYS = {
    "protocol_version",
    "op",
    "request_id",
    "agent_id",
    "agent_name",
    "agent_version",
    "runtime_provider",
    "model_provider",
    "model_name",
    "models",
    "detected_tools",
    "detected_actions",
    "detected_privileges",
    "listening_ports",
    "integration_transports",
    "active_integration_transport",
    "control_binding",
    "client_metadata",
    "process_metadata",
}
_SECRET_KEY = re.compile(
    r"token|secret|password|authorization|credential|prompt|content|body|query|recipient|email_address",
    re.IGNORECASE,
)
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
_DOMAIN = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z]{2,63}$|^(?:localhost|127\.0\.0\.1)$")


def _reject_secret_keys(value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _reject_secret_keys(item)
        return
    if not isinstance(value, dict):
        return
    for key, nested in value.items():
        if _SECRET_KEY.search(str(key)):
            raise AgentRegistrationError("secret-bearing registration field")
        _reject_secret_keys(nested)


def _text(value: Any, *, field: str, max_len: int = 128) -> str:
    if not isinstance(value, str):
        raise AgentRegistrationError(f"invalid {field}")
    normalized = value.strip()
    if not normalized or len(normalized) > max_len:
        raise AgentRegistrationError(f"invalid {field}")
    return normalized


def _identifier(value: Any, *, field: str) -> str:
    normalized = _text(value, field=field)
    if not _SAFE_ID.fullmatch(normalized):
        raise AgentRegistrationError(f"invalid {field}")
    return normalized


def _text_list(value: Any, *, field: str, max_items: int = 32) -> list[str]:
    if not isinstance(value, list) or len(value) > max_items:
        raise AgentRegistrationError(f"invalid {field}")
    output: list[str] = []
    for item in value:
        normalized = _text(item, field=field)
        if normalized not in output:
            output.append(normalized)
    return output


def _metadata(value: Any, *, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - keys:
        raise AgentRegistrationError(f"invalid {field}")
    return dict(value)


def normalize_agent_registration(request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise AgentRegistrationError("invalid agent registration")
    _reject_secret_keys(request)
    if set(request) - _TOP_LEVEL_KEYS:
        raise AgentRegistrationError("invalid agent registration")

    integrations_raw = request.get("integration_transports")
    if not isinstance(integrations_raw, list) or len(integrations_raw) > 16:
        raise AgentRegistrationError("invalid integration_transports")
    integrations: list[dict[str, Any]] = []
    for item in integrations_raw:
        normalized_item = _metadata(
            item,
            field="integration_transport",
            keys={"capability", "transport", "destination_domain", "active", "evidence_basis"},
        )
        capability = _identifier(normalized_item.get("capability"), field="capability")
        transport = _text(normalized_item.get("transport"), field="transport")
        destination = _text(normalized_item.get("destination_domain"), field="destination_domain", max_len=255).lower()
        evidence_basis = _text(normalized_item.get("evidence_basis"), field="evidence_basis")
        if transport not in _TRANSPORTS or evidence_basis not in _EVIDENCE_BASES:
            raise AgentRegistrationError("invalid integration transport")
        if not _DOMAIN.fullmatch(destination):
            raise AgentRegistrationError("invalid destination_domain")
        if type(normalized_item.get("active")) is not bool:
            raise AgentRegistrationError("invalid integration active state")
        integrations.append(
            {
                "capability": capability,
                "transport": transport,
                "destination_domain": destination,
                "active": normalized_item["active"],
                "evidence_basis": evidence_basis,
            }
        )

    active_transport = _text(
        request.get("active_integration_transport"),
        field="active_integration_transport",
    )
    if active_transport not in _TRANSPORTS:
        raise AgentRegistrationError("invalid active_integration_transport")
    active_gmail = {
        item["transport"]
        for item in integrations
        if item["capability"] == "gmail" and item["active"] is True
    }
    if active_gmail and active_transport not in active_gmail:
        raise AgentRegistrationError("active transport is not evidenced")

    binding = _metadata(
        request.get("control_binding"),
        field="control_binding",
        keys={"mode", "pre_action_surfaces"},
    )
    mode = _text(binding.get("mode"), field="control_binding.mode")
    surfaces = _text_list(
        binding.get("pre_action_surfaces"),
        field="control_binding.pre_action_surfaces",
        max_items=8,
    )
    if mode not in {"monitor", "enforce"} or any(surface not in _SURFACES for surface in surfaces):
        raise AgentRegistrationError("invalid control_binding")

    ports_raw = request.get("listening_ports")
    if not isinstance(ports_raw, list) or len(ports_raw) > 16:
        raise AgentRegistrationError("invalid listening_ports")
    ports: list[int] = []
    for value in ports_raw:
        if type(value) is not int or not 1 <= value <= 65535:
            raise AgentRegistrationError("invalid listening_ports")
        if value not in ports:
            ports.append(value)

    client = _metadata(
        request.get("client_metadata"),
        field="client_metadata",
        keys={"name", "version", "runtime", "runtime_version"},
    )
    process = _metadata(
        request.get("process_metadata"),
        field="process_metadata",
        keys={"pid", "platform", "architecture"},
    )
    pid = process.get("pid")
    if type(pid) is not int or pid <= 0:
        raise AgentRegistrationError("invalid process_metadata.pid")

    return {
        "protocol_version": 1,
        "op": "register_agent",
        "request_id": _identifier(request.get("request_id"), field="request_id"),
        "agent_id": _identifier(request.get("agent_id"), field="agent_id"),
        "agent_name": _text(request.get("agent_name"), field="agent_name", max_len=255),
        "agent_version": _text(request.get("agent_version"), field="agent_version"),
        "runtime_provider": _text(request.get("runtime_provider"), field="runtime_provider"),
        "model_provider": _text(request.get("model_provider"), field="model_provider"),
        "model_name": _text(request.get("model_name"), field="model_name"),
        "models": _text_list(request.get("models"), field="models", max_items=16),
        "detected_tools": _text_list(request.get("detected_tools"), field="detected_tools"),
        "detected_actions": _text_list(request.get("detected_actions"), field="detected_actions"),
        "detected_privileges": _text_list(request.get("detected_privileges"), field="detected_privileges"),
        "listening_ports": ports,
        "integration_transports": integrations,
        "active_integration_transport": active_transport,
        "control_binding": {"mode": mode, "pre_action_surfaces": surfaces},
        "client_metadata": {
            "name": _text(client.get("name"), field="client_metadata.name"),
            "version": _text(client.get("version"), field="client_metadata.version"),
            "runtime": _text(client.get("runtime"), field="client_metadata.runtime"),
            "runtime_version": _text(client.get("runtime_version"), field="client_metadata.runtime_version"),
        },
        "process_metadata": {
            "pid": pid,
            "platform": _text(process.get("platform"), field="process_metadata.platform"),
            "architecture": _text(process.get("architecture"), field="process_metadata.architecture"),
        },
    }


def registration_telemetry(registration: dict[str, Any]) -> dict[str, Any]:
    profile = {
        "schema_version": "1.0",
        "agent_id": registration["agent_id"],
        "agent_name": registration["agent_name"],
        "agent_version": registration["agent_version"],
        "runtime_provider": registration["runtime_provider"],
        "model_provider": registration["model_provider"],
        "model_name": registration["model_name"],
        "models": list(registration["models"]),
        "tools": list(registration["detected_tools"]),
        "actions": list(registration["detected_actions"]),
        "privileges": list(registration["detected_privileges"]),
        "listening_ports": list(registration["listening_ports"]),
        "integration_transports": list(registration["integration_transports"]),
        "active_integration_transport": registration["active_integration_transport"],
        "control_binding": dict(registration["control_binding"]),
        "evidence_basis": "sdk_self_registration",
        "process": dict(registration["process_metadata"]),
        "client": dict(registration["client_metadata"]),
    }
    return {
        "event_type": "agent_runtime_discovered",
        "domain": "agent-os.local",
        "application": registration["agent_name"],
        "source_surface": "endpoint-agent",
        "browser": "endpoint-agent",
        "extension_version": registration["client_metadata"]["version"],
        "agent_id": registration["agent_id"],
        "agent_name": registration["agent_name"],
        "agent_environment": "local",
        "runtime_provider": registration["runtime_provider"],
        "model_provider": registration["model_provider"],
        "model_name": registration["model_name"],
        "detected_tools": list(registration["detected_tools"]),
        "detected_actions": list(registration["detected_actions"]),
        "detected_privileges": list(registration["detected_privileges"]),
        "automation_suspected": True,
        "automation_confidence": 1.0,
        "automation_source": "sdk_self_registration",
        "active_integration_transport": registration["active_integration_transport"],
        "integration_transports": list(registration["integration_transports"]),
        "control_binding": dict(registration["control_binding"]),
        "evidence_basis": "sdk_self_registration",
        "agent_runtime_profile": profile,
        "control_mode": "telemetry_only",
        "action_taken": "allow:discovery_observation",
        "reason": "endpoint_bound_agent_self_registration",
        "correlation_id": registration["request_id"],
    }
