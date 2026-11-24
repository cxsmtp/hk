from __future__ import annotations

import json
import math
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .contracts import EndpointHealthState


_COUNTERS = frozenset(
    {
        "endpoint_auth_events_total",
        "endpoint_allow_total",
        "endpoint_block_total",
        "endpoint_shadow_block_total",
        "endpoint_policy_unknown_total",
        "endpoint_deadline_miss_total",
        "endpoint_permit_issued_total",
        "endpoint_permit_consumed_total",
        "endpoint_permit_mismatch_total",
        "endpoint_taint_created_total",
        "endpoint_external_transfer_block_total",
        "endpoint_component_unhealthy_total",
        "endpoint_tamper_total",
        "endpoint_proxy_bypass_total",
        "endpoint_quic_block_total",
        "endpoint_ipc_error_total",
    }
)

_LATENCIES = frozenset(
    {
        "file_auth_latency",
        "process_auth_latency",
        "network_auth_latency",
        "local_policy_latency",
        "permit_validation_latency",
        "proxy_latency",
    }
)


class EndpointOperationalMetrics:
    """Fixed-name, label-free local metrics with bounded latency memory."""

    def __init__(self, *, maximum_latency_samples: int = 2048) -> None:
        maximum = max(1, min(int(maximum_latency_samples), 16384))
        self._counters = {name: 0 for name in _COUNTERS}
        self._latencies = {name: deque(maxlen=maximum) for name in _LATENCIES}

    def increment(self, name: str, *, amount: int = 1) -> None:
        if name not in _COUNTERS:
            raise ValueError(f"unsupported counter: {name}")
        if type(amount) is not int or amount < 0:
            raise ValueError("counter amount must be a non-negative integer")
        self._counters[name] += amount

    def observe_latency(self, name: str, value_ns: int) -> None:
        if name not in _LATENCIES:
            raise ValueError(f"unsupported latency: {name}")
        if type(value_ns) is not int or value_ns < 0:
            raise ValueError("latency must be a non-negative integer")
        self._latencies[name].append(value_ns)

    def snapshot(self) -> dict[str, Any]:
        latencies: dict[str, dict[str, int]] = {}
        for name, samples in sorted(self._latencies.items()):
            if not samples:
                continue
            ordered = sorted(samples)
            latencies[name] = {
                "count": len(ordered),
                "p50": self._percentile(ordered, 0.50),
                "p95": self._percentile(ordered, 0.95),
                "p99": self._percentile(ordered, 0.99),
                "maximum": ordered[-1],
            }
        return {
            "counters": dict(sorted(self._counters.items())),
            "latencies": latencies,
            "labels_collected": False,
        }

    @staticmethod
    def _percentile(ordered: list[int], percentile: float) -> int:
        index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * percentile) - 1))
        return ordered[index]


@dataclass(frozen=True, slots=True)
class SelfProtectionObservation:
    component: str
    installed: bool
    active: bool
    expected_version: str
    observed_version: str | None
    expected_binary_digest: str
    observed_binary_digest: str | None
    expected_configuration_digest: str
    observed_configuration_digest: str | None
    policy_fresh: bool
    ipc_authenticated: bool
    management_profile_present: bool


@dataclass(frozen=True, slots=True)
class SelfProtectionResult:
    component: str
    health_state: EndpointHealthState
    reason_codes: tuple[str, ...]
    protected: bool


class EndpointSelfProtectionMonitor:
    def evaluate(self, observation: SelfProtectionObservation) -> SelfProtectionResult:
        reasons: list[str] = []
        if not observation.installed:
            state = EndpointHealthState.NOT_INSTALLED
            reasons.append("component_not_installed")
        elif (
            observation.observed_binary_digest != observation.expected_binary_digest
            or observation.observed_configuration_digest
            != observation.expected_configuration_digest
            or not observation.ipc_authenticated
            or not observation.management_profile_present
        ):
            state = EndpointHealthState.TAMPERED
            if observation.observed_binary_digest != observation.expected_binary_digest:
                reasons.append("binary_integrity_mismatch")
            if (
                observation.observed_configuration_digest
                != observation.expected_configuration_digest
            ):
                reasons.append("configuration_integrity_mismatch")
            if not observation.ipc_authenticated:
                reasons.append("ipc_authentication_failed")
            if not observation.management_profile_present:
                reasons.append("management_profile_missing")
        elif observation.observed_version != observation.expected_version:
            state = EndpointHealthState.VERSION_MISMATCH
            reasons.append("component_version_mismatch")
        elif not observation.active:
            state = EndpointHealthState.UNHEALTHY
            reasons.append("component_inactive")
        elif not observation.policy_fresh:
            state = EndpointHealthState.POLICY_STALE
            reasons.append("policy_stale")
        else:
            state = EndpointHealthState.HEALTHY
        return SelfProtectionResult(
            component=str(observation.component)[:256],
            health_state=state,
            reason_codes=tuple(reasons),
            protected=state is EndpointHealthState.HEALTHY,
        )


@dataclass(frozen=True, slots=True)
class ControlChannelValidationResult:
    accepted: bool
    reason: str
    message_type: str | None
    executable_material_present: bool


_DANGEROUS_CONTROL_KEYS = frozenset(
    {
        "command",
        "commands",
        "script",
        "scripts",
        "shell",
        "powershell",
        "path",
        "file_path",
        "read_file",
        "secret",
        "secret_reference",
        "get_secret",
        "binary",
        "binary_url",
        "executable",
        "executable_module",
        "module_url",
        "plugin_url",
        "plugin_urls",
        "update_url",
        "payload_url",
    }
)

_CONTROL_MESSAGE_FIELDS = {
    "signed_policy": {
        "type",
        "schema_version",
        "policy_version",
        "policy_epoch",
        "bundle_digest",
        "key_id",
        "signature",
    },
    "signed_configuration": {
        "type",
        "schema_version",
        "configuration_version",
        "configuration_digest",
        "key_id",
        "signature",
    },
    "credential_rotation_metadata": {
        "type",
        "schema_version",
        "credential_id",
        "credential_epoch",
        "not_before",
        "expires_at",
        "key_id",
        "signature",
    },
    "containment_request": {
        "type",
        "schema_version",
        "request_id",
        "action_id",
        "process_instance_id",
        "containment_class",
        "expires_at",
        "key_id",
        "signature",
    },
    "validation_request": {
        "type",
        "schema_version",
        "request_id",
        "validation_profile",
        "expires_at",
        "key_id",
        "signature",
    },
}


class EndpointControlChannelValidator:
    """Reject executable/update material on the declarative policy channel."""

    def validate(self, payload: Mapping[str, Any]) -> ControlChannelValidationResult:
        if not isinstance(payload, Mapping):
            return ControlChannelValidationResult(
                False, "control_channel_payload_invalid", None, False
            )
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            return ControlChannelValidationResult(
                False, "control_channel_payload_invalid", None, False
            )
        if len(encoded.encode("utf-8")) > 64 * 1024:
            return ControlChannelValidationResult(
                False, "control_channel_payload_oversized", None, False
            )
        dangerous = self._contains_dangerous_material(payload)
        message_type = str(payload.get("type") or "").strip()
        if dangerous:
            return ControlChannelValidationResult(
                False,
                "control_channel_executable_or_privileged_material_denied",
                message_type or None,
                True,
            )
        expected_fields = _CONTROL_MESSAGE_FIELDS.get(message_type)
        if expected_fields is None:
            return ControlChannelValidationResult(
                False,
                "control_channel_message_type_denied",
                message_type or None,
                False,
            )
        if set(payload) != expected_fields:
            return ControlChannelValidationResult(
                False,
                "control_channel_schema_invalid",
                message_type,
                False,
            )
        if payload.get("schema_version") != 1:
            return ControlChannelValidationResult(
                False,
                "control_channel_schema_version_invalid",
                message_type,
                False,
            )
        for epoch_field in ("policy_epoch", "credential_epoch"):
            if epoch_field in payload and (
                type(payload[epoch_field]) is not int or payload[epoch_field] <= 0
            ):
                return ControlChannelValidationResult(
                    False,
                    "control_channel_epoch_invalid",
                    message_type,
                    False,
                )
        for key, value in payload.items():
            if key in {"type", "schema_version", "policy_epoch", "credential_epoch"}:
                continue
            if not isinstance(value, str) or not value.strip() or len(value) > 2048:
                return ControlChannelValidationResult(
                    False,
                    "control_channel_value_invalid",
                    message_type,
                    False,
                )
        return ControlChannelValidationResult(
            True,
            "control_channel_declarative_message_accepted",
            message_type,
            False,
        )

    @classmethod
    def _contains_dangerous_material(cls, value: object) -> bool:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if str(key).strip().lower() in _DANGEROUS_CONTROL_KEYS:
                    return True
                if cls._contains_dangerous_material(nested):
                    return True
            return False
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            return any(cls._contains_dangerous_material(item) for item in value)
        return False
