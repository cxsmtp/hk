from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone, tzinfo
import inspect
import json
from pathlib import Path
import subprocess
import sys
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import ValidationError

from app.services.discovery_collector_endpoint_signal_adapter import (
    ENDPOINT_SIGNAL_COLLECTOR_TYPE,
    ENDPOINT_SIGNAL_EVIDENCE_MAX_AGE,
    ENDPOINT_SIGNAL_OBSERVATION_TYPES,
    ENDPOINT_SIGNAL_SOURCE_SYSTEM,
    EndpointSignalCollectorEvidence,
    build_endpoint_signal_collector_contract,
)


_EVALUATED_AT = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _current_evidence(**overrides: object) -> EndpointSignalCollectorEvidence:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "endpoint-primary",
        "source_system": "endpoint_agent",
        "collector_version": "0.1.0",
        "schema_version": "1.0",
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return EndpointSignalCollectorEvidence(**values)  # type: ignore[arg-type]


def _build_contract(**kwargs: Any):
    kwargs.setdefault("tenant_id", "tenant-a")
    kwargs.setdefault("collector_id", "endpoint-primary")
    kwargs.setdefault("source_system", "endpoint_agent")
    kwargs.setdefault("collector_version", "0.1.0")
    kwargs.setdefault("schema_version", "1.0")
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build_endpoint_signal_collector_contract(**kwargs)


def _literal_strings(node: ast.AST) -> set[str]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and type(child.value) is str
    }


def _endpoint_agent_emitted_event_types(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    event_types: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "event_type"
                ):
                    event_types.update(_literal_strings(value))
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
            )
            if any(
                isinstance(target, ast.Name) and target.id == "event_type"
                for target in targets
            ):
                event_types.update(_literal_strings(node.value))
    return event_types


def _endpoint_ingest_normalized_event_types(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    ingest_function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "ingest_endpoint_signal"
    )
    return {
        value
        for node in ast.walk(ingest_function)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "event_type"
        for value in _literal_strings(keyword.value)
    }


def test_declaration_fields_are_explicit_and_unknown_by_default() -> None:
    signature = inspect.signature(build_endpoint_signal_collector_contract)
    for field_name in (
        "tenant_id",
        "collector_id",
        "source_system",
        "collector_version",
        "schema_version",
        "evaluated_at",
    ):
        assert signature.parameters[field_name].default is inspect.Parameter.empty

    contract = _build_contract()

    assert contract.tenant_id == "tenant-a"
    assert contract.collector_id == "endpoint-primary"
    assert contract.collector_type == ENDPOINT_SIGNAL_COLLECTOR_TYPE == "endpoint_signal"
    assert contract.collector_version == "0.1.0"
    assert contract.source_system == ENDPOINT_SIGNAL_SOURCE_SYSTEM == "endpoint_agent"
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == ENDPOINT_SIGNAL_OBSERVATION_TYPES
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_adapter_declares_only_existing_endpoint_runtime_vocabulary() -> None:
    assert ENDPOINT_SIGNAL_OBSERVATION_TYPES == (
        "ai_tool_discovered",
        "chatgpt_desktop_observation",
        "device_audio_notetaker_control_applied",
        "device_audio_notetaker_detected",
        "meeting_ai_notetaker_detected",
        "shadow_ai.endpoint_discovered",
    )

    notetaker_module = (
        _REPO_ROOT
        / "apps/endpoint-agent/src/hawk_endpoint_agent/modules/notetaker.py"
    )
    desktop_module = (
        _REPO_ROOT
        / "apps/endpoint-agent/src/hawk_endpoint_agent/modules/desktop_native.py"
    )
    shadow_module = (
        _REPO_ROOT
        / "apps/endpoint-agent/src/hawk_endpoint_agent/modules/shadow_ai.py"
    )
    endpoint_normalizer = (
        _REPO_ROOT
        / "apps/api/app/services/shadow_ai/endpoint_ingest_service.py"
    )

    emitted = set().union(
        _endpoint_agent_emitted_event_types(notetaker_module),
        _endpoint_agent_emitted_event_types(desktop_module),
        _endpoint_agent_emitted_event_types(shadow_module),
    )
    normalized = _endpoint_ingest_normalized_event_types(
        endpoint_normalizer
    )

    assert emitted == {
        "ai_tool_discovered",
        "chatgpt_desktop_observation",
        "device_audio_notetaker_control_applied",
        "device_audio_notetaker_detected",
        "meeting_ai_notetaker_detected",
    }
    # ``ingest_endpoint_signal`` is itself the existing endpoint-signal
    # producer. Its exact normalized runtime event belongs in this adapter even
    # though it is emitted in the API rather than the endpoint-agent package.
    assert normalized == {"shadow_ai.endpoint_discovered"}
    assert set(ENDPOINT_SIGNAL_OBSERVATION_TYPES) == emitted | normalized

    for non_runtime_signal_type in (
        "endpoint.agent.heartbeat",
        "endpoint.agent.evidence",
        "endpoint.notetaker.detected",
        "shadow_ai.endpoint.signal",
    ):
        assert non_runtime_signal_type not in ENDPOINT_SIGNAL_OBSERVATION_TYPES


def test_verified_current_evidence_projects_only_explicit_values() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={
                "endpoint.events.read": True,
                "endpoint.metadata.read": True,
            },
            last_success=datetime(2026, 7, 24, 9, 30, tzinfo=timezone.utc),
            last_failure=datetime(2026, 7, 23, 9, 0, tzinfo=timezone.utc),
            authoritative_data_residency="uae-north",
            control_capability="monitor_only",
        ),
    )

    assert contract.health == "healthy"
    assert contract.permissions == {
        "endpoint.events.read": True,
        "endpoint.metadata.read": True,
    }
    assert contract.last_success == datetime(
        2026,
        7,
        24,
        9,
        30,
        tzinfo=timezone.utc,
    )
    assert contract.last_failure == datetime(
        2026,
        7,
        23,
        9,
        0,
        tzinfo=timezone.utc,
    )
    assert contract.data_residency == "uae-north"
    assert contract.control_capability == "monitor_only"


@pytest.mark.parametrize(
    ("verified", "current"),
    [
        (False, False),
        (False, True),
        (True, False),
    ],
)
def test_unverified_or_noncurrent_evidence_cannot_upgrade_unknowns(
    verified: bool,
    current: bool,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=EndpointSignalCollectorEvidence(
            tenant_id="tenant-a",
            collector_id="endpoint-primary",
            source_system="endpoint_agent",
            collector_version="0.1.0",
            schema_version="1.0",
            verified=verified,
            current=current,
            observed_at=_EVALUATED_AT,
            health="healthy",
            verified_permissions={"endpoint.events.read": True},
            last_success=_EVALUATED_AT,
            authoritative_data_residency="uae-north",
            control_capability="inline",
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_freshness_uses_shared_two_minute_warning_boundary() -> None:
    assert ENDPOINT_SIGNAL_EVIDENCE_MAX_AGE == timedelta(minutes=2)

    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            observed_at=_EVALUATED_AT - ENDPOINT_SIGNAL_EVIDENCE_MAX_AGE,
            health="healthy",
            verified_permissions={"endpoint.events.read": True},
            authoritative_data_residency="uae-north",
            control_capability="monitor_only",
        ),
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"endpoint.events.read": True}
    assert contract.data_residency == "uae-north"
    assert contract.control_capability == "monitor_only"


@pytest.mark.parametrize(
    "first_offset",
    [
        timedelta(hours=1),
        timedelta(hours=-1),
    ],
)
def test_stateful_observation_cannot_turn_stale_or_future_evidence_current(
    first_offset: timedelta,
) -> None:
    secret = "secret-second-offset-call"

    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta:
            self.calls += 1
            if self.calls == 1:
                return first_offset
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    stateful_tz = StatefulTimezone()
    observed_at = datetime(
        2026,
        7,
        24,
        10,
        0,
        tzinfo=stateful_tz,
    )

    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"endpoint.events.read": True},
            authoritative_data_residency="uae-north",
            control_capability="inline",
        )
    )

    assert stateful_tz.calls == 1
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"
    assert secret not in contract.canonical_json()


def test_stateful_evaluation_timestamp_is_normalized_once() -> None:
    secret = "secret-second-evaluation-offset-call"

    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta:
            self.calls += 1
            if self.calls == 1:
                return timedelta(0)
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    stateful_tz = StatefulTimezone()
    evaluated_at = datetime(
        2026,
        7,
        24,
        10,
        0,
        tzinfo=stateful_tz,
    )

    contract = _build_contract(evaluated_at=evaluated_at)

    assert stateful_tz.calls == 1
    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"
    assert secret not in contract.canonical_json()


@pytest.mark.parametrize(
    "observed_at",
    [
        _EVALUATED_AT - timedelta(minutes=2, microseconds=1),
        _EVALUATED_AT + timedelta(microseconds=1),
        _EVALUATED_AT + timedelta(days=1),
    ],
)
def test_stale_or_any_future_evidence_cannot_upgrade_unknowns(
    observed_at: datetime,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"endpoint.events.read": True},
            authoritative_data_residency="uae-north",
            control_capability="inline",
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    ("binding", "value"),
    [
        ("tenant_id", "tenant-b"),
        ("collector_id", "endpoint-secondary"),
        ("source_system", "other_endpoint_source"),
        ("collector_version", "0.0.9"),
        ("schema_version", "0.9"),
    ],
)
def test_cross_scope_or_declaration_replay_cannot_upgrade_unknowns(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"endpoint.events.read": True},
                "authoritative_data_residency": "uae-north",
                "control_capability": "inline",
            }
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_changing_reported_runtime_version_requires_same_version_evidence() -> None:
    old_evidence = _current_evidence(
        collector_version="0.1.0",
        health="healthy",
        verified_permissions={"endpoint.events.read": True},
        control_capability="inline",
    )
    changed = _build_contract(
        collector_version="0.1.1",
        evidence=old_evidence,
    )

    assert changed.collector_version == "0.1.1"
    assert changed.health == "unknown"
    assert changed.permissions == {"unknown": None}
    assert changed.control_capability == "unknown"

    matching = _build_contract(
        collector_version="0.1.1",
        evidence=_current_evidence(
            collector_version="0.1.1",
            health="healthy",
            verified_permissions={"endpoint.events.read": True},
            control_capability="monitor_only",
        ),
    )

    assert matching.collector_version == "0.1.1"
    assert matching.health == "healthy"
    assert matching.control_capability == "monitor_only"


def test_contract_projects_reported_endpoint_runtime_version() -> None:
    endpoint_init = ast.parse(
        (
            _REPO_ROOT
            / "apps/endpoint-agent/src/hawk_endpoint_agent/__init__.py"
        ).read_text(encoding="utf-8")
    )
    reported_version = next(
        node.value.value
        for node in endpoint_init.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is str
    )

    contract = _build_contract(collector_version=reported_version)

    assert reported_version == "0.2.1"
    assert contract.collector_version == reported_version


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("source_system", "other_endpoint_source"),
        ("schema_version", "0.9"),
    ],
)
def test_wrong_source_or_schema_declaration_is_rejected(
    field_name: str,
    value: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="^invalid endpoint signal collector declaration$",
    ) as captured:
        _build_contract(**{field_name: value})

    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("tenant_id", "tenant-a"),
        ("collector_id", "endpoint-primary"),
        ("source_system", "endpoint_agent"),
        ("collector_version", "0.1.0"),
        ("schema_version", "1.0"),
    ],
)
def test_declaration_rejects_string_subclasses_without_evaluating_them(
    field_name: str,
    value: str,
) -> None:
    secret = "secret-declaration-method"

    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError(secret)

        def __hash__(self) -> int:
            raise AssertionError(secret)

        def strip(self, *_args: object, **_kwargs: object) -> str:
            raise AssertionError(secret)

    with pytest.raises(
        ValueError,
        match="^invalid endpoint signal collector declaration$",
    ) as captured:
        _build_contract(**{field_name: HostileString(value)})

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    "collector_version",
    [
        "",
        "version with space",
        "v" * 65,
    ],
)
def test_invalid_reported_runtime_version_uses_sanitized_contract_error(
    collector_version: str,
) -> None:
    with pytest.raises(ValidationError):
        _build_contract(collector_version=collector_version)


def test_truthy_boolean_and_equality_spoofs_are_not_evaluated() -> None:
    class Spoof:
        def __bool__(self) -> bool:
            raise AssertionError("secret-bool-text")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-equality-text")

    boolean_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            verified=Spoof(),
            health="healthy",
            control_capability="inline",
        ),
    )
    current_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            current=Spoof(),
            health="healthy",
            control_capability="inline",
        ),
    )
    binding_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            tenant_id=Spoof(),
            health="healthy",
            control_capability="inline",
        ),
    )

    assert boolean_spoof.health == "unknown"
    assert boolean_spoof.control_capability == "unknown"
    assert current_spoof.health == "unknown"
    assert current_spoof.control_capability == "unknown"
    assert binding_spoof.health == "unknown"
    assert binding_spoof.control_capability == "unknown"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("tenant_id", "tenant-a"),
        ("collector_id", "endpoint-primary"),
        ("source_system", "endpoint_agent"),
        ("collector_version", "0.1.0"),
        ("schema_version", "1.0"),
    ],
)
def test_string_subclass_binding_is_not_compared_or_trusted(
    field_name: str,
    value: str,
) -> None:
    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-string-equality-text")

    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            **{field_name: HostileString(value)},
            health="healthy",
            control_capability="inline",
        ),
    )

    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"


def test_nonexact_or_hostile_evidence_type_is_rejected_without_access() -> None:
    secret = "secret-hostile-evidence-text"

    class HostileEvidence(EndpointSignalCollectorEvidence):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)

    with pytest.raises(
        ValueError,
        match="^invalid endpoint signal collector evidence$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="endpoint-primary",
            evidence=hostile,
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize("field_name", ["evaluated_at", "observed_at"])
@pytest.mark.parametrize("kind", ["subclass", "hostile_tzinfo"])
def test_hostile_timestamps_raise_fixed_safe_error(
    field_name: str,
    kind: str,
) -> None:
    secret = "secret-hostile-timestamp-text"

    class HostileDatetime(datetime):
        def utcoffset(self) -> timedelta | None:
            raise AssertionError(secret)

    class HostileTimezone(tzinfo):
        def utcoffset(self, _dt: datetime | None) -> timedelta | None:
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

        def tzname(self, _dt: datetime | None) -> str | None:
            return "hostile"

    if kind == "subclass":
        hostile_timestamp: datetime = HostileDatetime(
            2026,
            7,
            24,
            10,
            0,
            tzinfo=timezone.utc,
        )
    else:
        hostile_timestamp = datetime(
            2026,
            7,
            24,
            10,
            0,
            tzinfo=HostileTimezone(),
        )

    kwargs: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "endpoint-primary",
        "source_system": "endpoint_agent",
        "collector_version": "0.1.0",
        "schema_version": "1.0",
    }
    if field_name == "evaluated_at":
        kwargs["evaluated_at"] = hostile_timestamp
        kwargs["evidence"] = _current_evidence()
    else:
        kwargs["evaluated_at"] = _EVALUATED_AT
        kwargs["evidence"] = _current_evidence(observed_at=hostile_timestamp)

    with pytest.raises(
        ValueError,
        match="^invalid endpoint signal collector timestamp$",
    ) as captured:
        build_endpoint_signal_collector_contract(**kwargs)  # type: ignore[arg-type]

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("field_name", "invalid_timestamp"),
    [
        ("evaluated_at", None),
        ("evaluated_at", datetime(2026, 7, 24, 10, 0)),
        ("evaluated_at", "2026-07-24T10:00:00Z"),
        ("observed_at", None),
        ("observed_at", datetime(2026, 7, 24, 10, 0)),
        ("observed_at", "2026-07-24T10:00:00Z"),
        ("last_success", datetime(2026, 7, 24, 10, 0)),
        ("last_success", "2026-07-24T10:00:00Z"),
        ("last_failure", datetime(2026, 7, 24, 10, 0)),
        ("last_failure", "2026-07-24T10:00:00Z"),
    ],
)
def test_trusted_path_requires_exact_aware_datetimes(
    field_name: str,
    invalid_timestamp: object,
) -> None:
    kwargs: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "endpoint-primary",
        "source_system": "endpoint_agent",
        "collector_version": "0.1.0",
        "schema_version": "1.0",
        "evaluated_at": _EVALUATED_AT,
        "evidence": _current_evidence(),
    }
    if field_name == "evaluated_at":
        kwargs["evaluated_at"] = invalid_timestamp
    else:
        kwargs["evidence"] = _current_evidence(
            **{field_name: invalid_timestamp}
        )

    with pytest.raises(
        ValueError,
        match="^invalid endpoint signal collector timestamp$",
    ):
        build_endpoint_signal_collector_contract(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
@pytest.mark.parametrize(
    "invalid_timestamp",
    [
        _EVALUATED_AT - timedelta(minutes=1),
        _EVALUATED_AT + timedelta(microseconds=1),
    ],
)
def test_trusted_evidence_rejects_result_timestamps_after_observation_or_evaluation(
    field_name: str,
    invalid_timestamp: datetime,
) -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1, microseconds=1)

    with pytest.raises(
        ValueError,
        match="^invalid endpoint signal collector timestamp$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="endpoint-primary",
            evidence=_current_evidence(
                observed_at=observed_at,
                **{field_name: invalid_timestamp},
            ),
        )

    assert captured.value.__cause__ is None


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
def test_stateful_result_timestamp_cannot_reverse_invalid_chronology(
    field_name: str,
) -> None:
    secret = "secret-second-result-offset-call"

    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta:
            self.calls += 1
            if self.calls == 1:
                return -timedelta(hours=1)
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    stateful_tz = StatefulTimezone()
    result_timestamp = datetime(
        2026,
        7,
        24,
        9,
        59,
        tzinfo=stateful_tz,
    )

    with pytest.raises(
        ValueError,
        match="^invalid endpoint signal collector timestamp$",
    ) as captured:
        _build_contract(
            evidence=_current_evidence(
                observed_at=_EVALUATED_AT - timedelta(seconds=30),
                **{field_name: result_timestamp},
            )
        )

    assert stateful_tz.calls == 1
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_trusted_result_timestamps_may_equal_observation_time() -> None:
    observed_at = _EVALUATED_AT - timedelta(seconds=30)
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            last_success=observed_at,
            last_failure=observed_at,
        ),
    )

    assert contract.last_success == observed_at
    assert contract.last_failure == observed_at


def test_installed_or_running_state_never_infers_inline_control() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={
                "endpoint.agent.installed": True,
                "endpoint.agent.running": True,
                "endpoint.events.read": True,
            },
        ),
    )

    assert contract.health == "healthy"
    assert contract.permissions["endpoint.agent.installed"] is True
    assert contract.permissions["endpoint.agent.running"] is True
    assert contract.control_capability == "unknown"


def test_adapter_preserves_contract_immutability_privacy_and_safe_errors() -> None:
    permission_evidence = {"endpoint.events.read": True}
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="endpoint-primary",
        evidence=_current_evidence(
            verified_permissions=permission_evidence,
        ),
    )
    original_hash = contract.contract_hash
    permission_evidence["endpoint.events.read"] = False

    assert type(contract.permissions) is MappingProxyType
    with pytest.raises(TypeError):
        contract.permissions["endpoint.events.read"] = False  # type: ignore[index]
    assert contract.permissions == {"endpoint.events.read": True}
    assert contract.contract_hash == original_hash

    secret = "sk-endpoint-collector-secret-abcdefghijk"
    with pytest.raises(ValidationError) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="endpoint-primary",
            evidence=_current_evidence(
                verified_permissions={secret: True},
            ),
        )

    assert secret not in str(captured.value)
    assert secret not in json.dumps(captured.value.errors(), sort_keys=True)


def test_adapter_import_does_not_load_database_or_runtime_settings_modules() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys;"
                "import app.services.discovery_collector_endpoint_signal_adapter;"
                "assert 'sqlalchemy' not in sys.modules;"
                "assert 'app.core.config' not in sys.modules;"
                "assert 'app.db.session' not in sys.modules"
            ),
        ],
        cwd=_REPO_ROOT / "apps/api",
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
