from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest
from pydantic import ValidationError

import app.services.discovery_collector_mcp_gateway_adapter as mcp_adapter
from app.services.discovery_collector_mcp_gateway_adapter import (
    MCP_GATEWAY_ADAPTER_VERSION,
    MCP_GATEWAY_EVIDENCE_MAX_AGE,
    MCP_GATEWAY_OBSERVATION_TYPES,
    MCP_GATEWAY_SOURCE_SYSTEM,
    MCPGatewayCollectorEvidence,
    build_mcp_gateway_collector_contract,
)


_EVALUATED_AT = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)


def _current_evidence(**overrides: object) -> MCPGatewayCollectorEvidence:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "mcp-gateway-primary",
        "source_system": "mcp_gateway",
        "collector_version": MCP_GATEWAY_ADAPTER_VERSION,
        "schema_version": "1.0",
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return MCPGatewayCollectorEvidence(**values)  # type: ignore[arg-type]


def _build_contract(**kwargs: Any):
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build_mcp_gateway_collector_contract(**kwargs)


def test_adapter_defaults_to_unknown_without_direct_current_evidence() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
    )

    assert contract.tenant_id == "tenant-a"
    assert contract.collector_id == "mcp-gateway-primary"
    assert contract.collector_type == "mcp_gateway"
    assert contract.collector_version == MCP_GATEWAY_ADAPTER_VERSION == "1.0.0"
    assert contract.source_system == MCP_GATEWAY_SOURCE_SYSTEM == "mcp_gateway"
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == MCP_GATEWAY_OBSERVATION_TYPES
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_adapter_declares_only_existing_mcp_gateway_runtime_vocabulary() -> None:
    assert MCP_GATEWAY_OBSERVATION_TYPES == (
        "mcp_authorize",
        "mcp_tool_call_allowed",
        "mcp_tool_call_blocked",
        "mcp_tool_call_denied",
        "mcp_tool_call_requested",
    )
    assert "mcp_tool_call_approved" not in MCP_GATEWAY_OBSERVATION_TYPES
    assert "mcp_tool_result_returned" not in MCP_GATEWAY_OBSERVATION_TYPES
    assert "mcp_tool_scanned" not in MCP_GATEWAY_OBSERVATION_TYPES
    assert "mcp_tool_execute" not in MCP_GATEWAY_OBSERVATION_TYPES


def test_verified_current_evidence_projects_exact_declared_capabilities() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={
                "mcp.actions.authorize": True,
                "mcp.events.read": True,
            },
            last_success=datetime(
                2026,
                7,
                24,
                9,
                30,
                tzinfo=timezone.utc,
            ),
            last_failure=datetime(
                2026,
                7,
                23,
                9,
                0,
                tzinfo=timezone.utc,
            ),
            authoritative_data_residency="uae-north",
            control_capability="inline",
        ),
    )

    assert contract.health == "healthy"
    assert contract.permissions == {
        "mcp.actions.authorize": True,
        "mcp.events.read": True,
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
    assert contract.control_capability == "inline"


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
        collector_id="mcp-gateway-primary",
        evidence=MCPGatewayCollectorEvidence(
            tenant_id="tenant-a",
            collector_id="mcp-gateway-primary",
            source_system="mcp_gateway",
            collector_version=MCP_GATEWAY_ADAPTER_VERSION,
            schema_version="1.0",
            verified=verified,
            current=current,
            observed_at=_EVALUATED_AT,
            health="healthy",
            verified_permissions={"mcp.actions.authorize": True},
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
    assert MCP_GATEWAY_EVIDENCE_MAX_AGE == timedelta(minutes=2)

    at_boundary = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            observed_at=_EVALUATED_AT - MCP_GATEWAY_EVIDENCE_MAX_AGE,
            health="healthy",
            verified_permissions={"mcp.events.read": True},
            authoritative_data_residency="uae-north",
            control_capability="inline",
        ),
    )

    assert at_boundary.health == "healthy"
    assert at_boundary.permissions == {"mcp.events.read": True}
    assert at_boundary.data_residency == "uae-north"
    assert at_boundary.control_capability == "inline"


def test_adapter_import_does_not_load_database_or_settings_modules() -> None:
    api_root = Path(__file__).resolve().parents[1]
    script = f"""
import sys
sys.path.insert(0, {str(api_root)!r})
from app.services.discovery_collector_mcp_gateway_adapter import MCP_GATEWAY_EVIDENCE_MAX_AGE
for forbidden in (
    "app.core.config",
    "app.db",
    "app.services.control_coverage.deployment_surfaces",
    "sqlalchemy",
):
    assert not any(
        name == forbidden or name.startswith(forbidden + ".")
        for name in sys.modules
    )
assert MCP_GATEWAY_EVIDENCE_MAX_AGE.total_seconds() == 120
"""

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd="/",
        env={},
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr


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
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"mcp.events.read": True},
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
        ("collector_id", "mcp-gateway-secondary"),
        ("source_system", "other_gateway"),
    ],
)
def test_cross_scope_or_source_replay_cannot_upgrade_unknowns(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"mcp.events.read": True},
                "authoritative_data_residency": "uae-north",
                "control_capability": "inline",
            }
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    ("binding", "value"),
    [
        ("collector_version", "0.9.0"),
        ("schema_version", "0.9"),
    ],
)
def test_version_or_schema_replay_cannot_upgrade_unknowns(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"mcp.events.read": True},
                "last_success": _EVALUATED_AT,
                "last_failure": _EVALUATED_AT,
                "authoritative_data_residency": "uae-north",
                "control_capability": "inline",
            }
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_evidence_created_before_adapter_version_change_remains_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = _current_evidence(
        health="healthy",
        verified_permissions={"mcp.events.read": True},
        last_success=_EVALUATED_AT,
        authoritative_data_residency="uae-north",
        control_capability="inline",
    )
    monkeypatch.setattr(
        mcp_adapter,
        "MCP_GATEWAY_ADAPTER_VERSION",
        "1.0.1",
    )

    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=evidence,
    )

    assert contract.collector_version == "1.0.1"
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_truthy_boolean_and_equality_spoofs_are_not_evaluated() -> None:
    class Spoof:
        def __bool__(self) -> bool:
            raise AssertionError("secret-bool-text")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-equality-text")

    boolean_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            verified=Spoof(),
            health="healthy",
            control_capability="inline",
        ),
    )
    current_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            current=Spoof(),
            health="healthy",
            control_capability="inline",
        ),
    )
    binding_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
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


def test_string_subclass_binding_is_not_compared_or_trusted() -> None:
    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-string-equality-text")

    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            tenant_id=HostileString("tenant-a"),
            health="healthy",
            control_capability="inline",
        ),
    )

    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    "binding",
    ["collector_version", "schema_version"],
)
def test_version_or_schema_string_subclass_is_not_compared_or_trusted(
    binding: str,
) -> None:
    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-version-equality-text")

    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            **{
                binding: HostileString(
                    MCP_GATEWAY_ADAPTER_VERSION
                    if binding == "collector_version"
                    else "1.0"
                ),
                "health": "healthy",
                "verified_permissions": {"mcp.events.read": True},
                "last_success": _EVALUATED_AT,
                "authoritative_data_residency": "uae-north",
                "control_capability": "inline",
            }
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_nonexact_or_hostile_evidence_type_is_rejected_without_access() -> None:
    secret = "secret-hostile-evidence-text"

    class HostileEvidence(MCPGatewayCollectorEvidence):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)

    with pytest.raises(
        ValueError,
        match="^invalid MCP Gateway collector evidence$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="mcp-gateway-primary",
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
        "collector_id": "mcp-gateway-primary",
    }
    if field_name == "evaluated_at":
        kwargs["evaluated_at"] = hostile_timestamp
        kwargs["evidence"] = _current_evidence()
    else:
        kwargs["evaluated_at"] = _EVALUATED_AT
        kwargs["evidence"] = _current_evidence(observed_at=hostile_timestamp)

    with pytest.raises(
        ValueError,
        match="^invalid MCP Gateway collector timestamp$",
    ) as captured:
        build_mcp_gateway_collector_contract(**kwargs)  # type: ignore[arg-type]

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    error_chain: list[str] = []
    current_error: BaseException | None = captured.value
    seen_errors: set[int] = set()
    while current_error is not None and id(current_error) not in seen_errors:
        seen_errors.add(id(current_error))
        error_chain.append(str(current_error))
        current_error = current_error.__cause__ or current_error.__context__
    assert secret not in "\n".join(error_chain)


@pytest.mark.parametrize(
    "first_offset",
    [
        timedelta(hours=1),
        timedelta(hours=-1),
    ],
)
def test_stateful_observation_offset_cannot_turn_stale_or_future_evidence_current(
    first_offset: timedelta,
) -> None:
    secret = "secret-stateful-observation-offset"

    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta:
            self.calls += 1
            if self.calls == 1:
                return first_offset
            if self.calls == 2:
                return timedelta(0)
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
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"mcp.events.read": True},
            authoritative_data_residency="uae-north",
            control_capability="inline",
        ),
    )

    assert stateful_tz.calls == 1
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"
    assert secret not in contract.canonical_json()


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
        "collector_id": "mcp-gateway-primary",
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
        match="^invalid MCP Gateway collector timestamp$",
    ):
        build_mcp_gateway_collector_contract(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
@pytest.mark.parametrize(
    "future_timestamp",
    [
        _EVALUATED_AT - timedelta(seconds=30) + timedelta(microseconds=1),
        _EVALUATED_AT + timedelta(microseconds=1),
    ],
)
def test_trusted_optional_timestamp_cannot_be_after_observation_or_evaluation(
    field_name: str,
    future_timestamp: datetime,
) -> None:
    observed_at = _EVALUATED_AT - timedelta(seconds=30)

    with pytest.raises(
        ValueError,
        match="^invalid MCP Gateway collector timestamp chronology$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="mcp-gateway-primary",
            evidence=_current_evidence(
                observed_at=observed_at,
                **{field_name: future_timestamp},
            ),
        )

    assert captured.value.__cause__ is None


def test_trusted_optional_timestamps_may_equal_observation_time() -> None:
    observed_at = _EVALUATED_AT - timedelta(seconds=30)
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            last_success=observed_at,
            last_failure=observed_at,
        ),
    )

    assert contract.last_success == observed_at
    assert contract.last_failure == observed_at


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
def test_stateful_optional_timestamp_cannot_bypass_chronology(
    field_name: str,
) -> None:
    secret = "secret-stateful-optional-offset"

    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta:
            self.calls += 1
            if self.calls == 1:
                return -timedelta(hours=1)
            if self.calls == 2:
                return timedelta(0)
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    stateful_tz = StatefulTimezone()
    observed_at = _EVALUATED_AT - timedelta(seconds=30)
    stateful_timestamp = datetime(
        2026,
        7,
        24,
        9,
        59,
        30,
        tzinfo=stateful_tz,
    )

    with pytest.raises(
        ValueError,
        match="^invalid MCP Gateway collector timestamp chronology$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="mcp-gateway-primary",
            evidence=_current_evidence(
                observed_at=observed_at,
                **{field_name: stateful_timestamp},
            ),
        )

    assert stateful_tz.calls == 1
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_authorize_permission_or_known_route_does_not_infer_inline_capability() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={"mcp.actions.authorize": True},
        ),
    )

    assert contract.permissions == {"mcp.actions.authorize": True}
    assert contract.observation_types_emitted[0] == "mcp_authorize"
    assert contract.control_capability == "unknown"


def test_residency_stays_unknown_without_authoritative_residency_input() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(health="healthy"),
    )

    assert contract.health == "healthy"
    assert contract.data_residency == "unknown"


def test_adapter_preserves_contract_privacy_bounds_and_safe_errors() -> None:
    secret = "sk-mcp-collector-secret-abcdefghijk"
    with pytest.raises(ValidationError) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="mcp-gateway-primary",
            evidence=_current_evidence(
                verified_permissions={secret: True},
            ),
        )

    assert secret not in str(captured.value)
    assert secret not in json.dumps(captured.value.errors(), sort_keys=True)


def test_adapter_returns_deeply_immutable_contract_material() -> None:
    permission_evidence = {"mcp.events.read": True}
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="mcp-gateway-primary",
        evidence=_current_evidence(
            verified_permissions=permission_evidence,
        ),
    )
    original_hash = contract.contract_hash
    permission_evidence["mcp.events.read"] = False

    with pytest.raises(TypeError):
        contract.permissions["mcp.events.read"] = False

    assert contract.permissions == {"mcp.events.read": True}
    assert contract.contract_hash == original_hash
