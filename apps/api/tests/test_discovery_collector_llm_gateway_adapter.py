from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest
from pydantic import ValidationError

from app.services import discovery_collector_llm_gateway_adapter as adapter_module
from app.services.discovery_collector_contract import (
    COLLECTOR_CONTRACT_SCHEMA_VERSION,
)
from app.services.discovery_collector_llm_gateway_adapter import (
    LLM_GATEWAY_ADAPTER_VERSION,
    LLM_GATEWAY_EVIDENCE_MAX_AGE,
    LLM_GATEWAY_OBSERVATION_TYPES,
    LLM_GATEWAY_SOURCE_SYSTEM,
    LLMGatewayCollectorEvidence,
    build_llm_gateway_collector_contract,
)
from app.services.health_freshness import (
    COLLECTOR_EVIDENCE_MAX_AGE,
    HEARTBEAT_OFFLINE_AGE,
    HEARTBEAT_WARNING_AGE,
)


_EVALUATED_AT = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)


def _current_evidence(**overrides: object) -> LLMGatewayCollectorEvidence:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "gateway-primary",
        "source_system": "llm_gateway",
        "collector_version": LLM_GATEWAY_ADAPTER_VERSION,
        "schema_version": COLLECTOR_CONTRACT_SCHEMA_VERSION,
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return LLMGatewayCollectorEvidence(**values)  # type: ignore[arg-type]


def _build_contract(**kwargs: Any):
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build_llm_gateway_collector_contract(**kwargs)


def test_adapter_defaults_to_unknown_without_direct_current_evidence() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
    )

    assert contract.tenant_id == "tenant-a"
    assert contract.collector_id == "gateway-primary"
    assert contract.collector_type == "llm_gateway"
    assert contract.collector_version == LLM_GATEWAY_ADAPTER_VERSION == "1.0.0"
    assert contract.source_system == LLM_GATEWAY_SOURCE_SYSTEM == "llm_gateway"
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == LLM_GATEWAY_OBSERVATION_TYPES
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_verified_current_evidence_projects_exact_declared_capabilities() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={
                "runtime.actions.authorize": True,
                "runtime.events.read": True,
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
        "runtime.actions.authorize": True,
        "runtime.events.read": True,
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
        collector_id="gateway-primary",
        evidence=LLMGatewayCollectorEvidence(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            source_system="llm_gateway",
            collector_version=LLM_GATEWAY_ADAPTER_VERSION,
            schema_version=COLLECTOR_CONTRACT_SCHEMA_VERSION,
            verified=verified,
            current=current,
            observed_at=datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc),
            health="healthy",
            verified_permissions={"runtime.actions.authorize": True},
            last_success=datetime(2026, 7, 24, 9, 0, tzinfo=timezone.utc),
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
    assert COLLECTOR_EVIDENCE_MAX_AGE == timedelta(minutes=2)
    assert HEARTBEAT_WARNING_AGE == timedelta(minutes=2)
    assert HEARTBEAT_OFFLINE_AGE == timedelta(minutes=15)
    assert LLM_GATEWAY_EVIDENCE_MAX_AGE == COLLECTOR_EVIDENCE_MAX_AGE

    at_boundary = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            observed_at=_EVALUATED_AT - LLM_GATEWAY_EVIDENCE_MAX_AGE,
            health="healthy",
            verified_permissions={"runtime.events.read": True},
            authoritative_data_residency="uae-north",
            control_capability="inline",
        ),
    )

    assert at_boundary.health == "healthy"
    assert at_boundary.permissions == {"runtime.events.read": True}
    assert at_boundary.data_residency == "uae-north"
    assert at_boundary.control_capability == "inline"


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
        collector_id="gateway-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"runtime.events.read": True},
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
        ("collector_id", "gateway-secondary"),
        ("source_system", "other_gateway"),
    ],
)
def test_cross_scope_or_source_replay_cannot_upgrade_unknowns(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"runtime.events.read": True},
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
def test_old_or_mismatched_version_evidence_cannot_upgrade_unknowns(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"runtime.events.read": True},
                "authoritative_data_residency": "uae-north",
                "control_capability": "inline",
            }
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_adapter_version_change_invalidates_preupgrade_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preupgrade_evidence = _current_evidence(
        health="healthy",
        verified_permissions={"runtime.events.read": True},
        authoritative_data_residency="uae-north",
        control_capability="inline",
    )
    monkeypatch.setattr(
        adapter_module,
        "LLM_GATEWAY_ADAPTER_VERSION",
        "2.0.0",
    )

    contract = adapter_module.build_llm_gateway_collector_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evaluated_at=_EVALUATED_AT,
        evidence=preupgrade_evidence,
    )

    assert contract.collector_version == "2.0.0"
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    "binding",
    ["collector_version", "schema_version"],
)
def test_version_binding_string_subclasses_are_not_compared(
    binding: str,
) -> None:
    secret = "secret-version-equality-spoof"

    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError(secret)

    expected = (
        LLM_GATEWAY_ADAPTER_VERSION
        if binding == "collector_version"
        else COLLECTOR_CONTRACT_SCHEMA_VERSION
    )
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            **{
                binding: HostileString(expected),
                "health": "healthy",
                "control_capability": "inline",
            }
        ),
    )

    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"


def test_truthy_boolean_and_equality_spoofs_are_not_evaluated() -> None:
    class Spoof:
        def __bool__(self) -> bool:
            raise AssertionError("secret-bool-text")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-equality-text")

    boolean_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            verified=Spoof(),
            health="healthy",
            control_capability="inline",
        ),
    )
    binding_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            tenant_id=Spoof(),
            health="healthy",
            control_capability="inline",
        ),
    )

    assert boolean_spoof.health == "unknown"
    assert boolean_spoof.control_capability == "unknown"
    assert binding_spoof.health == "unknown"
    assert binding_spoof.control_capability == "unknown"


def test_nonexact_or_hostile_evidence_type_is_rejected_without_access() -> None:
    secret = "secret-hostile-evidence-text"

    class HostileEvidence(LLMGatewayCollectorEvidence):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)

    with pytest.raises(
        ValueError,
        match="^invalid LLM Gateway collector evidence$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            evidence=hostile,
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize("kind", ["subclass", "hostile_tzinfo"])
def test_hostile_observation_timestamps_raise_fixed_safe_error(kind: str) -> None:
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
        observed_at: datetime = HostileDatetime(
            2026,
            7,
            24,
            10,
            0,
            tzinfo=timezone.utc,
        )
    else:
        observed_at = datetime(
            2026,
            7,
            24,
            10,
            0,
            tzinfo=HostileTimezone(),
        )

    with pytest.raises(
        ValueError,
        match="^invalid LLM Gateway collector timestamp$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            evidence=_current_evidence(observed_at=observed_at),
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


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
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"runtime.events.read": True},
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


@pytest.mark.parametrize("timestamp_field", ["last_success", "last_failure"])
@pytest.mark.parametrize(
    "future_timestamp",
    [
        _EVALUATED_AT - timedelta(minutes=1) + timedelta(microseconds=1),
        _EVALUATED_AT + timedelta(microseconds=1),
    ],
)
def test_trusted_event_timestamps_cannot_be_after_observation(
    timestamp_field: str,
    future_timestamp: datetime,
) -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1)
    with pytest.raises(
        ValueError,
        match="^invalid LLM Gateway collector timestamp$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            evidence=_current_evidence(
                observed_at=observed_at,
                health="healthy",
                control_capability="inline",
                **{
                    timestamp_field: future_timestamp,
                },
            ),
        )

    assert captured.value.__cause__ is None


@pytest.mark.parametrize("timestamp_field", ["last_success", "last_failure"])
def test_hostile_trusted_event_timestamp_errors_never_expose_secret(
    timestamp_field: str,
) -> None:
    secret = "secret-hostile-event-timestamp"

    class HostileTimezone(tzinfo):
        def utcoffset(self, _dt: datetime | None) -> timedelta | None:
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    hostile_timestamp = datetime(
        2026,
        7,
        24,
        9,
        0,
        tzinfo=HostileTimezone(),
    )

    with pytest.raises(
        ValueError,
        match="^invalid LLM Gateway collector timestamp$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            evidence=_current_evidence(
                health="healthy",
                control_capability="inline",
                **{timestamp_field: hostile_timestamp},
            ),
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_adapter_import_is_independent_of_settings_database_and_deployment_stack() -> None:
    api_root = Path(__file__).resolve().parents[1]
    script = f"""
import sys
sys.path.insert(0, {str(api_root)!r})
import app.services.discovery_collector_llm_gateway_adapter
for forbidden in (
    "app.core.config",
    "app.db",
    "app.services.control_coverage.deployment_surfaces",
    "sqlalchemy",
):
    if any(name == forbidden or name.startswith(forbidden + ".") for name in sys.modules):
        raise AssertionError(forbidden)
print("standalone adapter import passed")
"""
    completed = subprocess.run(
        [sys.executable, "-E", "-c", script],
        cwd="/",
        env={},
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "standalone adapter import passed"


def test_authorize_permission_does_not_infer_inline_capability() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={"runtime.actions.authorize": True},
        ),
    )

    assert contract.permissions == {"runtime.actions.authorize": True}
    assert contract.control_capability == "unknown"


def test_residency_stays_unknown_without_authoritative_residency_input() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(health="healthy"),
    )

    assert contract.health == "healthy"
    assert contract.data_residency == "unknown"


@pytest.mark.parametrize(
    "observed_at",
    [
        None,
        datetime(2026, 7, 24, 10, 0),
        "2026-07-24T10:00:00Z",
    ],
)
def test_verified_current_evidence_requires_aware_observed_at(
    observed_at: object,
) -> None:
    with pytest.raises(ValueError):
        _build_contract(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            evidence=LLMGatewayCollectorEvidence(
                tenant_id="tenant-a",
                collector_id="gateway-primary",
                source_system="llm_gateway",
                collector_version=LLM_GATEWAY_ADAPTER_VERSION,
                schema_version=COLLECTOR_CONTRACT_SCHEMA_VERSION,
                verified=True,
                current=True,
                observed_at=observed_at,  # type: ignore[arg-type]
            ),
        )


def test_verified_evidence_timestamps_must_be_aware_datetimes() -> None:
    with pytest.raises(ValueError):
        _build_contract(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            evidence=_current_evidence(
                last_success=datetime(2026, 7, 24, 9, 0),
            ),
        )


def test_adapter_preserves_contract_privacy_bounds_and_safe_errors() -> None:
    secret = "sk-collector-secret-abcdefghijk"
    with pytest.raises(ValidationError) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="gateway-primary",
            evidence=_current_evidence(
                verified_permissions={secret: True},
            ),
        )

    assert secret not in str(captured.value)
    assert secret not in json.dumps(captured.value.errors(), sort_keys=True)


def test_adapter_returns_deeply_immutable_contract_material() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="gateway-primary",
        evidence=_current_evidence(
            verified_permissions={"runtime.events.read": True},
        ),
    )
    original_hash = contract.contract_hash

    with pytest.raises(TypeError):
        contract.permissions["runtime.events.read"] = False

    assert contract.contract_hash == original_hash
