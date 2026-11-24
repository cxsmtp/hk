from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone, tzinfo
import inspect
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import pytest
from pydantic import ValidationError

from app.services.discovery_collector_browser_extension_adapter import (
    BROWSER_EXTENSION_ADAPTER_VERSION,
    BROWSER_EXTENSION_EVIDENCE_MAX_AGE,
    BROWSER_EXTENSION_OBSERVATION_TYPES,
    BROWSER_EXTENSION_SOURCE_SYSTEM,
    BrowserExtensionCollectorEvidence,
    build_browser_extension_collector_contract,
)


_EVALUATED_AT = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)


def _current_evidence(**overrides: object) -> BrowserExtensionCollectorEvidence:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "browser-extension-primary",
        "source_system": "browser_extension",
        "collector_version": "0.1.0",
        "schema_version": "1.0",
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return BrowserExtensionCollectorEvidence(**values)  # type: ignore[arg-type]


def _build_contract(**kwargs: Any):
    kwargs.setdefault("tenant_id", "tenant-a")
    kwargs.setdefault("collector_id", "browser-extension-primary")
    kwargs.setdefault("source_system", "browser_extension")
    kwargs.setdefault("collector_version", "0.1.0")
    kwargs.setdefault("schema_version", "1.0")
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build_browser_extension_collector_contract(**kwargs)


def test_adapter_defaults_to_unknown_without_direct_current_evidence() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
    )

    assert contract.tenant_id == "tenant-a"
    assert contract.collector_id == "browser-extension-primary"
    assert contract.collector_type == "browser_extension"
    assert BROWSER_EXTENSION_ADAPTER_VERSION == "1.0.0"
    assert contract.collector_version == "0.1.0"
    assert (
        contract.source_system
        == BROWSER_EXTENSION_SOURCE_SYSTEM
        == "browser_extension"
    )
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == BROWSER_EXTENSION_OBSERVATION_TYPES
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_adapter_declares_exact_current_extension_api_normalized_vocabulary() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    telemetry_source = (
        repo_root / "extension" / "src" / "telemetry.ts"
    ).read_text(encoding="utf-8")
    browser_service_source = (
        repo_root
        / "apps"
        / "api"
        / "app"
        / "services"
        / "browser_extension_service.py"
    ).read_text(encoding="utf-8")
    union = re.search(
        r"export type BrowserEventType =(?P<body>[\s\S]*?);",
        telemetry_source,
    )
    assert union is not None
    raw_event_types = set(re.findall(r'"([a-z0-9_]+)"', union.group("body")))
    expected = {
        (
            "shadow_ai.browser_unknown_domain"
            if event_type == "unknown_ai_detected"
            else (
                "shadow_ai.browser_agent_runtime_discovered"
                if event_type == "agent_runtime_discovered"
                else f"browser.{event_type}"
            )
        )
        for event_type in raw_event_types
    }
    expected.add("browser.interaction.eval")

    assert len(raw_event_types) == 35
    assert set(BROWSER_EXTENSION_OBSERVATION_TYPES) == expected
    assert len(BROWSER_EXTENSION_OBSERVATION_TYPES) == len(expected) == 36
    assert '"shadow_ai.browser_unknown_domain"' in browser_service_source
    assert '"shadow_ai.browser_agent_runtime_discovered"' in browser_service_source
    assert 'else f"browser.{event_type}"' in browser_service_source
    assert 'signal_type="browser.interaction.eval"' in browser_service_source


def test_verified_current_evidence_projects_exact_declared_capabilities() -> None:
    permissions = {
        "telemetry.browser.read": True,
        "telemetry.browser.interaction.evaluate": True,
    }
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions=permissions,
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
            control_capability="warn_only",
        ),
    )

    assert contract.health == "healthy"
    assert contract.permissions == permissions
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
    assert contract.control_capability == "warn_only"


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
        collector_id="browser-extension-primary",
        evidence=BrowserExtensionCollectorEvidence(
            tenant_id="tenant-a",
            collector_id="browser-extension-primary",
            source_system="browser_extension",
            collector_version="0.1.0",
            schema_version="1.0",
            verified=verified,
            current=current,
            observed_at=_EVALUATED_AT,
            health="healthy",
            verified_permissions={"telemetry.browser.read": True},
            last_success=_EVALUATED_AT,
            authoritative_data_residency="uae-north",
            control_capability="warn_only",
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_freshness_uses_shared_two_minute_warning_boundary() -> None:
    assert BROWSER_EXTENSION_EVIDENCE_MAX_AGE == timedelta(minutes=2)

    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            observed_at=_EVALUATED_AT - BROWSER_EXTENSION_EVIDENCE_MAX_AGE,
            health="healthy",
            verified_permissions={"telemetry.browser.read": True},
            authoritative_data_residency="uae-north",
            control_capability="warn_only",
        ),
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"telemetry.browser.read": True}
    assert contract.data_residency == "uae-north"
    assert contract.control_capability == "warn_only"


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
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"telemetry.browser.read": True},
            authoritative_data_residency="uae-north",
            control_capability="warn_only",
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
        ("collector_id", "browser-extension-secondary"),
        ("source_system", "browser_agent"),
        ("collector_version", "0.2.0"),
        ("schema_version", "2.0"),
    ],
)
def test_cross_scope_or_source_replay_cannot_upgrade_unknowns(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"telemetry.browser.read": True},
                "authoritative_data_residency": "uae-north",
                "control_capability": "warn_only",
            }
        ),
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_declaration_fields_are_required_and_strictly_projected() -> None:
    signature = inspect.signature(build_browser_extension_collector_contract)
    for field_name in (
        "tenant_id",
        "collector_id",
        "source_system",
        "collector_version",
        "schema_version",
        "evaluated_at",
    ):
        assert signature.parameters[field_name].default is inspect.Parameter.empty

    contract = _build_contract(
        collector_version="0.2.7+managed",
    )

    assert contract.source_system == "browser_extension"
    assert contract.collector_version == "0.2.7+managed"
    assert contract.schema_version == "1.0"
    assert BROWSER_EXTENSION_ADAPTER_VERSION == "1.0.0"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("source_system", "browser_agent"),
        ("schema_version", "2.0"),
        ("source_system", str("browser_extension")),
        ("collector_version", str("0.1.0")),
    ],
)
def test_invalid_fixed_declaration_values_fail_closed(
    field_name: str,
    value: object,
) -> None:
    if (
        (field_name == "source_system" and value == "browser_extension")
        or (field_name == "collector_version" and value == "0.1.0")
    ):
        class DeclarationSubclass(str):
            pass

        value = DeclarationSubclass(value)

    with pytest.raises(
        ValueError,
        match="^invalid Browser Extension collector declaration$",
    ) as captured:
        _build_contract(**{field_name: value})

    assert captured.value.__cause__ is None


def test_runtime_version_changes_projection_and_evidence_binding() -> None:
    prior = _build_contract(collector_version="0.1.0")
    current = _build_contract(collector_version="0.2.0")
    current_with_matching_evidence = _build_contract(
        collector_version="0.2.0",
        evidence=_current_evidence(
            collector_version="0.2.0",
            health="healthy",
            verified_permissions={"telemetry.browser.read": True},
            control_capability="warn_only",
        ),
    )
    replay = _build_contract(
        collector_version="0.2.0",
        evidence=_current_evidence(
            collector_version="0.1.0",
            health="healthy",
            verified_permissions={"telemetry.browser.read": True},
            control_capability="warn_only",
        ),
    )

    assert prior.collector_version == "0.1.0"
    assert current.collector_version == "0.2.0"
    assert prior.contract_hash != current.contract_hash
    assert current_with_matching_evidence.health == "healthy"
    assert current_with_matching_evidence.permissions == {
        "telemetry.browser.read": True
    }
    assert current_with_matching_evidence.control_capability == "warn_only"
    assert replay.health == "unknown"
    assert replay.permissions == {"unknown": None}
    assert replay.control_capability == "unknown"


def test_truthy_boolean_and_equality_spoofs_are_not_evaluated() -> None:
    class Spoof:
        def __bool__(self) -> bool:
            raise AssertionError("secret-bool-text")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-equality-text")

    boolean_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            verified=Spoof(),
            health="healthy",
            control_capability="warn_only",
        ),
    )
    binding_spoof = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            tenant_id=Spoof(),
            health="healthy",
            control_capability="warn_only",
        ),
    )

    assert boolean_spoof.health == "unknown"
    assert boolean_spoof.control_capability == "unknown"
    assert binding_spoof.health == "unknown"
    assert binding_spoof.control_capability == "unknown"


def test_nonexact_or_hostile_evidence_type_is_rejected_without_access() -> None:
    secret = "secret-hostile-evidence-text"

    class HostileEvidence(BrowserExtensionCollectorEvidence):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)

    with pytest.raises(
        ValueError,
        match="^invalid Browser Extension collector evidence$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="browser-extension-primary",
            evidence=hostile,
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


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
        match="^invalid Browser Extension collector timestamp$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="browser-extension-primary",
            evidence=_current_evidence(observed_at=observed_at),
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


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
    secret = "secret-second-observation-offset-call"

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
            verified_permissions={"telemetry.browser.read": True},
            control_capability="warn_only",
        ),
    )

    assert stateful_tz.calls == 1
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"
    assert secret not in contract.canonical_json()


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
def test_stateful_result_offset_cannot_reverse_future_chronology(
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
        10,
        0,
        tzinfo=stateful_tz,
    )

    with pytest.raises(
        ValueError,
        match="^invalid Browser Extension collector timestamp$",
    ) as captured:
        _build_contract(
            evidence=_current_evidence(**{field_name: result_timestamp}),
        )

    assert stateful_tz.calls == 1
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_invalid_evaluated_at_is_rejected_even_without_evidence() -> None:
    with pytest.raises(
        ValueError,
        match="^invalid Browser Extension collector timestamp$",
    ):
        _build_contract(
            tenant_id="tenant-a",
            collector_id="browser-extension-primary",
            evaluated_at=datetime(2026, 7, 24, 10, 0),
        )


def test_invalid_optional_timestamp_is_privacy_safe() -> None:
    secret = "secret-optional-timestamp"

    class HostileDatetime(datetime):
        def utcoffset(self) -> timedelta | None:
            raise AssertionError(secret)

    with pytest.raises(
        ValueError,
        match="^invalid Browser Extension collector timestamp$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="browser-extension-primary",
            evidence=_current_evidence(
                last_success=HostileDatetime(
                    2026,
                    7,
                    24,
                    9,
                    59,
                    tzinfo=timezone.utc,
                )
            ),
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
@pytest.mark.parametrize(
    "timestamp",
    [
        _EVALUATED_AT + timedelta(microseconds=1),
        _EVALUATED_AT + timedelta(days=1),
    ],
)
def test_trusted_optional_timestamps_cannot_be_future_of_observation_or_evaluation(
    field_name: str,
    timestamp: datetime,
) -> None:
    with pytest.raises(
        ValueError,
        match="^invalid Browser Extension collector timestamp$",
    ) as captured:
        _build_contract(
            tenant_id="tenant-a",
            collector_id="browser-extension-primary",
            evidence=_current_evidence(**{field_name: timestamp}),
        )

    assert captured.value.__cause__ is None


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
def test_trusted_optional_timestamps_cannot_be_after_earlier_observation(
    field_name: str,
) -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1)
    timestamp = observed_at + timedelta(microseconds=1)

    with pytest.raises(
        ValueError,
        match="^invalid Browser Extension collector timestamp$",
    ):
        _build_contract(
            tenant_id="tenant-a",
            collector_id="browser-extension-primary",
            evidence=_current_evidence(
                observed_at=observed_at,
                **{field_name: timestamp},
            ),
        )


def test_current_health_does_not_infer_control_capability() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={"telemetry.browser.read": True},
        ),
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"telemetry.browser.read": True}
    assert contract.control_capability == "unknown"


def test_browser_extension_never_promotes_inline_from_declared_evidence() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            health="healthy",
            control_capability="inline",
        ),
    )

    assert contract.health == "healthy"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    "capability",
    ["monitor_only", "warn_only", "external_required"],
)
def test_verified_noninline_closed_capabilities_project_without_inference(
    capability: str,
) -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(control_capability=capability),
    )

    assert contract.control_capability == capability


def test_residency_stays_unknown_without_authoritative_residency_input() -> None:
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={"telemetry.browser.read": True},
        ),
    )

    assert contract.data_residency == "unknown"


def test_adapter_outputs_are_immutable_and_copy_nested_evidence_values() -> None:
    permissions = {"telemetry.browser.read": True}
    evidence = _current_evidence(
        health="healthy",
        verified_permissions=permissions,
        control_capability="warn_only",
    )
    contract = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
        evidence=evidence,
    )

    permissions["telemetry.browser.read"] = False
    evidence.verified_permissions["telemetry.browser.read"] = False  # type: ignore[index]

    assert contract.permissions == {"telemetry.browser.read": True}
    with pytest.raises(TypeError):
        contract.permissions["telemetry.browser.read"] = False  # type: ignore[index]
    with pytest.raises(ValidationError):
        contract.health = "degraded"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        evidence.current = False  # type: ignore[misc]


def test_contract_hash_is_tenant_and_source_identity_separated() -> None:
    first = _build_contract(
        tenant_id="tenant-a",
        collector_id="browser-extension-primary",
    )
    second = _build_contract(
        tenant_id="tenant-b",
        collector_id="browser-extension-primary",
    )

    assert first.contract_hash != second.contract_hash


def test_adapter_import_is_dependency_free_of_database_and_runtime_settings() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(repo_root / "apps" / "api")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "import app.services.discovery_collector_browser_extension_adapter; "
                "assert 'app.db.session' not in sys.modules; "
                "assert 'app.core.config' not in sys.modules"
            ),
        ],
        cwd=repo_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
