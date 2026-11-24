from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone, tzinfo
import importlib
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import sys
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import ValidationError


_MODULE_NAME = (
    "app.services.discovery_collector_microsoft_copilot_adapter"
)
_EVALUATED_AT = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)
_REPO_ROOT = Path(__file__).resolve().parents[3]
_ROUTER_PATH = (
    _REPO_ROOT / "apps/api/app/api/routers/surface_coverage.py"
)


def _adapter_module():
    return importlib.import_module(_MODULE_NAME)


def _symbol(name: str):
    module = _adapter_module()
    assert hasattr(module, name), f"{_MODULE_NAME} must export {name}"
    return getattr(module, name)


def _current_evidence(**overrides: object):
    evidence_type = _symbol("MicrosoftCopilotCollectorEvidence")
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "copilot-primary",
        "source_system": "microsoft_copilot_live_connector",
        "collector_version": "1.0.0",
        "schema_version": "1.0",
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return evidence_type(**values)


def _build_contract(**kwargs: Any):
    build = _symbol("build_microsoft_copilot_collector_contract")
    kwargs.setdefault("tenant_id", "tenant-a")
    kwargs.setdefault("collector_id", "copilot-primary")
    kwargs.setdefault(
        "source_system",
        "microsoft_copilot_live_connector",
    )
    kwargs.setdefault("collector_version", "1.0.0")
    kwargs.setdefault("schema_version", "1.0")
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build(**kwargs)


def _copilot_inventory_events(
    *,
    activity_event_type: str,
):
    router = importlib.import_module(
        "app.api.routers.surface_coverage"
    )
    payload = router.MicrosoftCopilotSyncRequest()
    inventory = {
        "m365_activity": [
            {
                "id": "activity-1",
                "event_type": activity_event_type,
            }
        ],
        "copilot_studio_agents": [{"id": "agent-1"}],
        "connectors": [{"id": "connector-1"}],
        "oauth_apps": [{"id": "oauth-app-1"}],
        "purview_signals": [{"id": "purview-1"}],
        "graph_permissions": [{"id": "permission-1"}],
        "remediation_hooks": [{"id": "hook-1"}],
    }
    return router._copilot_inventory_to_events(
        payload,
        inventory,
        sync_id="sync-1",
    )


def test_microsoft_copilot_collector_adapter_module_exists() -> None:
    assert importlib.util.find_spec(_MODULE_NAME) is not None


def test_adapter_declares_exact_existing_copilot_connector_vocabulary() -> None:
    source_system = _symbol("MICROSOFT_COPILOT_SOURCE_SYSTEM")
    observation_types = _symbol("MICROSOFT_COPILOT_OBSERVATION_TYPES")

    assert source_system == "microsoft_copilot_live_connector"
    assert observation_types == (
        "copilot.inventory.activity",
        "copilot.inventory.connector",
        "copilot.inventory.graph_permission",
        "copilot.inventory.oauth_app",
        "copilot.inventory.purview_signal",
        "copilot.inventory.remediation_hook",
        "copilot.inventory.studio_agent",
    )
    produced = {
        event.event_type
        for event in _copilot_inventory_events(
            activity_event_type="copilot.prompt"
        )
    }
    assert set(observation_types) == produced

    router_source = _ROUTER_PATH.read_text(encoding="utf-8")
    assert 'source="microsoft_copilot_live_connector"' in router_source
    for separate_source_event in (
        "copilot.prompt",
        "copilot_studio.agent_action",
        "office.copilot.prompt",
    ):
        assert separate_source_event not in observation_types


@pytest.mark.parametrize(
    "caller_event_type",
    [
        "copilot.prompt",
        "hostile.caller_controlled_event",
    ],
)
def test_m365_inventory_activity_event_type_is_server_owned(
    caller_event_type: str,
) -> None:
    events = _copilot_inventory_events(
        activity_event_type=caller_event_type
    )
    activity = next(
        event
        for event in events
        if event.correlation_id == "activity-1"
    )

    assert activity.event_type == "copilot.inventory.activity"
    assert caller_event_type not in {
        event.event_type
        for event in events
    }


def test_declaration_is_explicit_and_unknown_by_default() -> None:
    build = _symbol("build_microsoft_copilot_collector_contract")
    for field_name in (
        "tenant_id",
        "collector_id",
        "source_system",
        "collector_version",
        "schema_version",
        "evaluated_at",
    ):
        assert (
            inspect.signature(build).parameters[field_name].default
            is inspect.Parameter.empty
        )

    contract = _build_contract()

    assert contract.tenant_id == "tenant-a"
    assert contract.collector_id == "copilot-primary"
    assert contract.collector_type == "microsoft_copilot"
    assert contract.collector_version == "1.0.0"
    assert (
        contract.source_system
        == "microsoft_copilot_live_connector"
    )
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == _symbol(
        "MICROSOFT_COPILOT_OBSERVATION_TYPES"
    )
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_exact_fresh_bound_evidence_projects_only_explicit_values() -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1)
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"copilot.inventory.read": True},
            last_success=observed_at,
            last_failure=observed_at - timedelta(days=1),
            authoritative_data_residency="uae-north",
            control_capability="external_required",
        )
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"copilot.inventory.read": True}
    assert contract.last_success == observed_at
    assert contract.last_failure == observed_at - timedelta(days=1)
    assert contract.data_residency == "uae-north"
    assert contract.control_capability == "external_required"


def test_routing_permissions_and_remediation_never_infer_control() -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={
                "copilot.inventory.read": True,
                "copilot.gateway_routed_agent": True,
                "copilot.remediation_hook": True,
            },
        )
    )

    assert contract.health == "healthy"
    assert contract.control_capability == "unknown"
    for inferred_flag in (
        "gateway_routed",
        "gateway_routed_agent_ids",
        "inline_candidate",
        "remediation_hook_configured",
    ):
        with pytest.raises(TypeError):
            _build_contract(**{inferred_flag: True})


@pytest.mark.parametrize(
    ("verified", "current"),
    [(False, False), (False, True), (True, False)],
)
def test_unverified_or_noncurrent_evidence_cannot_upgrade_unknowns(
    verified: bool,
    current: bool,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            verified=verified,
            current=current,
            health="healthy",
            verified_permissions={"copilot.inventory.read": True},
            control_capability="inline",
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


def test_truthy_and_equality_spoofs_are_not_evaluated() -> None:
    class Spoof:
        def __bool__(self) -> bool:
            raise AssertionError("secret-bool-text")

        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-equality-text")

    contracts = (
        _build_contract(
            evidence=_current_evidence(
                verified=Spoof(),
                health="healthy",
                control_capability="inline",
            )
        ),
        _build_contract(
            evidence=_current_evidence(
                current=Spoof(),
                health="healthy",
                control_capability="inline",
            )
        ),
        _build_contract(
            evidence=_current_evidence(
                collector_id=Spoof(),
                health="healthy",
                control_capability="inline",
            )
        ),
    )

    for contract in contracts:
        assert contract.health == "unknown"
        assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    ("binding", "value"),
    [
        ("tenant_id", "tenant-b"),
        ("collector_id", "copilot-secondary"),
        ("source_system", "microsoft_copilot"),
        ("collector_version", "0.9.0"),
        ("schema_version", "0.9"),
    ],
)
def test_cross_scope_or_declaration_replay_cannot_upgrade_unknowns(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {
                    "copilot.inventory.read": True
                },
                "control_capability": "inline",
            }
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


def test_declaration_and_evidence_require_exact_plain_strings() -> None:
    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-string-equality")

    with pytest.raises(
        ValueError,
        match="^invalid Microsoft Copilot collector declaration$",
    ):
        _build_contract(
            source_system=HostileString(
                "microsoft_copilot_live_connector"
            )
        )

    contract = _build_contract(
        evidence=_current_evidence(
            source_system=HostileString(
                "microsoft_copilot_live_connector"
            ),
            health="healthy",
            control_capability="inline",
        )
    )
    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"


def test_freshness_boundary_is_shared_and_dependency_free() -> None:
    max_age = _symbol("MICROSOFT_COPILOT_EVIDENCE_MAX_AGE")

    assert max_age == timedelta(minutes=2)
    assert (
        max_age
        == importlib.import_module(
            "app.services.health_freshness"
        ).COLLECTOR_EVIDENCE_MAX_AGE
    )
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=_EVALUATED_AT - max_age,
            health="healthy",
            control_capability="monitor_only",
        )
    )
    assert contract.health == "healthy"
    assert contract.control_capability == "monitor_only"


@pytest.mark.parametrize(
    "observed_at",
    [
        _EVALUATED_AT - timedelta(minutes=2, microseconds=1),
        _EVALUATED_AT + timedelta(microseconds=1),
        _EVALUATED_AT + timedelta(days=1),
    ],
)
def test_stale_or_future_evidence_cannot_upgrade_unknowns(
    observed_at: datetime,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"copilot.inventory.read": True},
            authoritative_data_residency="uae-north",
            control_capability="inline",
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize("field_name", ["last_success", "last_failure"])
def test_result_timestamps_cannot_postdate_observation(
    field_name: str,
) -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1)
    with pytest.raises(
        ValueError,
        match="^invalid Microsoft Copilot collector timestamp$",
    ) as captured:
        _build_contract(
            evidence=_current_evidence(
                observed_at=observed_at,
                **{field_name: observed_at + timedelta(microseconds=1)},
            )
        )

    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("field_name", "invalid_timestamp"),
    [
        ("evaluated_at", None),
        ("evaluated_at", datetime(2026, 7, 24, 10, 0)),
        ("evaluated_at", "2026-07-24T10:00:00Z"),
        ("observed_at", None),
        ("observed_at", datetime(2026, 7, 24, 10, 0)),
        ("last_success", datetime(2026, 7, 24, 10, 0)),
        ("last_failure", "2026-07-24T10:00:00Z"),
    ],
)
def test_trusted_path_requires_exact_timezone_aware_datetimes(
    field_name: str,
    invalid_timestamp: object,
) -> None:
    kwargs: dict[str, object] = {"evidence": _current_evidence()}
    if field_name == "evaluated_at":
        kwargs["evaluated_at"] = invalid_timestamp
    else:
        kwargs["evidence"] = _current_evidence(
            **{field_name: invalid_timestamp}
        )

    with pytest.raises(
        ValueError,
        match="^invalid Microsoft Copilot collector timestamp$",
    ):
        _build_contract(**kwargs)


def test_each_timestamp_timezone_is_consulted_exactly_once() -> None:
    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(
            self,
            _dt: datetime | None,
        ) -> timedelta | None:
            self.calls += 1
            if self.calls == 1:
                return timedelta(0)
            raise AssertionError("secret-second-offset-call")

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    evaluated_tz = StatefulTimezone()
    observed_tz = StatefulTimezone()
    failure_tz = StatefulTimezone()
    contract = _build_contract(
        evaluated_at=datetime(2026, 7, 24, 10, 0, tzinfo=evaluated_tz),
        evidence=_current_evidence(
            observed_at=datetime(
                2026,
                7,
                24,
                9,
                59,
                tzinfo=observed_tz,
            ),
            last_failure=datetime(
                2026,
                7,
                24,
                9,
                59,
                tzinfo=failure_tz,
            ),
        ),
    )

    assert contract.last_failure == datetime(
        2026,
        7,
        24,
        9,
        59,
        tzinfo=timezone.utc,
    )
    assert evaluated_tz.calls == observed_tz.calls == failure_tz.calls == 1


def test_hostile_timestamp_raises_fixed_private_error() -> None:
    secret = "secret-hostile-copilot-timestamp"

    class HostileTimezone(tzinfo):
        def utcoffset(
            self,
            _dt: datetime | None,
        ) -> timedelta | None:
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    hostile = datetime(
        2026,
        7,
        24,
        10,
        0,
        tzinfo=HostileTimezone(),
    )
    with pytest.raises(
        ValueError,
        match="^invalid Microsoft Copilot collector timestamp$",
    ) as captured:
        _build_contract(
            evidence=_current_evidence(observed_at=hostile)
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_nonexact_evidence_type_is_rejected_without_access() -> None:
    evidence_type = _symbol("MicrosoftCopilotCollectorEvidence")
    secret = "secret-hostile-copilot-evidence"

    class HostileEvidence(evidence_type):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)
    with pytest.raises(
        ValueError,
        match="^invalid Microsoft Copilot collector evidence$",
    ) as captured:
        _build_contract(evidence=hostile)

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_contract_and_evidence_are_immutable_and_detached() -> None:
    evidence_type = _symbol("MicrosoftCopilotCollectorEvidence")
    permissions = {"copilot.inventory.read": True}
    evidence = _current_evidence(verified_permissions=permissions)
    contract = _build_contract(evidence=evidence)
    original_hash = contract.contract_hash

    with pytest.raises(FrozenInstanceError):
        evidence.health = "offline"
    permissions["copilot.inventory.read"] = False
    assert type(contract.permissions) is MappingProxyType
    with pytest.raises(TypeError):
        contract.permissions["copilot.inventory.read"] = False
    assert contract.permissions == {"copilot.inventory.read": True}
    assert contract.contract_hash == original_hash
    assert evidence_type.__dataclass_params__.frozen is True


def test_invalid_trusted_values_use_sanitized_contract_errors() -> None:
    secret = "sk-copilot-secret-abcdefghijk"

    with pytest.raises(ValidationError) as captured:
        _build_contract(
            evidence=_current_evidence(
                health=secret,
                verified_permissions={secret: True},
                authoritative_data_residency=secret,
                control_capability=secret,
            )
        )

    rendered = str(captured.value)
    structured = json.dumps(captured.value.errors(), sort_keys=True)
    assert secret not in rendered
    assert secret not in structured


def test_stale_evidence_does_not_inspect_optional_values() -> None:
    class Explosive:
        def __str__(self) -> str:
            raise AssertionError("secret-stale-copilot-value")

    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=_EVALUATED_AT - timedelta(days=1),
            health=Explosive(),
            verified_permissions=Explosive(),
            last_success=Explosive(),
            last_failure=Explosive(),
            authoritative_data_residency=Explosive(),
            control_capability=Explosive(),
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


def test_adapter_import_is_standalone_and_dependency_light() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys;"
                "import app.services."
                "discovery_collector_microsoft_copilot_adapter;"
                "assert 'sqlalchemy' not in sys.modules;"
                "assert 'app.core.config' not in sys.modules;"
                "assert 'app.db.session' not in sys.modules;"
                "assert 'app.api.routers.surface_coverage' not in sys.modules"
            ),
        ],
        cwd=_REPO_ROOT / "apps/api",
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
