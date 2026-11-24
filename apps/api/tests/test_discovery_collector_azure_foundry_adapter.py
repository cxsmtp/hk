from __future__ import annotations

import ast
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


_MODULE_NAME = "app.services.discovery_collector_azure_foundry_adapter"
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
    evidence_type = _symbol("AzureFoundryCollectorEvidence")
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "foundry-primary",
        "source_system": "azure_foundry_live_connector",
        "collector_version": "1.0.0",
        "schema_version": "1.0",
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return evidence_type(**values)


def _build_contract(**kwargs: Any):
    build = _symbol("build_azure_foundry_collector_contract")
    kwargs.setdefault("tenant_id", "tenant-a")
    kwargs.setdefault("collector_id", "foundry-primary")
    kwargs.setdefault("source_system", "azure_foundry_live_connector")
    kwargs.setdefault("collector_version", "1.0.0")
    kwargs.setdefault("schema_version", "1.0")
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build(**kwargs)


def _literal_strings(node: ast.AST) -> set[str]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and type(child.value) is str
    }


def _fixed_event_types(function_name: str, prefix: str) -> set[str]:
    tree = ast.parse(_ROUTER_PATH.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    return {
        value
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "event_type"
        for value in _literal_strings(keyword.value)
        if value.startswith(prefix)
    }


def test_azure_foundry_collector_adapter_module_exists() -> None:
    assert importlib.util.find_spec(_MODULE_NAME) is not None


def test_adapter_declares_exact_existing_foundry_connector_vocabulary() -> None:
    source_system = _symbol("AZURE_FOUNDRY_SOURCE_SYSTEM")
    observation_types = _symbol("AZURE_FOUNDRY_OBSERVATION_TYPES")

    assert source_system == "azure_foundry_live_connector"
    assert observation_types == (
        "foundry.inventory.agent",
        "foundry.inventory.data_source",
        "foundry.inventory.deployment",
        "foundry.inventory.model",
        "foundry.inventory.project",
        "foundry.inventory.service_principal",
        "foundry.inventory.tool",
    )
    assert set(observation_types) == _fixed_event_types(
        "_foundry_inventory_to_events",
        "foundry.",
    )

    router_source = _ROUTER_PATH.read_text(encoding="utf-8")
    assert 'source="azure_foundry_live_connector"' in router_source
    for separate_source_event in (
        "azure_openai.request",
        "foundry.agent_action",
        "office.copilot.prompt",
    ):
        assert separate_source_event not in observation_types


def test_declaration_is_explicit_and_unknown_by_default() -> None:
    build = _symbol("build_azure_foundry_collector_contract")
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
    assert contract.collector_id == "foundry-primary"
    assert contract.collector_type == "azure_foundry"
    assert contract.collector_version == "1.0.0"
    assert contract.source_system == "azure_foundry_live_connector"
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == _symbol(
        "AZURE_FOUNDRY_OBSERVATION_TYPES"
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
            verified_permissions={"foundry.inventory.read": True},
            last_success=observed_at,
            last_failure=observed_at - timedelta(days=1),
            authoritative_data_residency="uae-north",
            control_capability="monitor_only",
        )
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"foundry.inventory.read": True}
    assert contract.last_success == observed_at
    assert contract.last_failure == observed_at - timedelta(days=1)
    assert contract.data_residency == "uae-north"
    assert contract.control_capability == "monitor_only"


def test_inventory_routing_and_permissions_never_infer_control() -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={
                "foundry.inventory.read": True,
                "foundry.gateway_routed_agent": True,
            },
        )
    )

    assert contract.health == "healthy"
    assert contract.control_capability == "unknown"
    for inferred_flag in (
        "gateway_routed",
        "gateway_routed_agent_ids",
        "inline_candidate",
        "inventory_synced",
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
            verified_permissions={"foundry.inventory.read": True},
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
                tenant_id=Spoof(),
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
        ("collector_id", "foundry-secondary"),
        ("source_system", "microsoft_foundry"),
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
                "verified_permissions": {"foundry.inventory.read": True},
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
        match="^invalid Azure AI Foundry collector declaration$",
    ):
        _build_contract(
            source_system=HostileString("azure_foundry_live_connector")
        )

    contract = _build_contract(
        evidence=_current_evidence(
            source_system=HostileString(
                "azure_foundry_live_connector"
            ),
            health="healthy",
            control_capability="inline",
        )
    )
    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"


def test_freshness_boundary_is_shared_and_dependency_free() -> None:
    max_age = _symbol("AZURE_FOUNDRY_EVIDENCE_MAX_AGE")

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
            verified_permissions={"foundry.inventory.read": True},
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
        match="^invalid Azure AI Foundry collector timestamp$",
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
        match="^invalid Azure AI Foundry collector timestamp$",
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
    success_tz = StatefulTimezone()
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
            last_success=datetime(
                2026,
                7,
                24,
                9,
                59,
                tzinfo=success_tz,
            ),
        ),
    )

    assert contract.last_success == datetime(
        2026,
        7,
        24,
        9,
        59,
        tzinfo=timezone.utc,
    )
    assert evaluated_tz.calls == observed_tz.calls == success_tz.calls == 1


def test_hostile_timestamp_raises_fixed_private_error() -> None:
    secret = "secret-hostile-foundry-timestamp"

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
        match="^invalid Azure AI Foundry collector timestamp$",
    ) as captured:
        _build_contract(
            evidence=_current_evidence(observed_at=hostile)
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_nonexact_evidence_type_is_rejected_without_access() -> None:
    evidence_type = _symbol("AzureFoundryCollectorEvidence")
    secret = "secret-hostile-foundry-evidence"

    class HostileEvidence(evidence_type):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)
    with pytest.raises(
        ValueError,
        match="^invalid Azure AI Foundry collector evidence$",
    ) as captured:
        _build_contract(evidence=hostile)

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_contract_and_evidence_are_immutable_and_detached() -> None:
    evidence_type = _symbol("AzureFoundryCollectorEvidence")
    permissions = {"foundry.inventory.read": True}
    evidence = _current_evidence(verified_permissions=permissions)
    contract = _build_contract(evidence=evidence)
    original_hash = contract.contract_hash

    with pytest.raises(FrozenInstanceError):
        evidence.health = "offline"
    permissions["foundry.inventory.read"] = False
    assert type(contract.permissions) is MappingProxyType
    with pytest.raises(TypeError):
        contract.permissions["foundry.inventory.read"] = False
    assert contract.permissions == {"foundry.inventory.read": True}
    assert contract.contract_hash == original_hash
    assert evidence_type.__dataclass_params__.frozen is True


def test_invalid_trusted_values_use_sanitized_contract_errors() -> None:
    secret = "sk-foundry-secret-abcdefghijk"

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
            raise AssertionError("secret-stale-foundry-value")

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
                "discovery_collector_azure_foundry_adapter;"
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
