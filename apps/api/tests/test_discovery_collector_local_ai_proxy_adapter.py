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


_MODULE_NAME = "app.services.discovery_collector_local_ai_proxy_adapter"
_EVALUATED_AT = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _adapter_module():
    return importlib.import_module(_MODULE_NAME)


def _symbol(name: str):
    module = _adapter_module()
    assert hasattr(module, name), f"{_MODULE_NAME} must export {name}"
    return getattr(module, name)


def _current_evidence(**overrides: object):
    evidence_type = _symbol("LocalAIProxyCollectorEvidence")
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "local-proxy-primary",
        "source_system": "local_ai_proxy",
        "collector_version": "0.2.0",
        "schema_version": "1.0",
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return evidence_type(**values)


def _build_contract(**kwargs: Any):
    build = _symbol("build_local_ai_proxy_collector_contract")
    kwargs.setdefault("tenant_id", "tenant-a")
    kwargs.setdefault("collector_id", "local-proxy-primary")
    kwargs.setdefault("source_system", "local_ai_proxy")
    kwargs.setdefault("collector_version", "0.2.0")
    kwargs.setdefault("schema_version", "1.0")
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build(**kwargs)


def test_local_ai_proxy_collector_adapter_module_exists() -> None:
    assert importlib.util.find_spec(_MODULE_NAME) is not None


def test_adapter_declares_only_existing_proxy_observation_vocabulary() -> None:
    observation_types = _symbol("LOCAL_AI_PROXY_OBSERVATION_TYPES")

    assert observation_types == (
        "shadow_ai.proxy.signal",
        "shadow_ai.proxy_discovered",
    )

    proxy_ingest = (
        _REPO_ROOT
        / "apps/api/app/services/shadow_ai/proxy_ingest_service.py"
    ).read_text(encoding="utf-8")
    local_proxy = (
        _REPO_ROOT
        / "apps/endpoint-agent/src/hawk_endpoint_agent/proxy/local_proxy.py"
    ).read_text(encoding="utf-8")

    assert 'signal_type="shadow_ai.proxy.signal"' in proxy_ingest
    assert 'event_type="shadow_ai.proxy_discovered"' in proxy_ingest
    assert "class LocalProxy:" in local_proxy
    assert "dispatcher.evaluate(" in local_proxy
    assert 'adapter_path="local_proxy"' in local_proxy
    assert "pre_action=True" in local_proxy

    for invented_type in (
        "local_proxy.heartbeat",
        "local_proxy.inline_prevented",
        "local_proxy.request",
        "local_proxy.response",
        "proxy.heartbeat",
        "proxy.request",
        "proxy.response",
    ):
        assert invented_type not in observation_types


def test_declarations_are_explicit_and_unknown_by_default() -> None:
    build = _symbol("build_local_ai_proxy_collector_contract")
    signature = inspect.signature(build)
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
    assert contract.collector_id == "local-proxy-primary"
    assert contract.collector_type == "local_ai_proxy"
    assert contract.collector_version == "0.2.0"
    assert contract.source_system == "local_ai_proxy"
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == _symbol(
        "LOCAL_AI_PROXY_OBSERVATION_TYPES"
    )
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_configuration_running_routing_and_tls_never_infer_inline() -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={
                "proxy.requested": True,
                "proxy.running": True,
                "routing.managed": True,
                "tls_intercept.active": True,
            },
        )
    )

    assert contract.health == "healthy"
    assert contract.permissions == {
        "proxy.requested": True,
        "proxy.running": True,
        "routing.managed": True,
        "tls_intercept.active": True,
    }
    assert contract.control_capability == "unknown"

    for inferred_flag in (
        "installed",
        "configured",
        "proxy_running",
        "tls_active",
    ):
        with pytest.raises(TypeError):
            _build_contract(**{inferred_flag: True})


def test_exact_fresh_bound_evidence_projects_only_explicit_values() -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1)
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"shadow_ai.proxy.ingest": True},
            last_success=observed_at,
            last_failure=observed_at - timedelta(days=1),
            authoritative_data_residency="uae-north",
            control_capability="inline",
        )
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"shadow_ai.proxy.ingest": True}
    assert contract.last_success == observed_at
    assert contract.last_failure == observed_at - timedelta(days=1)
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
def test_nonliteral_current_state_cannot_upgrade_unknown(
    verified: bool,
    current: bool,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            verified=verified,
            current=current,
            health="healthy",
            verified_permissions={"shadow_ai.proxy.ingest": True},
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

    verified_spoof = _build_contract(
        evidence=_current_evidence(
            verified=Spoof(),
            health="healthy",
            control_capability="inline",
        )
    )
    current_spoof = _build_contract(
        evidence=_current_evidence(
            current=Spoof(),
            health="healthy",
            control_capability="inline",
        )
    )
    binding_spoof = _build_contract(
        evidence=_current_evidence(
            tenant_id=Spoof(),
            health="healthy",
            control_capability="inline",
        )
    )

    for contract in (verified_spoof, current_spoof, binding_spoof):
        assert contract.health == "unknown"
        assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    ("binding", "value"),
    [
        ("tenant_id", "tenant-b"),
        ("collector_id", "local-proxy-secondary"),
        ("source_system", "other_proxy"),
        ("collector_version", "0.1.0"),
        ("schema_version", "0.9"),
    ],
)
def test_cross_scope_or_declaration_replay_cannot_upgrade_unknown(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"shadow_ai.proxy.ingest": True},
                "control_capability": "inline",
            }
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


def test_string_subclass_declaration_and_binding_are_not_compared() -> None:
    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-string-equality-text")

    with pytest.raises(
        ValueError,
        match="^invalid Local AI Proxy collector declaration$",
    ):
        _build_contract(source_system=HostileString("local_ai_proxy"))

    contract = _build_contract(
        evidence=_current_evidence(
            source_system=HostileString("local_ai_proxy"),
            health="healthy",
            control_capability="inline",
        )
    )
    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"


def test_freshness_uses_dependency_free_collector_evidence_boundary() -> None:
    max_age = _symbol("LOCAL_AI_PROXY_EVIDENCE_MAX_AGE")

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
            verified_permissions={"shadow_ai.proxy.ingest": True},
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
def test_stale_or_future_evidence_cannot_upgrade_unknown(
    observed_at: datetime,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={"shadow_ai.proxy.ingest": True},
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
        match="^invalid Local AI Proxy collector timestamp$",
    ) as captured:
        _build_contract(
            evidence=_current_evidence(
                observed_at=observed_at,
                **{
                    field_name: observed_at + timedelta(microseconds=1),
                },
            )
        )

    assert captured.value.__cause__ is None


def test_result_timestamps_may_equal_observation() -> None:
    observed_at = _EVALUATED_AT - timedelta(seconds=30)
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at,
            last_success=observed_at,
            last_failure=observed_at,
        )
    )

    assert contract.last_success == observed_at
    assert contract.last_failure == observed_at


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
    kwargs: dict[str, object] = {"evidence": _current_evidence()}
    if field_name == "evaluated_at":
        kwargs["evaluated_at"] = invalid_timestamp
    else:
        kwargs["evidence"] = _current_evidence(
            **{field_name: invalid_timestamp}
        )

    with pytest.raises(
        ValueError,
        match="^invalid Local AI Proxy collector timestamp$",
    ):
        _build_contract(**kwargs)


@pytest.mark.parametrize("field_name", ["evaluated_at", "observed_at"])
@pytest.mark.parametrize("kind", ["subclass", "hostile_tzinfo"])
def test_hostile_timestamps_raise_fixed_private_error(
    field_name: str,
    kind: str,
) -> None:
    secret = "secret-hostile-local-proxy-timestamp"

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
        hostile: datetime = HostileDatetime(
            2026,
            7,
            24,
            10,
            0,
            tzinfo=timezone.utc,
        )
    else:
        hostile = datetime(
            2026,
            7,
            24,
            10,
            0,
            tzinfo=HostileTimezone(),
        )

    kwargs: dict[str, object] = {}
    if field_name == "evaluated_at":
        kwargs["evaluated_at"] = hostile
        kwargs["evidence"] = _current_evidence()
    else:
        kwargs["evidence"] = _current_evidence(observed_at=hostile)

    with pytest.raises(
        ValueError,
        match="^invalid Local AI Proxy collector timestamp$",
    ) as captured:
        _build_contract(**kwargs)

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_stateful_timezone_cannot_turn_stale_evidence_fresh() -> None:
    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta | None:
            self.calls += 1
            if self.calls == 1:
                return timedelta(0)
            return -timedelta(hours=23, minutes=59)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

        def tzname(self, _dt: datetime | None) -> str | None:
            return "stateful"

    timezone_state = StatefulTimezone()
    stale_observation = datetime(
        2026,
        7,
        23,
        10,
        0,
        tzinfo=timezone_state,
    )
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=stale_observation,
            health="healthy",
            verified_permissions={"shadow_ai.proxy.ingest": True},
            control_capability="inline",
        )
    )

    assert timezone_state.calls == 1
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


def test_stateful_timezone_cannot_turn_future_evidence_current() -> None:
    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta | None:
            self.calls += 1
            if self.calls == 1:
                return timedelta(0)
            return timedelta(hours=23, minutes=59)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    timezone_state = StatefulTimezone()
    future_observation = datetime(
        2026,
        7,
        25,
        9,
        59,
        tzinfo=timezone_state,
    )
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=future_observation,
            health="healthy",
            verified_permissions={"shadow_ai.proxy.ingest": True},
            control_capability="inline",
        )
    )

    assert timezone_state.calls == 1
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


def test_stateful_optional_timestamp_cannot_bypass_chronology() -> None:
    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta | None:
            self.calls += 1
            if self.calls == 1:
                return timedelta(0)
            return timedelta(hours=23, minutes=59)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    timezone_state = StatefulTimezone()
    future_success = datetime(
        2026,
        7,
        25,
        9,
        59,
        tzinfo=timezone_state,
    )

    with pytest.raises(
        ValueError,
        match="^invalid Local AI Proxy collector timestamp$",
    ):
        _build_contract(
            evidence=_current_evidence(
                last_success=future_success,
            )
        )

    assert timezone_state.calls == 1


def test_nonexact_or_hostile_evidence_type_is_rejected_without_access() -> None:
    evidence_type = _symbol("LocalAIProxyCollectorEvidence")
    secret = "secret-hostile-local-proxy-evidence"

    class HostileEvidence(evidence_type):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)

    with pytest.raises(
        ValueError,
        match="^invalid Local AI Proxy collector evidence$",
    ) as captured:
        _build_contract(evidence=hostile)

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_contract_and_evidence_are_immutable_and_detached_from_input() -> None:
    evidence_type = _symbol("LocalAIProxyCollectorEvidence")
    permissions = {"shadow_ai.proxy.ingest": True}
    evidence = _current_evidence(verified_permissions=permissions)
    contract = _build_contract(evidence=evidence)
    original_hash = contract.contract_hash

    with pytest.raises(FrozenInstanceError):
        evidence.health = "offline"
    permissions["shadow_ai.proxy.ingest"] = False

    assert type(contract.permissions) is MappingProxyType
    with pytest.raises(TypeError):
        contract.permissions["shadow_ai.proxy.ingest"] = False
    assert contract.permissions == {"shadow_ai.proxy.ingest": True}
    assert contract.contract_hash == original_hash
    assert evidence_type.__dataclass_params__.frozen is True


def test_invalid_trusted_values_use_sanitized_contract_errors() -> None:
    secret = "sk-local-proxy-secret-abcdefghijk"

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


def test_stale_evidence_does_not_inspect_untrusted_optional_values() -> None:
    class Explosive:
        def __str__(self) -> str:
            raise AssertionError("secret-stale-optional-value")

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
                "import app.services.discovery_collector_local_ai_proxy_adapter;"
                "assert 'sqlalchemy' not in sys.modules;"
                "assert 'app.core.config' not in sys.modules;"
                "assert 'app.db.session' not in sys.modules;"
                "assert 'app.services.shadow_ai.proxy_ingest_service' "
                "not in sys.modules"
            ),
        ],
        cwd=_REPO_ROOT / "apps/api",
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
