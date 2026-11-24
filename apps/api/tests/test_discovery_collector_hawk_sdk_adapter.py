from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone, tzinfo
import importlib
import inspect
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import pytest
from pydantic import ValidationError


_MODULE_NAME = "app.services.discovery_collector_hawk_sdk_adapter"
_EVALUATED_AT = datetime(2026, 7, 24, 10, 0, tzinfo=timezone.utc)
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _adapter_module():
    return importlib.import_module(_MODULE_NAME)


def _symbol(name: str):
    module = _adapter_module()
    assert hasattr(module, name), f"{_MODULE_NAME} must export {name}"
    return getattr(module, name)


def _current_evidence(**overrides: object):
    evidence_type = _symbol("HawkSDKCollectorEvidence")
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "collector_id": "sdk-primary",
        "source_system": "sdk",
        "collector_version": "0.2.0",
        "schema_version": "1.0",
        "verified": True,
        "current": True,
        "observed_at": _EVALUATED_AT,
    }
    values.update(overrides)
    return evidence_type(**values)


def _build_contract(**kwargs: Any):
    build = _symbol("build_hawk_sdk_collector_contract")
    kwargs.setdefault("tenant_id", "tenant-a")
    kwargs.setdefault("collector_id", "sdk-primary")
    kwargs.setdefault("source_system", "sdk")
    kwargs.setdefault("collector_version", "0.2.0")
    kwargs.setdefault("schema_version", "1.0")
    kwargs.setdefault("evaluated_at", _EVALUATED_AT)
    return build(**kwargs)


def _python_function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    assert len(matches) == 1
    return matches[0]


def _exact_call_keyword_strings(
    function: ast.FunctionDef,
    *,
    keyword: str,
) -> set[str]:
    return {
        value.value
        for call in ast.walk(function)
        if isinstance(call, ast.Call)
        for item in call.keywords
        if item.arg == keyword
        and isinstance((value := item.value), ast.Constant)
        and isinstance(value.value, str)
    }


def _exact_conditional_assignment_strings(
    function: ast.FunctionDef,
    *,
    target: str,
) -> set[str]:
    assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(item, ast.Name) and item.id == target
            for item in node.targets
        )
        and isinstance(node.value, ast.IfExp)
    ]
    assert len(assignments) == 1
    conditional = assignments[0].value
    assert isinstance(conditional.body, ast.Constant)
    assert isinstance(conditional.body.value, str)
    assert isinstance(conditional.orelse, ast.Constant)
    assert isinstance(conditional.orelse.value, str)
    return {conditional.body.value, conditional.orelse.value}


def test_hawk_sdk_collector_adapter_declares_only_existing_sdk_observations() -> None:
    observation_types = _symbol("HAWK_SDK_OBSERVATION_TYPES")
    sdk_client = (
        _REPO_ROOT / "packages/hawk-sdk/src/client.ts"
    ).read_text(encoding="utf-8")
    route_pattern = re.compile(
        r"^  (?P<method>"
        r"llmIntercept|mcpAuthorize|scanMcpTool|"
        r"dataTransferCheck|dataTransferJustify"
        r")\(payload: [^)]+\): Promise<[^>]+> \{\n"
        r"    return this\.postJson<[^>]+>"
        r'\("(?P<route>/[^"]+)", payload\);\n'
        r"  \}$",
        re.MULTILINE,
    )
    sdk_routes = {
        match.group("method"): match.group("route")
        for match in route_pattern.finditer(sdk_client)
    }
    assert sdk_routes == {
        "llmIntercept": "/gateway/llm/intercept",
        "mcpAuthorize": "/gateway/mcp/authorize",
        "scanMcpTool": "/gateway/mcp/tools/scan",
        "dataTransferCheck": "/runtime-control/data-transfer-check",
        "dataTransferJustify": "/runtime-control/data-transfer-justify",
    }

    gateway_normalizer = _python_function(
        _REPO_ROOT
        / "apps/api/app/services/runtime_intelligence/runtime_event_normalizer.py",
        "ingest_from_gateway_enforcement",
    )
    mcp_scan = _python_function(
        _REPO_ROOT
        / "apps/api/app/services/agentic_action_integrity_service.py",
        "scan_mcp_tool",
    )
    transfer_check = _python_function(
        _REPO_ROOT
        / "apps/api/app/services/runtime_control_data_transfer_service.py",
        "evaluate_data_transfer_and_record",
    )
    transfer_justification = _python_function(
        _REPO_ROOT
        / "apps/api/app/services/runtime_control_data_transfer_service.py",
        "submit_data_transfer_justification_and_record",
    )

    observations_by_route = {
        sdk_routes["llmIntercept"]: _exact_conditional_assignment_strings(
            gateway_normalizer,
            target="event_type",
        )
        - {"mcp_authorize"},
        sdk_routes["mcpAuthorize"]: _exact_conditional_assignment_strings(
            gateway_normalizer,
            target="event_type",
        )
        - {"llm_intercept"},
        sdk_routes["scanMcpTool"]: _exact_call_keyword_strings(
            mcp_scan,
            keyword="event_type",
        ),
        sdk_routes["dataTransferCheck"]: _exact_call_keyword_strings(
            transfer_check,
            keyword="event_type",
        ),
        sdk_routes["dataTransferJustify"]: _exact_call_keyword_strings(
            transfer_justification,
            keyword="event_type",
        ),
    }
    assert observations_by_route == {
        "/gateway/llm/intercept": {"llm_intercept"},
        "/gateway/mcp/authorize": {"mcp_authorize"},
        "/gateway/mcp/tools/scan": {"mcp_tool_scanned"},
        "/runtime-control/data-transfer-check": {"data_transfer_check"},
        "/runtime-control/data-transfer-justify": {
            "data_transfer_justification"
        },
    }
    source_observation_types = set().union(*observations_by_route.values())

    assert source_observation_types == {
        "data_transfer_check",
        "data_transfer_justification",
        "llm_intercept",
        "mcp_authorize",
        "mcp_tool_scanned",
    }
    assert observation_types == tuple(sorted(source_observation_types))


def test_declaration_fields_are_explicit_and_project_unknown_by_default() -> None:
    build = _symbol("build_hawk_sdk_collector_contract")
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
    assert contract.collector_id == "sdk-primary"
    assert contract.collector_type == "sdk"
    assert contract.collector_version == "0.2.0"
    assert contract.source_system == "sdk"
    assert contract.schema_version == "1.0"
    assert contract.observation_types_emitted == _symbol(
        "HAWK_SDK_OBSERVATION_TYPES"
    )
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


def test_sdk_package_identity_or_configuration_never_infers_inline() -> None:
    contract = _build_contract(collector_version="0.2.0")

    assert contract.health == "unknown"
    assert contract.control_capability == "unknown"
    assert contract.permissions == {"unknown": None}

    with pytest.raises(TypeError):
        _build_contract(installed=True)
    with pytest.raises(TypeError):
        _build_contract(configured_inline=True)


def test_exact_verified_current_evidence_projects_declared_values() -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1)
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at,
            health="healthy",
            verified_permissions={
                "sdk.events.read": True,
                "sdk.actions.authorize": True,
            },
            last_success=observed_at,
            last_failure=observed_at - timedelta(days=1),
            authoritative_data_residency="uae-north",
            control_capability="monitor_only",
        )
    )

    assert contract.health == "healthy"
    assert contract.permissions == {
        "sdk.actions.authorize": True,
        "sdk.events.read": True,
    }
    assert contract.last_success == observed_at
    assert contract.last_failure == observed_at - timedelta(days=1)
    assert contract.data_residency == "uae-north"
    assert contract.control_capability == "monitor_only"


def test_verified_evidence_cannot_promote_sdk_to_inline_prevention() -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            health="healthy",
            verified_permissions={"sdk.actions.authorize": True},
            control_capability="inline",
        )
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"sdk.actions.authorize": True}
    assert contract.control_capability == "unknown"


def test_freshness_uses_shared_two_minute_boundary() -> None:
    max_age = _symbol("HAWK_SDK_EVIDENCE_MAX_AGE")
    assert max_age == timedelta(minutes=2)

    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=_EVALUATED_AT - max_age,
            health="healthy",
            verified_permissions={"sdk.events.read": True},
            control_capability="monitor_only",
        )
    )

    assert contract.health == "healthy"
    assert contract.permissions == {"sdk.events.read": True}
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
            verified_permissions={"sdk.events.read": True},
            authoritative_data_residency="uae-north",
            control_capability="inline",
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    ("binding", "value"),
    [
        ("tenant_id", "tenant-b"),
        ("collector_id", "sdk-secondary"),
        ("source_system", "other"),
        ("collector_version", "0.3.0"),
        ("schema_version", "2.0"),
    ],
)
def test_cross_scope_evidence_replay_cannot_upgrade_unknown(
    binding: str,
    value: str,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            **{
                binding: value,
                "health": "healthy",
                "verified_permissions": {"sdk.events.read": True},
                "control_capability": "inline",
            }
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    ("verified", "current"),
    [
        (False, False),
        (False, True),
        (True, False),
    ],
)
def test_nonliteral_evidence_state_cannot_upgrade_unknown(
    verified: bool,
    current: bool,
) -> None:
    contract = _build_contract(
        evidence=_current_evidence(
            verified=verified,
            current=current,
            health="healthy",
            verified_permissions={"sdk.events.read": True},
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

    boolean_spoof = _build_contract(
        evidence=_current_evidence(
            verified=Spoof(),
            health="healthy",
            control_capability="inline",
        )
    )
    binding_spoofs = [
        _build_contract(
            evidence=_current_evidence(
                **{
                    field_name: Spoof(),
                    "health": "healthy",
                    "control_capability": "inline",
                }
            )
        )
        for field_name in (
            "tenant_id",
            "collector_id",
            "source_system",
            "collector_version",
            "schema_version",
        )
    ]

    assert boolean_spoof.health == "unknown"
    assert boolean_spoof.control_capability == "unknown"
    assert all(contract.health == "unknown" for contract in binding_spoofs)
    assert all(
        contract.control_capability == "unknown"
        for contract in binding_spoofs
    )


def test_nonexact_or_hostile_evidence_type_is_rejected_safely() -> None:
    evidence_type = _symbol("HawkSDKCollectorEvidence")
    secret = "secret-hostile-evidence-text"

    class HostileEvidence(evidence_type):
        def __getattribute__(self, _name: str) -> object:
            raise AssertionError(secret)

    hostile = object.__new__(HostileEvidence)

    with pytest.raises(
        ValueError,
        match="^invalid Hawk SDK collector evidence$",
    ) as captured:
        _build_contract(evidence=hostile)

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


@pytest.mark.parametrize("field_name", ["evaluated_at", "observed_at"])
@pytest.mark.parametrize("kind", ["subclass", "hostile_tzinfo"])
def test_hostile_timestamps_raise_fixed_safe_error(
    field_name: str,
    kind: str,
) -> None:
    secret = "secret-hostile-sdk-timestamp-text"

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

    kwargs: dict[str, object] = {}
    if field_name == "evaluated_at":
        kwargs["evaluated_at"] = hostile_timestamp
        kwargs["evidence"] = _current_evidence()
    else:
        kwargs["evidence"] = _current_evidence(observed_at=hostile_timestamp)

    with pytest.raises(
        ValueError,
        match="^invalid Hawk SDK collector timestamp$",
    ) as captured:
        _build_contract(**kwargs)

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
        match="^invalid Hawk SDK collector timestamp$",
    ):
        _build_contract(**kwargs)


@pytest.mark.parametrize(
    "field_name",
    ["last_success", "last_failure"],
)
@pytest.mark.parametrize(
    "future_timestamp",
    [
        _EVALUATED_AT + timedelta(microseconds=1),
        _EVALUATED_AT + timedelta(days=1),
    ],
)
def test_trusted_evidence_rejects_future_success_or_failure_chronology(
    field_name: str,
    future_timestamp: datetime,
) -> None:
    with pytest.raises(
        ValueError,
        match="^invalid Hawk SDK collector timestamp$",
    ):
        _build_contract(
            evidence=_current_evidence(
                **{field_name: future_timestamp}
            )
        )


@pytest.mark.parametrize(
    "field_name",
    ["last_success", "last_failure"],
)
def test_trusted_evidence_rejects_timestamp_after_earlier_observation(
    field_name: str,
) -> None:
    observed_at = _EVALUATED_AT - timedelta(minutes=1)
    with pytest.raises(
        ValueError,
        match="^invalid Hawk SDK collector timestamp$",
    ):
        _build_contract(
            evidence=_current_evidence(
                observed_at=observed_at,
                **{field_name: observed_at + timedelta(microseconds=1)},
            )
        )


@pytest.mark.parametrize(
    ("observed_at", "offsets"),
    [
        (
            datetime(2026, 7, 23, 10, 0),
            [timedelta(0), -timedelta(hours=23, minutes=59)],
        ),
        (
            datetime(2026, 7, 24, 10, 1),
            [timedelta(0), timedelta(hours=1)],
        ),
    ],
)
def test_stateful_observation_offset_cannot_change_freshness(
    observed_at: datetime,
    offsets: list[timedelta],
) -> None:
    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta:
            offset = offsets[min(self.calls, len(offsets) - 1)]
            self.calls += 1
            return offset

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    timezone_state = StatefulTimezone()
    contract = _build_contract(
        evidence=_current_evidence(
            observed_at=observed_at.replace(tzinfo=timezone_state),
            health="healthy",
            verified_permissions={"sdk.events.read": True},
            control_capability="monitor_only",
        )
    )

    assert timezone_state.calls == 1
    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.control_capability == "unknown"


def test_stateful_result_offset_cannot_change_chronology() -> None:
    class StatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _dt: datetime | None) -> timedelta:
            self.calls += 1
            return timedelta(0) if self.calls == 1 else timedelta(hours=1)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    timezone_state = StatefulTimezone()
    last_success = datetime(
        2026,
        7,
        24,
        10,
        1,
        tzinfo=timezone_state,
    )

    with pytest.raises(
        ValueError,
        match="^invalid Hawk SDK collector timestamp$",
    ):
        _build_contract(
            evidence=_current_evidence(last_success=last_success)
        )

    assert timezone_state.calls == 1


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("tenant_id", "tenant-a"),
        ("collector_id", "sdk-primary"),
        ("source_system", "sdk"),
        ("collector_version", "0.2.0"),
        ("schema_version", "1.0"),
    ],
)
def test_declaration_rejects_string_subclasses_with_fixed_safe_error(
    field_name: str,
    value: str,
) -> None:
    class HostileString(str):
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("secret-declaration-equality")

        def __hash__(self) -> int:
            raise AssertionError("secret-declaration-hash")

        def strip(self, *_args: object, **_kwargs: object) -> str:
            raise AssertionError("secret-declaration-strip")

    with pytest.raises(
        ValueError,
        match="^invalid Hawk SDK collector declaration$",
    ) as captured:
        _build_contract(**{field_name: HostileString(value)})

    assert "secret-declaration" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_non_sdk_source_is_rejected_as_wrong_adapter_declaration() -> None:
    with pytest.raises(
        ValueError,
        match="^invalid Hawk SDK collector declaration$",
    ):
        _build_contract(source_system="other")


def test_adapter_preserves_contract_privacy_and_immutability() -> None:
    secret = "sk-sdk-collector-secret-abcdefghijk"
    with pytest.raises(ValidationError) as captured:
        _build_contract(
            evidence=_current_evidence(
                verified_permissions={secret: True},
            )
        )

    assert secret not in str(captured.value)
    assert secret not in json.dumps(captured.value.errors(), sort_keys=True)

    permission_evidence = {"sdk.events.read": True}
    contract = _build_contract(
        evidence=_current_evidence(
            verified_permissions=permission_evidence,
        )
    )
    original_hash = contract.contract_hash
    permission_evidence["sdk.events.read"] = False

    with pytest.raises(TypeError):
        contract.permissions["sdk.events.read"] = False

    assert contract.permissions == {"sdk.events.read": True}
    assert contract.contract_hash == original_hash


def test_adapter_import_is_dependency_free_of_database_and_settings() -> None:
    api_root = _REPO_ROOT / "apps/api"
    script = (
        "import sys;"
        f"sys.path.insert(0, {str(api_root)!r});"
        "import app.services.discovery_collector_hawk_sdk_adapter;"
        "blocked=[name for name in sys.modules "
        "if name.startswith('app.db') or name == 'app.core.config' "
        "or name == 'sqlalchemy' or name.startswith('sqlalchemy.')];"
        "assert not blocked, blocked"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
