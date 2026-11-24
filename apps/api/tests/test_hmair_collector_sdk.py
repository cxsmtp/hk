from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import inspect
import json
from typing import Any

import pytest
from pydantic import ValidationError

from app.services.discovery_collector_contract import DiscoveryCollectorContract
from app.services.hmair.collector_registry import CollectorRegistry
from app.services.hmair.collector_sdk import (
    CollectorHealthReport,
    CollectorRecord,
    CollectorTerminalOutcome,
    ConnectivityResult,
    DiscoveryTargetView,
    HMAIRCollector,
    ScopeItem,
    collect_assignment_observations,
    collector_declaration_from_v1,
)
from app.services.hmair.contracts import (
    CollectorDeclaration,
    CollectorRunStatus,
    DiscoveryObservationInput,
    DiscoveryTargetType,
)


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
COLLECTION_METHODS = (
    "collect_inventory",
    "collect_configuration",
    "collect_usage",
    "collect_identity_hints",
    "collect_relationship_hints",
)
PROTOCOL_METHODS = {
    "validate_configuration",
    "test_connectivity",
    "enumerate_scope",
    *COLLECTION_METHODS,
    "emit_observations",
    "report_health",
    "report_limitations",
}
V1_COMPATIBILITY_LIMITATION = (
    "v1 omits supported depth, required-permission, active-capability, "
    "and sensitive-data metadata"
)
EXTERNAL_OPERATIONS = (
    "validate_configuration",
    "test_connectivity",
    "enumerate_scope",
    "collect_inventory",
    "collect_configuration",
    "collect_usage",
    "collect_identity_hints",
    "collect_relationship_hints",
    "emit_observations",
    "cancellation_check",
)


def _declaration(
    *,
    collector_id: str = "endpoint-primary",
    collector_type: str = "endpoint",
    supported_target: DiscoveryTargetType = DiscoveryTargetType.ENDPOINT_GROUP,
) -> CollectorDeclaration:
    return CollectorDeclaration(
        collector_id=collector_id,
        collector_type=collector_type,
        version="2.0",
        supported_targets=(supported_target,),
        active_capabilities=(),
        passive_capabilities=("inventory",),
        permissions_required=("endpoint.metadata.read",),
        sensitive_data_accessed=(),
        health="healthy",
        last_success_at=NOW,
        last_failure_at=None,
        data_residency="uae-north",
        control_capability="monitor_only",
        schema_version="2.0",
        limitations=("metadata-only",),
        declaration_hash="a" * 64,
    )


def _target(
    *,
    permitted_methods: tuple[str, ...] = COLLECTION_METHODS,
    target_type: DiscoveryTargetType = DiscoveryTargetType.ENDPOINT_GROUP,
) -> DiscoveryTargetView:
    return DiscoveryTargetView(
        target_id="endpoint-group-a",
        target_type=target_type,
        identifier="managed-endpoints-a",
        environment="production",
        owner_hint=None,
        credentials_reference="vault-ref-a",
        permitted_methods=permitted_methods,
        exclusions=(),
        rate_limit=100,
        active_scan_allowed=False,
        sensitive_scope=False,
        last_scanned_at=None,
    )


def _scope(
    scope_id: str = "scope-a",
    *,
    permitted_methods: tuple[str, ...] = COLLECTION_METHODS,
) -> ScopeItem:
    return ScopeItem(
        scope_id=scope_id,
        scope_type="endpoint_group",
        permitted_methods=permitted_methods,
    )


def _record(kind: str, scope_id: str) -> CollectorRecord:
    return CollectorRecord(
        record_type=kind,
        source_reference=f"{scope_id}:{kind}",
        observed_at=NOW,
        safe_summary="metadata-only",
    )


def _observation() -> DiscoveryObservationInput:
    return DiscoveryObservationInput(
        observation_id="observation-a",
        scan_id="00000000-0000-4000-8000-000000000001",
        collector_id="endpoint-primary",
        collector_type="endpoint",
        collector_version="2.0",
        target_id="endpoint-group-a",
        source_surface="endpoint",
        subject_reference="managed-device-a",
        observed_at=NOW,
        observation_type="running_process",
        normalized_signal={"process_family": "local_ai_runtime"},
        candidate_asset_type="runtime",
        observed_state="observed",
        identifiers={"runtime_name": "local-runtime-a"},
        attributes={"version": "1.0"},
        configuration_summary={},
        usage_summary={},
        capability_hints=("local_inference",),
        identity_hints=(),
        relationship_hints=(),
        evidence_reference="evidence://bundle-a/node-a",
        evidence_hash="b" * 64,
        signature_status="verified",
        confidence=0.9,
        freshness="fresh",
        verification_state="verified",
        source_trust="strong",
        collection_scope={"scope_type": "endpoint_group"},
        parser_version="2.0.0",
        schema_version="2.0",
        evidence_mode="direct",
        evidence_mutability="immutable",
        contradiction_state="none",
        contradiction_references=(),
        sensitivity="metadata",
        redaction_status="not_required",
    )


def _v1_contract(**overrides: object) -> DiscoveryCollectorContract:
    payload: dict[str, object] = {
        "collector_id": "gateway-primary",
        "tenant_id": "tenant-a",
        "collector_type": "llm_gateway",
        "collector_version": "1.4.2",
        "source_system": "hawk.llm_gateway",
        "health": "healthy",
        "permissions": {
            "runtime.events.read": True,
            "runtime.actions.authorize": None,
        },
        "last_success": "2026-07-23T16:30:00+04:00",
        "last_failure": None,
        "data_residency": "uae-north",
        "control_capability": "monitor_only",
        "observation_types_emitted": (
            "runtime.action",
            "runtime.health",
        ),
        "schema_version": "1.0",
    }
    payload.update(overrides)
    return DiscoveryCollectorContract.model_validate(payload)


class FakeCollector:
    def __init__(
        self,
        *,
        observations: tuple[DiscoveryObservationInput, ...] | tuple[object, ...]
        | None = None,
        scopes: tuple[ScopeItem, ...] | None = None,
        connectivity_status: str = "available",
        declaration: CollectorDeclaration | None = None,
        limitations: tuple[str, ...] = ("metadata-only",),
    ) -> None:
        self.declaration = declaration if declaration is not None else _declaration()
        self.calls: list[str] = []
        self._observations = (
            observations if observations is not None else (_observation(),)
        )
        self._scopes = scopes if scopes is not None else (_scope(),)
        self._connectivity_status = connectivity_status
        self._limitations = limitations

    def validate_configuration(self, configuration: Mapping[str, Any]) -> None:
        assert isinstance(configuration, Mapping)
        self.calls.append("validate_configuration")

    def test_connectivity(self, target: DiscoveryTargetView) -> ConnectivityResult:
        assert target.target_id == "endpoint-group-a"
        self.calls.append("test_connectivity")
        return ConnectivityResult(
            reachable=self._connectivity_status == "available",
            status=self._connectivity_status,
            checked_at=NOW,
            safe_message=(
                "connected"
                if self._connectivity_status == "available"
                else "unavailable"
            ),
        )

    def enumerate_scope(self, target: DiscoveryTargetView) -> tuple[ScopeItem, ...]:
        assert target.target_id == "endpoint-group-a"
        self.calls.append("enumerate_scope")
        return self._scopes

    def collect_inventory(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        self.calls.append(f"collect_inventory:{scope.scope_id}")
        return (_record("inventory", scope.scope_id),)

    def collect_configuration(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        self.calls.append(f"collect_configuration:{scope.scope_id}")
        return (_record("configuration", scope.scope_id),)

    def collect_usage(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        self.calls.append(f"collect_usage:{scope.scope_id}")
        return (_record("usage", scope.scope_id),)

    def collect_identity_hints(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        self.calls.append(f"collect_identity_hints:{scope.scope_id}")
        return (_record("identity_hint", scope.scope_id),)

    def collect_relationship_hints(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]:
        self.calls.append(f"collect_relationship_hints:{scope.scope_id}")
        return (_record("relationship_hint", scope.scope_id),)

    def emit_observations(self) -> tuple[DiscoveryObservationInput, ...]:
        self.calls.append("emit_observations")
        return self._observations  # type: ignore[return-value]

    def report_health(self) -> CollectorHealthReport:
        self.calls.append("report_health")
        return CollectorHealthReport(
            health="healthy",
            checked_at=NOW,
            safe_message="healthy",
        )

    def report_limitations(self) -> tuple[str, ...]:
        self.calls.append("report_limitations")
        return self._limitations


@pytest.fixture
def fake_collector() -> FakeCollector:
    return FakeCollector()


def test_protocol_contains_exactly_the_eleven_approved_methods(
    fake_collector: FakeCollector,
) -> None:
    declared = {
        name
        for name, member in HMAIRCollector.__dict__.items()
        if not name.startswith("_") and inspect.isfunction(member)
    }

    assert declared == PROTOCOL_METHODS
    assert getattr(HMAIRCollector, "_is_protocol", False) is True
    assert isinstance(fake_collector, HMAIRCollector)


@pytest.mark.parametrize(
    ("model", "payload", "bounded_field", "maximum"),
    [
        (
            ConnectivityResult,
            {
                "reachable": True,
                "status": "available",
                "checked_at": NOW,
                "safe_message": "connected",
            },
            "safe_message",
            255,
        ),
        (
            ScopeItem,
            {
                "scope_id": "scope-a",
                "scope_type": "endpoint_group",
                "permitted_methods": COLLECTION_METHODS,
            },
            "scope_id",
            128,
        ),
        (
            CollectorRecord,
            {
                "record_type": "inventory",
                "source_reference": "scope-a:inventory",
                "observed_at": NOW,
                "safe_summary": "metadata-only",
            },
            "source_reference",
            255,
        ),
        (
            CollectorRecord,
            {
                "record_type": "inventory",
                "source_reference": "scope-a:inventory",
                "observed_at": NOW,
                "safe_summary": "metadata-only",
            },
            "safe_summary",
            512,
        ),
        (
            CollectorHealthReport,
            {
                "health": "healthy",
                "checked_at": NOW,
                "safe_message": "healthy",
            },
            "safe_message",
            255,
        ),
        (
            DiscoveryTargetView,
            _target().model_dump(mode="python"),
            "identifier",
            512,
        ),
    ],
)
def test_sdk_models_are_frozen_exactly_bounded_and_forbid_arbitrary_payloads(
    model: type,
    payload: dict[str, object],
    bounded_field: str,
    maximum: int,
) -> None:
    boundary = {**payload, bounded_field: "x" * maximum}
    item = model.model_validate(boundary)

    with pytest.raises(ValidationError):
        item.safe_message = "changed"  # type: ignore[attr-defined,misc]
    with pytest.raises(ValidationError):
        model.model_validate({**payload, "payload": {"raw_prompt": "private"}})
    with pytest.raises(ValidationError):
        model.model_validate({**payload, bounded_field: "x" * (maximum + 1)})


def test_sdk_model_fields_are_exact() -> None:
    assert set(ConnectivityResult.model_fields) == {
        "reachable",
        "status",
        "checked_at",
        "safe_message",
    }
    assert set(ScopeItem.model_fields) == {
        "scope_id",
        "scope_type",
        "permitted_methods",
    }
    assert set(CollectorRecord.model_fields) == {
        "record_type",
        "source_reference",
        "observed_at",
        "safe_summary",
    }
    assert set(CollectorHealthReport.model_fields) == {
        "health",
        "checked_at",
        "safe_message",
    }
    assert set(DiscoveryTargetView.model_fields) == {
        "target_id",
        "target_type",
        "identifier",
        "environment",
        "owner_hint",
        "credentials_reference",
        "permitted_methods",
        "exclusions",
        "rate_limit",
        "active_scan_allowed",
        "sensitive_scope",
        "last_scanned_at",
    }


@pytest.mark.parametrize(
    ("status", "reachable"),
    [
        ("available", True),
        ("unsupported", False),
        ("permission_denied", False),
        ("rate_limited", False),
        ("stale", False),
    ],
)
def test_connectivity_accepts_exact_closed_statuses_and_utc_time(
    status: str,
    reachable: bool,
) -> None:
    payload = {
        "reachable": reachable,
        "status": status,
        "checked_at": NOW,
        "safe_message": "connected" if reachable else "unavailable",
    }
    ConnectivityResult.model_validate(payload)

    with pytest.raises(ValidationError):
        ConnectivityResult.model_validate(
            {**payload, "checked_at": datetime(2026, 7, 30, 12, 0)}
        )


@pytest.mark.parametrize(
    "status",
    ["unknown", "failed", "cancelled", "complete", "available_later"],
)
def test_connectivity_rejects_every_status_outside_the_closed_set(
    status: str,
) -> None:
    with pytest.raises(ValidationError):
        ConnectivityResult.model_validate(
            {
                "reachable": False,
                "status": status,
                "checked_at": NOW,
                "safe_message": "unavailable",
            }
        )


def test_sdk_validation_errors_never_echo_private_input() -> None:
    secret = "customer-private-prompt-do-not-log"
    payload = {
        "reachable": True,
        "status": "available",
        "checked_at": NOW,
        "safe_message": "connected",
        "raw_prompt": secret,
    }

    with pytest.raises(ValidationError) as captured:
        ConnectivityResult.model_validate(payload)

    rendered = json.dumps(captured.value.errors(), sort_keys=True)
    assert secret not in str(captured.value)
    assert secret not in rendered


def test_collector_emits_observations_not_assets(fake_collector: FakeCollector) -> None:
    emitted = tuple(fake_collector.emit_observations())

    assert emitted
    assert all(isinstance(item, DiscoveryObservationInput) for item in emitted)
    assert all(item.candidate_asset_type for item in emitted)
    assert all(not hasattr(item, "canonical_asset_id") for item in emitted)
    assert "canonical_asset_id" not in DiscoveryObservationInput.model_fields


class ArbitraryObservationObject:
    canonical_asset_id = "asset-final-a"
    payload = "customer-private-prompt-do-not-log"

    def __repr__(self) -> str:
        return self.payload


class ObservationSubclassWithFinalAsset(DiscoveryObservationInput):
    canonical_asset_id: str
    payload: str


@pytest.mark.parametrize(
    "arbitrary_observation",
    [
        {
            "canonical_asset_id": "asset-final-a",
            "payload": "customer-private-prompt-do-not-log",
        },
        ArbitraryObservationObject(),
        ObservationSubclassWithFinalAsset.model_validate(
            {
                **_observation().model_dump(mode="python"),
                "canonical_asset_id": "asset-final-a",
                "payload": "customer-private-prompt-do-not-log",
            }
        ),
    ],
)
def test_runner_rejects_arbitrary_payloads_and_final_asset_ids(
    arbitrary_observation: object,
) -> None:
    secret = "customer-private-prompt-do-not-log"
    bad_collector = FakeCollector(observations=(arbitrary_observation,))

    with pytest.raises(TypeError) as captured:
        collect_assignment_observations(bad_collector, _target())

    assert secret not in str(captured.value)
    assert "asset-final-a" not in str(captured.value)


@pytest.mark.parametrize(
    ("field", "hostile_value"),
    [
        ("collector_id", "hostile-collector-private-value"),
        ("collector_type", "hostile-type-private-value"),
        ("collector_version", "hostile-version-private-value"),
        ("target_id", "hostile-target-private-value"),
    ],
)
def test_runner_rejects_observation_identity_mismatch_without_echoing_values(
    field: str,
    hostile_value: str,
) -> None:
    observation = _observation().model_copy(update={field: hostile_value})
    collector = FakeCollector(observations=(observation,))

    with pytest.raises(TypeError) as captured:
        collect_assignment_observations(collector, _target())

    assert str(captured.value) == "collector returned inconsistent observation identity"
    assert hostile_value not in str(captured.value)


def test_registry_rejects_duplicate_collector_type(
    fake_collector: FakeCollector,
) -> None:
    registry = CollectorRegistry()
    registry.register("endpoint", fake_collector)

    with pytest.raises(ValueError, match="already registered"):
        registry.register("endpoint", fake_collector)


def test_registry_rejects_key_declaration_type_mismatch(
    fake_collector: FakeCollector,
) -> None:
    registry = CollectorRegistry()

    with pytest.raises(ValueError, match="collector_type"):
        registry.register("llm_gateway", fake_collector)


def test_registry_lists_two_collector_types_in_sorted_order() -> None:
    registry = CollectorRegistry()
    endpoint = FakeCollector()
    gateway = FakeCollector(
        declaration=_declaration(
            collector_id="gateway-primary",
            collector_type="llm_gateway",
            supported_target=DiscoveryTargetType.LLM_GATEWAY,
        )
    )

    registry.register("llm_gateway", gateway)
    registry.register("endpoint", endpoint)

    assert registry.get("endpoint") is endpoint
    assert registry.get("llm_gateway") is gateway
    assert registry.list_declarations() == (
        endpoint.declaration,
        gateway.declaration,
    )


def test_registry_lock_covers_concurrent_register_get_and_list() -> None:
    registry = CollectorRegistry()
    endpoint = FakeCollector()
    registry.register("endpoint", endpoint)
    target_types = tuple(DiscoveryTargetType)[1:9]
    collectors = {
        target.value: FakeCollector(
            declaration=_declaration(
                collector_id=f"{target.value}-primary",
                collector_type=target.value,
                supported_target=target,
            )
        )
        for target in target_types
    }

    def register(item: tuple[str, FakeCollector]) -> None:
        registry.register(*item)

    def read_registry() -> None:
        for _ in range(64):
            assert registry.get("endpoint") is endpoint
            collector_types = [
                item.collector_type for item in registry.list_declarations()
            ]
            assert collector_types == sorted(collector_types)

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            *(pool.submit(register, item) for item in collectors.items()),
            *(pool.submit(read_registry) for _ in range(4)),
        ]
        for future in futures:
            future.result()

    assert registry.get("endpoint") is endpoint
    assert all(registry.get(key) is value for key, value in collectors.items())
    assert len(registry.list_declarations()) == len(collectors) + 1


def test_registry_rejects_non_hmair_collectors() -> None:
    registry = CollectorRegistry()

    with pytest.raises(TypeError, match="HMAIRCollector"):
        registry.register("endpoint", object())  # type: ignore[arg-type]


def test_registry_snapshots_declaration_and_fails_closed_if_collector_changes() -> None:
    registry = CollectorRegistry()
    collector = FakeCollector()
    registry.register("endpoint", collector)
    registered_declarations = registry.list_declarations()
    hostile_id = "hostile-relabeled-collector-private-value"

    collector.declaration = _declaration(collector_id=hostile_id)

    assert registry.list_declarations() == registered_declarations
    with pytest.raises(RuntimeError) as captured:
        registry.get("endpoint")
    assert hostile_id not in str(captured.value)


def test_registry_never_dynamically_loads_an_unknown_collector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = CollectorRegistry()

    def forbidden_import(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("registry attempted dynamic import")

    monkeypatch.setattr("importlib.import_module", forbidden_import)
    with pytest.raises(KeyError, match="not registered"):
        registry.get("missing")


def test_v1_declaration_bridge_projects_every_v2_field_without_inference() -> None:
    contract = _v1_contract()
    declaration = collector_declaration_from_v1(contract)

    assert declaration.collector_id == contract.collector_id
    assert declaration.collector_type == contract.collector_type
    assert declaration.version == contract.collector_version
    assert declaration.supported_targets == (DiscoveryTargetType.LLM_GATEWAY,)
    assert declaration.active_capabilities == ()
    assert declaration.passive_capabilities == contract.observation_types_emitted
    assert declaration.permissions_required == ()
    assert declaration.sensitive_data_accessed == ()
    assert declaration.health == contract.health
    assert declaration.last_success_at == contract.last_success
    assert declaration.last_failure_at == contract.last_failure
    assert declaration.data_residency == contract.data_residency
    assert declaration.control_capability == contract.control_capability
    assert declaration.schema_version == contract.schema_version
    assert declaration.limitations == (V1_COMPATIBILITY_LIMITATION,)
    assert declaration.declaration_hash == contract.contract_hash


def test_v1_bridge_hash_and_projection_are_deterministic() -> None:
    first = _v1_contract(
        permissions={"z.read": None, "a.read": True},
        observation_types_emitted=("z.event", "a.event", "z.event"),
    )
    second = _v1_contract(
        permissions={"a.read": True, "z.read": None},
        observation_types_emitted=("a.event", "z.event"),
    )

    assert first.contract_hash == second.contract_hash
    assert collector_declaration_from_v1(first) == collector_declaration_from_v1(
        second
    )


def test_v1_bridge_does_not_infer_inline_authority() -> None:
    contract = _v1_contract(
        health="healthy",
        permissions={"runtime.actions.authorize": True},
        control_capability="unknown",
    )

    declaration = collector_declaration_from_v1(contract)

    assert declaration.control_capability == "unknown"
    assert "inline" not in declaration.active_capabilities
    assert declaration == collector_declaration_from_v1(contract)
    with pytest.raises(TypeError):
        collector_declaration_from_v1(contract.model_dump())  # type: ignore[arg-type]


@pytest.mark.parametrize("target_type", tuple(DiscoveryTargetType))
def test_v1_bridge_projects_every_exact_collector_type_to_that_target_only(
    target_type: DiscoveryTargetType,
) -> None:
    declaration = collector_declaration_from_v1(
        _v1_contract(collector_type=target_type.value)
    )

    assert declaration.supported_targets == (target_type,)


@pytest.mark.parametrize(
    "collector_type",
    ["llm-gateway", "LLM_GATEWAY", "custom_llm_gateway"],
)
def test_v1_bridge_fails_closed_when_collector_type_is_not_an_exact_target(
    collector_type: str,
) -> None:
    contract = _v1_contract(collector_type=collector_type)

    with pytest.raises(ValueError, match="supported target"):
        collector_declaration_from_v1(contract)


def test_runner_rejects_declaration_target_mismatch_before_collector_calls() -> None:
    collector = FakeCollector()

    with pytest.raises(CollectorTerminalOutcome) as captured:
        collect_assignment_observations(
            collector,
            _target(target_type=DiscoveryTargetType.BROWSER_TENANT),
        )

    assert captured.value.status is CollectorRunStatus.UNSUPPORTED
    assert collector.calls == []


def test_runner_orders_every_permitted_method_for_each_scope() -> None:
    collector = FakeCollector(scopes=(_scope("scope-a"), _scope("scope-b")))
    checkpoints: list[str] = []

    def cancellation_check() -> bool:
        checkpoints.append(collector.calls[-1])
        return False

    observations = collect_assignment_observations(
        collector,
        _target(),
        cancellation_check=cancellation_check,
    )

    assert observations == (_observation(),)
    assert collector.calls == [
        "validate_configuration",
        "test_connectivity",
        "enumerate_scope",
        "collect_inventory:scope-a",
        "collect_configuration:scope-a",
        "collect_usage:scope-a",
        "collect_identity_hints:scope-a",
        "collect_relationship_hints:scope-a",
        "collect_inventory:scope-b",
        "collect_configuration:scope-b",
        "collect_usage:scope-b",
        "collect_identity_hints:scope-b",
        "collect_relationship_hints:scope-b",
        "emit_observations",
    ]
    assert checkpoints == collector.calls[:-1]
    assert "report_health" not in collector.calls


def test_runner_uses_target_and_scope_permitted_method_intersection() -> None:
    collector = FakeCollector(
        scopes=(
            _scope(
                permitted_methods=(
                    "collect_configuration",
                    "collect_usage",
                )
            ),
        )
    )

    observations = collect_assignment_observations(
        collector,
        _target(permitted_methods=("collect_inventory", "collect_usage")),
    )

    assert observations == (_observation(),)
    assert collector.calls == [
        "validate_configuration",
        "test_connectivity",
        "enumerate_scope",
        "collect_usage:scope-a",
        "emit_observations",
    ]


def test_runner_fails_closed_when_no_collection_method_is_permitted() -> None:
    collector = FakeCollector(
        scopes=(
            _scope(permitted_methods=("collect_configuration",)),
        )
    )

    with pytest.raises(CollectorTerminalOutcome) as captured:
        collect_assignment_observations(
            collector,
            _target(permitted_methods=("collect_inventory",)),
        )

    assert captured.value.status is CollectorRunStatus.UNSUPPORTED
    assert collector.calls == [
        "validate_configuration",
        "test_connectivity",
        "enumerate_scope",
    ]


def test_runner_checks_cancellation_between_methods() -> None:
    collector = FakeCollector()
    checks = 0

    def cancellation_check() -> bool:
        nonlocal checks
        checks += 1
        return checks == 2

    with pytest.raises(CollectorTerminalOutcome) as captured:
        collect_assignment_observations(
            collector,
            _target(),
            cancellation_check=cancellation_check,
        )

    assert captured.value.status == CollectorRunStatus.CANCELLED
    assert collector.calls == ["validate_configuration", "test_connectivity"]


@pytest.mark.parametrize(
    "status",
    [
        CollectorRunStatus.UNSUPPORTED,
        CollectorRunStatus.PERMISSION_DENIED,
        CollectorRunStatus.RATE_LIMITED,
        CollectorRunStatus.STALE,
    ],
)
def test_connectivity_terminal_outcomes_are_explicit(
    status: CollectorRunStatus,
) -> None:
    collector = FakeCollector(connectivity_status=status.value)

    with pytest.raises(CollectorTerminalOutcome) as captured:
        collect_assignment_observations(collector, _target())

    assert captured.value.status is status
    assert captured.value.safe_message == "unavailable"
    assert collector.calls == ["validate_configuration", "test_connectivity"]


class PrivateSourceFailure(Exception):
    def __init__(self, secret: str) -> None:
        self.private_context = {"payload": secret}
        super().__init__(secret, self.private_context)


def _install_external_failure(
    collector: FakeCollector,
    failure_stage: str,
    failure: Exception,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    def explode(*_args: object, **_kwargs: object) -> bool:
        raise failure

    if failure_stage == "cancellation_check":
        return explode
    monkeypatch.setattr(collector, failure_stage, explode)
    return None


def _assert_generic_sanitized_failure(
    failure: Exception,
    secret: str,
) -> None:
    assert isinstance(failure, RuntimeError)
    assert not isinstance(failure, CollectorTerminalOutcome)
    assert str(failure) == "collector execution failed"
    assert secret not in repr(failure.args)
    assert failure.__cause__ is None
    assert failure.__context__ is None


def _assert_sanitized_runtime_failure(
    failure: Exception,
    secret: str,
) -> None:
    assert isinstance(failure, RuntimeError)
    assert not isinstance(failure, CollectorTerminalOutcome)
    assert secret not in str(failure)
    assert secret not in repr(failure.args)
    assert failure.__cause__ is None
    assert failure.__context__ is None


@pytest.mark.parametrize(
    "failure_stage",
    EXTERNAL_OPERATIONS,
)
def test_unexpected_source_failures_are_sanitized_and_not_terminal_outcomes(
    failure_stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = FakeCollector()
    secret = f"customer-private-{failure_stage}-context"
    cancellation_check = _install_external_failure(
        collector,
        failure_stage,
        PrivateSourceFailure(secret),
        monkeypatch,
    )

    with pytest.raises(RuntimeError) as captured:
        collect_assignment_observations(
            collector,
            _target(),
            cancellation_check=cancellation_check,
        )

    _assert_generic_sanitized_failure(captured.value, secret)


@pytest.mark.parametrize("failure_stage", EXTERNAL_OPERATIONS)
def test_invalid_mutated_terminal_outcome_from_every_operation_is_sanitized(
    failure_stage: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = f"customer-private-terminal-{failure_stage}"
    outcome = CollectorTerminalOutcome(
        CollectorRunStatus.UNSUPPORTED,
        "source unsupported",
    )
    outcome.status = CollectorRunStatus.COMPLETE
    outcome.safe_message = secret
    outcome.args = (secret, {"payload": secret})
    collector = FakeCollector()
    cancellation_check = _install_external_failure(
        collector,
        failure_stage,
        outcome,
        monkeypatch,
    )

    with pytest.raises(RuntimeError) as captured:
        collect_assignment_observations(
            collector,
            _target(),
            cancellation_check=cancellation_check,
        )

    _assert_generic_sanitized_failure(captured.value, secret)


def _assert_reconstructed_terminal_or_generic(
    failure: Exception,
    source: CollectorTerminalOutcome,
    secret: str,
) -> None:
    if isinstance(failure, CollectorTerminalOutcome):
        assert type(failure) is CollectorTerminalOutcome
        assert failure is not source
        assert type(failure.status) is CollectorRunStatus
        assert failure.status in {
            CollectorRunStatus.CANCELLED,
            CollectorRunStatus.UNSUPPORTED,
            CollectorRunStatus.PERMISSION_DENIED,
            CollectorRunStatus.RATE_LIMITED,
            CollectorRunStatus.STALE,
            CollectorRunStatus.EMPTY,
        }
        assert secret not in failure.safe_message
        assert failure.args == (failure.safe_message,)
        assert failure.__cause__ is None
        assert failure.__context__ is None
        return
    _assert_generic_sanitized_failure(failure, secret)


def test_mutated_terminal_message_and_args_never_cross_source_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "customer-private-mutated-terminal"
    source = CollectorTerminalOutcome(
        CollectorRunStatus.PERMISSION_DENIED,
        "permission denied",
    )
    source.safe_message = secret
    source.args = (secret, {"payload": secret})
    collector = FakeCollector()
    _install_external_failure(
        collector,
        "validate_configuration",
        source,
        monkeypatch,
    )

    with pytest.raises(Exception) as captured:
        collect_assignment_observations(collector, _target())

    _assert_reconstructed_terminal_or_generic(captured.value, source, secret)


def test_terminal_outcome_subclass_never_crosses_source_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "customer-private-terminal-subclass"

    class HostileTerminalOutcome(CollectorTerminalOutcome):
        def __str__(self) -> str:
            return secret

    source = HostileTerminalOutcome(
        CollectorRunStatus.STALE,
        "source stale",
    )
    source.safe_message = secret
    source.args = (secret, {"payload": secret})
    collector = FakeCollector()
    _install_external_failure(
        collector,
        "test_connectivity",
        source,
        monkeypatch,
    )

    with pytest.raises(Exception) as captured:
        collect_assignment_observations(collector, _target())

    _assert_reconstructed_terminal_or_generic(captured.value, source, secret)


@pytest.mark.parametrize(
    "status",
    [
        CollectorRunStatus.CANCELLED,
        CollectorRunStatus.UNSUPPORTED,
        CollectorRunStatus.PERMISSION_DENIED,
        CollectorRunStatus.RATE_LIMITED,
        CollectorRunStatus.STALE,
        CollectorRunStatus.EMPTY,
    ],
)
def test_valid_source_terminal_outcome_crosses_as_fresh_validated_instance(
    status: CollectorRunStatus,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = CollectorTerminalOutcome(status, "source unavailable")
    collector = FakeCollector()
    _install_external_failure(
        collector,
        "validate_configuration",
        source,
        monkeypatch,
    )

    with pytest.raises(CollectorTerminalOutcome) as captured:
        collect_assignment_observations(collector, _target())

    failure = captured.value
    assert type(failure) is CollectorTerminalOutcome
    assert failure is not source
    assert failure.status is status
    assert failure.safe_message == "source unavailable"
    assert failure.args == (failure.safe_message,)
    assert failure.__cause__ is None
    assert failure.__context__ is None


@pytest.mark.parametrize(
    "callback_result",
    [None, 0, 1, "false", object()],
    ids=["none", "zero", "one", "text", "object"],
)
def test_cancellation_callback_requires_an_exact_bool(
    callback_result: object,
) -> None:
    secret = "customer-private-cancellation-result"

    with pytest.raises(RuntimeError) as captured:
        collect_assignment_observations(
            FakeCollector(),
            _target(),
            cancellation_check=lambda: callback_result,  # type: ignore[arg-type]
        )

    _assert_generic_sanitized_failure(captured.value, secret)


def test_cancellation_result_never_invokes_hostile_truthiness() -> None:
    secret = "customer-private-hostile-truthiness"

    class HostileTruthiness:
        bool_calls = 0

        def __bool__(self) -> bool:
            self.bool_calls += 1
            raise PrivateSourceFailure(secret)

    result = HostileTruthiness()

    with pytest.raises(RuntimeError) as captured:
        collect_assignment_observations(
            FakeCollector(),
            _target(),
            cancellation_check=lambda: result,  # type: ignore[arg-type]
        )

    _assert_generic_sanitized_failure(captured.value, secret)
    assert result.bool_calls == 0


class HostileBoolCancellationCheck:
    def __init__(self, *, secret: str, raises: bool) -> None:
        self.secret = secret
        self.raises = raises
        self.bool_calls = 0
        self.call_calls = 0

    def __bool__(self) -> bool:
        self.bool_calls += 1
        raise PrivateSourceFailure(self.secret)

    def __call__(self) -> bool:
        self.call_calls += 1
        if self.raises:
            raise PrivateSourceFailure(self.secret)
        return False


def test_callable_cancellation_check_is_selected_without_truthiness() -> None:
    callback = HostileBoolCancellationCheck(
        secret="customer-private-callback-selection",
        raises=False,
    )

    assert collect_assignment_observations(
        FakeCollector(),
        _target(),
        cancellation_check=callback,
    ) == (_observation(),)
    assert callback.bool_calls == 0
    assert callback.call_calls > 0


def test_callable_cancellation_exception_is_sanitized_without_truthiness() -> None:
    secret = "customer-private-callback-exception"
    callback = HostileBoolCancellationCheck(secret=secret, raises=True)

    with pytest.raises(RuntimeError) as captured:
        collect_assignment_observations(
            FakeCollector(),
            _target(),
            cancellation_check=callback,
        )

    _assert_generic_sanitized_failure(captured.value, secret)
    assert callback.bool_calls == 0
    assert callback.call_calls == 1


@pytest.mark.parametrize(
    "method_name",
    [
        "validate_configuration",
        "test_connectivity",
        "enumerate_scope",
        "emit_observations",
    ],
)
def test_non_collection_method_property_failure_is_sanitized(
    method_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = f"customer-private-{method_name}-property"

    class PropertyCollector(FakeCollector):
        pass

    collector = PropertyCollector()

    def raise_from_property(_collector: PropertyCollector) -> object:
        raise PrivateSourceFailure(secret)

    monkeypatch.setattr(
        PropertyCollector,
        method_name,
        property(raise_from_property),
    )

    with pytest.raises(RuntimeError) as captured:
        collect_assignment_observations(collector, _target())

    _assert_generic_sanitized_failure(captured.value, secret)
    assert "report_health" not in collector.calls
    assert "report_limitations" not in collector.calls


class DeclarationPropertyCollector(FakeCollector):
    def __init__(self, secret: str) -> None:
        self._declaration_secret = secret
        self._declaration_fails = False
        super().__init__()

    @property
    def declaration(self) -> CollectorDeclaration:
        if self._declaration_fails:
            raise PrivateSourceFailure(self._declaration_secret)
        return self._stored_declaration

    @declaration.setter
    def declaration(self, value: CollectorDeclaration) -> None:
        self._stored_declaration = value


def test_runner_sanitizes_declaration_property_failure() -> None:
    secret = "customer-private-runner-declaration"
    collector = DeclarationPropertyCollector(secret)
    collector._declaration_fails = True

    with pytest.raises(RuntimeError) as captured:
        collect_assignment_observations(collector, _target())

    _assert_sanitized_runtime_failure(captured.value, secret)


def test_registry_register_sanitizes_declaration_property_failure() -> None:
    secret = "customer-private-register-declaration"
    collector = DeclarationPropertyCollector(secret)
    collector._declaration_fails = True

    with pytest.raises(RuntimeError) as captured:
        CollectorRegistry().register("endpoint", collector)

    _assert_sanitized_runtime_failure(captured.value, secret)


def test_registry_get_sanitizes_declaration_property_failure() -> None:
    secret = "customer-private-get-declaration"
    collector = DeclarationPropertyCollector(secret)
    registry = CollectorRegistry()
    registry.register("endpoint", collector)
    collector._declaration_fails = True

    with pytest.raises(RuntimeError) as captured:
        registry.get("endpoint")

    _assert_sanitized_runtime_failure(captured.value, secret)


@pytest.mark.parametrize(
    "status",
    [
        CollectorRunStatus.CANCELLED,
        CollectorRunStatus.UNSUPPORTED,
        CollectorRunStatus.PERMISSION_DENIED,
        CollectorRunStatus.RATE_LIMITED,
        CollectorRunStatus.STALE,
        CollectorRunStatus.EMPTY,
    ],
)
def test_terminal_outcome_accepts_only_closed_non_success_statuses(
    status: CollectorRunStatus,
) -> None:
    outcome = CollectorTerminalOutcome(status, "source unavailable")

    assert outcome.status is status
    assert outcome.safe_message == "source unavailable"


@pytest.mark.parametrize(
    "status",
    [
        CollectorRunStatus.PENDING,
        CollectorRunStatus.RUNNING,
        CollectorRunStatus.COMPLETE,
        CollectorRunStatus.FAILED,
    ],
)
def test_terminal_outcome_rejects_non_terminal_or_untyped_statuses(
    status: CollectorRunStatus,
) -> None:
    with pytest.raises(ValueError):
        CollectorTerminalOutcome(status, "invalid terminal state")
    with pytest.raises(TypeError):
        CollectorTerminalOutcome(
            status.value,  # type: ignore[arg-type]
            "untyped status",
        )


def test_terminal_outcome_sanitizes_and_bounds_messages() -> None:
    secret = "sk-super-secret-value"
    email = "operator@example.com"
    outcome = CollectorTerminalOutcome(
        CollectorRunStatus.PERMISSION_DENIED,
        f"{secret} belongs to {email} " + "x" * 4096,
    )

    assert secret not in outcome.safe_message
    assert email not in outcome.safe_message
    assert len(outcome.safe_message) <= 255


def test_empty_observation_result_is_explicit_not_success() -> None:
    collector = FakeCollector(observations=())

    with pytest.raises(CollectorTerminalOutcome) as captured:
        collect_assignment_observations(collector, _target())

    assert captured.value.status == CollectorRunStatus.EMPTY
