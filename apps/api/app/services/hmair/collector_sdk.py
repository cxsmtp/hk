from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field, StrictBool, ValidationInfo, field_validator, model_validator

from app.services.discovery_collector_contract import DiscoveryCollectorContract
from app.services.hmair.contracts import (
    CollectorDeclaration,
    CollectorRunStatus,
    DiscoveryObservationInput,
    DiscoveryTargetInput,
    DiscoveryTargetType,
    StrictContract,
)
from app.services.privacy_sanitizer import redact_sensitive_text


COLLECTION_METHODS = (
    "collect_inventory",
    "collect_configuration",
    "collect_usage",
    "collect_identity_hints",
    "collect_relationship_hints",
)
V1_COMPATIBILITY_LIMITATION = (
    "v1 omits supported depth, required-permission, active-capability, "
    "and sensitive-data metadata"
)
_TERMINAL_STATUSES = frozenset(
    {
        CollectorRunStatus.CANCELLED,
        CollectorRunStatus.UNSUPPORTED,
        CollectorRunStatus.PERMISSION_DENIED,
        CollectorRunStatus.RATE_LIMITED,
        CollectorRunStatus.STALE,
        CollectorRunStatus.EMPTY,
    }
)
_CONNECTIVITY_TERMINAL_STATUSES = {
    "unsupported": CollectorRunStatus.UNSUPPORTED,
    "permission_denied": CollectorRunStatus.PERMISSION_DENIED,
    "rate_limited": CollectorRunStatus.RATE_LIMITED,
    "stale": CollectorRunStatus.STALE,
}


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return value.astimezone(timezone.utc)


def _bounded_string_tuple(
    value: tuple[str, ...],
    *,
    field_name: str,
    maximum_items: int,
) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        raise ValueError(f"{field_name} is not a bounded tuple")
    normalized: list[str] = []
    for item in value:
        if type(item) is not str:
            raise ValueError(f"{field_name} items must be strings")
        clean = item.strip()
        if not clean or len(clean) > 128:
            raise ValueError(f"{field_name} items must contain 1 to 128 characters")
        if redact_sensitive_text(clean, max_len=128) != clean:
            raise ValueError(f"{field_name} items cannot contain private material")
        normalized.append(clean)
    return tuple(normalized)


class ConnectivityResult(StrictContract):
    reachable: StrictBool
    status: Literal[
        "available",
        "unsupported",
        "permission_denied",
        "rate_limited",
        "stale",
    ]
    checked_at: datetime
    safe_message: str = Field(min_length=1, max_length=255)

    @field_validator("checked_at")
    @classmethod
    def checked_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, field_name="checked_at")

    @field_validator("safe_message")
    @classmethod
    def message_is_safe(cls, value: str) -> str:
        if redact_sensitive_text(value, max_len=255) != value:
            raise ValueError("safe_message cannot contain private material")
        return value

    @model_validator(mode="after")
    def status_matches_reachability(self) -> "ConnectivityResult":
        if self.reachable != (self.status == "available"):
            raise ValueError("connectivity reachability and status disagree")
        return self


class ScopeItem(StrictContract):
    scope_id: str = Field(min_length=1, max_length=128)
    scope_type: str = Field(min_length=1, max_length=64)
    permitted_methods: tuple[str, ...] = Field(max_length=32)

    @field_validator("permitted_methods")
    @classmethod
    def bounded_methods(
        cls,
        value: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        return _bounded_string_tuple(
            value,
            field_name=info.field_name,
            maximum_items=32,
        )


class CollectorRecord(StrictContract):
    record_type: str = Field(min_length=1, max_length=128)
    source_reference: str = Field(min_length=1, max_length=255)
    observed_at: datetime
    safe_summary: str = Field(min_length=1, max_length=512)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, field_name="observed_at")

    @field_validator("safe_summary")
    @classmethod
    def summary_is_safe(cls, value: str) -> str:
        if redact_sensitive_text(value, max_len=512) != value:
            raise ValueError("safe_summary cannot contain private material")
        return value


class CollectorHealthReport(StrictContract):
    health: Literal["healthy", "warning", "degraded", "offline", "unknown"]
    checked_at: datetime
    safe_message: str = Field(min_length=1, max_length=255)

    @field_validator("checked_at")
    @classmethod
    def checked_at_is_utc(cls, value: datetime) -> datetime:
        return _utc(value, field_name="checked_at")

    @field_validator("safe_message")
    @classmethod
    def message_is_safe(cls, value: str) -> str:
        if redact_sensitive_text(value, max_len=255) != value:
            raise ValueError("safe_message cannot contain private material")
        return value


class DiscoveryTargetView(DiscoveryTargetInput):
    @field_validator("last_scanned_at")
    @classmethod
    def last_scanned_at_is_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _utc(value, field_name="last_scanned_at")


@runtime_checkable
class HMAIRCollector(Protocol):
    declaration: CollectorDeclaration

    def validate_configuration(self, configuration: Mapping[str, Any]) -> None: ...

    def test_connectivity(self, target: DiscoveryTargetView) -> ConnectivityResult: ...

    def enumerate_scope(self, target: DiscoveryTargetView) -> tuple[ScopeItem, ...]: ...

    def collect_inventory(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]: ...

    def collect_configuration(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]: ...

    def collect_usage(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]: ...

    def collect_identity_hints(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]: ...

    def collect_relationship_hints(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]: ...

    def emit_observations(self) -> tuple[DiscoveryObservationInput, ...]: ...

    def report_health(self) -> CollectorHealthReport: ...

    def report_limitations(self) -> tuple[str, ...]: ...


class CollectorTerminalOutcome(Exception):
    def __init__(self, status: CollectorRunStatus, safe_message: str) -> None:
        if type(status) is not CollectorRunStatus:
            raise TypeError("collector terminal status must be typed")
        if status not in _TERMINAL_STATUSES:
            raise ValueError("collector status is not an expected terminal outcome")
        if type(safe_message) is not str:
            raise TypeError("collector terminal message must be text")
        sanitized = redact_sensitive_text(safe_message, max_len=255)[:255].strip()
        self.status = status
        self.safe_message = sanitized or "collector unavailable"
        super().__init__(self.safe_message)


def collector_declaration_from_v1(
    contract: DiscoveryCollectorContract,
) -> CollectorDeclaration:
    if type(contract) is not DiscoveryCollectorContract:
        raise TypeError("v1 bridge requires DiscoveryCollectorContract")
    try:
        supported_target = DiscoveryTargetType(contract.collector_type)
    except ValueError:
        raise ValueError(
            "v1 declaration does not declare an exact supported target"
        ) from None
    return CollectorDeclaration(
        collector_id=contract.collector_id,
        collector_type=contract.collector_type,
        version=contract.collector_version,
        supported_targets=(supported_target,),
        active_capabilities=(),
        passive_capabilities=contract.observation_types_emitted,
        permissions_required=(),
        sensitive_data_accessed=(),
        health=contract.health,
        last_success_at=contract.last_success,
        last_failure_at=contract.last_failure,
        data_residency=contract.data_residency,
        control_capability=contract.control_capability,
        schema_version=contract.schema_version,
        limitations=(V1_COMPATIBILITY_LIMITATION,),
        declaration_hash=contract.contract_hash,
    )


def _validated_exact_model(value: object, model: type[StrictContract]) -> StrictContract:
    if type(value) is not model:
        raise TypeError("collector returned an invalid typed result")
    return model.model_validate(value.model_dump(mode="python"))


def _validated_tuple(value: object, model: type[StrictContract]) -> tuple[StrictContract, ...]:
    if type(value) is not tuple:
        raise TypeError("collector returned an invalid typed result")
    return tuple(_validated_exact_model(item, model) for item in value)


def _is_hmair_collector(value: object) -> bool:
    try:
        result = isinstance(value, HMAIRCollector)
    except Exception:
        pass
    else:
        return result
    raise RuntimeError("collector execution failed") from None


def _read_collector_declaration(collector: HMAIRCollector) -> object:
    try:
        declaration = collector.declaration
    except Exception:
        pass
    else:
        return declaration
    raise RuntimeError("collector execution failed") from None


def _invoke_collector(operation: Callable[..., Any], *args: object) -> Any:
    terminal_status: object | None = None
    try:
        result = operation(*args)
    except CollectorTerminalOutcome as outcome:
        if type(outcome) is CollectorTerminalOutcome:
            state = vars(outcome)
            terminal_status = state.get("status")
    except Exception:
        pass
    else:
        return result
    if terminal_status is not None:
        try:
            validated_outcome = CollectorTerminalOutcome(
                terminal_status,
                "source unavailable",
            )
        except (TypeError, ValueError):
            pass
        else:
            raise validated_outcome from None
    # Raise after leaving the source exception handler so neither its content
    # nor its exception context crosses the collector isolation boundary.
    raise RuntimeError("collector execution failed") from None


def collect_assignment_observations(
    collector: HMAIRCollector,
    target: DiscoveryTargetView,
    *,
    cancellation_check: Callable[[], bool] | None = None,
) -> tuple[DiscoveryObservationInput, ...]:
    if not _is_hmair_collector(collector):
        raise TypeError("collector must implement HMAIRCollector")
    collector_declaration = _read_collector_declaration(collector)
    if type(collector_declaration) is not CollectorDeclaration:
        raise TypeError("collector declaration is invalid")
    declaration = CollectorDeclaration.model_validate(
        collector_declaration.model_dump(mode="python")
    )
    if type(target) is not DiscoveryTargetView:
        raise TypeError("target must be a DiscoveryTargetView")
    checked_target = DiscoveryTargetView.model_validate(target.model_dump(mode="python"))
    if checked_target.target_type not in declaration.supported_targets:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "collector does not support target type",
        )

    is_cancelled = (lambda: False) if cancellation_check is None else cancellation_check

    def check_cancelled() -> None:
        cancelled = _invoke_collector(is_cancelled)
        if type(cancelled) is not bool:
            raise RuntimeError("collector execution failed") from None
        if cancelled:
            raise CollectorTerminalOutcome(
                CollectorRunStatus.CANCELLED,
                "collector run cancelled",
            )

    validate_configuration = _invoke_collector(
        getattr,
        collector,
        "validate_configuration",
    )
    validation_result = _invoke_collector(
        validate_configuration,
        MappingProxyType({}),
    )
    if validation_result is not None:
        raise TypeError("collector configuration validation returned invalid result")
    check_cancelled()

    test_connectivity = _invoke_collector(
        getattr,
        collector,
        "test_connectivity",
    )
    connectivity = _validated_exact_model(
        _invoke_collector(test_connectivity, checked_target),
        ConnectivityResult,
    )
    assert isinstance(connectivity, ConnectivityResult)
    check_cancelled()
    if connectivity.status != "available":
        raise CollectorTerminalOutcome(
            _CONNECTIVITY_TERMINAL_STATUSES[connectivity.status],
            connectivity.safe_message,
        )

    enumerate_scope = _invoke_collector(
        getattr,
        collector,
        "enumerate_scope",
    )
    scopes = _validated_tuple(
        _invoke_collector(enumerate_scope, checked_target),
        ScopeItem,
    )
    check_cancelled()
    if not scopes:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.EMPTY,
            "collector returned no permitted scope",
        )

    target_methods = frozenset(checked_target.permitted_methods)
    invoked_collection = False
    for scope_value in scopes:
        assert isinstance(scope_value, ScopeItem)
        permitted = target_methods & frozenset(scope_value.permitted_methods)
        for method_name in COLLECTION_METHODS:
            if method_name not in permitted:
                continue
            invoked_collection = True
            method = _invoke_collector(getattr, collector, method_name)
            result = _invoke_collector(method, scope_value)
            _validated_tuple(result, CollectorRecord)
            check_cancelled()

    if not invoked_collection:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "no collection method is permitted",
        )

    emit_observations = _invoke_collector(
        getattr,
        collector,
        "emit_observations",
    )
    raw_observations = _invoke_collector(emit_observations)
    if type(raw_observations) is not tuple:
        raise TypeError("collector returned invalid observations")
    observations: list[DiscoveryObservationInput] = []
    for item in raw_observations:
        if type(item) is not DiscoveryObservationInput:
            raise TypeError("collector returned invalid observations")
        observation = DiscoveryObservationInput.model_validate(
            item.model_dump(mode="python")
        )
        if (
            observation.collector_id != declaration.collector_id
            or observation.collector_type != declaration.collector_type
            or observation.collector_version != declaration.version
            or observation.target_id != checked_target.target_id
        ):
            raise TypeError("collector returned inconsistent observation identity")
        observations.append(observation)
    if not observations:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.EMPTY,
            "collector returned no observations",
        )
    return tuple(observations)


__all__ = [
    "CollectorHealthReport",
    "CollectorRecord",
    "CollectorTerminalOutcome",
    "ConnectivityResult",
    "DiscoveryTargetView",
    "HMAIRCollector",
    "ScopeItem",
    "collect_assignment_observations",
    "collector_declaration_from_v1",
]
