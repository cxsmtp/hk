from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Callable

from app.services.hmair.collector_sdk import (
    COLLECTION_METHODS,
    CollectorHealthReport,
    CollectorRecord,
    CollectorTerminalOutcome,
    ConnectivityResult,
    DiscoveryTargetView,
    HMAIRCollector,
    ScopeItem,
)
from app.services.hmair.contracts import (
    CollectorDeclaration,
    CollectorRunStatus,
    DiscoveryObservationInput,
)


_CONNECTIVITY_OUTCOMES = {
    "unsupported": CollectorRunStatus.UNSUPPORTED,
    "permission_denied": CollectorRunStatus.PERMISSION_DENIED,
    "rate_limited": CollectorRunStatus.RATE_LIMITED,
    "stale": CollectorRunStatus.STALE,
}


def _safe_call(operation: Callable[..., Any], *args: object) -> Any:
    try:
        return operation(*args)
    except CollectorTerminalOutcome:
        raise
    except Exception:
        raise RuntimeError("collector execution failed") from None


def _exact_model(value: object, model: type[Any]) -> Any:
    if type(value) is not model:
        raise TypeError("collector returned an invalid typed result")
    return model.model_validate(value.model_dump(mode="python"))


def _exact_tuple(value: object, model: type[Any]) -> tuple[Any, ...]:
    if type(value) is not tuple:
        raise TypeError("collector returned an invalid typed result")
    return tuple(_exact_model(item, model) for item in value)


class CollectorFacade:
    """Compact, observation-only facade over the strict HMAIR collector SDK.

    The facade deliberately has no database dependency and exposes no asset,
    ownership, risk, approval, or Shadow AI mutation primitive.
    """

    __slots__ = ("_collector", "_declaration")

    def __init__(self, collector: HMAIRCollector) -> None:
        if not isinstance(collector, HMAIRCollector):
            raise TypeError("collector must implement HMAIRCollector")
        declaration = _safe_call(getattr, collector, "declaration")
        self._declaration = _exact_model(declaration, CollectorDeclaration)
        self._collector = collector

    def validate(self, configuration: Mapping[str, Any]) -> None:
        if not isinstance(configuration, Mapping):
            raise TypeError("collector configuration must be a mapping")
        operation = _safe_call(
            getattr, self._collector, "validate_configuration"
        )
        result = _safe_call(operation, MappingProxyType(dict(configuration)))
        if result is not None:
            raise TypeError("collector configuration validation returned invalid result")

    def enumerate(self, target: DiscoveryTargetView) -> tuple[ScopeItem, ...]:
        checked_target = _exact_model(target, DiscoveryTargetView)
        if checked_target.target_type not in self._declaration.supported_targets:
            raise CollectorTerminalOutcome(
                CollectorRunStatus.UNSUPPORTED,
                "collector does not support target type",
            )
        connectivity_operation = _safe_call(
            getattr, self._collector, "test_connectivity"
        )
        connectivity = _exact_model(
            _safe_call(connectivity_operation, checked_target),
            ConnectivityResult,
        )
        if connectivity.status != "available":
            raise CollectorTerminalOutcome(
                _CONNECTIVITY_OUTCOMES[connectivity.status],
                connectivity.safe_message,
            )
        enumerate_operation = _safe_call(
            getattr, self._collector, "enumerate_scope"
        )
        scopes = _exact_tuple(
            _safe_call(enumerate_operation, checked_target), ScopeItem
        )
        if not scopes:
            raise CollectorTerminalOutcome(
                CollectorRunStatus.EMPTY,
                "collector returned no permitted scope",
            )
        return scopes

    def collect(self, scope: ScopeItem) -> None:
        checked_scope = _exact_model(scope, ScopeItem)
        invoked = False
        permitted = frozenset(checked_scope.permitted_methods)
        for method_name in COLLECTION_METHODS:
            if method_name not in permitted:
                continue
            invoked = True
            operation = _safe_call(getattr, self._collector, method_name)
            _exact_tuple(
                _safe_call(operation, checked_scope), CollectorRecord
            )
        if not invoked:
            raise CollectorTerminalOutcome(
                CollectorRunStatus.UNSUPPORTED,
                "no collection method is permitted",
            )

    def observe(self) -> tuple[DiscoveryObservationInput, ...]:
        operation = _safe_call(getattr, self._collector, "emit_observations")
        observations = _exact_tuple(
            _safe_call(operation), DiscoveryObservationInput
        )
        for observation in observations:
            if (
                observation.collector_id != self._declaration.collector_id
                or observation.collector_type
                != self._declaration.collector_type
                or observation.collector_version != self._declaration.version
            ):
                raise TypeError(
                    "collector returned inconsistent observation identity"
                )
        if not observations:
            raise CollectorTerminalOutcome(
                CollectorRunStatus.EMPTY,
                "collector returned no observations",
            )
        return observations

    def health(self) -> CollectorHealthReport:
        operation = _safe_call(getattr, self._collector, "report_health")
        return _exact_model(_safe_call(operation), CollectorHealthReport)

    def limitations(self) -> tuple[str, ...]:
        operation = _safe_call(getattr, self._collector, "report_limitations")
        value = _safe_call(operation)
        if type(value) is not tuple or any(
            type(item) is not str or not item.strip() or len(item) > 512
            for item in value
        ):
            raise TypeError("collector returned invalid limitations")
        return tuple(item.strip() for item in value)

    def schema_version(self) -> str:
        return self._declaration.schema_version


__all__ = ["CollectorFacade"]
