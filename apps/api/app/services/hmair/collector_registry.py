from __future__ import annotations

from threading import RLock

from app.services.hmair.collector_sdk import (
    HMAIRCollector,
    _is_hmair_collector,
    _read_collector_declaration,
)
from app.services.hmair.contracts import CollectorDeclaration


class CollectorRegistry:
    def __init__(self) -> None:
        self._lock = RLock()
        self._collectors: dict[str, HMAIRCollector] = {}
        self._declarations: dict[str, CollectorDeclaration] = {}

    def register(self, collector_type: str, collector: HMAIRCollector) -> None:
        if type(collector_type) is not str or not collector_type:
            raise TypeError("collector type must be bounded text")
        if not _is_hmair_collector(collector):
            raise TypeError("collector must implement HMAIRCollector")
        collector_declaration = _read_collector_declaration(collector)
        if type(collector_declaration) is not CollectorDeclaration:
            raise TypeError("collector declaration is invalid")
        declaration = CollectorDeclaration.model_validate(
            collector_declaration.model_dump(mode="python")
        )
        if collector_type != declaration.collector_type:
            raise ValueError("collector_type does not match declaration")
        with self._lock:
            if collector_type in self._collectors:
                raise ValueError("collector type already registered")
            self._collectors[collector_type] = collector
            self._declarations[collector_type] = declaration

    def get(self, collector_type: str) -> HMAIRCollector:
        with self._lock:
            try:
                collector = self._collectors[collector_type]
                declaration = self._declarations[collector_type]
            except KeyError:
                raise KeyError("collector type is not registered") from None
            current_declaration = _read_collector_declaration(collector)
            if type(current_declaration) is not CollectorDeclaration:
                raise RuntimeError("registered collector declaration changed")
            if current_declaration != declaration:
                raise RuntimeError("registered collector declaration changed")
            return collector

    def list_declarations(self) -> tuple[CollectorDeclaration, ...]:
        with self._lock:
            return tuple(
                self._declarations[key]
                for key in sorted(self._declarations)
            )


__all__ = ["CollectorRegistry"]
