"""Closed, local resolver registry for typed target and destination inputs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class ResolverRegistry:
    def __init__(self) -> None:
        self._resolvers: dict[tuple[str, str], Callable[[Any], Any]] = {}

    def register(self, resolver_id: str, version: str, resolver: Callable[[Any], Any]) -> None:
        key = (resolver_id, version)
        if key in self._resolvers:
            raise ValueError("resolver already registered")
        self._resolvers[key] = resolver

    def resolve(self, resolver_id: str, version: str, value: Any) -> Any:
        try:
            return self._resolvers[(resolver_id, version)](value)
        except KeyError as exc:
            raise ValueError("unsupported resolver") from exc
