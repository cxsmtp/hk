"""Closed registry for explicit HMAIR source providers."""

from __future__ import annotations

from dataclasses import dataclass

from app.services.hmair.source_connectors.contracts import (
    HMAIRSourceProvider,
    SOURCE_FLAG_BY_PROVIDER,
    TARGET_TYPE_BY_PROVIDER,
)


@dataclass(frozen=True)
class HMAIRSourceDefinition:
    provider_key: HMAIRSourceProvider
    target_type: str
    source_flag: str


class HMAIRSourceRegistry:
    def __init__(self) -> None:
        self._definitions = {
            provider.value: HMAIRSourceDefinition(
                provider_key=provider,
                target_type=TARGET_TYPE_BY_PROVIDER[provider],
                source_flag=SOURCE_FLAG_BY_PROVIDER[provider],
            )
            for provider in HMAIRSourceProvider
        }

    def get(self, provider_key: str) -> HMAIRSourceDefinition:
        try:
            return self._definitions[provider_key]
        except KeyError:
            raise LookupError("HMAIR source provider is not registered") from None

    def get_collector(self, provider_key: str):
        """Resolve only the explicitly registered source implementation."""

        provider = self.get(provider_key).provider_key
        if provider is HMAIRSourceProvider.MICROSOFT365:
            from app.services.hmair.source_connectors.microsoft365 import microsoft365

            return microsoft365
        if provider is HMAIRSourceProvider.GITHUB_CLOUD:
            from app.services.hmair.source_connectors.github_cloud import github_cloud

            return github_cloud
        if provider is HMAIRSourceProvider.GITHUB_GHES:
            from app.services.hmair.source_connectors.github_enterprise_server import ghes

            return ghes
        raise LookupError("HMAIR source provider is not registered")


source_registry = HMAIRSourceRegistry()

__all__ = ["HMAIRSourceDefinition", "HMAIRSourceRegistry", "source_registry"]
