"""Provider-neutral Account Boundary validation boundary.

Production has no built-in provider integrations.  Unknown providers are
explicitly unsupported and therefore cannot produce a passing validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol


@dataclass(frozen=True)
class IntegrationValidationResult:
    status: str
    route_health: str
    provider_version: str
    capabilities: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    valid_for_seconds: int = 0

    def valid_until(self, checked_at: datetime) -> datetime:
        return checked_at + timedelta(seconds=max(0, self.valid_for_seconds))


@dataclass(frozen=True)
class IdentityVerificationResult:
    account_class: str = "UNKNOWN"
    organisation_ids: tuple[str, ...] = ()
    workspace_ids: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


class AccountBoundaryProviderAdapter(Protocol):
    def validate_integration(self, *, tenant_id: str, provider: str, product: str, surface: str) -> IntegrationValidationResult: ...
    def verify_identity(self, *, tenant_id: str, provider: str, product: str, subject_ref: str, email: str | None) -> IdentityVerificationResult: ...


class UnsupportedAccountBoundaryAdapter:
    """Fail closed rather than inventing provider capabilities or evidence."""

    def validate_integration(self, *, tenant_id: str, provider: str, product: str, surface: str) -> IntegrationValidationResult:
        return IntegrationValidationResult(
            status="UNSUPPORTED",
            route_health="UNKNOWN",
            provider_version="unverified",
            limitations=("No server-owned provider adapter is configured.",),
        )

    def verify_identity(self, *, tenant_id: str, provider: str, product: str, subject_ref: str, email: str | None) -> IdentityVerificationResult:
        return IdentityVerificationResult()


class AccountBoundaryAdapterRegistry:
    def __init__(self, adapters: dict[str, AccountBoundaryProviderAdapter] | None = None) -> None:
        self._adapters = dict(adapters or {})
        self._unsupported = UnsupportedAccountBoundaryAdapter()

    def adapter_for(self, provider: str) -> AccountBoundaryProviderAdapter:
        return self._adapters.get(provider, self._unsupported)
