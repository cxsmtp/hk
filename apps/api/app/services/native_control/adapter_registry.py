from __future__ import annotations

from dataclasses import dataclass

from app.services.native_control.adapter_contract import (
    AdapterContractError,
    AdapterMaturity,
    AdapterResolutionState,
    NativeControlAdapter,
    validate_adapter_contract,
)
from app.services.native_control.contracts import (
    ProviderRuntimeContext,
    ProviderVersionState,
    VerificationStatus,
)


@dataclass(frozen=True, slots=True)
class AdapterResolution:
    state: AdapterResolutionState
    adapter_ids: tuple[str, ...]
    reason: str
    version_state: ProviderVersionState = ProviderVersionState.UNKNOWN
    enforcement_eligible: bool = False
    ineligibility_reasons: tuple[str, ...] = ()


class NativeControlAdapterRegistry:
    """Validated adapter inventory. It never evaluates policy or selects control points."""

    def __init__(self, *, environment: str) -> None:
        self.environment = str(environment or "").strip().lower() or "unknown"
        self._adapters: dict[str, NativeControlAdapter] = {}

    def register(self, adapter: NativeControlAdapter) -> None:
        validate_adapter_contract(adapter)
        adapter_id = adapter.descriptor.adapter_id
        if adapter_id in self._adapters:
            raise AdapterContractError("duplicate_adapter_id")
        self._adapters[adapter_id] = adapter

    def get(self, adapter_id: str) -> NativeControlAdapter:
        try:
            return self._adapters[str(adapter_id or "").strip()]
        except KeyError as exc:
            raise KeyError("adapter_not_registered") from exc

    def adapters(self) -> tuple[NativeControlAdapter, ...]:
        return tuple(self._adapters[key] for key in sorted(self._adapters))

    def eligible_adapters(
        self,
        *,
        include_experimental: bool = False,
    ) -> tuple[NativeControlAdapter, ...]:
        result: list[NativeControlAdapter] = []
        for adapter in self.adapters():
            if adapter.descriptor.maturity is AdapterMaturity.REFERENCE and self.environment in {
                "prod",
                "production",
            }:
                continue
            status = adapter.manifest.verification_status
            if status is VerificationStatus.VERIFIED:
                result.append(adapter)
            elif include_experimental and status is VerificationStatus.EXPERIMENTAL:
                result.append(adapter)
        return tuple(result)

    def resolve(
        self,
        *,
        provider: str,
        product: str,
        provider_version: str,
        runtime_context: ProviderRuntimeContext | None = None,
        require_deployment_acceptance: bool = True,
    ) -> AdapterResolution:
        provider_value = str(provider or "").strip().lower()
        product_value = str(product or "").strip().lower()
        version_value = str(provider_version or "").strip()
        provider_matches = [
            adapter
            for adapter in self.adapters()
            if adapter.descriptor.provider_family == provider_value
        ]
        if not provider_matches:
            return AdapterResolution(
                AdapterResolutionState.UNKNOWN,
                (),
                "provider_unknown",
                ProviderVersionState.UNKNOWN,
                False,
                ("provider_unknown",),
            )
        product_matches = [
            adapter
            for adapter in provider_matches
            if adapter.descriptor.product_family == product_value
        ]
        if not product_matches:
            return AdapterResolution(
                AdapterResolutionState.UNSUPPORTED,
                (),
                "product_unsupported",
                ProviderVersionState.UNSUPPORTED,
                False,
                ("product_unsupported",),
            )
        version_states = {
            adapter.descriptor.adapter_id: adapter.manifest.provider_version_state(version_value)
            for adapter in product_matches
        }
        compatible = [
            adapter
            for adapter in product_matches
            if version_states[adapter.descriptor.adapter_id]
            in {
                ProviderVersionState.EXACT_TESTED,
                ProviderVersionState.VERIFIED_COMPATIBLE_RANGE,
            }
        ]
        if not compatible:
            states = set(version_states.values())
            version_state = states.pop() if len(states) == 1 else ProviderVersionState.UNSUPPORTED
            resolution_state = {
                ProviderVersionState.UNVERIFIED_NEWER: AdapterResolutionState.UNVERIFIED_NEWER,
                ProviderVersionState.UNSUPPORTED_OLDER: AdapterResolutionState.UNSUPPORTED_OLDER,
                ProviderVersionState.BROKEN: AdapterResolutionState.BROKEN,
            }.get(version_state, AdapterResolutionState.UNSUPPORTED)
            return AdapterResolution(
                resolution_state,
                (),
                "provider_version_unsupported",
                version_state,
                False,
                (f"provider_version_{version_state.value}",),
            )
        ids = tuple(sorted(adapter.descriptor.adapter_id for adapter in compatible))
        if len(compatible) > 1:
            version_state = (
                ProviderVersionState.EXACT_TESTED
                if all(
                    version_states[adapter.descriptor.adapter_id]
                    is ProviderVersionState.EXACT_TESTED
                    for adapter in compatible
                )
                else ProviderVersionState.VERIFIED_COMPATIBLE_RANGE
            )
            return AdapterResolution(
                AdapterResolutionState.AMBIGUOUS,
                ids,
                "multiple_compatible_adapters",
                version_state,
                False,
                ("adapter_ambiguous",),
            )
        adapter = compatible[0]
        version_state = version_states[adapter.descriptor.adapter_id]
        reasons = adapter.manifest.enforcement_ineligibility_reasons(
            runtime_context,
            version_state,
            require_deployment_acceptance=require_deployment_acceptance,
        )
        if (
            runtime_context is not None
            and runtime_context.environment != self.environment
        ):
            reasons = tuple(dict.fromkeys((*reasons, "registry_environment_mismatch")))
        state = (
            AdapterResolutionState.EXACT_MATCH
            if version_state is ProviderVersionState.EXACT_TESTED
            else AdapterResolutionState.SUPPORTED_COMPATIBLE
        )
        return AdapterResolution(
            state,
            ids,
            "authoritative_provider_product_version_match",
            version_state,
            not reasons,
            reasons,
        )

    def health(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for adapter in self.adapters():
            health_fn = getattr(adapter, "health", None)
            if callable(health_fn):
                result[adapter.descriptor.adapter_id] = health_fn().state.value
            else:
                result[adapter.descriptor.adapter_id] = "unverified"
        return result
