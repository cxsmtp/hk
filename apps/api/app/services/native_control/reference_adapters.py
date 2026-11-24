from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Mapping

from app.core.control_engine.authorization import AuthorizationResponse
from app.services.native_control.adapter_contract import (
    AdapterDescriptor,
    AdapterError,
    AdapterErrorCode,
    AdapterMaturity,
    AdapterPipelineContext,
    CapabilityManifest,
    ControlConfigFingerprint,
    DeploymentFamily,
    EventSemantics,
    EvidenceQuality,
    InstallationPlan,
    InstallationResult,
    NativeControlEvent,
    SelectionCharacteristics,
    StructuredBlindSpot,
    TimeoutBudget,
    stable_hash,
)
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ControlPointHealth,
    DegradationMode,
    HealthState,
    SecurityProperties,
    VerificationStatus,
)


_REFERENCE_PROVIDER = "hawk_reference"
_REFERENCE_PRODUCT = "synthetic_control"
_REFERENCE_VERSION = "1.0.0"


def _claim(level: CapabilityLevel) -> CapabilityClaim:
    return CapabilityClaim(
        level=level,
        verification_status=VerificationStatus.VERIFIED,
        evidence_refs=("repo:apps/api/tests/test_native_control_adapter_foundation.py",),
    )


def _blind_spot(adapter_id: str, impact: str) -> StructuredBlindSpot:
    return StructuredBlindSpot(
        id=f"{adapter_id}.reference-only",
        control_dimension=CapabilityDimension.BYPASS_DETECTION,
        scope="synthetic test environment",
        condition="reference adapter used outside conformance tests",
        impact=impact,
        detection_method="descriptor maturity is REFERENCE",
        mitigation="production registry excludes REFERENCE maturity",
        evidence=("repo:apps/api/tests/test_native_control_adapter_foundation.py",),
    )


def _security(
    *,
    pre: bool,
    post: bool,
    blocking: int,
    parameter: int,
    target: int,
    result: int,
    latency: int,
    privacy: str,
) -> SecurityProperties:
    return SecurityProperties(
        pre_execution_capable=pre,
        post_execution_capable=post,
        blocking_strength=blocking,
        action_fidelity=max(parameter, target, 40),
        identity_quality=80,
        parameter_fidelity=parameter,
        target_fidelity=target,
        destination_fidelity=40,
        result_fidelity=result,
        bypass_resistance=70,
        tamper_resistance=85,
        expected_latency_ms=latency,
        availability_profile="reference_only",
        required_permissions=("reference.invoke",),
        privacy_impact=privacy,
    )


class _ReferenceBase:
    descriptor: AdapterDescriptor
    manifest: CapabilityManifest

    def limitations(self) -> tuple[StructuredBlindSpot, ...]:
        return self.manifest.known_blind_spots

    def health(self) -> ControlPointHealth:
        return ControlPointHealth(
            state=HealthState.HEALTHY,
            callback_authenticated=True,
            validation_current=True,
            evidence_flowing=True,
            configuration_integrity_valid=True,
            policy_fresh=True,
            observed_latency_ms=self.manifest.security_properties.expected_latency_ms,
        )

    def supported_versions(self) -> tuple[str, str]:
        return self.manifest.provider_version_min, self.manifest.provider_version_max

    def normalize_event(
        self,
        raw_payload: Mapping[str, Any],
        context: AdapterPipelineContext,
    ) -> NativeControlEvent:
        if not isinstance(raw_payload, Mapping):
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        event_type = str(raw_payload.get("event_type") or "").strip()
        tool_name = str(raw_payload.get("tool_name") or "").strip()
        if not event_type or not tool_name:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        parameters = raw_payload.get("parameters")
        canonical_parameters = dict(parameters) if isinstance(parameters, Mapping) else {}
        target = str(raw_payload.get("target") or "unknown")
        lifecycle = "before_tool" if self.manifest.event_semantics.pre_execution_events else "after_tool"
        return NativeControlEvent(
            tenant_id=context.tenant_id,
            integration_instance_id=context.integration_instance_id,
            provider=self.descriptor.provider_family,
            product=self.descriptor.product_family,
            raw_provider_event_type=event_type,
            provider_event_id=context.provider_event_id,
            provider_version=context.provider_version,
            adapter_version=self.descriptor.adapter_version,
            lifecycle_stage=lifecycle,
            actor=dict(context.resolved_actor),
            session={"session_id": context.session_id},
            runtime={
                "environment": context.environment,
                "credential_id": context.credential_id,
                "correlation_id": context.correlation_id,
            },
            tool={"name": tool_name, "version": "reference", "fingerprint_id": stable_hash(tool_name)},
            model={},
            mcp={},
            action={
                "action_type": "tool_execution",
                "canonical_parameters": canonical_parameters,
                "parameter_hash": stable_hash(canonical_parameters),
            },
            target={
                "resource": target,
                "canonical_target": target,
                "resource_hash": stable_hash(target),
            },
            destination={},
            side_effect_class="persistent_external_write" if "write" in tool_name or "create" in tool_name else "read",
            persistence={"persistent_side_effect": "write" in tool_name or "create" in tool_name},
            provider_correlation={"chain_id": context.chain_id, "correlation_id": context.correlation_id},
            timing={"received_at": context.received_at, "pre_execution": lifecycle.startswith("before_")},
            integrity={"transport": context.transport.value, "signature_valid": context.signature_valid},
            policy_snapshot_id=context.policy_snapshot_id,
            policy_profile=dict(context.policy_profile),
        )

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision == "block":
            return {"decision": "block", "continue": False, "reason": response.reason}
        if response.decision in {"review", "require_approval", "require_second_approval"}:
            return {"decision": response.decision, "continue": False, "paused": True}
        return {"decision": response.decision, "continue": True}

    def validation_probe(self) -> dict[str, bool]:
        return {
            "environment": True,
            "installation": True,
            "authentication": True,
            "replay_defense": True,
            "event_delivery": True,
            "normalization": True,
            "safe_allow": True,
            "safe_deny": True,
            "policy_callback": True,
            "configuration_integrity": True,
            "privacy": True,
        }


class ReferenceNativeBoundAdapter(_ReferenceBase):
    descriptor = AdapterDescriptor(
        adapter_id="reference.native-bound",
        provider_family=_REFERENCE_PROVIDER,
        product_family=_REFERENCE_PRODUCT,
        adapter_version=_REFERENCE_VERSION,
        deployment_families_supported=(DeploymentFamily.RUNTIME,),
        enforcement_methods_supported=(ControlMethod.NATIVE_HOOK,),
        event_schema_version="native-control-event/1.0",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.REFERENCE,
        description="Synthetic A5 native-bound adapter for Hawk conformance tests only.",
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider=_REFERENCE_PROVIDER,
        product=_REFERENCE_PRODUCT,
        provider_version_min="1.0.0",
        provider_version_max="1.9.9",
        exact_verified_versions=("1.0.0",),
        adapter_version=_REFERENCE_VERSION,
        verification_status=VerificationStatus.VERIFIED,
        verified_at="2026-08-11T00:00:00+00:00",
        source_reference="repo:apps/api/tests/test_native_control_adapter_foundation.py",
        capabilities={
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.INLINE),
            CapabilityDimension.PARAMETER_BINDING: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.TARGET_BINDING: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.POST_EXECUTION_VERIFICATION: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.CONFIG_INTEGRITY: _claim(CapabilityLevel.INLINE_BOUND),
        },
        security_properties=_security(
            pre=True, post=True, blocking=95, parameter=95, target=95, result=95,
            latency=25, privacy="normalized_reference_metadata",
        ),
        required_permissions=("reference.invoke",),
        event_semantics=EventSemantics(
            pre_execution_events=("before_tool",),
            post_execution_events=("after_tool",),
            normalized_fields=(
                "identity", "canonical_parameters", "parameter_hash", "canonical_target",
                "target_hash", "action_correlation", "execution_result",
            ),
            synchronous_decision_mechanism="reference_callback",
            ordering_guaranteed=True,
            runs_before_untrusted_mutators=True,
        ),
        known_blind_spots=(_blind_spot(descriptor.adapter_id, "No real provider coverage."),),
        failure_modes=("synthetic probe failure",),
        supported_installation_modes=("reference_in_memory",),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED,),
        execution_evidence_quality=EvidenceQuality.HAWK_EXTERNALLY_VERIFIED,
        selection_characteristics=SelectionCharacteristics(25, 80, 80, 50, 90),
    )

    def decision_deadline_ms(self) -> int:
        return 100

    def timeout_budget(self) -> TimeoutBudget:
        return TimeoutBudget(provider_timeout_ms=70, hawk_processing_budget_ms=20, response_deadline_ms=100)

    def capture_execution_result(self, provider_result: Mapping[str, Any]) -> dict[str, Any]:
        return {"quality": EvidenceQuality.HAWK_EXTERNALLY_VERIFIED.value, "result_hash": stable_hash(provider_result)}

    def supported_tool_events(self) -> tuple[str, ...]:
        return ("before_tool", "after_tool")

    def install_plan(self, existing_configuration: Mapping[str, Any]) -> InstallationPlan:
        return InstallationPlan(
            adapter_id=self.descriptor.adapter_id,
            files_or_settings_affected=("reference://configuration",),
            permissions_required=("reference.configure",),
            existing_configuration_detected=bool(existing_configuration),
            hawk_owned_fragment_key="hawk_native_control",
            rollback_strategy="remove Hawk-owned fragment only",
            restart_required=False,
            estimated_coverage_effect=("synthetic tool control",),
            known_risks=("reference adapter must never run in production",),
        )

    def install(
        self,
        plan: InstallationPlan,
        existing_configuration: Mapping[str, Any],
    ) -> InstallationResult:
        if plan.adapter_id != self.descriptor.adapter_id or plan.hawk_owned_fragment_key != "hawk_native_control":
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        configuration = deepcopy(dict(existing_configuration))
        before = deepcopy(configuration)
        fragment = {
            "adapter_id": self.descriptor.adapter_id,
            "adapter_version": self.descriptor.adapter_version,
            "events": ["before_tool", "after_tool"],
            "blocking": True,
        }
        configuration[plan.hawk_owned_fragment_key] = fragment
        fingerprint = ControlConfigFingerprint(
            integration_instance_id="reference-integration",
            provider=self.descriptor.provider_family,
            config_location="reference://configuration",
            hawk_owned_content_hash=stable_hash(fragment),
            surrounding_context_hash=stable_hash(before),
            ordering="before_untrusted_mutators",
            callback_identity="reference-callback",
            helper_identity="none",
            event_subscriptions=("before_tool", "after_tool"),
            blocking_semantics="synchronous_block",
            version=self.descriptor.adapter_version,
            last_verified=datetime.now(timezone.utc).isoformat(),
        )
        if not self.validate_installation(configuration):
            raise AdapterError(AdapterErrorCode.INSTALLATION_CONFLICT)
        return InstallationResult(configuration=configuration, fingerprint=fingerprint)

    def validate_installation(self, configuration: Mapping[str, Any]) -> bool:
        fragment = configuration.get("hawk_native_control")
        return isinstance(fragment, Mapping) and fragment.get("adapter_id") == self.descriptor.adapter_id

    def configure(self, configuration: Mapping[str, Any]) -> InstallationResult:
        return self.install(self.install_plan(configuration), configuration)

    def verify_integrity(self, configuration: Mapping[str, Any]) -> bool:
        return self.validate_installation(configuration)

    def detect_drift(self, configuration: Mapping[str, Any]) -> tuple[str, ...]:
        return () if self.verify_integrity(configuration) else ("hawk_owned_fragment_missing_or_changed",)

    def uninstall(self, configuration: Mapping[str, Any]) -> dict[str, Any]:
        result = deepcopy(dict(configuration))
        fragment = result.get("hawk_native_control")
        if isinstance(fragment, Mapping) and fragment.get("adapter_id") == self.descriptor.adapter_id:
            result.pop("hawk_native_control", None)
        return result


class ReferenceMiddlewareAdapter(_ReferenceBase):
    descriptor = AdapterDescriptor(
        adapter_id="reference.middleware",
        provider_family=_REFERENCE_PROVIDER,
        product_family=_REFERENCE_PRODUCT,
        adapter_version=_REFERENCE_VERSION,
        deployment_families_supported=(DeploymentFamily.RUNTIME,),
        enforcement_methods_supported=(ControlMethod.SDK_MIDDLEWARE,),
        event_schema_version="native-control-event/1.0",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.REFERENCE,
        description="Synthetic A3 middleware adapter for Hawk conformance tests only.",
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider=_REFERENCE_PROVIDER,
        product=_REFERENCE_PRODUCT,
        provider_version_min="1.0.0",
        provider_version_max="1.9.9",
        exact_verified_versions=("1.0.0",),
        adapter_version=_REFERENCE_VERSION,
        verification_status=VerificationStatus.VERIFIED,
        verified_at="2026-08-11T00:00:00+00:00",
        source_reference="repo:apps/api/tests/test_native_control_adapter_foundation.py",
        capabilities={
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.INLINE),
            CapabilityDimension.PARAMETER_BINDING: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.TARGET_BINDING: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
        },
        security_properties=_security(
            pre=True, post=False, blocking=75, parameter=45, target=45, result=20,
            latency=15, privacy="normalized_reference_metadata",
        ),
        required_permissions=("reference.invoke",),
        event_semantics=EventSemantics(
            pre_execution_events=("before_tool",),
            normalized_fields=("identity", "action_correlation"),
            synchronous_decision_mechanism="reference_middleware",
            ordering_guaranteed=False,
        ),
        known_blind_spots=(_blind_spot(descriptor.adapter_id, "No independent execution verification."),),
        failure_modes=("middleware bypass",),
        supported_installation_modes=("reference_in_process",),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED,),
        execution_evidence_quality=EvidenceQuality.NONE,
        selection_characteristics=SelectionCharacteristics(15, 40, 35, 35, 45),
    )

    def decision_deadline_ms(self) -> int:
        return 100

    def timeout_budget(self) -> TimeoutBudget:
        return TimeoutBudget(provider_timeout_ms=75, hawk_processing_budget_ms=20, response_deadline_ms=100)


class ReferenceObserveOnlyAdapter(_ReferenceBase):
    descriptor = AdapterDescriptor(
        adapter_id="reference.observe-only",
        provider_family=_REFERENCE_PROVIDER,
        product_family=_REFERENCE_PRODUCT,
        adapter_version=_REFERENCE_VERSION,
        deployment_families_supported=(DeploymentFamily.RUNTIME,),
        enforcement_methods_supported=(ControlMethod.OBSERVE_ONLY,),
        event_schema_version="native-control-event/1.0",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.REFERENCE,
        description="Synthetic A2 observation adapter for Hawk conformance tests only.",
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider=_REFERENCE_PROVIDER,
        product=_REFERENCE_PRODUCT,
        provider_version_min="1.0.0",
        provider_version_max="1.9.9",
        exact_verified_versions=("1.0.0",),
        adapter_version=_REFERENCE_VERSION,
        verification_status=VerificationStatus.VERIFIED,
        verified_at="2026-08-11T00:00:00+00:00",
        source_reference="repo:apps/api/tests/test_native_control_adapter_foundation.py",
        capabilities={
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
        },
        security_properties=_security(
            pre=False, post=True, blocking=0, parameter=20, target=20, result=30,
            latency=5, privacy="minimal_reference_metadata",
        ),
        required_permissions=("reference.observe",),
        event_semantics=EventSemantics(
            post_execution_events=("after_tool",),
            normalized_fields=("identity", "action_correlation"),
        ),
        known_blind_spots=(_blind_spot(descriptor.adapter_id, "Cannot block actions."),),
        failure_modes=("event source unavailable",),
        supported_installation_modes=("reference_observer",),
        supported_degradation_modes=(DegradationMode.MONITOR_ONLY, DegradationMode.FAIL_CLOSED),
        execution_evidence_quality=EvidenceQuality.HAWK_OBSERVED,
        selection_characteristics=SelectionCharacteristics(5, 5, 5, 5, 5),
    )

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision in {"block", "review", "require_approval", "require_second_approval"}:
            raise AdapterError(AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE)
        return {"decision": response.decision, "continue": True, "observed_only": True}


class AdversarialFalseA4Adapter(ReferenceObserveOnlyAdapter):
    descriptor = AdapterDescriptor(
        adapter_id="reference.adversarial-false-a4",
        provider_family=_REFERENCE_PROVIDER,
        product_family=_REFERENCE_PRODUCT,
        adapter_version=_REFERENCE_VERSION,
        deployment_families_supported=(DeploymentFamily.RUNTIME,),
        enforcement_methods_supported=(ControlMethod.NATIVE_HOOK,),
        event_schema_version="native-control-event/1.0",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.REFERENCE,
        description="Malicious fixture that claims bound parameters without normalized proof.",
    )
    manifest = replace(
        ReferenceObserveOnlyAdapter.manifest,
        descriptor_id=descriptor.adapter_id,
        capabilities={
            **ReferenceObserveOnlyAdapter.manifest.capabilities,
            CapabilityDimension.PARAMETER_BINDING: _claim(CapabilityLevel.INLINE_BOUND),
        },
    )


def build_reference_registry(*, environment: str) -> NativeControlAdapterRegistry:
    registry = NativeControlAdapterRegistry(environment=environment)
    for adapter in (
        ReferenceNativeBoundAdapter(),
        ReferenceMiddlewareAdapter(),
        ReferenceObserveOnlyAdapter(),
    ):
        registry.register(adapter)
    return registry
