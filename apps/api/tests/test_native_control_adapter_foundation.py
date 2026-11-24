from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.services.native_control.adapter_contract import (
    AdapterContractError,
    AdapterDescriptor,
    AdapterMaturity,
    AdapterPipelineContext,
    AdapterResolutionState,
    AdapterValidationSuite,
    CapabilityManifest,
    ControlConfigFingerprint,
    DeploymentFamily,
    EvidenceQuality,
    InstallationPlan,
    NativeControlEvent,
    ProviderTransport,
    SecretReference,
    StructuredBlindSpot,
    SynchronousBlockingAdapter,
    TimeoutBudget,
)
from app.services.native_control.adapter_pipeline import NativeControlAdapterPipeline
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.control_point_factory import (
    AdapterIntegrationContext,
    ControlPointFactory,
)
from app.services.native_control.conformance import NativeControlAdapterConformanceSuite
from app.services.native_control.contracts import (
    AssuranceLevel,
    CapabilityDimension,
    ControlPointHealth,
    ControlRequirementProfile,
    DegradationMode,
    HealthState,
    SelectionContext,
)
from app.services.native_control.reference_adapters import (
    AdversarialFalseA4Adapter,
    ReferenceMiddlewareAdapter,
    ReferenceNativeBoundAdapter,
    ReferenceObserveOnlyAdapter,
    build_reference_registry,
)
from app.services.native_control.selector import TrustedControlPointSelector
from app.services.native_control.local_helper import HawkNativeControlHelper


def _healthy(latency: int = 10) -> ControlPointHealth:
    return ControlPointHealth(
        state=HealthState.HEALTHY,
        callback_authenticated=True,
        validation_current=True,
        evidence_flowing=True,
        configuration_integrity_valid=True,
        policy_fresh=True,
        observed_latency_ms=latency,
    )


def _integration(adapter_id: str) -> AdapterIntegrationContext:
    return AdapterIntegrationContext(
        control_point_id=f"point:{adapter_id}",
        integration_instance_id=f"integration:{adapter_id}",
        tenant_id="tenant-1",
        provider_version="1.0.0",
        policy_version="policy-1",
        policy_binding_mode="pinned_snapshot",
        tenant_binding_valid=True,
        current_degradation_mode=DegradationMode.FAIL_CLOSED,
    )


def _selection_context() -> SelectionContext:
    return SelectionContext(
        tenant_id="tenant-1",
        action_id="action-1",
        policy_version="policy-1",
        matrix_version="reference-matrix/1",
        provider="hawk_reference",
        product="synthetic_control",
        provider_version="1.0.0",
        adapter_version="1.0.0",
        route_binding_source="authenticated_reference_test",
        allowed_control_methods=("native_hook", "sdk_middleware", "observe_only"),
        required_lifecycle_event="before_tool",
        current_bypass_state="none_detected",
        policy_fresh=True,
    )


def _bound_requirement() -> ControlRequirementProfile:
    return ControlRequirementProfile(
        action_class="persistent_side_effect",
        requires_pre_execution=True,
        pre_execution_capability=CapabilityDimension.TOOL_CONTROL,
        requires_identity=True,
        requires_parameter_binding=True,
        requires_target_binding=True,
        requires_destination_binding=False,
        requires_post_execution=True,
        requires_persistence_detection=False,
        minimum_assurance=AssuranceLevel.A5_VERIFIED,
        maximum_latency_ms=100,
        acceptable_degradation_modes=(DegradationMode.FAIL_CLOSED,),
    )


def test_reference_adapters_expose_only_genuine_composable_capabilities() -> None:
    native = ReferenceNativeBoundAdapter()
    middleware = ReferenceMiddlewareAdapter()
    observe = ReferenceObserveOnlyAdapter()

    assert isinstance(native, SynchronousBlockingAdapter)
    assert isinstance(middleware, SynchronousBlockingAdapter)
    assert native.timeout_budget().remaining_network_budget_ms >= 0
    assert middleware.timeout_budget().response_deadline_ms == middleware.decision_deadline_ms()
    assert not isinstance(observe, SynchronousBlockingAdapter)
    assert not hasattr(observe, "install")
    assert not hasattr(middleware, "capture_execution_result")


def test_manifest_conformance_rejects_false_a4_claim() -> None:
    registry = NativeControlAdapterRegistry(environment="test")

    with pytest.raises(AdapterContractError, match="parameter_binding"):
        registry.register(AdversarialFalseA4Adapter())


def test_registry_enforces_identity_resolution_and_production_reference_boundary() -> None:
    registry = build_reference_registry(environment="test")
    resolution = registry.resolve(
        provider="hawk_reference",
        product="synthetic_control",
        provider_version="1.0.0",
    )

    assert resolution.state is AdapterResolutionState.AMBIGUOUS
    assert len(resolution.adapter_ids) == 3
    assert len(registry.eligible_adapters(include_experimental=False)) == 3
    assert build_reference_registry(environment="production").eligible_adapters() == ()
    assert registry.resolve(
        provider="anthropic_like",
        product="synthetic_control",
        provider_version="1.0.0",
    ).state is AdapterResolutionState.UNKNOWN


def test_registry_rejects_duplicate_descriptor_identity() -> None:
    registry = NativeControlAdapterRegistry(environment="test")
    registry.register(ReferenceNativeBoundAdapter())

    with pytest.raises(AdapterContractError, match="duplicate_adapter_id"):
        registry.register(ReferenceNativeBoundAdapter())


def test_factory_creates_candidates_but_selector_remains_authoritative() -> None:
    adapters = (
        ReferenceNativeBoundAdapter(),
        ReferenceMiddlewareAdapter(),
        ReferenceObserveOnlyAdapter(),
    )
    factory = ControlPointFactory()
    candidates = [
        factory.create(adapter, integration=_integration(adapter.descriptor.adapter_id), health=_healthy())
        for adapter in adapters
    ]

    assert all(candidate.control_point_id.startswith("point:") for candidate in candidates)
    assert not any(hasattr(adapter, "select_control_point") for adapter in adapters)

    selected = TrustedControlPointSelector().select(
        _selection_context(),
        _bound_requirement(),
        candidates,
    )
    assert selected.primary_control_point == "point:reference.native-bound"
    assert selected.assurance_level is AssuranceLevel.A5_VERIFIED


def test_selector_refuses_weak_failover_when_native_bound_is_unhealthy() -> None:
    factory = ControlPointFactory()
    native = ReferenceNativeBoundAdapter()
    middleware = ReferenceMiddlewareAdapter()
    observe = ReferenceObserveOnlyAdapter()
    candidates = [
        factory.create(
            native,
            integration=_integration(native.descriptor.adapter_id),
            health=replace(_healthy(), state=HealthState.UNHEALTHY),
        ),
        factory.create(middleware, integration=_integration(middleware.descriptor.adapter_id), health=_healthy()),
        factory.create(observe, integration=_integration(observe.descriptor.adapter_id), health=_healthy()),
    ]

    result = TrustedControlPointSelector().select(
        _selection_context(),
        _bound_requirement(),
        candidates,
    )

    assert result.primary_control_point is None
    assert result.selection_reason == "CONTROL_REQUIREMENT_UNSATISFIED"


def test_observe_only_requirement_chooses_lowest_friction_verified_point() -> None:
    adapters = (
        ReferenceNativeBoundAdapter(),
        ReferenceMiddlewareAdapter(),
        ReferenceObserveOnlyAdapter(),
    )
    factory = ControlPointFactory()
    candidates = [
        factory.create(adapter, integration=_integration(adapter.descriptor.adapter_id), health=_healthy())
        for adapter in adapters
    ]
    requirement = ControlRequirementProfile(
        action_class="tool_observation",
        requires_pre_execution=False,
        pre_execution_capability=CapabilityDimension.TOOL_CONTROL,
        requires_identity=False,
        requires_parameter_binding=False,
        requires_target_binding=False,
        requires_destination_binding=False,
        requires_post_execution=False,
        requires_persistence_detection=False,
        minimum_assurance=AssuranceLevel.A2_OBSERVED,
        maximum_latency_ms=100,
        acceptable_degradation_modes=(DegradationMode.FAIL_CLOSED,),
    )

    result = TrustedControlPointSelector().select(
        replace(_selection_context(), required_lifecycle_event=None),
        requirement,
        candidates,
    )

    assert result.primary_control_point == "point:reference.observe-only"


def test_common_pipeline_owns_tenant_replay_policy_evidence_and_deduplication() -> None:
    adapter = ReferenceNativeBoundAdapter()
    evidence: list[dict[str, object]] = []
    pipeline = NativeControlAdapterPipeline(evidence_sink=evidence.append)
    context = AdapterPipelineContext.reference(
        tenant_id="tenant-trusted",
        integration_instance_id="integration-1",
        provider_event_id="event-1",
        policy_profile={"base_decision": "block", "dependencies_healthy": True},
    )
    payload = {
        "tenant_id": "attacker-tenant",
        "event_type": "tool_call",
        "tool_name": "github.create_pull_request",
        "parameters": {"title": "blocked"},
        "target": "github/repository",
    }

    first = pipeline.process(adapter=adapter, context=context, raw_payload=payload)
    second = pipeline.process(adapter=adapter, context=context, raw_payload=payload)

    assert first.authorization_request.tenant_id == "tenant-trusted"
    assert first.authorization_response.decision == "block"
    assert first.provider_response["continue"] is False
    assert second.duplicate is True
    assert second.action_id == first.action_id
    assert len(evidence) == 1
    assert not hasattr(first, "raw_payload")


def test_installation_preserves_customer_config_and_uninstall_removes_only_hawk_fragment() -> None:
    adapter = ReferenceNativeBoundAdapter()
    existing = {"customer_hook": {"command": "customer-helper"}, "settings": {"theme": "dark"}}
    plan = adapter.install_plan(existing)

    installed = adapter.install(plan, existing)
    uninstalled = adapter.uninstall(installed.configuration)

    assert isinstance(plan, InstallationPlan)
    assert installed.configuration["customer_hook"] == existing["customer_hook"]
    assert installed.configuration["hawk_native_control"]["adapter_id"] == adapter.descriptor.adapter_id
    assert isinstance(installed.fingerprint, ControlConfigFingerprint)
    assert uninstalled == existing


def test_validation_requires_real_blocking_checks_for_healthy_enforcement() -> None:
    adapter = ReferenceNativeBoundAdapter()
    report = AdapterValidationSuite().run(adapter, provider_version="1.0.0")

    assert report.passed is True
    assert set(report.verified_capabilities) >= {
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
    }
    assert report.assurance_achieved is AssuranceLevel.A5_VERIFIED
    assert report.resulting_health.state is HealthState.HEALTHY
    assert {row.name for row in report.tests if row.passed} >= {"safe_allow", "safe_deny", "replay_defense"}


def test_contract_models_reject_malformed_blind_spots_and_unsafe_transport() -> None:
    with pytest.raises(ValueError, match="blind_spot"):
        StructuredBlindSpot(
            id="",
            control_dimension=CapabilityDimension.TOOL_CONTROL,
            scope="all",
            condition="unknown",
            impact="unknown",
            detection_method="none",
            mitigation="none",
            evidence=(),
        )

    assert ProviderTransport("http_callback") is ProviderTransport.HTTP_CALLBACK
    with pytest.raises(ValueError):
        ProviderTransport("arbitrary_listener")


def test_reference_descriptor_is_static_and_never_claims_a_real_provider() -> None:
    descriptor = ReferenceNativeBoundAdapter().descriptor

    assert isinstance(descriptor, AdapterDescriptor)
    assert descriptor.maturity is AdapterMaturity.REFERENCE
    assert descriptor.provider_family == "hawk_reference"
    assert descriptor.deployment_families_supported == (DeploymentFamily.RUNTIME,)
    assert isinstance(ReferenceNativeBoundAdapter().manifest, CapabilityManifest)
    assert ReferenceNativeBoundAdapter().manifest.execution_evidence_quality is EvidenceQuality.HAWK_EXTERNALLY_VERIFIED


def test_normalized_event_retains_provider_correlation_without_trusting_provider_tenant() -> None:
    adapter = ReferenceObserveOnlyAdapter()
    context = AdapterPipelineContext.reference(
        tenant_id="tenant-trusted",
        integration_instance_id="integration-1",
        provider_event_id="event-42",
    )

    event = adapter.normalize_event(
        {"tenant_id": "tenant-hostile", "event_type": "tool_call", "tool_name": "gmail.read"},
        context,
    )

    assert isinstance(event, NativeControlEvent)
    assert event.tenant_id == "tenant-trusted"
    assert event.raw_provider_event_type == "tool_call"
    assert event.provider_event_id == "event-42"
    assert event.adapter_version == "1.0.0"


def test_conformance_suite_passes_reference_adapters_and_rejects_adversarial_fixture() -> None:
    suite = NativeControlAdapterConformanceSuite()

    for adapter in (
        ReferenceNativeBoundAdapter(),
        ReferenceMiddlewareAdapter(),
        ReferenceObserveOnlyAdapter(),
    ):
        result = suite.run(adapter)
        assert result.passed is True, result.failures
        assert result.exemptions == ()

    broken = suite.run(AdversarialFalseA4Adapter())
    assert broken.passed is False
    assert any("parameter_binding" in failure for failure in broken.failures)


def test_helper_surface_is_declarative_and_has_no_execution_channel() -> None:
    messages: list[dict[str, object]] = []
    helper = HawkNativeControlHelper(messages.append)

    helper.emit_event(event_hash="a" * 64, event_type="before_tool")
    helper.receive_decision(action_hash="b" * 64, decision="block", expires_at="2030-01-01T00:00:00Z")
    helper.report_health(state="healthy", observed_at="2026-08-11T00:00:00Z")
    helper.report_integrity(config_hash="c" * 64, observed_at="2026-08-11T00:00:00Z")

    assert [row["operation"] for row in messages] == [
        "event.emit",
        "decision.receive",
        "health.report",
        "integrity.report",
    ]
    assert not hasattr(helper, "execute_command")
    assert not hasattr(helper, "remote_shell")


def test_timeout_and_secret_contracts_are_bounded_and_opaque() -> None:
    budget = TimeoutBudget(provider_timeout_ms=80, hawk_processing_budget_ms=15, response_deadline_ms=100)
    assert budget.remaining_network_budget_ms == 5

    with pytest.raises(ValueError, match="timeout_budget"):
        TimeoutBudget(provider_timeout_ms=90, hawk_processing_budget_ms=20, response_deadline_ms=100)
    assert SecretReference("hsm://bank-hsm/hawk-adapter-signing").scheme == "hsm"
    with pytest.raises(ValueError, match="secret_reference"):
        SecretReference("raw-secret-value")


def test_provider_native_enforcement_accepts_only_real_binary_verified_version(monkeypatch) -> None:
    from app.api.routers.native_controls import _adapter_enforcement_eligible
    from app.core.config import settings

    monkeypatch.setitem(settings.__dict__, "native_control_adapter_framework", True)
    monkeypatch.setitem(settings.__dict__, "native_control_adapter_enforcement", True)
    integration = SimpleNamespace(
        integration_method="native_hook",
        provider="anthropic",
        product="claude_code",
        provider_version="2.1.183",
        adapter_version="1.2.0",
    )

    assert _adapter_enforcement_eligible(integration) is True
    integration.provider_version = "2.1.184"
    assert _adapter_enforcement_eligible(integration) is False
    integration.provider_version = "future"
    assert _adapter_enforcement_eligible(integration) is False
