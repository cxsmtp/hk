from __future__ import annotations

from dataclasses import replace
import json

import pytest

from app.services.native_control.adapter_contract import (
    DeploymentAcceptanceResult,
    DeploymentFamily,
)
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityDimension,
    ControlMethod,
    DeploymentAcceptanceState,
    ProviderVersionState,
    ProviderRuntimeContext,
    RuntimeLocation,
    VerificationStatus,
)
from app.services.native_control.reference_adapters import ReferenceNativeBoundAdapter


def _assert_json_native(value: object) -> None:
    if value is None or type(value) in {str, bool, int, float}:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            assert type(key) is str
            _assert_json_native(item)
        return
    if isinstance(value, list):
        for item in value:
            _assert_json_native(item)
        return
    pytest.fail(f"not JSON-native: {type(value).__name__}")


def test_provider_runtime_context_is_bounded_and_deterministic() -> None:
    context = ProviderRuntimeContext(
        provider="openai",
        product="agents_sdk",
        runtime="customer-agent-runtime",
        action_class=ActionClass.FUNCTION_TOOL,
        runtime_location=RuntimeLocation.CUSTOMER_RUNTIME,
        provider_version="1.2.3",
        adapter_version="1.0.0",
        control_method=ControlMethod.SDK_MIDDLEWARE,
        environment="test",
        lifecycle_stage="before_tool",
        model_provider="openai",
        model="gpt-5",
        route_identity="route:primary",
        deployment_identity="deployment:customer-agent-a",
        deployment_reference="deployment-ref:customer-agent-a",
        route_evidence_ref="repo:tests/provider-route.json",
        route_evidence_fresh=True,
    )

    assert context.is_resolved_for_enforcement is True
    assert context.fingerprint == context.fingerprint
    assert context.canonical_material()["action_class"] == "function_tool"


def test_provider_neutral_taxonomy_keeps_subject_authority_and_provider_controls_distinct() -> None:
    assert CapabilityDimension.SUBJECT_BINDING.value == "subject_binding"
    assert CapabilityDimension.BUSINESS_PURPOSE_BINDING.value == "business_purpose_binding"
    assert CapabilityDimension.AUTHORITY_BINDING.value == "authority_binding"
    assert CapabilityDimension.MODEL_ROUTE_BINDING.value == "model_route_binding"
    assert ControlMethod.PROVIDER_ENTERPRISE_HOOK.value == "provider_enterprise_hook"
    assert ControlMethod.PROVIDER_TENANT_RESTRICTION.value == "provider_tenant_restriction"


def _reviewed_context() -> ProviderRuntimeContext:
    return ProviderRuntimeContext(
        provider="hawk_reference",
        product="synthetic_control",
        runtime="reference-runtime",
        action_class=ActionClass.FUNCTION_TOOL,
        runtime_location=RuntimeLocation.CUSTOMER_RUNTIME,
        provider_version="1.0.0",
        adapter_version="1.0.0",
        control_method=ControlMethod.NATIVE_HOOK,
        environment="test",
        model_provider="hawk_reference",
        model="reference-model",
        lifecycle_stage="before_tool",
        route_identity="route:reference",
        deployment_identity="deployment:reference",
        deployment_reference="deployment-ref:reference-runtime",
        route_evidence_ref="repo:tests/provider-route.json",
        route_evidence_fresh=True,
    )


def _accepted_runtime_contract() -> tuple[object, ProviderRuntimeContext]:
    base = ReferenceNativeBoundAdapter().manifest
    reviewed = replace(
        base,
        supported_action_classes=(ActionClass.FUNCTION_TOOL,),
        supported_runtime_locations=(RuntimeLocation.CUSTOMER_RUNTIME,),
        supported_deployment_families=(DeploymentFamily.RUNTIME,),
        supported_runtimes=("reference-runtime",),
        supported_control_methods=(ControlMethod.NATIVE_HOOK,),
        supported_lifecycle_events=("before_tool",),
        reviewed_by="hawk-contract-review",
        reviewed_at="2026-08-20T00:00:00+00:00",
        reviewed_evidence_refs=("repo:tests/provider-contract-review.md",),
    )
    acceptance = DeploymentAcceptanceResult(
        state=DeploymentAcceptanceState.REAL_CLOUD_RUNTIME_ACCEPTED,
        environment="test",
        provider="hawk_reference",
        product="synthetic_control",
        runtime="reference-runtime",
        model_provider="hawk_reference",
        model="reference-model",
        route_identity="route:reference",
        deployment_identity="deployment:reference",
        deployment_reference="deployment-ref:reference-runtime",
        action_classes=(ActionClass.FUNCTION_TOOL,),
        control_method=ControlMethod.NATIVE_HOOK,
        provider_version="1.0.0",
        adapter_version="1.0.0",
        contract_fingerprint=reviewed.contract_fingerprint,
        acceptance_run_ref="repo:tests/provider-contract-acceptance.json",
        evidence_refs=("repo:tests/provider-contract-acceptance.json",),
        lifecycle_events=("before_tool",),
        allow_verified=True,
        block_verified=True,
        protected_callback_not_executed=True,
    )
    return replace(reviewed, deployment_acceptance=acceptance), _reviewed_context()


def test_real_acceptance_binds_a_reviewed_contract_without_changing_its_fingerprint() -> None:
    accepted, context = _accepted_runtime_contract()
    reviewed = replace(accepted, deployment_acceptance=DeploymentAcceptanceResult.not_tested())

    assert accepted.contract_fingerprint == reviewed.contract_fingerprint
    assert accepted.deployment_acceptance.is_real_acceptance is True
    assert accepted.enforcement_ineligibility_reasons(
        context, ProviderVersionState.EXACT_TESTED
    ) == ()
    adapter = ReferenceNativeBoundAdapter()
    adapter.manifest = accepted  # type: ignore[assignment]
    registry = NativeControlAdapterRegistry(environment="test")
    registry.register(adapter)
    resolution = registry.resolve(
        provider="hawk_reference",
        product="synthetic_control",
        provider_version="1.0.0",
        runtime_context=context,
    )
    assert resolution.enforcement_eligible is True


@pytest.mark.parametrize(
    ("updates", "expected_error"),
    (
        (
            {"action_classes": [ActionClass.FUNCTION_TOOL]},
            "deployment_acceptance_action_classes_invalid",
        ),
        (
            {"action_classes": (ActionClass.FUNCTION_TOOL, ActionClass.FUNCTION_TOOL)},
            "deployment_acceptance_action_classes_invalid",
        ),
        (
            {"evidence_refs": ["repo:tests/provider-contract-acceptance.json"]},
            "deployment_acceptance_evidence_invalid",
        ),
        (
            {"lifecycle_events": ["before_tool"]},
            "deployment_acceptance_lifecycle_invalid",
        ),
        (
            {
                "evidence_refs": (
                    "repo:tests/provider-contract-acceptance.json",
                    "repo:tests/provider-contract-acceptance.json",
                )
            },
            "deployment_acceptance_evidence_invalid",
        ),
        (
            {"lifecycle_events": ("before_tool", "before_tool")},
            "deployment_acceptance_lifecycle_invalid",
        ),
        (
            {"model_provider": "unknown"},
            "real_deployment_acceptance_scope_required",
        ),
        ({"model": "unknown"}, "real_deployment_acceptance_scope_required"),
        (
            {"route_identity": "unknown"},
            "real_deployment_acceptance_scope_required",
        ),
        (
            {"deployment_identity": "unknown"},
            "real_deployment_acceptance_scope_required",
        ),
    ),
)
def test_deployment_acceptance_rejects_mutable_or_repeated_collections(
    updates: dict[str, object],
    expected_error: str,
) -> None:
    accepted, _ = _accepted_runtime_contract()

    with pytest.raises(ValueError, match=expected_error):
        replace(accepted.deployment_acceptance, **updates)


def test_deployment_acceptance_uses_immutable_collection_values() -> None:
    accepted, _ = _accepted_runtime_contract()
    acceptance = accepted.deployment_acceptance

    assert all(
        isinstance(value, tuple)
        for value in (
            acceptance.action_classes,
            acceptance.evidence_refs,
            acceptance.lifecycle_events,
        )
    )
    with pytest.raises(AttributeError):
        acceptance.evidence_refs.append("repo:mutate")  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("updates", "expected_reason"),
    (
        ({"environment": "production"}, "deployment_acceptance_environment_mismatch"),
        ({"model_provider": "alternate"}, "deployment_acceptance_model_provider_mismatch"),
        ({"model": "alternate-model"}, "deployment_acceptance_model_mismatch"),
        ({"route_identity": "route:alternate"}, "deployment_acceptance_route_identity_mismatch"),
        (
            {"deployment_identity": "deployment:alternate"},
            "deployment_acceptance_deployment_identity_mismatch",
        ),
        ({"deployment_reference": "deployment-ref:other"}, "deployment_acceptance_deployment_mismatch"),
        ({"adapter_version": "2.0.0"}, "deployment_acceptance_adapter_version_mismatch"),
        ({"control_method": ControlMethod.GATEWAY_INLINE}, "control_method_not_reviewed"),
        ({"runtime_location": RuntimeLocation.LOCAL_ENDPOINT}, "deployment_acceptance_state_location_mismatch"),
    ),
)
def test_acceptance_scope_mismatches_are_never_enforcement_eligible(
    updates: dict[str, object],
    expected_reason: str,
) -> None:
    accepted, context = _accepted_runtime_contract()

    reasons = accepted.enforcement_ineligibility_reasons(
        replace(context, **updates),
        ProviderVersionState.EXACT_TESTED,
    )

    assert expected_reason in reasons


def test_unreviewed_runtime_or_control_method_is_never_enforcement_eligible() -> None:
    accepted, context = _accepted_runtime_contract()
    unreviewed = replace(
        accepted,
        supported_runtimes=(),
        supported_control_methods=(),
    )

    reasons = unreviewed.enforcement_ineligibility_reasons(
        context,
        ProviderVersionState.EXACT_TESTED,
    )

    assert "runtime_not_reviewed" in reasons
    assert "control_method_not_reviewed" in reasons


def test_accepted_control_method_cannot_differ_from_the_runtime_action() -> None:
    accepted, context = _accepted_runtime_contract()
    acceptance_with_other_method = replace(
        accepted.deployment_acceptance,
        control_method=ControlMethod.GATEWAY_INLINE,
    )
    mismatched = replace(accepted, deployment_acceptance=acceptance_with_other_method)

    reasons = mismatched.enforcement_ineligibility_reasons(
        context,
        ProviderVersionState.EXACT_TESTED,
    )

    assert "deployment_acceptance_control_method_mismatch" in reasons


def test_registry_environment_is_an_additional_acceptance_boundary() -> None:
    accepted, context = _accepted_runtime_contract()
    adapter = ReferenceNativeBoundAdapter()
    adapter.manifest = accepted  # type: ignore[assignment]
    registry = NativeControlAdapterRegistry(environment="production")
    registry.register(adapter)

    resolution = registry.resolve(
        provider="hawk_reference",
        product="synthetic_control",
        provider_version="1.0.0",
        runtime_context=context,
    )

    assert resolution.enforcement_eligible is False
    assert "registry_environment_mismatch" in resolution.ineligibility_reasons


def test_contract_review_material_is_plain_json_and_ignores_evidence_reference_order() -> None:
    accepted, _ = _accepted_runtime_contract()
    dimension, claim = next(iter(accepted.capabilities.items()))
    ordered_claim = replace(claim, evidence_refs=("repo:evidence-a", "repo:evidence-b"))
    reversed_claim = replace(claim, evidence_refs=("repo:evidence-b", "repo:evidence-a"))
    ordered = replace(accepted, capabilities={**accepted.capabilities, dimension: ordered_claim})
    reordered = replace(accepted, capabilities={**accepted.capabilities, dimension: reversed_claim})

    material = ordered.canonical_review_material()
    json.dumps(material, sort_keys=True)
    _assert_json_native(material)
    assert type(material["capabilities"][dimension.value]["verification_status"]) is str
    assert ordered.contract_fingerprint == reordered.contract_fingerprint


@pytest.mark.parametrize(
    (
        "contract_scope",
        "permitted_runtime_scope",
        "rejected_runtime_scope",
        "expected_reason",
    ),
    (
        (
            {"required_account_modes": ("enterprise_managed",)},
            {"account_mode": "enterprise_managed"},
            {"account_mode": "personal"},
            "account_mode_not_reviewed",
        ),
        (
            {"required_tenant_modes": ("enterprise_tenant",)},
            {"tenant_mode": "enterprise_tenant"},
            {"tenant_mode": "consumer"},
            "tenant_mode_not_reviewed",
        ),
    ),
)
def test_reviewed_account_and_tenant_modes_gate_enforcement_and_bind_the_contract(
    contract_scope: dict[str, tuple[str, ...]],
    permitted_runtime_scope: dict[str, str],
    rejected_runtime_scope: dict[str, str],
    expected_reason: str,
) -> None:
    accepted, context = _accepted_runtime_contract()
    scoped = replace(accepted, **contract_scope)
    scoped = replace(
        scoped,
        deployment_acceptance=replace(
            scoped.deployment_acceptance,
            contract_fingerprint=scoped.contract_fingerprint,
        ),
    )

    assert scoped.contract_fingerprint != accepted.contract_fingerprint
    assert scoped.enforcement_ineligibility_reasons(
        replace(context, **permitted_runtime_scope),
        ProviderVersionState.EXACT_TESTED,
    ) == ()
    assert expected_reason in scoped.enforcement_ineligibility_reasons(
        replace(context, **rejected_runtime_scope),
        ProviderVersionState.EXACT_TESTED,
    )


@pytest.mark.parametrize("field_name", ("required_account_modes", "required_tenant_modes"))
def test_registry_rejects_unbounded_required_account_or_tenant_modes(field_name: str) -> None:
    adapter = ReferenceNativeBoundAdapter()
    adapter.manifest = replace(  # type: ignore[assignment]
        adapter.manifest,
        **{field_name: ("a" * 257,)},
    )

    with pytest.raises(ValueError, match=f"manifest_{field_name}_invalid"):
        NativeControlAdapterRegistry(environment="test").register(adapter)


def test_unknown_or_unaccepted_contract_context_is_never_enforcement_eligible() -> None:
    adapter = ReferenceNativeBoundAdapter()
    registry = NativeControlAdapterRegistry(environment="test")
    registry.register(adapter)

    resolution = registry.resolve(
        provider="hawk_reference",
        product="synthetic_control",
        provider_version="1.0.0",
        runtime_context=_reviewed_context(),
    )

    assert resolution.version_state is ProviderVersionState.EXACT_TESTED
    assert resolution.enforcement_eligible is False
    assert "contract_review_missing" in resolution.ineligibility_reasons
    assert "deployment_acceptance_not_real" in resolution.ineligibility_reasons


def test_registry_rejects_malformed_provider_control_contract_envelope() -> None:
    adapter = ReferenceNativeBoundAdapter()
    adapter.manifest = replace(  # type: ignore[assignment]
        adapter.manifest,
        supported_action_classes=("function_tool",),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="manifest_supported_action_classes_invalid"):
        NativeControlAdapterRegistry(environment="test").register(adapter)


def test_registry_rejects_non_boolean_control_semantics() -> None:
    adapter = ReferenceNativeBoundAdapter()
    adapter.manifest = replace(  # type: ignore[assignment]
        adapter.manifest,
        supports_action_mutation="yes",  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="manifest_control_semantics_invalid"):
        NativeControlAdapterRegistry(environment="test").register(adapter)


def test_registry_rejects_invalid_reviewed_deployment_family() -> None:
    adapter = ReferenceNativeBoundAdapter()
    adapter.manifest = replace(  # type: ignore[assignment]
        adapter.manifest,
        supported_deployment_families=("runtime",),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="manifest_supported_deployment_families_invalid"):
        NativeControlAdapterRegistry(environment="test").register(adapter)


@pytest.mark.parametrize(
    ("provider_version", "expected"),
    (
        ("1.0.0", ProviderVersionState.EXACT_TESTED),
        ("1.0.1", ProviderVersionState.VERIFIED_COMPATIBLE_RANGE),
        ("2.0.0", ProviderVersionState.UNVERIFIED_NEWER),
        ("0.9.9", ProviderVersionState.UNSUPPORTED_OLDER),
        ("unknown", ProviderVersionState.UNKNOWN),
    ),
)
def test_registry_reports_version_truth_without_reclassifying_legacy_callers(
    provider_version: str,
    expected: ProviderVersionState,
) -> None:
    registry = NativeControlAdapterRegistry(environment="test")
    registry.register(ReferenceNativeBoundAdapter())

    resolution = registry.resolve(
        provider="hawk_reference",
        product="synthetic_control",
        provider_version=provider_version,
    )

    assert resolution.version_state is expected
    assert resolution.enforcement_eligible is False


def test_registry_reports_a_broken_contract_as_broken_not_supported() -> None:
    adapter = ReferenceNativeBoundAdapter()
    adapter.manifest = replace(  # type: ignore[assignment]
        adapter.manifest,
        verification_status=VerificationStatus.BROKEN,
    )
    registry = NativeControlAdapterRegistry(environment="test")
    registry.register(adapter)

    resolution = registry.resolve(
        provider="hawk_reference",
        product="synthetic_control",
        provider_version="1.0.0",
    )

    assert resolution.version_state is ProviderVersionState.BROKEN
    assert resolution.state.value == "broken"
    assert resolution.enforcement_eligible is False
