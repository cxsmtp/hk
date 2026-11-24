from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import attributes
from sqlalchemy.orm import sessionmaker

from app.core.control_engine.authorization import (
    AuthorizationRequest,
    AuthorizationRolloutOutcome,
    authorize_ai_action,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlSelection,
    NativeControlValidation,
    NativeWorkloadCredential,
)
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.native_control.selection_service import (
    apply_native_selection_to_rollout,
    select_and_persist_authorization,
    verify_control_plan_material,
)
from app.services.native_control.integrity import integration_configuration_fingerprint
from app.services.native_control.health import record_health_observation
from app.services.receipt_service import canonical_action_from_authorization


NOW = datetime(2026, 8, 11, 8, 0, tzinfo=timezone.utc)


def _request(
    tenant_id: str,
    *integration_ids: str,
    allowed_methods: list[str] | None = None,
    mandatory_enforcement_floors: list[dict[str, object]] | None = None,
    provider: str = "openai",
    product: str = "direct_api",
    action_type: str = "tool_execution",
    discovery_context_extra: dict[str, object] | None = None,
    route_binding_extra: dict[str, object] | None = None,
) -> AuthorizationRequest:
    return AuthorizationRequest.model_validate(
        {
            "tenant_id": tenant_id,
            "environment": "production",
            "collector_id": "mcp-gateway",
            "action_id": "action-persist-1",
            "chain_id": "chain-persist-1",
            "surface": "mcp_gateway",
            "actor": {"identity_id": "user-1"},
            "authority": {"verified": True},
            "action": {"action_type": action_type, "risk_level": "high"},
            "tool": {"name": "github.create_pull_request", "fingerprint_id": "github-pr"},
            "parameters": {"parameter_hash": "p" * 64},
            "target": {
                "resource_hash": "r" * 64,
                "destination": "github.com",
                "destination_hash": "d" * 64,
            },
            "side_effect_context": {"persistent_side_effect": True},
            "discovery_context": {
                "provider": provider,
                "product": product,
                "provider_version": "1.5.0",
                "adapter_version": "1.0.0",
                **(discovery_context_extra or {}),
            },
            "policy_snapshot_id": "policy-7",
            "policy_profile": {
                "dependencies_healthy": True,
                "degraded_behavior": "block",
                "minimum_control_assurance": "A5",
                "maximum_control_latency_ms": 100,
                **(
                    {"mandatory_enforcement_floors": mandatory_enforcement_floors}
                    if mandatory_enforcement_floors is not None
                    else {}
                ),
            },
            "path_evidence": (
                {
                    "native_control_route_binding": {
                        "verified": True,
                        "source": "authenticated_native_adapter",
                        "integration_instance_ids": list(integration_ids),
                        "allowed_methods": allowed_methods
                        or ["native_hook", "gateway_inline"],
                        "runtime_context_verified": True,
                        "lifecycle_stage": (
                            "before_model_request"
                            if action_type == "model_request"
                            else "before_tool"
                        ),
                        **(route_binding_extra or {}),
                    }
                }
                if integration_ids
                else {}
            ),
        }
    )


def _capabilities(*, execution: str, parameter: str = "inline_bound") -> dict[str, dict[str, object]]:
    return {
        "identity": {"level": "inline_bound", "verification_status": "verified", "evidence_refs": []},
        "tool_control": {"level": "inline_bound", "verification_status": "verified", "evidence_refs": []},
        "mcp_control": {"level": "inline_bound", "verification_status": "verified", "evidence_refs": []},
        "parameter_binding": {"level": parameter, "verification_status": "verified", "evidence_refs": []},
        "target_binding": {"level": "inline_bound", "verification_status": "verified", "evidence_refs": []},
        "destination_binding": {"level": "inline_bound", "verification_status": "verified", "evidence_refs": []},
        "post_execution_verification": {"level": execution, "verification_status": "verified", "evidence_refs": []},
        "persistent_side_effect_control": {"level": "observe", "verification_status": "verified", "evidence_refs": []},
        "containment": {"level": "external", "verification_status": "verified", "evidence_refs": []},
    }


def _add_point(
    db,
    tenant_id: str,
    *,
    name: str,
    method: str,
    capabilities: dict,
    provider: str = "openai",
    product: str = "direct_api",
    allowed_event_types: list[str] | None = None,
    runtime: str = "test_runtime",
    execution_location: str = "CUSTOMER_RUNTIME",
    deployment_reference: str = "runtime:test-deployment",
    provider_version: str = "1.5.0",
    adapter_version: str = "1.0.0",
    model_provider: str | None = None,
    model: str = "model-test-1",
    real_acceptance: bool = True,
    acceptance_overrides: dict[str, object] | None = None,
) -> NativeControlIntegration:
    action_classes = (
        ["model_request"]
        if provider == "anthropic" and product == "enterprise_inference_hook"
        else ["function_tool"]
    )
    contract_hash = hashlib.sha256(
        f"{provider}:{product}:{method}:{runtime}:{adapter_version}".encode("utf-8")
    ).hexdigest()
    profile = ControlCapabilityProfileRecord(
        manifest_id=f"{provider}:{product}:{method}:{name}",
        manifest_version="provider-capability-manifest/1.0",
        matrix_version="matrix-test",
        provider=provider,
        product=product,
        runtime=runtime,
        integration_method=method,
        adapter_version=adapter_version,
        tested_min_version="1.0.0",
        tested_max_version="2.0.0",
        current_verified_version=provider_version,
        verification_status="verified",
        verification_source="integration_test",
        verified_at=NOW,
        capabilities=capabilities,
        security_properties={
            "pre_execution_capable": True,
            "post_execution_capable": True,
            "blocking_strength": 90,
            "action_fidelity": 90,
            "identity_quality": 90,
            "parameter_fidelity": 90,
            "target_fidelity": 90,
            "destination_fidelity": 90,
            "result_fidelity": 90,
            "bypass_resistance": 90,
            "tamper_resistance": 90,
            "expected_latency_ms": 20,
            "availability_profile": "test",
            "required_permissions": [],
            "privacy_impact": "metadata_only",
        },
        health_requirements=[],
        degradation_modes=["fail_closed"],
        known_blind_spots=["direct_api_bypass"],
        documentation_references=["integration_test"],
        supported_action_classes=action_classes,
        supported_control_methods=[method],
        contract_hash=contract_hash,
        manifest_fingerprint=(name[0] * 64),
        active=True,
    )
    db.add(profile)
    db.flush()
    point = NativeControlIntegration(
        tenant_id=tenant_id,
        capability_profile_id=profile.id,
        instance_key=name,
        display_name=name,
        provider=provider,
        product=product,
        model_provider=model_provider or provider,
        model=model,
        runtime=runtime,
        execution_location=execution_location,
        deployment_reference=deployment_reference,
        integration_method=method,
        deployment_family="saas_api",
        environment="production",
        state="enforcing",
        mode="enforce",
        health_state="healthy",
        health_reasons=[],
        provider_version=provider_version,
        adapter_version=adapter_version,
        contract_hash=contract_hash,
        configuration_fingerprint=None,
        expected_configuration_fingerprint=None,
        policy_version="policy-7",
        policy_fresh_until=NOW + timedelta(hours=1),
        degradation_mode="fail_closed",
        capability_snapshot=capabilities,
        known_blind_spots=["direct_api_bypass"],
        last_validated_at=NOW,
    )
    db.add(point)
    db.flush()
    point.configuration_fingerprint = integration_configuration_fingerprint(point)
    point.expected_configuration_fingerprint = point.configuration_fingerprint
    db.add(
        NativeWorkloadCredential(
            tenant_id=tenant_id,
            integration_instance_id=point.id,
            credential_id=f"credential-{name}",
            credential_epoch=1,
            public_key_pem="test-public-key",
            key_thumbprint=(name[-1] * 64),
            signature_algorithm="ES256",
            environment="production",
            allowed_event_types=allowed_event_types or ["before_tool", "after_tool"],
            status="active",
            expires_at=NOW + timedelta(hours=1),
        )
    )
    validation_values: dict[str, object] = {
        "tenant_id": tenant_id,
        "integration_instance_id": point.id,
        "validation_version": "native-control-validation/2.0",
        "credential_id": f"credential-{name}",
        "credential_epoch": 1,
        "safe_synthetic": not real_acceptance,
        "acceptance_state": (
            {
                "LOCAL_ENDPOINT": "REAL_BINARY_ACCEPTED",
                "PROVIDER_HOSTED": "REAL_ENTERPRISE_TENANT_ACCEPTED",
                "REMOTE_AGENT": "REAL_ENTERPRISE_TENANT_ACCEPTED",
                "CUSTOMER_RUNTIME": "REAL_CLOUD_RUNTIME_ACCEPTED",
                "CUSTOMER_CLOUD": "REAL_CLOUD_RUNTIME_ACCEPTED",
                "MIXED": "REAL_CLOUD_RUNTIME_ACCEPTED",
            }.get(execution_location, "NOT_TESTED")
            if real_acceptance
            else "SYNTHETIC_ONLY"
        ),
        "deployment_environment": "production",
        "provider": provider,
        "product": product,
        "runtime": runtime,
        "model_provider": model_provider or provider,
        "model": model,
        "route_identity": f"native-control:{point.id}",
        "deployment_identity": f"integration:{name}",
        "execution_location": execution_location,
        "deployment_reference": deployment_reference,
        "action_classes": action_classes,
        "control_methods": [method],
        "lifecycle_events": allowed_event_types or ["before_tool", "after_tool"],
        "provider_version": provider_version,
        "adapter_version": adapter_version,
        "contract_hash": contract_hash,
        "acceptance_run_id": f"acceptance-{name}" if real_acceptance else None,
        "allow_result": "passed" if real_acceptance else "not_tested",
        "block_result": "passed" if real_acceptance else "not_tested",
        "non_execution_result": "passed" if real_acceptance else "not_tested",
        "checks": {"all": True},
        "result": "passed",
        "reason_codes": [],
        "evidence_refs": [f"evidence:validation-{name}"],
        "validated_at": NOW,
    }
    validation_values.update(acceptance_overrides or {})
    db.add(NativeControlValidation(**validation_values))
    record_health_observation(
        db,
        tenant_id=tenant_id,
        integration_id=point.id,
        credential_id=f"credential-{name}",
        credential_epoch=1,
        provider_event_id=f"health-{name}",
        provider_event_type="after_tool",
        callback_authenticated=True,
        evidence_flowing=True,
        latency_ms=20,
        source="signed_native_callback",
        evidence_ref=f"evidence:health-{name}",
        observed_at=NOW,
    )
    db.flush()
    return point


def _add_exact_reacceptance(
    db,
    point: NativeControlIntegration,
    *,
    acceptance_run_id: str,
    validated_at: datetime,
) -> None:
    credential = db.scalar(
        select(NativeWorkloadCredential).where(
            NativeWorkloadCredential.integration_instance_id == point.id,
            NativeWorkloadCredential.status == "active",
        )
    )
    assert credential is not None
    db.add(
        NativeControlValidation(
            tenant_id=point.tenant_id,
            integration_instance_id=point.id,
            validation_version="native-control-validation/2.0",
            credential_id=credential.credential_id,
            credential_epoch=credential.credential_epoch,
            safe_synthetic=False,
            acceptance_state="REAL_CLOUD_RUNTIME_ACCEPTED",
            deployment_environment=point.environment,
            provider=point.provider,
            product=point.product,
            runtime=point.runtime,
            model_provider=point.model_provider,
            model=point.model,
            route_identity=f"native-control:{point.id}",
            deployment_identity=f"integration:{point.instance_key}",
            execution_location=point.execution_location,
            deployment_reference=point.deployment_reference,
            action_classes=["function_tool"],
            control_methods=[point.integration_method],
            lifecycle_events=["before_tool", "after_tool"],
            provider_version=point.provider_version,
            adapter_version=point.adapter_version,
            contract_hash=point.contract_hash,
            acceptance_run_id=acceptance_run_id,
            allow_result="passed",
            block_result="passed",
            non_execution_result="passed",
            checks={"all": True},
            result="passed",
            reason_codes=[],
            evidence_refs=[f"evidence:{acceptance_run_id}"],
            validated_at=validated_at,
        )
    )
    db.flush()


def test_anthropic_enterprise_selection_requires_authenticated_route_bound_scope() -> None:
    """Discovery facts cannot turn a personal Claude route into an enterprise route."""

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Anthropic Scope Tenant", slug="anthropic-scope-tenant")
        db.add(tenant)
        db.flush()
        enterprise = _add_point(
            db,
            tenant.id,
            name="anthropic-enterprise-hook",
            method="provider_enterprise_hook",
            provider="anthropic",
            product="enterprise_inference_hook",
            runtime="anthropic_enterprise_inference_hook",
            execution_location="PROVIDER_HOSTED",
            deployment_reference="anthropic-enterprise:tenant-bound-route",
            provider_version="2026.08.20",
            allowed_event_types=["before_model", "before_model_request", "after_model"],
            capabilities={
                **_capabilities(execution="inline_bound"),
                "prompt_control": {
                    "level": "inline_bound",
                    "verification_status": "verified",
                    "evidence_refs": ["evidence:enterprise-hook"],
                },
            },
        )
        db.commit()

        untrusted_scope = _request(
            tenant.id,
            enterprise.id,
            allowed_methods=["provider_enterprise_hook"],
            provider="anthropic",
            product="enterprise_inference_hook",
            action_type="model_request",
            # These client/discovery fields must never satisfy an enterprise
            # control contract. Only the authenticated route binding can.
            discovery_context_extra={
                "account_mode": "enterprise",
                "tenant_mode": "tenant_verified",
            },
        )
        rejected = select_and_persist_authorization(
            db,
            request=untrusted_scope,
            now=NOW,
        )
        db.commit()

        assert rejected.primary_control_point is None
        rejection = next(
            item
            for item in rejected.rejected_candidates
            if item.control_point_id == enterprise.id
        )
        assert rejection.reason_codes == (
            "enterprise_account_context_required",
            "enterprise_tenant_context_required",
        )
        rejected_record = db.get(NativeControlSelection, rejected.selection_id)
        assert rejected_record is not None
        assert rejected_record.provider_runtime_context["account_mode"] == "unknown"
        assert rejected_record.provider_runtime_context["tenant_mode"] == "unknown"
        assert rejected_record.control_plan_reason_codes == [
            "CONTROL_REQUIREMENT_UNSATISFIED:semantic",
            "enterprise_account_context_required",
            "enterprise_tenant_context_required",
        ]

        authenticated_scope = _request(
            tenant.id,
            enterprise.id,
            allowed_methods=["provider_enterprise_hook"],
            provider="anthropic",
            product="enterprise_inference_hook",
            action_type="model_request",
            route_binding_extra={
                "enterprise_identity_verified": True,
                "enterprise_account_mode": "enterprise",
                "enterprise_tenant_mode": "tenant_verified",
                "runtime_context_verified": True,
                "lifecycle_stage": "before_model_request",
            },
        )
        selected = select_and_persist_authorization(
            db,
            request=authenticated_scope,
            now=NOW + timedelta(seconds=1),
        )
        db.commit()

        # Authenticated enterprise scope is necessary but not sufficient. The
        # reviewed provider profile remains unavailable until a real tenant
        # acceptance is independently recorded.
        assert selected.primary_control_point is None
        selected_rejection = next(
            item
            for item in selected.rejected_candidates
            if item.control_point_id == enterprise.id
        )
        assert selected_rejection.reason_codes == (
            "contract_not_verified",
            "deployment_acceptance_not_real",
        )
        selected_record = db.get(NativeControlSelection, selected.selection_id)
        assert selected_record is not None
        assert selected_record.provider_runtime_context["account_mode"] == "enterprise"
        assert selected_record.provider_runtime_context["tenant_mode"] == "tenant_verified"
        assert selected_record.provider_runtime_context["control_method"] == (
            "provider_enterprise_hook"
        )
        assert selected_record.provider_runtime_context["environment"] == "production"
        assert selected_record.provider_runtime_context["runtime"] == (
            "anthropic_enterprise_inference_hook"
        )
        assert selected_record.provider_runtime_context["runtime_location"] == (
            "provider_hosted"
        )
        assert selected_record.provider_runtime_context["provider_version"] == "2026.08.20"
        assert selected_record.provider_runtime_context["adapter_version"] == "1.0.0"
        assert selected_record.provider_runtime_context["deployment_reference"] == (
            "anthropic-enterprise:tenant-bound-route"
        )
        assert selected_record.provider_runtime_context["lifecycle_stage"] == (
            "before_model_request"
        )
        assert selected_record.control_plan_material["provider_runtime_requirements"] == {
            "required_account_modes": [
                "approved_enterprise",
                "enterprise",
                "enterprise_managed",
            ],
            "required_tenant_modes": [
                "approved_organization",
                "enterprise_managed",
                "tenant_verified",
            ],
        }
        receipt_request = authenticated_scope.model_copy(
            deep=True,
            update={
                "path_evidence": {
                    **authenticated_scope.path_evidence,
                    "native_control_selection_id": selected.selection_id,
                    "native_control_plan": selected_record.control_plan_material,
                }
            },
        )
        receipt_action = canonical_action_from_authorization(
            receipt_request,
            authorize_ai_action(receipt_request),
            db=db,
            now=NOW + timedelta(seconds=1),
        )
        assert receipt_action["policy"]["native_control_plan"][
            "provider_runtime_requirements"
        ] == selected_record.control_plan_material["provider_runtime_requirements"]
    engine.dispose()


def test_selection_is_action_specific_explainable_and_idempotently_persisted() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Selection Tenant", slug="selection-tenant")
        db.add(tenant)
        db.flush()
        strong = _add_point(
            db,
            tenant.id,
            name="strong-native",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        weak = _add_point(
            db,
            tenant.id,
            name="weak-gateway",
            method="gateway_inline",
            capabilities=_capabilities(execution="observe", parameter="inline"),
        )
        db.commit()

        request = _request(tenant.id, strong.id, weak.id)
        first = select_and_persist_authorization(db, request=request, now=NOW)
        db.commit()
        second = select_and_persist_authorization(
            db,
            request=request,
            now=NOW + timedelta(seconds=1),
        )
        db.commit()

        assert first.primary_control_point == strong.id
        assert second.selection_id == first.selection_id
        assert [(row.control_point_id, row.reason_codes) for row in first.rejected_candidates] == [
            (
                weak.id,
                (
                    "insufficient_parameter_binding",
                    "insufficient_post_execution_verification",
                    "minimum_assurance_unsatisfied",
                ),
            )
        ]
        assert db.scalar(select(func.count()).select_from(NativeControlSelection)) == 1
        assert (
            db.scalar(
                select(func.count())
                .select_from(EvidenceNode)
                .where(EvidenceNode.signal_type == "trusted_control_point_selected")
            )
            == 1
        )
        request = _request(tenant.id, strong.id, weak.id)
        initial_response = authorize_ai_action(request)
        rollout = AuthorizationRolloutOutcome(
            authoritative_decision=initial_response.decision,
            metadata={},
            v2_response=initial_response,
            enforced=True,
            request=request,
        )
        applied = apply_native_selection_to_rollout(
            db,
            rollout=rollout,
            settings_obj=type(
                "Settings",
                (),
                {
                    "native_control_framework": True,
                    "trusted_control_selector": True,
                    "native_control_enforce": True,
                    "native_control_openai": True,
                },
            )(),
            now=NOW,
        )
        assert applied.metadata["native_control_selection"]["selection_id"] == first.selection_id
        assert applied.request is not None
        assert applied.request.path_evidence["native_control_selection_id"] == first.selection_id
        assert applied.request.path_evidence["native_primary_control_point"] == strong.id
        assert applied.v2_response is not None
        receipt_action = canonical_action_from_authorization(
            applied.request,
            applied.v2_response,
            db=db,
            now=NOW,
        )
        assert receipt_action["policy"]["native_control_selection_id"] == first.selection_id
        assert receipt_action["policy"]["native_primary_control_point"] == strong.id
        assert receipt_action["policy"]["native_selector_version"] == first.selector_version
        assert receipt_action["policy"]["native_matrix_version"] == first.matrix_version

        # Keep the control point healthy while allowing the immutable action plan
        # itself to expire. A retry of the same action must not mint or trust a
        # replacement authority under the same idempotency key.
        record_health_observation(
            db,
            tenant_id=tenant.id,
            integration_id=strong.id,
            credential_id="credential-strong-native",
            credential_epoch=1,
            provider_event_id="health-strong-native-refresh",
            provider_event_type="after_tool",
            callback_authenticated=True,
            evidence_flowing=True,
            latency_ms=20,
            source="signed_native_callback",
            evidence_ref="evidence:health-strong-native-refresh",
            observed_at=NOW + timedelta(minutes=5, seconds=30),
        )
        record_health_observation(
            db,
            tenant_id=tenant.id,
            integration_id=weak.id,
            credential_id="credential-weak-gateway",
            credential_epoch=1,
            provider_event_id="health-weak-gateway-refresh",
            provider_event_type="after_tool",
            callback_authenticated=True,
            evidence_flowing=True,
            latency_ms=20,
            source="signed_native_callback",
            evidence_ref="evidence:health-weak-gateway-refresh",
            observed_at=NOW + timedelta(minutes=5, seconds=30),
        )
        db.commit()
        expired_applied = apply_native_selection_to_rollout(
            db,
            rollout=rollout,
            settings_obj=type(
                "Settings",
                (),
                {
                    "native_control_framework": True,
                    "trusted_control_selector": True,
                    "native_control_enforce": True,
                    "native_control_openai": True,
                },
            )(),
            now=NOW + timedelta(minutes=6),
        )
        assert expired_applied.request is not None
        assert (
            expired_applied.request.path_evidence[
                "native_control_requirement_satisfied"
            ]
            is False
        )
        assert expired_applied.v2_response is not None
        assert expired_applied.v2_response.decision == "block"
        assert "NATIVE_CONTROL_PLAN_INVALID" in expired_applied.v2_response.matched_rules

        strong.health_state = "degraded"
        db.commit()
        downgraded = select_and_persist_authorization(
            db,
            request=_request(tenant.id, strong.id, weak.id),
            now=NOW,
        )
        db.commit()

        assert downgraded.primary_control_point is None
        assert (
            db.scalar(
                select(func.count())
                .select_from(EvidenceNode)
                .where(EvidenceNode.signal_type == "control_point_downgraded")
            )
            == 1
        )
        finding_types = set(
            db.scalars(
                select(Finding.finding_type).where(Finding.tenant_id == tenant.id)
            ).all()
        )
        assert {"CONTROL_REQUIREMENT_UNSATISFIED", "PROVIDER_CONTROL_DOWNGRADED"} <= finding_types
    engine.dispose()


def test_composed_plan_persists_required_floor_and_binds_receipt_material() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Composed Plan Tenant", slug="composed-plan-tenant")
        db.add(tenant)
        db.flush()
        semantic = _add_point(
            db,
            tenant.id,
            name="composed-semantic",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        endpoint_capabilities = {
            **_capabilities(execution="inline_bound"),
            "file_read_control": {
                "level": "inline_bound",
                "verification_status": "verified",
                "evidence_refs": ["evidence:endpoint-file-read"],
            },
        }
        endpoint = _add_point(
            db,
            tenant.id,
            name="composed-endpoint-file",
            method="endpoint_runtime",
            provider="hawk_endpoint",
            product="macos_endpoint_file",
            capabilities=endpoint_capabilities,
        )
        db.commit()
        request = _request(
            tenant.id,
            semantic.id,
            endpoint.id,
            allowed_methods=["native_hook", "endpoint_runtime"],
            mandatory_enforcement_floors=[
                {
                    "floor_id": "file",
                    "capability": "file_read_control",
                    "minimum_level": "inline",
                    "allowed_methods": ["endpoint_runtime"],
                    "maximum_latency_ms": 100,
                }
            ],
        )

        first = select_and_persist_authorization(db, request=request, now=NOW)
        db.commit()
        second = select_and_persist_authorization(
            db,
            request=request,
            now=NOW + timedelta(seconds=1),
        )
        db.commit()

        assert first.primary_control_point == semantic.id
        assert second.selection_id == first.selection_id
        assert db.scalar(select(func.count()).select_from(NativeControlSelection)) == 1
        selection = db.get(NativeControlSelection, first.selection_id)
        assert selection is not None
        assert selection.canonical_action_hash is not None
        assert len(selection.canonical_action_hash) == 64
        assert selection.provider_runtime_context["provider"] == "openai"
        assert len(selection.provider_runtime_fingerprint) == 64
        assert selection.control_plan_id == first.selection_id
        assert len(selection.control_plan_digest) == 64
        assert selection.mandatory_enforcement_floor_requirements == [
            {
                "floor_id": "file",
                "capability": "file_read_control",
                "minimum_level": "inline",
                "allowed_methods": ["endpoint_runtime"],
                "maximum_latency_ms": 100,
            }
        ]
        assert selection.selected_mandatory_floors == [
            {"floor_id": "file", "control_point_id": endpoint.id}
        ]
        assert selection.semantic_primary_control_point_id == semantic.id
        assert selection.unsatisfied_mandatory_floors == []
        assert selection.control_requirement_unsatisfied is False
        assert selection.failure_behavior == "fail_closed"
        assert selection.plan_issued_at.replace(tzinfo=timezone.utc) == NOW
        assert selection.plan_expires_at.replace(tzinfo=timezone.utc) == (
            NOW + timedelta(minutes=5)
        )
        assert selection.control_plan_material["issued_at"] == NOW.isoformat()
        assert selection.control_plan_material["expires_at"] == (
            NOW + timedelta(minutes=5)
        ).isoformat()

        response = authorize_ai_action(request)
        rollout = AuthorizationRolloutOutcome(
            authoritative_decision=response.decision,
            metadata={},
            v2_response=response,
            enforced=True,
            request=request,
        )
        applied = apply_native_selection_to_rollout(
            db,
            rollout=rollout,
            settings_obj=type(
                "Settings",
                (),
                {
                    "native_control_framework": True,
                    "trusted_control_selector": True,
                    "native_control_enforce": True,
                    "native_control_openai": True,
                },
            )(),
            now=NOW,
        )
        assert applied.request is not None
        receipt_action = canonical_action_from_authorization(
            applied.request,
            applied.v2_response,
            db=db,
            now=NOW,
        )
        plan = receipt_action["policy"]["native_control_plan"]
        assert plan["plan_id"] == first.selection_id
        assert plan["plan_digest"] == selection.control_plan_digest
        assert plan["canonical_action_hash"] == selection.canonical_action_hash
        assert plan["mandatory_enforcement_floors"] == selection.selected_mandatory_floors
    engine.dispose()


def test_explicit_mandatory_floor_absence_is_persisted_and_fails_closed() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Missing Floor Tenant", slug="missing-floor-tenant")
        db.add(tenant)
        db.flush()
        semantic = _add_point(
            db,
            tenant.id,
            name="missing-floor-semantic",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        db.commit()
        request = _request(
            tenant.id,
            semantic.id,
            allowed_methods=["native_hook"],
            mandatory_enforcement_floors=[
                {
                    "floor_id": "file",
                    "capability": "file_read_control",
                    "minimum_level": "inline",
                    "allowed_methods": ["endpoint_runtime"],
                    "maximum_latency_ms": 100,
                }
            ],
        )
        response = authorize_ai_action(request)
        rollout = AuthorizationRolloutOutcome(
            authoritative_decision=response.decision,
            metadata={},
            v2_response=response,
            enforced=True,
            request=request,
        )

        applied = apply_native_selection_to_rollout(
            db,
            rollout=rollout,
            settings_obj=type(
                "Settings",
                (),
                {
                    "native_control_framework": True,
                    "trusted_control_selector": True,
                    "native_control_enforce": True,
                    "native_control_openai": True,
                },
            )(),
            now=NOW,
        )
        db.commit()

        assert applied.authoritative_decision == "block"
        assert applied.v2_response is not None
        assert "CONTROL_REQUIREMENT_UNSATISFIED" in applied.v2_response.matched_rules
        selection = db.scalar(select(NativeControlSelection))
        assert selection is not None
        assert selection.semantic_primary_control_point_id == semantic.id
        assert selection.primary_control_point_id is None
        assert selection.unsatisfied_mandatory_floors == ["file"]
        assert selection.control_requirement_unsatisfied is True
        assert selection.failure_behavior == "fail_closed"
    engine.dispose()


def test_synthetic_or_scope_mismatched_acceptance_never_selects_enforce() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Acceptance Gate Tenant", slug="acceptance-gate-tenant")
        db.add(tenant)
        db.flush()
        synthetic = _add_point(
            db,
            tenant.id,
            name="synthetic-only",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
            real_acceptance=False,
        )
        mismatch = _add_point(
            db,
            tenant.id,
            name="acceptance-version-mismatch",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
            acceptance_overrides={"provider_version": "9.9.9"},
        )
        db.commit()

        synthetic_result = select_and_persist_authorization(
            db,
            request=_request(
                tenant.id,
                synthetic.id,
                allowed_methods=["native_hook"],
            ),
            now=NOW,
        )
        mismatch_result = select_and_persist_authorization(
            db,
            request=_request(
                tenant.id,
                mismatch.id,
                allowed_methods=["native_hook"],
            ).model_copy(update={"action_id": "action-acceptance-mismatch"}),
            now=NOW,
        )

        assert synthetic_result.primary_control_point is None
        synthetic_rejection = next(
            item
            for item in synthetic_result.rejected_candidates
            if item.control_point_id == synthetic.id
        )
        assert "deployment_acceptance_not_current" in synthetic_rejection.reason_codes
        assert mismatch_result.primary_control_point is None
        mismatch_rejection = next(
            item
            for item in mismatch_result.rejected_candidates
            if item.control_point_id == mismatch.id
        )
        assert "deployment_acceptance_provider_version_mismatch" in (
            mismatch_rejection.reason_codes
        )
    engine.dispose()


@pytest.mark.parametrize(
    ("field", "value", "expected_reason"),
    (
        (
            "model_provider",
            "alternate-provider",
            "deployment_acceptance_model_provider_mismatch",
        ),
        ("model", "alternate-model", "deployment_acceptance_model_mismatch"),
        (
            "route_identity",
            "native-control:alternate",
            "deployment_acceptance_route_identity_mismatch",
        ),
        (
            "deployment_identity",
            "integration:alternate",
            "deployment_acceptance_deployment_identity_mismatch",
        ),
    ),
)
def test_real_acceptance_rejects_model_and_route_drift(
    field: str,
    value: str,
    expected_reason: str,
) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(
            name=f"Acceptance Drift {field}",
            slug=f"acceptance-drift-{field.replace('_', '-')}",
        )
        db.add(tenant)
        db.flush()
        point = _add_point(
            db,
            tenant.id,
            name=f"drift-{field}",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
            acceptance_overrides={field: value},
        )
        db.commit()

        result = select_and_persist_authorization(
            db,
            request=_request(tenant.id, point.id, allowed_methods=["native_hook"]),
            now=NOW,
        )

        assert result.primary_control_point is None
        rejection = next(
            row for row in result.rejected_candidates if row.control_point_id == point.id
        )
        assert expected_reason in rejection.reason_codes
    engine.dispose()


def test_plan_material_is_bounded_immutable_and_digest_verified_before_receipt() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Immutable Plan Tenant", slug="immutable-plan-tenant")
        db.add(tenant)
        db.flush()
        point = _add_point(
            db,
            tenant.id,
            name="immutable-plan-control",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        db.commit()
        request = _request(tenant.id, point.id, allowed_methods=["native_hook"])
        result = select_and_persist_authorization(db, request=request, now=NOW)
        db.commit()
        selection = db.get(NativeControlSelection, result.selection_id)
        assert selection is not None

        verified = verify_control_plan_material(
            selection.control_plan_material,
            expected_digest=selection.control_plan_digest,
            expected_plan_id=selection.control_plan_id,
            expected_canonical_action_hash=selection.canonical_action_hash,
            now=NOW,
        )
        assert verified["selection_reason"] == selection.selection_reason
        assert verified["rejected_candidates"] == selection.rejected_candidates
        assert verified["blind_spots"] == selection.known_blind_spots
        assert verified["degradation_policy"] == selection.degradation_policy

        with pytest.raises(ValueError, match="control plan expired"):
            verify_control_plan_material(
                selection.control_plan_material,
                expected_digest=selection.control_plan_digest,
                expected_plan_id=selection.control_plan_id,
                expected_canonical_action_hash=selection.canonical_action_hash,
                now=NOW + timedelta(minutes=5),
            )

        tampered = json.loads(json.dumps(selection.control_plan_material))
        tampered["failure_behavior"] = "fail_open_with_evidence"
        with pytest.raises(ValueError, match="control plan digest mismatch"):
            verify_control_plan_material(
                tampered,
                expected_digest=selection.control_plan_digest,
                expected_plan_id=selection.control_plan_id,
                expected_canonical_action_hash=selection.canonical_action_hash,
                now=NOW,
            )

        selection.selection_reason = "tampered"
        with pytest.raises(ValueError, match="native_control_selection_append_only"):
            db.flush()
        db.rollback()

        with pytest.raises(IntegrityError, match="immutable_table:native_control_selections"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "UPDATE native_control_selections "
                        "SET selection_reason = 'tampered' WHERE selection_id = :selection_id"
                    ),
                    {"selection_id": result.selection_id},
                )

        persisted = db.get(NativeControlSelection, result.selection_id)
        assert persisted is not None
        injected = request.model_copy(
            deep=True,
            update={
                "path_evidence": {
                    **request.path_evidence,
                    "native_control_selection_id": result.selection_id,
                    "native_control_plan": {
                        "plan_id": "caller-plan",
                        "plan_digest": "f" * 64,
                    },
                }
            },
        )
        canonical = canonical_action_from_authorization(
            injected,
            authorize_ai_action(injected),
            db=db,
            now=NOW,
        )
        assert canonical["policy"]["native_control_plan"]["plan_id"] == (
            persisted.control_plan_id
        )

        corrupted = json.loads(json.dumps(persisted.control_plan_material))
        corrupted["selection_reason"] = "corrupted"
        attributes.set_committed_value(persisted, "control_plan_material", corrupted)
        with pytest.raises(ValueError, match="control plan digest mismatch"):
            canonical_action_from_authorization(
                injected,
                authorize_ai_action(injected),
                db=db,
                now=NOW,
            )

        attributes.set_committed_value(
            persisted,
            "control_plan_material",
            verified,
        )
        with pytest.raises(ValueError, match="control plan expired"):
            canonical_action_from_authorization(
                injected,
                authorize_ai_action(injected),
                db=db,
                now=NOW + timedelta(minutes=6),
            )
    engine.dispose()


def test_existing_plan_fails_closed_after_exact_model_and_deployment_reacceptance() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Plan Authority Drift Tenant", slug="plan-authority-drift")
        db.add(tenant)
        db.flush()
        point = _add_point(
            db,
            tenant.id,
            name="plan-authority-control",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
            model="model-before",
            deployment_reference="deployment:before",
        )
        db.commit()
        request = _request(tenant.id, point.id, allowed_methods=["native_hook"])
        first = select_and_persist_authorization(db, request=request, now=NOW)
        db.commit()
        old_selection = db.get(NativeControlSelection, first.selection_id)
        assert old_selection is not None

        point.model = "model-after"
        point.deployment_reference = "deployment:after"
        point.configuration_fingerprint = integration_configuration_fingerprint(point)
        point.expected_configuration_fingerprint = point.configuration_fingerprint
        point.last_validated_at = NOW + timedelta(seconds=1)
        _add_exact_reacceptance(
            db,
            point,
            acceptance_run_id="acceptance-plan-authority-after",
            validated_at=NOW + timedelta(seconds=1),
        )
        db.commit()

        response = authorize_ai_action(request)
        rollout = AuthorizationRolloutOutcome(
            authoritative_decision=response.decision,
            metadata={},
            v2_response=response,
            enforced=True,
            request=request,
        )
        settings = type(
            "Settings",
            (),
            {
                "native_control_framework": True,
                "trusted_control_selector": True,
                "native_control_enforce": True,
                "native_control_openai": True,
            },
        )()
        with pytest.raises(ValueError, match="native control selection authority mismatch"):
            applied = apply_native_selection_to_rollout(
                db,
                rollout=rollout,
                settings_obj=settings,
                now=NOW + timedelta(seconds=1),
            )
            assert applied.request is not None
            canonical_action_from_authorization(
                applied.request,
                applied.v2_response,
                db=db,
                now=NOW + timedelta(seconds=1),
            )

        assert db.get(NativeControlSelection, first.selection_id) is old_selection
        assert db.scalar(select(func.count()).select_from(NativeControlSelection)) == 1
    engine.dispose()


def test_policy_epoch_is_persisted_in_plan_and_projected_into_receipt_material() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Policy Epoch Tenant", slug="policy-epoch-tenant")
        db.add(tenant)
        db.flush()
        point = _add_point(
            db,
            tenant.id,
            name="policy-epoch-native",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        db.commit()
        request = _request(tenant.id, point.id, allowed_methods=["native_hook"])
        request = request.model_copy(
            deep=True,
            update={
                "policy_profile": {
                    **request.policy_profile,
                    "policy_epoch": 12,
                }
            },
        )
        result = select_and_persist_authorization(db, request=request, now=NOW)
        db.commit()
        selection = db.get(NativeControlSelection, result.selection_id)
        assert selection is not None
        assert selection.control_plan_material["policy_epoch"] == 12

        receipt_request = request.model_copy(
            deep=True,
            update={
                "path_evidence": {
                    **request.path_evidence,
                    "native_control_selection_id": selection.selection_id,
                }
            },
        )
        canonical = canonical_action_from_authorization(
            receipt_request,
            authorize_ai_action(receipt_request),
            db=db,
            now=NOW,
        )
        assert canonical["policy"]["native_control_plan"]["policy_epoch"] == 12
    engine.dispose()


def test_composed_plan_hashes_require_canonical_lowercase_sha256() -> None:
    selection = NativeControlSelection(
        selection_id="selection-hash-test",
        tenant_id="tenant-hash-test",
        action_id="action-hash-test",
        selection_reason="test",
        assurance_level=0,
        selector_version="selector-test",
        matrix_version="matrix-test",
        policy_version="policy-test",
        input_digest="a" * 64,
    )

    with pytest.raises(ValueError, match="control_plan_digest_invalid"):
        selection.control_plan_digest = "A" * 64
    with pytest.raises(ValueError, match="canonical_action_hash_invalid"):
        selection.canonical_action_hash = "A" * 64
    with pytest.raises(ValueError, match="provider_runtime_fingerprint_invalid"):
        selection.provider_runtime_fingerprint = "A" * 64


def test_receipt_projection_rejects_caller_injected_plan_evidence() -> None:
    """A caller path mapping is never a receipt-authoritative control plan."""

    request = _request("tenant-receipt-safety", "integration-receipt-safety").model_copy(
        deep=True,
        update={
            "path_evidence": {
                "native_control_selection_id": "selection-receipt-safety",
                "native_control_plan": {
                    "schema_version": "native-control-composed-plan/1.0",
                    "plan_id": "selection-receipt-safety",
                    "plan_digest": "d" * 64,
                    "canonical_action_hash": "a" * 64,
                    "mandatory_enforcement_floor_requirements": [
                        {
                            "floor_id": "file",
                            "capability": "file_read_control",
                            "minimum_level": "inline",
                            "allowed_methods": ["endpoint_runtime"],
                            "maximum_latency_ms": {"not": "an integer"},
                        }
                    ],
                },
            }
        },
    )
    response = authorize_ai_action(request)

    with pytest.raises(ValueError, match="persisted native control plan is required"):
        canonical_action_from_authorization(request, response)


def test_monitoring_control_point_cannot_be_selected_as_inline_enforcement() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Monitor Tenant", slug="monitor-tenant")
        db.add(tenant)
        db.flush()
        point = _add_point(
            db,
            tenant.id,
            name="monitor-only-native",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        point.state = "monitoring"
        point.mode = "monitor"
        db.commit()

        result = select_and_persist_authorization(
            db,
            request=_request(tenant.id, point.id),
            now=NOW,
        )

        assert result.primary_control_point is None
        rejection = next(row for row in result.rejected_candidates if row.control_point_id == point.id)
        assert "blocking_semantics_unavailable" in rejection.reason_codes
    engine.dispose()


def test_unbound_request_cannot_select_an_unrelated_healthy_control_point() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Unbound Tenant", slug="unbound-tenant")
        db.add(tenant)
        db.flush()
        _add_point(
            db,
            tenant.id,
            name="healthy-but-unbound",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        db.commit()

        result = select_and_persist_authorization(db, request=_request(tenant.id), now=NOW)

        assert result.primary_control_point is None
        assert result.selection_reason == "CONTROL_REQUIREMENT_UNSATISFIED"
    engine.dispose()


def test_provider_specific_default_off_remains_monitor_only_without_changing_decision() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Provider Flag Tenant", slug="provider-flag-tenant")
        db.add(tenant)
        db.flush()
        point = _add_point(
            db,
            tenant.id,
            name="provider-disabled",
            method="native_hook",
            capabilities=_capabilities(execution="inline_bound"),
        )
        db.commit()
        request = _request(tenant.id, point.id)
        response = authorize_ai_action(request)
        rollout = AuthorizationRolloutOutcome(
            authoritative_decision=response.decision,
            metadata={},
            v2_response=response,
            enforced=True,
            request=request,
        )

        applied = apply_native_selection_to_rollout(
            db,
            rollout=rollout,
            settings_obj=type(
                "Settings",
                (),
                {
                    "native_control_framework": True,
                    "trusted_control_selector": True,
                    "native_control_enforce": True,
                    "native_control_openai": False,
                },
            )(),
            now=NOW,
        )

        assert applied.authoritative_decision == rollout.authoritative_decision
        assert applied.v2_response == rollout.v2_response
        assert applied.request.path_evidence["native_control_provider_enforce_enabled"] is False
    engine.dispose()


def test_configured_route_provider_cannot_be_spoofed_to_disable_fail_closed() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Spoof Resistant", slug="spoof-resistant")
        db.add(tenant)
        db.flush()
        point = _add_point(
            db,
            tenant.id,
            name="spoof-resistant-gateway",
            method="gateway_inline",
            capabilities=_capabilities(execution="inline_bound"),
        )
        point.health_state = "degraded"
        db.commit()
        request = _request(tenant.id).model_copy(
            deep=True,
            update={"discovery_context": {"provider": "unknown", "product": "custom"}},
        )
        response = authorize_ai_action(request)
        rollout = AuthorizationRolloutOutcome(
            authoritative_decision=response.decision,
            metadata={},
            v2_response=response,
            enforced=True,
            request=request,
        )
        settings_obj = type(
            "Settings",
            (),
            {
                "native_control_framework": True,
                "trusted_control_selector": True,
                "native_control_enforce": True,
                "native_control_openai": True,
                "native_control_route_bindings_json": json.dumps(
                    {
                        tenant.id: {
                            "mcp_gateway": {
                                "integration_instance_ids": [point.id],
                                "provider": "openai",
                                "provider_version": "1.5.0",
                                "adapter_version": "1.0.0",
                                "product": "direct_api",
                            }
                        }
                    }
                ),
            },
        )()

        applied = apply_native_selection_to_rollout(
            db,
            rollout=rollout,
            settings_obj=settings_obj,
            now=NOW,
        )

        assert applied.authoritative_decision == "block"
        assert applied.v2_response is not None
        assert "CONTROL_REQUIREMENT_UNSATISFIED" in applied.v2_response.matched_rules
        assert applied.request is not None
        assert applied.request.discovery_context["provider"] == "openai"
        assert applied.request.path_evidence["native_control_provider_enforce_enabled"] is True
    engine.dispose()
