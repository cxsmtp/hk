from __future__ import annotations

import os
import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.audit import AuditLog
from app.db.models.evidence import DecisionReceipt, EvidenceNode, ExecutionIntegrityResult, ExecutionReceipt
from app.db.models.finding import Finding
from app.db.models.policy import ApprovalBinding, ApprovalRequest
from app.db.models.tenant import Tenant
from app.db.models.user import User
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.activity_audit import AIAction
from app.db.session import Base
from app.core.config import settings
from app.core.control_engine.authorization import apply_trusted_pre_action_rollout
from app.services.mcp.context import MCPExecutionContext
from app.services.mcp.contracts import ToolContract, ToolRegistration
from app.services.mcp.registry import MCPToolRegistry
from app.services.mcp import registry as registry_module
from app.services.receipt_service import (
    ExecutionAttemptConflictError,
    canonical_action_from_authorization,
)
from app.services import receipt_service as receipt_contract


@pytest.fixture()
def test_db(tmp_path):
    db_file = tmp_path / "mcp_registry.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    try:
        with session_local() as db:
            yield db
            db.rollback()
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _seed_core_entities(db: Session) -> tuple[Tenant, User, AISystem]:
    suffix = uuid4().hex[:8]
    tenant = Tenant(
        name="Acme Tenant",
        slug=f"acme-{suffix}",
        is_active=True,
        platform_mode="enforce",
    )
    user = User(
        email=f"owner-{suffix}@acme.ai",
        hashed_password="x",
        full_name="Owner",
        is_active=True,
    )
    db.add_all([tenant, user])
    db.flush()

    ai_system = AISystem(
        tenant_id=tenant.id,
        name="MCP Tool AI",
        description="MCP test system",
        risk_tier="HIGH",
        status="active",
        metadata_json={},
    )
    db.add(ai_system)
    db.flush()
    return tenant, user, ai_system


def _base_context(*, tenant_id: str, user_id: str, user_role: str, ai_system_id: str | None = None) -> MCPExecutionContext:
    return MCPExecutionContext(
        tenant_id=tenant_id,
        user_id=user_id,
        user_role=user_role,
        platform_mode="enforce",
        correlation_id="corr-mcp-tests",
        ai_system_id=ai_system_id,
        risk_tier="HIGH",
        governance_version="v1",
        policy_version_id=None,
        brain_session_id="brain-session-1",
        brain_plan_id="brain-plan-1",
    )


def _internal_receipt_registry() -> MCPToolRegistry:
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.internal_approval_receipt",
                module="test",
                version="1.0.0",
                description="Internal approval receipt integration tool",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    return registry


def _enable_internal_receipts(
    monkeypatch: pytest.MonkeyPatch,
    tenant_id: str,
    *,
    authoritative: bool = False,
) -> None:
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce_rollout", f'{{"{tenant_id}":["internal_mcp"]}}')
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "internal-approval-binding-key-000001")
    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr(settings, "receipt_signing_active_key_id", "internal-approval-receipt-key")
    monkeypatch.setattr(
        settings,
        "receipt_signing_keys_json",
        '{"internal-approval-receipt-key":"internal-approval-receipt-signing-material-001"}',
    )
    # Do not inherit process-level native-control flags into tests that only
    # exercise the receipt seam.  Authoritative tests opt in explicitly.
    monkeypatch.setattr(settings, "native_control_framework", authoritative)
    monkeypatch.setattr(settings, "trusted_control_selector", authoritative)


def _seed_current_profile_selection(
    db: Session,
    *,
    provider,
    tenant_id: str,
) -> None:
    from app.services.action_integrity.stored_authority import (
        append_profile_selection_v1,
        issue_domain_semantic_profile_v1,
    )

    now = datetime.now(timezone.utc)
    profile = issue_domain_semantic_profile_v1(
        db,
        provider=provider,
        tenant_id=tenant_id,
        profile_id="profile:mcp-authoritative",
        version="1",
        status="reviewed",
        content={"materiality": "mcp-authoritative"},
        issued_at=now,
        effective_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    append_profile_selection_v1(
        db,
        provider=provider,
        tenant_id=tenant_id,
        profile=profile,
        policy_epoch=1,
        selected_by_principal_ref="user:owner",
        reason_code="mcp-authoritative-test",
        issued_at=now,
        effective_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    db.flush()


def _seed_authoritative_internal_mcp_control(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
    *,
    tenant_id: str,
) -> None:
    from app.db.models.native_control import (
        ControlCapabilityProfileRecord,
        NativeControlIntegration,
        NativeControlValidation,
        NativeWorkloadCredential,
    )
    from app.services.native_control.health import record_health_observation
    from app.services.native_control.integrity import integration_configuration_fingerprint

    now = datetime.now(timezone.utc)
    contract_hash = hashlib.sha256(b"hawk:internal-mcp-registry:gateway-inline:1").hexdigest()
    verified = lambda level: {  # noqa: E731 - compact typed fixture declaration
        "level": level,
        "verification_status": "verified",
        "evidence_refs": ["evidence:internal-mcp-acceptance"],
    }
    capabilities = {
        "identity": verified("inline_bound"),
        "tool_control": verified("inline_bound"),
        "mcp_control": verified("inline_bound"),
        "parameter_binding": verified("inline_bound"),
        "target_binding": verified("inline_bound"),
        "destination_binding": verified("inline_bound"),
        "post_execution_verification": verified("inline_bound"),
        "persistent_side_effect_control": verified("observe"),
        "containment": verified("external"),
    }
    profile = ControlCapabilityProfileRecord(
        manifest_id="hawk:internal-mcp-registry:gateway-inline",
        manifest_version="provider-capability-manifest/1.0",
        matrix_version="matrix-test",
        provider="hawk",
        product="internal_mcp_registry",
        runtime="hawk_api",
        integration_method="gateway_inline",
        adapter_version="1.0.0",
        tested_min_version="1.0.0",
        tested_max_version="1.0.0",
        current_verified_version="1.0.0",
        verification_status="verified",
        verification_source="authoritative_internal_mcp_test",
        verified_at=now,
        capabilities=capabilities,
        security_properties={
            "pre_execution_capable": True,
            "post_execution_capable": True,
            "blocking_strength": 100,
            "action_fidelity": 100,
            "identity_quality": 100,
            "parameter_fidelity": 100,
            "target_fidelity": 100,
            "destination_fidelity": 100,
            "result_fidelity": 100,
            "bypass_resistance": 100,
            "tamper_resistance": 100,
            "expected_latency_ms": 10,
            "availability_profile": "test",
            "required_permissions": [],
            "privacy_impact": "metadata_only",
        },
        health_requirements=[],
        degradation_modes=["fail_closed"],
        known_blind_spots=[],
        documentation_references=["test:authoritative-internal-mcp"],
        supported_action_classes=["function_tool"],
        supported_control_methods=["gateway_inline"],
        contract_hash=contract_hash,
        manifest_fingerprint=hashlib.sha256(b"internal-mcp-profile").hexdigest(),
        active=True,
    )
    db.add(profile)
    db.flush()
    integration = NativeControlIntegration(
        tenant_id=tenant_id,
        capability_profile_id=profile.id,
        instance_key="internal-mcp-registry",
        display_name="Hawk internal MCP registry",
        provider="hawk",
        product="internal_mcp_registry",
        model_provider="hawk",
        model="internal",
        runtime="hawk_api",
        execution_location="CUSTOMER_RUNTIME",
        deployment_reference="runtime:hawk-api",
        integration_method="gateway_inline",
        deployment_family="runtime",
        environment="internal",
        state="enforcing",
        mode="enforce",
        health_state="healthy",
        health_reasons=[],
        provider_version="1.0.0",
        adapter_version="1.0.0",
        contract_hash=contract_hash,
        policy_version="internal-mcp-registry",
        policy_fresh_until=now + timedelta(hours=1),
        degradation_mode="fail_closed",
        capability_snapshot=capabilities,
        known_blind_spots=[],
        last_validated_at=now,
    )
    db.add(integration)
    db.flush()
    integration.configuration_fingerprint = integration_configuration_fingerprint(integration)
    integration.expected_configuration_fingerprint = integration.configuration_fingerprint
    credential_id = "credential-internal-mcp-registry"
    db.add(
        NativeWorkloadCredential(
            tenant_id=tenant_id,
            integration_instance_id=integration.id,
            credential_id=credential_id,
            credential_epoch=1,
            public_key_pem="test-public-key",
            key_thumbprint=hashlib.sha256(b"internal-mcp-credential").hexdigest(),
            signature_algorithm="ES256",
            environment="internal",
            allowed_event_types=["before_tool"],
            status="active",
            expires_at=now + timedelta(hours=1),
        )
    )
    db.add(
        NativeControlValidation(
            tenant_id=tenant_id,
            integration_instance_id=integration.id,
            validation_version="native-control-validation/2.0",
            credential_id=credential_id,
            credential_epoch=1,
            safe_synthetic=False,
            acceptance_state="REAL_CLOUD_RUNTIME_ACCEPTED",
            deployment_environment="internal",
            provider="hawk",
            product="internal_mcp_registry",
            runtime="hawk_api",
            model_provider="hawk",
            model="internal",
            route_identity=f"native-control:{integration.id}",
            deployment_identity="integration:internal-mcp-registry",
            execution_location="CUSTOMER_RUNTIME",
            deployment_reference="runtime:hawk-api",
            action_classes=["function_tool"],
            control_methods=["gateway_inline"],
            lifecycle_events=["before_tool"],
            provider_version="1.0.0",
            adapter_version="1.0.0",
            contract_hash=contract_hash,
            acceptance_run_id="acceptance-internal-mcp-registry",
            allow_result="passed",
            block_result="passed",
            non_execution_result="passed",
            checks={"all": True},
            result="passed",
            reason_codes=[],
            evidence_refs=["evidence:internal-mcp-acceptance"],
            validated_at=now,
        )
    )
    record_health_observation(
        db,
        tenant_id=tenant_id,
        integration_id=integration.id,
        credential_id=credential_id,
        credential_epoch=1,
        provider_event_id="health-internal-mcp-registry",
        provider_event_type="before_tool",
        callback_authenticated=True,
        evidence_flowing=True,
        latency_ms=10,
        source="signed_native_callback",
        evidence_ref="evidence:internal-mcp-health",
        observed_at=now,
    )
    db.flush()
    monkeypatch.setattr(
        settings,
        "native_control_route_bindings_json",
        json.dumps(
            {
                tenant_id: {
                    "internal_mcp": {
                        "integration_instance_ids": [integration.id],
                        "provider": "hawk",
                        "provider_version": "1.0.0",
                        "adapter_version": "1.0.0",
                        "product": "internal_mcp_registry",
                    }
                }
            }
        ),
    )


def _internal_exact_approval_material(
    *, tenant_id: str, user_id: str
) -> dict[str, dict | str]:
    registry = _internal_receipt_registry()
    contract = registry.get("test.internal_approval_receipt").contract
    context = _base_context(tenant_id=tenant_id, user_id=user_id, user_role="viewer")
    args_hash = hashlib.sha256(b"{}").hexdigest()
    tool_fingerprint = hashlib.sha256(
        json.dumps(
            {"module": contract.module, "name": contract.tool_name, "version": contract.version},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    outcome = apply_trusted_pre_action_rollout(
        tenant_id=tenant_id,
        surface="internal_mcp",
        action_id=context.correlation_id,
        chain_id=context.brain_plan_id,
        collector_id="internal-mcp-registry",
        trusted_pre_action_governance_check={
            "action_id": context.correlation_id,
            "actor": {
                "identity_id": user_id,
                "identity_type": "human",
                "user_id": user_id,
                "session_id": context.brain_session_id,
            },
            "authority": {
                "authority_type": "internal_mcp_role",
                "authority_source": "server_tool_registry",
                "verified": True,
            },
            "surface": {
                "application": "hawk_internal_mcp",
                "asset_status": "registered",
                "environment": "internal",
            },
            "action": {
                "action_type": "tool_execution",
                "action_risk": context.risk_tier.lower(),
                "tool_name": contract.tool_name,
                "tool_version": contract.version,
                "tool_fingerprint_id": tool_fingerprint,
                "parameter_hash": args_hash,
                "target_resource": contract.module,
                "side_effect_class": contract.side_effect_level,
                "persistent_side_effect": contract.side_effect_level != "read",
            },
            "policy": {"policy_snapshot_id": "internal-mcp-registry", "control_ids": []},
        },
        legacy_decision="allow",
        legacy_reason="internal_mcp_registry_allow",
        legacy_control_mode="inline_allowed",
        policy_snapshot_id="internal-mcp-registry",
        settings_obj=settings,
    )
    assert outcome.request is not None and outcome.v2_response is not None
    canonical = canonical_action_from_authorization(outcome.request, outcome.v2_response)
    material = receipt_contract._canonical_material(canonical, tenant_id=tenant_id)
    return {
        "canonical_action_hash": material["canonical_action_hash"],
        "material_fields": receipt_contract._approval_material(material),
        "receipt_material_hash": receipt_contract._hash(
            receipt_contract._approval_material(material)
        ),
    }


def test_mcp_registry_schema_validation(test_db: Session) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    registry = MCPToolRegistry()

    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.schema_valid",
                module="test",
                version="1.0.0",
                description="Schema validation tool",
                input_schema={
                    "type": "object",
                    "properties": {
                        "value": {"type": "string", "minLength": 1},
                    },
                    "required": ["value"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean"},
                    },
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )

    context = _base_context(
        tenant_id=tenant.id,
        user_id=user.id,
        user_role="viewer",
    )
    result = registry.execute(
        db=db,
        context=context,
        tool_name="test.schema_valid",
        args={"value": "x"},
    )
    db.commit()
    assert result == {"ok": True}

    with pytest.raises(ValueError, match="input.value is required"):
        registry.execute(
            db=db,
            context=context,
            tool_name="test.schema_valid",
            args={},
        )

    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.output_invalid",
                module="test",
                version="1.0.0",
                description="Invalid output tool",
                input_schema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"unexpected": True},
        )
    )

    with pytest.raises(ValueError, match="output.ok is required"):
        registry.execute(
            db=db,
            context=context,
            tool_name="test.output_invalid",
            args={},
        )


def test_internal_mcp_execution_emits_shadow_runtime_and_activity_pair(
    test_db: Session, monkeypatch
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.commit()
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.internal_shadow",
                module="test",
                version="1.0.0",
                description="Internal shadow tool",
                input_schema={
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "internal-mcp-shadow-binding-key-0001")

    result = registry.execute(
        db=db,
        context=_base_context(
            tenant_id=tenant.id,
            user_id=user.id,
            user_role="viewer",
        ),
        tool_name="test.internal_shadow",
        args={"value": "do-not-persist-raw"},
    )
    db.commit()

    assert result == {"ok": True}
    runtime = db.scalar(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant.id,
            RuntimeEvent.source_surface == "internal_mcp",
        )
    )
    assert runtime is not None
    activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime.event_id))
    assert activity is not None
    shadow = runtime.metadata_json["authorization_kernel_v2_shadow"]
    assert shadow == activity.metadata_json["authorization_kernel_v2_shadow"]
    assert shadow["v2"]["decision"] == "allow"
    assert "do-not-persist-raw" not in str(shadow)


def test_selected_internal_mcp_persists_one_matched_receipt_pair(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.commit()
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.internal_receipt",
                module="test",
                version="1.0.0",
                description="Internal receipt integration tool",
                input_schema={
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        f'{{"{tenant.id}":["internal_mcp"]}}',
    )
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "internal-receipt-binding-key-0000001")
    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr(settings, "receipt_signing_active_key_id", "internal-receipt-key")
    monkeypatch.setattr(
        settings,
        "receipt_signing_keys_json",
        '{"internal-receipt-key":"internal-receipt-signing-material-000001"}',
    )

    result = registry.execute(
        db=db,
        context=_base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer"),
        tool_name="test.internal_receipt",
        args={"value": "hashed-before-storage"},
    )
    db.commit()
    assert result == {"ok": True}
    decision = db.scalar(select(DecisionReceipt).where(DecisionReceipt.tenant_id == tenant.id))
    assert decision is not None
    assert db.scalar(
        select(func.count(DecisionReceipt.receipt_id)).where(DecisionReceipt.tenant_id == tenant.id)
    ) == 1
    execution = db.scalar(
        select(ExecutionReceipt).where(
            ExecutionReceipt.tenant_id == tenant.id,
            ExecutionReceipt.decision_receipt_id == decision.receipt_id,
        )
    )
    assert execution is not None and execution.execution_status == "success"
    integrity = db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.tenant_id == tenant.id,
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
        )
    )
    assert integrity is not None and integrity.result == "matched"
    assert "hashed-before-storage" not in str(decision.__dict__)


def test_authoritative_mcp_post_callback_observation_drives_lifecycle_and_action_detail(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only a post-callback execution observation may create matched proof."""
    from app.db.models.action_integrity import (
        ExecutionComparisonV2,
        ExecutionPermitV2,
        DelegationContextV2,
        OutcomeVerificationV2,
        PersistentEffectV2,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.services.action_integrity.action_detail import materialize_action_detail
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.mcp.contracts import MCPExecutionObservation, MCPExecutionResult

    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.add_all(
        [
            TenantPolicyEpoch(tenant_id=tenant.id, epoch=1),
            TenantActionIntegrityRollout(
                tenant_id=tenant.id,
                mode="AUTHORITATIVE",
                policy_epoch=1,
            ),
        ]
    )
    db.commit()
    _enable_internal_receipts(monkeypatch, tenant.id, authoritative=True)
    provider = LocalSigningKeyProvider(development=True)
    for purpose, key_id, secret in (
        ("domain_profile_signing", "profile", b"f" * 32),
        ("domain_profile_selection_signing", "profile-selection", b"s" * 32),
        ("execution_permit_signing", "permit", b"p" * 32),
        ("decision_receipt_signing", "decision", b"d" * 32),
        ("execution_receipt_signing", "receipt", b"r" * 32),
        ("execution_comparison_signing", "comparison", b"c" * 32),
        ("action_plan_signing", "lifecycle", b"l" * 32),
        ("delegation_context_signing", "delegation", b"g" * 32),
        ("persistent_effect_signing", "effect", b"x" * 32),
        ("outcome_verification_signing", "outcome", b"o" * 32),
    ):
        provider.add_key(purpose=purpose, tenant_id=tenant.id, key_id=key_id, secret=secret)
    db.info["phase5_signing_provider"] = provider
    _seed_current_profile_selection(db, provider=provider, tenant_id=tenant.id)
    _seed_authoritative_internal_mcp_control(
        db, monkeypatch, tenant_id=tenant.id
    )
    lifecycle_evidence = EvidenceNode(
        tenant_id=tenant.id,
        correlation_id="mcp-observed-detail",
        node_type="mcp_execution_observation",
        signal_type="mcp.execution.observed",
        label="Observed internal MCP lifecycle evidence",
        payload={
            "source": "test_executor_callback",
            "raw_content_retained": False,
        },
    )
    db.add(lifecycle_evidence)
    db.flush()

    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.authoritative_observed", module="test", version="1.0.0",
                description="Post-callback observed MCP tool",
                input_schema={"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"], "additionalProperties": False},
                output_schema={"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False},
                required_role=["viewer"], requires_approval=False, writes_evidence=False, side_effect_level="read",
                citations_supported=False, governance_scope_required=False, tenant_scope_required=True, idempotent=True, timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: MCPExecutionResult(
                output={"ok": True},
                observation=MCPExecutionObservation(
                    actual_args={"value": "mutated-after-callback"},
                    tool_or_service_ref="test.authoritative_observed",
                    target_ref="test:observed-target",
                    operation="tool_execution",
                    persistent_effect={"downstream_object_hash": "d" * 64, "expected_object_state_hash": "e" * 64, "state": "APPLIED", "evidence_refs": [lifecycle_evidence.id]},
                    expected_outcome={"expected_state_hash": "e" * 64, "evidence_refs": [lifecycle_evidence.id]},
                    outcome_verification={"result": "MATCHED", "verification_source_set_hash": "s" * 64, "evidence_quality": "VERIFIED", "evidence_refs": [lifecycle_evidence.id]},
                    delegated_child={
                        "delegated_action_id": "delegated-observed-child",
                        "parent_scope": {"resources": ["test:observed-target"], "operations": ["tool_execution"], "max_value": "10"},
                        "child_scope": {"resources": ["test:observed-target"], "operations": ["tool_execution"], "max_value": "9"},
                        "source_principal_ref": "service:internal-mcp-registry",
                        "destination_principal_ref": "service:observed-child",
                    },
                ),
            ),
        )
    )
    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer").model_copy(
        update={"risk_tier": "low", "correlation_id": "mcp-observed-detail"}
    )
    assert registry.execute(db=db, context=context, tool_name="test.authoritative_observed", args={"value": "authorized"}) == {"ok": True}
    db.commit()

    comparison = db.scalar(select(ExecutionComparisonV2).where(ExecutionComparisonV2.tenant_id == tenant.id))
    permit = db.scalar(select(ExecutionPermitV2).where(ExecutionPermitV2.tenant_id == tenant.id))
    runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.tenant_id == tenant.id, RuntimeEvent.correlation_id == "mcp-observed-detail"))
    assert comparison is not None and comparison.result == "DRIFTED"
    assert permit is not None
    assert db.scalar(select(PersistentEffectV2).where(PersistentEffectV2.tenant_id == tenant.id)) is not None
    assert db.scalar(select(OutcomeVerificationV2).where(OutcomeVerificationV2.tenant_id == tenant.id)) is not None
    assert db.scalar(select(DelegationContextV2).where(DelegationContextV2.tenant_id == tenant.id)) is not None
    assert runtime is not None and runtime.metadata_json["action_id"] == permit.action_id
    detail = materialize_action_detail(db, tenant_id=tenant.id, runtime_event_id=runtime.event_id)
    assert detail is not None
    assert detail["identity"]["action_id"] == permit.action_id
    assert detail["execution"]["material_integrity"]["value"]["result"] == "DRIFTED"
    assert detail["execution"]["outcome_integrity"]["state"] == "OBSERVED"
    persistent_effect = next(
        item for item in detail["timeline"] if item["event_type"] == "PERSISTENT_EFFECT"
    )
    assert persistent_effect["state"] == "OBSERVED"


def test_authoritative_mcp_without_post_callback_observation_stays_unknown(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain dict result is not a post-callback execution observation."""
    from app.db.models.action_integrity import (
        ExecutionComparisonV2,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.services.action_integrity.action_detail import materialize_action_detail
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.add_all(
        [
            TenantPolicyEpoch(tenant_id=tenant.id, epoch=1),
            TenantActionIntegrityRollout(
                tenant_id=tenant.id,
                mode="AUTHORITATIVE",
                policy_epoch=1,
            ),
        ]
    )
    db.commit()
    _enable_internal_receipts(monkeypatch, tenant.id, authoritative=True)
    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="domain_profile_signing", tenant_id=tenant.id, key_id="profile", secret=b"f" * 32)
    provider.add_key(purpose="domain_profile_selection_signing", tenant_id=tenant.id, key_id="profile-selection", secret=b"s" * 32)
    provider.add_key(purpose="execution_permit_signing", tenant_id=tenant.id, key_id="permit", secret=b"p" * 32)
    provider.add_key(purpose="decision_receipt_signing", tenant_id=tenant.id, key_id="decision", secret=b"d" * 32)
    db.info["phase5_signing_provider"] = provider
    _seed_current_profile_selection(db, provider=provider, tenant_id=tenant.id)
    _seed_authoritative_internal_mcp_control(
        db, monkeypatch, tenant_id=tenant.id
    )
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.authoritative_unknown", module="test", version="1.0.0",
                description="MCP tool without an execution observer",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                output_schema={"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False},
                required_role=["viewer"], requires_approval=False, writes_evidence=False, side_effect_level="read",
                citations_supported=False, governance_scope_required=False, tenant_scope_required=True, idempotent=True, timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer").model_copy(
        update={"risk_tier": "low", "correlation_id": "mcp-no-observation"}
    )
    assert registry.execute(db=db, context=context, tool_name="test.authoritative_unknown", args={}) == {"ok": True}
    db.commit()

    assert db.scalar(select(ExecutionComparisonV2).where(ExecutionComparisonV2.tenant_id == tenant.id)) is None
    runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.tenant_id == tenant.id, RuntimeEvent.correlation_id == "mcp-no-observation"))
    assert runtime is not None and runtime.metadata_json.get("action_id")
    detail = materialize_action_detail(db, tenant_id=tenant.id, runtime_event_id=runtime.event_id)
    assert detail is not None
    assert detail["execution"]["material_integrity"]["state"] == "UNKNOWN"


def test_selected_internal_mcp_server_binds_one_exact_active_approval(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    _enable_internal_receipts(monkeypatch, tenant.id)
    exact = _internal_exact_approval_material(tenant_id=tenant.id, user_id=user.id)
    now = datetime.now(timezone.utc)
    binding = ApprovalBinding(
        tenant_id=tenant.id,
        chain_id="brain-plan-1",
        action_id="corr-mcp-tests",
        approval_id="internal-approval-one",
        canonical_action_hash=exact["canonical_action_hash"],
        receipt_material_hash=exact["receipt_material_hash"],
        signed_receipt="server-signed-approval-one",
        material_fields=exact["material_fields"],
        approved_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=10),
        status="active",
    )
    db.add(binding)
    db.commit()

    result = _internal_receipt_registry().execute(
        db=db,
        context=_base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer"),
        tool_name="test.internal_approval_receipt",
        args={},
    )
    db.commit()
    decision = db.scalar(
        select(DecisionReceipt).where(DecisionReceipt.tenant_id == tenant.id)
    )
    assert result == {"ok": True}
    assert decision is not None and decision.approval_binding_id == binding.id
    assert decision.approval_binding_hash not in {"unknown", binding.canonical_action_hash}


def test_selected_internal_mcp_rejects_ambiguous_exact_active_approvals(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    now = datetime.now(timezone.utc)
    for index in range(2):
        db.add(
            ApprovalBinding(
                tenant_id=tenant.id,
                chain_id="brain-plan-1",
                action_id="corr-mcp-tests",
                approval_id=f"internal-approval-{index}",
                canonical_action_hash="legacy-domain-not-v1",
                signed_receipt=f"server-signed-approval-{index}",
                material_fields={"source": "server", "index": index},
                approved_at=now - timedelta(minutes=1),
                expires_at=now + timedelta(minutes=10),
                status="active",
            )
        )
    db.commit()
    _enable_internal_receipts(monkeypatch, tenant.id)

    with pytest.raises(ValueError, match="ambiguous"):
        _internal_receipt_registry().execute(
            db=db,
            context=_base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer"),
            tool_name="test.internal_approval_receipt",
            args={},
        )
    assert db.scalar(
        select(func.count(DecisionReceipt.receipt_id)).where(DecisionReceipt.tenant_id == tenant.id)
    ) == 0


def test_selected_internal_mcp_handler_failure_keeps_known_failure_receipt_on_rollback(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.commit()
    registry = MCPToolRegistry()

    def _fail_handler(_db, _ctx, _args):
        raise RuntimeError("handler failed")

    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.internal_receipt_failure",
                module="test",
                version="1.0.0",
                description="Internal receipt failure tool",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=_fail_handler,
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        f'{{"{tenant.id}":["internal_mcp"]}}',
    )
    monkeypatch.setattr(settings, "canonical_action_binding_key", "internal-failure-binding-key-0000001")
    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr(settings, "receipt_signing_active_key_id", "internal-failure-key")
    monkeypatch.setattr(
        settings,
        "receipt_signing_keys_json",
        '{"internal-failure-key":"internal-failure-signing-material-00000001"}',
    )

    with pytest.raises(RuntimeError, match="handler failed"):
        registry.execute(
            db=db,
            context=_base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer"),
            tool_name="test.internal_receipt_failure",
            args={},
        )
    db.rollback()
    decision = db.scalar(select(DecisionReceipt).where(DecisionReceipt.tenant_id == tenant.id))
    assert decision is not None
    execution = db.scalar(
        select(ExecutionReceipt).where(
            ExecutionReceipt.decision_receipt_id == decision.receipt_id
        )
    )
    assert execution is not None and execution.execution_status == "failure"
    assert execution.signature and execution.evidence_node_id
    integrity = db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id
        )
    )
    assert integrity is not None and integrity.result == "matched"
    assert integrity.execution_receipt_id == execution.receipt_id


def test_internal_mcp_post_commit_persistence_failure_creates_fallback_finding(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.commit()
    _enable_internal_receipts(monkeypatch, tenant.id)

    def _fail_post_commit(**_kwargs):
        raise RuntimeError("post-commit persistence unavailable")

    monkeypatch.setattr(MCPToolRegistry, "_persist_shadow_runtime_event", _fail_post_commit)
    assert _internal_receipt_registry().execute(
        db=db,
        context=_base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer"),
        tool_name="test.internal_approval_receipt",
        args={},
    ) == {"ok": True}
    db.commit()
    decision = db.scalar(select(DecisionReceipt).where(DecisionReceipt.tenant_id == tenant.id))
    integrity = db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id
        )
    )
    assert integrity is not None and integrity.result == "incomplete" and integrity.signature
    fallback_finding = db.scalar(
        select(Finding).where(
            Finding.tenant_id == tenant.id,
            Finding.finding_type == "EXECUTION_RECEIPT_PERSISTENCE_FAILURE",
        )
    )
    assert fallback_finding is not None, {
        "findings": list(db.scalars(select(Finding.finding_type)).all()),
        "integrity_attempt": integrity.execution_attempt_id,
        "integrity_evidence": integrity.evidence_bundle_id,
    }


def test_internal_mcp_terminal_attempt_conflict_is_durable_deduped_and_fails_closed(
    test_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    tenant_id = tenant.id
    user_id = user.id
    engine = db.get_bind()
    db.commit()
    _enable_internal_receipts(monkeypatch, tenant_id)
    monkeypatch.setattr(registry_module, "uuid4", lambda: "fixed-internal-mcp-attempt")
    registry = _internal_receipt_registry()
    result_state = {"ok": True}
    registration = registry.get("test.internal_approval_receipt")
    assert registration is not None
    registration.executor = lambda _db, _ctx, _args: dict(result_state)
    context = _base_context(tenant_id=tenant_id, user_id=user_id, user_role="viewer")

    assert registry.execute(
        db=db,
        context=context,
        tool_name="test.internal_approval_receipt",
        args={},
    ) == {"ok": True}
    db.commit()

    result_state["ok"] = False
    assert registry.execute(
        db=db,
        context=context,
        tool_name="test.internal_approval_receipt",
        args={},
    ) == {"ok": False}
    with pytest.raises(ExecutionAttemptConflictError):
        db.commit()
    db.close()

    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with session_local() as reopened:
        conflict = reopened.scalar(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.finding_type == "EXECUTION_ATTEMPT_CONFLICT",
                Finding.execution_attempt_id == "fixed-internal-mcp-attempt",
            )
        )
        assert conflict is not None
        assert reopened.scalar(
            select(func.count(Finding.finding_id)).where(
                Finding.tenant_id == tenant_id,
                Finding.finding_type == "EXECUTION_ATTEMPT_CONFLICT",
                Finding.execution_attempt_id == "fixed-internal-mcp-attempt",
            )
        ) == 1

    with session_local() as repeated:
        assert registry.execute(
            db=repeated,
            context=context,
            tool_name="test.internal_approval_receipt",
            args={},
        ) == {"ok": False}
        with pytest.raises(ExecutionAttemptConflictError):
            repeated.commit()

    with session_local() as reopened:
        assert reopened.scalar(
            select(func.count(Finding.finding_id)).where(
                Finding.tenant_id == tenant_id,
                Finding.finding_type == "EXECUTION_ATTEMPT_CONFLICT",
                Finding.execution_attempt_id == "fixed-internal-mcp-attempt",
            )
        ) == 1


def test_internal_mcp_shadow_failure_isolated_from_tool_transaction(
    test_db: Session, monkeypatch
) -> None:
    from app.services.runtime_intelligence import runtime_event_normalizer

    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.commit()
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.shadow_isolation",
                module="test",
                version="1.0.0",
                description="Shadow transaction isolation tool",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    isolated_sessions: list[Session] = []

    def fail_in_isolated_session(shadow_db: Session, **_kwargs):
        isolated_sessions.append(shadow_db)
        shadow_db.add(Tenant(name="duplicate", slug=tenant.slug, is_active=True, platform_mode="enforce"))
        shadow_db.flush()
        raise AssertionError("unreachable")

    monkeypatch.setattr(runtime_event_normalizer, "ingest_runtime_event", fail_in_isolated_session)

    result = registry.execute(
        db=db,
        context=_base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer"),
        tool_name="test.shadow_isolation",
        args={},
    )
    db.commit()

    assert result == {"ok": True}
    assert isolated_sessions and isolated_sessions[0] is not db
    assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.tenant_id == tenant.id)) >= 1
    assert db.scalar(select(func.count(Tenant.id)).where(Tenant.slug == tenant.slug)) == 1


def test_internal_mcp_shadow_queue_clears_on_rollback_and_emits_once_per_execution(
    test_db: Session, monkeypatch
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    db.commit()
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.shadow_queue",
                module="test",
                version="1.0.0",
                description="Shadow queue semantics tool",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "internal-mcp-queue-binding-key-0001")
    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer")

    registry.execute(db=db, context=context, tool_name="test.shadow_queue", args={})
    assert len(db.info["internal_mcp_shadow_events"]) == 1
    db.rollback()
    assert "internal_mcp_shadow_events" not in db.info
    assert db.scalar(select(func.count(RuntimeEvent.event_id)).where(RuntimeEvent.tenant_id == tenant.id)) == 0
    db.rollback()

    registry.execute(db=db, context=context, tool_name="test.shadow_queue", args={})
    registry.execute(db=db, context=context, tool_name="test.shadow_queue", args={})
    assert len(db.info["internal_mcp_shadow_events"]) == 2
    db.commit()

    assert db.scalar(select(func.count(RuntimeEvent.event_id)).where(RuntimeEvent.tenant_id == tenant.id)) == 2


def test_selected_internal_mcp_v2_blocks_before_handler_side_effect(
    test_db: Session, monkeypatch
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    calls: list[str] = []
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.v2_pre_handler",
                module="test",
                version="1.0.0",
                description="Pre-handler authorization tool",
                input_schema={
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: calls.append("executed") or {"ok": True},
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        f'{{"{tenant.id}":["internal_mcp"]}}',
    )
    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer").model_copy(
        update={"risk_tier": "caller-invented-risk"}
    )

    with pytest.raises(PermissionError, match="authorization_kernel_v2:risk_classification_invalid"):
        registry.execute(
            db=db,
            context=context,
            tool_name="test.v2_pre_handler",
            args={"value": "x"},
        )

    assert calls == []


def test_selected_internal_mcp_v2_persists_precomputed_metadata_once(
    test_db: Session, monkeypatch
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.v2_selected_read",
                module="test",
                version="1.0.0",
                description="Selected read tool",
                input_schema={
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        f'{{"{tenant.id}":["internal_mcp"]}}',
    )
    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer").model_copy(
        update={"risk_tier": "low", "correlation_id": "internal-mcp-v2-selected"}
    )

    assert registry.execute(
        db=db,
        context=context,
        tool_name="test.v2_selected_read",
        args={"value": "x"},
    ) == {"ok": True}
    db.commit()

    runtime = db.scalar(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant.id,
            RuntimeEvent.source_surface == "internal_mcp",
            RuntimeEvent.correlation_id == "internal-mcp-v2-selected",
        )
    )
    assert runtime is not None
    activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime.event_id))
    assert activity is not None
    assert runtime.metadata_json["authorization_kernel_v2_shadow"] == activity.metadata_json[
        "authorization_kernel_v2_shadow"
    ]
    assert runtime.metadata_json["authorization_kernel_v2_shadow_health"] == activity.metadata_json[
        "authorization_kernel_v2_shadow_health"
    ]
    assert runtime.metadata_json["authorization_kernel_v2_shadow"]["action_id"] == (
        "internal-mcp-v2-selected"
    )
    assert db.scalar(
        select(func.count(RuntimeEvent.event_id)).where(
            RuntimeEvent.tenant_id == tenant.id,
            RuntimeEvent.source_surface == "internal_mcp",
            RuntimeEvent.correlation_id == "internal-mcp-v2-selected",
        )
    ) == 1


@pytest.mark.parametrize("enabled", (False, True))
def test_unselected_or_flag_off_internal_mcp_preserves_legacy_handler(
    test_db: Session, monkeypatch, enabled: bool
) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    calls: list[str] = []
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.v2_unselected",
                module="test",
                version="1.0.0",
                description="Unselected authorization tool",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="read",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: calls.append("executed") or {"ok": True},
        )
    )
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", enabled)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", enabled)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", enabled)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        '{"different-tenant":["internal_mcp"]}',
    )
    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer").model_copy(
        update={"risk_tier": "caller-invented-risk"}
    )

    result = registry.execute(db=db, context=context, tool_name="test.v2_unselected", args={})

    assert result == {"ok": True}
    assert calls == ["executed"]


def test_mcp_registry_permission_enforcement(test_db: Session) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.admin_only",
                module="test",
                version="1.0.0",
                description="Admin-only tool",
                input_schema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["admin"],
                requires_approval=False,
                writes_evidence=False,
                side_effect_level="admin",
                citations_supported=False,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )
    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer")

    with pytest.raises(PermissionError, match="Insufficient role"):
        registry.execute(
            db=db,
            context=context,
            tool_name="test.admin_only",
            args={},
        )

    failure_audit = db.scalar(
        select(AuditLog).where(
            AuditLog.tenant_id == tenant.id,
            AuditLog.resource_id == "test.admin_only",
            AuditLog.action == "mcp.tool.execute",
        )
    )
    assert failure_audit is not None
    assert failure_audit.payload.get("status") == "fail"


def test_mcp_registry_approval_gating(test_db: Session) -> None:
    db = test_db
    tenant, user, ai_system = _seed_core_entities(db)
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.requires_approval",
                module="test",
                version="1.0.0",
                description="Approval-gated tool",
                input_schema={
                    "type": "object",
                    "properties": {
                        "ai_system_id": {"type": "string", "minLength": 1},
                    },
                    "required": ["ai_system_id"],
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer", "operator", "auditor", "admin", "owner"],
                requires_approval=True,
                writes_evidence=False,
                side_effect_level="enforce",
                citations_supported=False,
                governance_scope_required=True,
                tenant_scope_required=True,
                idempotent=False,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )

    context = _base_context(
        tenant_id=tenant.id,
        user_id=user.id,
        user_role="viewer",
        ai_system_id=ai_system.id,
    )
    args = {"ai_system_id": ai_system.id}

    with pytest.raises(PermissionError, match="requires an approved request"):
        registry.execute(
            db=db,
            context=context,
            tool_name="test.requires_approval",
            args=args,
        )

    approval = ApprovalRequest(
        tenant_id=tenant.id,
        enforcement_event_id=None,
        ai_system_id=ai_system.id,
        request_payload={"reason": "MCP approval test"},
        required_roles=["owner", "admin"],
        sla_minutes=30,
        default_if_timeout="block",
        status="approved",
        decided_by=user.id,
        decision="approve",
    )
    db.add(approval)
    db.flush()

    result = registry.execute(
        db=db,
        context=context,
        tool_name="test.requires_approval",
        args=args,
    )
    assert result == {"ok": True}


def test_mcp_registry_writes_audit_and_evidence(test_db: Session) -> None:
    db = test_db
    tenant, user, _ = _seed_core_entities(db)
    registry = MCPToolRegistry()
    registry.register(
        ToolRegistration(
            contract=ToolContract(
                tool_name="test.evidence_writer",
                module="test",
                version="1.0.0",
                description="Tool that writes MCP evidence records",
                input_schema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                    "additionalProperties": False,
                },
                required_role=["viewer"],
                requires_approval=False,
                writes_evidence=True,
                side_effect_level="write",
                citations_supported=True,
                governance_scope_required=False,
                tenant_scope_required=True,
                idempotent=True,
                timeout_ms=5000,
            ),
            executor=lambda _db, _ctx, _args: {"ok": True},
        )
    )

    context = _base_context(tenant_id=tenant.id, user_id=user.id, user_role="viewer")
    registry.execute(
        db=db,
        context=context,
        tool_name="test.evidence_writer",
        args={},
    )

    audit_count = db.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.tenant_id == tenant.id,
            AuditLog.action == "mcp.tool.execute",
            AuditLog.resource_id == "test.evidence_writer",
        )
    )
    evidence_count = db.scalar(
        select(func.count())
        .select_from(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant.id,
            EvidenceNode.node_type == "mcp_tool_execution",
            EvidenceNode.signal_type == "mcp.tool.execute",
        )
    )
    assert int(audit_count or 0) == 1
    assert int(evidence_count or 0) == 1
