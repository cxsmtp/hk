from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import hashlib
import json

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.evidence import DecisionReceipt, EvidenceNode
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlSelection,
)
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.native_control.endpoint_permit_authority import (
    NativeEndpointAuthorityRequest,
    PRODUCTION_NATIVE_ENDPOINT_PERMIT_ROUTE_AVAILABLE,
    TrustedEndpointConsequence,
    native_endpoint_receipt_binding_hash,
    resolve_native_endpoint_permit_authority,
)
from app.services.receipt_service import create_decision_receipt


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def db(tmp_path) -> Session:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'permit-authority.sqlite3'}")
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    session.add(Tenant(id="tenant-1", name="Tenant 1", slug="tenant-1"))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _settings():
    return SimpleNamespace(
        decision_execution_receipts_enabled=True,
        receipt_signing_active_key_id="receipt-key-2026",
        receipt_signing_keys_json=(
            '{"receipt-key-2026":"new-receipt-signing-key-material-00000001"}'
        ),
    )


def _canonical_action(
    *,
    native_control_plan: dict[str, object],
    action_type: str = "FILE_READ",
) -> dict[str, object]:
    return {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "action_id": "action-1",
        "tenant_id": "tenant-1",
        "chain_id": "chain-1",
        "actor": {"identity_id": "user-1"},
        "authority": {
            "authority_type": "delegated",
            "authority_source": "authenticated_native_adapter",
            "permission_scope": ["tool:read"],
            "verified": True,
        },
        "purpose": {"declared_purpose": "development", "purpose_status": "verified"},
        "surface": {
            "surface_type": "native_control",
            "provider": "anthropic",
            "product": "claude_code",
            "provider_event": "PreToolUse",
        },
        "action": {
            "action_type": action_type,
            "action_category": "read",
            "tool_name": "Read",
            "tool_version": "2.1.183",
            "tool_fingerprint_id": "f" * 64,
            "parameter_hash": "p" * 64,
            "target_resource_hash": "t" * 64,
            "destination_hash": "d" * 64,
            "side_effect_class": "read_only",
        },
        "approval": {"approval_binding_hash": "approval-not-required"},
        "policy": {
            "policy_snapshot_id": "policy-12",
            "decision": "allow",
            "control_mode": "inline_allowed",
            "native_control_plan": native_control_plan,
        },
    }


def _persist_authority(
    db: Session,
    *,
    decision: str = "allow",
    policy_epoch: int = 12,
    signed_policy_epoch: int | None = None,
    include_floor: bool = True,
    assurance_level: int = 5,
    semantic_primary: str = "claude-code-pre-tool",
    semantic_method: str = "native_hook",
    integration_provider: str = "anthropic",
    persist_floor_integration: bool = True,
    floor_capability_level: str = "inline_bound",
) -> tuple[DecisionReceipt, NativeControlSelection]:
    floor_requirements = (
        [
            {
                "floor_id": "endpoint_file_floor",
                "capability": "file_read_control",
                "minimum_level": "inline_bound",
                "allowed_methods": ["endpoint_runtime"],
                "maximum_latency_ms": 25,
            }
        ]
        if include_floor
        else []
    )
    selected_floors = (
        [
            {
                "floor_id": "endpoint_file_floor",
                "control_point_id": "macos-endpoint-file",
            }
        ]
        if include_floor
        else []
    )
    plan_without_digest = {
        "plan_id": "plan-1",
        "canonical_action_hash": "1" * 64,
        "issued_at": (NOW - timedelta(seconds=1)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=2)).isoformat(),
        "provider_runtime_context": {
            "provider": "anthropic",
            "product": "claude_code",
            "control_method": semantic_method,
            "lifecycle_stage": "before_tool",
        },
        "semantic_primary_control_point_id": semantic_primary,
        "mandatory_enforcement_floor_requirements": floor_requirements,
        "mandatory_enforcement_floors": selected_floors,
        "required_capabilities": ["file_read_control"],
        "satisfied_capabilities": ["file_read_control"] if include_floor else [],
        "unsatisfied_mandatory_floors": [],
        "control_requirement_unsatisfied": False,
        "minimum_assurance": assurance_level,
        "policy_version": "policy-12",
        "policy_epoch": policy_epoch,
        "failure_behavior": "fail_closed",
    }
    digest = hashlib.sha256(
        json.dumps(plan_without_digest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    db.add(
        NativeControlIntegration(
            id=semantic_primary,
            tenant_id="tenant-1",
            instance_key=f"phase4-{semantic_primary}",
            display_name="Phase 4 semantic control",
            provider=integration_provider,
            product="claude_code",
            model_provider="anthropic",
            model="claude",
            runtime="claude_code",
            execution_location="LOCAL_ENDPOINT",
            deployment_reference="phase4:test",
            integration_method=semantic_method,
            deployment_family="runtime",
            environment="production",
            state="monitoring",
            mode="monitor",
            health_state="healthy",
            health_reasons=[],
            adapter_version="1.0.0",
            degradation_mode="fail_closed",
            capability_snapshot={},
            known_blind_spots=[],
        )
    )
    if include_floor and persist_floor_integration:
        floor_capabilities = {
            "file_read_control": {
                "level": floor_capability_level,
                "verification_status": "verified",
                "evidence_refs": ["phase4:test:macos-file-floor"],
            }
        }
        floor_profile = ControlCapabilityProfileRecord(
            id="macos-endpoint-file-profile",
            manifest_id="hawk_endpoint:macos_endpoint_file:endpoint_runtime",
            manifest_version="1.0.0",
            matrix_version="phase4-test",
            provider="hawk_endpoint",
            product="macos_endpoint_file",
            runtime="macos_endpoint_floor",
            integration_method="endpoint_runtime",
            adapter_version="1.0.0",
            tested_min_version="15.0",
            tested_max_version="15.0",
            current_verified_version="15.0",
            verification_status="verified",
            verification_source="phase4:test:macos-file-floor",
            verified_at=NOW,
            capabilities=floor_capabilities,
            security_properties={"pre_execution_capable": True},
            health_requirements=["runtime_acceptance_receipt"],
            degradation_modes=["fail_closed"],
            known_blind_spots=[],
            documentation_references=["phase4:test"],
            supported_action_classes=["file_read"],
            supported_control_methods=["endpoint_runtime"],
            manifest_fingerprint="e" * 64,
            active=True,
        )
        db.add(floor_profile)
        db.flush()
        db.add(
            NativeControlIntegration(
                id="macos-endpoint-file",
                tenant_id="tenant-1",
                capability_profile_id=floor_profile.id,
                instance_key="phase4-macos-endpoint-file",
                display_name="Phase 4 macOS endpoint file floor",
                provider="hawk_endpoint",
                product="macos_endpoint_file",
                model_provider="none",
                model="none",
                runtime="macos_endpoint_floor",
                execution_location="LOCAL_ENDPOINT",
                deployment_reference="phase4:test:endpoint-file",
                integration_method="endpoint_runtime",
                deployment_family="endpoint",
                environment="production",
                state="monitoring",
                mode="monitor",
                health_state="healthy",
                health_reasons=[],
                adapter_version="1.0.0",
                policy_version="policy-12",
                policy_fresh_until=NOW + timedelta(hours=1),
                degradation_mode="fail_closed",
                capability_snapshot=floor_capabilities,
                known_blind_spots=[],
                last_validated_at=NOW,
            )
        )
    db.flush()
    selection = NativeControlSelection(
        selection_id="selection-1",
        tenant_id="tenant-1",
        action_id="action-1",
        canonical_action_hash="1" * 64,
        provider_runtime_context=plan_without_digest["provider_runtime_context"],
        provider_runtime_fingerprint=None,
        control_plan_id="plan-1",
        control_plan_digest=digest,
        control_plan_material={**plan_without_digest, "plan_digest": digest},
        mandatory_enforcement_floor_requirements=floor_requirements,
        selected_mandatory_floors=selected_floors,
        semantic_primary_control_point_id=semantic_primary,
        secondary_context_points=[],
        verification_points=["endpoint_file_floor"] if include_floor else [],
        unsatisfied_mandatory_floors=[],
        rejected_mandatory_floor_candidates={},
        control_requirement_unsatisfied=False,
        control_plan_reason_codes=[],
        degradation_policy={"mode": "fail_closed"},
        failure_behavior="fail_closed",
        plan_issued_at=NOW - timedelta(seconds=1),
        plan_expires_at=NOW + timedelta(minutes=2),
        contract_hashes={},
        primary_control_point_id=semantic_primary,
        secondary_observation_points=[],
        containment_points=[],
        rejected_candidates=[],
        selection_reason="phase4_exact_native_endpoint_binding",
        required_capabilities=["file_read_control"],
        satisfied_capabilities=["file_read_control"] if include_floor else [],
        unsatisfied_capabilities=[],
        assurance_level=assurance_level,
        coverage_implications={"verification_status": "experimental"},
        known_blind_spots=["os_floor_real_device_acceptance_pending"],
        selector_version="phase4-test",
        matrix_version="phase4-test",
        policy_version="policy-12",
        control_profile_version="claude-code-2.1.183",
        input_digest="i" * 64,
        selected_at=NOW,
    )
    db.add(selection)
    db.flush()
    signed_plan = {
        **plan_without_digest,
        "plan_digest": digest,
        "policy_epoch": (
            policy_epoch if signed_policy_epoch is None else signed_policy_epoch
        ),
    }
    receipt = create_decision_receipt(
        db,
        tenant_id="tenant-1",
        canonical_action=_canonical_action(native_control_plan=signed_plan),
        decision=decision,
        control_mode="inline_allowed" if decision == "allow" else "inline_prevented",
        collector_id="native-control:claude-code",
        settings_obj=_settings(),
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=2),
    )
    assert receipt is not None
    db.commit()
    return receipt, selection


def _trusted() -> TrustedEndpointConsequence:
    return TrustedEndpointConsequence(
        tenant_id="tenant-1",
        device_id="device-1",
        process_instance_id="process-instance-1",
        primitive="file_read",
        requested_rights=("read_data",),
        target_identity="t" * 64,
        destination_identity="d" * 64,
    )


def _request(receipt: DecisionReceipt, selection: NativeControlSelection) -> NativeEndpointAuthorityRequest:
    trusted = _trusted()
    binding_hash = native_endpoint_receipt_binding_hash(
        trusted=trusted,
        action_id=receipt.action_id,
        canonical_action_hash=receipt.canonical_action_hash,
        policy_version=selection.policy_version,
        policy_epoch=12,
        control_plan_id=str(selection.control_plan_id),
        control_plan_digest=str(selection.control_plan_digest),
        decision_receipt_id=receipt.receipt_id,
        decision_receipt_signature=receipt.signature,
    )
    return NativeEndpointAuthorityRequest(
        tenant_id=trusted.tenant_id,
        device_id=trusted.device_id,
        process_instance_id=trusted.process_instance_id,
        action_id=receipt.action_id,
        canonical_action_hash=receipt.canonical_action_hash,
        primitive=trusted.primitive,
        requested_rights=trusted.requested_rights,
        target_identity=trusted.target_identity,
        destination_identity=trusted.destination_identity,
        policy_version=selection.policy_version,
        policy_epoch=12,
        control_plan_id=str(selection.control_plan_id),
        control_plan_digest=str(selection.control_plan_digest),
        decision_receipt_id=receipt.receipt_id,
        decision_receipt_binding_hash=binding_hash,
    )


def test_persisted_signed_receipt_and_verified_plan_resolve_exact_endpoint_authority(db: Session) -> None:
    receipt, selection = _persist_authority(db)
    request = _request(receipt, selection)

    authority = resolve_native_endpoint_permit_authority(
        db,
        request=request,
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    )

    assert authority is not None
    assert authority.tenant_id == "tenant-1"
    assert authority.device_id == "device-1"
    assert authority.process_instance_id == "process-instance-1"
    assert authority.primitive == "file_read"
    assert authority.requested_rights == ("read_data",)
    assert authority.target_identity == "t" * 64
    assert authority.destination_identity == "d" * 64
    assert authority.policy_epoch == 12
    assert authority.control_plan_digest == selection.control_plan_digest
    assert authority.decision_receipt_id == receipt.receipt_id
    assert authority.decision_receipt_binding_hash == request.decision_receipt_binding_hash
    assert authority.authority_reference == f"authority-sha256:{receipt.authority_hash}"
    assert authority.purpose_reference == f"purpose-sha256:{receipt.purpose_hash}"
    assert authority.verification_reference == f"verified-decision-receipt:{receipt.receipt_id}"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("device_id", "device-2"),
        ("process_instance_id", "process-instance-2"),
        ("primitive", "process_execute"),
        ("requested_rights", ("execute",)),
        ("target_identity", "x" * 64),
        ("policy_version", "policy-13"),
        ("policy_epoch", 13),
        ("control_plan_id", "plan-2"),
        ("control_plan_digest", "e" * 64),
        ("decision_receipt_binding_hash", "e" * 64),
    ],
)
def test_real_receipt_cannot_authorize_rebound_or_mutated_endpoint_material(
    db: Session, field: str, value: object
) -> None:
    receipt, selection = _persist_authority(db)
    request = replace(_request(receipt, selection), **{field: value})

    assert resolve_native_endpoint_permit_authority(
        db,
        request=request,
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    ) is None


def test_tampered_receipt_signature_fails_closed(db: Session) -> None:
    receipt, selection = _persist_authority(db)
    request = _request(receipt, selection)
    receipt.signature = "0" * 64
    db.commit()
    assert resolve_native_endpoint_permit_authority(
        db, request=request, trusted=_trusted(), settings_obj=_settings(), now=NOW
    ) is None


def test_non_executable_decision_fails_closed(db: Session) -> None:
    blocked_receipt, blocked_selection = _persist_authority(db, decision="block")
    assert resolve_native_endpoint_permit_authority(
        db,
        request=_request(blocked_receipt, blocked_selection),
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    ) is None


def test_endpoint_context_is_trusted_composition_input_not_a_client_assertion(db: Session) -> None:
    receipt, selection = _persist_authority(db)
    request = _request(receipt, selection)
    rebound_context = replace(_trusted(), device_id="device-2")

    assert resolve_native_endpoint_permit_authority(
        db,
        request=request,
        trusted=rebound_context,
        settings_obj=_settings(),
        now=NOW,
    ) is None


def test_policy_epoch_must_match_verified_plan_and_signed_receipt_material(db: Session) -> None:
    receipt, selection = _persist_authority(db, signed_policy_epoch=13)
    assert resolve_native_endpoint_permit_authority(
        db,
        request=_request(receipt, selection),
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    ) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"include_floor": False},
        {"assurance_level": 0},
        {
            "semantic_primary": "unrelated-gateway",
            "semantic_method": "gateway_inline",
        },
        {"integration_provider": "openai"},
    ],
)
def test_authority_requires_satisfied_endpoint_floor_and_exact_native_semantic_primary(
    db: Session, changes: dict[str, object]
) -> None:
    receipt, selection = _persist_authority(db, **changes)
    assert resolve_native_endpoint_permit_authority(
        db,
        request=_request(receipt, selection),
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    ) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"persist_floor_integration": False},
        {"floor_capability_level": "observe"},
    ],
)
def test_selected_endpoint_floor_requires_persisted_verified_floor_integration(
    db: Session, changes: dict[str, object]
) -> None:
    receipt, selection = _persist_authority(db, **changes)

    assert resolve_native_endpoint_permit_authority(
        db,
        request=_request(receipt, selection),
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    ) is None


def test_destination_is_required_and_receipt_bound_for_every_consequential_action(db: Session) -> None:
    receipt, selection = _persist_authority(db)
    request = _request(receipt, selection)
    missing_destination = replace(request, destination_identity=None)
    wrong_destination = replace(request, destination_identity="x" * 64)

    with pytest.raises(ValueError, match="destination_identity"):
        replace(_trusted(), destination_identity=None)
    assert resolve_native_endpoint_permit_authority(
        db,
        request=missing_destination,
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    ) is None
    assert resolve_native_endpoint_permit_authority(
        db,
        request=wrong_destination,
        trusted=replace(_trusted(), destination_identity="x" * 64),
        settings_obj=_settings(),
        now=NOW,
    ) is None


def test_one_receipt_and_plan_create_one_idempotent_persisted_endpoint_authority(db: Session) -> None:
    receipt, selection = _persist_authority(db)
    request = _request(receipt, selection)
    first = resolve_native_endpoint_permit_authority(
        db,
        request=request,
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    )
    repeated = resolve_native_endpoint_permit_authority(
        db,
        request=request,
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    )
    assert first == repeated
    assert db.scalar(
        select(func.count())
        .select_from(EvidenceNode)
        .where(EvidenceNode.signal_type == "native_endpoint_permit_authority_bound")
    ) == 1

    rebound = replace(_trusted(), device_id="device-2", process_instance_id="process-2")
    rebound_hash = native_endpoint_receipt_binding_hash(
        trusted=rebound,
        action_id=receipt.action_id,
        canonical_action_hash=receipt.canonical_action_hash,
        policy_version=selection.policy_version,
        policy_epoch=12,
        control_plan_id=str(selection.control_plan_id),
        control_plan_digest=str(selection.control_plan_digest),
        decision_receipt_id=receipt.receipt_id,
        decision_receipt_signature=receipt.signature,
    )
    rebound_request = replace(
        request,
        device_id="device-2",
        process_instance_id="process-2",
        decision_receipt_binding_hash=rebound_hash,
    )
    assert resolve_native_endpoint_permit_authority(
        db,
        request=rebound_request,
        trusted=rebound,
        settings_obj=_settings(),
        now=NOW,
    ) is None


def test_one_immutable_plan_cannot_bind_different_receipts_to_different_endpoints(
    db: Session,
) -> None:
    first_receipt, selection = _persist_authority(db)
    first_request = _request(first_receipt, selection)
    assert resolve_native_endpoint_permit_authority(
        db,
        request=first_request,
        trusted=_trusted(),
        settings_obj=_settings(),
        now=NOW,
    ) is not None

    second_receipt = create_decision_receipt(
        db,
        tenant_id="tenant-1",
        canonical_action=_canonical_action(
            native_control_plan=dict(selection.control_plan_material or {})
        ),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="native-control:claude-code:alternate-callback",
        settings_obj=_settings(),
        issued_at=NOW - timedelta(milliseconds=500),
        expires_at=NOW + timedelta(minutes=2),
    )
    assert second_receipt is not None
    assert second_receipt.receipt_id != first_receipt.receipt_id
    assert second_receipt.canonical_action_hash == first_receipt.canonical_action_hash
    db.commit()

    rebound = replace(_trusted(), device_id="device-2", process_instance_id="process-2")
    rebound_hash = native_endpoint_receipt_binding_hash(
        trusted=rebound,
        action_id=second_receipt.action_id,
        canonical_action_hash=second_receipt.canonical_action_hash,
        policy_version=selection.policy_version,
        policy_epoch=12,
        control_plan_id=str(selection.control_plan_id),
        control_plan_digest=str(selection.control_plan_digest),
        decision_receipt_id=second_receipt.receipt_id,
        decision_receipt_signature=second_receipt.signature,
    )
    second_request = replace(
        _request(second_receipt, selection),
        device_id="device-2",
        process_instance_id="process-2",
        decision_receipt_binding_hash=rebound_hash,
    )

    assert resolve_native_endpoint_permit_authority(
        db,
        request=second_request,
        trusted=rebound,
        settings_obj=_settings(),
        now=NOW,
    ) is None


def test_no_production_route_is_claimed_before_authenticated_endpoint_composition() -> None:
    assert PRODUCTION_NATIVE_ENDPOINT_PERMIT_ROUTE_AVAILABLE is False
