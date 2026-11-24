from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import hashlib
import json

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, func, select, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.activity_audit import AIAction, AISession
from app.db.models.evidence import (
    DecisionReceipt,
    EvidenceNode,
    ExecutionIntegrityResult,
    ExecutionReceipt,
)
from app.db.models.finding import Finding
from app.db.models.policy import ApprovalBinding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.core.config import Settings
from app.core.control_engine.authorization import AuthorizationRequest, AuthorizationResponse
from app.core.control_engine.canonical_action import canonical_action_hash
from app.services.receipt_service import (
    create_decision_receipt,
    create_execution_receipt,
    persist_execution_failure_fallback_isolated,
    persist_execution_receipt_isolated,
    record_execution_unknown,
    persist_pre_execution_decision_isolated,
    queue_post_execution_receipt,
    validate_pre_execution,
    verify_decision_receipt,
    verify_execution_receipt,
    verify_integrity_evidence,
    verify_receipt_evidence,
)
from app.services import receipt_service as receipt_contract
from app.services.privacy_sanitizer import sanitize_privacy_payload


@pytest.fixture()
def receipt_db(tmp_path) -> Session:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'decision-execution-receipts.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    db = session_local()
    db.add_all(
        [
            Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"),
            Tenant(id="tenant-b", name="Tenant B", slug="tenant-b"),
        ]
    )
    db.commit()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _settings(*, active_key_id: str = "receipt-key-2026", enabled: bool = True):
    return SimpleNamespace(
        decision_execution_receipts_enabled=enabled,
        receipt_signing_active_key_id=active_key_id,
        receipt_signing_keys_json=(
            '{"receipt-key-2025":"old-receipt-signing-key-material-00000001",'
            '"receipt-key-2026":"new-receipt-signing-key-material-00000001"}'
        ),
    )


def _canonical_action(*, tenant_id: str = "tenant-a") -> dict:
    return {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "action_id": "canonical-action-001",
        "tenant_id": tenant_id,
        "chain_id": "chain-001",
        "actor": {"identity_id": "user-001", "user_id": "user-001"},
        "authority": {
            "authority_type": "delegated",
            "authority_source": "server-session",
            "permission_scope": ["tool:read"],
            "verified": True,
        },
        "purpose": {"declared_purpose": "customer-support", "purpose_status": "verified"},
        "action": {
            "action_type": "tool_execution",
            "action_category": "read",
            "tool_name": "accounts.read",
            "tool_version": "1",
            "tool_fingerprint_id": "fingerprint-001",
            "parameter_hash": "parameter-hash-001",
            "target_resource_hash": "target-hash-001",
            "destination_hash": "destination-hash-001",
            "side_effect_class": "read_only",
        },
        "approval": {"approval_binding_hash": "approval-hash-001"},
        "policy": {
            "policy_snapshot_id": "policy-001",
            "decision": "allow",
            "control_mode": "inline_allowed",
        },
    }


def test_signed_decision_and_execution_receipts_form_verified_matched_pair(receipt_db: Session) -> None:
    issued_at = datetime(2026, 7, 21, tzinfo=timezone.utc)
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    execution, integrity = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="internal-mcp",
        settings_obj=_settings(),
        executed_at=issued_at + timedelta(seconds=1),
    )
    receipt_db.commit()
    repeated_execution, repeated_integrity = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="internal-mcp",
        settings_obj=_settings(),
        executed_at=issued_at + timedelta(seconds=1),
    )

    assert verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
        now=issued_at + timedelta(seconds=2),
    )
    assert integrity.result == "matched"
    assert integrity.drift_fields == []
    assert execution.schema_version == "1.1"
    assert execution.actual_chain_id == "chain-001"
    assert execution.actual_actor_hash == decision.actor_hash
    assert execution.actual_purpose_hash == decision.purpose_hash
    assert execution.actual_policy_snapshot_id == "policy-001"
    assert execution.decision_receipt_id == decision.receipt_id
    assert repeated_execution.receipt_id == execution.receipt_id
    assert repeated_integrity.result_id == integrity.result_id
    assert receipt_db.scalar(select(func.count(ExecutionReceipt.receipt_id))) == 1
    assert decision.receipt_id != execution.receipt_id
    assert verify_receipt_evidence(receipt_db, tenant_id="tenant-a", receipt=decision)
    assert verify_receipt_evidence(receipt_db, tenant_id="tenant-a", receipt=execution)
    assert verify_execution_receipt(execution, tenant_id="tenant-a", settings_obj=_settings())
    assert verify_integrity_evidence(
        receipt_db, tenant_id="tenant-a", integrity=integrity, settings_obj=_settings()
    )


def test_receipt_signature_rejects_tamper_wrong_tenant_expiry_and_unknown_key(receipt_db: Session) -> None:
    issued_at = datetime(2026, 7, 21, tzinfo=timezone.utc)
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="runtime-control",
        settings_obj=_settings(active_key_id="receipt-key-2025"),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    assert verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(active_key_id="receipt-key-2026"),
        now=issued_at + timedelta(seconds=1),
    )
    assert not verify_decision_receipt(
        decision,
        tenant_id="tenant-b",
        settings_obj=_settings(),
        now=issued_at + timedelta(seconds=1),
    )
    assert not verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
        now=issued_at + timedelta(minutes=6),
    )
    decision.parameter_hash = "tampered"
    assert not verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
        now=issued_at + timedelta(seconds=1),
    )
    decision.signing_key_id = "retired-unknown-key"
    assert not verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
        now=issued_at + timedelta(seconds=1),
    )


@pytest.mark.parametrize(
    ("path", "value", "drift_field", "finding_type"),
    (
        (("action", "parameter_hash"), "changed-args", "parameter_hash", "ARGUMENT_DRIFT_AFTER_APPROVAL"),
        (("action", "target_resource_hash"), "changed-target", "target_resource_hash", "TARGET_DRIFT_AFTER_APPROVAL"),
        (("action", "tool_fingerprint_id"), "changed-tool", "tool_fingerprint", "TOOL_VERSION_DRIFT_AFTER_APPROVAL"),
        (("authority", "authority_source"), "changed-authority", "authority_hash", "AUTHORITY_DRIFT_AFTER_APPROVAL"),
        (("action", "destination_hash"), "changed-destination", "destination_hash", "DESTINATION_DRIFT_AFTER_APPROVAL"),
        (("action", "side_effect_class"), "persistent_write", "side_effect_class", "SIDE_EFFECT_DRIFT_AFTER_APPROVAL"),
        (("root", "chain_id"), "changed-chain", "chain_id", "AGENT_CHAIN_DRIFT_AFTER_APPROVAL"),
        (("actor", "identity_id"), "changed-actor", "actor_hash", "ACTOR_DRIFT_AFTER_APPROVAL"),
        (("purpose", "declared_purpose"), "changed-purpose", "purpose_hash", "PURPOSE_DRIFT_AFTER_APPROVAL"),
        (("policy", "policy_snapshot_id"), "changed-policy", "policy_snapshot_id", "POLICY_SNAPSHOT_DRIFT_AFTER_APPROVAL"),
    ),
)
def test_each_material_execution_drift_emits_exact_deduplicated_findings(
    receipt_db: Session,
    path: tuple[str, str],
    value: str,
    drift_field: str,
    finding_type: str,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    actual = deepcopy(_canonical_action())
    if path[0] == "root":
        actual[path[1]] = value
    else:
        actual[path[0]][path[1]] = value
    first_allowed, first = validate_pre_execution(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=actual,
        settings_obj=_settings(),
    )
    second_allowed, second = validate_pre_execution(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=actual,
        settings_obj=_settings(),
    )
    receipt_db.commit()

    assert first_allowed is second_allowed is False
    assert first is not None and second is not None
    assert first.result == second.result == "drift_detected"
    assert drift_field in first.drift_fields
    assert first.execution_receipt_id is None
    assert receipt_db.scalar(select(func.count(ExecutionReceipt.receipt_id))) == 0
    finding_types = set(
        receipt_db.scalars(
            select(Finding.finding_type).where(Finding.tenant_id == "tenant-a")
        ).all()
    )
    assert {"APPROVAL_EXECUTION_DRIFT", finding_type} <= finding_types
    assert receipt_db.scalar(
        select(func.count(Finding.finding_id)).where(
            Finding.tenant_id == "tenant-a",
            Finding.finding_type == finding_type,
        )
    ) == 1
    finding = receipt_db.scalar(
        select(Finding).where(Finding.tenant_id == "tenant-a", Finding.finding_type == finding_type)
    )
    assert finding is not None
    assert "canonical-action-001" in finding.related_event_ids
    assert decision.receipt_id in finding.related_event_ids
    assert first.evidence_bundle_id in finding.evidence_node_ids
    assert finding.canonical_action_id == "canonical-action-001"


def test_unobservable_execution_is_recorded_honestly_and_flag_off_is_exact_noop(receipt_db: Session) -> None:
    assert create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="llm-gateway",
        settings_obj=_settings(enabled=False),
    ) is None
    assert receipt_db.scalar(select(func.count(DecisionReceipt.receipt_id))) == 0

    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="llm-gateway",
        settings_obj=_settings(),
    )
    integrity = record_execution_unknown(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert integrity.result == "execution_unknown"
    assert integrity.execution_receipt_id is None


def test_receipts_are_tenant_isolated_idempotent_and_never_persist_raw_secrets(receipt_db: Session) -> None:
    action = _canonical_action()
    action["content"] = {"raw_prompt": "SECRET-CARD-4111111111111111"}
    first = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=action,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    second = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=action,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    assert first.receipt_id == second.receipt_id
    assert receipt_db.scalar(
        select(func.count(DecisionReceipt.receipt_id)).where(DecisionReceipt.tenant_id == "tenant-a")
    ) == 1
    assert not verify_decision_receipt(
        first,
        tenant_id="tenant-b",
        settings_obj=_settings(),
    )
    persisted = " ".join(
        [
            str(first.signature),
            str(receipt_db.get(EvidenceNode, first.evidence_node_id).payload),
        ]
    )
    assert "SECRET-CARD" not in persisted
    assert "4111111111111111" not in persisted


def test_evidence_tamper_is_detected(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    evidence = receipt_db.get(EvidenceNode, decision.evidence_node_id)
    assert evidence is not None
    assert verify_receipt_evidence(receipt_db, tenant_id="tenant-a", receipt=decision)
    evidence.payload = {**dict(evidence.payload or {}), "receipt_body_hash": "tampered"}
    assert not verify_receipt_evidence(receipt_db, tenant_id="tenant-a", receipt=decision)


def test_exact_approval_binding_is_server_resolved_and_invalidated_on_drift(receipt_db: Session) -> None:
    issued_at = datetime(2026, 7, 21, tzinfo=timezone.utc)
    action = _canonical_action()
    canonical_material = receipt_contract._canonical_material(action, tenant_id="tenant-a")
    binding = ApprovalBinding(
        tenant_id="tenant-a",
        chain_id="chain-001",
        action_id="canonical-action-001",
        approval_id="approval-001",
        canonical_action_hash=canonical_material["canonical_action_hash"],
        receipt_material_hash=receipt_contract._hash(
            receipt_contract._approval_material(canonical_material)
        ),
        signed_receipt="legacy-signed-receipt",
        material_fields=receipt_contract._approval_material(canonical_material),
        approved_at=issued_at - timedelta(minutes=1),
        expires_at=issued_at + timedelta(minutes=10),
        status="active",
    )
    receipt_db.add(binding)
    receipt_db.flush()
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=action,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="internal-mcp",
        settings_obj=_settings(),
        issued_at=issued_at,
        clock=lambda: issued_at,
    )
    assert decision.approval_binding_hash not in {
        "unknown",
        canonical_material["canonical_action_hash"],
    }

    drifted = deepcopy(action)
    drifted["action"]["parameter_hash"] = "drifted"
    allowed, integrity = validate_pre_execution(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=drifted,
        settings_obj=_settings(),
        evaluated_at=issued_at + timedelta(seconds=1),
    )
    receipt_db.refresh(binding)
    assert not allowed and integrity is not None
    assert binding.status == "invalidated"
    assert binding.invalidation_reason == "approval_execution_drift"


def test_embedded_canonical_hash_must_match_recanonicalized_action(receipt_db: Session) -> None:
    action = _canonical_action()
    action["canonical_action_hash"] = canonical_action_hash(action)
    action["action"]["parameter_hash"] = "changed-after-hash"
    with pytest.raises(ValueError, match="embedded canonical action hash"):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=action,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="mcp-gateway",
            settings_obj=_settings(),
        )


def _settings_env(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "secret_key": "receipt-test-app-secret-key",
        "connector_secrets_key": "receipt-test-connector-key",
        "connector_secrets_kdf_salt": "receipt-test-kdf-salt",
        "onprem_bundle_signing_secret": "receipt-test-bundle-key",
        "canonical_action_binding_key": "receipt-test-canonical-binding-key-0001",
        "_env_file": None,
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    "overrides",
    (
        {"receipt_signing_active_key_id": ""},
        {"receipt_signing_keys_json": "{}"},
        {"receipt_signing_keys_json": '{"active":"short"}'},
        {"receipt_signing_active_key_id": "missing"},
        {
            "receipt_signing_keys_json": (
                '{"active":"receipt-signing-material-0000000001",'
                '"old":"receipt-signing-material-0000000001"}'
            )
        },
        {
            "receipt_signing_keys_json": (
                '{"active":"receipt-signing-material-0000000001",'
                '"active":"receipt-signing-material-0000000002"}'
            )
        },
        {
            "receipt_signing_keys_json": (
                '{" active ":"receipt-signing-material-0000000001",'
                '"active":"receipt-signing-material-0000000002"}'
            )
        },
        {"receipt_signing_keys_json": '{"active":{"secret":"not-a-string"}}'},
        {"receipt_signing_keys_json": '{"active":"receipt-test-app-secret-key"}'},
    ),
)
def test_enabled_receipt_keyring_fails_closed(overrides: dict[str, object]) -> None:
    defaults: dict[str, object] = {
        "decision_execution_receipts_enabled": True,
        "receipt_signing_active_key_id": "active",
        "receipt_signing_keys_json": '{"active":"receipt-signing-material-0000000001"}',
        "authorization_kernel_v2_enabled": True,
        "authorization_kernel_shadow_compare_enabled": True,
        "authorization_kernel_v2_enforce": True,
        "authorization_kernel_v2_enforce_rollout": '{"tenant-a":["llm_gateway"]}',
    }
    defaults.update(overrides)
    with pytest.raises(ValidationError):
        Settings(**_settings_env(**defaults))


def test_integrity_evidence_tamper_is_detected(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="runtime-control",
        settings_obj=_settings(),
    )
    integrity = record_execution_unknown(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert verify_integrity_evidence(
        receipt_db, tenant_id="tenant-a", integrity=integrity, settings_obj=_settings()
    )
    evidence = receipt_db.get(EvidenceNode, integrity.evidence_bundle_id)
    evidence.payload = {**dict(evidence.payload or {}), "result": "matched"}
    assert not verify_integrity_evidence(
        receipt_db, tenant_id="tenant-a", integrity=integrity, settings_obj=_settings()
    )


def test_integrity_result_enum_is_closed() -> None:
    assert ExecutionIntegrityResult.ALLOWED_RESULTS == {
        "matched",
        "drift_detected",
        "execution_unknown",
        "incomplete",
    }


def test_composite_foreign_keys_reject_cross_tenant_receipt_linkage(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    receipt_db.add(
        ExecutionReceipt(
            receipt_id="cross-tenant-execution",
            tenant_id="tenant-b",
            action_id=decision.action_id,
            decision_receipt_id=decision.receipt_id,
            execution_attempt_id="cross-tenant-attempt",
            actual_tool_fingerprint=decision.tool_fingerprint,
            actual_parameter_hash=decision.parameter_hash,
            actual_target_resource_hash=decision.target_resource_hash,
            actual_destination_hash=decision.destination_hash,
            actual_authority_hash=decision.authority_hash,
            actual_side_effect_class=decision.side_effect_class,
            downstream_objects=[],
            execution_status="success",
            executed_at=datetime.now(timezone.utc),
            collector_id="malicious-cross-tenant-writer",
            signature="0" * 64,
            signing_key_id="receipt-key-2026",
            idempotency_key="1" * 64,
        )
    )
    with pytest.raises(IntegrityError):
        receipt_db.flush()
    receipt_db.rollback()


def test_decision_receipt_lost_race_returns_committed_idempotent_winner(
    receipt_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    winner = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    loser = Session(bind=receipt_db.get_bind(), autoflush=False)
    original_scalar = loser.scalar
    scalar_calls = 0

    def _miss_first_idempotency_lookup(statement, *args, **kwargs):
        nonlocal scalar_calls
        scalar_calls += 1
        if scalar_calls == 1:
            return None
        return original_scalar(statement, *args, **kwargs)

    monkeypatch.setattr(loser, "scalar", _miss_first_idempotency_lookup)
    try:
        raced = create_decision_receipt(
            loser,
            tenant_id="tenant-a",
            canonical_action=_canonical_action(),
            decision="allow",
            control_mode="inline_allowed",
            collector_id="mcp-gateway",
            settings_obj=_settings(),
        )
        assert raced.receipt_id == winner.receipt_id
        assert original_scalar(select(func.count(DecisionReceipt.receipt_id))) == 1
    finally:
        loser.close()


@pytest.mark.parametrize(
    "mutate",
    (
        lambda action: action.__setitem__("action", []),
        lambda action: action["action"].__setitem__("parameter_hash", 123),
        lambda action: action["action"].__setitem__("target_resource_hash", "x" * 129),
        lambda action: action.__setitem__("authority", "caller-controlled-authority"),
        lambda action: action["policy"].__setitem__("policy_snapshot_id", {"not": "text"}),
    ),
)
def test_malformed_or_oversize_canonical_material_is_rejected_without_truncation(
    receipt_db: Session,
    mutate,
) -> None:
    action = _canonical_action()
    mutate(action)
    with pytest.raises((TypeError, ValueError)):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=action,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="mcp-gateway",
            settings_obj=_settings(),
        )


def test_same_prefix_overlength_execution_material_cannot_bypass_drift_check(receipt_db: Session) -> None:
    action = _canonical_action()
    action["action"]["parameter_hash"] = "x" * 128
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=action,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    actual = deepcopy(action)
    actual["action"]["parameter_hash"] = ("x" * 128) + "different-suffix"
    with pytest.raises(ValueError, match="parameter_hash exceeds"):
        validate_pre_execution(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=actual,
            settings_obj=_settings(),
        )


@pytest.mark.parametrize(
    ("decision", "control_mode"),
    (("caller_allow", "inline_allowed"), ("allow", "caller_inline")),
)
def test_decision_and_control_mode_enums_are_closed(
    receipt_db: Session,
    decision: str,
    control_mode: str,
) -> None:
    with pytest.raises(ValueError):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=_canonical_action(),
            decision=decision,
            control_mode=control_mode,
            collector_id="mcp-gateway",
            settings_obj=_settings(),
        )


def test_execution_status_and_downstream_object_bounds_are_closed(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    with pytest.raises(ValueError, match="execution_status"):
        create_execution_receipt(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="trust_me_success",
            collector_id="internal-mcp",
            settings_obj=_settings(),
        )
    with pytest.raises(ValueError, match="downstream_objects exceeds"):
        create_execution_receipt(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="internal-mcp",
            settings_obj=_settings(),
            downstream_objects=[{"type": "object", "id": str(index)} for index in range(129)],
        )


def _authorization_pair(action_id: str) -> tuple[AuthorizationRequest, AuthorizationResponse]:
    request = AuthorizationRequest(
        tenant_id="tenant-a",
        environment="prod",
        collector_id="llm-gateway-provider",
        action_id=action_id,
        chain_id=f"chain-{action_id}",
        surface="llm_gateway",
        actor={"identity_id": "user-001", "user_id": "user-001"},
        authority={"authority_type": "authenticated_user", "verified": True},
        purpose={"declared_purpose": "support"},
        action={"action_type": "prompt", "risk_level": "low"},
        tool={"name": "llm.generate", "version": "1", "fingerprint_id": "fingerprint-001"},
        parameters={"parameter_hash": "parameter-hash-001"},
        target={
            "resource": "provider",
            "resource_hash": "target-hash-001",
            "destination": "provider",
            "destination_hash": "destination-hash-001",
        },
        side_effect_context={"side_effect_class": "external_provider_call"},
        discovery_context={"application": "llm_gateway", "provider": "provider"},
        policy_snapshot_id="policy-001",
        policy_profile={"base_decision": "allow", "dependencies_healthy": True},
        path_evidence={"collector_inline_capable": True, "inline_pre_execution": True},
    )
    response = AuthorizationResponse(
        decision="allow",
        control_mode="inline_allowed",
        reason="policy_evaluated",
        policy_snapshot_id="policy-001",
        degraded_behavior="block",
        policy_profile_hash="a" * 64,
        response_hash="b" * 64,
    )
    return request, response


def test_isolated_lifecycle_survives_outer_commit_and_rollback_without_ghost_execution(
    receipt_db: Session,
) -> None:
    request, response = _authorization_pair("provider-action-commit")
    decision, canonical = persist_pre_execution_decision_isolated(
        receipt_db,
        request=request,
        response=response,
        settings_obj=_settings(),
    )
    assert decision is not None
    queue_post_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=canonical,
        execution_status="success",
        collector_id="llm-gateway-provider",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    committed_integrity = receipt_db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id
        )
    )
    assert committed_integrity is not None and committed_integrity.result == "matched"
    assert committed_integrity.execution_receipt_id is not None

    rollback_request, rollback_response = _authorization_pair("provider-action-rollback")
    rollback_decision, rollback_canonical = persist_pre_execution_decision_isolated(
        receipt_db,
        request=rollback_request,
        response=rollback_response,
        settings_obj=_settings(),
    )
    assert rollback_decision is not None
    queue_post_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=rollback_decision.receipt_id,
        actual_canonical_action=rollback_canonical,
        execution_status="success",
        collector_id="llm-gateway-provider",
        settings_obj=_settings(),
    )
    receipt_db.execute(select(Tenant.id).where(Tenant.id == "tenant-a"))
    receipt_db.rollback()
    rollback_integrity = receipt_db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.decision_receipt_id == rollback_decision.receipt_id
        )
    )
    assert rollback_integrity is not None and rollback_integrity.result == "matched"
    assert rollback_integrity.execution_receipt_id is not None


def test_queued_receipt_drains_once_only_after_outer_transaction_ends(
    receipt_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()

    original_writer = receipt_contract.persist_execution_receipt_isolated
    writer_calls: list[str] = []

    def _counted_writer(*args, **kwargs):
        writer_calls.append(kwargs["execution_attempt_id"])
        return original_writer(*args, **kwargs)

    monkeypatch.setattr(
        receipt_contract,
        "persist_execution_receipt_isolated",
        _counted_writer,
    )

    with receipt_db.begin():
        queue_post_execution_receipt(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="provider-observer",
            settings_obj=_settings(),
            execution_attempt_id="outermost-drain-attempt",
        )
        savepoint = receipt_db.begin_nested()
        receipt_db.execute(select(Tenant.id).where(Tenant.id == "tenant-a"))
        savepoint.commit()
        assert writer_calls == []
        assert len(receipt_db.info["decision_execution_receipt_queue"]) == 1

    assert writer_calls == ["outermost-drain-attempt"]
    assert "decision_execution_receipt_queue" not in receipt_db.info
    assert receipt_db.scalar(
        select(func.count(ExecutionReceipt.receipt_id)).where(
            ExecutionReceipt.decision_receipt_id == decision.receipt_id
        )
    ) == 1

    # A later terminal event cannot re-enter the drained queue or duplicate proof.
    receipt_db.commit()
    assert writer_calls == ["outermost-drain-attempt"]
    assert receipt_db.scalar(
        select(func.count(ExecutionReceipt.receipt_id)).where(
            ExecutionReceipt.decision_receipt_id == decision.receipt_id
        )
    ) == 1


def test_post_execution_observed_drift_always_persists_signed_receipt_and_findings(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    actual = deepcopy(_canonical_action())
    actual["action"]["parameter_hash"] = "observed-drift"
    execution, integrity = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=actual,
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
    )
    assert execution.signature and execution.actual_parameter_hash == "observed-drift"
    assert integrity.result == "drift_detected"
    assert integrity.execution_receipt_id == execution.receipt_id
    finding_types = set(
        receipt_db.scalars(
            select(Finding.finding_type).where(Finding.tenant_id == "tenant-a")
        ).all()
    )
    assert {"APPROVAL_EXECUTION_DRIFT", "ARGUMENT_DRIFT_AFTER_APPROVAL"} <= finding_types


def test_execution_receipt_signature_covers_extended_authorization_material(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    execution, _ = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
    )
    assert verify_execution_receipt(
        execution,
        tenant_id="tenant-a",
        settings_obj=_settings(),
    )

    execution.actual_policy_snapshot_id = "tampered-policy"

    assert not verify_execution_receipt(
        execution,
        tenant_id="tenant-a",
        settings_obj=_settings(),
    )


def test_integrity_signature_rejects_coordinated_row_and_evidence_tamper(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    _, integrity = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
    )
    assert integrity.signature and integrity.signing_key_id
    assert verify_integrity_evidence(
        receipt_db, tenant_id="tenant-a", integrity=integrity, settings_obj=_settings()
    )
    integrity.execution_receipt_id = None
    integrity.result = "execution_unknown"
    integrity.drift_fields = []
    integrity.severity = "low"
    integrity.response_action = "none"
    body = {
        "schema_version": integrity.schema_version,
        "result_id": integrity.result_id,
        "tenant_id": integrity.tenant_id,
        "action_id": integrity.action_id,
        "decision_receipt_id": integrity.decision_receipt_id,
        "execution_receipt_id": None,
        "result": "execution_unknown",
        "drift_fields": [],
        "severity": "low",
        "response_action": "none",
        "evaluated_at": integrity.evaluated_at.replace(tzinfo=timezone.utc).isoformat(),
        "signing_key_id": integrity.signing_key_id,
    }
    evidence = receipt_db.get(EvidenceNode, integrity.evidence_bundle_id)
    evidence.payload = sanitize_privacy_payload(
        {**body, "integrity_body_hash": receipt_contract._hash(body), "signature": integrity.signature}
    )
    assert not verify_integrity_evidence(
        receipt_db, tenant_id="tenant-a", integrity=integrity, settings_obj=_settings()
    )


def test_decision_signature_covers_collector_and_canonical_evidence_link(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="trusted-collector",
        settings_obj=_settings(),
    )
    canonical_node = receipt_db.get(EvidenceNode, decision.canonical_action_evidence_node_id)
    assert canonical_node is not None
    assert canonical_node.payload["action_id"] == decision.action_id
    assert canonical_node.payload["canonical_action_hash"] == decision.canonical_action_hash
    decision.collector_id = "tampered-collector"
    assert not verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
    )


def test_expired_idempotent_decision_is_never_reused(receipt_db: Session) -> None:
    issued = datetime(2026, 7, 21, tzinfo=timezone.utc)
    expired = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
        issued_at=issued,
        expires_at=issued + timedelta(seconds=1),
    )
    assert expired is not None
    with pytest.raises(ValueError, match="expired.*new action_id"):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=_canonical_action(),
            decision="allow",
            control_mode="inline_allowed",
            collector_id="mcp-gateway",
            settings_obj=_settings(),
            issued_at=issued + timedelta(minutes=1),
        )


def test_runtime_keyring_rejects_normalized_duplicate_ids_and_non_string_secret(
    receipt_db: Session,
) -> None:
    for raw in (
        '{" key ":"receipt-signing-material-0000000001","key":"receipt-signing-material-0000000002"}',
        '{"key":{"secret":"receipt-signing-material-0000000001"}}',
    ):
        bad = SimpleNamespace(
            decision_execution_receipts_enabled=True,
            receipt_signing_active_key_id="key",
            receipt_signing_keys_json=raw,
        )
        with pytest.raises(ValueError, match="keyring|signing"):
            create_decision_receipt(
                receipt_db,
                tenant_id="tenant-a",
                canonical_action=_canonical_action(),
                decision="allow",
                control_mode="inline_allowed",
                collector_id="mcp-gateway",
                settings_obj=bad,
            )


def test_receipt_flag_requires_selected_authorization_kernel_at_startup() -> None:
    with pytest.raises(ValidationError, match="AUTHORIZATION_KERNEL_V2"):
        Settings(
            **_settings_env(
                decision_execution_receipts_enabled=True,
                receipt_signing_active_key_id="active",
                receipt_signing_keys_json='{"active":"receipt-signing-material-0000000001"}',
                authorization_kernel_v2_enabled=False,
                authorization_kernel_shadow_compare_enabled=False,
                authorization_kernel_v2_enforce=False,
            )
        )


def test_database_rejects_invalid_persisted_integrity_result(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.add(
        ExecutionIntegrityResult(
            result_id="invalid-integrity-result",
            tenant_id="tenant-a",
            action_id=decision.action_id,
            decision_receipt_id=decision.receipt_id,
            execution_receipt_id=None,
            execution_attempt_id="invalid-integrity-attempt",
            result="caller_defined",
            drift_fields=[],
            severity="low",
            response_action="none",
            signature="0" * 64,
            signing_key_id="receipt-key-2026",
            evaluated_at=datetime.now(timezone.utc),
            idempotency_key="invalid-integrity-result-key",
        )
    )
    with pytest.raises(IntegrityError):
        receipt_db.flush()
    receipt_db.rollback()


def test_execution_receipt_lost_race_returns_committed_idempotent_winner(
    receipt_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    winner, _ = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    loser = Session(bind=receipt_db.get_bind(), autoflush=False)
    original_scalar = loser.scalar
    missed = False

    def _miss_first_execution_lookup(statement, *args, **kwargs):
        nonlocal missed
        if not missed and "FROM execution_receipts" in str(statement):
            missed = True
            return None
        return original_scalar(statement, *args, **kwargs)

    monkeypatch.setattr(loser, "scalar", _miss_first_execution_lookup)
    try:
        raced, _ = create_execution_receipt(
            loser,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="provider-observer",
            settings_obj=_settings(),
        )
        assert raced.receipt_id == winner.receipt_id
        assert original_scalar(select(func.count(ExecutionReceipt.receipt_id))) == 1
    finally:
        loser.close()


def test_integrity_result_lost_race_returns_committed_idempotent_winner(
    receipt_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    winner = record_execution_unknown(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    receipt_db.commit()
    loser = Session(bind=receipt_db.get_bind(), autoflush=False)
    loser_decision = loser.get(DecisionReceipt, decision.receipt_id)
    original_scalar = loser.scalar
    missed = False

    def _miss_first_integrity_lookup(statement, *args, **kwargs):
        nonlocal missed
        if not missed and "FROM execution_integrity_results" in str(statement):
            missed = True
            return None
        return original_scalar(statement, *args, **kwargs)

    monkeypatch.setattr(loser, "scalar", _miss_first_integrity_lookup)
    try:
        raced = receipt_contract._persist_integrity(
            loser,
            decision=loser_decision,
            execution_receipt_id=None,
            execution_attempt_id=winner.execution_attempt_id,
            result="execution_unknown",
            drift_fields=[],
            evaluated_at=winner.evaluated_at.replace(tzinfo=timezone.utc),
            settings_obj=_settings(),
        )
        assert raced.result_id == winner.result_id
        assert original_scalar(select(func.count(ExecutionIntegrityResult.result_id))) == 1
    finally:
        loser.close()


def test_queue_uses_observation_time_across_expiry_and_deduplicates_delivery(
    receipt_db: Session,
) -> None:
    issued = datetime(2026, 7, 21, tzinfo=timezone.utc)
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
        issued_at=issued,
        expires_at=issued + timedelta(seconds=2),
    )
    receipt_db.commit()
    observed = issued + timedelta(seconds=1)
    for _ in range(2):
        queue_post_execution_receipt(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="provider-observer",
            settings_obj=_settings(),
            observed_at=observed,
            execution_attempt_id="observed-attempt-001",
        )
    receipt_db.commit()
    execution = receipt_db.scalar(
        select(ExecutionReceipt).where(ExecutionReceipt.decision_receipt_id == decision.receipt_id)
    )
    assert execution is not None and execution.executed_at.replace(tzinfo=timezone.utc) == observed
    assert receipt_db.scalar(
        select(func.count(ExecutionReceipt.receipt_id)).where(
            ExecutionReceipt.decision_receipt_id == decision.receipt_id
        )
    ) == 1


def test_queue_preserves_distinct_attempts_and_deduplicates_same_attempt(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    observed = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    for attempt_id in ("queued-attempt-001", "queued-attempt-002", "queued-attempt-001"):
        queue_post_execution_receipt(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="provider-observer",
            settings_obj=_settings(),
            downstream_objects=[{"type": "provider_result", "hash": "same-result"}],
            observed_at=observed,
            execution_attempt_id=attempt_id,
        )

    pending = receipt_db.info["decision_execution_receipt_queue"]
    assert len(pending) == 2
    assert {item["execution_attempt_id"] for item in pending} == {
        "queued-attempt-001",
        "queued-attempt-002",
    }
    receipt_db.commit()

    executions = list(
        receipt_db.scalars(
            select(ExecutionReceipt).where(
                ExecutionReceipt.decision_receipt_id == decision.receipt_id
            )
        ).all()
    )
    assert len(executions) == 2
    assert {item.execution_attempt_id for item in executions} == {
        "queued-attempt-001",
        "queued-attempt-002",
    }
    assert all(item.executed_at.replace(tzinfo=timezone.utc) == observed for item in executions)


def test_queue_persists_128_redacted_downstream_objects_without_proof_failure(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    raw_type = "private-ssn-123-45-6789"
    queue_post_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id="queued-downstream-128",
        downstream_objects=[
            {"type": (raw_type if index == 0 else "webhook"), "id": f"raw-{index}"}
            for index in range(128)
        ],
    )
    receipt_db.commit()
    execution = receipt_db.scalar(
        select(ExecutionReceipt).where(
            ExecutionReceipt.decision_receipt_id == decision.receipt_id,
            ExecutionReceipt.execution_attempt_id == "queued-downstream-128",
        )
    )
    integrity = receipt_db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
            ExecutionIntegrityResult.execution_attempt_id == "queued-downstream-128",
        )
    )
    assert execution is not None and len(execution.downstream_objects) == 128
    assert execution.downstream_objects[0]["object_type"] == "other"
    assert execution.downstream_objects[0]["object_type_hash"]
    assert raw_type not in json.dumps(execution.downstream_objects)
    assert integrity is not None and integrity.result == "matched"
    assert verify_execution_receipt(
        execution, tenant_id="tenant-a", settings_obj=_settings()
    )
    assert verify_integrity_evidence(
        receipt_db,
        tenant_id="tenant-a",
        integrity=integrity,
        settings_obj=_settings(),
    )
    assert receipt_db.scalar(
        select(func.count(Finding.finding_id)).where(
            Finding.tenant_id == "tenant-a",
            Finding.finding_type == "EXECUTION_RECEIPT_PERSISTENCE_FAILURE",
        )
    ) == 0


def test_queue_persists_two_128_object_attempts_and_valid_latest_bundle(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    for attempt_index in range(2):
        queue_post_execution_receipt(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="provider-observer",
            settings_obj=_settings(),
            execution_attempt_id=f"queued-128-attempt-{attempt_index}",
            downstream_objects=[
                {"type": "webhook", "id": f"attempt-{attempt_index}-object-{index}"}
                for index in range(128)
            ],
        )
    receipt_db.commit()
    assert receipt_db.scalar(
        select(func.count(ExecutionReceipt.receipt_id)).where(
            ExecutionReceipt.decision_receipt_id == decision.receipt_id
        )
    ) == 2
    assert receipt_db.scalar(
        select(func.count(ExecutionIntegrityResult.result_id)).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id
        )
    ) == 2
    receipt_db.refresh(decision)
    from app.services.canonical_evidence_bundle_service import verify_evidence_bundle

    bundle = receipt_db.get(EvidenceNode, decision.evidence_bundle_id)
    assert bundle is not None
    assert verify_evidence_bundle(
        receipt_db,
        tenant_id="tenant-a",
        bundle=bundle,
        settings_obj=_settings(),
    )["valid"]


def test_forced_bundle_refresh_failure_keeps_known_terminal_receipt(
    receipt_db: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    runtime = RuntimeEvent(
        event_id="forced-refresh-runtime",
        tenant_id="tenant-a",
        source_surface="gateway",
        event_type="mcp_authorize",
        chain_id=decision.chain_id,
        evidence_node_ids=[],
        metadata_json={"existing": "preserved"},
    )
    ai_session = AISession(
        session_id="forced-refresh-session",
        tenant_id="tenant-a",
        source_surface="gateway",
    )
    activity = AIAction(
        action_id=decision.action_id,
        tenant_id="tenant-a",
        session_id=ai_session.session_id,
        runtime_event_id=runtime.event_id,
        action_type="tool_execution",
        metadata_json={"existing": "preserved"},
    )
    receipt_db.add_all([runtime, ai_session])
    receipt_db.flush()
    receipt_db.add(activity)
    receipt_db.commit()

    original_refresh = receipt_contract._refresh_canonical_bundle
    def _fail_bundle_refresh(*_args, **_kwargs):
        raise ValueError("forced bundle material cap")

    caplog.set_level("ERROR", logger="app.services.receipt_service")
    monkeypatch.setattr(receipt_contract, "_refresh_canonical_bundle", _fail_bundle_refresh)
    execution_id, integrity_id = persist_execution_receipt_isolated(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id="forced-refresh-failure-attempt",
        downstream_objects=[{"type": "webhook", "id": "known-terminal"}],
    )
    execution = receipt_db.get(ExecutionReceipt, execution_id)
    integrity = receipt_db.get(ExecutionIntegrityResult, integrity_id)
    assert execution is not None and execution.execution_status == "success"
    assert integrity is not None and integrity.result == "matched"
    assert integrity.execution_receipt_id == execution.receipt_id
    assert receipt_db.info["canonical_bundle_refresh_status"][decision.receipt_id] == "incomplete"
    assert "canonical evidence bundle refresh incomplete" in caplog.text
    assert receipt_db.scalar(
        select(func.count(ExecutionIntegrityResult.result_id)).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
            ExecutionIntegrityResult.result == "incomplete",
        )
    ) == 0
    reopened = sessionmaker(bind=receipt_db.get_bind(), autocommit=False, autoflush=False)()
    try:
        durable_execution = reopened.get(ExecutionReceipt, execution_id)
        durable_integrity = reopened.get(ExecutionIntegrityResult, integrity_id)
        durable_runtime = reopened.get(RuntimeEvent, runtime.event_id)
        durable_activity = reopened.get(AIAction, activity.action_id)
        findings = list(
            reopened.scalars(
                select(Finding).where(
                    Finding.tenant_id == "tenant-a",
                    Finding.finding_type == "EVIDENCE_BUNDLE_REFRESH_INCOMPLETE",
                    Finding.execution_attempt_id == "forced-refresh-failure-attempt",
                )
            ).all()
        )
        assert durable_execution is not None and durable_integrity is not None
        assert len(findings) == 1
        assert decision.receipt_id in findings[0].related_event_ids
        assert decision.action_id in findings[0].related_event_ids
        assert durable_integrity.evidence_bundle_id in findings[0].evidence_node_ids
        assert durable_runtime.metadata_json == {
            "existing": "preserved",
            "canonical_evidence_bundle_refresh_status": "incomplete",
        }
        assert durable_activity.metadata_json == {
            "existing": "preserved",
            "canonical_evidence_bundle_refresh_status": "incomplete",
        }
    finally:
        reopened.close()

    monkeypatch.setattr(receipt_contract, "_refresh_canonical_bundle", original_refresh)
    repeated_execution_id, repeated_integrity_id = persist_execution_receipt_isolated(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id="forced-refresh-failure-attempt",
        downstream_objects=[{"type": "webhook", "id": "known-terminal"}],
    )
    assert (repeated_execution_id, repeated_integrity_id) == (execution_id, integrity_id)
    receipt_db.expire_all()
    refreshed_decision = receipt_db.get(DecisionReceipt, decision.receipt_id)
    from app.services.canonical_evidence_bundle_service import verify_evidence_bundle

    bundle = receipt_db.get(EvidenceNode, refreshed_decision.evidence_bundle_id)
    assert bundle is not None
    assert verify_evidence_bundle(
        receipt_db,
        tenant_id="tenant-a",
        bundle=bundle,
        settings_obj=_settings(),
    )["valid"]
    assert receipt_db.scalar(
        select(func.count(Finding.finding_id)).where(
            Finding.tenant_id == "tenant-a",
            Finding.finding_type == "EVIDENCE_BUNDLE_REFRESH_INCOMPLETE",
            Finding.execution_attempt_id == "forced-refresh-failure-attempt",
        )
    ) == 1


def test_post_persistence_error_creates_signed_incomplete_and_finding(
    receipt_db: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()

    def _fail_post_writer(*_args, **_kwargs):
        raise RuntimeError("post writer unavailable")

    caplog.set_level("ERROR", logger="app.services.receipt_service")
    monkeypatch.setattr(receipt_contract, "persist_execution_receipt_isolated", _fail_post_writer)
    queue_post_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    integrity = receipt_db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id
        )
    )
    assert integrity is not None and integrity.result == "incomplete" and integrity.signature
    fallback_finding = receipt_db.scalar(
        select(Finding).where(
            Finding.tenant_id == "tenant-a",
            Finding.finding_type == "EXECUTION_RECEIPT_PERSISTENCE_FAILURE",
        )
    )
    assert fallback_finding is not None
    assert fallback_finding.execution_attempt_id == integrity.execution_attempt_id
    assert "post-commit execution receipt persistence failed" in caplog.text
    assert receipt_db.scalar(
        select(func.count(ExecutionIntegrityResult.result_id)).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id
        )
    ) == 1
    assert receipt_db.scalar(
        select(func.count(Finding.finding_id)).where(
            Finding.tenant_id == "tenant-a",
            Finding.finding_type == "EXECUTION_RECEIPT_PERSISTENCE_FAILURE",
        )
    ) == 1


def test_same_attempt_conflicting_terminal_material_fails_closed_with_linked_finding(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    attempt_id = "conflicting-terminal-attempt"
    create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id=attempt_id,
    )
    drifted = _canonical_action()
    drifted["action"]["parameter_hash"] = "conflicting-parameter-material"
    with pytest.raises(ValueError, match="execution attempt.*conflict"):
        create_execution_receipt(
            receipt_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=drifted,
            execution_status="success",
            collector_id="provider-observer",
            settings_obj=_settings(),
            execution_attempt_id=attempt_id,
        )
    conflict = receipt_db.scalar(
        select(Finding).where(
            Finding.tenant_id == "tenant-a",
            Finding.finding_type == "EXECUTION_ATTEMPT_CONFLICT",
            Finding.execution_attempt_id == attempt_id,
        )
    )
    assert conflict is not None


def test_isolated_terminal_conflict_persists_attempt_finding_after_rollback_and_deduplicates(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    attempt_id = "isolated-conflicting-terminal-attempt"
    persist_execution_receipt_isolated(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id=attempt_id,
    )
    drifted = _canonical_action()
    drifted["action"]["parameter_hash"] = "isolated-conflicting-parameter-material"

    for _ in range(2):
        with pytest.raises(ValueError, match="execution attempt.*conflict"):
            persist_execution_receipt_isolated(
                receipt_db,
                tenant_id="tenant-a",
                decision_receipt_id=decision.receipt_id,
                actual_canonical_action=drifted,
                execution_status="success",
                collector_id="provider-observer",
                settings_obj=_settings(),
                execution_attempt_id=attempt_id,
            )

        reopened = Session(bind=receipt_db.get_bind(), autoflush=False)
        try:
            conflicts = list(
                reopened.scalars(
                    select(Finding).where(
                        Finding.tenant_id == "tenant-a",
                        Finding.finding_type == "EXECUTION_ATTEMPT_CONFLICT",
                        Finding.execution_attempt_id == attempt_id,
                    )
                ).all()
            )
            assert len(conflicts) == 1
            assert conflicts[0].execution_attempt_id == attempt_id
        finally:
            reopened.close()


def test_server_resolves_one_exact_unclaimed_approval_and_rejects_ambiguity(
    receipt_db: Session,
) -> None:
    issued = datetime(2026, 7, 21, tzinfo=timezone.utc)
    canonical_material = receipt_contract._canonical_material(
        _canonical_action(), tenant_id="tenant-a"
    )

    def _binding(approval_id: str) -> ApprovalBinding:
        return ApprovalBinding(
            tenant_id="tenant-a",
            chain_id="chain-001",
            action_id="canonical-action-001",
            approval_id=approval_id,
                canonical_action_hash=canonical_material["canonical_action_hash"],
                receipt_material_hash=receipt_contract._hash(
                    receipt_contract._approval_material(canonical_material)
                ),
            signed_receipt=f"signed-{approval_id}",
            material_fields=receipt_contract._approval_material(canonical_material),
            approved_at=issued - timedelta(minutes=1),
            expires_at=issued + timedelta(minutes=10),
            status="active",
        )

    first = _binding("approval-one")
    receipt_db.add(first)
    receipt_db.flush()
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="internal-mcp",
        settings_obj=_settings(),
        issued_at=issued,
        clock=lambda: issued,
    )
    assert decision.approval_binding_id == first.id
    receipt_db.rollback()
    receipt_db.add_all([_binding("approval-one"), _binding("approval-two")])
    receipt_db.flush()
    with pytest.raises(ValueError, match="ambiguous"):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=_canonical_action(),
            decision="allow",
            control_mode="inline_allowed",
            collector_id="internal-mcp",
            settings_obj=_settings(),
            issued_at=issued,
        )


def test_each_signed_receipt_rejects_own_evidence_relink(receipt_db: Session) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    execution, integrity = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
    )
    decision.evidence_node_id = "forged-decision-evidence-link"
    execution.evidence_node_id = "forged-execution-evidence-link"
    integrity.evidence_bundle_id = "forged-integrity-evidence-link"
    assert not verify_decision_receipt(
        decision, tenant_id="tenant-a", settings_obj=_settings()
    )
    assert not verify_execution_receipt(
        execution, tenant_id="tenant-a", settings_obj=_settings()
    )
    assert not verify_integrity_evidence(
        receipt_db, tenant_id="tenant-a", integrity=integrity, settings_obj=_settings()
    )


def test_legacy_or_mismatched_approval_material_is_not_attached_as_exact(
    receipt_db: Session,
) -> None:
    issued = datetime(2026, 7, 21, tzinfo=timezone.utc)
    receipt_db.add(
        ApprovalBinding(
            tenant_id="tenant-a",
            chain_id="chain-001",
            action_id="canonical-action-001",
            approval_id="legacy-mismatch",
            canonical_action_hash="legacy-domain-not-current-canonical-action",
            signed_receipt="legacy-signed-receipt",
            material_fields={"arguments_hash": "different-arguments"},
            approved_at=issued - timedelta(minutes=1),
            expires_at=issued + timedelta(minutes=10),
            status="active",
        )
    )
    receipt_db.flush()
    with pytest.raises(ValueError, match="approval.*material|canonical"):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=_canonical_action(),
            decision="allow",
            control_mode="inline_allowed",
            collector_id="internal-mcp",
            settings_obj=_settings(),
            issued_at=issued,
        )


def test_nested_canonical_evidence_tamper_breaks_decision_and_recursive_integrity(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    _, integrity = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
    )
    canonical_node = receipt_db.get(EvidenceNode, decision.canonical_action_evidence_node_id)
    payload = deepcopy(dict(canonical_node.payload or {}))
    payload["canonical_action"]["action"]["parameter_hash"] = "nested-tamper"
    canonical_node.payload = payload
    assert not verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
        db=receipt_db,
    )
    assert not verify_integrity_evidence(
        receipt_db,
        tenant_id="tenant-a",
        integrity=integrity,
        settings_obj=_settings(),
    )


def test_execution_attempt_identity_distinguishes_calls_and_retries_idempotently(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    first, _ = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id="provider-attempt-001",
    )
    retried, _ = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id="provider-attempt-001",
    )
    second, _ = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        execution_attempt_id="provider-attempt-002",
    )
    assert retried.receipt_id == first.receipt_id
    assert second.receipt_id != first.receipt_id
    assert receipt_db.scalar(select(func.count(ExecutionReceipt.receipt_id))) == 2


def test_exact_approval_binding_is_consumed_atomically_and_cannot_be_reused(
    receipt_db: Session,
) -> None:
    issued = datetime(2026, 7, 21, tzinfo=timezone.utc)
    action = _canonical_action()
    material = receipt_contract._canonical_material(action, tenant_id="tenant-a")
    binding = ApprovalBinding(
        tenant_id="tenant-a",
        chain_id=material["chain_id"],
        action_id=material["action_id"],
        approval_id="exact-single-use-approval",
            canonical_action_hash=material["canonical_action_hash"],
            receipt_material_hash=receipt_contract._hash(
                receipt_contract._approval_material(material)
            ),
        signed_receipt="server-signed-exact-single-use",
        material_fields={
            "receipt_material_schema": "1.0",
            "action_id": material["action_id"],
            "tool_fingerprint": material["tool_fingerprint"],
            "arguments_hash": material["parameter_hash"],
            "target_resource_hash": material["target_resource_hash"],
            "destination_hash": material["destination_hash"],
            "authority_hash": material["authority_hash"],
            "side_effect_class": material["side_effect_class"],
        },
        approved_at=issued - timedelta(minutes=1),
        expires_at=issued + timedelta(minutes=10),
        status="active",
    )
    receipt_db.add(binding)
    receipt_db.flush()
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=action,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="internal-mcp",
        settings_obj=_settings(),
        issued_at=issued,
        clock=lambda: issued,
    )
    receipt_db.refresh(binding)
    assert decision.approval_binding_id == binding.id
    assert binding.status == "used"
    with pytest.raises(ValueError, match="consumed|used|new approval"):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=action,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="different-execution-path",
            settings_obj=_settings(),
            issued_at=issued + timedelta(seconds=1),
        )


def test_receipt_lifetime_is_bounded_by_exact_binding_and_verifier_rejects_expiry(
    receipt_db: Session,
) -> None:
    issued = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    action = _canonical_action()
    material = receipt_contract._canonical_material(action, tenant_id="tenant-a")
    binding_expiry = issued + timedelta(minutes=1)
    binding = ApprovalBinding(
        tenant_id="tenant-a",
        chain_id=material["chain_id"],
        action_id=material["action_id"],
        approval_id="short-lived-exact-approval",
        canonical_action_hash=material["canonical_action_hash"],
        receipt_material_hash=receipt_contract._hash(
            receipt_contract._approval_material(material)
        ),
        signed_receipt="server-signed-short-lived-approval",
        material_fields=receipt_contract._approval_material(material),
        approved_at=issued - timedelta(minutes=1),
        expires_at=binding_expiry,
        status="active",
    )
    receipt_db.add(binding)
    receipt_db.flush()

    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=action,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="internal-mcp",
        settings_obj=_settings(),
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
        clock=lambda: issued,
    )
    receipt_db.refresh(binding)
    assert binding.status == "used"
    assert decision.expires_at.replace(tzinfo=timezone.utc) <= binding_expiry
    assert verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
        now=issued + timedelta(seconds=30),
        db=receipt_db,
    )
    assert not verify_decision_receipt(
        decision,
        tenant_id="tenant-a",
        settings_obj=_settings(),
        now=issued + timedelta(minutes=2),
        db=receipt_db,
    )


def test_binding_expiry_crossing_during_atomic_consume_rolls_back_without_receipt_or_evidence(
    receipt_db: Session,
) -> None:
    issued = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    action = _canonical_action()
    material = receipt_contract._canonical_material(action, tenant_id="tenant-a")
    binding = ApprovalBinding(
        tenant_id="tenant-a",
        chain_id=material["chain_id"],
        action_id=material["action_id"],
        approval_id="expiry-crossing-approval",
        canonical_action_hash=material["canonical_action_hash"],
        receipt_material_hash=receipt_contract._hash(
            receipt_contract._approval_material(material)
        ),
        signed_receipt="server-signed-expiry-crossing-approval",
        material_fields=receipt_contract._approval_material(material),
        approved_at=issued - timedelta(minutes=1),
        expires_at=issued + timedelta(milliseconds=120),
        status="active",
    )
    receipt_db.add(binding)
    receipt_db.flush()
    clock_values = iter(
        (
            issued + timedelta(milliseconds=50),
            issued + timedelta(milliseconds=200),
        )
    )

    with pytest.raises(ValueError, match="expired.*consumption|consumption.*expired"):
        create_decision_receipt(
            receipt_db,
            tenant_id="tenant-a",
            canonical_action=action,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="internal-mcp",
            settings_obj=_settings(),
            issued_at=issued,
            expires_at=issued + timedelta(minutes=5),
            clock=lambda: next(clock_values),
        )

    receipt_db.refresh(binding)
    assert binding.status == "active"
    assert receipt_db.scalar(select(func.count(DecisionReceipt.receipt_id))) == 0
    assert receipt_db.scalar(select(func.count(EvidenceNode.id))) == 0


def test_approval_consume_cas_compiles_for_postgresql_without_json_equality() -> None:
    conditions = receipt_contract._approval_binding_consume_conditions(
        binding_id="binding-1",
        tenant_id="tenant-a",
        action_id="action-1",
        chain_id="chain-1",
        canonical_action_hash_value="a" * 64,
        receipt_material_hash="b" * 64,
        consume_now=datetime(2026, 7, 21, tzinfo=timezone.utc),
    )
    statement = update(ApprovalBinding).where(*conditions).values(status="used")
    compiled = str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "approval_bindings.receipt_material_hash" in compiled
    assert "approval_bindings.material_fields" not in compiled


def test_same_attempt_actual_receipt_reconciles_signed_incomplete_to_one_current_integrity(
    receipt_db: Session,
) -> None:
    decision = create_decision_receipt(
        receipt_db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="mcp-gateway",
        settings_obj=_settings(),
    )
    receipt_db.commit()
    attempt_id = "fallback-then-actual-attempt"
    observed = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)
    persist_execution_failure_fallback_isolated(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
        evaluated_at=observed,
        execution_attempt_id=attempt_id,
    )
    incomplete = receipt_db.scalar(
        select(ExecutionIntegrityResult).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
            ExecutionIntegrityResult.execution_attempt_id == attempt_id,
        )
    )
    assert incomplete is not None and incomplete.result == "incomplete"
    incomplete_evidence_id = incomplete.evidence_bundle_id

    execution, reconciled = create_execution_receipt(
        receipt_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="provider-observer",
        settings_obj=_settings(),
        executed_at=observed,
        execution_attempt_id=attempt_id,
    )
    receipt_db.commit()
    assert reconciled.result == "matched"
    assert reconciled.execution_receipt_id == execution.receipt_id
    assert receipt_db.scalar(
        select(func.count(ExecutionIntegrityResult.result_id)).where(
            ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id,
            ExecutionIntegrityResult.execution_attempt_id == attempt_id,
        )
    ) == 1
    historical_evidence = receipt_db.get(EvidenceNode, incomplete_evidence_id)
    assert historical_evidence is not None
    assert historical_evidence.payload["result"] == "incomplete"
    assert historical_evidence.payload["signature"]
    supersession = receipt_db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == "tenant-a",
            EvidenceNode.node_type == "execution_integrity_supersession",
        )
    )
    assert supersession is not None
    assert supersession.payload["superseded_evidence_node_id"] == incomplete_evidence_id
    assert supersession.payload["current_evidence_node_id"] == reconciled.evidence_bundle_id
    assert verify_integrity_evidence(
        receipt_db,
        tenant_id="tenant-a",
        integrity=reconciled,
        settings_obj=_settings(),
    )
    original_supersession_payload = dict(supersession.payload)
    supersession.payload = {**original_supersession_payload, "current_result": "tampered"}
    receipt_db.flush()
    assert not verify_integrity_evidence(
        receipt_db,
        tenant_id="tenant-a",
        integrity=reconciled,
        settings_obj=_settings(),
    )
    supersession.payload = original_supersession_payload
    receipt_db.flush()
    assert verify_integrity_evidence(
        receipt_db,
        tenant_id="tenant-a",
        integrity=reconciled,
        settings_obj=_settings(),
    )
    reconciled.superseded_evidence_node_id = "tampered-old-evidence-link"
    receipt_db.flush()
    assert not verify_integrity_evidence(
        receipt_db,
        tenant_id="tenant-a",
        integrity=reconciled,
        settings_obj=_settings(),
    )
    fallback_finding = receipt_db.scalar(
        select(Finding).where(
            Finding.tenant_id == "tenant-a",
            Finding.finding_type == "EXECUTION_RECEIPT_PERSISTENCE_FAILURE",
        )
    )
    assert fallback_finding is not None
    assert fallback_finding.execution_attempt_id == attempt_id
