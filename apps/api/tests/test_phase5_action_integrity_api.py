from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker


def test_action_detail_route_key_is_only_a_bounded_runtime_event_id() -> None:
    from app.api.routers.action_integrity import validate_runtime_event_id

    assert validate_runtime_event_id("event-1") == "event-1"
    assert validate_runtime_event_id("event%2Fkept-literal") == "event%2Fkept-literal"
    for value in ("", "a/b", "x" * 129):
        with pytest.raises(ValueError):
            validate_runtime_event_id(value)


def test_action_detail_uses_the_closed_authority_timeline_order() -> None:
    from app.services.action_integrity.action_detail import TIMELINE_STAGES

    assert TIMELINE_STAGES == (
        "REQUEST", "ACTOR_RESOLUTION", "REPRESENTED_SUBJECT_RESOLUTION", "PURPOSE",
        "PROPOSED_ACTION", "DOMAIN_SEMANTICS", "POLICY", "APPROVAL", "PERMIT",
        "EXECUTION", "TARGET_CONFIRMATION", "COMPARISON", "OUTCOME", "PERSISTENT_EFFECT",
    )


def test_action_detail_uses_the_exact_registry_section_field_contract() -> None:
    """§12 is a field contract, not five opaque evidence wrappers."""
    from app.services.action_integrity.action_detail import ACTION_DETAIL_SECTION_FIELDS

    assert ACTION_DETAIL_SECTION_FIELDS == {
        "context": (
            "actor_principal", "executing_identity", "represented_subjects", "business_purpose", "authority", "delegation",
        ),
        "action": (
            "operation", "tool_or_service", "safe_parameters", "resources", "targets", "destinations",
            "values_or_quantities", "side_effect", "persistence", "reversibility",
        ),
        "control": (
            "requirements", "control_plan", "mandatory_floors", "assurance", "rejected_controls", "blind_spots",
        ),
        "authorisation": (
            "policy", "decision", "approval_request", "approval_binding", "decision_receipt", "execution_permits",
        ),
        "execution": (
            "observed_semantics", "execution_receipts", "evidence_quality", "material_integrity", "execution_state",
            "drift_fields", "outcome_integrity",
        ),
    }


def test_v2_approval_decision_body_requires_versioned_idempotency_fields() -> None:
    from app.api.routers.enforcement import ApprovalDecisionRequestV2

    body = ApprovalDecisionRequestV2(schema_version="2.0", decision="approve", expected_version=1, idempotency_key="decision-0000000001", reason="reviewed")
    assert body.schema_version == "2.0"


def test_v2_approval_body_rejects_invalid_idempotency_key() -> None:
    from pydantic import ValidationError
    from app.api.routers.enforcement import ApprovalDecisionRequestV2

    with pytest.raises(ValidationError):
        ApprovalDecisionRequestV2(schema_version="2.0", decision="approve", expected_version=1, idempotency_key="short")
    with pytest.raises(ValidationError):
        ApprovalDecisionRequestV2(schema_version="2.0", decision="other", expected_version=1, idempotency_key="decision-0000000001")


def _add_evidence(db: Session, *, tenant_id: str, node_id: str) -> None:
    from app.db.models.evidence import EvidenceNode

    db.add(EvidenceNode(
        id=node_id,
        tenant_id=tenant_id,
        node_type="action_integrity_test",
        signal_type="test",
        label=node_id,
        payload={},
    ))


def _add_base_decision(db: Session, *, tenant_id: str, receipt_id: str, action_id: str, evidence_node_id: str, issued_at: datetime) -> None:
    from app.db.models.evidence import DecisionReceipt

    db.add(DecisionReceipt(
        receipt_id=receipt_id,
        schema_version="1.0",
        tenant_id=tenant_id,
        action_id=action_id,
        chain_id="chain-action-detail",
        canonical_action_hash="c" * 64,
        actor_hash="a" * 64,
        authority_hash="u" * 64,
        purpose_hash="p" * 64,
        tool_fingerprint="t" * 64,
        parameter_hash="m" * 64,
        target_resource_hash="r" * 64,
        destination_hash="d" * 64,
        side_effect_class="read",
        approval_binding_hash="",
        policy_snapshot_id="policy-detail",
        decision="allow",
        control_mode="inline",
        transformations=[],
        expires_at=issued_at + timedelta(minutes=5),
        issued_at=issued_at,
        signature="legacy-signature",
        signing_key_id="legacy",
        collector_id="test",
        canonical_action_evidence_node_id=evidence_node_id,
        policy_snapshot_evidence_node_id=evidence_node_id,
        evidence_bundle_id=evidence_node_id,
        evidence_node_id=evidence_node_id,
        idempotency_key=f"decision:{receipt_id}",
    ))


def test_action_detail_never_discovers_authority_by_coincident_action_id(tmp_path) -> None:
    """A route event without exact stored refs cannot borrow a same-action permit."""
    from app.db.models.action_integrity import ExecutionPermitV2
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.action_detail import materialize_action_detail

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'action-detail-no-scan.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="No scan tenant", slug=f"no-scan-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            db.add(RuntimeEvent(
                tenant_id=tenant.id, event_id="event-no-scan-1", source_surface="api", event_type="action.executed",
                entity_type="action", entity_id="shared-action-id", metadata_json={"canonical_action": {"operation": "write"}},
            ))
            # This row deliberately shares a legacy action ID but is not an
            # event-bound authority reference, so it must remain invisible.
            db.add(ExecutionPermitV2(
                permit_id="permit-coincident-1", tenant_id=tenant.id, action_id="shared-action-id",
                canonical_action_hash="a" * 64, material_fields_hash="b" * 64,
                attempt_id="attempt-coincident-1", expires_at=datetime.now(timezone.utc) + timedelta(minutes=5), signed_envelope={},
            ))
            detail = materialize_action_detail(db, tenant_id=tenant.id, runtime_event_id="event-no-scan-1")
            assert detail is not None
            assert detail["action"]["operation"]["state"] == "UNKNOWN"
            assert detail["action"]["operation"]["reason_code"] == "canonical_action_field_not_persisted"
            assert detail["authorisation"]["execution_permits"]["state"] == "UNKNOWN"
            assert detail["authorisation"]["execution_permits"]["reason_code"] == "execution_permit_not_referenced"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_action_detail_requires_a_tenant_valid_evidence_node_for_every_observation(tmp_path) -> None:
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.action_detail import materialize_action_detail

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'action-detail-evidence-gate.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Evidence gate", slug=f"evidence-gate-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            db.add(RuntimeEvent(
                tenant_id=tenant.id, event_id="event-evidence-gate-1", source_surface="api", event_type="action.executed",
                entity_type="action", entity_id="action-evidence-gate-1", evidence_node_ids=["not-a-node"],
                metadata_json={
                    "canonical_action": {"operation": "read"},
                    "action_integrity_refs": {
                        "canonical_action_id": "action-evidence-gate-1",
                        "evidence_node_ids": {"context": ["not-a-node"], "action": ["not-a-node"]},
                    },
                },
            ))
            detail = materialize_action_detail(db, tenant_id=tenant.id, runtime_event_id="event-evidence-gate-1")
            assert detail is not None
            assert detail["context"]["actor_principal"]["state"] == "UNKNOWN"
            assert detail["context"]["actor_principal"]["occurred_at"] is None
            assert detail["action"]["operation"]["state"] == "UNKNOWN"
            assert detail["action"]["operation"]["occurred_at"] is None
            assert detail["timeline"][0]["state"] == "UNKNOWN"
            assert detail["timeline"][0]["occurred_at"] is None
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_action_detail_preserves_repeated_explicit_timeline_events_in_stable_order(tmp_path) -> None:
    from app.db.models.action_integrity import DecisionReceiptV2Extension, ExecutionComparisonV2, ExecutionPermitAttemptV2, ExecutionPermitV2, ExecutionReceiptV2Extension
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.action_detail import materialize_action_detail
    from app.services.action_integrity.execution_authority import PERMIT_DOMAIN
    from app.services.action_integrity.execution_proof import EXECUTION_COMPARISON_DOMAIN, EXECUTION_RECEIPT_DOMAIN
    from app.services.action_integrity.lifecycle_persistence import (
        DECISION_RECEIPT_DOMAIN,
        append_action_execution_transition_v2,
        reconstruct_action_execution_history_v2,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider, active_key_id, sign_object

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'action-detail-repeated.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    issued_at = datetime(2026, 8, 25, 9, tzinfo=timezone.utc)
    try:
        provider = LocalSigningKeyProvider(development=True)
        with session_local.begin() as db:
            tenant = Tenant(name="Repeated", slug=f"repeated-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            _add_evidence(db, tenant_id=tenant_id, node_id="evidence-repeated-1")
            _add_base_decision(
                db, tenant_id=tenant_id, receipt_id="decision-repeated-1", action_id="action-repeated-1",
                evidence_node_id="evidence-repeated-1", issued_at=issued_at,
            )

        for purpose, key_id, secret in (
            ("decision_receipt_signing", "decision", b"d" * 32),
            ("execution_permit_signing", "permit", b"p" * 32),
            ("execution_receipt_signing", "receipt", b"r" * 32),
            ("execution_comparison_signing", "comparison", b"c" * 32),
            ("execution_transition_signing", "transition", b"t" * 32),
        ):
            provider.add_key(purpose=purpose, tenant_id=tenant_id, key_id=key_id, secret=secret)

        with session_local.begin() as db:
            decision_signed = sign_object(
                provider, purpose="decision_receipt_signing", domain=DECISION_RECEIPT_DOMAIN, tenant_id=tenant_id,
                key_id=active_key_id(provider, purpose="decision_receipt_signing", tenant_id=tenant_id),
                value={
                    "schema_version": "2.0", "receipt_id": "decision-repeated-1", "tenant_id": tenant_id,
                    "action_id": "action-repeated-1", "canonical_action_hash": "c" * 64, "material_fields_hash": "m" * 64,
                    "policy_epoch": 1, "control_plan_digest": "p" * 64, "expires_at": (issued_at + timedelta(minutes=5)).isoformat(),
                    "issued_at": issued_at.isoformat(), "authoritative_decision": "ALLOW",
                },
            )
            db.add(DecisionReceiptV2Extension(
                receipt_id="decision-repeated-1", tenant_id=tenant_id, action_id="action-repeated-1",
                canonical_action_hash="c" * 64, material_fields_hash="m" * 64, policy_epoch=1, control_plan_digest="p" * 64,
                expires_at=issued_at + timedelta(minutes=5), authoritative_decision="ALLOW", algorithm=decision_signed["algorithm"],
                signing_key_id=decision_signed["signing_key_id"], signature=decision_signed["signature"], signed_envelope=decision_signed,
            ))
            permit_signed = sign_object(
                provider, purpose="execution_permit_signing", domain=PERMIT_DOMAIN, tenant_id=tenant_id,
                key_id=active_key_id(provider, purpose="execution_permit_signing", tenant_id=tenant_id),
                value={
                    "schema_version": "1.0", "permit_id": "permit-repeated-1", "tenant_id": tenant_id,
                    "action_id": "action-repeated-1", "attempt_id": "attempt-repeated-1", "decision_receipt_id": "decision-repeated-1",
                    "canonical_action_hash": "c" * 64, "material_fields_hash": "m" * 64, "policy_epoch": 1,
                    "issued_at": issued_at.isoformat(),
                },
            )
            db.add(ExecutionPermitV2(
                permit_id="permit-repeated-1", tenant_id=tenant_id, action_id="action-repeated-1", attempt_id="attempt-repeated-1",
                decision_receipt_id="decision-repeated-1", canonical_action_hash="c" * 64, material_fields_hash="m" * 64,
                policy_epoch=1, expires_at=issued_at + timedelta(minutes=5), algorithm=permit_signed["algorithm"],
                signing_key_id=permit_signed["signing_key_id"], signature=permit_signed["signature"], signed_envelope=permit_signed,
                created_at=issued_at + timedelta(days=1),
            ))
            db.add(ExecutionPermitAttemptV2(
                tenant_id=tenant_id, attempt_id="attempt-repeated-1", action_id="action-repeated-1", canonical_action_hash="c" * 64,
                material_fields_hash="m" * 64, status="PERMIT_ISSUED", decision_receipt_id="decision-repeated-1",
                execution_permit_id="permit-repeated-1", created_at=issued_at,
            ))
            receipt_signed = sign_object(
                provider, purpose="execution_receipt_signing", domain=EXECUTION_RECEIPT_DOMAIN, tenant_id=tenant_id,
                key_id=active_key_id(provider, purpose="execution_receipt_signing", tenant_id=tenant_id),
                value={
                    "schema_version": "2.0", "receipt_id": "receipt-repeated-1", "tenant_id": tenant_id,
                    "attempt_id": "attempt-repeated-1", "permit_id": "permit-repeated-1", "canonical_action_hash": "c" * 64,
                    "actual_material_fields_hash": "m" * 64, "terminal_state": "EXECUTED", "evidence_quality": "OS_OBSERVED",
                    "issued_at": (issued_at + timedelta(seconds=30)).isoformat(),
                },
            )
            db.add(ExecutionReceiptV2Extension(
                receipt_id="receipt-repeated-1", tenant_id=tenant_id, attempt_id="attempt-repeated-1", permit_id="permit-repeated-1",
                canonical_action_hash="c" * 64, actual_material_fields_hash="m" * 64, terminal_state="EXECUTED", evidence_quality="OS_OBSERVED",
                algorithm=receipt_signed["algorithm"], signing_key_id=receipt_signed["signing_key_id"], signature=receipt_signed["signature"], signed_envelope=receipt_signed,
            ))
            comparison_signed = sign_object(
                provider, purpose="execution_comparison_signing", domain=EXECUTION_COMPARISON_DOMAIN, tenant_id=tenant_id,
                key_id=active_key_id(provider, purpose="execution_comparison_signing", tenant_id=tenant_id),
                value={
                    "schema_version": "2.0", "comparison_id": "comparison-repeated-1", "tenant_id": tenant_id,
                    "attempt_id": "attempt-repeated-1", "canonical_action_hash": "c" * 64,
                    "material_fields_hash": "m" * 64, "result": "MATCHED", "drift_fields": [],
                    "unresolved_fields": [], "difference_hashes": [],
                    "issued_at": (issued_at + timedelta(seconds=40)).isoformat(),
                },
            )
            db.add(ExecutionComparisonV2(
                id="comparison-repeated-1", tenant_id=tenant_id, attempt_id="attempt-repeated-1",
                decision_receipt_id="decision-repeated-1", execution_receipt_id="receipt-repeated-1",
                result="MATCHED", material_differences=[], unresolved_fields=[],
                algorithm=comparison_signed["algorithm"], signing_key_id=comparison_signed["signing_key_id"],
                signature=comparison_signed["signature"], signed_envelope=comparison_signed,
                created_at=issued_at + timedelta(days=1),
            ))
            db.flush()
            first = append_action_execution_transition_v2(
                db, provider=provider, tenant_id=tenant_id, attempt_id="attempt-repeated-1", expected_state="PERMIT_ISSUED",
                expected_version=0, to_state="QUEUED", source="test", evidence_refs=["evidence-repeated-1"], observed_at=issued_at,
                received_at=issued_at, idempotency_key="repeated:1",
            )
            second = append_action_execution_transition_v2(
                db, provider=provider, tenant_id=tenant_id, attempt_id="attempt-repeated-1", expected_state="QUEUED",
                expected_version=1, to_state="IN_PROGRESS", source="test", evidence_refs=["evidence-repeated-1"],
                observed_at=issued_at + timedelta(seconds=10), received_at=issued_at + timedelta(seconds=10), idempotency_key="repeated:2",
            )
            assert reconstruct_action_execution_history_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                attempt_id="attempt-repeated-1",
            ) == ("IN_PROGRESS", 2)
            db.add(RuntimeEvent(
                tenant_id=tenant_id, event_id="event-repeated-1", source_surface="api", event_type="action.executed",
                entity_type="action", entity_id="action-repeated-1", created_at=issued_at,
                metadata_json={"canonical_action": {"operation": "read"}, "action_integrity_refs": {
                    "canonical_action_id": "action-repeated-1", "decision_receipt_id": "decision-repeated-1",
                    "execution_permit_id": "permit-repeated-1", "execution_receipt_id": "receipt-repeated-1",
                    "execution_comparison_id": "comparison-repeated-1",
                    "evidence_node_ids": {"context": ["evidence-repeated-1"], "action": ["evidence-repeated-1"], "decision": ["evidence-repeated-1"], "permit": ["evidence-repeated-1"], "execution": ["evidence-repeated-1"], "comparison": ["evidence-repeated-1"]},
                    "timeline_events": [
                        {"stage": "EXECUTION", "authority_type": "execution_transition", "authority_id": second.id, "sequence": 99, "evidence_node_ids": []},
                        {"stage": "EXECUTION", "authority_type": "execution_transition", "authority_id": first.id, "sequence": 99, "evidence_node_ids": []},
                    ],
                }},
            ))
            db.info["phase5_signing_provider"] = provider
            detail = materialize_action_detail(db, tenant_id=tenant_id, runtime_event_id="event-repeated-1")
            assert detail is not None
            execution = [item for item in detail["timeline"] if item["event_type"] == "EXECUTION"]
            assert [item["timeline_event_id"] for item in execution] == [
                "event-repeated-1:EXECUTION:" + first.id,
                "event-repeated-1:10",
                "event-repeated-1:EXECUTION:" + second.id,
            ]
            assert all(item["state"] == "OBSERVED" for item in execution)
            assert execution[1]["value"]["receipt_id"] == "receipt-repeated-1"
            permit_item = next(item for item in detail["timeline"] if item["event_type"] == "PERMIT")
            comparison_item = next(item for item in detail["timeline"] if item["event_type"] == "COMPARISON")
            assert permit_item["occurred_at"] == issued_at.isoformat()
            assert comparison_item["occurred_at"] == (issued_at + timedelta(seconds=40)).isoformat()
            assert detail["execution"]["drift_fields"]["occurred_at"] == (
                issued_at + timedelta(seconds=40)
            ).isoformat()
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_action_detail_uses_exact_event_refs_signed_evidence_and_tenant_safe_404(tmp_path) -> None:
    from app.api.routers.action_integrity import action_detail
    from app.db.models.action_integrity import DecisionReceiptV2Extension
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.action_detail import materialize_action_detail
    from app.services.action_integrity.lifecycle_persistence import DECISION_RECEIPT_DOMAIN
    from app.services.action_integrity.signing import LocalSigningKeyProvider, active_key_id, sign_object

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'action-detail-explicit.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    issued_at = datetime(2026, 8, 25, 9, tzinfo=timezone.utc)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Explicit refs", slug=f"explicit-{uuid4().hex[:8]}", is_active=True)
            other = Tenant(name="Other tenant", slug=f"other-{uuid4().hex[:8]}", is_active=True)
            db.add_all([tenant, other])
            db.flush()
            _add_evidence(db, tenant_id=tenant.id, node_id="evidence-detail-1")
            _add_base_decision(
                db, tenant_id=tenant.id, receipt_id="decision-detail-1", action_id="action-detail-1",
                evidence_node_id="evidence-detail-1", issued_at=issued_at,
            )
            db.add(RuntimeEvent(
                tenant_id=tenant.id, event_id="event-detail-1", source_surface="api", event_type="action.executed",
                entity_type="action", entity_id="action-detail-1", decision="allow", created_at=issued_at,
                evidence_node_ids=["evidence-detail-1"],
                metadata_json={
                    "canonical_action": {"actor_principal": "user:detail", "business_purpose": "test", "operation": "read"},
                    "action_integrity_refs": {
                        "canonical_action_id": "action-detail-1",
                        "decision_receipt_id": "decision-detail-1",
                        "evidence_node_ids": {
                            "context": ["evidence-detail-1"], "action": ["evidence-detail-1"],
                            "decision": ["evidence-detail-1"], "approval": ["evidence-detail-1"],
                            "permit": ["evidence-detail-1"], "execution": ["evidence-detail-1"],
                            "comparison": ["evidence-detail-1"], "persistent_effect": ["evidence-detail-1"],
                            "outcome": ["evidence-detail-1"],
                        },
                    },
                },
            ))
            tenant_id = tenant.id
            other_id = other.id

        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="decision_receipt_signing", tenant_id=tenant_id, key_id="decision", secret=b"d" * 32)
        with session_local.begin() as db:
            key_id = active_key_id(provider, purpose="decision_receipt_signing", tenant_id=tenant_id)
            signed = sign_object(
                provider, purpose="decision_receipt_signing", domain=DECISION_RECEIPT_DOMAIN, tenant_id=tenant_id, key_id=key_id,
                value={
                    "schema_version": "2.0", "receipt_id": "decision-detail-1", "tenant_id": tenant_id,
                    "action_id": "action-detail-1", "canonical_action_hash": "c" * 64,
                    "material_fields_hash": "m" * 64, "policy_epoch": 1, "control_plan_digest": "p" * 64,
                    "expires_at": (issued_at + timedelta(minutes=5)).isoformat(), "issued_at": issued_at.isoformat(),
                    "authoritative_decision": "ALLOW",
                },
            )
            db.add(DecisionReceiptV2Extension(
                receipt_id="decision-detail-1", tenant_id=tenant_id, action_id="action-detail-1",
                canonical_action_hash="c" * 64, material_fields_hash="m" * 64, policy_epoch=1, control_plan_digest="p" * 64,
                expires_at=issued_at + timedelta(minutes=5), algorithm=signed["algorithm"], signing_key_id=signed["signing_key_id"],
                signature=signed["signature"], signed_envelope=signed, authoritative_decision="ALLOW",
            ))
            db.info["phase5_signing_provider"] = provider
            detail = materialize_action_detail(db, tenant_id=tenant_id, runtime_event_id="event-detail-1")
            assert detail is not None
            assert detail["identity"]["runtime_event_id"] == "event-detail-1"
            assert detail["identity"]["decision_receipt_id"] == "decision-detail-1"
            assert tuple(detail["context"]) == ("actor_principal", "executing_identity", "represented_subjects", "business_purpose", "authority", "delegation")
            assert tuple(detail["action"]) == ("operation", "tool_or_service", "safe_parameters", "resources", "targets", "destinations", "values_or_quantities", "side_effect", "persistence", "reversibility")
            assert tuple(detail["control"]) == ("requirements", "control_plan", "mandatory_floors", "assurance", "rejected_controls", "blind_spots")
            assert tuple(detail["authorisation"]) == ("policy", "decision", "approval_request", "approval_binding", "decision_receipt", "execution_permits")
            assert tuple(detail["execution"]) == ("observed_semantics", "execution_receipts", "evidence_quality", "material_integrity", "execution_state", "drift_fields", "outcome_integrity")
            for section in ("context", "action", "control", "authorisation", "execution"):
                for card in detail[section].values():
                    assert set(card) == {"state", "value", "evidence_refs", "occurred_at", "reason_code"}
            for section, field in (
                ("context", "represented_subjects"),
                ("action", "resources"), ("action", "targets"), ("action", "destinations"), ("action", "values_or_quantities"),
                ("control", "requirements"), ("control", "mandatory_floors"), ("control", "rejected_controls"), ("control", "blind_spots"),
                ("authorisation", "execution_permits"),
                ("execution", "execution_receipts"), ("execution", "drift_fields"),
            ):
                assert isinstance(detail[section][field]["value"], list)
            assert detail["action"]["operation"]["state"] == "OBSERVED"
            assert detail["authorisation"]["decision_receipt"]["state"] == "OBSERVED"
            assert detail["timeline"][10]["event_type"] == "TARGET_CONFIRMATION"
            assert detail["timeline"][10]["state"] == "UNKNOWN"
            assert detail["timeline"][10]["source_authority_ref"] == ""
            assert [row["event_type"] for row in detail["timeline"]] == list(__import__("app.services.action_integrity.action_detail", fromlist=["TIMELINE_STAGES"]).TIMELINE_STAGES)
            assert [row["stage_ordinal"] for row in detail["timeline"]] == list(range(1, 15))
            assert all(row["occurred_at"] is None for row in detail["timeline"] if row["state"] != "OBSERVED")

            # The API returns an href encoded from the one decoded route key.
            # A literal percent sequence is data, not a second route decode.
            db.add(RuntimeEvent(
                tenant_id=tenant_id, event_id="event%2Fkept-literal", source_surface="api", event_type="action.observed",
                metadata_json={},
            ))
            db.flush()
            literal = materialize_action_detail(db, tenant_id=tenant_id, runtime_event_id="event%2Fkept-literal")
            assert literal is not None
            assert literal["identity"]["runtime_event_id"] == "event%2Fkept-literal"
            assert literal["browser_hrefs"] == [{
                "relation": "ACTION_DETAIL", "route_key_type": "runtime_event_id", "route_key": "event%2Fkept-literal",
                "href": "/runtime-intelligence/action-trace/event%252Fkept-literal",
            }]

            # Both missing and foreign route keys are intentionally the same 404.
            with pytest.raises(HTTPException) as missing:
                action_detail("missing-event", ctx=SimpleNamespace(tenant=SimpleNamespace(id=other_id)), db=db)
            with pytest.raises(HTTPException) as foreign:
                action_detail("event-detail-1", ctx=SimpleNamespace(tenant=SimpleNamespace(id=other_id)), db=db)
            assert missing.value.status_code == foreign.value.status_code == 404
            assert missing.value.detail == foreign.value.detail

            extension = db.get(DecisionReceiptV2Extension, "decision-detail-1")
            assert extension is not None
            extension.signature = "tampered"
            tampered = materialize_action_detail(db, tenant_id=tenant_id, runtime_event_id="event-detail-1")
            assert tampered is not None
            assert tampered["authorisation"]["decision_receipt"]["state"] == "UNKNOWN"
            assert tampered["authorisation"]["decision_receipt"]["reason_code"] == "invalid_signed_evidence"

            # A valid signature is still insufficient when a material field that
            # the UI would display is absent from its signed envelope.
            incomplete = sign_object(
                provider, purpose="decision_receipt_signing", domain=DECISION_RECEIPT_DOMAIN, tenant_id=tenant_id, key_id=key_id,
                value={
                    "schema_version": "2.0", "receipt_id": "decision-detail-1", "tenant_id": tenant_id,
                    "action_id": "action-detail-1", "canonical_action_hash": "c" * 64,
                    "material_fields_hash": "m" * 64, "policy_epoch": 1, "control_plan_digest": "p" * 64,
                    "expires_at": (issued_at + timedelta(minutes=5)).isoformat(), "issued_at": issued_at.isoformat(),
                },
            )
            extension.algorithm = incomplete["algorithm"]
            extension.signing_key_id = incomplete["signing_key_id"]
            extension.signature = incomplete["signature"]
            extension.signed_envelope = incomplete
            incomplete_detail = materialize_action_detail(db, tenant_id=tenant_id, runtime_event_id="event-detail-1")
            assert incomplete_detail is not None
            assert incomplete_detail["authorisation"]["decision_receipt"]["state"] == "UNKNOWN"
            assert incomplete_detail["authorisation"]["decision_receipt"]["reason_code"] == "invalid_signed_evidence"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
