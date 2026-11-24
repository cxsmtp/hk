from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.activity_audit import AIAction, AISession
from app.db.models.evidence import DecisionReceipt, EvidenceEdge, EvidenceNode
from app.db.models.finding import Finding
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.receipt_service import (
    create_decision_receipt,
    create_execution_receipt,
    record_execution_unknown,
)
from app.services.ai_iam_service import build_ai_action_record


def _bundle_service():
    try:
        from app.services import canonical_evidence_bundle_service
    except ImportError:
        pytest.fail("canonical evidence bundle service is not implemented")
    return canonical_evidence_bundle_service


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        decision_execution_receipts_enabled=True,
        receipt_signing_active_key_id="bundle-key-2026",
        receipt_signing_keys_json=json.dumps(
            {
                "bundle-key-2025": "old-bundle-signing-material-000000001",
                "bundle-key-2026": "new-bundle-signing-material-000000001",
            }
        ),
    )


@pytest.fixture()
def bundle_db(tmp_path) -> Session:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'canonical-bundle.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with local() as db:
        db.add_all(
            [
                Tenant(id="tenant-a", name="Tenant A", slug="tenant-a", is_active=True),
                Tenant(id="tenant-b", name="Tenant B", slug="tenant-b", is_active=True),
            ]
        )
        db.flush()
        pack = PolicyPack(
            id="policy-pack-a",
            tenant_id="tenant-a",
            name="Selected runtime policy",
            description="Exact server authority",
            status="active",
        )
        db.add(pack)
        db.flush()
        db.add(
            PolicyVersion(
                id="policy-version-a",
                tenant_id="tenant-a",
                pack_id=pack.id,
                version="7.4.0",
                scope={
                    "applications": ["llm_gateway", "mcp_gateway"],
                    "secret_token": "raw-policy-secret-must-not-persist",
                },
                enforcement_defaults={"mode": "enforce", "decision": "allow"},
                guardian_contracts=[{"contract_id": "prompt_guardian", "version": "2"}],
                contract_json={"controls": ["PROMPT_CONTROL", "TOOL_CALL_VALIDATION"]},
            )
        )
        db.commit()
        yield db
        db.rollback()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def _canonical_action(*, action_id: str = "bundle-action-1") -> dict:
    return {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "action_id": action_id,
        "tenant_id": "tenant-a",
        "chain_id": "bundle-chain-1",
        "actor": {"identity_id": "user-1", "identity_type": "human"},
        "authority": {
            "authority_type": "authenticated_user",
            "authority_source": "tenant_context",
            "verified": True,
        },
        "purpose": {"declared_purpose": "customer support"},
        "surface": {"application": "llm_gateway", "environment": "prod"},
        "action": {
            "action_type": "prompt",
            "tool_name": "llm.generate",
            "tool_version": "model-v1",
            "tool_fingerprint_id": "tool-fingerprint-1",
            "parameter_hash": "parameter-hash-1",
            "target_resource": "provider-a",
            "target_resource_hash": "target-resource-hash-1",
            "data_destination": "provider-a",
            "destination_hash": "destination-hash-1",
            "side_effect_class": "external_provider_call",
        },
        "approval": {"approval_binding_id": None},
        "policy": {
            "policy_snapshot_id": "policy-version-a",
            "decision": "allow",
            "control_mode": "inline_allowed",
            "control_ids": ["PROMPT_CONTROL"],
        },
        "transformations": [],
    }


def _decision(db: Session) -> DecisionReceipt:
    issued = datetime.now(timezone.utc)
    decision = create_decision_receipt(
        db,
        tenant_id="tenant-a",
        canonical_action=_canonical_action(),
        decision="allow",
        control_mode="inline_allowed",
        collector_id="selected-llm",
        settings_obj=_settings(),
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
    )
    assert decision is not None
    return decision


def test_models_expose_tenant_safe_non_overwriting_canonical_bundle_links() -> None:
    assert hasattr(DecisionReceipt, "policy_snapshot_evidence_node_id")
    assert hasattr(DecisionReceipt, "evidence_bundle_id")
    assert hasattr(AIAction, "evidence_bundle_id")
    assert hasattr(RuntimeEvent, "evidence_bundle_id")


def test_canonical_edge_identity_is_stable_and_binds_integrity_key() -> None:
    service = _bundle_service()
    payload = {"role": "bundle_member", "member_hash": "member-hash"}
    first = service._canonical_edge_identity(
        tenant_id="tenant-a",
        from_node_id="manifest-a",
        to_node_id="member-a",
        edge_type="bundle_member",
        payload=payload,
    )
    repeated = service._canonical_edge_identity(
        tenant_id="tenant-a",
        from_node_id="manifest-a",
        to_node_id="member-a",
        edge_type="bundle_member",
        payload=payload,
    )
    integrity_key = service._receipt_contract()._hash(
        {
            "tenant_id": "tenant-a",
            "from_node_id": "manifest-a",
            "to_node_id": "member-a",
            "edge_type": "bundle_member",
            "payload": payload,
        }
    )
    expected_id = str(
        uuid5(
            NAMESPACE_URL,
            "hawk:evidence-edge:tenant-a:manifest-a:member-a:bundle_member:"
            f"{integrity_key}",
        )
    )
    assert first == repeated == (integrity_key, expected_id)


def test_policy_snapshot_signature_survives_source_change_but_reports_not_current(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    node = service.create_policy_snapshot(
        bundle_db,
        tenant_id="tenant-a",
        policy_version_id="policy-version-a",
        captured_at=datetime.now(timezone.utc),
        settings_obj=_settings(),
    )
    first = service.verify_policy_snapshot(
        bundle_db,
        tenant_id="tenant-a",
        snapshot=node,
        settings_obj=_settings(),
    )
    assert first == {"signature_valid": True, "source_current": True, "valid": True}
    assert "raw-policy-secret-must-not-persist" not in json.dumps(node.payload)

    policy = bundle_db.get(PolicyVersion, "policy-version-a")
    policy.scope = {**dict(policy.scope), "applications": ["llm_gateway"]}
    bundle_db.flush()
    changed = service.verify_policy_snapshot(
        bundle_db,
        tenant_id="tenant-a",
        snapshot=node,
        settings_obj=_settings(),
    )
    assert changed == {"signature_valid": True, "source_current": False, "valid": True}

    node.payload = {**dict(node.payload), "source_material_hash": "0" * 64}
    bundle_db.flush()
    tampered = service.verify_policy_snapshot(
        bundle_db,
        tenant_id="tenant-a",
        snapshot=node,
        settings_obj=_settings(),
    )
    assert tampered["signature_valid"] is False
    assert tampered["valid"] is False


def test_bundle_is_signed_recursive_redaction_safe_and_honestly_unknown(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    unknown = record_execution_unknown(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
        execution_attempt_id="unknown-attempt",
    )
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    verified = service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )
    assert verified["valid"] is True, verified
    assert verified["integrity_status"] == "execution_unknown"
    assert manifest.payload["execution_attempts"] == [
        {
            "execution_attempt_id": unknown.execution_attempt_id,
            "execution_receipt_id": None,
            "integrity_result_id": unknown.result_id,
            "integrity_result": "execution_unknown",
        }
    ]
    assert "raw-policy-secret-must-not-persist" not in json.dumps(root.payload)
    assert "raw-policy-secret-must-not-persist" not in json.dumps(manifest.payload)

    with pytest.raises(ValueError, match="tenant"):
        service.refresh_evidence_bundle(
            bundle_db,
            tenant_id="tenant-b",
            decision_receipt_id=decision.receipt_id,
            settings_obj=_settings(),
        )


def test_bundle_revision_chain_is_monotonic_idempotent_and_retains_history(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    first_root, first_manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    _, integrity = create_execution_receipt(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="selected-llm-provider",
        settings_obj=_settings(),
        execution_attempt_id="terminal-attempt",
    )
    second_root, second_manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    repeated_root, repeated_manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert first_root.id == second_root.id == repeated_root.id
    assert second_manifest.id == repeated_manifest.id
    assert second_manifest.id != first_manifest.id
    assert second_manifest.payload["manifest_version"] == first_manifest.payload["manifest_version"] + 1
    assert second_manifest.payload["previous_manifest_id"] == first_manifest.id
    assert second_manifest.payload["execution_attempts"][0]["integrity_result_id"] == integrity.result_id
    assert bundle_db.scalar(
        select(func.count(EvidenceNode.id)).where(
            EvidenceNode.tenant_id == "tenant-a",
            EvidenceNode.node_type == "canonical_evidence_bundle_manifest_v1",
        )
    ) == 2


def test_bundle_verifier_rejects_manifest_tamper_missing_members_and_unknown_keys(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    original = dict(manifest.payload)
    manifest.payload = {**original, "members_root_hash": "f" * 64}
    bundle_db.flush()
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]

    manifest.payload = original
    membership = bundle_db.scalar(
        select(EvidenceEdge).where(
            EvidenceEdge.tenant_id == "tenant-a",
            EvidenceEdge.from_node_id == manifest.id,
            EvidenceEdge.edge_type == "bundle_member",
        )
    )
    bundle_db.delete(membership)
    bundle_db.flush()
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]

    bundle_db.rollback()
    decision = bundle_db.scalar(
        select(DecisionReceipt).where(DecisionReceipt.tenant_id == "tenant-a")
    )
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    manifest.payload = {**dict(manifest.payload), "signing_key_id": "unknown-key"}
    bundle_db.flush()
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]


def test_same_member_can_hold_multiple_roles_without_duplicate_edges_on_retry(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    drifted = deepcopy(_canonical_action())
    drifted["action"]["parameter_hash"] = "changed-parameter-hash"
    create_execution_receipt(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=drifted,
        execution_status="success",
        collector_id="selected-llm-provider",
        settings_obj=_settings(),
        execution_attempt_id="drift-attempt",
    )
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    integrity_node_id = next(
        member["node_id"]
        for member in manifest.payload["members"]
        if member["role"] == "current_execution_integrity"
    )
    roles = {
        edge.payload["role"]
        for edge in bundle_db.scalars(
            select(EvidenceEdge).where(
                EvidenceEdge.tenant_id == "tenant-a",
                EvidenceEdge.from_node_id == manifest.id,
                EvidenceEdge.to_node_id == integrity_node_id,
                EvidenceEdge.edge_type == "bundle_member",
            )
        ).all()
    }
    assert roles == {"current_execution_integrity", "finding_evidence"}
    edge_count = bundle_db.scalar(
        select(func.count(EvidenceEdge.id)).where(
            EvidenceEdge.tenant_id == "tenant-a",
            EvidenceEdge.from_node_id == manifest.id,
            EvidenceEdge.to_node_id == integrity_node_id,
            EvidenceEdge.edge_type == "bundle_member",
        )
    )

    repeated_root, repeated_manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert repeated_root.id == root.id
    assert repeated_manifest.id == manifest.id
    assert bundle_db.scalar(
        select(func.count(EvidenceEdge.id)).where(
            EvidenceEdge.tenant_id == "tenant-a",
            EvidenceEdge.from_node_id == manifest.id,
            EvidenceEdge.to_node_id == integrity_node_id,
            EvidenceEdge.edge_type == "bundle_member",
        )
    ) == edge_count


def test_concurrent_refresh_is_stable_monotonic_and_loses_no_attempts_or_findings(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    bundle_db.commit()
    session_factory = sessionmaker(
        bind=bundle_db.get_bind(), autocommit=False, autoflush=False
    )

    with session_factory() as first:
        record_execution_unknown(
            first,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            settings_obj=_settings(),
            execution_attempt_id="race-attempt-a",
        )
        first.commit()
    drifted = deepcopy(_canonical_action())
    drifted["action"]["destination_hash"] = "race-destination-drift"
    with session_factory() as second:
        create_execution_receipt(
            second,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=drifted,
            execution_status="success",
            collector_id="selected-llm-provider",
            settings_obj=_settings(),
            execution_attempt_id="race-attempt-b",
        )
        second.commit()

    with session_factory() as staged:
        integrity_node_id = staged.scalar(
            select(EvidenceNode.id)
            .where(
                EvidenceNode.tenant_id == "tenant-a",
                EvidenceNode.node_type == "execution_integrity_result",
            )
            .order_by(EvidenceNode.created_at.desc())
        )
        staged.add(
            Finding(
                finding_id="race-staged-finding",
                tenant_id="tenant-a",
                source_surface="receipt",
                ai_tool="execution_integrity",
                severity="high",
                finding_type="RACE_STAGED_FINDING",
                risk_category="approval_execution_drift",
                decision="block",
                status="open",
                recommended_action="Review the staged race finding.",
                policy_id="decision_execution_receipts",
                evidence_node_ids=[integrity_node_id],
                related_event_ids=[decision.action_id, decision.receipt_id],
                related_control_ids=["TOOL_CALL_VALIDATION"],
                remediation_action_ids=[],
                evidence_status="complete",
                canonical_action_id=decision.action_id,
                execution_attempt_id="race-attempt-b",
                dedupe_key="race-staged-finding",
                occurrence_count=1,
            )
        )
        staged.commit()

    with session_factory() as before:
        revision_count = before.scalar(
            select(func.count(EvidenceNode.id)).where(
                EvidenceNode.tenant_id == "tenant-a",
                EvidenceNode.node_type == "canonical_evidence_bundle_manifest_v1",
            )
        )

    def _refresh() -> tuple[str, str]:
        with session_factory() as local:
            root, manifest = service.refresh_evidence_bundle(
                local,
                tenant_id="tenant-a",
                decision_receipt_id=decision.receipt_id,
                settings_obj=_settings(),
            )
            local.commit()
            return root.id, manifest.id

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: _refresh(), range(2)))
    assert len({root_id for root_id, _manifest_id in results}) == 1
    assert len({manifest_id for _root_id, manifest_id in results}) == 1

    with session_factory() as final:
        root = final.get(EvidenceNode, results[0][0])
        manifest = final.get(EvidenceNode, results[0][1])
        attempts = {
            item["execution_attempt_id"] for item in manifest.payload["execution_attempts"]
        }
        assert attempts == {"race-attempt-a", "race-attempt-b"}
        assert manifest.payload["findings"]
        manifests = list(
            final.scalars(
                select(EvidenceNode).where(
                    EvidenceNode.tenant_id == "tenant-a",
                    EvidenceNode.node_type == "canonical_evidence_bundle_manifest_v1",
                )
            ).all()
        )
        versions = sorted(int(item.payload["manifest_version"]) for item in manifests)
        assert versions == list(range(1, len(versions) + 1))
        assert len({item.id for item in manifests}) == len(manifests)
        assert len(manifests) == revision_count + 1
        assert any(
            item["finding_id"] == "race-staged-finding"
            for item in manifest.payload["findings"]
        )
        assert service.verify_evidence_bundle(
            final,
            tenant_id="tenant-a",
            bundle=root,
            settings_obj=_settings(),
        )["valid"]


def test_ai_iam_legacy_bundle_is_display_only_unless_canonical_verifier_supplies_reference() -> None:
    legacy = build_ai_action_record(
        tenant_id="tenant-a",
        action_id="legacy-action",
        timestamp="2026-07-22T00:00:00Z",
        source_surface="browser",
        event_type="page_view",
        user_id="user-1",
        evidence_node_ids=["legacy-node"],
        decision="allow",
    )
    assert legacy["evidence_bundle"]["integrity_status"] == "unverified_legacy"
    assert legacy["evidence_bundle"]["canonical_authority"] is False
    assert legacy["evidence_bundle"]["display_only"] is True

    canonical = build_ai_action_record(
        tenant_id="tenant-a",
        action_id="canonical-action",
        timestamp="2026-07-22T00:00:00Z",
        source_surface="gateway",
        event_type="gateway_model_call",
        user_id="user-1",
        evidence_node_ids=["canonical-root"],
        decision="allow",
        trusted_pre_action_governance_check={
            "evidence": {
                "canonical_evidence_bundle": {
                    "evidence_bundle_id": "canonical-root",
                    "manifest_id": "canonical-manifest",
                    "bundle_hash": "signed-manifest-hash",
                    "integrity_status": "complete",
                    "verified": True,
                }
            }
        },
    )
    assert canonical["evidence_bundle"] == {
        "evidence_bundle_id": "canonical-root",
        "bundle_hash": "signed-manifest-hash",
        "manifest_id": "canonical-manifest",
        "integrity_status": "complete",
        "verification_status": "verified",
        "canonical_authority": True,
        "authority_source": "canonical_evidence_bundle_verifier",
        "display_only": True,
        "evidence_refs": ["canonical-root"],
        "evidence_ref_count": 1,
    }


def test_append_only_refresh_works_with_real_immutable_evidence_triggers(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    bundle_db.commit()
    for table_name in ("evidence_nodes", "evidence_edges"):
        bundle_db.execute(
            text(
                f"""
                CREATE TRIGGER trg_test_{table_name}_immutable_update
                BEFORE UPDATE ON {table_name}
                FOR EACH ROW BEGIN
                  SELECT RAISE(ABORT, 'immutable_table:{table_name}');
                END
                """
            )
        )
    bundle_db.commit()

    record_execution_unknown(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
        execution_attempt_id="immutable-attempt",
    )
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    bundle_db.commit()
    repeated_root, repeated_manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert (repeated_root.id, repeated_manifest.id) == (root.id, manifest.id)
    bundle_db.commit()

    with pytest.raises(DBAPIError, match="immutable_table:evidence_nodes"):
        bundle_db.execute(
            text("UPDATE evidence_nodes SET label=label WHERE id=:node_id"),
            {"node_id": root.id},
        )
    bundle_db.rollback()
    edge_id = bundle_db.scalar(
        select(EvidenceEdge.id).where(EvidenceEdge.from_node_id == root.id)
    )
    with pytest.raises(DBAPIError, match="immutable_table:evidence_edges"):
        bundle_db.execute(
            text("UPDATE evidence_edges SET edge_type=edge_type WHERE id=:edge_id"),
            {"edge_id": edge_id},
        )
    bundle_db.rollback()


def test_signed_typed_node_identity_and_exact_extra_edge_are_enforced(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    snapshot = bundle_db.get(EvidenceNode, decision.policy_snapshot_evidence_node_id)
    cloned_snapshot = EvidenceNode(
        id="cloned-policy-snapshot",
        tenant_id="tenant-a",
        node_type=snapshot.node_type,
        signal_type=snapshot.signal_type,
        label=snapshot.label,
        payload=dict(snapshot.payload),
    )
    cloned_root = EvidenceNode(
        id="cloned-bundle-root",
        tenant_id="tenant-a",
        node_type=root.node_type,
        signal_type=root.signal_type,
        label=root.label,
        payload=dict(root.payload),
    )
    cloned_manifest = EvidenceNode(
        id="cloned-bundle-manifest",
        tenant_id="tenant-a",
        node_type=manifest.node_type,
        signal_type=manifest.signal_type,
        label=manifest.label,
        payload=dict(manifest.payload),
    )
    bundle_db.add_all([cloned_snapshot, cloned_root, cloned_manifest])
    bundle_db.flush()
    assert not service.verify_policy_snapshot(
        bundle_db,
        tenant_id="tenant-a",
        snapshot=cloned_snapshot,
        settings_obj=_settings(),
    )["valid"]
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=cloned_root,
        settings_obj=_settings(),
    )["valid"]
    service._edge(
        bundle_db,
        tenant_id="tenant-a",
        from_node_id=root.id,
        to_node_id=cloned_manifest.id,
        edge_type="bundle_manifest",
        payload={
            "manifest_version": manifest.payload["manifest_version"],
            "manifest_hash": service._receipt_contract()._hash(
                service._node_body(cloned_manifest)
            ),
        },
    )
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]


def test_latest_manifest_rejects_extra_member_edge_and_finding_cap_max_plus_one(
    bundle_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    member = manifest.payload["members"][0]
    service._edge(
        bundle_db,
        tenant_id="tenant-a",
        from_node_id=manifest.id,
        to_node_id=member["node_id"],
        edge_type="bundle_member",
        payload={"role": "unauthorized_extra", "member_hash": member["member_hash"]},
    )
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]
    bundle_db.rollback()
    decision = bundle_db.scalar(
        select(DecisionReceipt).where(DecisionReceipt.tenant_id == "tenant-a")
    )
    monkeypatch.setattr(service, "MAX_FINDINGS", 1)
    for index in range(2):
        bundle_db.add(
            Finding(
                finding_id=f"cap-finding-{index}",
                tenant_id="tenant-a",
                source_surface="receipt",
                ai_tool="execution_integrity",
                severity="low",
                finding_type="CAP_TEST",
                risk_category="test",
                decision="allow",
                status="open",
                recommended_action="none",
                evidence_node_ids=[],
                related_event_ids=[],
                related_control_ids=[],
                remediation_action_ids=[],
                evidence_status="complete",
                canonical_action_id=decision.action_id,
                dedupe_key=f"cap-finding-{index}",
                occurrence_count=1,
            )
        )
        bundle_db.flush()
        if index == 0:
            service.refresh_evidence_bundle(
                bundle_db,
                tenant_id="tenant-a",
                decision_receipt_id=decision.receipt_id,
                settings_obj=_settings(),
            )
    with pytest.raises(ValueError, match="findings limit exceeded"):
        service.refresh_evidence_bundle(
            bundle_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            settings_obj=_settings(),
        )


def test_historical_manifest_rejects_extra_member_edge_after_later_revision(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    root, first_manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    create_execution_receipt(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="selected-llm-provider",
        settings_obj=_settings(),
        execution_attempt_id="historical-topology-attempt",
    )
    _, second_manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert second_manifest.payload["previous_manifest_id"] == first_manifest.id
    historical_member = first_manifest.payload["members"][0]
    service._edge(
        bundle_db,
        tenant_id="tenant-a",
        from_node_id=first_manifest.id,
        to_node_id=historical_member["node_id"],
        edge_type="bundle_member",
        payload={
            "role": "unauthorized_historical_extra",
            "member_hash": historical_member["member_hash"],
        },
    )
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]


@pytest.mark.parametrize("object_count", [32, 33, 128])
def test_downstream_aggregate_accepts_receipt_boundary_without_member_explosion(
    bundle_db: Session,
    object_count: int,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    raw_secret = "ssn-123-45-6789-private"
    execution, _ = create_execution_receipt(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="selected-llm-provider",
        settings_obj=_settings(),
        execution_attempt_id=f"downstream-boundary-{object_count}",
        downstream_objects=[
            {"type": (raw_secret if index == 0 else "webhook"), "id": f"raw-{index}"}
            for index in range(object_count)
        ],
    )
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    downstream_members = [
        item for item in manifest.payload["members"]
        if item["role"] == "downstream_objects"
    ]
    assert len(downstream_members) == 1
    assert downstream_members[0]["object_count"] == object_count
    assert downstream_members[0]["aggregate_hash"]
    serialized = json.dumps(
        {
            "execution": execution.downstream_objects,
            "manifest": manifest.payload,
            "edges": [
                edge.payload
                for edge in bundle_db.scalars(
                    select(EvidenceEdge).where(
                        EvidenceEdge.from_node_id == manifest.id,
                        EvidenceEdge.edge_type == "bundle_member",
                    )
                ).all()
            ],
        }
    )
    assert raw_secret not in serialized
    assert '"object_type": "other"' in serialized
    assert service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]


def test_downstream_129_is_rejected_at_shared_receipt_boundary(
    bundle_db: Session,
) -> None:
    decision = _decision(bundle_db)
    with pytest.raises(ValueError, match="downstream_objects exceeds maximum items"):
        create_execution_receipt(
            bundle_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="selected-llm-provider",
            settings_obj=_settings(),
            execution_attempt_id="downstream-overflow-129",
            downstream_objects=[{"type": "webhook", "id": index} for index in range(129)],
        )


def test_two_terminal_attempts_with_128_objects_use_compact_signed_aggregates(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    for attempt_index in range(2):
        create_execution_receipt(
            bundle_db,
            tenant_id="tenant-a",
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=_canonical_action(),
            execution_status="success",
            collector_id="selected-llm-provider",
            settings_obj=_settings(),
            execution_attempt_id=f"compact-128-attempt-{attempt_index}",
            downstream_objects=[
                {"type": "webhook", "id": f"attempt-{attempt_index}-object-{index}"}
                for index in range(128)
            ],
        )
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert bundle_db.scalar(
        select(func.count()).select_from(service.ExecutionReceipt).where(
            service.ExecutionReceipt.decision_receipt_id == decision.receipt_id
        )
    ) == 2
    assert bundle_db.scalar(
        select(func.count()).select_from(service.ExecutionIntegrityResult).where(
            service.ExecutionIntegrityResult.decision_receipt_id == decision.receipt_id
        )
    ) == 2
    aggregates = manifest.payload["downstream_objects"]
    assert len(aggregates) == 2
    assert all(
        set(item) == {
            "execution_attempt_id",
            "execution_receipt_id",
            "object_count",
            "aggregate_hash",
        }
        and item["object_count"] == 128
        for item in aggregates
    )
    serialized = json.dumps(manifest.payload)
    assert '"object_hash"' not in serialized
    assert '"objects"' not in serialized
    assert service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]


def test_member_hash_binds_correlation_but_excludes_storage_timestamps(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    member = manifest.payload["members"][0]
    node = bundle_db.get(EvidenceNode, member["node_id"])
    assert service.NON_AUTHORITATIVE_NODE_STORAGE_FIELDS == {"created_at", "updated_at"}
    assert not service.NON_AUTHORITATIVE_NODE_STORAGE_FIELDS.intersection(
        service._node_body(node)
    )
    node.correlation_id = "tampered-correlation"
    bundle_db.flush()
    assert not service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]


def test_canonical_provenance_ids_survive_pii_heuristics_and_reverify(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    canonical = deepcopy(_canonical_action(action_id="pii-shaped-provenance-action"))
    actor_uuid = "12345678-1234-4234-8234-123456789012"
    owner_uuid = "98765432-1234-4234-8234-123456789012"
    canonical["actor"]["identity_id"] = actor_uuid
    canonical["authority"]["authority_owner"] = owner_uuid
    issued = datetime.now(timezone.utc)
    decision = create_decision_receipt(
        bundle_db,
        tenant_id="tenant-a",
        canonical_action=canonical,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="selected-mcp",
        settings_obj=_settings(),
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
    )
    canonical_node = bundle_db.get(
        EvidenceNode, decision.canonical_action_evidence_node_id
    )
    stored = canonical_node.payload["canonical_action"]
    assert stored["actor"]["identity_id"] == actor_uuid
    assert stored["authority"]["authority_owner"] == owner_uuid
    root, _ = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    assert service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]

    unsafe = deepcopy(_canonical_action(action_id="unsafe-provenance-action"))
    unsafe["actor"]["identity_id"] = "person@example.com"
    unsafe["authority"]["authority_owner"] = "+1 (555) 123-4567"
    unsafe_decision = create_decision_receipt(
        bundle_db,
        tenant_id="tenant-a",
        canonical_action=unsafe,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="selected-mcp",
        settings_obj=_settings(),
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
    )
    unsafe_node = bundle_db.get(
        EvidenceNode, unsafe_decision.canonical_action_evidence_node_id
    )
    unsafe_serialized = json.dumps(unsafe_node.payload)
    unsafe_stored = unsafe_node.payload["canonical_action"]
    assert "person@example.com" not in unsafe_serialized
    assert "+1 (555) 123-4567" not in unsafe_serialized
    assert unsafe_stored["actor"]["identity_id"].startswith("sha256:")
    assert unsafe_stored["authority"]["authority_owner"].startswith("sha256:")


@pytest.mark.parametrize("activity_count, expected_status", [(1, "complete"), (2, "incomplete_row_limit")])
def test_projection_rows_are_bounded_without_invalidating_durable_bundle(
    bundle_db: Session,
    monkeypatch: pytest.MonkeyPatch,
    activity_count: int,
    expected_status: str,
) -> None:
    service = _bundle_service()
    monkeypatch.setattr(service, "MAX_PROJECTION_ROWS", 1)
    decision = _decision(bundle_db)
    runtime = RuntimeEvent(
        event_id=f"projection-runtime-{activity_count}",
        tenant_id="tenant-a",
        source_surface="gateway",
        event_type="llm_intercept",
        chain_id=decision.chain_id,
        evidence_node_ids=[],
        metadata_json={},
    )
    session = AISession(
        session_id=f"projection-session-{activity_count}",
        tenant_id="tenant-a",
        source_surface="gateway",
    )
    bundle_db.add_all([runtime, session])
    bundle_db.flush()
    activities = [
        AIAction(
            action_id=f"projection-action-{activity_count}-{index}",
            tenant_id="tenant-a",
            session_id=session.session_id,
            runtime_event_id=runtime.event_id,
            action_type="prompt",
            metadata_json={},
        )
        for index in range(activity_count)
    ]
    bundle_db.add_all(activities)
    bundle_db.flush()
    root = service.link_bundle_to_runtime_projections(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
        runtime_event_id=runtime.event_id,
    )
    assert decision.evidence_bundle_id == root.id
    assert runtime.evidence_bundle_id == root.id
    assert runtime.metadata_json["canonical_evidence_bundle"]["projection_status"] == expected_status
    if activity_count == 1:
        assert activities[0].evidence_bundle_id == root.id
    else:
        assert all(item.evidence_bundle_id is None for item in activities)
    assert service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]


def test_manifest_includes_chain_and_explicit_traces_supersession_and_downstream_hashes(
    bundle_db: Session,
) -> None:
    service = _bundle_service()
    decision = _decision(bundle_db)
    chain_event = RuntimeEvent(
        event_id="trace-chain",
        tenant_id="tenant-a",
        source_surface="gateway",
        event_type="llm_intercept",
        chain_id=decision.chain_id,
        evidence_node_ids=[],
        metadata_json={},
    )
    wrong_action_event = RuntimeEvent(
        event_id="trace-wrong-action",
        tenant_id="tenant-a",
        source_surface="gateway",
        event_type="llm_intercept",
        chain_id=decision.action_id,
        evidence_node_ids=[],
        metadata_json={},
    )
    explicit_event = RuntimeEvent(
        event_id="trace-explicit",
        tenant_id="tenant-a",
        source_surface="gateway",
        event_type="llm_intercept",
        chain_id="different-chain",
        evidence_bundle_id=decision.evidence_bundle_id,
        evidence_node_ids=[],
        metadata_json={},
    )
    bundle_db.add_all([chain_event, wrong_action_event, explicit_event])
    bundle_db.flush()
    record_execution_unknown(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
        execution_attempt_id="reconciled-attempt",
    )
    create_execution_receipt(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        actual_canonical_action=_canonical_action(),
        execution_status="success",
        collector_id="selected-llm-provider",
        settings_obj=_settings(),
        execution_attempt_id="reconciled-attempt",
        downstream_objects=[{"type": "provider_result", "id": "raw-must-hash"}],
    )
    root, manifest = service.refresh_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        decision_receipt_id=decision.receipt_id,
        settings_obj=_settings(),
    )
    trace_ids = {item["runtime_event_id"] for item in manifest.payload["trace_refs"]}
    assert trace_ids == {"trace-chain", "trace-explicit"}
    roles = {item["role"] for item in manifest.payload["members"]}
    assert {
        "current_execution_integrity",
        "superseded_evidence",
        "supersession_evidence",
        "execution_receipt",
        "downstream_objects",
    } <= roles
    assert manifest.payload["downstream_objects"]
    assert "raw-must-hash" not in json.dumps(manifest.payload)
    assert service.verify_evidence_bundle(
        bundle_db,
        tenant_id="tenant-a",
        bundle=root,
        settings_obj=_settings(),
    )["valid"]
