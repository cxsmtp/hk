from __future__ import annotations

from sqlalchemy import CheckConstraint, UniqueConstraint, select
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def test_phase7_models_are_reference_only_tenant_scoped_and_bounded() -> None:
    from app.db.models.activity_lineage import (
        ActivityLineage,
        Investigation,
        InvestigationFinding,
        LineageEdge,
        LineageNode,
    )

    assert ActivityLineage.__tablename__ == "activity_lineages"
    assert LineageNode.__tablename__ == "activity_lineage_nodes"
    assert LineageEdge.__tablename__ == "activity_lineage_edges"
    assert Investigation.__tablename__ == "activity_investigations"
    assert InvestigationFinding.__tablename__ == "activity_investigation_findings"

    for model in (ActivityLineage, LineageNode, LineageEdge, Investigation, InvestigationFinding):
        assert "tenant_id" in model.__table__.c

    # Lineage stores authoritative references and safe projections, never raw
    # prompts, credentials, documents, cookies, or arbitrary event payloads.
    forbidden = {"prompt", "credential", "secret", "document_content", "session_cookie", "raw_payload"}
    for model in (LineageNode, LineageEdge):
        assert forbidden.isdisjoint(model.__table__.c.keys())

    node_constraints = set(LineageNode.__table__.constraints)
    edge_constraints = set(LineageEdge.__table__.constraints)
    assert any(isinstance(item, UniqueConstraint) and item.name == "uq_phase7_lineage_node_key" for item in node_constraints)
    assert any(isinstance(item, UniqueConstraint) and item.name == "uq_phase7_lineage_edge_key" for item in edge_constraints)
    assert any(isinstance(item, CheckConstraint) and item.name == "ck_phase7_node_certainty" for item in node_constraints)
    assert any(isinstance(item, CheckConstraint) and item.name == "ck_phase7_edge_certainty" for item in edge_constraints)


def _card(value, *, state="OBSERVED", refs=None, reason=None):
    return {
        "state": state,
        "value": value if state == "OBSERVED" else None,
        "evidence_refs": list(refs or (["evidence:phase7"] if state == "OBSERVED" else [])),
        "occurred_at": "2026-08-25T10:00:00+00:00" if state == "OBSERVED" else None,
        "reason_code": reason,
    }


def _detail(event_id: str, action_id: str, *, actor: str, executor: str, tool: str, target: str, comparison="MATCHED", drift=None, effect=False):
    unknown = _card(None, state="UNKNOWN", refs=[], reason="authority_not_persisted")
    timeline = []
    if effect:
        timeline.append({
            "event_type": "PERSISTENT_EFFECT", "state": "OBSERVED",
            "value": {"effect_id": f"effect:{action_id}", "state": "ACTIVE"},
            "evidence_node_ids": ["evidence:effect"],
        })
    return {
        "identity": {
            "runtime_event_id": event_id, "canonical_action_id": action_id, "action_id": action_id,
            "decision_receipt_id": f"decision:{action_id}", "execution_permit_ids": [f"permit:{action_id}"],
            "execution_receipt_ids": [f"receipt:{action_id}"], "evidence_node_ids": ["evidence:phase7"],
        },
        "context": {
            "actor_principal": _card(actor), "executing_identity": _card(executor),
            "represented_subjects": _card(["subject:synthetic"]),
            "business_purpose": _card("purpose:document-review"), "authority": _card("authority:bounded"),
            "delegation": unknown,
        },
        "action": {
            "operation": _card("modify"), "tool_or_service": _card(tool),
            "safe_parameters": _card({"field_hash": "a" * 64}), "resources": _card(["resource:synthetic-doc"]),
            "targets": _card([target]), "destinations": _card(["destination:internal"]),
            "values_or_quantities": _card([]), "side_effect": _card("isolated_write"),
            "persistence": _card("persistent"), "reversibility": _card("compensatable"),
        },
        "control": {
            "requirements": _card(["post_execution_verification"]),
            "control_plan": _card({"control_plan_id": f"plan:{action_id}"}),
            "mandatory_floors": _card([]), "assurance": _card(2),
            "rejected_controls": _card([]), "blind_spots": _card([]),
        },
        "authorisation": {
            "policy": _card({"decision": "allow", "policy_version_id": "policy:generic"}),
            "decision": _card({"authoritative_decision": "ALLOW"}),
            "approval_request": unknown, "approval_binding": unknown,
            "decision_receipt": _card({"receipt_id": f"decision:{action_id}"}),
            "execution_permits": _card([{"permit_id": f"permit:{action_id}"}]),
        },
        "execution": {
            "observed_semantics": _card({"receipt_id": f"receipt:{action_id}", "terminal_state": "EXECUTED"}),
            "execution_receipts": _card([{"receipt_id": f"receipt:{action_id}"}]),
            "evidence_quality": _card("OS_OBSERVED"),
            "material_integrity": _card({"comparison_id": f"comparison:{action_id}", "result": comparison, "drift_fields": list(drift or [])}),
            "execution_state": _card("EXECUTED"), "drift_fields": _card(list(drift or [])),
            "outcome_integrity": unknown,
        },
        "timeline": timeline,
    }


def test_phase7_reference_lineage_preserves_provenance_drift_assurance_effect_and_bounds(tmp_path, monkeypatch) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.continuous_assurance import ControlAssertion
    from app.db.models.evidence import EvidenceNode
    from app.db.models.native_control import NativeControlSelection
    from app.db.models.instruction_tool_provenance import (
        InstructionProvenanceSet,
        ToolActionProvenanceBinding,
        ToolPrincipalBinding,
    )
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services import activity_lineage as service

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'phase7.sqlite3'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 8, 25, 10, tzinfo=timezone.utc)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Phase 7", slug=f"phase7-{uuid4().hex[:8]}", is_active=True)
            foreign = Tenant(name="Foreign", slug=f"foreign-{uuid4().hex[:8]}", is_active=True)
            db.add_all([tenant, foreign])
            db.flush()
            provenance_set = InstructionProvenanceSet(
                tenant_id=tenant.id, run_id="run:phase7", action_id="action-child", inherited_record_ids=[],
            )
            tool_binding = ToolPrincipalBinding(
                tenant_id=tenant.id, visible_name="synthetic_edit", principal_type="MCP_SERVER",
                principal_ref="mcp:synthetic-server", origin="mcp://synthetic-server", runtime_ref="runtime:phase7",
                application_ref="app:phase7", publisher_ref="publisher:phase7", registration_source="test",
                tool_identity_hash="1" * 64, material_fingerprint="2" * 64, schema_fingerprint="3" * 64,
                material_bundle={}, cosmetic_metadata={}, lifecycle_version="1", lifecycle_state="AVAILABLE", state_version=1,
                capability_ref="dynamic-tool:phase7", trust_state="TRUSTED_CURRENT", evidence_quality="TEST",
                evidence_refs=[], revoked=False,
            )
            db.add_all([provenance_set, tool_binding])
            db.flush()
            db.add(ToolActionProvenanceBinding(
                tenant_id=tenant.id, action_id="action-child", tool_binding_id=tool_binding.id,
                provenance_set_id=provenance_set.id, tool_identity_hash=tool_binding.tool_identity_hash,
                material_fingerprint=tool_binding.material_fingerprint, schema_fingerprint=tool_binding.schema_fingerprint,
                lifecycle_version=tool_binding.lifecycle_version, provenance_record_ids=["record:phase7"],
                decision_receipt_id="decision:action-child", execution_permit_id="permit:action-child",
                execution_receipt_id="receipt:action-child", actual_identity_observed=False, comparison_state="UNVERIFIED",
            ))
            db.add(EvidenceNode(
                id="evidence:phase7", tenant_id=tenant.id, node_type="phase7_test",
                signal_type="lineage", label="Phase 7 reference evidence", payload={},
            ))
            db.add_all([
                RuntimeEvent(
                    tenant_id=tenant.id, event_id="event-root", source_surface="runtime", event_type="action.proposed",
                    entity_type="action", entity_id="action-root", chain_id="chain-generic", application="Generic AI",
                    agent_id="agent-a", evidence_node_ids=["evidence:phase7"], created_at=now,
                    metadata_json={"action_integrity_refs": {"control_selection_id": "selection-root"}, "runtime": "runtime:generic", "model": "model:generic"},
                ),
                RuntimeEvent(
                    tenant_id=tenant.id, event_id="event-child", source_surface="runtime", event_type="action.executed",
                    entity_type="action", entity_id="action-child", parent_action_id="action-root", chain_id="chain-generic",
                    application="Generic AI", agent_id="agent-b", decision="allow", evidence_node_ids=["evidence:phase7"],
                    created_at=now + timedelta(seconds=1),
                    metadata_json={
                        "action_integrity_refs": {"control_selection_id": "selection-child"},
                        "runtime": "runtime:generic", "model": "model:generic",
                        "mcp_server_id": "mcp:synthetic-server", "mcp_tool_name": "synthetic_edit",
                    },
                ),
                RuntimeEvent(
                    tenant_id=foreign.id, event_id="foreign-event-child", source_surface="runtime", event_type="action.executed",
                    entity_type="action", entity_id="action-foreign", chain_id="chain-foreign", created_at=now,
                    metadata_json={},
                ),
            ])
            for action_id, selection_id in (("action-root", "selection-root"), ("action-child", "selection-child")):
                db.execute(NativeControlSelection.__table__.insert().values(
                    selection_id=selection_id, tenant_id=tenant.id, action_id=action_id,
                    canonical_action_hash="a" * 64, control_plan_id=f"plan:{action_id}",
                    control_plan_digest="b" * 64, plan_issued_at=now, plan_expires_at=now + timedelta(minutes=5),
                    selection_reason="phase7-reference", required_capabilities=["post_execution_verification"],
                    satisfied_capabilities=["post_execution_verification"], semantic_primary_control_point_id="native:generic",
                    assurance_level=2, selector_version="phase7", matrix_version="phase7", policy_version="policy:generic",
                    input_digest="c" * 64,
                ))
            db.add(ControlAssertion(
                tenant_id=tenant.id, assertion_key="phase7:post-execution", assertion_type="execution_integrity",
                asset_ref="asset:generic", action_class="document_update", required_capability="post_execution_verification",
                expected_outcome="PASS_EXECUTION_MATCHED", required_evidence_level="HAWK_RUNTIME_OBSERVED",
                assurance_state="REGRESSED", assurance_version=2, last_validated_at=now - timedelta(hours=2),
                fresh_until=now - timedelta(hours=1),
            ))

        details = {
            "event-root": _detail("event-root", "action-root", actor="human:alice", executor="agent:a", tool="tool:planner", target="target:synthetic-primary"),
            "event-child": _detail(
                "event-child", "action-child", actor="human:alice", executor="service:agent-b", tool="tool:synthetic-editor",
                target="target:synthetic-secondary", comparison="DRIFTED", drift=["TARGET_DRIFT"], effect=True,
            ),
        }
        monkeypatch.setattr(service, "build_action_detail", lambda _db, *, tenant_id, runtime_event_id: details.get(runtime_event_id))

        with sessions.begin() as db:
            projection = service.materialize_lineage_projection(
                db, tenant_id=tenant.id, runtime_event_id="event-child", depth=3, limit=100,
            )
            assert projection is not None
            assert any(node["label"] == "human:alice" and node["node_type"] == "HUMAN" for node in projection["nodes"])
            assert any(node["label"] == "service:agent-b" and node["node_type"] == "SERVICE" for node in projection["nodes"])
            assert {node["label"] for node in projection["nodes"] if node["node_type"] == "AGENT"} >= {"agent-a", "agent-b"}
            assert any(edge["edge_type"] == "PARENT_OF" and edge["certainty"] == "CONFIRMED" for edge in projection["edges"])
            assert projection["authorised_vs_executed"]["result"] == "DRIFTED"
            assert projection["authorised_vs_executed"]["drift_fields"] == ["TARGET_DRIFT"]
            assert any(item["assurance_state"] == "REGRESSED" for item in projection["control_assurance"])
            assert projection["questions"]["persistent_effect"]["state"] == "CONFIRMED"
            assert projection["questions"]["expected_controls"]["state"] == "CORRELATED"
            assert projection["questions"]["actual_controls"]["state"] == "UNKNOWN"
            assert projection["questions"]["control_assurance"]["state"] == "CORRELATED"
            assert any(
                item["safe_attributes"].get("assurance_state") == "REGRESSED"
                for item in projection["questions"]["control_assurance"]["value"]
            )
            assert any(
                item["safe_attributes"].get("policy_version_id") == "policy:generic"
                and item["safe_attributes"].get("decision") == "allow"
                for item in projection["questions"]["policy_decision"]["value"]
            )
            assert any(node["node_type"] == "AI_APPLICATION" and node["certainty"] == "CORRELATED" for node in projection["nodes"])
            assert any(node["node_type"] == "MCP_SERVER" and node["label"] == "mcp:synthetic-server" for node in projection["nodes"])
            assert any(node["node_type"] == "MCP_TOOL" and node["label"] == "synthetic_edit" for node in projection["nodes"])
            assert any(node["authority_type"] == "ToolPrincipalBinding" and node["authority_id"] == tool_binding.id for node in projection["nodes"])
            assert any(node["authority_type"] == "InstructionProvenanceSet" and node["authority_id"] == provenance_set.id for node in projection["nodes"])
            assert any(edge["edge_type"] == "CONTROLLED_BY" and edge["certainty"] == "CONFIRMED" for edge in projection["edges"])
            assert any(edge["edge_type"] == "USED_TOOL" and edge["certainty"] == "CORRELATED" for edge in projection["edges"])
            assert not any(node["certainty"] == "CONFIRMED" and node["evidence_quality"] == "CORRELATED" for node in projection["nodes"])
            assert all("bank" not in (node["label"] + node["authority_type"]).lower() for node in projection["nodes"])
            assert service.materialize_lineage_projection(db, tenant_id=foreign.id, runtime_event_id="event-root") is None
            assert service.get_activity_lineage_projection(db, tenant_id=foreign.id, lineage_id=projection["lineage"]["id"]) is None
            action_node = next(node for node in projection["nodes"] if node["node_type"] == "ACTION" and node["authority_id"] == "action-child")
            traversed = service.traverse_lineage(
                db, tenant_id=tenant.id, lineage_id=projection["lineage"]["id"],
                seed_node_id=action_node["id"], direction="both", depth=2, limit=25,
            )
            assert traversed is not None
            assert any(node["node_type"] == "TARGET" for node in traversed["nodes"])
            searched = service.search_lineages(
                db, tenant_id=tenant.id,
                query=service.LineageQuery(node_type="PERSISTENT_EFFECT", limit=10),
            )
            assert [item["lineage_id"] for item in searched] == [projection["lineage"]["id"]]
            mcp_searched = service.search_lineages(
                db, tenant_id=tenant.id,
                query=service.LineageQuery(
                    mcp_server="mcp:synthetic-server", mcp_tool="synthetic_edit", limit=10,
                ),
            )
            assert [item["lineage_id"] for item in mcp_searched] == [projection["lineage"]["id"]]
            action_searched = service.search_lineages(
                db, tenant_id=tenant.id,
                query=service.LineageQuery(action_id="action-root", time_from=now - timedelta(seconds=1), limit=10),
            )
            assert [item["lineage_id"] for item in action_searched] == [projection["lineage"]["id"]]
            assert service.search_lineages(
                db, tenant_id=tenant.id,
                query=service.LineageQuery(time_from=now + timedelta(days=1), limit=10),
            ) == []
            investigation = service.create_investigation(
                db, tenant_id=tenant.id, lineage_id=projection["lineage"]["id"],
                title="Synthetic document drift", owner_ref="user:operator",
                scope={"action_id": "action-child"}, saved_query={"drift_type": "TARGET_DRIFT"},
            )
            assert investigation is not None
            finding = service.add_investigation_finding(
                db, tenant_id=tenant.id, investigation_id=investigation.id,
                finding_type="target_drift", severity="high", title="Execution target changed",
                reason_code="TARGET_DRIFT", lineage_node_ids=[action_node["id"]],
                evidence_refs=["evidence:phase7"],
            )
            assert finding is not None
            saved = service.get_investigation(db, tenant_id=tenant.id, investigation_id=investigation.id)
            assert saved is not None and saved["findings"][0]["reason_code"] == "TARGET_DRIFT"
            assert service.get_investigation(db, tenant_id=foreign.id, investigation_id=investigation.id) is None
            assert service.add_investigation_finding(
                db, tenant_id=foreign.id, investigation_id=investigation.id,
                finding_type="missing_evidence", severity="medium", title="Foreign",
                reason_code="FOREIGN",
            ) is None
            with pytest.raises(ValueError, match="depth"):
                service.traverse_lineage(
                    db, tenant_id=tenant.id, lineage_id=projection["lineage"]["id"],
                    seed_node_id=projection["nodes"][0]["id"], depth=7, limit=10,
                )
            with pytest.raises(ValueError, match="limit"):
                service.materialize_lineage_projection(db, tenant_id=tenant.id, runtime_event_id="event-child", limit=201)
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_phase7_uses_real_signed_phase5_comparison_and_outcome_authorities(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.action_integrity import (
        DecisionReceiptV2Extension,
        ExecutionComparisonV2,
        ExecutionPermitV2,
        OutcomeVerificationV2,
    )
    from app.db.models.evidence import DecisionReceipt
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.db.session import Base
    from app.services import activity_lineage as service
    from test_phase6_continuous_assurance import _add_phase5_evidence, _seed_tenant_and_provider

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'phase7-signed.sqlite3'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)
    try:
        with sessions.begin() as db:
            tenant, provider = _seed_tenant_and_provider(db, name="Phase 7 signed")
            evidence = _add_phase5_evidence(
                db, provider=provider, tenant_id=tenant.id, action_id="action-phase7-signed",
                at=now, matched_execution=True,
                action_template={"tool_ref": "tool:generic-document", "target_ref": "resource:generic-document"},
            )
            db.flush()
            decision = db.get(DecisionReceiptV2Extension, evidence.decision_receipt_id)
            assert decision is not None
            permit = db.scalar(select(ExecutionPermitV2).where(
                ExecutionPermitV2.tenant_id == tenant.id,
                ExecutionPermitV2.action_id == "action-phase7-signed",
            ))
            comparison = db.get(ExecutionComparisonV2, evidence.comparison_id)
            outcome = db.scalar(select(OutcomeVerificationV2).where(
                OutcomeVerificationV2.tenant_id == tenant.id,
                OutcomeVerificationV2.action_id == "action-phase7-signed",
            ))
            base = db.get(DecisionReceipt, evidence.decision_receipt_id)
            assert permit is not None and comparison is not None and outcome is not None and base is not None
            evidence_node_id = base.canonical_action_evidence_node_id
            canonical_action = dict(decision.signed_envelope["canonical_action"])
            stages = {
                stage: [evidence_node_id]
                for stage in ("context", "action", "control", "decision", "permit", "execution", "comparison", "outcome")
            }
            db.add(RuntimeEvent(
                tenant_id=tenant.id, event_id="event-phase7-signed", source_surface="runtime",
                event_type="action.executed", entity_type="action", entity_id="action-phase7-signed",
                chain_id=str(canonical_action["chain_id"]), decision="allow", evidence_node_ids=[evidence_node_id],
                created_at=now, metadata_json={
                    "canonical_action": canonical_action,
                    "runtime": "runtime:generic-dotnet",
                    "action_integrity_refs": {
                        "canonical_action_id": "action-phase7-signed",
                        "control_selection_id": decision.control_selection_id,
                        "decision_receipt_id": evidence.decision_receipt_id,
                        "execution_permit_id": permit.permit_id,
                        "execution_receipt_id": evidence.execution_receipt_id,
                        "execution_comparison_id": evidence.comparison_id,
                        "outcome_verification_id": outcome.verification_id,
                        "evidence_node_ids": stages,
                    },
                },
            ))
            db.info["phase5_signing_provider"] = provider
            projection = service.materialize_lineage_projection(
                db, tenant_id=tenant.id, runtime_event_id="event-phase7-signed", depth=1, limit=100,
            )
            assert projection is not None
            assert projection["authorised_vs_executed"]["result"] == "MATCHED"
            assert projection["questions"]["originating_actor"]["state"] == "CONFIRMED"
            assert projection["questions"]["executing_principal"]["state"] == "CONFIRMED"
            assert projection["questions"]["tools_or_services"]["state"] == "CONFIRMED"
            assert projection["questions"]["resources_targets_destinations"]["state"] == "CONFIRMED"
            assert projection["questions"]["policy_decision"]["state"] == "CONFIRMED"
            assert projection["questions"]["observed_outcome"]["state"] == "CONFIRMED"
            assert projection["questions"]["expected_outcome"]["state"] == "CONFIRMED"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
