from __future__ import annotations

import os

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.session import Base
from app.services.enforcement_routing_service import (
    fallback_decision_for_gateway_failure,
    normalize_enforcement_event,
    record_routing_failure,
    route_enforcement,
)


def _session_local(tmp_path):
    db_file = tmp_path / "enforcement_routing.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    return engine, session_local


def test_route_enforcement_maps_surfaces_to_expected_targets() -> None:
    browser = route_enforcement({}, {"source": "browser", "tenant_id": "t1"})
    assert browser["route_target"] == "browser_extension"
    assert browser["fallback_target"] == "gateway"

    api = route_enforcement({}, {"source": "api", "tenant_id": "t1"})
    assert api["route_target"] == "gateway"
    assert api["fallback_target"] == "fail_secure"

    connector = route_enforcement({}, {"source": "connector", "tenant_id": "t1"})
    assert connector["route_target"] == "connector_pipeline"
    assert connector["fallback_target"] is None

    agent = route_enforcement({}, {"source": "agent", "tenant_id": "t1"})
    assert agent["route_target"] == "agent_pipeline"
    assert agent["route_chain"][:2] == ["ai_iam", "gateway"]


def test_normalize_enforcement_event_has_canonical_fields() -> None:
    normalized = normalize_enforcement_event(
        {
            "tenant_id": "tenant-1",
            "source_surface": "browser_extension",
            "action_type": "copy_paste",
            "ai_system_id": "sys-1",
            "agent_id": None,
            "data_classification": "protected",
            "correlation_id": "corr-1",
        }
    )
    assert set(normalized.keys()) == {
        "event_id",
        "tenant_id",
        "source_surface",
        "action_type",
        "ai_system_id",
        "agent_id",
        "data_classification",
        "correlation_id",
    }
    assert normalized["source_surface"] == "browser"
    assert normalized["action_type"] == "copy_paste"
    assert normalized["correlation_id"] == "corr-1"


def test_gateway_failure_fallback_blocks_critical_actions() -> None:
    decision = fallback_decision_for_gateway_failure(
        platform_mode="enforce",
        normalized_event={
            "action_type": "api_call",
            "data_classification": "sensitive",
        },
    )
    assert decision["decision"] == "block"
    assert decision["reason_code"] == "gateway_enforcement_failure_fail_secure"


def test_record_routing_failure_writes_audit_and_evidence(tmp_path) -> None:
    engine, session_local = _session_local(tmp_path)
    try:
        with session_local() as db:
            routing = route_enforcement(
                {"policy_id": "p-1", "policy_version": "1.0"},
                {
                    "tenant_id": "tenant-1",
                    "source_surface": "browser",
                    "action_type": "prompt",
                    "correlation_id": "corr-route-fail",
                },
            )
            audit_id, evidence_id = record_routing_failure(
                db,
                tenant_id="tenant-1",
                actor_user_id=None,
                routing=routing,
                stage="browser_interaction_eval",
                error="simulated_failure",
                fallback_applied="gateway",
            )
            db.commit()

            assert audit_id is not None
            assert evidence_id is not None

            audit = db.scalar(select(AuditLog).where(AuditLog.id == audit_id))
            assert audit is not None
            assert audit.action == "enforcement.routing.failure"

            evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.id == evidence_id))
            assert evidence is not None
            assert evidence.signal_type == "enforcement.routing.failure"
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
