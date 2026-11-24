from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.agui import AGUIDecision
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.models.tenant import Tenant
from app.db.models.user import User
from app.db.session import Base
from app.services.agui.context import AGUIExecutionContext
from app.services.agui.contracts import AGUIActionContract, AGUIActionRegistration
from app.services.agui.registry import AGUIRegistry


@pytest.fixture()
def test_db(tmp_path):
    db_file = tmp_path / "agui_registry.sqlite3"
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


def _seed_identity(db: Session) -> tuple[Tenant, User]:
    suffix = uuid4().hex[:8]
    tenant = Tenant(
        name=f"AGUI Tenant {suffix}",
        slug=f"agui-{suffix}",
        is_active=True,
        platform_mode="enforce",
    )
    user = User(
        email=f"user-{suffix}@acme.ai",
        hashed_password="x",
        full_name="AGUI User",
        is_active=True,
    )
    db.add_all([tenant, user])
    db.flush()
    return tenant, user


def _context(*, tenant_id: str, user_id: str, role: str, evidence_displayed: bool = False) -> AGUIExecutionContext:
    return AGUIExecutionContext(
        tenant_id=tenant_id,
        user_id=user_id,
        user_role=role,
        correlation_id="corr-agui-tests",
        evidence_displayed=evidence_displayed,
        diff_preview_displayed=True,
    )


def _contract(
    *,
    action_id: str,
    required_role: list[str],
    requires_justification: bool = False,
    requires_evidence_display: bool = False,
    source_object_id: str = "finding-123",
) -> AGUIActionContract:
    return AGUIActionContract(
        action_id=action_id,
        action_type="approve",
        title="Approve recommendation",
        description="Approve a governance recommendation.",
        source_module="findings",
        source_object_type="finding",
        source_object_id=source_object_id,
        required_role=required_role,
        decision_options=["approve", "reject"],
        requires_justification=requires_justification,
        requires_evidence_display=requires_evidence_display,
        requires_diff_preview=False,
        side_effect_level="write",
    )


def test_agui_role_enforcement(test_db: Session) -> None:
    db = test_db
    tenant, user = _seed_identity(db)
    registry = AGUIRegistry()
    registry.register_action(
        AGUIActionRegistration(
            contract=_contract(action_id="findings.override", required_role=["admin"]),
            executor=lambda _db, _ctx, _contract, _decision, _justification, _evidence_ids: {"ok": True},
        )
    )

    with pytest.raises(PermissionError, match="Insufficient role"):
        registry.execute_decision(
            db=db,
            context=_context(tenant_id=tenant.id, user_id=user.id, role="viewer"),
            action_id="findings.override",
            decision="approve",
        )


def test_agui_requires_justification(test_db: Session) -> None:
    db = test_db
    tenant, user = _seed_identity(db)
    registry = AGUIRegistry()
    registry.register_action(
        AGUIActionRegistration(
            contract=_contract(
                action_id="findings.accept_risk",
                required_role=["owner", "admin"],
                requires_justification=True,
            ),
            executor=lambda _db, _ctx, _contract, _decision, _justification, _evidence_ids: {"status": "accepted"},
        )
    )

    context = _context(tenant_id=tenant.id, user_id=user.id, role="admin")
    with pytest.raises(ValueError, match="requires justification"):
        registry.execute_decision(
            db=db,
            context=context,
            action_id="findings.accept_risk",
            decision="approve",
            justification="",
        )

    record = registry.execute_decision(
        db=db,
        context=context,
        action_id="findings.accept_risk",
        decision="approve",
        justification="Risk accepted until compensating controls are deployed.",
    )
    assert record.action_id == "findings.accept_risk"
    assert record.justification is not None
    assert record.audit_log_id


def test_agui_evidence_display_requirement(test_db: Session) -> None:
    db = test_db
    tenant, user = _seed_identity(db)
    registry = AGUIRegistry()
    registry.register_action(
        AGUIActionRegistration(
            contract=_contract(
                action_id="findings.resolve",
                required_role=["operator", "admin", "owner"],
                requires_evidence_display=True,
            ),
            executor=lambda _db, _ctx, _contract, _decision, _justification, _evidence_ids: {"status": "resolved"},
        )
    )

    with pytest.raises(PermissionError, match="requires evidence display"):
        registry.execute_decision(
            db=db,
            context=_context(tenant_id=tenant.id, user_id=user.id, role="operator", evidence_displayed=False),
            action_id="findings.resolve",
            decision="approve",
        )

    record = registry.execute_decision(
        db=db,
        context=_context(tenant_id=tenant.id, user_id=user.id, role="operator", evidence_displayed=True),
        action_id="findings.resolve",
        decision="approve",
    )
    assert record.action_id == "findings.resolve"
    assert len(record.evidence_node_ids) >= 1


def test_agui_lineage_preservation_writes_audit_and_evidence(test_db: Session) -> None:
    db = test_db
    tenant, user = _seed_identity(db)
    registry = AGUIRegistry()
    registry.register_action(
        AGUIActionRegistration(
            contract=_contract(
                action_id="findings.escalate",
                required_role=["operator", "admin", "owner"],
                source_object_id="finding-9001",
            ),
            executor=lambda _db, _ctx, _contract, _decision, _justification, _evidence_ids: {"ticket_id": "JIRA-1"},
        )
    )

    record = registry.execute_decision(
        db=db,
        context=_context(tenant_id=tenant.id, user_id=user.id, role="operator", evidence_displayed=True),
        action_id="findings.escalate",
        decision="approve",
        justification="Escalating to incident response.",
        evidence_node_ids=["ev_input_1"],
    )

    decision_row = db.scalar(select(AGUIDecision).where(AGUIDecision.decision_id == record.decision_id))
    assert decision_row is not None
    assert decision_row.source_module == "findings"
    assert decision_row.source_object_type == "finding"
    assert decision_row.source_object_id == "finding-9001"
    assert "ev_input_1" in decision_row.evidence_node_ids

    audit_row = db.scalar(select(AuditLog).where(AuditLog.id == record.audit_log_id))
    assert audit_row is not None
    assert audit_row.payload.get("source_module") == "findings"
    assert audit_row.payload.get("source_object_type") == "finding"
    assert audit_row.payload.get("source_object_id") == "finding-9001"

    evidence_row = db.scalar(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant.id,
            EvidenceNode.node_type == "agui_decision",
            EvidenceNode.signal_type == "agui.decision.execute",
        )
        .order_by(EvidenceNode.created_at.desc())
        .limit(1)
    )
    assert evidence_row is not None
    assert evidence_row.payload.get("source_module") == "findings"
    assert evidence_row.payload.get("source_object_type") == "finding"
    assert evidence_row.payload.get("source_object_id") == "finding-9001"
