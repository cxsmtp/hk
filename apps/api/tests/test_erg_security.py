from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.erg.resolution_history import ResolutionConflict, ResolutionHistory
from app.services.hmair.resolution_graph_service import create_graph_node
from test_phase2_asset_resolution_service import _seed


NOW = datetime(2026, 8, 16, 16, 30, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def test_attach_rejects_cross_tenant_node_and_altered_replay() -> None:
    db = _db()
    try:
        first = _seed(db, suffix="erg-security-a")
        second = _seed(db, suffix="erg-security-b")
        local = create_graph_node(
            db,
            tenant_id=first["tenant_id"],
            node_class="application",
            subject_reference="application:security-local",
            idempotency_key="erg-security-local",
        )
        foreign = create_graph_node(
            db,
            tenant_id=second["tenant_id"],
            node_class="runtime",
            subject_reference="runtime:security-foreign",
            idempotency_key="erg-security-foreign",
        )
        attached = create_graph_node(
            db,
            tenant_id=first["tenant_id"],
            node_class="runtime",
            subject_reference="runtime:security-attached",
            idempotency_key="erg-security-attached",
        )
        history = ResolutionHistory()
        created = history.create_ecosystem(
            db,
            tenant_id=first["tenant_id"],
            canonical_name="Security fixture ecosystem",
            ecosystem_class="runtime",
            graph_node_ids=(local.graph_node_id,),
            evidence_node_id=first["node_id"],
            confidence=0.96,
            evidence_quality=0.96,
            operator_id="owner-1",
            operator_role="owner",
            reason="Security acceptance fixture",
            occurred_at=NOW,
            idempotency_key="erg-security-create",
        )
        ecosystem_id = created.ecosystem_ids[0]
        with pytest.raises(ResolutionConflict):
            history.attach_observation(
                db,
                tenant_id=first["tenant_id"],
                ecosystem_id=ecosystem_id,
                graph_node_id=foreign.graph_node_id,
                evidence_node_id=first["node_id"],
                confidence=0.99,
                evidence_quality=0.99,
                operator_id="owner-1",
                operator_role="owner",
                reason="Cross-tenant attempt",
                occurred_at=NOW,
                idempotency_key="erg-security-cross-tenant",
            )
        history.attach_observation(
            db,
            tenant_id=first["tenant_id"],
            ecosystem_id=ecosystem_id,
            graph_node_id=attached.graph_node_id,
            evidence_node_id=first["node_id"],
            confidence=0.99,
            evidence_quality=0.99,
            operator_id="owner-1",
            operator_role="owner",
            reason="Original reviewed evidence",
            occurred_at=NOW,
            idempotency_key="erg-security-replay",
        )
        with pytest.raises(ResolutionConflict, match="idempotency conflict"):
            history.attach_observation(
                db,
                tenant_id=first["tenant_id"],
                ecosystem_id=ecosystem_id,
                graph_node_id=attached.graph_node_id,
                evidence_node_id=first["node_id"],
                confidence=0.99,
                evidence_quality=0.99,
                operator_id="owner-1",
                operator_role="owner",
                reason="Altered replay material",
                occurred_at=NOW,
                idempotency_key="erg-security-replay",
            )
    finally:
        db.close()
        db.bind.dispose()

