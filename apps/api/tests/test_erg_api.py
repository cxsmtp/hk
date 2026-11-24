from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routers.discovery_erg import (
    AttachRequest,
    DispositionRequest,
    attach_observation,
    get_ecosystem,
    get_graph,
    get_timeline,
    list_ecosystems,
    record_disposition,
    router as erg_router,
)
from app.core.config import settings
from app.core.tenant import require_tenant
from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.db.session import get_db
from app.services.hmair.erg.resolution_history import ResolutionHistory
from app.services.hmair.ecosystem_resolution_service import resolve_ai_ecosystems
from app.services.hmair.resolution_graph_service import create_graph_node
from test_phase2_asset_resolution_service import _seed


NOW = datetime.now(timezone.utc) - timedelta(minutes=5)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _ctx(tenant_id: str, role: str = "owner") -> SimpleNamespace:
    return SimpleNamespace(
        tenant=SimpleNamespace(id=tenant_id),
        user=SimpleNamespace(id="user-owner"),
        role=role,
    )


def test_erg_read_api_is_tenant_scoped_and_explains_current_evidence(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cie_core", True)
    db = _db()
    try:
        seed = _seed(db, suffix="erg-api")
        other = _seed(db, suffix="erg-api-other")
        node = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="application",
            subject_reference="application:opaque-governed-client",
            idempotency_key="erg-api-node",
        )
        created = ResolutionHistory().create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Governed client ecosystem",
            ecosystem_class="agentic_workflow",
            graph_node_ids=(node.graph_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.94,
            operator_id="owner-1",
            operator_role="owner",
            reason="Verified test evidence",
            occurred_at=NOW,
            idempotency_key="erg-api-create",
        )
        ecosystem_id = created.ecosystem_ids[0]

        listed = list_ecosystems(ctx=_ctx(seed["tenant_id"]), db=db)
        assert [item.ecosystem_id for item in listed] == [ecosystem_id]
        detail = get_ecosystem(ecosystem_id, ctx=_ctx(seed["tenant_id"]), db=db)
        assert detail.why["methodology_id"] == "erg-reversible-resolution-history"
        assert detail.members[0]["node_class"] == "application"
        assert get_graph(ecosystem_id, ctx=_ctx(seed["tenant_id"]), db=db).nodes
        ResolutionHistory().record_disposition(
            db,
            tenant_id=seed["tenant_id"],
            action="manual_review",
            subject_reference="hypothesis:unbound-to-ecosystem",
            evidence_node_id=seed["node_id"],
            confidence=0.51,
            operator_id="owner-1",
            operator_role="owner",
            reason="Retain unrelated ambiguous evidence",
            occurred_at=NOW + timedelta(seconds=1),
            idempotency_key="erg-api-unbound-disposition",
        )
        timeline = get_timeline(
            ecosystem_id, limit=50, ctx=_ctx(seed["tenant_id"]), db=db
        )
        assert timeline.total >= 1
        assert all(ecosystem_id in item["ecosystem_ids"] for item in timeline.items)
        compatibility = resolve_ai_ecosystems(db, tenant_id=seed["tenant_id"])
        assert [item.ecosystem_id for item in compatibility] == [ecosystem_id]
        assert compatibility[0].resolution_method == "canonical_evidence_resolution_graph"

        with pytest.raises(HTTPException) as exc_info:
            get_ecosystem(ecosystem_id, ctx=_ctx(other["tenant_id"]), db=db)
        assert exc_info.value.status_code == 404
    finally:
        db.close()
        db.bind.dispose()


def test_owner_attach_api_records_new_member_without_cross_tenant_access(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cie_core", True)
    db = _db()
    try:
        seed = _seed(db, suffix="erg-api-attach")
        first = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="runtime",
            subject_reference="runtime:opaque",
            idempotency_key="erg-api-attach-first",
        )
        second = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="mcp",
            subject_reference="mcp:opaque",
            idempotency_key="erg-api-attach-second",
        )
        created = ResolutionHistory().create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Runtime ecosystem",
            ecosystem_class="runtime",
            graph_node_ids=(first.graph_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.9,
            evidence_quality=0.88,
            operator_id="owner-1",
            operator_role="owner",
            reason="Initial manual resolution",
            occurred_at=NOW,
            idempotency_key="erg-api-attach-create",
        )
        response = attach_observation(
            created.ecosystem_ids[0],
            AttachRequest(
                graph_node_id=second.graph_node_id,
                evidence_node_id=seed["node_id"],
                confidence=0.87,
                evidence_quality=0.85,
                reason="Owner reviewed the evidence",
                idempotency_key="erg-api-attach-action",
            ),
            ctx=_ctx(seed["tenant_id"]),
            db=db,
        )
        assert response.action == "attach"
        assert len(response.after_memberships) == 2
        assert len(get_ecosystem(
            created.ecosystem_ids[0], ctx=_ctx(seed["tenant_id"]), db=db
        ).members) == 2
        disposition = record_disposition(
            DispositionRequest(
                action="manual_review",
                subject_reference="hypothesis:opaque-ambiguous",
                evidence_node_id=seed["node_id"],
                confidence=0.61,
                reason="Owner retained competing hypotheses",
                idempotency_key="erg-api-manual-review",
            ),
            ctx=_ctx(seed["tenant_id"]),
            db=db,
        )
        assert disposition.action == "manual_review"
        assert disposition.ecosystem_ids == []
    finally:
        db.close()
        db.bind.dispose()


def test_erg_http_routes_enforce_viewer_read_and_owner_mutation(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cie_core", True)
    db = _db()
    app = FastAPI()
    app.include_router(erg_router)
    current = {"ctx": None}
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_tenant] = lambda: current["ctx"]
    try:
        seed = _seed(db, suffix="erg-api-http")
        current["ctx"] = _ctx(seed["tenant_id"], role="viewer")
        client = TestClient(app)
        assert client.get("/discovery/evidence-resolution/ecosystems").status_code == 200
        denied = client.post(
            "/discovery/evidence-resolution/dispositions",
            json={
                "action": "manual_review",
                "subject_reference": "hypothesis:http-viewer",
                "evidence_node_id": seed["node_id"],
                "confidence": 0.5,
                "reason": "Viewer must not mutate",
                "idempotency_key": "erg-http-viewer-denied",
            },
        )
        assert denied.status_code == 403

        current["ctx"] = _ctx(seed["tenant_id"], role="owner")
        allowed = client.post(
            "/discovery/evidence-resolution/dispositions",
            json={
                "action": "manual_review",
                "subject_reference": "hypothesis:http-owner",
                "evidence_node_id": seed["node_id"],
                "confidence": 0.5,
                "reason": "Owner retained the ambiguous hypothesis",
                "idempotency_key": "erg-http-owner-allowed",
            },
        )
        assert allowed.status_code == 200
        assert allowed.json()["action"] == "manual_review"
        replayed = client.post(
            "/discovery/evidence-resolution/dispositions",
            json={
                "action": "manual_review",
                "subject_reference": "hypothesis:http-owner",
                "evidence_node_id": seed["node_id"],
                "confidence": 0.5,
                "reason": "Owner retained the ambiguous hypothesis",
                "idempotency_key": "erg-http-owner-allowed",
            },
        )
        assert replayed.status_code == 200
        assert replayed.json() == allowed.json()
        resolved = client.post(
            "/discovery/evidence-resolution/resolve",
            json={
                "observation_ids": [seed["observation_id"]],
                "idempotency_key": "erg-http-resolve",
            },
        )
        assert resolved.status_code == 200
        assert resolved.json()["inference_run_id"]
        assert resolved.json()["evaluation_ids"]
    finally:
        db.close()
        db.bind.dispose()
