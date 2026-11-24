from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routers.discovery_exposure import router
from app.core.config import settings
from app.core.tenant import require_tenant
from app.db.models import *  # noqa: F401,F403
from app.db.session import Base, get_db
from test_exposure_source_reader import _seed_asset_sources, _seed_exact_action_path
from test_exposure_source_reader import NOW
import app.api.routers.discovery_exposure as discovery_exposure


@pytest.fixture
def exposure_api(monkeypatch):
    monkeypatch.setattr(settings, "cie_core", True)
    monkeypatch.setattr(discovery_exposure, "_utc_now", lambda: NOW)
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    db = Session(engine, autoflush=False, expire_on_commit=False)
    seed, asset, _ = _seed_asset_sources(db, suffix="exposure-api")
    other, other_asset, _ = _seed_asset_sources(db, suffix="exposure-api-other")
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_tenant] = lambda: SimpleNamespace(
        tenant=SimpleNamespace(id=seed["tenant_id"]),
        user=SimpleNamespace(id="viewer-user"),
        role="viewer",
    )
    client = TestClient(app)
    try:
        yield client, seed, asset, other, other_asset, app
    finally:
        client.close()
        db.rollback()
        db.close()
        engine.dispose()


def test_four_read_only_routes_are_viewer_accessible_and_bounded(exposure_api) -> None:
    client, _seed, asset, _other, _other_asset, _app = exposure_api

    projection = client.get(f"/discovery/assets/{asset.asset_id}/exposure")
    assert projection.status_code == 200, projection.text
    assert projection.json()["asset_id"] == asset.asset_id
    assert projection.json()["calculation_status"] == "partial"

    timeline = client.get(
        f"/discovery/assets/{asset.asset_id}/exposure/timeline",
        params={"page": 1, "page_size": 25, "lookback_days": 30},
    )
    assert timeline.status_code == 200, timeline.text
    assert timeline.json()["page_size"] == 25
    assert timeline.json()["asset_id"] == asset.asset_id
    assert timeline.json()["items"] == []
    assert "historical_exposure_state_unavailable" in timeline.json()["limitations"]

    graph = client.get(
        f"/discovery/assets/{asset.asset_id}/exposure/graph",
        params={"category_id": "coding_exposure", "max_nodes": 20, "max_edges": 20},
    )
    assert graph.status_code == 200, graph.text
    assert graph.json()["category_id"] == "coding_exposure"
    assert len(graph.json()["graph"]["nodes"]) <= 20
    assert len(graph.json()["graph"]["edges"]) <= 20

    methodology = client.get("/discovery/exposure/methodology")
    assert methodology.status_code == 200, methodology.text
    assert methodology.json()["reasoning_rule_version"] == "1.2.0"
    assert methodology.json()["aggregate_score"] is None

    assert client.get(
        f"/discovery/assets/{asset.asset_id}/exposure/timeline",
        params={"page_size": 201},
    ).status_code == 422
    assert client.get(
        f"/discovery/assets/{asset.asset_id}/exposure/graph",
        params={"max_nodes": 201},
    ).status_code == 422


def test_timeline_and_graph_share_the_requested_projection_clock(exposure_api) -> None:
    client, _seed, asset, _other, _other_asset, _app = exposure_api
    projection = client.get(f"/discovery/assets/{asset.asset_id}/exposure").json()
    as_of = projection["as_of"]

    timeline = client.get(
        f"/discovery/assets/{asset.asset_id}/exposure/timeline",
        params={"as_of": as_of},
    )
    graph = client.get(
        f"/discovery/assets/{asset.asset_id}/exposure/graph",
        params={"as_of": as_of, "category_id": "coding_exposure"},
    )

    assert timeline.status_code == graph.status_code == 200
    assert timeline.json()["source_input_digest"] == projection["source_input_digest"]
    assert graph.json()["source_input_digest"] == projection["source_input_digest"]
    assert client.get(
        f"/discovery/assets/{asset.asset_id}/exposure/timeline",
        params={"as_of": "2099-01-01T00:00:00Z"},
    ).status_code == 422


def test_cross_tenant_and_absent_asset_are_same_tenant_safe_404(exposure_api) -> None:
    client, _seed, _asset, _other, other_asset, _app = exposure_api
    cross_tenant = client.get(f"/discovery/assets/{other_asset.asset_id}/exposure")
    absent = client.get("/discovery/assets/00000000-0000-4000-8000-000000000000/exposure")
    assert cross_tenant.status_code == absent.status_code == 404
    assert cross_tenant.json() == absent.json() == {"detail": "Not Found"}


def test_openapi_has_exactly_four_exposure_get_routes_and_no_mutation(exposure_api) -> None:
    _client, _seed, _asset, _other, _other_asset, app = exposure_api
    paths = app.openapi()["paths"]
    exposure = {path: methods for path, methods in paths.items() if "exposure" in path}
    assert set(exposure) == {
        "/discovery/assets/{asset_id}/exposure",
        "/discovery/assets/{asset_id}/exposure/timeline",
        "/discovery/assets/{asset_id}/exposure/graph",
        "/discovery/exposure/methodology",
    }
    assert all(set(methods).issubset({"get", "parameters"}) for methods in exposure.values())


def test_api_isolates_malformed_persisted_coverage_without_disclosure_or_500(
    exposure_api,
) -> None:
    client, seed, asset, _other, _other_asset, app = exposure_api
    db = app.dependency_overrides[get_db]()
    _, malformed_evidence_path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="api-malformed-evidence-action",
    )
    _, malformed_clock_path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="api-malformed-clock-action",
    )
    db.add_all(
        [
            ControlCoverageAssertion(
                id=str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:api-malformed-evidence")),
                tenant_id=seed["tenant_id"],
                path_id=str(malformed_evidence_path.id),
                dimension="authorization",
                state="covered",
                reason_code="malformed_evidence",
                explanation="Malformed persisted evidence must be isolated.",
                methodology_version="1.0",
                evaluator_version="1.0",
                evidence_refs=[
                    seed["node_id"],
                    {"access_token": "api-secret-must-not-leak"},
                    "z" * 256,
                ],
                source_watermark="8" * 64,
                observed_at=NOW,
                evaluated_at=NOW,
                valid_until=NOW + timedelta(days=1),
            ),
            ControlCoverageAssertion(
                id=str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:api-malformed-clock")),
                tenant_id=seed["tenant_id"],
                path_id=str(malformed_clock_path.id),
                dimension="authorization",
                state="covered",
                reason_code="malformed_clock",
                explanation="Invalid persisted timestamp order must be isolated.",
                methodology_version="1.0",
                evaluator_version="1.0",
                evidence_refs=[seed["node_id"]],
                source_watermark="9" * 64,
                observed_at=NOW,
                evaluated_at=NOW - timedelta(minutes=1),
                valid_until=NOW + timedelta(days=1),
            ),
        ]
    )
    db.flush()

    response = client.get(f"/discovery/assets/{asset.asset_id}/exposure")
    assert response.status_code == 200, response.text
    body = response.json()
    serialized = response.text
    assert body["calculation_status"] == "partial"
    assert body["truncated"] is True
    assert "control_coverage" in body["failed_authorities"]
    assert all(item["extent"] == "unknown" for item in body["exposures"])
    assert "api-secret-must-not-leak" not in serialized
    assert "access_token" not in serialized
