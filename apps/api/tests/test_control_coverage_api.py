from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.control_coverage import ControlCoveragePath, ControlCoverageSnapshot, DeploymentSurface
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base, get_db
from app.main import app
from app.services.control_coverage.service import calculate_tenant_control_coverage


PASSWORD = "Password123!"


class _EmptyScalarResult:
    def all(self):
        return []


class _RecordingSession:
    def __init__(self) -> None:
        self.statements = []

    def scalars(self, statement):
        self.statements.append(statement)
        return _EmptyScalarResult()


@pytest.fixture()
def coverage_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "control_coverage_api.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    from app.api.routers import control_coverage

    monkeypatch.setattr(control_coverage.settings, "control_coverage_api_enabled", True)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, session_factory
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register(client: TestClient, email: str) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Coverage Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    tenant_id = payload["tenants"][0]["id"]
    return tenant_id, {
        "Authorization": f"Bearer {payload['access_token']}",
        "X-Tenant-ID": tenant_id,
    }


def _materialize(session_factory, *, tenant_id: str, event_id: str, methodology_version: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(
            RuntimeEvent(
                event_id=event_id,
                tenant_id=tenant_id,
                source_surface="browser",
                event_type="observed_action",
                user_id="user-1",
                app_id="chat-app",
                metadata_json={
                    "provider": "openai",
                    "model": "gpt-5",
                    "tool_name": "knowledge.search",
                    "control_mode": "telemetry_only",
                },
                created_at=now,
            )
        )
        db.flush()
        result = calculate_tenant_control_coverage(
            db,
            tenant_id=tenant_id,
            now=now,
            **({"methodology_version": methodology_version} if methodology_version else {}),
        )
        path_id = result.paths[0].id
        db.commit()
        return path_id


def test_missing_snapshot_returns_typed_unknown_without_materializing(coverage_env) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _register(client, "coverage-missing@example.com")

    response = client.get("/control-coverage?window_days=30", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["tenant_id"] == tenant_id
    assert payload["methodology_version"] == "control-coverage/1.0"
    assert payload["headline"]["score"] is None
    assert payload["headline"]["counts"]["denominator"] == 0
    assert {item["code"] for item in payload["diagnostics"]} == {"snapshot_missing"}
    with session_factory() as db:
        assert db.scalar(select(func.count()).select_from(ControlCoveragePath)) == 0
        assert db.scalar(select(func.count()).select_from(ControlCoverageSnapshot)) == 0


def test_path_list_query_avoids_postgres_distinct_on_json_source_refs() -> None:
    from app.api.routers.control_coverage import _list_paths

    db = _RecordingSession()
    result = _list_paths(
        db,
        tenant_id="tenant-a",
        page=1,
        page_size=100,
        dimension="authorization",
        state="not_covered",
    )

    assert result.total == 0
    sql = str(db.statements[0].compile(dialect=postgresql.dialect()))
    assert "SELECT DISTINCT" not in sql
    assert "EXISTS" in sql


def test_summary_deployment_improvements_keep_exact_counts_and_bound_references() -> None:
    from app.api.routers.control_coverage import _bounded_deployment_improvements

    surface = DeploymentSurface(
        tenant_id="tenant-a",
        source_kind="test",
        source_id="surface-a",
        name="Runtime control",
        surface_type="runtime",
        deployment_mode="inline",
        capability_profile={"inline_authorization": "yes"},
    )
    unresolved_rows = [
        (f"assertion-{index:03d}", f"path-{index:03d}", "authorization")
        for index in range(125)
    ]

    result = _bounded_deployment_improvements(
        unresolved_rows=unresolved_rows,
        surfaces=[surface, surface],
        reference_limit=10,
    )

    # Multiple connector instances with the same surface type remain one
    # bounded recommendation rather than duplicating all estate references.
    assert len(result) == 1
    assert result[0]["addressable_assertion_count"] == 125
    assert result[0]["impacted_path_count"] == 125
    assert len(result[0]["assertion_ids"]) == 10
    assert len(result[0]["path_ids"]) == 10
    assert result[0]["references_truncated"] is True
    assert result[0]["reference_limit"] == 10


def test_summary_and_path_drilldowns_use_materialized_evidence(coverage_env) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _register(client, "coverage-summary@example.com")
    path_id = _materialize(session_factory, tenant_id=tenant_id, event_id="event-summary")

    response = client.get("/control-coverage?window_days=30", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["methodology_version"] == "control-coverage/1.0"
    assert payload["window_days"] == 30
    assert payload["known_estate_limitation"]
    counts = payload["headline"]["counts"]
    assert payload["headline"]["score"] == round(counts["covered"] / counts["denominator"] * 100, 2)
    assert set(payload["dimensions"]) == {
        "discovery",
        "identity",
        "authorization",
        "evidence",
        "deployment",
        "runtime",
        "bypass",
    }
    paths = client.get(
        "/control-coverage/paths?state=not_covered&dimension=authorization",
        headers=headers,
    )
    assert paths.status_code == 200, paths.text
    assert paths.json()["total"] == 1
    assert paths.json()["items"][0]["path_id"] == path_id
    by_identity_type = client.get("/control-coverage/paths?identity_type=user", headers=headers)
    assert by_identity_type.status_code == 200, by_identity_type.text
    assert by_identity_type.json()["total"] == 1

    detail = client.get(f"/control-coverage/paths/{path_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    detail_payload = detail.json()
    assert detail_payload["identity_ref"] == "user:user-1"
    assert len(detail_payload["assertions"]) == 7
    assert "metadata_json" not in detail_payload

    asset = client.get("/control-coverage/assets/application:chat-app", headers=headers)
    assert asset.status_code == 200, asset.text
    assert asset.json()["total"] == 1
    identity = client.get("/control-coverage/identities/user/user:user-1", headers=headers)
    assert identity.status_code == 200, identity.text
    assert identity.json()["total"] == 1

    methodology = client.get("/control-coverage/methodology", headers=headers)
    assert methodology.status_code == 200, methodology.text
    assert methodology.json()["unknown_in_denominator"] is True
    assert methodology.json()["weighted"] is False


def test_phase5_summary_retrieves_the_materialized_13_dimension_snapshot(coverage_env) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _register(client, "coverage-phase5@example.com")
    _materialize(
        session_factory,
        tenant_id=tenant_id,
        event_id="event-phase5-summary",
        methodology_version="control-coverage/2.0",
    )

    response = client.get("/control-coverage?window_days=30&methodology_version=2.0", headers=headers)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["methodology_version"] == "control-coverage/2.0"
    assert len(payload["dimensions"]) == 13
    assert set(payload["dimensions"]) == {
        "subject_binding", "resource_binding", "purpose_binding", "authority_binding",
        "parameter_binding", "target_binding", "destination_binding", "approval_binding",
        "execution_visibility", "execution_verification", "persistence_tracking", "delegation_integrity",
        "outcome_verification",
    }


def test_foreign_path_and_projection_requests_are_404(coverage_env) -> None:
    client, session_factory = coverage_env
    tenant_a, _headers_a = _register(client, "coverage-tenant-a@example.com")
    _tenant_b, headers_b = _register(client, "coverage-tenant-b@example.com")
    path_id = _materialize(session_factory, tenant_id=tenant_a, event_id="event-tenant-a")

    assert client.get(f"/control-coverage/paths/{path_id}", headers=headers_b).status_code == 404
    assert client.get("/control-coverage/assets/application:chat-app", headers=headers_b).status_code == 404
    assert client.get("/control-coverage/identities/user/user:user-1", headers=headers_b).status_code == 404


def test_path_filters_are_closed_and_pagination_is_bounded(coverage_env) -> None:
    client, _session_factory = coverage_env
    _tenant_id, headers = _register(client, "coverage-filters@example.com")
    assert client.get("/control-coverage/paths?dimension=invented", headers=headers).status_code == 422
    assert client.get("/control-coverage/paths?state=maybe", headers=headers).status_code == 422
    assert client.get("/control-coverage/paths?identity_type=robot", headers=headers).status_code == 422
    assert client.get("/control-coverage/paths?page_size=201", headers=headers).status_code == 422


def test_identity_projection_filters_type_before_pagination(coverage_env) -> None:
    client, session_factory = coverage_env
    tenant_id, headers = _register(client, "coverage-identity-pagination@example.com")
    _materialize(session_factory, tenant_id=tenant_id, event_id="event-identity-pagination")

    with session_factory() as db:
        current = db.scalar(
            select(ControlCoveragePath).where(ControlCoveragePath.tenant_id == tenant_id)
        )
        assert current is not None
        identity_ref = current.identity_ref
        db.add(
            ControlCoveragePath(
                tenant_id=tenant_id,
                path_key="f" * 64,
                key_version="1.0",
                asset_ref="application:other-app",
                identity_type="service_identity",
                identity_ref=identity_ref,
                runtime_ref="model:other",
                deployment_surface_ref="source_surface:sdk",
                destination_type="tool",
                destination_ref="tool:other",
                lifecycle_status="active",
                source_refs=["runtime_event:other-event"],
                first_seen_at=current.first_seen_at + timedelta(seconds=1),
                last_seen_at=current.last_seen_at + timedelta(seconds=1),
            )
        )
        db.commit()

    response = client.get(
        f"/control-coverage/identities/user/{identity_ref}?page_size=1",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["identity_type"] == "user"
