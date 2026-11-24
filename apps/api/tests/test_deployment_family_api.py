from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings, settings
from app.core.security import create_access_token
from app.db.models.control_coverage import DeploymentSurface
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app


FAMILY_COUNTS = {
    "browser": 0,
    "endpoint": 0,
    "runtime": 0,
    "saas_api": 0,
    "unknown": 0,
}
HEALTH_COUNTS = {
    "healthy": 0,
    "warning": 0,
    "degraded": 0,
    "offline": 0,
    "stale": 0,
    "unknown": 0,
}
FAMILY_LABELS = {
    "browser": "Browser",
    "endpoint": "Endpoint",
    "runtime": "Runtime",
    "saas_api": "SaaS & APIs",
    "unknown": "Unknown",
}
INSTANCE_FIELDS = {
    "id",
    "tenant_id",
    "name",
    "deployment_family",
    "technical_surface_type",
    "deployment_mode",
    "hosting_mode",
    "environment",
    "provider",
    "region",
    "status",
    "feature_flag",
    "first_seen_at",
    "last_seen_at",
    "last_health_check_at",
    "policy_bundle_version",
    "collector_version",
    "control_capability",
    "evidence_capability",
    "containment_capability",
    "bypass_detection_capability",
    "health_status",
    "health_reason",
}
FORBIDDEN_INSTANCE_FIELDS = {
    "source_kind",
    "source_id",
    "capability_profile",
    "capability_sources",
    "metadata_json",
    "last_heartbeat_at",
}


@pytest.fixture()
def deployment_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "deployment_family_api.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setitem(
        settings.__dict__,
        "deployment_family_experience_enabled",
        True,
    )

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


@pytest.fixture()
def disabled_deployment_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "deployment_family_api_disabled.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setitem(
        settings.__dict__,
        "deployment_family_experience_enabled",
        False,
    )

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _settings(**overrides: Any) -> Settings:
    values = {
        "secret_key": "deployment-api-secret",
        "connector_secrets_key": "deployment-api-connector-secret",
        "connector_secrets_kdf_salt": "deployment-api-kdf-salt",
        "onprem_bundle_signing_secret": "deployment-api-onprem-secret",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def _identity(
    session_factory,
    *,
    role: str = "viewer",
    tenant: Tenant | None = None,
    email: str,
) -> tuple[Tenant, dict[str, str]]:
    with session_factory() as db:
        if tenant is None:
            tenant = Tenant(
                name=f"{email} tenant",
                slug=email.replace("@", "-").replace(".", "-"),
                is_active=True,
            )
            db.add(tenant)
            db.flush()
        else:
            tenant = db.merge(tenant)
        user = User(
            email=email,
            hashed_password="unused",
            full_name=email,
            is_active=True,
        )
        db.add(user)
        db.flush()
        db.add(
            UserTenantRole(
                user_id=user.id,
                tenant_id=tenant.id,
                role=role,
            )
        )
        db.commit()
        tenant_id = tenant.id
        user_id = user.id
    return tenant, {
        "Authorization": f"Bearer {create_access_token(user_id, tenant_id=tenant_id, role=role)}",
        "X-Tenant-ID": tenant_id,
    }


def _unscoped_identity(session_factory, *, email: str) -> dict[str, str]:
    with session_factory() as db:
        user = User(
            email=email,
            hashed_password="unused",
            full_name=email,
            is_active=True,
        )
        db.add(user)
        db.commit()
        user_id = user.id
    return {
        "Authorization": f"Bearer {create_access_token(user_id, tenant_id=None, role=None)}",
    }


def _surface(
    session_factory,
    *,
    tenant_id: str,
    source_id: str,
    id: str | None = None,
    name: str | None = None,
    deployment_family: str = "unknown",
    technical_surface_type: str = "custom_surface",
    deployment_mode: str = "unknown",
    hosting_mode: str = "unknown",
    environment: str = "unknown",
    provider: str | None = None,
    region: str | None = None,
    status: str = "unknown",
    feature_flag: str | None = None,
    first_seen_at: datetime | None = None,
    last_seen_at: datetime | None = None,
    last_health_check_at: datetime | None = None,
    policy_bundle_version: str | None = None,
    collector_version: str | None = None,
    control_capability: str = "unknown",
    evidence_capability: str = "unknown",
    containment_capability: str = "unknown",
    bypass_detection_capability: str = "unknown",
    health_status: str = "unknown",
    health_reason: str = "insufficient_evidence",
) -> str:
    now = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
    row = DeploymentSurface(
        tenant_id=tenant_id,
        source_kind="test",
        source_id=source_id,
        name=name or source_id,
        surface_type=technical_surface_type,
        deployment_mode=deployment_mode,
        deployment_family=deployment_family,
        hosting_mode=hosting_mode,
        environment=environment,
        provider=provider,
        region=region,
        status=status,
        feature_flag=feature_flag,
        capability_profile={"secret": "must-not-leak"},
        capability_sources=["must-not-leak"],
        control_capability=control_capability,
        evidence_capability=evidence_capability,
        containment_capability=containment_capability,
        bypass_detection_capability=bypass_detection_capability,
        health_status=health_status,
        health_reason=health_reason,
        first_seen_at=first_seen_at or now,
        last_seen_at=last_seen_at or now,
        last_heartbeat_at=now,
        last_health_check_at=last_health_check_at,
        policy_bundle_version=policy_bundle_version,
        collector_version=collector_version,
        metadata_json={"secret": "must-not-leak"},
    )
    if id is not None:
        row.id = id
    with session_factory() as db:
        db.add(row)
        db.commit()
        return row.id


def _snapshot_rows(session_factory, *, tenant_id: str) -> list[dict[str, Any]]:
    with session_factory() as db:
        rows = db.scalars(
            select(DeploymentSurface)
            .where(DeploymentSurface.tenant_id == tenant_id)
            .order_by(DeploymentSurface.id)
        ).all()
        return [
            {
                column.name: getattr(row, column.name)
                for column in DeploymentSurface.__table__.columns
            }
            for row in rows
        ]


@contextmanager
def _capture_deployment_surface_selects(session_factory):
    engine = session_factory.kw["bind"]
    statements: list[str] = []

    def before_cursor_execute(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(str(statement).split()).lower()
        if (
            normalized.startswith("select")
            and "deployment_surfaces" in normalized
        ):
            statements.append(normalized)

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)


def test_feature_flag_defaults_off_and_honors_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED", raising=False)
    assert _settings().deployment_family_experience_enabled is False

    monkeypatch.setenv("DEPLOYMENT_FAMILY_EXPERIENCE_ENABLED", "true")
    assert _settings().deployment_family_experience_enabled is True


@pytest.mark.parametrize(
    "path",
    [
        "/deployments/overview",
        "/deployments/families",
        "/deployments/instances",
        "/deployments/instances/missing",
    ],
)
def test_disabled_routes_are_nonrevealing_404(
    disabled_deployment_env: TestClient,
    path: str,
) -> None:
    response = disabled_deployment_env.get(path)
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_enabled_routes_enforce_auth_tenant_membership_and_viewer_floor(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant, viewer_headers = _identity(
        session_factory,
        role="viewer",
        email="deployment-viewer@example.com",
    )

    assert client.get("/deployments/overview").status_code == 401

    missing_tenant_headers = dict(viewer_headers)
    missing_tenant_headers.pop("X-Tenant-ID")
    assert client.get(
        "/deployments/overview",
        headers=missing_tenant_headers,
    ).status_code == 400

    outsider_headers = _unscoped_identity(
        session_factory,
        email="deployment-outsider@example.com",
    )
    outsider_headers["X-Tenant-ID"] = tenant.id
    assert client.get(
        "/deployments/overview",
        headers=outsider_headers,
    ).status_code == 403

    _, invalid_headers = _identity(
        session_factory,
        role="guest",
        tenant=tenant,
        email="deployment-guest@example.com",
    )
    assert client.get(
        "/deployments/overview",
        headers=invalid_headers,
    ).status_code == 403

    assert client.get(
        "/deployments/overview",
        headers=viewer_headers,
    ).status_code == 200
    for role in ("operator", "auditor", "admin", "owner"):
        _, headers = _identity(
            session_factory,
            role=role,
            tenant=tenant,
            email=f"deployment-{role}@example.com",
        )
        response = client.get("/deployments/overview", headers=headers)
        assert response.status_code == 200, (role, response.text)


def test_empty_responses_are_typed_and_include_all_family_buckets(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant, headers = _identity(
        session_factory,
        email="deployment-empty@example.com",
    )

    overview = client.get("/deployments/overview", headers=headers)
    assert overview.status_code == 200, overview.text
    assert overview.json() == {
        "tenant_id": tenant.id,
        "generated_at": overview.json()["generated_at"],
        "total_instances": 0,
        "family_counts": FAMILY_COUNTS,
        "health_counts": HEALTH_COUNTS,
        "status_counts": {},
    }
    datetime.fromisoformat(overview.json()["generated_at"])

    families = client.get("/deployments/families", headers=headers)
    assert families.status_code == 200, families.text
    assert families.json()["total"] == 5
    assert families.json()["page"] == 1
    assert families.json()["page_size"] == 50
    assert [item["family"] for item in families.json()["items"]] == list(
        FAMILY_LABELS
    )
    assert [item["label"] for item in families.json()["items"]] == list(
        FAMILY_LABELS.values()
    )
    for item in families.json()["items"]:
        assert item["instance_count"] == 0
        assert item["technical_surface_counts"] == {}
        assert item["deployment_mode_counts"] == {}
        assert item["hosting_mode_counts"] == {}
        assert item["health_counts"] == HEALTH_COUNTS
        assert item["status_counts"] == {}

    instances = client.get("/deployments/instances", headers=headers)
    assert instances.status_code == 200, instances.text
    assert instances.json() == {
        "items": [],
        "total": 0,
        "page": 1,
        "page_size": 50,
    }


def test_overview_and_family_aggregates_are_exact_stored_inventory_counts(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant_a, headers_a = _identity(
        session_factory,
        email="deployment-aggregate-a@example.com",
    )
    tenant_b, _headers_b = _identity(
        session_factory,
        email="deployment-aggregate-b@example.com",
    )
    rows = [
        ("browser-healthy", "browser", "browser_extension", "managed_extension", "saas", "healthy", "active"),
        ("browser-warning", "browser", "browser_agent", "monitor_only", "hybrid", "warning", "active"),
        ("runtime-stale", "runtime", "llm_gateway", "inline", "private_cloud", "stale", "disabled"),
        ("unknown-offline", "unknown", "llm_gateway", "custom", "unknown", "offline", "unknown"),
    ]
    for source_id, family, surface, mode, hosting, health, status_value in rows:
        _surface(
            session_factory,
            tenant_id=tenant_a.id,
            source_id=source_id,
            deployment_family=family,
            technical_surface_type=surface,
            deployment_mode=mode,
            hosting_mode=hosting,
            health_status=health,
            status=status_value,
        )
    _surface(
        session_factory,
        tenant_id=tenant_b.id,
        source_id="foreign-degraded",
        deployment_family="endpoint",
        health_status="degraded",
    )

    overview = client.get("/deployments/overview", headers=headers_a)
    assert overview.status_code == 200, overview.text
    payload = overview.json()
    assert payload["total_instances"] == 4
    assert payload["family_counts"] == {
        "browser": 2,
        "endpoint": 0,
        "runtime": 1,
        "saas_api": 0,
        "unknown": 1,
    }
    assert payload["health_counts"] == {
        "healthy": 1,
        "warning": 1,
        "degraded": 0,
        "offline": 1,
        "stale": 1,
        "unknown": 0,
    }
    assert payload["status_counts"] == {
        "active": 2,
        "disabled": 1,
        "unknown": 1,
    }
    assert "score" not in payload

    families = client.get("/deployments/families", headers=headers_a).json()
    browser = families["items"][0]
    assert browser == {
        "family": "browser",
        "label": "Browser",
        "instance_count": 2,
        "technical_surface_counts": {
            "browser_agent": 1,
            "browser_extension": 1,
        },
        "deployment_mode_counts": {
            "managed_extension": 1,
            "monitor_only": 1,
        },
        "hosting_mode_counts": {"hybrid": 1, "saas": 1},
        "health_counts": {
            "healthy": 1,
            "warning": 1,
            "degraded": 0,
            "offline": 0,
            "stale": 0,
            "unknown": 0,
        },
        "status_counts": {"active": 2},
    }
    assert families["items"][1]["instance_count"] == 0
    assert families["items"][1]["health_counts"] == HEALTH_COUNTS


def test_overview_and_families_aggregate_with_grouped_sql_counts(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant, headers = _identity(
        session_factory,
        email="deployment-sql-aggregate@example.com",
    )
    _surface(
        session_factory,
        tenant_id=tenant.id,
        source_id="sql-aggregate",
        deployment_family="browser",
        technical_surface_type="browser_extension",
        deployment_mode="managed_extension",
        hosting_mode="saas",
        health_status="healthy",
        status="active",
    )

    with _capture_deployment_surface_selects(session_factory) as overview_sql:
        overview = client.get("/deployments/overview", headers=headers)

    assert overview.status_code == 200, overview.text
    assert overview.json()["total_instances"] == 1
    assert overview.json()["family_counts"]["browser"] == 1
    assert len(overview_sql) == 3
    assert all("count(" in statement for statement in overview_sql)
    assert all("group by" in statement for statement in overview_sql)

    with _capture_deployment_surface_selects(session_factory) as family_sql:
        families = client.get("/deployments/families", headers=headers)

    assert families.status_code == 200, families.text
    assert families.json()["items"][0]["instance_count"] == 1
    assert len(family_sql) == 5
    assert all("count(" in statement for statement in family_sql)
    assert all("group by" in statement for statement in family_sql)


def test_family_pagination_is_fixed_order_bounded_and_allows_empty_pages(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    _tenant, headers = _identity(
        session_factory,
        email="deployment-family-pagination@example.com",
    )

    first = client.get(
        "/deployments/families",
        params={"page": 1, "page_size": 2},
        headers=headers,
    )
    assert first.status_code == 200, first.text
    assert first.json()["total"] == 5
    assert [item["family"] for item in first.json()["items"]] == [
        "browser",
        "endpoint",
    ]

    last = client.get(
        "/deployments/families",
        params={"page": 3, "page_size": 2},
        headers=headers,
    )
    assert [item["family"] for item in last.json()["items"]] == ["unknown"]

    empty = client.get(
        "/deployments/families",
        params={"page": 4, "page_size": 2},
        headers=headers,
    )
    assert empty.status_code == 200
    assert empty.json()["items"] == []
    assert empty.json()["total"] == 5

    for params in (
        {"page": 0},
        {"page_size": 0},
        {"page_size": 201},
    ):
        assert client.get(
            "/deployments/families",
            params=params,
            headers=headers,
        ).status_code == 422


def test_instances_use_deterministic_pagination_and_empty_out_of_range_pages(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant, headers = _identity(
        session_factory,
        email="deployment-instance-pagination@example.com",
    )
    base = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
    _surface(
        session_factory,
        tenant_id=tenant.id,
        id="00000000-0000-0000-0000-000000000003",
        source_id="older",
        last_seen_at=base,
    )
    _surface(
        session_factory,
        tenant_id=tenant.id,
        id="00000000-0000-0000-0000-000000000002",
        source_id="same-later-b",
        last_seen_at=base + timedelta(minutes=1),
    )
    _surface(
        session_factory,
        tenant_id=tenant.id,
        id="00000000-0000-0000-0000-000000000001",
        source_id="same-later-a",
        last_seen_at=base + timedelta(minutes=1),
    )

    first = client.get(
        "/deployments/instances",
        params={"page": 1, "page_size": 2},
        headers=headers,
    )
    assert first.status_code == 200, first.text
    assert first.json()["total"] == 3
    assert [item["id"] for item in first.json()["items"]] == [
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
    ]

    second = client.get(
        "/deployments/instances",
        params={"page": 2, "page_size": 2},
        headers=headers,
    )
    assert [item["id"] for item in second.json()["items"]] == [
        "00000000-0000-0000-0000-000000000003"
    ]

    empty = client.get(
        "/deployments/instances",
        params={"page": 99, "page_size": 2},
        headers=headers,
    )
    assert empty.status_code == 200
    assert empty.json()["items"] == []
    assert empty.json()["total"] == 3

    for params in (
        {"page": 0},
        {"page_size": 0},
        {"page_size": 201},
    ):
        assert client.get(
            "/deployments/instances",
            params=params,
            headers=headers,
        ).status_code == 422


def test_instance_filters_are_conjunctive_exact_and_persistence_bounded(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant, headers = _identity(
        session_factory,
        email="deployment-filters@example.com",
    )
    _surface(
        session_factory,
        tenant_id=tenant.id,
        source_id="filter-match",
        deployment_family="runtime",
        technical_surface_type="llm_gateway",
        deployment_mode="inline",
        hosting_mode="hybrid",
        environment="prod",
        provider="Azure",
        region="uae-north",
        status="active",
        feature_flag="runtime-v1",
        health_status="healthy",
    )
    _surface(
        session_factory,
        tenant_id=tenant.id,
        source_id="filter-other",
        deployment_family="browser",
        technical_surface_type="browser_extension",
        provider="Other",
    )
    exact = {
        "deployment_family": "runtime",
        "technical_surface_type": "llm_gateway",
        "deployment_mode": "inline",
        "hosting_mode": "hybrid",
        "environment": "prod",
        "provider": "Azure",
        "region": "uae-north",
        "status": "active",
        "feature_flag": "runtime-v1",
        "health_status": "healthy",
    }

    response = client.get(
        "/deployments/instances",
        params=exact,
        headers=headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["name"] == "filter-match"

    for key, value in (
        ("technical_surface_type", "LLM_GATEWAY"),
        ("technical_surface_type", "llm"),
        ("technical_surface_type", "%gateway%"),
        ("provider", "azure"),
        ("provider", " Azure "),
        ("provider", "x' OR 1=1 --"),
    ):
        filtered = client.get(
            "/deployments/instances",
            params={key: value},
            headers=headers,
        )
        assert filtered.status_code == 200, (key, filtered.text)
        assert filtered.json()["total"] == 0

    for key, value in (
        ("deployment_family", "Runtime"),
        ("deployment_family", "browser_extension"),
        ("hosting_mode", "cloud"),
        ("health_status", "HEALTHY"),
        ("health_status", "fresh"),
    ):
        assert client.get(
            "/deployments/instances",
            params={key: value},
            headers=headers,
        ).status_code == 422

    for key, value in (
        ("technical_surface_type", ""),
        ("technical_surface_type", "x" * 65),
        ("deployment_mode", "x" * 65),
        ("environment", "x" * 65),
        ("provider", "x" * 129),
        ("region", "x" * 65),
        ("status", "x" * 33),
        ("feature_flag", "x" * 129),
    ):
        assert client.get(
            "/deployments/instances",
            params={key: value},
            headers=headers,
        ).status_code == 422


def test_unknown_family_stale_health_and_raw_surface_are_preserved_without_inference(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant, headers = _identity(
        session_factory,
        email="deployment-unknown@example.com",
    )
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    instance_id = _surface(
        session_factory,
        tenant_id=tenant.id,
        source_id="unknown-runtime-looking",
        deployment_family="unknown",
        technical_surface_type="llm_gateway",
        last_seen_at=old,
        health_status="stale",
        health_reason="collector_reported_stale",
        control_capability="unknown",
        evidence_capability="unknown",
        containment_capability="unknown",
        bypass_detection_capability="unknown",
    )
    healthy_old_id = _surface(
        session_factory,
        tenant_id=tenant.id,
        source_id="old-but-healthy",
        deployment_family="unknown",
        technical_surface_type=" LLM_GATEWAY ",
        last_seen_at=old,
        health_status="healthy",
        health_reason="stored_healthy",
    )

    stale = client.get(
        f"/deployments/instances/{instance_id}",
        headers=headers,
    )
    assert stale.status_code == 200, stale.text
    assert stale.json()["deployment_family"] == "unknown"
    assert stale.json()["technical_surface_type"] == "llm_gateway"
    assert stale.json()["health_status"] == "stale"
    assert stale.json()["health_reason"] == "collector_reported_stale"

    old_healthy = client.get(
        f"/deployments/instances/{healthy_old_id}",
        headers=headers,
    )
    assert old_healthy.status_code == 200, old_healthy.text
    assert old_healthy.json()["deployment_family"] == "unknown"
    assert old_healthy.json()["technical_surface_type"] == " LLM_GATEWAY "
    assert old_healthy.json()["health_status"] == "healthy"
    assert old_healthy.json()["health_reason"] == "stored_healthy"


def test_instance_projection_is_exact_and_foreign_detail_is_indistinguishable_404(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant_a, headers_a = _identity(
        session_factory,
        email="deployment-detail-a@example.com",
    )
    tenant_b, headers_b = _identity(
        session_factory,
        email="deployment-detail-b@example.com",
    )
    instance_id = _surface(
        session_factory,
        tenant_id=tenant_a.id,
        source_id="detail",
        deployment_family="endpoint",
        technical_surface_type="endpoint_agent",
        deployment_mode="monitor_only",
        hosting_mode="on_premises",
        environment="pilot",
        provider="Hawk",
        region="local",
        status="active",
        feature_flag="endpoint-pilot",
        last_health_check_at=datetime(2026, 7, 20, 11, 0, tzinfo=timezone.utc),
        policy_bundle_version="policy-7",
        collector_version="collector-3",
        control_capability="monitor_only",
        evidence_capability="metadata_only",
        containment_capability="none",
        bypass_detection_capability="supported",
        health_status="warning",
        health_reason="metadata_only",
    )

    detail = client.get(
        f"/deployments/instances/{instance_id}",
        params={"tenant_id": tenant_b.id},
        headers=headers_a,
    )
    assert detail.status_code == 200, detail.text
    assert set(detail.json()) == INSTANCE_FIELDS
    assert not (set(detail.json()) & FORBIDDEN_INSTANCE_FIELDS)
    assert detail.json()["tenant_id"] == tenant_a.id

    listed = client.get("/deployments/instances", headers=headers_a)
    assert listed.status_code == 200
    assert set(listed.json()["items"][0]) == INSTANCE_FIELDS
    assert not (set(listed.json()["items"][0]) & FORBIDDEN_INSTANCE_FIELDS)

    missing = client.get(
        "/deployments/instances/does-not-exist",
        headers=headers_b,
    )
    foreign = client.get(
        f"/deployments/instances/{instance_id}",
        headers=headers_b,
    )
    assert missing.status_code == foreign.status_code == 404
    assert missing.json() == foreign.json() == {"detail": "Not found"}


def test_instance_selects_transfer_only_approved_projection_columns(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    tenant, headers = _identity(
        session_factory,
        email="deployment-sql-projection@example.com",
    )
    instance_id = _surface(
        session_factory,
        tenant_id=tenant.id,
        source_id="sql-projection",
        deployment_family="runtime",
        technical_surface_type="llm_gateway",
    )

    with _capture_deployment_surface_selects(session_factory) as statements:
        listed = client.get("/deployments/instances", headers=headers)
        detail = client.get(
            f"/deployments/instances/{instance_id}",
            headers=headers,
        )

    assert listed.status_code == 200, listed.text
    assert detail.status_code == 200, detail.text
    assert statements
    forbidden_columns = {
        "metadata_json",
        "capability_profile",
        "capability_sources",
        "last_heartbeat_at",
        "source_kind",
        "source_id",
    }
    for statement in statements:
        assert not {
            column
            for column in forbidden_columns
            if f"deployment_surfaces.{column}" in statement
        }, statement


def test_instance_detail_rejects_ids_beyond_persisted_length(
    deployment_env,
) -> None:
    client, session_factory = deployment_env
    _tenant, headers = _identity(
        session_factory,
        email="deployment-detail-length@example.com",
    )

    missing = client.get(
        "/deployments/instances/ordinary-missing-id",
        headers=headers,
    )
    overlong = client.get(
        f"/deployments/instances/{'x' * 37}",
        headers=headers,
    )

    assert missing.status_code == 404
    assert missing.json() == {"detail": "Not found"}
    assert overlong.status_code == 422


def test_all_gets_leave_deployment_rows_unchanged(deployment_env) -> None:
    client, session_factory = deployment_env
    tenant, headers = _identity(
        session_factory,
        email="deployment-read-only@example.com",
    )
    instance_id = _surface(
        session_factory,
        tenant_id=tenant.id,
        source_id="read-only",
        deployment_family="browser",
        technical_surface_type="browser_extension",
        health_status="healthy",
    )
    before = _snapshot_rows(session_factory, tenant_id=tenant.id)

    for path in (
        "/deployments/overview",
        "/deployments/families",
        "/deployments/instances",
        f"/deployments/instances/{instance_id}",
    ):
        response = client.get(path, headers=headers)
        assert response.status_code == 200, (path, response.text)

    assert _snapshot_rows(session_factory, tenant_id=tenant.id) == before


def test_route_table_exposes_only_approved_d3_through_d5_read_routes() -> None:
    from app.api.routers import deployments

    deployment_routes = [
        route
        for route in deployments.router.routes
        if isinstance(route, APIRoute)
    ]
    assert {route.path for route in deployment_routes} == {
        "/deployments/overview",
        "/deployments/families",
        "/deployments/instances",
        "/deployments/instances/{id}",
        "/deployments/coverage",
        "/deployments/coverage/{family}",
        "/deployments/blind-spots",
        "/deployments/health",
    }
    assert all(route.methods == {"GET"} for route in deployment_routes)
    assert "/deployments/families/{family}" not in {
        route.path for route in deployment_routes
    }


def test_read_service_contains_no_mutation_or_coverage_calculation_calls() -> None:
    source = (
        Path(__file__).parents[1]
        / "app/services/deployment_family_read_service.py"
    ).read_text(encoding="utf-8")

    for forbidden in (
        ".add(",
        ".flush(",
        ".commit(",
        ".update(",
        ".delete(",
        "reconcile_deployment_surfaces",
        "calculate_tenant_control_coverage",
    ):
        assert forbidden not in source
