from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.security import create_access_token
from app.db.models.audit import AuditChainHead, AuditLog
from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget
from app.db.models.monitoring import Connector
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.hmair.source_connectors import service as source_connection_service
from app.services.hmair.source_connectors.contracts import (
    HMAIRNormalizedRecord,
    HMAIRSourceCapability,
    HMAIRSourceCollectionResult,
    HMAIRSourceProvider,
)
from app.services.hmair.contracts import ObservationType, SourceSurface


M365_REQUEST = {
    "provider_key": "hmair_microsoft365_copilot",
    "display_name": "M365Production",
    "target_identifier": "tenant-0001",
    "environment": "production",
    "authorization_reference": "CAB-42",
    "requested_capabilities": ["copilot_usage"],
    "credentials": {
        "tenant_id": "tenant-0001",
        "client_id": "client-0001",
        "client_secret": "customer-secret-value",
    },
}

PERSONAL_GITHUB_REQUEST = {
    "provider_key": "hmair_github_cloud",
    "display_name": "PersonalGitHubDemo",
    "target_identifier": "octocat",
    "environment": "production",
    "authorization_reference": "DEMO-42",
    "requested_capabilities": ["repository_inventory"],
    "include_entra_account_evidence": False,
    "metadata": {
        "account_scope_kind": "PERSONAL",
        "account_login": "octocat",
        "selected_repository_scope": "SELECTED",
    },
    "credentials": {
        "app_id": "1",
        "installation_id": "2",
        "private_key_pem": "test-private-key",
    },
}


def test_source_connection_setup_catalog_exposes_all_admin_onboarding_paths(
    source_connection_env: dict[str, object],
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)

    response = client.get("/discovery/source-connections/setup-catalog", headers=headers["viewer"])

    assert response.status_code == 200, response.text
    body = response.json()
    families = {item["family"]: item for item in body["items"]}
    assert body["total"] == 5
    assert set(families) == {"github", "m365_teams", "identity", "saas", "cloud"}

    github = families["github"]
    assert github["entrypoint_href"] == "/control-coverage/source-control/github-repository-boundary"
    assert "hmair_github_cloud" in github["provider_keys"]
    assert "selected repositories" in " ".join(github["required_authority"]).lower()
    assert "No coverage is claimed until validation" in " ".join(github["limitations"])

    m365 = families["m365_teams"]
    assert "hmair_microsoft365_copilot" in m365["provider_keys"]
    assert "teams" in m365["provider_keys"]
    assert "tenant-admin" in " ".join(m365["required_authority"]).lower()

    for item in body["items"]:
        assert item["credential_requirements"]
        assert item["visibility"]
        assert item["status"] == "setup_required"


def test_authority_status_explains_missing_enterprise_denominators(
    source_connection_env: dict[str, object],
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)

    response = client.get("/discovery/source-connections/authority-status", headers=headers["viewer"])

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["overall_state"] == "missing_authoritative_sources"
    assert body["authoritative_denominator_complete"] is False
    domains = {item["domain"]: item for item in body["items"]}
    assert set(domains) == {
        "users",
        "devices",
        "browser",
        "repositories",
        "saas_apps",
        "cloud_runtimes",
        "models",
    }
    assert domains["users"]["state"] == "missing"
    assert domains["users"]["required_source_family"] == "identity"
    assert domains["repositories"]["connect_href"] == "/control-coverage/source-control/github-repository-boundary"
    assert domains["models"]["state"] == "observed_only"
    assert "provider-native" in domains["models"]["next_action"].lower()


def test_source_connection_authority_guidance_is_visible_before_hmair_rollout(
    source_connection_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)
    monkeypatch.setitem(settings.__dict__, "hmair_core", False)

    setup_response = client.get("/discovery/source-connections/setup-catalog", headers=headers["viewer"])
    authority_response = client.get("/discovery/source-connections/authority-status", headers=headers["viewer"])

    assert setup_response.status_code == 200, setup_response.text
    assert authority_response.status_code == 200, authority_response.text
    body = authority_response.json()
    assert body["authoritative_denominator_complete"] is False
    assert "Connect identity/SCIM" in body["how_to_get_full_authority"][0]


@pytest.fixture()
def source_connection_env(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'source-connection.sqlite3'}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    session_factory: sessionmaker[Session] = sessionmaker(
        bind=engine, autocommit=False, autoflush=False, expire_on_commit=False
    )
    tables = [
        Tenant.__table__,
        User.__table__,
        UserTenantRole.__table__,
        AuditLog.__table__,
        AuditChainHead.__table__,
        Connector.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
    ]
    Base.metadata.create_all(bind=engine, tables=tables)
    with session_factory() as db:
        tenant = Tenant(name="Source Tenant", slug="source-tenant")
        other_tenant = Tenant(name="Other Tenant", slug="other-source-tenant")
        owner = User(email="owner@example.test", hashed_password="x", full_name="Owner", is_active=True)
        viewer = User(email="viewer@example.test", hashed_password="x", full_name="Viewer", is_active=True)
        other_owner = User(email="other-owner@example.test", hashed_password="x", full_name="Other owner", is_active=True)
        db.add_all([tenant, other_tenant, owner, viewer, other_owner])
        db.flush()
        db.add_all(
            [
                UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"),
                UserTenantRole(user_id=viewer.id, tenant_id=tenant.id, role="viewer"),
                UserTenantRole(user_id=other_owner.id, tenant_id=other_tenant.id, role="owner"),
            ]
        )
        db.commit()

    monkeypatch.setitem(settings.__dict__, "hmair_core", True)

    def _headers(user_id: str, tenant_id: str, role: str) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + create_access_token(user_id, tenant_id=tenant_id, role=role),
            "X-Tenant-ID": tenant_id,
        }

    with session_factory() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "source-tenant"))
        other_tenant = db.scalar(select(Tenant).where(Tenant.slug == "other-source-tenant"))
        owner = db.scalar(select(User).where(User.email == "owner@example.test"))
        viewer = db.scalar(select(User).where(User.email == "viewer@example.test"))
        other_owner = db.scalar(select(User).where(User.email == "other-owner@example.test"))
        assert tenant and other_tenant and owner and viewer and other_owner
        headers = {
            "owner": _headers(owner.id, tenant.id, "owner"),
            "viewer": _headers(viewer.id, tenant.id, "viewer"),
            "other_owner": _headers(other_owner.id, other_tenant.id, "owner"),
        }

    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "headers": headers, "session_factory": session_factory}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))
        engine.dispose()


def test_owner_creates_not_connected_source_target_and_collector(
    source_connection_env: dict[str, object],
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)
    response = client.post(
        "/discovery/source-connections", headers=headers["owner"], json=M365_REQUEST
    )

    assert response.status_code == 201
    body = response.json()
    assert body["capability"]["state"] == "not_connected"
    assert body["target"]["target_type"] == "saas_tenant"
    assert "customer-secret-value" not in response.text
    session_factory = source_connection_env["session_factory"]
    assert callable(session_factory)
    with session_factory() as db:
        connector = db.scalar(select(Connector))
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "discovery.source_connection.create"))
        assert connector is not None and audit is not None
        assert connector.encrypted_secrets is not None
        assert "customer-secret-value" not in str(connector.config)
        assert "customer-secret-value" not in str(connector.metadata_json)
        assert "customer-secret-value" not in str(audit.payload)


def test_owner_creates_explicit_personal_github_account_connection(
    source_connection_env: dict[str, object],
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)

    response = client.post(
        "/discovery/source-connections",
        headers=headers["owner"],
        json=PERSONAL_GITHUB_REQUEST,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["account_scope_kind"] == "PERSONAL"
    assert body["target"]["target_type"] == "repository_org"
    assert body["capability"]["state"] == "not_connected"
    assert "test-private-key" not in response.text


def test_viewer_cannot_mutate_and_other_tenant_cannot_read(
    source_connection_env: dict[str, object],
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)
    assert client.post(
        "/discovery/source-connections", headers=headers["viewer"], json=M365_REQUEST
    ).status_code == 403
    created = client.post(
        "/discovery/source-connections", headers=headers["owner"], json=M365_REQUEST
    )
    assert created.status_code == 201
    connection_id = created.json()["connection_id"]
    assert client.get(
        f"/discovery/source-connections/{connection_id}", headers=headers["other_owner"]
    ).status_code == 404


class _ValidationTransport:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _M365ValidationCollector:
    def validate(self, *_: object, now: datetime) -> HMAIRSourceCapability:
        return HMAIRSourceCapability(
            provider_key=HMAIRSourceProvider.MICROSOFT365,
            state="partial",
            allowed_capabilities=("copilot_usage",),
            fresh_at=now,
            limitations=(
                "unlicensed_copilot_chat_not_reported_by_graph",
                "source_denominator_unavailable",
            ),
        )


class _ValidationRegistry:
    def get_collector(self, provider_key: str) -> _M365ValidationCollector:
        assert provider_key == HMAIRSourceProvider.MICROSOFT365.value
        return _M365ValidationCollector()


class _UnexpectedValidationRegistry:
    def get_collector(self, _: str) -> object:
        pytest.fail("a disabled source must not build or call a provider collector")


def test_owner_validation_persists_a_partial_capability_without_claiming_coverage(
    source_connection_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)
    transport = _ValidationTransport()
    monkeypatch.setitem(settings.__dict__, "hmair_connector_sources", True)
    monkeypatch.setitem(settings.__dict__, "hmair_microsoft365_source", True)
    monkeypatch.setattr(
        source_connection_service,
        "source_http_for_connection",
        lambda _connection: transport,
        raising=False,
    )
    monkeypatch.setattr(
        source_connection_service,
        "source_registry",
        _ValidationRegistry(),
        raising=False,
    )
    created = client.post(
        "/discovery/source-connections", headers=headers["owner"], json=M365_REQUEST
    )
    assert created.status_code == 201

    response = client.post(
        f"/discovery/source-connections/{created.json()['connection_id']}/validate",
        headers=headers["owner"],
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["capability"]["state"] == "partial"
    assert body["status"] == "active"
    assert body["collector"]["health"] == "warning"
    assert transport.closed is True
    session_factory = source_connection_env["session_factory"]
    assert callable(session_factory)
    with session_factory() as db:
        connector = db.scalar(select(Connector))
        assert connector is not None
        contract = connector.metadata_json["hmair_source_contract"]
        assert contract["capability"]["state"] == "partial"
        assert "customer-secret-value" not in str(contract)


def test_disabled_source_validation_never_dereferences_customer_credentials(
    source_connection_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)
    monkeypatch.setitem(settings.__dict__, "hmair_connector_sources", False)
    monkeypatch.setitem(settings.__dict__, "hmair_microsoft365_source", False)
    monkeypatch.setattr(
        source_connection_service,
        "source_http_for_connection",
        lambda _connection: pytest.fail("disabled source must not create a transport"),
        raising=False,
    )
    monkeypatch.setattr(
        source_connection_service,
        "source_registry",
        _UnexpectedValidationRegistry(),
        raising=False,
    )
    created = client.post(
        "/discovery/source-connections", headers=headers["owner"], json=M365_REQUEST
    )
    assert created.status_code == 201

    response = client.post(
        f"/discovery/source-connections/{created.json()['connection_id']}/validate",
        headers=headers["owner"],
    )

    assert response.status_code == 200
    assert response.json()["capability"]["state"] == "not_connected"


class _GitHubInventoryCollector:
    def validate(self, *_: object, now: datetime) -> HMAIRSourceCapability:
        return HMAIRSourceCapability(
            provider_key=HMAIRSourceProvider.GITHUB_CLOUD,
            state="ready",
            allowed_capabilities=("repository_inventory",),
            denominator=1,
            fresh_at=now,
            limitations=(),
        )

    def collect(
        self,
        *_: object,
        identifier_salt: str,
    ) -> HMAIRSourceCollectionResult:
        assert identifier_salt
        observed_at = datetime.now(UTC)
        records = (
            HMAIRNormalizedRecord(
                record_id="ghc-org-octocat",
                record_kind="github_organization",
                observed_at=observed_at,
                candidate_asset_type="repository_account",
                observation_type=ObservationType.API_CALL,
                source_surface=SourceSurface.SOURCE_CODE,
                identifiers={"organization_id": "personal:octocat", "host": "github.com"},
                metadata={"account_scope_kind": "PERSONAL", "sync_state": "COMPLETE"},
            ),
            HMAIRNormalizedRecord(
                record_id="ghc-repository-1",
                record_kind="github_repository",
                observed_at=observed_at,
                candidate_asset_type="repository",
                observation_type=ObservationType.PACKAGE_REFERENCE,
                source_surface=SourceSurface.SOURCE_CODE,
                identifiers={"organization_id": "personal:octocat", "repository_id": "1", "host": "github.com"},
                metadata={"full_name": "octocat/private-demo", "visibility": "PRIVATE"},
            ),
        )
        return HMAIRSourceCollectionResult(
            capability=HMAIRSourceCapability(
                provider_key=HMAIRSourceProvider.GITHUB_CLOUD,
                state="ready",
                allowed_capabilities=("repository_inventory",),
                denominator=1,
                fresh_at=observed_at,
                limitations=(),
            ),
            records=records,
            entra_records=(),
        )


class _GitHubInventoryRegistry:
    def get_collector(self, provider_key: str) -> _GitHubInventoryCollector:
        assert provider_key == HMAIRSourceProvider.GITHUB_CLOUD.value
        return _GitHubInventoryCollector()


def test_github_validation_persists_the_metadata_only_repository_inventory(
    source_connection_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)
    transport = _ValidationTransport()
    persisted: list[str] = []
    monkeypatch.setitem(settings.__dict__, "hmair_connector_sources", True)
    monkeypatch.setitem(settings.__dict__, "hmair_github_cloud_source", True)
    monkeypatch.setattr(
        source_connection_service,
        "source_http_for_connection",
        lambda _connection: transport,
    )
    monkeypatch.setattr(
        source_connection_service,
        "source_registry",
        _GitHubInventoryRegistry(),
    )
    from app.services import github_repository_access_service

    monkeypatch.setattr(
        github_repository_access_service,
        "persist_github_inventory_unit",
        lambda _db, **kwargs: persisted.append(kwargs["record"]["record_kind"]),
    )
    monkeypatch.setattr(
        github_repository_access_service,
        "derive_github_repository_ai_connections",
        lambda _db, **_kwargs: (),
    )
    created = client.post(
        "/discovery/source-connections",
        headers=headers["owner"],
        json=PERSONAL_GITHUB_REQUEST,
    )
    assert created.status_code == 201

    response = client.post(
        f"/discovery/source-connections/{created.json()['connection_id']}/validate",
        headers=headers["owner"],
    )

    assert response.status_code == 200, response.text
    assert response.json()["capability"]["denominator"] == 1
    assert persisted == ["github_organization", "github_repository"]
    assert transport.closed is True
    session_factory = source_connection_env["session_factory"]
    assert callable(session_factory)
    with session_factory() as db:
        connector = db.scalar(select(Connector))
        assert connector is not None
        assert connector.last_pull_status == "success"
        assert connector.last_signal_count == 2
        assert connector.last_run_at is not None
        assert "test-private-key" not in str(connector.metadata_json)


def test_authority_status_marks_validated_github_repository_denominator_authoritative(
    source_connection_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    client = source_connection_env["client"]
    headers = source_connection_env["headers"]
    assert isinstance(client, TestClient) and isinstance(headers, dict)
    transport = _ValidationTransport()
    monkeypatch.setitem(settings.__dict__, "hmair_connector_sources", True)
    monkeypatch.setitem(settings.__dict__, "hmair_github_cloud_source", True)
    monkeypatch.setattr(
        source_connection_service,
        "source_http_for_connection",
        lambda _connection: transport,
    )
    monkeypatch.setattr(
        source_connection_service,
        "source_registry",
        _GitHubInventoryRegistry(),
    )
    from app.services import github_repository_access_service

    monkeypatch.setattr(
        github_repository_access_service,
        "persist_github_inventory_unit",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        github_repository_access_service,
        "derive_github_repository_ai_connections",
        lambda *_args, **_kwargs: (),
    )
    created = client.post(
        "/discovery/source-connections",
        headers=headers["owner"],
        json=PERSONAL_GITHUB_REQUEST,
    )
    assert created.status_code == 201
    validated = client.post(
        f"/discovery/source-connections/{created.json()['connection_id']}/validate",
        headers=headers["owner"],
    )
    assert validated.status_code == 200, validated.text

    response = client.get("/discovery/source-connections/authority-status", headers=headers["viewer"])

    assert response.status_code == 200, response.text
    domains = {item["domain"]: item for item in response.json()["items"]}
    assert domains["repositories"]["state"] == "authoritative"
    assert domains["repositories"]["denominator"] == 1
    assert domains["repositories"]["connection_count"] == 1
    assert domains["repositories"]["fresh_at"] is not None
