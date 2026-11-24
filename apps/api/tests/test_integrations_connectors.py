from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.monitoring import Connector, DriftAlert, MonitoringSignal
from app.db.session import Base, get_db
from app.main import app
from app.core.config import settings
from app.services import outbound_destination_policy


PASSWORD = "Password123!"


@pytest.fixture(autouse=True)
def _outbound_policy_test_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        outbound_destination_policy,
        "_system_resolver",
        lambda _hostname, _port: ("93.184.216.34",),
    )
    monkeypatch.setattr(
        settings,
        "outbound_destination_allowlist",
        json.dumps(
            {
                "checkmarx": ["https://checkmarx.example.com"],
                "monitoring:sailpoint": [
                    "https://iiq.example.com",
                    "https://tenant.api.identitynow.com",
                ],
                "monitoring:fortinet": ["https://fortinet.example.com"],
                "monitoring:jira": ["https://acme.atlassian.net"],
            }
        ),
    )


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "integrations.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "SessionLocal": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Integration Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


class _FakeResponse:
    def __init__(self, payload, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://example.com")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("error", request=request, response=response)

    def json(self):
        return self._payload


class _FakeHTTPClient:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method: str, url: str, **kwargs):
        if method.upper() == "POST":
            return self.post(
                url,
                data=kwargs.get("data"),
                json=kwargs.get("json"),
                headers=kwargs.get("headers"),
            )
        return self.get(url, headers=kwargs.get("headers"))

    def get(self, url: str, headers=None):
        if "/auditLogs/signIns" in url:
            return _FakeResponse(
                {
                    "value": [
                        {
                            "id": "signin-1",
                            "riskLevelDuringSignIn": "high",
                            "appDisplayName": "Microsoft Copilot",
                            "body": {"contentType": "text", "content": "sensitive"},
                            "userPrincipalName": "ops@example.com",
                        }
                    ]
                }
            )
        if "/auditLogs/directoryAudits" in url:
            return _FakeResponse({"value": [{"id": "audit-1", "activityDisplayName": "Role updated"}]})
        if "/auditLogs/provisioning" in url:
            return _FakeResponse({"value": [{"id": "prov-1", "status": "failure"}]})

        if "/v3/identities" in url:
            return _FakeResponse({"items": [{"id": "sp-ident-1", "name": "svc-user"}]})
        if "/v3/access-requests" in url:
            return _FakeResponse({"items": [{"id": "sp-req-1", "state": "approved"}]})
        if "/v3/role-assignments" in url:
            return _FakeResponse({"items": [{"id": "sp-role-1", "role": "admin"}]})
        if "/Users" in url:
            return _FakeResponse({"Resources": [{"id": "iiq-user-1", "userName": "svc-user"}]})
        if "/Roles" in url:
            return _FakeResponse({"Resources": [{"id": "iiq-role-1", "displayName": "Privileged Role"}]})
        if "/Entitlements" in url:
            return _FakeResponse({"Resources": [{"id": "iiq-ent-1", "displayName": "FinanceData.Read"}]})
        if "/Accounts" in url:
            return _FakeResponse({"Resources": [{"id": "iiq-acct-1", "userName": "svc-account"}]})
        if "/TaskResults" in url:
            return _FakeResponse({"Resources": [{"id": "iiq-task-1", "name": "AggregationTask"}]})

        if "/rest/api/3/auditing/record" in url:
            return _FakeResponse({"records": [{"id": "jira-audit-1", "summary": "Ticket transitioned"}]})
        if "/rest/api/3/permissionscheme" in url:
            return _FakeResponse({"permissionSchemes": [{"id": "jira-perm-1", "name": "Default"}]})
        if "/rest/api/3/project/search" in url:
            return _FakeResponse({"values": [{"id": "jira-proj-1", "key": "SEC"}]})

        if "/api/scans" in url:
            return _FakeResponse({"scans": [{"id": "cx-scan-1", "riskLevel": "High"}]})
        if "/api/projects" in url:
            return _FakeResponse({"projects": [{"id": "cx-proj-1", "name": "gateway"}]})
        if "/api/results" in url:
            return _FakeResponse({"results": [{"id": "cx-find-1", "severity": "High"}]})

        if "/api/v2/monitor/log/event" in url:
            return _FakeResponse({"results": [{"id": "ft-event-1", "level": "warning"}]})
        if "/api/v2/cmdb/firewall/policy" in url:
            return _FakeResponse({"results": [{"id": "ft-policy-1", "action": "deny"}]})
        if "/api/v2/monitor/system/interface" in url:
            return _FakeResponse({"results": [{"id": "ft-intf-1", "status": "up"}]})

        if "/detects/queries/detects/v1" in url:
            return _FakeResponse({"resources": [{"id": "cs-detect-1"}]})
        if "/incidents/queries/incidents/v1" in url:
            return _FakeResponse({"resources": [{"id": "cs-inc-1"}]})
        if "/devices/queries/devices/v1" in url:
            return _FakeResponse({"resources": [{"id": "cs-host-1"}]})

        if "usage/completions" in url:
            return _FakeResponse({"data": [{"id": "cmp-1", "prompt_tokens": 10}]})
        if "usage/embeddings" in url:
            return _FakeResponse({"data": [{"id": "emb-1", "tokens": 25}]})
        if "organization/costs" in url:
            return _FakeResponse({"data": [{"id": "cost-1", "amount": 123.4}]})

        if "/models" in url:
            return _FakeResponse({"models": [{"name": "gemini-1.5-pro"}]})
        if "/files" in url:
            return _FakeResponse({"files": [{"name": "file-1"}]})
        if "/tunedModels" in url:
            return _FakeResponse({"tunedModels": [{"name": "tuned-1"}]})

        return _FakeResponse({"data": []})

    def post(self, url: str, data=None, json=None, headers=None):
        if "oauth" in url or "token" in url:
            return _FakeResponse({"access_token": "token-1"})
        if "Logon" in url:
            return _FakeResponse("cyberark-token")
        return _FakeResponse({})


def _create_connector(client: TestClient, *, headers: dict[str, str], name: str, provider_key: str, config: dict, secrets: dict) -> str:
    response = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": name,
            "provider_key": provider_key,
            "connector_type": provider_key,
            "config": config,
            "secrets": secrets,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_connector_provider_catalog_contains_phase_c1_pack(test_env) -> None:
    client: TestClient = test_env["client"]

    auth = _register_owner(client, email="integration-catalog-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    response = client.get("/monitoring/connectors/providers", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert sorted(body.keys()) == ["items", "page", "page_size", "total"]
    items = body["items"]
    assert isinstance(items, list)

    expected_keys = {
        "entra_id",
        "sailpoint",
        "aws",
        "microsoft_365",
        "outlook",
        "teams",
        "onedrive_sharepoint",
        "office_apps",
        "microsoft_defender",
        "azure_openai",
        "power_platform",
        "google_workspace",
        "slack",
        "gmail",
        "jira",
        "openai",
        "anthropic",
        "gemini",
        "fortinet",
        "netskope",
        "zscaler",
        "checkmarx",
        "akamai",
        "crowdstrike",
        "cyberark",
    }
    present_keys = {item["provider_key"] for item in items}
    assert expected_keys.issubset(present_keys)

    for item in items:
        assert item["supports_live_pull"] is True
        assert item["is_stub"] is False
        spec = item.get("connector_spec") or {}
        assert spec.get("auth_method")
        assert isinstance(spec.get("scopes"), list)
        assert isinstance(spec.get("data_pulled"), list)
        assert isinstance(spec.get("evidence_nodes_produced"), list)
        assert int(spec.get("polling_cadence_minutes") or 0) > 0

    signals_by_provider = {item["provider_key"]: {signal["signal_type"] for signal in (item.get("signals") or [])} for item in items}
    assert "saas.microsoft365.ai_usage" in signals_by_provider.get("microsoft_365", set())
    assert "saas.outlook.ai_usage" in signals_by_provider.get("outlook", set())
    assert "saas.teams.ai_usage" in signals_by_provider.get("teams", set())
    assert "saas.power_platform.usage" in signals_by_provider.get("power_platform", set())


def test_microsoft_permission_mode_and_admin_consent_endpoints(test_env) -> None:
    client: TestClient = test_env["client"]

    auth = _register_owner(client, email="integration-ms-perms-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    modes = client.get("/monitoring/connectors/microsoft/permission-modes", headers=headers)
    assert modes.status_code == 200, modes.text
    mode_items = modes.json()["items"]
    assert {item["mode"] for item in mode_items} >= {"poc_safe", "standard", "full_enterprise"}

    resolve = client.post(
        "/monitoring/connectors/microsoft/resolve-scopes",
        headers=headers,
        json={"provider_key": "microsoft_365", "permission_mode": "standard", "include_optional": True},
    )
    assert resolve.status_code == 200, resolve.text
    resolved = resolve.json()
    assert resolved["provider_key"] == "microsoft_365"
    assert resolved["permission_mode"] == "standard"
    assert "AuditLog.Read.All" in resolved["selected_scopes"]
    assert "Files.Read.All" in resolved["selected_scopes"]
    assert resolved["security_profile"]["tls_minimum"] == "1.3"

    consent = client.post(
        "/monitoring/connectors/microsoft/admin-consent-url",
        headers=headers,
        json={
            "tenant_id": "example-tenant-id",
            "client_id": "example-client-id",
            "redirect_uri": "https://hawk.example.com/oauth/callback",
            "state": "hawk-demo",
        },
    )
    assert consent.status_code == 200, consent.text
    consent_url = consent.json()["consent_url"]
    parsed = urlparse(consent_url)
    assert parsed.scheme == "https"
    assert parsed.netloc == "login.microsoftonline.com"
    assert parsed.path.endswith("/adminconsent")
    query = parse_qs(parsed.query)
    assert query.get("client_id") == ["example-client-id"]
    assert query.get("redirect_uri") == ["https://hawk.example.com/oauth/callback"]
    assert query.get("state") == ["hawk-demo"]

    template = client.get("/monitoring/connectors/microsoft/app-registration-template", headers=headers)
    assert template.status_code == 200, template.text
    t = template.json()
    assert t["app_registration_mode"] == "single_tenant"
    assert "client_credentials" in t["oauth_supported"]
    assert "tenant_id" in t["required_fields"]
    assert "client_id" in t["required_fields"]


def test_slack_bootstrap_endpoint_creates_connector_and_install_url(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-slack-bootstrap-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    response = client.post(
        "/monitoring/connectors/bootstrap/slack",
        headers=headers,
        json={
            "name": "Slack Bootstrapped",
            "client_id": "slack-client-id",
            "client_secret": "slack-client-secret",
            "redirect_uri": "https://hawk.example.com/slack/callback",
            "state": "demo-state",
            "create_connector": True,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider_key"] == "slack"
    assert body["created"] is True
    assert body["connector_id"]
    assert body["install_url"].startswith("https://slack.com/oauth/v2/authorize?")
    assert "channels:history" in body["selected_scopes"]
    assert body["connector"]["provider_key"] == "slack"

    with session_local() as db:
        row = db.scalar(
            select(Connector).where(
                Connector.id == body["connector_id"],
                Connector.tenant_id == auth["tenant_id"],
            )
        )
        assert row is not None
        assert row.provider_key == "slack"


def test_slack_bootstrap_endpoint_without_connector_creation_returns_install_url_only(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-slack-bootstrap-no-create-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    response = client.post(
        "/monitoring/connectors/bootstrap/slack",
        headers=headers,
        json={
            "name": "Slack Install Only",
            "client_id": "slack-client-id",
            "client_secret": "slack-client-secret",
            "redirect_uri": "https://hawk.example.com/slack/callback",
            "create_connector": False,
            "scopes": ["channels:history", "search:read"],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider_key"] == "slack"
    assert body["created"] is False
    assert body["connector_id"] is None
    assert body["connector"] is None
    assert body["install_url"].startswith("https://slack.com/oauth/v2/authorize?")
    assert body["selected_scopes"] == ["channels:history", "search:read"]

    with session_local() as db:
        rows = db.scalars(select(Connector).where(Connector.tenant_id == auth["tenant_id"])).all()
        assert rows == []


def test_microsoft_bootstrap_endpoint_creates_connector_and_consent_url(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-bootstrap-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    response = client.post(
        "/monitoring/connectors/bootstrap/microsoft",
        headers=headers,
        json={
            "name": "Microsoft Bootstrapped",
            "provider_key": "microsoft_365",
            "tenant_id": "sample-tenant-id",
            "client_id": "sample-client-id",
            "client_secret": "sample-client-secret",
            "redirect_uri": "https://hawk.example.com/ms/callback",
            "permission_mode": "standard",
            "create_connector": True,
            "include_optional_scopes": True,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider_key"] == "microsoft_365"
    assert body["created"] is True
    assert body["connector_id"]
    assert body["consent_url"].startswith("https://login.microsoftonline.com/")
    assert "Directory.Read.All" in body["selected_scopes"]
    assert body["connector"]["provider_key"] == "microsoft_365"

    with session_local() as db:
        row = db.scalar(
            select(Connector).where(
                Connector.id == body["connector_id"],
                Connector.tenant_id == auth["tenant_id"],
            )
        )
        assert row is not None
        assert row.provider_key == "microsoft_365"


def test_microsoft_bootstrap_repairs_existing_tenant_connector_without_duplicate(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-repair-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])
    created = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Existing Microsoft 365",
            "provider_key": "microsoft_365",
            "connector_type": "microsoft_365",
            "enabled": True,
            "config": {},
            "secrets": {},
        },
    )
    assert created.status_code == 200, created.text
    connector_id = created.json()["id"]

    repaired = client.post(
        "/monitoring/connectors/bootstrap/microsoft",
        headers=headers,
        json={
            "connector_id": connector_id,
            "name": "Existing Microsoft 365",
            "provider_key": "microsoft_365",
            "tenant_id": "sample-tenant-id",
            "client_id": "sample-client-id",
            "client_secret": "replacement-client-secret",
            "redirect_uri": "https://hawk.example.com/ms/callback",
            "permission_mode": "standard",
            "create_connector": True,
            "include_optional_scopes": True,
        },
    )
    assert repaired.status_code == 200, repaired.text
    body = repaired.json()
    assert body["created"] is False
    assert body["updated"] is True
    assert body["connector_id"] == connector_id
    assert body["connector"]["has_secrets"] is True

    with session_local() as db:
        rows = db.scalars(
            select(Connector).where(
                Connector.tenant_id == auth["tenant_id"],
                Connector.provider_key == "microsoft_365",
            )
        ).all()
        assert len(rows) == 1
        assert rows[0].id == connector_id
        assert rows[0].status == "active"
        assert rows[0].last_pull_status == "never"
        assert rows[0].last_pull_error is None
        assert rows[0].encrypted_secrets


def test_microsoft_bootstrap_cannot_repair_another_tenants_connector(test_env) -> None:
    client: TestClient = test_env["client"]
    first = _register_owner(client, email="integration-ms-repair-first@example.com")
    second = _register_owner(client, email="integration-ms-repair-second@example.com")
    created = client.post(
        "/monitoring/connectors",
        headers=_headers(first["access_token"], first["tenant_id"]),
        json={
            "name": "First tenant Microsoft 365",
            "provider_key": "microsoft_365",
            "connector_type": "microsoft_365",
            "enabled": True,
            "config": {},
            "secrets": {},
        },
    )
    assert created.status_code == 200, created.text

    denied = client.post(
        "/monitoring/connectors/bootstrap/microsoft",
        headers=_headers(second["access_token"], second["tenant_id"]),
        json={
            "connector_id": created.json()["id"],
            "name": "Cross-tenant repair",
            "provider_key": "microsoft_365",
            "tenant_id": "sample-tenant-id",
            "client_id": "sample-client-id",
            "client_secret": "replacement-client-secret",
            "redirect_uri": "https://hawk.example.com/ms/callback",
            "permission_mode": "poc_safe",
            "create_connector": True,
        },
    )
    assert denied.status_code == 404


def test_microsoft_bootstrap_endpoint_client_assertion_mode(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-bootstrap-assert-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    response = client.post(
        "/monitoring/connectors/bootstrap/microsoft",
        headers=headers,
        json={
            "name": "Microsoft Bootstrapped Assertion",
            "provider_key": "microsoft_365",
            "tenant_id": "sample-tenant-id",
            "client_id": "sample-client-id",
            "credential_mode": "client_assertion",
            "client_assertion": "signed-jwt-assertion",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "redirect_uri": "https://hawk.example.com/ms/callback",
            "permission_mode": "standard",
            "create_connector": True,
            "include_optional_scopes": True,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["created"] is True
    assert body["connector_id"]
    assert body["consent_url"].startswith("https://login.microsoftonline.com/")

    with session_local() as db:
        row = db.scalar(
            select(Connector).where(
                Connector.id == body["connector_id"],
                Connector.tenant_id == auth["tenant_id"],
            )
        )
        assert row is not None
        assert row.provider_key == "microsoft_365"
        assert row.encrypted_secrets


def test_microsoft_bootstrap_endpoint_without_connector_creation_returns_consent_only(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-bootstrap-no-create-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    response = client.post(
        "/monitoring/connectors/bootstrap/microsoft",
        headers=headers,
        json={
            "name": "Microsoft Consent Only",
            "provider_key": "microsoft_365",
            "tenant_id": "sample-tenant-id",
            "client_id": "sample-client-id",
            "client_secret": "sample-client-secret",
            "redirect_uri": "https://hawk.example.com/ms/callback",
            "permission_mode": "poc_safe",
            "create_connector": False,
            "include_optional_scopes": False,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["created"] is False
    assert body["connector_id"] is None
    assert body["connector"] is None
    assert body["consent_url"].startswith("https://login.microsoftonline.com/")

    with session_local() as db:
        rows = db.scalars(select(Connector).where(Connector.tenant_id == auth["tenant_id"])).all()
        assert rows == []


def test_microsoft_connector_creation_applies_least_privilege_defaults(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-create-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    response = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "M365 Connector",
            "provider_key": "microsoft_365",
            "connector_type": "microsoft_365",
            "config": {
                "tenant_id": "graph-tenant-id",
                "client_id": "graph-client-id",
                "redirect_uri": "https://hawk.example.com/oauth/callback",
            },
            "secrets": {
                "client_secret": "graph-client-secret",
            },
        },
    )
    assert response.status_code == 200, response.text
    connector_id = response.json()["id"]

    with session_local() as db:
        row = db.scalar(
            select(Connector).where(
                Connector.id == connector_id,
                Connector.tenant_id == auth["tenant_id"],
            )
        )
        assert row is not None
        cfg = dict(row.config or {})
        metadata = dict(row.metadata_json or {})
        assert cfg.get("permission_mode") == "poc_safe"
        assert cfg.get("metadata_only_ingestion") is True
        assert cfg.get("app_registration_mode") == "single_tenant"
        ms_meta = dict(metadata.get("microsoft_graph") or {})
        assert ms_meta.get("permission_mode") == "poc_safe"
        assert "AuditLog.Read.All" in list(ms_meta.get("selected_scopes") or [])
        assert str(ms_meta.get("admin_consent_url") or "").startswith("https://login.microsoftonline.com/")


@pytest.mark.parametrize(
    ("provider_key", "signal_type", "record"),
    [
        ("slack", "saas.slack.ai_usage", {"domain": "chat.openai.com", "user": "ops@example.com"}),
        ("gmail", "saas.gmail.ai_usage", {"domain": "mail.google.com", "user": "ops@example.com"}),
        ("outlook", "saas.outlook.ai_usage", {"domain": "outlook.office.com", "user": "ops@example.com"}),
        ("microsoft_365", "saas.microsoft365.ai_usage", {"appDisplayName": "Microsoft Copilot", "user": "ops@example.com"}),
    ],
)
def test_connector_ai_usage_signal_applies_retroactive_policy_and_governance_finding(
    test_env,
    provider_key: str,
    signal_type: str,
    record: dict[str, str],
) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email=f"integration-retro-policy-{provider_key}@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    ingest = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "signal_type": signal_type,
            "severity": "high",
            "payload": {
                "provider_key": provider_key,
                "record": record,
            },
        },
    )
    assert ingest.status_code == 200, ingest.text
    payload = ingest.json()
    retro = dict(payload.get("payload", {}).get("retroactive_policy") or {})
    assert retro
    assert retro.get("decision") in {"warn", "block"}
    assert retro.get("reason_code")
    assert retro.get("recommended_action")
    assert retro.get("provider_key") == provider_key
    assert str(retro.get("ai_tool") or "").strip() != ""

    with session_local() as db:
        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == auth["tenant_id"],
                Finding.finding_type == "unregistered_ai_system",
                Finding.source_surface == "connector",
            )
        )
        assert finding is not None
        assert finding.finding_type == "unregistered_ai_system"
        assert finding.source_surface == "connector"


def test_openai_connector_pull_normalizes_signals_and_encrypts_secrets(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "OpenAI Integration",
            "provider_key": "openai",
            "connector_type": "openai",
            "auth_type": "bearer",
            "enabled": True,
            "polling_interval_minutes": 15,
            "config": {"base_url": "https://api.openai.com/v1"},
            "secrets": {"access_token": "secret-token-value"},
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    with session_local() as db:
        connector = db.scalar(
            select(Connector).where(
                Connector.id == connector_id,
                Connector.tenant_id == auth["tenant_id"],
            )
        )
        assert connector is not None
        assert connector.encrypted_secrets is not None
        assert "secret-token-value" not in connector.encrypted_secrets

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text
    pull_body = pull_resp.json()
    assert pull_body["last_pull_status"] == "success"
    assert pull_body["is_stub"] is False
    assert pull_body["last_signal_count"] >= 3

    with session_local() as db:
        signals = db.scalars(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type.like("ai.openai.%"),
            )
        ).all()
        assert len(signals) >= 3

        evidence_nodes = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == auth["tenant_id"],
                EvidenceNode.signal_type.like("connector.openai.%"),
            )
        ).all()
        assert len(evidence_nodes) >= 3
        integration_nodes = [node for node in evidence_nodes if node.node_type == "integration_signal"]
        assert integration_nodes
        for node in integration_nodes:
            payload = node.payload or {}
            assert "source_metadata" in payload

        alerts = db.scalars(
            select(DriftAlert).where(
                DriftAlert.tenant_id == auth["tenant_id"],
            )
        ).all()
        assert len(alerts) >= 1


def test_gemini_connector_ingestion_produces_evidence_and_drift_alerts(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-gemini-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Gemini Integration",
            "provider_key": "gemini",
            "connector_type": "gemini",
            "config": {"base_url": "https://generativelanguage.googleapis.com/v1beta"},
            "secrets": {"api_key": "gemini-api-key"},
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text
    payload = pull_resp.json()
    assert payload["is_stub"] is False
    assert payload["last_pull_status"] == "success"
    assert payload["last_signal_count"] >= 3

    with session_local() as db:
        evidence_nodes = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == auth["tenant_id"],
                EvidenceNode.signal_type.like("connector.gemini.%"),
            )
        ).all()
        assert len(evidence_nodes) >= 3

        alerts = db.scalars(
            select(DriftAlert).where(
                DriftAlert.tenant_id == auth["tenant_id"],
            )
        ).all()
        assert len(alerts) >= 1


def test_microsoft_graph_client_credentials_pull_uses_metadata_only_records(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-pull-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Outlook Graph Connector",
            "provider_key": "outlook",
            "connector_type": "outlook",
            "config": {
                "base_url": "https://graph.microsoft.com/v1.0",
                "tenant_id": "graph-tenant-id",
                "client_id": "graph-client-id",
                "permission_mode": "standard",
            },
            "secrets": {
                "client_secret": "graph-client-secret",
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text
    body = pull_resp.json()
    assert body["last_pull_status"] == "success"
    assert body["last_signal_count"] >= 3

    with session_local() as db:
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "saas.outlook.mail_activity",
            )
        )
        assert signal is not None
        payload = dict(signal.payload or {})
        source_meta = dict(payload.get("source_metadata") or {})
        assert source_meta.get("permission_mode") == "standard"
        resolved_scopes = list(source_meta.get("resolved_scopes") or [])
        assert "Mail.Read" in resolved_scopes
        record = dict(payload.get("record") or {})
        assert record.get("record_mode") == "metadata_only"
        assert "body" not in record
        assert record.get("content_redacted") is True


def test_microsoft_graph_content_scan_requires_policy_storage_allowance(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-content-policy-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Outlook Graph Content Policy Connector",
            "provider_key": "outlook",
            "connector_type": "outlook",
            "config": {
                "base_url": "https://graph.microsoft.com/v1.0",
                "tenant_id": "graph-tenant-id",
                "client_id": "graph-client-id",
                "permission_mode": "standard",
                "metadata_only_ingestion": True,
                "content_scanning_enabled": True,
            },
            "secrets": {
                "client_secret": "graph-client-secret",
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text

    with session_local() as db:
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "saas.outlook.mail_activity",
            )
        )
        assert signal is not None
        payload = dict(signal.payload or {})
        source_meta = dict(payload.get("source_metadata") or {})
        record = dict(payload.get("record") or {})
        assert source_meta.get("metadata_only_ingestion") is True
        assert source_meta.get("content_storage_policy") == "metadata_only"
        assert record.get("record_mode") == "metadata_only"
        assert record.get("content_redacted") is True
        assert "subject" not in record
        assert "bodyPreview" not in record


def test_microsoft_graph_pull_enriches_oauth_supply_chain_context(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-oauth-supply-chain-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "M365 OAuth Discovery Connector",
            "provider_key": "microsoft_365",
            "connector_type": "microsoft_365",
            "config": {
                "base_url": "https://graph.microsoft.com/v1.0",
                "tenant_id": "graph-tenant-id",
                "client_id": "graph-client-id",
                "permission_mode": "standard",
            },
            "secrets": {
                "access_token": "graph-access-token",
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    def _fake_pull_http_signals(
        provider, *, connector_config, secrets, headers, base_url, mappings=None, destination_policy=None
    ):
        del connector_config, secrets, headers, base_url, mappings
        from app.services.integration_connector_service import PullSignal

        now = datetime.now(timezone.utc)
        assert provider.key == "microsoft_365"
        return [
            PullSignal(
                signal_key="unified_audit",
                payload={
                    "appId": "oauth-app-123",
                    "clientId": "oauth-client-123",
                    "appDisplayName": "Suspicious AI Add-on",
                    "publisherName": "Unknown Publisher",
                    "scopes": [
                        "Files.Read.All",
                        "Mail.ReadWrite",
                        "Directory.Read.All",
                    ],
                    "users": ["owner@example.com"],
                    "activityDisplayName": "Consent to application",
                    "riskLevelDuringSignIn": "high",
                    "targetResources": [
                        {"displayName": "SharePoint"},
                        {"displayName": "OneDrive"},
                        {"displayName": "Exchange"},
                    ],
                    "environmentVariables": {"OPENAI_API_KEY": "x", "DB_PASSWORD": "y"},
                    "secrets": ["OPENAI_API_KEY"],
                    "content_redacted": False,
                },
                observed_at=now,
            )
        ]

    monkeypatch.setattr("app.services.integration_connector_service._pull_http_signals", _fake_pull_http_signals)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text
    body = pull_resp.json()
    assert body["last_pull_status"] == "success"
    assert body["last_signal_count"] >= 1

    with session_local() as db:
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "saas.microsoft365.audit.unified",
            )
        )
        assert signal is not None
        payload = dict(signal.payload or {})
        oauth_app = dict(payload.get("oauth_app") or {})
        assert oauth_app.get("app_id") == "oauth-app-123"
        assert oauth_app.get("client_id") == "oauth-client-123"
        assert oauth_app.get("name") == "Suspicious AI Add-on"
        assert "Directory.Read.All" in list(oauth_app.get("scopes") or [])
        assert float(oauth_app.get("risk_score") or 0.0) >= 0.8
        assert payload.get("oauth_new_app") is True
        assert payload.get("oauth_high_risk_scopes") is True
        assert payload.get("abnormal_access_pattern") is True
        assert payload.get("reason_code") == "oauth_supply_chain_attack"
        assert payload.get("connector_risk_exposed") is True
        assert payload.get("unprotected_secrets_accessed") is True
        assert "OPENAI_API_KEY" in list(payload.get("secrets") or [])
        assert len(list(payload.get("systems_accessed") or [])) >= 3
        relationships = list(payload.get("oauth_relationships") or [])
        assert relationships
        assert relationships[0]["app_id"] == "oauth-app-123"
        assert relationships[0]["user_id"] == "owner@example.com"

    findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=AI_SUPPLY_CHAIN_ATTACK",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    assert findings.json()["total"] >= 1
    finding = findings.json()["items"][0]
    assert finding["risk_category"] == "supply_chain"
    assert "revoke oauth app" in str(finding.get("recommended_action") or "").lower()

    triggers = client.get(
        "/runtime-intelligence/triggers?page=1&page_size=100&reason_code=oauth_supply_chain_attack",
        headers=headers,
    )
    assert triggers.status_code == 200, triggers.text
    assert triggers.json()["total"] >= 1

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    recommendation_payloads = [
        dict(item.get("payload") or {})
        for item in recommendations.json()["items"]
        if str(item.get("reason_code") or "") == "oauth_supply_chain_attack"
    ]
    assert recommendation_payloads
    actions = {
        str(suggestion.get("action") or "")
        for payload in recommendation_payloads
        for suggestion in list(payload.get("remediation_suggestions") or [])
        if isinstance(suggestion, dict)
    }
    assert {"revoke_oauth_app", "revoke_tokens", "rotate_secrets", "disable_user"}.issubset(actions)

    events = client.get("/runtime-intelligence/events?page=1&page_size=100", headers=headers)
    assert events.status_code == 200, events.text
    oauth_events = [
        item
        for item in events.json()["items"]
        if str(dict(item.get("metadata") or {}).get("reason_code") or "") == "oauth_supply_chain_attack"
    ]
    assert oauth_events
    trace = client.get(f"/runtime/trace/{oauth_events[0]['event_id']}", headers=headers)
    assert trace.status_code == 200, trace.text
    assert trace.json()["steps"]


def test_google_workspace_pull_enriches_oauth_supply_chain_context(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-google-oauth-supply-chain-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Google OAuth Discovery Connector",
            "provider_key": "google_workspace",
            "connector_type": "google_workspace",
            "config": {
                "base_url": "https://admin.googleapis.com",
                "customer_id": "my_customer",
            },
            "secrets": {
                "access_token": "google-access-token",
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    def _fake_pull_http_signals(
        provider, *, connector_config, secrets, headers, base_url, mappings=None, destination_policy=None
    ):
        del connector_config, secrets, headers, base_url, mappings
        from app.services.integration_connector_service import PullSignal

        now = datetime.now(timezone.utc)
        assert provider.key == "google_workspace"
        return [
            PullSignal(
                signal_key="admin_activity",
                payload={
                    "appId": "google-oauth-app-123",
                    "clientId": "google-client-123",
                    "appDisplayName": "Suspicious Gemini Workspace Add-on",
                    "publisherName": "Unknown Publisher",
                    "scopes": [
                        "https://www.googleapis.com/auth/drive",
                        "https://www.googleapis.com/auth/gmail.modify",
                        "https://www.googleapis.com/auth/admin.directory.user",
                    ],
                    "users": ["owner@example.com"],
                    "event_type": "oauth app installed",
                    "riskLevel": "high",
                    "targetResources": [
                        {"displayName": "Google Drive"},
                        {"displayName": "Gmail"},
                        {"displayName": "Admin Directory"},
                    ],
                    "environmentVariables": {"GEMINI_API_KEY": "x"},
                    "secrets": ["GEMINI_API_KEY"],
                    "content_redacted": False,
                },
                observed_at=now,
            )
        ]

    monkeypatch.setattr("app.services.integration_connector_service._pull_http_signals", _fake_pull_http_signals)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text
    assert pull_resp.json()["last_pull_status"] == "success"

    with session_local() as db:
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "saas.google_workspace.admin_activity",
            )
        )
        assert signal is not None
        payload = dict(signal.payload or {})
        oauth_app = dict(payload.get("oauth_app") or {})
        assert oauth_app.get("app_id") == "google-oauth-app-123"
        assert oauth_app.get("client_id") == "google-client-123"
        assert oauth_app.get("name") == "Suspicious Gemini Workspace Add-on"
        assert "https://www.googleapis.com/auth/drive" in list(oauth_app.get("scopes") or [])
        assert float(oauth_app.get("risk_score") or 0.0) >= 0.8
        assert payload.get("oauth_new_app") is True
        assert payload.get("oauth_high_risk_scopes") is True
        assert payload.get("abnormal_access_pattern") is True
        assert payload.get("reason_code") == "oauth_supply_chain_attack"
        assert payload.get("connector_risk_exposed") is True
        assert payload.get("unprotected_secrets_accessed") is True
        assert "GEMINI_API_KEY" in list(payload.get("secrets") or [])
        assert {"Google Drive", "Gmail", "Admin Directory"}.issubset(set(payload.get("systems_accessed") or []))
        relationships = list(payload.get("oauth_relationships") or [])
        assert relationships
        assert relationships[0]["app_id"] == "google-oauth-app-123"
        assert relationships[0]["user_id"] == "owner@example.com"

    findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=AI_SUPPLY_CHAIN_ATTACK",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    assert findings.json()["total"] >= 1

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    recommendation_payloads = [
        dict(item.get("payload") or {})
        for item in recommendations.json()["items"]
        if str(item.get("reason_code") or "") == "oauth_supply_chain_attack"
    ]
    assert recommendation_payloads
    actions = {
        str(suggestion.get("action") or "")
        for payload in recommendation_payloads
        for suggestion in list(payload.get("remediation_suggestions") or [])
        if isinstance(suggestion, dict)
    }
    assert {"revoke_oauth_app", "revoke_tokens", "rotate_secrets", "disable_user"}.issubset(actions)


def test_microsoft_graph_client_assertion_pull_is_supported(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-ms-assertion-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Teams Graph Connector",
            "provider_key": "teams",
            "connector_type": "teams",
            "config": {
                "base_url": "https://graph.microsoft.com/v1.0",
                "tenant_id": "graph-tenant-id",
                "client_id": "graph-client-id",
                "permission_mode": "standard",
            },
            "secrets": {
                "client_assertion": "dummy.jwt.assertion.token",
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text
    body = pull_resp.json()
    assert body["last_pull_status"] == "success"
    assert body["last_signal_count"] >= 1

    with session_local() as db:
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "saas.teams.ai_usage",
            )
        )
        assert signal is not None


def test_sailpoint_iiq_scim_pull_supports_identities_roles_events_entitlements_accounts(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-sailpoint-iiq-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    create_resp = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "SailPoint IIQ SCIM Connector",
            "provider_key": "sailpoint",
            "connector_type": "sailpoint",
            "config": {
                "base_url": "https://iiq.example.com/identityiq/scim/v2",
                "api_variant": "iiq_scim",
            },
            "secrets": {
                "username": "svc_hawk",
                "api_key": "iiq-api-key",
            },
        },
    )
    assert create_resp.status_code == 200, create_resp.text
    connector_id = create_resp.json()["id"]

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    pull_resp = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull_resp.status_code == 200, pull_resp.text
    body = pull_resp.json()
    assert body["last_pull_status"] == "success"
    assert body["last_signal_count"] >= 5

    with session_local() as db:
        signal_types = {
            row.signal_type
            for row in db.scalars(
                select(MonitoringSignal).where(
                    MonitoringSignal.tenant_id == auth["tenant_id"],
                    MonitoringSignal.signal_type.like("identity.sailpoint.%"),
                )
            ).all()
        }
        assert {
            "identity.sailpoint.identities",
            "identity.sailpoint.roles",
            "identity.sailpoint.events",
            "identity.sailpoint.entitlements",
            "identity.sailpoint.accounts",
        }.issubset(signal_types)

        sample = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "identity.sailpoint.accounts",
            )
        )
        assert sample is not None
        source_metadata = dict((sample.payload or {}).get("source_metadata") or {})
        assert source_metadata.get("sailpoint_api_variant") == "iiq_scim"


def test_first_real_connector_pack_ingests_identity_cloud_and_jira_flows(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="integration-pack-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    def _fake_pull_aws_signals(secrets: dict, connector_config: dict):
        del secrets, connector_config
        from datetime import datetime, timezone
        from app.services.integration_connector_service import PullSignal

        now = datetime.now(timezone.utc)
        return (
            [
                PullSignal(signal_key="cloudtrail_events", payload={"eventName": "PutBucketAcl"}, observed_at=now),
                PullSignal(signal_key="iam_roles", payload={"roleName": "AdminRole"}, observed_at=now),
                PullSignal(signal_key="s3_public_access", payload={"bucket": "public-bucket", "acl": {"Grants": ["AllUsers"]}}, observed_at=now),
            ],
            None,
        )

    monkeypatch.setattr("app.services.integration_connector_service._pull_aws_signals", _fake_pull_aws_signals)

    connector_ids = {
        "entra_id": _create_connector(
            client,
            headers=headers,
            name="Entra Connector",
            provider_key="entra_id",
            config={"base_url": "https://graph.microsoft.com/v1.0"},
            secrets={"access_token": "entra-token"},
        ),
        "sailpoint": _create_connector(
            client,
            headers=headers,
            name="SailPoint Connector",
            provider_key="sailpoint",
            config={"base_url": "https://tenant.api.identitynow.com"},
            secrets={"client_id": "sp-client", "client_secret": "sp-secret"},
        ),
        "aws": _create_connector(
            client,
            headers=headers,
            name="AWS Connector",
            provider_key="aws",
            config={"region": "us-east-1"},
            secrets={"access_key_id": "AKIA123", "secret_access_key": "SECRET123"},
        ),
        "checkmarx": _create_connector(
            client,
            headers=headers,
            name="Checkmarx Connector",
            provider_key="checkmarx",
            config={"base_url": "https://checkmarx.example.com"},
            secrets={"access_token": "checkmarx-token"},
        ),
        "crowdstrike": _create_connector(
            client,
            headers=headers,
            name="CrowdStrike Connector",
            provider_key="crowdstrike",
            config={"base_url": "https://api.crowdstrike.com"},
            secrets={"client_id": "cs-client", "client_secret": "cs-secret"},
        ),
        "fortinet": _create_connector(
            client,
            headers=headers,
            name="Fortinet Connector",
            provider_key="fortinet",
            config={"base_url": "https://fortinet.example.com"},
            secrets={"access_token": "fortinet-token"},
        ),
        "jira": _create_connector(
            client,
            headers=headers,
            name="Jira Connector",
            provider_key="jira",
            config={"base_url": "https://acme.atlassian.net"},
            secrets={"email": "owner@example.com", "api_token": "jira-token"},
        ),
    }

    for provider_key, connector_id in connector_ids.items():
        response = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["provider_key"] == provider_key
        assert body["last_pull_status"] == "success"
        assert body["is_stub"] is False
        assert body["last_signal_count"] >= 3

    with session_local() as db:
        # Identity change path (Entra / SailPoint)
        identity_signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "identity.entra.directory_audit",
            )
        )
        assert identity_signal is not None
        sailpoint_signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "identity.sailpoint.role_assignments",
            )
        )
        assert sailpoint_signal is not None

        # AWS drift path
        aws_signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "cloud.aws.s3.public_access",
            )
        )
        assert aws_signal is not None
        aws_evidence = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == auth["tenant_id"],
                EvidenceNode.signal_type.like("connector.aws.%"),
            )
        ).all()
        assert len(aws_evidence) >= 3
        aws_finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == auth["tenant_id"],
                Finding.ai_tool == "aws",
                Finding.finding_type == "drift_alert",
            )
        )
        assert aws_finding is not None

        # Jira remediation visibility path
        jira_signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == auth["tenant_id"],
                MonitoringSignal.signal_type == "ticketing.jira.audit.records",
            )
        )
        assert jira_signal is not None
        jira_finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == auth["tenant_id"],
                Finding.ai_tool == "jira",
                Finding.finding_type == "drift_alert",
            )
        )
        assert jira_finding is not None

        alerts = db.scalars(select(DriftAlert).where(DriftAlert.tenant_id == auth["tenant_id"])).all()
        assert len(alerts) >= 7

    coverage_response = client.get("/monitoring/connectors/coverage?page=1&page_size=200", headers=headers)
    assert coverage_response.status_code == 200, coverage_response.text
    coverage_body = coverage_response.json()
    assert sorted(coverage_body.keys()) == ["items", "page", "page_size", "total"]
    assert coverage_body["total"] >= 21
    coverage_items = coverage_body["items"]
    target_rows = [
        row
        for row in coverage_items
        if row["provider_key"] in {"entra_id", "sailpoint", "aws", "checkmarx", "crowdstrike", "fortinet", "jira"}
    ]
    assert target_rows
    assert all(isinstance(row["modules"], list) for row in target_rows)
    assert all(row["control_id"] for row in target_rows)

    aws_coverage = [row for row in target_rows if row["provider_key"] == "aws" and row["signal_type"] == "cloud.aws.s3.public_access"]
    assert aws_coverage
    assert aws_coverage[0]["observed_count"] >= 1
