"""Settings of the whole server are changed only by its administrators (app/core/installation.py): the owners and admins
of the installation's first tenant. Another tenant's owners and admins read them (read-only) and are refused, in the
audit log, when they try to change them; on a server with one tenant nothing changes for its owners and admins."""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.installation import INSTALLATION_ONLY, SET_BY_SERVER
from app.core.rbac import REFUSED
from app.core.security import get_password_hash
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.auth_service import issue_tokens

PASSWORD = "correct-Horse-2026"

#: Every route that changes a setting kept once for the whole server (no tenant_id): the sign-in rules
#: (sign_in_policy), the compliance settings (compliance_policy), the licence (activation_state), and what is kept
#: in the server's data folder (email server, branding, HTTPS, network and trusted certificates, updates, backups,
#: hands-off, the evidence signing key).
GATED = {
    ("PUT", "/auth/sign-in-settings"),
    ("POST", "/auth/sign-in-settings/test-email"),
    ("PUT", "/compliance/settings"),
    ("PUT", "/settings/branding"),
    ("PUT", "/settings/smtp"),
    ("POST", "/settings/smtp/test"),
    ("POST", "/settings/smtp/send-test"),
    ("DELETE", "/settings/smtp"),
    ("POST", "/https/certificate"),
    ("POST", "/https/certificate/previous"),
    ("DELETE", "/https/certificate"),
    ("POST", "/https/self-signed"),
    ("POST", "/https/request"),
    ("POST", "/https/mode"),
    ("POST", "/https/hardening"),
    ("POST", "/https/acme"),
    ("POST", "/https/acme/renew"),
    ("DELETE", "/https/acme"),
    ("PUT", "/network"),
    ("DELETE", "/network"),
    ("POST", "/trust/presented"),
    ("POST", "/trust/upload"),
    ("DELETE", "/trust/{fingerprint}"),
    ("POST", "/updates/check"),
    ("POST", "/updates/install"),
    ("PUT", "/updates/settings"),
    ("POST", "/updates/restart"),
    ("POST", "/integrity/check"),
    ("POST", "/backups"),
    ("POST", "/backups/key/show"),
    ("POST", "/backups/key/confirm"),
    ("POST", "/backups/encryption"),
    ("POST", "/backups/restore"),
    ("DELETE", "/backups/restore"),
    ("PUT", "/backups/readiness/{check_id}"),
    ("GET", "/backups/{name}"),
    ("PUT", "/hands-off"),
    ("POST", "/hands-off/status"),
    ("POST", "/hands-off/check"),
    ("POST", "/licence/import"),
    ("POST", "/evidence-signing/rotate"),
}


def _api_routes(routes, prefix: str = ""):
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from _api_routes(original.routes, prefix + (route.include_context.prefix or ""))
        elif hasattr(route, "dependant"):
            yield prefix + route.path, route


def _gated(route) -> bool:
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if getattr(dep.call, "installation", False):
            return True
        stack.extend(dep.dependencies)
    return False


@pytest.fixture()
def env(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setattr(settings, "hawk_data_dir", str(folder))
    for name in ("smtp_host", "smtp_user", "smtp_pass", "smtp_from"):
        monkeypatch.setattr(settings, name, "")
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'installation.sqlite3'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield {"client": client, "db": factory}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def member(env, email: str, role: str, slug: str) -> dict:
    with env["db"]() as db:
        t = db.scalar(select(Tenant).where(Tenant.slug == slug))
        if t is None:
            # The first tenant made is the installation's: made a day apart, so which is first never depends on the clock.
            first = slug == "acme"
            t = Tenant(name=slug.title(), slug=slug, is_active=True, created_at=dt.datetime(2026, 1, 1 if first else 2, tzinfo=dt.timezone.utc))
            db.add(t)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0].title(), hashed_password=get_password_hash(PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=t.id, role=role))
        db.flush()
        tokens = issue_tokens(db, user=user, tenant_id=t.id, role=role)
        db.commit()
        return {"id": user.id, "tenant": t.id, "h": {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": t.id}}


def _call(client: TestClient, method: str, path: str, headers: dict):
    concrete = path.replace("{fingerprint}", "ab" * 32).replace("{check_id}", "offsite").replace("{name}", "hawk-backup.tar")
    kwargs = {} if method in ("GET", "DELETE") else {"json": {}}
    return client.request(method, concrete, headers=headers, **kwargs)


def test_every_route_that_changes_a_setting_of_the_whole_server_is_gated_and_nothing_else():
    found = {(method, path) for path, route in _api_routes(app.routes) if _gated(route) for method in (route.methods or ())}
    assert found == GATED


def test_another_tenants_admin_is_refused_every_change_in_the_audit_log_and_reads_read_only(env):
    member(env, "owner@acme.test", "owner", "acme")
    other = member(env, "admin@beta.test", "admin", "beta")
    c = env["client"]
    for method, path in sorted(GATED):
        answer = _call(c, method, path, other["h"])
        assert answer.status_code == 403, (method, path, answer.text)
        assert answer.json()["detail"] == INSTALLATION_ONLY, (method, path)
    with env["db"]() as db:
        refused = db.scalars(select(AuditLog).where(AuditLog.action == "settings.installation.refused")).all()
    assert len(refused) == len(GATED)
    assert {r.tenant_id for r in refused} == {other["tenant"]}
    assert all(r.payload["outcome"] == "refused" and "whole server" in r.payload["reason"] and r.actor_user_id == other["id"] for r in refused)
    # Reads stay open to the tenant's admins, marked read-only.
    me = c.get("/settings/me", headers=other["h"]).json()
    assert me["installationAdmin"] is False and me["readOnlyNote"] == SET_BY_SERVER
    sign_in = c.get("/auth/sign-in-settings", headers=other["h"]).json()
    assert sign_in["mayChange"] is False and sign_in["readOnlyNote"] == SET_BY_SERVER and "passwordRule" in sign_in
    compliance = c.get("/compliance", headers=other["h"]).json()
    assert compliance["mayChange"] is False and compliance["readOnlyNote"] == SET_BY_SERVER
    smtp = c.get("/settings/smtp", headers=other["h"]).json()
    assert smtp["mayChange"] is False
    assert c.get("/hands-off", headers=other["h"]).json()["canSave"] is False
    assert c.get("/licence/status", headers=other["h"]).json()["canManage"] is False
    assert c.get("/evidence-signing", headers=other["h"]).status_code in (200, 503)
    for path in ("/network", "/https", "/updates", "/backups"):
        assert c.get(path, headers=other["h"]).status_code != 403, path
    # Their own tenant's settings stay theirs.
    assert c.put("/settings/ai-system-approvals", headers=other["h"], json={}).status_code != 403


def test_the_permission_check_comes_first_and_is_not_logged_as_an_installation_refusal(env):
    member(env, "owner@acme.test", "owner", "acme")
    viewer = member(env, "viewer@acme.test", "viewer", "acme")
    answer = env["client"].put("/compliance/settings", headers=viewer["h"], json={"incidentContact": "x"})
    assert answer.status_code == 403 and answer.json()["detail"] == REFUSED
    with env["db"]() as db:
        assert db.scalars(select(AuditLog).where(AuditLog.action == "settings.installation.refused")).all() == []


def test_the_first_tenants_owners_and_admins_change_them_as_before(env):
    owner = member(env, "owner@acme.test", "owner", "acme")
    admin = member(env, "admin@acme.test", "admin", "acme")
    member(env, "admin@beta.test", "admin", "beta")
    c = env["client"]
    for who in (owner, admin):
        me = c.get("/settings/me", headers=who["h"]).json()
        assert me["installationAdmin"] is True and me["readOnlyNote"] == ""
        assert c.get("/auth/sign-in-settings", headers=who["h"]).json()["mayChange"] is True
        assert c.get("/compliance", headers=who["h"]).json()["mayChange"] is True
    saved = c.put("/compliance/settings", headers=admin["h"], json={"incidentContact": "SOC, soc@acme.test"})
    assert saved.status_code == 200, saved.text
    assert saved.json()["settings"]["incidentContact"] == "SOC, soc@acme.test"
    rule = c.put("/auth/sign-in-settings", headers=owner["h"], json={"passwordRule": {"minLength": 12, "classes": 3, "history": 5, "maxAgeDays": 90}, "sessionIdleMinutes": 15, "banner": "Authorised use only."})
    assert rule.status_code == 200, rule.text
    assert rule.json()["sessionIdleMinutes"] == 15 and rule.json()["banner"] == "Authorised use only."
    assert c.put("/settings/branding", headers=admin["h"], json={"appName": "Acme Guard"}).status_code == 200
    assert c.put("/hands-off", headers=admin["h"], json={"handsOff": {"on": False}}).status_code == 200


def test_a_single_tenant_installation_changes_nothing_for_its_owners_and_admins(env):
    admin = member(env, "admin@solo.test", "admin", "solo")
    c = env["client"]
    assert c.get("/settings/me", headers=admin["h"]).json()["installationAdmin"] is True
    assert c.put("/compliance/settings", headers=admin["h"], json={"dataLocation": "Dubai, United Arab Emirates"}).status_code == 200
    assert c.put("/auth/sign-in-settings", headers=admin["h"], json={"banner": "Authorised use only."}).status_code == 200
    with env["db"]() as db:
        assert db.scalars(select(AuditLog).where(AuditLog.action == "settings.installation.refused")).all() == []
