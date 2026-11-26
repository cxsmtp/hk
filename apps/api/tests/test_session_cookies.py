"""The console's sign-in in HttpOnly cookies (app/core/session_cookies.py): issued at every sign-in, refreshed and
cleared through the refresh path only, CSRF-checked on requests that change something, while bearer clients (the SDK,
the MCP proxy, the endpoint agent, the extension) keep getting tokens in the body and need no CSRF token."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.tenant import Tenant
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import account_security, mfa_service


PASSWORD = "correct-Horse-2026"
NEW_PASSWORD = "a-new-Password-2026"
COOKIE = {"X-Hawk-Session": "cookie"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'cookies.sqlite3'}", connect_args={"check_same_thread": False})
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

    monkeypatch.setattr(settings, "api_base_url", "")
    app.dependency_overrides[get_db] = override_get_db
    # https, as behind the front proxy: Secure cookies with their __Host-/__Secure- names.
    client = TestClient(app, base_url="https://testserver")
    plain = TestClient(app)
    try:
        yield {"client": client, "plain": plain, "db": factory}
    finally:
        client.close()
        plain.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def make_user(env, email: str, *, role: str = "owner", tenant: str = "acme") -> tuple[str, str]:
    with env["db"]() as db:
        tenant_row = db.scalar(select(Tenant).where(Tenant.slug == tenant))
        if tenant_row is None:
            tenant_row = Tenant(name=tenant.title(), slug=tenant, is_active=True)
            db.add(tenant_row)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0], hashed_password=get_password_hash(PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant_row.id, role=role))
        db.commit()
        return user.id, tenant_row.id


def set_cookies(response) -> dict[str, str]:
    """Each Set-Cookie header of a response, by cookie name."""

    out = {}
    for header in response.headers.get_list("set-cookie"):
        out[header.split("=", 1)[0]] = header
    return out


def sign_in(env, email: str, client_key: str = "client"):
    response = env[client_key].post("/auth/login", json={"email": email, "password": PASSWORD}, headers=COOKIE)
    assert response.status_code == 200, response.text
    return response


def csrf(env, client_key: str = "client") -> dict[str, str]:
    jar = env[client_key].cookies
    value = jar.get("__Host-hawk_csrf") or jar.get("hawk_csrf")
    assert value
    return {"X-CSRF-Token": value}


def live_refresh_tokens(env, user_id: str) -> int:
    with env["db"]() as db:
        return len(db.scalars(select(RefreshToken).where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))).all())


def test_sign_in_sets_httponly_strict_cookies_and_keeps_tokens_out_of_the_body(env):
    _, tenant_id = make_user(env, "ann@example.test")
    response = sign_in(env, "ann@example.test")
    body = response.json()
    assert body["access_token"] == "" and body["refresh_token"] == ""
    assert body["selected_tenant_id"] == tenant_id and body["user"]["email"] == "ann@example.test"
    assert response.headers["cache-control"] == "no-store"
    cookies = set_cookies(response)
    access, refresh, token = cookies["__Host-hawk_access"], cookies["__Secure-hawk_refresh"], cookies["__Host-hawk_csrf"]
    for header in (access, refresh, token):
        assert "Secure" in header and "SameSite=strict" in header
    assert "HttpOnly" in access and "Path=/;" in access
    assert "HttpOnly" in refresh and "Path=/auth/refresh" in refresh
    assert "HttpOnly" not in token and "Path=/;" in token
    assert f"Max-Age={settings.access_token_expire_minutes * 60}" in access


def test_plain_http_drops_secure_and_the_prefixes_for_localhost(env):
    make_user(env, "dev@example.test")
    cookies = set_cookies(sign_in(env, "dev@example.test", "plain"))
    assert set(cookies) == {"hawk_access", "hawk_refresh", "hawk_csrf"}
    assert all("Secure" not in header for header in cookies.values())
    assert env["plain"].get("/auth/me").status_code == 200


def test_the_refresh_cookie_path_follows_where_the_browser_reaches_the_api(env, monkeypatch):
    make_user(env, "ann@example.test")
    proxied = env["client"].post("/auth/login", json={"email": "ann@example.test", "password": PASSWORD}, headers={**COOKIE, "X-Forwarded-Prefix": "/api"})
    assert "Path=/api/auth/refresh" in set_cookies(proxied)["__Secure-hawk_refresh"]
    monkeypatch.setattr(settings, "api_base_url", "https://hawk.example.test/hawk-api/")
    configured = sign_in(env, "ann@example.test")
    assert "Path=/hawk-api/auth/refresh" in set_cookies(configured)["__Secure-hawk_refresh"]
    # Anything but a plain path is ignored.
    odd = env["client"].post("/auth/login", json={"email": "ann@example.test", "password": PASSWORD}, headers={**COOKIE, "X-Forwarded-Prefix": "/x;Domain=evil"})
    assert "Path=/hawk-api/auth/refresh" in set_cookies(odd)["__Secure-hawk_refresh"]


def test_bearer_clients_are_unchanged_tokens_in_the_body_no_cookies_no_csrf(env):
    make_user(env, "sdk@example.test")
    response = env["client"].post("/auth/login", json={"email": "sdk@example.test", "password": PASSWORD})
    tokens = response.json()
    assert tokens["access_token"] and tokens["refresh_token"]
    assert response.headers.get_list("set-cookie") == []
    headers = {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}
    assert env["client"].get("/auth/me", headers=headers).status_code == 200
    # A request that changes something needs no CSRF token with a bearer header.
    changed = env["client"].post("/auth/select-tenant", headers=headers, json={"tenant_id": tokens["selected_tenant_id"]})
    assert changed.status_code == 200, changed.text
    assert changed.json()["access_token"] and changed.headers.get_list("set-cookie") == []
    refreshed = env["client"].post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200 and refreshed.json()["access_token"] and refreshed.json()["refresh_token"]
    assert refreshed.headers.get_list("set-cookie") == []


def test_a_bearer_header_wins_over_cookies_and_needs_no_csrf(env):
    make_user(env, "ann@example.test")
    sign_in(env, "ann@example.test")
    tokens = env["plain"].post("/auth/login", json={"email": "ann@example.test", "password": PASSWORD}).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    answer = env["client"].post("/auth/select-tenant", headers=headers, json={"tenant_id": tokens["selected_tenant_id"]})
    assert answer.status_code == 200, answer.text


def test_cookie_requests_that_change_something_need_the_csrf_header(env):
    _, tenant_id = make_user(env, "ann@example.test")
    sign_in(env, "ann@example.test")
    client = env["client"]
    # Reading needs none.
    assert client.get("/auth/me").status_code == 200
    body = {"tenant_id": tenant_id}
    missing = client.post("/auth/select-tenant", json=body)
    assert missing.status_code == 403 and "CSRF" in missing.json()["detail"]
    wrong = client.post("/auth/select-tenant", json=body, headers={"X-CSRF-Token": "not-the-cookie"})
    assert wrong.status_code == 403
    # A CSRF cookie with no session is no session.
    assert client.post("/auth/select-tenant", json=body, headers={"X-CSRF-Token": ""}).status_code == 403
    right = client.post("/auth/select-tenant", json=body, headers=csrf(env))
    assert right.status_code == 200, right.text
    # Signed in by cookie: the new tokens come as cookies, never in the body, even without X-Hawk-Session.
    assert right.json()["access_token"] == "" and "__Host-hawk_access" in set_cookies(right)


def test_an_http_cookie_is_not_read_over_https(env):
    make_user(env, "ann@example.test")
    sign_in(env, "ann@example.test", "plain")
    planted = env["plain"].cookies.get("hawk_access")
    # A cookie without the __Host- prefix could have been planted over http or by a sibling host.
    env["client"].cookies.set("hawk_access", planted)
    assert env["client"].get("/auth/me").status_code == 401
    assert env["plain"].get("/auth/me").status_code == 200


def test_refresh_through_the_cookie_rotates_it_keeps_the_csrf_token_and_needs_the_header(env):
    user_id, _ = make_user(env, "ann@example.test")
    sign_in(env, "ann@example.test")
    client = env["client"]
    before = client.cookies.get("__Host-hawk_csrf")
    old_refresh = client.cookies.get("__Secure-hawk_refresh")
    assert client.post("/auth/refresh", json={}).status_code == 403
    response = client.post("/auth/refresh", json={}, headers=csrf(env))
    assert response.status_code == 200, response.text
    assert response.json()["access_token"] == "" and response.json()["refresh_token"] == ""
    cookies = set_cookies(response)
    assert {"__Host-hawk_access", "__Secure-hawk_refresh", "__Host-hawk_csrf"} <= set(cookies)
    assert client.cookies.get("__Host-hawk_csrf") == before
    assert client.cookies.get("__Secure-hawk_refresh") != old_refresh
    assert live_refresh_tokens(env, user_id) == 1
    # The old refresh token was revoked by the rotation.
    assert client.post("/auth/refresh", json={"refresh_token": old_refresh}).status_code == 401
    # No body at all works too.
    assert client.post("/auth/refresh", headers=csrf(env)).status_code == 200
    assert client.get("/auth/me").status_code == 200


def test_refresh_without_any_token_is_refused(env):
    assert env["client"].post("/auth/refresh", json={}).status_code == 401
    assert env["client"].post("/auth/refresh").status_code == 401


def test_sign_out_revokes_the_refresh_token_and_clears_the_cookies(env):
    user_id, _ = make_user(env, "ann@example.test")
    sign_in(env, "ann@example.test")
    client = env["client"]
    assert client.post("/auth/refresh/sign-out", json={}).status_code == 403
    out = client.post("/auth/refresh/sign-out", json={}, headers=csrf(env))
    assert out.status_code == 200 and out.json() == {"ok": True}
    cleared = set_cookies(out)
    for name in ("__Host-hawk_access", "__Secure-hawk_refresh", "__Host-hawk_csrf"):
        assert 'Max-Age=0' in cleared[name] or "expires=Thu, 01 Jan 1970" in cleared[name]
    assert "Path=/auth/refresh" in cleared["__Secure-hawk_refresh"]
    assert live_refresh_tokens(env, user_id) == 0
    assert client.get("/auth/me").status_code == 401
    with env["db"]() as db:
        from app.db.models.audit import AuditLog

        assert db.scalar(select(AuditLog).where(AuditLog.action == "auth.sign_out")) is not None
    # A bearer client may revoke its own refresh token the same way.
    tokens = env["plain"].post("/auth/login", json={"email": "ann@example.test", "password": PASSWORD}).json()
    assert env["plain"].post("/auth/refresh/sign-out", json={"refresh_token": tokens["refresh_token"]}).status_code == 200
    assert env["plain"].post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_password_change_reissues_the_cookies(env):
    user_id, _ = make_user(env, "ann@example.test")
    with env["db"]() as db:
        db.get(User, user_id).must_change_password = True
        db.commit()
    sign_in(env, "ann@example.test")
    client = env["client"]
    # The gate still stands: until the password is changed, the console gets 403 password_change_required.
    assert client.get("/auth/tenants").status_code == 403
    old_access = client.cookies.get("__Host-hawk_access")
    changed = client.post("/auth/me/password", json={"current": PASSWORD, "next": NEW_PASSWORD}, headers=csrf(env))
    assert changed.status_code == 200, changed.text
    assert changed.json()["access_token"] == "" and changed.json()["must_change_password"] is False
    assert client.cookies.get("__Host-hawk_access") != old_access
    assert client.get("/auth/tenants").status_code == 200


def test_register_and_two_step_sign_in_set_the_cookies(env, monkeypatch):
    monkeypatch.setattr(settings, "self_registration_enabled", True)
    registered = env["client"].post("/auth/register", json={"email": "new@example.com", "password": PASSWORD, "full_name": "New"}, headers=COOKIE)
    assert registered.status_code == 200, registered.text
    assert registered.json()["access_token"] == "" and "__Host-hawk_access" in set_cookies(registered)

    user_id, _ = make_user(env, "mfa@example.test")
    secret = mfa_service.new_secret()
    with env["db"]() as db:
        account_security.enable_two_step(db.get(User, user_id), secret, step=mfa_service.totp_step() - 10)
        db.commit()
    assert account_security.two_step_on(_user(env, user_id))
    first = env["client"].post("/auth/login", json={"email": "mfa@example.test", "password": PASSWORD}, headers=COOKIE)
    assert first.json()["two_step"] is True and set_cookies(first).get("__Host-hawk_access") is None
    done = env["client"].post("/auth/two-step", json={"ticket": first.json()["ticket"], "code": mfa_service.totp(secret)}, headers=COOKIE)
    assert done.status_code == 200, done.text
    assert done.json()["access_token"] == "" and "__Host-hawk_access" in set_cookies(done)


def _user(env, user_id: str) -> User:
    with env["db"]() as db:
        user = db.get(User, user_id)
        db.expunge(user)
        return user


def test_first_administrator_setup_sets_the_cookies(env, monkeypatch):
    from app.services import first_run_service

    admin = {}

    def use_setup_code(db, *, code, email, full_name, password):
        tenant = Tenant(name="Acme", slug="acme", is_active=True)
        db.add(tenant)
        db.flush()
        user = User(email=email, full_name=full_name, hashed_password=get_password_hash(password), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role="owner"))
        db.flush()
        admin["id"] = user.id
        return user

    monkeypatch.setattr(first_run_service, "use_setup_code", use_setup_code)
    response = env["client"].post("/setup", json={"code": "x", "email": "admin@example.test", "name": "Admin", "password": PASSWORD}, headers=COOKIE)
    assert response.status_code == 201, response.text
    assert response.json()["access_token"] == "" and response.json()["selected_tenant_id"]
    assert {"__Host-hawk_access", "__Secure-hawk_refresh", "__Host-hawk_csrf"} <= set(set_cookies(response))
    assert response.headers["cache-control"] == "no-store"
    assert env["client"].get("/auth/me").json()["id"] == admin["id"]


def test_terms_read_who_is_asking_from_the_cookie_too(env):
    make_user(env, "ann@example.test")
    assert "you" not in env["client"].get("/terms").json()
    sign_in(env, "ann@example.test")
    assert "you" in env["client"].get("/terms").json()


def test_sign_out_without_a_session_still_clears_and_answers(env):
    out = env["client"].post("/auth/refresh/sign-out", json={})
    assert out.status_code == 200
    assert "__Host-hawk_access" in set_cookies(out)


def test_single_sign_on_always_ends_in_cookies_never_in_the_body(env, monkeypatch):
    from app.services import auth_service, oidc_auth_service

    user_id, tenant_id = make_user(env, "sso@example.test")

    def complete(*, ticket, browser, db):
        user = db.get(User, user_id)
        tokens = auth_service.issue_tokens(db, user=user, tenant_id=tenant_id, role="owner")
        return {**tokens, "user": {"id": user.id, "email": user.email, "full_name": user.full_name}, "tenants": [{"id": tenant_id, "name": "Acme", "role": "owner"}], "selected_tenant_id": tenant_id}

    monkeypatch.setattr(oidc_auth_service, "complete", complete)
    env["client"].cookies.set(oidc_auth_service.TICKET_COOKIE, "browser-binding")
    # Even without X-Hawk-Session: the ticket only ever comes back to the console.
    response = env["client"].post("/auth/oidc/complete", json={"ticket": "t"})
    assert response.status_code == 200, response.text
    assert response.json()["access_token"] == "" and response.json()["refresh_token"] == ""
    assert {"__Host-hawk_access", "__Secure-hawk_refresh", "__Host-hawk_csrf"} <= set(set_cookies(response))
    assert env["client"].get("/auth/me").json()["id"] == user_id
