from __future__ import annotations

import json
import time
from types import SimpleNamespace
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import pytest
import jwt

from app.core.config import settings
from app.services import oidc_auth_service as oidc
from app.services.connector_secret_service import encrypt_connector_secrets


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.expiry = {}

    def setex(self, key, ttl, value):
        self.values[key] = value
        self.expiry[key] = time.time() + ttl

    def getdel(self, key):
        if key not in self.values or self.expiry[key] <= time.time():
            self.values.pop(key, None)
            return None
        return self.values.pop(key)


class FakeResponse:
    status_code = 200
    content = b"{}"

    def __init__(self, payload):
        self.payload = payload
        self.content = json.dumps(payload).encode()

    def json(self):
        return self.payload


def configure(monkeypatch):
    providers = [
        {"key": "entra", "kind": "entra", "display_name": "Microsoft", "workspace_slug": "acme", "issuer": "https://login.microsoftonline.com/tenant/v2.0", "client_id": "entra-client", "tenant_id": "t1"},
        {"key": "okta", "kind": "okta", "display_name": "Okta", "workspace_slug": "acme", "issuer": "https://acme.okta.com/oauth2/default", "client_id": "okta-client", "tenant_id": "t1"},
    ]
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    monkeypatch.setattr(settings, "oidc_providers_json", json.dumps(providers))
    monkeypatch.setattr(settings, "oidc_callback_url", "https://api.example.test/auth/oidc/callback")
    monkeypatch.setattr(settings, "oidc_frontend_url", "https://app.example.test/login/oidc/callback")
    monkeypatch.setattr(settings, "oidc_bindings_json", json.dumps([{"provider_key": "entra", "issuer": providers[0]["issuer"], "subject": "subject-1", "user_id": "u1", "tenant_id": "t1"}]))
    monkeypatch.setattr(settings, "oidc_provider_secrets_json", encrypt_connector_secrets({"entra": {"client_secret": "secret"}, "okta": {"client_secret": "secret"}}))
    oidc._CACHE.clear()


def test_authorization_url_uses_s256_and_exact_provider(monkeypatch):
    configure(monkeypatch)
    provider = oidc.provider_for("entra", workspace_slug="acme")
    url = oidc.build_authorization_url(provider, state="state", nonce="nonce", verifier="verifier", metadata={"authorization_endpoint": "https://login.example.test/authorize"})
    assert "code_challenge_method=S256" in url
    assert "client_id=entra-client" in url
    assert "redirect_uri=https%3A%2F%2Fapi.example.test%2Fauth%2Foidc%2Fcallback" in url


@pytest.mark.parametrize("provider_key", ["entra", "okta"])
def test_signed_rs256_assertion_requires_mfa_and_rejects_wrong_claims(monkeypatch, provider_key):
    configure(monkeypatch)
    provider = oidc.provider_for(provider_key, workspace_slug="acme")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_numbers()
    enc = lambda value: base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    monkeypatch.setattr(oidc, "provider_metadata", lambda p: {"issuer": p.issuer, "jwks_uri": p.issuer + "/keys"})
    monkeypatch.setattr(oidc, "_jwks", lambda p, metadata, force=False: {"keys": [{"kid": "kid-1", "kty": "RSA", "n": enc(public.n), "e": enc(public.e)}]})
    def signed(**overrides):
        payload = {"sub": "subject-1", "nonce": "n", "amr": ["pwd", "mfa"], "iat": int(time.time()), "exp": int(time.time()) + 60, "iss": provider.issuer, "aud": provider.client_id}
        payload.update(overrides)
        return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": "kid-1"})
    claims = oidc._decode_id_token(signed(), provider, nonce="n")
    assert claims["sub"] == "subject-1"
    with pytest.raises(oidc.OIDCError):
        oidc._decode_id_token(signed(amr=["pwd"]), provider, nonce="n")
    # A minute of clock difference is allowed (CxMissionZero), so an expired token is one more than a minute old.
    for overrides in ({"iss": "https://wrong.example"}, {"aud": "wrong"}, {"exp": int(time.time()) - 61}, {"iat": int(time.time()) + 3600}, {"nonce": "wrong"}, {"sub": ""}):
        with pytest.raises(oidc.OIDCError):
            oidc._decode_id_token(signed(**overrides), provider, nonce="n")
    bad_alg = jwt.encode({"sub": "subject-1", "nonce": "n", "amr": ["mfa"], "exp": int(time.time()) + 60, "iss": provider.issuer, "aud": provider.client_id}, "secret", algorithm="HS256", headers={"kid": "kid-1"})
    with pytest.raises(oidc.OIDCError):
        oidc._decode_id_token(bad_alg, provider, nonce="n")


def test_state_is_browser_bound_single_use_and_provider_failures_are_generic(monkeypatch):
    configure(monkeypatch)
    redis = FakeRedis()
    monkeypatch.setattr(oidc, "provider_metadata", lambda provider: {"issuer": provider.issuer, "authorization_endpoint": provider.issuer + "/authorize", "token_endpoint": provider.issuer + "/token", "jwks_uri": provider.issuer + "/keys"})
    url, browser = oidc.start(provider_key="entra", workspace_slug="acme", redis=redis)
    assert "code_challenge=" in url
    state = next(key.split(":")[-1] for key in redis.values if key.startswith("oidc:state:"))
    with pytest.raises(oidc.OIDCError, match="state invalid"):
        oidc.callback(code="c", state=state, browser="wrong", redis=redis)
    # The failed browser attempt does not reveal provider details; the state is
    # consumed before any exchange and therefore cannot be replayed.
    with pytest.raises(oidc.OIDCError):
        oidc.callback(code="c", state=state, browser=browser, redis=redis)


def test_provider_discovery_is_workspace_scoped_and_never_exposes_secret(monkeypatch):
    configure(monkeypatch)
    rows = oidc.public_provider_rows(workspace_slug="acme")
    assert {row["key"] for row in rows} == {"entra", "okta"}
    assert all("client_secret" not in row for row in rows)
    assert oidc.public_provider_rows(workspace_slug="other") == []


def test_completion_consumes_ticket_once_and_returns_existing_login_shape(monkeypatch):
    configure(monkeypatch)
    redis = FakeRedis()
    redis.setex("oidc:ticket:t", 60, oidc._fernet_payload({"user_id": "u1", "tenant_id": "t1", "workspace": "acme", "browser": oidc._browser_hash("browser")}))
    user = SimpleNamespace(id="u1", email="bound@example.test", full_name="Bound User", is_active=True)
    membership = SimpleNamespace(user_id="u1", tenant_id="t1", role="viewer")
    tenant = SimpleNamespace(id="t1", slug="acme", name="Acme", is_active=True)
    class DB:
        def scalar(self, stmt):
            text = str(stmt)
            if "users" in text: return user
            if "user_tenant_roles" in text: return membership
            return tenant
        def scalars(self, stmt): return SimpleNamespace(all=lambda: [membership])
        def get(self, model, value): return tenant
    monkeypatch.setattr(oidc, "issue_tokens", lambda db, **kwargs: {"access_token": "a", "refresh_token": "r", "token_type": "bearer", "expires_in": 30})
    result = oidc.complete(ticket="t", browser="browser", db=DB(), redis=redis)
    assert result["user"]["email"] == "bound@example.test"
    assert result["tenants"] == [{"id": "t1", "name": "Acme", "role": "viewer"}]
    with pytest.raises(oidc.OIDCError):
        oidc.complete(ticket="t", browser="browser", db=DB(), redis=redis)


def test_metadata_requires_exact_issuer_origin_for_all_endpoints(monkeypatch):
    configure(monkeypatch)
    provider = oidc.provider_for("entra", workspace_slug="acme")
    monkeypatch.setattr(oidc, "_request", lambda *args, **kwargs: FakeResponse({"issuer": provider.issuer, "authorization_endpoint": "https://evil.example/authorize", "token_endpoint": provider.issuer + "/token", "jwks_uri": provider.issuer + "/keys"}))
    with pytest.raises(oidc.OIDCError):
        oidc.provider_metadata(provider)


def _two_workspaces(monkeypatch, *, domains=True):
    providers = [
        {"key": "acme-entra", "kind": "entra", "display_name": "Acme Microsoft", "workspace_slug": "acme", "issuer": "https://login.microsoftonline.com/acme/v2.0", "client_id": "a", "tenant_id": "t1"},
        {"key": "globex-okta", "kind": "okta", "display_name": "Globex Okta", "workspace_slug": "globex", "issuer": "https://globex.okta.com/oauth2/default", "client_id": "g", "tenant_id": "t2"},
    ]
    if domains:
        providers[0]["domains"] = ["acme.test", "@acme-group.test"]
        providers[1]["domains"] = "globex.test"
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    monkeypatch.setattr(settings, "oidc_providers_json", json.dumps(providers))
    oidc._CACHE.clear()


def test_sign_in_page_lists_providers_without_a_workspace_when_there_is_one(monkeypatch):
    configure(monkeypatch)
    answer = oidc.sign_in_providers()
    assert answer["byEmail"] is False
    assert {row["key"] for row in answer["providers"]} == {"entra", "okta"}
    # With one workspace, any address finds them (no domains need listing).
    assert {row["key"] for row in oidc.discover_providers("someone@anything.test")} == {"entra", "okta"}
    monkeypatch.setattr(settings, "company_sso_enabled", False)
    assert oidc.sign_in_providers() == {"providers": [], "byEmail": False}
    assert oidc.discover_providers("someone@acme.test") == []


def test_several_workspaces_ask_for_the_email_and_find_providers_by_its_domain_only(monkeypatch):
    _two_workspaces(monkeypatch)
    assert oidc.sign_in_providers() == {"providers": [], "byEmail": True}
    assert [row["key"] for row in oidc.discover_providers("ana@acme.test")] == ["acme-entra"]
    assert [row["key"] for row in oidc.discover_providers("Bo@ACME-GROUP.test ")] == ["acme-entra"]
    assert [row["key"] for row in oidc.discover_providers("cy@globex.test")] == ["globex-okta"]
    # Unknown domain, or not an address: nothing, and never a hint about who has an account.
    for email in ("someone@gmail.com", "not-an-address", "a@b", ""):
        assert oidc.discover_providers(email) == []
    # No domains listed and several workspaces: nothing can be worked out from the address.
    _two_workspaces(monkeypatch, domains=False)
    assert oidc.discover_providers("ana@acme.test") == []


def test_start_without_a_workspace_uses_the_providers_own(monkeypatch):
    _two_workspaces(monkeypatch)
    redis = FakeRedis()
    monkeypatch.setattr(oidc, "provider_metadata", lambda provider: {"issuer": provider.issuer, "authorization_endpoint": provider.issuer + "/authorize", "token_endpoint": provider.issuer + "/token", "jwks_uri": provider.issuer + "/keys"})
    url, _browser = oidc.start(provider_key="globex-okta", redis=redis)
    assert url.startswith("https://globex.okta.com/oauth2/default/authorize?")
    state = next(iter(redis.values.values()))
    from app.services.connector_secret_service import decrypt_connector_secrets
    assert decrypt_connector_secrets(state)["workspace"] == "globex"
    # A workspace given must still match the provider's.
    with pytest.raises(oidc.OIDCError):
        oidc.start(provider_key="globex-okta", workspace_slug="acme", redis=redis)


def test_discovery_endpoint_answers_the_same_for_any_address_at_a_domain(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app

    _two_workspaces(monkeypatch)
    client = TestClient(app)
    known = client.post("/auth/oidc/discover", json={"email": "admin@acme.test"})
    unknown = client.post("/auth/oidc/discover", json={"email": "nobody-at-all-1234@acme.test"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {"providers": [{"key": "acme-entra", "display_name": "Acme Microsoft", "kind": "entra"}]}
    assert client.get("/auth/oidc/providers").json() == {"providers": [], "byEmail": True}
    assert client.get("/auth/oidc/providers", params={"workspace": "globex"}).json() == {"providers": [{"key": "globex-okta", "display_name": "Globex Okta", "kind": "okta"}], "byEmail": False}
