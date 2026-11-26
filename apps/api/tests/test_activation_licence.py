"""Activation codes and the product licence (/settings/guide/licence), ported from CxMissionZero's checks.

These tests run the real dates, caps and licence gate (the ``real_licence`` marker keeps conftest from patching
them out), with the clock injected through activation_service.now_ms.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.routers import licence as licence_routes
from app.db.models.activation import ActivationState
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import activation_service
from app.services.activation_service import ActivationStore, check_code


pytestmark = pytest.mark.real_licence

PASSWORD = "Password123!"
DEACTIVATED = "The product has been deactivated. Please reach out to Bhawani Singh."


def ms(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp() * 1000


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_key_of(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()


def make_code(private_key: Ed25519PrivateKey, prefix: str = "HK1", **payload) -> str:
    full = {"v": 1, "id": "a1b2c3d4e5f6", "issued": "2026-11-01T00:00:00.000Z", "expires": "2027-11-01T00:00:00.000Z", **payload}
    head = f"{prefix}.{b64url(json.dumps(full).encode())}"
    return f"{head}.{b64url(private_key.sign(head.encode()))}"


def product_code(key, *, expires: str, issued: str = "2026-11-01T00:00:00.000Z", code_id: str = "prod00000001", org: str = "Everyone") -> str:
    return make_code(key, id=code_id, org=org, scope="product", action="activate", issued=issued, expires=expires)


def tenants_code(key, *, max_tenants: int, max_users: int | None = None, expires: str = "2027-11-01T00:00:00.000Z", issued: str = "2026-11-01T00:00:00.000Z") -> str:
    extra = {} if max_users is None else {"maxUsers": max_users}
    return make_code(key, id="tenants00001", org="Acme Corp", scope="tenants", maxTenants=max_tenants, issued=issued, expires=expires, **extra)


@pytest.fixture()
def key(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("HAWK_ACTIVATION_TEST_KEY", public_key_of(private_key))
    return private_key


@pytest.fixture()
def clock(monkeypatch):
    """The wall clock the licence sees: set with clock.set('2027-01-15T00:00:00')."""

    class Clock:
        value = ms("2026-11-25T12:00:00")

        def set(self, text: str) -> None:
            self.value = ms(text)

    current = Clock()
    monkeypatch.setattr(activation_service, "now_ms", lambda: int(current.value))
    return current


@pytest.fixture()
def env(tmp_path, monkeypatch, key, clock):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'activation.sqlite3'}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(activation_service, "licence_session_factory", session_factory)
    licence_routes.licence_tries.clear()
    licence_routes.licence_refusals.reset()
    client = TestClient(app)
    try:
        yield {"client": client, "db": session_factory, "key": key, "clock": clock}
    finally:
        client.close()
        app.dependency_overrides.clear()
        licence_routes.licence_tries.clear()
        licence_routes.licence_refusals.reset()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def register(client: TestClient, email: str) -> dict:
    return client.post("/auth/register", json={"email": email, "password": PASSWORD, "full_name": "Licence Owner"})


def owner_headers(client: TestClient, email: str = "owner@example.com") -> dict[str, str]:
    response = register(client, email)
    assert response.status_code == 200, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["tenants"][0]["id"]}


def audit_rows(env, action: str) -> list[AuditLog]:
    with env["db"]() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action)).all())


# ---- Codes ------------------------------------------------------------------------------------------------------


def test_a_valid_code_reads_as_signed(key):
    code = tenants_code(key, max_tenants=3, max_users=25)
    result = check_code(code, now=ms("2026-12-01T00:00:00"))
    assert result["valid"] is True
    assert result["scope"] == "tenants"
    assert result["org"] == "Acme Corp"
    assert result["maxTenants"] == 3
    assert result["maxUsers"] == 25
    assert result["expires"] == "2027-11-01T00:00:00.000Z"
    assert result["code"] == code
    assert result["warn"] is False
    # Thirty days before its end, admins are warned.
    assert check_code(code, now=ms("2027-10-05T00:00:00"))["warn"] is True


def test_the_users_cap_is_optional_and_the_tenant_count_starts_at_one(key):
    assert check_code(tenants_code(key, max_tenants=1), now=0)["maxUsers"] is None
    assert check_code(tenants_code(key, max_tenants=1), now=0)["valid"] is True
    assert check_code(tenants_code(key, max_tenants=0), now=0)["reason"] == "This activation code is not valid."
    assert check_code(tenants_code(key, max_tenants=2, max_users=0), now=0)["reason"] == "This activation code is not valid."
    assert check_code(make_code(key, org="Acme", scope="tenants", maxTenants=2, maxUsers="5"), now=0)["valid"] is False


def test_a_code_with_another_prefix_is_not_an_activation_code(key):
    # A CxMissionZero code, even signed with the same key, never works here: the prefix is part of what is signed.
    mz = make_code(key, prefix="MZ1", org="Everyone", scope="product", action="activate")
    assert check_code(mz, now=0) == {"valid": False, "reason": "This is not an activation code."}
    hawk = make_code(key, org="Everyone", scope="product", action="activate")
    relabelled = "MZ1" + hawk[3:]
    assert check_code(relabelled, now=0)["reason"] == "This is not an activation code."
    assert check_code("HK1.only-two", now=0)["reason"] == "This is not an activation code."
    assert check_code("", now=0)["reason"] == "This is not an activation code."


def test_a_code_signed_by_another_key_is_not_valid(key):
    other = Ed25519PrivateKey.generate()
    code = product_code(other, expires="2027-12-31T00:00:00.000Z")
    assert check_code(code, now=0) == {"valid": False, "reason": "This activation code is not valid."}


def test_a_tampered_payload_is_not_valid(key):
    code = tenants_code(key, max_tenants=2)
    prefix, payload, signature = code.split(".")
    changed = json.loads(base64.urlsafe_b64decode(payload + "=="))
    changed["maxTenants"] = 50
    tampered = f"{prefix}.{b64url(json.dumps(changed).encode())}.{signature}"
    assert check_code(tampered, now=0)["reason"] == "This activation code is not valid."


def test_an_expired_code_says_when_it_expired(key):
    result = check_code(product_code(key, expires="2027-03-01T00:00:00.000Z"), now=ms("2027-03-02T00:00:00"))
    assert result["valid"] is False
    assert result["expired"] is True
    assert result["reason"] == "This activation code expired on 2027-03-01."


def test_no_key_means_no_code_is_valid(key):
    assert check_code(product_code(key, expires="2027-12-31T00:00:00.000Z"), now=0, keys=[])["reason"] == (
        "This installation has no activation key to check codes with."
    )


def test_the_test_key_is_trusted_only_under_pytest_and_never_in_production(key, monkeypatch):
    code = product_code(key, expires="2027-12-31T00:00:00.000Z")
    assert check_code(code, now=0)["valid"] is True
    monkeypatch.setattr(activation_service.settings, "env", "production")
    assert check_code(code, now=0)["valid"] is False
    monkeypatch.setattr(activation_service.settings, "env", "test")
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    assert check_code(code, now=0)["valid"] is False


def test_the_owners_issuer_key_is_built_in():
    assert activation_service.ISSUER_KEYS == ["MCowBQYDK2VwAyEAlWEwF9lhzKv0IZ1GaDJSmlJqaZd7Gc1JqvYju52uKo4="]
    assert activation_service.PRODUCT_DEADLINE == "2027-02-01T00:00:00.000Z"
    assert activation_service.DEACTIVATED_MESSAGE == DEACTIVATED
    assert activation_service.WARN_DAYS == 30


# ---- The product licence ----------------------------------------------------------------------------------------


def test_without_a_code_hawk_works_until_the_end_of_31_january_2027(key):
    store = ActivationStore()
    before = store.product(ms("2026-12-01T00:00:00"))
    assert before == {
        "active": True,
        "until": "2027-02-01T00:00:00.000Z",
        "daysLeft": 62,
        "warn": False,
        "activation": None,
        "message": "",
    }
    # The admins' banner starts 30 days before: on 2 January 2027.
    assert ActivationStore().product(ms("2027-01-01T23:59:00"))["warn"] is False
    on_the_second = ActivationStore().product(ms("2027-01-02T00:00:00"))
    assert on_the_second["warn"] is True and on_the_second["daysLeft"] == 30
    assert ActivationStore().product(ms("2027-01-31T23:59:59"))["active"] is True
    after = ActivationStore().product(ms("2027-02-01T00:00:00"))
    assert after["active"] is False
    assert after["warn"] is False
    assert after["message"] == DEACTIVATED


def test_a_product_code_extends_the_deadline(key):
    store = ActivationStore()
    result = check_code(product_code(key, expires="2027-07-01T00:00:00.000Z"), now=ms("2026-12-01T00:00:00"))
    store.record(result, "admin@example.com")
    product = store.product(ms("2027-03-01T00:00:00"))
    assert product["active"] is True
    assert product["until"] == "2027-07-01T00:00:00.000Z"
    assert product["activation"]["org"] == "Everyone"
    assert store.product(ms("2027-07-01T00:00:00"))["active"] is False
    # A product code that ends before the built-in date does not shorten it.
    early = ActivationStore()
    early.record(check_code(product_code(key, expires="2026-12-15T00:00:00.000Z"), now=ms("2026-12-01T00:00:00")))
    assert early.product(ms("2027-01-15T00:00:00"))["until"] == "2027-02-01T00:00:00.000Z"


def test_an_older_code_does_not_undo_a_newer_one(key):
    store = ActivationStore()
    newer = check_code(product_code(key, issued="2026-11-20T00:00:00.000Z", expires="2027-06-01T00:00:00.000Z", code_id="newer0000001"), now=0)
    store.record(newer)
    older = check_code(product_code(key, issued="2026-11-01T00:00:00.000Z", expires="2028-01-01T00:00:00.000Z", code_id="older0000001"), now=0)
    assert store.refusal(older) == "This activation code was issued before the one in force (issued 2026-11-20): ask for a new one."
    # Signed in, an admin may still enter a newer code that ends sooner; the open page only takes one that runs longer.
    sooner = check_code(product_code(key, issued="2026-11-25T00:00:00.000Z", expires="2027-04-01T00:00:00.000Z", code_id="sooner000001"), now=0)
    assert store.refusal(sooner) == ""
    assert store.refusal(sooner, must_extend=True) == (
        "An activation code that runs until 2027-06-01 is already in force: this one does not run longer."
    )


def test_history_keeps_the_last_50(key):
    store = ActivationStore()
    result = check_code(product_code(key, expires="2027-07-01T00:00:00.000Z"), now=0)
    for _ in range(55):
        store.record(result, "admin@example.com")
    assert len(store.history()) == 50
    assert "code" not in store.history()[0]


def test_a_date_changed_by_hand_counts_for_nothing(env):
    key = env["key"]
    with env["db"]() as db:
        store = activation_service.load_store(db)
        store.record(check_code(product_code(key, expires="2027-04-01T00:00:00.000Z"), now=0), "admin@example.com")
        db.commit()
    with env["db"]() as db:
        row = db.get(ActivationState, 1)
        state = json.loads(json.dumps(row.state))
        assert state["product"]["code"]
        state["product"]["expires"] = "2099-01-01T00:00:00.000Z"
        row.state = state
        db.commit()
    with env["db"]() as db:
        assert activation_service.load_store(db).product(ms("2027-03-01T00:00:00"))["until"] == "2027-04-01T00:00:00.000Z"
    # An entry whose code was edited, or that has no code at all, counts for nothing: the built-in date applies.
    with env["db"]() as db:
        row = db.get(ActivationState, 1)
        state = json.loads(json.dumps(row.state))
        prefix, payload, signature = state["product"]["code"].split(".")
        edited = json.loads(base64.urlsafe_b64decode(payload + "=="))
        edited["expires"] = "2099-01-01T00:00:00.000Z"
        state["product"]["code"] = f"{prefix}.{b64url(json.dumps(edited).encode())}.{signature}"
        state["tenants"] = {"org": "Acme", "scope": "tenants", "maxTenants": 99, "expires": "2099-01-01T00:00:00.000Z"}
        row.state = state
        db.commit()
    with env["db"]() as db:
        store = activation_service.load_store(db)
        assert store.product(ms("2027-01-01T00:00:00"))["until"] == "2027-02-01T00:00:00.000Z"
        assert store.product(ms("2027-01-01T00:00:00"))["activation"] is None
        assert store.tenants() is None


def test_setting_the_clock_back_does_not_reactivate(env):
    env["clock"].set("2027-02-05T00:00:00")
    assert activation_service.licence_active() is False
    with env["db"]() as db:
        assert db.get(ActivationState, 1).state["seenAt"] == "2027-02-05T00:00:00.000Z"
    env["clock"].set("2027-01-10T00:00:00")
    assert activation_service.licence_active() is False
    assert env["client"].get("/licence").json()["active"] is False
    # A code whose date has already passed on the licence's clock is refused on the open page.
    code = product_code(env["key"], expires="2027-02-03T00:00:00.000Z")
    response = env["client"].post("/licence/activate", json={"code": code})
    assert response.status_code == 400
    assert response.json() == {"error": "This activation code ended on 2027-02-03."}


def test_the_clock_is_kept_at_most_hourly(env):
    env["clock"].set("2026-12-01T10:00:00")
    activation_service.licence_active()
    env["clock"].set("2026-12-01T10:30:00")
    activation_service.licence_active()
    with env["db"]() as db:
        assert db.get(ActivationState, 1).state["seenAt"] == "2026-12-01T10:00:00.000Z"
    env["clock"].set("2026-12-01T11:00:01")
    activation_service.licence_active()
    with env["db"]() as db:
        assert db.get(ActivationState, 1).state["seenAt"] == "2026-12-01T11:00:01.000Z"


# ---- The licence gate -------------------------------------------------------------------------------------------


def test_once_deactivated_every_request_is_refused_but_health_and_the_licence_stay_open(env):
    client = env["client"]
    headers = owner_headers(client)
    assert client.get("/auth/me", headers=headers).status_code == 200
    env["clock"].set("2027-02-01T00:00:01")
    for path in ("/auth/me", "/activation", "/system/platform-mode", "/no-such-route"):
        response = client.get(path, headers=headers)
        assert response.status_code == 503, path
        assert response.json() == {"error": DEACTIVATED, "deactivated": True}
        assert response.headers["cache-control"] == "no-store"
    assert client.post("/auth/login", json={"email": "owner@example.com", "password": PASSWORD}).status_code == 503
    assert client.get("/health/live").status_code == 200
    licence = client.get("/licence")
    assert licence.status_code == 200
    assert licence.headers["cache-control"] == "no-store"
    assert licence.json() == {"active": False, "until": "2027-02-01T00:00:00.000Z", "message": DEACTIVATED}
    # Nothing is deleted: once a code is entered, everything works again as it was.
    code = product_code(env["key"], expires="2027-08-01T00:00:00.000Z")
    activated = client.post("/licence/activate", json={"code": code})
    assert activated.status_code == 200, activated.text
    assert activated.json() == {"active": True, "until": "2027-08-01T00:00:00.000Z"}
    assert client.get("/auth/me", headers=headers).status_code == 200


def test_the_open_route_takes_only_product_codes_that_run_longer(env):
    client = env["client"]
    key = env["key"]
    env["clock"].set("2027-02-02T00:00:00")
    wrong_scope = client.post("/licence/activate", json={"code": tenants_code(key, max_tenants=3)})
    assert wrong_scope.status_code == 400
    assert wrong_scope.json() == {"error": "This is not a Hawk AI activation code."}
    assert client.post("/licence/activate", json={"code": "nonsense"}).json() == {"error": "This is not an activation code."}
    first = product_code(key, expires="2027-06-30T00:00:00.000Z", issued="2026-11-01T00:00:00.000Z", code_id="first0000001")
    assert client.post("/licence/activate", json={"code": first}).status_code == 200
    shorter = product_code(key, expires="2027-05-31T00:00:00.000Z", issued="2026-12-01T00:00:00.000Z", code_id="short0000001")
    refused = client.post("/licence/activate", json={"code": shorter})
    assert refused.status_code == 400
    assert refused.json() == {"error": "An activation code that runs until 2027-06-30 is already in force: this one does not run longer."}
    longer = product_code(key, expires="2027-12-31T00:00:00.000Z", issued="2026-12-01T00:00:00.000Z", code_id="long00000001")
    assert client.post("/licence/activate", json={"code": longer}).json() == {"active": True, "until": "2027-12-31T00:00:00.000Z"}
    # A code longer than 4000 characters is cut, so it is not a code.
    assert client.post("/licence/activate", json={"code": longer + "x" * 5000}).json() == {"error": "This activation code is not valid."}


def test_the_open_route_allows_ten_tries_a_minute_from_one_address(env):
    client = env["client"]
    for _ in range(10):
        assert client.post("/licence/activate", json={"code": "HK1.x.y"}).status_code == 400
    too_many = client.post("/licence/activate", json={"code": "HK1.x.y"})
    assert too_many.status_code == 429
    assert too_many.json() == {"error": "Too many tries. Wait a minute, then enter the code again."}
    env["clock"].value += 61_000
    assert client.post("/licence/activate", json={"code": "HK1.x.y"}).status_code == 400


def test_codes_entered_on_the_open_page_are_audited(env):
    client = env["client"]
    client.post("/licence/activate", json={"code": "nonsense"})
    client.post("/licence/activate", json={"code": product_code(env["key"], expires="2027-09-01T00:00:00.000Z")})
    refused = audit_rows(env, "licence.activation_code.refused")
    assert len(refused) == 1
    assert refused[0].tenant_id is None
    assert refused[0].actor_type == "system"
    assert refused[0].payload["outcome"] == "refused"
    assert refused[0].payload["reason"] == "Product activation code refused: This is not an activation code."
    assert refused[0].payload["actor_id"] == "deactivation page (testclient)"
    applied = audit_rows(env, "licence.activation_code.applied")
    assert len(applied) == 1
    assert applied[0].payload["reason"] == "Product activation code applied: Hawk AI works until 2027-09-01 (Everyone)."
    assert applied[0].payload["actor_id"] == "deactivation page (testclient)"
    assert applied[0].payload["activation"]["scope"] == "product"
    with env["db"]() as db:
        assert db.get(ActivationState, 1).state["history"][0]["by"] == "deactivation page (testclient)"


# ---- Settings → Activation codes --------------------------------------------------------------------------------


def test_admins_view_and_apply_codes_and_each_is_audited(env):
    client = env["client"]
    key = env["key"]
    headers = owner_headers(client)
    view = client.get("/activation", headers=headers)
    assert view.status_code == 200
    assert view.headers["cache-control"] == "no-store"
    body = view.json()
    assert body["canManage"] is True and body["keyConfigured"] is True
    assert body["tenants"] is None and body["history"] == []
    assert body["product"]["until"] == "2027-02-01T00:00:00.000Z"

    applied = client.post("/activation", headers=headers, json={"code": tenants_code(key, max_tenants=3, max_users=10)})
    assert applied.status_code == 200, applied.text
    assert applied.json()["applied"] == "several tenants unlocked for Acme Corp: up to 3, with up to 10 active users in each, until 2027-11-01"
    assert applied.json()["tenants"]["maxTenants"] == 3
    assert applied.json()["history"][0]["by"] == "owner@example.com"

    product = client.post("/activation", headers=headers, json={"code": product_code(key, expires="2027-12-31T00:00:00.000Z", issued="2026-11-10T00:00:00.000Z")})
    assert product.json()["applied"] == "Hawk AI activated for Everyone until 2027-12-31"
    assert product.json()["product"]["until"] == "2027-12-31T00:00:00.000Z"

    older = client.post("/activation", headers=headers, json={"code": product_code(key, expires="2028-12-31T00:00:00.000Z", issued="2026-11-01T00:00:00.000Z")})
    assert older.status_code == 400
    assert older.json() == {"error": "This activation code was issued before the one in force (issued 2026-11-10): ask for a new one."}
    expired = client.post("/activation", headers=headers, json={"code": product_code(key, expires="2026-11-01T00:00:00.000Z")})
    assert expired.json() == {"error": "This activation code expired on 2026-11-01."}

    applied_rows = audit_rows(env, "activation.code.applied")
    assert [row.payload["reason"] for row in applied_rows] == [
        "Activation code applied: several tenants unlocked for Acme Corp: up to 3, with up to 10 active users in each, until 2027-11-01.",
        "Activation code applied: Hawk AI activated for Everyone until 2027-12-31.",
    ]
    assert all(row.actor_type == "human" and row.actor_user_id and row.tenant_id == headers["X-Tenant-ID"] for row in applied_rows)
    refused_rows = audit_rows(env, "activation.code.refused")
    assert sorted(row.payload["reason"] for row in refused_rows) == [
        "Activation code refused: This activation code expired on 2026-11-01.",
        "Activation code refused: This activation code was issued before the one in force (issued 2026-11-10): ask for a new one.",
    ]


def test_only_owners_and_admins_manage_codes(env):
    client = env["client"]
    headers = owner_headers(client)
    with env["db"]() as db:
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.tenant_id == headers["X-Tenant-ID"]))
        membership.role = "auditor"
        db.commit()
    assert client.get("/activation", headers=headers).status_code == 403
    assert client.post("/activation", headers=headers, json={"code": "x"}).status_code == 403
    assert client.get("/auth/me", headers=headers).json()["licence"] is None


def test_admins_see_the_licence_end_with_the_current_user(env):
    client = env["client"]
    headers = owner_headers(client)
    env["clock"].set("2027-01-10T00:00:00")
    licence = client.get("/auth/me", headers=headers).json()["licence"]
    assert licence == {"until": "2027-02-01T00:00:00.000Z", "daysLeft": 22, "warn": True, "activation": None}


# ---- Several tenants, and their users ----------------------------------------------------------------------------


def test_one_tenant_without_a_code_and_as_many_as_the_code_allows(env):
    client = env["client"]
    headers = owner_headers(client, "first@example.com")
    second = register(client, "second@example.com")
    assert second.status_code == 403
    assert second.json()["detail"] == (
        "Without a tenants activation code Hawk AI serves 1 tenant, and it is in use. Apply a tenants activation code under Settings → Activation codes."
    )
    with env["db"]() as db:
        assert db.scalar(select(User).where(User.email == "second@example.com")) is None
    assert client.post("/activation", headers=headers, json={"code": tenants_code(env["key"], max_tenants=2)}).status_code == 200
    assert register(client, "second@example.com").status_code == 200
    third = register(client, "third@example.com")
    assert third.status_code == 403
    assert third.json()["detail"] == (
        "The activation code allows up to 2 tenants, and all are in use. Apply a new tenants activation code under Settings → Activation codes."
    )
    # Once the code has expired, the installation is back to one tenant; nothing already there is removed.
    env["clock"].set("2027-11-02T00:00:00")
    with env["db"]() as db:
        assert activation_service.tenant_limits(db) == (1, None)
        assert len(db.scalars(select(Tenant).where(Tenant.is_active.is_(True))).all()) == 2


def test_a_tenant_takes_no_more_active_users_than_the_code_allows(env):
    client = env["client"]
    headers = owner_headers(client)
    tenant_id = headers["X-Tenant-ID"]
    with env["db"]() as db:
        # No code: no cap on users.
        activation_service.assert_may_add_member(db, tenant_id)
    client.post("/activation", headers=headers, json={"code": tenants_code(env["key"], max_tenants=2, max_users=2)})
    with env["db"]() as db:
        activation_service.assert_may_add_member(db, tenant_id)
        other = User(email="member@example.com", hashed_password="x", full_name="Member", is_active=True)
        db.add(other)
        db.flush()
        db.add(UserTenantRole(user_id=other.id, tenant_id=tenant_id, role="viewer"))
        db.commit()
        with pytest.raises(HTTPException) as refused:
            activation_service.assert_may_add_member(db, tenant_id)
        assert refused.value.status_code == 403
        assert refused.value.detail == (
            "The activation code allows up to 2 active users in each tenant, and all are in use in this one. "
            "Apply a new tenants activation code under Settings → Activation codes."
        )
        # A user who is not active does not count.
        other.is_active = False
        db.commit()
        activation_service.assert_may_add_member(db, tenant_id)


# ---- Background tasks -------------------------------------------------------------------------------------------


def test_background_tasks_do_not_run_while_deactivated(env, caplog):
    from app.jobs.celery_app import celery_app

    ran: list[str] = []

    @celery_app.task(name="tests.activation.probe")
    def probe():
        ran.append("ran")
        return "ran"

    assert probe() == "ran"
    env["clock"].set("2027-02-02T00:00:00")
    with caplog.at_level("WARNING", logger="app.jobs.licence_task"):
        assert probe() is None
        assert probe() is None
    assert ran == ["ran"]
    assert len([r for r in caplog.records if "deactivated" in r.getMessage()]) <= 1
    client = env["client"]
    client.post("/licence/activate", json={"code": product_code(env["key"], expires="2027-08-01T00:00:00.000Z")})
    assert probe() == "ran"
