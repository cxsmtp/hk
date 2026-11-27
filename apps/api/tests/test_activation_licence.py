"""The product licence (/settings/guide/licence): the 3-day trial per installation and the .hawkai licence file.

These tests run the real trial, licences, caps and licence gate (the ``real_licence`` marker keeps conftest from
patching them out), with the clock injected through activation_service.now_ms. Licences are signed with a keypair
made for each test (trusted through HAWK_ACTIVATION_TEST_KEY, only under pytest); no private key is kept anywhere.
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

from app.core.security import get_password_hash
from app.db.models.activation import ActivationState
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import activation_service
from app.services.activation_service import ActivationStore, check_licence, licence_from_file


pytestmark = pytest.mark.real_licence

PASSWORD = "Password123!"
DEACTIVATED = "The product has been deactivated. Please reach out to Bhawani Singh."
HOUR = 60 * 60 * 1000
START = "2026-11-25T12:00:00"


def ms(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp() * 1000


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_key_of(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()


def make_licence(private_key: Ed25519PrivateKey, installation_id: str, prefix: str = "HK2", **payload) -> str:
    full = {
        "v": 2,
        "id": "lic000000001",
        "org": "Acme Corp",
        "installationId": installation_id,
        "scopes": ["product"],
        "issued": "2026-11-01T00:00:00.000Z",
        "expires": "2027-11-01T00:00:00.000Z",
        **payload,
    }
    head = f"{prefix}.{b64url(json.dumps(full).encode())}"
    return f"{head}.{b64url(private_key.sign(head.encode()))}"


def licence_file(code: str, **extra) -> bytes:
    return json.dumps({"format": "hawkai-licence", "v": 2, "licence": code, **extra}).encode()


@pytest.fixture()
def key(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("HAWK_ACTIVATION_TEST_KEY", public_key_of(private_key))
    return private_key


@pytest.fixture()
def clock(monkeypatch):
    """The wall clock the licence sees: set with clock.set('2027-01-15T00:00:00') or moved with clock.add(hours)."""

    class Clock:
        value = ms(START)

        def set(self, text: str) -> None:
            self.value = ms(text)

        def add(self, hours: float) -> None:
            self.value += hours * HOUR

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
    monkeypatch.setattr(activation_service, "_last_product", None)
    client = TestClient(app)
    try:
        yield {"client": client, "db": session_factory, "key": key, "clock": clock}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def register(client: TestClient, email: str) -> dict:
    return client.post("/auth/register", json={"email": email, "password": PASSWORD, "full_name": "Licence Owner"})


def owner_headers(client: TestClient, email: str = "owner@example.com") -> dict[str, str]:
    response = register(client, email)
    assert response.status_code == 200, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["tenants"][0]["id"]}


def sign_in(client: TestClient, email: str) -> dict[str, str]:
    response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["selected_tenant_id"]}


def installation_id(env) -> str:
    return env["client"].get("/licence").json()["installationId"]


def upload(client: TestClient, headers: dict, content: bytes, name: str = "acme.hawkai"):
    return client.post("/licence/import", headers=headers, files={"file": (name, content, "application/octet-stream")})


def audit_rows(env, action: str) -> list[AuditLog]:
    with env["db"]() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.action == action)).all())


def add_member(env, email: str, role: str, *, slug: str | None = None, must_change: bool = False) -> None:
    """A person in the installation's first tenant (or a new tenant ``slug``), straight in the database."""
    with env["db"]() as db:
        if slug:
            tenant = Tenant(name=slug.title(), slug=slug, is_active=True)
            db.add(tenant)
            db.flush()
        else:
            tenant = db.scalars(select(Tenant).order_by(Tenant.created_at)).first()
        user = User(email=email, full_name="Member", hashed_password=get_password_hash(PASSWORD), is_active=True, must_change_password=must_change)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
        db.commit()


# ---- Licences ---------------------------------------------------------------------------------------------------


def test_a_valid_licence_reads_as_signed(key):
    code = make_licence(key, "HK-AAAA-BBBB-CCCC-DDDD", scopes=["product", "tenants"], maxTenants=3, maxUsers=25)
    result = check_licence(code, now=ms("2026-12-01T00:00:00"), installation_id="hk-aaaa-bbbb-cccc-dddd")
    assert result["valid"] is True
    assert result["scopes"] == ["product", "tenants"]
    assert result["org"] == "Acme Corp"
    assert (result["maxTenants"], result["maxUsers"]) == (3, 25)
    assert result["expires"] == "2027-11-01T00:00:00.000Z"
    assert result["installationId"] == "HK-AAAA-BBBB-CCCC-DDDD"
    assert result["code"] == code
    assert result["warn"] is False
    # Thirty days before its end, admins are warned.
    assert check_licence(code, now=ms("2027-10-05T00:00:00"))["warn"] is True


def test_a_licence_for_another_installation_is_refused_with_a_clear_message(key):
    code = make_licence(key, "HK-AAAA-BBBB-CCCC-DDDD")
    result = check_licence(code, now=0, installation_id="HK-ZZZZ-ZZZZ-ZZZZ-ZZZZ")
    assert result["valid"] is False and result["wrongInstallation"] is True
    assert result["reason"] == (
        "This licence is for installation HK-AAAA-BBBB-CCCC-DDDD, not this one (HK-ZZZZ-ZZZZ-ZZZZ-ZZZZ). "
        "Send this installation's licence request to the owner of Hawk AI for a licence made for it."
    )


def test_older_codes_and_other_prefixes_are_not_licences(key):
    # An HK1 activation code or a CxMissionZero code, even signed with the same key, is not a licence: the prefix is
    # part of what is signed, so relabelling one does not verify either.
    for prefix in ("HK1", "MZ1"):
        assert check_licence(make_licence(key, "HK-A", prefix=prefix), now=0) == {"valid": False, "reason": "This file is not a Hawk AI licence."}
    relabelled = "HK2" + make_licence(key, "HK-A", prefix="HK1")[3:]
    assert check_licence(relabelled, now=0)["reason"] == activation_service.NOT_VALID
    assert check_licence("HK2.only-two", now=0)["reason"] == "This file is not a Hawk AI licence."
    assert check_licence("", now=0)["valid"] is False


def test_a_licence_signed_by_another_key_or_tampered_is_not_valid(key):
    other = Ed25519PrivateKey.generate()
    assert check_licence(make_licence(other, "HK-A"), now=0) == {"valid": False, "reason": activation_service.NOT_VALID}
    prefix, payload, signature = make_licence(key, "HK-A").split(".")
    changed = json.loads(base64.urlsafe_b64decode(payload + "=="))
    changed["installationId"] = "HK-B"
    assert check_licence(f"{prefix}.{b64url(json.dumps(changed).encode())}.{signature}", now=0)["reason"] == activation_service.NOT_VALID


def test_malformed_payloads_are_not_valid(key):
    for payload in (
        {"scopes": ["tenants"], "maxTenants": 2},  # no product scope
        {"scopes": ["product", "unknown"]},
        {"scopes": "product"},
        {"scopes": ["product", "tenants"]},  # tenants without maxTenants
        {"scopes": ["product", "tenants"], "maxTenants": 0},
        {"scopes": ["product", "tenants"], "maxTenants": 2, "maxUsers": "5"},
        {"v": 1},
        {"installationId": ""},
        {"expires": "soon"},
    ):
        assert check_licence(make_licence(key, "HK-A", **payload), now=0)["valid"] is False, payload


def test_an_expired_licence_says_when_it_expired(key):
    result = check_licence(make_licence(key, "HK-A", expires="2027-03-01T00:00:00.000Z"), now=ms("2027-03-02T00:00:00"))
    assert result["valid"] is False and result["expired"] is True
    assert result["reason"] == "This licence expired on 2027-03-01."


def test_no_key_means_no_licence_is_valid_and_the_test_key_is_trusted_only_under_pytest(key, monkeypatch):
    code = make_licence(key, "HK-A")
    assert check_licence(code, now=0, keys=[])["reason"] == "This installation has no key to check licences with."
    assert check_licence(code, now=0)["valid"] is True
    monkeypatch.setattr(activation_service.settings, "env", "production")
    assert check_licence(code, now=0)["valid"] is False
    monkeypatch.setattr(activation_service.settings, "env", "test")
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    assert check_licence(code, now=0)["valid"] is False


def test_the_owners_issuer_key_and_the_trial_are_built_in():
    assert activation_service.ISSUER_KEYS == ["MCowBQYDK2VwAyEAlWEwF9lhzKv0IZ1GaDJSmlJqaZd7Gc1JqvYju52uKo4="]
    assert activation_service.TRIAL_HOURS == 72
    assert activation_service.PREFIX == "HK2"
    assert activation_service.MAX_FILE_BYTES == 16 * 1024
    assert activation_service.DEACTIVATED_MESSAGE == DEACTIVATED
    assert activation_service.WARN_DAYS == 30
    assert not hasattr(activation_service, "PRODUCT_DEADLINE")


# ---- The .hawkai file ---------------------------------------------------------------------------------------------


def test_the_licence_file_is_read_and_anything_else_refused(key):
    code = make_licence(key, "HK-A")
    assert licence_from_file(licence_file(code, org="Acme Corp"), "acme.HAWKAI") == (code, "")
    assert licence_from_file(b"\xef\xbb\xbf" + licence_file(code), "acme.hawkai") == (code, "")
    assert licence_from_file(licence_file(code), "acme.txt")[1] == "Choose a .hawkai licence file: this file does not end in .hawkai."
    assert licence_from_file(licence_file(code) + b" " * 17000, "acme.hawkai")[1] == "This file is too large to be a Hawk AI licence (at most 16 KB)."
    assert licence_from_file(None, "")[1] == "Choose a .hawkai licence file."
    for garbage in (b"\x00\xff\xfe garbage", b"[]", b'{"format": "hawkai-licence", "v": 1, "licence": "x"}', b'{"format": "other", "v": 2, "licence": "x"}', b'{"format": "hawkai-licence", "v": 2}', code.encode()):
        assert licence_from_file(garbage, "acme.hawkai")[1] == "This file is not a Hawk AI licence.", garbage


# ---- The trial --------------------------------------------------------------------------------------------------


def test_a_new_installation_gets_an_id_and_works_for_72_hours(key):
    store = ActivationStore()
    first = store.product(ms(START))
    assert first["active"] is True and first["trial"] is True and first["warn"] is True
    assert first["until"] == "2026-11-28T12:00:00.000Z"
    assert (first["daysLeft"], first["hoursLeft"]) == (3, 72)
    assert first["activation"] is None and first["message"] == ""
    assert first["installationId"].startswith("HK-") and len(first["installationId"]) == 22
    assert store.product(ms("2026-11-28T11:59:59"))["active"] is True
    after = store.product(ms("2026-11-28T12:00:00"))
    assert after["active"] is False and after["trial"] is False and after["warn"] is False
    assert after["message"] == DEACTIVATED
    # Each installation has an ID of its own.
    assert ActivationStore().product(ms(START))["installationId"] != first["installationId"]


def test_an_upgraded_installation_gets_72_hours_from_the_upgrade(key):
    # The state an earlier version kept: an HK1 product code and the clock, but no installation ID yet.
    legacy = {"product": {"code": "HK1.x.y", "expires": "2027-02-01T00:00:00.000Z"}, "tenants": None, "seenAt": "2026-11-20T00:00:00.000Z", "history": [{"id": "old"}]}
    store = ActivationStore(legacy)
    upgraded = store.product(ms("2026-12-10T08:00:00"))
    assert upgraded["active"] is True and upgraded["trial"] is True
    assert upgraded["until"] == "2026-12-13T08:00:00.000Z"
    assert store.history() == [{"id": "old"}]
    assert "product" not in store.state and "tenants" not in store.state


def test_setting_the_clock_back_does_not_lengthen_the_trial(key):
    store = ActivationStore()
    store.product(ms(START))
    assert store.product(ms("2026-11-29T00:00:00"))["active"] is False
    # Back to the first day: the licence's clock never goes back.
    back = store.product(ms("2026-11-25T13:00:00"))
    assert back["active"] is False


def test_a_clock_set_forward_at_install_and_then_back_still_ends_the_trial(key):
    store = ActivationStore()
    assert store.product(ms("2030-01-01T00:00:00"))["active"] is True
    t = ms("2026-11-25T00:00:00")
    for hour in range(0, 73, 2):
        product = store.product(t + hour * HOUR)
    # 72 hours have been seen to pass, even though the clock never reached the trial's end date.
    assert product["active"] is False


def test_hours_the_server_is_seen_running_count_once(key):
    store = ActivationStore()
    t = ms(START)
    store.product(t)
    for minute in range(0, 70 * 60, 10):
        store.product(t + minute * 60_000)
    left = store.product(t + 70 * HOUR)
    assert left["active"] is True and left["hoursLeft"] == 2


# ---- Kept in the database ---------------------------------------------------------------------------------------


def test_the_trial_starts_at_first_start_and_is_kept(env):
    logged: list[str] = []
    activation_service.start_installation(env["db"], log=logged.append)
    with env["db"]() as db:
        state = db.get(ActivationState, 1).state
    assert state["trialStart"] == "2026-11-25T12:00:00.000Z"
    assert logged == [f"[licence] Installation {state['installationId']}: trial until 2026-11-28T12:00:00.000Z (72 hours left). Import a .hawkai licence under Settings → Licence."]
    env["clock"].add(10)
    activation_service.start_installation(env["db"])
    with env["db"]() as db:
        again = db.get(ActivationState, 1).state
    assert (again["installationId"], again["trialStart"]) == (state["installationId"], state["trialStart"])


def test_the_migrated_empty_row_gives_an_upgrade_its_72_hours(env):
    client = env["client"]
    owner_headers(client)
    with env["db"]() as db:
        # An installation upgraded with users months old: migration 0106 has made an empty row.
        db.get(ActivationState, 1).state = {}
        for user in db.scalars(select(User)):
            user.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        db.commit()
    env["clock"].set("2026-12-01T00:00:00")
    body = client.get("/licence").json()
    assert body["active"] is True and body["trial"] is True and body["until"] == "2026-12-04T00:00:00.000Z"


def test_a_row_deleted_by_hand_counts_the_trial_from_the_oldest_account(env):
    client = env["client"]
    owner_headers(client)
    with env["db"]() as db:
        db.delete(db.get(ActivationState, 1))
        for user in db.scalars(select(User)):
            user.created_at = datetime(2026, 11, 1, tzinfo=timezone.utc)
        db.commit()
    assert client.get("/licence").json()["active"] is False


def test_an_identity_changed_by_hand_gets_a_new_id_and_no_trial(env):
    client = env["client"]
    first = installation_id(env)
    with env["db"]() as db:
        row = db.get(ActivationState, 1)
        state = json.loads(json.dumps(row.state))
        state["trialStart"] = "2099-01-01T00:00:00.000Z"
        row.state = state
        db.commit()
    body = client.get("/licence").json()
    assert body["active"] is False
    assert body["installationId"] != first
    with env["db"]() as db:
        assert db.get(ActivationState, 1).state["history"][0]["outcome"] == "identity"


def test_another_installations_id_written_in_the_database_does_not_make_its_licence_work(env):
    client = env["client"]
    headers = owner_headers(client)
    env["clock"].add(80)
    other = "HK-ZZZZ-ZZZZ-ZZZZ-ZZZZ"
    with env["db"]() as db:
        row = db.get(ActivationState, 1)
        state = json.loads(json.dumps(row.state))
        state["installationId"] = other
        state["licence"] = {"code": make_licence(env["key"], other), "expires": "2027-11-01T00:00:00.000Z"}
        row.state = state
        db.commit()
    assert client.get("/licence").json()["active"] is False
    refused = upload(client, headers, licence_file(make_licence(env["key"], other)))
    assert refused.status_code == 400 and "not this one" in refused.json()["error"]


def test_a_licence_changed_by_hand_counts_for_nothing(env):
    client = env["client"]
    headers = owner_headers(client)
    ours = installation_id(env)
    assert upload(client, headers, licence_file(make_licence(env["key"], ours, expires="2026-12-15T00:00:00.000Z"))).status_code == 200
    with env["db"]() as db:
        row = db.get(ActivationState, 1)
        state = json.loads(json.dumps(row.state))
        state["licence"]["expires"] = "2099-01-01T00:00:00.000Z"
        row.state = state
        db.commit()
    env["clock"].set("2026-12-10T00:00:00")
    assert client.get("/licence").json()["until"] == "2026-12-15T00:00:00.000Z"
    with env["db"]() as db:
        row = db.get(ActivationState, 1)
        state = json.loads(json.dumps(row.state))
        prefix, payload, signature = state["licence"]["code"].split(".")
        edited = json.loads(base64.urlsafe_b64decode(payload + "=="))
        edited["expires"] = "2099-01-01T00:00:00.000Z"
        state["licence"]["code"] = f"{prefix}.{b64url(json.dumps(edited).encode())}.{signature}"
        row.state = state
        db.commit()
    body = client.get("/licence").json()
    assert body["active"] is False


def test_setting_the_clock_back_does_not_reactivate(env):
    client = env["client"]
    client.get("/licence")
    env["clock"].set("2026-11-29T00:00:00")
    assert activation_service.licence_active() is False
    with env["db"]() as db:
        assert db.get(ActivationState, 1).state["seenAt"] == "2026-11-29T00:00:00.000Z"
    env["clock"].set("2026-11-26T00:00:00")
    assert activation_service.licence_active() is False
    assert client.get("/licence").json()["active"] is False


def test_the_clock_is_kept_at_most_hourly(env):
    activation_service.licence_active()
    env["clock"].set("2026-11-25T12:30:00")
    activation_service.licence_active()
    with env["db"]() as db:
        assert db.get(ActivationState, 1).state["seenAt"] == "2026-11-25T12:00:00.000Z"
    env["clock"].set("2026-11-25T13:00:01")
    activation_service.licence_active()
    with env["db"]() as db:
        state = db.get(ActivationState, 1).state
        assert state["seenAt"] == "2026-11-25T13:00:01.000Z"
        assert state["trialUsedMs"] == HOUR + 1000


def test_an_unreadable_state_never_starts_a_new_trial(env, monkeypatch):
    def broken():
        raise RuntimeError("no database")

    monkeypatch.setattr(activation_service, "licence_session_factory", broken)
    monkeypatch.setattr(activation_service, "_last_product", None)
    assert activation_service.licence_active() is False


# ---- The licence gate -------------------------------------------------------------------------------------------


def test_after_the_trial_every_request_is_refused_but_sign_in_and_the_licence_stay_open(env):
    client = env["client"]
    headers = owner_headers(client)
    assert client.get("/auth/me", headers=headers).status_code == 200
    env["clock"].add(72)
    for path in ("/auth/me", "/settings/about", "/system/platform-mode", "/no-such-route"):
        response = client.get(path, headers=headers)
        assert response.status_code == 503, path
        assert response.json() == {"error": DEACTIVATED, "deactivated": True}
        assert response.headers["cache-control"] == "no-store"
    assert client.get("/health/live").status_code == 200
    assert client.get("/setup").status_code == 200
    licence = client.get("/licence")
    assert licence.status_code == 200 and licence.headers["cache-control"] == "no-store"
    ours = licence.json()["installationId"]
    assert licence.json() == {"active": False, "until": "2026-11-28T12:00:00.000Z", "trial": False, "installationId": ours, "message": DEACTIVATED}
    # The owner signs in on the deactivation page and imports the licence: nothing was deleted, everything works again.
    signed_in = sign_in(client, "owner@example.com")
    status = client.get("/licence/status", headers=signed_in)
    assert status.status_code == 200 and status.json()["canManage"] is True and status.json()["installationId"] == ours
    assert client.get("/licence/request", headers=signed_in).status_code == 200
    imported = upload(client, signed_in, licence_file(make_licence(env["key"], ours, expires="2027-08-01T00:00:00.000Z")))
    assert imported.status_code == 200, imported.text
    assert imported.json()["product"]["active"] is True and imported.json()["product"]["until"] == "2027-08-01T00:00:00.000Z"
    assert client.get("/auth/me", headers=headers).status_code == 200
    # The token got on the deactivation page reaches nothing else while deactivated.
    env["clock"].set("2027-08-02T00:00:00")
    assert client.get("/auth/me", headers=signed_in).status_code == 503


def test_an_administrator_with_a_temporary_password_can_still_import_on_the_deactivation_page(env):
    client = env["client"]
    owner_headers(client)
    add_member(env, "temp@example.com", "admin", must_change=True)
    env["clock"].add(73)
    headers = sign_in(client, "temp@example.com")
    imported = upload(client, headers, licence_file(make_licence(env["key"], installation_id(env))))
    assert imported.status_code == 200, imported.text


# ---- Settings → Licence -----------------------------------------------------------------------------------------


def test_status_shows_the_installation_trial_and_licence(env):
    client = env["client"]
    headers = owner_headers(client)
    view = client.get("/licence/status", headers=headers)
    assert view.status_code == 200 and view.headers["cache-control"] == "no-store"
    body = view.json()
    assert body["canManage"] is True and body["keyConfigured"] is True
    assert body["installationId"] == installation_id(env)
    assert body["trial"] == {"start": "2026-11-25T12:00:00.000Z", "end": "2026-11-28T12:00:00.000Z", "active": True}
    assert body["licence"] is None and body["tenants"] is None and body["history"] == []
    assert body["product"]["daysLeft"] == 3 and body["maxFileBytes"] == 16384
    # The admins' banner shows the time left with the current user.
    me = client.get("/auth/me", headers=headers).json()["licence"]
    assert me["warn"] is True and me["trial"] is True and me["hoursLeft"] == 72 and me["until"] == "2026-11-28T12:00:00.000Z"


def test_importing_a_licence_is_recorded_and_audited(env):
    client = env["client"]
    headers = owner_headers(client)
    ours = installation_id(env)
    code = make_licence(env["key"], ours, scopes=["product", "tenants"], maxTenants=3, maxUsers=10)
    imported = upload(client, headers, licence_file(code, org="Acme Corp"))
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["imported"] == "Hawk AI licensed to Acme Corp until 2027-11-01, for up to 3 tenants, with up to 10 active users in each"
    assert body["licence"]["org"] == "Acme Corp" and body["licence"]["scopes"] == ["product", "tenants"]
    assert body["tenants"]["maxTenants"] == 3
    assert body["product"]["trial"] is False and body["product"]["warn"] is False
    assert body["history"][0]["outcome"] == "imported" and body["history"][0]["by"] == "owner@example.com"
    assert "code" not in body["history"][0]
    rows = audit_rows(env, "licence.imported")
    assert len(rows) == 1
    assert rows[0].payload["reason"] == "Licence imported: Hawk AI licensed to Acme Corp until 2027-11-01, for up to 3 tenants, with up to 10 active users in each."
    assert rows[0].payload["licence"]["installationId"] == ours and rows[0].payload["file"] == "acme.hawkai"
    assert rows[0].actor_type == "human" and rows[0].tenant_id == headers["X-Tenant-ID"]
    # Admins hear 30 days before it ends.
    env["clock"].set("2027-10-10T00:00:00")
    assert client.get("/auth/me", headers=headers).json()["licence"]["warn"] is True


@pytest.mark.parametrize(
    "case, error",
    [
        ("wrong-installation", "This licence is for installation HK-ZZZZ-ZZZZ-ZZZZ-ZZZZ, not this one"),
        ("bad-signature", activation_service.NOT_VALID),
        ("expired", "This licence expired on 2026-11-01."),
        ("garbage", "This file is not a Hawk AI licence."),
        ("oversize", "This file is too large to be a Hawk AI licence (at most 16 KB)."),
        ("extension", "Choose a .hawkai licence file: this file does not end in .hawkai."),
        ("hk1-code", "This file is not a Hawk AI licence."),
    ],
)
def test_refused_files_are_recorded_and_audited(env, case, error):
    client = env["client"]
    headers = owner_headers(client)
    ours = installation_id(env)
    name = "acme.hawkai"
    if case == "wrong-installation":
        content = licence_file(make_licence(env["key"], "HK-ZZZZ-ZZZZ-ZZZZ-ZZZZ"))
    elif case == "bad-signature":
        content = licence_file(make_licence(Ed25519PrivateKey.generate(), ours))
    elif case == "expired":
        content = licence_file(make_licence(env["key"], ours, expires="2026-11-01T00:00:00.000Z"))
    elif case == "garbage":
        content = b"\x89PNG\r\n\x1a\n not a licence"
    elif case == "oversize":
        content = licence_file(make_licence(env["key"], ours), padding="x" * 20_000)
    elif case == "extension":
        content, name = licence_file(make_licence(env["key"], ours)), "acme.json"
    else:
        content = licence_file(make_licence(env["key"], ours, prefix="HK1"))
    refused = upload(client, headers, content, name)
    assert refused.status_code == 400
    assert refused.json()["error"].startswith(error)
    rows = audit_rows(env, "licence.import.refused")
    assert len(rows) == 1 and rows[0].payload["reason"].startswith(f"Licence refused: {error}")
    with env["db"]() as db:
        state = db.get(ActivationState, 1).state
        assert state["history"][0]["outcome"] == "refused" and state["history"][0]["reason"].startswith(error)
        assert state["licence"] is None
    assert client.get("/licence/status", headers=headers).json()["product"]["trial"] is True


def test_a_missing_file_is_refused(env):
    client = env["client"]
    headers = owner_headers(client)
    refused = client.post("/licence/import", headers=headers)
    assert refused.status_code == 400 and refused.json() == {"error": "Choose a .hawkai licence file."}


def test_an_older_licence_does_not_undo_a_newer_one(env):
    client = env["client"]
    headers = owner_headers(client)
    ours = installation_id(env)
    newer = make_licence(env["key"], ours, id="newer0000001", issued="2026-11-20T00:00:00.000Z", expires="2027-06-01T00:00:00.000Z")
    assert upload(client, headers, licence_file(newer)).status_code == 200
    older = make_licence(env["key"], ours, id="older0000001", issued="2026-11-01T00:00:00.000Z", expires="2028-01-01T00:00:00.000Z")
    refused = upload(client, headers, licence_file(older))
    assert refused.json() == {"error": "This licence was issued before the one in force (issued 2026-11-20): ask for a new one."}
    # A newer one that ends sooner replaces it.
    sooner = make_licence(env["key"], ours, id="sooner000001", issued="2026-11-24T00:00:00.000Z", expires="2027-04-01T00:00:00.000Z")
    assert upload(client, headers, licence_file(sooner)).json()["product"]["until"] == "2027-04-01T00:00:00.000Z"


def test_the_licence_request_file_names_the_installation_and_nothing_secret(env):
    client = env["client"]
    headers = owner_headers(client)
    response = client.get("/licence/request", headers=headers)
    assert response.status_code == 200
    ours = installation_id(env)
    assert response.headers["content-disposition"] == f'attachment; filename="hawk-ai-{ours}.hawkai-request"'
    body = json.loads(response.content)
    assert set(body) == {"format", "v", "installationId", "organisation", "hostname", "publicUrl", "version", "trialEnds", "requestedAt", "requestedBy"}
    assert body["format"] == "hawkai-licence-request" and body["installationId"] == ours
    assert body["organisation"] and body["hostname"] and body["version"]
    text = response.text.lower()
    assert "secret" not in text and "password" not in text and "seal" not in text
    assert len(audit_rows(env, "licence.request.downloaded")) == 1


def test_only_owners_and_admins_of_the_installation_manage_the_licence(env):
    client = env["client"]
    headers = owner_headers(client)
    content = licence_file(make_licence(env["key"], installation_id(env)))
    add_member(env, "auditor@example.com", "auditor")
    auditor = sign_in(client, "auditor@example.com")
    for path in ("/licence/status", "/licence/request"):
        assert client.get(path, headers=auditor).status_code == 403, path
    assert upload(client, auditor, content).status_code == 403
    assert client.get("/auth/me", headers=auditor).json()["licence"] is None
    # An admin of another tenant sees the licence, read only, and cannot import one.
    add_member(env, "other-admin@example.com", "admin", slug="other")
    other = sign_in(client, "other-admin@example.com")
    assert client.get("/licence/status", headers=other).json()["canManage"] is False
    assert upload(client, other, content).status_code == 403
    assert len(audit_rows(env, "settings.installation.refused")) == 1
    assert audit_rows(env, "licence.imported") == []
    assert upload(client, headers, content).status_code == 200


# ---- Several tenants, and their users ----------------------------------------------------------------------------


def test_one_tenant_without_a_licence_and_as_many_as_the_licence_allows(env):
    client = env["client"]
    headers = owner_headers(client, "first@example.com")
    second = register(client, "second@example.com")
    assert second.status_code == 403
    assert second.json()["detail"] == (
        "Without a licence for several tenants Hawk AI serves 1 tenant, and it is in use. Import a licence for several tenants under Settings → Licence."
    )
    code = make_licence(env["key"], installation_id(env), scopes=["product", "tenants"], maxTenants=2)
    assert upload(client, headers, licence_file(code)).status_code == 200
    assert register(client, "second@example.com").status_code == 200
    third = register(client, "third@example.com")
    assert third.status_code == 403
    assert third.json()["detail"] == "The licence allows up to 2 tenants, and all are in use. Import a licence that allows more under Settings → Licence."
    # Once it has expired, the installation is back to one tenant; nothing already there is removed.
    env["clock"].set("2027-11-02T00:00:00")
    with env["db"]() as db:
        assert activation_service.tenant_limits(db) == (1, None)
        assert len(db.scalars(select(Tenant).where(Tenant.is_active.is_(True))).all()) == 2


def test_a_tenant_takes_no_more_active_users_than_the_licence_allows(env):
    client = env["client"]
    headers = owner_headers(client)
    tenant_id = headers["X-Tenant-ID"]
    with env["db"]() as db:
        activation_service.assert_may_add_member(db, tenant_id)
    upload(client, headers, licence_file(make_licence(env["key"], installation_id(env), scopes=["product", "tenants"], maxTenants=2, maxUsers=2)))
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
            "The licence allows up to 2 active users in each tenant, and all are in use in this one. Import a licence that allows more under Settings → Licence."
        )
        other.is_active = False
        db.commit()
        activation_service.assert_may_add_member(db, tenant_id)


# ---- Background tasks -------------------------------------------------------------------------------------------


def test_background_tasks_do_not_run_after_the_trial(env, caplog):
    from app.jobs.celery_app import celery_app

    ran: list[str] = []

    @celery_app.task(name="tests.activation.probe")
    def probe():
        ran.append("ran")
        return "ran"

    assert probe() == "ran"
    env["clock"].add(73)
    with caplog.at_level("WARNING", logger="app.jobs.licence_task"):
        assert probe() is None
        assert probe() is None
    assert ran == ["ran"]
    assert len([r for r in caplog.records if "deactivated" in r.getMessage()]) <= 1
    with env["db"]() as db:
        store = activation_service.load_store(db)
        store.record(store.check(make_licence(env["key"], store.installation_id)), "test")
        db.commit()
    assert probe() == "ran"


# ---- Migration 0106 ---------------------------------------------------------------------------------------------


def test_migration_0106_makes_the_row_an_upgrade_needs_and_keeps_one_already_there(tmp_path):
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = Path(__file__).resolve().parents[1] / "app/db/migrations/versions/0106_installation_licence.py"
    spec = importlib.util.spec_from_file_location("migration_0106", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert (migration.revision, migration.down_revision) == ("0106_installation_licence", "0105_compliance_packs")
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'm.sqlite3'}")
    ActivationState.__table__.create(bind=engine)
    for _ in range(2):
        with engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.upgrade()
    with sessionmaker(bind=engine)() as db:
        rows = db.scalars(select(ActivationState)).all()
        assert [(row.id, row.state) for row in rows] == [(1, {})]
        rows[0].state = {"seenAt": "2026-11-01T00:00:00.000Z"}
        db.commit()
    with engine.begin() as connection:
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
    with sessionmaker(bind=engine)() as db:
        assert db.get(ActivationState, 1).state == {"seenAt": "2026-11-01T00:00:00.000Z"}
    engine.dispose()
