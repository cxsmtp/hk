"""Regression tests for the Checkmarx One triage fixes (HK-00.03.00): races on single-use tokens and counted limits,
error messages that named server internals, log lines that could be split, and outbound addresses."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import get_password_hash
from app.db import xact_lock
from app.db.models.tenant import Tenant
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.db.session import Base

PASSWORD = "Password123!"
LEAK = "password authentication failed for user hawk at db.internal:5432 /srv/hawk/secret"


@pytest.fixture()
def db():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _person(db, email: str = "pat@example.com", role: str = "owner") -> tuple[User, Tenant]:
    tenant = Tenant(name="Acme", slug=f"acme-{email.split('@')[0]}", is_active=True)
    user = User(email=email, full_name="Pat", hashed_password=get_password_hash(PASSWORD), is_active=True)
    db.add_all([tenant, user])
    db.flush()
    db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
    db.commit()
    return user, tenant


# ---- Races ----------------------------------------------------------------------------------------------------------


def test_refresh_token_spent_by_a_concurrent_request_is_refused(db, monkeypatch):
    """Two refreshes with one token: the one that loses the race gets 401, not a second pair of tokens."""

    from app.services import auth_service

    user, tenant = _person(db)
    tokens = auth_service.issue_tokens(db, user=user, tenant_id=tenant.id, role="owner")
    db.commit()
    real = auth_service._as_utc
    raced = {"done": False}

    def other_request_spends_it_first(value):
        if not raced["done"]:
            raced["done"] = True
            db.execute(update(RefreshToken).values(revoked_at=datetime.now(timezone.utc)).execution_options(synchronize_session=False))
        return real(value)

    monkeypatch.setattr(auth_service, "_as_utc", other_request_spends_it_first)
    with pytest.raises(HTTPException) as refused:
        auth_service.refresh_tokens(db, tokens["refresh_token"])
    assert refused.value.status_code == 401
    assert db.query(RefreshToken).count() == 1


def test_refresh_token_still_rotates_once(db):
    from app.services import auth_service

    user, tenant = _person(db)
    tokens = auth_service.issue_tokens(db, user=user, tenant_id=tenant.id, role="owner")
    db.commit()
    fresh = auth_service.refresh_tokens(db, tokens["refresh_token"])
    db.commit()
    assert fresh["refresh_token"] and fresh["refresh_token"] != tokens["refresh_token"]
    with pytest.raises(HTTPException):
        auth_service.refresh_tokens(db, tokens["refresh_token"])


def test_sign_in_checks_hold_the_persons_row(db, monkeypatch):
    """The password and two-step checks read the person's row under a lock (FOR UPDATE), so racing wrong attempts
    are all counted and a recovery code or a code's step cannot be used twice."""

    from app.services import account_security, mfa_service

    user, _ = _person(db)
    locked: list[bool] = []
    real_refresh = db.refresh

    def spy(instance, *args, **kwargs):
        if instance is user:
            locked.append(bool(kwargs.get("with_for_update")))
        return real_refresh(instance, *args, **kwargs)

    monkeypatch.setattr(db, "refresh", spy)
    with pytest.raises(account_security.SignInRefused):
        account_security.check_password(db, user.email, "wrong-password-123")
    assert locked == [True]
    assert user.failed_logins == 1
    assert account_security.check_password(db, user.email, PASSWORD, more=True) is user
    assert locked == [True, True]

    monkeypatch.setattr(mfa_service, "open_secret", lambda sealed: "JBSWY3DPEHPK3PXP")
    with pytest.raises(account_security.SignInRefused):
        account_security.check_two_step(db, user, "000000", recovery=False)
    assert locked[-1] is True


def test_xact_lock_is_taken_on_postgresql_only():
    calls: list[tuple[str, dict]] = []

    class Fake:
        def __init__(self, name):
            self.name = name

        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name=self.name))

        def execute(self, statement, params=None):
            calls.append((str(statement), params))

    assert xact_lock.hold(Fake("sqlite"), "tenant-people", "t1") is False
    assert calls == []
    assert xact_lock.hold(Fake("postgresql"), "tenant-people", "t1") is True
    assert calls == [("SELECT pg_advisory_xact_lock(:key)", {"key": xact_lock.lock_key("tenant-people", "t1")})]
    assert xact_lock.lock_key("tenant-people", "t1") != xact_lock.lock_key("tenant-people", "t2")
    assert -(2**63) <= xact_lock.lock_key("tenants") < 2**63


@pytest.mark.real_licence
def test_licence_caps_count_under_the_lock(db, monkeypatch):
    from app.services import activation_service

    held: list[tuple[str, ...]] = []
    monkeypatch.setattr(xact_lock, "hold", lambda session, *parts: held.append(parts) or True)
    _, tenant = _person(db)
    monkeypatch.setattr(activation_service, "tenant_limits", lambda session, now=None: (1, 1))
    with pytest.raises(HTTPException) as full:
        activation_service.assert_may_add_member(db, tenant.id)
    assert full.value.status_code == 403
    assert held == [("tenant-people", tenant.id)]
    with pytest.raises(HTTPException):
        activation_service.assert_may_add_tenant(db)
    assert held[-1] == ("tenants",)


def test_last_owner_rule_counts_under_the_lock(db, monkeypatch):
    from app.services import iam_service

    held: list[tuple[str, ...]] = []
    monkeypatch.setattr(xact_lock, "hold", lambda session, *parts: held.append(parts) or True)
    user, tenant = _person(db)
    membership = db.query(UserTenantRole).filter_by(user_id=user.id).one()
    with pytest.raises(iam_service.Refused):
        iam_service.keep_an_owner(db, membership, user, new_role="viewer")
    assert held == [("tenant-people", tenant.id)]
    iam_service.keep_an_owner(db, membership, user, new_role="owner")
    assert len(held) == 1


def test_support_request_is_locked_for_a_change():
    from app.services import support_desk

    seen: dict = {}

    class Fake:
        def get(self, model, key, **kwargs):
            seen.update(kwargs, key=key)

    support_desk.get(Fake(), "sup-0001", lock=True)
    assert seen == {"with_for_update": True, "key": "SUP-0001"}
    support_desk.get(Fake(), "sup-0001")
    assert seen["with_for_update"] is None


# ---- Error messages -------------------------------------------------------------------------------------------------


def test_public_health_does_not_echo_the_database_error(monkeypatch):
    from fastapi.testclient import TestClient

    import app.main as main

    def broken():
        raise OperationalError("SELECT 1", {}, Exception(LEAK))

    monkeypatch.setattr(main, "SessionLocal", broken)
    client = TestClient(main.app)
    for path, field in (("/health", "error"), ("/health/schema", "notes")):
        response = client.get(path)
        assert response.status_code == 503
        assert "db.internal" not in response.text and "/srv/hawk" not in response.text
        assert "OperationalError" in response.text, field


def test_control_plane_checks_do_not_echo_driver_messages(caplog):
    from sqlalchemy.exc import SQLAlchemyError

    from app.services import control_plane_health_service as health

    class Broken:
        def execute(self, *_args, **_kwargs):
            raise SQLAlchemyError(LEAK)

    with caplog.at_level(logging.WARNING, logger=health.__name__):
        result = health._check_database_connectivity(Broken())
    assert result.ok is False
    assert "db.internal" not in result.detail and "SQLAlchemyError" in result.detail
    assert any("database connectivity failed" in r.getMessage() for r in caplog.records)


def test_auditor_storage_failure_is_a_plain_sentence(caplog):
    from app.api.routers.auditor import _storage_failure

    with caplog.at_level(logging.ERROR):
        error = _storage_failure(RuntimeError("Failed to create artifact directory '/srv/hawk/secret': [Errno 13]"))
    assert error.status_code == 500
    assert "/srv/hawk" not in str(error.detail)
    assert caplog.records


# ---- Logs -----------------------------------------------------------------------------------------------------------


def test_text_log_lines_cannot_be_split_by_a_value():
    from app.core.log_config import TextFormatter

    record = logging.LogRecord("app.test", logging.WARNING, __file__, 1, "Reply from %s", ("x\n2026-01-01T00:00:00.000Z INFO  app.auth  forged",), None)
    record.subject = "a\r\nb"
    line = TextFormatter().format(record)
    assert "\n" not in line and "\r" not in line
    assert "x\\n2026-01-01" in line and "subject=" in line


# ---- Outbound addresses ---------------------------------------------------------------------------------------------


def test_registry_redirects_never_reach_a_metadata_address(monkeypatch):
    from app.services.updates import registry

    with pytest.raises(registry.UpdateError):
        registry.refuse_metadata_hop(httpx.Request("GET", "http://169.254.169.254/latest/meta-data/"))
    with pytest.raises(registry.UpdateError):
        registry.refuse_metadata_hop(httpx.Request("GET", "https://metadata.google.internal/computeMetadata/v1/"))
    registry.refuse_metadata_hop(httpx.Request("GET", "https://pkg-containers.githubusercontent.com/blob"))

    made: dict = {}

    class FakeClient:
        def __init__(self, **kwargs):
            made.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, headers=None):
            return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr(registry.httpx, "Client", FakeClient)
    registry.ImageRegistry("ghcr.io/acme/app")._send("https://ghcr.io/v2/acme/app/tags/list", {})
    assert made["follow_redirects"] is True
    assert registry.refuse_metadata_hop in made["event_hooks"]["request"]


def test_hands_off_mailbox_is_never_a_metadata_address():
    from app.services import hands_off

    for host in ("169.254.169.254", "metadata.google.internal", "100.100.100.200"):
        with pytest.raises(hands_off.HandsOffError):
            hands_off.merge_hands_off({}, {"imapHost": host})
    assert hands_off.merge_hands_off({}, {"imapHost": "imap.example.com"})["imapHost"] == "imap.example.com"

