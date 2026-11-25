"""The platform's records and network, ported from CxMissionZero (src/audit-log.js, src/routes/audit.js,
src/activity-log.js, src/support.js, src/routes/support.js, src/network.js, src/trust.js, src/outbound-url.js) with the
console pages of FTR Command Center: the tamper-evident audit chain (tampering, concurrency, exports, the check), the
limits on refusals from people not signed in, the privacy sanitizer's dates and addresses, the user activity log,
support cases (numbers, statuses, limits, emails), the proxy check step by step against a local proxy, trusting a
company proxy's root and completing a chain, the SSRF guard, and the connector API activity recorder."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import socket
import ssl
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, insert, select, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.audit import AuditChainHead, AuditLog
from app.db.models.platform_records import ConnectorCall, SupportTicket, UserActivity
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import (
    account_security,
    audit_chain,
    connector_activity,
    mailer,
    network_proxy,
    outbound_url,
    refusal_audit,
    support_desk,
    trust_store,
    user_activity,
)
from app.services.audit_service import write_audit_log
from app.services.outbound_destination_policy import (
    OutboundDestinationPolicy,
    OutboundDestinationPolicyError,
    PinnedHTTPTransport,
    request_with_redirect_validation,
)
from app.services.privacy_sanitizer import redact_sensitive_text, sanitize_privacy_payload

PASSWORD = "correct-Horse-2026"


# ---------------------------------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------------------------------


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setattr(settings, "hawk_data_dir", str(folder))
    audit_chain.forget_key()
    trust_store._context_cache.clear()  # noqa: SLF001
    network_proxy.use_proxy("", "")
    monkeypatch.setitem(network_proxy._applied, "at_start", {})  # noqa: SLF001 - no container proxy in tests
    yield folder
    audit_chain.forget_key()
    trust_store._context_cache.clear()  # noqa: SLF001
    network_proxy.use_proxy("", "")


@pytest.fixture()
def factory(tmp_path, data_dir, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'records.sqlite3'}", connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(bind=engine)
    made = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(user_activity, "session_factory", made)
    monkeypatch.setattr(connector_activity, "session_factory", made)
    yield made
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def env(factory, monkeypatch):
    def override_get_db():
        db = factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    monkeypatch.setattr(settings, "web_origin", "https://hawk.example.test")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_from", "hawk@example.test")
    monkeypatch.setattr(settings, "smtp_pass", "smtp-secret")
    sent: list[dict[str, str]] = []

    def fake_send(message, to, smtp=None):  # noqa: ANN001, ARG001
        sent.append({"to": to, "subject": message["Subject"], "text": message.get_body(("plain",)).get_content(), "reply_to": message.get("Reply-To") or ""})

    monkeypatch.setattr(mailer, "send", fake_send)
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "db": factory, "sent": sent}
    finally:
        client.close()
        app.dependency_overrides.clear()


def make_user(env, email: str, *, role: str = "owner", tenant: str = "acme") -> tuple[str, str]:
    with env["db"]() as db:
        tenant_row = db.scalar(select(Tenant).where(Tenant.slug == tenant))
        if tenant_row is None:
            tenant_row = Tenant(name=tenant.title(), slug=tenant, is_active=True)
            db.add(tenant_row)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0].title(), hashed_password=get_password_hash(PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant_row.id, role=role))
        db.commit()
        return user.id, tenant_row.id


def sign_in(env, email: str) -> dict[str, str]:
    answer = env["client"].post("/auth/login", json={"email": email, "password": PASSWORD})
    assert answer.status_code == 200, answer.text
    tokens = answer.json()
    return {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}


def tested_smtp(env) -> None:
    with env["db"]() as db:
        account_security.policy(db).smtp_verified = mailer.fingerprint()
        db.commit()


def audit(db, *, tenant_id: str | None = None, action: str = "x.y", **payload: Any) -> AuditLog:
    return write_audit_log(db, tenant_id=tenant_id, actor_user_id=None, actor_type="system", action=action, resource_type="test", resource_id="r", payload=payload or {"reason": "r"})


# ---------------------------------------------------------------------------------------------------------------------
# The audit chain
# ---------------------------------------------------------------------------------------------------------------------


def test_every_entry_is_numbered_and_chained_to_the_one_before(factory, data_dir):
    with factory() as db:
        rows = [audit(db, n=i) for i in range(5)]
        db.commit()
        assert [r.seq for r in rows] == [1, 2, 3, 4, 5]
        assert rows[0].prev_mac == "genesis"
        assert all(rows[i].prev_mac == rows[i - 1].mac for i in range(1, 5))
        assert all(r.chain == "system" for r in rows)
        result = audit_chain.verify(db, "system")
    assert result["ok"] is True and result["entries"] == 5 and result["problems"] == [] and result["head"] == 5
    key = data_dir / "audit.key"
    assert key.stat().st_mode & 0o777 == 0o600 and len(key.read_bytes()) == 32


def test_each_tenant_has_a_chain_of_its_own(factory, data_dir):
    with factory() as db:
        a = Tenant(name="A", slug="a", is_active=True)
        b = Tenant(name="B", slug="b", is_active=True)
        db.add_all([a, b])
        db.flush()
        audit(db, tenant_id=a.id)
        audit(db, tenant_id=b.id)
        audit(db, tenant_id=a.id)
        db.commit()
        assert [r.seq for r in db.scalars(select(AuditLog).where(AuditLog.tenant_id == a.id).order_by(AuditLog.seq))] == [1, 2]
        assert audit_chain.verify(db, a.id)["ok"] and audit_chain.verify(db, b.id)["entries"] == 1


@pytest.mark.parametrize(
    "tamper, problem",
    [
        ("UPDATE audit_logs SET payload = '{\"reason\": \"edited\"}' WHERE seq = 3", "Contents changed after it was written."),
        ("UPDATE audit_logs SET action = 'x.other' WHERE seq = 2", "Contents changed after it was written."),
        ("UPDATE audit_logs SET created_at = '2020-01-01 00:00:00.000000' WHERE seq = 4", "Contents changed after it was written."),
        ("DELETE FROM audit_logs WHERE seq = 3", "Expected entry #3: entries missing or reordered."),
        ("UPDATE audit_logs SET mac = 'forged' WHERE seq = 2", "Contents changed after it was written."),
    ],
)
def test_the_check_names_each_edited_removed_or_reordered_entry(factory, tamper, problem):
    with factory() as db:
        for i in range(5):
            audit(db, n=i)
        db.commit()
    with factory() as db:
        # The database's own triggers refuse this (migration 0002); a person with access to the files can still do it.
        db.execute(text(tamper))
        db.commit()
        result = audit_chain.verify(db, "system")
    assert result["ok"] is False
    assert problem in [p["problem"] for p in result["problems"]]


def test_removing_the_newest_entries_is_found_through_the_chain_head(factory):
    with factory() as db:
        for i in range(4):
            audit(db, n=i)
        db.commit()
        db.execute(text("DELETE FROM audit_logs WHERE seq >= 3"))
        db.commit()
        result = audit_chain.verify(db, "system")
    assert not result["ok"]
    assert result["problems"][-1]["problem"] == "Entries #3 to #4 are missing (removed after they were written)."


def test_a_different_key_breaks_every_mac_and_a_short_key_is_never_replaced(factory, data_dir):
    with factory() as db:
        audit(db)
        db.commit()
        assert audit_chain.verify(db, "system", key=b"k" * 32)["problems"][0]["problem"] == "Contents changed after it was written."
    audit_chain.forget_key()
    (data_dir / "audit.key").write_bytes(b"short")
    with pytest.raises(audit_chain.AuditKeyError, match="holds 5 bytes"):
        audit_chain.load_key()
    assert (data_dir / "audit.key").read_bytes() == b"short"


def test_two_processes_making_the_key_at_once_end_with_one_key(data_dir):
    keys: list[bytes] = []

    def make() -> None:
        keys.append(audit_chain._create_key(data_dir / "audit.key"))  # noqa: SLF001

    threads = [threading.Thread(target=make) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(keys)) == 1 and keys[0] == (data_dir / "audit.key").read_bytes()
    assert not [p for p in data_dir.iterdir() if p.name.endswith(".tmp")]


def test_concurrent_writers_never_number_two_entries_alike(factory):
    errors: list[BaseException] = []

    def writer(n: int) -> None:
        try:
            for i in range(10):
                with factory() as db:
                    audit(db, writer=n, i=i)
                    db.commit()
        except BaseException as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    with factory() as db:
        seqs = sorted(r.seq for r in db.scalars(select(AuditLog)))
        assert seqs == list(range(1, 61))
        assert audit_chain.verify(db, "system")["ok"]
        assert db.get(AuditChainHead, "system").seq == 60


def test_entries_written_before_the_chain_began_are_counted_not_failed(factory):
    with factory() as db:
        db.execute(insert(AuditLog.__table__).values(id="legacy-1", tenant_id=None, actor_type="system", action="old", resource_type="r", resource_id="r", payload={}, created_at=dt.datetime(2026, 1, 1)))
        audit(db)
        db.commit()
        result = audit_chain.verify(db, "system")
    assert result["ok"] and result["entries"] == 1 and result["unchained"] == 1


def test_the_orm_still_refuses_to_change_an_entry(factory):
    with factory() as db:
        row = audit(db)
        db.commit()
        row.action = "changed"
        with pytest.raises(ValueError, match="immutable"):
            db.commit()


def test_csv_cells_never_become_formulas_and_jsonl_entries_can_be_checked(factory, data_dir):
    assert audit_chain.csv_cell("=SUM(A1)") == "'=SUM(A1)"
    assert audit_chain.csv_cell("+1") == "'+1" and audit_chain.csv_cell("-2") == "'-2" and audit_chain.csv_cell("@x") == "'@x"
    assert audit_chain.csv_cell("\tx") == "'\tx" and audit_chain.csv_cell("ok") == "ok" and audit_chain.csv_cell(None) == ""
    with factory() as db:
        row = audit(db, reason="=HYPERLINK(\"http://evil\")")
        db.commit()
        line = json.loads(audit_chain.jsonl_entry(row))
    body = {k: v for k, v in line.items() if k not in ("prev", "mac")}
    assert audit_chain.compute_mac(audit_chain.load_key(), line["prev"], body) == line["mac"]


# ---- The audit log routes ------------------------------------------------------------------------------------------


def test_the_audit_log_page_lists_filters_exports_and_checks(env):
    _, tenant = make_user(env, "owner@acme.test")
    headers = sign_in(env, "owner@acme.test")
    with env["db"]() as db:
        audit(db, tenant_id=tenant, action="settings.network", reason="=cmd|' /C calc'!A0", ip="192.168.100.200")
        audit(db, tenant_id=tenant, action="auth.sign_in.refused", reason="refused at 2026-11-25T10:00:00.123Z")
        audit(db, tenant_id=tenant, action="x.formula", reason="r", ip="=HYPERLINK(\"http://evil\")")
        db.commit()
    client = env["client"]
    page = client.get("/audit/log", headers=headers).json()
    actions = [e["action"] for e in page["events"]]
    assert "settings.network" in actions and "auth.sign_in.refused" in actions
    network = next(e for e in page["events"] if e["action"] == "settings.network")
    assert network["ip"] == "192.168.100.200" and "ip" not in network["details"] and network["mac"]
    assert any(p["email"] == "owner@acme.test" for p in page["people"])
    refused = client.get("/audit/log?outcome=refused", headers=headers).json()["events"]
    assert {e["action"] for e in refused} == {"auth.sign_in.refused"}
    assert refused[0]["details"]["reason"] == "refused at 2026-11-25T10:00:00.123Z"
    assert client.get("/audit/log?what=settings", headers=headers).json()["events"][0]["action"] == "settings.network"
    assert client.get("/audit/log?q=calc", headers=headers).json()["events"][0]["action"] == "settings.network"

    csv_answer = client.get("/audit/log/export.csv", headers=headers)
    assert csv_answer.status_code == 200 and csv_answer.headers["content-type"].startswith("text/csv")
    assert "attachment;" in csv_answer.headers["content-disposition"]
    lines = csv_answer.text.splitlines()
    assert lines[0].startswith("Notice:") and lines[1] == "When,Who,Email,Action,On,Details,Address,Seq,MAC"
    import csv as csv_module

    cells = [cell for row in csv_module.reader(lines[2:]) for cell in row]
    assert not [cell for cell in cells if cell[:1] in ("=", "+", "-", "@")]
    assert "'=HYPERLINK(\"http://evil\")" in cells

    jsonl = client.get("/audit/log/export.jsonl", headers=headers)
    rows = [json.loads(line) for line in jsonl.text.splitlines()]
    assert "notice" in rows[0] and all(r["mac"] and r["chain"] == tenant for r in rows[1:])

    verify = client.get("/audit/log/verify", headers=headers).json()
    assert verify["ok"] and verify["events"] == verify["entries"] and verify["brokenAt"] is None
    with env["db"]() as db:
        actions = [r.action for r in db.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant))]
        assert "audit.verify" in actions and actions.count("audit.export") == 2
        db.execute(text("UPDATE audit_logs SET payload = '{}' WHERE action = 'settings.network'"))
        db.commit()
    broken = client.get("/audit/log/verify", headers=headers).json()
    assert not broken["ok"] and broken["brokenAt"] == network["seq"] and broken["why"] == "Contents changed after it was written"


def test_viewers_cannot_read_the_audit_log(env):
    make_user(env, "viewer@acme.test", role="viewer")
    headers = sign_in(env, "viewer@acme.test")
    assert env["client"].get("/audit/log", headers=headers).status_code == 403
    assert env["client"].get("/audit/log/export.csv", headers=headers).status_code == 403


# ---------------------------------------------------------------------------------------------------------------------
# Refusals from people not signed in
# ---------------------------------------------------------------------------------------------------------------------


def test_refusals_are_listed_ten_a_minute_per_address_and_forty_in_all():
    limiter = refusal_audit.RefusalsListed("unauthenticated")
    listed = [limiter.listed("address 1", 1000)[0] for _ in range(12)]
    assert listed.count(True) == 10
    for n in range(2, 6):
        for _ in range(10):
            limiter.listed(f"address {n}", 2000)
    assert limiter.listed("address 9", 3000) == (False, 0)
    # The next minute: the ones left out are said in one line.
    allowed, left = limiter.listed("address 1", 61_500)
    # Address 1: 2 over its 10; address 5: all 10 (the 40 in all were reached); address 9: 1.
    assert allowed is True and left == 13
    assert limiter.left_out_line(left) == "13 more refused requests from people not signed in in the minute before were not listed one by one (too many at once)."


def test_sign_in_refusals_are_listed_thirty_per_address_and_one_hundred_twenty_in_all():
    limiter = refusal_audit.RefusalsListed("sign_in")
    assert [limiter.listed("address a", 0)[0] for _ in range(31)].count(True) == 30
    for n in range(4):
        for _ in range(30):
            limiter.listed(f"address {n}", 0)
    assert limiter.listed("address z", 0)[0] is False


def test_the_left_out_refusals_become_one_audit_entry(factory):
    refusal_audit.reset_all()
    with factory() as db:
        for _ in range(35):
            if refusal_audit.may_list(db, "sign_in", "10.0.0.1", now_ms=0):
                audit(db, action="auth.sign_in.refused")
        assert refusal_audit.may_list(db, "sign_in", "10.0.0.1", now_ms=61_000) is True
        db.commit()
        rows = db.scalars(select(AuditLog).order_by(AuditLog.seq)).all()
    assert [r.action for r in rows].count("auth.sign_in.refused") == 30
    line = rows[-1]
    assert line.action == "audit.refusals_not_listed.sign_in" and line.payload["count"] == 5
    assert line.payload["reason"] == "5 more refused sign-ins in the minute before were not listed one by one (too many at once)."


def test_wrong_setup_codes_are_listed_only_ten_a_minute(env, monkeypatch):
    from app.services import first_run_service

    def refuse(*args, **kwargs):  # noqa: ANN002, ANN003
        raise first_run_service.SetupRefused(403, "That setup code is not right.")

    from app.api.routers import access as access_routes

    monkeypatch.setattr(first_run_service, "use_setup_code", refuse)
    # The route's own limit of tries is not what is tested here.
    monkeypatch.setattr(access_routes.setup_tries, "allow", lambda ip: True)
    for _ in range(13):
        env["client"].post("/setup", json={"code": "x", "email": "a@b.test", "name": "A", "password": PASSWORD})
    with env["db"]() as db:
        assert len(db.scalars(select(AuditLog).where(AuditLog.action == "access.setup.refused")).all()) == 10


# ---------------------------------------------------------------------------------------------------------------------
# The privacy sanitizer: dates, times and addresses are not phone numbers
# ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kept",
    [
        "Sign-in refused from 192.168.100.200 at 2026-11-25T10:00:00.123Z.",
        "Backup hawk-ai-2026-11-25T10-00-00Z.hkbackup written.",
        "at 2026-11-25T10:00:00.123456789Z",
        "until 2027-01-31 (activation)",
        "from 10.0.0.5:8080 and 172.16.254.1",
        "2026-11-25 10:00:00+01:00",
    ],
)
def test_system_written_dates_times_and_ipv4_addresses_are_kept(kept):
    assert redact_sensitive_text(kept) == kept
    assert sanitize_privacy_payload({"reason": kept, "ip": "203.0.113.200"}) == {"reason": kept, "ip": "203.0.113.200"}


@pytest.mark.parametrize(
    "phone",
    ["call +1 (555) 123-4567", "+44 20 7946 0958", "555-123-4567", "tel 212.555.1234", "+1.212.555.0123", "+1 2026-11-25 5555", "0044 20 7946 0958"],
)
def test_phone_numbers_are_still_redacted(phone):
    assert "[phone]" in redact_sensitive_text(phone)


def test_card_numbers_and_emails_are_still_redacted():
    out = redact_sensitive_text("card 4111 1111 1111 1111 from jo@acme.test on 2026-11-25")
    assert "4111" not in out and "[email]" in out and "2026-11-25" in out


# ---------------------------------------------------------------------------------------------------------------------
# The user activity log
# ---------------------------------------------------------------------------------------------------------------------


def test_what_people_change_is_logged_with_field_names_never_values(env):
    _, tenant = make_user(env, "owner@acme.test")
    headers = sign_in(env, "owner@acme.test")
    client = env["client"]
    answer = client.put("/support/settings", headers=headers, json={"mode": "portal", "email": "secret-help@acme.test"})
    assert answer.status_code == 200, answer.text
    client.get("/audit/log/export.csv", headers=headers)
    client.get("/audit/log", headers=headers)  # an ordinary read: not logged
    with env["db"]() as db:
        rows = db.scalars(select(UserActivity).where(UserActivity.tenant_id == tenant).order_by(UserActivity.at)).all()
    assert [r.action for r in rows] == ["Changed where Get help sends requests", "Exported the audit log"]
    change = rows[0]
    assert change.fields == ["mode", "email"] and change.user == "owner@acme.test" and change.role == "owner"
    assert change.method == "PUT" and change.route == "/support/settings" and change.status == 200 and change.ms is not None
    assert "secret-help" not in json.dumps([user_activity.view(r) for r in rows])
    listing = client.get("/activity/log", headers=headers).json()
    assert listing["total"] == 2 and listing["people"] == [{"email": "owner@acme.test", "name": "Owner"}]
    assert client.get("/activity/log?q=exported", headers=headers).json()["total"] == 1
    csv_text = client.get("/activity/log/export.csv", headers=headers).text
    assert csv_text.splitlines()[0] == "at,user,name,role,ip,kind,action,target,fields,status,ms"
    assert "mode email" in csv_text


def test_activity_rows_are_cut_to_size_described_and_pruned_after_a_year(factory):
    assert user_activity.describe("PUT", "/backups/readiness/{check_id}") == "Changed a readiness check"
    assert user_activity.describe("POST", "/some-thing/{id}/run_now") == "Did some thing › run now"
    assert user_activity.field_names({"a": 1, "b": {"c": 2, "d": 3}, "e": [1]}) == ["a", "b.c", "b.d", "e"]
    assert user_activity.target_of({"id": "7f3a"}) == "id 7f3a"
    assert user_activity.should_record("GET", "/audit/log/export.csv") and not user_activity.should_record("GET", "/audit/log")
    now = dt.datetime.now(dt.timezone.utc)
    with factory() as db:
        row = user_activity.record(db, {"tenant_id": "t", "user": "x" * 400, "action": "=bad\u0000thing", "fields": ["f"] * 50, "kind": "nope"}, now=now)
        user_activity.record(db, {"tenant_id": "t", "action": "old"}, now=now - dt.timedelta(days=400))
        db.commit()
        assert len(row.user) == 254 and row.action == "=bad thing" and len(row.fields) == 30 and row.kind == "action"
        assert user_activity.listing(db, "t")["total"] == 1
        assert user_activity.prune(db, "t") == 1
        db.commit()
        assert len(db.scalars(select(UserActivity)).all()) == 1
        rows = list(user_activity.csv_rows(db, "t"))
    assert audit_chain.to_csv(user_activity.CSV_COLUMNS, rows).splitlines()[1].split(",")[6] == "'=bad thing"


# ---------------------------------------------------------------------------------------------------------------------
# Support cases
# ---------------------------------------------------------------------------------------------------------------------


def test_support_requests_are_numbered_by_kind_and_their_limits_hold(env):
    make_user(env, "owner@acme.test")
    make_user(env, "jo@acme.test", role="viewer")
    tested_smtp(env)
    headers = sign_in(env, "jo@acme.test")
    client = env["client"]
    first = client.post("/support", headers=headers, json={"kind": "case", "subject": "S" * 300, "text": "T" * 20_000, "priority": "urgent"})
    assert first.status_code == 201, first.text
    r = first.json()["request"]
    assert r["id"] == "SUP-0001" and r["status"] == "new" and r["priority"] == "urgent"
    assert len(r["subject"]) == 200 and len(r["conversation"][0]["text"]) == 10_000
    enhancement = client.post("/support", headers=headers, json={"kind": "enhancement", "subject": "More", "text": "Please", "priority": "high"}).json()["request"]
    assert enhancement["id"] == "ENH-0001" and enhancement["priority"] == ""
    assert client.post("/support", headers=headers, json={"kind": "case", "subject": "S", "text": "T"}).json()["request"]["id"] == "SUP-0002"
    assert client.post("/support", headers=headers, json={"kind": "bug", "subject": "S", "text": "T"}).status_code == 400
    assert client.post("/support", headers=headers, json={"kind": "case", "subject": " ", "text": "T"}).json()["error"] == "Give it a short title."
    for _ in range(17):
        assert client.post("/support", headers=headers, json={"kind": "case", "subject": "S", "text": "T"}).status_code == 201
    too_many = client.post("/support", headers=headers, json={"kind": "case", "subject": "S", "text": "T"})
    assert too_many.status_code == 429 and too_many.json()["error"] == support_desk.TOO_MANY


def test_a_request_goes_through_its_statuses_with_an_email_at_every_step(env):
    make_user(env, "owner@acme.test")
    make_user(env, "admin@acme.test", role="admin")
    make_user(env, "jo@acme.test", role="viewer")
    make_user(env, "other@acme.test", role="viewer")
    make_user(env, "elsewhere@beta.test", tenant="beta")
    tested_smtp(env)
    jo, owner, other = sign_in(env, "jo@acme.test"), sign_in(env, "owner@acme.test"), sign_in(env, "other@acme.test")
    client, sent = env["client"], env["sent"]

    raised = client.post("/support", headers=jo, json={"kind": "case", "subject": "Connector stops", "text": "It stops at page 2."}).json()
    assert raised["emailed"] == {"sent": 3, "error": ""}
    assert {m["to"] for m in sent} == {"jo@acme.test", "owner@acme.test", "admin@acme.test"}
    to_jo = next(m for m in sent if m["to"] == "jo@acme.test")
    assert to_jo["subject"] == "[SUP-0001] Connector stops" and "Thank you: your support case is SUP-0001." in to_jo["text"]
    assert "https://hawk.example.test/help?open=SUP-0001" in to_jo["text"]
    assert next(m for m in sent if m["to"] == "owner@acme.test")["reply_to"] == "jo@acme.test"
    sent.clear()

    # Others see nothing of it; the team sees it in its queue.
    assert client.get("/support/SUP-0001", headers=other).status_code == 404
    assert client.get("/support", headers=other).json()["requests"] == []
    queue = client.get("/support", headers=owner).json()
    assert queue["team"] is True and [r["id"] for r in queue["requests"]] == ["SUP-0001"]
    assert client.get("/support", headers=sign_in(env, "elsewhere@beta.test")).json()["requests"] == []
    assert client.post("/support/SUP-0001/status", headers=jo, json={"status": "completed"}).status_code == 403

    waiting = client.post("/support/SUP-0001/messages", headers=owner, json={"text": "Which connector?"}).json()
    assert waiting["request"]["conversation"][-1]["team"] is True and [m["to"] for m in sent] == ["jo@acme.test"]
    assert "The support team answered on SUP-0001." in sent[-1]["text"] and sent[-1]["subject"] == "[SUP-0001] New message: Connector stops"
    sent.clear()
    moved = client.post("/support/SUP-0001/status", headers=owner, json={"status": "waiting"}).json()
    assert moved["request"]["status"] == "waiting" and [m["to"] for m in sent] == ["jo@acme.test"]
    assert sent[-1]["subject"] == "[SUP-0001] Waiting for reply: Connector stops"
    sent.clear()
    again = client.post("/support/SUP-0001/messages", headers=jo, json={"text": "The Slack one."}).json()
    assert again["request"]["status"] == "in-progress"
    assert {m["to"] for m in sent} == {"owner@acme.test", "admin@acme.test"}
    client.post("/support/SUP-0001/status", headers=owner, json={"status": "completed"})
    reopened = client.post("/support/SUP-0001/messages", headers=jo, json={"text": "It is back."}).json()["request"]
    assert reopened["status"] == "new"
    assert [h["status"] for h in reopened["history"]] == ["new", "waiting", "in-progress", "completed", "new"]
    assert client.post("/support/SUP-0001/status", headers=owner, json={"status": "lost"}).status_code == 400
    with env["db"]() as db:
        assert {"support.case", "support.status"} <= {r.action for r in db.scalars(select(AuditLog))}


def test_a_request_is_kept_when_the_email_server_is_not_tested(env):
    make_user(env, "jo@acme.test", role="viewer")
    headers = sign_in(env, "jo@acme.test")
    answer = env["client"].post("/support", headers=headers, json={"kind": "case", "subject": "S", "text": "T"})
    assert answer.status_code == 201
    assert answer.json()["emailed"]["sent"] == 0 and "not tested" in answer.json()["emailed"]["error"]
    assert env["sent"] == []
    with env["db"]() as db:
        assert db.get(SupportTicket, "SUP-0001") is not None


def test_a_conversation_is_full_at_five_hundred_messages(factory):
    with factory() as db:
        ticket = support_desk.create(db, kind="case", tenant_id="t", subject="S", text="T", requester={"id": "u", "email": "u@x.test"})
        ticket.messages = [{"at": "", "by": {}, "team": False, "text": "x"}] * 500
        with pytest.raises(support_desk.SupportError, match="This conversation is full"):
            support_desk.reply(db, ticket, by={"id": "u"}, team=False, text="one more")


def test_email_mode_sends_people_to_their_own_email_app(env, monkeypatch):
    make_user(env, "owner@acme.test")
    headers = sign_in(env, "owner@acme.test")
    client = env["client"]
    monkeypatch.setenv("SUPPORT_MODE", "email")
    monkeypatch.setenv("SUPPORT_EMAIL", "vendor@help.test")
    assert client.get("/support/settings", headers=headers).json() == {"mode": "email", "email": "vendor@help.test", "chosen": "email"}
    refused = client.post("/support", headers=headers, json={"kind": "case", "subject": "S", "text": "T"})
    assert refused.status_code == 409 and refused.json()["email"] == "vendor@help.test"
    href = client.get("/support/mailto/case", headers=headers).json()["href"]
    assert href.startswith("mailto:vendor@help.test?subject=Support%20case%3A%20") and "Hawk%20AI%20version" in href and "Tenant%3A%20Acme" in href
    # The page's choice wins over the environment; email without a valid address stays on the portal.
    assert client.put("/support/settings", headers=headers, json={"mode": "portal"}).json()["mode"] == "portal"
    assert client.post("/support", headers=headers, json={"kind": "case", "subject": "S", "text": "T"}).status_code == 201
    assert client.put("/support/settings", headers=headers, json={"email": "not-an-address"}).status_code == 400
    monkeypatch.delenv("SUPPORT_EMAIL")
    assert client.put("/support/settings", headers=headers, json={"mode": "email", "email": ""}).json()["mode"] == "portal"
    viewer = make_user(env, "v@acme.test", role="viewer")
    del viewer
    assert client.put("/support/settings", headers=sign_in(env, "v@acme.test"), json={"mode": "portal"}).status_code == 403


# ---------------------------------------------------------------------------------------------------------------------
# A local CA, servers that present its certificates, and a proxy
# ---------------------------------------------------------------------------------------------------------------------


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Zscaler Test")])


def make_ca(cn: str, issuer: tuple[x509.Certificate, Any] | None = None, *, aia: str = "") -> tuple[x509.Certificate, Any]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer[0].subject if issuer else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
    )
    if aia:
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]), critical=False)
    cert = builder.sign(issuer[1] if issuer else key, hashes.SHA256())
    return cert, key


def make_leaf(issuer: tuple[x509.Certificate, Any], *, aia: str = "") -> tuple[x509.Certificate, Any]:
    import ipaddress

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(issuer[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
    )
    if aia:
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]), critical=False)
    return builder.sign(issuer[1], hashes.SHA256()), key


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@contextmanager
def tls_server(tmp_path: Path, leaf: tuple[x509.Certificate, Any], chain: list[x509.Certificate] = ()):  # type: ignore[assignment]
    cert_file, key_file = tmp_path / f"leaf-{id(leaf)}.pem", tmp_path / f"leaf-{id(leaf)}.key"
    cert_file.write_bytes(pem(leaf[0]) + b"".join(pem(c) for c in chain))
    key_file.write_bytes(leaf[1].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=answer, args=(conn,), daemon=True).start()

    def answer(conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            with context.wrap_socket(conn, server_side=True) as secure:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = secure.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        thread.join(2)


@contextmanager
def http_proxy(answer_status: int = 200, *, need_auth: str = ""):
    """A forward proxy: CONNECT host:port answered with ``answer_status`` (or 407 without the expected basic sign-in);
    on 200 the bytes are passed both ways."""

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.2)
    stop = threading.Event()
    seen: list[str] = []

    def pipe(a: socket.socket, b: socket.socket) -> None:
        try:
            while True:
                chunk = a.recv(65536)
                if not chunk:
                    break
                b.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(conn: socket.socket) -> None:
        conn.settimeout(5)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                conn.close()
                return
            data += chunk
        head = data.split(b"\r\n\r\n")[0].decode("latin-1")
        seen.append(head)
        target = head.split(" ")[1]
        auth_ok = not need_auth or f"Proxy-Authorization: Basic {base64.b64encode(need_auth.encode()).decode()}" in head
        status = answer_status if auth_ok else 407
        if status != 200:
            reason = {403: "Forbidden", 407: "Proxy Authentication Required"}.get(status, "No")
            conn.sendall(f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n".encode())
            conn.close()
            return
        host, port = target.rsplit(":", 1)
        upstream = socket.create_connection((host, int(port)), timeout=5)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        conn.settimeout(None)
        upstream.settimeout(None)
        threading.Thread(target=pipe, args=(conn, upstream), daemon=True).start()
        threading.Thread(target=pipe, args=(upstream, conn), daemon=True).start()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}", seen
    finally:
        stop.set()
        listener.close()
        thread.join(2)


@contextmanager
def cert_host(certs: dict[str, x509.Certificate]):
    """A plain-http server that hands out certificates (DER), as a CA's "CA Issuers" address does."""

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            cert = certs.get(self.path)
            if cert is None:
                self.send_response(404)
                self.end_headers()
                return
            body = cert.public_bytes(serialization.Encoding.DER)
            self.send_response(200)
            self.send_header("Content-Type", "application/pkix-cert")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # noqa: ANN002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------------------------------------------------
# Network & proxy
# ---------------------------------------------------------------------------------------------------------------------


def test_a_proxy_is_cleaned_as_typed_and_carried_with_its_sign_in():
    assert network_proxy.clean_proxy(url="proxy.acme.local:8080", username=" u ", password="p@ss", no_proxy=".acme.local, 10.0.0.5;.acme.local") == {
        "url": "http://proxy.acme.local:8080",
        "username": "u",
        "password": "p@ss",
        "noProxy": ".acme.local,10.0.0.5",
    }
    assert network_proxy.clean_proxy(url="https://p")["url"] == "https://p:443"
    for bad, says in [("socks5://p:1080", "SOCKS"), ("http://u:p@p:80", "own fields"), ("p:80/path", "without a path"), ("p:99999", "host:port")]:
        with pytest.raises(network_proxy.NetworkError, match=says):
            network_proxy.clean_proxy(url=bad)
    with pytest.raises(network_proxy.NetworkError, match="Hosts that skip"):
        network_proxy.clean_proxy(url="p:80", no_proxy="bad host!")
    assert network_proxy.proxy_with_auth({"url": "http://p:8080", "username": "a b", "password": "p:@w"}) == "http://a%20b:p%3A%40w@p:8080"


def test_no_proxy_rules_and_what_each_process_gets(data_dir):
    assert network_proxy.bypasses("smtp.acme.local", ".acme.local") and network_proxy.bypasses("acme.local", ".acme.local")
    assert network_proxy.bypasses("x.acme.local", "*.acme.local") and network_proxy.bypasses("anything", "*")
    assert network_proxy.bypasses("postgres") and network_proxy.bypasses("localhost")
    assert not network_proxy.bypasses("graph.microsoft.com", ".acme.local,10.0.0.5")
    assert network_proxy.proxy_environment({}) == {}
    from_env = network_proxy.proxy_environment({"HTTPS_PROXY": "http://env:3128", "NO_PROXY": "corp.local"})
    assert from_env["HTTPS_PROXY"] == "http://env:3128" and from_env["NO_PROXY"].endswith(",corp.local") and "redis" in from_env["NO_PROXY"]
    network_proxy.save_network({"proxy": {"url": "http://saved:8080", "username": "u", "password": "pw", "noProxy": ".acme.local"}})
    file = data_dir / "network.json"
    assert file.stat().st_mode & 0o777 == 0o600 and not Path(f"{file}.bak").exists()
    env: dict[str, str] = {"HTTPS_PROXY": "http://env:3128"}
    network_proxy._applied["at_start"] = None  # noqa: SLF001 - a process starting
    added = network_proxy.apply_to_environment(env)
    assert added["HTTPS_PROXY"] == "http://u:pw@saved:8080" and env["https_proxy"] == "http://u:pw@saved:8080"
    assert network_proxy.proxy_for("graph.microsoft.com") == "http://u:pw@saved:8080" and network_proxy.proxy_for("x.acme.local") == ""
    assert network_proxy.active_proxy()["source"] == "settings" and network_proxy.active_proxy()["running"] is True
    network_proxy.save_network(None)
    assert not file.exists()
    assert network_proxy.active_proxy()["source"] == "environment"


def test_the_check_goes_step_by_step_through_the_proxy(tmp_path, data_dir):
    root = make_ca("Hawk Test Root")
    leaf = make_leaf(root)
    trust_store.store().add([root[0]], source="uploaded")
    with tls_server(tmp_path, leaf) as port:
        with http_proxy(200, need_auth="u:pw") as (proxy, seen):
            ok = network_proxy.check_route(proxy=proxy.replace("http://", "http://u:pw@"), host="localhost", port=port, timeout=5)
            assert ok["ok"] is True, ok
            assert [s["step"] for s in ok["steps"]] == ["proxy", "tunnel", "certificate", "answer"]
            assert seen[-1].startswith(f"CONNECT localhost:{port} HTTP/1.1")
            refused = network_proxy.check_route(proxy=proxy, host="localhost", port=port, timeout=5)
            assert [s["ok"] for s in refused["steps"]] == [True, False]
            assert refused["steps"][1]["status"] == 407 and "Proxy Authentication Required" in refused["steps"][1]["detail"]
        with http_proxy(403) as (proxy, _):
            forbidden = network_proxy.check_route(proxy=proxy, host="localhost", port=port, timeout=5)
            assert forbidden["steps"][-1]["step"] == "tunnel" and forbidden["steps"][-1]["status"] == 403
    unreachable = network_proxy.check_route(proxy="http://127.0.0.1:1", host="localhost", port=443, timeout=2)
    assert unreachable["steps"] == [{**unreachable["steps"][0], "step": "proxy", "ok": False}]
    assert "could not be reached" in unreachable["steps"][0]["detail"]


def test_an_untrusted_certificate_stops_the_check_at_the_certificate_step(tmp_path, data_dir):
    root = make_ca("Zscaler Root CA")
    leaf = make_leaf(root)
    with tls_server(tmp_path, leaf) as port:
        result = network_proxy.check_route(host="localhost", port=port, timeout=5)
    assert [s["step"] for s in result["steps"]] == ["tunnel", "certificate"]
    step = result["steps"][-1]
    assert step["ok"] is False and step["code"] == "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" and step["issuer"] == "Zscaler Root CA"


def test_a_proxy_is_saved_only_when_it_lets_the_service_through(env, tmp_path, data_dir):
    make_user(env, "owner@acme.test")
    headers = sign_in(env, "owner@acme.test")
    client = env["client"]
    root = make_ca("Hawk Test Root")
    trust_store.store().add([root[0]], source="uploaded")
    with tls_server(tmp_path, make_leaf(root)) as port:
        with http_proxy(403) as (proxy, _):
            refused = client.put("/network", headers=headers, json={"url": proxy, "target": f"localhost:{port}"})
            assert refused.status_code == 422 and refused.json()["error"] == "Not saved: the service could not be reached through this proxy."
            assert not (data_dir / "network.json").exists()
        with http_proxy(200) as (proxy, _):
            check = client.post("/network/check", headers=headers, json={"url": proxy, "target": f"localhost:{port}"}).json()
            assert check["ok"] is True and check["via"] == proxy
            saved = client.put("/network", headers=headers, json={"url": proxy, "username": "u", "password": "secret", "target": f"localhost:{port}", "noProxy": ".acme.local"})
            assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["restartRequired"] is True and body["proxy"]["source"] == "settings" and body["proxy"]["hasPassword"] is True
    assert "secret" not in json.dumps(body)
    assert "docker compose -f deploy/compose.yaml restart api worker beat" in body["restart"]
    assert json.loads((data_dir / "network.json").read_text())["proxy"]["password"] == "secret"
    # The same user, the password left blank: the saved one is kept.
    assert client.post("/network/check", headers=headers, json={"url": proxy, "username": "u", "target": "bad host"}).status_code == 400
    removed = client.delete("/network", headers=headers)
    assert removed.status_code == 200 and not (data_dir / "network.json").exists()
    assert client.delete("/network", headers=headers).status_code == 404
    with env["db"]() as db:
        reasons = [r.payload["reason"] for r in db.scalars(select(AuditLog).where(AuditLog.action == "settings.network"))]
    assert reasons[0] == f"Outgoing connections now go through the proxy {proxy}:{proxy.rsplit(':', 1)[1]} (signing in as u)." or reasons[0].startswith("Outgoing connections now go through the proxy http://127.0.0.1:")
    assert reasons[-1] == "Outgoing connections no longer go through the proxy set in Settings."
    viewer = make_user(env, "v@acme.test", role="viewer")
    del viewer
    assert client.get("/network", headers=sign_in(env, "v@acme.test")).status_code == 403


def test_the_network_sheet_lists_the_connectors_services(env, monkeypatch):
    from app.db.models.monitoring import Connector

    _, tenant = make_user(env, "owner@acme.test")
    headers = sign_in(env, "owner@acme.test")
    with env["db"]() as db:
        db.add(Connector(tenant_id=tenant, name="Slack", connector_type="slack", provider_key="slack", config={}))
        db.commit()
    info = env["client"].get("/network", headers=headers).json()
    rows = info["requirements"]
    slack = [r for r in rows if r["host"] == "slack.com"]
    assert slack and slack[0]["why"].startswith("A connector you set up")
    assert any(r["host"] == "graph.microsoft.com" and r["why"] == "Only if you connect it." for r in rows)
    assert any(r["host"] == "iam.checkmarx.net" for r in rows)
    assert any(r["what"] == "Email server" and r["route"].startswith("Direct") for r in rows)
    assert info["targets"] == [{"host": "slack.com", "port": 443}]
    assert info["text"].startswith("Network requirements for Hawk AI\n\nOutgoing web traffic goes directly")
    assert "- Outgoing to slack.com, port 443 (Direct): Slack." in info["text"]


# ---------------------------------------------------------------------------------------------------------------------
# Trusted certificates
# ---------------------------------------------------------------------------------------------------------------------


def test_trust_and_connect_trusts_only_the_root_that_was_shown(tmp_path, data_dir):
    root = make_ca("Zscaler Root CA")
    fetch = lambda url: trust_store.fetch_issuer(url, allow_loopback=True)  # noqa: E731
    with cert_host({"/root.cer": root[0]}) as base:
        leaf = make_leaf(root, aia=f"{base}/root.cer")
        with tls_server(tmp_path, leaf) as port:
            store = trust_store.store()
            found = store.diagnose("localhost", port, fetch=fetch)
            assert found["status"] == "needs-consent" and found["candidate"]["subject"] == "Zscaler Root CA"
            assert found["candidate"]["vendor"] == "Zscaler" and found["candidate"]["selfSigned"] is True
            with pytest.raises(trust_store.TrustError, match="no longer presents that certificate") as refused:
                store.trust_presented("localhost", port, "AA:BB", fetch=fetch)
            assert refused.value.status_code == 409
            done = store.trust_presented("localhost", port, found["candidate"]["fingerprint256"], by="owner@acme.test", fetch=fetch)
            assert done["status"] == "trusted" and [a["subject"] for a in done["added"]] == ["Zscaler Root CA"]
            # Applied at once: the next connection trusts it, with no restart.
            assert trust_store.inspect("localhost", port)["authorized"] is True
            listed = store.list()
            assert listed[0]["source"] == "detected" and listed[0]["addedBy"] == "owner@acme.test" and listed[0]["host"] == "localhost"
            assert (data_dir / "trust" / "bundle.pem").exists()
            assert store.remove(found["candidate"]["fingerprint256"])["subject"] == "Zscaler Root CA"
            assert trust_store.inspect("localhost", port)["authorized"] is False
            assert not (data_dir / "trust" / "bundle.pem").exists()


def test_a_left_out_intermediate_is_fetched_and_kept_when_a_trusted_root_vouches(tmp_path, data_dir):
    root = make_ca("Public Test Root")
    with cert_host({}) as base:
        intermediate = make_ca("Issuing CA 1", root)
        leaf = make_leaf(intermediate, aia=f"{base}/inter.cer")
        store = trust_store.store()
        store.add([root[0]], source="uploaded")
        fetch_calls: list[str] = []

        def fetch(url: str) -> x509.Certificate:
            fetch_calls.append(url)
            assert url == f"{base}/inter.cer"
            return intermediate[0]

        with tls_server(tmp_path, leaf) as port:
            assert trust_store.inspect("localhost", port)["error"] == "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
            done = store.diagnose("localhost", port, fetch=fetch)
            assert done["status"] == "repaired" and [a["subject"] for a in done["added"]] == ["Issuing CA 1"]
            assert store.list()[0]["source"] == "intermediate"
            assert trust_store.inspect("localhost", port)["authorized"] is True


def test_an_upload_keeps_only_what_the_failing_chain_needs(tmp_path, data_dir):
    root = make_ca("Company Root")
    other = make_ca("Someone Else")
    leaf = make_leaf(root)
    bundle = pem(other[0]) + pem(root[0])
    with tls_server(tmp_path, leaf) as port:
        chain = trust_store.inspect("localhost", port)["chain"]
        store = trust_store.store()
        with pytest.raises(trust_store.TrustError, match='issued by "Company Root"'):
            store.upload(pem(other[0]), chain=chain, host="localhost")
        added = store.upload(bundle, chain=chain, host="localhost", by="a@b.test")
        assert [a["subject"] for a in added] == ["Company Root"]
        assert trust_store.inspect("localhost", port)["authorized"] is True
    with pytest.raises(trust_store.TrustError, match="holds no certificate"):
        store.upload(b"nothing")
    with pytest.raises(trust_store.TrustError, match="not a certificate authority"):
        store.upload(pem(leaf[0]))
    der = base64.b64encode(other[0].public_bytes(serialization.Encoding.DER)).decode()
    assert [a["subject"] for a in store.upload(der)] == ["Someone Else"]


def test_the_trust_routes_audit_every_change(env, tmp_path, data_dir):
    make_user(env, "owner@acme.test")
    headers = sign_in(env, "owner@acme.test")
    client = env["client"]
    root = make_ca("Company Root")
    uploaded = client.post("/trust/upload", headers=headers, json={"data": pem(root[0]).decode()})
    assert uploaded.status_code == 200 and uploaded.json()["added"][0]["subject"] == "Company Root"
    fp = uploaded.json()["added"][0]["fingerprint256"]
    assert client.get("/trust", headers=headers).json()["certificates"][0]["fingerprint256"] == fp
    assert client.post("/trust/upload", headers=headers, json={"data": ""}).status_code == 400
    assert client.post("/trust/diagnose", headers=headers, json={"host": "169.254.169.254"}).status_code == 400
    with tls_server(tmp_path, make_leaf(root)) as port:
        assert client.post("/trust/diagnose", headers=headers, json={"host": "localhost", "port": port}).json()["status"] == "trusted"
    assert client.delete(f"/trust/{fp}", headers=headers).json()["certificates"] == []
    assert client.delete(f"/trust/{fp}", headers=headers).status_code == 404
    with env["db"]() as db:
        reasons = [r.payload["reason"] for r in db.scalars(select(AuditLog).where(AuditLog.action == "settings.trust").order_by(AuditLog.seq))]
    assert reasons == ['Trusted uploaded certificate: "Company Root".', 'No longer trusts the certificate "Company Root".']


# ---------------------------------------------------------------------------------------------------------------------
# The SSRF guard
# ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url, problem",
    [
        ("http://example.com/x", "must be an https address"),
        ("https://169.254.169.254/latest/meta-data", "link-local or cloud metadata"),
        ("https://metadata.google.internal/", "link-local or cloud metadata"),
        ("https://[::ffff:a9fe:a9fe]/", "link-local or cloud metadata"),
        ("https://[fe80::1]/", "link-local or cloud metadata"),
        ("https://100.100.100.200/", "link-local or cloud metadata"),
        ("https://168.63.129.16/", "link-local or cloud metadata"),
        ("https://0.0.0.0/", "link-local or cloud metadata"),
        ("https://user:pw@example.com/", "user name or password"),
        ("not a url", "is not a web address"),
        ("https://example.com/", ""),
        ("https://10.0.0.5/", ""),
        ("http://localhost:8080/", ""),
    ],
)
def test_outbound_addresses_must_be_https_and_never_metadata(url, problem):
    found = outbound_url.outbound_url_problem(url)
    assert (problem in found and found) if problem else found == ""
    if problem:
        with pytest.raises(outbound_url.OutboundUrlError):
            outbound_url.check_outbound_url(url)


def test_issuer_links_are_never_followed_to_metadata_or_this_machine():
    for url in ("http://169.254.169.254/x.cer", "http://metadata/x", "ftp://ca.test/x.cer", "http://127.0.0.1/x.cer"):
        with pytest.raises(trust_store.TrustError, match="is not followed"):
            trust_store.fetch_issuer(url, resolver=lambda host: ["10.0.0.1"])
    with pytest.raises(trust_store.TrustError, match="local, link-local or metadata"):
        trust_store.fetch_issuer("http://rebind.test/x.cer", resolver=lambda host: ["169.254.169.254"])
    assert trust_store.followable_address("10.1.2.3") and not trust_store.followable_address("::ffff:127.0.0.1")


def test_credentialed_calls_refuse_metadata_names_and_go_through_the_proxy_when_one_is_set(data_dir):
    policy = OutboundDestinationPolicy({"s": ["https://metadata.google.internal", "https://api.example.test"]}, resolver=lambda host, port: ["93.184.216.34"])
    with pytest.raises(OutboundDestinationPolicyError, match="non_public_address"):
        policy.validate("https://metadata.google.internal/x", source="s")
    direct = policy.validate("https://api.example.test/v1", source="s")
    assert direct.proxy == "" and direct.addresses == ("93.184.216.34",)
    with http_proxy(403, need_auth="u:p w") as (proxy, seen):
        network_proxy.use_proxy(proxy.replace("http://", "http://u:p%20w@"), "")
        through = policy.validate("https://api.example.test/v1", source="s")
        assert through.proxy and through.addresses == ()
        transport = PinnedHTTPTransport(through)
        with httpx.Client(transport=transport, timeout=5) as client:
            with pytest.raises(httpx.ProxyError):
                client.get("https://api.example.test/v1")
    assert seen and seen[-1].startswith("CONNECT api.example.test:443 HTTP/1.1")


# ---------------------------------------------------------------------------------------------------------------------
# Connector API activity
# ---------------------------------------------------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}


class FakeClient:
    def __init__(self, status_code: int = 200, error: Exception | None = None, **kwargs: Any) -> None:
        self.status_code, self.error = status_code, error

    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        if self.error:
            raise self.error
        return FakeResponse(self.status_code)


def test_each_connector_call_is_recorded_without_its_query(factory):
    policy = OutboundDestinationPolicy({"monitoring:slack": ["https://slack.com"]}, resolver=lambda host, port: ["93.184.216.34"])
    with connector_activity.connector_scope(tenant_id="t1", connector="Slack", connector_id="c1"):
        request_with_redirect_validation("GET", "https://slack.com/api/team.accessLogs?token=SECRET&count=5", source="monitoring:slack", policy=policy, client_factory=lambda **kw: FakeClient(200), transport_factory=lambda d, verify=True: None)
        with pytest.raises(RuntimeError):
            request_with_redirect_validation("POST", "https://slack.com/api/x", source="monitoring:slack", policy=policy, client_factory=lambda **kw: FakeClient(error=RuntimeError("boom https://slack.com/api/x?token=SECRET")), transport_factory=lambda d, verify=True: None)
    request_with_redirect_validation("GET", "https://slack.com/api/y", source="monitoring:slack", policy=policy, client_factory=lambda **kw: FakeClient(503), transport_factory=lambda d, verify=True: None)
    with factory() as db:
        rows = db.scalars(select(ConnectorCall).order_by(ConnectorCall.at)).all()
    assert [(r.tenant_id, r.connector, r.connector_id, r.method, r.host, r.path, r.status, r.ok) for r in rows] == [
        ("t1", "Slack", "c1", "GET", "slack.com", "/api/team.accessLogs", 200, True),
        ("t1", "Slack", "c1", "POST", "slack.com", "/api/x", None, False),
        (None, "monitoring:slack", None, "GET", "slack.com", "/api/y", 503, False),
    ]
    assert "SECRET" not in json.dumps([connector_activity.view(r) for r in rows]) and rows[1].error.startswith("RuntimeError: boom https://slack.com/api/x")
    assert all(r.ms is not None for r in rows)


def test_opaque_path_segments_are_hidden_and_httpx_hooks_record(factory):
    assert connector_activity.safe_path("https://API.example.test/v1/" + "a" * 48 + "/items?x=1#f") == ("api.example.test", "/v1/…/items")
    hooks = connector_activity.httpx_hooks("discovery source")
    transport = httpx.MockTransport(lambda request: httpx.Response(201))
    with connector_activity.connector_scope(tenant_id="t2", connector="Drive"):
        with httpx.Client(transport=transport, event_hooks=hooks) as client:
            client.get("https://www.googleapis.com/drive/v3/files?pageToken=abc")
    with factory() as db:
        row = db.scalars(select(ConnectorCall)).one()
    assert (row.tenant_id, row.connector, row.host, row.path, row.status) == ("t2", "Drive", "www.googleapis.com", "/drive/v3/files", 201)


def test_recording_never_fails_the_call(monkeypatch):
    def broken() -> Any:
        raise RuntimeError("no database")

    monkeypatch.setattr(connector_activity, "session_factory", broken)
    connector_activity.record_call("GET", "https://x.test/", status=200, ms=1.0)


def test_the_connector_activity_page_lists_filters_sums_up_and_exports(env):
    _, tenant = make_user(env, "owner@acme.test")
    headers = sign_in(env, "owner@acme.test")
    now = dt.datetime.now(dt.timezone.utc)
    with connector_activity.connector_scope(tenant_id=tenant, connector="Slack"):
        connector_activity.record_call("GET", "https://slack.com/api/a", status=200, ms=100, now=now - dt.timedelta(minutes=2))
        connector_activity.record_call("GET", "https://slack.com/api/b", status=429, ms=300, now=now - dt.timedelta(minutes=1))
    with connector_activity.connector_scope(tenant_id=tenant, connector="=Evil"):
        connector_activity.record_call("GET", "https://graph.microsoft.com/v1.0/users", status=200, ms=50, now=now)
    with connector_activity.connector_scope(tenant_id="other-tenant", connector="Slack"):
        connector_activity.record_call("GET", "https://slack.com/api/c", status=200, ms=1, now=now)
    client = env["client"]
    page = client.get("/connector-activity", headers=headers).json()
    assert [e["path"] for e in page["events"]] == ["/v1.0/users", "/api/b", "/api/a"]
    assert page["summary"] == {"calls": 3, "avgMs": 150, "failed": 1, "connectors": 2, "hosts": 2}
    assert page["connectors"] == ["=Evil", "Slack"] and page["hosts"] == ["graph.microsoft.com", "slack.com"]
    assert [e["path"] for e in client.get("/connector-activity?connector=Slack&outcome=failed", headers=headers).json()["events"]] == ["/api/b"]
    assert [e["path"] for e in client.get(f"/connector-activity?before={page['events'][0]['at']}", headers=headers).json()["events"]] == ["/api/b", "/api/a"]
    exported = client.get("/connector-activity/export.csv", headers=headers).text.splitlines()
    assert exported[0] == "When,Connector,Method,Host,Path,Status,ms,Error" and len(exported) == 4
    assert ",'=Evil," in exported[3]


def test_a_connector_run_records_its_calls_for_its_tenant(factory, monkeypatch):
    from app.db.models.monitoring import Connector
    from app.services import monitoring_service

    seen: list[dict[str, Any] | None] = []

    def pull(**kwargs: Any) -> Any:
        seen.append(connector_activity.current_scope())
        raise RuntimeError("stop after the pull")

    monkeypatch.setattr(monitoring_service, "run_provider_pull", pull)
    monkeypatch.setattr(monitoring_service, "validate_monitoring_connector_destination", lambda **kw: None)
    monkeypatch.setattr(monitoring_service, "decrypt_connector_secrets", lambda value: {})
    with factory() as db:
        tenant = Tenant(name="T", slug="t", is_active=True)
        db.add(tenant)
        db.flush()
        connector = Connector(tenant_id=tenant.id, name="Slack prod", connector_type="slack", provider_key="slack", config={})
        db.add(connector)
        db.flush()
        with pytest.raises(RuntimeError):
            monitoring_service.run_connector_once(db, tenant_id=tenant.id, connector=connector)
    assert seen == [{"tenant_id": tenant.id, "connector": "Slack prod", "connector_id": connector.id, "user_id": None}]
    assert connector_activity.current_scope() is None


def test_the_audit_key_is_backed_up_with_the_data_folder_and_the_cli_checks_every_chain(factory, data_dir, monkeypatch, capsys):
    from app.cli import audit_verify
    from app.services import backup_archive

    with factory() as db:
        audit(db)
        db.commit()
    names = [name for name, _ in backup_archive.collect_data_files(data_dir)]
    assert "data/audit.key" in names
    monkeypatch.setattr(audit_verify, "SessionLocal", factory)
    assert audit_verify.main() == 0
    assert "system: 1 entries, intact" in capsys.readouterr().out
    with factory() as db:
        db.execute(text("UPDATE audit_logs SET action = 'edited'"))
        db.commit()
    assert audit_verify.main() == 1
    assert "entry 1: Contents changed after it was written." in capsys.readouterr().out
