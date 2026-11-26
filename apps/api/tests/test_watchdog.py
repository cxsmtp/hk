"""The self-healing watchdog and hands-off, ported from CxMissionZero (src/watchdog.js, src/routes/hands-off.js,
src/hands-off.js, src/action-links.js, src/connection-guard.js, src/mail-inbox.js readReplies): each check, each repair
tried once per problem, never a rollback for an outage on the far side, the email sequence, when a support case is
raised, the signed links (expiry, tampering), the reply commands against a fake inbox, and the state kept on disk."""

from __future__ import annotations

import datetime as dt
import email
import email.policy
import json
import socket
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.routers import hands_off as hands_off_router
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.audit import AuditLog
from app.db.models.job_run import ScheduledJobRun
from app.db.models.monitoring import Connector
from app.db.models.platform_records import SupportTicket
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import account_security, action_links, audit_chain, error_counter, hands_off, mail_inbox, mailer, network_proxy, trust_store
from app.services.checkmarx_one_service import CheckmarxAuthError
from app.services.connection_guard import ConnectionGuard
from app.services.control_plane_health_service import CELERY_BEAT_HEARTBEAT_KEY, CELERY_WORKER_HEARTBEAT_KEY
from app.services.self_check import SelfCheck, inbox_every_seconds, watchdog_every_seconds
from app.services.watchdog import Watchdog, outside_fault, rollback_target, should_notify, should_raise_case

PASSWORD = "correct-Horse-2026"
T0 = dt.datetime(2026, 11, 25, 10, 0, tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------------------------------------------------------------
# Fakes and fixtures
# ---------------------------------------------------------------------------------------------------------------------


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {}
        self.down = False
        beat = str(time.time())
        self.values[CELERY_WORKER_HEARTBEAT_KEY] = beat
        self.values[CELERY_BEAT_HEARTBEAT_KEY] = beat

    def ping(self) -> bool:
        if self.down:
            raise ConnectionRefusedError("Connection refused")
        return True

    def get(self, key: str) -> Any:
        return self.values.get(key)

    def mget(self, keys: list[str]) -> list[Any]:
        return [self.values.get(k) for k in keys]

    def incr(self, key: str) -> int:
        self.values[key] = int(self.values.get(key) or 0) + 1
        return self.values[key]

    def expire(self, key: str, seconds: int) -> None:  # noqa: ARG002
        return None


class FakeUpdates:
    def __init__(self) -> None:
        self.auto = True
        self.last_check: dict[str, Any] | None = {"at": T0.isoformat().replace("+00:00", "Z"), "error": "", "versions": []}
        self.installed: list[tuple[str, str]] = []

    def settings(self) -> dict[str, Any]:
        return {"auto": self.auto}

    def status(self) -> dict[str, Any]:
        return {"updateAvailable": False, "latest": None}

    def install(self, ref: str, *, by: str = "") -> dict[str, Any]:
        self.installed.append((ref, by))
        return {"requested": {"id": "x"}, "version": ref}


class Clock:
    def __init__(self, at: dt.datetime = T0) -> None:
        self.at = at

    def __call__(self) -> dt.datetime:
        return self.at

    def tick(self, minutes: int = 5) -> None:
        self.at += dt.timedelta(minutes=minutes)


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setattr(settings, "hawk_data_dir", str(folder))
    audit_chain.forget_key()
    trust_store._context_cache.clear()  # noqa: SLF001
    network_proxy.use_proxy("", "")
    monkeypatch.setitem(network_proxy._applied, "at_start", {})  # noqa: SLF001
    yield folder
    audit_chain.forget_key()


@pytest.fixture()
def factory(tmp_path, data_dir):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'watchdog.sqlite3'}", connect_args={"check_same_thread": False, "timeout": 30})
    Base.metadata.create_all(bind=engine)
    made = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    yield made
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture()
def world(factory, data_dir, tmp_path, monkeypatch):
    """A tested email server, an https address, two administrators and a member, and a self-check whose outside world
    is fake."""

    monkeypatch.setattr(settings, "web_origin", "https://hawk.example.test")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_from", "hawk@example.test")
    monkeypatch.setattr(settings, "smtp_user", "hawk@example.test")
    monkeypatch.setattr(settings, "smtp_pass", "smtp-secret")
    sent: list[dict[str, Any]] = []

    def send(message, to):  # noqa: ANN001
        attachments = [(part.get_filename(), part.get_content()) for part in message.iter_attachments()]
        sent.append({"to": to, "subject": str(message["Subject"]), "text": message.get_body(("plain",)).get_content(), "attachments": attachments})

    with factory() as db:
        tenant = Tenant(name="Acme", slug="acme", is_active=True)
        db.add(tenant)
        db.flush()
        for address, role in (("owner@acme.test", "owner"), ("admin@acme.test", "admin"), ("member@acme.test", "viewer")):
            user = User(email=address, full_name=address.split("@")[0], hashed_password=get_password_hash(PASSWORD), is_active=True)
            db.add(user)
            db.flush()
            db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
        account_security.policy(db).smtp_verified = mailer.fingerprint()
        db.commit()
        tenant_id = tenant.id

    updater = tmp_path / "updater"
    updater.mkdir()
    state: dict[str, Any] = {"smtp": None, "checkmarx": {}, "sleeps": [], "runs": 0, "replies": []}
    redis = FakeRedis()
    updates = FakeUpdates()
    clock = Clock()

    def test_smtp() -> None:
        if state["smtp"] is not None:
            raise state["smtp"]

    def probe(connector) -> None:  # noqa: ANN001
        error = state["checkmarx"].get(json.dumps(connector.config, sort_keys=True))
        if error is not None:
            raise error

    def make(**overrides: Any) -> SelfCheck:
        options: dict[str, Any] = dict(
            data_dir=data_dir,
            session_factory=factory,
            send=send,
            probe_checkmarx=probe,
            test_smtp=test_smtp,
            redis_factory=lambda: redis,
            read_replies=lambda account: list(state["replies"]),
            updates=updates,
            updater_dir=updater,
            version="0.3.0",
            sleep=lambda seconds: state["sleeps"].append(seconds),
            enqueue_run=lambda: state.__setitem__("runs", state["runs"] + 1),
            now=clock,
            zone=dt.timezone.utc,
            env={"MAINTAINER_EMAIL": "maintainer@example.test"},
        )
        options.update(overrides)
        return SelfCheck(**options)

    yield {"make": make, "sent": sent, "db": factory, "state": state, "redis": redis, "updates": updates, "clock": clock, "tenant": tenant_id, "updater": updater, "data_dir": data_dir}


def subjects(world) -> list[tuple[str, str]]:
    return [(m["to"], m["subject"]) for m in world["sent"]]


def add_runs(world, job: str, *statuses: str) -> None:
    with world["db"]() as db:
        for i, status in enumerate(statuses):
            at = T0 - dt.timedelta(hours=len(statuses) - i)
            db.add(ScheduledJobRun(job_name=job, started_at=at, finished_at=at, status=status, error_message="disk full" if status != "success" else None))
        db.commit()


def add_checkmarx(world, config: dict[str, Any] | None = None) -> str:
    with world["db"]() as db:
        row = Connector(tenant_id=world["tenant"], name="CX", connector_type="checkmarx", provider_key="checkmarx", config=config or {"tenant_name": "acme", "region": "us"}, encrypted_secrets="enc-1")
        db.add(row)
        db.commit()
        return row.id


def http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://ast.checkmarx.net/api/projects")
    return httpx.HTTPStatusError(f"{status}", request=request, response=httpx.Response(status, request=request))


def updater_switched(world, *, at: dt.datetime, previous: str = "0.2.0", running: str = "0.3.0", manages: bool = True) -> None:
    folder: Path = world["updater"]
    (folder / "events.jsonl").write_text(json.dumps({"at": at.isoformat().replace("+00:00", "Z"), "type": "switch", "action": "update", "from": previous, "to": running}) + "\n")
    (folder / "updater.json").write_text(json.dumps({"at": world["clock"]().isoformat().replace("+00:00", "Z"), "manages": manages}))


def heartbeat(world, manages: bool = True) -> None:
    """The updater's heartbeat, fresh at the fake clock's time."""

    (world["updater"] / "updater.json").write_text(json.dumps({"at": world["clock"]().isoformat().replace("+00:00", "Z"), "manages": manages}))


# ---------------------------------------------------------------------------------------------------------------------
# The bookkeeping (src/watchdog.js)
# ---------------------------------------------------------------------------------------------------------------------


def test_problems_start_continue_and_recover_and_the_notes_are_kept_on_disk(tmp_path):
    file = tmp_path / "watchdog.json"
    w = Watchdog(file=file)
    first = w.record([{"key": "smtp", "title": "Email server", "detail": "refused"}], version="0.3.0", now=T0)
    assert [p["key"] for p in first["started"]] == ["smtp"] and first["recovered"] == []
    again = Watchdog(file=file).record([{"key": "smtp", "title": "Email server", "detail": "still refused"}], version="0.3.0", now=T0 + dt.timedelta(minutes=5))
    assert again["continuing"][0]["checks"] == 2 and again["continuing"][0]["detail"] == "still refused"
    w = Watchdog(file=file)
    w.tried("smtp", "Tried the mail server again after a pause", "did not help")
    w.mark_notified("smtp")
    w.mark_case("smtp", "SUP-0001")
    w = Watchdog(file=file)
    assert w.problem("smtp")["tried"] == ["Tried the mail server again after a pause"] and w.problem("smtp")["caseId"] == "SUP-0001"
    cleared = w.record([], version="0.3.0", now=T0 + dt.timedelta(minutes=10))
    assert cleared["recovered"][0]["key"] == "smtp" and cleared["recovered"][0]["caseId"] == "SUP-0001"
    assert Watchdog(file=file).was_healthy("0.3.0") and not Watchdog(file=file).was_healthy("0.2.0")
    kinds = [e["kind"] for e in Watchdog(file=file).events()]
    assert kinds == ["recovered", "tried", "problem"]
    assert file.stat().st_mode & 0o777 == 0o600


def test_a_damaged_state_file_starts_the_self_check_afresh(tmp_path):
    file = tmp_path / "watchdog.json"
    file.write_text("{not json")
    w = Watchdog(file=file)
    assert w.problems() == [] and w.state["lastCheckAt"] == ""
    w.record([], version="1.0.0", now=T0)
    assert json.loads(file.read_text())["healthy"] == {"1.0.0": "2026-11-25T10:00:00.000Z"}


def test_events_are_capped_at_200(tmp_path):
    w = Watchdog(file=tmp_path / "watchdog.json")
    for i in range(250):
        w.event("tried", f"event {i}")
    assert len(Watchdog(file=tmp_path / "watchdog.json").events(1000)) == 200


def test_tell_after_two_checks_and_a_case_after_three_only_with_auto_update_and_the_internet():
    p = {"checks": 1, "notifiedAt": "", "caseId": ""}
    assert not should_notify(p)
    p["checks"] = 2
    assert should_notify(p) and not should_raise_case(p, auto_update=True, online=True)
    p["notifiedAt"] = "x"
    assert not should_notify(p)
    p["checks"] = 3
    assert should_raise_case(p, auto_update=True, online=True)
    assert not should_raise_case(p, auto_update=False, online=True)
    assert not should_raise_case(p, auto_update=True, online=False)
    p["caseId"] = "SUP-0001"
    assert not should_raise_case(p, auto_update=True, online=True)


@pytest.mark.parametrize(
    "error, outside",
    [
        (http_error(503), True),
        (http_error(502), True),
        (http_error(429), True),
        (http_error(401), False),
        (http_error(403), False),
        (http_error(404), False),
        (httpx.ConnectTimeout("timed out"), True),
        (httpx.ConnectError("unreachable"), True),
        (ConnectionRefusedError("refused"), True),
        (socket.timeout("timed out"), True),
        (socket.gaierror("name"), True),
        (ValueError("bad config"), False),
        (None, False),
    ],
)
def test_an_outage_on_the_far_side_is_told_from_a_refusal(error, outside):
    assert outside_fault(error) is outside


def test_a_sign_in_refused_by_checkmarx_one_counts_only_when_it_is_not_an_outage():
    refused = CheckmarxAuthError("Authentication failed (401): invalid_grant")
    refused.http_status = 401
    down = CheckmarxAuthError("Authentication failed (503): unavailable")
    down.http_status = 503
    assert not outside_fault(refused) and outside_fault(down)
    try:
        try:
            raise socket.timeout("timed out")
        except OSError as cause:
            raise mailer.MailError("The mail server could not be reached") from cause
    except mailer.MailError as wrapped:
        assert outside_fault(wrapped)


def _target(**overrides: Any) -> str:
    since = "2026-11-25T09:00:00.000Z"
    base: dict[str, Any] = dict(
        problems=[{"key": "smtp", "checks": 2, "outside": False, "since": since}],
        running="0.3.0",
        previous="0.2.0",
        switched_at="2026-11-25T08:00:00.000Z",
        was_healthy=lambda v: v == "0.2.0",
        has_rolled_back=lambda v: False,
        now=T0,
    )
    base.update(overrides)
    return rollback_target(**base)


def test_a_version_that_broke_what_worked_goes_back_only_within_a_day_and_never_for_an_outage():
    assert _target() == "0.2.0"
    assert _target(problems=[{"key": "cx", "checks": 5, "outside": True, "since": "2026-11-25T09:00:00.000Z"}]) == ""
    assert _target(problems=[{"key": "smtp", "checks": 1, "outside": False, "since": "2026-11-25T09:00:00.000Z"}]) == ""
    assert _target(problems=[{"key": "smtp", "checks": 2, "outside": False, "since": "2026-11-25T07:00:00.000Z"}]) == ""
    assert _target(switched_at="2026-11-24T09:59:00.000Z") == ""
    assert _target(was_healthy=lambda v: False) == ""
    assert _target(has_rolled_back=lambda v: v == "0.3.0") == ""
    assert _target(previous="") == "" and _target(previous="0.3.0") == ""


# ---------------------------------------------------------------------------------------------------------------------
# Each check
# ---------------------------------------------------------------------------------------------------------------------


def keys(result: dict[str, Any]) -> list[str]:
    return sorted(p["key"] for p in result["problems"])


def test_all_checks_pass_on_a_healthy_server(world):
    check = world["make"]()
    assert check.run()["problems"] == []
    assert check.health_view()["lastCheckAt"] == "2026-11-25T10:00:00.000Z"
    assert check.watchdog.was_healthy("0.3.0")


def test_the_machines_own_checks_from_the_installer_are_shown_with_the_self_check(world):
    """deploy/install.sh writes host-check.json (CIS Linux items, reported only) into the updater folder."""

    check = world["make"]()
    assert check.health_view()["host"] is None
    (Path(world["updater"]) / "host-check.json").write_text(
        json.dumps(
            {
                "checkedAt": "2026-11-26T10:00:00Z",
                "by": "deploy/install.sh",
                "checks": [
                    {"id": "firewall", "status": "pass", "title": "Firewall", "detail": "ufw is active."},
                    {"id": "auditd", "status": "warn", "title": "Audit daemon", "detail": "auditd is not running."},
                    {"id": "odd", "status": "maybe", "title": "Not a check", "detail": ""},
                ],
            }
        ),
        encoding="utf-8",
    )
    host = check.health_view()["host"]
    assert host["checkedAt"] == "2026-11-26T10:00:00Z"
    assert [(c["id"], c["status"]) for c in host["checks"]] == [("firewall", "pass"), ("auditd", "warn")]
    (Path(world["updater"]) / "host-check.json").write_text("not json", encoding="utf-8")
    assert check.health_view()["host"] is None


def test_the_database_redis_worker_and_beat_are_checked(world):
    from unittest.mock import MagicMock

    db = MagicMock()
    db.execute.side_effect = RuntimeError("connection refused")
    assert [p["key"] for p in world["make"]().liveness_problems(db)] == ["database"]
    world["redis"].values[CELERY_BEAT_HEARTBEAT_KEY] = str(time.time() - 3600)
    del world["redis"].values[CELERY_WORKER_HEARTBEAT_KEY]
    found = world["make"]().run()
    assert keys(found) == ["beat", "worker"]
    world["redis"].down = True
    assert keys(world["make"]().run()) == ["redis"]


def test_the_email_server_is_checked_only_once_set_up_and_tested(world):
    world["state"]["smtp"] = mailer.MailError("The server rejected that username and password.")
    assert keys(world["make"]().run()) == ["smtp"]
    with world["db"]() as db:
        account_security.policy(db).smtp_verified = ""
        db.commit()
    assert keys(world["make"]().run()) == []


def test_a_checkmarx_one_connector_is_asked_one_small_question(world):
    add_checkmarx(world)
    world["state"]["checkmarx"][json.dumps({"region": "us", "tenant_name": "acme"}, sort_keys=True)] = http_error(401)
    result = world["make"]().run()
    assert keys(result)[0].startswith("checkmarx:")
    problem = result["problems"][0]
    assert problem["tenant"] == world["tenant"] and problem["outside"] is False and "Checkmarx One connection (CX)" == problem["title"]
    world["state"]["checkmarx"].clear()
    world["state"]["checkmarx"][json.dumps({"region": "us", "tenant_name": "acme"}, sort_keys=True)] = http_error(503)
    problem = world["make"]().run()["problems"][0]
    assert problem["outside"] is True and "on Checkmarx One's side" in problem["detail"]


def test_two_failed_automatic_runs_in_a_row_are_a_problem_and_one_is_not(world):
    add_runs(world, "scheduled_backup", "success", "fail")
    add_runs(world, "monitoring_cycle_15m", "fail", "success")
    assert keys(world["make"]().run()) == []
    add_runs(world, "monitoring_cycle_hourly", "fail", "fail")
    result = world["make"]().run()
    assert keys(result) == ["runs:monitoring_cycle_hourly"] and result["problems"][0]["detail"] == "disk full"


def test_more_than_30_errors_in_15_minutes_is_a_problem(world):
    now = time.time()
    for _ in range(30):
        error_counter.note(world["redis"], now=now)
    assert error_counter.recent(world["redis"], now=now) == 30
    assert keys(world["make"]().run()) == []
    error_counter.note(world["redis"], now=now)
    assert keys(world["make"]().run()) == ["errors"]
    assert error_counter.recent(world["redis"], now=now + 16 * 60) == 0


def test_errors_are_counted_from_the_apis_error_handler(monkeypatch):
    noted: list[int] = []
    monkeypatch.setattr(error_counter, "note", lambda *a, **k: noted.append(1))

    @app.get("/__boom_for_watchdog_test")
    def boom():  # pragma: no cover - raises
        raise RuntimeError("boom")

    try:
        answer = TestClient(app, raise_server_exceptions=False).get("/__boom_for_watchdog_test")
        assert answer.status_code == 500 and noted == [1]
    finally:
        app.router.routes = [r for r in app.router.routes if getattr(r, "path", "") != "/__boom_for_watchdog_test"]


def test_reading_replies_failing_three_times_is_a_problem(world):
    hands_off.save({"on": True, "replies": True}, world["data_dir"])

    def broken(account):  # noqa: ANN001
        raise mail_inbox.MailboxError(mail_inbox.NO_STARTTLS)

    check = world["make"](read_replies=broken)
    for _ in range(2):
        check.inbox_tick()
    assert keys(world["make"]().run()) == []
    check.inbox_tick()
    result = world["make"]().run()
    assert keys(result) == ["inbox"] and "STARTTLS" in result["problems"][0]["detail"]
    world["make"]().inbox_tick()  # a good read clears the count
    assert keys(world["make"]().run()) == []


# ---------------------------------------------------------------------------------------------------------------------
# Repairs: each once while the problem lasts
# ---------------------------------------------------------------------------------------------------------------------


def test_the_mail_server_is_tried_again_after_a_pause_once_per_problem(world):
    world["state"]["smtp"] = mailer.MailError("refused")
    for _ in range(4):
        world["make"]().run()
        world["clock"].tick()
    assert world["state"]["sleeps"] == [10]
    problem = Watchdog(file=world["data_dir"] / "watchdog.json").problem("smtp")
    assert problem["tried"] == ["Tried the mail server again after a pause"] and problem["checks"] == 4
    # Cleared, then back: a new problem, so the repair is tried again.
    world["state"]["smtp"] = None
    world["make"]().run()
    world["state"]["smtp"] = mailer.MailError("refused")
    world["make"]().run()
    assert world["state"]["sleeps"] == [10, 10]


def test_a_repair_that_works_closes_the_problem_at_once(world):
    world["state"]["smtp"] = mailer.MailError("refused")
    calls = {"n": 0}

    def flaky() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise mailer.MailError("refused")

    result = world["make"](test_smtp=flaky).run()
    assert result["problems"] == []
    events = [e["message"] for e in Watchdog(file=world["data_dir"] / "watchdog.json").events()]
    assert "Email server: fixed by itself." in events and "Tried the mail server again after a pause: fixed." in events


def test_a_changed_checkmarx_connection_that_does_not_work_is_put_back_once(world):
    connector_id = add_checkmarx(world)
    world["make"]().run()  # works: remembered as the last good settings
    assert ConnectionGuard(world["data_dir"]).last_good(connector_id)["config"] == {"tenant_name": "acme", "region": "us"}
    with world["db"]() as db:
        row = db.get(Connector, connector_id)
        row.config = {"tenant_name": "typo", "region": "us"}
        row.encrypted_secrets = "enc-2"
        db.commit()
    world["state"]["checkmarx"][json.dumps({"region": "us", "tenant_name": "typo"}, sort_keys=True)] = http_error(401)
    result = world["make"]().run()
    assert result["problems"] == []
    with world["db"]() as db:
        row = db.get(Connector, connector_id)
        assert row.config == {"tenant_name": "acme", "region": "us"} and row.encrypted_secrets == "enc-1"
        assert db.scalar(select(AuditLog).where(AuditLog.action == "selfcheck.connection_restored")) is not None


def test_signing_in_to_checkmarx_one_again_is_tried_once_while_it_lasts(world):
    add_checkmarx(world)
    world["state"]["checkmarx"][json.dumps({"region": "us", "tenant_name": "acme"}, sort_keys=True)] = http_error(401)
    for _ in range(3):
        world["make"]().run()
        world["clock"].tick()
    problem = Watchdog(file=world["data_dir"] / "watchdog.json").problems()[0]
    assert problem["tried"] == ["Signed in to Checkmarx One again"]
    tries = [e for e in Watchdog(file=world["data_dir"] / "watchdog.json").events(100) if e["kind"] == "tried"]
    assert len(tries) == 1


# ---------------------------------------------------------------------------------------------------------------------
# Who is told, and when
# ---------------------------------------------------------------------------------------------------------------------


def test_the_administrators_hear_after_two_checks_then_a_case_after_three_then_working_again(world):
    world["state"]["smtp"] = None
    add_runs(world, "scheduled_backup", "fail", "fail")
    world["make"]().run()
    assert world["sent"] == []
    world["clock"].tick()
    world["make"]().run()
    assert sorted(subjects(world)) == [
        ("admin@acme.test", f"Hawk AI needs attention: Scheduled backups [{action_links.reply_reference('admin@acme.test')}]"),
        ("owner@acme.test", f"Hawk AI needs attention: Scheduled backups [{action_links.reply_reference('owner@acme.test')}]"),
    ]
    assert "member@acme.test" not in [to for to, _ in subjects(world)]
    assert "If it lasts, Hawk AI raises a support case" in world["sent"][0]["text"]
    world["sent"].clear()
    world["clock"].tick()
    world["make"]().run()
    with world["db"]() as db:
        ticket = db.scalar(select(SupportTicket))
        assert ticket.id == "SUP-0001" and ticket.subject == "[Automatic] Scheduled backups" and ticket.priority == "high"
        assert ticket.requester_name == "Hawk AI (automatic)" and ticket.tenant_id == world["tenant"]
    assert len(world["sent"]) == 2
    mail = world["sent"][0]
    assert mail["subject"].startswith("[SUP-0001] Hawk AI needs the maintainer: Scheduled backups")
    assert "forward this email, with its attachment, to maintainer@example.test" in mail["text"]
    assert "never sends anything outside your network" in mail["text"]
    assert "/hands-off/confirm#a=" in mail["text"] and "https://hawk.example.test/help?open=SUP-0001" in mail["text"]
    name, content = mail["attachments"][0]
    assert name == "hawk-ai-SUP-0001-troubleshooting.json"
    log = json.loads(content)
    assert log["selfCheck"]["problem"]["title"] == "Scheduled backups" and "smtp-secret" not in json.dumps(log)
    # One case per problem.
    world["sent"].clear()
    world["clock"].tick()
    world["make"]().run()
    assert world["sent"] == []
    with world["db"]() as db:
        assert len(db.scalars(select(SupportTicket)).all()) == 1
    # It clears: the case says so, and whoever was told hears it.
    add_runs(world, "scheduled_backup", "success")
    with world["db"]() as db:
        db.add(ScheduledJobRun(job_name="scheduled_backup", started_at=T0 + dt.timedelta(hours=1), finished_at=T0 + dt.timedelta(hours=1), status="success"))
        db.commit()
    world["clock"].tick()
    world["make"]().run()
    assert sorted(s for _, s in subjects(world))[0].startswith("Hawk AI is working again: Scheduled backups")
    assert "Mark as solved: https://hawk.example.test/hands-off/confirm#a=" in world["sent"][0]["text"]
    with world["db"]() as db:
        ticket = db.get(SupportTicket, "SUP-0001")
        assert ticket.messages[-1]["text"].startswith("Working again since") and ticket.messages[-1]["team"] is True


def test_a_repair_that_fixes_a_problem_already_told_says_it_fixed_itself(world):
    world["state"]["smtp"] = mailer.MailError("refused")
    world["make"]().run()
    world["clock"].tick()
    world["make"]().run()  # told (the email server itself is down: the fake send still records)
    world["sent"].clear()
    # A new problem on the same key cannot be re-tried; give the check a working repair by clearing the tried list.
    w = Watchdog(file=world["data_dir"] / "watchdog.json")
    w._state["problems"]["smtp"]["tried"] = []  # noqa: SLF001
    w._save()  # noqa: SLF001
    calls = {"n": 0}

    def flaky() -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise mailer.MailError("refused")

    world["clock"].tick()
    world["make"](test_smtp=flaky).run()
    assert [s for _, s in subjects(world)][0].startswith("Hawk AI fixed itself: Email server")


@pytest.mark.parametrize("auto, check_error, age_days", [(False, "", 0), (True, "registry unreachable", 0), (True, "", 3)])
def test_no_case_without_auto_update_or_the_internet(world, auto, check_error, age_days):
    world["updates"].auto = auto
    world["updates"].last_check = {"at": (T0 - dt.timedelta(days=age_days)).isoformat().replace("+00:00", "Z"), "error": check_error}
    add_runs(world, "scheduled_backup", "fail", "fail")
    for _ in range(4):
        world["make"]().run()
        world["clock"].tick()
    with world["db"]() as db:
        assert db.scalars(select(SupportTicket)).all() == []
    assert all("raises a support case" not in m["text"] for m in world["sent"])


def test_no_email_goes_out_before_the_email_server_is_tested(world):
    with world["db"]() as db:
        account_security.policy(db).smtp_verified = ""
        db.commit()
    add_runs(world, "scheduled_backup", "fail", "fail")
    for _ in range(3):
        world["make"]().run()
        world["clock"].tick()
    assert world["sent"] == []


# ---------------------------------------------------------------------------------------------------------------------
# Going back a version
# ---------------------------------------------------------------------------------------------------------------------


def _broken_after_update(world, *, outside: bool) -> None:
    w = Watchdog(file=world["data_dir"] / "watchdog.json")
    w._state["healthy"]["0.2.0"] = "2026-11-24T10:00:00.000Z"  # noqa: SLF001
    w._save()  # noqa: SLF001
    updater_switched(world, at=T0 - dt.timedelta(hours=2))
    if outside:
        add_checkmarx(world)
        world["state"]["checkmarx"][json.dumps({"region": "us", "tenant_name": "acme"}, sort_keys=True)] = http_error(503)
    else:
        add_runs(world, "scheduled_backup", "fail", "fail")


def test_a_new_version_that_broke_what_worked_goes_back_once_through_the_updater(world):
    _broken_after_update(world, outside=False)
    world["make"]().run()
    assert world["updates"].installed == []
    world["clock"].tick()
    heartbeat(world)
    world["make"]().run()
    assert world["updates"].installed == [("0.2.0", "self-check")]
    assert any(s.startswith("Hawk AI went back to HK-00.02.00") for _, s in subjects(world))
    for _ in range(3):
        world["clock"].tick()
        heartbeat(world)
        world["make"]().run()
    assert world["updates"].installed == [("0.2.0", "self-check")]
    with world["db"]() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "selfcheck.rollback")) is not None


def test_an_outage_on_the_far_side_never_rolls_back(world):
    _broken_after_update(world, outside=True)
    for _ in range(4):
        heartbeat(world)
        world["make"]().run()
        world["clock"].tick()
    assert world["updates"].installed == []


def test_no_rollback_when_the_updater_does_not_look_after_the_services(world):
    _broken_after_update(world, outside=False)
    updater_switched(world, at=T0 - dt.timedelta(hours=2), manages=False)
    for _ in range(3):
        heartbeat(world, manages=False)
        world["make"]().run()
        world["clock"].tick()
    assert world["updates"].installed == []


# ---------------------------------------------------------------------------------------------------------------------
# Signed links and the "Yes, do it" page
# ---------------------------------------------------------------------------------------------------------------------


def test_a_link_is_signed_expires_after_30_days_and_cannot_be_changed():
    token = action_links.sign_action("pause", "Owner@Acme.test", now=1_000_000)
    payload = action_links.read_action(token, now=1_000_000 + 29 * 86_400)
    assert payload["a"] == "pause" and payload["e"] == "owner@acme.test"
    assert action_links.read_action(token, now=1_000_000 + 30 * 86_400 + 1) is None
    body, sig = token.split(".")
    forged = action_links._b64({**payload, "a": "stop"})  # noqa: SLF001
    assert action_links.read_action(f"{forged}.{sig}", now=1_000_000) is None
    assert action_links.read_action(f"{body}.{sig[:-1]}x", now=1_000_000) is None
    assert action_links.read_action(f"{body}.{sig}.extra", now=1_000_000) is None
    assert action_links.read_action("", now=1_000_000) is None
    with pytest.raises(ValueError):
        action_links.sign_action("delete-everything", "a@b.c")


def test_the_reply_reference_belongs_to_one_address():
    ref = action_links.reply_reference("Owner@Acme.test")
    assert ref.startswith("HKR-") and len(ref) == 16 and ref == action_links.reply_reference("owner@acme.test")
    assert ref != action_links.reply_reference("admin@acme.test")
    assert action_links.find_references(f"Re: Hawk AI this week [{ref}] [{ref}]") == [ref]


@pytest.fixture()
def api(world, factory):
    def override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    hands_off_router._factory["self_check"] = world["make"]  # noqa: SLF001
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()
        app.dependency_overrides.clear()
        hands_off_router._factory.clear()  # noqa: SLF001


def sign_in(client, address: str) -> dict[str, str]:
    answer = client.post("/auth/login", json={"email": address, "password": PASSWORD})
    assert answer.status_code == 200, answer.text
    tokens = answer.json()
    return {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}


def test_opening_a_link_only_asks_and_yes_do_it_acts(world, api):
    hands_off.save({"on": True, "statusTo": ["lead@acme.test"]}, world["data_dir"])
    token = action_links.sign_action("pause", "lead@acme.test", now=T0.timestamp())
    shown = api.post("/hands-off/link", json={"token": token})
    assert shown.status_code == 200 and shown.json()["title"] == "Pause the weekly status for 7 days?" and shown.json()["confirm"] == "Yes, do it"
    assert shown.headers["cache-control"] == "no-store"
    assert hands_off.load(world["data_dir"])["pausedUntil"] == ""
    done = api.post("/hands-off/link/confirm", json={"token": token})
    assert done.status_code == 200 and done.json()["title"] == "Done" and done.json()["message"].startswith("Paused")
    assert hands_off.load(world["data_dir"])["pausedUntil"] == "2026-12-02T10:00:00.000Z"
    expired = action_links.sign_action("resume", "lead@acme.test", now=T0.timestamp() - 31 * 86_400)
    assert api.post("/hands-off/link", json={"token": expired}).json()["title"] == "This link has expired"
    assert api.post("/hands-off/link/confirm", json={"token": expired}).status_code == 404


def test_a_link_for_someone_no_longer_allowed_does_nothing(world, api):
    token = action_links.sign_action("pause", "stranger@else.test", now=T0.timestamp())
    refused = api.post("/hands-off/link/confirm", json={"token": token})
    assert refused.status_code == 403 and refused.json()["title"] == "Not done"
    assert hands_off.load(world["data_dir"])["pausedUntil"] == ""


def test_the_hands_off_page_is_for_owners_and_admins(world, api):
    member = sign_in(api, "member@acme.test")
    assert api.get("/hands-off", headers=member).status_code == 403
    admin = sign_in(api, "admin@acme.test")
    page = api.get("/hands-off", headers=admin).json()
    assert page["ready"] == {"smtp": True, "serverUrl": True} and page["handsOff"]["on"] is False and page["health"]["everyMinutes"] == 5
    saved = api.put("/hands-off", headers=admin, json={"handsOff": {"statusTo": "lead@acme.test, nope", "statusDay": 5, "statusHour": 9, "replies": True}}).json()
    assert saved["handsOff"]["on"] is True and saved["handsOff"]["statusTo"] == ["lead@acme.test"] and saved["handsOff"]["statusDay"] == 5
    assert api.put("/hands-off", headers=admin, json={"handsOff": {"statusHour": 24}}).status_code == 400
    sent = api.post("/hands-off/status", headers=admin).json()
    assert sent == {"sent": 1} and world["sent"][-1]["subject"].startswith("Hawk AI this week [HKR-")
    checked = api.post("/hands-off/check", headers=admin).json()
    assert checked["health"]["lastCheckAt"] and api.get("/hands-off/health", headers=admin).json()["health"]["problems"] == []
    off = api.put("/hands-off", headers=admin, json={"handsOff": {"on": False}}).json()
    assert off["handsOff"]["on"] is False
    with world["db"]() as db:
        reasons = [r.payload["reason"] for r in db.scalars(select(AuditLog).where(AuditLog.action == "hands_off.settings"))]
    assert reasons[0].startswith("Hands-off turned on") and reasons[-1].startswith("Hands-off turned off")


# ---------------------------------------------------------------------------------------------------------------------
# The weekly status
# ---------------------------------------------------------------------------------------------------------------------


def test_the_weekly_status_goes_out_on_its_day_and_hour_once(world):
    # 2026-11-25 is a Wednesday (3); the status is on Wednesdays at 11:00. Never sent before: it goes out now (MZ).
    hands_off.save({"on": True, "statusTo": ["lead@acme.test"], "statusDay": 3, "statusHour": 11}, world["data_dir"])
    assert world["make"]().status_tick() == 1
    assert world["make"]().status_tick() == 0
    world["clock"].at = T0.replace(hour=10, minute=58)
    assert world["make"]().status_tick() == 0
    world["clock"].at = T0.replace(hour=11, minute=2)
    assert world["make"]().status_tick() == 1
    assert world["make"]().status_tick() == 0
    mail = world["sent"][0]
    assert "Hawk AI ran on its own this week" in mail["text"] and "Health: all checks pass" in mail["text"]
    assert "Run the checks now: https://hawk.example.test/hands-off/confirm#a=" in mail["text"] and "Pause for 7 days" in mail["text"]
    assert "Or reply to this email with one word: PAUSE, RESUME, RUN, STATUS, STOP." in mail["text"]
    world["clock"].at = T0 + dt.timedelta(days=7, hours=1, minutes=5)
    hands_off.save({"pausedUntil": "2026-12-31T00:00:00Z"}, world["data_dir"])
    assert world["make"]().status_tick() == 0


def test_status_due_follows_the_day_and_hour():
    h = hands_off.merge_hands_off({}, {"on": True, "statusTo": ["a@b.co"], "statusDay": 1, "statusHour": 8})
    monday_9 = dt.datetime(2026, 11, 23, 9, tzinfo=dt.timezone.utc)
    assert hands_off.status_due(h, monday_9, dt.timezone.utc)
    assert not hands_off.status_due({**h, "lastStatusAt": "2026-11-23T08:00:00Z"}, monday_9, dt.timezone.utc)
    assert hands_off.status_due({**h, "lastStatusAt": "2026-11-16T08:00:00Z"}, monday_9, dt.timezone.utc)
    assert not hands_off.status_due({**h, "on": False}, monday_9, dt.timezone.utc)


def test_hands_off_settings_are_checked_and_kept_on_disk(tmp_path):
    saved = hands_off.save({"statusTo": "A@b.co; bad; c@d.io", "imapHost": "imap.acme.test", "imapPort": 143}, tmp_path)
    assert saved["statusTo"] == ["a@b.co", "c@d.io"] and hands_off.load(tmp_path)["imapPort"] == 143
    for bad in ({"statusDay": 7}, {"statusHour": -1}, {"imapHost": "imap acme"}, {"imapPort": 0}, {"statusDay": True}):
        with pytest.raises(hands_off.HandsOffError):
            hands_off.merge_hands_off({}, bad)
    assert (tmp_path / "hands-off.json").stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------------------------------------------------------------
# Replies: one word, from the address the email went to
# ---------------------------------------------------------------------------------------------------------------------


def reply(sender: str, text: str, subject: str = "Re: Hawk AI this week") -> dict[str, str]:
    return {"from": sender, "subject": f"{subject} [{action_links.reply_reference(sender)}]", "text": text}


@pytest.mark.parametrize(
    "text, parsed",
    [
        ("PAUSE", {"command": "pause", "days": 7}),
        ("pause 14\n\nthanks", {"command": "pause", "days": 14}),
        ("PAUSE 200", {"command": "pause", "days": 90}),
        ("PAUSE 0", {"command": "pause", "days": 7}),
        ("Resume please", {"command": "resume"}),
        ("RUN", {"command": "run"}),
        ("status", {"command": "status"}),
        ("STOP", {"command": "stop"}),
        ("Solved, thanks", {"command": "solved"}),
        ("unsubscribe", {"command": "stop"}),
        ("> PAUSE", None),
        ("On Mon, Nov 23 Hawk wrote:\nPAUSE", None),
        ("Hello, can you pause?", None),
        ("", None),
    ],
)
def test_only_the_first_word_above_the_quote_counts(text, parsed):
    assert hands_off.parse_command(text) == parsed


def test_reply_commands_act_for_the_right_address_only(world):
    hands_off.save({"on": True, "replies": True, "statusTo": ["lead@acme.test"]}, world["data_dir"])
    check = world["make"]()
    assert check.handle_reply(reply("lead@acme.test", "PAUSE 14")).startswith("Paused: no weekly status until 2026-12-09")
    assert check.handle_reply(reply("lead@acme.test", "RESUME")).startswith("Resumed")
    assert check.handle_reply(reply("lead@acme.test", "RUN")) == "The monitoring checks that are due are on their way." and world["state"]["runs"] == 1
    assert check.handle_reply(reply("lead@acme.test", "STATUS")) == "The status is on its way to you."
    assert check.handle_reply(reply("lead@acme.test", "STOP")) == "You will not get the weekly status any more."
    assert hands_off.load(world["data_dir"])["statusTo"] == []
    # Each answered with one line.
    answers = [m for m in world["sent"] if m["subject"].startswith("Re: ")]
    assert len(answers) == 5 and answers[0]["text"].startswith("Paused")
    # Someone else, even with the same subject: ignored.
    stolen = {**reply("lead@acme.test", "PAUSE"), "from": "mallory@evil.test"}
    assert check.handle_reply(stolen) == ""
    # Auto-replies, bounces and our own address: never answered.
    assert check.handle_reply(reply("lead@acme.test", "PAUSE", subject="Automatic reply: Hawk AI this week")) == ""
    assert check.handle_reply(reply("mailer-daemon@acme.test", "PAUSE")) == ""
    assert check.handle_reply(reply("hawk@example.test", "PAUSE")) == ""
    # A member who is neither on the status list nor an administrator is told no.
    assert check.handle_reply(reply("member@acme.test", "PAUSE")).startswith("Not done: This address may no longer steer Hawk AI")
    with world["db"]() as db:
        assert len(db.scalars(select(AuditLog).where(AuditLog.action == "hands_off.command")).all()) == 5


def test_no_status_is_sent_before_the_email_server_is_tested(world):
    hands_off.save({"on": True, "statusTo": ["lead@acme.test"]}, world["data_dir"])
    with world["db"]() as db:
        account_security.policy(db).smtp_verified = ""
        db.commit()
    token = action_links.sign_action("status", "lead@acme.test", now=T0.timestamp())
    answer = world["make"]().follow_link(token)
    assert answer["ok"] is False and answer["status"] == 409
    assert world["make"]().status_tick() == 0 and world["sent"] == []


def test_solved_closes_the_case_for_an_administrator_only(world):
    with world["db"]() as db:
        from app.services import support_desk

        ticket = support_desk.create(db, kind="case", tenant_id=world["tenant"], subject="[Automatic] Email server", text="x", priority="high", requester={"id": "system", "name": "Hawk AI (automatic)"})
        db.commit()
        ticket_id = ticket.id
    w = Watchdog(file=world["data_dir"] / "watchdog.json")
    w.record([{"key": "smtp", "title": "Email server", "detail": "x"}], now=T0)
    w.mark_case("smtp", ticket_id)
    check = world["make"]()
    subject = f"Re: [{ticket_id}] Hawk AI needs the maintainer"
    assert check.handle_reply(reply("member@acme.test", "SOLVED", subject=subject)).startswith("Not done: Only an administrator")
    assert check.handle_reply(reply("admin@acme.test", "SOLVED", subject=subject)) == f"{ticket_id} is closed. Thank you."
    with world["db"]() as db:
        assert db.get(SupportTicket, ticket_id).status == "completed"
    assert Watchdog(file=world["data_dir"] / "watchdog.json").problem("smtp")["caseId"] == ""


def test_the_inbox_is_read_only_when_hands_off_and_replies_are_on(world):
    world["state"]["replies"] = [reply("lead@acme.test", "PAUSE")]
    hands_off.save({"on": True, "replies": False, "statusTo": ["lead@acme.test"]}, world["data_dir"])
    assert world["make"]().inbox_tick() == 0
    hands_off.save({"replies": True}, world["data_dir"])
    assert world["make"]().inbox_tick() == 1
    assert hands_off.load(world["data_dir"])["pausedUntil"]


class FakeImap:
    """An IMAP server with two unread messages: a reply, and one with an attachment."""

    def __init__(self, messages: dict[bytes, bytes]) -> None:
        self.messages = messages
        self.calls: list[tuple] = []
        self.seen: list[bytes] = []

    def login(self, user, password):  # noqa: ANN001
        self.calls.append(("login", user))
        return "OK", [b""]

    def select(self, box, readonly=False):  # noqa: ANN001
        self.calls.append(("select", box, readonly))
        return "OK", [b"2"]

    def uid(self, command, *args):  # noqa: ANN001
        self.calls.append(("uid", command, *args))
        if command == "SEARCH":
            return "OK", [b" ".join(self.messages)]
        if command == "FETCH":
            return "OK", [(b"1 (UID 1 BODY[]<0> {100}", self.messages[args[0]]), b")"]
        if command == "STORE":
            self.seen.extend(args[0].split(b","))
            return "OK", [b""]
        return "NO", []

    def logout(self):
        return "BYE", [b""]


def test_read_replies_keeps_the_sender_subject_and_text_and_marks_them_read():
    plain = b"From: Lead <Lead@Acme.test>\r\nSubject: Re: Hawk AI this week [HKR-abc]\r\nContent-Type: text/plain\r\n\r\nPAUSE 3\r\n> quoted\r\n"
    with_attachment = (
        b"From: a@acme.test\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n"
        b"--X\r\nContent-Type: text/html\r\n\r\n<p>STATUS</p><blockquote>old</blockquote>\r\n"
        b"--X\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=evil.bin\r\n\r\nAAAA\r\n--X--\r\n"
    )
    server = FakeImap({b"1": plain, b"2": with_attachment})
    found = mail_inbox.read_replies(mail_inbox.MailboxAccount(host="imap.acme.test", user="hawk", password="pw"), connect=lambda account: server)
    assert found[0] == {"from": "lead@acme.test", "subject": "Re: Hawk AI this week [HKR-abc]", "text": "PAUSE 3\n> quoted\n"}
    assert found[1]["from"] == "a@acme.test" and found[1]["text"].strip() == "STATUS"
    assert server.seen == [b"1", b"2"] and ("uid", "SEARCH", None, "UNSEEN") in server.calls


def test_a_mailbox_error_never_carries_the_password():
    def broken(account):  # noqa: ANN001
        raise OSError(f"login failed for {account.password}")

    with pytest.raises(mail_inbox.MailboxError) as raised:
        mail_inbox.read_replies(mail_inbox.MailboxAccount(host="imap.acme.test", user="hawk", password="s3cret-pw"), connect=broken)
    assert "s3cret-pw" not in str(raised.value)


# ---------------------------------------------------------------------------------------------------------------------
# The schedule, and the runs it watches
# ---------------------------------------------------------------------------------------------------------------------


def test_it_runs_every_300_seconds_and_reads_replies_every_120():
    from app.jobs import watchdog_schedule
    from app.jobs.celery_app import celery_app

    assert watchdog_every_seconds({}) == 300 and inbox_every_seconds({}) == 120
    entries = watchdog_schedule.beat_entries({})
    assert entries["self-check"]["schedule"].run_every == dt.timedelta(seconds=300)
    assert entries["hands-off-replies"]["schedule"].run_every == dt.timedelta(seconds=120)
    assert entries["hands-off-weekly-status"]["schedule"].run_every == dt.timedelta(minutes=5)
    assert watchdog_schedule.beat_entries({"WATCHDOG_EVERY_SECONDS": "60"})["self-check"]["schedule"].run_every == dt.timedelta(seconds=60)
    assert {"self-check", "hands-off-replies", "hands-off-weekly-status"} <= set(celery_app.conf.beat_schedule)


def test_a_scheduled_backup_records_its_run(monkeypatch):
    from app.jobs import backup_jobs

    written: list[dict[str, Any]] = []
    monkeypatch.setattr("app.services.job_run_service.write_scheduled_job_run", lambda **kw: written.append(kw))
    backup_jobs.record_run({"ok": False, "error": "disk full"}, T0)
    backup_jobs.record_run({"ok": True}, T0)
    assert [(w["job_name"], w["status"], w["error_message"]) for w in written] == [("scheduled_backup", "fail", "disk full"), ("scheduled_backup", "success", None)]


def test_the_system_email_carries_the_reference_and_how_to_reply():
    message = hands_off.system_email(subject="Hawk AI this week", lines=["x"], buttons=[("Mark as solved", "https://h/a")], reference="HKR-abcdefabcdef")
    parsed = email.message_from_bytes(message.as_bytes(), policy=email.policy.default)
    assert parsed["Subject"] == "Hawk AI this week [HKR-abcdefabcdef]"
    body = parsed.get_body(("plain",)).get_content()
    assert "PAUSE, RESUME, RUN, STATUS, STOP, SOLVED." in body and "Hawk AI reference: HKR-abcdefabcdef" in body
