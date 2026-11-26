"""Hands-off and self-healing, ported from CxMissionZero's src/routes/hands-off.js (registerHandsOff): Hawk AI's own
emails (the weekly status, the one-click links, the replies it reads from the mailbox) and the self-check that looks,
repairs and tells the administrators. The bookkeeping is app/services/watchdog.py; the settings app/services/
hands_off.py; the links app/services/action_links.py. Beat runs it (app/jobs/watchdog_jobs.py): the self-check every
WATCHDOG_EVERY_SECONDS (300), the replies every INBOX_EVERY_SECONDS (120), the weekly status's turn every 5 minutes.

The checks (MZ's, adapted to Hawk AI):
  - each Checkmarx One connector: it signs in and asks one small question (MZ's Checkmarx One check);
  - each other connector with a health call (the monitoring connectors that sign in and read over HTTP): it signs in
    with the connector's own credentials and makes the first read of its pull, keeping nothing;
  - the email server, once set up and tested: it connects and signs in, but sends nothing;
  - reading replies, when it failed three times in a row;
  - the automatic runs Hawk AI relies on (backups, the monitoring checks, the daily snapshot pack): did the last two
    fail? (MZ: the automatic reminders);
  - more than 30 errors in 15 minutes (counted in Redis, app/services/error_counter.py);
  - and what Hawk AI needs that MZ does not have: the database, Redis, the worker's and the scheduler's heartbeats.

The repairs, each tried once while a problem lasts: put back the last working connection (a Checkmarx One connector
changed since it last worked, app/services/connection_guard.py), sign in to Checkmarx One again, try the mail server
again after a pause, and go back to the previous version (through the updater) when one that came in less than a day
ago broke what worked, never for an outage on the far side.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import json
import logging
import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.log_config import recent_error_lines
from app.services import action_links, error_counter, hands_off, mailer, support_desk
from app.services.connection_guard import ConnectionGuard
from app.services.state_file import read_state, write_state
from app.services.watchdog import (
    FILE_NAME as WATCHDOG_FILE,
    Watchdog,
    outside_fault,
    parse_iso,
    rollback_target,
    should_notify,
    should_raise_case,
)
from app.version import PACKAGE_VERSION, display_version

log = logging.getLogger("hawk.self_check")

ERRORS_PER_15_MIN = 30
INBOX_FAILURES_FILE = "hands-off-inbox.json"
LOCK_FILE = "watchdog.lock"
APP_NAME = "Hawk AI"
AUTOMATIC = {"id": "system", "name": "Hawk AI (automatic)", "email": ""}
#: The automatic runs Hawk AI relies on, by the name their runs are recorded under (scheduled_job_runs), and what a
#: person calls them (MZ looks at its automatic reminders).
WATCHED_RUNS = {
    "scheduled_backup": "Scheduled backups",
    "monitoring_cycle_15m": "Monitoring checks (every 15 minutes)",
    "monitoring_cycle_hourly": "Monitoring checks (hourly)",
    "monitoring_cycle_daily": "Monitoring checks (daily)",
    "daily_snapshot_pack": "Daily snapshot pack",
}
FAILED_RUN = ("fail", "failed", "dead_letter")
#: What RUN (and the button) starts: the monitoring checks Hawk AI runs on its own (MZ: its automatic reminders).
RUN_TASK = "app.jobs.monitoring_jobs.run_monitoring_15m_checks"
#: Never answered: auto-replies, out-of-office messages and bounces, so mail cannot loop.
AUTOMATIC_MAIL = re.compile(r"auto(matic)?[ -]?(reply|response)|out of (the )?office|undeliverable|delivery status|mailer-daemon", re.IGNORECASE)

ACTION_TITLES = {
    "pause": "Pause the weekly status for 7 days?",
    "resume": "Resume Hawk AI's weekly status?",
    "run": "Run the monitoring checks that are due now?",
    "status": "Email me the status now?",
    "stop": "Stop sending me the weekly status?",
    "solved": "Mark this case as solved?",
}
EXPIRED = ("This link has expired", "Links in Hawk AI emails work for 30 days. The next email has fresh ones.")


def every_seconds(name: str, default: int, env: Any = None) -> int:
    env = os.environ if env is None else env
    try:
        return max(5, int(float(str(env.get(name) or default))))
    except ValueError:
        return default


def watchdog_every_seconds(env: Any = None) -> int:
    return every_seconds("WATCHDOG_EVERY_SECONDS", 300, env)


def inbox_every_seconds(env: Any = None) -> int:
    return every_seconds("INBOX_EVERY_SECONDS", 120, env)


def maintainer_email(env: Any = None) -> str:
    """Where automatic cases are forwarded (MZ's MAINTAINER_EMAIL). No default: Hawk AI names nobody in its code."""

    env = os.environ if env is None else env
    return str(env.get("MAINTAINER_EMAIL") or "").strip()


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _when(iso: Any) -> str:
    return str(iso or "")[:16].replace("T", " ") + " UTC" if iso else ""


class Refused(Exception):
    """A request refused on purpose: its words are for the person who asked (MZ's error.status)."""

    def __init__(self, message: str, status_code: int = 403) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def _default_session_factory() -> Callable[[], Session]:
    from app.db.session import SessionLocal

    return SessionLocal


def _default_send(message: Any, to: str) -> None:
    mailer.send(message, to)


def _probe_checkmarx(connector: Any) -> None:
    """One small question to Checkmarx One with the connector's own key: a connector that exists is not one that
    works (MZ asks for one project)."""

    from app.services.checkmarx_one_service import CheckmarxAuthError, create_client_from_connector_config
    from app.services.connector_secret_service import decrypt_connector_secrets

    client = create_client_from_connector_config(dict(connector.config or {}), decrypt_connector_secrets(connector.encrypted_secrets or ""))
    try:
        client.authenticate()
        client.list_projects(limit=1)
    except CheckmarxAuthError as error:
        # "Authentication failed (503): …": what the far side answered decides whether it is on that side.
        found = re.search(r"\((\d{3})\)", str(error))
        if found:
            error.http_status = int(found.group(1))  # type: ignore[attr-defined]
        raise


def _probe_connector(connector: Any) -> None:
    """The other connectors that have a health call (app/services/integration_connector_service.py
    check_connector_health): they sign in with their own credentials and make the first read of their pull."""

    from app.services.connector_secret_service import decrypt_connector_secrets
    from app.services.integration_connector_service import check_connector_health

    check_connector_health(provider_key=str(connector.provider_key), connector_config=dict(connector.config or {}), secrets=decrypt_connector_secrets(connector.encrypted_secrets or ""))


def _redis_factory() -> Any | None:
    if (os.getenv("TEST_PROFILE") or "").strip().lower() == "unit":
        return None
    from app.services.control_plane_health_service import _redis_client

    return _redis_client()


class SelfCheck:
    """Everything the self-check and hands-off do. What reaches outside (mail, Checkmarx One, Redis, the updater, the
    clock) can be handed in, for the tests."""

    def __init__(
        self,
        *,
        data_dir: Path | str | None = None,
        session_factory: Callable[[], Session] | None = None,
        send: Callable[[Any, str], None] | None = None,
        probe_checkmarx: Callable[[Any], None] = _probe_checkmarx,
        probe_connector: Callable[[Any], None] = _probe_connector,
        test_smtp: Callable[[], None] | None = None,
        redis_factory: Callable[[], Any | None] = _redis_factory,
        read_replies: Callable[[Any], list[dict[str, str]]] | None = None,
        updates: Any = None,
        updater_dir: Path | str | None = None,
        version: str = PACKAGE_VERSION,
        sleep: Callable[[float], None] = time.sleep,
        enqueue_run: Callable[[], None] | None = None,
        now: Callable[[], dt.datetime] | None = None,
        zone: dt.tzinfo | None = None,
        env: Any = None,
    ) -> None:
        self.data_dir = Path(data_dir or settings.hawk_data_dir)
        self.session_factory = session_factory or _default_session_factory()
        self.send = send or _default_send
        self.probe_checkmarx = probe_checkmarx
        self.probe_connector = probe_connector
        self.test_smtp = test_smtp or (lambda: mailer.test_connection())
        self.redis_factory = redis_factory
        self._read_replies = read_replies
        self._updates = updates
        self.updater_dir = Path(updater_dir) if updater_dir else None
        self.version = version
        self.sleep = sleep
        self.enqueue_run = enqueue_run or self._enqueue_run
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self._zone = zone
        self.env = os.environ if env is None else env
        self.watchdog = Watchdog(file=self.data_dir / WATCHDOG_FILE)

    # ---- What it is handed -----------------------------------------------------------------------------------------

    @property
    def updates(self) -> Any:
        if self._updates is None:
            from app.services.updates.service import UpdateService

            self._updates = UpdateService(data_dir=self.data_dir, updater=self.updater_dir)
        return self._updates

    @property
    def zone(self) -> dt.tzinfo:
        if self._zone is None:
            from app.services.updates.service import server_zone

            self._zone = server_zone()
        return self._zone

    def _updater(self) -> Path:
        from app.services.updates import companion

        return self.updater_dir or companion.updater_dir()

    @staticmethod
    def _enqueue_run() -> None:
        from app.jobs.celery_app import celery_app

        celery_app.send_task(RUN_TASK, queue="monitoring")

    # ---- Who: the administrators, and who may steer it -------------------------------------------------------------

    @staticmethod
    def administrators(db: Session, tenant_id: str | None = None) -> list[str]:
        """Who hears about problems and may close the cases Hawk AI raises: the owners and admins of the tenant
        concerned (MZ: those who may update the server or connect Checkmarx One or the email server), or of every
        tenant for a problem of the server itself."""

        from app.db.models.user import User, UserTenantRole

        query = select(User.email).join(UserTenantRole, UserTenantRole.user_id == User.id).where(UserTenantRole.role.in_(support_desk.TEAM_ROLES), User.is_active.is_(True))
        if tenant_id:
            query = query.where(UserTenantRole.tenant_id == tenant_id)
        return sorted({str(e).lower() for e in db.scalars(query).all() if e})

    def owners(self, db: Session, settings_now: dict[str, Any] | None = None) -> list[str]:
        """Who may steer hands-off from an email: the status list and the administrators."""

        settings_now = settings_now or hands_off.load(self.data_dir)
        return list(dict.fromkeys([*settings_now.get("statusTo", []), *self.administrators(db)]))

    @staticmethod
    def default_tenant(db: Session) -> str | None:
        """The tenant a case about the server itself is raised in (MZ: the default tenant): the first one made."""

        from app.db.models.tenant import Tenant

        return db.scalar(select(Tenant.id).where(Tenant.is_active.is_(True)).order_by(Tenant.created_at, Tenant.id).limit(1))

    @staticmethod
    def mail_ready(db: Session) -> bool:
        """Email goes out only once the email server is set up and tested (docs/sign-in.md)."""

        from app.services import account_security

        return mailer.configured() and account_security.policy(db).smtp_verified == mailer.fingerprint()

    # ---- Email -----------------------------------------------------------------------------------------------------

    def link(self, action: str, email: str, ref: str = "") -> str:
        """A one-click link, or '' when the server's address is not known."""

        from app.services.password_reset_service import link_base

        base = link_base()
        if not base:
            return ""
        token = action_links.sign_action(action, email, r=ref, now=self.now().timestamp())
        # After "#": browsers never send it to a server or in a Referer (as the password reset link).
        return f"{base}/hands-off/confirm#a={token}"

    def button(self, label: str, action: str, email: str, ref: str = "") -> list[tuple[str, str]]:
        url = self.link(action, email, ref)
        return [(label, url)] if url else []

    def send_system_mail(self, to: list[str], message_for: Callable[[str, str], Any], *, attachments: list[tuple[str, bytes, str]] = ()) -> int:
        """One personal copy for each address (their own links and reply reference); never throws. Returns how many
        went out."""

        sent = 0
        for address in dict.fromkeys(a for a in to if a):
            message = message_for(address, action_links.reply_reference(address))
            for filename, content, content_type in attachments:
                maintype, _, subtype = content_type.partition("/")
                message.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)
            try:
                self.send(message, address)
                sent += 1
            except Exception as error:  # noqa: BLE001 - said in the log; the self-check carries on
                log.warning("[self-check] Could not email %s: %s", address, error)
        return sent

    def tell_administrators(self, db: Session, problem: dict[str, Any], build: Callable[[str, str], Any], **options: Any) -> int:
        if not self.mail_ready(db):
            return 0
        tenant = problem.get("tenant") or None
        return self.send_system_mail(self.administrators(db, tenant), build, **options)

    def problem_facts(self, db: Session, p: dict[str, Any]) -> list[tuple[str, str]]:
        from app.db.models.tenant import Tenant

        facts = [("Problem", f"{p['title']}: {p['detail']}"), ("Since", _when(p["since"])), ("Tried", "; ".join(p.get("tried") or []) or "nothing could be tried yet")]
        if p.get("tenant"):
            tenant = db.get(Tenant, p["tenant"])
            if tenant is not None:
                facts.append(("Tenant", tenant.name))
        facts.append(("Version", display_version(self.version)))
        return facts

    # ---- The weekly status -----------------------------------------------------------------------------------------

    def status_facts(self, db: Session) -> list[tuple[str, str]]:
        from app.db.models.job_run import ScheduledJobRun
        from app.services import backup_service

        since = self.now() - dt.timedelta(days=7)
        rows = db.execute(select(ScheduledJobRun.status, func.count()).where(ScheduledJobRun.started_at >= since).group_by(ScheduledJobRun.status)).all()
        runs = sum(int(n) for _, n in rows)
        failed = sum(int(n) for s, n in rows if s in FAILED_RUN)
        last = backup_service.last_backup()
        backup = "none yet" if not last else f"{_when(last.get('at'))}{'' if last.get('ok') else ' (failed: ' + str(last.get('error') or '')[:120] + ')'}"
        try:
            status = self.updates.status()
            newer = f" ({status['latest']['label']} is available)" if status.get("updateAvailable") and status.get("latest") else ""
        except Exception:  # noqa: BLE001
            newer = ""
        open_ = self.watchdog.problems()
        return [
            ("Automatic runs", f"{runs} in the last 7 days{f' ({failed} failed)' if failed else ''}"),
            ("Last backup", backup),
            ("Version", f"{display_version(self.version)}{newer}"),
            ("Health", "; ".join(p["title"] for p in open_) if open_ else "all checks pass"),
        ]

    def send_status(self, db: Session, to: list[str]) -> int:
        """Email the weekly status to ``to`` (each gets their own links). Returns how many went out."""

        if not self.mail_ready(db):
            return 0
        current = hands_off.load(self.data_dir)
        facts = self.status_facts(db)
        paused = hands_off.is_paused(current, self.now())

        def build(email: str, reference: str) -> Any:
            return hands_off.system_email(
                subject=f"{APP_NAME} this week",
                lines=["Hawk AI is paused: no weekly status goes out until it is resumed." if paused else "Hawk AI ran on its own this week. Here is where things stand."],
                facts=facts,
                buttons=[
                    *self.button("Run the checks now", "run", email),
                    *(self.button("Resume", "resume", email) if paused else self.button("Pause for 7 days", "pause", email)),
                    *self.button("Stop sending me this", "stop", email),
                ],
                reference=reference,
            )

        return self.send_system_mail(to, build)

    def status_tick(self) -> int:
        """The weekly status, when its day and hour have come."""

        current = hands_off.load(self.data_dir)
        now = self.now()
        with self.session_factory() as db:
            if not hands_off.status_due(current, now, self.zone) or not self.mail_ready(db):
                return 0
            hands_off.save({"lastStatusAt": _iso(now)}, self.data_dir)
            return self.send_status(db, current["statusTo"])

    # ---- Links and replies -----------------------------------------------------------------------------------------

    def perform(self, db: Session, *, command: str, email: str, days: int = 7, ref: str = "") -> str:
        """Do what a link or a reply asks, for ``email``. Returns the sentence that says what happened (shown on the
        page, or emailed back). Raises Refused."""

        email = str(email or "").lower()
        current = hands_off.load(self.data_dir)
        owners = self.owners(db, current)
        if command == "stop":
            allowed = email in current["statusTo"] or email in owners
        elif command == "solved":
            ticket = support_desk.get(db, ref)
            allowed = ticket is not None and email in self.administrators(db, ticket.tenant_id)
            if ticket is None and email in self.administrators(db):
                raise Refused("No such case.", 404)
        else:
            allowed = email in owners
        if not allowed:
            raise Refused("Only an administrator can close this case." if command == "solved" else "This address may no longer steer Hawk AI. Ask an administrator.")
        if command == "pause":
            until = self.now() + dt.timedelta(days=days)
            hands_off.save({"pausedUntil": _iso(until)}, self.data_dir)
            said = f"Paused: no weekly status until {_iso(until)[:10]}. Resume at any time."
        elif command == "resume":
            hands_off.save({"pausedUntil": ""}, self.data_dir)
            said = "Resumed: the weekly status goes out on its schedule again."
        elif command == "run":
            try:
                self.enqueue_run()
            except Exception as error:  # noqa: BLE001
                log.warning("[hands-off] Could not start the monitoring checks: %s", error)
                raise Refused("The checks could not be started: the worker cannot be reached. Hawk AI's self-check will say more.", 503) from None
            said = "The monitoring checks that are due are on their way."
        elif command == "status":
            if not self.mail_ready(db):
                raise Refused("The email server is not set up and tested, so no status can be sent.", 409)
            self.send_status(db, [email])
            said = "The status is on its way to you."
        elif command == "stop":
            hands_off.save({"statusTo": [a for a in current["statusTo"] if a != email]}, self.data_dir)
            said = "You will not get the weekly status any more."
        elif command == "solved":
            ticket = support_desk.get(db, ref)
            assert ticket is not None
            if ticket.status not in ("completed", "declined"):
                support_desk.set_status(db, ticket, "completed", by={"id": "", "name": email, "email": email})
            self.watchdog.forget_case(ticket.id)
            said = f"{ticket.id} is closed. Thank you."
        else:
            raise Refused("Hawk AI does not know that request.", 400)
        self.audit(db, "hands_off.command", f"Hands-off: {email} asked by email to {command}{f' for {days} days' if command == 'pause' else ''}{f' ({ref})' if ref else ''}. {said}", actor=email)
        db.commit()
        return said

    def describe_link(self, token: str) -> dict[str, Any]:
        """What the "Yes, do it" page shows for a link, before anything is done."""

        payload = action_links.read_action(token, now=self.now().timestamp())
        if not payload:
            return {"ok": False, "title": EXPIRED[0], "message": EXPIRED[1]}
        ref = payload.get("r") or ""
        return {"ok": True, "action": payload["a"], "title": ACTION_TITLES[payload["a"]], "message": f"{f'{ref}. ' if ref else ''}For {payload['e']}.", "confirm": "Yes, do it"}

    def follow_link(self, token: str) -> dict[str, Any]:
        """The confirmation: do what the link says. {ok, title, message}."""

        payload = action_links.read_action(token, now=self.now().timestamp())
        if not payload:
            return {"ok": False, "status": 404, "title": EXPIRED[0], "message": EXPIRED[1]}
        with self.session_factory() as db:
            try:
                said = self.perform(db, command=payload["a"], email=payload["e"], ref=payload.get("r") or "")
            except Refused as error:
                db.rollback()
                return {"ok": False, "status": error.status_code, "title": "Not done", "message": error.message}
        return {"ok": True, "status": 200, "title": "Done", "message": said}

    def _inbox_failures(self) -> dict[str, Any]:
        try:
            value = read_state(self.data_dir / INBOX_FAILURES_FILE, fallback={})
        except Exception:  # noqa: BLE001
            return {}
        return value if isinstance(value, dict) else {}

    def _set_inbox_failures(self, value: dict[str, Any]) -> None:
        try:
            write_state(self.data_dir / INBOX_FAILURES_FILE, value, keep_last=False)
        except OSError:
            pass

    def mailbox_account(self, current: dict[str, Any]) -> Any:
        from app.services.mail_inbox import MailboxAccount

        smtp = mailer.current()
        return MailboxAccount(host=current.get("imapHost") or smtp.host, port=int(current.get("imapPort") or 993), user=smtp.user, password=smtp.password)

    def inbox_tick(self) -> int:
        """Replies to Hawk AI's emails: one word each, from the address the email went to. Returns how many were read."""

        current = hands_off.load(self.data_dir)
        with self.session_factory() as db:
            if not current["on"] or not current["replies"] or not self.mail_ready(db) or not mailer.current().user:
                return 0
        reader = self._read_replies
        if reader is None:
            from app.services.mail_inbox import read_replies as reader
        try:
            messages = reader(self.mailbox_account(current))
            self._set_inbox_failures({})
        except Exception as error:  # noqa: BLE001 - counted: three in a row is a problem the self-check reports
            failed = self._inbox_failures()
            self._set_inbox_failures({"count": int(failed.get("count") or 0) + 1, "error": str(error)[:300]})
            return 0
        for message in messages:
            try:
                self.handle_reply(message)
            except Exception as error:  # noqa: BLE001
                log.warning("[hands-off] A reply could not be handled: %s", error)
        return len(messages)

    def handle_reply(self, message: dict[str, str]) -> str:
        """One reply: acted on only when it answers an email sent to that very address. Returns what was done ('' when
        it was ignored)."""

        sender = str(message.get("from") or "").lower()
        subject = str(message.get("subject") or "")
        body = str(message.get("text") or "")
        own = mailer.current().from_address.lower()
        # Never answer ourselves, an auto-reply or a bounce: that is how mail loops start.
        if not sender or sender == own or AUTOMATIC_MAIL.search(f"{subject} {sender}"):
            return ""
        if action_links.reply_reference(sender) not in action_links.find_references(f"{subject}\n{body}"):
            return ""
        asked = hands_off.parse_command(body)
        if not asked:
            return ""
        ref_match = re.search(r"\b(SUP-\d{4,})\b", subject)
        ref = ref_match.group(1) if ref_match else ""
        with self.session_factory() as db:
            try:
                said = self.perform(db, command=asked["command"], email=sender, days=asked.get("days", 7), ref=ref)
            except Refused as error:
                db.rollback()
                said = f"Not done: {error.message}"
            clean_subject = re.sub(r"^(re:\s*)+", "", subject, flags=re.IGNORECASE)[:150]
            self.send_system_mail([sender], lambda _e, _r: hands_off.system_email(subject=f"Re: {clean_subject}", lines=[said], reply_help=False))
        return said

    # ---- The checks -------------------------------------------------------------------------------------------------

    def liveness_problems(self, db: Session) -> list[dict[str, Any]]:
        """What Hawk AI needs that MZ has not: the database, Redis, the worker and the scheduler (beat)."""

        found = []
        try:
            db.execute(text("SELECT 1"))
        except Exception as error:  # noqa: BLE001
            db.rollback()
            found.append({"key": "database", "title": "Database", "detail": f"The database cannot be reached: {str(error)[:200]}"})
        try:
            client = self.redis_factory()
        except Exception:  # noqa: BLE001
            client = None
        if client is None:
            return found
        try:
            client.ping()
        except Exception as error:  # noqa: BLE001
            found.append({"key": "redis", "title": "Redis", "detail": f"Redis cannot be reached: {str(error)[:200]}"})
            return found
        from app.services.control_plane_health_service import CELERY_BEAT_HEARTBEAT_KEY, CELERY_WORKER_HEARTBEAT_KEY, _check_celery_heartbeat

        for key, actor, title in (("worker", "worker", "Worker"), ("beat", "beat", "Scheduler (beat)")):
            result = _check_celery_heartbeat(redis_client=client, key=CELERY_WORKER_HEARTBEAT_KEY if key == "worker" else CELERY_BEAT_HEARTBEAT_KEY, actor=actor, strict_mode=True)
            if not result.ok:
                found.append({"key": key, "title": title, "detail": f"Its heartbeat is {result.status}: {result.detail}."})
        return found

    def checkmarx_connectors(self, db: Session) -> list[Any]:
        from app.db.models.monitoring import Connector

        return list(db.scalars(select(Connector).where(Connector.provider_key == "checkmarx", Connector.enabled.is_(True), Connector.is_stub.is_(False)).order_by(Connector.created_at)).all())

    def check_checkmarx(self, connector: Any) -> dict[str, Any] | None:
        key = f"checkmarx:{connector.tenant_id}:{connector.id}"
        title = f"Checkmarx One connection ({connector.name})"
        try:
            self.probe_checkmarx(connector)
        except Exception as error:  # noqa: BLE001
            outside = outside_fault(error)
            message = " ".join(str(error).split())[:300] or error.__class__.__name__
            detail = f"{message}. This is on Checkmarx One's side; Hawk AI keeps trying." if outside else message
            return {"key": key, "title": title, "detail": detail, "tenant": connector.tenant_id, "outside": outside}
        try:
            ConnectionGuard(self.data_dir).remember(connector)
        except Exception as error:  # noqa: BLE001
            log.warning("[self-check] Could not note the working connection: %s", error)
        return None

    def other_connectors(self, db: Session) -> list[Any]:
        """Every other connector that is on, real (not a stub) and has a health call: the monitoring connectors that
        sign in and read over HTTP (Microsoft 365, Okta, Slack, SailPoint, CrowdStrike, the AI providers' admin APIs…)."""

        from app.db.models.monitoring import Connector
        from app.services.integration_connector_service import has_health_check

        rows = db.scalars(select(Connector).where(Connector.provider_key != "checkmarx", Connector.enabled.is_(True), Connector.is_stub.is_(False)).order_by(Connector.created_at)).all()
        return [c for c in rows if has_health_check(str(c.provider_key))]

    def check_connector(self, connector: Any) -> dict[str, Any] | None:
        from app.services.integration_connector_service import PROVIDERS

        provider = PROVIDERS.get(str(connector.provider_key))
        label = provider.display_name if provider else str(connector.provider_key)
        key = f"connector:{connector.tenant_id}:{connector.id}"
        title = f"{label} connection ({connector.name})"
        try:
            self.probe_connector(connector)
        except Exception as error:  # noqa: BLE001
            outside = outside_fault(error)
            message = " ".join(str(error).split())[:300] or error.__class__.__name__
            detail = f"{message}. This is on {label}'s side; Hawk AI keeps trying." if outside else message
            return {"key": key, "title": title, "detail": detail, "tenant": connector.tenant_id, "outside": outside}
        return None

    def check_smtp(self, db: Session) -> dict[str, Any] | None:
        if not self.mail_ready(db):
            return None
        try:
            self.test_smtp()
        except Exception as error:  # noqa: BLE001
            return {"key": "smtp", "title": "Email server", "detail": str(error)[:300], "outside": outside_fault(error)}
        return None

    def check_runs(self, db: Session) -> list[dict[str, Any]]:
        from app.db.models.job_run import ScheduledJobRun

        found = []
        for job, label in WATCHED_RUNS.items():
            runs = db.scalars(select(ScheduledJobRun).where(ScheduledJobRun.job_name == job).order_by(ScheduledJobRun.started_at.desc()).limit(2)).all()
            if len(runs) == 2 and all(r.status in FAILED_RUN for r in runs):
                found.append({"key": f"runs:{job}", "title": label, "detail": (runs[0].error_message or "The last two runs failed.")[:300]})
        return found

    def errors_problem(self) -> dict[str, Any] | None:
        try:
            client = self.redis_factory()
        except Exception:  # noqa: BLE001
            client = None
        errors = error_counter.recent(client) if client is not None else 0
        if errors > ERRORS_PER_15_MIN:
            return {"key": "errors", "title": "Errors on the server", "detail": f"{errors} errors in the last 15 minutes."}
        return None

    def collect(self, db: Session) -> list[dict[str, Any]]:
        """Everything wrong now: [{key, title, detail, tenant, outside}]."""

        found = self.liveness_problems(db)
        if any(p["key"] == "database" for p in found):
            return found
        for connector in self.checkmarx_connectors(db):
            problem = self.check_checkmarx(connector)
            if problem:
                found.append(problem)
        for connector in self.other_connectors(db):
            problem = self.check_connector(connector)
            if problem:
                found.append(problem)
        smtp = self.check_smtp(db)
        if smtp:
            found.append(smtp)
        current = hands_off.load(self.data_dir)
        inbox = self._inbox_failures()
        if current["on"] and current["replies"] and int(inbox.get("count") or 0) >= 3:
            found.append({"key": "inbox", "title": "Reading replies", "detail": str(inbox.get("error") or "")})
        found.extend(self.check_runs(db))
        errors = self.errors_problem()
        if errors:
            found.append(errors)
        return found

    def recheck(self, db: Session, key: str) -> bool:
        """Is this problem gone now? One check of that problem alone."""

        if key.startswith("checkmarx:"):
            connector_id = key.rsplit(":", 1)[1]
            connector = next((c for c in self.checkmarx_connectors(db) if c.id == connector_id), None)
            return connector is None or self.check_checkmarx(connector) is None
        if key.startswith("connector:"):
            connector_id = key.rsplit(":", 1)[1]
            connector = next((c for c in self.other_connectors(db) if c.id == connector_id), None)
            return connector is None or self.check_connector(connector) is None
        if key == "smtp":
            return self.check_smtp(db) is None
        return not any(p["key"] == key for p in self.collect(db))

    # ---- The repairs ------------------------------------------------------------------------------------------------

    def repair(self, db: Session, problem: dict[str, Any]) -> bool:
        """Try to put one problem right (each repair once while it lasts). True when it is fixed."""

        key = problem["key"]

        def attempt(name: str, fn: Callable[[], Any]) -> bool:
            if self.watchdog.has_tried(key, name):
                return False
            try:
                fn()
            except Exception:  # noqa: BLE001 - whether it helped is what the check says
                pass
            fixed = self.recheck(db, key)
            self.watchdog.tried(key, name, "fixed" if fixed else "did not help")
            return fixed

        if key.startswith("checkmarx:"):
            connector_id = key.rsplit(":", 1)[1]
            connector = next((c for c in self.checkmarx_connectors(db) if c.id == connector_id), None)
            if connector is None:
                return False
            guard = ConnectionGuard(self.data_dir)
            # A changed connection that does not work: back to the last one that did.
            if guard.pending(connector):

                def put_back() -> None:
                    if guard.put_back(connector):
                        self.audit(db, "selfcheck.connection_restored", f"Self-check: the Checkmarx One connector {connector.name} did not work after it was changed; its last working settings are back.", tenant_id=connector.tenant_id)
                        db.commit()

                if attempt("Put back the last working connection", put_back):
                    return True
            # Signing in again: a new client, so a new token (Checkmarx One's tokens are per client).
            return attempt("Signed in to Checkmarx One again", lambda: self.probe_checkmarx(connector))
        if key.startswith("connector:"):
            connector_id = key.rsplit(":", 1)[1]
            connector = next((c for c in self.other_connectors(db) if c.id == connector_id), None)
            if connector is None:
                return False
            # Signing in again: a new token for each look (none is kept between them).
            return attempt("Signed in to the connector again", lambda: self.probe_connector(connector))
        if key == "smtp":
            return attempt("Tried the mail server again after a pause", lambda: self.sleep(10))
        return False

    # ---- Cases ------------------------------------------------------------------------------------------------------

    def troubleshooting_log(self, problem: dict[str, Any]) -> dict[str, Any]:
        """What the email carries: the problem and the self-check's last events. No personal data, keys or findings."""

        return {
            "product": APP_NAME,
            "version": display_version(self.version),
            "generatedAt": _iso(self.now()),
            "selfCheck": {
                "problem": {k: problem.get(k) for k in ("key", "title", "detail", "since", "checks", "tried", "outside")},
                "open": [{k: p.get(k) for k in ("key", "title", "since", "checks")} for p in self.watchdog.problems()],
                "events": [{k: v for k, v in e.items() if k != "tenant"} for e in self.watchdog.events(30)],
            },
            # The last error lines of this process (app/core/log_config.py), emails and phone numbers taken out.
            "recentErrors": recent_error_lines(20),
        }

    def raise_case(self, db: Session, problem: dict[str, Any]) -> Any:
        """Raise a support case for a problem Hawk AI could not fix, and ask an administrator to forward it."""

        maintainer = maintainer_email(self.env)
        forward_to = maintainer or "the maintainer (whoever supplied Hawk AI; MAINTAINER_EMAIL is not set)"
        tenant = problem.get("tenant") or self.default_tenant(db)
        facts = self.problem_facts(db, problem)
        ticket = support_desk.create(
            db,
            kind="case",
            tenant_id=tenant,
            subject=f"[Automatic] {problem['title']}",
            text="\n".join(["Hawk AI raised this case by itself: it could not fix the problem on its own.", "", *(f"{k}: {v}" for k, v in facts), "", f"Forward the email about it to {forward_to}."]),
            priority="high",
            requester=AUTOMATIC,
            version=display_version(self.version),
            now=self.now(),
        )
        self.audit(db, "selfcheck.case_raised", f"Self-check raised {ticket.id}: {problem['title']} ({problem['detail']}).", tenant_id=tenant)
        db.commit()
        self.watchdog.mark_case(problem["key"], ticket.id)
        self.watchdog.event("case", f"{ticket.id} raised for {problem['title']}.", key=problem["key"], tenant=problem.get("tenant") or "")
        from app.services.password_reset_service import link_base

        base = link_base()
        report = json.dumps(self.troubleshooting_log(problem), indent=2).encode("utf-8")
        self.tell_administrators(
            db,
            {**problem, "tenant": tenant},
            lambda email, reference: hands_off.system_email(
                subject=f"[{ticket.id}] Hawk AI needs the maintainer: {problem['title']}",
                lines=[
                    f"Hawk AI could not fix this on its own, so it raised support case {ticket.id}.",
                    f"Please forward this email, with its attachment, to {forward_to}. Hawk AI never sends anything outside your network by itself.",
                    "The attachment is the troubleshooting log: no personal data, keys or findings.",
                ],
                facts=facts,
                buttons=[*self.button("Mark as solved", "solved", email, ticket.id), *([(f"Open {ticket.id}", f"{base}/help?open={ticket.id}")] if base else [])],
                reference=reference,
                reply_help=False,
                footer=f"When it is solved, reply SOLVED to this email, or use the button. {ticket.id} then closes.",
            ),
            attachments=[(f"hawk-ai-{ticket.id}-troubleshooting.json", report, "application/json")],
        )
        return ticket

    # ---- One self-check ---------------------------------------------------------------------------------------------

    def online(self) -> bool:
        """Did the last update check reach the internet (in the last two days)?"""

        check = getattr(self.updates, "last_check", None)
        if not isinstance(check, dict) or check.get("error"):
            return False
        at = parse_iso(check.get("at"))
        return bool(at and (self.now() - at).total_seconds() < 2 * 86_400)

    def run(self) -> dict[str, Any]:
        """One self-check: look at everything, repair what can be repaired, tell who needs to know. Two at once never
        run: the second is skipped."""

        self.data_dir.mkdir(parents=True, exist_ok=True)
        with open(self.data_dir / LOCK_FILE, "a+") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return {"skipped": True}
            try:
                # Another process may have checked since this one read the notes.
                self.watchdog = Watchdog(file=self.data_dir / WATCHDOG_FILE)
                return self._run()
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _run(self) -> dict[str, Any]:
        with self.session_factory() as db:
            try:
                found = self.collect(db)
            except Exception as error:  # noqa: BLE001 - a check that breaks is itself a problem
                db.rollback()
                found = [{"key": "check", "title": "Self-check", "detail": str(error)[:300]}]
            changes = self.watchdog.record(found, version=self.version, now=self.now())
            if any(p["key"] == "database" for p in found):
                # Without the database nobody can be found to tell, and no case can be raised.
                return {"problems": self.watchdog.problems()}

            for p in self.watchdog.problems():
                try:
                    fixed = self.repair(db, p)
                except Exception:  # noqa: BLE001
                    db.rollback()
                    fixed = False
                if fixed:
                    self.watchdog.resolve(p["key"], now=self.now())
                    self.audit(db, "selfcheck.fixed", f"Self-check fixed it: {p['title']} ({p['detail']}).", tenant_id=p.get("tenant") or None)
                    db.commit()
                    if p.get("notifiedAt"):
                        self.tell_administrators(db, p, lambda email, reference, p=p: hands_off.system_email(subject=f"Hawk AI fixed itself: {p['title']}", lines=["Hawk AI found a problem and put it right on its own. Nothing is needed from you."], facts=self.problem_facts(db, p), reference=reference, reply_help=False))

            try:
                auto = bool(self.updates.settings().get("auto"))
            except Exception:  # noqa: BLE001
                auto = False
            online = self.online()
            for p in self.watchdog.problems():
                if should_notify(p):
                    self.watchdog.mark_notified(p["key"], now=self.now())
                    self.tell_administrators(
                        db,
                        p,
                        lambda email, reference, p=p: hands_off.system_email(
                            subject=f"Hawk AI needs attention: {p['title']}",
                            lines=[
                                "Hawk AI found a problem it could not fix on its own yet. It keeps checking every few minutes and will tell you when it works again.",
                                *(["If it lasts, Hawk AI raises a support case by itself and asks you to forward it."] if auto and online else []),
                            ],
                            facts=self.problem_facts(db, p),
                            reference=reference,
                            reply_help=False,
                        ),
                    )
                if should_raise_case(p, auto_update=auto, online=online):
                    try:
                        self.raise_case(db, p)
                    except Exception as error:  # noqa: BLE001
                        db.rollback()
                        self.watchdog.event("tried", f"Raising a support case for {p['title']} failed: {str(error)[:200]}", key=p["key"])

            for p in changes["recovered"]:
                if p.get("caseId"):
                    ticket = support_desk.get(db, p["caseId"])
                    if ticket is not None:
                        try:
                            support_desk.reply(db, ticket, by=AUTOMATIC, team=True, text=f"Working again since {_when(p['recoveredAt'])}. Close the case once you are happy.", now=self.now())
                            db.commit()
                        except support_desk.SupportError:
                            db.rollback()
                if p.get("notifiedAt"):
                    self.tell_administrators(
                        db,
                        p,
                        lambda email, reference, p=p: hands_off.system_email(
                            subject=f"Hawk AI is working again: {p['title']}",
                            lines=["The problem Hawk AI told you about has cleared."],
                            facts=self.problem_facts(db, p),
                            buttons=self.button("Mark as solved", "solved", email, p["caseId"]) if p.get("caseId") else [],
                            reference=reference,
                            reply_help=False,
                        ),
                    )

            self.maybe_roll_back(db)
            return {"problems": self.watchdog.problems()}

    def maybe_roll_back(self, db: Session) -> str:
        """A version that came in less than a day ago and broke what worked: back to the one before it, through the
        updater. Returns the version gone back to ('' when not)."""

        from app.services.updates import companion

        directory = self._updater()
        # The updater's record of this version coming in: a switch to it from another.
        switched = next((e for e in companion.events(directory, 50) if e.get("type") == "switch" and e.get("from") and e.get("from") != self.version and e.get("to") == self.version), None)
        target = rollback_target(
            problems=self.watchdog.problems(),
            running=self.version,
            previous=str((switched or {}).get("from") or ""),
            switched_at=str((switched or {}).get("at") or ""),
            was_healthy=self.watchdog.was_healthy,
            has_rolled_back=self.watchdog.has_rolled_back,
            now=self.now(),
        )
        # Only when the updater looks after the services (MZ: only under its launcher).
        if not target or not companion.companion_state(directory, self.now())["manages"]:
            return ""
        running, back = display_version(self.version), display_version(target)
        self.watchdog.mark_rolled_back(self.version, now=self.now())
        self.watchdog.event("rollback", f"{running} put back to {back}: it broke what worked before.")
        self.audit(db, "selfcheck.rollback", f"Self-check: {running} broke what worked before; going back to {back}.")
        db.commit()
        self.tell_administrators(
            db,
            {"tenant": ""},
            lambda email, reference: hands_off.system_email(
                subject=f"Hawk AI went back to {back}",
                lines=[f"{running} came in less than a day ago and broke what worked before, so Hawk AI is going back to {back}. It will not install {running} again by itself."],
                facts=[("Problem", f"{p['title']}: {p['detail']}") for p in self.watchdog.problems()],
                reference=reference,
                reply_help=False,
            ),
        )
        try:
            self.updates.install(target, by="self-check")
        except Exception as error:  # noqa: BLE001
            self.watchdog.event("tried", f"Going back to {back} failed: {str(error)[:200]}")
        return target

    # ---- What the pages show ----------------------------------------------------------------------------------------

    def health_view(self) -> dict[str, Any]:
        state = self.watchdog.state
        return {
            "lastCheckAt": state["lastCheckAt"],
            "everyMinutes": round(watchdog_every_seconds(self.env) / 60),
            "problems": self.watchdog.problems(),
            "events": self.watchdog.events(20),
            "maintainer": maintainer_email(self.env),
        }

    # ---- The audit log ----------------------------------------------------------------------------------------------

    @staticmethod
    def audit(db: Session, action: str, reason: str, *, actor: str = APP_NAME, tenant_id: str | None = None) -> None:
        from app.services.audit_service import write_audit_log

        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action=action,
            resource_type="system",
            resource_id="self-check",
            payload={"outcome": "changed", "reason": reason, "actor_id": actor, "type": "Updates & system"},
        )


__all__ = ["ACTION_TITLES", "ERRORS_PER_15_MIN", "Refused", "SelfCheck", "WATCHED_RUNS", "inbox_every_seconds", "maintainer_email", "watchdog_every_seconds"]
