"""The first administrator, ported from CxMissionZero's prepareAccess (src/routes/session.js) and
scripts/reset-admin.mjs.

When the API starts on a database with no users (settings.first_run_access, on in deploy/compose.yaml):

- default: an administrator ``admin@hawk.local`` (or ADMIN_EMAIL) is created with a generated password, 4 groups of 5
  characters, printed once in the API's log inside a 64-character ``=`` banner and kept in
  ``<HAWK_DATA_DIR>/first-admin-password.txt`` (0600) until they choose their own at first sign-in;
- ADMIN_EMAIL + ADMIN_PASSWORD: the administrator is created from those values instead (they still choose a new
  password at first sign-in);
- FIRST_ADMIN=setup-code: nobody is created; a setup code is printed instead, and whoever has it creates the first
  administrator on the sign-in page (POST /setup), once.

On a database that already has users, the log names an administrator and gives the reset command.

Hawk is multi-tenant: the first administrator gets a tenant of their own, as its owner, within what the activation
codes allow (app/services/activation_service.py). Several API processes may start at once: a PostgreSQL advisory lock
(a process lock on SQLite) makes sure only one of them creates the administrator.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.access import FirstRunState
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.services import activation_service
from app.services.audit_service import write_audit_log
from app.services.passwords import generate_password, password_problem


DEFAULT_ADMIN_EMAIL = "admin@hawk.local"
FIRST_ADMIN_FILE_NAME = "first-admin-password.txt"
#: The same lock infra/scripts/production_bootstrap.py takes: one first administrator, however many processes start.
BOOTSTRAP_LOCK_ID = 7_269_001_010
RESET_COMMAND = "python -m app.cli.reset_admin  (with Docker: docker compose exec api python -m app.cli.reset_admin)"
ADMIN_ROLES = ("owner", "admin")
#: The first administrator's tenant, until the organisation's name is given (ORGANISATION_NAME, or with the terms).
DEFAULT_TENANT_NAME = "My organisation"
DEFAULT_TENANT_SLUG = "default"
SETUP_STATE_ID = 1
BANNER = "=" * 64

_EMAIL = re.compile(r"^[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")
_sqlite_lock = threading.Lock()


class AccessError(ValueError):
    """A first administrator that cannot be made from what was given (shown to the person, never a secret)."""


@dataclass
class Outcome:
    """What prepare_access did, for the tests and the start-up log."""

    kind: str  # "existing", "from_environment", "setup_code", "generated"
    email: str = ""
    password: str = ""
    setup_code: str = ""


def normalize_email(value: str) -> str:
    email = str(value or "").strip()
    if "@" in email:
        local, _, domain = email.rpartition("@")
        email = f"{local}@{domain.lower()}"
    return email


def first_admin_file() -> Path:
    return Path(settings.hawk_data_dir) / FIRST_ADMIN_FILE_NAME


def _prepare_data_dir() -> Path:
    directory = Path(settings.hawk_data_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    return directory


def _write_owner_only(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)


def remove_first_admin_file() -> None:
    try:
        first_admin_file().unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


@contextmanager
def bootstrap_lock(db: Session) -> Iterator[None]:
    """Held until the end of the caller's transaction on PostgreSQL; a process lock on SQLite (tests, local runs)."""

    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": BOOTSTRAP_LOCK_ID})
        yield
        return
    with _sqlite_lock:
        yield


def has_users(db: Session) -> bool:
    return int(db.scalar(select(func.count()).select_from(User)) or 0) > 0


def an_administrator(db: Session) -> User | None:
    return db.scalar(
        select(User)
        .join(UserTenantRole, UserTenantRole.user_id == User.id)
        .where(UserTenantRole.role.in_(ADMIN_ROLES), User.is_active.is_(True))
        .order_by(User.created_at, User.email)
        .limit(1)
    )


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:63].strip("-")
    return slug if len(slug) >= 3 else DEFAULT_TENANT_SLUG


def create_administrator(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str = "Administrator",
    must_change_password: bool = True,
    organisation_name: str | None = None,
) -> tuple[User, Tenant]:
    """A tenant owner with their own tenant, within the activation codes' caps (the caller commits)."""

    email = normalize_email(email)
    if not _EMAIL.match(email) or len(email) > 320:
        raise AccessError("Enter a valid email address.")
    problem = password_problem(password)
    if problem:
        raise AccessError(problem)
    if db.scalar(select(User.id).where(func.lower(User.email) == email.lower())):
        raise AccessError(f"{email} already has access here.")
    name = (organisation_name or os.environ.get("ORGANISATION_NAME") or "").strip()[:255] or DEFAULT_TENANT_NAME
    activation_service.assert_may_add_tenant(db)
    slug = _slug(name)
    if db.scalar(select(Tenant.id).where(Tenant.slug == slug)):
        slug = f"{slug[:54]}-{secrets.token_hex(4)}"
    tenant = Tenant(name=name, slug=slug, is_active=True)
    user = User(
        email=email,
        full_name=(full_name or "Administrator").strip()[:255] or "Administrator",
        hashed_password=get_password_hash(password),
        is_active=True,
        must_change_password=must_change_password,
    )
    db.add_all([tenant, user])
    db.flush()
    activation_service.assert_may_add_member(db, tenant.id)
    db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role="owner"))
    db.flush()
    return user, tenant


def _audit(db: Session, *, tenant_id: str | None, user: User, reason: str, actor_user_id: str | None = None, actor_type: str = "system") -> None:
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        action="access.administrator",
        resource_type="user",
        resource_id=user.id,
        payload={"reason": reason, "email": user.email},
    )


def new_setup_code() -> str:
    """9 random bytes as base64url, upper-cased, in groups of 4 (CxMissionZero's format), e.g. ``K7QX-M2ZA-9WPE``."""

    raw = base64.urlsafe_b64encode(secrets.token_bytes(9)).decode().rstrip("=").upper()
    raw = re.sub(r"[^A-Z0-9]", "X", raw)
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def _setup_state(db: Session) -> FirstRunState:
    state = db.get(FirstRunState, SETUP_STATE_ID)
    if state is None:
        state = FirstRunState(id=SETUP_STATE_ID, setup_code_hash=None)
        db.add(state)
        db.flush()
    return state


def setup_pending(db: Session) -> bool:
    """Whether the sign-in page should offer to create the first administrator with the setup code."""

    if has_users(db):
        return False
    state = db.get(FirstRunState, SETUP_STATE_ID)
    return bool(state and state.setup_code_hash)


def prepare_access(
    session_factory: Callable[[], Session],
    *,
    env: Mapping[str, str] | None = None,
    log: Callable[[str], None] = lambda line: print(line, flush=True),
) -> Outcome:
    env = os.environ if env is None else env
    with session_factory() as db:
        with bootstrap_lock(db):
            outcome = _prepare_access_locked(db, env, log)
            db.commit()
    return outcome


def _prepare_access_locked(db: Session, env: Mapping[str, str], log: Callable[[str], None]) -> Outcome:
    if has_users(db):
        # A database used before: no new sign-in is printed, so say whom to sign in as and how to get back in.
        admin = an_administrator(db)
        named = f"; an administrator is {admin.email}" if admin else ""
        log(f"[access] Users already set up in this database{named}. Lost the password? Run: {RESET_COMMAND}")
        return Outcome(kind="existing", email=admin.email if admin else "")

    email = str(env.get("ADMIN_EMAIL") or "").strip()
    password = str(env.get("ADMIN_PASSWORD") or "")
    if email and password:
        try:
            # Everything is checked before anything is written, so a refusal leaves nothing behind.
            admin, tenant = create_administrator(db, email=email, password=password, organisation_name=env.get("ORGANISATION_NAME"))
            _audit(db, tenant_id=tenant.id, user=admin, reason=f"First administrator {admin.email} created from ADMIN_EMAIL.")
            log("[access] First administrator created from ADMIN_EMAIL; they choose a new password at first sign-in.")
            return Outcome(kind="from_environment", email=admin.email)
        except Exception as error:  # noqa: BLE001 - said in the log, then the default below
            log(f"! [access] ADMIN_EMAIL / ADMIN_PASSWORD could not be used: {_reason(error)}")

    if str(env.get("FIRST_ADMIN") or "").strip() == "setup-code":
        # Nobody can use Hawk AI until someone proves they can read this server's log.
        code = new_setup_code()
        _setup_state(db).setup_code_hash = _code_hash(code)
        db.flush()
        log("")
        log("  No users yet. Open Hawk AI and create the first administrator with this setup code:")
        log(f"      {code}")
        log("")
        return Outcome(kind="setup_code", setup_code=code)

    # Default (and in containers): generate the first administrator and print the sign-in once, in this log. It is
    # also kept in a file only the API's user can read, until they choose their own password at first sign-in.
    admin_email = email or DEFAULT_ADMIN_EMAIL
    generated = generate_password()
    admin, tenant = create_administrator(db, email=admin_email, password=generated, organisation_name=env.get("ORGANISATION_NAME"))
    path = first_admin_file()
    _prepare_data_dir()
    _write_owner_only(path, f"{generated}\n")
    _audit(db, tenant_id=tenant.id, user=admin, reason=f"First administrator {admin.email} created with a generated password (printed in the server log once).")
    log("")
    log(BANNER)
    log("  First start: an administrator was created. Sign in with:")
    log(f"      Email:    {admin.email}")
    log(f"      Password: {generated}")
    log("  You choose your own password at first sign-in. This is shown only once;")
    log(f"  until then it is also in {path}.")
    log(f"  Lost it? Run: {RESET_COMMAND}")
    log(BANNER)
    log("")
    return Outcome(kind="generated", email=admin.email, password=generated)


def _reason(error: Exception) -> str:
    detail = getattr(error, "detail", None)
    return str(detail if detail else error)


def use_setup_code(db: Session, *, code: str, email: str, full_name: str, password: str) -> User:
    """POST /setup: whoever holds the setup code from the server log creates the first administrator, once.

    The code is claimed and the administrator created in one transaction under the bootstrap lock, so two requests
    cannot both create one; a refused password (too weak, say) rolls back and the code stays usable. The caller
    commits. Raises SetupRefused with the HTTP status and message to give.
    """

    with bootstrap_lock(db):
        if has_users(db):
            raise SetupRefused(409, "Hawk AI already has an administrator.")
        state = db.get(FirstRunState, SETUP_STATE_ID)
        expected = state.setup_code_hash if state else None
        given = _code_hash(str(code or ""))
        if not expected or not hmac.compare_digest(given, expected):
            raise SetupRefused(403, "Wrong setup code. It is printed in the server log at start-up.")
        try:
            admin, tenant = create_administrator(db, email=email, password=password, full_name=full_name or "Administrator", must_change_password=False)
        except AccessError as error:
            raise SetupRefused(400, str(error)) from error
        state.setup_code_hash = None
        _audit(db, tenant_id=tenant.id, user=admin, reason=f"First administrator {admin.email} created with the setup code.", actor_user_id=admin.id, actor_type="human")
        db.flush()
        return admin


class SetupRefused(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


@dataclass
class ResetResult:
    email: str
    password: str
    created: bool
    # Two-step sign-in was on and was taken off with the password (CxMissionZero's reset-admin does both).
    two_step_reset: bool = False


def reset_admin(db: Session, wanted: str | None = None, *, env: Mapping[str, str] | None = None) -> ResetResult:
    """scripts/reset-admin.mjs: a new temporary password for an administrator (the caller commits).

    Without an email: the first active owner or admin, created if there is none. The person chooses their own password
    at the next sign-in (and anyone already signed in as them, at their next click). A disabled administrator is
    enabled again. Recorded in the audit log.
    """

    env = os.environ if env is None else env
    password = generate_password()
    wanted = normalize_email(wanted or "")
    with bootstrap_lock(db):
        if wanted:
            user = db.scalar(select(User).where(func.lower(User.email) == wanted.lower()))
            if user is None:
                users = db.execute(select(User.email, UserTenantRole.role).outerjoin(UserTenantRole, UserTenantRole.user_id == User.id).order_by(User.email)).all()
                listed = ", ".join(f"{email} ({role or 'no tenant'})" for email, role in users) or "none"
                raise LookupError(f"No user {wanted}. Users: {listed}")
        else:
            user = an_administrator(db)
        if user is None:
            admin, tenant = create_administrator(db, email=str(env.get("ADMIN_EMAIL") or "").strip() or DEFAULT_ADMIN_EMAIL, password=password)
            _audit(db, tenant_id=tenant.id, user=admin, reason=f"Administrator {admin.email} created from the command line.")
            return ResetResult(email=admin.email, password=password, created=True)
        user.hashed_password = get_password_hash(password)
        user.must_change_password = True
        # A locked administrator could not use it otherwise; two-step sign-in goes with the password: whoever needs
        # this command may have lost the phone as well (docs/sign-in.md).
        user.failed_logins = 0
        user.locked_until = None
        from app.services import account_security

        two_step_reset = account_security.reset_two_step(user)
        if not user.is_active and an_admin_role(db, user):
            # A disabled administrator could not use it otherwise.
            user.is_active = True
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user.id).limit(1))
        _audit(
            db,
            tenant_id=membership.tenant_id if membership else None,
            user=user,
            reason=f"Temporary password set for {user.email} from the command line (reset_admin){'; their two-step sign-in was taken off' if two_step_reset else ''}.",
        )
        db.flush()
        return ResetResult(email=user.email, password=password, created=False, two_step_reset=two_step_reset)


def an_admin_role(db: Session, user: User) -> bool:
    return db.scalar(select(UserTenantRole.id).where(UserTenantRole.user_id == user.id, UserTenantRole.role.in_(ADMIN_ROLES)).limit(1)) is not None
