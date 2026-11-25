"""The audit log's chain: what makes it tamper-evident. Ported from CxMissionZero's src/audit-log.js (and the
verify and export routes of src/routes/audit.js), with Hawk's audit log in PostgreSQL instead of monthly JSONL files.

- Each entry carries a sequence number and ``mac``: an HMAC-SHA256 over the previous entry's MAC and this entry
  (canonical JSON, keys sorted), keyed by ``audit.key`` in the data folder (HAWK_DATA_DIR). Editing, removing or
  reordering any entry breaks the chain from that point on, which :func:`verify` reports, naming each broken entry.
- One chain per tenant (``chain`` is the tenant's id) and one for entries that belong to no tenant (``system``), so
  each organisation's administrators can check their own log.
- The key is made at the first entry (32 random bytes, 0600). It lives in the data folder, so every backup carries it
  beside the database it signs (app/services/backup_archive.py) and a restore brings both back together. A key file
  that is there but cut short is never replaced by a new key without a word (nothing written so far could be checked
  any more): the write stops and says what to do, as MZ's readState does.
- Appending is serialised across processes (api, worker): the chain head (audit_chain_heads) is advanced with an
  UPDATE, which holds that row's lock until the transaction ends, so a second writer waits and then chains after
  the first. Entries are never updated or deleted (triggers since migration 0002, and the ORM refuses too).
- Entries written before the chain began (migration 0097) carry no MAC; the check counts them and says so.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any, Iterable, Iterator
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session

GENESIS = "genesis"
SYSTEM_CHAIN = "system"
KEY_FILE = "audit.key"
KEY_BYTES = 32

#: Shown at the top of every export, as CxMissionZero's SUPPORTING_NOTICE is.
EXPORT_NOTICE = "Exported from Hawk AI's audit log. Each entry carries its sequence number and MAC; the JSON Lines export can be checked against the chain."


class AuditKeyError(RuntimeError):
    """The key the audit log is signed with cannot be used: says what to do."""


_key_lock = threading.Lock()
_key_cache: dict[str, bytes] = {}


def key_path() -> Path:
    from app.core.config import settings

    return Path(str(settings.hawk_data_dir or ".runtime/data")) / KEY_FILE


def _read_key(file: Path) -> bytes | None:
    try:
        raw = file.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise AuditKeyError(f"The key the audit log is signed with ({file}) cannot be read: {error}. Nothing is written to the audit log until it can be.") from error
    if len(raw) < KEY_BYTES:
        raise AuditKeyError(
            f"The key the audit log is signed with ({file}) holds {len(raw)} bytes, and a key is at least {KEY_BYTES}. "
            "It is not replaced with a new one, because nothing written so far could be checked any more. Restore it from a backup of the data folder, "
            f"or start the audit chain afresh on purpose: move {file.name} out of {file.parent} (somewhere safe), then start again."
        )
    return raw


def _create_key(file: Path) -> bytes:
    """32 random bytes, flushed to the disk, 0600; when another process made one meanwhile, that one is used."""

    file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = file.with_name(f".{file.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, secrets.token_bytes(KEY_BYTES))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        # A hard link fails when the name is taken: never two keys, whichever process came first wins.
        os.link(tmp, file)
    except FileExistsError:
        pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    key = _read_key(file)
    if key is None:  # pragma: no cover - the link above made it
        raise AuditKeyError(f"The key the audit log is signed with could not be made at {file}.")
    return key


def load_key(file: Path | None = None) -> bytes:
    file = Path(file or key_path())
    cached = _key_cache.get(str(file))
    if cached is not None:
        return cached
    with _key_lock:
        key = _read_key(file) or _create_key(file)
        _key_cache[str(file)] = key
        return key


def forget_key() -> None:
    """For a restore (a different key comes back with the data folder) and for tests."""

    with _key_lock:
        _key_cache.clear()


# ---------------------------------------------------------------------------------------------------------------------
# The MAC
# ---------------------------------------------------------------------------------------------------------------------


def canonical(value: Any) -> str:
    """Stable JSON: keys sorted, no spaces, so the MAC does not depend on key order or on how the database stores it."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def iso(moment: Any) -> str:
    """A time as the chain signs it: UTC, microseconds, whatever the database gives back (naive means UTC)."""

    if isinstance(moment, str):
        moment = dt.datetime.fromisoformat(moment.replace("Z", "+00:00"))
    if not isinstance(moment, dt.datetime):
        return str(moment or "")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def entry_body(row: Any) -> dict[str, Any]:
    """What the MAC covers: every column but the MAC itself."""

    return {
        "id": str(row.id),
        "chain": row.chain,
        "seq": int(row.seq) if row.seq is not None else None,
        "at": iso(row.created_at),
        "tenant": row.tenant_id,
        "actor": row.actor_user_id,
        "actorType": row.actor_type,
        "action": row.action,
        "resourceType": row.resource_type,
        "resourceId": row.resource_id,
        "correlationId": row.correlation_id,
        "payload": row.payload if row.payload is not None else {},
    }


def compute_mac(key: bytes, prev_mac: str, body: dict[str, Any]) -> str:
    digest = hmac.new(key, (prev_mac or GENESIS).encode("utf-8") + b"\n" + canonical(body).encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def chain_of(tenant_id: str | None) -> str:
    return str(tenant_id) if tenant_id else SYSTEM_CHAIN


def chain_entry(connection: Any, target: Any) -> None:
    """Give a new audit entry its place in its chain (the mapper's before_insert, app/db/models/audit.py)."""

    if not target.id:
        target.id = str(uuid4())
    now = target.created_at if isinstance(target.created_at, dt.datetime) else dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=dt.timezone.utc)
    # What the database will give back: UTC, to the microsecond.
    target.created_at = now.astimezone(dt.timezone.utc)
    if target.payload is None:
        target.payload = {}
    target.chain = chain_of(target.tenant_id)
    key = load_key()
    # The head row is created once, then advanced: the UPDATE holds its lock until this transaction ends.
    connection.execute(
        text("INSERT INTO audit_chain_heads (chain, seq, mac) VALUES (:chain, 0, :genesis) ON CONFLICT (chain) DO NOTHING"),
        {"chain": target.chain, "genesis": GENESIS},
    )
    head = connection.execute(
        text("UPDATE audit_chain_heads SET seq = seq + 1 WHERE chain = :chain RETURNING seq, mac"),
        {"chain": target.chain},
    ).one()
    target.seq = int(head[0])
    target.prev_mac = str(head[1] or GENESIS)
    target.mac = compute_mac(key, target.prev_mac, entry_body(target))
    connection.execute(text("UPDATE audit_chain_heads SET mac = :mac WHERE chain = :chain"), {"mac": target.mac, "chain": target.chain})


# ---------------------------------------------------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------------------------------------------------


def _rows(db: Session, chain: str, batch: int = 2000) -> Iterator[Any]:
    from app.db.models.audit import AuditLog

    last = 0
    while True:
        rows = db.scalars(select(AuditLog).where(AuditLog.chain == chain, AuditLog.seq > last).order_by(AuditLog.seq).limit(batch)).all()
        if not rows:
            return
        yield from rows
        last = int(rows[-1].seq)


def verify(db: Session, chain: str, *, key: bytes | None = None, max_problems: int = 50) -> dict[str, Any]:
    """Walk one chain. Returns {ok, entries, first, last, problems: [{seq, at, problem}], unchained, head}: any
    edited, missing, reordered or unsigned entry is reported with its place (CxMissionZero's verify())."""

    from sqlalchemy import func

    from app.db.models.audit import AuditChainHead, AuditLog

    key = key or load_key()
    prev = GENESIS
    expected = 1
    count = 0
    first = last = None
    problems: list[dict[str, Any]] = []
    for row in _rows(db, chain):
        count += 1
        at = iso(row.created_at)
        first = first or at
        last = at
        if row.seq != expected:
            problems.append({"seq": row.seq, "at": at, "problem": f"Expected entry #{expected}: entries missing or reordered."})
        if (row.prev_mac or "") != prev:
            problems.append({"seq": row.seq, "at": at, "problem": "Does not follow the previous entry (chain broken)."})
        if not row.mac or not hmac.compare_digest(compute_mac(key, row.prev_mac or "", entry_body(row)), row.mac):
            problems.append({"seq": row.seq, "at": at, "problem": "Contents changed after it was written."})
        prev = row.mac or ""
        expected = int(row.seq) + 1
        if len(problems) > max_problems:
            break
    head = db.get(AuditChainHead, chain)
    if head is not None and len(problems) <= max_problems and int(head.seq) > expected - 1:
        problems.append({"seq": expected, "at": None, "problem": f"Entries #{expected} to #{int(head.seq)} are missing (removed after they were written)."})
    if chain == SYSTEM_CHAIN:
        unchained = int(db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.chain.is_(None), AuditLog.tenant_id.is_(None))) or 0)
    else:
        unchained = int(db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.chain.is_(None), AuditLog.tenant_id == chain)) or 0)
    return {"ok": not problems, "entries": count, "first": first, "last": last, "problems": problems, "unchained": unchained, "head": int(head.seq) if head else 0}


def chains(db: Session) -> list[str]:
    from app.db.models.audit import AuditChainHead

    return [str(c) for c in db.scalars(select(AuditChainHead.chain).order_by(AuditChainHead.chain)).all()]


# ---------------------------------------------------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------------------------------------------------


def csv_cell(value: Any) -> str:
    """A spreadsheet cell that is never a formula (CxMissionZero's csvCell): =, +, -, @, tab and CR are prefixed."""

    text_value = "" if value is None else (json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value))
    return f"'{text_value}" if text_value[:1] in ("=", "+", "-", "@", "\t", "\r") else text_value


def to_csv(header: list[str], rows: Iterable[list[Any]], *, notice: str = "") -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    if notice:
        writer.writerow([csv_cell(f"Notice: {notice}")])
    writer.writerow(header)
    for row in rows:
        writer.writerow([csv_cell(v) for v in row])
    return out.getvalue()


def jsonl_entry(row: Any) -> str:
    """One entry, complete and checkable: what the MAC covers, the previous MAC and the MAC."""

    return json.dumps({**entry_body(row), "prev": row.prev_mac, "mac": row.mac}, ensure_ascii=False, sort_keys=True)
