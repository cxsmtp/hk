"""A lock held until the transaction ends, for a rule that counts rows and then adds or changes one (the licence's
active users and tenants, "at least one active Owner"). Without it two requests at the same moment both count, both
find room, and both go ahead.

PostgreSQL: ``pg_advisory_xact_lock`` on a key made from the rule's name and its scope (a tenant), released at commit
or rollback. Other databases (SQLite in tests and development) have a single writer and nothing is done.
"""

from __future__ import annotations

import hashlib

from sqlalchemy import text
from sqlalchemy.orm import Session


def lock_key(*parts: str) -> int:
    """A signed 64-bit key for ``parts`` (stable across processes and versions)."""

    digest = hashlib.sha256("\x00".join(("hawk-xact-lock", *parts)).encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def hold(db: Session, *parts: str) -> bool:
    """Take the lock for ``parts`` until ``db``'s transaction ends. Returns whether a lock was taken."""

    if db.get_bind().dialect.name != "postgresql":
        return False
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key(*parts)})
    return True


__all__ = ["hold", "lock_key"]
