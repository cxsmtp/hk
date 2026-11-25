"""The database part of a backup: ``pg_dump`` and ``pg_restore`` (PostgreSQL's own tools, from the postgresql-client
package in the API image, infra/Dockerfile.api), and the lock that keeps a restore and a running Hawk AI apart.

The lock is CxMissionZero's instance lock (src/instance-lock.js) in a multi-container shape: every running api, worker
and beat holds a *shared* PostgreSQL advisory lock for as long as it runs (on a connection of its own, looked at every
10 s and taken again if the connection was lost), and a restore takes the same lock *exclusively*. So a restore
refuses while any of them runs (``--force`` skips the check), and one that starts while a restore runs waits for it.
A process that dies lets go at once (its connection closes), so there is no stale lock to wait out.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url

log = logging.getLogger("hawk.backup")

#: The advisory lock every running Hawk AI process shares and a restore takes alone (an arbitrary, fixed number).
INSTANCE_LOCK_ID = 7_269_004_001
HEARTBEAT_SECONDS = 10


class DatabaseToolError(RuntimeError):
    pass


def is_postgres(database_url: str) -> bool:
    try:
        return make_url(database_url).get_backend_name() == "postgresql"
    except Exception:  # noqa: BLE001
        return False


def _connection_env(database_url: str) -> tuple[dict[str, str], str]:
    url = make_url(database_url)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update(
        {
            "PGHOST": url.host or "localhost",
            "PGPORT": str(url.port or 5432),
            "PGUSER": url.username or "",
            "PGDATABASE": url.database or "",
            "PGCONNECT_TIMEOUT": "15",
        }
    )
    if url.password:
        # Handed to the tools in their environment, never on a command line (which `ps` shows).
        env["PGPASSWORD"] = str(url.password)
    return env, url.database or ""


def _run(args: list[str], env: dict[str, str], *, timeout: float) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(args, env=env, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        raise DatabaseToolError(f"{args[0]} is not installed in this image (postgresql-client).") from None
    except subprocess.TimeoutExpired:
        raise DatabaseToolError(f"{args[0]} did not finish within {int(timeout)} s.") from None


def _tail(stderr: bytes) -> str:
    lines = [line for line in stderr.decode("utf-8", "replace").splitlines() if line.strip()]
    return " ".join(lines[-3:])[:400] or "no reason given"


def dump_database(database_url: str, *, timeout: float = 600) -> bytes:
    """The whole database, as ``pg_dump --format=custom`` writes it."""

    env, _ = _connection_env(database_url)
    with tempfile.TemporaryDirectory(prefix="hawk-dump-") as folder:
        out = Path(folder) / "database.pgdump"
        result = _run(["pg_dump", "--format=custom", "--no-owner", "--no-privileges", f"--file={out}"], env, timeout=timeout)
        if result.returncode != 0:
            raise DatabaseToolError(f"pg_dump failed: {_tail(result.stderr)}")
        return out.read_bytes()


#: What PostgreSQL 17's pg_restore writes that the PostgreSQL 16 server of deploy/compose.yaml does not know.
_NEWER_ONLY = (b"SET transaction_timeout = 0;",)


def _schemas(database_url: str) -> list[str]:
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            return list(
                connection.execute(
                    text("SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema' ORDER BY nspname")
                ).scalars()
            )
    finally:
        engine.dispose()


def restore_database(database_url: str, dump: bytes, *, timeout: float = 1800) -> None:
    """Replace the database with ``dump``, in one transaction: every schema of Hawk AI's is dropped and the dump is
    restored (pg_restore writes it as SQL, psql runs it with ON_ERROR_STOP and --single-transaction). Anything that
    fails leaves the database as it was. The caller has put a dump of what was there aside first."""

    env, database = _connection_env(database_url)
    with tempfile.TemporaryDirectory(prefix="hawk-restore-") as folder:
        file = Path(folder) / "database.pgdump"
        file.write_bytes(dump)
        listed = _run(["pg_restore", "--list", str(file)], env, timeout=120)
        if listed.returncode != 0:
            raise DatabaseToolError(f"The database dump in this backup cannot be read: {_tail(listed.stderr)}")
        drops = "".join(f'DROP SCHEMA IF EXISTS "{name}" CASCADE;\n' for name in _schemas(database_url) if '"' not in name)
        try:
            producer = subprocess.Popen(["pg_restore", "--no-owner", "--no-privileges", "--file=-", str(file)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            consumer = subprocess.Popen(
                ["psql", "--no-psqlrc", "--quiet", "--set=ON_ERROR_STOP=1", "--single-transaction", f"--dbname={database}"],
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            raise DatabaseToolError("pg_restore or psql is not installed in this image (postgresql-client).") from None
        errors: dict[str, bytes] = {}

        def drain(name: str, stream: Any) -> None:
            errors[name] = stream.read()

        readers = [threading.Thread(target=drain, args=("pg_restore", producer.stderr)), threading.Thread(target=drain, args=("psql", consumer.stderr))]
        for reader in readers:
            reader.start()
        try:
            assert consumer.stdin is not None and producer.stdout is not None
            consumer.stdin.write((drops + "CREATE SCHEMA IF NOT EXISTS public;\n").encode("utf-8"))
            for line in producer.stdout:
                if line.rstrip(b"\r\n") in _NEWER_ONLY:
                    continue
                consumer.stdin.write(line)
            consumer.stdin.close()
        except BrokenPipeError:
            pass
        try:
            produced = producer.wait(timeout=timeout)
            consumed = consumer.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            producer.kill()
            consumer.kill()
            raise DatabaseToolError(f"The database restore did not finish within {int(timeout)} s; the database is as it was.") from None
        for reader in readers:
            reader.join(5)
        if consumed != 0:
            raise DatabaseToolError(f"The database restore failed, and the database is as it was: {_tail(errors.get('psql', b''))}")
        if produced != 0:
            raise DatabaseToolError(f"pg_restore failed: {_tail(errors.get('pg_restore', b''))}")


def has_tables(database_url: str) -> bool:
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            return bool(connection.execute(text("SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")).scalar())
    finally:
        engine.dispose()


class InstanceLock:
    """One running Hawk AI process's share of the instance lock (api, worker, beat): held while it runs."""

    def __init__(self, database_url: str, *, name: str) -> None:
        self.database_url = database_url
        self.name = name
        self._engine: Engine | None = None
        self._connection: Any = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _take(self) -> None:
        if self._engine is None:
            self._engine = create_engine(self.database_url, pool_size=1, max_overflow=0, pool_pre_ping=True)
        connection = self._engine.connect()
        # Waits while a restore holds the lock alone: this process starts once the restore is done.
        connection.execute(text("SELECT pg_advisory_lock_shared(:id)"), {"id": INSTANCE_LOCK_ID})
        connection.commit()
        self._connection = connection

    def _beat(self) -> None:
        while not self._stop.wait(HEARTBEAT_SECONDS):
            try:
                self._connection.execute(text("SELECT 1"))
                self._connection.commit()
            except Exception:  # noqa: BLE001 - the connection was lost (a database restart): take the lock again
                try:
                    self._connection.close()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    self._take()
                except Exception as error:  # noqa: BLE001
                    log.warning("[backup] Could not take the instance lock again (%s); trying again in %s s.", error, HEARTBEAT_SECONDS)

    def acquire(self) -> InstanceLock:
        if not is_postgres(self.database_url):
            return self
        self._take()
        self._thread = threading.Thread(target=self._beat, daemon=True, name=f"hawk-instance-lock-{self.name}")
        self._thread.start()
        return self

    def release(self) -> None:
        self._stop.set()
        try:
            if self._connection is not None:
                self._connection.close()
        except Exception:  # noqa: BLE001
            pass
        if self._engine is not None:
            self._engine.dispose()


class RestoreLock:
    """The instance lock taken alone, for a restore: refused while any Hawk AI process runs."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._engine: Engine | None = None
        self._connection: Any = None

    def try_acquire(self, *, wait_seconds: float = 0) -> bool:
        if not is_postgres(self.database_url):
            return True
        self._engine = create_engine(self.database_url, pool_size=1, max_overflow=0)
        self._connection = self._engine.connect()
        deadline = time.monotonic() + wait_seconds
        while True:
            got = bool(self._connection.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": INSTANCE_LOCK_ID}).scalar())
            self._connection.commit()
            if got or time.monotonic() >= deadline:
                return got
            time.sleep(1)

    def holders(self) -> int:
        """How many other processes hold their share now (for the message)."""

        if self._connection is None:
            return 0
        try:
            return int(
                self._connection.execute(
                    text("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND objid = :lo AND pid <> pg_backend_pid()"),
                    {"lo": INSTANCE_LOCK_ID & 0xFFFFFFFF},
                ).scalar()
                or 0
            )
        except Exception:  # noqa: BLE001
            return 0

    def release(self) -> None:
        try:
            if self._connection is not None:
                self._connection.close()
        except Exception:  # noqa: BLE001
            pass
        if self._engine is not None:
            self._engine.dispose()
