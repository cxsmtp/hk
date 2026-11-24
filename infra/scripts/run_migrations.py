from __future__ import annotations

import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

API_ROOT = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.core.config import settings


MIGRATION_LOCK_ID = 7_269_001_009
MIGRATIONS_ROOT = API_ROOT / "app" / "db" / "migrations"


def _alembic_config(migrations_root: Path | None = None) -> Config:
    config = Config(str(MIGRATIONS_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(migrations_root or MIGRATIONS_ROOT))
    config.set_main_option("prepend_sys_path", str(API_ROOT))
    return config


@contextmanager
def _private_migration_snapshot() -> Iterator[Path]:
    """Copy migration content to a private tree without filesystem metadata sidecars."""

    with tempfile.TemporaryDirectory(prefix="hawk-migrations-") as temporary:
        temporary_root = Path(temporary)
        os.chmod(temporary_root, 0o700)
        snapshot = temporary_root / "migrations"
        shutil.copytree(
            MIGRATIONS_ROOT,
            snapshot,
            ignore=shutil.ignore_patterns("._*", "__pycache__"),
        )
        yield snapshot


def main() -> None:
    url = make_url(settings.database_url)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("The supported production migration runner requires PostgreSQL.")

    with _private_migration_snapshot() as migration_root:
        config = _alembic_config(migration_root)
        engine = create_engine(settings.database_url, pool_pre_ping=True)
        try:
            with engine.begin() as connection:
                connection.execute(text("SELECT pg_advisory_lock(:lock_id)"), {"lock_id": MIGRATION_LOCK_ID})
                try:
                    config.attributes["connection"] = connection
                    command.upgrade(config, "head")
                finally:
                    connection.execute(text("SELECT pg_advisory_unlock(:lock_id)"), {"lock_id": MIGRATION_LOCK_ID})
        finally:
            engine.dispose()


if __name__ == "__main__":
    main()
