from __future__ import annotations

from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from sqlalchemy.engine import make_url

config = context.config


def _normalize_sqlite_database_url(raw_url: str) -> str:
    url = make_url(raw_url)
    if url.get_backend_name() != "sqlite":
        return raw_url
    database = str(url.database or "").strip()
    if not database or database == ":memory:":
        return raw_url

    path = Path(database).expanduser()
    if not path.is_absolute():
        api_root = Path(__file__).resolve().parents[3]
        path = (api_root / path).resolve()
        return url.set(database=str(path)).render_as_string(hide_password=False)
    expanded = path.resolve()
    if str(expanded) != database:
        return url.set(database=str(expanded)).render_as_string(hide_password=False)
    return raw_url


config.set_main_option("sqlalchemy.url", _normalize_sqlite_database_url(settings.database_url))

if config.config_file_name is not None:
    # Alembic is invoked in-process by migration acceptance tests and by some
    # administrative workflows.  Reconfiguring its handlers must not disable
    # already-created application loggers; doing so suppresses receipt failure
    # evidence later in the same process.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, compare_type=True)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        context.configure(
            connection=supplied_connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
