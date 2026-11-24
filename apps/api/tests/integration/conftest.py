from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.test_settings import get_test_profile


@pytest.fixture(scope="session", autouse=True)
def integration_db_ready() -> None:
    if get_test_profile() != "integration":
        pytest.skip("Integration tests require TEST_PROFILE=integration.")

    database_url = settings.database_url
    if not database_url.startswith("postgresql"):
        pytest.fail(
            "Integration tests require a PostgreSQL DATABASE_URL. "
            f"Current DATABASE_URL={database_url!r}",
            pytrace=False,
        )

    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        pytest.fail(
            "Integration tests could not connect to PostgreSQL. "
            "Start test containers and retry.",
            pytrace=False,
        )
    finally:
        engine.dispose()

    base_dir = Path(__file__).resolve().parents[2]
    alembic_ini = base_dir / "app" / "db" / "migrations" / "alembic.ini"
    alembic_cfg = Config(str(alembic_ini))
    command.upgrade(alembic_cfg, "head")

    yield
