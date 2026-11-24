from __future__ import annotations

from pathlib import Path

import app.db.models  # noqa: F401 - registers every existing model with Base
from app.db.session import Base


PROHIBITED_TABLES = {
    "ai_exposures",
    "ai_exposure_graphs",
    "ai_exposure_events",
    "ai_exposure_scores",
}


def test_exposure_never_becomes_database_truth() -> None:
    assert set(Base.metadata.tables).isdisjoint(PROHIBITED_TABLES)


def test_part_five_adds_no_exposure_migration() -> None:
    versions = Path("app/db/migrations/versions")
    migration_names = {
        path.name.lower()
        for path in versions.glob("*.py")
        if not path.name.startswith("._")
    }
    assert not any("exposure_reason" in name for name in migration_names)
    assert not any("ai_exposure" in name for name in migration_names)

