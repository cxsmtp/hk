from __future__ import annotations

import importlib.util
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.models.simulation import Control
from app.db.models.tenant import Tenant
from app.db.session import Base


def _load_seed_module():
    seed_path = Path(__file__).resolve().parents[3] / "infra" / "scripts" / "seed.py"
    spec = importlib.util.spec_from_file_location("hawk_seed", seed_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seed_controls_are_scoped_to_the_active_tenant(tmp_path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'seed.sqlite3'}")
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    seed_module = _load_seed_module()

    with session_local() as db:
        tenant = Tenant(name="Seed Tenant", slug="seed-tenant", is_active=True)
        db.add(tenant)
        db.flush()

        seed_module.seed_controls(db, tenant)
        db.flush()

        controls = db.scalars(select(Control)).all()
        assert controls
        assert {control.tenant_id for control in controls} == {tenant.id}

    engine.dispose()
