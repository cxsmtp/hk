from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import stat

from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest

from app.services import control_plane_health_service

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "infra" / "scripts" / "run_migrations.py"


def _load_runner():
    spec = importlib.util.spec_from_file_location("hawk_run_migrations", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runner_resolves_api_pythonpath_and_alembic_script_location_from_any_cwd(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = _load_runner()

    assert runner.API_ROOT == ROOT / "apps" / "api"
    config = runner._alembic_config()

    assert config.get_main_option("script_location") == str(
        ROOT / "apps" / "api" / "app" / "db" / "migrations"
    )
    assert config.get_main_option("prepend_sys_path") == str(ROOT / "apps" / "api")


def test_runner_snapshot_filters_only_metadata_and_cache_without_changing_migrations(
    tmp_path: Path, monkeypatch,
) -> None:
    runner = _load_runner()
    actual_source = runner.MIGRATIONS_ROOT
    source = tmp_path / "migration-source"
    shutil.copytree(actual_source, source, ignore=shutil.ignore_patterns("__pycache__"))
    (source / "versions/._0092_github_repository_runtime_controls.py").write_bytes(b"AppleDouble\x00metadata")
    cache = source / "versions/__pycache__"
    cache.mkdir()
    (cache / "discarded.pyc").write_bytes(b"cache")
    monkeypatch.setattr(runner, "MIGRATIONS_ROOT", source)

    def copied_content(root: Path) -> dict[Path, bytes]:
        return {
            path.relative_to(root): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    expected = {
        path.relative_to(source): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
        and not path.name.startswith("._")
        and "__pycache__" not in path.parts
    }
    with runner._private_migration_snapshot() as snapshot:
        private_root = snapshot.parent
        assert stat.S_IMODE(private_root.stat().st_mode) == 0o700
        assert copied_content(snapshot) == expected
        assert (snapshot / "versions/0092_github_repository_runtime_controls.py").read_bytes() == (
            actual_source / "versions/0092_github_repository_runtime_controls.py"
        ).read_bytes()
        assert (snapshot / "env.py").read_bytes() == (source / "env.py").read_bytes()
        assert (snapshot / "alembic.ini").read_bytes() == (source / "alembic.ini").read_bytes()
        assert not list(snapshot.rglob("._*"))
        assert not list(snapshot.rglob("__pycache__"))

        config = runner._alembic_config(snapshot)
        assert config.get_main_option("script_location") == str(snapshot)
        assert config.get_main_option("prepend_sys_path") == str(ROOT / "apps" / "api")
        assert ScriptDirectory.from_config(config).get_heads()

    assert not snapshot.exists()
    assert not private_root.exists()


def test_runner_snapshot_is_removed_when_alembic_fails() -> None:
    runner = _load_runner()
    snapshot_path = None

    with pytest.raises(RuntimeError, match="migration_failure"):
        with runner._private_migration_snapshot() as snapshot:
            snapshot_path = snapshot
            raise RuntimeError("migration_failure")

    assert snapshot_path is not None
    assert not snapshot_path.exists()
    assert not snapshot_path.parent.exists()


def test_control_plane_migration_health_loads_repository_heads_from_api_cwd(monkeypatch) -> None:
    api_root = ROOT / "apps" / "api"
    monkeypatch.chdir(api_root)
    expected_heads = set(
        ScriptDirectory.from_config(Config("app/db/migrations/alembic.ini")).get_heads()
    )

    class StubMigrationContext:
        def get_current_heads(self):
            return expected_heads

    monkeypatch.setattr(
        control_plane_health_service.MigrationContext,
        "configure",
        lambda _connection: StubMigrationContext(),
    )

    class StubDatabase:
        def connection(self):
            return object()

    result = control_plane_health_service._check_migrations_applied(
        StubDatabase(), strict_mode=True
    )

    assert result.ok is True
    assert result.status == "ok"


def test_control_plane_migration_health_reports_root_cwd_mismatch(monkeypatch) -> None:
    monkeypatch.chdir(ROOT)

    class StubMigrationContext:
        def get_current_heads(self):
            return {"head"}

    monkeypatch.setattr(
        control_plane_health_service.MigrationContext,
        "configure",
        lambda _connection: StubMigrationContext(),
    )

    class StubDatabase:
        def connection(self):
            return object()

    result = control_plane_health_service._check_migrations_applied(
        StubDatabase(), strict_mode=True
    )

    assert result.ok is False
    assert result.status == "unavailable"
