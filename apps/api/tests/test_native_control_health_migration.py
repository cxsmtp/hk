from pathlib import Path


MIGRATION = Path("app/db/migrations/versions/0050_native_control_health_observations.py")


def test_health_migration_is_linear_additive_and_recoverable() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert 'revision = "0050_native_control_health_observations"' in source
    assert 'down_revision = "0049_native_control_framework"' in source
    assert 'op.create_table(\n        "native_control_health_observations"' in source
    assert "op.alter_column" not in source
    assert "op.drop_column" not in source
    downgrade = source.split("def downgrade()", maxsplit=1)[1]
    assert 'op.drop_table("native_control_health_observations")' in downgrade
    assert "native_control_integrations" not in downgrade

