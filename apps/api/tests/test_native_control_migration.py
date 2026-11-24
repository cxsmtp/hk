from __future__ import annotations

from pathlib import Path


MIGRATION = Path("app/db/migrations/versions/0049_native_control_framework.py")


def test_native_control_migration_is_linear_and_additive() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert 'revision = "0049_native_control_framework"' in source
    assert 'down_revision = "0048_endpoint_device_identity"' in source
    for table in (
        "control_capability_profiles",
        "native_control_integrations",
        "native_workload_credentials",
        "native_control_validations",
        "native_control_replays",
        "native_control_selections",
    ):
        assert f'op.create_table(\n        "{table}"' in source
    assert "op.alter_column" not in source
    assert "op.drop_column" not in source


def test_downgrade_only_removes_native_control_tables() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    downgrade = source.split("def downgrade()", maxsplit=1)[1]
    for table in (
        "native_control_selections",
        "native_control_replays",
        "native_control_validations",
        "native_workload_credentials",
        "native_control_integrations",
        "control_capability_profiles",
    ):
        assert f'op.drop_table("{table}")' in downgrade
    assert "deployment_surfaces" not in downgrade
    assert "decision_receipts" not in downgrade

