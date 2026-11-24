"""enforce immutability on audit and evidence tables

Revision ID: 0002_immutable_audit_evidence
Revises: 0001_initial
Create Date: 2026-02-20 00:00:00.000000
"""

from __future__ import annotations

from alembic import op


revision = "0002_immutable_audit_evidence"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


IMMUTABLE_TABLES = ("audit_logs", "evidence_nodes", "evidence_edges")


def _upgrade_postgresql() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION deny_immutable_table_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'immutable_table:%', TG_TABLE_NAME;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for table_name in IMMUTABLE_TABLES:
        trigger_name = f"trg_{table_name}_immutable"
        op.execute(f"DROP TRIGGER IF EXISTS {trigger_name} ON {table_name};")
        op.execute(
            f"""
            CREATE TRIGGER {trigger_name}
            BEFORE UPDATE OR DELETE ON {table_name}
            FOR EACH ROW
            EXECUTE FUNCTION deny_immutable_table_mutation();
            """
        )


def _upgrade_sqlite() -> None:
    for table_name in IMMUTABLE_TABLES:
        update_trigger = f"trg_{table_name}_immutable_update"
        delete_trigger = f"trg_{table_name}_immutable_delete"
        op.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS {update_trigger}
            BEFORE UPDATE ON {table_name}
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'immutable_table:{table_name}');
            END;
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS {delete_trigger}
            BEFORE DELETE ON {table_name}
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'immutable_table:{table_name}');
            END;
            """
        )


def _downgrade_postgresql() -> None:
    for table_name in IMMUTABLE_TABLES:
        trigger_name = f"trg_{table_name}_immutable"
        op.execute(f"DROP TRIGGER IF EXISTS {trigger_name} ON {table_name};")
    op.execute("DROP FUNCTION IF EXISTS deny_immutable_table_mutation();")


def _downgrade_sqlite() -> None:
    for table_name in IMMUTABLE_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table_name}_immutable_update;")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table_name}_immutable_delete;")


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        _upgrade_postgresql()
        return
    if dialect == "sqlite":
        _upgrade_sqlite()
        return
    raise RuntimeError(f"Unsupported dialect for immutability migration: {dialect}")


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        _downgrade_postgresql()
        return
    if dialect == "sqlite":
        _downgrade_sqlite()
        return
    raise RuntimeError(f"Unsupported dialect for immutability migration: {dialect}")

