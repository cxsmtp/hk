"""add simulation templates and integration connector hardening fields

Revision ID: 0007_sim_templates_integrations
Revises: 0006_observability_correlation
Create Date: 2026-02-23 00:00:05.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0007_sim_templates_integrations"
down_revision = "0006_observability_correlation"
branch_labels = None
depends_on = None


def _json_default_object() -> sa.TextClause:
    return sa.text("'{}'")


def _connector_boolean_backfills():
    connectors = sa.table(
        "connectors",
        sa.column("enabled", sa.Boolean()),
        sa.column("is_stub", sa.Boolean()),
    )
    return (
        connectors.update()
        .where(connectors.c.enabled.is_(None))
        .values(enabled=True),
        connectors.update()
        .where(connectors.c.is_stub.is_(None))
        .values(is_stub=False),
    )


def upgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.create_table(
        "simulation_templates",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("target_module", sa.String(length=64), nullable=False),
        sa.Column("version_prefix", sa.String(length=32), nullable=False, server_default="1.0"),
        sa.Column("parameter_schema", sa.JSON(), nullable=False, server_default=_json_default_object()),
        sa.Column("template_body", sa.JSON(), nullable=False),
        sa.Column("generation_defaults", sa.JSON(), nullable=False, server_default=_json_default_object()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_sim_template_tenant", "simulation_templates", ["tenant_id"])

    if dialect != "sqlite":
        op.alter_column("simulation_templates", "description", server_default=None)
        op.alter_column("simulation_templates", "status", server_default=None)
        op.alter_column("simulation_templates", "version_prefix", server_default=None)
        op.alter_column("simulation_templates", "parameter_schema", server_default=None)
        op.alter_column("simulation_templates", "generation_defaults", server_default=None)

    op.add_column("connectors", sa.Column("provider_key", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("connectors", sa.Column("auth_type", sa.String(length=32), nullable=False, server_default="bearer"))
    op.add_column("connectors", sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("connectors", sa.Column("encrypted_secrets", sa.Text(), nullable=True))
    op.add_column("connectors", sa.Column("kms_key_ref", sa.String(length=255), nullable=True))
    op.add_column("connectors", sa.Column("is_stub", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("connectors", sa.Column("stub_reason", sa.Text(), nullable=False, server_default=""))
    op.add_column("connectors", sa.Column("last_pull_status", sa.String(length=16), nullable=False, server_default="never"))
    op.add_column("connectors", sa.Column("last_pull_error", sa.Text(), nullable=True))
    op.add_column("connectors", sa.Column("last_signal_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("connectors", sa.Column("polling_interval_minutes", sa.Integer(), nullable=False, server_default="15"))
    op.add_column("connectors", sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=_json_default_object()))

    op.execute("UPDATE connectors SET provider_key = connector_type WHERE provider_key IS NULL OR provider_key = ''")
    op.execute("UPDATE connectors SET auth_type = 'bearer' WHERE auth_type IS NULL OR auth_type = ''")
    for statement in _connector_boolean_backfills():
        op.execute(statement)
    op.execute("UPDATE connectors SET stub_reason = '' WHERE stub_reason IS NULL")
    op.execute("UPDATE connectors SET last_pull_status = 'never' WHERE last_pull_status IS NULL OR last_pull_status = ''")
    op.execute("UPDATE connectors SET last_signal_count = 0 WHERE last_signal_count IS NULL")
    op.execute("UPDATE connectors SET polling_interval_minutes = 15 WHERE polling_interval_minutes IS NULL")
    op.execute("UPDATE connectors SET metadata_json = '{}' WHERE metadata_json IS NULL")

    if dialect != "sqlite":
        op.alter_column("connectors", "provider_key", server_default=None)
        op.alter_column("connectors", "auth_type", server_default=None)
        op.alter_column("connectors", "enabled", server_default=None)
        op.alter_column("connectors", "is_stub", server_default=None)
        op.alter_column("connectors", "stub_reason", server_default=None)
        op.alter_column("connectors", "last_pull_status", server_default=None)
        op.alter_column("connectors", "last_signal_count", server_default=None)
        op.alter_column("connectors", "polling_interval_minutes", server_default=None)
        op.alter_column("connectors", "metadata_json", server_default=None)


def downgrade() -> None:
    op.drop_column("connectors", "metadata_json")
    op.drop_column("connectors", "polling_interval_minutes")
    op.drop_column("connectors", "last_signal_count")
    op.drop_column("connectors", "last_pull_error")
    op.drop_column("connectors", "last_pull_status")
    op.drop_column("connectors", "stub_reason")
    op.drop_column("connectors", "is_stub")
    op.drop_column("connectors", "kms_key_ref")
    op.drop_column("connectors", "encrypted_secrets")
    op.drop_column("connectors", "enabled")
    op.drop_column("connectors", "auth_type")
    op.drop_column("connectors", "provider_key")

    op.drop_index("idx_sim_template_tenant", table_name="simulation_templates")
    op.drop_table("simulation_templates")
