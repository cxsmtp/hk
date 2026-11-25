"""The tamper-evident audit log and the platform's other records (CxMissionZero's src/audit-log.js,
src/activity-log.js and src/support.js; FTR Command Center's CxOne API audit):

- audit_logs: chain, seq, prev_mac, mac (an HMAC-SHA256 chain per tenant, app/services/audit_chain.py), unique per
  (chain, seq). Entries already there keep no MAC: the check counts them as written before the chain began. The
  triggers of migration 0002 still refuse UPDATE and DELETE (columns are added with ALTER TABLE ADD COLUMN, never by
  copying the table, so SQLite keeps its triggers too).
- audit_chain_heads: each chain's last sequence number and MAC; appending advances it under its row lock.
- user_activity: what people do in the console (field names only).
- support_tickets, support_counters, support_settings: Get help.
- connector_calls: the calls connectors make to outside services.
"""

from alembic import op
import sqlalchemy as sa


revision = "0097_audit_chain"
down_revision = "0096_signin_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("chain", sa.String(length=64), nullable=True))
    op.add_column("audit_logs", sa.Column("seq", sa.BigInteger(), nullable=True))
    op.add_column("audit_logs", sa.Column("prev_mac", sa.String(length=64), nullable=True))
    op.add_column("audit_logs", sa.Column("mac", sa.String(length=64), nullable=True))
    op.create_index("uq_audit_logs_chain_seq", "audit_logs", ["chain", "seq"], unique=True)
    op.create_table(
        "audit_chain_heads",
        sa.Column("chain", sa.String(length=64), primary_key=True),
        sa.Column("seq", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("mac", sa.String(length=64), nullable=False, server_default="genesis"),
    )

    op.create_table(
        "user_activity",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("user", sa.String(length=254), nullable=False, server_default=""),
        sa.Column("name", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("role", sa.String(length=60), nullable=False, server_default=""),
        sa.Column("ip", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("kind", sa.String(length=16), nullable=False, server_default="action"),
        sa.Column("action", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("target", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("fields", sa.JSON(), nullable=False),
        sa.Column("method", sa.String(length=8), nullable=False, server_default=""),
        sa.Column("route", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("ms", sa.Integer(), nullable=True),
    )
    op.create_index("idx_user_activity_tenant_at", "user_activity", ["tenant_id", "at"])

    op.create_table(
        "support_tickets",
        sa.Column("id", sa.String(length=16), primary_key=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("subject", sa.String(length=200), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="new"),
        sa.Column("requester_id", sa.String(length=36), nullable=False),
        sa.Column("requester_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("requester_email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("page", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("version", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("messages", sa.JSON(), nullable=False),
        sa.Column("history", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_support_tickets_tenant_id", "support_tickets", ["tenant_id"])
    op.create_index("idx_support_tickets_requester_created", "support_tickets", ["requester_id", "created_at"])
    op.create_table(
        "support_counters",
        sa.Column("kind", sa.String(length=16), primary_key=True),
        sa.Column("value", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.create_table(
        "support_settings",
        sa.Column("tenant_id", sa.String(length=36), primary_key=True),
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="portal"),
        sa.Column("email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=320), nullable=False, server_default=""),
    )

    op.create_table(
        "connector_calls",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("connector", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("connector_id", sa.String(length=36), nullable=True),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("method", sa.String(length=10), nullable=False, server_default=""),
        sa.Column("host", sa.String(length=253), nullable=False, server_default=""),
        sa.Column("path", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("ms", sa.BigInteger(), nullable=True),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("idx_connector_calls_tenant_at", "connector_calls", ["tenant_id", "at"])


def downgrade() -> None:
    op.drop_index("idx_connector_calls_tenant_at", table_name="connector_calls")
    op.drop_table("connector_calls")
    op.drop_table("support_settings")
    op.drop_table("support_counters")
    op.drop_index("idx_support_tickets_requester_created", table_name="support_tickets")
    op.drop_index("ix_support_tickets_tenant_id", table_name="support_tickets")
    op.drop_table("support_tickets")
    op.drop_index("idx_user_activity_tenant_at", table_name="user_activity")
    op.drop_table("user_activity")
    op.drop_table("audit_chain_heads")
    op.drop_index("uq_audit_logs_chain_seq", table_name="audit_logs")
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        # SQLite drops a column in place since 3.35 (no table copy, so the 0002 triggers stay).
        for column in ("mac", "prev_mac", "seq", "chain"):
            op.execute(f"ALTER TABLE audit_logs DROP COLUMN {column}")
        return
    for column in ("mac", "prev_mac", "seq", "chain"):
        op.drop_column("audit_logs", column)
