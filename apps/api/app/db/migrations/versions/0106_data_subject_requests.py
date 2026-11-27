"""Requests from data subjects (Settings → Compliance → Data requests; app/services/data_subject_requests.py).

- data_subject_requests: a person's request to a tenant to see, correct or erase their personal data, a grievance or
  a nomination (DPDP Act s.11-14, R.14; UAE PDPL Art. 13-15): kind, who it is about, received and due, status, who
  handles it, how it ended.
- data_subject_request_events: each request's trail, append-only: database triggers refuse UPDATE and DELETE (as
  0002 does for the audit log).
- data_subject_request_settings: per tenant, the days a request has (30 by default) and the grievance contact.

down_revision is 0105_compliance_packs.
"""

from alembic import op
import sqlalchemy as sa


revision = "0106_data_subject_requests"
down_revision = "0105_compliance_packs"
branch_labels = None
depends_on = None

EVENTS = "data_subject_request_events"


def upgrade() -> None:
    op.create_table(
        "data_subject_requests",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("law", sa.String(length=16), nullable=False, server_default="other"),
        sa.Column("subject_email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("subject_identifier", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("subject_hash", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("subject_user_id", sa.String(length=36), nullable=True),
        sa.Column("channel", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="received"),
        sa.Column("refusal_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("handled_by", sa.String(length=36), nullable=True),
        sa.Column("handled_by_email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.String(length=36), nullable=True),
        sa.Column("created_by_email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_dsr_tenant_status", "data_subject_requests", ["tenant_id", "status"])
    op.create_index("idx_dsr_tenant_due", "data_subject_requests", ["tenant_id", "due_at"])
    op.create_table(
        EVENTS,
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("request_id", sa.String(length=36), sa.ForeignKey("data_subject_requests.id"), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_user_id", sa.String(length=36), nullable=True),
        sa.Column("actor_email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("from_status", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("to_status", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("idx_dsr_event_request_at", EVENTS, ["request_id", "at"])
    op.create_table(
        "data_subject_request_settings",
        sa.Column("tenant_id", sa.String(length=36), primary_key=True),
        sa.Column("due_days", sa.Integer(), nullable=False, server_default=sa.text("30")),
        sa.Column("grievance_contact", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("updated_by_email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
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
        op.execute(f"CREATE TRIGGER trg_{EVENTS}_immutable BEFORE UPDATE OR DELETE ON {EVENTS} FOR EACH ROW EXECUTE FUNCTION deny_immutable_table_mutation();")
    elif dialect == "sqlite":
        for what in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER IF NOT EXISTS trg_{EVENTS}_immutable_{what.lower()} BEFORE {what} ON {EVENTS} FOR EACH ROW "
                f"BEGIN SELECT RAISE(ABORT, 'immutable_table:{EVENTS}'); END;"
            )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(f"DROP TRIGGER IF EXISTS trg_{EVENTS}_immutable ON {EVENTS};")
    elif dialect == "sqlite":
        for what in ("update", "delete"):
            op.execute(f"DROP TRIGGER IF EXISTS trg_{EVENTS}_immutable_{what};")
    op.drop_table("data_subject_request_settings")
    op.drop_index("idx_dsr_event_request_at", table_name=EVENTS)
    op.drop_table(EVENTS)
    op.drop_index("idx_dsr_tenant_due", table_name="data_subject_requests")
    op.drop_index("idx_dsr_tenant_status", table_name="data_subject_requests")
    op.drop_table("data_subject_requests")
