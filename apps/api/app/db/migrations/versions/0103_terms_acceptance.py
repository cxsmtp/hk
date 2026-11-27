"""The licence agreement's acceptance record and its emailed copy (TERMS.md, app/services/terms_service.py).

- terms_acceptances: the acceptor's full name, tenant, browser (user agent) and whether they confirmed they are
  authorised to accept for the company. Rows are never changed or deleted (app/db/models/access.py).
- terms_texts: the exact rendered text of each accepted version, by its SHA-256.
- terms_copy_emails: the emailed copy of each acceptance, queued until the email server is set up and tested
  (app/services/terms_copy_service.py).

down_revision is 0102_ai_system_approval_policy.
"""

from alembic import op
import sqlalchemy as sa


revision = "0103_terms_acceptance"
down_revision = "0102_ai_system_approval_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("terms_acceptances", sa.Column("full_name", sa.String(length=200), nullable=False, server_default=""))
    op.add_column("terms_acceptances", sa.Column("tenant_id", sa.String(length=36), nullable=True))
    op.add_column("terms_acceptances", sa.Column("user_agent", sa.String(length=512), nullable=False, server_default=""))
    op.add_column("terms_acceptances", sa.Column("authorised", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "terms_texts",
        sa.Column("text_hash", sa.String(length=64), primary_key=True),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "terms_copy_emails",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("acceptance_id", sa.String(length=36), sa.ForeignKey("terms_acceptances.id"), nullable=False),
        sa.Column("to_email", sa.String(length=320), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("requested_by", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_terms_copy_emails_acceptance_id", "terms_copy_emails", ["acceptance_id"])
    op.create_index("idx_terms_copy_email_status", "terms_copy_emails", ["status", "next_attempt_at"])


def downgrade() -> None:
    op.drop_index("idx_terms_copy_email_status", table_name="terms_copy_emails")
    op.drop_index("ix_terms_copy_emails_acceptance_id", table_name="terms_copy_emails")
    op.drop_table("terms_copy_emails")
    op.drop_table("terms_texts")
    op.drop_column("terms_acceptances", "authorised")
    op.drop_column("terms_acceptances", "user_agent")
    op.drop_column("terms_acceptances", "tenant_id")
    op.drop_column("terms_acceptances", "full_name")
