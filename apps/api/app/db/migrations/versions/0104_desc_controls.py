"""Controls for the Dubai Electronic Security Center's Information Security Regulation (DESC ISR), the UAE IA
Standard and India's CERT-In directions (Settings → Compliance, /settings/guide/compliance).

- sign_in_policy: the password rule (shortest length, kinds of character, how many earlier passwords may not come
  back, how many days a password lasts), the idle sign-out when set here instead of SESSION_IDLE_MINUTES, and the
  notice shown on the sign-in page.
- users: when the password was last set, and the hashes of the earlier ones (for the "not one of the last N" rule).
- compliance_policy: one row: how long the user activity and connector API activity are kept (180 days at least,
  CERT-In), the data location statement shown in About, and whom an incident report names as the contact.

down_revision is 0103_terms_acceptance.
"""

from alembic import op
import sqlalchemy as sa


revision = "0104_desc_controls"
down_revision = "0103_terms_acceptance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("sign_in_policy") as batch:
        batch.add_column(sa.Column("password_min_length", sa.Integer(), nullable=False, server_default=sa.text("12")))
        batch.add_column(sa.Column("password_classes", sa.Integer(), nullable=False, server_default=sa.text("0")))
        batch.add_column(sa.Column("password_history", sa.Integer(), nullable=False, server_default=sa.text("0")))
        batch.add_column(sa.Column("password_max_age_days", sa.Integer(), nullable=False, server_default=sa.text("0")))
        batch.add_column(sa.Column("session_idle_minutes", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("banner_text", sa.Text(), nullable=False, server_default=""))
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("password_history", sa.Text(), nullable=True))
    op.create_table(
        "compliance_policy",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("activity_retention_days", sa.Integer(), nullable=False, server_default=sa.text("365")),
        sa.Column("connector_retention_days", sa.Integer(), nullable=False, server_default=sa.text("180")),
        sa.Column("data_location", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("incident_contact", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("compliance_policy")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("password_history")
        batch.drop_column("password_changed_at")
    with op.batch_alter_table("sign_in_policy") as batch:
        for column in ("banner_text", "session_idle_minutes", "password_max_age_days", "password_history", "password_classes", "password_min_length"):
            batch.drop_column(column)
