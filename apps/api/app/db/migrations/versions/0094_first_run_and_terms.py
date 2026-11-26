"""First run and terms of use (/settings/guide/install, ported from CxMissionZero).

- users.must_change_password: the generated first administrator, and anyone given a temporary password by
  reset_admin, chooses their own password at first sign-in.
- terms_acceptances: who accepted TERMS.md, for the organisation or for themselves, tied to the hash of its text.
- first_run_state: the SHA-256 of the pending first-administrator setup code (FIRST_ADMIN=setup-code), one row.
"""

from alembic import op
import sqlalchemy as sa


revision = "0094_first_run_and_terms"
down_revision = "0093_activation_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "terms_acceptances",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("text_hash", sa.String(length=64), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("via", sa.String(length=32), nullable=False),
        sa.Column("everyone", sa.Boolean(), nullable=False),
        sa.Column("organisation_name", sa.String(length=120), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_terms_acceptance_scope_hash", "terms_acceptances", ["scope", "text_hash"])
    op.create_index("idx_terms_acceptance_user", "terms_acceptances", ["user_id"])
    op.create_table(
        "first_run_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("setup_code_hash", sa.String(length=64), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("first_run_state")
    op.drop_index("idx_terms_acceptance_user", table_name="terms_acceptances")
    op.drop_index("idx_terms_acceptance_scope_hash", table_name="terms_acceptances")
    op.drop_table("terms_acceptances")
    op.drop_column("users", "must_change_password")
