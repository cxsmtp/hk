"""Sign-in hardening (/settings/guide/people-and-access, ported from CxMissionZero's src/iam.js, src/mfa.js, src/oidc.js and
src/password-reset.js).

- users: wrong attempts and the lock after 5 of them (failed_logins, locked_until), the last sign-in, the moment the
  person was signed out everywhere (signed_out_at), two-step sign-in (mfa_*), and the identity provider account they
  are linked to (sso_issuer, sso_subject, unique together).
- sign_in_policy: the administrator's sign-in rules for the whole installation, one row.
- executive_mcp_oauth_clients: clients registered for the Executive MCP connector, with their exact redirect URIs.

down_revision is 0094: another change adds 0095 at the same time; whoever merges both relinks this one after it.
"""

from alembic import op
import sqlalchemy as sa


revision = "0096_signin_hardening"
down_revision = "0094_first_run_and_terms"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("failed_logins", sa.Integer(), nullable=False, server_default=sa.text("0")))
        batch.add_column(sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("signed_out_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("mfa_secret", sa.Text(), nullable=True))
        batch.add_column(sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("mfa_last_step", sa.BigInteger(), nullable=False, server_default=sa.text("0")))
        batch.add_column(sa.Column("mfa_recovery", sa.Text(), nullable=True))
        batch.add_column(sa.Column("sso_issuer", sa.String(length=300), nullable=True))
        batch.add_column(sa.Column("sso_subject", sa.String(length=255), nullable=True))
        batch.create_unique_constraint("uq_users_sso_identity", ["sso_issuer", "sso_subject"])
    op.create_table(
        "sign_in_policy",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("password_reset", sa.String(length=16), nullable=False, server_default="everyone"),
        sa.Column("two_step_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("two_step_reset_for", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("sso_provision", sa.String(length=16), nullable=False, server_default="existing"),
        sa.Column("sso_role", sa.String(length=32), nullable=False, server_default="viewer"),
        sa.Column("sso_domains", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("sso_require_verified_email", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("sso_password_admins_only", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("smtp_verified", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "executive_mcp_oauth_clients",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("client_name", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("redirect_uris", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_executive_mcp_oauth_clients_client_id", "executive_mcp_oauth_clients", ["client_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_executive_mcp_oauth_clients_client_id", table_name="executive_mcp_oauth_clients")
    op.drop_table("executive_mcp_oauth_clients")
    op.drop_table("sign_in_policy")
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("uq_users_sso_identity", type_="unique")
        for column in (
            "sso_subject",
            "sso_issuer",
            "mfa_recovery",
            "mfa_last_step",
            "mfa_enabled_at",
            "mfa_secret",
            "signed_out_at",
            "last_login_at",
            "locked_until",
            "failed_logins",
        ):
            batch.drop_column(column)
