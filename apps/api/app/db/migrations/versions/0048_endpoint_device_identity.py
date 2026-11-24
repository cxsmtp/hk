"""add secretless endpoint device identity

Revision ID: 0048_endpoint_device_identity
Revises: 0047_discovery_scan_obs
"""

from alembic import op
import sqlalchemy as sa


revision = "0048_endpoint_device_identity"
down_revision = "0047_discovery_scan_obs"
branch_labels = None
depends_on = None


def _json_default(value: str) -> sa.TextClause:
    suffix = "::json" if op.get_context().dialect.name == "postgresql" else ""
    return sa.text(f"'{value}'{suffix}")


def upgrade() -> None:
    op.create_table(
        "endpoint_device_identities",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("endpoint_id", sa.String(length=128), nullable=False),
        sa.Column("assigned_user_id", sa.String(length=36), nullable=True),
        sa.Column("public_key_pem", sa.String(length=2048), nullable=False),
        sa.Column("key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column("key_provider", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("enrolled_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("revocation_reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('active','revoked','quarantined')", name="ck_endpoint_identity_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["enrolled_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["revoked_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "endpoint_id", name="uq_endpoint_identity_tenant_endpoint"),
        sa.UniqueConstraint("key_thumbprint", name="uq_endpoint_identity_key_thumbprint"),
    )
    op.create_index("idx_endpoint_identity_tenant_status", "endpoint_device_identities", ["tenant_id", "status"])
    op.create_index("idx_endpoint_identity_assigned_user", "endpoint_device_identities", ["tenant_id", "assigned_user_id"])

    op.create_table(
        "endpoint_enrollment_authorizations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("endpoint_id", sa.String(length=128), nullable=True),
        sa.Column("assigned_user_id", sa.String(length=36), nullable=True),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("issued_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["issued_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash", name="uq_endpoint_enrollment_code_hash"),
        sa.UniqueConstraint("nonce_hash", name="uq_endpoint_enrollment_nonce_hash"),
    )
    op.create_index("idx_endpoint_enrollment_tenant_expiry", "endpoint_enrollment_authorizations", ["tenant_id", "expires_at"])

    op.create_table(
        "endpoint_auth_challenges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("device_identity_id", sa.String(length=36), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["device_identity_id"], ["endpoint_device_identities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("nonce_hash", name="uq_endpoint_auth_challenge_nonce_hash"),
    )
    op.create_index("idx_endpoint_auth_challenge_identity_expiry", "endpoint_auth_challenges", ["device_identity_id", "expires_at"])

    op.create_table(
        "endpoint_proof_replays",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("device_identity_id", sa.String(length=36), nullable=False),
        sa.Column("proof_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["device_identity_id"], ["endpoint_device_identities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("proof_hash", name="uq_endpoint_proof_hash"),
    )
    op.create_index("idx_endpoint_proof_identity_expiry", "endpoint_proof_replays", ["device_identity_id", "expires_at"])


def downgrade() -> None:
    op.drop_index("idx_endpoint_proof_identity_expiry", table_name="endpoint_proof_replays")
    op.drop_table("endpoint_proof_replays")
    op.drop_index("idx_endpoint_auth_challenge_identity_expiry", table_name="endpoint_auth_challenges")
    op.drop_table("endpoint_auth_challenges")
    op.drop_index("idx_endpoint_enrollment_tenant_expiry", table_name="endpoint_enrollment_authorizations")
    op.drop_table("endpoint_enrollment_authorizations")
    op.drop_index("idx_endpoint_identity_assigned_user", table_name="endpoint_device_identities")
    op.drop_index("idx_endpoint_identity_tenant_status", table_name="endpoint_device_identities")
    op.drop_table("endpoint_device_identities")
