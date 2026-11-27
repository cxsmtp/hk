"""Framework packs on Settings → Compliance (app/services/compliance_packs, /settings/guide/compliance).

- compliance_attestations: what a tenant's owner or admin recorded about one requirement of a pack: in place (the
  organisation's own process, with where its evidence is) or not applicable (with the reason), until it is due for
  review. One row per tenant, pack and requirement; every change is in the audit log.

down_revision is 0104_desc_controls.
"""

from alembic import op
import sqlalchemy as sa


revision = "0105_compliance_packs"
down_revision = "0104_desc_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_attestations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("pack_id", sa.String(length=64), nullable=False),
        sa.Column("requirement_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("reference", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("attested_by", sa.String(length=36), nullable=True),
        sa.Column("attested_by_email", sa.String(length=320), nullable=False, server_default=""),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("uq_compliance_attestation", "compliance_attestations", ["tenant_id", "pack_id", "requirement_id"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_compliance_attestation", table_name="compliance_attestations")
    op.drop_table("compliance_attestations")
