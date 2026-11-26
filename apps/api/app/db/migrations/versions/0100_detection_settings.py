"""Per-tenant DLP and prompt-injection settings (app/services/detection/profile.py):

- detection_settings: one row per tenant: category toggles, custom dictionaries and injection thresholds (config), and
  the exact-data-match sets as salted HMAC digests only (fingerprints), under the tenant's own salt. No row means the
  defaults, which are what every tenant had before.
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0100_detection_settings"
down_revision = "0099_iam_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_settings",
        sa.Column("tenant_id", sa.String(length=36), primary_key=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("fingerprint_salt", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("fingerprints", sa.JSON(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=320), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_table("detection_settings")
