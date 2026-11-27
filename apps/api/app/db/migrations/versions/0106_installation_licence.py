"""The installation's licence: a 3-day trial per installation, then a .hawkai licence (/settings/guide/licence).

The activation_state row (id 1) now also holds the installation ID and when its trial started
(app/services/activation_service.py). This makes sure the row exists on every database that is upgraded, so an
installation upgraded to this version is told apart from one whose row was deleted by hand: the first gets its
72 hours from the upgrade, the second counts them from its oldest account. Nothing else changes.

down_revision is 0105_compliance_packs.
"""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = "0106_installation_licence"
down_revision = "0105_compliance_packs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    present = bind.execute(sa.text("SELECT COUNT(*) FROM activation_state WHERE id = 1")).scalar()
    if not present:
        table = sa.table(
            "activation_state",
            sa.column("id", sa.Integer()),
            sa.column("state", sa.JSON()),
            sa.column("updated_at", sa.DateTime(timezone=True)),
        )
        op.bulk_insert(table, [{"id": 1, "state": {}, "updated_at": datetime.now(timezone.utc)}])


def downgrade() -> None:
    # The row is kept: the earlier version reads it as it is, and ignores what it does not know.
    pass
