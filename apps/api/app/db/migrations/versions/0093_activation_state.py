"""Keep the accepted activation codes and the licence's clock (/settings/guide/licence).

One row (id 1) holds the JSON state CxMissionZero keeps in DATA_DIR/activation.json:
{tenants, product, seenAt, history}. Each code is kept as the signed code itself and checked again
whenever it is read (app/services/activation_service.py).
"""

from alembic import op
import sqlalchemy as sa


revision = "0093_activation_state"
down_revision = "0092_github_repository_runtime_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "activation_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("activation_state")
