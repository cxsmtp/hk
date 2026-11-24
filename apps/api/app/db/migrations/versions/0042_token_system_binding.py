"""Bind capability tokens to their exact AI system.

Revision ID: 0042_token_system_binding
Revises: 0041_tenant_guardian_sim
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0042_token_system_binding"
down_revision = "0041_tenant_guardian_sim"
branch_labels = None
depends_on = None


def _backfill_unambiguous_token_systems() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            """
            SELECT token_bindings.token_id, MIN(token_bindings.ai_system_id) AS ai_system_id
            FROM (
                SELECT parent_token_id AS token_id, tenant_id, ai_system_id
                FROM agent_delegations
                WHERE ai_system_id IS NOT NULL
                UNION ALL
                SELECT child_token_id AS token_id, tenant_id, ai_system_id
                FROM agent_delegations
                WHERE ai_system_id IS NOT NULL
            ) AS token_bindings
            JOIN capability_tokens AS capability_token
              ON capability_token.id = token_bindings.token_id
             AND capability_token.tenant_id = token_bindings.tenant_id
            GROUP BY token_bindings.token_id
            HAVING COUNT(DISTINCT token_bindings.ai_system_id) = 1
            """
        )
    ).mappings()
    for row in rows:
        bind.execute(
            sa.text(
                "UPDATE capability_tokens SET ai_system_id = :ai_system_id "
                "WHERE id = :token_id AND ai_system_id IS NULL"
            ),
            {"token_id": row["token_id"], "ai_system_id": row["ai_system_id"]},
        )


def upgrade() -> None:
    with op.batch_alter_table("capability_tokens") as batch_op:
        batch_op.add_column(sa.Column("ai_system_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_capability_tokens_ai_system",
            "ai_systems",
            ["ai_system_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_index("idx_token_ai_system", ["ai_system_id"], unique=False)
    _backfill_unambiguous_token_systems()


def downgrade() -> None:
    with op.batch_alter_table("capability_tokens") as batch_op:
        batch_op.drop_index("idx_token_ai_system")
        batch_op.drop_constraint("fk_capability_tokens_ai_system", type_="foreignkey")
        batch_op.drop_column("ai_system_id")
