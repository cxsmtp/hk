"""canonical policy snapshots and evidence bundles

Revision ID: 0044_canonical_evidence_bundles
Revises: 0043_decision_execution_receipts
"""

from alembic import op
import sqlalchemy as sa


revision = "0044_canonical_evidence_bundles"
down_revision = "0043_decision_execution_receipts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("evidence_edges") as batch:
        batch.add_column(sa.Column("integrity_key", sa.String(length=64), nullable=True))
        batch.create_foreign_key(
            "fk_evidence_edge_tenant_from", "evidence_nodes",
            ["tenant_id", "from_node_id"], ["tenant_id", "id"], ondelete="CASCADE",
        )
        batch.create_foreign_key(
            "fk_evidence_edge_tenant_to", "evidence_nodes",
            ["tenant_id", "to_node_id"], ["tenant_id", "id"], ondelete="CASCADE",
        )
        batch.create_index(
            "idx_evidence_edge_tenant_from_type",
            ["tenant_id", "from_node_id", "edge_type"], unique=False,
        )
        batch.create_unique_constraint(
            "uq_evidence_edges_canonical_integrity",
            ["tenant_id", "from_node_id", "edge_type", "integrity_key"],
        )
        batch.create_check_constraint(
            "ck_evidence_edges_canonical_integrity_key",
            "edge_type NOT IN ('bundle_manifest', 'bundle_member') OR integrity_key IS NOT NULL",
        )
    with op.batch_alter_table("decision_receipts") as batch:
        batch.add_column(sa.Column("policy_snapshot_evidence_node_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("evidence_bundle_id", sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            "fk_decision_receipt_tenant_policy_snapshot_evidence", "evidence_nodes",
            ["tenant_id", "policy_snapshot_evidence_node_id"], ["tenant_id", "id"], ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_decision_receipt_tenant_bundle", "evidence_nodes",
            ["tenant_id", "evidence_bundle_id"], ["tenant_id", "id"], ondelete="RESTRICT",
        )
        batch.create_index(
            "idx_decision_receipts_tenant_bundle", ["tenant_id", "evidence_bundle_id"], unique=False,
        )
    with op.batch_alter_table("runtime_events") as batch:
        batch.add_column(sa.Column("evidence_bundle_id", sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            "fk_runtime_events_tenant_bundle", "evidence_nodes",
            ["tenant_id", "evidence_bundle_id"], ["tenant_id", "id"], ondelete="SET NULL",
        )
        batch.create_index(
            "idx_runtime_events_tenant_bundle", ["tenant_id", "evidence_bundle_id"], unique=False,
        )
    with op.batch_alter_table("ai_actions") as batch:
        batch.add_column(sa.Column("evidence_bundle_id", sa.String(length=36), nullable=True))
        batch.create_foreign_key(
            "fk_ai_actions_tenant_bundle", "evidence_nodes",
            ["tenant_id", "evidence_bundle_id"], ["tenant_id", "id"], ondelete="SET NULL",
        )
        batch.create_index(
            "idx_ai_actions_tenant_bundle", ["tenant_id", "evidence_bundle_id"], unique=False,
        )
    if op.get_bind().dialect.name == "sqlite":
        for table_name in ("evidence_nodes", "evidence_edges"):
            op.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS trg_{table_name}_immutable_update
                BEFORE UPDATE ON {table_name}
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT, 'immutable_table:{table_name}');
                END;
                """
            )
            op.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS trg_{table_name}_immutable_delete
                BEFORE DELETE ON {table_name}
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT, 'immutable_table:{table_name}');
                END;
                """
            )


def downgrade() -> None:
    with op.batch_alter_table("ai_actions") as batch:
        batch.drop_index("idx_ai_actions_tenant_bundle")
        batch.drop_constraint("fk_ai_actions_tenant_bundle", type_="foreignkey")
        batch.drop_column("evidence_bundle_id")
    with op.batch_alter_table("runtime_events") as batch:
        batch.drop_index("idx_runtime_events_tenant_bundle")
        batch.drop_constraint("fk_runtime_events_tenant_bundle", type_="foreignkey")
        batch.drop_column("evidence_bundle_id")
    with op.batch_alter_table("decision_receipts") as batch:
        batch.drop_index("idx_decision_receipts_tenant_bundle")
        batch.drop_constraint("fk_decision_receipt_tenant_bundle", type_="foreignkey")
        batch.drop_constraint("fk_decision_receipt_tenant_policy_snapshot_evidence", type_="foreignkey")
        batch.drop_column("evidence_bundle_id")
        batch.drop_column("policy_snapshot_evidence_node_id")
    with op.batch_alter_table("evidence_edges") as batch:
        batch.drop_index("idx_evidence_edge_tenant_from_type")
        batch.drop_constraint("ck_evidence_edges_canonical_integrity_key", type_="check")
        batch.drop_constraint("uq_evidence_edges_canonical_integrity", type_="unique")
        batch.drop_constraint("fk_evidence_edge_tenant_to", type_="foreignkey")
        batch.drop_constraint("fk_evidence_edge_tenant_from", type_="foreignkey")
        batch.drop_column("integrity_key")
    if op.get_bind().dialect.name == "sqlite":
        for table_name in ("evidence_nodes", "evidence_edges"):
            op.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS trg_{table_name}_immutable_update
                BEFORE UPDATE ON {table_name}
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT, 'immutable_table:{table_name}');
                END;
                """
            )
            op.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS trg_{table_name}_immutable_delete
                BEFORE DELETE ON {table_name}
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT, 'immutable_table:{table_name}');
                END;
                """
            )
