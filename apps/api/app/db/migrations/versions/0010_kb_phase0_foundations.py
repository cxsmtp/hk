"""add phase0 knowledge base foundation tables

Revision ID: 0010_kb_phase0_foundations
Revises: 0009_brain_phase1_model_logs
Create Date: 2026-02-24 13:15:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0010_kb_phase0_foundations"
down_revision = "0009_brain_phase1_model_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kb_framework",
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.CheckConstraint("source_type in ('authored','customer_provided')", name="ck_kb_framework_source_type"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_framework_name", "kb_framework", ["name"])
    op.create_index("idx_kb_framework_source", "kb_framework", ["source_type"])

    op.create_table(
        "kb_control",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("framework_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("requirement_level", sa.String(length=8), nullable=False),
        sa.Column("applicability_tags", sa.JSON(), nullable=False),
        sa.Column("maturity_model", sa.JSON(), nullable=False),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("requirement_level in ('MUST','SHOULD','MAY')", name="ck_kb_control_requirement_level"),
        sa.ForeignKeyConstraint(["framework_id"], ["kb_framework.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_control_framework", "kb_control", ["framework_id"])
    op.create_index("idx_kb_control_requirement", "kb_control", ["requirement_level"])

    op.create_table(
        "kb_crosswalk",
        sa.Column("from_control_id", sa.String(length=128), nullable=False),
        sa.Column("to_control_id", sa.String(length=128), nullable=False),
        sa.Column("mapping_type", sa.String(length=16), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.CheckConstraint("mapping_type in ('equivalent','partial','supports')", name="ck_kb_crosswalk_mapping_type"),
        sa.ForeignKeyConstraint(["from_control_id"], ["kb_control.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["to_control_id"], ["kb_control.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_crosswalk_from", "kb_crosswalk", ["from_control_id"])
    op.create_index("idx_kb_crosswalk_to", "kb_crosswalk", ["to_control_id"])

    op.create_table(
        "kb_threat",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("framework_ref", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description_short", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_threat_framework_ref", "kb_threat", ["framework_ref"])

    op.create_table(
        "kb_threat_control_map",
        sa.Column("threat_id", sa.String(length=128), nullable=False),
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("coverage", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.CheckConstraint("coverage in ('detect','prevent','respond')", name="ck_kb_tcm_coverage"),
        sa.CheckConstraint("severity in ('low','med','high','critical')", name="ck_kb_tcm_severity"),
        sa.ForeignKeyConstraint(["threat_id"], ["kb_threat.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["control_id"], ["kb_control.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_tcm_threat", "kb_threat_control_map", ["threat_id"])
    op.create_index("idx_kb_tcm_control", "kb_threat_control_map", ["control_id"])

    op.create_table(
        "kb_simulation_template",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("template_schema", sa.JSON(), nullable=False),
        sa.Column("safe_boundary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_sim_template_category", "kb_simulation_template", ["category"])

    op.create_table(
        "kb_control_sim_map",
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("simulation_template_id", sa.String(length=36), nullable=False),
        sa.Column("required_frequency", sa.String(length=16), nullable=False),
        sa.Column("failure_impact", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.CheckConstraint("required_frequency in ('daily','weekly','monthly','on_change')", name="ck_kb_csm_frequency"),
        sa.ForeignKeyConstraint(["control_id"], ["kb_control.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["simulation_template_id"], ["kb_simulation_template.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_csm_control", "kb_control_sim_map", ["control_id"])
    op.create_index("idx_kb_csm_template", "kb_control_sim_map", ["simulation_template_id"])

    op.create_table(
        "kb_guardian_contract",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("intent", sa.Text(), nullable=False),
        sa.Column("detection_inputs", sa.JSON(), nullable=False),
        sa.Column("enforcement_contract", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "kb_control_guardian_map",
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("guardian_contract_id", sa.String(length=36), nullable=False),
        sa.Column("enforcement_strength", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "enforcement_strength in ('baseline','strict','maximum')",
            name="ck_kb_cgm_strength",
        ),
        sa.ForeignKeyConstraint(["control_id"], ["kb_control.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["guardian_contract_id"], ["kb_guardian_contract.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_cgm_control", "kb_control_guardian_map", ["control_id"])
    op.create_index("idx_kb_cgm_guardian", "kb_control_guardian_map", ["guardian_contract_id"])

    op.create_table(
        "kb_doc",
        sa.Column("framework_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.CheckConstraint("source_type in ('authored','customer_provided')", name="ck_kb_doc_source_type"),
        sa.ForeignKeyConstraint(["framework_id"], ["kb_framework.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_doc_framework", "kb_doc", ["framework_id"])
    op.create_index("idx_kb_doc_source", "kb_doc", ["source_type"])

    op.create_table(
        "kb_embedding",
        sa.Column("doc_id", sa.String(length=36), nullable=False),
        sa.Column("embedding_model", sa.String(length=128), nullable=False),
        sa.Column("vector", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["doc_id"], ["kb_doc.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_kb_embedding_doc", "kb_embedding", ["doc_id"])


def downgrade() -> None:
    op.drop_index("idx_kb_embedding_doc", table_name="kb_embedding")
    op.drop_table("kb_embedding")

    op.drop_index("idx_kb_doc_source", table_name="kb_doc")
    op.drop_index("idx_kb_doc_framework", table_name="kb_doc")
    op.drop_table("kb_doc")

    op.drop_index("idx_kb_cgm_guardian", table_name="kb_control_guardian_map")
    op.drop_index("idx_kb_cgm_control", table_name="kb_control_guardian_map")
    op.drop_table("kb_control_guardian_map")

    op.drop_table("kb_guardian_contract")

    op.drop_index("idx_kb_csm_template", table_name="kb_control_sim_map")
    op.drop_index("idx_kb_csm_control", table_name="kb_control_sim_map")
    op.drop_table("kb_control_sim_map")

    op.drop_index("idx_kb_sim_template_category", table_name="kb_simulation_template")
    op.drop_table("kb_simulation_template")

    op.drop_index("idx_kb_tcm_control", table_name="kb_threat_control_map")
    op.drop_index("idx_kb_tcm_threat", table_name="kb_threat_control_map")
    op.drop_table("kb_threat_control_map")

    op.drop_index("idx_kb_threat_framework_ref", table_name="kb_threat")
    op.drop_table("kb_threat")

    op.drop_index("idx_kb_crosswalk_to", table_name="kb_crosswalk")
    op.drop_index("idx_kb_crosswalk_from", table_name="kb_crosswalk")
    op.drop_table("kb_crosswalk")

    op.drop_index("idx_kb_control_requirement", table_name="kb_control")
    op.drop_index("idx_kb_control_framework", table_name="kb_control")
    op.drop_table("kb_control")

    op.drop_index("idx_kb_framework_source", table_name="kb_framework")
    op.drop_index("idx_kb_framework_name", table_name="kb_framework")
    op.drop_table("kb_framework")
