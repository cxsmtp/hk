"""Add canonical Evidence Resolution Graph reasoning and ecosystems.

Revision ID: 0060_evidence_resolution_graph
Revises: 0059_capability_inference_engine
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0060_evidence_resolution_graph"
down_revision = "0059_capability_inference_engine"
branch_labels = None
depends_on = None


TABLES = (
    "discovery_hypothesis_evaluations",
    "discovery_hypothesis_evaluation_edges",
    "discovery_collector_quality_snapshots",
    "discovery_observation_quality_snapshots",
    "discovery_ai_ecosystems",
    "discovery_ecosystem_memberships",
    "discovery_ecosystem_resolution_events",
    "discovery_ecosystem_history_members",
)
IMMUTABLE_TABLES = TABLES
EDGE_TABLE = "discovery_resolution_graph_edges"


def _dialect() -> str:
    value = op.get_bind().dialect.name
    if value not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {value}")
    return value


def _hash_check(column: str, dialect: str) -> str:
    if dialect == "postgresql":
        return f"{column} ~ '^[0-9a-f]{{64}}$'"
    return f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9a-f]*'"


def _json_limit(column: str, limit: int, dialect: str) -> str:
    if dialect == "postgresql":
        return f"octet_length(CAST({column} AS text)) <= {limit}"
    return f"length(CAST({column} AS BLOB)) <= {limit}"


def _json_default(value: str, dialect: str) -> sa.TextClause:
    return sa.text(f"'{value}'{'::json' if dialect == 'postgresql' else ''}")


def _tenant_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id"], ["tenants.id"], name=name, ondelete="CASCADE"
    )


def _extend_graph_edges() -> None:
    if _dialect() == "postgresql":
        _extend_graph_edges_postgresql()
        return
    with op.batch_alter_table(EDGE_TABLE, recreate="always") as batch:
        batch.add_column(sa.Column("collector_id", sa.String(128), nullable=True))
        batch.add_column(sa.Column("source_surface", sa.String(64), nullable=True))
        batch.add_column(sa.Column("signal_class", sa.String(64), server_default=sa.text("'unknown'"), nullable=False))
        batch.add_column(sa.Column("base_confidence", sa.Float(), nullable=True))
        batch.add_column(sa.Column("observation_quality_factor", sa.Float(), nullable=True))
        batch.add_column(sa.Column("collector_quality_factor", sa.Float(), nullable=True))
        batch.add_column(sa.Column("relationship_weight", sa.Float(), server_default=sa.text("1.0"), nullable=False))
        batch.add_column(sa.Column("relationship_rule_id", sa.String(128), server_default=sa.text("'legacy-resolution-graph-v1'"), nullable=False))
        batch.add_column(sa.Column("relationship_rule_version", sa.String(32), server_default=sa.text("'1.0.0'"), nullable=False))
        batch.add_column(sa.Column("decay_policy_id", sa.String(128), server_default=sa.text("'legacy-no-decay'"), nullable=False))
        batch.add_column(sa.Column("decay_policy_version", sa.String(32), server_default=sa.text("'1.0.0'"), nullable=False))
        batch.add_column(sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("edge_schema_version", sa.String(32), server_default=sa.text("'1.0.0'"), nullable=False))
        batch.add_column(sa.Column("edge_sequence", sa.Integer(), server_default=sa.text("1"), nullable=False))
        batch.add_column(sa.Column("predecessor_edge_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_discovery_resolution_graph_edge_tenant_predecessor",
            EDGE_TABLE,
            ["tenant_id", "predecessor_edge_id"],
            ["tenant_id", "edge_id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_edge_base_confidence",
            "base_confidence IS NULL OR (base_confidence >= 0.0 AND base_confidence <= 1.0)",
        )
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_edge_observation_quality",
            "observation_quality_factor IS NULL OR (observation_quality_factor >= 0.0 AND observation_quality_factor <= 1.0)",
        )
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_edge_collector_quality",
            "collector_quality_factor IS NULL OR (collector_quality_factor >= 0.0 AND collector_quality_factor <= 1.0)",
        )
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_edge_weight",
            "relationship_weight > 0.0 AND relationship_weight <= 10.0",
        )
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_edge_sequence",
            "edge_sequence >= 1 AND (predecessor_edge_id IS NOT NULL OR edge_sequence = 1)",
        )
        batch.create_unique_constraint(
            "uq_discovery_resolution_graph_edge_tenant_predecessor",
            ["tenant_id", "predecessor_edge_id"],
        )
        batch.create_index(
            "idx_discovery_resolution_graph_edge_tenant_predecessor",
            ["tenant_id", "predecessor_edge_id", "edge_id"],
        )
    op.execute(
        "UPDATE discovery_resolution_graph_edges SET "
        "base_confidence = confidence, last_validated_at = last_observed_at, "
        "source_surface = 'unknown' "
        "WHERE base_confidence IS NULL OR last_validated_at IS NULL "
        "OR source_surface IS NULL"
    )
    with op.batch_alter_table(EDGE_TABLE, recreate="always") as batch:
        batch.alter_column("source_surface", existing_type=sa.String(64), nullable=False)
        batch.alter_column("base_confidence", existing_type=sa.Float(), nullable=False)
        batch.alter_column("last_validated_at", existing_type=sa.DateTime(timezone=True), nullable=False)


def _extend_graph_edges_postgresql() -> None:
    for column in (
        sa.Column("collector_id", sa.String(128), nullable=True),
        sa.Column("source_surface", sa.String(64), nullable=True),
        sa.Column("signal_class", sa.String(64), server_default=sa.text("'unknown'"), nullable=False),
        sa.Column("base_confidence", sa.Float(), nullable=True),
        sa.Column("observation_quality_factor", sa.Float(), nullable=True),
        sa.Column("collector_quality_factor", sa.Float(), nullable=True),
        sa.Column("relationship_weight", sa.Float(), server_default=sa.text("1.0"), nullable=False),
        sa.Column("relationship_rule_id", sa.String(128), server_default=sa.text("'legacy-resolution-graph-v1'"), nullable=False),
        sa.Column("relationship_rule_version", sa.String(32), server_default=sa.text("'1.0.0'"), nullable=False),
        sa.Column("decay_policy_id", sa.String(128), server_default=sa.text("'legacy-no-decay'"), nullable=False),
        sa.Column("decay_policy_version", sa.String(32), server_default=sa.text("'1.0.0'"), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("edge_schema_version", sa.String(32), server_default=sa.text("'1.0.0'"), nullable=False),
        sa.Column("edge_sequence", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("predecessor_edge_id", sa.String(36), nullable=True),
    ):
        op.add_column(EDGE_TABLE, column)
    op.create_foreign_key(
        "fk_discovery_resolution_graph_edge_tenant_predecessor",
        EDGE_TABLE,
        EDGE_TABLE,
        ["tenant_id", "predecessor_edge_id"],
        ["tenant_id", "edge_id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "ck_discovery_resolution_graph_edge_base_confidence",
        EDGE_TABLE,
        "base_confidence IS NULL OR (base_confidence >= 0.0 AND base_confidence <= 1.0)",
    )
    op.create_check_constraint(
        "ck_discovery_resolution_graph_edge_observation_quality",
        EDGE_TABLE,
        "observation_quality_factor IS NULL OR (observation_quality_factor >= 0.0 AND observation_quality_factor <= 1.0)",
    )
    op.create_check_constraint(
        "ck_discovery_resolution_graph_edge_collector_quality",
        EDGE_TABLE,
        "collector_quality_factor IS NULL OR (collector_quality_factor >= 0.0 AND collector_quality_factor <= 1.0)",
    )
    op.create_check_constraint(
        "ck_discovery_resolution_graph_edge_weight",
        EDGE_TABLE,
        "relationship_weight > 0.0 AND relationship_weight <= 10.0",
    )
    op.create_check_constraint(
        "ck_discovery_resolution_graph_edge_sequence",
        EDGE_TABLE,
        "edge_sequence >= 1 AND (predecessor_edge_id IS NOT NULL OR edge_sequence = 1)",
    )
    op.create_unique_constraint(
        "uq_discovery_resolution_graph_edge_tenant_predecessor",
        EDGE_TABLE,
        ["tenant_id", "predecessor_edge_id"],
    )
    op.create_index(
        "idx_discovery_resolution_graph_edge_tenant_predecessor",
        EDGE_TABLE,
        ["tenant_id", "predecessor_edge_id", "edge_id"],
    )
    op.execute(
        "UPDATE discovery_resolution_graph_edges SET "
        "base_confidence = confidence, last_validated_at = last_observed_at, "
        "source_surface = 'unknown' "
        "WHERE base_confidence IS NULL OR last_validated_at IS NULL "
        "OR source_surface IS NULL"
    )
    op.alter_column(
        EDGE_TABLE, "source_surface", existing_type=sa.String(64), nullable=False
    )
    op.alter_column(
        EDGE_TABLE, "base_confidence", existing_type=sa.Float(), nullable=False
    )
    op.alter_column(
        EDGE_TABLE,
        "last_validated_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
    )


def _remove_graph_extensions() -> None:
    if _dialect() == "postgresql":
        op.drop_index(
            "idx_discovery_resolution_graph_edge_tenant_predecessor",
            table_name=EDGE_TABLE,
        )
        op.drop_constraint(
            "fk_discovery_resolution_graph_edge_tenant_predecessor",
            EDGE_TABLE,
            type_="foreignkey",
        )
        for name in (
            "ck_discovery_resolution_graph_edge_base_confidence",
            "ck_discovery_resolution_graph_edge_observation_quality",
            "ck_discovery_resolution_graph_edge_collector_quality",
            "ck_discovery_resolution_graph_edge_weight",
            "ck_discovery_resolution_graph_edge_sequence",
        ):
            op.drop_constraint(name, EDGE_TABLE, type_="check")
        op.drop_constraint(
            "uq_discovery_resolution_graph_edge_tenant_predecessor",
            EDGE_TABLE,
            type_="unique",
        )
        for column in (
            "collector_id", "source_surface", "signal_class", "base_confidence",
            "observation_quality_factor", "collector_quality_factor", "relationship_weight",
            "relationship_rule_id", "relationship_rule_version", "decay_policy_id",
            "decay_policy_version", "last_validated_at", "edge_schema_version",
            "edge_sequence", "predecessor_edge_id",
        ):
            op.drop_column(EDGE_TABLE, column)
        return
    with op.batch_alter_table(EDGE_TABLE, recreate="always") as batch:
        batch.drop_index("idx_discovery_resolution_graph_edge_tenant_predecessor")
        batch.drop_constraint("fk_discovery_resolution_graph_edge_tenant_predecessor", type_="foreignkey")
        batch.drop_constraint("ck_discovery_resolution_graph_edge_base_confidence", type_="check")
        batch.drop_constraint("ck_discovery_resolution_graph_edge_observation_quality", type_="check")
        batch.drop_constraint("ck_discovery_resolution_graph_edge_collector_quality", type_="check")
        batch.drop_constraint("ck_discovery_resolution_graph_edge_weight", type_="check")
        batch.drop_constraint("ck_discovery_resolution_graph_edge_sequence", type_="check")
        batch.drop_constraint("uq_discovery_resolution_graph_edge_tenant_predecessor", type_="unique")
        for column in (
            "collector_id", "source_surface", "signal_class", "base_confidence",
            "observation_quality_factor", "collector_quality_factor", "relationship_weight",
            "relationship_rule_id", "relationship_rule_version", "decay_policy_id",
            "decay_policy_version", "last_validated_at", "edge_schema_version",
            "edge_sequence", "predecessor_edge_id",
        ):
            batch.drop_column(column)


def _create_hypothesis_tables(dialect: str) -> None:
    op.create_table(
        "discovery_hypothesis_evaluations",
        sa.Column("evaluation_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("hypothesis_id", sa.String(36), nullable=False),
        sa.Column("inference_run_id", sa.String(36), nullable=False),
        sa.Column("predecessor_evaluation_id", sa.String(36), nullable=True),
        sa.Column("evaluation_sequence", sa.Integer(), nullable=False),
        sa.Column("candidate_ecosystem_class", sa.String(128), nullable=False),
        sa.Column("required_anchors_json", sa.JSON(), nullable=False),
        sa.Column("required_anchor_results_json", sa.JSON(), nullable=False),
        sa.Column("base_confidence", sa.Float(), nullable=False),
        sa.Column("effective_confidence", sa.Float(), nullable=True),
        sa.Column("evidence_quality", sa.Float(), nullable=True),
        sa.Column("source_diversity", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("confidence_methodology_id", sa.String(128), nullable=False),
        sa.Column("confidence_methodology_version", sa.String(32), nullable=False),
        sa.Column("decay_policy_id", sa.String(128), nullable=False),
        sa.Column("decay_policy_version", sa.String(32), nullable=False),
        sa.Column("threshold_considered", sa.Float(), nullable=False),
        sa.Column("recommended_action", sa.String(32), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("idempotency_key", sa.String(255), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_eval_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "hypothesis_id"], ["discovery_asset_hypotheses.tenant_id", "discovery_asset_hypotheses.hypothesis_id"], name="fk_erg_eval_tenant_hypothesis", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "inference_run_id"], ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"], name="fk_erg_eval_tenant_run", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "predecessor_evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_erg_eval_tenant_predecessor", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("evaluation_id"),
        sa.UniqueConstraint("tenant_id", "evaluation_id", name="uq_erg_eval_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_eval_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "hypothesis_id", "evaluation_sequence", name="uq_erg_eval_tenant_sequence"),
        sa.UniqueConstraint("tenant_id", "input_digest", name="uq_erg_eval_tenant_digest"),
        sa.CheckConstraint("evaluation_sequence >= 1", name="ck_erg_eval_sequence"),
        sa.CheckConstraint("base_confidence >= 0.0 AND base_confidence <= 1.0", name="ck_erg_eval_base_confidence"),
        sa.CheckConstraint("effective_confidence IS NULL OR (effective_confidence >= 0.0 AND effective_confidence <= 1.0)", name="ck_erg_eval_effective_confidence"),
        sa.CheckConstraint("evidence_quality IS NULL OR (evidence_quality >= 0.0 AND evidence_quality <= 1.0)", name="ck_erg_eval_quality"),
        sa.CheckConstraint("source_diversity >= 0 AND source_diversity <= 64", name="ck_erg_eval_sources"),
        sa.CheckConstraint("threshold_considered >= 0.0 AND threshold_considered <= 1.0", name="ck_erg_eval_threshold"),
        sa.CheckConstraint("recommended_action IN ('create_ecosystem','attach_observation','reject_observation','manual_review','unknown')", name="ck_erg_eval_action"),
        sa.CheckConstraint("first_observed_at <= last_observed_at AND last_observed_at <= validated_at", name="ck_erg_eval_time_order"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_eval_digest"),
        sa.CheckConstraint(_json_limit("required_anchors_json", 16384, dialect), name="ck_erg_eval_anchors_bytes"),
        sa.CheckConstraint(_json_limit("required_anchor_results_json", 16384, dialect), name="ck_erg_eval_anchor_results_bytes"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_erg_eval_limitations_bytes"),
    )
    op.create_index("idx_erg_eval_tenant_hypothesis", "discovery_hypothesis_evaluations", ["tenant_id", "hypothesis_id", "evaluation_sequence", "evaluation_id"])
    op.create_index("idx_erg_eval_tenant_action", "discovery_hypothesis_evaluations", ["tenant_id", "recommended_action", "validated_at", "evaluation_id"])

    op.create_table(
        "discovery_hypothesis_evaluation_edges",
        sa.Column("evaluation_edge_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("evaluation_id", sa.String(36), nullable=False),
        sa.Column("graph_edge_id", sa.String(36), nullable=False),
        sa.Column("contribution", sa.String(32), nullable=False),
        sa.Column("required_anchor", sa.Boolean(), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_eval_edge_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_erg_eval_edge_tenant_eval", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "graph_edge_id"], ["discovery_resolution_graph_edges.tenant_id", "discovery_resolution_graph_edges.edge_id"], name="fk_erg_eval_edge_tenant_graph", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("evaluation_edge_id"),
        sa.UniqueConstraint("tenant_id", "evaluation_edge_id", name="uq_erg_eval_edge_tenant_id"),
        sa.UniqueConstraint("tenant_id", "evaluation_id", "graph_edge_id", name="uq_erg_eval_edge_tenant_member"),
        sa.CheckConstraint("contribution IN ('supporting','contradicting','unknown')", name="ck_erg_eval_edge_contribution"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_eval_edge_digest"),
    )
    op.create_index("idx_erg_eval_edge_tenant_eval", "discovery_hypothesis_evaluation_edges", ["tenant_id", "evaluation_id", "contribution", "evaluation_edge_id"])
    op.create_index("idx_erg_eval_edge_tenant_graph", "discovery_hypothesis_evaluation_edges", ["tenant_id", "graph_edge_id", "evaluation_edge_id"])


def _create_quality_tables(dialect: str) -> None:
    op.create_table(
        "discovery_collector_quality_snapshots",
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=False),
        sa.Column("quality", sa.Float(), nullable=True),
        sa.Column("input_count", sa.Integer(), nullable=False),
        sa.Column("validated_count", sa.Integer(), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("signature_state", sa.String(32), nullable=False),
        sa.Column("methodology_id", sa.String(128), nullable=False),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("input_summary_json", sa.JSON(), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_collector_quality_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "collector_id"], ["discovery_collectors.tenant_id", "discovery_collectors.collector_id"], name="fk_erg_collector_quality_tenant_collector", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint("tenant_id", "snapshot_id", name="uq_erg_collector_quality_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_collector_quality_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "input_digest", name="uq_erg_collector_quality_tenant_digest"),
        sa.CheckConstraint("quality IS NULL OR (quality >= 0.0 AND quality <= 1.0)", name="ck_erg_collector_quality_value"),
        sa.CheckConstraint("input_count >= 0 AND validated_count >= 0 AND validated_count <= input_count", name="ck_erg_collector_quality_counts"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_collector_quality_digest"),
        sa.CheckConstraint(_json_limit("input_summary_json", 16384, dialect), name="ck_erg_collector_quality_input_bytes"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_erg_collector_quality_limitations_bytes"),
    )
    op.create_index("idx_erg_collector_quality_tenant_collector", "discovery_collector_quality_snapshots", ["tenant_id", "collector_id", "calculated_at", "snapshot_id"])

    op.create_table(
        "discovery_observation_quality_snapshots",
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(128), nullable=False),
        sa.Column("collector_quality_snapshot_id", sa.String(36), nullable=False),
        sa.Column("quality", sa.Float(), nullable=True),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("signature_state", sa.String(32), nullable=False),
        sa.Column("validation_state", sa.String(32), nullable=False),
        sa.Column("methodology_id", sa.String(128), nullable=False),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("quality_factors_json", sa.JSON(), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_observation_quality_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_erg_observation_quality_tenant_observation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "collector_quality_snapshot_id"], ["discovery_collector_quality_snapshots.tenant_id", "discovery_collector_quality_snapshots.snapshot_id"], name="fk_erg_observation_quality_tenant_collector", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint("tenant_id", "snapshot_id", name="uq_erg_observation_quality_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_observation_quality_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "input_digest", name="uq_erg_observation_quality_tenant_digest"),
        sa.CheckConstraint("quality IS NULL OR (quality >= 0.0 AND quality <= 1.0)", name="ck_erg_observation_quality_value"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_observation_quality_digest"),
        sa.CheckConstraint(_json_limit("quality_factors_json", 16384, dialect), name="ck_erg_observation_quality_factors_bytes"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_erg_observation_quality_limitations_bytes"),
    )
    op.create_index("idx_erg_observation_quality_tenant_observation", "discovery_observation_quality_snapshots", ["tenant_id", "observation_id", "calculated_at", "snapshot_id"])


def _create_ecosystem_tables(dialect: str) -> None:
    op.create_table(
        "discovery_ai_ecosystems",
        sa.Column("ecosystem_record_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_id", sa.String(36), nullable=False),
        sa.Column("resolution_version", sa.Integer(), nullable=False),
        sa.Column("supersedes_record_id", sa.String(36), nullable=True),
        sa.Column("canonical_name", sa.String(255), nullable=False),
        sa.Column("ecosystem_class", sa.String(128), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("resolution_state", sa.String(32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("evidence_quality", sa.Float(), nullable=True),
        sa.Column("capability_genome_id", sa.String(36), nullable=True),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("methodology_id", sa.String(128), nullable=False),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("outstanding_contradictions", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_ecosystem_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "capability_genome_id"], ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"], name="fk_erg_ecosystem_tenant_genome", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "supersedes_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_erg_ecosystem_tenant_predecessor", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("ecosystem_record_id"),
        sa.UniqueConstraint("tenant_id", "ecosystem_record_id", name="uq_erg_ecosystem_tenant_record"),
        sa.UniqueConstraint("tenant_id", "ecosystem_id", "resolution_version", name="uq_erg_ecosystem_tenant_version"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_ecosystem_tenant_idempotency"),
        sa.CheckConstraint("resolution_version >= 1", name="ck_erg_ecosystem_version"),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)", name="ck_erg_ecosystem_confidence"),
        sa.CheckConstraint("evidence_quality IS NULL OR (evidence_quality >= 0.0 AND evidence_quality <= 1.0)", name="ck_erg_ecosystem_quality"),
        sa.CheckConstraint("lifecycle_state IN ('candidate','active','superseded','rejected','split','unknown')", name="ck_erg_ecosystem_lifecycle"),
        sa.CheckConstraint("resolution_state IN ('hypothesized','resolved','manual_review','unknown','reversed')", name="ck_erg_ecosystem_resolution"),
        sa.CheckConstraint("outstanding_contradictions >= 0", name="ck_erg_ecosystem_contradictions"),
        sa.CheckConstraint("first_observed_at <= last_observed_at AND last_observed_at <= last_validated_at", name="ck_erg_ecosystem_time_order"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_ecosystem_digest"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_erg_ecosystem_limitations_bytes"),
    )
    op.create_index("idx_erg_ecosystem_tenant_id", "discovery_ai_ecosystems", ["tenant_id", "ecosystem_id", "resolution_version", "ecosystem_record_id"])
    op.create_index("idx_erg_ecosystem_tenant_state", "discovery_ai_ecosystems", ["tenant_id", "lifecycle_state", "resolution_state", "last_validated_at", "ecosystem_record_id"])

    op.create_table(
        "discovery_ecosystem_memberships",
        sa.Column("membership_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_record_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_id", sa.String(36), nullable=False),
        sa.Column("graph_node_id", sa.String(36), nullable=False),
        sa.Column("member_type", sa.String(64), nullable=False),
        sa.Column("membership_state", sa.String(32), nullable=False),
        sa.Column("membership_sequence", sa.Integer(), nullable=False),
        sa.Column("predecessor_membership_id", sa.String(36), nullable=True),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_membership_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_erg_membership_tenant_ecosystem", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "graph_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_erg_membership_tenant_graph", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_erg_membership_tenant_evidence", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "predecessor_membership_id"], ["discovery_ecosystem_memberships.tenant_id", "discovery_ecosystem_memberships.membership_id"], name="fk_erg_membership_tenant_predecessor", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("membership_id"),
        sa.UniqueConstraint("tenant_id", "membership_id", name="uq_erg_membership_tenant_id"),
        sa.UniqueConstraint("tenant_id", "ecosystem_id", "graph_node_id", "membership_sequence", name="uq_erg_membership_tenant_sequence"),
        sa.CheckConstraint("membership_sequence >= 1", name="ck_erg_membership_sequence"),
        sa.CheckConstraint("membership_state IN ('active','superseded','rejected','historical')", name="ck_erg_membership_state"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_erg_membership_confidence"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_membership_digest"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_erg_membership_limitations_bytes"),
    )
    op.create_index("idx_erg_membership_tenant_ecosystem", "discovery_ecosystem_memberships", ["tenant_id", "ecosystem_id", "membership_state", "membership_id"])
    op.create_index("idx_erg_membership_tenant_graph", "discovery_ecosystem_memberships", ["tenant_id", "graph_node_id", "membership_state", "membership_id"])

    op.create_table(
        "discovery_ecosystem_resolution_events",
        sa.Column("resolution_event_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("source_ecosystem_ids_json", sa.JSON(), nullable=False),
        sa.Column("result_ecosystem_ids_json", sa.JSON(), nullable=False),
        sa.Column("before_memberships_json", sa.JSON(), nullable=False),
        sa.Column("after_memberships_json", sa.JSON(), nullable=False),
        sa.Column("subject_reference", sa.String(255), nullable=True),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("operator_id", sa.String(128), nullable=False),
        sa.Column("operator_role", sa.String(32), nullable=False),
        sa.Column("methodology_id", sa.String(128), nullable=False),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("reverses_event_id", sa.String(36), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_resolution_event_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_erg_resolution_event_tenant_evidence", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "reverses_event_id"], ["discovery_ecosystem_resolution_events.tenant_id", "discovery_ecosystem_resolution_events.resolution_event_id"], name="fk_erg_resolution_event_tenant_reversal", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("resolution_event_id"),
        sa.UniqueConstraint("tenant_id", "resolution_event_id", name="uq_erg_resolution_event_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_resolution_event_tenant_idempotency"),
        sa.CheckConstraint("action IN ('create','attach','reject','merge','split','reversal','manual_review','unknown')", name="ck_erg_resolution_event_action"),
        sa.CheckConstraint("operator_role IN ('owner','admin','operator','system')", name="ck_erg_resolution_event_role"),
        sa.CheckConstraint("confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)", name="ck_erg_resolution_event_confidence"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_resolution_event_digest"),
        sa.CheckConstraint(_json_limit("source_ecosystem_ids_json", 16384, dialect), name="ck_erg_resolution_event_source_bytes"),
        sa.CheckConstraint(_json_limit("result_ecosystem_ids_json", 16384, dialect), name="ck_erg_resolution_event_result_bytes"),
        sa.CheckConstraint(_json_limit("before_memberships_json", 65536, dialect), name="ck_erg_resolution_event_before_bytes"),
        sa.CheckConstraint(_json_limit("after_memberships_json", 65536, dialect), name="ck_erg_resolution_event_after_bytes"),
    )
    op.create_index("idx_erg_resolution_event_tenant_time", "discovery_ecosystem_resolution_events", ["tenant_id", "occurred_at", "resolution_event_id"])
    op.create_index("idx_erg_resolution_event_tenant_action", "discovery_ecosystem_resolution_events", ["tenant_id", "action", "occurred_at", "resolution_event_id"])

    op.create_table(
        "discovery_ecosystem_history_members",
        sa.Column("history_member_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("resolution_event_id", sa.String(36), nullable=False),
        sa.Column("side", sa.String(16), nullable=False),
        sa.Column("ecosystem_id", sa.String(36), nullable=False),
        sa.Column("graph_node_id", sa.String(36), nullable=False),
        sa.Column("membership_snapshot_json", sa.JSON(), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_erg_history_member_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "resolution_event_id"], ["discovery_ecosystem_resolution_events.tenant_id", "discovery_ecosystem_resolution_events.resolution_event_id"], name="fk_erg_history_member_tenant_event", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "graph_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_erg_history_member_tenant_graph", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("history_member_id"),
        sa.UniqueConstraint("tenant_id", "history_member_id", name="uq_erg_history_member_tenant_id"),
        sa.UniqueConstraint("tenant_id", "resolution_event_id", "side", "ecosystem_id", "graph_node_id", name="uq_erg_history_member_tenant_fact"),
        sa.CheckConstraint("side IN ('before','after')", name="ck_erg_history_member_side"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_erg_history_member_digest"),
        sa.CheckConstraint(_json_limit("membership_snapshot_json", 32768, dialect), name="ck_erg_history_member_snapshot_bytes"),
    )
    op.create_index("idx_erg_history_member_tenant_event", "discovery_ecosystem_history_members", ["tenant_id", "resolution_event_id", "side", "history_member_id"])
    op.create_index("idx_erg_history_member_tenant_ecosystem", "discovery_ecosystem_history_members", ["tenant_id", "ecosystem_id", "history_member_id"])


def _install_immutable_guards(dialect: str) -> None:
    guarded = (*IMMUTABLE_TABLES, EDGE_TABLE)
    if dialect == "sqlite":
        for table in guarded:
            short = table.removeprefix("discovery_").replace("resolution_graph_", "graph_")
            for action in ("update", "delete"):
                op.execute(
                    f"CREATE TRIGGER trg_erg_{short}_immutable_{action} "
                    f"BEFORE {action.upper()} ON {table} BEGIN "
                    "SELECT RAISE(ABORT, 'ERG evidence is append-only'); END"
                )
        return
    op.execute(
        "CREATE FUNCTION hawk_reject_erg_mutation() RETURNS trigger AS $$ "
        "BEGIN RAISE EXCEPTION 'ERG evidence is append-only'; END; "
        "$$ LANGUAGE plpgsql"
    )
    for table in guarded:
        short = table.removeprefix("discovery_").replace("resolution_graph_", "graph_")
        op.execute(
            f"CREATE TRIGGER trg_erg_{short}_immutable BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION hawk_reject_erg_mutation()"
        )


def _install_edge_successor_guard(dialect: str) -> None:
    if dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER trg_erg_graph_edge_successor_shape "
            "BEFORE INSERT ON discovery_resolution_graph_edges "
            "WHEN NEW.predecessor_edge_id IS NOT NULL BEGIN "
            "SELECT CASE WHEN NOT EXISTS ("
            "SELECT 1 FROM discovery_resolution_graph_edges predecessor "
            "WHERE predecessor.tenant_id = NEW.tenant_id "
            "AND predecessor.edge_id = NEW.predecessor_edge_id "
            "AND predecessor.from_node_id = NEW.from_node_id "
            "AND predecessor.to_node_id = NEW.to_node_id "
            "AND predecessor.edge_type = NEW.edge_type "
            "AND NEW.edge_sequence = predecessor.edge_sequence + 1"
            ") THEN RAISE(ABORT, 'ERG edge successor shape is invalid') END; END"
        )
        return
    op.execute(
        "CREATE FUNCTION hawk_validate_erg_edge_successor() RETURNS trigger AS $$ "
        "DECLARE predecessor discovery_resolution_graph_edges%ROWTYPE; "
        "BEGIN "
        "IF NEW.predecessor_edge_id IS NULL THEN "
        "IF NEW.edge_sequence <> 1 THEN "
        "RAISE EXCEPTION 'ERG root edge sequence is invalid'; END IF; "
        "RETURN NEW; END IF; "
        "SELECT * INTO predecessor FROM discovery_resolution_graph_edges "
        "WHERE tenant_id = NEW.tenant_id AND edge_id = NEW.predecessor_edge_id "
        "FOR SHARE; "
        "IF NOT FOUND OR predecessor.from_node_id <> NEW.from_node_id "
        "OR predecessor.to_node_id <> NEW.to_node_id "
        "OR predecessor.edge_type <> NEW.edge_type "
        "OR NEW.edge_sequence <> predecessor.edge_sequence + 1 THEN "
        "RAISE EXCEPTION 'ERG edge successor shape is invalid'; END IF; "
        "RETURN NEW; END; $$ LANGUAGE plpgsql"
    )
    op.execute(
        "CREATE TRIGGER trg_erg_graph_edge_successor_shape "
        "BEFORE INSERT ON discovery_resolution_graph_edges "
        "FOR EACH ROW EXECUTE FUNCTION hawk_validate_erg_edge_successor()"
    )


def upgrade() -> None:
    dialect = _dialect()
    _extend_graph_edges()
    _create_hypothesis_tables(dialect)
    _create_quality_tables(dialect)
    _create_ecosystem_tables(dialect)
    _install_edge_successor_guard(dialect)
    _install_immutable_guards(dialect)


def downgrade() -> None:
    dialect = _dialect()
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_erg_graph_edge_successor_shape")
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_erg_graph_edge_successor_shape "
            "ON discovery_resolution_graph_edges"
        )
        op.execute("DROP FUNCTION IF EXISTS hawk_validate_erg_edge_successor()")
        for table in (*IMMUTABLE_TABLES, EDGE_TABLE):
            short = table.removeprefix("discovery_").replace("resolution_graph_", "graph_")
            op.execute(f"DROP TRIGGER IF EXISTS trg_erg_{short}_immutable ON {table}")
    for table in reversed(TABLES):
        op.drop_table(table)
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS hawk_reject_erg_mutation()")
    _remove_graph_extensions()
