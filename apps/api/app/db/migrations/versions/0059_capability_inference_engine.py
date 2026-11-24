"""Add append-only Capability Inference Engine evidence.

Revision ID: 0059_capability_inference_engine
Revises: 0058_discovery_intelligence
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0059_capability_inference_engine"
down_revision = "0058_discovery_intelligence"
branch_labels = None
depends_on = None


TABLES = (
    "discovery_capability_inference_runs",
    "discovery_capability_evidence",
    "discovery_capability_genomes",
    "discovery_capability_events",
)
IMMUTABLE_TABLES = TABLES

GRAPH_NODE_CLASSES = (
    "'observation','hypothesis','ai_asset','identity','runtime','model','tool',"
    "'mcp_server','data_asset','network_destination','repository','cloud_resource',"
    "'saas_app','capability','provider','configuration','marketplace','extension',"
    "'dependency','project','database','process','mcp','usage','user',"
    "'service_account','application','environment','permission','relationship',"
    "'ai_ecosystem'"
)
GRAPH_EDGE_TYPES = (
    "'supports','contradicts','observed_on','runs_on','used_by','calls',"
    "'connects_to','depends_on','authenticates_as','hosted_in','exposes','accesses',"
    "'possibly_same_as','replaces','split_from','merged_from','observed_by','uses',"
    "'invokes','provides','connected_to','same_identity','same_runtime',"
    "'same_repository','same_configuration','same_provider','same_project',"
    "'same_user','potential_match','resolved_match','historical_match'"
)
LEGACY_GRAPH_NODE_CLASSES = (
    "'observation','hypothesis','ai_asset','identity','runtime','model','tool',"
    "'mcp_server','data_asset','network_destination','repository','cloud_resource',"
    "'saas_app'"
)
LEGACY_GRAPH_EDGE_TYPES = (
    "'supports','contradicts','observed_on','runs_on','used_by','calls',"
    "'connects_to','depends_on','authenticates_as','hosted_in','exposes','accesses',"
    "'possibly_same_as','replaces','split_from','merged_from'"
)


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


def _create_runs(dialect: str) -> None:
    op.create_table(
        "discovery_capability_inference_runs",
        sa.Column("inference_run_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("subject_reference_hash", sa.String(64), nullable=False),
        sa.Column("observation_ids_json", sa.JSON(), nullable=False),
        sa.Column("engine_version", sa.String(64), nullable=False),
        sa.Column("catalog_version", sa.String(64), nullable=False),
        sa.Column("ruleset_version", sa.String(64), nullable=False),
        sa.Column("run_sequence", sa.Integer(), nullable=False),
        sa.Column("supersedes_run_id", sa.String(36), nullable=True),
        sa.Column("recommended_asset_type", sa.String(64), nullable=False),
        sa.Column("recommended_ecosystem", sa.String(128), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("output_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_cie_run_tenant"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_cie_run_tenant_evidence", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "supersedes_run_id"],
            ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"],
            name="fk_cie_run_tenant_predecessor", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("inference_run_id"),
        sa.UniqueConstraint("tenant_id", "inference_run_id", name="uq_cie_run_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_cie_run_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "subject_reference_hash", "run_sequence", name="uq_cie_run_tenant_subject_seq"),
        sa.CheckConstraint(_hash_check("subject_reference_hash", dialect), name="ck_cie_run_subject_hash"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_cie_run_input_digest"),
        sa.CheckConstraint(_hash_check("output_digest", dialect), name="ck_cie_run_output_digest"),
        sa.CheckConstraint("run_sequence >= 1", name="ck_cie_run_sequence"),
        sa.CheckConstraint("first_observed_at <= last_observed_at AND last_observed_at <= validated_at", name="ck_cie_run_time_order"),
        sa.CheckConstraint(_json_limit("observation_ids_json", 65536, dialect), name="ck_cie_run_observations_bytes"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_cie_run_limitations_bytes"),
    )
    op.create_index("idx_cie_run_tenant_subject", "discovery_capability_inference_runs", ["tenant_id", "subject_reference_hash", "run_sequence", "inference_run_id"])
    op.create_index("idx_cie_run_tenant_validated", "discovery_capability_inference_runs", ["tenant_id", "validated_at", "inference_run_id"])


def _create_evidence(dialect: str) -> None:
    op.create_table(
        "discovery_capability_evidence",
        sa.Column("capability_evidence_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("inference_run_id", sa.String(36), nullable=False),
        sa.Column("capability_id", sa.String(64), nullable=False),
        sa.Column("family", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.String(32), nullable=False),
        sa.Column("calibration_version", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("supporting_signal_ids_json", sa.JSON(), nullable=False),
        sa.Column("conflicting_signal_ids_json", sa.JSON(), nullable=False),
        sa.Column("unknown_predicates_json", sa.JSON(), nullable=False),
        sa.Column("source_diversity", sa.Integer(), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("explanation", sa.String(1500), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("recommended_asset_type", sa.String(64), nullable=False),
        sa.Column("recommended_ecosystem", sa.String(128), nullable=False),
        sa.Column("evidence_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_cie_evidence_tenant"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "inference_run_id"],
            ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"],
            name="fk_cie_evidence_tenant_run", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("capability_evidence_id"),
        sa.UniqueConstraint("tenant_id", "capability_evidence_id", name="uq_cie_evidence_tenant_id"),
        sa.UniqueConstraint("tenant_id", "inference_run_id", "rule_id", name="uq_cie_evidence_tenant_rule"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_cie_evidence_confidence"),
        sa.CheckConstraint("source_diversity >= 0 AND source_diversity <= 64", name="ck_cie_evidence_sources"),
        sa.CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_cie_evidence_freshness"),
        sa.CheckConstraint("verification_state IN ('verified','partially_verified','inferred','contradicted','unknown')", name="ck_cie_evidence_verification"),
        sa.CheckConstraint(_hash_check("evidence_digest", dialect), name="ck_cie_evidence_digest"),
        sa.CheckConstraint(_json_limit("supporting_signal_ids_json", 65536, dialect), name="ck_cie_evidence_support_bytes"),
        sa.CheckConstraint(_json_limit("conflicting_signal_ids_json", 65536, dialect), name="ck_cie_evidence_conflict_bytes"),
        sa.CheckConstraint(_json_limit("unknown_predicates_json", 16384, dialect), name="ck_cie_evidence_unknown_bytes"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_cie_evidence_limitations_bytes"),
    )
    op.create_index("idx_cie_evidence_tenant_run", "discovery_capability_evidence", ["tenant_id", "inference_run_id", "capability_id", "capability_evidence_id"])
    op.create_index("idx_cie_evidence_tenant_capability", "discovery_capability_evidence", ["tenant_id", "capability_id", "confidence", "capability_evidence_id"])


def _create_genomes(dialect: str) -> None:
    json_columns = (
        "capabilities_json", "dependencies_json", "permissions_json",
        "reachability_json", "usage_json", "models_json", "providers_json",
        "runtime_json", "data_json", "marketplace_json", "identity_json",
    )
    op.create_table(
        "discovery_capability_genomes",
        sa.Column("genome_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("inference_run_id", sa.String(36), nullable=False),
        sa.Column("subject_reference_hash", sa.String(64), nullable=False),
        sa.Column("genome_version", sa.Integer(), nullable=False),
        sa.Column("supersedes_genome_id", sa.String(36), nullable=True),
        sa.Column("genome_digest", sa.String(64), nullable=False),
        sa.Column("capabilities_json", sa.JSON(), nullable=False),
        *(
            sa.Column(column, sa.JSON(), server_default=_json_default("[]", dialect), nullable=False)
            for column in json_columns[1:]
        ),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_cie_genome_tenant"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "inference_run_id"],
            ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"],
            name="fk_cie_genome_tenant_run", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "supersedes_genome_id"],
            ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"],
            name="fk_cie_genome_tenant_predecessor", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("genome_id"),
        sa.UniqueConstraint("tenant_id", "genome_id", name="uq_cie_genome_tenant_id"),
        sa.UniqueConstraint("tenant_id", "subject_reference_hash", "genome_version", name="uq_cie_genome_tenant_subject_ver"),
        sa.UniqueConstraint("tenant_id", "inference_run_id", name="uq_cie_genome_tenant_run"),
        sa.CheckConstraint(_hash_check("subject_reference_hash", dialect), name="ck_cie_genome_subject_hash"),
        sa.CheckConstraint(_hash_check("genome_digest", dialect), name="ck_cie_genome_digest"),
        sa.CheckConstraint("genome_version >= 1", name="ck_cie_genome_version"),
        sa.CheckConstraint("first_observed_at <= last_observed_at", name="ck_cie_genome_time_order"),
        *(
            sa.CheckConstraint(_json_limit(column, 32768, dialect), name=f"ck_cie_genome_{column.removesuffix('_json')}_bytes")
            for column in json_columns
        ),
    )
    op.create_index("idx_cie_genome_tenant_subject", "discovery_capability_genomes", ["tenant_id", "subject_reference_hash", "genome_version", "genome_id"])
    op.create_index("idx_cie_genome_tenant_run", "discovery_capability_genomes", ["tenant_id", "inference_run_id", "genome_id"])


def _create_events(dialect: str) -> None:
    op.create_table(
        "discovery_capability_events",
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("subject_reference_hash", sa.String(64), nullable=False),
        sa.Column("genome_id", sa.String(36), nullable=False),
        sa.Column("previous_genome_id", sa.String(36), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("entity_reference", sa.String(255), nullable=False),
        sa.Column("before_json", sa.JSON(), nullable=False),
        sa.Column("after_json", sa.JSON(), nullable=False),
        sa.Column("evidence_references_json", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_cie_event_tenant"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "genome_id"],
            ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"],
            name="fk_cie_event_tenant_genome", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "previous_genome_id"],
            ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"],
            name="fk_cie_event_tenant_previous", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint("tenant_id", "event_id", name="uq_cie_event_tenant_id"),
        sa.UniqueConstraint("tenant_id", "input_digest", name="uq_cie_event_tenant_digest"),
        sa.CheckConstraint(_hash_check("subject_reference_hash", dialect), name="ck_cie_event_subject_hash"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_cie_event_input_digest"),
        sa.CheckConstraint("event_type IN ('capability_added','capability_removed','confidence_changed','dependency_added','dependency_removed','marketplace_changed','provider_changed','model_changed','runtime_changed','data_changed','identity_changed','permission_changed','usage_changed','repository_changed','configuration_changed','genome_changed')", name="ck_cie_event_type"),
        sa.CheckConstraint(_json_limit("before_json", 32768, dialect), name="ck_cie_event_before_bytes"),
        sa.CheckConstraint(_json_limit("after_json", 32768, dialect), name="ck_cie_event_after_bytes"),
        sa.CheckConstraint(_json_limit("evidence_references_json", 16384, dialect), name="ck_cie_event_evidence_bytes"),
    )
    op.create_index("idx_cie_event_tenant_subject", "discovery_capability_events", ["tenant_id", "subject_reference_hash", "occurred_at", "event_id"])
    op.create_index("idx_cie_event_tenant_type", "discovery_capability_events", ["tenant_id", "event_type", "occurred_at", "event_id"])


def _install_immutable_guards(dialect: str) -> None:
    if dialect == "sqlite":
        for table in IMMUTABLE_TABLES:
            short = table.removeprefix("discovery_capability_").replace("inference_", "")
            for action in ("update", "delete"):
                op.execute(
                    f"CREATE TRIGGER trg_cie_{short}_immutable_{action} "
                    f"BEFORE {action.upper()} ON {table} BEGIN "
                    "SELECT RAISE(ABORT, 'CIE evidence is append-only'); END"
                )
        return
    op.execute(
        "CREATE FUNCTION hawk_reject_cie_mutation() RETURNS trigger AS $$ "
        "BEGIN RAISE EXCEPTION 'CIE evidence is append-only'; END; "
        "$$ LANGUAGE plpgsql"
    )
    for table in IMMUTABLE_TABLES:
        short = table.removeprefix("discovery_capability_").replace("inference_", "")
        op.execute(
            f"CREATE TRIGGER trg_cie_{short}_immutable "
            f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW "
            "EXECUTE FUNCTION hawk_reject_cie_mutation()"
        )


def _extend_resolution_graph_taxonomy() -> None:
    if _dialect() == "postgresql":
        op.drop_constraint(
            "ck_discovery_resolution_graph_edge_type",
            "discovery_resolution_graph_edges",
            type_="check",
        )
        op.create_check_constraint(
            "ck_discovery_resolution_graph_edge_type",
            "discovery_resolution_graph_edges",
            f"edge_type IN ({GRAPH_EDGE_TYPES})",
        )
        op.drop_constraint(
            "ck_discovery_resolution_graph_node_class",
            "discovery_resolution_graph_nodes",
            type_="check",
        )
        op.create_check_constraint(
            "ck_discovery_resolution_graph_node_class",
            "discovery_resolution_graph_nodes",
            f"node_class IN ({GRAPH_NODE_CLASSES})",
        )
        return
    with op.batch_alter_table("discovery_resolution_graph_edges", recreate="always") as batch:
        batch.drop_constraint("ck_discovery_resolution_graph_edge_type", type_="check")
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_edge_type",
            f"edge_type IN ({GRAPH_EDGE_TYPES})",
        )
    with op.batch_alter_table("discovery_resolution_graph_nodes", recreate="always") as batch:
        batch.drop_constraint("ck_discovery_resolution_graph_node_class", type_="check")
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_node_class",
            f"node_class IN ({GRAPH_NODE_CLASSES})",
        )


def _restore_resolution_graph_taxonomy() -> None:
    if _dialect() == "postgresql":
        op.drop_constraint(
            "ck_discovery_resolution_graph_edge_type",
            "discovery_resolution_graph_edges",
            type_="check",
        )
        op.create_check_constraint(
            "ck_discovery_resolution_graph_edge_type",
            "discovery_resolution_graph_edges",
            f"edge_type IN ({LEGACY_GRAPH_EDGE_TYPES})",
        )
        op.drop_constraint(
            "ck_discovery_resolution_graph_node_class",
            "discovery_resolution_graph_nodes",
            type_="check",
        )
        op.create_check_constraint(
            "ck_discovery_resolution_graph_node_class",
            "discovery_resolution_graph_nodes",
            f"node_class IN ({LEGACY_GRAPH_NODE_CLASSES})",
        )
        return
    with op.batch_alter_table("discovery_resolution_graph_edges", recreate="always") as batch:
        batch.drop_constraint("ck_discovery_resolution_graph_edge_type", type_="check")
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_edge_type",
            f"edge_type IN ({LEGACY_GRAPH_EDGE_TYPES})",
        )
    with op.batch_alter_table("discovery_resolution_graph_nodes", recreate="always") as batch:
        batch.drop_constraint("ck_discovery_resolution_graph_node_class", type_="check")
        batch.create_check_constraint(
            "ck_discovery_resolution_graph_node_class",
            f"node_class IN ({LEGACY_GRAPH_NODE_CLASSES})",
        )


def upgrade() -> None:
    dialect = _dialect()
    _extend_resolution_graph_taxonomy()
    _create_runs(dialect)
    _create_evidence(dialect)
    _create_genomes(dialect)
    _create_events(dialect)
    _install_immutable_guards(dialect)


def downgrade() -> None:
    dialect = _dialect()
    for table in reversed(TABLES):
        if dialect == "postgresql":
            short = table.removeprefix("discovery_capability_").replace("inference_", "")
            op.execute(f"DROP TRIGGER IF EXISTS trg_cie_{short}_immutable ON {table}")
        op.drop_table(table)
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS hawk_reject_cie_mutation()")
    _restore_resolution_graph_taxonomy()
