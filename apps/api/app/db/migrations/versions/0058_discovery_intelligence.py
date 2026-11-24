"""Add evidence-backed usage, Shadow AI classification, and findings.

Revision ID: 0058_discovery_intelligence
Revises: 0057_discovery_attribution
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0058_discovery_intelligence"
down_revision = "0057_discovery_attribution"
branch_labels = None
depends_on = None


TABLES = (
    "discovery_asset_usage_facts",
    "discovery_shadow_classifications",
    "discovery_asset_findings",
)


def _dialect() -> str:
    value = op.get_bind().dialect.name
    if value not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {value}")
    return value


def _tenant_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id"], ["tenants.id"], name=name, ondelete="CASCADE"
    )


def _hash_check(column: str, dialect: str) -> str:
    if dialect == "postgresql":
        return f"{column} ~ '^[0-9a-f]{{64}}$'"
    return f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9a-f]*'"


def _json_default(value: str, dialect: str) -> sa.TextClause:
    return sa.text(f"'{value}'{'::json' if dialect == 'postgresql' else ''}")


def _json_limit(column: str, limit: int, dialect: str) -> str:
    if dialect == "postgresql":
        return f"octet_length(CAST({column} AS text)) <= {limit}"
    return f"length(CAST({column} AS BLOB)) <= {limit}"


def _create_usage(dialect: str) -> None:
    op.create_table(
        "discovery_asset_usage_facts",
        sa.Column("usage_fact_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("actor_reference_hash", sa.String(64), nullable=True),
        sa.Column("usage_state", sa.String(32), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_surface", sa.String(64), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("telemetry_complete", sa.Boolean(), nullable=False),
        sa.Column("methodology_id", sa.String(128), nullable=False),
        sa.Column(
            "limitations_json", sa.JSON(),
            server_default=_json_default("[]", dialect), nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        _tenant_fk("fk_discovery_usage_tenant"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_usage_tenant_asset", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_usage_tenant_evidence", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("usage_fact_id"),
        sa.UniqueConstraint(
            "tenant_id", "usage_fact_id", name="uq_discovery_usage_tenant_id"
        ),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_discovery_usage_tenant_idempotency",
        ),
        sa.CheckConstraint(
            "usage_state IN ('never_observed','historical','occasional','active','high_usage','unknown')",
            name="ck_discovery_usage_state",
        ),
        sa.CheckConstraint(
            "actor_type IN ('human','agent','service','workload','automation','unknown')",
            name="ck_discovery_usage_actor_type",
        ),
        sa.CheckConstraint(
            "(actor_type = 'unknown' AND actor_reference_hash IS NULL) OR "
            "(actor_type <> 'unknown' AND actor_reference_hash IS NOT NULL)",
            name="ck_discovery_usage_actor_reference",
        ),
        sa.CheckConstraint(
            "verification_state IN ('verified','partially_verified','inferred','contradicted','stale','unknown')",
            name="ck_discovery_usage_verification",
        ),
        sa.CheckConstraint(
            "freshness IN ('fresh','stale','expired','unknown')",
            name="ck_discovery_usage_freshness",
        ),
        sa.CheckConstraint("event_count >= 0", name="ck_discovery_usage_count"),
        sa.CheckConstraint(
            "first_observed_at IS NULL OR last_observed_at IS NULL OR "
            "first_observed_at <= last_observed_at",
            name="ck_discovery_usage_seen_order",
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_usage_confidence",
        ),
        sa.CheckConstraint(
            "length(trim(source_surface)) BETWEEN 1 AND 64",
            name="ck_discovery_usage_surface_bounded",
        ),
        sa.CheckConstraint(
            "length(trim(methodology_id)) BETWEEN 1 AND 128",
            name="ck_discovery_usage_methodology_bounded",
        ),
        sa.CheckConstraint(
            "length(trim(idempotency_key)) BETWEEN 1 AND 128",
            name="ck_discovery_usage_idempotency_bounded",
        ),
        sa.CheckConstraint(
            _hash_check("input_digest", dialect),
            name="ck_discovery_usage_digest",
        ),
        sa.CheckConstraint(
            "actor_reference_hash IS NULL OR ("
            + _hash_check("actor_reference_hash", dialect)
            + ")",
            name="ck_discovery_usage_actor_hash",
        ),
        sa.CheckConstraint(
            _json_limit("limitations_json", 4096, dialect),
            name="ck_discovery_usage_limitations_bytes",
        ),
    )
    op.create_index(
        "idx_discovery_usage_tenant_asset_seen",
        "discovery_asset_usage_facts",
        ["tenant_id", "asset_id", "last_observed_at", "usage_fact_id"],
    )
    op.create_index(
        "idx_discovery_usage_tenant_actor",
        "discovery_asset_usage_facts",
        ["tenant_id", "actor_type", "actor_reference_hash", "usage_fact_id"],
    )
    op.create_index(
        "idx_discovery_usage_tenant_state",
        "discovery_asset_usage_facts",
        ["tenant_id", "usage_state", "freshness", "usage_fact_id"],
    )


def _create_shadow_classifications(dialect: str) -> None:
    op.create_table(
        "discovery_shadow_classifications",
        sa.Column("classification_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("management_class", sa.String(32), nullable=False),
        sa.Column("shadow_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("primary_evidence_node_id", sa.String(36), nullable=False),
        sa.Column("evidence_node_ids_json", sa.JSON(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("methodology_id", sa.String(128), nullable=False),
        sa.Column(
            "limitations_json", sa.JSON(),
            server_default=_json_default("[]", dialect), nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        _tenant_fk("fk_discovery_shadow_class_tenant"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_shadow_class_tenant_asset", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "primary_evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_shadow_class_tenant_evidence", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("classification_id"),
        sa.UniqueConstraint(
            "tenant_id", "classification_id",
            name="uq_discovery_shadow_class_tenant_id",
        ),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_discovery_shadow_class_tenant_idempotency",
        ),
        sa.CheckConstraint(
            "management_class IN ('enterprise_managed','enterprise_approved','personal','unmanaged','unknown')",
            name="ck_discovery_shadow_class_management",
        ),
        sa.CheckConstraint(
            "shadow_type IN ('unapproved_ai_app','personal_ai_on_managed_device','direct_model_api','unmanaged_agent','unknown_ai_workload','unapproved_model','unmanaged_mcp','unapproved_saas_ai','unregistered_rag','unknown_vector_store')",
            name="ck_discovery_shadow_class_type",
        ),
        sa.CheckConstraint(
            "severity IN ('low','medium','high','critical')",
            name="ck_discovery_shadow_class_severity",
        ),
        sa.CheckConstraint(
            "verification_state IN ('verified','partially_verified','inferred','contradicted','stale','unknown')",
            name="ck_discovery_shadow_class_verification",
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_shadow_class_confidence",
        ),
        sa.CheckConstraint(
            "first_observed_at <= last_observed_at",
            name="ck_discovery_shadow_class_seen_order",
        ),
        sa.CheckConstraint(
            _json_limit("evidence_node_ids_json", 8192, dialect),
            name="ck_discovery_shadow_class_evidence_bytes",
        ),
        sa.CheckConstraint(
            _json_limit("limitations_json", 4096, dialect),
            name="ck_discovery_shadow_class_limitations_bytes",
        ),
        sa.CheckConstraint(
            "length(trim(methodology_id)) BETWEEN 1 AND 128",
            name="ck_discovery_shadow_class_methodology_bounded",
        ),
        sa.CheckConstraint(
            "length(trim(idempotency_key)) BETWEEN 1 AND 128",
            name="ck_discovery_shadow_class_idempotency_bounded",
        ),
        sa.CheckConstraint(
            _hash_check("input_digest", dialect),
            name="ck_discovery_shadow_class_digest",
        ),
    )
    op.create_index(
        "idx_discovery_shadow_class_tenant_asset",
        "discovery_shadow_classifications",
        ["tenant_id", "asset_id", "last_observed_at", "classification_id"],
    )
    op.create_index(
        "idx_discovery_shadow_class_tenant_type",
        "discovery_shadow_classifications",
        ["tenant_id", "shadow_type", "severity", "classification_id"],
    )


def _create_findings(dialect: str) -> None:
    op.create_table(
        "discovery_asset_findings",
        sa.Column("finding_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("finding_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("primary_evidence_node_id", sa.String(36), nullable=False),
        sa.Column("evidence_node_ids_json", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("remediation", sa.String(1000), nullable=False),
        sa.Column("verification_action", sa.String(1000), nullable=False),
        sa.Column("coverage_impact", sa.String(1000), nullable=False),
        sa.Column("dedupe_key", sa.String(128), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("status", sa.String(32), server_default=sa.text("'open'"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_finding_tenant"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_finding_tenant_asset", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "primary_evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_finding_tenant_evidence", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("finding_id"),
        sa.UniqueConstraint(
            "tenant_id", "finding_id", name="uq_discovery_finding_tenant_id"
        ),
        sa.UniqueConstraint(
            "tenant_id", "dedupe_key", name="uq_discovery_finding_tenant_dedupe"
        ),
        sa.CheckConstraint(
            "severity IN ('low','medium','high','critical')",
            name="ck_discovery_finding_severity",
        ),
        sa.CheckConstraint(
            "verification_state IN ('verified','partially_verified','inferred','contradicted','stale','unknown')",
            name="ck_discovery_finding_verification",
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_finding_confidence",
        ),
        sa.CheckConstraint(
            "first_seen_at <= last_seen_at",
            name="ck_discovery_finding_seen_order",
        ),
        sa.CheckConstraint("occurrence_count >= 1", name="ck_discovery_finding_occurrence"),
        sa.CheckConstraint(
            "status IN ('open','reviewing','resolved','accepted','dismissed')",
            name="ck_discovery_finding_status",
        ),
        sa.CheckConstraint(
            "length(trim(finding_type)) BETWEEN 1 AND 64",
            name="ck_discovery_finding_type_bounded",
        ),
        sa.CheckConstraint(
            "length(trim(remediation)) BETWEEN 1 AND 1000",
            name="ck_discovery_finding_remediation_bounded",
        ),
        sa.CheckConstraint(
            "length(trim(verification_action)) BETWEEN 1 AND 1000",
            name="ck_discovery_finding_verification_action_bounded",
        ),
        sa.CheckConstraint(
            "length(trim(coverage_impact)) BETWEEN 1 AND 1000",
            name="ck_discovery_finding_coverage_impact_bounded",
        ),
        sa.CheckConstraint(
            "length(trim(dedupe_key)) BETWEEN 1 AND 128",
            name="ck_discovery_finding_dedupe_bounded",
        ),
        sa.CheckConstraint(
            _json_limit("evidence_node_ids_json", 8192, dialect),
            name="ck_discovery_finding_evidence_bytes",
        ),
    )
    op.create_index(
        "idx_discovery_finding_tenant_asset",
        "discovery_asset_findings",
        ["tenant_id", "asset_id", "status", "finding_id"],
    )
    op.create_index(
        "idx_discovery_finding_tenant_type",
        "discovery_asset_findings",
        ["tenant_id", "finding_type", "severity", "finding_id"],
    )
    op.create_index(
        "idx_discovery_finding_tenant_seen",
        "discovery_asset_findings",
        ["tenant_id", "last_seen_at", "finding_id"],
    )


def _create_immutable_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        for table, token in (
            ("discovery_asset_usage_facts", "discovery_usage"),
            ("discovery_shadow_classifications", "discovery_shadow_class"),
        ):
            op.execute(
                f"CREATE TRIGGER trg_{token}_immutable BEFORE UPDATE OR DELETE "
                f"ON {table} FOR EACH ROW EXECUTE FUNCTION deny_immutable_table_mutation()"
            )
        return
    for table, token in (
        ("discovery_asset_usage_facts", "discovery_usage"),
        ("discovery_shadow_classifications", "discovery_shadow_class"),
    ):
        op.execute(
            f"CREATE TRIGGER trg_{token}_immutable_update BEFORE UPDATE ON {table} "
            f"BEGIN SELECT RAISE(ABORT, 'immutable_table:{table}'); END"
        )
        op.execute(
            f"CREATE TRIGGER trg_{token}_immutable_delete BEFORE DELETE ON {table} "
            f"BEGIN SELECT RAISE(ABORT, 'immutable_table:{table}'); END"
        )


def _drop_immutable_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_discovery_usage_immutable "
            "ON discovery_asset_usage_facts"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS trg_discovery_shadow_class_immutable "
            "ON discovery_shadow_classifications"
        )
        return
    for token in ("discovery_usage", "discovery_shadow_class"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{token}_immutable_update")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{token}_immutable_delete")


def upgrade() -> None:
    dialect = _dialect()
    _create_usage(dialect)
    _create_shadow_classifications(dialect)
    _create_findings(dialect)
    _create_immutable_triggers(dialect)


def downgrade() -> None:
    dialect = _dialect()
    _drop_immutable_triggers(dialect)
    for table in reversed(TABLES):
        op.drop_table(table)

