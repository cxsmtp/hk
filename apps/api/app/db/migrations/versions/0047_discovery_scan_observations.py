"""additive canonical HMAIR discovery persistence

Revision ID: 0047_discovery_scan_obs
Revises: 0046_deployment_family_exp
"""

from alembic import op
import sqlalchemy as sa


revision = "0047_discovery_scan_obs"
down_revision = "0046_deployment_family_exp"
branch_labels = None
depends_on = None


INDEXES: tuple[tuple[str, str, list[str]], ...] = (
    ("idx_discovery_scan_tenant_status", "discovery_scans", ["tenant_id", "status"]),
    ("idx_discovery_scan_tenant_created", "discovery_scans", ["tenant_id", "created_at"]),
    ("idx_discovery_scan_tenant_rescan", "discovery_scans", ["tenant_id", "rescan_of_scan_id"]),
    ("idx_discovery_target_tenant_type", "discovery_targets", ["tenant_id", "target_type"]),
    ("idx_discovery_target_tenant_scanned", "discovery_targets", ["tenant_id", "last_scanned_at"]),
    ("idx_discovery_collector_tenant_type", "discovery_collectors", ["tenant_id", "collector_type"]),
    ("idx_discovery_collector_tenant_health", "discovery_collectors", ["tenant_id", "health"]),
    ("idx_discovery_scan_target_tenant_target", "discovery_scan_targets", ["tenant_id", "target_id"]),
    ("idx_discovery_assignment_tenant_scan_status", "discovery_scan_assignments", ["tenant_id", "scan_id", "status"]),
    ("idx_discovery_assignment_tenant_collector_status", "discovery_scan_assignments", ["tenant_id", "collector_id", "status"]),
    ("idx_discovery_observation_tenant_scan_time", "discovery_observations", ["tenant_id", "scan_id", "observed_at"]),
    ("idx_discovery_observation_tenant_collector_time", "discovery_observations", ["tenant_id", "collector_id", "observed_at"]),
    ("idx_discovery_observation_tenant_type_time", "discovery_observations", ["tenant_id", "observation_type", "observed_at"]),
    ("idx_discovery_observation_tenant_freshness_time", "discovery_observations", ["tenant_id", "freshness", "observed_at"]),
    ("idx_discovery_observation_tenant_assignment", "discovery_observations", ["tenant_id", "assignment_id"]),
)


def _hash_check(column: str, dialect: str) -> str:
    if dialect == "postgresql":
        return f"{column} ~ '^[0-9a-f]{{64}}$'"
    return f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9a-f]*'"


def _json_default(value: str, dialect: str) -> sa.TextClause:
    suffix = "::json" if dialect == "postgresql" else ""
    return sa.text(f"'{value}'{suffix}")


def _timestamps() -> tuple[sa.Column[object], sa.Column[object]]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def _dialect_name() -> str:
    name = op.get_context().dialect.name
    if name not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {name}")
    return name


def upgrade() -> None:
    dialect = _dialect_name()

    op.create_table(
        "discovery_targets",
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=False),
        sa.Column("identifier", sa.String(length=512), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("owner_hint", sa.String(length=255), nullable=True),
        sa.Column("credentials_reference", sa.String(length=255), nullable=True),
        sa.Column("permitted_methods_json", sa.JSON(), nullable=False),
        sa.Column(
            "exclusions_json",
            sa.JSON(),
            server_default=_json_default("[]", dialect),
            nullable=False,
        ),
        sa.Column("rate_limit", sa.Integer(), nullable=False),
        sa.Column(
            "active_scan_allowed",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column(
            "sensitive_scope",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "target_type IN ("
            "'endpoint_group','browser_tenant','cloud_subscription',"
            "'cloud_project','kubernetes_cluster','saas_tenant',"
            "'identity_tenant','repository_org','repository','network_range',"
            "'dns_domain','api_gateway','database_platform',"
            "'ai_provider_account','mcp_environment','llm_gateway',"
            "'runtime_environment')",
            name="ck_discovery_target_type",
        ),
        sa.CheckConstraint(
            "rate_limit >= 1 AND rate_limit <= 10000",
            name="ck_discovery_target_rate_limit",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("target_id"),
        sa.UniqueConstraint(
            "tenant_id", "target_id", name="uq_discovery_target_tenant_id"
        ),
    )

    op.create_table(
        "discovery_collectors",
        sa.Column("collector_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("collector_type", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("supported_targets_json", sa.JSON(), nullable=False),
        sa.Column("active_capabilities_json", sa.JSON(), nullable=False),
        sa.Column("passive_capabilities_json", sa.JSON(), nullable=False),
        sa.Column("permissions_required_json", sa.JSON(), nullable=False),
        sa.Column("sensitive_data_accessed_json", sa.JSON(), nullable=False),
        sa.Column("health", sa.String(length=32), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("data_residency", sa.String(length=128), nullable=False),
        sa.Column("control_capability", sa.String(length=32), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("limitations_json", sa.JSON(), nullable=False),
        sa.Column("declaration_hash", sa.String(length=64), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "health IN ('healthy','warning','degraded','offline','unknown')",
            name="ck_discovery_collector_health",
        ),
        sa.CheckConstraint(
            "control_capability IN "
            "('inline','warn_only','monitor_only','external_required','unknown')",
            name="ck_discovery_collector_control_capability",
        ),
        sa.CheckConstraint(
            _hash_check("declaration_hash", dialect),
            name="ck_discovery_collector_declaration_hash",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("collector_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "collector_id",
            name="uq_discovery_collector_tenant_id",
        ),
    )

    op.create_table(
        "discovery_scans",
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("requested_by", sa.String(length=36), nullable=True),
        sa.Column("scan_type", sa.String(length=32), nullable=False),
        sa.Column("scope_json", sa.JSON(), nullable=False),
        sa.Column("safety_profile", sa.String(length=64), nullable=False),
        sa.Column(
            "request_idempotency_key", sa.String(length=128), nullable=False
        ),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'queued'"),
            nullable=False,
        ),
        sa.Column(
            "dry_run", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "observations_count",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "assets_created",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "assets_updated",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "assets_unresolved",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "warnings_json",
            sa.JSON(),
            server_default=_json_default("[]", dialect),
            nullable=False,
        ),
        sa.Column(
            "errors_json",
            sa.JSON(),
            server_default=_json_default("[]", dialect),
            nullable=False,
        ),
        sa.Column(
            "coverage_summary_json",
            sa.JSON(),
            server_default=_json_default("{}", dialect),
            nullable=False,
        ),
        sa.Column("evidence_bundle_id", sa.String(length=36), nullable=True),
        sa.Column("rescan_of_scan_id", sa.String(length=36), nullable=True),
        *_timestamps(),
        sa.CheckConstraint(
            "scan_type IN ('full_enterprise','targeted','incremental',"
            "'verification','scheduled','collector_specific')",
            name="ck_discovery_scan_type",
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','partially_complete','complete',"
            "'failed','cancelled')",
            name="ck_discovery_scan_status",
        ),
        sa.CheckConstraint(
            "observations_count >= 0 AND assets_created >= 0 AND "
            "assets_updated >= 0 AND assets_unresolved >= 0",
            name="ck_discovery_scan_counters",
        ),
        sa.CheckConstraint(
            _hash_check("request_digest", dialect),
            name="ck_discovery_scan_request_digest",
        ),
        sa.CheckConstraint(
            "rescan_of_scan_id IS NULL OR rescan_of_scan_id <> scan_id",
            name="ck_discovery_scan_not_self_rescan",
        ),
        sa.CheckConstraint(
            "(status = 'queued' AND started_at IS NULL AND completed_at IS NULL "
            "AND cancelled_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND "
            "completed_at IS NULL AND cancelled_at IS NULL) OR "
            "(status IN ('complete','partially_complete') AND "
            "started_at IS NOT NULL AND completed_at IS NOT NULL AND "
            "cancelled_at IS NULL) OR "
            "(status = 'failed' AND completed_at IS NOT NULL AND "
            "cancelled_at IS NULL) OR "
            "(status = 'cancelled' AND completed_at IS NULL AND "
            "cancelled_at IS NOT NULL)",
            name="ck_discovery_scan_lifecycle",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "rescan_of_scan_id"],
            ["discovery_scans.tenant_id", "discovery_scans.scan_id"],
            name="fk_discovery_scan_tenant_rescan",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_scan_tenant_evidence_bundle",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("scan_id"),
        sa.UniqueConstraint(
            "tenant_id", "scan_id", name="uq_discovery_scan_tenant_id"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "request_idempotency_key",
            name="uq_discovery_scan_tenant_request",
        ),
    )

    op.create_table(
        "discovery_scan_targets",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "scan_id"],
            ["discovery_scans.tenant_id", "discovery_scans.scan_id"],
            name="fk_discovery_scan_target_tenant_scan",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "target_id"],
            ["discovery_targets.tenant_id", "discovery_targets.target_id"],
            name="fk_discovery_scan_target_tenant_target",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("tenant_id", "scan_id", "target_id"),
    )

    op.create_table(
        "discovery_scan_assignments",
        sa.Column("assignment_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("collector_id", sa.String(length=128), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("warning", sa.String(length=500), nullable=True),
        sa.Column("error", sa.String(length=500), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "observations_count",
            sa.BigInteger(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        *_timestamps(),
        sa.CheckConstraint(
            "status IN ('pending','running','complete','failed','cancelled',"
            "'unsupported','permission_denied','rate_limited','stale','empty')",
            name="ck_discovery_assignment_status",
        ),
        sa.CheckConstraint(
            "observations_count >= 0",
            name="ck_discovery_assignment_observations_count",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND started_at IS NULL AND "
            "completed_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND "
            "completed_at IS NULL) OR "
            "(status IN ('complete','failed','cancelled','unsupported',"
            "'permission_denied','rate_limited','stale','empty') AND "
            "completed_at IS NOT NULL)",
            name="ck_discovery_assignment_lifecycle",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "scan_id", "target_id"],
            [
                "discovery_scan_targets.tenant_id",
                "discovery_scan_targets.scan_id",
                "discovery_scan_targets.target_id",
            ],
            name="fk_discovery_assignment_tenant_scan_target",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "collector_id"],
            [
                "discovery_collectors.tenant_id",
                "discovery_collectors.collector_id",
            ],
            name="fk_discovery_assignment_tenant_collector",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("assignment_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "assignment_id",
            name="uq_discovery_assignment_tenant_id",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "scan_id",
            "target_id",
            "collector_id",
            name="uq_discovery_assignment_tenant_work",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "assignment_id",
            "scan_id",
            "target_id",
            "collector_id",
            name="uq_discovery_assignment_observation_parent",
        ),
    )

    op.create_table(
        "discovery_observations",
        sa.Column("observation_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("assignment_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("collector_id", sa.String(length=128), nullable=False),
        sa.Column("collector_type", sa.String(length=64), nullable=False),
        sa.Column("collector_version", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_type", sa.String(length=128), nullable=False),
        sa.Column("candidate_asset_type", sa.String(length=64), nullable=False),
        sa.Column("identifiers_json", sa.JSON(), nullable=False),
        sa.Column("attributes_json", sa.JSON(), nullable=False),
        sa.Column("configuration_summary_json", sa.JSON(), nullable=False),
        sa.Column("usage_summary_json", sa.JSON(), nullable=False),
        sa.Column("capability_hints_json", sa.JSON(), nullable=False),
        sa.Column("identity_hints_json", sa.JSON(), nullable=False),
        sa.Column("relationship_hints_json", sa.JSON(), nullable=False),
        sa.Column("evidence_reference", sa.String(length=255), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("signature_status", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("freshness", sa.String(length=32), nullable=False),
        sa.Column("sensitivity", sa.String(length=32), nullable=False),
        sa.Column("redaction_status", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_observation_confidence",
        ),
        sa.CheckConstraint(
            "freshness IN ('fresh','stale','expired','unknown')",
            name="ck_discovery_observation_freshness",
        ),
        sa.CheckConstraint(
            _hash_check("evidence_hash", dialect),
            name="ck_discovery_observation_evidence_hash",
        ),
        sa.CheckConstraint(
            _hash_check("idempotency_key", dialect),
            name="ck_discovery_observation_idempotency_key",
        ),
        sa.CheckConstraint(
            _hash_check("payload_digest", dialect),
            name="ck_discovery_observation_payload_digest",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "scan_id"],
            ["discovery_scans.tenant_id", "discovery_scans.scan_id"],
            name="fk_discovery_observation_tenant_scan",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "target_id"],
            ["discovery_targets.tenant_id", "discovery_targets.target_id"],
            name="fk_discovery_observation_tenant_target",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "collector_id"],
            [
                "discovery_collectors.tenant_id",
                "discovery_collectors.collector_id",
            ],
            name="fk_discovery_observation_tenant_collector",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            [
                "tenant_id",
                "assignment_id",
                "scan_id",
                "target_id",
                "collector_id",
            ],
            [
                "discovery_scan_assignments.tenant_id",
                "discovery_scan_assignments.assignment_id",
                "discovery_scan_assignments.scan_id",
                "discovery_scan_assignments.target_id",
                "discovery_scan_assignments.collector_id",
            ],
            name="fk_discovery_observation_assignment_tuple",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("observation_id"),
        sa.UniqueConstraint(
            "tenant_id",
            "observation_id",
            name="uq_discovery_observation_tenant_id",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "scan_id",
            "collector_id",
            "idempotency_key",
            name="uq_discovery_observation_retry",
        ),
    )

    for index_name, table_name, columns in INDEXES:
        op.create_index(index_name, table_name, columns)

    if dialect == "postgresql":
        op.execute(
            "CREATE TRIGGER trg_discovery_observations_immutable "
            "BEFORE UPDATE OR DELETE ON discovery_observations "
            "FOR EACH ROW EXECUTE FUNCTION deny_immutable_table_mutation()"
        )
    else:
        op.execute(
            "CREATE TRIGGER trg_discovery_observations_immutable_update "
            "BEFORE UPDATE ON discovery_observations BEGIN "
            "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
        )
        op.execute(
            "CREATE TRIGGER trg_discovery_observations_immutable_delete "
            "BEFORE DELETE ON discovery_observations BEGIN "
            "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
        )


def downgrade() -> None:
    dialect = _dialect_name()

    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_discovery_observations_immutable "
            "ON discovery_observations"
        )
    else:
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "trg_discovery_observations_immutable_update"
        )
        op.execute(
            "DROP TRIGGER IF EXISTS "
            "trg_discovery_observations_immutable_delete"
        )

    for index_name, table_name, _columns in reversed(INDEXES):
        op.drop_index(index_name, table_name=table_name)

    op.drop_table("discovery_observations")
    op.drop_table("discovery_scan_assignments")
    op.drop_table("discovery_scan_targets")
    op.drop_table("discovery_scans")
    op.drop_table("discovery_collectors")
    op.drop_table("discovery_targets")
