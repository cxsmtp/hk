"""Extend capability truth and add reachability, identity, and ownership facts.

Revision ID: 0057_discovery_attribution
Revises: 0056_discovery_resolution_graph
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0057_discovery_attribution"
down_revision = "0056_discovery_resolution_graph"
branch_labels = None
depends_on = None


TABLES = (
    "discovery_asset_reachability",
    "discovery_asset_identity_links",
    "discovery_asset_ownership_assertions",
)


EXPANDED_CAPABILITIES = (
    "'inference','model_inference','embeddings','multimodal','image_generation',"
    "'audio','code_generation','file_read','file_write','file_upload','file_download',"
    "'source_code_access','terminal_execution','process_execution',"
    "'filesystem_read','filesystem_write','browser_automation','email_send',"
    "'messaging_send','database_read','database_write','vector_search',"
    "'knowledge_retrieval','memory_read','shell_execution','code_execution',"
    "'ci_cd_execution','git_read','git_write','repository_access',"
    "'code_modification','patch_application','internet_access','internal_network',"
    "'api_call','cloud_api','webhook','a2a','delegation','subagent','planning',"
    "'persistent_automation','oauth','managed_identity','service_principal',"
    "'user_impersonation','MCP_client','MCP_server','tool_execution',"
    "'external_network','secret_access','cloud_admin','identity_change',"
    "'memory_write','persistent_side_effect','code_change','CI_CD',"
    "'customer_data_access'"
)

ORIGINAL_CAPABILITIES = (
    "'model_inference','embeddings','file_upload','file_download',"
    "'source_code_access','terminal_execution','process_execution',"
    "'filesystem_read','filesystem_write','browser_automation','email_send',"
    "'messaging_send','database_read','database_write','vector_search',"
    "'MCP_client','MCP_server','tool_execution','external_network',"
    "'secret_access','cloud_admin','identity_change','memory_write',"
    "'persistent_side_effect','code_change','CI_CD','customer_data_access'"
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


def _restore_capability_triggers() -> None:
    op.execute(
        "CREATE TRIGGER trg_discovery_ai_capabilities_immutable_update "
        "BEFORE UPDATE ON discovery_ai_capabilities BEGIN "
        "SELECT RAISE(ABORT, 'immutable_table:discovery_ai_capabilities'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_discovery_ai_capabilities_immutable_delete "
        "BEFORE DELETE ON discovery_ai_capabilities BEGIN "
        "SELECT RAISE(ABORT, 'immutable_table:discovery_ai_capabilities'); END"
    )


def _extend_capabilities(dialect: str) -> None:
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_discovery_ai_capabilities_immutable_update")
        op.execute("DROP TRIGGER IF EXISTS trg_discovery_ai_capabilities_immutable_delete")
    with op.batch_alter_table(
        "discovery_ai_capabilities",
        recreate="always" if dialect == "sqlite" else "auto",
        reflect_kwargs={"resolve_fks": False} if dialect == "sqlite" else {},
    ) as batch:
        batch.add_column(sa.Column("verification_state", sa.String(32), server_default=sa.text("'unknown'"), nullable=False))
        batch.add_column(sa.Column("freshness", sa.String(32), server_default=sa.text("'unknown'"), nullable=False))
        batch.add_column(sa.Column("observed_usage", sa.Boolean(), server_default=sa.false(), nullable=False))
        batch.add_column(sa.Column("declared_only", sa.Boolean(), server_default=sa.false(), nullable=False))
        batch.add_column(sa.Column("inferred_only", sa.Boolean(), server_default=sa.false(), nullable=False))
        batch.drop_constraint("ck_discovery_ai_capability_name", type_="check")
        batch.create_check_constraint(
            "ck_discovery_ai_capability_name",
            f"capability_name IN ({EXPANDED_CAPABILITIES})",
        )
        batch.create_check_constraint(
            "ck_discovery_ai_capability_verification",
            "verification_state IN ('verified','partially_verified','inferred','unknown')",
        )
        batch.create_check_constraint(
            "ck_discovery_ai_capability_freshness",
            "freshness IN ('fresh','stale','expired','unknown')",
        )
        batch.create_check_constraint(
            "ck_discovery_ai_capability_truth_shape",
            "NOT (declared_only AND inferred_only)",
        )
    if dialect == "sqlite":
        _restore_capability_triggers()


def upgrade() -> None:
    dialect = _dialect()
    _extend_capabilities(dialect)

    op.create_table(
        "discovery_asset_reachability",
        sa.Column("reachability_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("target_category", sa.String(64), nullable=False),
        sa.Column("target_reference_hash", sa.String(64), nullable=False),
        sa.Column("reachability_state", sa.String(32), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("observed_usage", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_asset_reachability_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_reachability_tenant_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_asset_reachability_tenant_evidence", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("reachability_id"),
        sa.UniqueConstraint("tenant_id", "reachability_id", name="uq_discovery_asset_reachability_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_reachability_tenant_idempotency"),
        sa.CheckConstraint("target_category IN ('model','mcp','internal_api','external_api','database','vector_db','filesystem','cloud_control_plane','saas','ci_cd','source_repo','internal_network','internet')", name="ck_discovery_asset_reachability_category"),
        sa.CheckConstraint("reachability_state IN ('configured','observed','potential','verified','unknown')", name="ck_discovery_asset_reachability_state"),
        sa.CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_asset_reachability_verification"),
        sa.CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_discovery_asset_reachability_freshness"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_reachability_confidence"),
        sa.CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_asset_reachability_seen_order"),
        sa.CheckConstraint(_hash_check("target_reference_hash", dialect), name="ck_discovery_asset_reachability_target_hash"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_asset_reachability_digest"),
        sa.CheckConstraint("length(CAST(limitations_json AS TEXT)) <= 4096", name="ck_discovery_asset_reachability_limitations_bytes"),
    )
    op.create_index("idx_discovery_asset_reachability_tenant_asset", "discovery_asset_reachability", ["tenant_id", "asset_id", "target_category", "reachability_id"])
    op.create_index("idx_discovery_asset_reachability_tenant_target", "discovery_asset_reachability", ["tenant_id", "target_reference_hash", "reachability_state", "reachability_id"])

    op.create_table(
        "discovery_asset_identity_links",
        sa.Column("identity_link_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("identity_type", sa.String(64), nullable=False),
        sa.Column("identity_reference_hash", sa.String(64), nullable=False),
        sa.Column("access_state", sa.String(32), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("usage_proven", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_asset_identity_link_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_identity_link_tenant_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_asset_identity_link_tenant_evidence", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("identity_link_id"),
        sa.UniqueConstraint("tenant_id", "identity_link_id", name="uq_discovery_asset_identity_link_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_identity_link_tenant_idempotency"),
        sa.CheckConstraint("identity_type IN ('user','group','service_principal','managed_identity','oauth_app','api_key_reference','workload_identity','agent_identity','unknown')", name="ck_discovery_asset_identity_link_type"),
        sa.CheckConstraint("access_state IN ('assigned','configured','observed','active','unknown')", name="ck_discovery_asset_identity_link_access"),
        sa.CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_asset_identity_link_verification"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_identity_link_confidence"),
        sa.CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_asset_identity_link_seen_order"),
        sa.CheckConstraint(_hash_check("identity_reference_hash", dialect), name="ck_discovery_asset_identity_link_reference_hash"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_asset_identity_link_digest"),
    )
    op.create_index("idx_discovery_asset_identity_link_tenant_asset", "discovery_asset_identity_links", ["tenant_id", "asset_id", "identity_type", "identity_link_id"])
    op.create_index("idx_discovery_asset_identity_link_tenant_identity", "discovery_asset_identity_links", ["tenant_id", "identity_reference_hash", "access_state", "identity_link_id"])

    op.create_table(
        "discovery_asset_ownership_assertions",
        sa.Column("ownership_assertion_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("owner_type", sa.String(64), nullable=False),
        sa.Column("owner_reference_hash", sa.String(64), nullable=True),
        sa.Column("ownership_state", sa.String(32), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_asset_ownership_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_ownership_tenant_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_asset_ownership_tenant_evidence", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("ownership_assertion_id"),
        sa.UniqueConstraint("tenant_id", "ownership_assertion_id", name="uq_discovery_asset_ownership_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_ownership_tenant_idempotency"),
        sa.CheckConstraint("owner_type IN ('business_owner','technical_owner','team','department','repository_owner','cloud_account','saas_admin','cost_center','unknown')", name="ck_discovery_asset_ownership_type"),
        sa.CheckConstraint("ownership_state IN ('asserted','inferred','verified','unknown','contradicted')", name="ck_discovery_asset_ownership_state"),
        sa.CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_asset_ownership_verification"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_ownership_confidence"),
        sa.CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_asset_ownership_seen_order"),
        sa.CheckConstraint("(owner_type = 'unknown' AND owner_reference_hash IS NULL) OR (owner_type <> 'unknown' AND owner_reference_hash IS NOT NULL)", name="ck_discovery_asset_ownership_reference_shape"),
        sa.CheckConstraint("owner_reference_hash IS NULL OR length(owner_reference_hash) = 64", name="ck_discovery_asset_ownership_reference_hash"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_asset_ownership_digest"),
    )
    op.create_index("idx_discovery_asset_ownership_tenant_asset", "discovery_asset_ownership_assertions", ["tenant_id", "asset_id", "owner_type", "ownership_assertion_id"])
    op.create_index("idx_discovery_asset_ownership_tenant_owner", "discovery_asset_ownership_assertions", ["tenant_id", "owner_reference_hash", "ownership_state", "ownership_assertion_id"])


def downgrade() -> None:
    dialect = _dialect()
    for name, table in (
        ("idx_discovery_asset_ownership_tenant_owner", "discovery_asset_ownership_assertions"),
        ("idx_discovery_asset_ownership_tenant_asset", "discovery_asset_ownership_assertions"),
        ("idx_discovery_asset_identity_link_tenant_identity", "discovery_asset_identity_links"),
        ("idx_discovery_asset_identity_link_tenant_asset", "discovery_asset_identity_links"),
        ("idx_discovery_asset_reachability_tenant_target", "discovery_asset_reachability"),
        ("idx_discovery_asset_reachability_tenant_asset", "discovery_asset_reachability"),
    ):
        op.drop_index(name, table_name=table)
    for table in reversed(TABLES):
        op.drop_table(table)
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_discovery_ai_capabilities_immutable_update")
        op.execute("DROP TRIGGER IF EXISTS trg_discovery_ai_capabilities_immutable_delete")
    with op.batch_alter_table(
        "discovery_ai_capabilities",
        recreate="always" if dialect == "sqlite" else "auto",
        reflect_kwargs={"resolve_fks": False} if dialect == "sqlite" else {},
    ) as batch:
        batch.drop_constraint("ck_discovery_ai_capability_name", type_="check")
        batch.drop_constraint("ck_discovery_ai_capability_truth_shape", type_="check")
        batch.drop_constraint("ck_discovery_ai_capability_freshness", type_="check")
        batch.drop_constraint("ck_discovery_ai_capability_verification", type_="check")
        batch.drop_column("inferred_only")
        batch.drop_column("declared_only")
        batch.drop_column("observed_usage")
        batch.drop_column("freshness")
        batch.drop_column("verification_state")
        batch.create_check_constraint(
            "ck_discovery_ai_capability_name",
            f"capability_name IN ({ORIGINAL_CAPABILITIES})",
        )
    if dialect == "sqlite":
        _restore_capability_triggers()
