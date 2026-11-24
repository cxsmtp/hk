"""Persist canonical HMAIR assets and reversible resolution provenance.

Revision ID: 0055_discovery_assets_res
Revises: 0054_discovery_obs_truth
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0055_discovery_assets_res"
down_revision = "0054_discovery_obs_truth"
branch_labels = None
depends_on = None


H1B_TABLES = (
    "discovery_ai_assets",
    "discovery_evidence_claims",
    "discovery_asset_history_events",
    "discovery_resolution_decisions",
    "discovery_resolution_decision_observations",
    "discovery_observation_asset_links",
    "discovery_asset_fingerprints",
    "discovery_ai_capabilities",
    "discovery_asset_history_members",
)

APPEND_ONLY_TABLES = H1B_TABLES[1:]

INDEXES: tuple[tuple[str, str, list[str]], ...] = (
    ("idx_discovery_ai_asset_tenant_type_name", "discovery_ai_assets", ["tenant_id", "asset_type", "canonical_name", "asset_id"]),
    ("idx_discovery_ai_asset_tenant_shadow_seen", "discovery_ai_assets", ["tenant_id", "shadow_ai_status", "last_seen_at", "asset_id"]),
    ("idx_discovery_ai_asset_tenant_seen", "discovery_ai_assets", ["tenant_id", "last_seen_at", "asset_id"]),
    ("idx_discovery_ai_asset_tenant_evidence", "discovery_ai_assets", ["tenant_id", "evidence_bundle_id", "asset_id"]),
    ("idx_discovery_evidence_claim_tenant_asset", "discovery_evidence_claims", ["tenant_id", "subject_asset_id", "created_at", "claim_id"]),
    ("idx_discovery_evidence_claim_tenant_subject_observation", "discovery_evidence_claims", ["tenant_id", "subject_observation_id", "created_at", "claim_id"]),
    ("idx_discovery_evidence_claim_tenant_source", "discovery_evidence_claims", ["tenant_id", "source_observation_id", "created_at", "claim_id"]),
    ("idx_discovery_evidence_claim_tenant_node", "discovery_evidence_claims", ["tenant_id", "evidence_node_id", "claim_id"]),
    ("idx_discovery_asset_history_event_tenant_type", "discovery_asset_history_events", ["tenant_id", "event_type", "created_at", "history_event_id"]),
    ("idx_discovery_asset_history_event_tenant_reversal", "discovery_asset_history_events", ["tenant_id", "reversal_of_event_id", "history_event_id"]),
    ("idx_discovery_asset_history_event_tenant_created", "discovery_asset_history_events", ["tenant_id", "created_at", "history_event_id"]),
    ("idx_discovery_resolution_decision_tenant_asset", "discovery_resolution_decisions", ["tenant_id", "canonical_asset_id", "created_at", "decision_id"]),
    ("idx_discovery_resolution_decision_tenant_action", "discovery_resolution_decisions", ["tenant_id", "action", "created_at", "decision_id"]),
    ("idx_discovery_resolution_decision_tenant_history", "discovery_resolution_decisions", ["tenant_id", "history_event_id", "operation_index", "decision_id"]),
    ("idx_discovery_decision_observation_tenant_observation", "discovery_resolution_decision_observations", ["tenant_id", "observation_id", "decision_id"]),
    ("idx_discovery_observation_asset_link_tenant_observation", "discovery_observation_asset_links", ["tenant_id", "observation_id", "sequence_no", "link_id"]),
    ("idx_discovery_observation_asset_link_tenant_asset", "discovery_observation_asset_links", ["tenant_id", "asset_id", "created_at", "link_id"]),
    ("idx_discovery_observation_asset_link_tenant_history", "discovery_observation_asset_links", ["tenant_id", "history_event_id", "link_id"]),
    ("idx_discovery_asset_fingerprint_tenant_asset", "discovery_asset_fingerprints", ["tenant_id", "asset_id", "chain_sequence", "fingerprint_id"]),
    ("idx_discovery_asset_fingerprint_tenant_observation", "discovery_asset_fingerprints", ["tenant_id", "source_observation_id", "created_at", "fingerprint_id"]),
    ("idx_discovery_ai_capability_tenant_asset_name", "discovery_ai_capabilities", ["tenant_id", "asset_id", "capability_name", "last_observed_at", "capability_id"]),
    ("idx_discovery_ai_capability_tenant_observation", "discovery_ai_capabilities", ["tenant_id", "source_observation_id", "created_at", "capability_id"]),
    ("idx_discovery_asset_history_member_tenant_asset", "discovery_asset_history_members", ["tenant_id", "asset_id", "created_at", "history_member_id"]),
    ("idx_discovery_asset_history_member_tenant_event", "discovery_asset_history_members", ["tenant_id", "history_event_id", "member_role", "ordinal", "history_member_id"]),
)


def _dialect_name() -> str:
    name = op.get_bind().dialect.name
    if name not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {name}")
    return name


def _json_default(value: str, dialect: str) -> sa.TextClause:
    return sa.text(f"'{value}'{'::json' if dialect == 'postgresql' else ''}")


def _hash_check(column: str, dialect: str) -> str:
    if dialect == "postgresql":
        return f"{column} ~ '^[0-9a-f]{{64}}$'"
    return f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9a-f]*'"


def _json_check(column: str, limit: int, dialect: str) -> str:
    if dialect == "postgresql":
        return f"octet_length(CAST({column} AS text)) <= {limit}"
    return f"length(CAST({column} AS BLOB)) <= {limit}"


def _tenant_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id"], ["tenants.id"], name=name, ondelete="CASCADE"
    )


def _created_at() -> sa.Column[object]:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
        nullable=False,
    )


def _create_assets() -> None:
    asset_types = (
        "'ai_application','ai_saas','ai_feature','model','model_endpoint',"
        "'agent','agent_framework','runtime','llm_gateway','mcp_server',"
        "'mcp_client','mcp_tool','ide','cli','browser_extension',"
        "'endpoint_application','sdk','api','workflow','plugin',"
        "'vector_database','knowledge_base','prompt_store','memory_store',"
        "'data_connector','identity','service_account','oauth_application',"
        "'unknown_ai_candidate'"
    )
    shadow_states = (
        "'approved','approved_but_uncontrolled','known_unapproved',"
        "'suspected_shadow','confirmed_shadow','personal_account',"
        "'owner_unknown','unknown'"
    )
    op.create_table(
        "discovery_ai_assets",
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_type", sa.String(64), nullable=False),
        sa.Column("canonical_name", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("framework", sa.String(255), nullable=True),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column("deployment_family", sa.String(64), nullable=True),
        sa.Column("technical_surface", sa.String(128), nullable=True),
        sa.Column("environment", sa.String(64), nullable=True),
        sa.Column("approved_status", sa.String(64), server_default=sa.text("'unknown'"), nullable=False),
        sa.Column("lifecycle_status", sa.String(64), server_default=sa.text("'unknown'"), nullable=False),
        sa.Column("shadow_ai_status", sa.String(32), server_default=sa.text("'unknown'"), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolution_confidence", sa.Float(), server_default=sa.text("0.0"), nullable=False),
        sa.Column("evidence_bundle_id", sa.String(36), nullable=False),
        sa.Column("projection_version", sa.BigInteger(), server_default=sa.text("1"), nullable=False),
        _created_at(),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_ai_asset_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_bundle_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_ai_asset_tenant_evidence_bundle", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("asset_id"),
        sa.UniqueConstraint("tenant_id", "asset_id", name="uq_discovery_ai_asset_tenant_id"),
        sa.CheckConstraint(f"asset_type IN ({asset_types})", name="ck_discovery_ai_asset_type"),
        sa.CheckConstraint(f"shadow_ai_status IN ({shadow_states})", name="ck_discovery_ai_asset_shadow_status"),
        sa.CheckConstraint("length(trim(approved_status)) BETWEEN 1 AND 64", name="ck_discovery_ai_asset_approved_status_bounded"),
        sa.CheckConstraint("length(trim(lifecycle_status)) BETWEEN 1 AND 64", name="ck_discovery_ai_asset_lifecycle_status_bounded"),
        sa.CheckConstraint("first_seen_at <= last_seen_at", name="ck_discovery_ai_asset_seen_order"),
        sa.CheckConstraint("resolution_confidence >= 0.0 AND resolution_confidence <= 1.0", name="ck_discovery_ai_asset_confidence"),
        sa.CheckConstraint("projection_version >= 1", name="ck_discovery_ai_asset_projection_version"),
    )


def _create_claims(dialect: str) -> None:
    op.create_table(
        "discovery_evidence_claims",
        sa.Column("claim_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("claim_type", sa.String(64), nullable=False),
        sa.Column("subject_observation_id", sa.String(128), nullable=True),
        sa.Column("subject_asset_id", sa.String(36), nullable=True),
        sa.Column("source_observation_id", sa.String(128), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("claim_result", sa.String(500), server_default=sa.text("'unknown'"), nullable=False),
        sa.Column("claim_method", sa.String(500), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        _created_at(),
        _tenant_fk("fk_discovery_evidence_claim_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "subject_observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_discovery_claim_tenant_subject_observation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "source_observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_discovery_claim_tenant_source_observation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "subject_asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_claim_tenant_subject_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_claim_tenant_evidence_node", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("claim_id"),
        sa.UniqueConstraint("tenant_id", "claim_id", name="uq_discovery_evidence_claim_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_evidence_claim_tenant_idempotency"),
        sa.CheckConstraint("(subject_observation_id IS NULL) <> (subject_asset_id IS NULL)", name="ck_discovery_evidence_claim_subject_xor"),
        sa.CheckConstraint("length(trim(claim_type)) BETWEEN 1 AND 64", name="ck_discovery_evidence_claim_type_bounded"),
        sa.CheckConstraint("length(trim(claim_result)) BETWEEN 1 AND 500", name="ck_discovery_evidence_claim_result_bounded"),
        sa.CheckConstraint("length(trim(claim_method)) BETWEEN 1 AND 500", name="ck_discovery_evidence_claim_method_bounded"),
        sa.CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_discovery_evidence_claim_freshness"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_evidence_claim_confidence"),
        sa.CheckConstraint("length(trim(idempotency_key)) BETWEEN 1 AND 128", name="ck_discovery_evidence_claim_idempotency_bounded"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_evidence_claim_input_digest_sha256"),
        sa.CheckConstraint(_json_check("limitations_json", 4096, dialect), name="ck_discovery_evidence_claim_limitations_bytes"),
    )


def _create_history_events(dialect: str) -> None:
    op.create_table(
        "discovery_asset_history_events",
        sa.Column("history_event_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(16), nullable=False),
        sa.Column("reversal_of_event_id", sa.String(36), nullable=True),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("actor_role", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("evidence_claim_id", sa.String(36), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        _created_at(),
        _tenant_fk("fk_discovery_asset_history_event_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_claim_id"], ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"], name="fk_discovery_asset_history_tenant_claim", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "reversal_of_event_id"], ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"], name="fk_discovery_asset_history_tenant_reversal", ondelete="RESTRICT", deferrable=False),
        sa.PrimaryKeyConstraint("history_event_id"),
        sa.UniqueConstraint("tenant_id", "history_event_id", name="uq_discovery_asset_history_event_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_history_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "reversal_of_event_id", name="uq_discovery_asset_history_tenant_reversal"),
        sa.CheckConstraint("event_type IN ('create','attach','merge','split','reversal')", name="ck_discovery_asset_history_event_type"),
        sa.CheckConstraint("((event_type = 'reversal' AND reversal_of_event_id IS NOT NULL) OR (event_type <> 'reversal' AND reversal_of_event_id IS NULL)) AND (reversal_of_event_id IS NULL OR reversal_of_event_id <> history_event_id)", name="ck_discovery_asset_history_reversal"),
        sa.CheckConstraint("length(trim(actor_id)) BETWEEN 1 AND 128", name="ck_discovery_asset_history_actor_id_bounded"),
        sa.CheckConstraint("actor_role IN ('system','owner','admin')", name="ck_discovery_asset_history_actor_role"),
        sa.CheckConstraint("length(trim(reason)) BETWEEN 1 AND 500", name="ck_discovery_asset_history_reason_bounded"),
        sa.CheckConstraint("length(trim(idempotency_key)) BETWEEN 1 AND 128", name="ck_discovery_asset_history_idempotency_bounded"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_asset_history_input_digest_sha256"),
    )


def _create_decisions(dialect: str) -> None:
    op.create_table(
        "discovery_resolution_decisions",
        sa.Column("decision_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("canonical_asset_id", sa.String(36), nullable=True),
        sa.Column("history_event_id", sa.String(36), nullable=True),
        sa.Column("operation_index", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("matched_signals_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("conflicting_signals_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("algorithm_version", sa.String(64), nullable=False),
        sa.Column("evidence_claim_id", sa.String(36), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        _created_at(),
        _tenant_fk("fk_discovery_resolution_decision_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "canonical_asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_resolution_decision_tenant_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "history_event_id"], ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"], name="fk_discovery_resolution_decision_tenant_history", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_claim_id"], ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"], name="fk_discovery_resolution_decision_tenant_claim", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("decision_id"),
        sa.UniqueConstraint("tenant_id", "decision_id", name="uq_discovery_resolution_decision_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_resolution_decision_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "history_event_id", "operation_index", name="uq_discovery_resolution_decision_history_operation"),
        sa.CheckConstraint("action IN ('create','merge','attach','reject','manual_review')", name="ck_discovery_resolution_decision_action"),
        sa.CheckConstraint("((action IN ('create','merge','attach') AND canonical_asset_id IS NOT NULL) OR (action IN ('reject','manual_review') AND canonical_asset_id IS NULL))", name="ck_discovery_resolution_decision_asset_shape"),
        sa.CheckConstraint("((action IN ('create','merge','attach') AND history_event_id IS NOT NULL) OR (action IN ('reject','manual_review') AND history_event_id IS NULL))", name="ck_discovery_resolution_decision_history_shape"),
        sa.CheckConstraint("operation_index >= 0", name="ck_discovery_resolution_decision_operation_index"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_resolution_decision_confidence"),
        sa.CheckConstraint("length(trim(algorithm_version)) BETWEEN 1 AND 64", name="ck_discovery_resolution_decision_algorithm_bounded"),
        sa.CheckConstraint(_hash_check("idempotency_key", dialect), name="ck_discovery_resolution_decision_idempotency_sha256"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_resolution_decision_input_digest_sha256"),
        sa.CheckConstraint(_json_check("matched_signals_json", 16384, dialect), name="ck_discovery_resolution_decision_matched_signals_bytes"),
        sa.CheckConstraint(_json_check("conflicting_signals_json", 16384, dialect), name="ck_discovery_resolution_decision_conflict_signals_bytes"),
    )


def _create_decision_observations() -> None:
    op.create_table(
        "discovery_resolution_decision_observations",
        sa.Column("decision_observation_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("decision_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(128), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        _created_at(),
        _tenant_fk("fk_discovery_decision_observation_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "decision_id"], ["discovery_resolution_decisions.tenant_id", "discovery_resolution_decisions.decision_id"], name="fk_discovery_decision_observation_tenant_decision", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_discovery_decision_observation_tenant_observation", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("decision_observation_id"),
        sa.UniqueConstraint("tenant_id", "decision_observation_id", name="uq_discovery_decision_observation_tenant_id"),
        sa.UniqueConstraint("tenant_id", "decision_id", "observation_id", name="uq_discovery_decision_observation_member"),
        sa.UniqueConstraint("tenant_id", "decision_id", "ordinal", name="uq_discovery_decision_observation_ordinal"),
        sa.CheckConstraint("ordinal >= 0", name="ck_discovery_decision_observation_ordinal"),
    )


def _create_observation_links() -> None:
    op.create_table(
        "discovery_observation_asset_links",
        sa.Column("link_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("observation_id", sa.String(128), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=True),
        sa.Column("decision_id", sa.String(36), nullable=True),
        sa.Column("history_event_id", sa.String(36), nullable=False),
        sa.Column("link_kind", sa.String(16), nullable=False),
        sa.Column("sequence_no", sa.BigInteger(), nullable=False),
        sa.Column("predecessor_link_id", sa.String(36), nullable=True),
        sa.Column("reversal_of_link_id", sa.String(36), nullable=True),
        _created_at(),
        _tenant_fk("fk_discovery_observation_asset_link_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_discovery_observation_asset_link_tenant_observation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_observation_asset_link_tenant_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "decision_id"], ["discovery_resolution_decisions.tenant_id", "discovery_resolution_decisions.decision_id"], name="fk_discovery_observation_asset_link_tenant_decision", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "history_event_id"], ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"], name="fk_discovery_observation_asset_link_tenant_history", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_id", "predecessor_link_id"], ["discovery_observation_asset_links.tenant_id", "discovery_observation_asset_links.observation_id", "discovery_observation_asset_links.link_id"], name="fk_discovery_observation_asset_link_tenant_predecessor", ondelete="RESTRICT", deferrable=False),
        sa.ForeignKeyConstraint(["tenant_id", "observation_id", "reversal_of_link_id"], ["discovery_observation_asset_links.tenant_id", "discovery_observation_asset_links.observation_id", "discovery_observation_asset_links.link_id"], name="fk_discovery_observation_asset_link_tenant_reversal", ondelete="RESTRICT", deferrable=False),
        sa.PrimaryKeyConstraint("link_id"),
        sa.UniqueConstraint("tenant_id", "link_id", name="uq_discovery_observation_asset_link_tenant_id"),
        sa.UniqueConstraint("tenant_id", "observation_id", "link_id", name="uq_discovery_observation_asset_link_tenant_observation"),
        sa.UniqueConstraint("tenant_id", "observation_id", "sequence_no", name="uq_discovery_observation_asset_link_sequence"),
        sa.UniqueConstraint("tenant_id", "observation_id", "predecessor_link_id", name="uq_discovery_observation_asset_link_predecessor"),
        sa.UniqueConstraint("tenant_id", "observation_id", "reversal_of_link_id", name="uq_discovery_observation_asset_link_reversal"),
        sa.UniqueConstraint("tenant_id", "decision_id", "observation_id", name="uq_discovery_observation_asset_link_decision"),
        sa.CheckConstraint("link_kind IN ('attach','reassign','reverse')", name="ck_discovery_observation_asset_link_kind"),
        sa.CheckConstraint("((sequence_no = 1 AND predecessor_link_id IS NULL AND link_kind = 'attach') OR (sequence_no > 1 AND predecessor_link_id IS NOT NULL))", name="ck_discovery_observation_asset_link_root"),
        sa.CheckConstraint("((link_kind IN ('attach','reassign') AND asset_id IS NOT NULL AND decision_id IS NOT NULL AND reversal_of_link_id IS NULL) OR (link_kind = 'reverse' AND decision_id IS NULL AND reversal_of_link_id = predecessor_link_id))", name="ck_discovery_observation_asset_link_shape"),
        sa.CheckConstraint("(predecessor_link_id IS NULL OR predecessor_link_id <> link_id) AND (reversal_of_link_id IS NULL OR reversal_of_link_id <> link_id)", name="ck_discovery_observation_asset_link_self"),
    )


def _create_fingerprints(dialect: str) -> None:
    op.create_table(
        "discovery_asset_fingerprints",
        sa.Column("fingerprint_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("source_observation_id", sa.String(128), nullable=False),
        sa.Column("evidence_claim_id", sa.String(36), nullable=False),
        sa.Column("fingerprint_version", sa.String(32), nullable=False),
        sa.Column("chain_sequence", sa.BigInteger(), nullable=False),
        sa.Column("supersedes_fingerprint_id", sa.String(36), nullable=True),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("component_hashes_json", sa.JSON(), nullable=False),
        sa.Column("detected_products_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("detected_frameworks_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("detected_models_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("detected_protocols_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("detected_capabilities_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("observed_destinations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("drift_summary_json", sa.JSON(), server_default=_json_default("{}", dialect), nullable=False),
        _created_at(),
        _tenant_fk("fk_discovery_asset_fingerprint_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_fingerprint_tenant_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "source_observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_discovery_asset_fingerprint_tenant_observation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_claim_id"], ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"], name="fk_discovery_asset_fingerprint_tenant_claim", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id", "supersedes_fingerprint_id"], ["discovery_asset_fingerprints.tenant_id", "discovery_asset_fingerprints.asset_id", "discovery_asset_fingerprints.fingerprint_id"], name="fk_discovery_asset_fingerprint_tenant_predecessor", ondelete="RESTRICT", deferrable=False),
        sa.PrimaryKeyConstraint("fingerprint_id"),
        sa.UniqueConstraint("tenant_id", "fingerprint_id", name="uq_discovery_asset_fingerprint_tenant_id"),
        sa.UniqueConstraint("tenant_id", "asset_id", "fingerprint_id", name="uq_discovery_asset_fingerprint_tenant_asset_id"),
        sa.UniqueConstraint("tenant_id", "asset_id", "chain_sequence", name="uq_discovery_asset_fingerprint_sequence"),
        sa.UniqueConstraint("tenant_id", "asset_id", "supersedes_fingerprint_id", name="uq_discovery_asset_fingerprint_predecessor"),
        sa.UniqueConstraint("tenant_id", "asset_id", "fingerprint_version", "input_digest", name="uq_discovery_asset_fingerprint_input"),
        sa.CheckConstraint("((chain_sequence = 1 AND supersedes_fingerprint_id IS NULL) OR (chain_sequence > 1 AND supersedes_fingerprint_id IS NOT NULL))", name="ck_discovery_asset_fingerprint_root"),
        sa.CheckConstraint("supersedes_fingerprint_id IS NULL OR supersedes_fingerprint_id <> fingerprint_id", name="ck_discovery_asset_fingerprint_self"),
        sa.CheckConstraint("length(trim(fingerprint_version)) BETWEEN 1 AND 32", name="ck_discovery_asset_fingerprint_version_bounded"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_fingerprint_confidence"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_asset_fingerprint_input_digest_sha256"),
        sa.CheckConstraint(_json_check("component_hashes_json", 4096, dialect), name="ck_discovery_asset_fingerprint_components_bytes"),
        sa.CheckConstraint(_json_check("detected_products_json", 8192, dialect), name="ck_discovery_asset_fingerprint_products_bytes"),
        sa.CheckConstraint(_json_check("detected_frameworks_json", 8192, dialect), name="ck_discovery_asset_fingerprint_frameworks_bytes"),
        sa.CheckConstraint(_json_check("detected_models_json", 8192, dialect), name="ck_discovery_asset_fingerprint_models_bytes"),
        sa.CheckConstraint(_json_check("detected_protocols_json", 8192, dialect), name="ck_discovery_asset_fingerprint_protocols_bytes"),
        sa.CheckConstraint(_json_check("detected_capabilities_json", 8192, dialect), name="ck_discovery_asset_fingerprint_capabilities_bytes"),
        sa.CheckConstraint(_json_check("observed_destinations_json", 8192, dialect), name="ck_discovery_asset_fingerprint_destinations_bytes"),
        sa.CheckConstraint(_json_check("drift_summary_json", 4096, dialect), name="ck_discovery_asset_fingerprint_drift_bytes"),
    )


def _create_capabilities(dialect: str) -> None:
    capability_names = (
        "'model_inference','embeddings','file_upload','file_download',"
        "'source_code_access','terminal_execution','process_execution',"
        "'filesystem_read','filesystem_write','browser_automation','email_send',"
        "'messaging_send','database_read','database_write','vector_search',"
        "'MCP_client','MCP_server','tool_execution','external_network',"
        "'secret_access','cloud_admin','identity_change','memory_write',"
        "'persistent_side_effect','code_change','CI_CD','customer_data_access'"
    )
    op.create_table(
        "discovery_ai_capabilities",
        sa.Column("capability_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("source_observation_id", sa.String(128), nullable=False),
        sa.Column("evidence_claim_id", sa.String(36), nullable=False),
        sa.Column("capability_name", sa.String(64), nullable=False),
        sa.Column("capability_state", sa.String(32), nullable=False),
        sa.Column("extractor_version", sa.String(64), nullable=False),
        sa.Column("assertion_sequence", sa.BigInteger(), nullable=False),
        sa.Column("supersedes_capability_id", sa.String(36), nullable=True),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        _created_at(),
        _tenant_fk("fk_discovery_ai_capability_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_ai_capability_tenant_asset", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "source_observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_discovery_ai_capability_tenant_observation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_claim_id"], ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"], name="fk_discovery_ai_capability_tenant_claim", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id", "capability_name", "supersedes_capability_id"], ["discovery_ai_capabilities.tenant_id", "discovery_ai_capabilities.asset_id", "discovery_ai_capabilities.capability_name", "discovery_ai_capabilities.capability_id"], name="fk_discovery_ai_capability_tenant_predecessor", ondelete="RESTRICT", deferrable=False),
        sa.PrimaryKeyConstraint("capability_id"),
        sa.UniqueConstraint("tenant_id", "capability_id", name="uq_discovery_ai_capability_tenant_id"),
        sa.UniqueConstraint("tenant_id", "asset_id", "capability_name", "capability_id", name="uq_discovery_ai_capability_tenant_asset_name_id"),
        sa.UniqueConstraint("tenant_id", "asset_id", "capability_name", "assertion_sequence", name="uq_discovery_ai_capability_sequence"),
        sa.UniqueConstraint("tenant_id", "asset_id", "capability_name", "supersedes_capability_id", name="uq_discovery_ai_capability_predecessor"),
        sa.UniqueConstraint("tenant_id", "asset_id", "capability_name", "capability_state", "extractor_version", "input_digest", name="uq_discovery_ai_capability_input"),
        sa.CheckConstraint(f"capability_name IN ({capability_names})", name="ck_discovery_ai_capability_name"),
        sa.CheckConstraint("capability_state IN ('declared','configured','observed','inferred','denied','unknown')", name="ck_discovery_ai_capability_state"),
        sa.CheckConstraint("((assertion_sequence = 1 AND supersedes_capability_id IS NULL) OR (assertion_sequence > 1 AND supersedes_capability_id IS NOT NULL))", name="ck_discovery_ai_capability_root"),
        sa.CheckConstraint("supersedes_capability_id IS NULL OR supersedes_capability_id <> capability_id", name="ck_discovery_ai_capability_self"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_ai_capability_confidence"),
        sa.CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_ai_capability_observed_order"),
        sa.CheckConstraint("length(trim(extractor_version)) BETWEEN 1 AND 64", name="ck_discovery_ai_capability_extractor_bounded"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_ai_capability_input_digest_sha256"),
    )


def _create_history_members() -> None:
    op.create_table(
        "discovery_asset_history_members",
        sa.Column("history_member_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("history_event_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("member_role", sa.String(16), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        _created_at(),
        _tenant_fk("fk_discovery_asset_history_member_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "history_event_id"], ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"], name="fk_discovery_asset_history_member_tenant_event", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_history_member_tenant_asset", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("history_member_id"),
        sa.UniqueConstraint("tenant_id", "history_member_id", name="uq_discovery_asset_history_member_tenant_id"),
        sa.UniqueConstraint("tenant_id", "history_event_id", "member_role", "asset_id", name="uq_discovery_asset_history_member_asset"),
        sa.UniqueConstraint("tenant_id", "history_event_id", "member_role", "ordinal", name="uq_discovery_asset_history_member_ordinal"),
        sa.CheckConstraint("member_role IN ('source','result')", name="ck_discovery_asset_history_member_role"),
        sa.CheckConstraint("ordinal >= 0", name="ck_discovery_asset_history_member_ordinal"),
    )


_SQLITE_TRIGGER_TOKEN = {
    "discovery_evidence_claims": "discovery_evidence_claims",
    "discovery_asset_history_events": "discovery_asset_history_events",
    "discovery_resolution_decisions": "discovery_resolution_decisions",
    "discovery_resolution_decision_observations": "discovery_resolution_decision_obs",
    "discovery_observation_asset_links": "discovery_observation_asset_links",
    "discovery_asset_fingerprints": "discovery_asset_fingerprints",
    "discovery_ai_capabilities": "discovery_ai_capabilities",
    "discovery_asset_history_members": "discovery_asset_history_members",
}


def _create_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "CREATE OR REPLACE FUNCTION deny_discovery_ai_asset_delete() "
            "RETURNS trigger AS $$ BEGIN "
            "RAISE EXCEPTION 'immutable_delete:discovery_ai_assets'; "
            "END; $$ LANGUAGE plpgsql"
        )
        op.execute(
            "CREATE TRIGGER trg_discovery_ai_assets_no_delete "
            "BEFORE DELETE ON discovery_ai_assets FOR EACH ROW "
            "EXECUTE FUNCTION deny_discovery_ai_asset_delete()"
        )
        for table_name in APPEND_ONLY_TABLES:
            token = _SQLITE_TRIGGER_TOKEN[table_name]
            op.execute(
                f"CREATE TRIGGER trg_{token}_immutable BEFORE UPDATE OR DELETE "
                f"ON {table_name} FOR EACH ROW "
                "EXECUTE FUNCTION deny_immutable_table_mutation()"
            )
        return

    op.execute(
        "CREATE TRIGGER trg_discovery_ai_assets_no_delete "
        "BEFORE DELETE ON discovery_ai_assets BEGIN "
        "SELECT RAISE(ABORT, 'immutable_delete:discovery_ai_assets'); END"
    )
    for table_name in APPEND_ONLY_TABLES:
        token = _SQLITE_TRIGGER_TOKEN[table_name]
        op.execute(
            f"CREATE TRIGGER trg_{token}_immutable_update BEFORE UPDATE ON "
            f"{table_name} BEGIN SELECT RAISE(ABORT, "
            f"'immutable_table:{table_name}'); END"
        )
        op.execute(
            f"CREATE TRIGGER trg_{token}_immutable_delete BEFORE DELETE ON "
            f"{table_name} BEGIN SELECT RAISE(ABORT, "
            f"'immutable_table:{table_name}'); END"
        )


def _drop_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_discovery_ai_assets_no_delete "
            "ON discovery_ai_assets"
        )
        for table_name in APPEND_ONLY_TABLES:
            token = _SQLITE_TRIGGER_TOKEN[table_name]
            op.execute(
                f"DROP TRIGGER IF EXISTS trg_{token}_immutable ON {table_name}"
            )
        return
    op.execute("DROP TRIGGER IF EXISTS trg_discovery_ai_assets_no_delete")
    for table_name in APPEND_ONLY_TABLES:
        token = _SQLITE_TRIGGER_TOKEN[table_name]
        op.execute(f"DROP TRIGGER IF EXISTS trg_{token}_immutable_update")
        op.execute(f"DROP TRIGGER IF EXISTS trg_{token}_immutable_delete")


def upgrade() -> None:
    dialect = _dialect_name()
    _create_assets()
    _create_claims(dialect)
    _create_history_events(dialect)
    _create_decisions(dialect)
    _create_decision_observations()
    _create_observation_links()
    _create_fingerprints(dialect)
    _create_capabilities(dialect)
    _create_history_members()
    for index_name, table_name, columns in INDEXES:
        op.create_index(index_name, table_name, columns, unique=False)
    _create_triggers(dialect)


def downgrade() -> None:
    dialect = _dialect_name()
    _drop_triggers(dialect)
    for index_name, table_name, _columns in reversed(INDEXES):
        op.drop_index(index_name, table_name=table_name)
    for table_name in reversed(H1B_TABLES):
        op.drop_table(table_name)
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS deny_discovery_ai_asset_delete()")
