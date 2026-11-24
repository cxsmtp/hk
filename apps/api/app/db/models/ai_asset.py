from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


def _hash_check(column: str) -> str:
    stripped = column
    for character in "0123456789abcdef":
        stripped = f"replace({stripped}, '{character}', '')"
    return (
        f"length({column}) = 64 AND {column} = lower({column}) "
        f"AND {stripped} = ''"
    )


def _json_check(column: str, limit: int) -> str:
    return f"length(CAST({column} AS TEXT)) <= {limit}"


_ASSET_TYPES = (
    "'ai_application','ai_saas','ai_feature','model','model_endpoint',"
    "'agent','agent_framework','runtime','llm_gateway','mcp_server',"
    "'mcp_client','mcp_tool','ide','cli','browser_extension',"
    "'endpoint_application','sdk','api','workflow','plugin',"
    "'vector_database','knowledge_base','prompt_store','memory_store',"
    "'data_connector','identity','service_account','oauth_application',"
    "'unknown_ai_candidate'"
)
_SHADOW_STATES = (
    "'approved','approved_but_uncontrolled','known_unapproved',"
    "'suspected_shadow','confirmed_shadow','personal_account',"
    "'owner_unknown','unknown'"
)
_CAPABILITY_NAMES = (
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
    "'user_impersonation',"
    "'MCP_client','MCP_server','tool_execution','external_network',"
    "'secret_access','cloud_admin','identity_change','memory_write',"
    "'persistent_side_effect','code_change','CI_CD','customer_data_access'"
)


class DiscoveryAIAsset(Base):
    __tablename__ = "discovery_ai_assets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_ai_asset_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_ai_asset_tenant_evidence_bundle",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "asset_id", name="uq_discovery_ai_asset_tenant_id"
        ),
        CheckConstraint(
            f"asset_type IN ({_ASSET_TYPES})", name="ck_discovery_ai_asset_type"
        ),
        CheckConstraint(
            f"shadow_ai_status IN ({_SHADOW_STATES})",
            name="ck_discovery_ai_asset_shadow_status",
        ),
        CheckConstraint(
            "length(trim(approved_status)) BETWEEN 1 AND 64",
            name="ck_discovery_ai_asset_approved_status_bounded",
        ),
        CheckConstraint(
            "length(trim(lifecycle_status)) BETWEEN 1 AND 64",
            name="ck_discovery_ai_asset_lifecycle_status_bounded",
        ),
        CheckConstraint(
            "first_seen_at <= last_seen_at",
            name="ck_discovery_ai_asset_seen_order",
        ),
        CheckConstraint(
            "resolution_confidence >= 0.0 AND resolution_confidence <= 1.0",
            name="ck_discovery_ai_asset_confidence",
        ),
        CheckConstraint(
            "projection_version >= 1",
            name="ck_discovery_ai_asset_projection_version",
        ),
        Index(
            "idx_discovery_ai_asset_tenant_type_name", "tenant_id",
            "asset_type", "canonical_name", "asset_id",
        ),
        Index(
            "idx_discovery_ai_asset_tenant_shadow_seen", "tenant_id",
            "shadow_ai_status", "last_seen_at", "asset_id",
        ),
        Index(
            "idx_discovery_ai_asset_tenant_seen", "tenant_id", "last_seen_at",
            "asset_id",
        ),
        Index(
            "idx_discovery_ai_asset_tenant_evidence", "tenant_id",
            "evidence_bundle_id", "asset_id",
        ),
    )

    asset_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    framework: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deployment_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    technical_surface: Mapped[str | None] = mapped_column(String(128), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_status: Mapped[str] = mapped_column(
        String(64), server_default=text("'unknown'"), nullable=False
    )
    lifecycle_status: Mapped[str] = mapped_column(
        String(64), server_default=text("'unknown'"), nullable=False
    )
    shadow_ai_status: Mapped[str] = mapped_column(
        String(32), server_default=text("'unknown'"), nullable=False
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolution_confidence: Mapped[float] = mapped_column(
        Float, server_default=text("0.0"), nullable=False
    )
    evidence_bundle_id: Mapped[str] = mapped_column(String(36), nullable=False)
    projection_version: Mapped[int] = mapped_column(
        BigInteger, server_default=text("1"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
        nullable=False,
    )


class DiscoveryEvidenceClaim(Base):
    __tablename__ = "discovery_evidence_claims"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_evidence_claim_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "subject_observation_id"],
            ["discovery_observations.tenant_id", "discovery_observations.observation_id"],
            name="fk_discovery_claim_tenant_subject_observation", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "source_observation_id"],
            ["discovery_observations.tenant_id", "discovery_observations.observation_id"],
            name="fk_discovery_claim_tenant_source_observation", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "subject_asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_claim_tenant_subject_asset", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_claim_tenant_evidence_node", ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "claim_id", name="uq_discovery_evidence_claim_tenant_id"
        ),
        UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_discovery_evidence_claim_tenant_idempotency",
        ),
        CheckConstraint(
            "(subject_observation_id IS NULL) <> (subject_asset_id IS NULL)",
            name="ck_discovery_evidence_claim_subject_xor",
        ),
        CheckConstraint(
            "length(trim(claim_type)) BETWEEN 1 AND 64",
            name="ck_discovery_evidence_claim_type_bounded",
        ),
        CheckConstraint(
            "length(trim(claim_result)) BETWEEN 1 AND 500",
            name="ck_discovery_evidence_claim_result_bounded",
        ),
        CheckConstraint(
            "length(trim(claim_method)) BETWEEN 1 AND 500",
            name="ck_discovery_evidence_claim_method_bounded",
        ),
        CheckConstraint(
            "freshness IN ('fresh','stale','expired','unknown')",
            name="ck_discovery_evidence_claim_freshness",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_evidence_claim_confidence",
        ),
        CheckConstraint(
            "length(trim(idempotency_key)) BETWEEN 1 AND 128",
            name="ck_discovery_evidence_claim_idempotency_bounded",
        ),
        CheckConstraint(
            _hash_check("input_digest"),
            name="ck_discovery_evidence_claim_input_digest_sha256",
        ),
        CheckConstraint(
            _json_check("limitations_json", 4096),
            name="ck_discovery_evidence_claim_limitations_bytes",
        ),
        Index(
            "idx_discovery_evidence_claim_tenant_asset", "tenant_id",
            "subject_asset_id", "created_at", "claim_id",
        ),
        Index(
            "idx_discovery_evidence_claim_tenant_subject_observation", "tenant_id",
            "subject_observation_id", "created_at", "claim_id",
        ),
        Index(
            "idx_discovery_evidence_claim_tenant_source", "tenant_id",
            "source_observation_id", "created_at", "claim_id",
        ),
        Index(
            "idx_discovery_evidence_claim_tenant_node", "tenant_id",
            "evidence_node_id", "claim_id",
        ),
    )

    claim_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    claim_type: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_observation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    subject_asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_observation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    claim_result: Mapped[str] = mapped_column(
        String(500), server_default=text("'unknown'"), nullable=False
    )
    claim_method: Mapped[str] = mapped_column(String(500), nullable=False)
    limitations_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DiscoveryAssetHistoryEvent(Base):
    __tablename__ = "discovery_asset_history_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_asset_history_event_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_claim_id"],
            ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"],
            name="fk_discovery_asset_history_tenant_claim", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "reversal_of_event_id"],
            ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"],
            name="fk_discovery_asset_history_tenant_reversal", ondelete="RESTRICT",
            deferrable=False,
        ),
        UniqueConstraint(
            "tenant_id", "history_event_id",
            name="uq_discovery_asset_history_event_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_discovery_asset_history_tenant_idempotency",
        ),
        UniqueConstraint(
            "tenant_id", "reversal_of_event_id",
            name="uq_discovery_asset_history_tenant_reversal",
        ),
        CheckConstraint(
            "event_type IN ('create','attach','merge','split','reversal')",
            name="ck_discovery_asset_history_event_type",
        ),
        CheckConstraint(
            "((event_type = 'reversal' AND reversal_of_event_id IS NOT NULL) OR "
            "(event_type <> 'reversal' AND reversal_of_event_id IS NULL)) AND "
            "(reversal_of_event_id IS NULL OR reversal_of_event_id <> history_event_id)",
            name="ck_discovery_asset_history_reversal",
        ),
        CheckConstraint(
            "length(trim(actor_id)) BETWEEN 1 AND 128",
            name="ck_discovery_asset_history_actor_id_bounded",
        ),
        CheckConstraint(
            "actor_role IN ('system','owner','admin')",
            name="ck_discovery_asset_history_actor_role",
        ),
        CheckConstraint(
            "length(trim(reason)) BETWEEN 1 AND 500",
            name="ck_discovery_asset_history_reason_bounded",
        ),
        CheckConstraint(
            "length(trim(idempotency_key)) BETWEEN 1 AND 128",
            name="ck_discovery_asset_history_idempotency_bounded",
        ),
        CheckConstraint(
            _hash_check("input_digest"),
            name="ck_discovery_asset_history_input_digest_sha256",
        ),
        Index(
            "idx_discovery_asset_history_event_tenant_type", "tenant_id",
            "event_type", "created_at", "history_event_id",
        ),
        Index(
            "idx_discovery_asset_history_event_tenant_reversal", "tenant_id",
            "reversal_of_event_id", "history_event_id",
        ),
        Index(
            "idx_discovery_asset_history_event_tenant_created", "tenant_id",
            "created_at", "history_event_id",
        ),
    )

    history_event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    reversal_of_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    evidence_claim_id: Mapped[str] = mapped_column(String(36), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DiscoveryResolutionDecision(Base):
    __tablename__ = "discovery_resolution_decisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_resolution_decision_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "canonical_asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_resolution_decision_tenant_asset", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "history_event_id"],
            ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"],
            name="fk_discovery_resolution_decision_tenant_history", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_claim_id"],
            ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"],
            name="fk_discovery_resolution_decision_tenant_claim", ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "decision_id",
            name="uq_discovery_resolution_decision_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_discovery_resolution_decision_tenant_idempotency",
        ),
        UniqueConstraint(
            "tenant_id", "history_event_id", "operation_index",
            name="uq_discovery_resolution_decision_history_operation",
        ),
        CheckConstraint(
            "action IN ('create','merge','attach','reject','manual_review')",
            name="ck_discovery_resolution_decision_action",
        ),
        CheckConstraint(
            "((action IN ('create','merge','attach') AND canonical_asset_id IS NOT NULL) "
            "OR (action IN ('reject','manual_review') AND canonical_asset_id IS NULL))",
            name="ck_discovery_resolution_decision_asset_shape",
        ),
        CheckConstraint(
            "((action IN ('create','merge','attach') AND history_event_id IS NOT NULL) "
            "OR (action IN ('reject','manual_review') AND history_event_id IS NULL))",
            name="ck_discovery_resolution_decision_history_shape",
        ),
        CheckConstraint(
            "operation_index >= 0",
            name="ck_discovery_resolution_decision_operation_index",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_resolution_decision_confidence",
        ),
        CheckConstraint(
            "length(trim(algorithm_version)) BETWEEN 1 AND 64",
            name="ck_discovery_resolution_decision_algorithm_bounded",
        ),
        CheckConstraint(
            _hash_check("idempotency_key"),
            name="ck_discovery_resolution_decision_idempotency_sha256",
        ),
        CheckConstraint(
            _hash_check("input_digest"),
            name="ck_discovery_resolution_decision_input_digest_sha256",
        ),
        CheckConstraint(
            _json_check("matched_signals_json", 16384),
            name="ck_discovery_resolution_decision_matched_signals_bytes",
        ),
        CheckConstraint(
            _json_check("conflicting_signals_json", 16384),
            name="ck_discovery_resolution_decision_conflict_signals_bytes",
        ),
        Index(
            "idx_discovery_resolution_decision_tenant_asset", "tenant_id",
            "canonical_asset_id", "created_at", "decision_id",
        ),
        Index(
            "idx_discovery_resolution_decision_tenant_action", "tenant_id",
            "action", "created_at", "decision_id",
        ),
        Index(
            "idx_discovery_resolution_decision_tenant_history", "tenant_id",
            "history_event_id", "operation_index", "decision_id",
        ),
    )

    decision_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    canonical_asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    history_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    operation_index: Mapped[int] = mapped_column(
        Integer, server_default=text("0"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    matched_signals_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    conflicting_signals_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    algorithm_version: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_claim_id: Mapped[str] = mapped_column(String(36), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DiscoveryResolutionDecisionObservation(Base):
    __tablename__ = "discovery_resolution_decision_observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_decision_observation_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "decision_id"],
            ["discovery_resolution_decisions.tenant_id", "discovery_resolution_decisions.decision_id"],
            name="fk_discovery_decision_observation_tenant_decision", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_id"],
            ["discovery_observations.tenant_id", "discovery_observations.observation_id"],
            name="fk_discovery_decision_observation_tenant_observation", ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "decision_observation_id",
            name="uq_discovery_decision_observation_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id", "decision_id", "observation_id",
            name="uq_discovery_decision_observation_member",
        ),
        UniqueConstraint(
            "tenant_id", "decision_id", "ordinal",
            name="uq_discovery_decision_observation_ordinal",
        ),
        CheckConstraint(
            "ordinal >= 0", name="ck_discovery_decision_observation_ordinal"
        ),
        Index(
            "idx_discovery_decision_observation_tenant_observation", "tenant_id",
            "observation_id", "decision_id",
        ),
    )

    decision_observation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    decision_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DiscoveryObservationAssetLink(Base):
    __tablename__ = "discovery_observation_asset_links"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_observation_asset_link_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_id"],
            ["discovery_observations.tenant_id", "discovery_observations.observation_id"],
            name="fk_discovery_observation_asset_link_tenant_observation", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_observation_asset_link_tenant_asset", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "decision_id"],
            ["discovery_resolution_decisions.tenant_id", "discovery_resolution_decisions.decision_id"],
            name="fk_discovery_observation_asset_link_tenant_decision", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "history_event_id"],
            ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"],
            name="fk_discovery_observation_asset_link_tenant_history", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_id", "predecessor_link_id"],
            ["discovery_observation_asset_links.tenant_id", "discovery_observation_asset_links.observation_id", "discovery_observation_asset_links.link_id"],
            name="fk_discovery_observation_asset_link_tenant_predecessor",
            ondelete="RESTRICT", deferrable=False,
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_id", "reversal_of_link_id"],
            ["discovery_observation_asset_links.tenant_id", "discovery_observation_asset_links.observation_id", "discovery_observation_asset_links.link_id"],
            name="fk_discovery_observation_asset_link_tenant_reversal",
            ondelete="RESTRICT", deferrable=False,
        ),
        UniqueConstraint(
            "tenant_id", "link_id", name="uq_discovery_observation_asset_link_tenant_id"
        ),
        UniqueConstraint(
            "tenant_id", "observation_id", "link_id",
            name="uq_discovery_observation_asset_link_tenant_observation",
        ),
        UniqueConstraint(
            "tenant_id", "observation_id", "sequence_no",
            name="uq_discovery_observation_asset_link_sequence",
        ),
        UniqueConstraint(
            "tenant_id", "observation_id", "predecessor_link_id",
            name="uq_discovery_observation_asset_link_predecessor",
        ),
        UniqueConstraint(
            "tenant_id", "observation_id", "reversal_of_link_id",
            name="uq_discovery_observation_asset_link_reversal",
        ),
        UniqueConstraint(
            "tenant_id", "decision_id", "observation_id",
            name="uq_discovery_observation_asset_link_decision",
        ),
        CheckConstraint(
            "link_kind IN ('attach','reassign','reverse')",
            name="ck_discovery_observation_asset_link_kind",
        ),
        CheckConstraint(
            "((sequence_no = 1 AND predecessor_link_id IS NULL AND link_kind = 'attach') "
            "OR (sequence_no > 1 AND predecessor_link_id IS NOT NULL))",
            name="ck_discovery_observation_asset_link_root",
        ),
        CheckConstraint(
            "((link_kind IN ('attach','reassign') AND asset_id IS NOT NULL AND "
            "decision_id IS NOT NULL AND reversal_of_link_id IS NULL) OR "
            "(link_kind = 'reverse' AND decision_id IS NULL AND "
            "reversal_of_link_id = predecessor_link_id))",
            name="ck_discovery_observation_asset_link_shape",
        ),
        CheckConstraint(
            "(predecessor_link_id IS NULL OR predecessor_link_id <> link_id) AND "
            "(reversal_of_link_id IS NULL OR reversal_of_link_id <> link_id)",
            name="ck_discovery_observation_asset_link_self",
        ),
        Index(
            "idx_discovery_observation_asset_link_tenant_observation", "tenant_id",
            "observation_id", "sequence_no", "link_id",
        ),
        Index(
            "idx_discovery_observation_asset_link_tenant_asset", "tenant_id",
            "asset_id", "created_at", "link_id",
        ),
        Index(
            "idx_discovery_observation_asset_link_tenant_history", "tenant_id",
            "history_event_id", "link_id",
        ),
    )

    link_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    history_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    link_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    sequence_no: Mapped[int] = mapped_column(BigInteger, nullable=False)
    predecessor_link_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reversal_of_link_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DiscoveryAssetFingerprint(Base):
    __tablename__ = "discovery_asset_fingerprints"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_asset_fingerprint_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_asset_fingerprint_tenant_asset", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "source_observation_id"],
            ["discovery_observations.tenant_id", "discovery_observations.observation_id"],
            name="fk_discovery_asset_fingerprint_tenant_observation", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_claim_id"],
            ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"],
            name="fk_discovery_asset_fingerprint_tenant_claim", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id", "supersedes_fingerprint_id"],
            ["discovery_asset_fingerprints.tenant_id", "discovery_asset_fingerprints.asset_id", "discovery_asset_fingerprints.fingerprint_id"],
            name="fk_discovery_asset_fingerprint_tenant_predecessor",
            ondelete="RESTRICT", deferrable=False,
        ),
        UniqueConstraint(
            "tenant_id", "fingerprint_id",
            name="uq_discovery_asset_fingerprint_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id", "asset_id", "fingerprint_id",
            name="uq_discovery_asset_fingerprint_tenant_asset_id",
        ),
        UniqueConstraint(
            "tenant_id", "asset_id", "chain_sequence",
            name="uq_discovery_asset_fingerprint_sequence",
        ),
        UniqueConstraint(
            "tenant_id", "asset_id", "supersedes_fingerprint_id",
            name="uq_discovery_asset_fingerprint_predecessor",
        ),
        UniqueConstraint(
            "tenant_id", "asset_id", "fingerprint_version", "input_digest",
            name="uq_discovery_asset_fingerprint_input",
        ),
        CheckConstraint(
            "((chain_sequence = 1 AND supersedes_fingerprint_id IS NULL) OR "
            "(chain_sequence > 1 AND supersedes_fingerprint_id IS NOT NULL))",
            name="ck_discovery_asset_fingerprint_root",
        ),
        CheckConstraint(
            "supersedes_fingerprint_id IS NULL OR supersedes_fingerprint_id <> fingerprint_id",
            name="ck_discovery_asset_fingerprint_self",
        ),
        CheckConstraint(
            "length(trim(fingerprint_version)) BETWEEN 1 AND 32",
            name="ck_discovery_asset_fingerprint_version_bounded",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_asset_fingerprint_confidence",
        ),
        CheckConstraint(
            _hash_check("input_digest"),
            name="ck_discovery_asset_fingerprint_input_digest_sha256",
        ),
        CheckConstraint(_json_check("component_hashes_json", 4096), name="ck_discovery_asset_fingerprint_components_bytes"),
        CheckConstraint(_json_check("detected_products_json", 8192), name="ck_discovery_asset_fingerprint_products_bytes"),
        CheckConstraint(_json_check("detected_frameworks_json", 8192), name="ck_discovery_asset_fingerprint_frameworks_bytes"),
        CheckConstraint(_json_check("detected_models_json", 8192), name="ck_discovery_asset_fingerprint_models_bytes"),
        CheckConstraint(_json_check("detected_protocols_json", 8192), name="ck_discovery_asset_fingerprint_protocols_bytes"),
        CheckConstraint(_json_check("detected_capabilities_json", 8192), name="ck_discovery_asset_fingerprint_capabilities_bytes"),
        CheckConstraint(_json_check("observed_destinations_json", 8192), name="ck_discovery_asset_fingerprint_destinations_bytes"),
        CheckConstraint(_json_check("drift_summary_json", 4096), name="ck_discovery_asset_fingerprint_drift_bytes"),
        Index(
            "idx_discovery_asset_fingerprint_tenant_asset", "tenant_id",
            "asset_id", "chain_sequence", "fingerprint_id",
        ),
        Index(
            "idx_discovery_asset_fingerprint_tenant_observation", "tenant_id",
            "source_observation_id", "created_at", "fingerprint_id",
        ),
    )

    fingerprint_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_observation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_claim_id: Mapped[str] = mapped_column(String(36), nullable=False)
    fingerprint_version: Mapped[str] = mapped_column(String(32), nullable=False)
    chain_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    supersedes_fingerprint_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    component_hashes_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    detected_products_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    detected_frameworks_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    detected_models_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    detected_protocols_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    detected_capabilities_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    observed_destinations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    drift_summary_json: Mapped[dict] = mapped_column(JSON, server_default=text("'{}'"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryAICapability(Base):
    __tablename__ = "discovery_ai_capabilities"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_ai_capability_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_ai_capability_tenant_asset", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "source_observation_id"],
            ["discovery_observations.tenant_id", "discovery_observations.observation_id"],
            name="fk_discovery_ai_capability_tenant_observation", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_claim_id"],
            ["discovery_evidence_claims.tenant_id", "discovery_evidence_claims.claim_id"],
            name="fk_discovery_ai_capability_tenant_claim", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id", "capability_name", "supersedes_capability_id"],
            ["discovery_ai_capabilities.tenant_id", "discovery_ai_capabilities.asset_id", "discovery_ai_capabilities.capability_name", "discovery_ai_capabilities.capability_id"],
            name="fk_discovery_ai_capability_tenant_predecessor",
            ondelete="RESTRICT", deferrable=False,
        ),
        UniqueConstraint("tenant_id", "capability_id", name="uq_discovery_ai_capability_tenant_id"),
        UniqueConstraint("tenant_id", "asset_id", "capability_name", "capability_id", name="uq_discovery_ai_capability_tenant_asset_name_id"),
        UniqueConstraint("tenant_id", "asset_id", "capability_name", "assertion_sequence", name="uq_discovery_ai_capability_sequence"),
        UniqueConstraint("tenant_id", "asset_id", "capability_name", "supersedes_capability_id", name="uq_discovery_ai_capability_predecessor"),
        UniqueConstraint("tenant_id", "asset_id", "capability_name", "capability_state", "extractor_version", "input_digest", name="uq_discovery_ai_capability_input"),
        CheckConstraint(f"capability_name IN ({_CAPABILITY_NAMES})", name="ck_discovery_ai_capability_name"),
        CheckConstraint("capability_state IN ('declared','configured','observed','inferred','denied','unknown')", name="ck_discovery_ai_capability_state"),
        CheckConstraint("((assertion_sequence = 1 AND supersedes_capability_id IS NULL) OR (assertion_sequence > 1 AND supersedes_capability_id IS NOT NULL))", name="ck_discovery_ai_capability_root"),
        CheckConstraint("supersedes_capability_id IS NULL OR supersedes_capability_id <> capability_id", name="ck_discovery_ai_capability_self"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_ai_capability_confidence"),
        CheckConstraint(
            "verification_state IN ('verified','partially_verified','inferred','unknown')",
            name="ck_discovery_ai_capability_verification",
        ),
        CheckConstraint(
            "freshness IN ('fresh','stale','expired','unknown')",
            name="ck_discovery_ai_capability_freshness",
        ),
        CheckConstraint(
            "NOT (declared_only AND inferred_only)",
            name="ck_discovery_ai_capability_truth_shape",
        ),
        CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_ai_capability_observed_order"),
        CheckConstraint("length(trim(extractor_version)) BETWEEN 1 AND 64", name="ck_discovery_ai_capability_extractor_bounded"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_ai_capability_input_digest_sha256"),
        Index("idx_discovery_ai_capability_tenant_asset_name", "tenant_id", "asset_id", "capability_name", "last_observed_at", "capability_id"),
        Index("idx_discovery_ai_capability_tenant_observation", "tenant_id", "source_observation_id", "created_at", "capability_id"),
    )

    capability_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_observation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_claim_id: Mapped[str] = mapped_column(String(36), nullable=False)
    capability_name: Mapped[str] = mapped_column(String(64), nullable=False)
    capability_state: Mapped[str] = mapped_column(String(32), nullable=False)
    extractor_version: Mapped[str] = mapped_column(String(64), nullable=False)
    assertion_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    supersedes_capability_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(
        String(32), server_default=text("'unknown'"), nullable=False
    )
    freshness: Mapped[str] = mapped_column(
        String(32), server_default=text("'unknown'"), nullable=False
    )
    observed_usage: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    declared_only: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    inferred_only: Mapped[bool] = mapped_column(
        Boolean, server_default=text("false"), nullable=False
    )
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryAssetHistoryMember(Base):
    __tablename__ = "discovery_asset_history_members"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_asset_history_member_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "history_event_id"], ["discovery_asset_history_events.tenant_id", "discovery_asset_history_events.history_event_id"], name="fk_discovery_asset_history_member_tenant_event", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_history_member_tenant_asset", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "history_member_id", name="uq_discovery_asset_history_member_tenant_id"),
        UniqueConstraint("tenant_id", "history_event_id", "member_role", "asset_id", name="uq_discovery_asset_history_member_asset"),
        UniqueConstraint("tenant_id", "history_event_id", "member_role", "ordinal", name="uq_discovery_asset_history_member_ordinal"),
        CheckConstraint("member_role IN ('source','result')", name="ck_discovery_asset_history_member_role"),
        CheckConstraint("ordinal >= 0", name="ck_discovery_asset_history_member_ordinal"),
        Index("idx_discovery_asset_history_member_tenant_asset", "tenant_id", "asset_id", "created_at", "history_member_id"),
        Index("idx_discovery_asset_history_member_tenant_event", "tenant_id", "history_event_id", "member_role", "ordinal", "history_member_id"),
    )

    history_member_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    history_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    member_role: Mapped[str] = mapped_column(String(16), nullable=False)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


H1B_TABLE_MODELS = {
    DiscoveryAIAsset.__tablename__: DiscoveryAIAsset,
    DiscoveryEvidenceClaim.__tablename__: DiscoveryEvidenceClaim,
    DiscoveryAssetHistoryEvent.__tablename__: DiscoveryAssetHistoryEvent,
    DiscoveryResolutionDecision.__tablename__: DiscoveryResolutionDecision,
    DiscoveryResolutionDecisionObservation.__tablename__: DiscoveryResolutionDecisionObservation,
    DiscoveryObservationAssetLink.__tablename__: DiscoveryObservationAssetLink,
    DiscoveryAssetFingerprint.__tablename__: DiscoveryAssetFingerprint,
    DiscoveryAICapability.__tablename__: DiscoveryAICapability,
    DiscoveryAssetHistoryMember.__tablename__: DiscoveryAssetHistoryMember,
}

H1B_PRIMARY_KEYS = {
    table_name: next(iter(model.__table__.primary_key.columns)).name
    for table_name, model in H1B_TABLE_MODELS.items()
}


__all__ = [
    "DiscoveryAIAsset",
    "DiscoveryEvidenceClaim",
    "DiscoveryAssetHistoryEvent",
    "DiscoveryResolutionDecision",
    "DiscoveryResolutionDecisionObservation",
    "DiscoveryObservationAssetLink",
    "DiscoveryAssetFingerprint",
    "DiscoveryAICapability",
    "DiscoveryAssetHistoryMember",
]
