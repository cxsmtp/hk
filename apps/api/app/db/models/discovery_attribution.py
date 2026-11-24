from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
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
    return f"length({column}) = 64 AND {column} = lower({column}) AND {stripped} = ''"


class DiscoveryAssetReachability(Base):
    __tablename__ = "discovery_asset_reachability"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_asset_reachability_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_reachability_tenant_asset", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_asset_reachability_tenant_evidence", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "reachability_id", name="uq_discovery_asset_reachability_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_reachability_tenant_idempotency"),
        CheckConstraint("target_category IN ('model','mcp','internal_api','external_api','database','vector_db','filesystem','cloud_control_plane','saas','ci_cd','source_repo','internal_network','internet')", name="ck_discovery_asset_reachability_category"),
        CheckConstraint("reachability_state IN ('configured','observed','potential','verified','unknown')", name="ck_discovery_asset_reachability_state"),
        CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_asset_reachability_verification"),
        CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_discovery_asset_reachability_freshness"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_reachability_confidence"),
        CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_asset_reachability_seen_order"),
        CheckConstraint(_hash_check("target_reference_hash"), name="ck_discovery_asset_reachability_target_hash"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_asset_reachability_digest"),
        CheckConstraint("length(CAST(limitations_json AS TEXT)) <= 4096", name="ck_discovery_asset_reachability_limitations_bytes"),
        Index("idx_discovery_asset_reachability_tenant_asset", "tenant_id", "asset_id", "target_category", "reachability_id"),
        Index("idx_discovery_asset_reachability_tenant_target", "tenant_id", "target_reference_hash", "reachability_state", "reachability_id"),
    )

    reachability_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target_category: Mapped[str] = mapped_column(String(64), nullable=False)
    target_reference_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    reachability_state: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_usage: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryAssetIdentityLink(Base):
    __tablename__ = "discovery_asset_identity_links"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_asset_identity_link_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_identity_link_tenant_asset", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_asset_identity_link_tenant_evidence", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "identity_link_id", name="uq_discovery_asset_identity_link_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_identity_link_tenant_idempotency"),
        CheckConstraint("identity_type IN ('user','group','service_principal','managed_identity','oauth_app','api_key_reference','workload_identity','agent_identity','unknown')", name="ck_discovery_asset_identity_link_type"),
        CheckConstraint("access_state IN ('assigned','configured','observed','active','unknown')", name="ck_discovery_asset_identity_link_access"),
        CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_asset_identity_link_verification"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_identity_link_confidence"),
        CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_asset_identity_link_seen_order"),
        CheckConstraint(_hash_check("identity_reference_hash"), name="ck_discovery_asset_identity_link_reference_hash"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_asset_identity_link_digest"),
        Index("idx_discovery_asset_identity_link_tenant_asset", "tenant_id", "asset_id", "identity_type", "identity_link_id"),
        Index("idx_discovery_asset_identity_link_tenant_identity", "tenant_id", "identity_reference_hash", "access_state", "identity_link_id"),
    )

    identity_link_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    identity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_reference_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    access_state: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    usage_proven: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryAssetOwnershipAssertion(Base):
    __tablename__ = "discovery_asset_ownership_assertions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_asset_ownership_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_ownership_tenant_asset", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_asset_ownership_tenant_evidence", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "ownership_assertion_id", name="uq_discovery_asset_ownership_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_ownership_tenant_idempotency"),
        CheckConstraint("owner_type IN ('business_owner','technical_owner','team','department','repository_owner','cloud_account','saas_admin','cost_center','unknown')", name="ck_discovery_asset_ownership_type"),
        CheckConstraint("ownership_state IN ('asserted','inferred','verified','unknown','contradicted')", name="ck_discovery_asset_ownership_state"),
        CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_asset_ownership_verification"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_ownership_confidence"),
        CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_asset_ownership_seen_order"),
        CheckConstraint("(owner_type = 'unknown' AND owner_reference_hash IS NULL) OR (owner_type <> 'unknown' AND owner_reference_hash IS NOT NULL)", name="ck_discovery_asset_ownership_reference_shape"),
        CheckConstraint("owner_reference_hash IS NULL OR length(owner_reference_hash) = 64", name="ck_discovery_asset_ownership_reference_hash"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_asset_ownership_digest"),
        Index("idx_discovery_asset_ownership_tenant_asset", "tenant_id", "asset_id", "owner_type", "ownership_assertion_id"),
        Index("idx_discovery_asset_ownership_tenant_owner", "tenant_id", "owner_reference_hash", "ownership_state", "ownership_assertion_id"),
    )

    ownership_assertion_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    owner_type: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_reference_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ownership_state: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


ATTRIBUTION_TABLE_MODELS = {
    model.__tablename__: model
    for model in (
        DiscoveryAssetReachability,
        DiscoveryAssetIdentityLink,
        DiscoveryAssetOwnershipAssertion,
    )
}


__all__ = [
    "ATTRIBUTION_TABLE_MODELS",
    "DiscoveryAssetIdentityLink",
    "DiscoveryAssetOwnershipAssertion",
    "DiscoveryAssetReachability",
]
