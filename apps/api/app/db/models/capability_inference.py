from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
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
    return f"length({column}) = 64 AND {column} = lower({column}) AND {stripped} = ''"


def _json_limit(column: str, limit: int) -> str:
    return f"length(CAST({column} AS TEXT)) <= {limit}"


class DiscoveryCapabilityInferenceRun(Base):
    __tablename__ = "discovery_capability_inference_runs"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_cie_run_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_cie_run_tenant_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "supersedes_run_id"],
            ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"],
            name="fk_cie_run_tenant_predecessor",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "inference_run_id", name="uq_cie_run_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_cie_run_tenant_idempotency"),
        UniqueConstraint("tenant_id", "subject_reference_hash", "run_sequence", name="uq_cie_run_tenant_subject_seq"),
        CheckConstraint(_hash_check("subject_reference_hash"), name="ck_cie_run_subject_hash"),
        CheckConstraint(_hash_check("input_digest"), name="ck_cie_run_input_digest"),
        CheckConstraint(_hash_check("output_digest"), name="ck_cie_run_output_digest"),
        CheckConstraint("run_sequence >= 1", name="ck_cie_run_sequence"),
        CheckConstraint("first_observed_at <= last_observed_at AND last_observed_at <= validated_at", name="ck_cie_run_time_order"),
        CheckConstraint(_json_limit("observation_ids_json", 65536), name="ck_cie_run_observations_bytes"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_cie_run_limitations_bytes"),
        Index("idx_cie_run_tenant_subject", "tenant_id", "subject_reference_hash", "run_sequence", "inference_run_id"),
        Index("idx_cie_run_tenant_validated", "tenant_id", "validated_at", "inference_run_id"),
    )

    inference_run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    subject_reference_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    observation_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    engine_version: Mapped[str] = mapped_column(String(64), nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    run_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    supersedes_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    recommended_asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    recommended_ecosystem: Mapped[str] = mapped_column(String(128), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    output_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryCapabilityEvidence(Base):
    __tablename__ = "discovery_capability_evidence"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_cie_evidence_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(
            ["tenant_id", "inference_run_id"],
            ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"],
            name="fk_cie_evidence_tenant_run",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "capability_evidence_id", name="uq_cie_evidence_tenant_id"),
        UniqueConstraint("tenant_id", "inference_run_id", "rule_id", name="uq_cie_evidence_tenant_rule"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_cie_evidence_confidence"),
        CheckConstraint("source_diversity >= 0 AND source_diversity <= 64", name="ck_cie_evidence_sources"),
        CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_cie_evidence_freshness"),
        CheckConstraint("verification_state IN ('verified','partially_verified','inferred','contradicted','unknown')", name="ck_cie_evidence_verification"),
        CheckConstraint(_hash_check("evidence_digest"), name="ck_cie_evidence_digest"),
        CheckConstraint(_json_limit("supporting_signal_ids_json", 65536), name="ck_cie_evidence_support_bytes"),
        CheckConstraint(_json_limit("conflicting_signal_ids_json", 65536), name="ck_cie_evidence_conflict_bytes"),
        CheckConstraint(_json_limit("unknown_predicates_json", 16384), name="ck_cie_evidence_unknown_bytes"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_cie_evidence_limitations_bytes"),
        Index("idx_cie_evidence_tenant_run", "tenant_id", "inference_run_id", "capability_id", "capability_evidence_id"),
        Index("idx_cie_evidence_tenant_capability", "tenant_id", "capability_id", "confidence", "capability_evidence_id"),
    )

    capability_evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    inference_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    capability_id: Mapped[str] = mapped_column(String(64), nullable=False)
    family: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    calibration_version: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    supporting_signal_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    conflicting_signal_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    unknown_predicates_json: Mapped[list] = mapped_column(JSON, nullable=False)
    source_diversity: Mapped[int] = mapped_column(Integer, nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    last_validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    explanation: Mapped[str] = mapped_column(String(1500), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    recommended_asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    recommended_ecosystem: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryCapabilityGenome(Base):
    __tablename__ = "discovery_capability_genomes"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_cie_genome_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(
            ["tenant_id", "inference_run_id"],
            ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"],
            name="fk_cie_genome_tenant_run",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "supersedes_genome_id"],
            ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"],
            name="fk_cie_genome_tenant_predecessor",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "genome_id", name="uq_cie_genome_tenant_id"),
        UniqueConstraint("tenant_id", "subject_reference_hash", "genome_version", name="uq_cie_genome_tenant_subject_ver"),
        UniqueConstraint("tenant_id", "inference_run_id", name="uq_cie_genome_tenant_run"),
        CheckConstraint(_hash_check("subject_reference_hash"), name="ck_cie_genome_subject_hash"),
        CheckConstraint(_hash_check("genome_digest"), name="ck_cie_genome_digest"),
        CheckConstraint("genome_version >= 1", name="ck_cie_genome_version"),
        CheckConstraint("first_observed_at <= last_observed_at", name="ck_cie_genome_time_order"),
        *tuple(
            CheckConstraint(_json_limit(column, 32768), name=f"ck_cie_genome_{short}_bytes")
            for column, short in (
                ("capabilities_json", "capabilities"),
                ("dependencies_json", "dependencies"),
                ("permissions_json", "permissions"),
                ("reachability_json", "reachability"),
                ("usage_json", "usage"),
                ("models_json", "models"),
                ("providers_json", "providers"),
                ("runtime_json", "runtime"),
                ("data_json", "data"),
                ("marketplace_json", "marketplace"),
                ("identity_json", "identity"),
            )
        ),
        Index("idx_cie_genome_tenant_subject", "tenant_id", "subject_reference_hash", "genome_version", "genome_id"),
        Index("idx_cie_genome_tenant_run", "tenant_id", "inference_run_id", "genome_id"),
    )

    genome_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    inference_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    subject_reference_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    genome_version: Mapped[int] = mapped_column(Integer, nullable=False)
    supersedes_genome_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    genome_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    capabilities_json: Mapped[list] = mapped_column(JSON, nullable=False)
    dependencies_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    permissions_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    reachability_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    usage_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    models_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    providers_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    runtime_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    data_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    marketplace_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    identity_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryCapabilityEvent(Base):
    __tablename__ = "discovery_capability_events"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_cie_event_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(
            ["tenant_id", "genome_id"],
            ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"],
            name="fk_cie_event_tenant_genome",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "previous_genome_id"],
            ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"],
            name="fk_cie_event_tenant_previous",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "event_id", name="uq_cie_event_tenant_id"),
        UniqueConstraint("tenant_id", "input_digest", name="uq_cie_event_tenant_digest"),
        CheckConstraint(_hash_check("subject_reference_hash"), name="ck_cie_event_subject_hash"),
        CheckConstraint(_hash_check("input_digest"), name="ck_cie_event_input_digest"),
        CheckConstraint(
            "event_type IN ('capability_added','capability_removed','confidence_changed','dependency_added','dependency_removed','marketplace_changed','provider_changed','model_changed','runtime_changed','data_changed','identity_changed','permission_changed','usage_changed','repository_changed','configuration_changed','genome_changed')",
            name="ck_cie_event_type",
        ),
        CheckConstraint(_json_limit("before_json", 32768), name="ck_cie_event_before_bytes"),
        CheckConstraint(_json_limit("after_json", 32768), name="ck_cie_event_after_bytes"),
        CheckConstraint(_json_limit("evidence_references_json", 16384), name="ck_cie_event_evidence_bytes"),
        Index("idx_cie_event_tenant_subject", "tenant_id", "subject_reference_hash", "occurred_at", "event_id"),
        Index("idx_cie_event_tenant_type", "tenant_id", "event_type", "occurred_at", "event_id"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    subject_reference_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    genome_id: Mapped[str] = mapped_column(String(36), nullable=False)
    previous_genome_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    before_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    after_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    evidence_references_json: Mapped[list] = mapped_column(JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


CIE_TABLE_MODELS = {
    model.__tablename__: model
    for model in (
        DiscoveryCapabilityInferenceRun,
        DiscoveryCapabilityEvidence,
        DiscoveryCapabilityGenome,
        DiscoveryCapabilityEvent,
    )
}


__all__ = [
    "CIE_TABLE_MODELS",
    "DiscoveryCapabilityEvidence",
    "DiscoveryCapabilityEvent",
    "DiscoveryCapabilityGenome",
    "DiscoveryCapabilityInferenceRun",
]
