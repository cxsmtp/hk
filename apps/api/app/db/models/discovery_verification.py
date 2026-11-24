from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _hash_check(column: str) -> str:
    stripped = column
    for character in "0123456789abcdef":
        stripped = f"replace({stripped}, '{character}', '')"
    return (
        f"length({column}) = 64 AND {column} = lower({column}) "
        f"AND {stripped} = ''"
    )


def _json_limit(column: str, limit: int) -> str:
    return f"length(CAST({column} AS TEXT)) <= {limit}"


class DiscoveryVerificationPolicy(Base):
    __tablename__ = "discovery_verification_policies"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_adv_policy_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "predecessor_policy_record_id"],
            ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"],
            name="fk_adv_policy_tenant_predecessor", ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "policy_record_id", name="uq_adv_policy_tenant_id"),
        UniqueConstraint("tenant_id", "policy_id", "version", name="uq_adv_policy_tenant_version"),
        UniqueConstraint("tenant_id", "predecessor_policy_record_id", name="uq_adv_policy_tenant_predecessor"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_policy_tenant_idempotency"),
        CheckConstraint("version >= 1", name="ck_adv_policy_version"),
        CheckConstraint("minimum_evidence_quality >= 0.0 AND minimum_evidence_quality <= 1.0", name="ck_adv_policy_evidence_quality"),
        CheckConstraint("minimum_confidence >= 0.0 AND minimum_confidence <= 1.0", name="ck_adv_policy_confidence"),
        CheckConstraint("minimum_source_diversity BETWEEN 1 AND 64", name="ck_adv_policy_diversity"),
        CheckConstraint("assertion_ttl_seconds BETWEEN 60 AND 31536000", name="ck_adv_policy_ttl"),
        CheckConstraint("rescan_interval_seconds BETWEEN 60 AND 31536000", name="ck_adv_policy_rescan"),
        CheckConstraint("effective_until IS NULL OR effective_from < effective_until", name="ck_adv_policy_effective_order"),
        CheckConstraint("(predecessor_policy_record_id IS NULL AND version = 1) OR predecessor_policy_record_id IS NOT NULL", name="ck_adv_policy_predecessor_shape"),
        CheckConstraint(_hash_check("input_digest"), name="ck_adv_policy_digest"),
        CheckConstraint(_json_limit("ecosystem_classes_json", 8192), name="ck_adv_policy_classes_bytes"),
        CheckConstraint(_json_limit("environments_json", 4096), name="ck_adv_policy_environments_bytes"),
        Index("idx_adv_policy_tenant_effective", "tenant_id", "policy_id", "effective_from", "policy_record_id"),
    )

    policy_record_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_policy_record_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ecosystem_classes_json: Mapped[list] = mapped_column(JSON, nullable=False)
    environments_json: Mapped[list] = mapped_column(JSON, nullable=False)
    minimum_evidence_quality: Mapped[float] = mapped_column(Float, nullable=False)
    minimum_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    minimum_source_diversity: Mapped[int] = mapped_column(Integer, nullable=False)
    assertion_ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    rescan_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    effective_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    requirements: Mapped[list["DiscoveryVerificationPolicyRequirement"]] = relationship(
        back_populates="policy",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="DiscoveryVerificationPolicyRequirement.requirement_id",
    )


class DiscoveryVerificationPolicyRequirement(Base):
    __tablename__ = "discovery_verification_policy_requirements"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "policy_record_id"],
            ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"],
            name="fk_adv_requirement_tenant_policy", ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "requirement_record_id", name="uq_adv_requirement_tenant_id"),
        UniqueConstraint("tenant_id", "policy_record_id", "requirement_id", name="uq_adv_requirement_tenant_key"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_requirement_tenant_idempotency"),
        CheckConstraint("length(trim(requirement_id)) BETWEEN 1 AND 128", name="ck_adv_requirement_id"),
        CheckConstraint("minimum_result_count BETWEEN 1 AND 32", name="ck_adv_requirement_result_count"),
        CheckConstraint("maximum_age_seconds BETWEEN 60 AND 31536000", name="ck_adv_requirement_age"),
        CheckConstraint(_hash_check("input_digest"), name="ck_adv_requirement_digest"),
        CheckConstraint(_json_limit("accepted_methods_json", 8192), name="ck_adv_requirement_methods_bytes"),
        CheckConstraint(_json_limit("applicability_json", 8192), name="ck_adv_requirement_applicability_bytes"),
        Index("idx_adv_requirement_tenant_policy", "tenant_id", "policy_record_id", "required", "requirement_record_id"),
    )

    requirement_record_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(128), nullable=False)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    accepted_methods_json: Mapped[list] = mapped_column(JSON, nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(64), nullable=False)
    independence_group: Mapped[str] = mapped_column(String(128), nullable=False)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    minimum_result_count: Mapped[int] = mapped_column(Integer, nullable=False)
    maximum_age_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    applicability_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    policy: Mapped[DiscoveryVerificationPolicy] = relationship(
        back_populates="requirements"
    )


class DiscoveryVerificationEpisode(Base):
    __tablename__ = "discovery_verification_episodes"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_adv_episode_tenant_ecosystem", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "hypothesis_evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_adv_episode_tenant_evaluation", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "policy_record_id"], ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"], name="fk_adv_episode_tenant_policy", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "predecessor_episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_episode_tenant_predecessor", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "episode_id", name="uq_adv_episode_tenant_id"),
        UniqueConstraint("tenant_id", "ecosystem_id", "episode_sequence", name="uq_adv_episode_tenant_sequence"),
        UniqueConstraint("tenant_id", "predecessor_episode_id", name="uq_adv_episode_tenant_predecessor"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_episode_tenant_idempotency"),
        CheckConstraint("episode_sequence >= 1", name="ck_adv_episode_sequence"),
        CheckConstraint("started_at <= due_at AND due_at <= expires_at", name="ck_adv_episode_time_order"),
        CheckConstraint("(predecessor_episode_id IS NULL AND episode_sequence = 1) OR predecessor_episode_id IS NOT NULL", name="ck_adv_episode_predecessor_shape"),
        CheckConstraint(_hash_check("graph_input_digest"), name="ck_adv_episode_graph_digest"),
        CheckConstraint(_hash_check("evidence_input_digest"), name="ck_adv_episode_evidence_digest"),
        CheckConstraint(_hash_check("policy_digest"), name="ck_adv_episode_policy_digest"),
        CheckConstraint(_hash_check("input_digest"), name="ck_adv_episode_digest"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_adv_episode_limitations_bytes"),
        Index("idx_adv_episode_tenant_ecosystem", "tenant_id", "ecosystem_id", "episode_sequence", "episode_id"),
        Index("idx_adv_episode_tenant_due", "tenant_id", "due_at", "expires_at", "episode_id"),
    )

    episode_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    hypothesis_evaluation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    episode_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_episode_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    trigger: Mapped[str] = mapped_column(String(64), nullable=False)
    trigger_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    graph_input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryVerificationAttempt(Base):
    __tablename__ = "discovery_verification_attempts"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_attempt_tenant_episode", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "task_id"], ["discovery_verification_tasks.tenant_id", "discovery_verification_tasks.task_id"], name="fk_adv_attempt_tenant_task", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "attempt_id", name="uq_adv_attempt_tenant_id"),
        UniqueConstraint("tenant_id", "task_id", "attempt_sequence", name="uq_adv_attempt_tenant_sequence"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_attempt_tenant_idempotency"),
        CheckConstraint("attempt_sequence >= 1", name="ck_adv_attempt_sequence"),
        CheckConstraint("execution_state IN ('completed','transport_failed','expired','cancelled')", name="ck_adv_attempt_state"),
        CheckConstraint("completed_at IS NULL OR started_at <= completed_at", name="ck_adv_attempt_time_order"),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_adv_attempt_latency"),
        CheckConstraint(_hash_check("input_digest"), name="ck_adv_attempt_digest"),
        CheckConstraint("output_digest IS NULL OR (" + _hash_check("output_digest") + ")", name="ck_adv_attempt_output_digest"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_adv_attempt_limitations_bytes"),
        Index("idx_adv_attempt_tenant_task", "tenant_id", "task_id", "attempt_sequence", "attempt_id"),
        Index("idx_adv_attempt_tenant_episode", "tenant_id", "episode_id", "execution_state", "attempt_id"),
    )

    attempt_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    episode_id: Mapped[str] = mapped_column(String(36), nullable=False)
    task_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_id: Mapped[str] = mapped_column(String(255), nullable=False)
    collector_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    collector_integrity_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_state: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryVerificationResult(Base):
    __tablename__ = "discovery_verification_results"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_result_tenant_episode", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "requirement_record_id"], ["discovery_verification_policy_requirements.tenant_id", "discovery_verification_policy_requirements.requirement_record_id"], name="fk_adv_result_tenant_requirement", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "task_id"], ["discovery_verification_tasks.tenant_id", "discovery_verification_tasks.task_id"], name="fk_adv_result_tenant_task", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "attempt_id"], ["discovery_verification_attempts.tenant_id", "discovery_verification_attempts.attempt_id"], name="fk_adv_result_tenant_attempt", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "predecessor_result_id"], ["discovery_verification_results.tenant_id", "discovery_verification_results.result_id"], name="fk_adv_result_tenant_predecessor", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "result_id", name="uq_adv_result_tenant_id"),
        UniqueConstraint("tenant_id", "requirement_record_id", "result_sequence", name="uq_adv_result_tenant_sequence"),
        UniqueConstraint("tenant_id", "predecessor_result_id", name="uq_adv_result_tenant_predecessor"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_result_tenant_idempotency"),
        CheckConstraint("outcome IN ('verified','failed','contradicted','unsupported','unknown')", name="ck_adv_result_outcome"),
        CheckConstraint("integrity_state IN ('verified','unverified','failed','unknown')", name="ck_adv_result_integrity"),
        CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_adv_result_freshness"),
        CheckConstraint("result_sequence >= 1", name="ck_adv_result_sequence"),
        CheckConstraint("observed_at <= validated_at AND validated_at <= expires_at", name="ck_adv_result_time_order"),
        CheckConstraint("(predecessor_result_id IS NULL AND result_sequence = 1) OR predecessor_result_id IS NOT NULL", name="ck_adv_result_predecessor_shape"),
        CheckConstraint("outcome NOT IN ('verified','contradicted') OR length(CAST(evidence_node_ids_json AS TEXT)) > 2", name="ck_adv_result_evidence_required"),
        CheckConstraint("(outcome = 'verified' AND satisfies_requirement = true) OR (outcome <> 'verified' AND satisfies_requirement = false)", name="ck_adv_result_satisfaction"),
        CheckConstraint(_hash_check("input_digest"), name="ck_adv_result_digest"),
        CheckConstraint(_json_limit("evidence_node_ids_json", 8192), name="ck_adv_result_evidence_bytes"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_adv_result_limitations_bytes"),
        Index("idx_adv_result_tenant_episode", "tenant_id", "episode_id", "outcome", "result_id"),
        Index("idx_adv_result_tenant_requirement", "tenant_id", "requirement_record_id", "result_sequence", "result_id"),
    )

    result_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    episode_id: Mapped[str] = mapped_column(String(36), nullable=False)
    requirement_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    attempt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    predecessor_result_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    result_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_node_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    source_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    collector_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    integrity_state: Mapped[str] = mapped_column(String(32), nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    satisfies_requirement: Mapped[bool] = mapped_column(Boolean, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryVerificationAssertion(Base):
    __tablename__ = "discovery_verification_assertions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_adv_assertion_tenant_ecosystem", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_assertion_tenant_episode", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "erg_evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_adv_assertion_tenant_evaluation", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "policy_record_id"], ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"], name="fk_adv_assertion_tenant_policy", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "predecessor_assertion_id"], ["discovery_verification_assertions.tenant_id", "discovery_verification_assertions.assertion_id"], name="fk_adv_assertion_tenant_predecessor", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "assertion_id", name="uq_adv_assertion_tenant_id"),
        UniqueConstraint("tenant_id", "ecosystem_id", "assertion_sequence", name="uq_adv_assertion_tenant_sequence"),
        UniqueConstraint("tenant_id", "predecessor_assertion_id", name="uq_adv_assertion_tenant_predecessor"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_assertion_tenant_idempotency"),
        CheckConstraint("conclusion IN ('verified','incomplete','contradicted','expired')", name="ck_adv_assertion_conclusion"),
        CheckConstraint("assertion_sequence >= 1", name="ck_adv_assertion_sequence"),
        CheckConstraint("required_requirement_count >= 0 AND required_verified_count >= 0 AND required_verified_count <= required_requirement_count", name="ck_adv_assertion_required_coverage"),
        CheckConstraint("optional_requirement_count >= 0 AND optional_verified_count >= 0 AND optional_verified_count <= optional_requirement_count", name="ck_adv_assertion_optional_coverage"),
        CheckConstraint("conclusion <> 'verified' OR (required_requirement_count > 0 AND required_verified_count = required_requirement_count)", name="ck_adv_assertion_verified_complete"),
        CheckConstraint("source_diversity BETWEEN 0 AND 64", name="ck_adv_assertion_diversity"),
        CheckConstraint("evidence_quality IS NULL OR (evidence_quality >= 0.0 AND evidence_quality <= 1.0)", name="ck_adv_assertion_evidence_quality"),
        CheckConstraint("verification_quality IS NULL OR (verification_quality >= 0.0 AND verification_quality <= 1.0)", name="ck_adv_assertion_verification_quality"),
        CheckConstraint("issued_at <= valid_from AND valid_from < valid_until", name="ck_adv_assertion_time_order"),
        CheckConstraint("invalidated_at IS NULL OR valid_from <= invalidated_at", name="ck_adv_assertion_invalidation_time"),
        CheckConstraint("(predecessor_assertion_id IS NULL AND assertion_sequence = 1) OR predecessor_assertion_id IS NOT NULL", name="ck_adv_assertion_predecessor_shape"),
        CheckConstraint(_hash_check("input_digest"), name="ck_adv_assertion_digest"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_adv_assertion_limitations_bytes"),
        CheckConstraint(_json_limit("contradictions_json", 16384), name="ck_adv_assertion_contradictions_bytes"),
        Index("idx_adv_assertion_tenant_ecosystem", "tenant_id", "ecosystem_id", "assertion_sequence", "assertion_id"),
        Index("idx_adv_assertion_tenant_validity", "tenant_id", "conclusion", "valid_until", "assertion_id"),
    )

    assertion_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    episode_id: Mapped[str] = mapped_column(String(36), nullable=False)
    erg_evaluation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    predecessor_assertion_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    assertion_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    conclusion: Mapped[str] = mapped_column(String(32), nullable=False)
    required_requirement_count: Mapped[int] = mapped_column(Integer, nullable=False)
    required_verified_count: Mapped[int] = mapped_column(Integer, nullable=False)
    optional_requirement_count: Mapped[int] = mapped_column(Integer, nullable=False)
    optional_verified_count: Mapped[int] = mapped_column(Integer, nullable=False)
    source_diversity: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_quality: Mapped[float | None] = mapped_column(Float, nullable=True)
    verification_quality: Mapped[float | None] = mapped_column(Float, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    invalidated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    contradictions_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryVerificationEvent(Base):
    __tablename__ = "discovery_verification_events"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_adv_event_tenant_ecosystem", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_event_tenant_episode", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "assertion_id"], ["discovery_verification_assertions.tenant_id", "discovery_verification_assertions.assertion_id"], name="fk_adv_event_tenant_assertion", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "event_id", name="uq_adv_event_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_event_tenant_idempotency"),
        CheckConstraint("event_type IN ('verification_started','verification_passed','verification_failed','verification_expired','verification_contradicted','verification_updated','confidence_changed','evidence_added','evidence_removed')", name="ck_adv_event_type"),
        CheckConstraint("actor_type IN ('system','collector','operator','admin')", name="ck_adv_event_actor_type"),
        CheckConstraint(_hash_check("input_digest"), name="ck_adv_event_digest"),
        CheckConstraint(_json_limit("evidence_node_ids_json", 8192), name="ck_adv_event_evidence_bytes"),
        CheckConstraint(_json_limit("before_json", 16384), name="ck_adv_event_before_bytes"),
        CheckConstraint(_json_limit("after_json", 16384), name="ck_adv_event_after_bytes"),
        Index("idx_adv_event_tenant_ecosystem", "tenant_id", "ecosystem_id", "occurred_at", "event_id"),
        Index("idx_adv_event_tenant_type", "tenant_id", "event_type", "occurred_at", "event_id"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    episode_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    assertion_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_node_ids_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    before_json: Mapped[dict] = mapped_column(JSON, server_default=text("'{}'"), nullable=False)
    after_json: Mapped[dict] = mapped_column(JSON, server_default=text("'{}'"), nullable=False)
    reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


ADV_TABLE_MODELS = {
    model.__tablename__: model
    for model in (
        DiscoveryVerificationPolicy,
        DiscoveryVerificationPolicyRequirement,
        DiscoveryVerificationEpisode,
        DiscoveryVerificationAttempt,
        DiscoveryVerificationResult,
        DiscoveryVerificationAssertion,
        DiscoveryVerificationEvent,
    )
}


__all__ = [
    "ADV_TABLE_MODELS",
    "DiscoveryVerificationAssertion",
    "DiscoveryVerificationAttempt",
    "DiscoveryVerificationEpisode",
    "DiscoveryVerificationEvent",
    "DiscoveryVerificationPolicy",
    "DiscoveryVerificationPolicyRequirement",
    "DiscoveryVerificationResult",
]
