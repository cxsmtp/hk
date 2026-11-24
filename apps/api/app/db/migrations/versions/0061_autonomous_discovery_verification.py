"""Add path-native Autonomous Discovery Verification evidence records.

Revision ID: 0061_autonomous_discovery_verification
Revises: 0060_evidence_resolution_graph
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0061_autonomous_discovery_verification"
down_revision = "0060_evidence_resolution_graph"
branch_labels = None
depends_on = None


TABLES = (
    "discovery_verification_policies",
    "discovery_verification_policy_requirements",
    "discovery_verification_episodes",
    "discovery_verification_attempts",
    "discovery_verification_results",
    "discovery_verification_assertions",
    "discovery_verification_events",
)
IMMUTABLE_TABLES = TABLES


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


def _create_policy_tables(dialect: str) -> None:
    op.create_table(
        "discovery_verification_policies",
        sa.Column("policy_record_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("policy_id", sa.String(128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("predecessor_policy_record_id", sa.String(36), nullable=True),
        sa.Column("ecosystem_classes_json", sa.JSON(), nullable=False),
        sa.Column("environments_json", sa.JSON(), nullable=False),
        sa.Column("minimum_evidence_quality", sa.Float(), nullable=False),
        sa.Column("minimum_confidence", sa.Float(), nullable=False),
        sa.Column("minimum_source_diversity", sa.Integer(), nullable=False),
        sa.Column("assertion_ttl_seconds", sa.Integer(), nullable=False),
        sa.Column("rescan_interval_seconds", sa.Integer(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_adv_policy_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "predecessor_policy_record_id"], ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"], name="fk_adv_policy_tenant_predecessor", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("policy_record_id"),
        sa.UniqueConstraint("tenant_id", "policy_record_id", name="uq_adv_policy_tenant_id"),
        sa.UniqueConstraint("tenant_id", "policy_id", "version", name="uq_adv_policy_tenant_version"),
        sa.UniqueConstraint("tenant_id", "predecessor_policy_record_id", name="uq_adv_policy_tenant_predecessor"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_policy_tenant_idempotency"),
        sa.CheckConstraint("version >= 1", name="ck_adv_policy_version"),
        sa.CheckConstraint("minimum_evidence_quality >= 0.0 AND minimum_evidence_quality <= 1.0", name="ck_adv_policy_evidence_quality"),
        sa.CheckConstraint("minimum_confidence >= 0.0 AND minimum_confidence <= 1.0", name="ck_adv_policy_confidence"),
        sa.CheckConstraint("minimum_source_diversity BETWEEN 1 AND 64", name="ck_adv_policy_diversity"),
        sa.CheckConstraint("assertion_ttl_seconds BETWEEN 60 AND 31536000", name="ck_adv_policy_ttl"),
        sa.CheckConstraint("rescan_interval_seconds BETWEEN 60 AND 31536000", name="ck_adv_policy_rescan"),
        sa.CheckConstraint("effective_until IS NULL OR effective_from < effective_until", name="ck_adv_policy_effective_order"),
        sa.CheckConstraint("(predecessor_policy_record_id IS NULL AND version = 1) OR predecessor_policy_record_id IS NOT NULL", name="ck_adv_policy_predecessor_shape"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_adv_policy_digest"),
        sa.CheckConstraint(_json_limit("ecosystem_classes_json", 8192, dialect), name="ck_adv_policy_classes_bytes"),
        sa.CheckConstraint(_json_limit("environments_json", 4096, dialect), name="ck_adv_policy_environments_bytes"),
    )
    op.create_index("idx_adv_policy_tenant_effective", "discovery_verification_policies", ["tenant_id", "policy_id", "effective_from", "policy_record_id"])

    op.create_table(
        "discovery_verification_policy_requirements",
        sa.Column("requirement_record_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("policy_record_id", sa.String(36), nullable=False),
        sa.Column("requirement_id", sa.String(128), nullable=False),
        sa.Column("task_type", sa.String(64), nullable=False),
        sa.Column("accepted_methods_json", sa.JSON(), nullable=False),
        sa.Column("evidence_class", sa.String(64), nullable=False),
        sa.Column("independence_group", sa.String(128), nullable=False),
        sa.Column("required", sa.Boolean(), nullable=False),
        sa.Column("minimum_result_count", sa.Integer(), nullable=False),
        sa.Column("maximum_age_seconds", sa.Integer(), nullable=False),
        sa.Column("applicability_json", sa.JSON(), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "policy_record_id"], ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"], name="fk_adv_requirement_tenant_policy", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("requirement_record_id"),
        sa.UniqueConstraint("tenant_id", "requirement_record_id", name="uq_adv_requirement_tenant_id"),
        sa.UniqueConstraint("tenant_id", "policy_record_id", "requirement_id", name="uq_adv_requirement_tenant_key"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_requirement_tenant_idempotency"),
        sa.CheckConstraint("length(trim(requirement_id)) BETWEEN 1 AND 128", name="ck_adv_requirement_id"),
        sa.CheckConstraint("minimum_result_count BETWEEN 1 AND 32", name="ck_adv_requirement_result_count"),
        sa.CheckConstraint("maximum_age_seconds BETWEEN 60 AND 31536000", name="ck_adv_requirement_age"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_adv_requirement_digest"),
        sa.CheckConstraint(_json_limit("accepted_methods_json", 8192, dialect), name="ck_adv_requirement_methods_bytes"),
        sa.CheckConstraint(_json_limit("applicability_json", 8192, dialect), name="ck_adv_requirement_applicability_bytes"),
    )
    op.create_index("idx_adv_requirement_tenant_policy", "discovery_verification_policy_requirements", ["tenant_id", "policy_record_id", "required", "requirement_record_id"])


def _create_episode_table(dialect: str) -> None:
    op.create_table(
        "discovery_verification_episodes",
        sa.Column("episode_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_record_id", sa.String(36), nullable=False),
        sa.Column("hypothesis_evaluation_id", sa.String(36), nullable=False),
        sa.Column("policy_record_id", sa.String(36), nullable=False),
        sa.Column("environment", sa.String(64), nullable=False),
        sa.Column("episode_sequence", sa.Integer(), nullable=False),
        sa.Column("predecessor_episode_id", sa.String(36), nullable=True),
        sa.Column("trigger", sa.String(64), nullable=False),
        sa.Column("trigger_event_id", sa.String(36), nullable=True),
        sa.Column("graph_input_digest", sa.String(64), nullable=False),
        sa.Column("evidence_input_digest", sa.String(64), nullable=False),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_adv_episode_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_adv_episode_tenant_ecosystem", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "hypothesis_evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_adv_episode_tenant_evaluation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "policy_record_id"], ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"], name="fk_adv_episode_tenant_policy", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "predecessor_episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_episode_tenant_predecessor", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("episode_id"),
        sa.UniqueConstraint("tenant_id", "episode_id", name="uq_adv_episode_tenant_id"),
        sa.UniqueConstraint("tenant_id", "ecosystem_id", "episode_sequence", name="uq_adv_episode_tenant_sequence"),
        sa.UniqueConstraint("tenant_id", "predecessor_episode_id", name="uq_adv_episode_tenant_predecessor"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_episode_tenant_idempotency"),
        sa.CheckConstraint("episode_sequence >= 1", name="ck_adv_episode_sequence"),
        sa.CheckConstraint("started_at <= due_at AND due_at <= expires_at", name="ck_adv_episode_time_order"),
        sa.CheckConstraint("(predecessor_episode_id IS NULL AND episode_sequence = 1) OR predecessor_episode_id IS NOT NULL", name="ck_adv_episode_predecessor_shape"),
        sa.CheckConstraint(_hash_check("graph_input_digest", dialect), name="ck_adv_episode_graph_digest"),
        sa.CheckConstraint(_hash_check("evidence_input_digest", dialect), name="ck_adv_episode_evidence_digest"),
        sa.CheckConstraint(_hash_check("policy_digest", dialect), name="ck_adv_episode_policy_digest"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_adv_episode_digest"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_adv_episode_limitations_bytes"),
    )
    op.create_index("idx_adv_episode_tenant_ecosystem", "discovery_verification_episodes", ["tenant_id", "ecosystem_id", "episode_sequence", "episode_id"])
    op.create_index("idx_adv_episode_tenant_due", "discovery_verification_episodes", ["tenant_id", "due_at", "expires_at", "episode_id"])


def _extend_verification_tasks() -> None:
    with op.batch_alter_table("discovery_verification_tasks", recreate="always") as batch:
        batch.add_column(sa.Column("verification_episode_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("verification_requirement_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("task_contract_version", sa.String(32), server_default=sa.text("'legacy'"), nullable=False))
        batch.create_foreign_key("fk_discovery_verification_task_tenant_episode", "discovery_verification_episodes", ["tenant_id", "verification_episode_id"], ["tenant_id", "episode_id"], ondelete="RESTRICT")
        batch.create_foreign_key("fk_discovery_verification_task_tenant_requirement", "discovery_verification_policy_requirements", ["tenant_id", "verification_requirement_id"], ["tenant_id", "requirement_record_id"], ondelete="RESTRICT")
        batch.create_index("idx_discovery_verification_task_tenant_episode", ["tenant_id", "verification_episode_id", "verification_requirement_id", "task_id"])


def _create_attempt_result_tables(dialect: str) -> None:
    op.create_table(
        "discovery_verification_attempts",
        sa.Column("attempt_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("episode_id", sa.String(36), nullable=False),
        sa.Column("task_id", sa.String(36), nullable=False),
        sa.Column("attempt_sequence", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(255), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=True),
        sa.Column("collector_integrity_ref", sa.String(255), nullable=True),
        sa.Column("execution_state", sa.String(32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("output_digest", sa.String(64), nullable=True),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_adv_attempt_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_attempt_tenant_episode", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "task_id"], ["discovery_verification_tasks.tenant_id", "discovery_verification_tasks.task_id"], name="fk_adv_attempt_tenant_task", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("attempt_id"),
        sa.UniqueConstraint("tenant_id", "attempt_id", name="uq_adv_attempt_tenant_id"),
        sa.UniqueConstraint("tenant_id", "task_id", "attempt_sequence", name="uq_adv_attempt_tenant_sequence"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_attempt_tenant_idempotency"),
        sa.CheckConstraint("attempt_sequence >= 1", name="ck_adv_attempt_sequence"),
        sa.CheckConstraint("execution_state IN ('completed','transport_failed','expired','cancelled')", name="ck_adv_attempt_state"),
        sa.CheckConstraint("completed_at IS NULL OR started_at <= completed_at", name="ck_adv_attempt_time_order"),
        sa.CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_adv_attempt_latency"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_adv_attempt_digest"),
        sa.CheckConstraint("output_digest IS NULL OR (" + _hash_check("output_digest", dialect) + ")", name="ck_adv_attempt_output_digest"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_adv_attempt_limitations_bytes"),
    )
    op.create_index("idx_adv_attempt_tenant_task", "discovery_verification_attempts", ["tenant_id", "task_id", "attempt_sequence", "attempt_id"])
    op.create_index("idx_adv_attempt_tenant_episode", "discovery_verification_attempts", ["tenant_id", "episode_id", "execution_state", "attempt_id"])

    op.create_table(
        "discovery_verification_results",
        sa.Column("result_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("episode_id", sa.String(36), nullable=False),
        sa.Column("requirement_record_id", sa.String(36), nullable=False),
        sa.Column("task_id", sa.String(36), nullable=True),
        sa.Column("attempt_id", sa.String(36), nullable=True),
        sa.Column("predecessor_result_id", sa.String(36), nullable=True),
        sa.Column("result_sequence", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("evidence_node_ids_json", sa.JSON(), nullable=False),
        sa.Column("source_identity", sa.String(255), nullable=False),
        sa.Column("collector_id", sa.String(128), nullable=True),
        sa.Column("integrity_state", sa.String(32), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("satisfies_requirement", sa.Boolean(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_adv_result_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_result_tenant_episode", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "requirement_record_id"], ["discovery_verification_policy_requirements.tenant_id", "discovery_verification_policy_requirements.requirement_record_id"], name="fk_adv_result_tenant_requirement", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "task_id"], ["discovery_verification_tasks.tenant_id", "discovery_verification_tasks.task_id"], name="fk_adv_result_tenant_task", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "attempt_id"], ["discovery_verification_attempts.tenant_id", "discovery_verification_attempts.attempt_id"], name="fk_adv_result_tenant_attempt", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "predecessor_result_id"], ["discovery_verification_results.tenant_id", "discovery_verification_results.result_id"], name="fk_adv_result_tenant_predecessor", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("result_id"),
        sa.UniqueConstraint("tenant_id", "result_id", name="uq_adv_result_tenant_id"),
        sa.UniqueConstraint("tenant_id", "requirement_record_id", "result_sequence", name="uq_adv_result_tenant_sequence"),
        sa.UniqueConstraint("tenant_id", "predecessor_result_id", name="uq_adv_result_tenant_predecessor"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_result_tenant_idempotency"),
        sa.CheckConstraint("outcome IN ('verified','failed','contradicted','unsupported','unknown')", name="ck_adv_result_outcome"),
        sa.CheckConstraint("integrity_state IN ('verified','unverified','failed','unknown')", name="ck_adv_result_integrity"),
        sa.CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_adv_result_freshness"),
        sa.CheckConstraint("result_sequence >= 1", name="ck_adv_result_sequence"),
        sa.CheckConstraint("observed_at <= validated_at AND validated_at <= expires_at", name="ck_adv_result_time_order"),
        sa.CheckConstraint("(predecessor_result_id IS NULL AND result_sequence = 1) OR predecessor_result_id IS NOT NULL", name="ck_adv_result_predecessor_shape"),
        sa.CheckConstraint("outcome NOT IN ('verified','contradicted') OR length(CAST(evidence_node_ids_json AS TEXT)) > 2", name="ck_adv_result_evidence_required"),
        sa.CheckConstraint("(outcome = 'verified' AND satisfies_requirement = true) OR (outcome <> 'verified' AND satisfies_requirement = false)", name="ck_adv_result_satisfaction"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_adv_result_digest"),
        sa.CheckConstraint(_json_limit("evidence_node_ids_json", 8192, dialect), name="ck_adv_result_evidence_bytes"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_adv_result_limitations_bytes"),
    )
    op.create_index("idx_adv_result_tenant_episode", "discovery_verification_results", ["tenant_id", "episode_id", "outcome", "result_id"])
    op.create_index("idx_adv_result_tenant_requirement", "discovery_verification_results", ["tenant_id", "requirement_record_id", "result_sequence", "result_id"])


def _create_assertion_event_tables(dialect: str) -> None:
    op.create_table(
        "discovery_verification_assertions",
        sa.Column("assertion_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_record_id", sa.String(36), nullable=False),
        sa.Column("episode_id", sa.String(36), nullable=False),
        sa.Column("erg_evaluation_id", sa.String(36), nullable=False),
        sa.Column("policy_record_id", sa.String(36), nullable=False),
        sa.Column("predecessor_assertion_id", sa.String(36), nullable=True),
        sa.Column("assertion_sequence", sa.Integer(), nullable=False),
        sa.Column("conclusion", sa.String(32), nullable=False),
        sa.Column("required_requirement_count", sa.Integer(), nullable=False),
        sa.Column("required_verified_count", sa.Integer(), nullable=False),
        sa.Column("optional_requirement_count", sa.Integer(), nullable=False),
        sa.Column("optional_verified_count", sa.Integer(), nullable=False),
        sa.Column("source_diversity", sa.Integer(), nullable=False),
        sa.Column("evidence_quality", sa.Float(), nullable=True),
        sa.Column("verification_quality", sa.Float(), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("invalidated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("methodology_version", sa.String(32), nullable=False),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("contradictions_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_adv_assertion_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_adv_assertion_tenant_ecosystem", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_assertion_tenant_episode", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "erg_evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_adv_assertion_tenant_evaluation", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "policy_record_id"], ["discovery_verification_policies.tenant_id", "discovery_verification_policies.policy_record_id"], name="fk_adv_assertion_tenant_policy", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "predecessor_assertion_id"], ["discovery_verification_assertions.tenant_id", "discovery_verification_assertions.assertion_id"], name="fk_adv_assertion_tenant_predecessor", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("assertion_id"),
        sa.UniqueConstraint("tenant_id", "assertion_id", name="uq_adv_assertion_tenant_id"),
        sa.UniqueConstraint("tenant_id", "ecosystem_id", "assertion_sequence", name="uq_adv_assertion_tenant_sequence"),
        sa.UniqueConstraint("tenant_id", "predecessor_assertion_id", name="uq_adv_assertion_tenant_predecessor"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_assertion_tenant_idempotency"),
        sa.CheckConstraint("conclusion IN ('verified','incomplete','contradicted','expired')", name="ck_adv_assertion_conclusion"),
        sa.CheckConstraint("assertion_sequence >= 1", name="ck_adv_assertion_sequence"),
        sa.CheckConstraint("required_requirement_count >= 0 AND required_verified_count >= 0 AND required_verified_count <= required_requirement_count", name="ck_adv_assertion_required_coverage"),
        sa.CheckConstraint("optional_requirement_count >= 0 AND optional_verified_count >= 0 AND optional_verified_count <= optional_requirement_count", name="ck_adv_assertion_optional_coverage"),
        sa.CheckConstraint("conclusion <> 'verified' OR (required_requirement_count > 0 AND required_verified_count = required_requirement_count)", name="ck_adv_assertion_verified_complete"),
        sa.CheckConstraint("source_diversity BETWEEN 0 AND 64", name="ck_adv_assertion_diversity"),
        sa.CheckConstraint("evidence_quality IS NULL OR (evidence_quality >= 0.0 AND evidence_quality <= 1.0)", name="ck_adv_assertion_evidence_quality"),
        sa.CheckConstraint("verification_quality IS NULL OR (verification_quality >= 0.0 AND verification_quality <= 1.0)", name="ck_adv_assertion_verification_quality"),
        sa.CheckConstraint("issued_at <= valid_from AND valid_from < valid_until", name="ck_adv_assertion_time_order"),
        sa.CheckConstraint("invalidated_at IS NULL OR valid_from <= invalidated_at", name="ck_adv_assertion_invalidation_time"),
        sa.CheckConstraint("(predecessor_assertion_id IS NULL AND assertion_sequence = 1) OR predecessor_assertion_id IS NOT NULL", name="ck_adv_assertion_predecessor_shape"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_adv_assertion_digest"),
        sa.CheckConstraint(_json_limit("limitations_json", 8192, dialect), name="ck_adv_assertion_limitations_bytes"),
        sa.CheckConstraint(_json_limit("contradictions_json", 16384, dialect), name="ck_adv_assertion_contradictions_bytes"),
    )
    op.create_index("idx_adv_assertion_tenant_ecosystem", "discovery_verification_assertions", ["tenant_id", "ecosystem_id", "assertion_sequence", "assertion_id"])
    op.create_index("idx_adv_assertion_tenant_validity", "discovery_verification_assertions", ["tenant_id", "conclusion", "valid_until", "assertion_id"])

    op.create_table(
        "discovery_verification_events",
        sa.Column("event_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_id", sa.String(36), nullable=False),
        sa.Column("ecosystem_record_id", sa.String(36), nullable=False),
        sa.Column("episode_id", sa.String(36), nullable=True),
        sa.Column("assertion_id", sa.String(36), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("evidence_node_ids_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("before_json", sa.JSON(), server_default=_json_default("{}", dialect), nullable=False),
        sa.Column("after_json", sa.JSON(), server_default=_json_default("{}", dialect), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_adv_event_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_adv_event_tenant_ecosystem", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_adv_event_tenant_episode", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "assertion_id"], ["discovery_verification_assertions.tenant_id", "discovery_verification_assertions.assertion_id"], name="fk_adv_event_tenant_assertion", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint("tenant_id", "event_id", name="uq_adv_event_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_adv_event_tenant_idempotency"),
        sa.CheckConstraint("event_type IN ('verification_started','verification_passed','verification_failed','verification_expired','verification_contradicted','verification_updated','confidence_changed','evidence_added','evidence_removed')", name="ck_adv_event_type"),
        sa.CheckConstraint("actor_type IN ('system','collector','operator','admin')", name="ck_adv_event_actor_type"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_adv_event_digest"),
        sa.CheckConstraint(_json_limit("evidence_node_ids_json", 8192, dialect), name="ck_adv_event_evidence_bytes"),
        sa.CheckConstraint(_json_limit("before_json", 16384, dialect), name="ck_adv_event_before_bytes"),
        sa.CheckConstraint(_json_limit("after_json", 16384, dialect), name="ck_adv_event_after_bytes"),
    )
    op.create_index("idx_adv_event_tenant_ecosystem", "discovery_verification_events", ["tenant_id", "ecosystem_id", "occurred_at", "event_id"])
    op.create_index("idx_adv_event_tenant_type", "discovery_verification_events", ["tenant_id", "event_type", "occurred_at", "event_id"])


def _install_immutable_guards(dialect: str) -> None:
    if dialect == "sqlite":
        for table in IMMUTABLE_TABLES:
            short = table.removeprefix("discovery_verification_")
            for action in ("update", "delete"):
                op.execute(
                    f"CREATE TRIGGER trg_adv_{short}_immutable_{action} "
                    f"BEFORE {action.upper()} ON {table} BEGIN "
                    "SELECT RAISE(ABORT, 'ADV evidence is append-only'); END"
                )
        return
    op.execute(
        "CREATE FUNCTION hawk_reject_adv_mutation() RETURNS trigger AS $$ "
        "BEGIN RAISE EXCEPTION 'ADV evidence is append-only'; END; "
        "$$ LANGUAGE plpgsql"
    )
    for table in IMMUTABLE_TABLES:
        short = table.removeprefix("discovery_verification_")
        op.execute(
            f"CREATE TRIGGER trg_adv_{short}_immutable BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION hawk_reject_adv_mutation()"
        )


def _install_predecessor_guards(dialect: str) -> None:
    guards = (
        (
            "policy", "discovery_verification_policies",
            "predecessor_policy_record_id", "policy_record_id",
            "policy_id", "version",
        ),
        (
            "episode", "discovery_verification_episodes",
            "predecessor_episode_id", "episode_id",
            "ecosystem_id", "episode_sequence",
        ),
        (
            "result", "discovery_verification_results",
            "predecessor_result_id", "result_id",
            "requirement_record_id", "result_sequence",
        ),
        (
            "assertion", "discovery_verification_assertions",
            "predecessor_assertion_id", "assertion_id",
            "ecosystem_id", "assertion_sequence",
        ),
    )
    if dialect == "sqlite":
        for short, table, predecessor, primary, subject, sequence in guards:
            op.execute(
                f"CREATE TRIGGER trg_adv_{short}_predecessor_sequence "
                f"BEFORE INSERT ON {table} "
                f"WHEN NEW.{predecessor} IS NOT NULL BEGIN "
                "SELECT CASE WHEN NOT EXISTS ("
                f"SELECT 1 FROM {table} prior "
                f"WHERE prior.tenant_id = NEW.tenant_id "
                f"AND prior.{primary} = NEW.{predecessor} "
                f"AND prior.{subject} = NEW.{subject} "
                f"AND prior.{sequence} + 1 = NEW.{sequence}"
                ") THEN RAISE(ABORT, 'ADV predecessor sequence is invalid') END; END"
            )
        return
    for short, table, predecessor, primary, subject, sequence in guards:
        function = f"hawk_validate_adv_{short}_predecessor"
        op.execute(
            f"CREATE FUNCTION {function}() RETURNS trigger AS $$ "
            "BEGIN "
            f"IF NEW.{predecessor} IS NOT NULL AND NOT EXISTS ("
            f"SELECT 1 FROM {table} prior "
            f"WHERE prior.tenant_id = NEW.tenant_id "
            f"AND prior.{primary} = NEW.{predecessor} "
            f"AND prior.{subject} = NEW.{subject} "
            f"AND prior.{sequence} + 1 = NEW.{sequence}"
            ") THEN RAISE EXCEPTION 'ADV predecessor sequence is invalid'; END IF; "
            "RETURN NEW; END; $$ LANGUAGE plpgsql"
        )
        op.execute(
            f"CREATE TRIGGER trg_adv_{short}_predecessor_sequence "
            f"BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {function}()"
        )


def upgrade() -> None:
    dialect = _dialect()
    _create_policy_tables(dialect)
    _create_episode_table(dialect)
    _extend_verification_tasks()
    _create_attempt_result_tables(dialect)
    _create_assertion_event_tables(dialect)
    _install_predecessor_guards(dialect)
    _install_immutable_guards(dialect)


def downgrade() -> None:
    dialect = _dialect()
    for table in (
        "discovery_verification_events",
        "discovery_verification_assertions",
        "discovery_verification_results",
        "discovery_verification_attempts",
    ):
        op.drop_table(table)
    with op.batch_alter_table("discovery_verification_tasks", recreate="always") as batch:
        batch.drop_index("idx_discovery_verification_task_tenant_episode")
        batch.drop_constraint("fk_discovery_verification_task_tenant_requirement", type_="foreignkey")
        batch.drop_constraint("fk_discovery_verification_task_tenant_episode", type_="foreignkey")
        batch.drop_column("task_contract_version")
        batch.drop_column("verification_requirement_id")
        batch.drop_column("verification_episode_id")
    for table in (
        "discovery_verification_episodes",
        "discovery_verification_policy_requirements",
        "discovery_verification_policies",
    ):
        op.drop_table(table)
    if dialect == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS hawk_reject_adv_mutation()")
        for short in ("policy", "episode", "result", "assertion"):
            op.execute(f"DROP FUNCTION IF EXISTS hawk_validate_adv_{short}_predecessor()")
