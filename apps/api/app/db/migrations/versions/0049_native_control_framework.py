"""add evidence-backed native control framework

Revision ID: 0049_native_control_framework
Revises: 0048_endpoint_device_identity
"""

from alembic import op
import sqlalchemy as sa


revision = "0049_native_control_framework"
down_revision = "0048_endpoint_device_identity"
branch_labels = None
depends_on = None


def _json_default(value: str) -> sa.TextClause:
    suffix = "::json" if op.get_context().dialect.name == "postgresql" else ""
    return sa.text(f"'{value}'{suffix}")


def upgrade() -> None:
    op.create_table(
        "control_capability_profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("manifest_id", sa.String(length=255), nullable=False),
        sa.Column("manifest_version", sa.String(length=64), nullable=False),
        sa.Column("matrix_version", sa.String(length=96), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("product", sa.String(length=128), nullable=False),
        sa.Column("integration_method", sa.String(length=64), nullable=False),
        sa.Column("adapter_version", sa.String(length=64), nullable=False),
        sa.Column("tested_min_version", sa.String(length=64), nullable=True),
        sa.Column("tested_max_version", sa.String(length=64), nullable=True),
        sa.Column("current_verified_version", sa.String(length=64), nullable=True),
        sa.Column("verification_status", sa.String(length=32), nullable=False),
        sa.Column("verification_source", sa.String(length=512), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("security_properties", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("health_requirements", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("degradation_modes", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("known_blind_spots", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("documentation_references", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("manifest_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "verification_status IN ('verified','experimental','unverified','broken','removed')",
            name="ck_control_profile_verification_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("manifest_id", "manifest_version", name="uq_control_profile_manifest_version"),
    )
    op.create_index("idx_control_profile_provider_product", "control_capability_profiles", ["provider", "product"])
    op.create_index("idx_control_profile_matrix", "control_capability_profiles", ["matrix_version"])

    op.create_table(
        "native_control_integrations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("capability_profile_id", sa.String(length=36), nullable=True),
        sa.Column("deployment_surface_id", sa.String(length=36), nullable=True),
        sa.Column("instance_key", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("product", sa.String(length=128), nullable=False),
        sa.Column("integration_method", sa.String(length=64), nullable=False),
        sa.Column("deployment_family", sa.String(length=32), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="discovered"),
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="discover"),
        sa.Column("health_state", sa.String(length=32), nullable=False, server_default="unverified"),
        sa.Column("health_reasons", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("provider_version", sa.String(length=64), nullable=True),
        sa.Column("adapter_version", sa.String(length=64), nullable=False),
        sa.Column("configuration_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("expected_configuration_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("policy_version", sa.String(length=64), nullable=True),
        sa.Column("policy_fresh_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("degradation_mode", sa.String(length=64), nullable=False, server_default="fail_closed"),
        sa.Column("capability_snapshot", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("known_blind_spots", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("last_health_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "state IN ('discovered','configuring','validating','monitoring','enforcing','degraded','unhealthy','disabled','unsupported')",
            name="ck_native_integration_state",
        ),
        sa.CheckConstraint("mode IN ('discover','monitor','enforce')", name="ck_native_integration_mode"),
        sa.CheckConstraint(
            "health_state IN ('healthy','degraded','unhealthy','unverified','version_mismatch','tampered')",
            name="ck_native_integration_health",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["capability_profile_id"], ["control_capability_profiles.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_native_integration_tenant_id"),
        sa.UniqueConstraint(
            "tenant_id", "provider", "product", "environment", "instance_key",
            name="uq_native_integration_tenant_instance",
        ),
    )
    op.create_index("idx_native_integration_tenant_state", "native_control_integrations", ["tenant_id", "state"])
    op.create_index(
        "idx_native_integration_tenant_provider", "native_control_integrations", ["tenant_id", "provider", "product"]
    )

    op.create_table(
        "native_workload_credentials",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("integration_instance_id", sa.String(length=36), nullable=False),
        sa.Column("credential_id", sa.String(length=128), nullable=False),
        sa.Column("credential_epoch", sa.Integer(), nullable=False),
        sa.Column("public_key_pem", sa.String(length=2048), nullable=False),
        sa.Column("key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=16), nullable=False, server_default="ES256"),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("allowed_event_types", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('active','rotating','revoked','expired')", name="ck_native_credential_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_credential_tenant_integration",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "credential_id", name="uq_native_credential_tenant_id"),
        sa.UniqueConstraint(
            "tenant_id", "integration_instance_id", "credential_epoch",
            name="uq_native_credential_tenant_epoch",
        ),
    )
    op.create_index("idx_native_credential_tenant_status", "native_workload_credentials", ["tenant_id", "status"])

    op.create_table(
        "native_control_validations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("integration_instance_id", sa.String(length=36), nullable=False),
        sa.Column("validation_version", sa.String(length=64), nullable=False),
        sa.Column("credential_id", sa.String(length=128), nullable=False),
        sa.Column("credential_epoch", sa.Integer(), nullable=False),
        sa.Column("safe_synthetic", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("checks", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("result", sa.String(length=16), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("result IN ('passed','failed','partial','unknown')", name="ck_native_validation_result"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_validation_tenant_integration",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_native_validation_tenant_time", "native_control_validations", ["tenant_id", "validated_at"])

    op.create_table(
        "native_control_replays",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("integration_instance_id", sa.String(length=36), nullable=False),
        sa.Column("event_id_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("credential_id", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_replay_tenant_integration",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "integration_instance_id", "event_id_hash", name="uq_native_replay_tenant_event"
        ),
        sa.UniqueConstraint(
            "tenant_id", "integration_instance_id", "nonce_hash", name="uq_native_replay_tenant_nonce"
        ),
    )
    op.create_index("idx_native_replay_tenant_expiry", "native_control_replays", ["tenant_id", "expires_at"])

    op.create_table(
        "native_control_selections",
        sa.Column("selection_id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("primary_control_point_id", sa.String(length=36), nullable=True),
        sa.Column("secondary_observation_points", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("containment_points", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("rejected_candidates", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("selection_reason", sa.String(length=128), nullable=False),
        sa.Column("required_capabilities", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("satisfied_capabilities", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("unsatisfied_capabilities", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("assurance_level", sa.Integer(), nullable=False),
        sa.Column("coverage_implications", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("known_blind_spots", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("selector_version", sa.String(length=64), nullable=False),
        sa.Column("matrix_version", sa.String(length=96), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("control_profile_version", sa.String(length=64), nullable=True),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("selected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("selection_id"),
        sa.UniqueConstraint("tenant_id", "selection_id", name="uq_native_selection_tenant_id"),
    )
    op.create_index(
        "idx_native_selection_tenant_action", "native_control_selections", ["tenant_id", "action_id", "selected_at"]
    )


def downgrade() -> None:
    op.drop_index("idx_native_selection_tenant_action", table_name="native_control_selections")
    op.drop_table("native_control_selections")
    op.drop_index("idx_native_replay_tenant_expiry", table_name="native_control_replays")
    op.drop_table("native_control_replays")
    op.drop_index("idx_native_validation_tenant_time", table_name="native_control_validations")
    op.drop_table("native_control_validations")
    op.drop_index("idx_native_credential_tenant_status", table_name="native_workload_credentials")
    op.drop_table("native_workload_credentials")
    op.drop_index("idx_native_integration_tenant_provider", table_name="native_control_integrations")
    op.drop_index("idx_native_integration_tenant_state", table_name="native_control_integrations")
    op.drop_table("native_control_integrations")
    op.drop_index("idx_control_profile_matrix", table_name="control_capability_profiles")
    op.drop_index("idx_control_profile_provider_product", table_name="control_capability_profiles")
    op.drop_table("control_capability_profiles")
