"""Add Hawk AI Account Boundary primitives.

Revision ID: 0074_ai_account_boundary
Revises: 0073_external_capability_integrity
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0074_ai_account_boundary"
down_revision = "0073_external_capability_integrity"
branch_labels = None
depends_on = None


def _json_default(value: str) -> sa.TextClause:
    return sa.text(f"'{value}'")


ACCOUNT_CLASSES = (
    "ENTERPRISE_MANAGED",
    "ENTERPRISE_MEMBER_PERSONAL_IDENTITY",
    "ENTERPRISE_MANAGED_USER",
    "ENTERPRISE_SERVICE_IDENTITY",
    "PARTNER_ENTERPRISE",
    "EXTERNAL_ENTERPRISE",
    "PERSONAL_FREE",
    "PERSONAL_PAID",
    "PERSONAL_DEVELOPER",
    "ANONYMOUS",
    "UNKNOWN",
)

SESSION_STATES = (
    "VERIFYING",
    "ENTERPRISE_VERIFIED",
    "PARTNER_VERIFIED",
    "PERSONAL_DETECTED",
    "ANONYMOUS_DETECTED",
    "EXTERNAL_UNAPPROVED",
    "UNKNOWN",
    "EXPIRED",
    "REVOKED",
    "DRIFTED",
    "BYPASS_SUSPECTED",
)

ACCOUNT_ACCESS_DECISIONS = (
    "ALLOW_ENTERPRISE",
    "ALLOW_PARTNER",
    "ALLOW_RESTRICTED",
    "REQUIRE_ENTERPRISE_LOGIN",
    "REQUIRE_MANAGED_PROFILE",
    "REQUIRE_REAUTHENTICATION",
    "BLOCK_PERSONAL",
    "BLOCK_ANONYMOUS",
    "BLOCK_EXTERNAL_TENANT",
    "BLOCK_UNKNOWN",
    "BLOCK_ROUTE_BYPASS",
    "MONITOR_ONLY",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


def upgrade() -> None:
    op.create_table(
        "provider_account_capability_manifests",
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("manifest_version", sa.String(32), nullable=False),
        sa.Column("provider_tier", sa.String(32), nullable=False, server_default="tier_3"),
        sa.Column("supported_surfaces", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("capabilities", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("limitations", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("verification_status", sa.String(32), nullable=False, server_default="UNVERIFIED"),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider", "product", "manifest_version", name="uq_account_manifest_provider_product_version"),
    )
    op.create_index("idx_account_manifest_provider", "provider_account_capability_manifests", ["provider", "product"])

    op.create_table(
        "ai_auth_transactions",
        sa.Column("auth_transaction_id", sa.String(96), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("user_identity_ref", sa.String(255), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("device_trust_ref", sa.String(255), nullable=True),
        sa.Column("application_asset_id", sa.String(255), nullable=True),
        sa.Column("application_family", sa.String(128), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("surface", sa.String(64), nullable=False),
        sa.Column("initiating_process_instance", sa.String(255), nullable=True),
        sa.Column("initiating_browser_profile", sa.String(255), nullable=True),
        sa.Column("initiating_tab_or_navigation_id", sa.String(255), nullable=True),
        sa.Column("initiating_extension_id", sa.String(255), nullable=True),
        sa.Column("terminal_session_id", sa.String(255), nullable=True),
        sa.Column("auth_protocol", sa.String(32), nullable=False),
        sa.Column("auth_method", sa.String(64), nullable=True),
        sa.Column("expected_issuer", sa.String(512), nullable=True),
        sa.Column("expected_client_id", sa.String(255), nullable=True),
        sa.Column("expected_redirect_uri", sa.String(512), nullable=True),
        sa.Column("expected_saml_entity_id", sa.String(512), nullable=True),
        sa.Column("expected_acs_url", sa.String(512), nullable=True),
        sa.Column("state_hash", sa.String(64), nullable=True),
        sa.Column("nonce_hash", sa.String(64), nullable=True),
        sa.Column("pkce_challenge_hash", sa.String(64), nullable=True),
        sa.Column("relay_state_hash", sa.String(64), nullable=True),
        sa.Column("device_code_hash", sa.String(64), nullable=True),
        sa.Column("intended_enterprise_org_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("intended_workspace_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("intended_tenant_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("intended_subscription_class", sa.String(128), nullable=True),
        sa.Column("policy_id", sa.String(128), nullable=True),
        sa.Column("policy_version", sa.String(64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current_state", sa.String(32), nullable=False, server_default="STARTED"),
        sa.Column("correlation_confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("safe_event_log", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("auth_transaction_id", name="uq_ai_auth_transaction_id"),
    )
    op.create_index("idx_ai_auth_transaction_tenant_state", "ai_auth_transactions", ["tenant_id", "current_state"])
    op.create_index(
        "idx_ai_auth_transaction_tenant_provider",
        "ai_auth_transactions",
        ["tenant_id", "provider", "product", "surface"],
    )

    op.create_table(
        "ai_account_identities",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("provider_subject_ref", sa.String(255), nullable=False),
        sa.Column("email_hash", sa.String(64), nullable=True),
        sa.Column("email_domain", sa.String(255), nullable=True),
        sa.Column("account_class", sa.String(64), nullable=False, server_default="UNKNOWN"),
        sa.Column("organisation_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("workspace_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("tenant_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("subscription_class", sa.String(128), nullable=True),
        sa.Column("enterprise_membership", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("role_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("licence_state", sa.String(64), nullable=True),
        sa.Column("verification_method", sa.String(128), nullable=False, server_default="unknown"),
        sa.Column("verification_status", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"account_class IN ({_quoted(ACCOUNT_CLASSES)})", name="ck_ai_account_identity_class"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "provider", "provider_subject_ref", name="uq_ai_account_identity_subject"),
    )
    op.create_index("idx_ai_account_identity_tenant_provider", "ai_account_identities", ["tenant_id", "provider", "account_class"])

    op.create_table(
        "ai_account_sessions",
        sa.Column("account_session_id", sa.String(96), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("surface", sa.String(64), nullable=False),
        sa.Column("user_identity_ref", sa.String(255), nullable=False),
        sa.Column("account_identity_ref", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("process_instance", sa.String(255), nullable=True),
        sa.Column("browser_profile", sa.String(255), nullable=True),
        sa.Column("tab_or_app_session", sa.String(255), nullable=True),
        sa.Column("organisation_id", sa.String(255), nullable=True),
        sa.Column("workspace_id", sa.String(255), nullable=True),
        sa.Column("tenant_id_external", sa.String(255), nullable=True),
        sa.Column("subscription_class", sa.String(128), nullable=True),
        sa.Column("created_from_auth_transaction", sa.String(96), nullable=True),
        sa.Column("assurance_level", sa.String(16), nullable=False, server_default="AB0"),
        sa.Column("verification_method", sa.String(128), nullable=False, server_default="unknown"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=True),
        sa.Column("session_state", sa.String(32), nullable=False, server_default="VERIFYING"),
        sa.Column("drift_state", sa.String(32), nullable=False, server_default="NONE"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"session_state IN ({_quoted(SESSION_STATES)})", name="ck_ai_account_session_state"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["account_identity_ref"], ["ai_account_identities.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_session_id", name="uq_ai_account_session_id"),
    )
    op.create_index("idx_ai_account_session_tenant_state", "ai_account_sessions", ["tenant_id", "session_state"])
    op.create_index(
        "idx_ai_account_session_tenant_provider",
        "ai_account_sessions",
        ["tenant_id", "provider", "product", "surface"],
    )

    op.create_table(
        "ai_account_session_permits",
        sa.Column("permit_id", sa.String(96), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("account_session_ref", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("surface", sa.String(64), nullable=False),
        sa.Column("user_identity_ref", sa.String(255), nullable=False),
        sa.Column("account_identity_ref", sa.String(36), nullable=False),
        sa.Column("process_instance", sa.String(255), nullable=True),
        sa.Column("browser_profile", sa.String(255), nullable=True),
        sa.Column("workspace_or_org_binding", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("allowed_destination_scope", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("allowed_data_classes", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("allowed_business_purposes", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("signing_key_id", sa.String(128), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("consumed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["account_session_ref"], ["ai_account_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "permit_id", name="uq_ai_account_session_permit"),
    )
    op.create_index("idx_ai_account_permit_tenant_session", "ai_account_session_permits", ["tenant_id", "account_session_ref"])

    op.create_table(
        "account_access_receipts",
        sa.Column("receipt_id", sa.String(96), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("device", sa.String(255), nullable=False),
        sa.Column("application", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("surface", sa.String(64), nullable=False),
        sa.Column("auth_transaction_id", sa.String(96), nullable=True),
        sa.Column("account_class", sa.String(64), nullable=False),
        sa.Column("organisation_or_workspace", sa.String(255), nullable=True),
        sa.Column("verification_method", sa.String(128), nullable=False),
        sa.Column("assurance_level", sa.String(16), nullable=False),
        sa.Column("decision", sa.String(64), nullable=False),
        sa.Column("control_point", sa.String(64), nullable=False),
        sa.Column("policy_id", sa.String(128), nullable=True),
        sa.Column("policy_version", sa.String(64), nullable=True),
        sa.Column("managed_route_state", sa.String(64), nullable=False, server_default="UNKNOWN"),
        sa.Column("session_permit_id", sa.String(96), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("blind_spots", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("safe_payload", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"decision IN ({_quoted(ACCOUNT_ACCESS_DECISIONS)})", name="ck_account_access_receipt_decision"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_id", name="uq_account_access_receipt_id"),
    )
    op.create_index("idx_account_access_receipt_tenant_decision", "account_access_receipts", ["tenant_id", "decision"])

    op.create_table(
        "account_boundary_integrations",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("surfaces", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("approved_organisation_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("approved_workspace_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("approved_tenant_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("partner_tenant_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("mode", sa.String(32), nullable=False, server_default="monitor"),
        sa.Column("health", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("capability_manifest_ref", sa.String(36), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_account_boundary_integration_tenant_provider",
        "account_boundary_integrations",
        ["tenant_id", "provider", "product"],
    )

    op.create_table(
        "account_boundary_validations",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("integration_id", sa.String(36), nullable=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("surface", sa.String(64), nullable=False),
        sa.Column("validation_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("limitations", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("measured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["integration_id"], ["account_boundary_integrations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_account_boundary_validation_integration",
        "account_boundary_validations",
        ["tenant_id", "integration_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("idx_account_boundary_validation_integration", table_name="account_boundary_validations")
    op.drop_table("account_boundary_validations")
    op.drop_index("idx_account_boundary_integration_tenant_provider", table_name="account_boundary_integrations")
    op.drop_table("account_boundary_integrations")
    op.drop_index("idx_account_access_receipt_tenant_decision", table_name="account_access_receipts")
    op.drop_table("account_access_receipts")
    op.drop_index("idx_ai_account_permit_tenant_session", table_name="ai_account_session_permits")
    op.drop_table("ai_account_session_permits")
    op.drop_index("idx_ai_account_session_tenant_provider", table_name="ai_account_sessions")
    op.drop_index("idx_ai_account_session_tenant_state", table_name="ai_account_sessions")
    op.drop_table("ai_account_sessions")
    op.drop_index("idx_ai_account_identity_tenant_provider", table_name="ai_account_identities")
    op.drop_table("ai_account_identities")
    op.drop_index("idx_ai_auth_transaction_tenant_provider", table_name="ai_auth_transactions")
    op.drop_index("idx_ai_auth_transaction_tenant_state", table_name="ai_auth_transactions")
    op.drop_table("ai_auth_transactions")
    op.drop_index("idx_account_manifest_provider", table_name="provider_account_capability_manifests")
    op.drop_table("provider_account_capability_manifests")
