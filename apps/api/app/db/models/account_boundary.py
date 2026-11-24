from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


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


class ProviderAccountCapabilityManifest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "provider_account_capability_manifests"
    __table_args__ = (
        UniqueConstraint("provider", "product", "manifest_version", name="uq_account_manifest_provider_product_version"),
        Index("idx_account_manifest_provider", "provider", "product"),
    )

    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    manifest_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0")
    provider_tier: Mapped[str] = mapped_column(String(32), nullable=False, default="tier_3")
    supported_surfaces: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    capabilities: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNVERIFIED")


class AIAuthTransaction(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_auth_transactions"
    __table_args__ = (
        Index("idx_ai_auth_transaction_tenant_state", "tenant_id", "current_state"),
        Index("idx_ai_auth_transaction_tenant_provider", "tenant_id", "provider", "product", "surface"),
    )

    auth_transaction_id: Mapped[str] = mapped_column(String(96), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_identity_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    device_trust_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    application_asset_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    application_family: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    surface: Mapped[str] = mapped_column(String(64), nullable=False)
    initiating_process_instance: Mapped[str | None] = mapped_column(String(255), nullable=True)
    initiating_browser_profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    initiating_tab_or_navigation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    initiating_extension_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    terminal_session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    auth_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expected_issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    expected_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expected_redirect_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    expected_saml_entity_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    expected_acs_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    state_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nonce_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pkce_challenge_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    relay_state_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    intended_enterprise_org_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    intended_workspace_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    intended_tenant_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    intended_subscription_class: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    current_state: Mapped[str] = mapped_column(String(32), nullable=False, default="STARTED")
    correlation_confidence: Mapped[float] = mapped_column(nullable=False, default=0.0)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    safe_event_log: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=list)


class AIAccountIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_account_identities"
    __table_args__ = (
        CheckConstraint(f"account_class IN ({_quoted(ACCOUNT_CLASSES)})", name="ck_ai_account_identity_class"),
        Index("idx_ai_account_identity_tenant_provider", "tenant_id", "provider", "account_class"),
        UniqueConstraint("tenant_id", "provider", "provider_subject_ref", name="uq_ai_account_identity_subject"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_subject_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    email_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    email_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    account_class: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
    organisation_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    workspace_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tenant_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    subscription_class: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enterprise_membership: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    role_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    licence_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_method: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class AIAccountSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_account_sessions"
    __table_args__ = (
        CheckConstraint(f"session_state IN ({_quoted(SESSION_STATES)})", name="ck_ai_account_session_state"),
        Index("idx_ai_account_session_tenant_state", "tenant_id", "session_state"),
        Index("idx_ai_account_session_tenant_provider", "tenant_id", "provider", "product", "surface"),
    )

    account_session_id: Mapped[str] = mapped_column(String(96), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    surface: Mapped[str] = mapped_column(String(64), nullable=False)
    user_identity_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    account_identity_ref: Mapped[str] = mapped_column(String(36), ForeignKey("ai_account_identities.id", ondelete="RESTRICT"), nullable=False)
    account_boundary_integration_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("account_boundary_integrations.id", ondelete="RESTRICT"), nullable=True)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    process_instance: Mapped[str | None] = mapped_column(String(255), nullable=True)
    browser_profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tab_or_app_session: Mapped[str | None] = mapped_column(String(255), nullable=True)
    organisation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workspace_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tenant_id_external: Mapped[str | None] = mapped_column(String(255), nullable=True)
    subscription_class: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_from_auth_transaction: Mapped[str | None] = mapped_column(String(96), nullable=True)
    assurance_level: Mapped[str] = mapped_column(String(16), nullable=False, default="AB0")
    verification_method: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_state: Mapped[str] = mapped_column(String(32), nullable=False, default="VERIFYING")
    drift_state: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class AIAccountSessionPermit(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_account_session_permits"
    __table_args__ = (
        Index("idx_ai_account_permit_tenant_session", "tenant_id", "account_session_ref"),
        UniqueConstraint("tenant_id", "permit_id", name="uq_ai_account_session_permit"),
    )

    permit_id: Mapped[str] = mapped_column(String(96), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    account_session_ref: Mapped[str] = mapped_column(String(36), ForeignKey("ai_account_sessions.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    surface: Mapped[str] = mapped_column(String(64), nullable=False)
    user_identity_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    account_identity_ref: Mapped[str] = mapped_column(String(36), nullable=False)
    process_instance: Mapped[str | None] = mapped_column(String(255), nullable=True)
    browser_profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workspace_or_org_binding: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    allowed_destination_scope: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_data_classes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_business_purposes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    signing_algorithm: Mapped[str | None] = mapped_column(String(16), nullable=True)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    consumed_count: Mapped[int] = mapped_column(nullable=False, default=0)
    max_uses: Mapped[int] = mapped_column(nullable=False, default=1)
    consumed_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNCONSUMED")
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AccountAccessReceipt(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "account_access_receipts"
    __table_args__ = (
        CheckConstraint(f"decision IN ({_quoted(ACCOUNT_ACCESS_DECISIONS)})", name="ck_account_access_receipt_decision"),
        Index("idx_account_access_receipt_tenant_decision", "tenant_id", "decision"),
    )

    receipt_id: Mapped[str] = mapped_column(String(96), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    device: Mapped[str] = mapped_column(String(255), nullable=False)
    application: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    surface: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_transaction_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    account_class: Mapped[str] = mapped_column(String(64), nullable=False)
    organisation_or_workspace: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_method: Mapped[str] = mapped_column(String(128), nullable=False)
    assurance_level: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    control_point: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    managed_route_state: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
    session_permit_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    blind_spots: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signing_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signing_algorithm: Mapped[str | None] = mapped_column(String(16), nullable=True)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    safe_payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class AccountBoundaryIntegration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "account_boundary_integrations"
    __table_args__ = (
        Index("idx_account_boundary_integration_tenant_provider", "tenant_id", "provider", "product"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    surfaces: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    approved_organisation_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    approved_workspace_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    approved_tenant_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    partner_tenant_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="monitor")
    health: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False, default="DISCOVER")
    provider_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    route_health: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    capability_manifest_ref: Mapped[str | None] = mapped_column(String(36), nullable=True)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)


class AccountBoundaryValidation(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "account_boundary_validations"
    __table_args__ = (
        Index("idx_account_boundary_validation_integration", "tenant_id", "integration_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    integration_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("account_boundary_integrations.id", ondelete="CASCADE"), nullable=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    surface: Mapped[str] = mapped_column(String(64), nullable=False)
    validation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    route_health: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    provider_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    signing_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signing_algorithm: Mapped[str | None] = mapped_column(String(16), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
