"""Tenant-scoped, metadata-only GitHub repository relationship projection."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class GitHubSourceOrganization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "github_source_organizations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "host", "external_organization_id", name="uq_github_source_org_identity"),
        Index("idx_github_source_org_tenant_host", "tenant_id", "host"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    connection_id: Mapped[Optional[str]] = mapped_column(ForeignKey("connectors.id", ondelete="SET NULL"), nullable=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    external_organization_id: Mapped[str] = mapped_column(String(255), nullable=False)
    login: Mapped[str] = mapped_column(String(255), nullable=False)
    installation_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    capabilities_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    selected_repository_scope: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    sync_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    last_complete_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    limitations_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class GitHubRepository(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "github_repositories"
    __table_args__ = (
        UniqueConstraint("tenant_id", "host", "source_organization_id", "external_repository_id", name="uq_github_repository_identity"),
        Index("idx_github_repository_tenant_org", "tenant_id", "source_organization_id"),
        Index("idx_github_repository_tenant_last_seen", "tenant_id", "last_seen_at"),
        Index("idx_github_repository_tenant_evidence", "tenant_id", "evidence_state"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_organization_id: Mapped[str] = mapped_column(ForeignKey("github_source_organizations.id", ondelete="CASCADE"), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    external_repository_id: Mapped[str] = mapped_column(String(255), nullable=False)
    node_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    full_name: Mapped[str] = mapped_column(String(512), nullable=False)
    visibility: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    default_branch: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    protection_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evidence_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    governance_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    approved_scope_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    policy_mapping_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    policy_current: Mapped[bool] = mapped_column(nullable=False, default=False)
    read_posture: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    governance_version: Mapped[int] = mapped_column(nullable=False, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    operation_controls_json: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=lambda: {"READ": "BLOCK", "EDIT": "BLOCK", "COMMIT": "BLOCK", "PULL": "BLOCK", "PUSH": "BLOCK"},
    )
    # Owner/admin-set AI agent write posture (write mode, extra protected
    # branches/paths, change-size and rate limits). Empty means the safe
    # defaults in github_repository_access_service: every write needs a bound
    # approval. Discovery never writes this column.
    agent_policy_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class GitHubRepositoryAccess(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "github_repository_access"
    __table_args__ = (
        UniqueConstraint("tenant_id", "repository_id", "external_principal_id", "access_path", name="uq_github_repository_access_path"),
        Index("idx_github_repo_access_tenant_repository", "tenant_id", "repository_id"),
        Index("idx_github_repo_access_tenant_principal", "tenant_id", "external_principal_id"),
        Index("idx_github_repo_access_tenant_user", "tenant_id", "mapped_user_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    repository_id: Mapped[str] = mapped_column(ForeignKey("github_repositories.id", ondelete="CASCADE"), nullable=False)
    external_principal_id: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(32), nullable=False)
    access_path: Mapped[str] = mapped_column(String(32), nullable=False)
    permission: Mapped[str] = mapped_column(String(32), nullable=False)
    source_team_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mapped_user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    mapped_group_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    evidence_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class GitHubRepositoryAIConnection(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "github_repository_ai_connections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "repository_id", "ai_system_id", "agent_id", "external_capability_id", "source_surface", name="uq_github_repository_ai_connection"),
        Index("idx_github_repo_ai_tenant_repository", "tenant_id", "repository_id"),
        Index("idx_github_repo_ai_tenant_user", "tenant_id", "user_id"),
        Index("idx_github_repo_ai_tenant_agent", "tenant_id", "agent_id"),
        Index("idx_github_repo_ai_tenant_model", "tenant_id", "model"),
        Index("idx_github_repo_ai_tenant_last_seen", "tenant_id", "last_seen_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    repository_id: Mapped[str] = mapped_column(ForeignKey("github_repositories.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    ai_asset_id: Mapped[Optional[str]] = mapped_column(ForeignKey("discovery_ai_assets.asset_id", ondelete="SET NULL"), nullable=True)
    provider: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    client_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mcp_server_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    external_capability_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tool_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tool_schema_fingerprint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    relationship_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    source_surface: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    action_count: Mapped[int] = mapped_column(nullable=False, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class GitHubRepositoryRuntimeBinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Admin-bound local workspace identity for one signed native integration."""

    __tablename__ = "github_repository_runtime_bindings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "native_integration_id", "canonical_root_sha256", "common_dir_sha256", name="uq_github_repo_runtime_binding"),
        CheckConstraint("scope = 'EXACT_FOLDER'", name="ck_github_repo_runtime_scope"),
        CheckConstraint("state IN ('OBSERVED','ACTIVE','REVOKED')", name="ck_github_repo_runtime_state"),
        CheckConstraint("(state = 'OBSERVED' AND repository_id IS NULL) OR (state IN ('ACTIVE','REVOKED') AND repository_id IS NOT NULL)", name="ck_github_repo_runtime_repository_state"),
        Index("idx_github_repo_runtime_tenant_state", "tenant_id", "state"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    repository_id: Mapped[Optional[str]] = mapped_column(ForeignKey("github_repositories.id", ondelete="CASCADE"), nullable=True)
    native_integration_id: Mapped[str] = mapped_column(ForeignKey("native_control_integrations.id", ondelete="CASCADE"), nullable=False)
    canonical_root_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    common_dir_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="EXACT_FOLDER")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="OBSERVED")
    signed_evidence_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)


class GitHubRepositoryMutationApproval(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One approved, MAC-bound, expiring and single-use AI agent repository mutation.

    ``action_mac`` is an HMAC (CANONICAL_ACTION_BINDING_KEY, tenant and purpose
    separated) over the exact canonical action the approver saw: repository,
    host, action, branch, actor, executing principal, AI system, provider,
    model, tool fingerprints, target, change digests, governance version,
    nonce and expiry. The fields are not stored here; the verifier recomputes
    the MAC from the live request, so a row edited in the database cannot widen
    what it authorizes.
    """

    __tablename__ = "github_repository_mutation_approvals"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "approval_request_id"], ["approval_requests.tenant_id", "approval_requests.id"], name="fk_github_repo_mutation_approval_request", ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "approval_request_id", name="uq_github_repo_mutation_approval_request"),
        UniqueConstraint("tenant_id", "nonce", name="uq_github_repo_mutation_approval_nonce"),
        CheckConstraint("state IN ('ACTIVE','CONSUMED','REVOKED')", name="ck_github_repo_mutation_approval_state"),
        CheckConstraint("use_limit = 1", name="ck_github_repo_mutation_approval_single_use"),
        CheckConstraint("uses_consumed >= 0 AND uses_consumed <= use_limit", name="ck_github_repo_mutation_approval_uses"),
        Index("idx_github_repo_mutation_approval_repository", "tenant_id", "repository_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    approval_request_id: Mapped[str] = mapped_column(String(36), nullable=False)
    repository_id: Mapped[str] = mapped_column(ForeignKey("github_repositories.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    action_mac: Mapped[str] = mapped_column(String(64), nullable=False)
    mac_version: Mapped[str] = mapped_column(String(16), nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    governance_version: Mapped[int] = mapped_column(nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    use_limit: Mapped[int] = mapped_column(nullable=False, default=1)
    uses_consumed: Mapped[int] = mapped_column(nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    issued_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


__all__ = [
    "GitHubRepository",
    "GitHubRepositoryMutationApproval",
    "GitHubRepositoryAIConnection",
    "GitHubRepositoryAccess",
    "GitHubRepositoryRuntimeBinding",
    "GitHubSourceOrganization",
]
