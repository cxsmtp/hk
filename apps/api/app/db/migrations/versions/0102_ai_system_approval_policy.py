"""AI system approval workflow (app/services/ai_system_approval_service.py):

- ai_system_approval_policies: one row per tenant: for each risk tier, how many distinct people approve, whether the
  requester may approve their own request, which roles approve, and which scopes (blanket, one-time, time-bound) an
  approver may choose. No row means the defaults.
- ai_system_approval_grants: one row per standing approval of an AI system, with its scope, expiry and state.

Upgrade: every AI system that is approved now (its governance state, or failing that its lifecycle state or status,
is approved, active or live, as app/services/governance_resolution.py reads it) gets a blanket grant with origin
"upgrade", so it stays approved, can be seen on Settings → AI system approvals and can be revoked there. Nothing that
was approved stops working.

down_revision is 0101_github_agent_controls.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


revision = "0102_ai_system_approval_policy"
down_revision = "0101_github_agent_controls"
branch_labels = None
depends_on = None

_APPROVED = {"APPROVED", "ACTIVE", "LIVE"}
_NEUTRAL = {"DRAFT", "PENDING", "REVIEW", "PENDING_REVIEW", "PAUSED"}


def _metadata(value: object) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, (str, bytes)) and value:
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}
    return {}


def _approved_now(status: object, metadata: dict) -> bool:
    """app/services/governance_resolution.py's reading of an AI system, as it stood before this revision."""

    governance = str(metadata.get("governance_state") or "").strip().upper()
    lifecycle = str(metadata.get("lifecycle_state") or "").strip().upper()
    compliance = str(metadata.get("compliance_state") or "").strip().upper()
    ownership = str(metadata.get("ownership_state") or "").strip().upper()
    status_value = str(status or "").strip().upper()
    if compliance == "NON_COMPLIANT" or ownership in {"UNKNOWN", "MISSING"}:
        return False
    if governance:
        return governance in _APPROVED
    if lifecycle:
        return lifecycle in _APPROVED
    return bool(status_value) and status_value not in _NEUTRAL and status_value in _APPROVED


def upgrade() -> None:
    op.create_table(
        "ai_system_approval_policies",
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(length=320), nullable=False, server_default=""),
    )
    op.create_table(
        "ai_system_approval_grants",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), sa.ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "approval_request_id",
            sa.String(length=36),
            sa.ForeignKey("approval_requests.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="ACTIVE"),
        sa.Column("risk_tier", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("origin", sa.String(length=16), nullable=False, server_default="workflow"),
        sa.Column("requested_by", sa.String(length=36), nullable=True),
        sa.Column("approver_user_ids", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_by", sa.String(length=36), nullable=True),
        sa.Column("end_reason", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("scope IN ('blanket','one_time','time_bound')", name="ck_ai_system_approval_grant_scope"),
        sa.CheckConstraint(
            "state IN ('ACTIVE','CONSUMED','EXPIRED','REVOKED','SUPERSEDED')", name="ck_ai_system_approval_grant_state"
        ),
        sa.CheckConstraint("scope <> 'time_bound' OR expires_at IS NOT NULL", name="ck_ai_system_approval_grant_expiry"),
    )
    op.create_index("idx_ai_system_approval_grant_tenant_state", "ai_system_approval_grants", ["tenant_id", "state"])
    op.create_index("idx_ai_system_approval_grant_system", "ai_system_approval_grants", ["tenant_id", "ai_system_id"])

    # Systems approved before this revision stay approved, as blanket approvals carried over on upgrade.
    bind = op.get_bind()
    systems = sa.table(
        "ai_systems",
        sa.column("id", sa.String),
        sa.column("tenant_id", sa.String),
        sa.column("risk_tier", sa.String),
        sa.column("status", sa.String),
        sa.column("metadata_json", sa.JSON),
    )
    grants = sa.table(
        "ai_system_approval_grants",
        sa.column("id", sa.String),
        sa.column("tenant_id", sa.String),
        sa.column("ai_system_id", sa.String),
        sa.column("scope", sa.String),
        sa.column("state", sa.String),
        sa.column("risk_tier", sa.String),
        sa.column("origin", sa.String),
        sa.column("approver_user_ids", sa.JSON),
        sa.column("end_reason", sa.String),
    )
    now = datetime.now(timezone.utc).isoformat()
    rows = bind.execute(sa.select(systems.c.id, systems.c.tenant_id, systems.c.risk_tier, systems.c.status, systems.c.metadata_json)).fetchall()
    for row in rows:
        metadata = _metadata(row.metadata_json)
        if not _approved_now(row.status, metadata):
            continue
        grant_id = str(uuid.uuid4())
        bind.execute(
            grants.insert().values(
                id=grant_id,
                tenant_id=row.tenant_id,
                ai_system_id=row.id,
                scope="blanket",
                state="ACTIVE",
                risk_tier=str(row.risk_tier or "")[:16],
                origin="upgrade",
                approver_user_ids=[],
                end_reason="",
            )
        )
        metadata["approval"] = {
            "grant_id": grant_id,
            "scope": "blanket",
            "state": "active",
            "origin": "upgrade",
            "expires_at": None,
            "approved_at": now,
            "approver_user_ids": [],
        }
        bind.execute(systems.update().where(systems.c.id == row.id).values(metadata_json=metadata))


def downgrade() -> None:
    op.drop_index("idx_ai_system_approval_grant_system", table_name="ai_system_approval_grants")
    op.drop_index("idx_ai_system_approval_grant_tenant_state", table_name="ai_system_approval_grants")
    op.drop_table("ai_system_approval_grants")
    op.drop_table("ai_system_approval_policies")
