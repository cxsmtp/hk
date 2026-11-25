"""People, teams and editable roles (FTR Command Center's server/iam.js, server/rbac.js and server/teams.js;
app/services/iam_service.py):

- iam_roles: each tenant's roles. Seeded here from the memberships there are: the five built-in roles for every tenant
  (no permissions stored: the defaults of app/core/permissions.py, which are exactly what each role could do before),
  and, for a role name a membership carries that is none of them, a role of that name with no permissions (such a
  membership passed no check before either). Nobody gains or loses anything.
- iam_teams: teams (a tree, with leaders), per tenant.
- iam_join_settings: joining by oneself, per tenant; off.
- user_tenant_roles: team, title, whom one reports to, and for those who joined by themselves what they chose and who
  reviewed it.

down_revision is 0097_audit_chain: 0098_watchdog is being added in parallel; relink this one onto it when both merge.
"""

from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa


revision = "0099_iam_roles"
down_revision = "0097_audit_chain"
branch_labels = None
depends_on = None

BUILTIN = {
    "owner": ("Owner", "Everything, in this tenant: people, teams, roles, settings and every record. Only an Owner gives or takes the Owner role."),
    "admin": ("Admin", "Everything, in this tenant: people, teams, roles, settings and every record."),
    "auditor": ("Auditor", "Reads everything an Operator reads, never changes it; reviews evidence, findings and enforcement, and exports the audit log."),
    "operator": ("Operator", "Works day to day: runs scans and simulations, acts on activity, drafts policies and deploys controls. Not the Admin settings."),
    "viewer": ("Viewer", "Read only: the dashboards, inventory, activity, policies, deployments and evidence."),
}


def upgrade() -> None:
    op.create_table(
        "iam_roles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=60), nullable=False),
        sa.Column("description", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("permissions", sa.JSON(), nullable=True),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "key", name="uq_iam_roles_tenant_key"),
    )
    op.create_index("ix_iam_roles_tenant_id", "iam_roles", ["tenant_id"])
    op.create_table(
        "iam_teams",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("region", sa.String(length=60), nullable=False, server_default=""),
        sa.Column("parent_id", sa.String(length=36), nullable=True),
        sa.Column("leader_ids", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_iam_teams_tenant", "iam_teams", ["tenant_id"])
    op.create_table(
        "iam_join_settings",
        sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("domains", sa.JSON(), nullable=False),
        sa.Column("roles", sa.JSON(), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    with op.batch_alter_table("user_tenant_roles") as batch:
        batch.add_column(sa.Column("team_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("title", sa.String(length=120), nullable=False, server_default=""))
        batch.add_column(sa.Column("manager_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("joined_role", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("joined_team_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("reviewed_by", sa.String(length=255), nullable=True))

    # Seed each tenant's roles from what is there.
    bind = op.get_bind()
    roles = sa.table(
        "iam_roles",
        sa.column("id", sa.String),
        sa.column("tenant_id", sa.String),
        sa.column("key", sa.String),
        sa.column("name", sa.String),
        sa.column("description", sa.String),
        sa.column("permissions", sa.JSON),
        sa.column("builtin", sa.Boolean),
    )
    tenant_ids = [row[0] for row in bind.execute(sa.text("SELECT id FROM tenants"))]
    in_use: dict[str, set[str]] = {}
    for tenant_id, role in bind.execute(sa.text("SELECT tenant_id, role FROM user_tenant_roles")):
        in_use.setdefault(str(tenant_id), set()).add(str(role))
    rows = []
    for tenant_id in tenant_ids:
        for key, (name, description) in BUILTIN.items():
            rows.append({"id": str(uuid.uuid4()), "tenant_id": tenant_id, "key": key, "name": name, "description": description, "permissions": None, "builtin": True})
        for key in sorted(in_use.get(str(tenant_id), set()) - set(BUILTIN)):
            rows.append({"id": str(uuid.uuid4()), "tenant_id": tenant_id, "key": key[:32], "name": key[:60] or "Unnamed role", "description": "A role from before roles could be edited. It holds no permissions, as before.", "permissions": [], "builtin": False})
    if rows:
        op.bulk_insert(roles, rows)


def downgrade() -> None:
    with op.batch_alter_table("user_tenant_roles") as batch:
        for column in ("reviewed_by", "reviewed_at", "joined_team_id", "joined_role", "joined_at", "manager_id", "title", "team_id"):
            batch.drop_column(column)
    op.drop_table("iam_join_settings")
    op.drop_index("idx_iam_teams_tenant", table_name="iam_teams")
    op.drop_table("iam_teams")
    op.drop_index("ix_iam_roles_tenant_id", table_name="iam_roles")
    op.drop_table("iam_roles")
