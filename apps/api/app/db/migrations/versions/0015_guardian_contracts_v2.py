"""add guardian contracts v2 tables

Revision ID: 0015_guardian_contracts_v2
Revises: 0014_ai_iam_enterprise_hardening
Create Date: 2026-02-27 13:20:00.000000
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "0015_guardian_contracts_v2"
down_revision = "0014_ai_iam_enterprise_hardening"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.create_table(
        "guardian_contract_v2",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=False, server_default="2.0"),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("trigger_conditions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("block_conditions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("mandatory_actions", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("escalation_path", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("framework_mappings", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "guardian_contract_binding_v2",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("guardian_contract_id", sa.String(length=128), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("policy_version_id", sa.String(length=36), nullable=True),
        sa.Column("enforcement_strength", sa.String(length=16), nullable=False, server_default="baseline"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["guardian_contract_id"], ["guardian_contract_v2.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_guardian_binding_v2_tenant", "guardian_contract_binding_v2", ["tenant_id"])
    op.create_index("idx_guardian_binding_v2_guardian", "guardian_contract_binding_v2", ["guardian_contract_id"])
    op.create_index("idx_guardian_binding_v2_ai_system", "guardian_contract_binding_v2", ["ai_system_id"])
    op.create_index("idx_guardian_binding_v2_policy_version", "guardian_contract_binding_v2", ["policy_version_id"])

    contracts_table = sa.table(
        "guardian_contract_v2",
        sa.column("id", sa.String(length=128)),
        sa.column("version", sa.String(length=16)),
        sa.column("name", sa.String(length=255)),
        sa.column("trigger_conditions", sa.JSON()),
        sa.column("block_conditions", sa.JSON()),
        sa.column("mandatory_actions", sa.JSON()),
        sa.column("escalation_path", sa.JSON()),
        sa.column("evidence_requirements", sa.JSON()),
        sa.column("framework_mappings", sa.JSON()),
    )
    contract_rows = [
            {
                "id": "prompt_injection_guard",
                "version": "2.0",
                "name": "Prompt Injection Guard",
                "trigger_conditions": [
                    {"field": "prompt.text", "operator": "contains", "value": "ignore previous instructions", "case_sensitive": False}
                ],
                "block_conditions": [
                    {"field": "prompt.text", "operator": "contains", "value": "reveal secrets", "case_sensitive": False}
                ],
                "mandatory_actions": {"notify": {"channels": ["email"]}},
                "escalation_path": {"mode": "notify"},
                "evidence_requirements": {"link_to_controls": ["CTRL-PI-001"]},
                "framework_mappings": {"control_ids": ["CTRL-PI-001"]},
            },
            {
                "id": "sensitive_data_leak_guard",
                "version": "2.0",
                "name": "Sensitive Data Leak Guard",
                "trigger_conditions": [
                    {"field": "prompt.text", "operator": "contains", "value": "ssn", "case_sensitive": False}
                ],
                "block_conditions": [
                    {"field": "prompt.text", "operator": "contains", "value": "customer data", "case_sensitive": False}
                ],
                "mandatory_actions": {"redact": {"fields": ["prompt"], "strategy": "mask"}},
                "escalation_path": {"mode": "notify"},
                "evidence_requirements": {"link_to_controls": ["CTRL-DLP-001"]},
                "framework_mappings": {"control_ids": ["CTRL-DLP-001"]},
            },
            {
                "id": "tool_output_injection_guard",
                "version": "2.0",
                "name": "Tool Output Injection Guard",
                "trigger_conditions": [
                    {"field": "tool_output", "operator": "contains", "value": "ignore policy", "case_sensitive": False}
                ],
                "block_conditions": [
                    {"field": "tool_output", "operator": "contains", "value": "execute shell", "case_sensitive": False}
                ],
                "mandatory_actions": {"mutate_output": {"enabled": True, "strategy": "safe_completion"}},
                "escalation_path": {"mode": "notify"},
                "evidence_requirements": {"link_to_controls": ["CTRL-TOOL-001"]},
                "framework_mappings": {"control_ids": ["CTRL-TOOL-001"]},
            },
        ]
    json_fields = (
        "trigger_conditions",
        "block_conditions",
        "mandatory_actions",
        "escalation_path",
        "evidence_requirements",
        "framework_mappings",
    )
    for row in contract_rows:
        for field in json_fields:
            row[field] = op.inline_literal(
                json.dumps(row[field], sort_keys=True, separators=(",", ":"))
            )
    op.bulk_insert(contracts_table, contract_rows, multiinsert=False)

    if dialect != "sqlite":
        op.alter_column("guardian_contract_v2", "version", server_default=None)
        op.alter_column("guardian_contract_v2", "trigger_conditions", server_default=None)
        op.alter_column("guardian_contract_v2", "block_conditions", server_default=None)
        op.alter_column("guardian_contract_v2", "mandatory_actions", server_default=None)
        op.alter_column("guardian_contract_v2", "escalation_path", server_default=None)
        op.alter_column("guardian_contract_v2", "evidence_requirements", server_default=None)
        op.alter_column("guardian_contract_v2", "framework_mappings", server_default=None)
        op.alter_column("guardian_contract_binding_v2", "enforcement_strength", server_default=None)
        op.alter_column("guardian_contract_binding_v2", "enabled", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_guardian_binding_v2_policy_version", table_name="guardian_contract_binding_v2")
    op.drop_index("idx_guardian_binding_v2_ai_system", table_name="guardian_contract_binding_v2")
    op.drop_index("idx_guardian_binding_v2_guardian", table_name="guardian_contract_binding_v2")
    op.drop_index("idx_guardian_binding_v2_tenant", table_name="guardian_contract_binding_v2")
    op.drop_table("guardian_contract_binding_v2")
    op.drop_table("guardian_contract_v2")
