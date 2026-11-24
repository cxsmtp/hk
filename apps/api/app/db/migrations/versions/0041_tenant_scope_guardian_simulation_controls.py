"""tenant-scope guardian v2 contracts and simulation controls

Revision ID: 0041_tenant_guardian_sim
Revises: 0040_agentic_action_integrity
Create Date: 2026-07-21 06:15:00.000000
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "0041_tenant_guardian_sim"
down_revision = "0040_agentic_action_integrity"
branch_labels = None
depends_on = None


SYSTEM_GUARDIAN_IDS = {
    "prompt_injection_guard",
    "sensitive_data_leak_guard",
    "tool_output_injection_guard",
}

# These are deterministic product catalog rows, not customer-authored controls.
# They may be copied to every existing tenant. Any other unowned/global row makes
# the migration abort instead of guessing an owner.
SYSTEM_CONTROL_IDS = {
    "PROMPT_INJECTION_DETECTION",
    "JAILBREAK_DETECTION",
    "SENSITIVE_DATA_DETECTION",
    "PII_EXFILTRATION_PREVENTION",
    "FILE_UPLOAD_INSPECTION",
    "OCR_DATA_EXTRACTION_CONTROL",
    "RAG_POISONING_DETECTION",
    "MODEL_OUTPUT_VALIDATION",
    "MODEL_ACCESS_CONTROL",
    "MODEL_INTEGRITY_CHECK",
    "SHADOW_AI_DETECTION",
    "AI_SYSTEM_INVENTORY_CONTROL",
    "AI_IDENTITY_BINDING",
    "NON_HUMAN_IDENTITY_CONTROL",
    "TOKEN_SCOPE_ENFORCEMENT",
    "PRIVILEGE_DRIFT_DETECTION",
    "TOOL_CALL_VALIDATION",
    "TOOL_MISUSE_PREVENTION",
    "AGENT_ACTION_AUTHORIZATION",
    "CHAIN_OF_ACTION_VALIDATION",
    "CROSS_AGENT_BOUNDARY_CONTROL",
    "CONTEXT_LEAKAGE_DETECTION",
    "POLICY_ENFORCEMENT_CONTROL",
    "RISK_CLASSIFICATION_CONTROL",
}

CONTROL_CHILD_TABLES = (
    "control_maturity",
    "control_maturity_history",
    "control_conflicts",
    "conflict_resolutions",
)


def _abort(message: str) -> None:
    raise RuntimeError(
        "0041 tenant scoping aborted: "
        f"{message}. Assign every legacy row to a trusted tenant and retry."
    )


def _rows(table_name: str) -> list[dict[str, Any]]:
    bind = op.get_bind()
    table = sa.Table(table_name, sa.MetaData(), autoload_with=bind)
    return [dict(row) for row in bind.execute(sa.select(table)).mappings().all()]


def _tenant_ids() -> list[str]:
    return sorted(str(row["id"]) for row in _rows("tenants"))


def _control_fk_operation_shape(dialect_name: str) -> dict[str, Any]:
    """Return a reviewable, dependency-safe FK operation plan."""

    return {
        "mode": "direct" if dialect_name == "postgresql" else "batch",
        "drop": [
            ("conflict_resolutions", "control_conflicts"),
            ("conflict_resolutions", "controls"),
            ("control_conflicts", "controls"),
            ("control_maturity_history", "controls"),
            ("control_maturity", "controls"),
        ],
        "create": [
            ("control_maturity", "controls", "CASCADE"),
            ("control_maturity_history", "controls", "CASCADE"),
            ("control_conflicts", "controls", "CASCADE"),
            ("conflict_resolutions", "controls", "CASCADE"),
            ("conflict_resolutions", "control_conflicts", "SET NULL"),
        ],
    }


def _fk_name(*, table_name: str, referred_table: str) -> str | None:
    inspector = inspect(op.get_bind())
    fk = next(
        (
            item
            for item in inspector.get_foreign_keys(table_name)
            if item.get("referred_table") == referred_table
        ),
        None,
    )
    if fk is None:
        return None
    if fk.get("name"):
        return str(fk["name"])
    local_column = "conflict_id" if referred_table == "control_conflicts" else "control_id"
    return f"fk_{table_name}_{local_column}_{referred_table}"


def _drop_control_foreign_keys() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    shape = _control_fk_operation_shape(dialect_name)
    naming = {"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"}
    for table_name, referred_table in shape["drop"]:
        inspector = inspect(bind)
        if table_name not in inspector.get_table_names():
            continue
        constraint_name = _fk_name(table_name=table_name, referred_table=referred_table)
        if constraint_name is None:
            continue
        if shape["mode"] == "direct":
            op.drop_constraint(constraint_name, table_name, type_="foreignkey")
        else:
            with op.batch_alter_table(
                table_name,
                recreate="always",
                naming_convention=naming,
            ) as batch_op:
                batch_op.drop_constraint(constraint_name, type_="foreignkey")


def _create_control_foreign_keys(*, composite: bool) -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    shape = _control_fk_operation_shape(dialect_name)
    for table_name, referred_table, ondelete in shape["create"]:
        if table_name not in inspect(bind).get_table_names():
            continue
        if referred_table == "controls":
            local_columns = ["control_id", "tenant_id"] if composite else ["control_id"]
            remote_columns = ["id", "tenant_id"] if composite else ["id"]
            constraint_name = (
                f"fk_{table_name}_tenant_control"
                if composite
                else f"fk_{table_name}_control_id_controls"
            )
        else:
            local_columns = ["conflict_id"]
            remote_columns = ["id"]
            constraint_name = "fk_conflict_resolutions_conflict_id_control_conflicts"

        if shape["mode"] == "direct":
            op.create_foreign_key(
                constraint_name,
                table_name,
                referred_table,
                local_columns,
                remote_columns,
                ondelete=ondelete,
            )
        else:
            with op.batch_alter_table(table_name, recreate="always") as batch_op:
                batch_op.create_foreign_key(
                    constraint_name,
                    referred_table,
                    local_columns,
                    remote_columns,
                    ondelete=ondelete,
                )


def _create_guardian_scoped_table(name: str) -> sa.Table:
    return op.create_table(
        name,
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("trigger_conditions", sa.JSON(), nullable=False),
        sa.Column("block_conditions", sa.JSON(), nullable=False),
        sa.Column("mandatory_actions", sa.JSON(), nullable=False),
        sa.Column("escalation_path", sa.JSON(), nullable=False),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False),
        sa.Column("framework_mappings", sa.JSON(), nullable=False),
        sa.Column("canonical_policy", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id", "id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_guardian_contract_v2_tenant_id"),
    )


def _create_guardian_legacy_table(name: str) -> sa.Table:
    return op.create_table(
        name,
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("trigger_conditions", sa.JSON(), nullable=False),
        sa.Column("block_conditions", sa.JSON(), nullable=False),
        sa.Column("mandatory_actions", sa.JSON(), nullable=False),
        sa.Column("escalation_path", sa.JSON(), nullable=False),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False),
        sa.Column("framework_mappings", sa.JSON(), nullable=False),
        sa.Column("canonical_policy", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_guardian_binding_table(*, composite: bool) -> sa.Table:
    constraints: list[Any] = [
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    ]
    if composite:
        constraints.append(
            sa.ForeignKeyConstraint(
                ["tenant_id", "guardian_contract_id"],
                ["guardian_contract_v2.tenant_id", "guardian_contract_v2.id"],
                ondelete="CASCADE",
                name="fk_guardian_binding_v2_tenant_contract",
            )
        )
    else:
        constraints.append(
            sa.ForeignKeyConstraint(
                ["guardian_contract_id"],
                ["guardian_contract_v2.id"],
                ondelete="CASCADE",
            )
        )
    return op.create_table(
        "guardian_contract_binding_v2",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("guardian_contract_id", sa.String(length=128), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("policy_version_id", sa.String(length=36), nullable=True),
        sa.Column("enforcement_strength", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        *constraints,
    )


def _create_control_table(name: str, *, composite: bool) -> sa.Table:
    pk = sa.PrimaryKeyConstraint("id", "tenant_id") if composite else sa.PrimaryKeyConstraint("id")
    return op.create_table(
        name,
        sa.Column("tenant_id", sa.String(length=36), nullable=not composite),
        sa.Column("is_global", sa.Boolean(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mapped_framework_refs", sa.JSON(), nullable=False),
        sa.Column("risk_tags", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("enforcement_points", sa.JSON(), nullable=False),
        sa.Column("detection_methods", sa.JSON(), nullable=False),
        sa.Column("response_actions", sa.JSON(), nullable=False),
        sa.Column("evidence_types", sa.JSON(), nullable=False),
        sa.Column("remediation_templates", sa.JSON(), nullable=False),
        sa.Column("success_criteria", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        pk,
    )


def _create_indexes() -> None:
    op.create_index("idx_guardian_contract_v2_tenant", "guardian_contract_v2", ["tenant_id"])
    op.create_index("idx_guardian_binding_v2_tenant", "guardian_contract_binding_v2", ["tenant_id"])
    op.create_index("idx_guardian_binding_v2_guardian", "guardian_contract_binding_v2", ["guardian_contract_id"])
    op.create_index("idx_guardian_binding_v2_ai_system", "guardian_contract_binding_v2", ["ai_system_id"])
    op.create_index("idx_guardian_binding_v2_policy_version", "guardian_contract_binding_v2", ["policy_version_id"])
    op.create_index("idx_control_tenant", "controls", ["tenant_id"])
    op.create_index("idx_control_tenant_category", "controls", ["tenant_id", "category"])


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    required = {"tenants", "guardian_contract_v2", "guardian_contract_binding_v2", "controls"}
    missing = sorted(required - set(inspector.get_table_names()))
    if missing:
        _abort(f"required legacy tables are missing: {', '.join(missing)}")

    # Additive nullable phase for the previously global Guardian table.
    guardian_columns = {column["name"] for column in inspector.get_columns("guardian_contract_v2")}
    if "tenant_id" not in guardian_columns:
        op.add_column("guardian_contract_v2", sa.Column("tenant_id", sa.String(length=36), nullable=True))

    tenants = _tenant_ids()
    guardian_rows = _rows("guardian_contract_v2")
    binding_rows = _rows("guardian_contract_binding_v2")
    bindings_by_contract: dict[str, set[str]] = defaultdict(set)
    for row in binding_rows:
        bindings_by_contract[str(row["guardian_contract_id"])].add(str(row["tenant_id"]))

    scoped_guardians: list[dict[str, Any]] = []
    for row in guardian_rows:
        contract_id = str(row["id"])
        mapped_tenants = sorted(bindings_by_contract.get(contract_id) or set())
        if contract_id in SYSTEM_GUARDIAN_IDS:
            # System defaults were globally visible before this migration. An
            # incidental tenant binding does not make that tenant the owner.
            mapped_tenants = tenants
        elif len(mapped_tenants) > 1:
            _abort(
                f"guardian_contract_v2 id={contract_id!r} is shared by multiple tenants "
                f"({', '.join(mapped_tenants)}) and cannot be assigned without an explicit owner"
            )
        if not mapped_tenants:
            if not tenants and contract_id in SYSTEM_GUARDIAN_IDS:
                # A brand-new database has no tenant owner to copy product
                # catalog defaults to. Tenant-scoped defaults are seeded by
                # the service after the first tenant exists, so discard only
                # these known system rows instead of inventing an owner.
                bind.execute(
                    sa.text("DELETE FROM guardian_contract_v2 WHERE id=:id"),
                    {"id": contract_id},
                )
                continue
            _abort(f"guardian_contract_v2 id={contract_id!r} has no trusted tenant mapping")
        bind.execute(
            sa.text("UPDATE guardian_contract_v2 SET tenant_id=:tenant_id WHERE id=:id"),
            {"tenant_id": mapped_tenants[0], "id": contract_id},
        )
        for tenant_id in mapped_tenants:
            copied = {key: value for key, value in row.items() if key != "tenant_id"}
            copied["tenant_id"] = tenant_id
            canonical = dict(copied.get("canonical_policy") or {})
            canonical["tenant_id"] = tenant_id
            copied["canonical_policy"] = canonical
            scoped_guardians.append(copied)

    null_guardians = bind.scalar(sa.text("SELECT COUNT(*) FROM guardian_contract_v2 WHERE tenant_id IS NULL"))
    if int(null_guardians or 0) != 0:
        _abort("guardian_contract_v2 nullable backfill verification failed")

    control_rows = _rows("controls")
    scoped_controls: list[dict[str, Any]] = []
    trusted_control_keys: set[tuple[str, str]] = set()
    for row in control_rows:
        control_id = str(row["id"])
        tenant_id = str(row.get("tenant_id") or "").strip()
        is_global = bool(row.get("is_global"))
        if is_global and control_id in SYSTEM_CONTROL_IDS:
            # Product catalog globals retain their previous visibility for all
            # existing tenants even if a legacy row happened to carry one ID.
            mapped_tenants = tenants
        elif is_global:
            _abort(
                f"controls id={control_id!r} is marked global but is not a trusted system catalog row"
            )
        elif tenant_id:
            mapped_tenants = [tenant_id]
        else:
            _abort(f"controls id={control_id!r} has no trusted tenant mapping")
        for mapped_tenant in mapped_tenants:
            copied = dict(row)
            copied["tenant_id"] = mapped_tenant
            copied["is_global"] = False
            scoped_controls.append(copied)
            trusted_control_keys.add((mapped_tenant, control_id))

    for child_table in CONTROL_CHILD_TABLES:
        if child_table not in inspector.get_table_names():
            continue
        for row in _rows(child_table):
            key = (str(row["tenant_id"]), str(row["control_id"]))
            if key not in trusted_control_keys:
                _abort(
                    f"{child_table} id={row.get('id')!r} references control_id={key[1]!r} "
                    f"without a control owned by tenant_id={key[0]!r}"
                )

    guardian_scoped = _create_guardian_scoped_table("guardian_contract_v2_tenant_scoped")
    if scoped_guardians:
        bind.execute(guardian_scoped.insert(), scoped_guardians)
    control_scoped = _create_control_table("controls_tenant_scoped", composite=True)
    if scoped_controls:
        bind.execute(control_scoped.insert(), scoped_controls)

    saved_bindings = binding_rows
    for index in inspect(bind).get_indexes("guardian_contract_binding_v2"):
        if index.get("name"):
            op.drop_index(str(index["name"]), table_name="guardian_contract_binding_v2")
    op.drop_table("guardian_contract_binding_v2")
    op.drop_table("guardian_contract_v2")
    op.rename_table("guardian_contract_v2_tenant_scoped", "guardian_contract_v2")
    binding_table = _create_guardian_binding_table(composite=True)
    if saved_bindings:
        bind.execute(binding_table.insert(), saved_bindings)

    _drop_control_foreign_keys()
    for index in inspect(bind).get_indexes("controls"):
        if index.get("name"):
            op.drop_index(str(index["name"]), table_name="controls")
    op.drop_table("controls")
    op.rename_table("controls_tenant_scoped", "controls")
    _create_control_foreign_keys(composite=True)
    _create_indexes()


def downgrade() -> None:
    bind = op.get_bind()
    guardian_rows = _rows("guardian_contract_v2")
    control_rows = _rows("controls")
    binding_rows = _rows("guardian_contract_binding_v2")

    guardian_ids = [str(row["id"]) for row in guardian_rows]
    duplicate_guardians = sorted({item for item in guardian_ids if guardian_ids.count(item) > 1})
    if duplicate_guardians:
        _abort(
            "downgrade cannot collapse tenant-specific Guardian contracts with duplicate ids: "
            + ", ".join(duplicate_guardians)
        )
    control_ids = [str(row["id"]) for row in control_rows]
    duplicate_controls = sorted({item for item in control_ids if control_ids.count(item) > 1})
    if duplicate_controls:
        _abort(
            "downgrade cannot collapse tenant-specific controls with duplicate ids: "
            + ", ".join(duplicate_controls)
        )

    guardian_legacy = _create_guardian_legacy_table("guardian_contract_v2_legacy")
    legacy_guardians = [
        {key: value for key, value in row.items() if key != "tenant_id"}
        for row in guardian_rows
    ]
    if legacy_guardians:
        bind.execute(guardian_legacy.insert(), legacy_guardians)

    control_legacy = _create_control_table("controls_legacy", composite=False)
    legacy_controls = [dict(row) for row in control_rows]
    if legacy_controls:
        bind.execute(control_legacy.insert(), legacy_controls)

    for index in inspect(bind).get_indexes("guardian_contract_binding_v2"):
        if index.get("name"):
            op.drop_index(str(index["name"]), table_name="guardian_contract_binding_v2")
    op.drop_table("guardian_contract_binding_v2")
    op.drop_table("guardian_contract_v2")
    op.rename_table("guardian_contract_v2_legacy", "guardian_contract_v2")
    binding_table = _create_guardian_binding_table(composite=False)
    if binding_rows:
        bind.execute(binding_table.insert(), binding_rows)

    _drop_control_foreign_keys()
    for index in inspect(bind).get_indexes("controls"):
        if index.get("name"):
            op.drop_index(str(index["name"]), table_name="controls")
    op.drop_table("controls")
    op.rename_table("controls_legacy", "controls")
    _create_control_foreign_keys(composite=False)

    op.create_index("idx_guardian_binding_v2_tenant", "guardian_contract_binding_v2", ["tenant_id"])
    op.create_index("idx_guardian_binding_v2_guardian", "guardian_contract_binding_v2", ["guardian_contract_id"])
    op.create_index("idx_guardian_binding_v2_ai_system", "guardian_contract_binding_v2", ["ai_system_id"])
    op.create_index("idx_guardian_binding_v2_policy_version", "guardian_contract_binding_v2", ["policy_version_id"])
    op.create_index("idx_control_tenant", "controls", ["tenant_id"])
