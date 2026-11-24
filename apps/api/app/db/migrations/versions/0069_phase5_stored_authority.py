"""Bind Phase 5 issuance to durable signed current authority.

Revision ID: 0069_phase5_stored_authority
Revises: 0068_phase5_delegation_lineage
"""

from __future__ import annotations

import importlib

from alembic import op
import sqlalchemy as sa


revision = "0069_phase5_stored_authority"
down_revision = "0068_phase5_delegation_lineage"
branch_labels = None
depends_on = None


def _json_default(value: str, dialect: str) -> sa.TextClause:
    return sa.text(f"'{value}'{'::json' if dialect == 'postgresql' else ''}")


def _table_columns(table_name: str) -> set[str]:
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table_name)}


_LINEAGE_COLUMNS_OWNED_BY_0065 = {
    "domain_semantic_profiles": (
        sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("signed_envelope", sa.JSON(), nullable=True),
    ),
    "tenant_domain_profile_selections": (
        sa.Column("selection_hash", sa.String(64), nullable=True),
        sa.Column("selection_generation", sa.Integer(), nullable=False),
        sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("selected_by_principal_ref", sa.String(255), nullable=True),
        sa.Column("reason_code", sa.String(128), nullable=True),
        sa.Column("signed_envelope", sa.JSON(), nullable=True),
    ),
    "tenant_domain_profile_selection_projections_v2": (
        sa.Column("current_selection_generation", sa.Integer(), nullable=False),
    ),
}
_SELECTION_HISTORY_SEQUENCE_COLUMNS = ("selection_generation", "selection_sequence")


def _repair_empty_legacy_0065_lineage_contract() -> None:
    """Replace only an empty, pre-lineage 0065 schema with the exact 0065 DDL.

    Earlier development deployments stamped revision 0065 before the signed
    profile/selection lineage and projection CAS contract existed.  Those
    databases cannot satisfy 0069.  Rebuilding empty authority tables is safe
    and exact; non-empty legacy tables are refused because Hawk cannot invent
    signatures, hashes, audit principals, or selection history for them.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    core_tables = (
        "tenant_action_integrity_rollouts",
        "tenant_policy_epochs",
        "tenant_domain_profile_selection_projections_v2",
        "tenant_domain_profile_selections",
        "domain_semantic_profiles",
    )
    present = tuple(table for table in core_tables if inspector.has_table(table))
    if not present:
        raise RuntimeError("Phase 5 migration 0065 authority schema is missing")

    profile_columns = _table_columns("domain_semantic_profiles") if inspector.has_table("domain_semantic_profiles") else set()
    selection_columns = (
        _table_columns("tenant_domain_profile_selections")
        if inspector.has_table("tenant_domain_profile_selections")
        else set()
    )
    projection_columns = (
        _table_columns("tenant_domain_profile_selection_projections_v2")
        if inspector.has_table("tenant_domain_profile_selection_projections_v2")
        else set()
    )
    complete = (
        {column.name for column in _LINEAGE_COLUMNS_OWNED_BY_0065["domain_semantic_profiles"]}
        <= profile_columns
        and {
            *(column.name for column in _LINEAGE_COLUMNS_OWNED_BY_0065["tenant_domain_profile_selections"]),
            *_SELECTION_HISTORY_SEQUENCE_COLUMNS,
        }
        <= selection_columns
        and {
            column.name
            for column in _LINEAGE_COLUMNS_OWNED_BY_0065[
                "tenant_domain_profile_selection_projections_v2"
            ]
        }
        <= projection_columns
    )
    if complete:
        return

    for table in present:
        if bind.execute(sa.text(f'SELECT 1 FROM "{table}" LIMIT 1')).first() is not None:
            raise RuntimeError(
                "refusing Phase 5 legacy 0065 repair: signed lineage cannot be fabricated for non-empty "
                f"{table}"
            )

    if inspector.has_table("tenant_domain_profile_selection_projections_v2"):
        if bind.dialect.name == "postgresql":
            bind.execute(sa.text(
                "DROP TRIGGER IF EXISTS trg_phase5_profile_selection_projection_cas "
                "ON tenant_domain_profile_selection_projections_v2"
            ))
        elif bind.dialect.name == "sqlite":
            for action in ("insert", "update", "delete"):
                bind.execute(sa.text(
                    f"DROP TRIGGER IF EXISTS trg_phase5_profile_selection_projection_cas_{action}"
                ))
    if bind.dialect.name == "postgresql":
        if inspector.has_table("domain_semantic_profiles"):
            bind.execute(sa.text(
                "DROP TRIGGER IF EXISTS trg_phase5_profile_authority_immutable ON domain_semantic_profiles"
            ))
        if inspector.has_table("tenant_domain_profile_selections"):
            bind.execute(sa.text(
                "DROP TRIGGER IF EXISTS trg_phase5_selection_authority_immutable "
                "ON tenant_domain_profile_selections"
            ))
        for function in (
            "phase5_profile_selection_projection_cas()",
            "phase5_profile_history_immutable()",
            "phase5_selection_history_immutable()",
        ):
            bind.execute(sa.text(f"DROP FUNCTION IF EXISTS {function}"))
    elif bind.dialect.name == "sqlite":
        for trigger in (
            "trg_phase5_profile_authority_immutable_update",
            "trg_phase5_profile_authority_immutable_delete",
            "trg_phase5_selection_authority_immutable_update",
            "trg_phase5_selection_authority_immutable_delete",
        ):
            bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {trigger}"))

    for table in core_tables:
        if inspector.has_table(table):
            op.drop_table(table)

    core = importlib.import_module(
        "app.db.migrations.versions.0065_phase5_action_integrity_core"
    )
    core.create_action_integrity_core_schema()


def _require_0065_lineage_contract() -> None:
    """Fail loudly if an incomplete 0065 schema precedes this revision.

    0069 must neither recreate nor rewrite profile/selection lineage.  The
    descriptor makes that dependency explicit while retaining a clear failure
    mode for manually repaired or partially applied migration histories.
    """
    for table_name, columns in _LINEAGE_COLUMNS_OWNED_BY_0065.items():
        available = _table_columns(table_name)
        required = {column.name for column in columns}
        if table_name == "tenant_domain_profile_selections":
            required.update(_SELECTION_HISTORY_SEQUENCE_COLUMNS)
        missing = required - available
        if missing:
            raise RuntimeError(
                f"Phase 5 migration 0065 lineage contract is incomplete for {table_name}: "
                f"missing {', '.join(sorted(missing))}"
            )


def _add_decision_authority_columns() -> None:
    with op.batch_alter_table("decision_receipt_v2_extensions") as batch:
        batch.add_column(sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("profile_selection_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("profile_selection_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("control_selection_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("control_plan_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("authoritative_decision", sa.String(32), nullable=True))
        batch.add_column(sa.Column("authority_status", sa.String(32), nullable=True))
        batch.add_column(sa.Column("decision_version", sa.Integer(), nullable=True))


def _add_permit_authority_columns() -> None:
    with op.batch_alter_table("execution_permits_v2") as batch:
        batch.add_column(sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("profile_selection_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("profile_selection_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("control_selection_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("control_plan_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("authoritative_decision", sa.String(32), nullable=True))
        batch.add_column(sa.Column("authority_status", sa.String(32), nullable=True))
        batch.add_column(sa.Column("decision_version", sa.Integer(), nullable=True))


def _add_approval_authority_columns() -> None:
    with op.batch_alter_table("approval_requests") as batch:
        batch.add_column(sa.Column("decision_receipt_id", sa.String(36), nullable=True))
    with op.batch_alter_table("approval_binding_v2_extensions") as batch:
        batch.add_column(sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("decision_receipt_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("control_selection_id", sa.String(64), nullable=True))


def _create_authority_constraints() -> None:
    # PostgreSQL requires the referenced composite key to be unique before any
    # dependent foreign key is created.  Create the decision authority key and
    # its own constraints first; SQLite's batch rebuild did not expose this
    # ordering requirement during the earlier migration tests.
    with op.batch_alter_table("decision_receipt_v2_extensions") as batch:
        batch.create_unique_constraint("uq_phase5_decision_extension_tenant_receipt", ["tenant_id", "receipt_id"])
        batch.create_check_constraint("ck_phase5_decision_binding_version", "authority_binding_version IN (0, 1)")
        batch.create_check_constraint(
            "ck_phase5_decision_v1_complete",
            "(authority_binding_version = 0 AND profile_selection_id IS NULL AND profile_selection_hash IS NULL "
            "AND control_selection_id IS NULL AND control_plan_id IS NULL AND authoritative_decision IS NULL "
            "AND authority_status IS NULL AND decision_version IS NULL) "
            "OR (authority_binding_version = 1 AND profile_selection_id IS NOT NULL "
            "AND profile_selection_hash IS NOT NULL AND control_selection_id IS NOT NULL "
            "AND control_plan_id IS NOT NULL AND authoritative_decision IS NOT NULL "
            "AND authority_status IS NOT NULL AND decision_version > 0)",
        )
        batch.create_foreign_key(
            "fk_phase5_decision_profile_selection",
            "tenant_domain_profile_selections",
            ["tenant_id", "profile_selection_id", "profile_selection_hash"],
            ["tenant_id", "selection_id", "selection_hash"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_phase5_decision_native_selection",
            "native_control_selections",
            ["tenant_id", "control_selection_id"],
            ["tenant_id", "selection_id"],
            ondelete="RESTRICT",
        )
    with op.batch_alter_table("approval_requests") as batch:
        batch.create_check_constraint(
            "ck_phase5_approval_request_v1_decision",
            "authority_schema_version <> '2.0' OR decision_receipt_id IS NOT NULL",
        )
        batch.create_foreign_key(
            "fk_phase5_approval_request_decision_extension",
            "decision_receipt_v2_extensions",
            ["tenant_id", "decision_receipt_id"],
            ["tenant_id", "receipt_id"],
            ondelete="RESTRICT",
        )
    with op.batch_alter_table("approval_binding_v2_extensions") as batch:
        batch.create_check_constraint("ck_phase5_approval_binding_version", "authority_binding_version IN (0, 1)")
        batch.create_check_constraint(
            "ck_phase5_approval_binding_v1_complete",
            "(authority_binding_version = 0 AND decision_receipt_id IS NULL AND control_selection_id IS NULL) "
            "OR (authority_binding_version = 1 AND decision_receipt_id IS NOT NULL AND control_selection_id IS NOT NULL)",
        )
        batch.create_foreign_key(
            "fk_phase5_approval_binding_decision_extension",
            "decision_receipt_v2_extensions",
            ["tenant_id", "decision_receipt_id"],
            ["tenant_id", "receipt_id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_phase5_approval_binding_native_selection",
            "native_control_selections",
            ["tenant_id", "control_selection_id"],
            ["tenant_id", "selection_id"],
            ondelete="RESTRICT",
        )
    with op.batch_alter_table("execution_permits_v2") as batch:
        batch.create_check_constraint("ck_phase5_permit_binding_version", "authority_binding_version IN (0, 1)")
        batch.create_check_constraint(
            "ck_phase5_permit_v1_complete",
            "(authority_binding_version = 0 AND profile_selection_id IS NULL AND profile_selection_hash IS NULL "
            "AND control_selection_id IS NULL AND control_plan_id IS NULL AND authoritative_decision IS NULL "
            "AND authority_status IS NULL AND decision_version IS NULL) "
            "OR (authority_binding_version = 1 AND decision_receipt_id IS NOT NULL "
            "AND profile_selection_id IS NOT NULL AND profile_selection_hash IS NOT NULL "
            "AND control_selection_id IS NOT NULL AND control_plan_id IS NOT NULL "
            "AND authoritative_decision IS NOT NULL AND authority_status IS NOT NULL AND decision_version > 0)",
        )
        batch.create_foreign_key(
            "fk_phase5_permit_decision_extension",
            "decision_receipt_v2_extensions",
            ["tenant_id", "decision_receipt_id"],
            ["tenant_id", "receipt_id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_phase5_permit_profile_selection",
            "tenant_domain_profile_selections",
            ["tenant_id", "profile_selection_id", "profile_selection_hash"],
            ["tenant_id", "selection_id", "selection_hash"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_phase5_permit_native_selection",
            "native_control_selections",
            ["tenant_id", "control_selection_id"],
            ["tenant_id", "selection_id"],
            ondelete="RESTRICT",
        )


def _create_immutability_guards(bind: sa.Connection) -> None:
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_native_control_selections_immutable'
                ) THEN
                    RAISE EXCEPTION 'Phase 5 requires the 0063 native-control selection immutability trigger';
                END IF;
            END $$
        """))
        bind.execute(sa.text("""
            CREATE FUNCTION phase5_decision_authority_immutable() RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'INSERT' AND NEW.authority_binding_version <> 1 THEN
                    RAISE EXCEPTION 'new decision extensions require authority binding version 1';
                ELSIF TG_OP IN ('UPDATE', 'DELETE') THEN
                    RAISE EXCEPTION 'decision extensions are append-only';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """))
        bind.execute(sa.text("""
            CREATE FUNCTION phase5_permit_authority_immutable() RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'INSERT' AND NEW.authority_binding_version <> 1 THEN
                    RAISE EXCEPTION 'new permits require authority binding version 1';
                ELSIF TG_OP = 'UPDATE' AND (
                    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.permit_id IS DISTINCT FROM OLD.permit_id OR
                    NEW.action_id IS DISTINCT FROM OLD.action_id OR NEW.canonical_action_hash IS DISTINCT FROM OLD.canonical_action_hash OR
                    NEW.material_fields_hash IS DISTINCT FROM OLD.material_fields_hash OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id OR
                    NEW.decision_receipt_id IS DISTINCT FROM OLD.decision_receipt_id OR NEW.approval_binding_id IS DISTINCT FROM OLD.approval_binding_id OR
                    NEW.permitted_variation_hash IS DISTINCT FROM OLD.permitted_variation_hash OR NEW.policy_epoch IS DISTINCT FROM OLD.policy_epoch OR
                    NEW.control_plan_digest IS DISTINCT FROM OLD.control_plan_digest OR NEW.action_plan_binding_type IS DISTINCT FROM OLD.action_plan_binding_type OR
                    NEW.action_plan_id IS DISTINCT FROM OLD.action_plan_id OR NEW.action_plan_digest IS DISTINCT FROM OLD.action_plan_digest OR
                    NEW.action_plan_step_id IS DISTINCT FROM OLD.action_plan_step_id OR NEW.action_plan_step_digest IS DISTINCT FROM OLD.action_plan_step_digest OR
                    NEW.algorithm IS DISTINCT FROM OLD.algorithm OR NEW.signing_key_id IS DISTINCT FROM OLD.signing_key_id OR
                    NEW.signature IS DISTINCT FROM OLD.signature OR NEW.signed_envelope::jsonb IS DISTINCT FROM OLD.signed_envelope::jsonb OR
                    NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.authority_binding_version IS DISTINCT FROM OLD.authority_binding_version OR
                    NEW.profile_selection_id IS DISTINCT FROM OLD.profile_selection_id OR NEW.profile_selection_hash IS DISTINCT FROM OLD.profile_selection_hash OR
                    NEW.control_selection_id IS DISTINCT FROM OLD.control_selection_id OR NEW.control_plan_id IS DISTINCT FROM OLD.control_plan_id OR
                    NEW.authoritative_decision IS DISTINCT FROM OLD.authoritative_decision OR NEW.authority_status IS DISTINCT FROM OLD.authority_status OR
                    NEW.decision_version IS DISTINCT FROM OLD.decision_version
                ) THEN
                    RAISE EXCEPTION 'execution permit authority is immutable';
                ELSIF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'execution permits are append-only authority';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """))
        for table, trigger, function, events in (
            ("decision_receipt_v2_extensions", "trg_phase5_decision_authority_immutable", "phase5_decision_authority_immutable", "INSERT OR UPDATE OR DELETE"),
            ("execution_permits_v2", "trg_phase5_permit_authority_immutable", "phase5_permit_authority_immutable", "INSERT OR UPDATE OR DELETE"),
        ):
            bind.execute(sa.text(f"CREATE TRIGGER {trigger} BEFORE {events} ON {table} FOR EACH ROW EXECUTE FUNCTION {function}()"))
        return

    if bind.dialect.name == "sqlite":
        for table, prefix, message in (
            ("decision_receipt_v2_extensions", "decision", "decision extensions are append-only"),
        ):
            bind.execute(sa.text(
                f"CREATE TRIGGER trg_phase5_{prefix}_authority_insert BEFORE INSERT ON {table} "
                "WHEN NEW.authority_binding_version <> 1 "
                f"BEGIN SELECT RAISE(ABORT, 'new {prefix}s require authority binding version 1'); END"
            ))
            for action in ("UPDATE", "DELETE"):
                bind.execute(sa.text(
                    f"CREATE TRIGGER trg_phase5_{prefix}_authority_{action.lower()} BEFORE {action} ON {table} "
                    f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
                ))
        bind.execute(sa.text("""
            CREATE TRIGGER trg_phase5_permit_authority_insert
            BEFORE INSERT ON execution_permits_v2
            WHEN NEW.authority_binding_version <> 1
            BEGIN SELECT RAISE(ABORT, 'new permits require authority binding version 1'); END
        """))
        bind.execute(sa.text("""
            CREATE TRIGGER trg_phase5_permit_authority_update
            BEFORE UPDATE ON execution_permits_v2
            WHEN NEW.tenant_id IS NOT OLD.tenant_id OR NEW.permit_id IS NOT OLD.permit_id
              OR NEW.action_id IS NOT OLD.action_id OR NEW.canonical_action_hash IS NOT OLD.canonical_action_hash
              OR NEW.material_fields_hash IS NOT OLD.material_fields_hash OR NEW.attempt_id IS NOT OLD.attempt_id
              OR NEW.decision_receipt_id IS NOT OLD.decision_receipt_id OR NEW.approval_binding_id IS NOT OLD.approval_binding_id
              OR NEW.permitted_variation_hash IS NOT OLD.permitted_variation_hash OR NEW.policy_epoch IS NOT OLD.policy_epoch
              OR NEW.control_plan_digest IS NOT OLD.control_plan_digest OR NEW.action_plan_binding_type IS NOT OLD.action_plan_binding_type
              OR NEW.action_plan_id IS NOT OLD.action_plan_id OR NEW.action_plan_digest IS NOT OLD.action_plan_digest
              OR NEW.action_plan_step_id IS NOT OLD.action_plan_step_id OR NEW.action_plan_step_digest IS NOT OLD.action_plan_step_digest
              OR NEW.algorithm IS NOT OLD.algorithm OR NEW.signing_key_id IS NOT OLD.signing_key_id
              OR NEW.signature IS NOT OLD.signature OR NEW.signed_envelope IS NOT OLD.signed_envelope
              OR NEW.expires_at IS NOT OLD.expires_at OR NEW.authority_binding_version IS NOT OLD.authority_binding_version
              OR NEW.profile_selection_id IS NOT OLD.profile_selection_id OR NEW.profile_selection_hash IS NOT OLD.profile_selection_hash
              OR NEW.control_selection_id IS NOT OLD.control_selection_id OR NEW.control_plan_id IS NOT OLD.control_plan_id
              OR NEW.authoritative_decision IS NOT OLD.authoritative_decision OR NEW.authority_status IS NOT OLD.authority_status
              OR NEW.decision_version IS NOT OLD.decision_version
            BEGIN SELECT RAISE(ABORT, 'execution permit authority is immutable'); END
        """))
        bind.execute(sa.text("""
            CREATE TRIGGER trg_phase5_permit_authority_delete
            BEFORE DELETE ON execution_permits_v2
            BEGIN SELECT RAISE(ABORT, 'execution permits are append-only authority'); END
        """))


def _drop_immutability_guards(bind: sa.Connection) -> None:
    if bind.dialect.name == "postgresql":
        for table, trigger, function in (
            ("execution_permits_v2", "trg_phase5_permit_authority_immutable", "phase5_permit_authority_immutable"),
            ("decision_receipt_v2_extensions", "trg_phase5_decision_authority_immutable", "phase5_decision_authority_immutable"),
        ):
            bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {trigger} ON {table}"))
            bind.execute(sa.text(f"DROP FUNCTION IF EXISTS {function}()"))
    elif bind.dialect.name == "sqlite":
        for prefix in ("decision",):
            for action in ("insert", "update", "delete"):
                bind.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_phase5_{prefix}_authority_{action}"))
        for action in ("insert", "update", "delete"):
            bind.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_phase5_permit_authority_{action}"))


def upgrade() -> None:
    bind = op.get_bind()
    _repair_empty_legacy_0065_lineage_contract()
    _require_0065_lineage_contract()
    _add_decision_authority_columns()
    _add_permit_authority_columns()
    _add_approval_authority_columns()

    # 0065 exclusively owns the profile/selection history and its current-head
    # projection.  Apart from replacing the explicitly empty legacy 0065
    # shape above, this revision extends only decision, approval, and permit
    # authority records and never rewrites V1 lineage.
    bind.execute(sa.text("""
        UPDATE decision_receipt_v2_extensions
        SET authority_binding_version = 0, profile_selection_id = NULL, profile_selection_hash = NULL,
            control_selection_id = NULL, control_plan_id = NULL, authoritative_decision = NULL,
            authority_status = NULL, decision_version = NULL
    """))
    bind.execute(sa.text("""
        UPDATE execution_permits_v2
        SET authority_binding_version = 0, profile_selection_id = NULL, profile_selection_hash = NULL,
            control_selection_id = NULL, control_plan_id = NULL, authoritative_decision = NULL,
            authority_status = NULL, decision_version = NULL, reconstruction_status = 'INVALID'
    """))
    # Historic requests/bindings are V0 evidence. They cannot gain a V1
    # decision link retroactively and therefore remain ineligible.
    bind.execute(sa.text("""
        UPDATE approval_requests
        SET authority_schema_version = NULL
        WHERE authority_schema_version = '2.0' AND decision_receipt_id IS NULL
    """))

    _create_authority_constraints()
    # 0065 owns the full profile/selection/projection authority lineage,
    # including its CAS guard.  0069 must not mutate or remove that contract.
    _create_immutability_guards(bind)


def downgrade() -> None:
    bind = op.get_bind()
    checks = (
        "SELECT 1 FROM decision_receipt_v2_extensions WHERE authority_binding_version = 1 LIMIT 1",
        "SELECT 1 FROM execution_permits_v2 WHERE authority_binding_version = 1 LIMIT 1",
    )
    if any(bind.execute(sa.text(query)).first() is not None for query in checks):
        raise RuntimeError("refusing Phase 5 downgrade: V1 stored authority exists")

    _drop_immutability_guards(bind)
    with op.batch_alter_table("execution_permits_v2") as batch:
        batch.drop_constraint("fk_phase5_permit_native_selection", type_="foreignkey")
        batch.drop_constraint("fk_phase5_permit_profile_selection", type_="foreignkey")
        batch.drop_constraint("fk_phase5_permit_decision_extension", type_="foreignkey")
        batch.drop_constraint("ck_phase5_permit_v1_complete", type_="check")
        batch.drop_constraint("ck_phase5_permit_binding_version", type_="check")
        for column in ("decision_version", "authority_status", "authoritative_decision", "control_plan_id", "control_selection_id", "profile_selection_hash", "profile_selection_id", "authority_binding_version"):
            batch.drop_column(column)
    with op.batch_alter_table("approval_binding_v2_extensions") as batch:
        batch.drop_constraint("fk_phase5_approval_binding_native_selection", type_="foreignkey")
        batch.drop_constraint("fk_phase5_approval_binding_decision_extension", type_="foreignkey")
        batch.drop_constraint("ck_phase5_approval_binding_v1_complete", type_="check")
        batch.drop_constraint("ck_phase5_approval_binding_version", type_="check")
        for column in ("control_selection_id", "decision_receipt_id", "authority_binding_version"):
            batch.drop_column(column)
    with op.batch_alter_table("approval_requests") as batch:
        batch.drop_constraint("fk_phase5_approval_request_decision_extension", type_="foreignkey")
        batch.drop_constraint("ck_phase5_approval_request_v1_decision", type_="check")
        batch.drop_column("decision_receipt_id")
    with op.batch_alter_table("decision_receipt_v2_extensions") as batch:
        batch.drop_constraint("fk_phase5_decision_native_selection", type_="foreignkey")
        batch.drop_constraint("fk_phase5_decision_profile_selection", type_="foreignkey")
        batch.drop_constraint("ck_phase5_decision_v1_complete", type_="check")
        batch.drop_constraint("ck_phase5_decision_binding_version", type_="check")
        batch.drop_constraint("uq_phase5_decision_extension_tenant_receipt", type_="unique")
        for column in ("decision_version", "authority_status", "authoritative_decision", "control_plan_id", "control_selection_id", "profile_selection_hash", "profile_selection_id", "authority_binding_version"):
            batch.drop_column(column)
