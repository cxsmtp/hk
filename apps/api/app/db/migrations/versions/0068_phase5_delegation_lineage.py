"""Add fail-closed V1 delegation lineage and lifecycle evidence.

Revision ID: 0068_phase5_delegation_lineage
Revises: 0067_phase5_control_coverage
"""

from alembic import op
import sqlalchemy as sa


revision = "0068_phase5_delegation_lineage"
down_revision = "0067_phase5_control_coverage"
branch_labels = None
depends_on = None


def _create_immutability_guards(bind: sa.Connection) -> None:
    if bind.dialect.name == "postgresql":
        bind.execute(
            sa.text(
                """
                CREATE FUNCTION phase5_delegation_lineage_guard() RETURNS trigger AS $$
                BEGIN
                    IF TG_OP = 'INSERT' AND NEW.lineage_binding_version <> 1 THEN
                        RAISE EXCEPTION 'new delegation contexts require lineage binding version 1';
                    END IF;
                    IF TG_OP = 'UPDATE' AND (
                        NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR
                        NEW.delegation_context_id IS DISTINCT FROM OLD.delegation_context_id OR
                        NEW.parent_action_id IS DISTINCT FROM OLD.parent_action_id OR
                        NEW.parent_delegation_context_id IS DISTINCT FROM OLD.parent_delegation_context_id OR
                        NEW.delegated_action_id IS DISTINCT FROM OLD.delegated_action_id OR
                        NEW.lineage_binding_version IS DISTINCT FROM OLD.lineage_binding_version OR
                        NEW.source_principal_ref IS DISTINCT FROM OLD.source_principal_ref OR
                        NEW.destination_principal_ref IS DISTINCT FROM OLD.destination_principal_ref OR
                        NEW.authority_scope_hash IS DISTINCT FROM OLD.authority_scope_hash OR
                        NEW.depth IS DISTINCT FROM OLD.depth OR
                        NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
                        NEW.algorithm IS DISTINCT FROM OLD.algorithm OR
                        NEW.signing_key_id IS DISTINCT FROM OLD.signing_key_id OR
                        NEW.signature IS DISTINCT FROM OLD.signature OR
                        NEW.signed_envelope::jsonb IS DISTINCT FROM OLD.signed_envelope::jsonb
                    ) THEN
                        RAISE EXCEPTION 'delegation lineage binding is immutable';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        bind.execute(
            sa.text(
                """
                CREATE TRIGGER trg_phase5_delegation_lineage_guard
                BEFORE INSERT OR UPDATE ON delegation_contexts_v2
                FOR EACH ROW EXECUTE FUNCTION phase5_delegation_lineage_guard()
                """
            )
        )
        bind.execute(
            sa.text(
                """
                CREATE FUNCTION phase5_delegation_event_immutable() RETURNS trigger AS $$
                BEGIN
                    IF TG_OP IN ('UPDATE', 'DELETE') THEN
                        RAISE EXCEPTION 'delegation lifecycle events are append-only';
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM delegation_contexts_v2 context
                        WHERE context.tenant_id = NEW.tenant_id
                          AND context.delegation_context_id = NEW.delegation_context_id
                          AND context.lineage_binding_version = 1
                    ) THEN
                        RAISE EXCEPTION 'delegation events require a V1 context';
                    END IF;
                    IF NEW.algorithm = '' OR NEW.signing_key_id = '' OR NEW.signature = ''
                       OR NEW.signed_envelope IS NULL
                       OR NEW.signed_envelope::text IN ('{}', 'null')
                       OR NEW.observed_at IS NULL OR NEW.evidence_refs IS NULL
                       OR NEW.affected_unconsumed_descendant_refs IS NULL
                       OR (NEW.sequence = 1 AND (NEW.prior_event_id IS NOT NULL OR NEW.prior_event_hash IS NOT NULL))
                       OR (NEW.sequence > 1 AND (NEW.prior_event_id IS NULL OR NEW.prior_event_hash IS NULL)) THEN
                        RAISE EXCEPTION 'new delegation events require complete signed fields';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        bind.execute(
            sa.text(
                """
                CREATE TRIGGER trg_phase5_delegation_event_immutable
                BEFORE INSERT OR UPDATE OR DELETE ON delegation_lifecycle_events_v2
                FOR EACH ROW EXECUTE FUNCTION phase5_delegation_event_immutable()
                """
            )
        )
        return

    if bind.dialect.name == "sqlite":
        bind.execute(
            sa.text(
                """
                CREATE TRIGGER trg_phase5_delegation_lineage_insert
                BEFORE INSERT ON delegation_contexts_v2
                WHEN NEW.lineage_binding_version <> 1
                BEGIN
                    SELECT RAISE(ABORT, 'new delegation contexts require lineage binding version 1');
                END
                """
            )
        )
        bind.execute(
            sa.text(
                """
                CREATE TRIGGER trg_phase5_delegation_lineage_update
                BEFORE UPDATE ON delegation_contexts_v2
                WHEN NEW.parent_delegation_context_id IS NOT OLD.parent_delegation_context_id
                   OR NEW.tenant_id IS NOT OLD.tenant_id
                   OR NEW.delegation_context_id IS NOT OLD.delegation_context_id
                   OR NEW.parent_action_id IS NOT OLD.parent_action_id
                   OR NEW.delegated_action_id IS NOT OLD.delegated_action_id
                   OR NEW.lineage_binding_version IS NOT OLD.lineage_binding_version
                   OR NEW.source_principal_ref IS NOT OLD.source_principal_ref
                   OR NEW.destination_principal_ref IS NOT OLD.destination_principal_ref
                   OR NEW.authority_scope_hash IS NOT OLD.authority_scope_hash
                   OR NEW.depth IS NOT OLD.depth
                   OR NEW.expires_at IS NOT OLD.expires_at
                   OR NEW.algorithm IS NOT OLD.algorithm
                   OR NEW.signing_key_id IS NOT OLD.signing_key_id
                   OR NEW.signature IS NOT OLD.signature
                   OR NEW.signed_envelope IS NOT OLD.signed_envelope
                BEGIN
                    SELECT RAISE(ABORT, 'delegation lineage binding is immutable');
                END
                """
            )
        )
        bind.execute(
            sa.text(
                """
                CREATE TRIGGER trg_phase5_delegation_event_insert
                BEFORE INSERT ON delegation_lifecycle_events_v2
                WHEN NOT EXISTS (
                    SELECT 1 FROM delegation_contexts_v2 context
                    WHERE context.tenant_id = NEW.tenant_id
                      AND context.delegation_context_id = NEW.delegation_context_id
                      AND context.lineage_binding_version = 1
                )
                   OR NEW.algorithm IS NULL OR NEW.algorithm = ''
                   OR NEW.signing_key_id IS NULL OR NEW.signing_key_id = ''
                   OR NEW.signature IS NULL OR NEW.signature = ''
                   OR NEW.signed_envelope IS NULL OR NEW.signed_envelope IN ('{}', 'null')
                   OR NEW.observed_at IS NULL OR NEW.evidence_refs IS NULL
                   OR NEW.affected_unconsumed_descendant_refs IS NULL
                   OR (NEW.sequence = 1 AND (NEW.prior_event_id IS NOT NULL OR NEW.prior_event_hash IS NOT NULL))
                   OR (NEW.sequence > 1 AND (NEW.prior_event_id IS NULL OR NEW.prior_event_hash IS NULL))
                BEGIN
                    SELECT RAISE(ABORT, 'delegation events require a V1 context');
                END
                """
            )
        )
        bind.execute(
            sa.text(
                """
                CREATE TRIGGER trg_phase5_delegation_event_update
                BEFORE UPDATE ON delegation_lifecycle_events_v2
                BEGIN
                    SELECT RAISE(ABORT, 'delegation lifecycle events are append-only');
                END
                """
            )
        )
        bind.execute(
            sa.text(
                """
                CREATE TRIGGER trg_phase5_delegation_event_delete
                BEFORE DELETE ON delegation_lifecycle_events_v2
                BEGIN
                    SELECT RAISE(ABORT, 'delegation lifecycle events are append-only');
                END
                """
            )
        )


def _drop_immutability_guards(bind: sa.Connection) -> None:
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_phase5_delegation_event_immutable ON delegation_lifecycle_events_v2"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS phase5_delegation_event_immutable()"))
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_phase5_delegation_lineage_guard ON delegation_contexts_v2"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS phase5_delegation_lineage_guard()"))
    elif bind.dialect.name == "sqlite":
        for name in (
            "trg_phase5_delegation_event_delete",
            "trg_phase5_delegation_event_update",
            "trg_phase5_delegation_event_insert",
            "trg_phase5_delegation_lineage_update",
            "trg_phase5_delegation_lineage_insert",
        ):
            bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {name}"))


def upgrade() -> None:
    with op.batch_alter_table("delegation_contexts_v2") as batch:
        batch.add_column(sa.Column("parent_delegation_context_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("delegated_action_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("lineage_binding_version", sa.SmallInteger(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("history_head_event_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("history_head_event_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("history_head_sequence", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("reconstruction_status", sa.String(16), nullable=False, server_default="VERIFIED"))

    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            UPDATE delegation_contexts_v2
            SET lineage_binding_version = 0,
                parent_delegation_context_id = NULL,
                delegated_action_id = NULL,
                history_head_event_id = NULL,
                history_head_event_hash = NULL,
                history_head_sequence = 0,
                reconstruction_status = 'INVALID'
            """
        )
    )

    with op.batch_alter_table("delegation_contexts_v2") as batch:
        batch.create_unique_constraint(
            "uq_phase5_delegation_context_action",
            ["tenant_id", "delegation_context_id", "delegated_action_id"],
        )
        batch.create_unique_constraint(
            "uq_phase5_delegated_action_context",
            ["tenant_id", "delegated_action_id"],
        )
        batch.create_check_constraint("ck_phase5_delegation_lineage_version", "lineage_binding_version IN (0, 1)")
        batch.create_check_constraint("ck_phase5_delegation_positive_depth", "depth > 0")
        batch.create_check_constraint(
            "ck_phase5_delegation_lineage_binding",
            "(lineage_binding_version = 0 AND parent_delegation_context_id IS NULL "
            "AND delegated_action_id IS NULL AND reconstruction_status = 'INVALID') "
            "OR (lineage_binding_version = 1 AND delegated_action_id IS NOT NULL "
            "AND length(trim(delegated_action_id)) > 0 AND "
            "((parent_delegation_context_id IS NULL AND depth = 1) OR "
            "(parent_delegation_context_id IS NOT NULL AND depth > 1 "
            "AND parent_delegation_context_id <> delegation_context_id)))",
        )
        batch.create_index("ix_phase5_delegation_lineage_parent", ["tenant_id", "parent_delegation_context_id"])

    # PostgreSQL requires the referenced key to exist before it can install a
    # self-referential composite FK.  Keep this a second ALTER operation: a
    # SQLite batch rebuild otherwise masks the invalid PostgreSQL ordering.
    with op.batch_alter_table("delegation_contexts_v2") as batch:
        batch.create_foreign_key(
            "fk_phase5_delegation_parent_context",
            "delegation_contexts_v2",
            ["tenant_id", "parent_delegation_context_id", "parent_action_id"],
            ["tenant_id", "delegation_context_id", "delegated_action_id"],
            ondelete="RESTRICT",
        )

    with op.batch_alter_table("delegation_lifecycle_events_v2") as batch:
        batch.add_column(sa.Column("prior_event_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("prior_event_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("affected_unconsumed_descendant_refs", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("reason_code", sa.String(128), nullable=True))
        batch.add_column(sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("evidence_refs", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("signed_envelope", sa.JSON(), nullable=True))
        batch.drop_constraint("uq_phase5_delegation_event_idempotency", type_="unique")
        batch.create_unique_constraint(
            "uq_phase5_delegation_event_context_id",
            ["tenant_id", "delegation_context_id", "id"],
        )
        batch.create_foreign_key(
            "fk_phase5_delegation_event_prior",
            "delegation_lifecycle_events_v2",
            ["tenant_id", "delegation_context_id", "prior_event_id"],
            ["tenant_id", "delegation_context_id", "id"],
            ondelete="RESTRICT",
        )
        batch.create_unique_constraint(
            "uq_phase5_delegation_event_state_version",
            ["tenant_id", "delegation_context_id", "new_state_version"],
        )
        batch.create_unique_constraint("uq_phase5_delegation_event_idempotency", ["tenant_id", "idempotency_key"])

    _create_immutability_guards(bind)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT 1 FROM delegation_contexts_v2 WHERE lineage_binding_version = 1 LIMIT 1")).first() is not None:
        raise RuntimeError("refusing Phase 5 downgrade: V1 delegation lineage exists")
    if bind.execute(
        sa.text(
            """
            SELECT 1
            FROM delegation_lifecycle_events_v2 event
            JOIN delegation_contexts_v2 context
              ON context.tenant_id = event.tenant_id
             AND context.delegation_context_id = event.delegation_context_id
            WHERE context.lineage_binding_version = 1
            LIMIT 1
            """
        )
    ).first() is not None:
        raise RuntimeError("refusing Phase 5 downgrade: V1 delegation lifecycle events exist")

    _drop_immutability_guards(bind)
    with op.batch_alter_table("delegation_lifecycle_events_v2") as batch:
        batch.drop_constraint("uq_phase5_delegation_event_idempotency", type_="unique")
        batch.drop_constraint("uq_phase5_delegation_event_state_version", type_="unique")
        batch.drop_constraint("fk_phase5_delegation_event_prior", type_="foreignkey")
        batch.drop_constraint("uq_phase5_delegation_event_context_id", type_="unique")
        batch.create_unique_constraint(
            "uq_phase5_delegation_event_idempotency",
            ["tenant_id", "delegation_context_id", "idempotency_key"],
        )
        batch.drop_column("signed_envelope")
        batch.drop_column("evidence_refs")
        batch.drop_column("observed_at")
        batch.drop_column("reason_code")
        batch.drop_column("affected_unconsumed_descendant_refs")
        batch.drop_column("prior_event_hash")
        batch.drop_column("prior_event_id")
    with op.batch_alter_table("delegation_contexts_v2") as batch:
        batch.drop_index("ix_phase5_delegation_lineage_parent")
        batch.drop_constraint("ck_phase5_delegation_lineage_binding", type_="check")
        batch.drop_constraint("ck_phase5_delegation_positive_depth", type_="check")
        batch.drop_constraint("ck_phase5_delegation_lineage_version", type_="check")
        batch.drop_constraint("uq_phase5_delegation_context_action", type_="unique")
        batch.drop_constraint("uq_phase5_delegated_action_context", type_="unique")
        batch.drop_constraint("fk_phase5_delegation_parent_context", type_="foreignkey")
        batch.drop_column("reconstruction_status")
        batch.drop_column("history_head_sequence")
        batch.drop_column("history_head_event_hash")
        batch.drop_column("history_head_event_id")
        batch.drop_column("lineage_binding_version")
        batch.drop_column("delegated_action_id")
        batch.drop_column("parent_delegation_context_id")
