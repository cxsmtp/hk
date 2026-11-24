"""Phase 5 profile, selection, epoch, and rollout persistence only.

Revision ID: 0065_phase5_action_integrity_core
Revises: 0064_native_control_logical_action_claims
"""

from alembic import op
import sqlalchemy as sa


revision = "0065_phase5_action_integrity_core"
down_revision = "0064_native_control_logical_action_claims"
branch_labels = None
depends_on = None


_CORE_TABLES = (
    "tenant_action_integrity_rollouts",
    "tenant_policy_epochs",
    "tenant_domain_profile_selection_projections_v2",
    "tenant_domain_profile_selections",
    "domain_semantic_profiles",
)


def _create_profile_history_guards(bind: sa.Connection) -> None:
    """The profile/selection log is append-only before any later authority slice."""
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("""
            CREATE FUNCTION phase5_profile_history_immutable() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'domain semantic profile history is immutable'; END;
            $$ LANGUAGE plpgsql
        """))
        bind.execute(sa.text("""
            CREATE FUNCTION phase5_selection_history_immutable() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'domain profile selection history is immutable'; END;
            $$ LANGUAGE plpgsql
        """))
        for table, trigger, function in (
            ("domain_semantic_profiles", "trg_phase5_profile_authority_immutable", "phase5_profile_history_immutable"),
            ("tenant_domain_profile_selections", "trg_phase5_selection_authority_immutable", "phase5_selection_history_immutable"),
        ):
            bind.execute(sa.text(f"CREATE TRIGGER {trigger} BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION {function}()"))
        return
    if bind.dialect.name == "sqlite":
        for table, prefix, message in (
            ("domain_semantic_profiles", "profile", "domain semantic profile history is immutable"),
            ("tenant_domain_profile_selections", "selection", "domain profile selection history is immutable"),
        ):
            for operation in ("UPDATE", "DELETE"):
                bind.execute(sa.text(
                    f"CREATE TRIGGER trg_phase5_{prefix}_authority_immutable_{operation.lower()} "
                    f"BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, '{message}'); END"
                ))


def _drop_profile_history_guards(bind: sa.Connection) -> None:
    if bind.dialect.name == "postgresql":
        for table, trigger in (
            ("domain_semantic_profiles", "trg_phase5_profile_authority_immutable"),
            ("tenant_domain_profile_selections", "trg_phase5_selection_authority_immutable"),
        ):
            bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {trigger} ON {table}"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS phase5_profile_history_immutable()"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS phase5_selection_history_immutable()"))
    elif bind.dialect.name == "sqlite":
        for trigger in (
            "trg_phase5_profile_authority_immutable_update", "trg_phase5_profile_authority_immutable_delete",
            "trg_phase5_selection_authority_immutable_update", "trg_phase5_selection_authority_immutable_delete",
        ):
            bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {trigger}"))


def _create_projection_cas_guard(bind: sa.Connection) -> None:
    """Keep the current-head projection bound to the append-only V1 log."""
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("""
            CREATE FUNCTION phase5_profile_selection_projection_cas() RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'INSERT' THEN
                    IF NEW.current_selection_generation <> 1
                       OR NEW.current_selection_sequence <> 1
                       OR NEW.state_version <> 1
                       OR NOT EXISTS (
                            SELECT 1
                            FROM tenant_domain_profile_selections selection
                            JOIN domain_semantic_profiles profile
                              ON profile.tenant_id = selection.tenant_id
                             AND profile.profile_id = selection.profile_id
                             AND profile.version = selection.profile_version
                             AND profile.content_hash = selection.profile_content_hash
                            WHERE selection.tenant_id = NEW.tenant_id
                              AND selection.selection_id = NEW.current_selection_id
                              AND selection.selection_hash = NEW.current_selection_hash
                              AND selection.selection_generation = NEW.current_selection_generation
                              AND selection.selection_sequence = NEW.current_selection_sequence
                              AND selection.authority_binding_version = 1
                              AND selection.prior_selection_id IS NULL
                              AND selection.prior_selection_hash IS NULL
                              AND selection.profile_id = NEW.profile_id
                              AND selection.profile_version = NEW.profile_version
                              AND selection.profile_content_hash = NEW.profile_content_hash
                              AND selection.policy_epoch = NEW.policy_epoch
                              AND profile.authority_binding_version = 1
                       ) THEN
                        RAISE EXCEPTION 'profile selection projection insert must bind the first V1 selection';
                    END IF;
                ELSIF TG_OP = 'UPDATE' THEN
                    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                       OR NEW.current_selection_generation <> OLD.current_selection_generation
                       OR NEW.current_selection_sequence <> OLD.current_selection_sequence + 1
                       OR NEW.state_version <> OLD.state_version + 1
                       OR NEW.policy_epoch <= OLD.policy_epoch
                       OR NOT EXISTS (
                            SELECT 1
                            FROM tenant_domain_profile_selections selection
                            JOIN domain_semantic_profiles profile
                              ON profile.tenant_id = selection.tenant_id
                             AND profile.profile_id = selection.profile_id
                             AND profile.version = selection.profile_version
                             AND profile.content_hash = selection.profile_content_hash
                            WHERE selection.tenant_id = NEW.tenant_id
                              AND selection.selection_id = NEW.current_selection_id
                              AND selection.selection_hash = NEW.current_selection_hash
                              AND selection.selection_generation = NEW.current_selection_generation
                              AND selection.selection_sequence = NEW.current_selection_sequence
                              AND selection.authority_binding_version = 1
                              AND selection.prior_selection_id = OLD.current_selection_id
                              AND selection.prior_selection_hash = OLD.current_selection_hash
                              AND selection.profile_id = NEW.profile_id
                              AND selection.profile_version = NEW.profile_version
                              AND selection.profile_content_hash = NEW.profile_content_hash
                              AND selection.policy_epoch = NEW.policy_epoch
                              AND profile.authority_binding_version = 1
                       ) THEN
                        RAISE EXCEPTION 'profile selection projection update must compare-and-swap the exact prior head';
                    END IF;
                ELSE
                    RAISE EXCEPTION 'profile selection projections cannot be deleted';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
        """))
        bind.execute(sa.text("""
            CREATE TRIGGER trg_phase5_profile_selection_projection_cas
            BEFORE INSERT OR UPDATE OR DELETE ON tenant_domain_profile_selection_projections_v2
            FOR EACH ROW EXECUTE FUNCTION phase5_profile_selection_projection_cas()
        """))
        return
    if bind.dialect.name == "sqlite":
        bind.execute(sa.text("""
            CREATE TRIGGER trg_phase5_profile_selection_projection_cas_insert
            BEFORE INSERT ON tenant_domain_profile_selection_projections_v2
            WHEN NEW.current_selection_generation <> 1
              OR NEW.current_selection_sequence <> 1
              OR NEW.state_version <> 1
              OR NOT EXISTS (
                  SELECT 1
                  FROM tenant_domain_profile_selections AS selection
                  JOIN domain_semantic_profiles AS profile
                    ON profile.tenant_id = selection.tenant_id
                   AND profile.profile_id = selection.profile_id
                   AND profile.version = selection.profile_version
                   AND profile.content_hash = selection.profile_content_hash
                  WHERE selection.tenant_id = NEW.tenant_id
                    AND selection.selection_id = NEW.current_selection_id
                    AND selection.selection_hash = NEW.current_selection_hash
                    AND selection.selection_generation = NEW.current_selection_generation
                    AND selection.selection_sequence = NEW.current_selection_sequence
                    AND selection.authority_binding_version = 1
                    AND selection.prior_selection_id IS NULL
                    AND selection.prior_selection_hash IS NULL
                    AND selection.profile_id = NEW.profile_id
                    AND selection.profile_version = NEW.profile_version
                    AND selection.profile_content_hash = NEW.profile_content_hash
                    AND selection.policy_epoch = NEW.policy_epoch
                    AND profile.authority_binding_version = 1
              )
            BEGIN
                SELECT RAISE(ABORT, 'profile selection projection insert must bind the first V1 selection');
            END
        """))
        bind.execute(sa.text("""
            CREATE TRIGGER trg_phase5_profile_selection_projection_cas_update
            BEFORE UPDATE ON tenant_domain_profile_selection_projections_v2
            WHEN NEW.tenant_id IS NOT OLD.tenant_id
              OR NEW.current_selection_generation <> OLD.current_selection_generation
              OR NEW.current_selection_sequence <> OLD.current_selection_sequence + 1
              OR NEW.state_version <> OLD.state_version + 1
              OR NEW.policy_epoch <= OLD.policy_epoch
              OR NOT EXISTS (
                  SELECT 1
                  FROM tenant_domain_profile_selections AS selection
                  JOIN domain_semantic_profiles AS profile
                    ON profile.tenant_id = selection.tenant_id
                   AND profile.profile_id = selection.profile_id
                   AND profile.version = selection.profile_version
                   AND profile.content_hash = selection.profile_content_hash
                  WHERE selection.tenant_id = NEW.tenant_id
                    AND selection.selection_id = NEW.current_selection_id
                    AND selection.selection_hash = NEW.current_selection_hash
                    AND selection.selection_generation = NEW.current_selection_generation
                    AND selection.selection_sequence = NEW.current_selection_sequence
                    AND selection.authority_binding_version = 1
                    AND selection.prior_selection_id = OLD.current_selection_id
                    AND selection.prior_selection_hash = OLD.current_selection_hash
                    AND selection.profile_id = NEW.profile_id
                    AND selection.profile_version = NEW.profile_version
                    AND selection.profile_content_hash = NEW.profile_content_hash
                    AND selection.policy_epoch = NEW.policy_epoch
                    AND profile.authority_binding_version = 1
              )
            BEGIN
                SELECT RAISE(ABORT, 'profile selection projection update must compare-and-swap the exact prior head');
            END
        """))
        bind.execute(sa.text("""
            CREATE TRIGGER trg_phase5_profile_selection_projection_cas_delete
            BEFORE DELETE ON tenant_domain_profile_selection_projections_v2
            BEGIN
                SELECT RAISE(ABORT, 'profile selection projections cannot be deleted');
            END
        """))


def _drop_projection_cas_guard(bind: sa.Connection) -> None:
    if bind.dialect.name == "postgresql":
        bind.execute(sa.text(
            "DROP TRIGGER IF EXISTS trg_phase5_profile_selection_projection_cas "
            "ON tenant_domain_profile_selection_projections_v2"
        ))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS phase5_profile_selection_projection_cas()"))
    elif bind.dialect.name == "sqlite":
        for action in ("insert", "update", "delete"):
            bind.execute(sa.text(
                f"DROP TRIGGER IF EXISTS trg_phase5_profile_selection_projection_cas_{action}"
            ))


def create_action_integrity_core_schema() -> None:
    """Create the exact 0065 authority schema.

    The named helper lets a later migration repair the empty legacy 0065
    shape that existed before signed profile/selection lineage was added,
    without maintaining a second copy of this security-sensitive DDL.
    """
    op.create_table(
        "domain_semantic_profiles",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("profile_id", sa.String(128), nullable=False), sa.Column("version", sa.String(64), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False), sa.Column("status", sa.String(32), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False), sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True), sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("tenant_id", "profile_id", "version", name="uq_phase5_profile_version"),
        sa.UniqueConstraint("tenant_id", "profile_id", "version", "content_hash", name="uq_phase5_profile_version_content"),
        sa.CheckConstraint("authority_binding_version IN (0, 1)", name="ck_phase5_profile_binding_version"),
        sa.CheckConstraint("(authority_binding_version = 0 AND issued_at IS NULL AND signed_envelope IS NULL) OR (authority_binding_version = 1 AND issued_at IS NOT NULL AND signed_envelope IS NOT NULL AND issued_at <= effective_at AND effective_at < expires_at)", name="ck_phase5_profile_v1_complete"),
    )
    op.create_table(
        "tenant_domain_profile_selections",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("selection_id", sa.String(36), nullable=False), sa.Column("selection_hash", sa.String(64), nullable=True), sa.Column("selection_generation", sa.Integer(), nullable=False, server_default="0"), sa.Column("selection_sequence", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.String(128), nullable=False), sa.Column("profile_version", sa.String(64), nullable=False), sa.Column("profile_content_hash", sa.String(64), nullable=False),
        sa.Column("prior_selection_id", sa.String(36), nullable=True), sa.Column("prior_selection_hash", sa.String(64), nullable=True), sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False, server_default="0"), sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True), sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True), sa.Column("selected_by_principal_ref", sa.String(255), nullable=True), sa.Column("reason_code", sa.String(128), nullable=True),
        sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "profile_id", "profile_version", "profile_content_hash"], ["domain_semantic_profiles.tenant_id", "domain_semantic_profiles.profile_id", "domain_semantic_profiles.version", "domain_semantic_profiles.content_hash"], name="fk_phase5_selection_profile_content", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "prior_selection_id", "prior_selection_hash", "selection_generation"], ["tenant_domain_profile_selections.tenant_id", "tenant_domain_profile_selections.selection_id", "tenant_domain_profile_selections.selection_hash", "tenant_domain_profile_selections.selection_generation"], name="fk_phase5_selection_prior_hash", ondelete="RESTRICT"),
        sa.UniqueConstraint("tenant_id", "selection_id", name="uq_phase5_selection_id"), sa.UniqueConstraint("tenant_id", "selection_id", "selection_hash", name="uq_phase5_selection_id_hash"), sa.UniqueConstraint("tenant_id", "selection_id", "selection_hash", "selection_generation", name="uq_phase5_selection_id_hash_generation"), sa.UniqueConstraint("tenant_id", "selection_id", "selection_hash", "selection_generation", "selection_sequence", name="uq_phase5_selection_id_hash_generation_sequence"), sa.UniqueConstraint("tenant_id", "selection_generation", "selection_sequence", name="uq_phase5_selection_generation_sequence"), sa.UniqueConstraint("tenant_id", "selection_generation", "prior_selection_id", name="uq_phase5_selection_prior_id"),
        sa.CheckConstraint("authority_binding_version IN (0, 1)", name="ck_phase5_selection_binding_version"), sa.CheckConstraint("selection_sequence > 0", name="ck_phase5_selection_positive_sequence_0069"), sa.CheckConstraint("policy_epoch > 0", name="ck_phase5_selection_positive_epoch_0069"), sa.CheckConstraint("selection_generation IN (0, 1)", name="ck_phase5_selection_generation"), sa.CheckConstraint("(authority_binding_version = 0 AND selection_generation = 0 AND issued_at IS NULL AND effective_at IS NULL AND expires_at IS NULL AND selected_by_principal_ref IS NULL AND reason_code IS NULL AND signed_envelope IS NULL AND selection_hash IS NULL) OR (authority_binding_version = 1 AND selection_generation = 1 AND issued_at IS NOT NULL AND effective_at IS NOT NULL AND expires_at IS NOT NULL AND selected_by_principal_ref IS NOT NULL AND reason_code IS NOT NULL AND signed_envelope IS NOT NULL AND selection_hash IS NOT NULL AND issued_at <= effective_at AND effective_at < expires_at)", name="ck_phase5_selection_v1_complete"), sa.CheckConstraint("(selection_sequence = 1 AND prior_selection_id IS NULL AND prior_selection_hash IS NULL) OR (selection_sequence > 1 AND prior_selection_id IS NOT NULL AND prior_selection_hash IS NOT NULL)", name="ck_phase5_selection_prior_shape"),
    )
    op.create_table(
        "tenant_domain_profile_selection_projections_v2",
        sa.Column("tenant_id", sa.String(36), primary_key=True), sa.Column("current_selection_id", sa.String(36), nullable=False), sa.Column("current_selection_hash", sa.String(64), nullable=False), sa.Column("current_selection_generation", sa.Integer(), nullable=False, server_default="1"), sa.Column("current_selection_sequence", sa.Integer(), nullable=False), sa.Column("profile_id", sa.String(128), nullable=False), sa.Column("profile_version", sa.String(64), nullable=False), sa.Column("profile_content_hash", sa.String(64), nullable=False), sa.Column("policy_epoch", sa.Integer(), nullable=False), sa.Column("state_version", sa.Integer(), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "current_selection_id", "current_selection_hash", "current_selection_generation", "current_selection_sequence"], ["tenant_domain_profile_selections.tenant_id", "tenant_domain_profile_selections.selection_id", "tenant_domain_profile_selections.selection_hash", "tenant_domain_profile_selections.selection_generation", "tenant_domain_profile_selections.selection_sequence"], name="fk_phase5_current_profile_selection_head", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "profile_id", "profile_version", "profile_content_hash"], ["domain_semantic_profiles.tenant_id", "domain_semantic_profiles.profile_id", "domain_semantic_profiles.version", "domain_semantic_profiles.content_hash"], name="fk_phase5_current_profile_selection_profile", ondelete="RESTRICT"),
        sa.CheckConstraint("current_selection_sequence > 0", name="ck_phase5_current_selection_positive_sequence"), sa.CheckConstraint("current_selection_generation = 1", name="ck_phase5_current_selection_generation"), sa.CheckConstraint("policy_epoch > 0", name="ck_phase5_current_selection_positive_epoch"), sa.CheckConstraint("state_version > 0", name="ck_phase5_current_selection_positive_state_version"),
    )
    op.create_table("tenant_policy_epochs", sa.Column("tenant_id", sa.String(36), primary_key=True), sa.Column("epoch", sa.Integer(), nullable=False), sa.Column("current_policy_snapshot_id", sa.String(64), nullable=True), sa.Column("material_policy_digest", sa.String(64), nullable=True), sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"), sa.Column("updated_by_principal_ref", sa.String(255), nullable=True), sa.Column("reason_code", sa.String(128), nullable=True), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.CheckConstraint("epoch > 0", name="ck_phase5_policy_epoch_positive"), sa.CheckConstraint("state_version > 0", name="ck_phase5_policy_epoch_positive_state_version"), sa.CheckConstraint("(epoch = 1 AND state_version = 1 AND current_policy_snapshot_id IS NULL AND material_policy_digest IS NULL AND updated_by_principal_ref IS NULL AND reason_code IS NULL) OR (epoch > 1 AND state_version = epoch AND current_policy_snapshot_id IS NOT NULL AND material_policy_digest IS NOT NULL AND updated_by_principal_ref IS NOT NULL AND reason_code IS NOT NULL)", name="ck_phase5_policy_epoch_audit_complete"))
    op.create_table("tenant_action_integrity_rollouts", sa.Column("tenant_id", sa.String(36), primary_key=True), sa.Column("mode", sa.String(32), nullable=False, server_default="DISABLED"), sa.Column("policy_epoch", sa.Integer(), nullable=False), sa.Column("profile_selection_id", sa.String(36), nullable=True), sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.CheckConstraint("mode IN ('DISABLED','OBSERVE','SHADOW','AUTHORITATIVE')", name="ck_phase5_rollout_mode"), sa.CheckConstraint("policy_epoch > 0", name="ck_phase5_rollout_positive_epoch"))
    bind = op.get_bind()
    _create_profile_history_guards(bind)
    _create_projection_cas_guard(bind)


def upgrade() -> None:
    create_action_integrity_core_schema()


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table in _CORE_TABLES:
        if inspector.has_table(table) and bind.execute(sa.text(f'SELECT 1 FROM "{table}" LIMIT 1')).first() is not None:
            raise RuntimeError(f"refusing Phase 5 downgrade: rollout authority data exists in {table}")
    _drop_projection_cas_guard(bind)
    _drop_profile_history_guards(bind)
    for table in _CORE_TABLES:
        op.drop_table(table)
