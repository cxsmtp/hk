from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import UniqueConstraint, create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.models.action_integrity import PersistentEffectV2


def test_phase5_migrations_are_linear_and_keep_unknown_backfills() -> None:
    root = Path(__file__).resolve().parents[1]
    migrations = root / "app/db/migrations/versions"
    core = (migrations / "0065_phase5_action_integrity_core.py").read_text()
    lifecycle = (migrations / "0066_phase5_execution_lifecycle.py").read_text()
    coverage = (migrations / "0067_phase5_control_coverage.py").read_text()

    assert 'down_revision = "0064_native_control_logical_action_claims"' in core
    assert 'down_revision = "0065_phase5_action_integrity_core"' in lifecycle
    assert 'down_revision = "0066_phase5_execution_lifecycle"' in coverage
    assert "tenant_action_integrity_rollouts" in core
    assert 'sa.Column("selection_id", sa.String(36), nullable=False)' in core
    assert 'sa.Column("prior_selection_hash", sa.String(64), nullable=True)' in core
    assert 'sa.Column("state_version", sa.Integer(), nullable=False' in core
    assert 'sa.Column("signing_key_id", sa.String(64), nullable=False)' in core
    assert "decision_receipt_v2_extensions" in lifecycle
    assert "execution_permits_v2" in lifecycle
    assert 'sa.Column("permit_id", sa.String(36), primary_key=True)' in lifecycle
    assert 'sa.Column("action_id", sa.String(64), nullable=False)' in lifecycle
    assert 'sa.Column("canonical_action_hash", sa.String(64), nullable=False)' in lifecycle
    assert 'sa.Column("material_fields_hash", sa.String(64), nullable=False)' in lifecycle
    assert 'sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False)' in lifecycle
    assert "decision_receipt_v2_extensions" in lifecycle
    assert "approval_binding_v2_extensions" in lifecycle
    assert "approval_authority_events_v2" in lifecycle
    assert "approval_authority_projections_v2" in lifecycle
    assert "uq_phase5_approval_idempotency" in lifecycle
    assert "ck_phase5_approval_positive_epoch" in lifecycle
    assert 'batch.add_column(sa.Column("decision_version"' in lifecycle
    assert 'batch.add_column(sa.Column("authority_schema_version"' in lifecycle
    assert "_refuse_downgrade_when_authority_exists" in lifecycle
    assert "_id_table" not in lifecycle
    assert "action_integrity_detail_projections" not in lifecycle
    assert "action_integrity_detail_projections" in coverage
    assert "control_coverage_v2_projections" not in coverage
    assert "subject_binding" in coverage
    assert "outcome_verification" in coverage


def test_phase5_delegation_lineage_migration_is_additive_and_fail_closed() -> None:
    root = Path(__file__).resolve().parents[1]
    lineage = (root / "app/db/migrations/versions/0068_phase5_delegation_lineage.py").read_text()

    assert 'down_revision = "0067_phase5_control_coverage"' in lineage
    assert 'parent_delegation_context_id' in lineage
    assert 'delegated_action_id' in lineage
    assert 'parent_action_id' in lineage
    assert 'lineage_binding_version' in lineage
    assert 'history_head_event_id' in lineage
    assert 'history_head_event_hash' in lineage
    assert 'history_head_sequence' in lineage
    assert 'reconstruction_status' in lineage
    assert 'prior_event_id' in lineage
    assert 'prior_event_hash' in lineage
    assert 'affected_unconsumed_descendant_refs' in lineage
    assert 'uq_phase5_delegation_event_state_version' in lineage
    assert 'uq_phase5_delegation_context_action' in lineage
    assert 'uq_phase5_delegated_action_context' in lineage
    assert 'uq_phase5_delegation_event_context_id' in lineage
    assert 'uq_phase5_delegation_event_idempotency' in lineage
    assert 'fk_phase5_delegation_parent_context' in lineage
    assert 'fk_phase5_delegation_event_prior' in lineage
    assert 'lineage_binding_version = 1 AND delegated_action_id IS NOT NULL' in lineage
    assert 'depth = 1' in lineage
    assert 'sa.Column("affected_unconsumed_descendant_refs", sa.JSON(), nullable=True)' in lineage
    assert 'sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True)' in lineage
    assert 'sa.Column("evidence_refs", sa.JSON(), nullable=True)' in lineage
    assert 'sa.Column("signed_envelope", sa.JSON(), nullable=True)' in lineage
    assert 'new delegation events require complete signed fields' in lineage
    assert 'delegation lifecycle events are append-only' in lineage
    assert 'NEW.signed_envelope::jsonb IS DISTINCT FROM OLD.signed_envelope::jsonb' in lineage
    assert 'refusing Phase 5 downgrade' in lineage
    # PostgreSQL requires the referenced composite key before the self-FK can
    # be installed.  Keep the migration order explicit rather than relying on
    # a SQLite batch-table rebuild to hide it.
    assert lineage.index('"uq_phase5_delegation_context_action"') < lineage.index(
        '"fk_phase5_delegation_parent_context"'
    )


def test_phase5_0069_authority_bindings_are_additive_and_fail_closed() -> None:
    root = Path(__file__).resolve().parents[1]
    core = (root / "app/db/migrations/versions/0065_phase5_action_integrity_core.py").read_text()
    migration = (root / "app/db/migrations/versions/0069_phase5_stored_authority.py").read_text()

    assert 'revision = "0069_phase5_stored_authority"' in migration
    assert 'down_revision = "0068_phase5_delegation_lineage"' in migration
    for table in (
        "domain_semantic_profiles",
        "tenant_domain_profile_selections",
        "tenant_domain_profile_selection_projections_v2",
        "decision_receipt_v2_extensions",
        "execution_permits_v2",
    ):
        assert table in migration
    assert 'sa.Column("authority_binding_version", sa.SmallInteger(), nullable=False' in migration
    assert 'sa.Column("selection_hash", sa.String(64), nullable=True)' in migration
    assert 'sa.Column("selection_generation", sa.Integer(), nullable=False' in migration
    assert 'sa.Column("current_selection_generation", sa.Integer(), nullable=False)' in migration
    assert '"selection_generation", "selection_sequence"' in migration
    assert 'sa.Column("control_selection_id", sa.String(64), nullable=True)' in migration
    assert 'sa.Column("authoritative_decision", sa.String(32), nullable=True)' in migration
    assert "fk_phase5_decision_profile_selection" in migration
    assert "fk_phase5_permit_decision_extension" in migration
    assert migration.index("uq_phase5_decision_extension_tenant_receipt") < migration.index(
        "fk_phase5_approval_request_decision_extension"
    )
    assert "trg_native_control_selections_immutable" in migration
    # 0065 owns the full profile/selection/projection lineage, including the
    # CAS guard.  A 0069 downgrade must therefore never remove it.
    assert "phase5_profile_selection_projection_cas" in core
    assert "def _create_projection_cas_guard" in core
    assert "def _drop_projection_cas_guard" in core
    assert "def _create_projection_cas_guard" not in migration
    assert "def _drop_projection_cas_guard" not in migration
    assert "_require_0065_lineage_contract" in migration
    assert "_repair_empty_legacy_0065_lineage_contract" in migration
    assert "refusing Phase 5 legacy 0065 repair" in migration
    assert "create_action_integrity_core_schema" in migration
    assert "refusing Phase 5 downgrade" in migration


def test_phase5_0069_orm_models_expose_the_stored_authority_bindings() -> None:
    from app.db.models.action_integrity import (
        DecisionReceiptV2Extension,
        DomainSemanticProfileV2,
        ExecutionPermitV2,
        TenantDomainProfileSelectionProjectionV2,
        TenantDomainProfileSelectionV2,
    )

    assert DomainSemanticProfileV2.__tablename__ == "domain_semantic_profiles"
    assert TenantDomainProfileSelectionV2.__tablename__ == "tenant_domain_profile_selections"
    assert TenantDomainProfileSelectionProjectionV2.__tablename__ == "tenant_domain_profile_selection_projections_v2"
    for model in (DomainSemanticProfileV2, TenantDomainProfileSelectionV2):
        assert "authority_binding_version" in model.__table__.c
        assert "signed_envelope" in model.__table__.c
    assert "selection_generation" in TenantDomainProfileSelectionV2.__table__.c
    assert "current_selection_generation" in TenantDomainProfileSelectionProjectionV2.__table__.c
    for model in (DecisionReceiptV2Extension, ExecutionPermitV2):
        assert {"authority_binding_version", "profile_selection_id", "profile_selection_hash", "control_selection_id", "control_plan_id", "authoritative_decision", "authority_status", "decision_version"} <= set(model.__table__.c.keys())


def test_fresh_phase5_schema_keeps_persistent_effect_tenant_identity_unique(
    tmp_path, monkeypatch,
) -> None:
    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5-effects.sqlite3'}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        api_root / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    try:
        database_constraints = {
            constraint["name"]: tuple(constraint["column_names"])
            for constraint in inspect(engine).get_unique_constraints("persistent_effects_v2")
        }
    finally:
        engine.dispose()
    model_constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in PersistentEffectV2.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    expected = ("tenant_id", "id")
    assert database_constraints["uq_phase5_effect_tenant_id"] == expected
    assert model_constraints["uq_phase5_effect_tenant_id"] == expected


def test_phase5_0069_keeps_legacy_v0_selection_history_and_starts_a_fresh_v1_generation(
    tmp_path, monkeypatch,
) -> None:
    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5-selection-generations.sqlite3'}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        api_root / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0068_phase5_delegation_lineage")

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys=ON"))
            connection.execute(text("INSERT INTO tenants (id, name, slug, is_active) VALUES ('tenant-generation', 'Generation', 'tenant-generation', 1)"))
            connection.execute(text("""
                INSERT INTO domain_semantic_profiles
                (id, tenant_id, profile_id, version, content_hash, status, content, effective_at, expires_at, algorithm, signing_key_id, signature)
                VALUES ('legacy-profile-row', 'tenant-generation', 'profile:legacy', '0', :profile_hash, 'reviewed', '{}',
                        '2026-08-24T00:00:00+00:00', '2026-08-25T00:00:00+00:00', 'HS256', 'legacy', :signature)
            """), {"profile_hash": "a" * 64, "signature": "s" * 43})
            connection.execute(text("""
                INSERT INTO tenant_domain_profile_selections
                (id, tenant_id, selection_id, selection_sequence, profile_id, profile_version, profile_content_hash,
                 prior_selection_id, prior_selection_hash, policy_epoch, algorithm, signing_key_id, signature)
                VALUES ('legacy-selection-row', 'tenant-generation', 'legacy-selection', 1, 'profile:legacy', '0', :profile_hash,
                        NULL, NULL, 1, 'HS256', 'legacy', :signature)
            """), {"profile_hash": "a" * 64, "signature": "s" * 43})
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys=ON"))
            legacy = connection.execute(text("""
                SELECT authority_binding_version, selection_generation, selection_sequence, selection_hash
                FROM tenant_domain_profile_selections WHERE selection_id = 'legacy-selection'
            """)).one()
            assert legacy == (0, 0, 1, None)
            connection.execute(text("""
                INSERT INTO domain_semantic_profiles
                (id, tenant_id, profile_id, version, content_hash, status, content, authority_binding_version,
                 issued_at, effective_at, expires_at, algorithm, signing_key_id, signature, signed_envelope)
                VALUES ('fresh-profile-row', 'tenant-generation', 'profile:fresh', '1', :profile_hash, 'reviewed', '{}', 1,
                        '2026-08-24T00:00:00+00:00', '2026-08-24T00:00:00+00:00', '2026-08-25T00:00:00+00:00',
                        'HS256', 'fresh', :signature, '{}')
            """), {"profile_hash": "b" * 64, "signature": "t" * 43})
            connection.execute(text("""
                INSERT INTO tenant_domain_profile_selections
                (id, tenant_id, selection_id, selection_hash, selection_generation, selection_sequence,
                 profile_id, profile_version, profile_content_hash, prior_selection_id, prior_selection_hash, policy_epoch,
                 authority_binding_version, issued_at, effective_at, expires_at, selected_by_principal_ref, reason_code,
                 algorithm, signing_key_id, signature, signed_envelope)
                VALUES ('fresh-selection-row', 'tenant-generation', 'fresh-selection', :selection_hash, 1, 1,
                        'profile:fresh', '1', :profile_hash, NULL, NULL, 2, 1,
                        '2026-08-24T00:00:00+00:00', '2026-08-24T00:00:00+00:00', '2026-08-25T00:00:00+00:00',
                        'user:owner', 'migration-acceptance', 'HS256', 'fresh', :signature, '{}')
            """), {"profile_hash": "b" * 64, "selection_hash": "c" * 64, "signature": "t" * 43})
            connection.execute(text("""
                INSERT INTO tenant_domain_profile_selection_projections_v2
                (tenant_id, current_selection_id, current_selection_hash, current_selection_generation,
                 current_selection_sequence, profile_id, profile_version, profile_content_hash, policy_epoch, state_version)
                VALUES ('tenant-generation', 'fresh-selection', :selection_hash, 1, 1,
                        'profile:fresh', '1', :profile_hash, 2, 1)
            """), {"profile_hash": "b" * 64, "selection_hash": "c" * 64})
            with pytest.raises(IntegrityError, match="compare-and-swap"):
                connection.execute(text("""
                    UPDATE tenant_domain_profile_selection_projections_v2
                    SET current_selection_sequence = 3, state_version = 2
                    WHERE tenant_id = 'tenant-generation'
                """))
            generations = connection.execute(text("""
                SELECT selection_generation, selection_sequence
                FROM tenant_domain_profile_selections
                WHERE tenant_id = 'tenant-generation'
                ORDER BY selection_generation, selection_sequence
            """)).all()
            assert generations == [(0, 1), (1, 1)]
    finally:
        engine.dispose()

    # 0069 must leave the 0065-owned V1 lineage and its projection CAS guard
    # intact when it is removed.  This counterexample uses real V1 profile,
    # selection, and projection rows and then verifies the guard still blocks
    # a forged current-head update at the 0068 schema level.
    command.downgrade(config, "0068_phase5_delegation_lineage")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            preserved = connection.execute(text("""
                SELECT current_selection_id, current_selection_sequence, state_version
                FROM tenant_domain_profile_selection_projections_v2
                WHERE tenant_id = 'tenant-generation'
            """)).one()
            assert preserved == ("fresh-selection", 1, 1)
            with pytest.raises(IntegrityError, match="compare-and-swap"):
                connection.execute(text("""
                    UPDATE tenant_domain_profile_selection_projections_v2
                    SET current_selection_sequence = 3, state_version = 2
                    WHERE tenant_id = 'tenant-generation'
                """))
    finally:
        engine.dispose()


def test_fresh_phase5_lineage_schema_rejects_legacy_writes_and_mutable_bindings(
    tmp_path, monkeypatch,
) -> None:
    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5-lineage.sqlite3'}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        api_root / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    context_columns = (
        "id, tenant_id, delegation_context_id, parent_action_id, parent_delegation_context_id, "
        "delegated_action_id, lineage_binding_version, source_principal_ref, destination_principal_ref, "
        "authority_scope_hash, depth, state, state_version, history_head_event_id, history_head_event_hash, "
        "history_head_sequence, reconstruction_status, expires_at, algorithm, signing_key_id, signature, signed_envelope"
    )
    context_values = (
        ":id, 'tenant-lineage-ddl', :context_id, :parent_action_id, NULL, :delegated_action_id, 1, "
        "'agent:root', 'agent:child', :scope_hash, 1, 'REGISTERED', 0, NULL, NULL, 0, 'VERIFIED', "
        "'2026-08-25T00:00:00+00:00', 'HS256', 'lineage', :signature, :signed_envelope"
    )
    try:
        with engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys=ON"))
            connection.execute(text("INSERT INTO tenants (id, name, slug, is_active) VALUES ('tenant-lineage-ddl', 'Lineage', 'tenant-lineage-ddl', 1)"))
            connection.execute(
                text(f"INSERT INTO delegation_contexts_v2 ({context_columns}) VALUES ({context_values})"),
                {
                    "id": "root-row",
                    "context_id": "root-context",
                    "parent_action_id": "root-action",
                    "delegated_action_id": "root-delegated-action",
                    "scope_hash": "a" * 64,
                    "signature": "s" * 43,
                    "signed_envelope": "{\"schema_version\":\"2.1\"}",
                },
            )
        with pytest.raises(IntegrityError, match="lineage binding version 1"):
            with engine.begin() as connection:
                connection.execute(
                    text(f"INSERT INTO delegation_contexts_v2 ({context_columns}) VALUES ({context_values.replace(', 1, ', ', 0, ')})"),
                    {
                        "id": "legacy-row",
                        "context_id": "legacy-context",
                        "parent_action_id": "legacy-action",
                        "delegated_action_id": "legacy-delegated-action",
                        "scope_hash": "b" * 64,
                        "signature": "s" * 43,
                        "signed_envelope": "{\"schema_version\":\"2.1\"}",
                    },
                )
        with pytest.raises(IntegrityError, match="delegation lineage binding is immutable"):
            with engine.begin() as connection:
                connection.execute(text("UPDATE delegation_contexts_v2 SET delegated_action_id = 'mutated' WHERE delegation_context_id = 'root-context'"))
        with pytest.raises(IntegrityError, match="delegation events require a V1 context"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        INSERT INTO delegation_lifecycle_events_v2
                        (id, tenant_id, delegation_context_id, sequence, event_type, from_state, to_state,
                         prior_state_version, new_state_version, idempotency_key, algorithm, signing_key_id, signature)
                        VALUES
                        ('event-missing-signed', 'tenant-lineage-ddl', 'root-context', 1, 'ISSUED', 'REGISTERED', 'ACTIVE',
                         0, 1, 'event-missing-signed', 'HS256', 'lineage', 'sssssssssssssssssssssssssssssssssssssssssss')
                        """
                    )
                )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="refusing Phase 5 downgrade"):
        command.downgrade(config, "0067_phase5_control_coverage")


def test_populated_phase5_core_refuses_downgrade(tmp_path, monkeypatch) -> None:
    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5-downgrade.sqlite3'}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        api_root / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0065_phase5_action_integrity_core")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO tenants (id, name, slug, is_active) VALUES ('tenant-phase5', 'Phase 5', 'phase5-downgrade', 1)"))
            connection.execute(text("INSERT INTO tenant_action_integrity_rollouts (tenant_id, mode, policy_epoch, state_version) VALUES ('tenant-phase5', 'AUTHORITATIVE', 1, 1)"))
    finally:
        engine.dispose()
    with pytest.raises(RuntimeError, match="refusing Phase 5 downgrade"):
        command.downgrade(config, "0064_native_control_logical_action_claims")
