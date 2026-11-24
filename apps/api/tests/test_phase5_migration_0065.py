from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from app.core.config import settings


def test_0065_creates_only_core_authority_tables_with_epoch_audit_columns(tmp_path, monkeypatch) -> None:
    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5-0065.sqlite3'}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(api_root / "app/db/migrations", clean_migrations, ignore=shutil.ignore_patterns("._*", "__pycache__"))
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0065_phase5_action_integrity_core")

    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert {
            "domain_semantic_profiles", "tenant_domain_profile_selections",
            "tenant_domain_profile_selection_projections_v2", "tenant_policy_epochs",
            "tenant_action_integrity_rollouts",
        } <= tables
        assert "decision_receipt_v2_extensions" not in tables
        epoch_columns = {column["name"] for column in inspector.get_columns("tenant_policy_epochs")}
        assert {
            "tenant_id", "epoch", "current_policy_snapshot_id", "material_policy_digest",
            "state_version", "updated_by_principal_ref", "reason_code", "updated_at",
        } <= epoch_columns
        assert {"authority_binding_version", "issued_at", "signed_envelope"} <= {
            column["name"] for column in inspector.get_columns("domain_semantic_profiles")
        }
        assert {
            "authority_binding_version", "issued_at", "effective_at", "expires_at",
            "selected_by_principal_ref", "reason_code", "signed_envelope",
            "selection_hash", "selection_generation",
        } <= {column["name"] for column in inspector.get_columns("tenant_domain_profile_selections")}
        with engine.connect() as connection:
            trigger_names = {
                row[0] for row in connection.execute(
                    text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
                )
            }
        assert {
            "trg_phase5_profile_authority_immutable_update",
            "trg_phase5_profile_authority_immutable_delete",
            "trg_phase5_selection_authority_immutable_update",
            "trg_phase5_selection_authority_immutable_delete",
            "trg_phase5_profile_selection_projection_cas_insert",
            "trg_phase5_profile_selection_projection_cas_update",
            "trg_phase5_profile_selection_projection_cas_delete",
        } <= trigger_names
        with engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys=ON"))
            connection.execute(text("INSERT INTO tenants (id, name, slug, is_active) VALUES ('tenant-a', 'Tenant A', 'tenant-a-0065', 1)"))
            connection.execute(text("INSERT INTO tenant_policy_epochs (tenant_id, epoch) VALUES ('tenant-a', 1)"))
            assert connection.execute(text("SELECT state_version FROM tenant_policy_epochs WHERE tenant_id = 'tenant-a'")).scalar_one() == 1
            connection.execute(text("""
                INSERT INTO domain_semantic_profiles
                (id, tenant_id, profile_id, version, content_hash, status, content, effective_at, expires_at, algorithm, signing_key_id, signature)
                VALUES ('profile-history', 'tenant-a', 'profile-a', '0', :digest, 'reviewed', '{}',
                        '2026-08-24T00:00:00+00:00', '2027-08-24T00:00:00+00:00', 'HS256', 'legacy', :signature)
            """), {"digest": "a" * 64, "signature": "s" * 43})
            connection.execute(text("""
                INSERT INTO tenant_domain_profile_selections
                (id, tenant_id, selection_id, selection_hash, selection_generation, selection_sequence,
                 profile_id, profile_version, profile_content_hash, prior_selection_id, prior_selection_hash,
                 policy_epoch, authority_binding_version, algorithm, signing_key_id, signature)
                VALUES ('selection-history', 'tenant-a', 'selection-a', NULL, 0, 1,
                        'profile-a', '0', :digest, NULL, NULL, 1, 0, 'HS256', 'legacy', :signature)
            """), {"digest": "a" * 64, "signature": "s" * 43})
            with connection.begin_nested(), pytest.raises(IntegrityError, match="immutable"):
                connection.execute(text("UPDATE domain_semantic_profiles SET status = 'retired' WHERE id = 'profile-history'"))
            with connection.begin_nested(), pytest.raises(IntegrityError, match="immutable"):
                connection.execute(text("DELETE FROM tenant_domain_profile_selections WHERE id = 'selection-history'"))
            with connection.begin_nested(), pytest.raises(IntegrityError):
                connection.execute(text("""
                    INSERT INTO tenant_domain_profile_selections
                    (id, tenant_id, selection_id, selection_hash, selection_generation, selection_sequence,
                     profile_id, profile_version, profile_content_hash, prior_selection_id, prior_selection_hash,
                     policy_epoch, authority_binding_version, algorithm, signing_key_id, signature)
                    VALUES ('selection-invalid-fk', 'tenant-a', 'selection-invalid', NULL, 0, 1,
                            'profile-missing', '0', :digest, NULL, NULL, 1, 0, 'HS256', 'legacy', :signature)
                """), {"digest": "a" * 64, "signature": "s" * 43})
            with connection.begin_nested(), pytest.raises(IntegrityError):
                connection.execute(text("""
                    INSERT INTO tenant_domain_profile_selections
                    (id, tenant_id, selection_id, selection_hash, selection_generation, selection_sequence,
                     profile_id, profile_version, profile_content_hash, prior_selection_id, prior_selection_hash,
                     policy_epoch, authority_binding_version, algorithm, signing_key_id, signature)
                    VALUES ('selection-duplicate', 'tenant-a', 'selection-a', NULL, 0, 1,
                            'profile-a', '0', :digest, NULL, NULL, 1, 0, 'HS256', 'legacy', :signature)
                """), {"digest": "a" * 64, "signature": "s" * 43})
            with connection.begin_nested(), pytest.raises(IntegrityError, match="first V1 selection"):
                connection.execute(text("""
                    INSERT INTO tenant_domain_profile_selection_projections_v2
                    (tenant_id, current_selection_id, current_selection_hash, current_selection_generation,
                     current_selection_sequence, profile_id, profile_version, profile_content_hash,
                     policy_epoch, state_version)
                    VALUES ('tenant-a', 'selection-a', :selection_hash, 1, 1,
                            'profile-a', '0', :digest, 1, 1)
                """), {"digest": "a" * 64, "selection_hash": "b" * 64})
            with connection.begin_nested(), pytest.raises(IntegrityError):
                connection.execute(text("DELETE FROM tenants WHERE id = 'tenant-a'"))
    finally:
        engine.dispose()


def test_orm_create_all_rejects_incomplete_v1_profile_authority() -> None:
    from app.db.models.action_integrity import DomainSemanticProfileV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with engine.begin() as connection:
            connection.execute(text("PRAGMA foreign_keys=ON"))
            connection.execute(text(
                "INSERT INTO tenants "
                "(id, name, slug, is_active, platform_mode, "
                "user_visibility_full_content_reveal_enabled, "
                "user_visibility_prompt_retention_days) "
                "VALUES ('tenant-orm', 'ORM', 'tenant-orm-0065', 1, "
                "'enforce', 0, 0)"
            ))
            with pytest.raises(IntegrityError):
                connection.execute(DomainSemanticProfileV2.__table__.insert().values(
                    id="profile-v1-invalid", tenant_id="tenant-orm", profile_id="profile", version="1",
                    content_hash="a" * 64, status="reviewed", content={}, authority_binding_version=1,
                    issued_at=None,
                    effective_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
                    expires_at=datetime(2027, 8, 24, tzinfo=timezone.utc),
                    algorithm="ES256", signing_key_id="key", signature="A" * 86, signed_envelope={},
                ))
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
