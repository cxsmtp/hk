from __future__ import annotations

from datetime import datetime, timezone
from importlib import import_module
import json
import logging
from pathlib import Path
import shutil

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlValidation,
    deployment_acceptance_state_from_db,
    deployment_acceptance_state_to_db,
    runtime_location_from_db,
    runtime_location_to_db,
)
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.core.config import settings
from app.services.native_control.contracts import (
    DeploymentAcceptanceState,
    RuntimeLocation,
)
from app.services import receipt_service


NOW = datetime(2026, 8, 20, tzinfo=timezone.utc)
REAL_ACCEPTANCE_STATES = {
    "REAL_BINARY_ACCEPTED",
    "REAL_ENTERPRISE_TENANT_ACCEPTED",
    "REAL_CLOUD_RUNTIME_ACCEPTED",
}


def _profile() -> ControlCapabilityProfileRecord:
    return ControlCapabilityProfileRecord(
        manifest_id="openai:codex_cli:native_hook",
        manifest_version="provider-control-contract/1.0",
        matrix_version="matrix-phase4",
        provider="openai",
        product="codex_cli",
        runtime="codex_cli_local",
        integration_method="native_hook",
        adapter_version="1.0.0",
        tested_min_version="0.137.0",
        tested_max_version="0.137.0",
        current_verified_version="0.137.0",
        verification_status="experimental",
        verification_source="test",
        verified_at=None,
        capabilities={},
        security_properties={},
        health_requirements=[],
        degradation_modes=["fail_closed"],
        known_blind_spots=[],
        documentation_references=["test"],
        supported_action_classes=["FUNCTION_TOOL"],
        supported_control_methods=["native_hook"],
        contract_hash="a" * 64,
        manifest_fingerprint="b" * 64,
        active=True,
    )


def _integration(tenant_id: str, profile_id: str) -> NativeControlIntegration:
    return NativeControlIntegration(
        tenant_id=tenant_id,
        capability_profile_id=profile_id,
        instance_key="codex-local",
        display_name="Codex local",
        provider="openai",
        product="codex_cli",
        model_provider="openai",
        model="gpt-test-1",
        runtime="codex_cli_local",
        execution_location="LOCAL_ENDPOINT",
        deployment_reference="device:trusted-mac",
        integration_method="native_hook",
        deployment_family="endpoint",
        environment="production",
        state="monitoring",
        mode="monitor",
        health_state="policy_stale",
        health_reasons=["policy_expired"],
        provider_version="0.137.0",
        adapter_version="1.0.0",
        contract_hash="a" * 64,
        configuration_fingerprint=None,
        expected_configuration_fingerprint=None,
        policy_version=None,
        policy_fresh_until=None,
        degradation_mode="fail_closed",
        capability_snapshot={},
        known_blind_spots=[],
    )


def _validation(tenant_id: str, integration_id: str, **overrides: object) -> NativeControlValidation:
    values: dict[str, object] = {
        "tenant_id": tenant_id,
        "integration_instance_id": integration_id,
        "validation_version": "native-control-validation/2.0",
        "credential_id": "credential-1",
        "credential_epoch": 1,
        "safe_synthetic": False,
        "acceptance_state": "REAL_BINARY_ACCEPTED",
        "deployment_environment": "production",
        "provider": "openai",
        "product": "codex_cli",
        "runtime": "codex_cli_local",
        "model_provider": "openai",
        "model": "gpt-test-1",
        "route_identity": "native-control:test-route",
        "deployment_identity": "integration:test-deployment",
        "execution_location": "LOCAL_ENDPOINT",
        "deployment_reference": "device:trusted-mac",
        "action_classes": ["FUNCTION_TOOL"],
        "control_methods": ["native_hook"],
        "lifecycle_events": ["pre_tool_use"],
        "provider_version": "0.137.0",
        "adapter_version": "1.0.0",
        "contract_hash": "a" * 64,
        "acceptance_run_id": "acceptance-run-1",
        "allow_result": "passed",
        "block_result": "passed",
        "non_execution_result": "passed",
        "checks": {"allow": True, "block": True, "non_execution": True},
        "result": "passed",
        "reason_codes": [],
        "evidence_refs": ["evidence:acceptance-run-1"],
        "validated_at": NOW,
    }
    values.update(overrides)
    return NativeControlValidation(**values)


_RAW_VALIDATION_INSERT = text(
    "INSERT INTO native_control_validations ("
    "id, tenant_id, integration_instance_id, validation_version, credential_id, credential_epoch, "
    "safe_synthetic, acceptance_state, deployment_environment, provider, product, runtime, "
    "model_provider, model, route_identity, deployment_identity, "
    "execution_location, deployment_reference, action_classes, control_methods, lifecycle_events, "
    "provider_version, adapter_version, contract_hash, acceptance_run_id, allow_result, block_result, "
    "non_execution_result, checks, result, reason_codes, evidence_refs"
    ") VALUES ("
    ":id, :tenant_id, :integration_instance_id, :validation_version, :credential_id, :credential_epoch, "
    ":safe_synthetic, :acceptance_state, :deployment_environment, :provider, :product, :runtime, "
    ":model_provider, :model, :route_identity, :deployment_identity, "
    ":execution_location, :deployment_reference, :action_classes, :control_methods, :lifecycle_events, "
    ":provider_version, :adapter_version, :contract_hash, :acceptance_run_id, :allow_result, :block_result, "
    ":non_execution_result, :checks, :result, :reason_codes, :evidence_refs"
    ")"
)


def _raw_validation_values(
    tenant_id: str,
    integration_id: str,
    validation_id: str,
    **overrides: object,
) -> dict[str, object]:
    values: dict[str, object] = {
        "id": validation_id,
        "tenant_id": tenant_id,
        "integration_instance_id": integration_id,
        "validation_version": "native-control-validation/2.0",
        "credential_id": f"credential-{validation_id}",
        "credential_epoch": 1,
        "safe_synthetic": False,
        "acceptance_state": "REAL_BINARY_ACCEPTED",
        "deployment_environment": "production",
        "provider": "openai",
        "product": "codex_cli",
        "runtime": "codex_cli_local",
        "model_provider": "openai",
        "model": "gpt-test-1",
        "route_identity": "native-control:test-route",
        "deployment_identity": "integration:test-deployment",
        "execution_location": "LOCAL_ENDPOINT",
        "deployment_reference": "device:trusted-mac",
        "action_classes": ["FUNCTION_TOOL"],
        "control_methods": ["native_hook"],
        "lifecycle_events": ["pre_tool_use"],
        "provider_version": "0.137.0",
        "adapter_version": "1.0.0",
        "contract_hash": "a" * 64,
        "acceptance_run_id": f"acceptance-run-{validation_id}",
        "allow_result": "passed",
        "block_result": "passed",
        "non_execution_result": "passed",
        "checks": {"allow": True, "block": True, "non_execution": True},
        "result": "passed",
        "reason_codes": [],
        "evidence_refs": ["evidence:acceptance-run"],
    }
    values.update(overrides)
    for field in (
        "action_classes",
        "control_methods",
        "lifecycle_events",
        "checks",
        "reason_codes",
        "evidence_refs",
    ):
        values[field] = json.dumps(values[field], separators=(",", ":"))
    return values


REAL_VALIDATION_SCOPE_REJECTIONS = (
    ("deployment_environment", " \t "),
    ("provider", " UNKNOWN "),
    ("product", "  "),
    ("runtime", " unknown "),
    ("model_provider", " unknown "),
    ("model", " unknown "),
    ("route_identity", " unknown "),
    ("deployment_identity", " unknown "),
    ("deployment_reference", " \n "),
    ("acceptance_run_id", " unknown "),
    ("provider_version", None),
    ("provider_version", " \tUNKNOWN\n "),
    ("adapter_version", " \t "),
    ("action_classes", "FUNCTION_TOOL"),
    ("control_methods", []),
    ("lifecycle_events", [1]),
    ("evidence_refs", [" \t "]),
    ("action_classes", ["x" * 257]),
    ("evidence_refs", ["x" * 1025]),
    ("execution_location", "CUSTOMER_RUNTIME"),
    ("acceptance_state", "REAL_ENTERPRISE_TENANT_ACCEPTED"),
    ("acceptance_state", "REAL_CLOUD_RUNTIME_ACCEPTED"),
)


def test_phase4_models_persist_exact_acceptance_scope_and_distinct_health_states() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Phase 4 acceptance", slug="phase4-acceptance")
        db.add(tenant)
        db.flush()
        profile = _profile()
        db.add(profile)
        db.flush()
        integration = _integration(tenant.id, profile.id)
        db.add(integration)
        db.flush()
        validation = _validation(tenant.id, integration.id)
        db.add(validation)
        db.commit()

        assert integration.health_state == "policy_stale"
        assert validation.acceptance_state == "REAL_BINARY_ACCEPTED"
        assert validation.runtime == "codex_cli_local"
        assert validation.action_classes == ["FUNCTION_TOOL"]
        assert validation.control_methods == ["native_hook"]
        assert validation.allow_result == "passed"
        assert validation.block_result == "passed"
        assert validation.non_execution_result == "passed"

        for health_state in ("healthy", "degraded", "not_installed", "unknown"):
            integration.health_state = health_state
            db.flush()
            assert integration.health_state == health_state
    engine.dispose()


def test_real_acceptance_cannot_be_inferred_from_safe_synthetic_validation() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Phase 4 synthetic", slug="phase4-synthetic")
        db.add(tenant)
        db.flush()
        profile = _profile()
        db.add(profile)
        db.flush()
        integration = _integration(tenant.id, profile.id)
        db.add(integration)
        db.flush()
        db.add(_validation(tenant.id, integration.id, safe_synthetic=True))
        with pytest.raises((IntegrityError, ValueError)):
            db.flush()
    engine.dispose()


def test_real_acceptance_requires_complete_scope_evidence_and_explicit_results() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Phase 4 incomplete", slug="phase4-incomplete")
        db.add(tenant)
        db.flush()
        profile = _profile()
        db.add(profile)
        db.flush()
        integration = _integration(tenant.id, profile.id)
        db.add(integration)
        db.flush()
        db.add(
            _validation(
                tenant.id,
                integration.id,
                acceptance_run_id=None,
                non_execution_result="not_tested",
            )
        )
        with pytest.raises((IntegrityError, ValueError)):
            db.flush()
    engine.dispose()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("result", "partial"),
        ("allow_result", "failed"),
        ("block_result", "not_applicable"),
        ("non_execution_result", "failed"),
        ("provider_version", None),
        ("provider_version", ""),
        ("adapter_version", "unknown"),
        ("adapter_version", " UNKNOWN "),
        ("evidence_refs", ["evidence:" + ("x" * 8192)]),
    ),
)
def test_real_acceptance_requires_passed_proof_versions_and_bounded_evidence(
    field: str,
    value: object,
) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name=f"Phase 4 real {field}", slug=f"phase4-real-{field}")
        db.add(tenant)
        db.flush()
        profile = _profile()
        db.add(profile)
        db.flush()
        integration = _integration(tenant.id, profile.id)
        db.add(integration)
        db.flush()
        db.add(
            _validation(
                tenant.id,
                integration.id,
                acceptance_run_id=f"acceptance-run-{field}",
                **{field: value},
            )
        )
        with pytest.raises((IntegrityError, ValueError)):
            db.flush()
    engine.dispose()


@pytest.mark.parametrize(("field", "value"), REAL_VALIDATION_SCOPE_REJECTIONS)
def test_real_acceptance_scope_is_normalized_and_strictly_typed_in_orm(
    field: str,
    value: object,
) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name=f"Phase 4 ORM {field}", slug=f"phase4-orm-{field}")
        db.add(tenant)
        db.flush()
        profile = _profile()
        db.add(profile)
        db.flush()
        integration = _integration(tenant.id, profile.id)
        db.add(integration)
        db.flush()
        overrides = {"acceptance_run_id": f"orm-scope-{field}"}
        overrides[field] = value
        db.add(
            _validation(
                tenant.id,
                integration.id,
                **overrides,
            )
        )
        with pytest.raises(ValueError, match="native_control_validation_real_scope_invalid"):
            db.flush()
    engine.dispose()


def test_base_metadata_direct_sql_rejects_invalid_scope_and_uppercase_hash() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Phase 4 raw", slug="phase4-raw")
        db.add(tenant)
        db.flush()
        profile = _profile()
        db.add(profile)
        db.flush()
        integration = _integration(tenant.id, profile.id)
        db.add(integration)
        db.commit()

        with pytest.raises(IntegrityError):
            db.execute(
                _RAW_VALIDATION_INSERT,
                _raw_validation_values(
                    tenant.id,
                    integration.id,
                    "raw-scalar",
                    action_classes="FUNCTION_TOOL",
                ),
            )
        db.rollback()
        for contract_hash in ("A" * 64, "z" * 64):
            with pytest.raises(IntegrityError):
                db.execute(
                    text(
                        "UPDATE control_capability_profiles SET contract_hash = :contract_hash "
                        "WHERE id = :profile_id"
                    ),
                    {"contract_hash": contract_hash, "profile_id": profile.id},
                )
            db.rollback()
    engine.dispose()


def test_native_control_integration_cannot_self_assert_acceptance_state() -> None:
    assert "acceptance_state" not in NativeControlIntegration.__table__.c


def test_native_control_acceptance_and_runtime_enums_round_trip_through_database_values() -> None:
    for state in DeploymentAcceptanceState:
        assert deployment_acceptance_state_from_db(
            deployment_acceptance_state_to_db(state)
        ) is state
    for location in RuntimeLocation:
        assert runtime_location_from_db(runtime_location_to_db(location)) is location


def test_contract_hash_orm_validation_matches_database_hex_rule() -> None:
    with pytest.raises(ValueError, match="contract_hash_invalid"):
        _profile().contract_hash = "A" * 64


def test_native_control_validation_is_append_only_for_orm_mutations() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        tenant = Tenant(name="Phase 4 immutable", slug="phase4-immutable")
        db.add(tenant)
        db.flush()
        profile = _profile()
        db.add(profile)
        db.flush()
        integration = _integration(tenant.id, profile.id)
        db.add(integration)
        db.flush()
        validation = _validation(tenant.id, integration.id)
        db.add(validation)
        db.commit()

        validation.result = "failed"
        with pytest.raises(ValueError, match="native_control_validation_append_only"):
            db.flush()
        db.rollback()

        validation = db.get(NativeControlValidation, validation.id)
        assert validation is not None
        db.delete(validation)
        with pytest.raises(ValueError, match="native_control_validation_append_only"):
            db.flush()
    engine.dispose()


def test_phase4_migration_declares_linear_acceptance_and_health_corrections() -> None:
    migration = import_module(
        "app.db.migrations.versions.0062_provider_control_fabric"
    )
    assert migration.revision == "0062_provider_control_fabric"
    assert migration.down_revision == "0061_autonomous_discovery_verification"
    assert set(migration.ACCEPTANCE_STATES) == {
        *REAL_ACCEPTANCE_STATES,
        "SYNTHETIC_ONLY",
        "DOCS_ONLY",
        "NOT_TESTED",
    }
    assert {"policy_stale", "not_installed", "unknown"} <= set(migration.HEALTH_STATES)
    source = Path(migration.__file__).read_text(encoding="utf-8")
    assert "safe_synthetic = true" in source
    assert "SYNTHETIC_ONLY" in source
    assert "NOT_TESTED" in source
    assert "ck_native_integration_health" in source
    assert "_create_validation_immutability_triggers" in source
    assert "REAL_VALIDATION_SCOPE_TEXT_FIELDS" in source
    assert "result = 'passed'" in source
    assert "_create_validation_scope_guards" in source
    assert "ck_native_validation_real_state_location" in source


def test_0062_upgrade_backfills_legacy_validation_truth_without_claiming_real_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_path = tmp_path / "phase4-acceptance.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"
    api_root = Path(__file__).resolve().parents[1]
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

    receipt_logger = logging.getLogger(receipt_service.__name__)
    receipt_logger.disabled = False
    command.upgrade(config, "0061_autonomous_discovery_verification")
    assert receipt_logger.disabled is False
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            tenant_id = "00000000-0000-0000-0000-000000000062"
            connection.execute(
                text(
                    "INSERT INTO tenants (id, name, slug, is_active, platform_mode) "
                    "VALUES (:tenant_id, 'Phase 4 migration', 'phase4-migration', true, 'enforce')"
                ),
                {"tenant_id": tenant_id},
            )
            connection.execute(
                text(
                    "INSERT INTO native_control_integrations ("
                    "id, tenant_id, instance_key, display_name, provider, product, "
                    "integration_method, deployment_family, environment, state, mode, "
                    "health_state, health_reasons, adapter_version, degradation_mode, "
                    "capability_snapshot, known_blind_spots) VALUES ("
                    ":id, :tenant_id, 'legacy', 'Legacy', 'openai', 'codex_cli', "
                    "'native_hook', 'endpoint', 'production', 'monitoring', 'monitor', "
                    "'unverified', '[]', '1.0.0', 'fail_closed', '{}', '[]')"
                ),
                {"id": "00000000-0000-0000-0000-000000000062", "tenant_id": tenant_id},
            )
            for suffix, safe_synthetic in (("a", True), ("b", False)):
                connection.execute(
                    text(
                        "INSERT INTO native_control_validations ("
                        "id, tenant_id, integration_instance_id, validation_version, "
                        "credential_id, credential_epoch, safe_synthetic, checks, result, "
                        "reason_codes, evidence_refs) VALUES ("
                        ":id, :tenant_id, :integration_id, '1.0', :credential_id, 1, "
                        ":safe_synthetic, '{}', 'passed', '[]', '[\"evidence:legacy\"]')"
                    ),
                    {
                        "id": f"00000000-0000-0000-0000-00000000006{suffix}",
                        "tenant_id": tenant_id,
                        "integration_id": "00000000-0000-0000-0000-000000000062",
                        "credential_id": f"credential-{suffix}",
                        "safe_synthetic": safe_synthetic,
                    },
                )

        command.upgrade(config, "0062_provider_control_fabric")
        with engine.begin() as connection:
            rows = connection.execute(
                text(
                    "SELECT acceptance_state, deployment_environment, provider, product, "
                    "runtime, provider_version, adapter_version "
                    "FROM native_control_validations ORDER BY credential_id"
                )
            ).mappings().all()
            assert [row["acceptance_state"] for row in rows] == [
                "SYNTHETIC_ONLY",
                "NOT_TESTED",
            ]
            assert all(row["deployment_environment"] == "production" for row in rows)
            assert all(row["provider"] == "openai" for row in rows)
            assert all(row["product"] == "codex_cli" for row in rows)
            assert all(row["runtime"] == "unknown" for row in rows)
            assert all(row["provider_version"] is None for row in rows)
            assert all(row["adapter_version"] == "1.0.0" for row in rows)
            integration_columns = {
                row[1]
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(native_control_integrations)"
                )
            }
            assert "acceptance_state" not in integration_columns

            for index, (field, value) in enumerate(REAL_VALIDATION_SCOPE_REJECTIONS):
                validation_id = f"00000000-0000-0000-0000-{index + 100:012d}"
                with pytest.raises(IntegrityError):
                    connection.execute(
                        _RAW_VALIDATION_INSERT,
                        _raw_validation_values(
                            tenant_id,
                            "00000000-0000-0000-0000-000000000062",
                            validation_id,
                            **{field: value},
                        ),
                    )

            connection.execute(
                text(
                    "UPDATE native_control_integrations SET health_state = 'policy_stale' "
                    "WHERE instance_key = 'legacy'"
                )
            )
            assert connection.execute(
                text(
                    "SELECT health_state FROM native_control_integrations "
                    "WHERE instance_key = 'legacy'"
                )
            ).scalar_one() == "policy_stale"
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "UPDATE native_control_integrations SET health_state = 'not-a-health-state' "
                        "WHERE instance_key = 'legacy'"
                    )
                )
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "UPDATE native_control_integrations SET contract_hash = :contract_hash "
                        "WHERE instance_key = 'legacy'"
                    ),
                    {"contract_hash": "A" * 64},
                )
            with pytest.raises(IntegrityError, match="immutable_table:native_control_validations"):
                connection.execute(
                    text(
                        "UPDATE native_control_validations SET validation_version = 'mutated' "
                        "WHERE credential_id = 'credential-a'"
                    )
                )
            with pytest.raises(IntegrityError, match="immutable_table:native_control_validations"):
                connection.execute(
                    text(
                        "DELETE FROM native_control_validations "
                        "WHERE credential_id = 'credential-a'"
                    )
                )

        command.downgrade(config, "0061_autonomous_discovery_verification")
        with engine.connect() as connection:
            columns = {
                row[1]
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(native_control_validations)"
                )
            }
            assert "acceptance_state" not in columns
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == "0061_autonomous_discovery_verification"
    finally:
        engine.dispose()
