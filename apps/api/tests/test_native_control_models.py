from __future__ import annotations

from sqlalchemy import create_engine, inspect

from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlHealthObservation,
    NativeControlReplay,
    NativeControlSelection,
    NativeControlValidation,
    NativeWorkloadCredential,
)
from app.db.session import Base


TABLES = {
    "control_capability_profiles",
    "native_control_integrations",
    "native_control_health_observations",
    "native_workload_credentials",
    "native_control_validations",
    "native_control_replays",
    "native_control_selections",
}


def test_native_control_tables_are_registered() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    assert TABLES.issubset(set(inspect(engine).get_table_names()))
    engine.dispose()


def test_tenant_records_have_composite_identity_and_replay_uniqueness() -> None:
    tenant_tables = (
        NativeControlIntegration.__table__,
        NativeControlHealthObservation.__table__,
        NativeWorkloadCredential.__table__,
        NativeControlValidation.__table__,
        NativeControlReplay.__table__,
        NativeControlSelection.__table__,
    )
    assert all("tenant_id" in table.c for table in tenant_tables)
    names = {
        constraint.name
        for table in tenant_tables
        for constraint in table.constraints
        if constraint.name
    }
    assert "uq_native_integration_tenant_id" in names
    assert "uq_native_replay_tenant_event" in names
    assert "uq_native_replay_tenant_nonce" in names
    assert "uq_native_selection_tenant_id" in names
    assert "uq_native_health_tenant_provider_event" in names


def test_security_state_columns_are_closed_and_private_keys_are_absent() -> None:
    check_names = {
        constraint.name
        for table in (ControlCapabilityProfileRecord.__table__, NativeControlIntegration.__table__)
        for constraint in table.constraints
        if constraint.name
    }
    assert "ck_control_profile_verification_status" in check_names
    assert "ck_native_integration_state" in check_names
    assert "ck_native_integration_mode" in check_names
    assert "ck_native_integration_health" in check_names
    assert "private_key" not in NativeWorkloadCredential.__table__.c
    assert "secret" not in NativeWorkloadCredential.__table__.c
