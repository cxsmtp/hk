from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

from sqlalchemy import Boolean, CheckConstraint, DDL, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, UniqueConstraint, event, func
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base
from app.services.native_control.contracts import (
    DeploymentAcceptanceState,
    RuntimeLocation,
)


DEPLOYMENT_ACCEPTANCE_STATE_DB_VALUES = {
    DeploymentAcceptanceState.REAL_BINARY_ACCEPTED: "REAL_BINARY_ACCEPTED",
    DeploymentAcceptanceState.REAL_ENTERPRISE_TENANT_ACCEPTED: "REAL_ENTERPRISE_TENANT_ACCEPTED",
    DeploymentAcceptanceState.REAL_CLOUD_RUNTIME_ACCEPTED: "REAL_CLOUD_RUNTIME_ACCEPTED",
    DeploymentAcceptanceState.SYNTHETIC_ONLY: "SYNTHETIC_ONLY",
    DeploymentAcceptanceState.DOCS_ONLY: "DOCS_ONLY",
    DeploymentAcceptanceState.NOT_TESTED: "NOT_TESTED",
}
RUNTIME_LOCATION_DB_VALUES = {
    RuntimeLocation.LOCAL_ENDPOINT: "LOCAL_ENDPOINT",
    RuntimeLocation.CUSTOMER_RUNTIME: "CUSTOMER_RUNTIME",
    RuntimeLocation.CUSTOMER_CLOUD: "CUSTOMER_CLOUD",
    RuntimeLocation.PROVIDER_HOSTED: "PROVIDER_HOSTED",
    RuntimeLocation.REMOTE_AGENT: "REMOTE_AGENT",
    RuntimeLocation.MIXED: "MIXED",
    RuntimeLocation.UNKNOWN: "UNKNOWN",
}
_DEPLOYMENT_ACCEPTANCE_STATE_FROM_DB = {
    value: state for state, value in DEPLOYMENT_ACCEPTANCE_STATE_DB_VALUES.items()
}
_RUNTIME_LOCATION_FROM_DB = {
    value: location for location, value in RUNTIME_LOCATION_DB_VALUES.items()
}


def deployment_acceptance_state_to_db(state: DeploymentAcceptanceState) -> str:
    return DEPLOYMENT_ACCEPTANCE_STATE_DB_VALUES[state]


def deployment_acceptance_state_from_db(value: str) -> DeploymentAcceptanceState:
    return _DEPLOYMENT_ACCEPTANCE_STATE_FROM_DB[value]


def runtime_location_to_db(location: RuntimeLocation) -> str:
    return RUNTIME_LOCATION_DB_VALUES[location]


def runtime_location_from_db(value: str) -> RuntimeLocation:
    return _RUNTIME_LOCATION_FROM_DB[value]


ACCEPTANCE_STATES = tuple(DEPLOYMENT_ACCEPTANCE_STATE_DB_VALUES.values())
REAL_ACCEPTANCE_STATES = ACCEPTANCE_STATES[:3]
NATIVE_INTEGRATION_HEALTH_STATES = (
    "healthy",
    "degraded",
    "unhealthy",
    "unverified",
    "version_mismatch",
    "tampered",
    "policy_stale",
    "not_installed",
    "unknown",
)
EXECUTION_LOCATIONS = tuple(RUNTIME_LOCATION_DB_VALUES.values())
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_REAL_ACCEPTANCE_RUNTIME_LOCATIONS = {
    "REAL_BINARY_ACCEPTED": frozenset({"LOCAL_ENDPOINT"}),
    "REAL_ENTERPRISE_TENANT_ACCEPTED": frozenset({"PROVIDER_HOSTED", "REMOTE_AGENT"}),
    "REAL_CLOUD_RUNTIME_ACCEPTED": frozenset(
        {"CUSTOMER_RUNTIME", "CUSTOMER_CLOUD", "MIXED"}
    ),
}
_REAL_VALIDATION_SCOPE_TEXT_FIELDS = (
    "deployment_environment",
    "provider",
    "product",
    "runtime",
    "model_provider",
    "model",
    "route_identity",
    "deployment_identity",
    "deployment_reference",
    "acceptance_run_id",
    "provider_version",
    "adapter_version",
)
_REAL_VALIDATION_ARRAY_LIMITS = {
    "action_classes": 256,
    "control_methods": 256,
    "lifecycle_events": 256,
    "evidence_refs": 1024,
}


def _strict_hash_check_sql(column: str) -> str:
    remaining = column
    for character in "0123456789abcdef":
        remaining = f"replace({remaining}, '{character}', '')"
    return (
        f"{column} IS NULL OR (length({column}) = 64 AND {column} = lower({column}) "
        f"AND length({remaining}) = 0)"
    )


def _known_scope_text_check_sql(column: str) -> str:
    return (
        f"{column} IS NOT NULL AND trim({column}) <> '' "
        f"AND lower(trim({column})) <> 'unknown'"
    )


def _real_acceptance_location_check_sql() -> str:
    allowed = " OR ".join(
        "(acceptance_state = "
        f"'{state}' AND execution_location IN ({','.join(repr(location) for location in locations)}))"
        for state, locations in _REAL_ACCEPTANCE_RUNTIME_LOCATIONS.items()
    )
    return f"acceptance_state NOT IN ({','.join(repr(state) for state in REAL_ACCEPTANCE_STATES)}) OR ({allowed})"


def _real_validation_scope_check_sql() -> str:
    text_fields = " AND ".join(
        _known_scope_text_check_sql(field)
        for field in _REAL_VALIDATION_SCOPE_TEXT_FIELDS
    )
    arrays = " AND ".join(
        f"length(CAST({field} AS TEXT)) > 2"
        for field in _REAL_VALIDATION_ARRAY_LIMITS
    )
    return (
        f"acceptance_state NOT IN ({','.join(repr(state) for state in REAL_ACCEPTANCE_STATES)}) OR ("
        f"safe_synthetic = false AND {text_fields} AND execution_location <> 'UNKNOWN' "
        f"AND contract_hash IS NOT NULL AND {arrays} "
        "AND result = 'passed' AND allow_result = 'passed' AND block_result = 'passed' "
        "AND non_execution_result = 'passed')"
    )


def _scope_text_is_known(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.strip().lower() != "unknown"


def _real_validation_scope_is_valid(validation: "NativeControlValidation") -> bool:
    if validation.acceptance_state not in REAL_ACCEPTANCE_STATES:
        return True
    if validation.safe_synthetic is not False:
        return False
    if any(
        not _scope_text_is_known(getattr(validation, field))
        for field in _REAL_VALIDATION_SCOPE_TEXT_FIELDS
    ):
        return False
    allowed_locations = _REAL_ACCEPTANCE_RUNTIME_LOCATIONS.get(
        validation.acceptance_state,
        frozenset(),
    )
    if validation.execution_location not in allowed_locations:
        return False
    if validation.result != "passed" or any(
        getattr(validation, field) != "passed"
        for field in ("allow_result", "block_result", "non_execution_result")
    ):
        return False
    for field, maximum in _REAL_VALIDATION_ARRAY_LIMITS.items():
        values = getattr(validation, field)
        if not isinstance(values, list) or not values:
            return False
        if any(
            not isinstance(value, str)
            or not value.strip()
            or len(value) > maximum
            or any(character in value for character in "\r\n\x00")
            for value in values
        ):
            return False
    return _SHA256_HEX.fullmatch(validation.contract_hash or "") is not None


def _sqlite_whitespace_stripped(expression: str) -> str:
    return (
        "trim(replace(replace(replace(coalesce("
        f"{expression}, ''), char(9), ''), char(10), ''), char(13), ''))"
    )


def _sqlite_scope_text_invalid(expression: str) -> str:
    normalized = _sqlite_whitespace_stripped(expression)
    return f"length({normalized}) = 0 OR lower({normalized}) = 'unknown'"


def _sqlite_scope_array_invalid(column: str, maximum: int) -> str:
    return (
        f"json_valid(NEW.{column}) = 0 OR json_type(NEW.{column}) <> 'array' "
        f"OR json_array_length(NEW.{column}) = 0 OR EXISTS ("
        f"SELECT 1 FROM json_each(NEW.{column}) "
        f"WHERE type <> 'text' OR length({_sqlite_whitespace_stripped('value')}) = 0 "
        f"OR length(value) > {maximum})"
    )


def _sqlite_real_validation_scope_guard_sql() -> str:
    invalid_text = " OR ".join(
        _sqlite_scope_text_invalid(f"NEW.{field}")
        for field in _REAL_VALIDATION_SCOPE_TEXT_FIELDS
    )
    invalid_arrays = " OR ".join(
        _sqlite_scope_array_invalid(field, maximum)
        for field, maximum in _REAL_VALIDATION_ARRAY_LIMITS.items()
    )
    location_match = _real_acceptance_location_check_sql().replace(
        "acceptance_state", "NEW.acceptance_state"
    ).replace("execution_location", "NEW.execution_location")
    return (
        f"({invalid_text}) OR ({invalid_arrays}) "
        "OR NEW.safe_synthetic <> 0 OR NEW.result <> 'passed' "
        "OR NEW.allow_result <> 'passed' OR NEW.block_result <> 'passed' "
        "OR NEW.non_execution_result <> 'passed' "
        "OR NEW.contract_hash IS NULL "
        f"OR NOT ({location_match})"
    )


def _validate_contract_hash(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise ValueError("contract_hash_invalid")
    return value


class ControlCapabilityProfileRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "control_capability_profiles"
    __table_args__ = (
        UniqueConstraint("manifest_id", "manifest_version", name="uq_control_profile_manifest_version"),
        CheckConstraint(
            "verification_status IN ('verified','experimental','unverified','broken','removed')",
            name="ck_control_profile_verification_status",
        ),
        CheckConstraint(
            _strict_hash_check_sql("contract_hash"),
            name="ck_control_profile_contract_hash",
        ),
        CheckConstraint(
            "length(CAST(supported_action_classes AS TEXT)) <= 8192",
            name="ck_control_profile_action_classes_bytes",
        ),
        CheckConstraint(
            "length(CAST(supported_control_methods AS TEXT)) <= 8192",
            name="ck_control_profile_control_methods_bytes",
        ),
        Index("idx_control_profile_provider_product", "provider", "product"),
        Index("idx_control_profile_matrix", "matrix_version"),
    )

    manifest_id: Mapped[str] = mapped_column(String(255), nullable=False)
    manifest_version: Mapped[str] = mapped_column(String(64), nullable=False)
    matrix_version: Mapped[str] = mapped_column(String(96), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    runtime: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    integration_method: Mapped[str] = mapped_column(String(64), nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(64), nullable=False)
    tested_min_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tested_max_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_verified_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_source: Mapped[str] = mapped_column(String(512), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    capabilities: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    security_properties: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    health_requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    degradation_modes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    known_blind_spots: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    documentation_references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    supported_action_classes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    supported_control_methods: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    contract_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manifest_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    active: Mapped[bool] = mapped_column(nullable=False, default=True)

    @validates("contract_hash")
    def _validate_contract_hash_value(self, _key: str, value: str | None) -> str | None:
        return _validate_contract_hash(value)


class NativeControlIntegration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "native_control_integrations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_native_integration_tenant_id"),
        UniqueConstraint(
            "tenant_id", "provider", "product", "environment", "instance_key",
            name="uq_native_integration_tenant_instance",
        ),
        CheckConstraint(
            "state IN ('discovered','configuring','validating','monitoring','enforcing','degraded','unhealthy','disabled','unsupported')",
            name="ck_native_integration_state",
        ),
        CheckConstraint("mode IN ('discover','monitor','enforce')", name="ck_native_integration_mode"),
        CheckConstraint(
            "health_state IN ('healthy','degraded','unhealthy','unverified','version_mismatch','tampered',"
            "'policy_stale','not_installed','unknown')",
            name="ck_native_integration_health",
        ),
        CheckConstraint(
            "execution_location IN ('LOCAL_ENDPOINT','CUSTOMER_RUNTIME','CUSTOMER_CLOUD',"
            "'PROVIDER_HOSTED','REMOTE_AGENT','MIXED','UNKNOWN')",
            name="ck_native_integration_execution_location",
        ),
        CheckConstraint(
            _strict_hash_check_sql("contract_hash"),
            name="ck_native_integration_contract_hash",
        ),
        Index("idx_native_integration_tenant_state", "tenant_id", "state"),
        Index("idx_native_integration_tenant_provider", "tenant_id", "provider", "product"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    capability_profile_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_capability_profiles.id", ondelete="RESTRICT"), nullable=True
    )
    deployment_surface_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    instance_key: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    model_provider: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    model: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    runtime: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    execution_location: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    deployment_reference: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    integration_method: Mapped[str] = mapped_column(String(64), nullable=False)
    deployment_family: Mapped[str] = mapped_column(String(32), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="discovered")
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="discover")
    health_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
    health_reasons: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    provider_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    adapter_version: Mapped[str] = mapped_column(String(64), nullable=False)
    contract_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    configuration_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expected_configuration_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_fresh_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    degradation_mode: Mapped[str] = mapped_column(String(64), nullable=False, default="fail_closed")
    capability_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    known_blind_spots: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @validates("contract_hash")
    def _validate_contract_hash_value(self, _key: str, value: str | None) -> str | None:
        return _validate_contract_hash(value)


class NativeWorkloadCredential(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "native_workload_credentials"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_credential_tenant_integration",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "credential_id", name="uq_native_credential_tenant_id"),
        UniqueConstraint(
            "tenant_id", "integration_instance_id", "credential_epoch",
            name="uq_native_credential_tenant_epoch",
        ),
        CheckConstraint("status IN ('active','rotating','revoked','expired')", name="ck_native_credential_status"),
        Index("idx_native_credential_tenant_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    integration_instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    credential_id: Mapped[str] = mapped_column(String(128), nullable=False)
    credential_epoch: Mapped[int] = mapped_column(nullable=False)
    public_key_pem: Mapped[str] = mapped_column(String(2048), nullable=False)
    key_thumbprint: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="ES256")
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    allowed_event_types: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)


class NativeControlValidation(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "native_control_validations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_validation_tenant_integration",
            ondelete="CASCADE",
        ),
        CheckConstraint("result IN ('passed','failed','partial','unknown')", name="ck_native_validation_result"),
        CheckConstraint(
            "acceptance_state IN ('REAL_BINARY_ACCEPTED','REAL_ENTERPRISE_TENANT_ACCEPTED',"
            "'REAL_CLOUD_RUNTIME_ACCEPTED','SYNTHETIC_ONLY','DOCS_ONLY','NOT_TESTED')",
            name="ck_native_validation_acceptance_state",
        ),
        CheckConstraint(
            "execution_location IN ('LOCAL_ENDPOINT','CUSTOMER_RUNTIME','CUSTOMER_CLOUD',"
            "'PROVIDER_HOSTED','REMOTE_AGENT','MIXED','UNKNOWN')",
            name="ck_native_validation_execution_location",
        ),
        CheckConstraint(
            "allow_result IN ('passed','failed','not_tested','not_applicable') "
            "AND block_result IN ('passed','failed','not_tested','not_applicable') "
            "AND non_execution_result IN ('passed','failed','not_tested','not_applicable')",
            name="ck_native_validation_acceptance_results",
        ),
        CheckConstraint(
            "acceptance_state NOT IN ('REAL_BINARY_ACCEPTED','REAL_ENTERPRISE_TENANT_ACCEPTED',"
            "'REAL_CLOUD_RUNTIME_ACCEPTED') OR safe_synthetic = false",
            name="ck_native_validation_real_not_synthetic",
        ),
        CheckConstraint(
            _real_validation_scope_check_sql(),
            name="ck_native_validation_real_scope",
        ),
        CheckConstraint(
            _strict_hash_check_sql("contract_hash"),
            name="ck_native_validation_contract_hash",
        ),
        CheckConstraint(
            _real_acceptance_location_check_sql(),
            name="ck_native_validation_real_state_location",
        ),
        CheckConstraint(
            "length(CAST(action_classes AS TEXT)) <= 8192 "
            "AND length(CAST(control_methods AS TEXT)) <= 8192 "
            "AND length(CAST(lifecycle_events AS TEXT)) <= 8192 "
            "AND length(CAST(evidence_refs AS TEXT)) <= 8192",
            name="ck_native_validation_scope_bytes",
        ),
        UniqueConstraint(
            "tenant_id", "integration_instance_id", "acceptance_run_id",
            name="uq_native_validation_tenant_acceptance_run",
        ),
        Index("idx_native_validation_tenant_time", "tenant_id", "validated_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    integration_instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    validation_version: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_id: Mapped[str] = mapped_column(String(128), nullable=False)
    credential_epoch: Mapped[int] = mapped_column(nullable=False)
    safe_synthetic: Mapped[bool] = mapped_column(nullable=False, default=True)
    acceptance_state: Mapped[str] = mapped_column(String(40), nullable=False, default="NOT_TESTED")
    deployment_environment: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    product: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    runtime: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    model_provider: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    model: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    route_identity: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    deployment_identity: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    execution_location: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    deployment_reference: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    action_classes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    control_methods: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    lifecycle_events: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    provider_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    adapter_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    contract_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acceptance_run_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    allow_result: Mapped[str] = mapped_column(String(16), nullable=False, default="not_tested")
    block_result: Mapped[str] = mapped_column(String(16), nullable=False, default="not_tested")
    non_execution_result: Mapped[str] = mapped_column(String(16), nullable=False, default="not_tested")
    checks: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    reason_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    @validates("contract_hash")
    def _validate_contract_hash_value(self, _key: str, value: str | None) -> str | None:
        return _validate_contract_hash(value)


@event.listens_for(NativeControlValidation, "before_insert")
def _validate_native_control_validation_before_insert(
    _mapper: object,
    _connection: object,
    target: NativeControlValidation,
) -> None:
    if not _real_validation_scope_is_valid(target):
        raise ValueError("native_control_validation_real_scope_invalid")


@event.listens_for(NativeControlValidation, "before_update")
def _prevent_native_control_validation_update(_mapper: object, _connection: object, _target: object) -> None:
    raise ValueError("native_control_validation_append_only")


@event.listens_for(NativeControlValidation, "before_delete")
def _prevent_native_control_validation_delete(_mapper: object, _connection: object, _target: object) -> None:
    raise ValueError("native_control_validation_append_only")


event.listen(
    NativeControlValidation.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS trg_native_validation_scope_guard_insert "
        "BEFORE INSERT ON native_control_validations "
        f"WHEN NEW.acceptance_state IN ({','.join(repr(state) for state in REAL_ACCEPTANCE_STATES)}) "
        f"AND ({_sqlite_real_validation_scope_guard_sql()}) "
        "BEGIN SELECT RAISE(ABORT, 'native_control_validation_real_scope_invalid'); END"
    ).execute_if(dialect="sqlite"),
)


class NativeControlHealthObservation(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "native_control_health_observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_health_tenant_integration",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id", "integration_instance_id", "provider_event_id_hash",
            name="uq_native_health_tenant_provider_event",
        ),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_native_health_latency_nonnegative"),
        CheckConstraint(
            "source IN ('signed_native_callback','endpoint_runtime_probe','health_reconciler')",
            name="ck_native_health_source",
        ),
        Index(
            "idx_native_health_tenant_integration_time",
            "tenant_id", "integration_instance_id", "observed_at",
        ),
        Index("idx_native_health_expiry", "expires_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    integration_instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    credential_id: Mapped[str] = mapped_column(String(128), nullable=False)
    credential_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    provider_event_id_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    callback_authenticated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_flowing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NativeControlReplay(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "native_control_replays"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_replay_tenant_integration",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id", "integration_instance_id", "event_id_hash",
            name="uq_native_replay_tenant_event",
        ),
        UniqueConstraint(
            "tenant_id", "integration_instance_id", "nonce_hash",
            name="uq_native_replay_tenant_nonce",
        ),
        Index("idx_native_replay_tenant_expiry", "tenant_id", "expires_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    integration_instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_id_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_id: Mapped[str] = mapped_column(String(128), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class NativeControlLogicalActionClaim(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One bounded logical provider-action claim, separate from envelope replay.

    A provider retry carries a new signed envelope ID and nonce, so transport
    replay protection alone cannot prevent duplicate policy evaluation. This
    bounded record atomically reserves the provider's stable logical-action
    identifier without storing raw provider inputs, policy results, or a
    parallel evidence payload. A conflict is a one-way safety state: once a
    provider reuses the logical identifier with different material, future
    retries cannot resurrect the earlier authorization.
    """

    __tablename__ = "native_control_logical_action_claims"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_logical_claim_tenant_integration",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id",
            "integration_instance_id",
            "provider_event_id_hash",
            name="uq_native_logical_claim_tenant_provider_event",
        ),
        CheckConstraint(
            _strict_hash_check_sql("provider_event_id_hash"),
            name="ck_native_logical_claim_provider_event_hash",
        ),
        CheckConstraint(
            _strict_hash_check_sql("canonical_material_hash"),
            name="ck_native_logical_claim_material_hash",
        ),
        CheckConstraint(
            _strict_hash_check_sql("contract_hash"),
            name="ck_native_logical_claim_contract_hash",
        ),
        CheckConstraint(
            _strict_hash_check_sql("configuration_fingerprint"),
            name="ck_native_logical_claim_configuration_hash",
        ),
        CheckConstraint(
            _strict_hash_check_sql("conflict_material_hash"),
            name="ck_native_logical_claim_conflict_material_hash",
        ),
        CheckConstraint(
            "length(trim(policy_snapshot_id)) BETWEEN 1 AND 64",
            name="ck_native_logical_claim_policy_snapshot",
        ),
        Index(
            "idx_native_logical_claim_tenant_integration_created",
            "tenant_id",
            "integration_instance_id",
            "created_at",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    integration_instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provider_event_id_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_material_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    contract_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    conflicted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    conflict_material_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    @validates(
        "provider_event_id_hash",
        "canonical_material_hash",
        "contract_hash",
        "configuration_fingerprint",
        "conflict_material_hash",
    )
    def _validate_claim_hash(self, key: str, value: str | None) -> str | None:
        if value is None and key == "conflict_material_hash":
            return None
        normalized = _validate_contract_hash(value)
        if normalized is None:
            raise ValueError(f"{key}_invalid")
        return normalized


class NativeControlSelection(Base):
    __tablename__ = "native_control_selections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "selection_id", name="uq_native_selection_tenant_id"),
        UniqueConstraint(
            "tenant_id",
            "action_id",
            "control_plan_digest",
            name="uq_native_selection_tenant_action_plan_digest",
        ),
        CheckConstraint(
            "canonical_action_hash IS NULL OR length(canonical_action_hash) = 64",
            name="ck_native_selection_canonical_action_hash",
        ),
        CheckConstraint(
            "provider_runtime_fingerprint IS NULL OR length(provider_runtime_fingerprint) = 64",
            name="ck_native_selection_runtime_fingerprint",
        ),
        CheckConstraint(
            "control_plan_digest IS NULL OR length(control_plan_digest) = 64",
            name="ck_native_selection_plan_digest",
        ),
        CheckConstraint(
            "plan_expires_at > plan_issued_at",
            name="ck_native_selection_plan_time_order",
        ),
        Index("idx_native_selection_tenant_action", "tenant_id", "action_id", "selected_at"),
        Index(
            "idx_native_selection_tenant_canonical_action",
            "tenant_id",
            "canonical_action_hash",
            "selected_at",
        ),
    )

    selection_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # Legacy selection fields retain the effective semantic selection. The
    # additive fields retain the full composed plan even when its mandatory
    # endpoint floor makes the effective decision fail closed.
    canonical_action_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provider_runtime_context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    provider_runtime_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_plan_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_plan_material: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    mandatory_enforcement_floor_requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    selected_mandatory_floors: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    semantic_primary_control_point_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    secondary_context_points: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    verification_points: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    unsatisfied_mandatory_floors: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rejected_mandatory_floor_candidates: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    control_requirement_unsatisfied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    control_plan_reason_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    degradation_policy: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    failure_behavior: Mapped[str] = mapped_column(String(64), nullable=False, default="fail_closed")
    plan_issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    plan_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    contract_hashes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    primary_control_point_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    secondary_observation_points: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    containment_points: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rejected_candidates: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    selection_reason: Mapped[str] = mapped_column(String(128), nullable=False)
    required_capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    satisfied_capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    unsatisfied_capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    assurance_level: Mapped[int] = mapped_column(nullable=False)
    coverage_implications: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    known_blind_spots: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    selector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    matrix_version: Mapped[str] = mapped_column(String(96), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    control_profile_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    selected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    @validates(
        "canonical_action_hash",
        "provider_runtime_fingerprint",
        "control_plan_digest",
    )
    def _validate_plan_hashes(self, key: str, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
            raise ValueError(f"{key}_invalid")
        return value


def _selection_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@event.listens_for(NativeControlSelection, "before_insert")
def _validate_native_control_selection_before_insert(
    _mapper: object,
    _connection: object,
    target: NativeControlSelection,
) -> None:
    issued = _selection_utc(target.plan_issued_at)
    expires = _selection_utc(target.plan_expires_at)
    if (
        issued is None
        or expires is None
        or expires <= issued
        or expires - issued > timedelta(minutes=5)
    ):
        raise ValueError("native_control_selection_plan_lifetime_invalid")
    material = target.control_plan_material
    if not isinstance(material, dict):
        raise ValueError("native_control_selection_plan_material_invalid")
    bounded = json.loads(json.dumps(material, sort_keys=True, separators=(",", ":")))
    digest = bounded.pop("plan_digest", None)
    recomputed = hashlib.sha256(
        json.dumps(bounded, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    ).hexdigest()
    if (
        digest != target.control_plan_digest
        or digest != recomputed
        or bounded.get("plan_id") != target.control_plan_id
        or bounded.get("canonical_action_hash") != target.canonical_action_hash
        or bounded.get("issued_at") != issued.isoformat()
        or bounded.get("expires_at") != expires.isoformat()
    ):
        raise ValueError("native_control_selection_plan_binding_invalid")


@event.listens_for(NativeControlSelection, "before_update")
def _prevent_native_control_selection_update(
    _mapper: object,
    _connection: object,
    _target: object,
) -> None:
    raise ValueError("native_control_selection_append_only")


@event.listens_for(NativeControlSelection, "before_delete")
def _prevent_native_control_selection_delete(
    _mapper: object,
    _connection: object,
    _target: object,
) -> None:
    raise ValueError("native_control_selection_append_only")


event.listen(
    NativeControlSelection.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS trg_native_control_selections_immutable_update "
        "BEFORE UPDATE ON native_control_selections "
        "BEGIN SELECT RAISE(ABORT, 'immutable_table:native_control_selections'); END"
    ).execute_if(dialect="sqlite"),
)

event.listen(
    NativeControlSelection.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS trg_native_control_selections_immutable_delete "
        "BEFORE DELETE ON native_control_selections "
        "BEGIN SELECT RAISE(ABORT, 'immutable_table:native_control_selections'); END"
    ).execute_if(dialect="sqlite"),
)
