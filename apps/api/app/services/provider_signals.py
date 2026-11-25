from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from enum import StrEnum
from hashlib import sha256
import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.provider_signal import ProviderSeatSnapshot, ProviderSignalRecord
from app.services.activity_lineage import materialize_activity_lineage
from app.services.control_coverage.path_projection import runtime_event_candidate, upsert_path
from app.services.external_capability_integrity import ExternalCapabilityIntegrityService


class ProviderSignalKind(StrEnum):
    CAPABILITY = "capability"
    USAGE = "usage"
    SPEND = "spend"
    PROMPT = "prompt"
    TOOL = "tool"
    MEETING = "meeting"
    CLIENT_SESSION = "client_session"


class ProviderSourceType(StrEnum):
    PROVIDER_ANALYTICS = "provider_analytics"
    PROVIDER_ADMIN = "provider_admin"
    PROVIDER_SPEND_API = "provider_spend_api"
    PROVIDER_COMPLIANCE = "provider_compliance"
    PROVIDER_AUDIT = "provider_audit"
    OTEL = "otel"
    HOOK = "hook"
    ENDPOINT = "endpoint"
    MCP_CONFIG = "mcp_config"
    MEETING_ADMIN = "meeting_admin"
    CONTRACT_RATE_CARD = "contract_rate_card"
    INVOICE = "invoice"
    UNKNOWN = "unknown"


class CostType(StrEnum):
    PROVIDER_BILLED = "PROVIDER_BILLED"
    PROVIDER_REPORTED = "PROVIDER_REPORTED"
    CONTRACT_RATE_CARD = "CONTRACT_RATE_CARD"
    CREDIT_CONSUMPTION = "CREDIT_CONSUMPTION"
    CLIENT_ESTIMATE = "CLIENT_ESTIMATE"
    HAWK_ESTIMATE = "HAWK_ESTIMATE"
    UNAVAILABLE = "UNAVAILABLE"


class CapabilityState(StrEnum):
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNVERIFIED = "UNVERIFIED"
    EXPERIMENTAL = "EXPERIMENTAL"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class AIProviderConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    product: str
    edition: str | None = None
    connector_id: str | None = None
    source_types: list[ProviderSourceType] = Field(default_factory=list)
    secret_ref: str | None = None
    last_success_at: datetime | None = None
    freshness_state: Literal["CURRENT", "STALE", "FAILED", "UNKNOWN"] = "UNKNOWN"


class AIClientIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: str
    client_name: str
    client_type: str
    version: str | None = None
    device_ref: str | None = None
    configuration_scope: str | None = None


class AIClientSession(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_ref: str
    client_id: str
    account_class: str | None = None
    device_assurance: str | None = None
    started_at: datetime
    ended_at: datetime | None = None


class ProviderUsageRecord(BaseModel):
    model_config = ConfigDict(extra="allow")
    metric: str
    value: Decimal
    unit: str
    reconciliation_key: str
    authoritative: bool = False
    duplicate_confidence: str = "UNKNOWN"


class ProviderSpendRecord(BaseModel):
    model_config = ConfigDict(extra="allow")
    cost_type: CostType
    amount: Decimal | None = None
    currency: str | None = None
    reconciliation_key: str
    allocation_method: str | None = None
    billing_group: str | None = None
    contract_reference: str | None = None

    @model_validator(mode="after")
    def validate_cost(self) -> "ProviderSpendRecord":
        if self.cost_type == CostType.UNAVAILABLE:
            if self.amount is not None:
                raise ValueError("unavailable cost cannot include an amount")
            return self
        if self.amount is None or self.amount < 0:
            raise ValueError("available cost requires a non-negative amount")
        return self


class PromptObservation(BaseModel):
    model_config = ConfigDict(extra="allow")
    content_level: Literal[
        "METADATA_ONLY",
        "CLASSIFIED_SUMMARY",
        "REDACTED_PREVIEW",
        "FULL_CONTENT_PRIVILEGED",
        "CONTENT_UNAVAILABLE",
    ]
    category: str | None = None
    prompt_category: str | None = None
    classified_summary: str | None = None
    redacted_preview: str | None = None
    data_classifications: list[str] = Field(default_factory=list)
    injection_indicators: list[str] = Field(default_factory=list)
    instruction_provenance: list[str] = Field(default_factory=list)
    policy_decision: str | None = None


class ToolConnectionObservation(BaseModel):
    model_config = ConfigDict(extra="allow")
    server_identity: str
    client: str | None = None
    configuration_scope: str = "UNKNOWN"
    connection_state: str
    authentication_state: str | None = None
    transport: str | None = None
    tool_name: str | None = None
    tool_schema_hash: str | None = None
    invocation_count: int = Field(default=0, ge=0)
    trust_state: str = "UNKNOWN"
    drift_state: str = "UNKNOWN"
    observation_mode: Literal["CONFIGURATION_INVENTORY", "GATEWAY_ATTESTED_INVOCATION", "INFERRED"] = "CONFIGURATION_INVENTORY"
    gateway_event_id: str | None = None

    @model_validator(mode="after")
    def require_direct_gateway_attestation_for_action_projection(self) -> "ToolConnectionObservation":
        if self.observation_mode == "GATEWAY_ATTESTED_INVOCATION":
            if self.connection_state.strip().upper() != "USED" or self.invocation_count < 1:
                raise ValueError("gateway-attested MCP observations require USED state and invocation_count >= 1")
            if not self.gateway_event_id or len(self.gateway_event_id.strip()) > 64:
                raise ValueError("gateway-attested MCP observations require a bounded gateway_event_id")
        elif self.gateway_event_id is not None:
            raise ValueError("gateway_event_id is permitted only for gateway-attested MCP observations")
        # A provider or client report cannot assert an internal trust or drift
        # state. External Capability Integrity remains the only authority.
        self.trust_state = "UNKNOWN"
        self.drift_state = "UNKNOWN"
        return self


class MeetingAIObservation(BaseModel):
    model_config = ConfigDict(extra="allow")
    vendor: str | None = None
    application_id: str | None = None
    service_principal: str | None = None
    bot_id: str | None = None
    participant_identity: str | None = None
    platform: str
    action_state: str
    evidence_source: str

    @model_validator(mode="after")
    def require_identity_evidence(self) -> "MeetingAIObservation":
        if not any((self.application_id, self.service_principal, self.bot_id, self.participant_identity)):
            raise ValueError("meeting AI requires a non-display-name identity")
        return self


class CapabilityObservation(BaseModel):
    model_config = ConfigDict(extra="allow")
    dimension: str
    status: CapabilityState
    source_version: str | None = None
    limitation: str | None = None


class ClientSessionObservation(BaseModel):
    model_config = ConfigDict(extra="allow")
    client_id: str
    account_class: str | None = None
    device_assurance: str | None = None
    surface: str


_PAYLOAD_MODELS: dict[ProviderSignalKind, type[BaseModel]] = {
    ProviderSignalKind.CAPABILITY: CapabilityObservation,
    ProviderSignalKind.USAGE: ProviderUsageRecord,
    ProviderSignalKind.SPEND: ProviderSpendRecord,
    ProviderSignalKind.PROMPT: PromptObservation,
    ProviderSignalKind.TOOL: ToolConnectionObservation,
    ProviderSignalKind.MEETING: MeetingAIObservation,
    ProviderSignalKind.CLIENT_SESSION: ClientSessionObservation,
}

_FORBIDDEN_KEYS = {
    "authorization",
    "authorization_header",
    "api_key",
    "access_token",
    "refresh_token",
    "bearer_token",
    "client_secret",
    "password",
    "cookie",
    "cookies",
    "private_key",
    "mcp_secret",
    "credential",
    "credentials",
}
_RAW_PROMPT_KEYS = {"raw_prompt", "prompt_text", "prompt_content", "full_prompt", "request_body"}
_SAFE_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def _walk_keys(value: object) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            keys.append(str(key).strip().lower())
            keys.extend(_walk_keys(nested))
    elif isinstance(value, list):
        for nested in value:
            keys.extend(_walk_keys(nested))
    return keys


class ProviderSignalEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str | None = None
    connector_id: str | None = None
    provider: str
    product: str
    source_type: ProviderSourceType
    source_schema_version: str
    source_record_id: str
    record_kind: ProviderSignalKind
    occurred_at: datetime
    watermark: str | None = None
    user_id: str | None = None
    department: str | None = None
    client: str | None = None
    model: str | None = None
    session_ref: str | None = None
    evidence_quality: Literal["CONFIRMED", "OBSERVED", "CORRELATED", "INFERRED", "UNKNOWN"] = "UNKNOWN"
    payload: dict[str, Any]

    @field_validator("provider", "product")
    @classmethod
    def normalize_slug(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _SAFE_SLUG.fullmatch(normalized):
            raise ValueError("provider and product must be stable slugs")
        return normalized

    @field_validator("source_schema_version", "source_record_id")
    @classmethod
    def nonempty_bounded(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 255 or any(character in normalized for character in "\r\n\x00"):
            raise ValueError("source identifiers must be non-empty and bounded")
        return normalized

    @model_validator(mode="after")
    def validate_payload(self) -> "ProviderSignalEnvelope":
        encoded = json.dumps(self.payload, default=str, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 64 * 1024:
            raise ValueError("provider signal payload exceeds 64 KiB")
        keys = set(_walk_keys(self.payload))
        forbidden = keys & _FORBIDDEN_KEYS
        if forbidden:
            raise ValueError(f"secret-bearing field is not permitted: {sorted(forbidden)[0]}")
        if keys & _RAW_PROMPT_KEYS:
            raise ValueError("raw prompt content is not permitted in provider signal ingestion")
        typed = _PAYLOAD_MODELS[self.record_kind].model_validate(self.payload)
        self.payload = typed.model_dump(mode="json", exclude_none=True)
        return self


class ProviderSignalIngestResult(BaseModel):
    created: bool
    record: ProviderSignalRecord

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ProviderSeatSnapshotEnvelope(BaseModel):
    """A provider-admin aggregate seat snapshot with no individual seat data."""

    model_config = ConfigDict(extra="forbid")
    tenant_id: str | None = None
    connector_id: str | None = None
    provider: str
    product: str
    source_type: ProviderSourceType
    source_schema_version: str
    source_record_id: str
    observed_at: datetime
    billing_group: str | None = None
    authority_reference: str
    total_licensed_seats: int = Field(ge=0)
    assigned_seats: int = Field(ge=0)
    active_seats: int = Field(ge=0)
    inactive_seats: int = Field(ge=0)
    never_used_seats: int = Field(ge=0)
    unknown_activity_seats: int = Field(ge=0)
    completeness: Literal["COMPLETE", "PARTIAL", "UNKNOWN"] = "UNKNOWN"
    evidence_quality: Literal["CONFIRMED", "OBSERVED"] = "CONFIRMED"

    @field_validator("provider", "product")
    @classmethod
    def normalize_slug(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _SAFE_SLUG.fullmatch(normalized):
            raise ValueError("provider and product must be stable slugs")
        return normalized

    @field_validator("source_schema_version", "source_record_id")
    @classmethod
    def nonempty_bounded(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 255 or any(character in normalized for character in "\r\n\x00"):
            raise ValueError("source identifiers must be non-empty and bounded")
        return normalized

    @field_validator("billing_group", "authority_reference")
    @classmethod
    def optional_bounded_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.split())
        if not normalized or len(normalized) > 255:
            raise ValueError("seat snapshot metadata must be non-empty and bounded when supplied")
        return normalized

    @model_validator(mode="after")
    def require_authoritative_population(self) -> "ProviderSeatSnapshotEnvelope":
        if self.source_type != ProviderSourceType.PROVIDER_ADMIN:
            raise ValueError("authoritative seat snapshots require provider_admin source_type")
        if self.assigned_seats != (
            self.active_seats
            + self.inactive_seats
            + self.never_used_seats
            + self.unknown_activity_seats
        ):
            raise ValueError("assigned seats must equal active plus inactive plus never-used plus unknown-activity seats")
        if self.total_licensed_seats < self.assigned_seats:
            raise ValueError("total licensed seats must be greater than or equal to assigned seats")
        if self.completeness == "COMPLETE" and self.total_licensed_seats != self.assigned_seats:
            raise ValueError("complete seat snapshots cannot contain unassigned seats")
        return self


class ProviderSeatSnapshotIngestResult(BaseModel):
    created: bool
    record: ProviderSeatSnapshot

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ProviderSignalRetentionResult(BaseModel):
    tenant_id: str
    retention_days: int
    cutoff_at: datetime
    candidate_signal_records: int
    candidate_seat_snapshots: int
    deleted_signal_records: int
    deleted_seat_snapshots: int
    more_remaining: bool
    executed: bool

    model_config = ConfigDict(arbitrary_types_allowed=True)


_COST_PRECEDENCE = {
    CostType.PROVIDER_BILLED.value: 1,
    CostType.PROVIDER_REPORTED.value: 2,
    CostType.CONTRACT_RATE_CARD.value: 3,
    CostType.CREDIT_CONSUMPTION.value: 4,
    CostType.CLIENT_ESTIMATE.value: 5,
    CostType.HAWK_ESTIMATE.value: 6,
    CostType.UNAVAILABLE.value: 7,
}
_CURRENT_AGE = timedelta(hours=24)
_INDIVIDUAL_ROLES = {"operator", "auditor", "admin", "owner"}


def _dedup_key(envelope: ProviderSignalEnvelope) -> str:
    material = "\x1f".join(
        (
            envelope.provider,
            envelope.product,
            envelope.source_type.value,
            envelope.record_kind.value,
            envelope.source_record_id,
        )
    )
    return sha256(material.encode("utf-8")).hexdigest()


def _seat_dedup_key(envelope: ProviderSeatSnapshotEnvelope) -> str:
    material = "\x1f".join(
        (
            envelope.provider,
            envelope.product,
            envelope.source_type.value,
            envelope.source_record_id,
        )
    )
    return sha256(material.encode("utf-8")).hexdigest()


def _bounded_projection_text(value: object, *, maximum: int = 128, fallback: str = "unknown") -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return fallback
    lowered = text.lower()
    if any(marker in lowered for marker in ("api_key=", "access_token=", "authorization:", "bearer ", "password=", "secret=", "token=")):
        return f"redacted_hash:{sha256(text.encode('utf-8')).hexdigest()}"
    return text[:maximum]


def _provider_signal_ref(record: ProviderSignalRecord) -> str:
    return f"provider_signal:{record.id}"


def _mcp_capability_ref(record: ProviderSignalRecord) -> str:
    server_identity = _bounded_projection_text(record.payload.get("server_identity"), maximum=255)
    identity_hash = sha256(server_identity.encode("utf-8")).hexdigest()[:40]
    return f"provider_signal_mcp:{record.provider}:{identity_hash}"


def _tool_projection_complete(record: ProviderSignalRecord) -> bool:
    projection = record.projection_refs if isinstance(record.projection_refs, dict) else {}
    if projection.get("version") != "provider-signal-mcp-projection/2":
        return False
    mode = str((record.payload or {}).get("observation_mode") or "CONFIGURATION_INVENTORY")
    if mode == "GATEWAY_ATTESTED_INVOCATION":
        return bool(projection.get("runtime_event_id") and projection.get("activity_lineage_id") and projection.get("control_coverage_path_id"))
    return bool(projection.get("external_capability_id"))


def _project_tool_signal(db: Session, *, record: ProviderSignalRecord) -> None:
    """Materialize references to existing authorities for one MCP/tool signal.

    The projection is deliberately metadata-only and idempotent. It does not
    manufacture an HMAIR canonical asset, approval, control assertion, or
    verified execution result from a provider observation.
    """

    if _tool_projection_complete(record):
        return
    payload = dict(record.payload or {})
    server_identity = _bounded_projection_text(payload.get("server_identity"), maximum=255)
    tool_name = _bounded_projection_text(payload.get("tool_name"), maximum=128, fallback="")
    schema_hash = _bounded_projection_text(payload.get("tool_schema_hash"), maximum=128, fallback="")
    source_ref = _provider_signal_ref(record)
    capability_ref = _mcp_capability_ref(record)
    observation = {
        "configured_locator": capability_ref,
        "registry_source": f"provider_signal:{record.source_type}",
        "registry_identity": record.provider,
        "publisher_identity": record.provider,
        "transport": _bounded_projection_text(payload.get("transport"), maximum=64),
        "auth_mode": _bounded_projection_text(payload.get("authentication_state"), maximum=64),
        "server_metadata": {"name": f"mcp:{sha256(server_identity.encode('utf-8')).hexdigest()[:24]}", "version": record.source_schema_version},
        "tools": (
            [{
                "name": tool_name,
                "version": record.source_schema_version,
                "annotations": {"source_schema_hash": schema_hash} if schema_hash else {},
            }]
            if tool_name
            else []
        ),
    }
    projection_mode = str(payload.get("observation_mode") or "CONFIGURATION_INVENTORY")
    direct_gateway_attested = projection_mode == "GATEWAY_ATTESTED_INVOCATION"
    capability = ExternalCapabilityIntegrityService().observe_mcp_capability(
        db,
        tenant_id=record.tenant_id,
        capability_ref=capability_ref,
        observation=observation,
        observed_at=_as_utc(record.occurred_at),
        evidence_refs=[source_ref],
        evidence_quality=record.evidence_quality,
        observation_mode=("GATEWAY_ATTESTED_INVOCATION" if direct_gateway_attested else "CONFIGURATION_INVENTORY"),
    )
    runtime_event = None
    path = None
    lineage = None
    if direct_gateway_attested:
        gateway_event_id = str(payload.get("gateway_event_id") or "").strip()
        runtime_event = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == record.tenant_id,
                RuntimeEvent.event_id == gateway_event_id,
                RuntimeEvent.source_surface == "gateway",
                RuntimeEvent.event_type == "mcp_authorize",
            )
        )
        if runtime_event is None:
            raise ValueError("gateway-attested MCP observation references no tenant-scoped mcp_authorize event")
        event_metadata = dict(runtime_event.metadata_json or {})
        event_server = _bounded_projection_text(event_metadata.get("mcp_server_id") or runtime_event.app_id, maximum=255)
        event_tool = _bounded_projection_text(event_metadata.get("mcp_tool_id") or event_metadata.get("tool_name"), maximum=128, fallback="")
        if event_server != server_identity or (tool_name and event_tool and event_tool != tool_name):
            raise ValueError("gateway-attested MCP observation does not match the referenced gateway event")
        path = upsert_path(
            db,
            tenant_id=record.tenant_id,
            candidate=runtime_event_candidate(runtime_event),
            observed_at=_as_utc(record.occurred_at),
        )
        lineage = materialize_activity_lineage(
            db,
            tenant_id=record.tenant_id,
            runtime_event_id=runtime_event.event_id,
        )
    record.projection_refs = {
        "version": "provider-signal-mcp-projection/2",
        "projection_mode": projection_mode,
        "external_capability_id": capability.capability_id,
        "external_capability_ref": capability.capability_ref,
        "runtime_event_id": runtime_event.event_id if runtime_event is not None else None,
        "activity_lineage_id": lineage.id if lineage is not None else None,
        "control_coverage_path_id": path.id if path is not None else None,
        "asset_intelligence_application_id": None,
        "hmair": {
            "status": "UNRESOLVED",
            "reason": "provider_signal_requires_attested_hmair_observation_for_canonical_asset_binding",
        },
    }
    db.flush()


def ingest_provider_signal(
    db: Session, *, tenant_id: str, envelope: ProviderSignalEnvelope
) -> ProviderSignalIngestResult:
    if envelope.tenant_id and envelope.tenant_id != tenant_id:
        raise PermissionError("provider signal tenant mismatch")
    dedup_key = _dedup_key(envelope)
    existing = db.scalar(
        select(ProviderSignalRecord).where(
            ProviderSignalRecord.tenant_id == tenant_id,
            ProviderSignalRecord.dedup_key == dedup_key,
        )
    )
    if existing is not None:
        if existing.record_kind == ProviderSignalKind.TOOL.value:
            _project_tool_signal(db, record=existing)
        return ProviderSignalIngestResult(created=False, record=existing)
    record = ProviderSignalRecord(
        tenant_id=tenant_id,
        connector_id=envelope.connector_id,
        provider=envelope.provider,
        product=envelope.product,
        source_type=envelope.source_type.value,
        source_schema_version=envelope.source_schema_version,
        source_record_id=envelope.source_record_id,
        dedup_key=dedup_key,
        record_kind=envelope.record_kind.value,
        occurred_at=envelope.occurred_at,
        watermark=envelope.watermark,
        user_id=envelope.user_id,
        department=envelope.department,
        client=envelope.client,
        model=envelope.model,
        session_ref=envelope.session_ref,
        evidence_quality=envelope.evidence_quality,
        payload=envelope.payload,
    )
    db.add(record)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(ProviderSignalRecord).where(
                ProviderSignalRecord.tenant_id == tenant_id,
                ProviderSignalRecord.dedup_key == dedup_key,
            )
        )
        if existing is None:
            raise
        if existing.record_kind == ProviderSignalKind.TOOL.value:
            _project_tool_signal(db, record=existing)
        return ProviderSignalIngestResult(created=False, record=existing)
    if record.record_kind == ProviderSignalKind.TOOL.value:
        _project_tool_signal(db, record=record)
    return ProviderSignalIngestResult(created=True, record=record)


def ingest_provider_seat_snapshot(
    db: Session, *, tenant_id: str, envelope: ProviderSeatSnapshotEnvelope
) -> ProviderSeatSnapshotIngestResult:
    if envelope.tenant_id and envelope.tenant_id != tenant_id:
        raise PermissionError("provider seat snapshot tenant mismatch")
    dedup_key = _seat_dedup_key(envelope)
    existing = db.scalar(
        select(ProviderSeatSnapshot).where(
            ProviderSeatSnapshot.tenant_id == tenant_id,
            ProviderSeatSnapshot.dedup_key == dedup_key,
        )
    )
    if existing is not None:
        return ProviderSeatSnapshotIngestResult(created=False, record=existing)
    record = ProviderSeatSnapshot(
        tenant_id=tenant_id,
        connector_id=envelope.connector_id,
        provider=envelope.provider,
        product=envelope.product,
        source_type=envelope.source_type.value,
        source_schema_version=envelope.source_schema_version,
        source_record_id=envelope.source_record_id,
        dedup_key=dedup_key,
        billing_group=envelope.billing_group,
        authority_reference=envelope.authority_reference,
        assigned_seats=envelope.assigned_seats,
        active_seats=envelope.active_seats,
        inactive_seats=envelope.inactive_seats,
        never_used_seats=envelope.never_used_seats,
        unknown_activity_seats=envelope.unknown_activity_seats,
        total_licensed_seats=envelope.total_licensed_seats,
        completeness=envelope.completeness,
        evidence_quality=envelope.evidence_quality,
        observed_at=_as_utc(envelope.observed_at),
    )
    db.add(record)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(ProviderSeatSnapshot).where(
                ProviderSeatSnapshot.tenant_id == tenant_id,
                ProviderSeatSnapshot.dedup_key == dedup_key,
            )
        )
        if existing is None:
            raise
        return ProviderSeatSnapshotIngestResult(created=False, record=existing)
    return ProviderSeatSnapshotIngestResult(created=True, record=record)


def purge_expired_provider_signal_records(
    db: Session,
    *,
    tenant_id: str,
    retention_days: int,
    now: datetime | None = None,
    batch_limit: int = 500,
    execute: bool = False,
) -> ProviderSignalRetentionResult:
    """Return bounded received-at retention candidates, optionally deleting them.

    Callers must make the destructive path explicitly opt-in *after* tenant
    rollout authorization.  A plain invocation is therefore a count-only,
    tenant-scoped audit preview and cannot alter customer records.
    """
    safe_days = max(1, min(int(retention_days), 3650))
    safe_limit = max(1, min(int(batch_limit), 1000))
    current = _as_utc(now or datetime.now(UTC))
    cutoff = current - timedelta(days=safe_days)

    signal_ids = list(
        db.scalars(
            select(ProviderSignalRecord.id)
            .where(
                ProviderSignalRecord.tenant_id == tenant_id,
                ProviderSignalRecord.received_at < cutoff,
            )
            .order_by(ProviderSignalRecord.received_at.asc(), ProviderSignalRecord.id.asc())
            .limit(safe_limit)
        ).all()
    )
    remaining = max(0, safe_limit - len(signal_ids))
    seat_ids = list(
        db.scalars(
            select(ProviderSeatSnapshot.id)
            .where(
                ProviderSeatSnapshot.tenant_id == tenant_id,
                ProviderSeatSnapshot.received_at < cutoff,
            )
            .order_by(ProviderSeatSnapshot.received_at.asc(), ProviderSeatSnapshot.id.asc())
            .limit(remaining)
        ).all()
    )
    if execute and signal_ids:
        db.execute(
            delete(ProviderSignalRecord).where(
                ProviderSignalRecord.tenant_id == tenant_id,
                ProviderSignalRecord.id.in_(signal_ids),
            )
        )
    if execute and seat_ids:
        db.execute(
            delete(ProviderSeatSnapshot).where(
                ProviderSeatSnapshot.tenant_id == tenant_id,
                ProviderSeatSnapshot.id.in_(seat_ids),
            )
        )
    more_remaining = bool(
        db.scalar(
            select(ProviderSignalRecord.id)
            .where(
                ProviderSignalRecord.tenant_id == tenant_id,
                ProviderSignalRecord.received_at < cutoff,
            )
            .limit(1)
        )
        or db.scalar(
            select(ProviderSeatSnapshot.id)
            .where(
                ProviderSeatSnapshot.tenant_id == tenant_id,
                ProviderSeatSnapshot.received_at < cutoff,
            )
            .limit(1)
        )
    )
    return ProviderSignalRetentionResult(
        tenant_id=tenant_id,
        retention_days=safe_days,
        cutoff_at=cutoff,
        candidate_signal_records=len(signal_ids),
        candidate_seat_snapshots=len(seat_ids),
        deleted_signal_records=len(signal_ids) if execute else 0,
        deleted_seat_snapshots=len(seat_ids) if execute else 0,
        more_remaining=more_remaining,
        executed=bool(execute),
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _decimal(value: object) -> Decimal | None:
    try:
        return Decimal(str(value)) if value is not None else None
    except (InvalidOperation, ValueError):
        return None


def _clean_string(value: object, *, max_length: int = 255) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_length]


def _metadata(row: RuntimeEvent) -> dict[str, Any]:
    return row.metadata_json if isinstance(row.metadata_json, dict) else {}


def _metadata_first(metadata: dict[str, Any], *keys: str) -> object | None:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, ""):
            return value
    return None


def _metadata_list(metadata: dict[str, Any], *keys: str) -> list[str]:
    value = _metadata_first(metadata, *keys)
    if value in (None, ""):
        return []
    if isinstance(value, list):
        candidates = value
    elif isinstance(value, (tuple, set)):
        candidates = list(value)
    else:
        candidates = [value]
    result: list[str] = []
    for item in candidates:
        normalized = _clean_string(item, max_length=128)
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _normalized_metadata_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def _metadata_deep_first(
    metadata: dict[str, Any],
    *keys: str,
    excluded_path_markers: set[str] | None = None,
    required_path_markers: set[str] | None = None,
) -> tuple[object | None, tuple[str, ...]]:
    """Return the first bounded nested metadata value matching any key alias.

    Runtime clients and provider hooks use inconsistent usage/cost schemas.
    This search deliberately stays shallow and can exclude CRQ/risk paths so
    financial-risk projections are never mistaken for provider spend.
    """

    targets = {_normalized_metadata_key(key) for key in keys}
    excluded = {_normalized_metadata_key(key) for key in (excluded_path_markers or set())}
    required = {_normalized_metadata_key(key) for key in (required_path_markers or set())}
    visited = 0
    max_nodes = 750

    def walk(
        value: object,
        path: tuple[str, ...],
        normalized_path: frozenset[str],
        depth: int,
    ) -> tuple[object, tuple[str, ...]] | None:
        nonlocal visited
        visited += 1
        if visited > max_nodes:
            return None
        if excluded and normalized_path.intersection(excluded):
            return None
        if depth > 6:
            return None
        if isinstance(value, dict):
            for key, nested in list(value.items())[:100]:
                next_key = str(key)
                normalized_key = _normalized_metadata_key(next_key)
                next_path = (*path, next_key)
                normalized_next_path = normalized_path | {normalized_key}
                if normalized_key in targets and nested not in (None, ""):
                    if not required or normalized_next_path.intersection(required):
                        return nested, next_path
                if isinstance(nested, (dict, list)):
                    found = walk(nested, next_path, frozenset(normalized_next_path), depth + 1)
                    if found is not None:
                        return found
        elif isinstance(value, list):
            next_path = (*path, "[]")
            normalized_next_path = normalized_path | {"[]"}
            for nested in value[:10]:
                if isinstance(nested, (dict, list)):
                    found = walk(nested, next_path, frozenset(normalized_next_path), depth + 1)
                    if found is not None:
                        return found
        return None

    result = walk(metadata, tuple(), frozenset(), 0)
    return result if result is not None else (None, tuple())


def _token_estimate_from_chars(value: object) -> Decimal | None:
    chars = _decimal(value)
    if chars is None or chars <= 0:
        return None
    return max(Decimal("1"), (chars / Decimal("4")).to_integral_value(rounding=ROUND_CEILING))


def _metadata_text_length(metadata: dict[str, Any], *keys: str) -> Decimal | None:
    value, _ = _metadata_deep_first(metadata, *keys)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return Decimal(len(text))


def _runtime_haystack(row: RuntimeEvent, metadata: dict[str, Any]) -> str:
    values = [
        row.source_surface,
        row.event_type,
        row.app_id,
        row.application,
        row.agent_id,
        _metadata_first(metadata, "provider", "provider_name", "model_provider", "provider_id", "llm_provider"),
        _metadata_first(metadata, "model", "model_name", "model_id"),
        _metadata_first(
            metadata,
            "ai_client",
            "client",
            "client_name",
            "runtime_provider",
            "client_application",
            "host_application",
        ),
        _metadata_first(metadata, "mcp_server_id", "server_identity", "mcp_server_name", "mcp_server"),
        _metadata_first(metadata, "url", "page_url", "browser_url", "domain", "destination", "host"),
    ]
    return " ".join(str(value).lower() for value in values if value not in (None, ""))


def _runtime_provider(row: RuntimeEvent, metadata: dict[str, Any]) -> str:
    explicit = _clean_string(
        _metadata_first(metadata, "provider", "provider_name", "model_provider", "provider_id", "llm_provider"),
        max_length=64,
    )
    haystack = _runtime_haystack(row, metadata)
    candidate = (explicit or "").lower()
    if candidate in {"anthropic", "claude"} or "anthropic" in haystack or "claude" in haystack:
        return "anthropic"
    if candidate in {"openai", "chatgpt", "codex"} or any(item in haystack for item in ("openai", "chatgpt", "codex")):
        return "openai"
    if candidate == "cursor" or "cursor" in haystack:
        return "cursor"
    if candidate in {"google", "gemini"} or any(item in haystack for item in ("google", "gemini")):
        return "google"
    return explicit.lower() if explicit else "unknown"


def _runtime_client(row: RuntimeEvent, metadata: dict[str, Any]) -> str:
    return (
        _clean_string(
            _metadata_first(
                metadata,
                "ai_client",
                "client",
                "client_name",
                "runtime_provider",
                "client_application",
                "host_application",
            ),
            max_length=128,
        )
        or _clean_string(row.application, max_length=128)
        or _clean_string(row.app_id, max_length=128)
        or _clean_string(row.source_surface, max_length=128)
        or "Unknown client"
    )


def _runtime_product(provider: str, row: RuntimeEvent, metadata: dict[str, Any]) -> str:
    haystack = _runtime_haystack(row, metadata)
    if provider == "anthropic":
        if "desktop" in haystack:
            return "claude_desktop"
        if "code" in haystack or "cli" in haystack:
            return "claude_code"
        return "claude"
    if provider == "openai":
        if "codex" in haystack:
            return "codex"
        if "chatgpt" in haystack:
            return "chatgpt"
        return "openai"
    if provider == "cursor":
        return "cursor"
    if provider == "google":
        return "gemini" if "gemini" in haystack else "google_ai"
    return (
        _clean_string(
            _metadata_first(metadata, "product", "application_product", "ai_product"),
            max_length=128,
        )
        or "unknown"
    )


def _runtime_source_type(row: RuntimeEvent, metadata: dict[str, Any]) -> str:
    surface = (row.source_surface or "").lower()
    event_type = (row.event_type or "").lower()
    if (
        "mcp" in surface
        or "mcp" in event_type
        or _metadata_first(
            metadata,
            "mcp_server_id",
            "mcp_tool_id",
            "mcp_server_name",
            "mcp_server",
            "server_identity",
        )
    ):
        return ProviderSourceType.MCP_CONFIG.value
    if surface in {"browser", "extension"}:
        return ProviderSourceType.ENDPOINT.value
    if surface in {"endpoint", "desktop"}:
        return ProviderSourceType.ENDPOINT.value
    if surface in {"hook", "native", "cli"} or "hook" in event_type:
        return ProviderSourceType.HOOK.value
    if surface in {"runtime", "gateway"}:
        return ProviderSourceType.OTEL.value
    return ProviderSourceType.UNKNOWN.value


def _runtime_model(metadata: dict[str, Any]) -> str | None:
    return _clean_string(_metadata_first(metadata, "model", "model_name", "model_id"), max_length=128)


def _runtime_session_ref(row: RuntimeEvent, metadata: dict[str, Any]) -> str | None:
    return _clean_string(
        _metadata_first(metadata, "session_ref", "session_id", "conversation_id", "thread_id")
        or row.context_id
        or row.chain_id,
        max_length=255,
    )


def _runtime_decision(row: RuntimeEvent, metadata: dict[str, Any]) -> str:
    value = _metadata_first(metadata, "policy_decision", "final_decision", "decision") or row.decision
    return str(value or "UNKNOWN").strip().upper()


def _runtime_evidence_quality(row: RuntimeEvent) -> str:
    confidence = (row.confidence_tier or "").lower()
    if confidence in {"confirmed", "clear_positive", "high"}:
        return "OBSERVED"
    if confidence in {"inferred", "low"}:
        return "INFERRED"
    return "OBSERVED" if row.event_id else "UNKNOWN"


def _runtime_record(
    row: RuntimeEvent,
    *,
    provider: str,
    product: str,
    source_type: str,
    record_kind: ProviderSignalKind,
    suffix: str,
    payload: dict[str, Any],
) -> ProviderSignalRecord:
    metadata = _metadata(row)
    source_record_id = f"runtime:{row.event_id}:{suffix}"[:255]
    digest = sha256(f"{row.tenant_id}:{source_record_id}:{record_kind.value}".encode("utf-8")).hexdigest()
    return ProviderSignalRecord(
        id=digest[:36],
        tenant_id=row.tenant_id,
        provider=provider,
        product=product,
        source_type=source_type,
        source_schema_version="runtime-projection/1.0",
        source_record_id=source_record_id,
        dedup_key=digest,
        record_kind=record_kind.value,
        occurred_at=_as_utc(row.created_at),
        user_id=_clean_string(row.user_id, max_length=64),
        department=_clean_string(_metadata_first(metadata, "department", "department_name"), max_length=128),
        client=_runtime_client(row, metadata),
        model=_runtime_model(metadata),
        session_ref=_runtime_session_ref(row, metadata),
        evidence_quality=_runtime_evidence_quality(row),
        payload=payload,
        projection_refs={
            "runtime_event_id": row.event_id,
            "projection_mode": "RUNTIME_OBSERVED",
            "source_surface": row.source_surface,
        },
    )


def _runtime_prompt_payload(row: RuntimeEvent, metadata: dict[str, Any]) -> dict[str, Any] | None:
    category = _clean_string(
        _metadata_first(metadata, "prompt_category", "category", "action_type") or row.event_type,
        max_length=128,
    )
    redacted_preview = _clean_string(
        _metadata_first(
            metadata,
            "redacted_preview",
            "prompt_preview_redacted",
            "redacted_prompt",
            "classified_summary",
            "prompt_preview",
            "original_intent",
            "input_context_summary",
        ),
        max_length=500,
    )
    has_prompt_signal = bool(
        redacted_preview
        or _metadata_first(
            metadata,
            "prompt_category",
            "content_level",
            "data_classifications",
            "classifications",
            "data_classes",
            "injection_indicators",
            "prompt_injection_indicators",
        )
        or "prompt" in (row.event_type or "").lower()
    )
    if not has_prompt_signal:
        return None
    content_level = str(metadata.get("content_level") or ("REDACTED_PREVIEW" if redacted_preview else "METADATA_ONLY"))
    if content_level not in {
        "METADATA_ONLY",
        "CLASSIFIED_SUMMARY",
        "REDACTED_PREVIEW",
        "FULL_CONTENT_PRIVILEGED",
        "CONTENT_UNAVAILABLE",
    }:
        content_level = "METADATA_ONLY"
    classifications = _metadata_list(metadata, "data_classifications", "classifications", "data_classes")
    indicators = _metadata_list(metadata, "injection_indicators", "prompt_injection_indicators")
    provenance = _metadata_list(metadata, "instruction_provenance", "provenance")
    return {
        "content_level": content_level,
        "category": category,
        "prompt_category": category,
        "classified_summary": _clean_string(metadata.get("classified_summary"), max_length=500),
        "redacted_preview": redacted_preview,
        "data_classifications": classifications,
        "injection_indicators": indicators,
        "instruction_provenance": provenance,
        "policy_decision": _runtime_decision(row, metadata),
    }


def _runtime_tool_payload(row: RuntimeEvent, metadata: dict[str, Any]) -> dict[str, Any] | None:
    event_type = (row.event_type or "").lower()
    invoked = bool(
        metadata.get("tool_invoked") or metadata.get("tool_call_id") or metadata.get("function_call_id")
        or any(marker in event_type for marker in ("tool_call", "function_call", "mcp_authorize", "mcp_activity"))
    )
    if not invoked:
        return None
    server_identity = _clean_string(
        _metadata_first(
            metadata,
            "mcp_server_id",
            "server_identity",
            "server_name",
            "mcp_server_name",
            "mcp_server",
            "tool_server",
            "gateway_server_id",
        )
        or row.app_id,
        max_length=128,
    )
    tool_name = _clean_string(
        _metadata_first(
            metadata,
            "tool_name",
            "mcp_tool_id",
            "tool",
            "name",
            "function_name",
            "tool_id",
        ),
        max_length=128,
    )
    is_tool_event = bool(server_identity and (tool_name or "mcp" in event_type))
    if not is_tool_event:
        return None
    decision = _runtime_decision(row, metadata)
    blocked = decision in {"BLOCK", "BLOCKED", "DENY", "DENIED", "QUARANTINE", "QUARANTINED"}
    return {
        "server_identity": server_identity,
        "client": _runtime_client(row, metadata),
        "configuration_scope": _clean_string(
            _metadata_first(metadata, "configuration_scope", "repository_scope", "scope"),
            max_length=128,
        )
        or "OBSERVED_RUNTIME",
        "connection_state": "BLOCKED" if blocked else "USED",
        "authentication_state": _clean_string(metadata.get("authentication_state"), max_length=64),
        "transport": _clean_string(metadata.get("transport"), max_length=64),
        "tool_name": tool_name,
        "tool_schema_hash": _clean_string(metadata.get("tool_schema_hash"), max_length=128),
        "invocation_count": int(metadata.get("invocation_count") or 1),
        "trust_state": "UNKNOWN",
        "drift_state": "UNKNOWN",
        "observation_mode": "CONFIGURATION_INVENTORY",
    }


def _runtime_usage_payloads(row: RuntimeEvent, metadata: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    input_value, _ = _metadata_deep_first(
        metadata,
        "input_tokens",
        "prompt_tokens",
        "inputTokenCount",
        "promptTokenCount",
        "input_token_count",
        "prompt_token_count",
        "tokens_in",
        "inputTokens",
        "promptTokens",
    )
    output_value, _ = _metadata_deep_first(
        metadata,
        "output_tokens",
        "completion_tokens",
        "outputTokenCount",
        "completionTokenCount",
        "output_token_count",
        "completion_token_count",
        "tokens_out",
        "outputTokens",
        "completionTokens",
    )
    total_value, _ = _metadata_deep_first(
        metadata,
        "total_tokens",
        "totalTokenCount",
        "total_token_count",
        "tokens_total",
        "totalTokens",
        "token_count",
    )
    input_amount = _decimal(input_value)
    output_amount = _decimal(output_value)
    total_amount = _decimal(total_value)
    if input_amount is None:
        input_chars, _ = _metadata_deep_first(
            metadata,
            "input_chars",
            "prompt_chars",
            "request_chars",
            "inputCharacterCount",
            "promptCharacterCount",
            "requestCharacterCount",
        )
        input_amount = _token_estimate_from_chars(input_chars)
        if input_amount is None:
            input_amount = _token_estimate_from_chars(
                _metadata_text_length(
                    metadata,
                    "prompt_preview_redacted",
                    "redacted_prompt",
                    "original_intent",
                    "input_context_summary",
                )
            )
    if output_amount is None:
        output_chars, _ = _metadata_deep_first(
            metadata,
            "output_chars",
            "response_chars",
            "completion_chars",
            "outputCharacterCount",
            "responseCharacterCount",
            "completionCharacterCount",
        )
        output_amount = _token_estimate_from_chars(output_chars)
        if output_amount is None:
            output_amount = _token_estimate_from_chars(
                _metadata_text_length(
                    metadata,
                    "output_text_preview_redacted",
                    "response_preview_redacted",
                    "completion_preview_redacted",
                )
            )
    if total_amount is None and input_amount is not None and output_amount is not None:
        total_amount = input_amount + output_amount
    elif total_amount is None and (input_amount is not None or output_amount is not None):
        total_amount = (input_amount or Decimal("0")) + (output_amount or Decimal("0"))
    candidates = {
        "input_tokens": input_amount,
        "output_tokens": output_amount,
        "total_tokens": total_amount,
    }
    payloads: list[tuple[str, dict[str, Any]]] = []
    for metric, value in candidates.items():
        amount = value if isinstance(value, Decimal) else _decimal(value)
        if amount is None:
            continue
        payloads.append(
            (
                metric,
                {
                    "metric": metric,
                    "value": amount,
                    "unit": "tokens",
                    "reconciliation_key": f"runtime:{row.event_id}:{metric}",
                    "authoritative": False,
                    "duplicate_confidence": "UNKNOWN",
                },
            )
        )
    return payloads


def _runtime_spend_payload(row: RuntimeEvent, metadata: dict[str, Any]) -> dict[str, Any] | None:
    excluded = {
        "crq",
        "financials",
        "risk_event",
        "risk_reduced_usd",
        "risk_exposure_usd",
        "at_risk_if_ignored_usd",
        "annualized_loss_expectancy",
        "decision_score",
        "control_risk_profile",
    }
    billed_value, billed_path = _metadata_deep_first(
        metadata,
        "provider_billed_cost_usd",
        "billed_cost_usd",
        "invoice_cost_usd",
        excluded_path_markers=excluded,
    )
    reported_value, reported_path = _metadata_deep_first(
        metadata,
        "provider_reported_cost_usd",
        "reported_cost_usd",
        "provider_cost_usd",
        excluded_path_markers=excluded,
    )
    estimate_value, estimate_path = _metadata_deep_first(
        metadata,
        "estimated_cost_usd",
        "cost_usd",
        "usd_cost",
        "amount_usd",
        "estimatedCostUsd",
        "costUsd",
        excluded_path_markers=excluded,
    )
    generic_value, generic_path = _metadata_deep_first(
        metadata,
        "amount",
        "estimated_cost",
        "costAmount",
        excluded_path_markers=excluded,
        required_path_markers={"usage", "cost", "billing", "spend", "price"},
    )
    cents_value, _ = _metadata_deep_first(
        metadata,
        "estimated_cost_cents",
        "cost_cents",
        "costCents",
        excluded_path_markers=excluded,
    )
    micros_value, _ = _metadata_deep_first(
        metadata,
        "estimated_cost_micros",
        "cost_micros",
        "costMicros",
        "cost_usd_micros",
        excluded_path_markers=excluded,
    )

    amount = _decimal(billed_value or reported_value or estimate_value or generic_value)
    if amount is None and (cents := _decimal(cents_value)) is not None:
        amount = cents / Decimal("100")
    if amount is None and (micros := _decimal(micros_value)) is not None:
        amount = micros / Decimal("1000000")
    if amount is None:
        rate_card = metadata.get("rate_card")
        if isinstance(rate_card, dict):
            input_rate = _decimal(
                rate_card.get("input_usd_per_million")
                or rate_card.get("inputUsdPerMillion")
            )
            output_rate = _decimal(
                rate_card.get("output_usd_per_million")
                or rate_card.get("outputUsdPerMillion")
            )
            reference = _clean_string(rate_card.get("reference") or rate_card.get("contract_reference"))
            usage_payloads = {metric: payload for metric, payload in _runtime_usage_payloads(row, metadata)}
            input_tokens = _decimal((usage_payloads.get("input_tokens") or {}).get("value")) or Decimal("0")
            output_tokens = _decimal((usage_payloads.get("output_tokens") or {}).get("value")) or Decimal("0")
            if reference and input_rate is not None and output_rate is not None and (input_tokens or output_tokens):
                return {
                    "cost_type": CostType.CONTRACT_RATE_CARD.value,
                    "amount": ((input_tokens * input_rate) + (output_tokens * output_rate)) / Decimal("1000000"),
                    "currency": "USD",
                    "reconciliation_key": f"runtime:{row.event_id}:cost",
                    "allocation_method": "runtime_event_rate_card_projection",
                    "contract_reference": reference,
                }
    if amount is None:
        return None

    if billed_value is not None:
        cost_type = CostType.PROVIDER_BILLED.value
        selected_path = billed_path
    elif reported_value is not None:
        cost_type = CostType.PROVIDER_REPORTED.value
        selected_path = reported_path
    else:
        cost_type = CostType.CLIENT_ESTIMATE.value
        selected_path = estimate_path or generic_path

    currency_value, _ = _metadata_deep_first(
        metadata,
        "currency",
        "cost_currency",
        "costCurrency",
        excluded_path_markers=excluded,
        required_path_markers=set(selected_path) if selected_path else {"usage", "cost", "billing", "spend"},
    )
    currency = str(currency_value or metadata.get("currency") or "USD").upper()
    return {
        "cost_type": cost_type,
        "amount": amount,
        "currency": currency,
        "reconciliation_key": f"runtime:{row.event_id}:cost",
        "allocation_method": "runtime_event_projection",
    }


def _runtime_events_as_provider_signals(events: list[RuntimeEvent]) -> list[ProviderSignalRecord]:
    records: list[ProviderSignalRecord] = []
    for row in events:
        metadata = _metadata(row)
        provider = _runtime_provider(row, metadata)
        product = _runtime_product(provider, row, metadata)
        source_type = _runtime_source_type(row, metadata)
        client = _runtime_client(row, metadata)
        records.append(
            _runtime_record(
                row,
                provider=provider,
                product=product,
                source_type=source_type,
                record_kind=ProviderSignalKind.CLIENT_SESSION,
                suffix="client-session",
                payload={
                    "client_id": client,
                    "client_name": client,
                    "client_type": row.source_surface or "unknown",
                    "session_ref": _runtime_session_ref(row, metadata) or f"runtime:{row.event_id}",
                    "account_class": _clean_string(
                        _metadata_first(metadata, "account_class", "account_type"),
                        max_length=64,
                    ),
                    "device_assurance": _clean_string(metadata.get("device_assurance"), max_length=64),
                    "surface": row.source_surface or source_type or "unknown",
                    "started_at": _as_utc(row.created_at).isoformat(),
                },
            )
        )
        tool_payload = _runtime_tool_payload(row, metadata)
        if tool_payload:
            records.append(
                _runtime_record(
                    row,
                    provider=provider,
                    product=product,
                    source_type=source_type,
                    record_kind=ProviderSignalKind.TOOL,
                    suffix="tool",
                    payload=tool_payload,
                )
            )
        prompt_payload = _runtime_prompt_payload(row, metadata)
        if prompt_payload:
            records.append(
                _runtime_record(
                    row,
                    provider=provider,
                    product=product,
                    source_type=source_type,
                    record_kind=ProviderSignalKind.PROMPT,
                    suffix="prompt",
                    payload=prompt_payload,
                )
            )
        for metric, usage_payload in _runtime_usage_payloads(row, metadata):
            records.append(
                _runtime_record(
                    row,
                    provider=provider,
                    product=product,
                    source_type=source_type,
                    record_kind=ProviderSignalKind.USAGE,
                    suffix=f"usage:{metric}",
                    payload=usage_payload,
                )
            )
        spend_payload = _runtime_spend_payload(row, metadata)
        if spend_payload:
            records.append(
                _runtime_record(
                    row,
                    provider=provider,
                    product=product,
                    source_type=source_type,
                    record_kind=ProviderSignalKind.SPEND,
                    suffix="spend",
                    payload=spend_payload,
                )
            )
    return records


def _merge_provider_signal_records(
    provider_records: list[ProviderSignalRecord],
    runtime_records: list[ProviderSignalRecord],
) -> list[ProviderSignalRecord]:
    merged: dict[tuple[str, str, str, str], ProviderSignalRecord] = {}
    for row in [*runtime_records, *provider_records]:
        key = (row.tenant_id, row.provider, row.record_kind, row.source_record_id)
        current = merged.get(key)
        if current is None or _as_utc(row.occurred_at) >= _as_utc(current.occurred_at):
            merged[key] = row
    return list(merged.values())


def _record_summary(row: ProviderSignalRecord) -> dict[str, Any]:
    return {
        "id": row.id,
        "provider": row.provider,
        "product": row.product,
        "source_type": row.source_type,
        "source_schema_version": row.source_schema_version,
        "source_record_id": row.source_record_id,
        "record_kind": row.record_kind,
        "occurred_at": _as_utc(row.occurred_at).isoformat(),
        "user_id": row.user_id,
        "department": row.department,
        "client": row.client,
        "model": row.model,
        "session_ref": row.session_ref,
        "evidence_quality": row.evidence_quality,
    }


def _provider_rows(records: list[ProviderSignalRecord], now: datetime) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    known = ("anthropic", "openai", "cursor", "google")
    observed_extra = sorted(
        {
            row.provider
            for row in records
            if row.provider and row.provider not in known
        }
    )
    for provider in [*known, *observed_extra]:
        source_records = [row for row in records if row.provider == provider]
        latest = max((_as_utc(row.occurred_at) for row in source_records), default=None)
        dimensions: dict[str, str] = {}
        for row in sorted(source_records, key=lambda item: _as_utc(item.occurred_at)):
            if row.record_kind == ProviderSignalKind.CAPABILITY.value:
                dimensions[str(row.payload.get("dimension"))] = str(row.payload.get("status", "UNKNOWN"))
        result.append(
            {
                "provider": provider,
                "connection_state": "OBSERVED" if source_records else "DISCONNECTED",
                "source_types": sorted({row.source_type for row in source_records}),
                "products": sorted({row.product for row in source_records}),
                "last_event_at": latest.isoformat() if latest else None,
                "freshness": (
                    "CURRENT"
                    if latest and _as_utc(now) - latest <= _CURRENT_AGE
                    else "STALE"
                    if latest
                    else "UNKNOWN"
                ),
                "capabilities": dimensions,
                "capability_note": "Authentication or an observed event does not verify unobserved dimensions.",
            }
        )
    return result


def _usage(records: list[ProviderSignalRecord]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], Decimal] = defaultdict(Decimal)
    for row in records:
        if row.record_kind != ProviderSignalKind.USAGE.value:
            continue
        metric = str(row.payload.get("metric") or "").strip()
        unit = str(row.payload.get("unit") or "").strip()
        value = _decimal(row.payload.get("value"))
        if metric and unit and value is not None:
            buckets[(row.provider, metric, unit)] += value
    return [
        {"provider": provider, "metric": metric, "unit": unit, "value": value}
        for (provider, metric, unit), value in sorted(buckets.items())
    ]


def _spend(records: list[ProviderSignalRecord]) -> dict[str, Any]:
    groups: dict[tuple[str, str | None], list[ProviderSignalRecord]] = defaultdict(list)
    for row in records:
        if row.record_kind == ProviderSignalKind.SPEND.value:
            key = str(row.payload.get("reconciliation_key") or row.source_record_id)
            currency = str(row.payload.get("currency") or "").upper() or None
            groups[(key, currency)].append(row)
    chosen_records: list[dict[str, Any]] = []
    totals: dict[str, Decimal] = defaultdict(Decimal)
    for (reconciliation_key, currency), candidates in sorted(groups.items()):
        chosen = min(
            candidates,
            key=lambda row: _COST_PRECEDENCE.get(
                str(row.payload.get("cost_type") or CostType.UNAVAILABLE.value), 99
            ),
        )
        cost_type = str(chosen.payload.get("cost_type") or CostType.UNAVAILABLE.value)
        amount = _decimal(chosen.payload.get("amount"))
        if currency and amount is not None and cost_type != CostType.UNAVAILABLE.value:
            totals[currency] += amount
        chosen_records.append(
            {
                **_record_summary(chosen),
                "reconciliation_key": reconciliation_key,
                "cost_type": cost_type,
                "amount": amount,
                "currency": currency,
                "allocation_method": chosen.payload.get("allocation_method"),
                "billing_group": chosen.payload.get("billing_group"),
                "contract_reference": chosen.payload.get("contract_reference"),
                "supplementary_cost_types": sorted(
                    {
                        str(row.payload.get("cost_type"))
                        for row in candidates
                        if row is not chosen
                    }
                ),
            }
        )
    return {
        "totals_by_currency": dict(totals),
        "records": chosen_records,
        "cost_precedence": list(_COST_PRECEDENCE),
        "mixed_currency_total": None,
        "productivity_score_generated": False,
    }


def _seat_utilization(snapshots: list[ProviderSeatSnapshot], *, now: datetime) -> dict[str, Any]:
    """Return only the newest authoritative snapshot for each provider scope."""

    latest: dict[tuple[str, str, str], ProviderSeatSnapshot] = {}
    for row in snapshots:
        if row.source_type != ProviderSourceType.PROVIDER_ADMIN.value:
            continue
        key = (row.provider, row.product, row.billing_group or "")
        current = latest.get(key)
        if current is None or _as_utc(row.observed_at) > _as_utc(current.observed_at):
            latest[key] = row
    rows: list[dict[str, Any]] = []
    assigned_total = 0
    active_total = 0
    inactive_total = 0
    for (_, _, _), row in sorted(latest.items()):
        total_licensed = int(row.total_licensed_seats)
        assigned = int(row.assigned_seats)
        active = int(row.active_seats)
        inactive = int(row.inactive_seats)
        never_used = int(row.never_used_seats)
        unknown_activity = int(row.unknown_activity_seats)
        unassigned = total_licensed - assigned
        assigned_total += assigned
        active_total += active
        inactive_total += inactive
        freshness = "CURRENT" if _as_utc(now) - _as_utc(row.observed_at) <= _CURRENT_AGE else "STALE"
        status = (
            "UNKNOWN" if row.completeness == "UNKNOWN"
            else "PARTIAL" if row.completeness == "PARTIAL" or unassigned > 0
            else "STALE" if freshness == "STALE"
            else "CURRENT"
        )
        rows.append(
            {
                "id": row.id,
                "provider": row.provider,
                "product": row.product,
                "billing_group": row.billing_group,
                "total_licensed_seats": total_licensed,
                "assigned_seats": assigned,
                "active_seats": active,
                "inactive_seats": inactive,
                "never_used_seats": never_used,
                "unknown_activity_seats": unknown_activity,
                "unassigned_seats": unassigned,
                "utilization_percent": (Decimal(active) * Decimal("100") / Decimal(assigned)) if assigned else None,
                "observed_at": _as_utc(row.observed_at).isoformat(),
                "source_type": row.source_type,
                "evidence_quality": row.evidence_quality,
                "completeness": row.completeness,
                "freshness": freshness,
                "status": status,
            }
        )
    return {
        "assigned_seats": assigned_total,
        "total_licensed_seats": sum(int(row.total_licensed_seats) for row in latest.values()),
        "active_seats": active_total,
        "inactive_seats": inactive_total,
        "never_used_seats": sum(int(row.never_used_seats) for row in latest.values()),
        "unknown_activity_seats": sum(int(row.unknown_activity_seats) for row in latest.values()),
        "unassigned_seats": sum(int(row.total_licensed_seats) - int(row.assigned_seats) for row in latest.values()),
        "utilization_percent": (Decimal(active_total) * Decimal("100") / Decimal(assigned_total)) if assigned_total else None,
        "authoritative_snapshot_count": len(rows),
        "snapshots": rows,
        "unavailable_reason": None if rows else "no_current_provider_admin_seat_snapshot",
    }


def _mcp(records: list[ProviderSignalRecord]) -> dict[str, Any]:
    latest: dict[tuple[str, str, str], ProviderSignalRecord] = {}
    for row in records:
        if row.record_kind != ProviderSignalKind.TOOL.value:
            continue
        key = (
            str(row.payload.get("server_identity")),
            str(row.client or row.payload.get("client") or "unknown"),
            str(row.payload.get("configuration_scope") or "UNKNOWN"),
        )
        if key not in latest or _as_utc(row.occurred_at) > _as_utc(latest[key].occurred_at):
            latest[key] = row
    servers: list[dict[str, Any]] = []
    for (server_identity, client, scope), row in sorted(latest.items()):
        state = str(row.payload.get("connection_state") or "UNKNOWN").upper()
        invocation_count = int(row.payload.get("invocation_count") or 0)
        servers.append(
            {
                **_record_summary(row),
                "server_identity": server_identity,
                "connected_clients": [client],
                "configuration_scope": scope,
                "connection_state": state,
                "authentication_state": row.payload.get("authentication_state"),
                "transport": row.payload.get("transport"),
                "tool_name": row.payload.get("tool_name"),
                "tool_schema_hash": row.payload.get("tool_schema_hash"),
                "invocation_count": invocation_count,
                "trust_state": row.payload.get("trust_state", "UNKNOWN"),
                "drift_state": row.payload.get("drift_state", "UNKNOWN"),
                "configured_at_is_last_used": False,
            }
        )
    return {
        "summary": {
            "total_servers": len({row[0] for row in latest}),
            "configured": sum(1 for row in servers if row["connection_state"] == "CONFIGURED"),
            # A used server necessarily completed a connection even when the
            # source emits USED as its most advanced observed lifecycle state.
            "connected": sum(
                1
                for row in servers
                if row["connection_state"] in {"CONNECTED", "USED"}
            ),
            "used": sum(1 for row in servers if row["invocation_count"] > 0),
            "authentication_required": sum(1 for row in servers if row["connection_state"] == "AUTHENTICATION_REQUIRED"),
            "unhealthy": sum(1 for row in servers if row["connection_state"] == "UNHEALTHY"),
            "blocked": sum(1 for row in servers if row["connection_state"] in {"BLOCKED", "REVOKED", "QUARANTINED"}),
        },
        "servers": servers,
    }


def _prompts(records: list[ProviderSignalRecord], role: str) -> dict[str, Any]:
    prompt_records = [row for row in records if row.record_kind == ProviderSignalKind.PROMPT.value]
    can_view_individual = role in _INDIVIDUAL_ROLES
    items: list[dict[str, Any]] = []
    if can_view_individual:
        for row in sorted(prompt_records, key=lambda item: _as_utc(item.occurred_at), reverse=True)[:200]:
            items.append(
                {
                    **_record_summary(row),
                    "content_level": row.payload.get("content_level", "CONTENT_UNAVAILABLE"),
                    "category": row.payload.get("category") or row.payload.get("prompt_category"),
                    "classified_summary": row.payload.get("classified_summary"),
                    "redacted_preview": row.payload.get("redacted_preview"),
                    "data_classifications": list(row.payload.get("data_classifications") or []),
                    "injection_indicators": list(row.payload.get("injection_indicators") or []),
                    "instruction_provenance": list(row.payload.get("instruction_provenance") or []),
                    "policy_decision": row.payload.get("policy_decision"),
                }
            )
    return {
        "total": len(prompt_records),
        "items": items,
        "aggregate_only": not can_view_individual,
        "raw_prompt_stored": False,
        "privacy_levels": [
            "METADATA_ONLY",
            "CLASSIFIED_SUMMARY",
            "REDACTED_PREVIEW",
            "FULL_CONTENT_PRIVILEGED",
            "CONTENT_UNAVAILABLE",
        ],
    }


def _meeting(records: list[ProviderSignalRecord]) -> dict[str, Any]:
    rows = [row for row in records if row.record_kind == ProviderSignalKind.MEETING.value]
    return {
        "detected": len(rows),
        "held": sum(1 for row in rows if str(row.payload.get("action_state")).upper() == "HELD"),
        "blocked": sum(1 for row in rows if str(row.payload.get("action_state")).upper() == "BLOCKED"),
        "observed_only": sum(1 for row in rows if str(row.payload.get("action_state")).upper() == "OBSERVED"),
        "vendors": sorted({str(row.payload.get("vendor")) for row in rows if row.payload.get("vendor")}),
        "events": [{**_record_summary(row), **row.payload} for row in rows[:200]],
        "unsupported_physical_recording": True,
    }


def _accounts_devices(records: list[ProviderSignalRecord]) -> dict[str, Any]:
    rows = [row for row in records if row.record_kind == ProviderSignalKind.CLIENT_SESSION.value]
    account_classes = sorted(
        {
            str(row.payload.get("account_class"))
            for row in rows
            if row.payload.get("account_class")
        }
    )
    device_assurance = sorted(
        {
            str(row.payload.get("device_assurance"))
            for row in rows
            if row.payload.get("device_assurance")
        }
    )
    surfaces = sorted(
        {
            str(row.payload.get("surface") or row.source_type)
            for row in rows
            if row.payload.get("surface") or row.source_type
        }
    )
    clients = sorted({row.client or str(row.payload.get("client_id")) for row in rows if row.client or row.payload.get("client_id")})
    return {
        "source": "runtime client-session projection plus account-boundary and endpoint context where supplied",
        "summary": {
            "observed_sessions": len(rows),
            "account_classes": account_classes,
            "device_assurance": device_assurance,
            "surfaces": surfaces,
            "clients": clients,
        },
        "items": [
            {
                **_record_summary(row),
                "client_id": row.payload.get("client_id"),
                "account_class": row.payload.get("account_class"),
                "device_assurance": row.payload.get("device_assurance"),
                "surface": row.payload.get("surface"),
            }
            for row in sorted(rows, key=lambda item: _as_utc(item.occurred_at), reverse=True)[:200]
        ],
    }


def _data_controls(records: list[ProviderSignalRecord]) -> dict[str, Any]:
    prompt_rows = [row for row in records if row.record_kind == ProviderSignalKind.PROMPT.value]
    tool_rows = [row for row in records if row.record_kind == ProviderSignalKind.TOOL.value]
    classifications = sorted(
        {
            str(item)
            for row in prompt_rows
            for item in (row.payload.get("data_classifications") or [])
            if item
        }
    )
    upload_events = sum(
        1
        for row in [*prompt_rows, *tool_rows]
        if "upload" in " ".join(
            str(value or "")
            for value in (
                row.payload.get("category"),
                row.payload.get("prompt_category"),
                row.payload.get("tool_name"),
                row.source_record_id,
            )
        ).lower()
    )
    download_events = sum(
        1
        for row in [*prompt_rows, *tool_rows]
        if "download" in " ".join(
            str(value or "")
            for value in (
                row.payload.get("category"),
                row.payload.get("prompt_category"),
                row.payload.get("tool_name"),
                row.source_record_id,
            )
        ).lower()
    )
    return {
        "classifications": classifications,
        "classified_prompt_events": sum(1 for row in prompt_rows if row.payload.get("data_classifications")),
        "upload_events": upload_events,
        "download_events": download_events,
        "raw_values_exposed": False,
    }


def _capability_is_verified(records: list[ProviderSignalRecord], *dimensions: str) -> bool:
    requested = {dimension.strip().lower() for dimension in dimensions}
    for row in records:
        if row.record_kind != ProviderSignalKind.CAPABILITY.value:
            continue
        dimension = str(row.payload.get("dimension") or "").strip().lower()
        status = str(row.payload.get("status") or "").strip().upper()
        if dimension in requested and status in {"VERIFIED", "CURRENT"}:
            return True
    return False


def _has_runtime_projection(records: list[ProviderSignalRecord]) -> bool:
    return any(
        isinstance(row.projection_refs, dict)
        and row.projection_refs.get("projection_mode") == "RUNTIME_OBSERVED"
        for row in records
    )


def _authoritative_source_readiness(
    records: list[ProviderSignalRecord],
    *,
    spend: dict[str, Any],
    seats: dict[str, Any],
    mcp: dict[str, Any],
) -> dict[str, Any]:
    """Describe what is proven and which source is still required.

    This is intentionally a readiness contract, not a synthetic proof.  Runtime,
    browser, MCP and hook evidence can make activity visible, but cannot by
    itself become an enterprise denominator, billed spend, provider-admin seat
    truth or full control-coverage assertion.
    """

    spend_records = spend.get("records") if isinstance(spend, dict) else []
    cost_types = {
        str(row.get("cost_type") or "").upper()
        for row in spend_records
        if isinstance(row, dict)
    }
    source_types = {row.source_type for row in records if row.source_type}
    has_runtime = _has_runtime_projection(records)
    has_mcp_activity = bool(
        (mcp.get("summary") or {}).get("used")
        or (mcp.get("summary") or {}).get("blocked")
    )

    observed_spend: list[str] = []
    if "PROVIDER_REPORTED" in cost_types:
        observed_spend.append("provider_reported_spend")
    if "CONTRACT_RATE_CARD" in cost_types:
        observed_spend.append("contract_rate_card")
    if "CREDIT_CONSUMPTION" in cost_types:
        observed_spend.append("credit_consumption")
    if cost_types.intersection({"CLIENT_ESTIMATE", "HAWK_ESTIMATE"}):
        observed_spend.append("client_estimated_spend")

    control_evidence: list[str] = []
    if has_runtime:
        control_evidence.append("runtime_activity")
    if has_mcp_activity:
        control_evidence.append("mcp_activity")
    if source_types.intersection({ProviderSourceType.ENDPOINT.value, ProviderSourceType.HOOK.value}):
        control_evidence.append("client_or_endpoint_signal")
    if source_types.intersection({ProviderSourceType.PROVIDER_COMPLIANCE.value, ProviderSourceType.PROVIDER_AUDIT.value}):
        control_evidence.append("provider_control_signal")

    enterprise_denominator_authoritative = _capability_is_verified(
        records,
        "enterprise_denominator",
        "authoritative_denominator",
        "identity_denominator",
    )
    billed_spend_authoritative = "PROVIDER_BILLED" in cost_types
    seat_authoritative = bool((seats or {}).get("authoritative_snapshot_count"))
    control_coverage_authoritative = _capability_is_verified(
        records,
        "control_coverage",
        "full_control_coverage",
        "surface_coverage",
    )

    readiness = {
        "enterprise_denominator": {
            "status": "AUTHORITATIVE" if enterprise_denominator_authoritative else "MISSING_SOURCE",
            "label": "Enterprise denominator",
            "required_sources": [
                "identity_directory",
                "device_inventory",
                "managed_browser_fleet",
                "provider_admin",
            ],
            "observed_evidence": sorted(source_types),
            "connect_action": "Connect IdP/SCIM, MDM/endpoint inventory, managed browser fleet and provider-admin source.",
            "why_missing": "A complete enterprise population cannot be inferred from activity events alone.",
        },
        "provider_billed_spend": {
            "status": "AUTHORITATIVE" if billed_spend_authoritative else "MISSING_SOURCE",
            "label": "Provider-billed spend",
            "required_sources": ["provider_billing_api", "invoice_feed"],
            "observed_evidence": observed_spend,
            "connect_action": "Connect provider billing API or invoice feed for billed spend truth.",
            "why_missing": "Client-estimated or rate-card usage is useful for direction, but not billing truth.",
        },
        "provider_admin_seat_utilization": {
            "status": "AUTHORITATIVE" if seat_authoritative else "MISSING_SOURCE",
            "label": "Provider-admin seat utilization",
            "required_sources": ["provider_admin_seat_snapshot"],
            "observed_evidence": ["provider_admin_snapshot"] if seat_authoritative else [],
            "connect_action": "Connect provider-admin aggregate seat snapshot for licensed, assigned, active and inactive seats.",
            "why_missing": "Activity events cannot prove the licensed seat denominator.",
        },
        "full_control_coverage": {
            "status": "AUTHORITATIVE" if control_coverage_authoritative else "PARTIAL_EVIDENCE" if control_evidence else "MISSING_SOURCE",
            "label": "Full control coverage",
            "required_sources": [
                "control_receipts",
                "surface_health",
                "validation_results",
                "policy_assignments",
            ],
            "observed_evidence": control_evidence,
            "connect_action": "Connect control receipts, surface health and validation results before claiming full coverage.",
            "why_missing": "Observed actions do not prove every surface can enforce every control.",
        },
    }
    all_authoritative = all(
        item["status"] == "AUTHORITATIVE" for item in readiness.values()
    )
    any_observed = bool(records or (seats or {}).get("authoritative_snapshot_count"))
    return {
        "overall_status": "AUTHORITATIVE" if all_authoritative else "OBSERVED_ONLY" if any_observed else "MISSING_SOURCE",
        "items": list(readiness.values()),
        **readiness,
    }


def _anthropic_source_profiles(records: list[ProviderSignalRecord]) -> dict[str, Any] | None:
    anthropic_records = [row for row in records if row.provider == "anthropic"]
    if not anthropic_records:
        return None

    def has_record(*, org_types: set[str], source_types: set[str]) -> bool:
        return any(
            str(row.payload.get("anthropic_org_type") or "").strip().upper() in org_types
            or row.source_type in source_types
            for row in anthropic_records
        )

    def profile_source_types(*, org_types: set[str], source_types: set[str]) -> list[str]:
        return sorted(
            {
                row.source_type
                for row in anthropic_records
                if str(row.payload.get("anthropic_org_type") or "").strip().upper() in org_types
                or row.source_type in source_types
            }
        )

    console_sources = profile_source_types(
        org_types={"CONSOLE_ORG", "PLATFORM_ORG"},
        source_types={ProviderSourceType.PROVIDER_ADMIN.value, ProviderSourceType.PROVIDER_SPEND_API.value},
    )
    enterprise_sources = profile_source_types(
        org_types={"ENTERPRISE_ORG"},
        source_types={ProviderSourceType.PROVIDER_ANALYTICS.value},
    )
    personal_sources = profile_source_types(
        org_types={"PERSONAL_OR_SELF_REPORTED", "PERSONAL_PROXY", "PERSONAL_CODE_OTEL"},
        source_types={ProviderSourceType.OTEL.value},
    )
    desktop_sources = profile_source_types(
        org_types={"DESKTOP_OR_CONSUMER_CHAT", "CONSUMER_CHAT"},
        source_types=set(),
    )

    profiles = [
        {
            "profile": "console_admin_api",
            "status": "ATTESTED" if console_sources else "MISSING_SOURCE",
            "cost_label": "provider_reported" if console_sources else "unavailable",
            "source_types": console_sources,
            "required_credential": "Anthropic Admin API key or org-admin OAuth token",
            "notes": [
                "Admin keys are high-privilege organization credentials; do not present them as read-only scoped keys.",
                "Default workspace usage may have null workspace_id; playground API usage may have null api_key_id.",
            ],
        },
        {
            "profile": "enterprise_analytics_api",
            "status": "ATTESTED" if enterprise_sources else "MISSING_SOURCE",
            "cost_label": "provider_reported" if enterprise_sources else "unavailable",
            "source_types": enterprise_sources,
            "required_credential": "Claude Enterprise Analytics API key with read:analytics",
            "notes": [
                "Claude Enterprise parent organizations do not appear in Claude Console and do not use Console Admin API keys.",
            ],
        },
        {
            "profile": "personal_or_proxy",
            "status": "SELF_REPORTED" if personal_sources else "MISSING_SOURCE",
            "cost_label": "client_estimate" if personal_sources else "unavailable",
            "source_types": personal_sources,
            "required_credential": "Hawk proxy response usage or Claude Code OpenTelemetry",
            "notes": [
                "Personal-tier usage is modeled or client-reported, not provider-billed truth.",
                "Join Claude Code OTel to hook evidence with prompt_id and tool_use_id when present.",
            ],
        },
        {
            "profile": "desktop_or_consumer_chat",
            "status": "NOT_COVERED" if desktop_sources or has_record(org_types={"DESKTOP_OR_CONSUMER_CHAT", "CONSUMER_CHAT"}, source_types=set()) else "NO_PROVIDER_API",
            "cost_label": "unavailable",
            "source_types": desktop_sources,
            "required_credential": "No provider-side billing or usage API",
            "notes": [
                "Claude Desktop and consumer chat usage can be observed only through governed local surfaces; provider-billed telemetry is unavailable.",
            ],
        },
    ]
    statuses = {row["status"] for row in profiles}
    if "ATTESTED" in statuses and statuses.intersection({"SELF_REPORTED", "NOT_COVERED", "MISSING_SOURCE", "NO_PROVIDER_API"}):
        overall = "PARTIAL"
    elif statuses == {"ATTESTED"}:
        overall = "ATTESTED"
    elif "SELF_REPORTED" in statuses:
        overall = "SELF_REPORTED"
    else:
        overall = "MISSING_SOURCE"
    return {
        "provider": "anthropic",
        "overall_status": overall,
        "profiles": profiles,
        "source_contract": "anthropic-console-enterprise-personal/1",
        "connector_guidance": {
            "console_path": "Use Anthropic Console organization Admin API for usage_report/messages, cost_report and Claude Code usage reports.",
            "enterprise_path": "Use Claude Enterprise Analytics API for claude.ai Enterprise organizations.",
            "personal_path": "Use Hawk proxy response usage or Claude Code OpenTelemetry; mark costs as self-reported/client-estimated.",
            "desktop_path": "Do not claim provider billing telemetry for Claude Desktop or consumer chat.",
        },
    }


def _provider_source_profiles(records: list[ProviderSignalRecord]) -> dict[str, Any]:
    profiles: dict[str, Any] = {}
    anthropic = _anthropic_source_profiles(records)
    if anthropic is not None:
        profiles["anthropic"] = anthropic
    return profiles


def build_provider_signal_workspace_from_records(
    records: list[ProviderSignalRecord],
    *,
    tenant_id: str,
    now: datetime,
    role: str,
    seat_snapshots: list[ProviderSeatSnapshot] | None = None,
) -> dict[str, Any]:
    scoped = [row for row in records if row.tenant_id == tenant_id]
    usage = _usage(scoped)
    prompts = _prompts(scoped, role)
    spend = _spend(scoped)
    spend["seats"] = _seat_utilization(
        [row for row in (seat_snapshots or []) if row.tenant_id == tenant_id], now=now
    )
    mcp = _mcp(scoped)
    providers = _provider_rows(scoped, now)
    departments = sorted({row.department for row in scoped if row.department})
    users = {row.user_id for row in scoped if row.user_id}
    clients = sorted({row.client for row in scoped if row.client})
    data_controls = _data_controls(scoped)
    latest = max((_as_utc(row.occurred_at) for row in scoped), default=None)
    provider_gaps = [
        f"{row['provider']}: no current provider signal"
        for row in providers
        if row["freshness"] != "CURRENT"
    ]
    authoritative_readiness = _authoritative_source_readiness(
        scoped,
        spend=spend,
        seats=spend["seats"],
        mcp=mcp,
    )
    source_profiles = _provider_source_profiles(scoped)
    return {
        "tenant_id": tenant_id,
        "generated_at": _as_utc(now).isoformat(),
        "window": {"record_count": len(scoped), "bounded_limit": 5000, "last_signal_at": latest.isoformat() if latest else None},
        "overview": {
            "providers_observed": sum(1 for row in providers if row["connection_state"] != "DISCONNECTED"),
            "active_users": len(users),
            "departments": len(departments),
            "clients": len(clients),
            "prompts_observed": prompts["total"],
            "mcp_servers": mcp["summary"]["total_servers"],
            "meeting_bots": _meeting(scoped)["detected"],
            "source_coverage": sorted({row.source_type for row in scoped}),
            "freshness": "CURRENT" if latest and _as_utc(now) - latest <= _CURRENT_AGE else "STALE" if latest else "UNKNOWN",
        },
        "providers": providers,
        "users_departments": {"users": len(users), "departments": departments, "clients": clients},
        "usage": usage,
        "spend_utilization": spend,
        "prompts_actions": prompts,
        "mcp_tools": mcp,
        "accounts_devices": _accounts_devices(scoped),
        "data_controls": data_controls,
        "meeting_ai": _meeting(scoped),
        "policies": {"source": "existing deterministic Policy Engine", "items": []},
        "coverage_gaps": {"status": "PARTIAL" if scoped else "UNKNOWN", "gaps": provider_gaps},
        "authoritative_source_readiness": authoritative_readiness,
        "provider_source_profiles": source_profiles,
        "connector_health": [
            {
                "provider": row["provider"],
                "state": row["freshness"],
                "last_event_at": row["last_event_at"],
                "source_types": row["source_types"],
            }
            for row in providers
        ],
        "executive_report": {
            "title": "Enterprise AI Tools, Usage and Spend",
            "usage_is_not_productivity": True,
            "next_actions": provider_gaps[:5],
        },
    }


def build_provider_signal_workspace(
    db: Session,
    *,
    tenant_id: str,
    role: str,
    now: datetime | None = None,
    window_days: int = 30,
    limit: int = 5000,
) -> dict[str, Any]:
    observed_now = _as_utc(now or datetime.now(UTC))
    lower_bound = observed_now - timedelta(days=max(1, min(window_days, 366)))
    bounded_limit = max(1, min(limit, 5000))
    records = list(
        db.scalars(
            select(ProviderSignalRecord)
            .where(
                ProviderSignalRecord.tenant_id == tenant_id,
                ProviderSignalRecord.occurred_at >= lower_bound,
            )
            .order_by(ProviderSignalRecord.occurred_at.desc())
            .limit(bounded_limit)
        ).all()
    )
    runtime_events = list(
        db.scalars(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.tenant_id == tenant_id,
                RuntimeEvent.created_at >= lower_bound,
            )
            .order_by(RuntimeEvent.created_at.desc())
            .limit(bounded_limit)
        ).all()
    )
    runtime_projected_records = _runtime_events_as_provider_signals(runtime_events)
    scoped_records = _merge_provider_signal_records(records, runtime_projected_records)
    seat_snapshots = list(
        db.scalars(
            select(ProviderSeatSnapshot)
            .where(ProviderSeatSnapshot.tenant_id == tenant_id)
            .order_by(ProviderSeatSnapshot.observed_at.desc(), ProviderSeatSnapshot.id.asc())
            .limit(bounded_limit)
        ).all()
    )
    workspace = build_provider_signal_workspace_from_records(
        scoped_records,
        tenant_id=tenant_id,
        now=observed_now,
        role=role,
        seat_snapshots=seat_snapshots,
    )
    workspace["window"]["days"] = window_days
    workspace["window"]["bounded_limit"] = bounded_limit
    workspace["window"]["provider_signal_record_count"] = len(records)
    workspace["window"]["runtime_event_count"] = len(runtime_events)
    workspace["window"]["runtime_projection_count"] = len(runtime_projected_records)
    return workspace
