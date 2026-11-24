"""Privacy-bounded projection for one enrolled endpoint metadata snapshot.

This module deliberately accepts only the existing endpoint metadata scanner's
allowlisted output. It creates typed HMAIR observation contracts but does not
perform network discovery, collect raw endpoint material, or claim fleet-wide
coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryTarget,
)
from app.services.hmair.contracts import DiscoveryObservationInput
from app.services.hmair.contracts import DiscoveryScanCreate
from app.services.hmair.evidence_fusion_service import fuse_scan_observations
from app.services.hmair.observation_service import ingest_observation
from app.services.hmair.scan_service import (
    claim_assignment_batch,
    create_scan_with_outcome,
    finalize_assignment,
    finalize_scan,
    start_assignment,
)
from app.services.hmair.endpoint_metadata_inventory_service import (
    complete_endpoint_metadata_inventory_assignment,
    fail_endpoint_metadata_inventory_assignment,
)
from app.services.privacy_sanitizer import redact_sensitive_text


ENDPOINT_METADATA_SCHEMA_VERSION = "hawk.endpoint_metadata.v1"
ENDPOINT_SNAPSHOT_COLLECTOR_TYPE = "endpoint_metadata_snapshot"
ENDPOINT_SNAPSHOT_PROJECTION_VERSION = "1.0.0"
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+ -]{0,127}$")
_SAFE_SNAPSHOT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SEMANTIC_VERSION_RE = re.compile(
    r"^\d{1,3}(?:\.\d{1,5}){1,3}(?:[-+][A-Za-z0-9.-]{1,32})?$"
)
_PHONE_LIKE_DOTTED_VALUE_RE = re.compile(
    r"^(?:\d{1,3}\.)?\d{2,3}\.\d{3}\.\d{4}$"
)


def _safe_text(value: object, *, field: str, max_length: int = 128) -> str:
    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > max_length
        or _SAFE_TEXT.fullmatch(normalized) is None
        or redact_sensitive_text(normalized, max_len=max_length) != normalized
    ):
        raise ValueError(f"{field} contains unsafe metadata")
    return normalized


def _safe_version(value: object, *, field: str) -> str:
    """Accept only a bounded semantic version or the explicit unknown marker."""

    if type(value) is not str:
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if normalized == "unknown":
        return normalized
    if (
        len(normalized) > 64
        or _PHONE_LIKE_DOTTED_VALUE_RE.fullmatch(normalized)
        or _SEMANTIC_VERSION_RE.fullmatch(normalized) is None
    ):
        raise ValueError(f"{field} contains unsafe metadata")
    return normalized


class _StrictSnapshotModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )


class EndpointMetadataAccount(_StrictSnapshotModel):
    status: Literal["unknown"]
    identifiers_collected: Literal[False]


class EndpointMetadataProduct(_StrictSnapshotModel):
    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    category: str = Field(min_length=1, max_length=64)
    presence: Literal["present", "unknown"]
    version: str = Field(min_length=1, max_length=64)
    evidence_types: tuple[str, ...] = Field(max_length=16)
    approval_status: Literal["unknown"]
    account: EndpointMetadataAccount

    @field_validator("id", "name", "provider", "category")
    @classmethod
    def _safe_scalar(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return _safe_text(value, field=info.field_name, max_length=128)

    @field_validator("version")
    @classmethod
    def _safe_version_scalar(cls, value: str) -> str:
        return _safe_version(value, field="version")

    @field_validator("evidence_types")
    @classmethod
    def _safe_evidence_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _safe_text(item, field="evidence_types", max_length=64)
            for item in value
        )


class EndpointMetadataExtension(_StrictSnapshotModel):
    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    host: str = Field(min_length=1, max_length=64)
    category: Literal["ide", "browser"]
    presence: Literal["present", "unknown"]
    version: str = Field(min_length=1, max_length=64)
    approval_status: Literal["unknown"]

    @field_validator("id", "name", "provider", "host")
    @classmethod
    def _safe_scalar(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return _safe_text(value, field=info.field_name, max_length=128)

    @field_validator("version")
    @classmethod
    def _safe_version_scalar(cls, value: str) -> str:
        return _safe_version(value, field="version")


class EndpointMCPConfiguration(_StrictSnapshotModel):
    name: str = Field(min_length=1, max_length=128)
    transport: Literal["remote", "stdio", "unknown"]
    destination_host: str | None = Field(default=None, max_length=128, pattern=r"^[a-z0-9.-]+$")
    executable: Literal["npx", "node", "uvx", "uv", "python", "python3", "docker", "npx.cmd", "node.exe", "python.exe"] | None = None

    @field_validator("name", "destination_host")
    @classmethod
    def _safe_mcp_text(cls, value: str | None, info) -> str | None:
        return _safe_text(value, field=info.field_name, max_length=128) if value is not None else None


class EndpointConfigurationMetadata(_StrictSnapshotModel):
    model: str | None = Field(default=None, max_length=128)
    model_provider: str | None = Field(default=None, max_length=64)
    approval_policy: str | None = Field(default=None, max_length=64)
    sandbox_mode: str | None = Field(default=None, max_length=64)
    mcp_server_names: tuple[str, ...] = Field(default=(), max_length=32)
    mcp_servers: tuple[EndpointMCPConfiguration, ...] = Field(default=(), max_length=32)

    @field_validator(
        "model", "model_provider", "approval_policy", "sandbox_mode"
    )
    @classmethod
    def _safe_optional_scalar(
        cls, value: str | None, info  # type: ignore[no-untyped-def]
    ) -> str | None:
        if value is None:
            return None
        return _safe_text(value, field=info.field_name, max_length=128)

    @field_validator("mcp_server_names")
    @classmethod
    def _safe_mcp_server_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            _safe_text(item, field="mcp_server_names", max_length=128)
            for item in value
        )


class EndpointMetadataConfiguration(_StrictSnapshotModel):
    product_id: str = Field(min_length=1, max_length=64)
    kind: Literal["mcp_agent_configuration"]
    source: str = Field(min_length=1, max_length=64)
    status: Literal["present"]
    metadata: EndpointConfigurationMetadata

    @field_validator("product_id", "source")
    @classmethod
    def _safe_scalar(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return _safe_text(value, field=info.field_name, max_length=64)


class EndpointMetadataError(_StrictSnapshotModel):
    source: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=1, max_length=64)

    @field_validator("source", "code")
    @classmethod
    def _safe_scalar(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return _safe_text(value, field=info.field_name, max_length=64)


class EndpointMetadataPrivacy(_StrictSnapshotModel):
    raw_file_contents_collected: Literal[False]
    prompts_collected: Literal[False]
    browser_history_collected: Literal[False]
    cookies_collected: Literal[False]
    secrets_or_tokens_collected: Literal[False]
    account_identifiers_collected: Literal[False]
    persistent_state_written: Literal[False]


class EndpointMetadataSnapshotInput(_StrictSnapshotModel):
    """The exact safe payload the endpoint agent may submit for a lab scan."""

    snapshot_id: str = Field(min_length=1, max_length=128)
    inventory_assignment_id: UUID | None = None
    schema_version: Literal[ENDPOINT_METADATA_SCHEMA_VERSION]
    collected_at: datetime
    collection_mode: Literal["one_shot_read_only"]
    status: Literal["completed", "error"]
    network_used: Literal[False]
    products: tuple[EndpointMetadataProduct, ...] = Field(max_length=32)
    extensions: tuple[EndpointMetadataExtension, ...] = Field(max_length=64)
    configurations: tuple[EndpointMetadataConfiguration, ...] = Field(max_length=32)
    errors: tuple[EndpointMetadataError, ...] = Field(max_length=64)
    privacy: EndpointMetadataPrivacy

    @field_validator("snapshot_id")
    @classmethod
    def _safe_snapshot_id(cls, value: str) -> str:
        normalized = value.strip()
        if _SAFE_SNAPSHOT_ID.fullmatch(normalized) is None:
            raise ValueError("snapshot_id contains unsafe metadata")
        return normalized

    @field_validator("collected_at")
    @classmethod
    def _aware_collected_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a timezone")
        return value.astimezone(timezone.utc)


def _digest_snapshot(snapshot: EndpointMetadataSnapshotInput) -> str:
    return sha256(
        json.dumps(
            snapshot.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _observation_id(
    *, scan_id: str, snapshot_id: str, kind: str, identifier: str
) -> str:
    digest = sha256(
        f"{scan_id}:{snapshot_id}:{kind}:{identifier}".encode("utf-8")
    ).hexdigest()
    return f"endpoint-snapshot-{digest}"


def _endpoint_reference(endpoint_id: str) -> str:
    """Keep local endpoint identifiers out of HMAIR observation payloads."""

    # The general privacy sanitizer correctly recognizes long digit runs as
    # possible phone data. Encode each hash nibble as a letter so this stable
    # pseudonym is not reinterpreted as a human identifier downstream.
    digest = sha256(endpoint_id.encode("utf-8")).hexdigest()[:24]
    token = "".join(chr(ord("a") + int(character, 16)) for character in digest)
    return f"endpoint:{token}"


def _opaque_token(value: str) -> str:
    digest = sha256(value.encode("utf-8")).hexdigest()[:32]
    return "".join(chr(ord("a") + int(character, 16)) for character in digest)


def _scope(endpoint_reference: str) -> dict[str, object]:
    return {
        "scope_type": "enrolled_endpoint",
        "endpoint_reference": endpoint_reference,
        "endpoint_denominator": 1,
        "coverage_claim": "single_enrolled_endpoint",
        "scanner_mode": "one_shot_read_only",
    }


def _observation(
    *,
    snapshot: EndpointMetadataSnapshotInput,
    scan_id: str,
    collector_id: str,
    collector_version: str,
    target_id: str,
    endpoint_reference: str,
    kind: str,
    identifier: str,
    observation_type: str,
    source_surface: str,
    candidate_asset_type: str,
    observed_state: str,
    identifiers: dict[str, str],
    attributes: dict[str, object],
    configuration_summary: dict[str, object],
    capability_hints: tuple[str, ...] = (),
) -> DiscoveryObservationInput:
    evidence_hash = _digest_snapshot(snapshot)
    return DiscoveryObservationInput(
        observation_id=_observation_id(
            scan_id=scan_id,
            snapshot_id=snapshot.snapshot_id,
            kind=kind,
            identifier=identifier,
        ),
        scan_id=scan_id,
        collector_id=collector_id,
        collector_type=ENDPOINT_SNAPSHOT_COLLECTOR_TYPE,
        collector_version=collector_version,
        target_id=target_id,
        source_surface=source_surface,
        subject_reference=endpoint_reference,
        observation_type=observation_type,
        normalized_signal={
            "observation_kind": kind,
            "scanner_schema": snapshot.schema_version,
            "collection_mode": snapshot.collection_mode,
        },
        observed_at=snapshot.collected_at,
        candidate_asset_type=candidate_asset_type,
        observed_state=observed_state,
        identifiers=identifiers,
        attributes=attributes,
        configuration_summary=configuration_summary,
        usage_summary={"usage_evidence": "not_collected"},
        capability_hints=capability_hints,
        identity_hints=({"identity_type": "endpoint_device"},),
        relationship_hints=(
            {
                "relationship_type": "observed_on",
                "target_id": target_id,
            },
        ),
        evidence_reference=(
            f"endpoint-snapshot://{endpoint_reference}/{snapshot.snapshot_id}"
        ),
        evidence_hash=evidence_hash,
        signature_status="verified_endpoint_dpop",
        confidence=0.8,
        freshness="fresh",
        verification_state="partially_verified",
        source_trust="strong",
        collection_scope=_scope(endpoint_reference),
        parser_version=ENDPOINT_SNAPSHOT_PROJECTION_VERSION,
        schema_version=snapshot.schema_version,
        evidence_mode="direct",
        evidence_mutability="mutable",
        contradiction_state="none",
        contradiction_references=(),
        sensitivity="metadata",
        redaction_status="not_required",
    )


def project_endpoint_metadata_snapshot(
    *,
    snapshot: EndpointMetadataSnapshotInput,
    scan_id: str,
    collector_id: str,
    collector_version: str,
    target_id: str,
    endpoint_id: str,
) -> tuple[DiscoveryObservationInput, ...]:
    """Project one safe local snapshot into evidence-backed HMAIR facts.

    No observation represents organisation-wide use, policy approval, account
    identity, runtime execution, or a connected remote source.
    """

    result: list[DiscoveryObservationInput] = []
    endpoint_reference = _endpoint_reference(endpoint_id)
    for product in sorted(snapshot.products, key=lambda item: item.id):
        if product.presence != "present":
            continue
        result.append(
            _observation(
                snapshot=snapshot,
                scan_id=scan_id,
                collector_id=collector_id,
                collector_version=collector_version,
                target_id=target_id,
                endpoint_reference=endpoint_reference,
                kind="product",
                identifier=product.id,
                observation_type="installed_application",
                source_surface="endpoint",
                candidate_asset_type="ai_application",
                observed_state="installed",
                identifiers={"product_id": product.id},
                attributes={
                    "name": product.name,
                    "provider": product.provider,
                    "category": product.category,
                    "version": product.version,
                },
                configuration_summary={
                    "evidence_types": list(product.evidence_types),
                    "approval_status": product.approval_status,
                    "account_status": product.account.status,
                },
                capability_hints=tuple(product.evidence_types),
            )
        )

    for extension in sorted(
        snapshot.extensions, key=lambda item: (item.host, item.id)
    ):
        if extension.presence != "present":
            continue
        result.append(
            _observation(
                snapshot=snapshot,
                scan_id=scan_id,
                collector_id=collector_id,
                collector_version=collector_version,
                target_id=target_id,
                endpoint_reference=endpoint_reference,
                kind="extension",
                identifier=f"{extension.host}:{extension.id}",
                observation_type="browser_extension",
                source_surface=(
                    "browser" if extension.category == "browser" else "endpoint"
                ),
                candidate_asset_type="ai_application",
                observed_state="installed",
                identifiers={
                    "extension_id": extension.id,
                    "host": extension.host,
                },
                attributes={
                    "name": extension.name,
                    "provider": extension.provider,
                    "version": extension.version,
                    "category": extension.category,
                },
                configuration_summary={
                    "approval_status": extension.approval_status,
                    "activity_observed": False,
                },
            )
        )

    for configuration in sorted(
        snapshot.configurations, key=lambda item: (item.product_id, item.source)
    ):
        metadata = configuration.metadata
        configuration_attributes = {
            key: value
            for key, value in {
                "model": metadata.model,
                "model_provider": metadata.model_provider,
                "approval_policy": metadata.approval_policy,
                "sandbox_mode": metadata.sandbox_mode,
            }.items()
            if value is not None
        }
        if configuration_attributes:
            result.append(
                _observation(
                    snapshot=snapshot,
                    scan_id=scan_id,
                    collector_id=collector_id,
                    collector_version=collector_version,
                    target_id=target_id,
                    endpoint_reference=endpoint_reference,
                    kind="configuration",
                    identifier=f"{configuration.product_id}:{configuration.source}",
                    observation_type="agent_config",
                    source_surface="endpoint",
                    candidate_asset_type="agent_configuration",
                    observed_state="configured",
                    identifiers={
                        "product_id": configuration.product_id,
                        "configuration_source": configuration.source,
                    },
                    attributes=configuration_attributes,
                    configuration_summary={
                        "configuration_kind": configuration.kind,
                        "mcp_server_count": len(metadata.mcp_server_names),
                    },
                )
            )
        for mcp_server_name in sorted(set(metadata.mcp_server_names)):
            connection = next((item for item in metadata.mcp_servers if item.name == mcp_server_name), None)
            connection_metadata = connection.model_dump(exclude_none=True, exclude={"name"}) if connection else {}
            result.append(
                _observation(
                    snapshot=snapshot,
                    scan_id=scan_id,
                    collector_id=collector_id,
                    collector_version=collector_version,
                    target_id=target_id,
                    endpoint_reference=endpoint_reference,
                    kind="mcp_server",
                    identifier=(
                        f"{configuration.product_id}:{configuration.source}:"
                        f"{mcp_server_name}"
                    ),
                    observation_type="mcp_server",
                    source_surface="mcp",
                    candidate_asset_type="mcp_server",
                    observed_state="configured",
                    identifiers={"mcp_server_name": mcp_server_name},
                    attributes={
                        "product_id": configuration.product_id,
                        "configuration_source": configuration.source,
                        **connection_metadata,
                    },
                    configuration_summary={
                        "configuration_kind": configuration.kind,
                        "runtime_activity_observed": False,
                    },
                )
            )

    return tuple(result)


_UNCONNECTED_SURFACE_LIMITATIONS = (
    "browser_activity:not_connected",
    "mcp_runtime:not_connected",
    "llm_runtime:not_connected",
    "saas:not_connected",
    "cloud:not_connected",
    "identity:not_connected",
    "repository:not_connected",
    "network:not_connected",
    "database:not_connected",
)


@dataclass(frozen=True, slots=True)
class EndpointMetadataSnapshotReceipt:
    scan_id: str
    status: str
    observations_count: int
    endpoint_denominator: int
    limitations: tuple[str, ...]


def _snapshot_limitations(
    snapshot: EndpointMetadataSnapshotInput,
) -> tuple[str, ...]:
    scanner_errors = tuple(
        f"scanner:{item.source}:{item.code}" for item in snapshot.errors
    )
    return (
        "coverage:single_enrolled_endpoint",
        "active_scan:not_performed",
        "raw_content:not_collected",
        *_UNCONNECTED_SURFACE_LIMITATIONS,
        *scanner_errors,
    )


def _snapshot_target_id(endpoint_id: str) -> str:
    return f"endpoint-group:{_opaque_token(endpoint_id)}"


def _snapshot_collector_id(endpoint_id: str) -> str:
    return f"endpoint-metadata:{_opaque_token(endpoint_id)}"


def _collector_declaration_hash(
    *, collector_id: str, collector_version: str
) -> str:
    declaration = {
        "collector_id": collector_id,
        "collector_type": ENDPOINT_SNAPSHOT_COLLECTOR_TYPE,
        "version": collector_version,
        "supported_targets": ["endpoint_group"],
        "active_capabilities": [],
        "passive_capabilities": ["metadata_snapshot"],
        "permissions_required": ["endpoint:discovery:write"],
        "sensitive_data_accessed": [],
        "data_residency": "endpoint_local_metadata",
        "control_capability": "monitor_only",
        "schema_version": ENDPOINT_METADATA_SCHEMA_VERSION,
    }
    return sha256(
        json.dumps(
            declaration, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()


def _ensure_target_and_collector(
    db: Session,
    *,
    tenant_id: str,
    endpoint_id: str,
    collector_version: str,
    snapshot: EndpointMetadataSnapshotInput,
    limitations: tuple[str, ...],
) -> tuple[DiscoveryTarget, DiscoveryCollector]:
    target_id = _snapshot_target_id(endpoint_id)
    collector_id = _snapshot_collector_id(endpoint_id)
    endpoint_reference = _endpoint_reference(endpoint_id)
    target = db.scalar(
        select(DiscoveryTarget).where(
            DiscoveryTarget.tenant_id == tenant_id,
            DiscoveryTarget.target_id == target_id,
        )
    )
    if target is None:
        target = DiscoveryTarget(
            target_id=target_id,
            tenant_id=tenant_id,
            target_type="endpoint_group",
            identifier=f"enrolled-endpoint:{endpoint_reference.split(':', 1)[1]}",
            environment="controlled_lab",
            owner_hint=None,
            credentials_reference=None,
            permitted_methods_json=["collect_inventory"],
            exclusions_json=list(_UNCONNECTED_SURFACE_LIMITATIONS),
            rate_limit=1,
            active_scan_allowed=True,
            sensitive_scope=False,
            coverage_baseline_json={
                "expected_count": 1,
                "authority_kind": "mdm",
                "authority_reference": f"endpoint_identity:{_opaque_token(endpoint_reference)}",
                "verified_at": snapshot.collected_at.isoformat(),
                "expires_at": (snapshot.collected_at + timedelta(days=7)).isoformat(),
            },
            last_scanned_at=snapshot.collected_at,
        )
        db.add(target)
    elif (
        target.target_type != "endpoint_group"
        or not str(target.identifier or "").startswith("enrolled-endpoint:")
    ):
        raise ValueError("endpoint snapshot target configuration conflict")
    else:
        target.permitted_methods_json = ["collect_inventory"]
        target.active_scan_allowed = True
        target.coverage_baseline_json = {
            "expected_count": 1,
            "authority_kind": "mdm",
            "authority_reference": f"endpoint_identity:{_opaque_token(endpoint_reference)}",
            "verified_at": snapshot.collected_at.isoformat(),
            "expires_at": (snapshot.collected_at + timedelta(days=7)).isoformat(),
        }
        target.last_scanned_at = snapshot.collected_at

    collector = db.scalar(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id == collector_id,
        )
    )
    healthy = snapshot.status == "completed"
    declaration_hash = _collector_declaration_hash(
        collector_id=collector_id,
        collector_version=collector_version,
    )
    if collector is None:
        collector = DiscoveryCollector(
            collector_id=collector_id,
            tenant_id=tenant_id,
            collector_type=ENDPOINT_SNAPSHOT_COLLECTOR_TYPE,
            version=collector_version,
            supported_targets_json=["endpoint_group"],
            active_capabilities_json=[],
            passive_capabilities_json=["metadata_snapshot"],
            permissions_required_json=["endpoint:discovery:write"],
            sensitive_data_accessed_json=[],
            health="healthy" if healthy else "warning",
            last_success_at=snapshot.collected_at if healthy else None,
            last_failure_at=snapshot.collected_at if not healthy else None,
            data_residency="endpoint_local_metadata",
            control_capability="monitor_only",
            schema_version=ENDPOINT_METADATA_SCHEMA_VERSION,
            limitations_json=list(limitations),
            declaration_hash=declaration_hash,
        )
        db.add(collector)
    elif collector.collector_type != ENDPOINT_SNAPSHOT_COLLECTOR_TYPE:
        raise ValueError("endpoint snapshot collector configuration conflict")
    else:
        collector.version = collector_version
        collector.health = "healthy" if healthy else "warning"
        collector.last_success_at = snapshot.collected_at if healthy else collector.last_success_at
        collector.last_failure_at = snapshot.collected_at if not healthy else collector.last_failure_at
        collector.limitations_json = list(limitations)
        collector.declaration_hash = declaration_hash
    db.flush()
    return target, collector


def _receipt(
    scan: DiscoveryScan,
    *,
    limitations: tuple[str, ...],
) -> EndpointMetadataSnapshotReceipt:
    return EndpointMetadataSnapshotReceipt(
        scan_id=scan.scan_id,
        status=scan.status,
        observations_count=scan.observations_count,
        endpoint_denominator=1,
        limitations=limitations,
    )


def ingest_endpoint_metadata_snapshot(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    endpoint_id: str,
    endpoint_identity_id: str | None = None,
    collector_version: str,
    snapshot: EndpointMetadataSnapshotInput,
) -> EndpointMetadataSnapshotReceipt:
    """Persist one passive, enrolled-endpoint HMAIR scan.

    The caller owns the transaction. Replaying the same endpoint/snapshot pair
    returns the original scan. A changed payload under the same snapshot ID is
    rejected by the existing scan idempotency digest.
    """

    if type(endpoint_id) is not str or not endpoint_id.strip():
        raise ValueError("endpoint snapshot endpoint identifier is invalid")
    collector_version = _safe_text(
        collector_version, field="collector_version", max_length=64
    )
    endpoint_reference = _endpoint_reference(endpoint_id)
    limitations = _snapshot_limitations(snapshot)
    target, collector = _ensure_target_and_collector(
        db,
        tenant_id=tenant_id,
        endpoint_id=endpoint_id,
        collector_version=collector_version,
        snapshot=snapshot,
        limitations=limitations,
    )
    snapshot_token = _opaque_token(
        f"{endpoint_reference}:{snapshot.snapshot_id}:{_digest_snapshot(snapshot)}"
    )
    payload = DiscoveryScanCreate(
        name="Endpoint metadata snapshot",
        scan_type="collector_specific",
        scope={
            "scope_type": "enrolled_endpoint",
            "endpoint_reference": endpoint_reference,
            "endpoint_denominator": 1,
            "coverage_claim": "single_enrolled_endpoint",
            "snapshot_evidence_marker": snapshot_token,
            "limitations": list(limitations),
        },
        target_ids=(target.target_id,),
        collector_ids=(collector.collector_id,),
        safety_profile="metadata_only",
        dry_run=False,
    )
    request_idempotency_key = sha256(
        f"endpoint-snapshot:{endpoint_reference}:{snapshot.snapshot_id}".encode(
            "utf-8"
        )
    ).hexdigest()
    outcome = create_scan_with_outcome(
        db,
        tenant_id=tenant_id,
        requested_by=actor_user_id,
        request_idempotency_key=request_idempotency_key,
        payload=payload,
    )
    if not outcome.created:
        receipt = _receipt(outcome.scan, limitations=limitations)
        _bind_inventory_assignment(
            db,
            tenant_id=tenant_id,
            endpoint_identity_id=endpoint_identity_id,
            snapshot=snapshot,
            receipt=receipt,
        )
        return receipt

    claimed = claim_assignment_batch(
        db, tenant_id=tenant_id, scan_id=outcome.scan.scan_id, limit=1
    )
    if len(claimed) != 1:
        raise RuntimeError("endpoint snapshot assignment could not be claimed")
    assignment = start_assignment(
        db,
        tenant_id=tenant_id,
        assignment_id=claimed[0].assignment_id,
    )
    if assignment is None:
        raise RuntimeError("endpoint snapshot assignment is unavailable")

    observations = project_endpoint_metadata_snapshot(
        snapshot=snapshot,
        scan_id=outcome.scan.scan_id,
        collector_id=collector.collector_id,
        collector_version=collector_version,
        target_id=target.target_id,
        endpoint_id=endpoint_id,
    )
    for observation in observations:
        ingest_observation(db, tenant_id=tenant_id, payload=observation)
    if settings.hmair_fingerprinting:
        fuse_scan_observations(
            db,
            tenant_id=tenant_id,
            scan_id=outcome.scan.scan_id,
        )
    terminal_status = "complete" if snapshot.status == "completed" else "failed"
    finalize_assignment(
        db,
        tenant_id=tenant_id,
        assignment_id=assignment.assignment_id,
        status=terminal_status,
        observations_count=len(observations),
        warning=("metadata scanner reported one or more bounded errors" if snapshot.errors else None),
        error=("metadata scanner did not complete" if terminal_status == "failed" else None),
    )
    scan = finalize_scan(db, tenant_id=tenant_id, scan_id=outcome.scan.scan_id)
    scan.coverage_summary_json = {
        "observed_endpoint_count": 1,
        "endpoint_denominator": 1,
        "coverage_claim": "single_enrolled_endpoint",
        "unconnected_sources": list(_UNCONNECTED_SURFACE_LIMITATIONS),
    }
    scan.warnings_json = list(limitations)
    scan.errors_json = [
        f"scanner:{item.source}:{item.code}" for item in snapshot.errors
    ]
    db.flush()
    receipt = _receipt(scan, limitations=limitations)
    _bind_inventory_assignment(
        db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoint_identity_id,
        snapshot=snapshot,
        receipt=receipt,
    )
    return receipt


def _bind_inventory_assignment(
    db: Session,
    *,
    tenant_id: str,
    endpoint_identity_id: str | None,
    snapshot: EndpointMetadataSnapshotInput,
    receipt: EndpointMetadataSnapshotReceipt,
) -> None:
    """Atomically bind a fleet receipt when the endpoint was assigned work."""

    if snapshot.inventory_assignment_id is None:
        return
    if type(endpoint_identity_id) is not str or not endpoint_identity_id:
        raise ValueError("endpoint inventory receipt lacks an authenticated identity")
    assignment_id = str(snapshot.inventory_assignment_id)
    if receipt.status in {"complete", "completed"}:
        complete_endpoint_metadata_inventory_assignment(
            db,
            tenant_id=tenant_id,
            endpoint_identity_id=endpoint_identity_id,
            assignment_id=assignment_id,
            scan_id=receipt.scan_id,
            observations_count=receipt.observations_count,
        )
        return
    fail_endpoint_metadata_inventory_assignment(
        db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoint_identity_id,
        assignment_id=assignment_id,
        code="scanner_rejected",
    )


__all__ = [
    "ENDPOINT_METADATA_SCHEMA_VERSION",
    "ENDPOINT_SNAPSHOT_COLLECTOR_TYPE",
    "ENDPOINT_SNAPSHOT_PROJECTION_VERSION",
    "EndpointMetadataSnapshotInput",
    "EndpointMetadataSnapshotReceipt",
    "ingest_endpoint_metadata_snapshot",
    "project_endpoint_metadata_snapshot",
]
