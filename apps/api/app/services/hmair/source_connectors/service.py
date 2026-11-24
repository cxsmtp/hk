"""Tenant-scoped provisioning for explicitly typed HMAIR source connections."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget
from app.db.models.monitoring import Connector
from app.services.connector_secret_service import (
    decrypt_connector_secrets,
    encrypt_connector_secrets,
)
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.source_connectors.contracts import (
    HMAIRSourceCapability,
    HMAIRSourceConnectionInput,
    HMAIRSourceProvider,
    SOURCE_FLAG_BY_PROVIDER,
    TARGET_TYPE_BY_PROVIDER,
)
from app.services.hmair.source_connectors.registry import source_registry
from app.services.hmair.source_connectors.runtime import source_http_for_connection


_SOURCE_LIMITATIONS = {
    HMAIRSourceProvider.MICROSOFT365: (
        "unlicensed_copilot_chat_not_reported_by_graph",
        "customer_connection_pending",
    ),
    HMAIRSourceProvider.GITHUB_CLOUD: (
        "source_denominator_unavailable",
        "customer_connection_pending",
    ),
    HMAIRSourceProvider.GITHUB_GHES: (
        "copilot_usage_source_not_confirmed",
        "customer_connection_pending",
    ),
}


@dataclass(frozen=True)
class HMAIRSourceConnectionRecord:
    connector: Connector
    target: DiscoveryTarget
    collector: DiscoveryCollector
    capability: HMAIRSourceCapability
    created: bool


def _digest(*parts: str) -> str:
    return sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _binding_hash(input: HMAIRSourceConnectionInput) -> str:
    return _digest(
        input.provider_key.value,
        input.target_identifier,
        input.authorization_reference,
    )


def _capability(input: HMAIRSourceConnectionInput) -> HMAIRSourceCapability:
    return HMAIRSourceCapability(
        provider_key=input.provider_key,
        state="not_connected",
        allowed_capabilities=(),
        limitations=_SOURCE_LIMITATIONS[input.provider_key],
    )


def _stored_capability(
    connector: Connector, *, provider: HMAIRSourceProvider
) -> HMAIRSourceCapability:
    metadata = connector.metadata_json if isinstance(connector.metadata_json, dict) else {}
    contract = metadata.get("hmair_source_contract")
    stored = contract.get("capability") if isinstance(contract, dict) else None
    try:
        capability = HMAIRSourceCapability.model_validate(stored)
    except (TypeError, ValueError):
        capability = None
    if capability is not None and capability.provider_key is provider:
        return capability
    return HMAIRSourceCapability(
        provider_key=provider,
        state="not_connected",
        allowed_capabilities=(),
        limitations=_SOURCE_LIMITATIONS[provider],
    )


def _connection_input(
    *, connector: Connector, target: DiscoveryTarget, provider: HMAIRSourceProvider
) -> HMAIRSourceConnectionInput:
    metadata = connector.metadata_json if isinstance(connector.metadata_json, dict) else {}
    contract = metadata.get("hmair_source_contract")
    if not isinstance(contract, dict):
        raise ValueError("HMAIR source contract is missing")
    return HMAIRSourceConnectionInput.model_validate(
        {
            "provider_key": provider.value,
            "display_name": connector.name,
            "target_identifier": target.identifier,
            "environment": target.environment,
            # The request reference is deliberately stored only as a one-way
            # binding hash. Validation never needs the original value.
            "authorization_reference": "source-approval-binding",
            "requested_capabilities": tuple(contract.get("requested_capabilities", ())),
            "include_entra_account_evidence": bool(
                contract.get("include_entra_account_evidence", False)
            ),
            "metadata": contract.get("source_metadata", {}),
            "credentials": decrypt_connector_secrets(connector.encrypted_secrets),
        }
    )


def _persist_capability(
    *,
    connector: Connector,
    collector: DiscoveryCollector,
    capability: HMAIRSourceCapability,
    validated_at: datetime,
) -> None:
    """Persist only the bounded capability result, never provider responses."""

    metadata = dict(connector.metadata_json) if isinstance(connector.metadata_json, dict) else {}
    contract = metadata.get("hmair_source_contract")
    if not isinstance(contract, dict):
        raise ValueError("HMAIR source contract is missing")
    next_contract = dict(contract)
    next_contract["capability"] = capability.model_dump(mode="json")
    metadata["hmair_source_contract"] = next_contract
    connector.metadata_json = metadata

    if capability.state in {"ready", "partial", "empty"}:
        connector.enabled = True
        connector.status = "active"
        connector.last_pull_status = "never"
        connector.last_pull_error = None
        collector.health = "warning" if capability.state == "partial" else "healthy"
        collector.last_success_at = capability.fresh_at or validated_at
        collector.last_failure_at = None
        return

    connector.enabled = False
    connector.status = "degraded"
    connector.last_pull_status = "error"
    connector.last_pull_error = capability.state
    collector.health = "unknown" if capability.state == "not_connected" else "degraded"
    collector.last_failure_at = validated_at


def validate_source_connection(
    db: Session,
    *,
    tenant_id: str,
    connection_id: str,
    now: datetime | None = None,
) -> HMAIRSourceConnectionRecord | None:
    """Validate an explicitly enabled customer connection with no stored payloads.

    A disabled bridge is intentionally a no-op: its configured secret is never
    dereferenced and its prior capability is left unchanged.
    """

    record = get_source_connection(db, tenant_id=tenant_id, connection_id=connection_id)
    if record is None:
        return None
    provider = record.capability.provider_key
    if (
        settings.hmair_connector_sources is not True
        or getattr(settings, SOURCE_FLAG_BY_PROVIDER[provider], False) is not True
    ):
        return record
    validated_at = now or datetime.now(UTC)
    if validated_at.tzinfo is None or validated_at.utcoffset() is None:
        raise ValueError("HMAIR source validation requires a timezone-aware time")
    source_http: object | None = None
    inventory_record_count: int | None = None
    try:
        connection = _connection_input(
            connector=record.connector, target=record.target, provider=provider
        )
        source_http = source_http_for_connection(connection)
        collector = source_registry.get_collector(provider.value)
        capability = collector.validate(
            connection, source_http, now=validated_at.astimezone(UTC)
        )
        if (
            provider
            in {
                HMAIRSourceProvider.GITHUB_CLOUD,
                HMAIRSourceProvider.GITHUB_GHES,
            }
            and "repository_inventory" in capability.allowed_capabilities
            and capability.state in {"ready", "partial"}
        ):
            result = collector.collect(
                connection,
                (validated_at - timedelta(days=1), validated_at),
                source_http,
                identifier_salt=tenant_id,
            )
            from app.services.github_repository_access_service import (
                derive_github_repository_ai_connections,
                persist_github_inventory_unit,
            )

            for row in result.records:
                if row.record_kind in {
                    "github_organization",
                    "github_repository",
                    "github_repository_access",
                    "github_repository_protection",
                    "github_repository_ai_connection",
                }:
                    persist_github_inventory_unit(
                        db,
                        tenant_id=tenant_id,
                        connection_id=record.connector.id,
                        record=row.model_dump(mode="python"),
                    )
            derive_github_repository_ai_connections(db, tenant_id=tenant_id)
            capability = result.capability
            inventory_record_count = len(result.records)
    except Exception:
        capability = HMAIRSourceCapability(
            provider_key=provider,
            state="failed",
            allowed_capabilities=(),
            limitations=("source_validation_failed",),
        )
    finally:
        close = getattr(source_http, "close", None)
        if callable(close):
            close()
    _persist_capability(
        connector=record.connector,
        collector=record.collector,
        capability=capability,
        validated_at=validated_at.astimezone(UTC),
    )
    if inventory_record_count is not None:
        record.connector.last_run_at = validated_at.astimezone(UTC)
        record.connector.last_pull_status = "success"
        record.connector.last_pull_error = None
        record.connector.last_signal_count = inventory_record_count
    return HMAIRSourceConnectionRecord(
        connector=record.connector,
        target=record.target,
        collector=record.collector,
        capability=capability,
        created=False,
    )


def _source_contract(input: HMAIRSourceConnectionInput, *, binding_hash: str) -> dict[str, Any]:
    authorization_hash = _digest(input.authorization_reference)
    return {
        "version": "v1",
        "provider_key": input.provider_key.value,
        "metadata_only": True,
        "target_binding_hash": binding_hash,
        "authorization_binding_hash": authorization_hash,
        "requested_capabilities": list(input.requested_capabilities),
        "include_entra_account_evidence": input.include_entra_account_evidence,
        "source_metadata": dict(input.metadata),
        "capability": _capability(input).model_dump(mode="json"),
    }


def _find_connector(
    db: Session, *, tenant_id: str, provider_key: str, binding_hash: str
) -> Connector | None:
    candidates = tuple(
        db.scalars(
            select(Connector).where(
                Connector.tenant_id == tenant_id,
                Connector.provider_key == provider_key,
                Connector.connector_type == "hmair_source",
            )
        ).all()
    )
    for row in candidates:
        config = row.config if isinstance(row.config, dict) else {}
        if config.get("source_binding_hash") == binding_hash:
            return row
    return None


def _records_for_connector(
    db: Session, *, tenant_id: str, connector: Connector
) -> tuple[DiscoveryTarget, DiscoveryCollector] | None:
    target = db.scalar(
        select(DiscoveryTarget).where(
            DiscoveryTarget.tenant_id == tenant_id,
            DiscoveryTarget.credentials_reference == f"connector:{connector.id}",
        )
    )
    if target is None:
        return None
    config = connector.config if isinstance(connector.config, dict) else {}
    binding_hash = config.get("source_binding_hash")
    if not isinstance(binding_hash, str) or not binding_hash:
        return None
    collector = db.scalar(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id == f"hmair-source-{binding_hash[:48]}",
        )
    )
    if collector is None:
        return None
    return target, collector


def provision_source_connection(
    db: Session,
    *,
    tenant_id: str,
    input: HMAIRSourceConnectionInput,
) -> HMAIRSourceConnectionRecord:
    """Create a disabled source prerequisite without writing any secret to metadata."""

    binding_hash = _binding_hash(input)
    connector = _find_connector(
        db,
        tenant_id=tenant_id,
        provider_key=input.provider_key.value,
        binding_hash=binding_hash,
    )
    if connector is not None:
        records = _records_for_connector(db, tenant_id=tenant_id, connector=connector)
        if records is not None:
            target, collector = records
            return HMAIRSourceConnectionRecord(
                connector=connector,
                target=target,
                collector=collector,
                capability=_capability(input),
                created=False,
            )
        raise RuntimeError("HMAIR source connection is incomplete")

    target_id = f"hmair-source-{binding_hash[:48]}"
    collector_id = f"hmair-source-{binding_hash[:48]}"
    source_contract = _source_contract(input, binding_hash=binding_hash)
    encrypted_secrets = encrypt_connector_secrets(dict(input.credentials))
    connector = Connector(
        tenant_id=tenant_id,
        name=input.display_name,
        connector_type="hmair_source",
        provider_key=input.provider_key.value,
        auth_type=(
            "client_credentials"
            if input.provider_key is HMAIRSourceProvider.MICROSOFT365
            else "github_app"
            if input.provider_key is HMAIRSourceProvider.GITHUB_CLOUD
            else "bearer"
        ),
        enabled=False,
        status="pending",
        config={"source_binding_hash": binding_hash, "contract_version": "v1"},
        encrypted_secrets=encrypted_secrets,
        is_stub=False,
        last_pull_status="never",
        metadata_json={"hmair_source_contract": source_contract},
    )
    db.add(connector)
    db.flush()
    target = DiscoveryTarget(
        tenant_id=tenant_id,
        target_id=target_id,
        target_type=TARGET_TYPE_BY_PROVIDER[input.provider_key],
        identifier=input.target_identifier,
        environment=input.environment,
        owner_hint="customer_source_admin",
        credentials_reference=f"connector:{connector.id}",
        permitted_methods_json=["collect_inventory"],
        exclusions_json=["raw_content", "source_payload_retention"],
        rate_limit=100,
        active_scan_allowed=False,
        sensitive_scope=False,
        coverage_baseline_json={},
    )
    declaration_material = {
        "collector_id": collector_id,
        "provider_key": input.provider_key.value,
        "target_type": target.target_type,
        "capabilities": list(input.requested_capabilities),
        "limitations": list(_SOURCE_LIMITATIONS[input.provider_key]),
    }
    collector = DiscoveryCollector(
        tenant_id=tenant_id,
        collector_id=collector_id,
        collector_type="hmair_source_connector",
        version="v1",
        supported_targets_json=[target.target_type],
        active_capabilities_json=[],
        passive_capabilities_json=list(input.requested_capabilities),
        permissions_required_json=list(input.requested_capabilities),
        sensitive_data_accessed_json=[],
        health="unknown",
        last_success_at=None,
        last_failure_at=None,
        data_residency="customer_source",
        control_capability="monitor_only",
        schema_version="v1",
        limitations_json=list(_SOURCE_LIMITATIONS[input.provider_key]),
        declaration_hash=sha256(canonical_json_bytes(declaration_material)).hexdigest(),
    )
    db.add_all([target, collector])
    db.flush()
    return HMAIRSourceConnectionRecord(
        connector=connector,
        target=target,
        collector=collector,
        capability=_capability(input),
        created=True,
    )


def get_source_connection(
    db: Session, *, tenant_id: str, connection_id: str
) -> HMAIRSourceConnectionRecord | None:
    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.id == connection_id,
            Connector.connector_type == "hmair_source",
        )
    )
    if connector is None:
        return None
    records = _records_for_connector(db, tenant_id=tenant_id, connector=connector)
    if records is None:
        return None
    contract = connector.metadata_json.get("hmair_source_contract", {}) if isinstance(connector.metadata_json, dict) else {}
    provider_value = contract.get("provider_key") if isinstance(contract, dict) else None
    try:
        provider = HMAIRSourceProvider(provider_value)
    except ValueError:
        return None
    capability = _stored_capability(connector, provider=provider)
    target, collector = records
    return HMAIRSourceConnectionRecord(
        connector=connector,
        target=target,
        collector=collector,
        capability=capability,
        created=False,
    )


def list_source_connections(
    db: Session, *, tenant_id: str
) -> tuple[HMAIRSourceConnectionRecord, ...]:
    rows = tuple(
        db.scalars(
            select(Connector)
            .where(
                Connector.tenant_id == tenant_id,
                Connector.connector_type == "hmair_source",
            )
            .order_by(Connector.name, Connector.id)
        ).all()
    )
    return tuple(
        record
        for row in rows
        if (record := get_source_connection(db, tenant_id=tenant_id, connection_id=row.id))
        is not None
    )


__all__ = [
    "HMAIRSourceConnectionRecord",
    "get_source_connection",
    "list_source_connections",
    "provision_source_connection",
    "validate_source_connection",
]
