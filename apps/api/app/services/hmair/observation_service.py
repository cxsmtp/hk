from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryObservation,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryTarget,
)
from app.services.hmair.contracts import (
    DiscoveryObservationInput,
    is_safe_semantic_version,
)
from app.services.privacy_sanitizer import sanitize_privacy_payload


_OBSERVATION_RETRY_CONSTRAINT = "uq_discovery_observation_retry"
_SQLITE_OBSERVATION_RETRY_COLUMNS = (
    "discovery_observations.tenant_id",
    "discovery_observations.scan_id",
    "discovery_observations.collector_id",
    "discovery_observations.idempotency_key",
)
_SANITIZED_PAYLOAD_FIELDS = (
    "subject_reference",
    "normalized_signal",
    "attributes",
    "configuration_summary",
    "usage_summary",
    "identity_hints",
    "relationship_hints",
    "collection_scope",
    "contradiction_references",
)


class HMAIRScopeError(RuntimeError):
    """The observation does not belong to the caller's declared scan scope."""


class HMAIRIdempotencyConflict(RuntimeError):
    """An observation retry reused an idempotency key with altered content."""


def observation_idempotency_key(
    *, tenant_id: str, payload: DiscoveryObservationInput
) -> str:
    material = {
        "tenant_id": tenant_id,
        "scan_id": payload.scan_id,
        "collector_id": payload.collector_id,
        "target_id": payload.target_id,
        "observation_id": payload.observation_id,
    }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def observation_payload_digest(
    *, sanitized_payload: Mapping[str, Any]
) -> str:
    encoded = json.dumps(
        sanitized_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sanitized_payload(payload: DiscoveryObservationInput) -> dict[str, Any]:
    material = payload.model_dump(mode="json")
    for field_name in _SANITIZED_PAYLOAD_FIELDS:
        original = material[field_name]
        sanitized = sanitize_privacy_payload(original)
        if (
            field_name == "attributes"
            and isinstance(original, Mapping)
            and isinstance(sanitized, dict)
            and is_safe_semantic_version(original.get("version"))
        ):
            sanitized["version"] = original["version"]
        material[field_name] = sanitized
    return material


def _scope_assignment(
    db: Session,
    *,
    tenant_id: str,
    payload: DiscoveryObservationInput,
) -> DiscoveryScanAssignment:
    scan_exists = db.scalar(
        select(DiscoveryScan.scan_id).where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.scan_id == payload.scan_id,
        )
    )
    collector_exists = db.scalar(
        select(DiscoveryCollector.collector_id).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id == payload.collector_id,
        )
    )
    target_exists = db.scalar(
        select(DiscoveryTarget.target_id).where(
            DiscoveryTarget.tenant_id == tenant_id,
            DiscoveryTarget.target_id == payload.target_id,
        )
    )
    if scan_exists is None or collector_exists is None or target_exists is None:
        raise HMAIRScopeError("observation scope is not available")

    assignment = db.scalar(
        select(DiscoveryScanAssignment).where(
            DiscoveryScanAssignment.tenant_id == tenant_id,
            DiscoveryScanAssignment.scan_id == payload.scan_id,
            DiscoveryScanAssignment.target_id == payload.target_id,
            DiscoveryScanAssignment.collector_id == payload.collector_id,
        )
    )
    if assignment is None:
        raise HMAIRScopeError("observation assignment is not available")
    return assignment


def _existing_observation(
    db: Session,
    *,
    tenant_id: str,
    payload: DiscoveryObservationInput,
    idempotency_key: str,
) -> DiscoveryObservation | None:
    return db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.tenant_id == tenant_id,
            DiscoveryObservation.scan_id == payload.scan_id,
            DiscoveryObservation.collector_id == payload.collector_id,
            DiscoveryObservation.idempotency_key == idempotency_key,
        )
    )


def _is_observation_retry_unique_violation(error: IntegrityError) -> bool:
    original = error.orig
    sqlstate = getattr(original, "sqlstate", None) or getattr(
        original, "pgcode", None
    )
    diagnostic = getattr(original, "diag", None)
    if sqlstate == "23505":
        return (
            getattr(diagnostic, "constraint_name", None)
            == _OBSERVATION_RETRY_CONSTRAINT
        )

    if not isinstance(original, sqlite3.IntegrityError):
        return False
    if (
        getattr(original, "sqlite_errorcode", None)
        != sqlite3.SQLITE_CONSTRAINT_UNIQUE
    ):
        return False
    if len(original.args) != 1 or not isinstance(original.args[0], str):
        return False
    expected = "UNIQUE constraint failed: " + ", ".join(
        _SQLITE_OBSERVATION_RETRY_COLUMNS
    )
    return original.args[0] == expected


def _resolve_replay(
    existing: DiscoveryObservation | None,
    *,
    payload_digest: str,
) -> DiscoveryObservation:
    if existing is None:
        raise HMAIRIdempotencyConflict(
            "observation retry could not be resolved"
        )
    if existing.payload_digest != payload_digest:
        raise HMAIRIdempotencyConflict(
            "observation idempotency key was reused with altered content"
        )
    return existing


def ingest_observation(
    db: Session,
    *,
    tenant_id: str,
    payload: DiscoveryObservationInput,
) -> DiscoveryObservation:
    assignment = _scope_assignment(
        db,
        tenant_id=tenant_id,
        payload=payload,
    )
    sanitized_payload = _sanitized_payload(payload)
    idempotency_key = observation_idempotency_key(
        tenant_id=tenant_id,
        payload=payload,
    )
    payload_digest = observation_payload_digest(
        sanitized_payload=sanitized_payload
    )

    existing = _existing_observation(
        db,
        tenant_id=tenant_id,
        payload=payload,
        idempotency_key=idempotency_key,
    )
    if existing is not None:
        return _resolve_replay(existing, payload_digest=payload_digest)

    observation = DiscoveryObservation(
        observation_id=payload.observation_id,
        tenant_id=tenant_id,
        assignment_id=assignment.assignment_id,
        scan_id=payload.scan_id,
        collector_id=payload.collector_id,
        collector_type=payload.collector_type,
        collector_version=payload.collector_version,
        target_id=payload.target_id,
        source_surface=payload.source_surface.value,
        subject_reference=sanitized_payload["subject_reference"],
        normalized_signal_json=sanitized_payload["normalized_signal"],
        observed_at=payload.observed_at,
        received_at=datetime.now(timezone.utc),
        observation_type=payload.observation_type,
        candidate_asset_type=payload.candidate_asset_type,
        observed_state=payload.observed_state.value,
        identifiers_json=sanitized_payload["identifiers"],
        attributes_json=sanitized_payload["attributes"],
        configuration_summary_json=sanitized_payload[
            "configuration_summary"
        ],
        usage_summary_json=sanitized_payload["usage_summary"],
        capability_hints_json=sanitized_payload["capability_hints"],
        identity_hints_json=sanitized_payload["identity_hints"],
        relationship_hints_json=sanitized_payload["relationship_hints"],
        evidence_reference=payload.evidence_reference,
        evidence_hash=payload.evidence_hash,
        signature_status=payload.signature_status,
        confidence=payload.confidence,
        freshness=payload.freshness.value,
        verification_state=payload.verification_state.value,
        source_trust=payload.source_trust.value,
        collection_scope_json=sanitized_payload["collection_scope"],
        parser_version=payload.parser_version,
        schema_version=payload.schema_version,
        evidence_mode=payload.evidence_mode.value,
        evidence_mutability=payload.evidence_mutability.value,
        contradiction_state=payload.contradiction_state.value,
        contradiction_references_json=sanitized_payload[
            "contradiction_references"
        ],
        sensitivity=payload.sensitivity,
        redaction_status=payload.redaction_status,
        idempotency_key=idempotency_key,
        payload_digest=payload_digest,
    )

    try:
        with db.begin_nested():
            db.add(observation)
            db.flush()
    except IntegrityError as error:
        if not _is_observation_retry_unique_violation(error):
            raise
        winner = _existing_observation(
            db,
            tenant_id=tenant_id,
            payload=payload,
            idempotency_key=idempotency_key,
        )
        return _resolve_replay(winner, payload_digest=payload_digest)

    return observation
