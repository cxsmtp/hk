from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.discovery_resolution import (
    DiscoveryAssetHypothesis,
    DiscoveryVerificationTask,
)
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes


TASK_TYPES = frozenset(
    {
        "endpoint_confirm", "process_confirm", "package_confirm",
        "cloud_resource_confirm", "saas_admin_confirm", "identity_confirm",
        "network_confirm", "repo_confirm", "mcp_confirm",
        "model_endpoint_confirm", "usage_confirm", "owner_confirm",
        "runtime_confirm",
    }
)
SAFE_METHODS = frozenset(
    {
        "endpoint_metadata", "process_metadata", "package_metadata",
        "cloud_metadata", "saas_admin_metadata", "identity_metadata",
        "network_metadata", "repository_metadata", "mcp_metadata",
        "model_metadata", "usage_aggregate", "owner_directory",
        "runtime_metadata",
    }
)
SENSITIVE_KEY_TOKENS = (
    "secret", "token", "password", "credential", "cookie", "prompt",
    "source_code", "file_content", "database_row", "vector_content",
)


class VerificationTaskConflict(RuntimeError):
    """Verification work is unsafe, out of scope, expired, or conflicting."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerificationTaskConflict("verification timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime) -> datetime:
    """SQLite drops offsets from persisted UTC verification timestamps."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_metadata(value: object, *, depth: int = 0) -> None:
    if depth > 6:
        raise VerificationTaskConflict("verification scope is too deeply nested")
    if isinstance(value, Mapping):
        if len(value) > 64:
            raise VerificationTaskConflict("verification scope is too large")
        for key, nested in value.items():
            if type(key) is not str or any(
                token in key.casefold() for token in SENSITIVE_KEY_TOKENS
            ):
                raise VerificationTaskConflict(
                    "verification scope may contain metadata references only"
                )
            _safe_metadata(nested, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 128:
            raise VerificationTaskConflict("verification scope is too large")
        for nested in value:
            _safe_metadata(nested, depth=depth + 1)
        return
    if value is None or type(value) in {str, int, float, bool}:
        if type(value) is str and len(value.encode("utf-8")) > 1024:
            raise VerificationTaskConflict("verification metadata value is too large")
        return
    raise VerificationTaskConflict("verification scope contains unsupported data")


def _digest(material: dict[str, object]) -> str:
    return hashlib.sha256(
        b"hawk:discovery:verification-task:v1" + canonical_json_bytes(material)
    ).hexdigest()


def _hypothesis(
    db: Session, *, tenant_id: str, hypothesis_id: str
) -> DiscoveryAssetHypothesis:
    row = db.scalar(
        select(DiscoveryAssetHypothesis).where(
            DiscoveryAssetHypothesis.tenant_id == tenant_id,
            DiscoveryAssetHypothesis.hypothesis_id == hypothesis_id,
        )
    )
    if row is None:
        raise VerificationTaskConflict("verification hypothesis is unavailable")
    return row


def enqueue_verification_task(
    db: Session,
    *,
    tenant_id: str,
    hypothesis_id: str,
    task_type: str,
    method: str,
    scope: Mapping[str, object],
    rate_limit_key: str,
    priority: int,
    max_attempts: int,
    expires_at: datetime,
    idempotency_key: str,
    now: datetime,
    max_active_per_key: int = 5,
    verification_episode_id: str | None = None,
    verification_requirement_id: str | None = None,
    task_contract_version: str = "legacy",
) -> DiscoveryVerificationTask:
    if task_type not in TASK_TYPES or method not in SAFE_METHODS:
        raise VerificationTaskConflict("verification task is unsupported or unsafe")
    if type(priority) is not int or not 0 <= priority <= 100:
        raise VerificationTaskConflict("verification priority is invalid")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
        raise VerificationTaskConflict("verification attempt bound is invalid")
    if not rate_limit_key or len(rate_limit_key) > 255:
        raise VerificationTaskConflict("verification rate limit key is invalid")
    if (verification_episode_id is None) != (verification_requirement_id is None):
        raise VerificationTaskConflict("verification episode binding is incomplete")
    if not task_contract_version or len(task_contract_version) > 32:
        raise VerificationTaskConflict("verification task contract version is invalid")
    _safe_metadata(scope)
    if len(canonical_json_bytes(dict(scope))) > 8192:
        raise VerificationTaskConflict("verification scope exceeds its byte budget")
    now = _utc(now)
    expires_at = _utc(expires_at)
    if expires_at <= now:
        raise VerificationTaskConflict("verification task is already expired")
    if expires_at - now > timedelta(days=7):
        raise VerificationTaskConflict("verification task expiry exceeds seven days")
    _hypothesis(db, tenant_id=tenant_id, hypothesis_id=hypothesis_id)
    material = {
        "tenant_id": tenant_id,
        "hypothesis_id": hypothesis_id,
        "task_type": task_type,
        "method": method,
        "scope": dict(scope),
        "rate_limit_key": rate_limit_key,
        "priority": priority,
        "max_attempts": max_attempts,
        "expires_at": expires_at.isoformat(),
        "verification_episode_id": verification_episode_id,
        "verification_requirement_id": verification_requirement_id,
        "task_contract_version": task_contract_version,
    }
    input_digest = _digest(material)
    existing = db.scalar(
        select(DiscoveryVerificationTask).where(
            DiscoveryVerificationTask.tenant_id == tenant_id,
            DiscoveryVerificationTask.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != input_digest:
            raise VerificationTaskConflict("verification idempotency conflict")
        return existing
    active = db.scalar(
        select(func.count(DiscoveryVerificationTask.task_id)).where(
            DiscoveryVerificationTask.tenant_id == tenant_id,
            DiscoveryVerificationTask.rate_limit_key == rate_limit_key,
            DiscoveryVerificationTask.status.in_(("pending", "claimed")),
        )
    )
    if int(active or 0) >= max_active_per_key:
        raise VerificationTaskConflict("verification rate limit is saturated")
    row = DiscoveryVerificationTask(
        task_id=str(uuid4()),
        tenant_id=tenant_id,
        hypothesis_id=hypothesis_id,
        verification_episode_id=verification_episode_id,
        verification_requirement_id=verification_requirement_id,
        task_contract_version=task_contract_version,
        task_type=task_type,
        status="pending",
        method=method,
        scope_json=dict(scope),
        rate_limit_key=rate_limit_key,
        priority=priority,
        max_attempts=max_attempts,
        attempt_count=0,
        expires_at=expires_at,
        claimed_by=None,
        claimed_at=None,
        completed_at=None,
        result_evidence_node_id=None,
        limitations_json=[],
        idempotency_key=idempotency_key,
        input_digest=input_digest,
    )
    db.add(row)
    db.flush()
    return row


def claim_verification_task(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
    worker_id: str,
    now: datetime,
) -> DiscoveryVerificationTask:
    statement = select(DiscoveryVerificationTask).where(
        DiscoveryVerificationTask.tenant_id == tenant_id,
        DiscoveryVerificationTask.task_id == task_id,
    )
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True)
    row = db.scalar(statement)
    if row is None:
        raise VerificationTaskConflict("verification task is unavailable")
    now = _utc(now)
    expires_at = _stored_utc(row.expires_at)
    if expires_at <= now:
        row.status = "expired"
        row.completed_at = now
        db.flush()
        raise VerificationTaskConflict("verification task expired before claim")
    if row.status != "pending" or row.attempt_count >= row.max_attempts:
        raise VerificationTaskConflict("verification task cannot be claimed")
    if not worker_id or worker_id != worker_id.strip() or len(worker_id) > 255:
        raise VerificationTaskConflict("verification worker identity is invalid")
    row.status = "claimed"
    row.claimed_by = worker_id
    row.claimed_at = now
    row.attempt_count += 1
    db.flush()
    return row


def complete_verification_task(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
    worker_id: str,
    outcome: str,
    evidence_node_id: str | None,
    limitations: Sequence[str],
    now: datetime,
) -> DiscoveryVerificationTask:
    row = db.scalar(
        select(DiscoveryVerificationTask).where(
            DiscoveryVerificationTask.tenant_id == tenant_id,
            DiscoveryVerificationTask.task_id == task_id,
        )
    )
    if row is None or row.status != "claimed" or row.claimed_by != worker_id:
        raise VerificationTaskConflict("verification completion is not authorized")
    if outcome not in {"succeeded", "failed"}:
        raise VerificationTaskConflict("verification outcome is invalid")
    if len(limitations) > 32 or any(
        type(item) is not str or not item or len(item) > 255
        for item in limitations
    ):
        raise VerificationTaskConflict("verification limitations are invalid")
    if outcome == "succeeded" and evidence_node_id is None:
        raise VerificationTaskConflict("successful verification requires evidence")
    if evidence_node_id is not None:
        evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id == evidence_node_id,
            )
        )
        if evidence is None:
            raise VerificationTaskConflict("verification evidence is unavailable")
    row.status = outcome
    row.result_evidence_node_id = evidence_node_id
    row.limitations_json = list(limitations)
    row.completed_at = _utc(now)
    db.flush()
    return row


__all__ = [
    "VerificationTaskConflict",
    "claim_verification_task",
    "complete_verification_task",
    "enqueue_verification_task",
]
