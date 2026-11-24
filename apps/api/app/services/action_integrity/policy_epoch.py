"""Tenant policy epochs are positive, monotonic, and transaction-bound."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import TenantPolicyEpoch


def _tenant_id(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("tenant id is invalid")
    return value


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _audit_reference(value: str | None, *, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} is required for a material policy change")
    return value


def _digest(value: str | None) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("material policy digest must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class PolicyEpochSnapshot:
    tenant_id: str
    epoch: int
    current_policy_snapshot_id: str | None
    material_policy_digest: str | None
    state_version: int


class PolicyEpochService:
    """The database-backed epoch authority for material policy changes.

    The caller owns the surrounding transaction and performs the policy/profile
    mutation before returning.  This service makes an epoch rollback or a
    lost-update a hard failure instead of a best-effort cache refresh.
    """

    def __init__(self, db: Session) -> None:
        self._db = db

    def current(self, *, tenant_id: str, lock: bool = False) -> PolicyEpochSnapshot:
        tenant_id = _tenant_id(tenant_id)
        statement = select(TenantPolicyEpoch).where(TenantPolicyEpoch.tenant_id == tenant_id)
        if lock:
            statement = statement.with_for_update()
        row = self._db.scalar(statement)
        if row is None or row.epoch <= 0 or row.state_version <= 0:
            raise ValueError("tenant policy epoch authority is missing or invalid")
        return PolicyEpochSnapshot(
            tenant_id=tenant_id,
            epoch=row.epoch,
            current_policy_snapshot_id=row.current_policy_snapshot_id,
            material_policy_digest=row.material_policy_digest,
            state_version=row.state_version,
        )

    def bump_material_change(
        self,
        *,
        tenant_id: str,
        expected_epoch: int,
        expected_state_version: int,
        current_policy_snapshot_id: str | None,
        material_policy_digest: str | None,
        actor_principal_ref: str | None,
        reason_code: str,
    ) -> PolicyEpochSnapshot:
        if type(expected_epoch) is not int or expected_epoch <= 0:
            raise ValueError("expected policy epoch is invalid")
        if type(expected_state_version) is not int or expected_state_version <= 0:
            raise ValueError("expected policy state version is invalid")
        if not isinstance(reason_code, str) or not reason_code or reason_code != reason_code.strip():
            raise ValueError("material policy change reason is invalid")
        current_policy_snapshot_id = _audit_reference(
            current_policy_snapshot_id, field="current policy snapshot id",
        )
        material_policy_digest = _digest(material_policy_digest)
        actor_principal_ref = _audit_reference(actor_principal_ref, field="actor principal reference")
        previous = self.current(tenant_id=tenant_id, lock=True)
        if previous.epoch != expected_epoch or previous.state_version != expected_state_version:
            raise ValueError("policy epoch compare-and-set conflict")
        row = self._db.get(TenantPolicyEpoch, previous.tenant_id)
        if row is None:  # Defensive after the locked read above.
            raise ValueError("tenant policy epoch authority disappeared")
        row.epoch = previous.epoch + 1
        row.current_policy_snapshot_id = current_policy_snapshot_id
        row.material_policy_digest = material_policy_digest
        row.state_version = previous.state_version + 1
        row.updated_by_principal_ref = actor_principal_ref
        row.reason_code = reason_code
        row.updated_at = datetime.now(timezone.utc)
        return PolicyEpochSnapshot(
            tenant_id=previous.tenant_id,
            epoch=row.epoch,
            current_policy_snapshot_id=row.current_policy_snapshot_id,
            material_policy_digest=row.material_policy_digest,
            state_version=row.state_version,
        )


class PolicyEpochStore:
    """Retired compatibility shell.

    Policy epoch authority is database-backed and lock/CAS protected.  A
    process-local map would split authority across workers and is therefore a
    fail-closed error, never a development fallback.
    """

    def __init__(self) -> None:
        pass

    def current(self, tenant_id: str) -> int:
        _tenant_id(tenant_id)
        raise RuntimeError("database-backed policy epoch authority is required")

    def advance(self, tenant_id: str, *, expected: int) -> int:
        _tenant_id(tenant_id)
        if not isinstance(expected, int) or expected <= 0:
            raise ValueError("policy epoch compare-and-set conflict")
        raise RuntimeError("database-backed policy epoch authority is required")
