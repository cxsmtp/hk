from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any

from .contracts import EndpointPrimitive


_RESOURCE_BOUND_PRIMITIVES = {
    EndpointPrimitive.FILE_OPEN,
    EndpointPrimitive.FILE_READ,
    EndpointPrimitive.FILE_WRITE,
    EndpointPrimitive.FILE_CREATE,
    EndpointPrimitive.FILE_TRUNCATE,
    EndpointPrimitive.FILE_RENAME,
    EndpointPrimitive.FILE_MOVE,
    EndpointPrimitive.FILE_DELETE,
    EndpointPrimitive.FILE_EXECUTE,
    EndpointPrimitive.FILE_MEMORY_MAP,
    EndpointPrimitive.FILE_METADATA_CHANGE,
    EndpointPrimitive.PROCESS_EXECUTE,
    EndpointPrimitive.PROCESS_CHILD_CREATE,
    EndpointPrimitive.PROCESS_SCRIPT_LAUNCH,
    EndpointPrimitive.PROCESS_INTERPRETER_LAUNCH,
}
_DESTINATION_BOUND_PRIMITIVES = {
    EndpointPrimitive.NETWORK_CONNECT,
    EndpointPrimitive.NETWORK_REDIRECT,
    EndpointPrimitive.NETWORK_SEND,
    EndpointPrimitive.NETWORK_QUIC,
    EndpointPrimitive.UPLOAD,
    EndpointPrimitive.EXTERNAL_TRANSFER,
    EndpointPrimitive.LOCAL_MCP_CONNECTION,
    EndpointPrimitive.LOCAL_AGENT_CONNECTION,
    EndpointPrimitive.LOCAL_MODEL_CONNECTION,
    EndpointPrimitive.LOCAL_SERVICE_CONNECTION,
}


def _bounded(value: str | None, *, field: str, limit: int = 1024) -> str | None:
    if value is None:
        return None
    rendered = str(value).replace("\x00", "").strip()
    if not rendered:
        return None
    if len(rendered) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    return rendered


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value.astimezone(UTC)


def _sha256_hex(value: str | None, *, field: str) -> str | None:
    rendered = _bounded(value, field=field, limit=64)
    if rendered is None:
        return None
    if len(rendered) != 64 or any(character not in "0123456789abcdef" for character in rendered):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return rendered


def _rights(values: tuple[str, ...]) -> tuple[str, ...]:
    if not values:
        raise ValueError("at least one requested right is required")
    if len(values) > 32:
        raise ValueError("at most 32 requested rights are permitted")
    normalized = tuple(
        sorted(
            {
                right
                for value in values
                if (right := _bounded(value, field="requested_right", limit=128)) is not None
            }
        )
    )
    if not normalized:
        raise ValueError("at least one requested right is required")
    return normalized


def _immutable_evidence(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class EndpointPermitStep:
    step_id: str
    primitive: EndpointPrimitive
    requested_rights: tuple[str, ...]
    stable_resource_identity: str | None = None
    destination_identity: str | None = None
    maximum_uses: int = 1

    def __post_init__(self) -> None:
        step_id = _bounded(self.step_id, field="step_id", limit=256)
        if step_id is None:
            raise ValueError("step_id is required")
        object.__setattr__(self, "step_id", step_id)
        object.__setattr__(self, "requested_rights", _rights(self.requested_rights))
        object.__setattr__(
            self,
            "stable_resource_identity",
            _bounded(self.stable_resource_identity, field="stable_resource_identity"),
        )
        object.__setattr__(
            self,
            "destination_identity",
            _bounded(self.destination_identity, field="destination_identity"),
        )
        if self.primitive in _RESOURCE_BOUND_PRIMITIVES and self.stable_resource_identity is None:
            raise ValueError("stable_resource_identity is required for this primitive")
        if self.primitive in _DESTINATION_BOUND_PRIMITIVES and self.destination_identity is None:
            raise ValueError("destination_identity is required for this primitive")
        if type(self.maximum_uses) is not int or not 1 <= self.maximum_uses <= 64:
            raise ValueError("maximum_uses must be between 1 and 64")


@dataclass(frozen=True, slots=True)
class EndpointExecutionPermitRequest:
    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    steps: tuple[EndpointPermitStep, ...]
    authority_reference: str
    purpose_reference: str
    policy_version: str
    policy_epoch: int
    issued_at: datetime
    expires_at: datetime
    source_control_point: str
    # These references are optional only for retained Phase 3 callers. Phase 4
    # native-to-endpoint bindings require both pairs and the broker binds and
    # enforces them as part of the same opaque permit material.
    control_plan_id: str | None = None
    control_plan_digest: str | None = None
    decision_receipt_id: str | None = None
    decision_receipt_binding_hash: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "device_id",
            "process_instance_id",
            "action_id",
            "canonical_action_hash",
            "authority_reference",
            "purpose_reference",
            "policy_version",
            "source_control_point",
        ):
            value = _bounded(getattr(self, field), field=field)
            if value is None:
                raise ValueError(f"{field} is required")
            object.__setattr__(self, field, value)
        if type(self.policy_epoch) is not int or self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")
        if not 1 <= len(self.steps) <= 16:
            raise ValueError("permit requires between 1 and 16 bounded steps")
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("permit step IDs must be unique")
        object.__setattr__(self, "issued_at", _aware_utc(self.issued_at, field="issued_at"))
        object.__setattr__(self, "expires_at", _aware_utc(self.expires_at, field="expires_at"))
        if self.expires_at <= self.issued_at:
            raise ValueError("permit expiration must follow issuance")
        object.__setattr__(
            self,
            "control_plan_id",
            _bounded(self.control_plan_id, field="control_plan_id", limit=256),
        )
        object.__setattr__(
            self,
            "control_plan_digest",
            _sha256_hex(self.control_plan_digest, field="control_plan_digest"),
        )
        object.__setattr__(
            self,
            "decision_receipt_id",
            _bounded(self.decision_receipt_id, field="decision_receipt_id", limit=256),
        )
        object.__setattr__(
            self,
            "decision_receipt_binding_hash",
            _sha256_hex(
                self.decision_receipt_binding_hash,
                field="decision_receipt_binding_hash",
            ),
        )
        if bool(self.control_plan_id) != bool(self.control_plan_digest):
            raise ValueError("control plan ID and digest must be bound together")
        if bool(self.decision_receipt_id) != bool(self.decision_receipt_binding_hash):
            raise ValueError("decision receipt ID and binding hash must be bound together")


def _native_authority_scope_digest(request: EndpointExecutionPermitRequest) -> str:
    payload = {
        "tenant_id": request.tenant_id,
        "device_id": request.device_id,
        "process_instance_id": request.process_instance_id,
        "action_id": request.action_id,
        "canonical_action_hash": request.canonical_action_hash,
        "steps": [
            {
                "primitive": step.primitive.value,
                "requested_rights": list(step.requested_rights),
                "stable_resource_identity": step.stable_resource_identity,
                "destination_identity": step.destination_identity,
                "maximum_uses": step.maximum_uses,
            }
            for step in request.steps
        ],
        "policy_version": request.policy_version,
        "policy_epoch": request.policy_epoch,
        "control_plan_id": request.control_plan_id,
        "control_plan_digest": request.control_plan_digest,
        "decision_receipt_id": request.decision_receipt_id,
        "decision_receipt_binding_hash": request.decision_receipt_binding_hash,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class SQLiteEndpointAuthorityReplayStore:
    """Durably consume native endpoint authority without persisting a bearer secret.

    Rows are permanent security tombstones. They are deliberately not expired
    with the short-lived permit: a provider callback/Decision Receipt/Control
    Plan authority may mint at most one local permit, including across endpoint
    agent restarts. The database stores only identifiers and one-way digests.
    """

    def __init__(self, path: str | Path) -> None:
        rendered = str(path)
        if not rendered:
            raise ValueError("authority replay store path is required")
        if rendered != ":memory:":
            store_path = Path(rendered)
            if store_path.exists() and store_path.is_symlink():
                raise ValueError("authority replay store must not be a symlink")
            if not store_path.parent.exists():
                raise ValueError("authority replay store parent directory does not exist")
        self._path = rendered
        self._lock = RLock()
        self._closed = False
        self._connection = sqlite3.connect(
            rendered,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.execute("PRAGMA journal_mode=DELETE")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS native_endpoint_authority_claims (
                authority_binding_hash TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                process_instance_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                control_plan_id TEXT NOT NULL,
                control_plan_digest TEXT NOT NULL,
                decision_receipt_id TEXT NOT NULL,
                authority_scope_digest TEXT NOT NULL,
                claimed_at TEXT NOT NULL,
                UNIQUE (tenant_id, action_id, control_plan_id, control_plan_digest)
            )
            """
        )
        if rendered != ":memory:":
            os.chmod(rendered, 0o600)

    def claim(self, request: EndpointExecutionPermitRequest, *, now: datetime) -> bool:
        if (
            request.control_plan_id is None
            or request.control_plan_digest is None
            or request.decision_receipt_id is None
            or request.decision_receipt_binding_hash is None
        ):
            raise ValueError("native authority requires exact plan and receipt bindings")
        current = _aware_utc(now, field="now")
        scope_digest = _native_authority_scope_digest(request)
        with self._lock:
            if self._closed:
                raise RuntimeError("authority replay store is closed")
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO native_endpoint_authority_claims (
                        authority_binding_hash,
                        tenant_id,
                        device_id,
                        process_instance_id,
                        action_id,
                        control_plan_id,
                        control_plan_digest,
                        decision_receipt_id,
                        authority_scope_digest,
                        claimed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request.decision_receipt_binding_hash,
                        request.tenant_id,
                        request.device_id,
                        request.process_instance_id,
                        request.action_id,
                        request.control_plan_id,
                        request.control_plan_digest,
                        request.decision_receipt_id,
                        scope_digest,
                        current.isoformat(),
                    ),
                )
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError:
                self._connection.execute("ROLLBACK")
                return False
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "SQLiteEndpointAuthorityReplayStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class EndpointPermitConsumption:
    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    primitive: EndpointPrimitive
    requested_rights: tuple[str, ...]
    stable_resource_identity: str | None
    destination_identity: str | None
    authority_reference: str
    purpose_reference: str
    policy_version: str
    policy_epoch: int
    control_plan_id: str | None = None
    control_plan_digest: str | None = None
    decision_receipt_id: str | None = None
    decision_receipt_binding_hash: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "device_id",
            "process_instance_id",
            "action_id",
            "canonical_action_hash",
            "authority_reference",
            "purpose_reference",
            "policy_version",
        ):
            value = _bounded(getattr(self, field), field=field)
            if value is None:
                raise ValueError(f"{field} is required")
            object.__setattr__(self, field, value)
        object.__setattr__(self, "requested_rights", _rights(self.requested_rights))
        object.__setattr__(
            self,
            "stable_resource_identity",
            _bounded(self.stable_resource_identity, field="stable_resource_identity"),
        )
        object.__setattr__(
            self,
            "destination_identity",
            _bounded(self.destination_identity, field="destination_identity"),
        )
        if type(self.policy_epoch) is not int or self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")
        object.__setattr__(
            self,
            "control_plan_id",
            _bounded(self.control_plan_id, field="control_plan_id", limit=256),
        )
        object.__setattr__(
            self,
            "control_plan_digest",
            _sha256_hex(self.control_plan_digest, field="control_plan_digest"),
        )
        object.__setattr__(
            self,
            "decision_receipt_id",
            _bounded(self.decision_receipt_id, field="decision_receipt_id", limit=256),
        )
        object.__setattr__(
            self,
            "decision_receipt_binding_hash",
            _sha256_hex(
                self.decision_receipt_binding_hash,
                field="decision_receipt_binding_hash",
            ),
        )
        if bool(self.control_plan_id) != bool(self.control_plan_digest):
            raise ValueError("control plan ID and digest must be bound together")
        if bool(self.decision_receipt_id) != bool(self.decision_receipt_binding_hash):
            raise ValueError("decision receipt ID and binding hash must be bound together")


@dataclass(frozen=True, slots=True)
class EndpointPermitIssueResult:
    accepted: bool
    permit_id: str
    permit_digest: str
    expires_at: datetime
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", _immutable_evidence(self.evidence))


@dataclass(frozen=True, slots=True)
class EndpointPermitDecision:
    allowed: bool
    reason: str
    evidence: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", _immutable_evidence(self.evidence))


@dataclass(slots=True)
class _StoredPermit:
    request: EndpointExecutionPermitRequest
    nonce: str
    permit_digest: str
    integrity_mac: bytes
    current_step: int = 0
    current_step_uses: int = 0


def _permit_material(request: EndpointExecutionPermitRequest, nonce: str) -> bytes:
    payload = {
        "tenant_id": request.tenant_id,
        "device_id": request.device_id,
        "process_instance_id": request.process_instance_id,
        "action_id": request.action_id,
        "canonical_action_hash": request.canonical_action_hash,
        "steps": [
            {
                "step_id": step.step_id,
                "primitive": step.primitive.value,
                "requested_rights": list(step.requested_rights),
                "stable_resource_identity": step.stable_resource_identity,
                "destination_identity": step.destination_identity,
                "maximum_uses": step.maximum_uses,
            }
            for step in request.steps
        ],
        "authority_reference": request.authority_reference,
        "purpose_reference": request.purpose_reference,
        "policy_version": request.policy_version,
        "policy_epoch": request.policy_epoch,
        "issued_at": request.issued_at.isoformat(),
        "expires_at": request.expires_at.isoformat(),
        "source_control_point": request.source_control_point,
        "control_plan_id": request.control_plan_id,
        "control_plan_digest": request.control_plan_digest,
        "decision_receipt_id": request.decision_receipt_id,
        "decision_receipt_binding_hash": request.decision_receipt_binding_hash,
        "nonce": nonce,
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


class EndpointPermitBroker:
    """Own and atomically consume narrowly scoped endpoint authority.

    Applications receive only an opaque reference. The permit material and its
    integrity MAC remain inside the broker and are never serialized as a bearer
    token or written to persistent storage by this component.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        device_id: str,
        active_policy_epoch: int,
        integrity_key: bytes,
        nonce_factory: Callable[[], str] | None = None,
        maximum_lifetime: timedelta = timedelta(minutes=5),
        maximum_active_permits: int = 4096,
        maximum_tombstones: int = 8192,
        authority_replay_store: SQLiteEndpointAuthorityReplayStore | None = None,
    ) -> None:
        self._tenant_id = _bounded(tenant_id, field="tenant_id")
        self._device_id = _bounded(device_id, field="device_id")
        if self._tenant_id is None or self._device_id is None:
            raise ValueError("broker tenant and device are required")
        if type(active_policy_epoch) is not int or active_policy_epoch <= 0:
            raise ValueError("active_policy_epoch must be positive")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ValueError("integrity_key must contain at least 256 bits")
        if not timedelta(seconds=1) <= maximum_lifetime <= timedelta(minutes=5):
            raise ValueError("maximum_lifetime must be between one second and five minutes")
        self._active_policy_epoch = active_policy_epoch
        self._integrity_key = bytearray(integrity_key)
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(32))
        self._maximum_lifetime = maximum_lifetime
        self._maximum_active_permits = max(1, min(maximum_active_permits, 16384))
        self._maximum_tombstones = max(1, min(maximum_tombstones, 32768))
        self._authority_replay_store = authority_replay_store
        self._active: OrderedDict[str, _StoredPermit] = OrderedDict()
        self._tombstones: OrderedDict[str, str] = OrderedDict()
        self._lock = RLock()
        self._closed = False

    @property
    def active_policy_epoch(self) -> int:
        return self._active_policy_epoch

    def issue(
        self,
        request: EndpointExecutionPermitRequest,
        *,
        now: datetime,
    ) -> EndpointPermitIssueResult:
        with self._lock:
            return self._issue(request, now=now)

    def _issue(
        self,
        request: EndpointExecutionPermitRequest,
        *,
        now: datetime,
    ) -> EndpointPermitIssueResult:
        self._require_open()
        current = _aware_utc(now, field="now")
        if request.tenant_id != self._tenant_id or request.device_id != self._device_id:
            raise ValueError("permit request is outside broker scope")
        if request.policy_epoch != self._active_policy_epoch:
            raise ValueError("permit request does not match active policy epoch")
        if request.issued_at > current or current >= request.expires_at:
            raise ValueError("permit request is not current")
        if request.expires_at - request.issued_at > self._maximum_lifetime:
            raise ValueError("permit exceeds broker maximum lifetime")
        if len(self._active) >= self._maximum_active_permits:
            raise RuntimeError("active permit capacity exhausted")
        if request.decision_receipt_binding_hash is not None:
            if self._authority_replay_store is None:
                raise RuntimeError("durable_authority_replay_store_required")
            if not self._authority_replay_store.claim(request, now=current):
                raise ValueError("decision_receipt_authority_already_bound")

        nonce = _bounded(self._nonce_factory(), field="nonce", limit=256)
        if nonce is None:
            raise RuntimeError("permit nonce generation failed")
        material = _permit_material(request, nonce)
        digest = f"sha256:{hashlib.sha256(material).hexdigest()}"
        integrity_mac = hmac.digest(bytes(self._integrity_key), material, "sha256")
        permit_id = "ep-" + hashlib.sha256(material + integrity_mac).hexdigest()[:40]
        if permit_id in self._active or permit_id in self._tombstones:
            raise RuntimeError("permit nonce reuse detected")
        self._active[permit_id] = _StoredPermit(
            request=request,
            nonce=nonce,
            permit_digest=digest,
            integrity_mac=integrity_mac,
        )
        return EndpointPermitIssueResult(
            accepted=True,
            permit_id=permit_id,
            permit_digest=digest,
            expires_at=request.expires_at,
            evidence={
                "lifecycle": "issued",
                "permit_id": permit_id,
                "permit_digest": digest,
                "action_id": request.action_id,
                "process_instance_id": request.process_instance_id,
                "policy_version": request.policy_version,
                "policy_epoch": request.policy_epoch,
                "source_control_point": request.source_control_point,
                "control_plan_id": request.control_plan_id,
                "control_plan_digest": request.control_plan_digest,
                "decision_receipt_id": request.decision_receipt_id,
                "decision_receipt_binding_hash": request.decision_receipt_binding_hash,
                "step_count": len(request.steps),
                "persisted_secret_material": False,
            },
        )

    def consume(
        self,
        permit_id: str,
        consumption: EndpointPermitConsumption,
        *,
        now: datetime,
    ) -> EndpointPermitDecision:
        with self._lock:
            return self._consume(permit_id, consumption, now=now)

    def _consume(
        self,
        permit_id: str,
        consumption: EndpointPermitConsumption,
        *,
        now: datetime,
    ) -> EndpointPermitDecision:
        self._require_open()
        reference = _bounded(permit_id, field="permit_id", limit=128)
        if reference is None:
            return self._deny("permit_not_found", permit_id="")
        tombstone = self._tombstones.get(reference)
        if tombstone is not None:
            return self._deny(tombstone, permit_id=reference)
        stored = self._active.get(reference)
        if stored is None:
            return self._deny("permit_not_found", permit_id=reference)
        request = stored.request
        material = _permit_material(request, stored.nonce)
        expected_mac = hmac.digest(bytes(self._integrity_key), material, "sha256")
        expected_digest = f"sha256:{hashlib.sha256(material).hexdigest()}"
        if not hmac.compare_digest(expected_mac, stored.integrity_mac) or not hmac.compare_digest(
            expected_digest, stored.permit_digest
        ):
            self._retire(reference, "permit_integrity_invalid")
            return self._deny("permit_integrity_invalid", permit_id=reference)

        current = _aware_utc(now, field="now")
        if request.policy_epoch != self._active_policy_epoch:
            self._retire(reference, "permit_policy_invalidated")
            return self._deny("permit_policy_invalidated", permit_id=reference)
        if current < request.issued_at or current >= request.expires_at:
            self._retire(reference, "permit_expired")
            return self._deny("permit_expired", permit_id=reference)

        global_checks = (
            (consumption.tenant_id, request.tenant_id, "tenant_mismatch"),
            (consumption.device_id, request.device_id, "device_mismatch"),
            (
                consumption.process_instance_id,
                request.process_instance_id,
                "process_instance_mismatch",
            ),
            (consumption.action_id, request.action_id, "action_mismatch"),
            (
                consumption.canonical_action_hash,
                request.canonical_action_hash,
                "canonical_action_mismatch",
            ),
            (
                consumption.authority_reference,
                request.authority_reference,
                "authority_mismatch",
            ),
            (
                consumption.purpose_reference,
                request.purpose_reference,
                "purpose_mismatch",
            ),
            (
                consumption.policy_version,
                request.policy_version,
                "policy_version_mismatch",
            ),
            (consumption.policy_epoch, request.policy_epoch, "policy_epoch_mismatch"),
            (consumption.control_plan_id, request.control_plan_id, "control_plan_mismatch"),
            (
                consumption.control_plan_digest,
                request.control_plan_digest,
                "control_plan_digest_mismatch",
            ),
            (
                consumption.decision_receipt_id,
                request.decision_receipt_id,
                "decision_receipt_mismatch",
            ),
            (
                consumption.decision_receipt_binding_hash,
                request.decision_receipt_binding_hash,
                "decision_receipt_binding_mismatch",
            ),
        )
        for actual, expected, reason in global_checks:
            if actual != expected:
                return self._deny(reason, permit_id=reference, action_id=request.action_id)

        step = request.steps[stored.current_step]
        step_checks = (
            (consumption.primitive, step.primitive, "primitive_mismatch"),
            (
                consumption.requested_rights,
                step.requested_rights,
                "requested_rights_mismatch",
            ),
            (
                consumption.stable_resource_identity,
                step.stable_resource_identity,
                "resource_mismatch",
            ),
            (
                consumption.destination_identity,
                step.destination_identity,
                "destination_mismatch",
            ),
        )
        for actual, expected, reason in step_checks:
            if actual != expected:
                return self._deny(
                    reason,
                    permit_id=reference,
                    action_id=request.action_id,
                    expected_step_id=step.step_id,
                )

        stored.current_step_uses += 1
        step_complete = stored.current_step_uses >= step.maximum_uses
        permit_complete = step_complete and stored.current_step == len(request.steps) - 1
        next_step_id: str | None = None
        remaining_step_uses = step.maximum_uses - stored.current_step_uses
        if step_complete and not permit_complete:
            stored.current_step += 1
            stored.current_step_uses = 0
            next_step_id = request.steps[stored.current_step].step_id
        if permit_complete:
            self._retire(reference, "permit_replay")
        else:
            self._active.move_to_end(reference)
        return EndpointPermitDecision(
            allowed=True,
            reason="permit_consumed",
            evidence={
                "lifecycle": "consumed",
                "permit_id": reference,
                "permit_digest": stored.permit_digest,
                "action_id": request.action_id,
                "step_id": step.step_id,
                "primitive": step.primitive.value,
                "remaining_step_uses": max(0, remaining_step_uses),
                "next_step_id": next_step_id,
                "permit_complete": permit_complete,
                "policy_version": request.policy_version,
                "policy_epoch": request.policy_epoch,
                "control_plan_id": request.control_plan_id,
                "control_plan_digest": request.control_plan_digest,
                "decision_receipt_id": request.decision_receipt_id,
                "decision_receipt_binding_hash": request.decision_receipt_binding_hash,
                "persisted_secret_material": False,
            },
        )

    def consume_bound_operation(
        self,
        permit_id: str,
        *,
        tenant_id: str,
        device_id: str,
        process_instance_id: str,
        action_id: str,
        canonical_action_hash: str,
        primitive: EndpointPrimitive,
        requested_rights: tuple[str, ...],
        stable_resource_identity: str | None,
        destination_identity: str | None,
        now: datetime,
    ) -> EndpointPermitDecision:
        """Consume OS-observed material while retaining trusted authority inside the broker.

        Policy, plan, receipt, authority and purpose bindings are copied from
        the already-verified stored request.  They are never accepted from the
        application presenting the opaque permit reference.
        """

        with self._lock:
            reference = _bounded(permit_id, field="permit_id", limit=128)
            if reference is None:
                return self._deny("permit_not_found", permit_id="")
            tombstone = self._tombstones.get(reference)
            if tombstone is not None:
                return self._deny(tombstone, permit_id=reference)
            stored = self._active.get(reference)
            if stored is None:
                return self._deny("permit_not_found", permit_id=reference)
            request = stored.request
            consumption = EndpointPermitConsumption(
                tenant_id=tenant_id,
                device_id=device_id,
                process_instance_id=process_instance_id,
                action_id=action_id,
                canonical_action_hash=canonical_action_hash,
                primitive=primitive,
                requested_rights=requested_rights,
                stable_resource_identity=stable_resource_identity,
                destination_identity=destination_identity,
                authority_reference=request.authority_reference,
                purpose_reference=request.purpose_reference,
                policy_version=request.policy_version,
                policy_epoch=request.policy_epoch,
                control_plan_id=request.control_plan_id,
                control_plan_digest=request.control_plan_digest,
                decision_receipt_id=request.decision_receipt_id,
                decision_receipt_binding_hash=request.decision_receipt_binding_hash,
            )
            return self._consume(reference, consumption, now=now)

    def activate_policy_epoch(self, policy_epoch: int) -> int:
        with self._lock:
            self._require_open()
            if type(policy_epoch) is not int or policy_epoch <= 0:
                raise ValueError("policy_epoch must be positive")
            self._active_policy_epoch = policy_epoch
            invalid = [
                permit_id
                for permit_id, stored in self._active.items()
                if stored.request.policy_epoch != policy_epoch
            ]
            for permit_id in invalid:
                self._retire(permit_id, "permit_policy_invalidated")
            return len(invalid)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._active.clear()
            self._tombstones.clear()
            for index in range(len(self._integrity_key)):
                self._integrity_key[index] = 0
            self._closed = True

    def _retire(self, permit_id: str, reason: str) -> None:
        self._active.pop(permit_id, None)
        self._tombstones[permit_id] = reason
        self._tombstones.move_to_end(permit_id)
        while len(self._tombstones) > self._maximum_tombstones:
            self._tombstones.popitem(last=False)

    @staticmethod
    def _deny(reason: str, *, permit_id: str, **details: Any) -> EndpointPermitDecision:
        return EndpointPermitDecision(
            allowed=False,
            reason=reason,
            evidence={
                "lifecycle": "denied",
                "permit_id": permit_id,
                "reason": reason,
                "persisted_secret_material": False,
                **details,
            },
        )

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("permit broker is closed")

    def __enter__(self) -> "EndpointPermitBroker":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
