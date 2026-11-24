from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from .contracts import EndpointPrimitive, EndpointProcessIdentity


class TaintConfidence(str, Enum):
    CONFIRMED = "confirmed"
    STRONG_CORRELATION = "strong_correlation"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


class TaintPropagationState(str, Enum):
    ORIGIN = "origin"
    CHILD = "child"
    HELPER = "helper"
    LOCAL_MCP = "local_mcp"
    TEMP_FILE = "temp_file"
    ARCHIVE = "archive"
    NETWORK = "network"
    CLEARED = "cleared"


def _bounded(value: str | None, *, field: str, limit: int = 1024) -> str | None:
    if value is None:
        return None
    rendered = str(value).replace("\x00", "").strip()
    if not rendered:
        return None
    if len(rendered) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    return rendered


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value.astimezone(UTC)


def _evidence(values: tuple[str, ...], *, maximum: int = 32) -> tuple[str, ...]:
    if not values or len(values) > maximum:
        raise ValueError(f"between 1 and {maximum} evidence references are required")
    normalized = tuple(
        dict.fromkeys(
            reference
            for value in values
            if (reference := _bounded(value, field="evidence_ref", limit=512)) is not None
        )
    )
    if not normalized:
        raise ValueError("at least one evidence reference is required")
    return normalized


@dataclass(frozen=True, slots=True)
class EndpointTaintContext:
    taint_id: str
    tenant_id: str
    device_id: str
    process_instance_id: str
    session_id: str | None
    source_reference: str
    classification: str
    access_operation: EndpointPrimitive
    observed_at: datetime
    confidence: TaintConfidence
    propagation_state: TaintPropagationState
    expires_at: datetime
    action_id: str
    chain_reference: str
    purpose_reference: str
    policy_version: str
    policy_epoch: int
    evidence_refs: tuple[str, ...]
    parent_taint_id: str | None = None

    def __post_init__(self) -> None:
        required = (
            "taint_id",
            "tenant_id",
            "device_id",
            "process_instance_id",
            "source_reference",
            "classification",
            "action_id",
            "chain_reference",
            "purpose_reference",
            "policy_version",
        )
        for field in required:
            value = _bounded(getattr(self, field), field=field)
            if value is None:
                raise ValueError(f"{field} is required")
            object.__setattr__(self, field, value)
        for field in ("session_id", "parent_taint_id"):
            object.__setattr__(self, field, _bounded(getattr(self, field), field=field))
        object.__setattr__(self, "observed_at", _utc(self.observed_at, field="observed_at"))
        object.__setattr__(self, "expires_at", _utc(self.expires_at, field="expires_at"))
        if self.expires_at <= self.observed_at:
            raise ValueError("taint expiration must follow observation")
        if type(self.policy_epoch) is not int or self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")
        object.__setattr__(self, "evidence_refs", _evidence(self.evidence_refs))

    def as_evidence(self) -> dict[str, Any]:
        return {
            "taint_id": self.taint_id,
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "process_instance_id": self.process_instance_id,
            "session_id": self.session_id,
            "source_reference": self.source_reference,
            "classification": self.classification,
            "access_operation": self.access_operation.value,
            "observed_at": self.observed_at.isoformat(),
            "confidence": self.confidence.value,
            "propagation_state": self.propagation_state.value,
            "expires_at": self.expires_at.isoformat(),
            "action_id": self.action_id,
            "chain_reference": self.chain_reference,
            "purpose_reference": self.purpose_reference,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "evidence_refs": list(self.evidence_refs),
            "parent_taint_id": self.parent_taint_id,
            "raw_content_collected": False,
        }


class EndpointTaintRegistry:
    def __init__(
        self,
        *,
        tenant_id: str,
        device_id: str,
        maximum_ttl: timedelta = timedelta(hours=1),
        maximum_active: int = 8192,
        maximum_cleared: int = 8192,
    ) -> None:
        self._tenant_id = _bounded(tenant_id, field="tenant_id")
        self._device_id = _bounded(device_id, field="device_id")
        if self._tenant_id is None or self._device_id is None:
            raise ValueError("registry tenant and device are required")
        if not timedelta(seconds=1) <= maximum_ttl <= timedelta(hours=24):
            raise ValueError("maximum_ttl must be between one second and 24 hours")
        self._maximum_ttl = maximum_ttl
        self._maximum_active = max(1, min(maximum_active, 32768))
        self._maximum_cleared = max(1, min(maximum_cleared, 32768))
        self._active: OrderedDict[str, EndpointTaintContext] = OrderedDict()
        self._cleared: OrderedDict[str, EndpointTaintContext] = OrderedDict()
        self._sequence = 0

    def create_origin(
        self,
        *,
        process: EndpointProcessIdentity,
        source_reference: str,
        classification: str,
        access_operation: EndpointPrimitive,
        observed_at: datetime,
        expires_at: datetime,
        action_id: str,
        chain_reference: str,
        purpose_reference: str,
        policy_version: str,
        policy_epoch: int,
        evidence_refs: tuple[str, ...],
    ) -> EndpointTaintContext:
        self._validate_process(process)
        observed = _utc(observed_at, field="observed_at")
        expires = _utc(expires_at, field="expires_at")
        if expires - observed > self._maximum_ttl:
            raise ValueError("taint exceeds maximum TTL")
        self._sequence += 1
        taint_id = self._taint_id(
            process.process_instance_id,
            action_id,
            source_reference,
            self._sequence,
        )
        context = EndpointTaintContext(
            taint_id=taint_id,
            tenant_id=self._tenant_id,
            device_id=self._device_id,
            process_instance_id=str(process.process_instance_id),
            session_id=process.session_id,
            source_reference=source_reference,
            classification=classification,
            access_operation=access_operation,
            observed_at=observed,
            confidence=TaintConfidence.CONFIRMED,
            propagation_state=TaintPropagationState.ORIGIN,
            expires_at=expires,
            action_id=action_id,
            chain_reference=chain_reference,
            purpose_reference=purpose_reference,
            policy_version=policy_version,
            policy_epoch=policy_epoch,
            evidence_refs=evidence_refs,
        )
        self._remember(context)
        return context

    def propagate(
        self,
        taint_id: str,
        *,
        target_process: EndpointProcessIdentity,
        state: TaintPropagationState,
        confidence: TaintConfidence,
        observed_at: datetime,
        evidence_refs: tuple[str, ...],
    ) -> EndpointTaintContext:
        source = self._active.get(str(taint_id))
        if source is None:
            raise ValueError("source taint is not active")
        self._validate_process(target_process)
        observed = _utc(observed_at, field="observed_at")
        if observed < source.observed_at or observed >= source.expires_at:
            raise ValueError("propagation observation is outside the active taint window")
        references = _evidence(evidence_refs)
        if confidence is TaintConfidence.CONFIRMED and not any(
            reference.startswith(("os:", "native:", "semantic:", "permit:"))
            for reference in references
        ):
            raise ValueError("confirmed propagation requires authoritative evidence")
        if state is TaintPropagationState.CHILD and (
            target_process.parent_process_instance_id != source.process_instance_id
        ):
            raise ValueError("child propagation requires stable parent lineage")
        if state in {TaintPropagationState.ORIGIN, TaintPropagationState.CLEARED}:
            raise ValueError("invalid propagation state")

        self._sequence += 1
        target_instance = str(target_process.process_instance_id)
        propagated = EndpointTaintContext(
            taint_id=self._taint_id(
                target_instance,
                source.action_id,
                source.source_reference,
                self._sequence,
            ),
            tenant_id=source.tenant_id,
            device_id=source.device_id,
            process_instance_id=target_instance,
            session_id=target_process.session_id,
            source_reference=source.source_reference,
            classification=source.classification,
            access_operation=source.access_operation,
            observed_at=observed,
            confidence=confidence,
            propagation_state=state,
            expires_at=source.expires_at,
            action_id=source.action_id,
            chain_reference=source.chain_reference,
            purpose_reference=source.purpose_reference,
            policy_version=source.policy_version,
            policy_epoch=source.policy_epoch,
            evidence_refs=references,
            parent_taint_id=source.taint_id,
        )
        self._remember(propagated)
        return propagated

    def active_for_process(self, process_instance_id: str | None) -> tuple[EndpointTaintContext, ...]:
        if not process_instance_id:
            return ()
        return tuple(
            context
            for context in self._active.values()
            if context.process_instance_id == process_instance_id
        )

    def expire(self, *, now: datetime) -> tuple[str, ...]:
        current = _utc(now, field="now")
        expired = tuple(
            taint_id
            for taint_id, context in self._active.items()
            if current >= context.expires_at
        )
        for taint_id in expired:
            self._clear(taint_id, observed_at=current)
        return expired

    def clear_process(self, process_instance_id: str, *, observed_at: datetime) -> tuple[str, ...]:
        return self._clear_matching(
            lambda context: context.process_instance_id == process_instance_id,
            observed_at=observed_at,
        )

    def clear_session(self, session_id: str, *, observed_at: datetime) -> tuple[str, ...]:
        return self._clear_matching(
            lambda context: context.session_id == session_id,
            observed_at=observed_at,
        )

    def clear_action(self, action_id: str, *, observed_at: datetime) -> tuple[str, ...]:
        return self._clear_matching(
            lambda context: context.action_id == action_id,
            observed_at=observed_at,
        )

    def _clear_matching(self, predicate: Any, *, observed_at: datetime) -> tuple[str, ...]:
        current = _utc(observed_at, field="observed_at")
        matches = tuple(
            taint_id for taint_id, context in self._active.items() if predicate(context)
        )
        for taint_id in matches:
            self._clear(taint_id, observed_at=current)
        return matches

    def _clear(self, taint_id: str, *, observed_at: datetime) -> None:
        context = self._active.pop(taint_id, None)
        if context is None:
            return
        cleared_at = max(context.observed_at, observed_at)
        cleared = replace(
            context,
            propagation_state=TaintPropagationState.CLEARED,
            observed_at=cleared_at,
            expires_at=max(context.expires_at, cleared_at + timedelta(microseconds=1)),
        )
        self._cleared[taint_id] = cleared
        self._cleared.move_to_end(taint_id)
        while len(self._cleared) > self._maximum_cleared:
            self._cleared.popitem(last=False)

    def _remember(self, context: EndpointTaintContext) -> None:
        if len(self._active) >= self._maximum_active:
            raise RuntimeError("active taint capacity exhausted")
        self._active[context.taint_id] = context

    def _validate_process(self, process: EndpointProcessIdentity) -> None:
        if process.device_id != self._device_id:
            raise ValueError("process is outside registry device scope")
        if process.tenant_id not in {None, self._tenant_id}:
            raise ValueError("process is outside registry tenant scope")
        if not process.process_instance_id:
            raise ValueError("stable process instance identity is required")

    @staticmethod
    def _taint_id(
        process_instance_id: str | None,
        action_id: str,
        source_reference: str,
        sequence: int,
    ) -> str:
        material = json.dumps(
            {
                "process_instance_id": process_instance_id,
                "action_id": action_id,
                "source_reference": source_reference,
                "sequence": sequence,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "taint-" + hashlib.sha256(material).hexdigest()[:40]


@dataclass(frozen=True, slots=True)
class DownloadCorrelation:
    action_id: str
    process_instance_id: str
    source_reference: str
    target_resource_identity: str
    confidence: TaintConfidence
    evidence_refs: tuple[str, ...]
    observation_count: int
    first_observed_at: datetime
    last_observed_at: datetime


@dataclass(slots=True)
class _MutableDownload:
    action_id: str
    process_instance_id: str
    source_reference: str
    target_resource_identity: str
    evidence_refs: list[str]
    first_observed_at: datetime
    last_observed_at: datetime
    semantic_binding: bool = False


class DownloadEvidenceAccumulator:
    """Collapse flow and file-write evidence into one bounded download action."""

    def __init__(self, *, maximum_actions: int = 4096, maximum_evidence_refs: int = 64) -> None:
        self._maximum_actions = max(1, min(maximum_actions, 16384))
        self._maximum_evidence_refs = max(2, min(maximum_evidence_refs, 256))
        self._actions: OrderedDict[str, _MutableDownload] = OrderedDict()

    def record(
        self,
        *,
        action_id: str,
        process_instance_id: str | None,
        source_reference: str,
        target_resource_identity: str,
        evidence_ref: str,
        observed_at: datetime,
        semantic_binding: bool = False,
    ) -> DownloadCorrelation:
        action = _bounded(action_id, field="action_id")
        process = _bounded(process_instance_id, field="process_instance_id")
        source = _bounded(source_reference, field="source_reference")
        target = _bounded(target_resource_identity, field="target_resource_identity")
        evidence = _bounded(evidence_ref, field="evidence_ref", limit=512)
        if None in {action, process, source, target, evidence}:
            raise ValueError("download correlation requires bounded identity and evidence")
        observed = _utc(observed_at, field="observed_at")
        existing = self._actions.get(action)
        if existing is None:
            if len(self._actions) >= self._maximum_actions:
                self._actions.popitem(last=False)
            existing = _MutableDownload(
                action_id=action,
                process_instance_id=process,
                source_reference=source,
                target_resource_identity=target,
                evidence_refs=[],
                first_observed_at=observed,
                last_observed_at=observed,
            )
            self._actions[action] = existing
        elif (
            existing.process_instance_id != process
            or existing.source_reference != source
            or existing.target_resource_identity != target
        ):
            raise ValueError("download action identity drift detected")
        if evidence not in existing.evidence_refs and len(existing.evidence_refs) < self._maximum_evidence_refs:
            existing.evidence_refs.append(evidence)
        existing.last_observed_at = max(existing.last_observed_at, observed)
        existing.semantic_binding = existing.semantic_binding or semantic_binding
        self._actions.move_to_end(action)

        has_network = any(reference.startswith("net:") for reference in existing.evidence_refs)
        has_file = any(reference.startswith("file:") for reference in existing.evidence_refs)
        if existing.semantic_binding:
            confidence = TaintConfidence.CONFIRMED
        elif has_network and has_file:
            confidence = TaintConfidence.STRONG_CORRELATION
        elif existing.evidence_refs:
            confidence = TaintConfidence.POSSIBLE
        else:
            confidence = TaintConfidence.UNKNOWN
        return DownloadCorrelation(
            action_id=existing.action_id,
            process_instance_id=existing.process_instance_id,
            source_reference=existing.source_reference,
            target_resource_identity=existing.target_resource_identity,
            confidence=confidence,
            evidence_refs=tuple(existing.evidence_refs),
            observation_count=len(existing.evidence_refs),
            first_observed_at=existing.first_observed_at,
            last_observed_at=existing.last_observed_at,
        )
