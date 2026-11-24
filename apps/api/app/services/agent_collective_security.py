"""Deterministic security controls for an existing delegated agent collective.

This module does not orchestrate agents and does not make a second policy
decision.  It constrains the already-signed Phase 5 delegation tree, records
only visible communication/provenance, and binds a pre-assessed collective
action to the existing execution-permit claim seam.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace as dataclass_replace
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import DelegationContextV2, DelegationLifecycleEventV2
from app.db.models.agent_collective import (
    AgentCollectiveContext,
    AgentCommunicationEvent,
    CollectiveSecuritySignal,
    DelegationRootRevocation,
)
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.action_integrity.delegation_lifecycle import (
    fresh_delegation_context_fold,
    require_active_delegation_ancestry,
    revoke_delegation_context_v2,
)
from app.services.action_integrity.signing import SigningKeyProvider


_VISIBLE_CHANNEL_TYPES = frozenset(
    {
        "registered_a2a",
        "message_queue",
        "shared_memory",
        "file",
        "database",
        "object_store",
        "repository",
        "network_endpoint",
        "tool_result",
        "external_message",
    }
)
_CONSEQUENTIAL_OPERATIONS = frozenset(
    {"write", "create", "delete", "execute", "send", "publish", "transfer", "deploy"}
)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _unique(values: list[str] | tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if value))


@dataclass(frozen=True, slots=True)
class CollectiveConstraintSet:
    max_active_agents: int
    max_delegation_depth: int
    max_fan_out_per_agent: int
    max_active_descendants: int
    max_aggregate_tool_classes: int
    max_external_destinations: int
    max_concurrent_consequential_actions: int
    max_attempts: int
    max_equivalent_failures: int
    max_execution_duration_seconds: int
    approved_channels: tuple[str, ...] = ()
    monitored_channels: tuple[str, ...] = ()
    approval_required_channels: tuple[str, ...] = ()
    internet_access: bool = False

    def __post_init__(self) -> None:
        numeric = (
            self.max_active_agents,
            self.max_delegation_depth,
            self.max_fan_out_per_agent,
            self.max_active_descendants,
            self.max_aggregate_tool_classes,
            self.max_external_destinations,
            self.max_concurrent_consequential_actions,
            self.max_attempts,
            self.max_equivalent_failures,
            self.max_execution_duration_seconds,
        )
        if any(not isinstance(value, int) or value < 1 for value in numeric):
            raise ValueError("collective limits must be positive integers")
        for name in ("approved_channels", "monitored_channels", "approval_required_channels"):
            normalized = tuple(sorted(set(getattr(self, name))))
            if normalized != getattr(self, name):
                object.__setattr__(self, name, normalized)

    def replace(self, **changes: Any) -> "CollectiveConstraintSet":
        return dataclass_replace(self, **changes)

    def to_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        for name in ("approved_channels", "monitored_channels", "approval_required_channels"):
            value[name] = list(getattr(self, name))
        return value

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CollectiveConstraintSet":
        payload = dict(value)
        for name in ("approved_channels", "monitored_channels", "approval_required_channels"):
            payload[name] = tuple(payload.get(name) or ())
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class DelegationRoot:
    context_id: str
    action_id: str
    principal_ref: str
    authority_envelope: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class CollectiveDecision:
    allowed: bool
    decision: str
    reason_code: str
    signal_types: tuple[str, ...] = ()
    affected_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CommunicationResult:
    event_id: str
    runtime_event_id: str
    decision: str


class AgentCollectiveSecurityService:
    def __init__(
        self,
        db: Session,
        *,
        signing_provider: SigningKeyProvider,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._db = db
        self._signing_provider = signing_provider
        self._now = now or (lambda: datetime.now(timezone.utc))
        # Phase 7 uses the same provider to verify signed delegation edges.
        self._db.info.setdefault("phase5_signing_provider", signing_provider)

    def _locked_context(self, *, tenant_id: str, collective_id: str) -> AgentCollectiveContext:
        context = self._db.scalar(
            select(AgentCollectiveContext)
            .where(
                AgentCollectiveContext.tenant_id == tenant_id,
                AgentCollectiveContext.id == collective_id,
            )
            .with_for_update()
        )
        if context is None:
            exists = self._db.scalar(
                select(AgentCollectiveContext.id).where(AgentCollectiveContext.id == collective_id)
            )
            if exists is not None:
                raise PermissionError("collective is not available for this tenant")
            raise LookupError("collective does not exist")
        return context

    def get_context(self, *, tenant_id: str, collective_id: str) -> AgentCollectiveContext:
        return self._locked_context(tenant_id=tenant_id, collective_id=collective_id)

    def _root(self, context: AgentCollectiveContext) -> DelegationContextV2:
        return require_active_delegation_ancestry(
            self._db,
            provider=self._signing_provider,
            tenant_id=context.tenant_id,
            delegation_context_id=context.delegation_root_context_id,
            now=_utc(self._now()),
        )

    def _runtime_event(
        self,
        *,
        context: AgentCollectiveContext,
        event_type: str,
        entity_id: str,
        parent_action_id: str | None,
        agent_ref: str | None,
        decision: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> RuntimeEvent:
        row = RuntimeEvent(
            tenant_id=context.tenant_id,
            source_surface="runtime",
            event_type=event_type,
            agent_id=agent_ref,
            decision=decision,
            confidence_tier="CONFIRMED",
            chain_id=context.id,
            context_id=f"collective:{context.id}",
            parent_action_id=parent_action_id,
            entity_type="action",
            entity_id=entity_id,
            metadata_json={
                "collective_id": context.id,
                "delegation_root_context_id": context.delegation_root_context_id,
                "root_objective_ref": context.root_objective_ref,
                **dict(metadata or {}),
            },
            created_at=_utc(self._now()),
        )
        self._db.add(row)
        self._db.flush()
        return row

    def _touch(self, context: AgentCollectiveContext) -> None:
        context.state_version += 1
        context.last_event_at = _utc(self._now())

    def _signal(
        self,
        *,
        context: AgentCollectiveContext,
        signal_type: str,
        reason_code: str,
        agent_ref: str | None = None,
        action_id: str | None = None,
        severity: str = "high",
        evidence_refs: tuple[str, ...] = (),
        safe_context: Mapping[str, Any] | None = None,
    ) -> CollectiveSecuritySignal:
        monitoring = MonitoringSignal(
            tenant_id=context.tenant_id,
            signal_type=signal_type,
            severity=severity,
            payload={
                "collective_id": context.id,
                "reason_code": reason_code,
                "agent_ref": agent_ref,
                "action_id": action_id,
            },
            created_at=_utc(self._now()),
        )
        self._db.add(monitoring)
        self._db.flush()
        runtime = self._runtime_event(
            context=context,
            event_type="agent_collective.signal",
            entity_id=action_id or f"collective-signal:{signal_type}:{context.state_version + 1}",
            parent_action_id=context.root_action_id,
            agent_ref=agent_ref,
            decision="BLOCK",
            metadata={"signal_type": signal_type, "reason_code": reason_code},
        )
        signal = CollectiveSecuritySignal(
            tenant_id=context.tenant_id,
            collective_id=context.id,
            signal_type=signal_type,
            severity=severity,
            agent_ref=agent_ref,
            action_id=action_id,
            reason_code=reason_code,
            evidence_refs=list(evidence_refs),
            safe_context=dict(safe_context or {}),
            monitoring_signal_id=monitoring.id,
            runtime_event_id=runtime.event_id,
            occurred_at=_utc(self._now()),
        )
        self._db.add(signal)
        self._db.flush()
        return signal

    def create_collective(
        self,
        *,
        tenant_id: str,
        delegation_root_context_id: str,
        originating_actor_ref: str,
        represented_subject_ref: str,
        business_purpose_ref: str,
        root_objective_ref: str,
        constraints: CollectiveConstraintSet,
    ) -> AgentCollectiveContext:
        existing = self._db.scalar(
            select(AgentCollectiveContext).where(
                AgentCollectiveContext.tenant_id == tenant_id,
                AgentCollectiveContext.delegation_root_context_id == delegation_root_context_id,
            )
        )
        if existing is not None:
            return existing
        root = require_active_delegation_ancestry(
            self._db,
            provider=self._signing_provider,
            tenant_id=tenant_id,
            delegation_context_id=delegation_root_context_id,
            now=_utc(self._now()),
        )
        if root.parent_delegation_context_id is not None or root.depth != 1:
            raise ValueError("collective delegation root must be a root context")
        authority = dict((root.signed_envelope or {}).get("effective_scope") or {})
        context = AgentCollectiveContext(
            tenant_id=tenant_id,
            delegation_root_context_id=root.delegation_context_id,
            root_action_id=str(root.parent_action_id),
            originating_actor_ref=originating_actor_ref,
            represented_subject_ref=represented_subject_ref,
            business_purpose_ref=business_purpose_ref,
            root_objective_ref=root_objective_ref,
            authority_envelope=authority,
            constraint_set=constraints.to_mapping(),
            member_agent_refs=[root.destination_principal_ref],
            member_delegation_context_ids=[root.delegation_context_id],
            active_principal_refs=[root.destination_principal_ref],
            observed_channel_refs=[],
            shared_store_refs=[],
            observed_tool_classes=[],
            observed_external_destinations=[],
            active_consequential_action_ids=[],
            authorized_action_ids=[],
            retry_fingerprints={},
            agent_count=1,
            maximum_depth=1,
            maximum_fan_out=0,
            retry_count=0,
            failure_count=0,
            status="ACTIVE",
            state_version=0,
            last_event_at=_utc(self._now()),
            created_at=_utc(self._now()),
            updated_at=_utc(self._now()),
        )
        self._db.add(context)
        self._db.flush()
        self._runtime_event(
            context=context,
            event_type="agent_collective.started",
            entity_id=context.root_action_id,
            parent_action_id=None,
            agent_ref=root.destination_principal_ref,
            decision="ALLOW",
            metadata={
                "originating_actor_ref": originating_actor_ref,
                "represented_subject_ref": represented_subject_ref,
                "business_purpose_ref": business_purpose_ref,
            },
        )
        return context

    def replace_constraints(
        self,
        *,
        tenant_id: str,
        collective_id: str,
        constraints: CollectiveConstraintSet,
    ) -> AgentCollectiveContext:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        current = CollectiveConstraintSet.from_mapping(context.constraint_set)
        numeric_fields = (
            "max_active_agents",
            "max_delegation_depth",
            "max_fan_out_per_agent",
            "max_active_descendants",
            "max_aggregate_tool_classes",
            "max_external_destinations",
            "max_concurrent_consequential_actions",
            "max_attempts",
            "max_equivalent_failures",
            "max_execution_duration_seconds",
        )
        if any(getattr(constraints, name) > getattr(current, name) for name in numeric_fields):
            raise PermissionError("collective constraints may only be tightened in place")
        current_channels = set(current.approved_channels) | set(current.monitored_channels) | set(
            current.approval_required_channels
        )
        replacement_channels = set(constraints.approved_channels) | set(
            constraints.monitored_channels
        ) | set(constraints.approval_required_channels)
        if not replacement_channels.issubset(current_channels):
            raise PermissionError("communication channel authority may not be widened")
        if constraints.internet_access and not current.internet_access:
            raise PermissionError("internet authority may not be widened")
        context.constraint_set = constraints.to_mapping()
        self._touch(context)
        self._db.flush()
        return context

    def register_member(
        self,
        *,
        tenant_id: str,
        collective_id: str,
        delegation_context_id: str,
    ) -> CollectiveDecision:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        if context.status == "REVOKED":
            return CollectiveDecision(False, "BLOCK", "delegation_root_revoked")
        if context.status == "ABANDONED":
            return CollectiveDecision(False, "BLOCK", "collective_abandoned")
        leaf = require_active_delegation_ancestry(
            self._db,
            provider=self._signing_provider,
            tenant_id=tenant_id,
            delegation_context_id=delegation_context_id,
            now=_utc(self._now()),
        )
        if leaf.delegation_context_id in set(context.member_delegation_context_ids or []):
            return CollectiveDecision(True, "ALLOW", "member_already_registered")
        ancestor_ids: set[str] = set()
        cursor: DelegationContextV2 | None = leaf
        while cursor is not None:
            ancestor_ids.add(cursor.delegation_context_id)
            if cursor.parent_delegation_context_id is None:
                break
            cursor = self._db.scalar(
                select(DelegationContextV2).where(
                    DelegationContextV2.tenant_id == tenant_id,
                    DelegationContextV2.delegation_context_id == cursor.parent_delegation_context_id,
                )
            )
        if context.delegation_root_context_id not in ancestor_ids:
            raise PermissionError("delegation context is not a descendant of this collective root")
        constraints = CollectiveConstraintSet.from_mapping(context.constraint_set)
        signal_type: str | None = None
        reason_code: str | None = None
        if context.agent_count + 1 > constraints.max_active_agents:
            signal_type, reason_code = "AGENT_POPULATION_EXCEEDED", "agent_population_exceeded"
        elif context.agent_count > constraints.max_active_descendants:
            signal_type, reason_code = "AGENT_POPULATION_EXCEEDED", "active_descendants_exceeded"
        elif leaf.depth > constraints.max_delegation_depth:
            signal_type, reason_code = "DELEGATION_DEPTH_EXCEEDED", "delegation_depth_exceeded"
        else:
            sibling_count = int(
                self._db.scalar(
                    select(func.count(DelegationContextV2.id)).where(
                        DelegationContextV2.tenant_id == tenant_id,
                        DelegationContextV2.parent_delegation_context_id
                        == leaf.parent_delegation_context_id,
                        DelegationContextV2.delegation_context_id.in_(
                            list(context.member_delegation_context_ids or [])
                        ),
                    )
                )
                or 0
            )
            if sibling_count + 1 > constraints.max_fan_out_per_agent:
                signal_type, reason_code = "FANOUT_EXCEEDED", "fanout_exceeded"
        if signal_type and reason_code:
            self._signal(
                context=context,
                signal_type=signal_type,
                reason_code=reason_code,
                agent_ref=leaf.destination_principal_ref,
                action_id=leaf.delegated_action_id,
                safe_context={"delegation_depth": leaf.depth},
            )
            self._touch(context)
            return CollectiveDecision(False, "BLOCK", reason_code, (signal_type,))
        context.member_agent_refs = _unique(list(context.member_agent_refs or []) + [leaf.destination_principal_ref])
        context.member_delegation_context_ids = _unique(
            list(context.member_delegation_context_ids or []) + [leaf.delegation_context_id]
        )
        context.active_principal_refs = _unique(
            list(context.active_principal_refs or []) + [leaf.destination_principal_ref]
        )
        context.agent_count = len(context.member_delegation_context_ids)
        context.maximum_depth = max(context.maximum_depth, leaf.depth)
        context.maximum_fan_out = max(context.maximum_fan_out, sibling_count + 1)
        self._touch(context)
        self._runtime_event(
            context=context,
            event_type="agent_collective.member_registered",
            entity_id=str(leaf.delegated_action_id),
            parent_action_id=str(leaf.parent_action_id),
            agent_ref=leaf.destination_principal_ref,
            decision="ALLOW",
            metadata={"delegation_context_id": leaf.delegation_context_id, "depth": leaf.depth},
        )
        return CollectiveDecision(True, "ALLOW", "member_registered")

    def assess_action(
        self,
        *,
        tenant_id: str,
        collective_id: str,
        agent_ref: str,
        action_id: str,
        operation: str,
        resource_ref: str,
        tool_class: str,
        destination_ref: str | None,
        consequential: bool,
    ) -> CollectiveDecision:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        if context.status == "REVOKED":
            return CollectiveDecision(False, "BLOCK", "delegation_root_revoked")
        if context.status == "ABANDONED":
            return CollectiveDecision(False, "BLOCK", "collective_abandoned")
        self._root(context)
        if agent_ref not in set(context.member_agent_refs or []):
            raise PermissionError("agent is not a member of this collective")
        constraints = CollectiveConstraintSet.from_mapping(context.constraint_set)
        if context.created_at is not None:
            elapsed = max(0.0, (_utc(self._now()) - _utc(context.created_at)).total_seconds())
            if elapsed >= constraints.max_execution_duration_seconds:
                context.status = "ABANDONED"
                self._signal(
                    context=context,
                    signal_type="RETRY_LIMIT_EXCEEDED",
                    reason_code="execution_duration_exceeded",
                    agent_ref=agent_ref,
                    action_id=action_id,
                    safe_context={"elapsed_seconds": int(elapsed)},
                )
                self._touch(context)
                return CollectiveDecision(
                    False, "BLOCK", "execution_duration_exceeded", ("RETRY_LIMIT_EXCEEDED",)
                )
        scope = dict(context.authority_envelope or {})
        allowed_operations = {str(item) for item in scope.get("operations", [])}
        allowed_resources = {str(item) for item in scope.get("resources", [])}
        if operation not in allowed_operations or resource_ref not in allowed_resources:
            self._signal(
                context=context,
                signal_type="AUTHORITY_AMPLIFICATION",
                reason_code="authority_amplification",
                agent_ref=agent_ref,
                action_id=action_id,
                safe_context={"operation": operation, "resource_ref": resource_ref},
            )
            self._touch(context)
            return CollectiveDecision(
                False, "BLOCK", "authority_amplification", ("AUTHORITY_AMPLIFICATION",)
            )
        tools = _unique(list(context.observed_tool_classes or []) + [tool_class])
        if len(tools) > constraints.max_aggregate_tool_classes:
            self._signal(
                context=context,
                signal_type="AUTHORITY_AMPLIFICATION",
                reason_code="aggregate_tool_budget_exceeded",
                agent_ref=agent_ref,
                action_id=action_id,
                safe_context={"tool_class": tool_class},
            )
            self._touch(context)
            return CollectiveDecision(
                False, "BLOCK", "aggregate_tool_budget_exceeded", ("AUTHORITY_AMPLIFICATION",)
            )
        destinations = list(context.observed_external_destinations or [])
        if destination_ref:
            if not constraints.internet_access:
                self._signal(
                    context=context,
                    signal_type="UNEXPECTED_INTERNET_ACCESS",
                    reason_code="unexpected_internet_access",
                    agent_ref=agent_ref,
                    action_id=action_id,
                    safe_context={"destination_ref": destination_ref},
                )
                self._touch(context)
                return CollectiveDecision(
                    False,
                    "BLOCK",
                    "unexpected_internet_access",
                    ("UNEXPECTED_INTERNET_ACCESS",),
                )
            destinations = _unique(destinations + [destination_ref])
            if len(destinations) > constraints.max_external_destinations:
                self._signal(
                    context=context,
                    signal_type="AUTHORITY_AMPLIFICATION",
                    reason_code="external_destination_budget_exceeded",
                    agent_ref=agent_ref,
                    action_id=action_id,
                    safe_context={"destination_ref": destination_ref},
                )
                self._touch(context)
                return CollectiveDecision(
                    False,
                    "BLOCK",
                    "external_destination_budget_exceeded",
                    ("AUTHORITY_AMPLIFICATION",),
                )
        active_actions = list(context.active_consequential_action_ids or [])
        effective_consequential = consequential or operation in _CONSEQUENTIAL_OPERATIONS
        if effective_consequential and action_id not in active_actions:
            if len(active_actions) >= constraints.max_concurrent_consequential_actions:
                self._signal(
                    context=context,
                    signal_type="AUTHORITY_AMPLIFICATION",
                    reason_code="consequential_concurrency_exceeded",
                    agent_ref=agent_ref,
                    action_id=action_id,
                )
                self._touch(context)
                return CollectiveDecision(
                    False,
                    "BLOCK",
                    "consequential_concurrency_exceeded",
                    ("AUTHORITY_AMPLIFICATION",),
                )
            active_actions.append(action_id)
        context.observed_tool_classes = tools
        context.observed_external_destinations = destinations
        context.active_consequential_action_ids = _unique(active_actions)
        context.authorized_action_ids = _unique(list(context.authorized_action_ids or []) + [action_id])
        self._touch(context)
        self._runtime_event(
            context=context,
            event_type="agent_collective.action_assessed",
            entity_id=action_id,
            parent_action_id=context.root_action_id,
            agent_ref=agent_ref,
            decision="ALLOW",
            metadata={
                "operation": operation,
                "resource_ref": resource_ref,
                "tool_class": tool_class,
                "destination_ref": destination_ref,
                "consequential": effective_consequential,
            },
        )
        return CollectiveDecision(True, "ALLOW", "collective_constraints_satisfied")

    def complete_action(self, *, tenant_id: str, collective_id: str, action_id: str) -> None:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        context.active_consequential_action_ids = [
            ref for ref in list(context.active_consequential_action_ids or []) if ref != action_id
        ]
        self._touch(context)

    def record_communication(
        self,
        *,
        tenant_id: str,
        collective_id: str,
        writer_agent_ref: str | None,
        reader_agent_ref: str | None,
        channel_type: str,
        channel_ref: str,
        operation: str,
        evidence_quality: str,
        shared_resource_ref: str | None = None,
        instruction_ref: str | None = None,
        evidence_refs: tuple[str, ...] = (),
    ) -> CommunicationResult:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        known = channel_type in _VISIBLE_CHANNEL_TYPES and evidence_quality != "UNKNOWN"
        constraints = CollectiveConstraintSet.from_mapping(context.constraint_set)
        channel_key = f"{channel_type}:{channel_ref}"
        if not known:
            decision = "UNKNOWN"
        elif channel_key in set(constraints.approved_channels):
            decision = "ALLOW"
        elif channel_key in set(constraints.monitored_channels):
            decision = "MONITOR"
        elif channel_key in set(constraints.approval_required_channels):
            decision = "REQUIRE_APPROVAL"
        else:
            decision = "BLOCK"
        row = AgentCommunicationEvent(
            tenant_id=tenant_id,
            collective_id=collective_id,
            writer_agent_ref=writer_agent_ref,
            reader_agent_ref=reader_agent_ref,
            channel_type=channel_type,
            channel_ref=channel_ref,
            operation=operation,
            decision=decision,
            shared_resource_ref=shared_resource_ref,
            originating_objective_ref=context.root_objective_ref,
            instruction_ref=instruction_ref,
            authority_context_ref=f"collective:{context.id}",
            evidence_quality=evidence_quality,
            evidence_refs=list(evidence_refs),
            occurred_at=_utc(self._now()),
        )
        self._db.add(row)
        self._db.flush()
        prior_entity = context.root_action_id
        if operation == "READ" and shared_resource_ref:
            prior = self._db.scalar(
                select(AgentCommunicationEvent)
                .where(
                    AgentCommunicationEvent.tenant_id == tenant_id,
                    AgentCommunicationEvent.collective_id == collective_id,
                    AgentCommunicationEvent.shared_resource_ref == shared_resource_ref,
                    AgentCommunicationEvent.operation == "WRITE",
                    AgentCommunicationEvent.id != row.id,
                )
                .order_by(AgentCommunicationEvent.occurred_at.desc(), AgentCommunicationEvent.id.desc())
                .limit(1)
            )
            if prior is not None and prior.runtime_event_id:
                prior_event = self._db.get(RuntimeEvent, prior.runtime_event_id)
                if prior_event is not None and prior_event.entity_id:
                    prior_entity = prior_event.entity_id
        runtime = self._runtime_event(
            context=context,
            event_type="agent_collective.communication",
            entity_id=f"communication:{row.id}",
            parent_action_id=prior_entity,
            agent_ref=writer_agent_ref or reader_agent_ref,
            decision=decision,
            metadata={
                "writer_agent_ref": writer_agent_ref,
                "reader_agent_ref": reader_agent_ref,
                "channel_type": channel_type,
                "channel_ref": channel_ref,
                "operation": operation,
                "shared_resource_ref": shared_resource_ref,
                "instruction_ref": instruction_ref,
                "evidence_quality": evidence_quality,
            },
        )
        row.runtime_event_id = runtime.event_id
        context.observed_channel_refs = _unique(
            list(context.observed_channel_refs or []) + [f"{channel_type}:{channel_ref}"]
        )
        if shared_resource_ref:
            context.shared_store_refs = _unique(list(context.shared_store_refs or []) + [shared_resource_ref])
        if decision == "BLOCK":
            self._signal(
                context=context,
                signal_type="UNAPPROVED_COMMUNICATION_CHANNEL",
                reason_code="unapproved_communication_channel",
                agent_ref=writer_agent_ref or reader_agent_ref,
                evidence_refs=(f"communication:{row.id}",),
                safe_context={"channel_type": channel_type, "channel_ref": channel_ref},
            )
        elif decision == "UNKNOWN" and evidence_quality != "UNKNOWN":
            self._signal(
                context=context,
                signal_type="UNKNOWN_COLLECTIVE_BEHAVIOR",
                reason_code="visible_channel_unclassified",
                agent_ref=writer_agent_ref or reader_agent_ref,
                evidence_refs=(f"communication:{row.id}",),
                safe_context={"channel_type": channel_type, "channel_ref": channel_ref},
                severity="medium",
            )
        self._touch(context)
        self._db.flush()
        return CommunicationResult(row.id, runtime.event_id, decision)

    def evaluate_goal_adoption(
        self,
        *,
        tenant_id: str,
        collective_id: str,
        agent_ref: str,
        action_id: str,
        source: str,
        source_event_id: str | None,
        objective_ref: str,
        materially_different: bool,
        source_authorized: bool,
        consequential: bool,
    ) -> CollectiveDecision:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        if context.status == "REVOKED":
            return CollectiveDecision(False, "BLOCK", "delegation_root_revoked")
        if not materially_different or source_authorized:
            return CollectiveDecision(True, "ALLOW", "goal_provenance_authorized")
        signal_types = ["SHARED_STATE_GOAL_PROPAGATION"]
        self._signal(
            context=context,
            signal_type="SHARED_STATE_GOAL_PROPAGATION",
            reason_code="unauthorized_goal_adoption",
            agent_ref=agent_ref,
            action_id=action_id,
            evidence_refs=(f"communication:{source_event_id}",) if source_event_id else (),
            safe_context={"source": source, "objective_ref": objective_ref},
        )
        if consequential:
            signal_types.append("AUTHORITY_AMPLIFICATION")
            self._signal(
                context=context,
                signal_type="AUTHORITY_AMPLIFICATION",
                reason_code="unauthorized_goal_adoption",
                agent_ref=agent_ref,
                action_id=action_id,
                evidence_refs=(f"communication:{source_event_id}",) if source_event_id else (),
                safe_context={"source": source, "objective_ref": objective_ref},
            )
        context.status = "RESTRICTED"
        self._touch(context)
        return CollectiveDecision(
            False, "BLOCK", "unauthorized_goal_adoption", tuple(signal_types)
        )

    def record_failure(
        self,
        *,
        tenant_id: str,
        collective_id: str,
        agent_ref: str,
        failure_fingerprint: str,
    ) -> CollectiveDecision:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        if context.status in {"REVOKED", "ABANDONED"}:
            return CollectiveDecision(False, "BLOCK", f"collective_{context.status.lower()}")
        constraints = CollectiveConstraintSet.from_mapping(context.constraint_set)
        fingerprints = dict(context.retry_fingerprints or {})
        fingerprints[failure_fingerprint] = int(fingerprints.get(failure_fingerprint, 0)) + 1
        context.retry_fingerprints = fingerprints
        context.retry_count += 1
        context.failure_count += 1
        exceeded = (
            context.retry_count >= constraints.max_attempts
            or fingerprints[failure_fingerprint] >= constraints.max_equivalent_failures
        )
        if exceeded:
            context.status = "ABANDONED"
            self._signal(
                context=context,
                signal_type="RETRY_LIMIT_EXCEEDED",
                reason_code="retry_limit_exceeded",
                agent_ref=agent_ref,
                safe_context={
                    "attempt_count": context.retry_count,
                    "equivalent_failure_count": fingerprints[failure_fingerprint],
                },
            )
            self._touch(context)
            return CollectiveDecision(
                False, "BLOCK", "retry_limit_exceeded", ("RETRY_LIMIT_EXCEEDED",)
            )
        self._touch(context)
        return CollectiveDecision(True, "MONITOR", "retry_budget_remaining")

    def revoke_delegation_root(
        self,
        *,
        tenant_id: str,
        collective_id: str,
        actor_ref: str,
        reason_code: str,
    ) -> CollectiveDecision:
        context = self._locked_context(tenant_id=tenant_id, collective_id=collective_id)
        if context.status == "REVOKED":
            return CollectiveDecision(
                False,
                "BLOCK",
                "delegation_root_revoked",
                ("DELEGATION_ROOT_REVOKED",),
                tuple(context.member_delegation_context_ids or []),
            )
        revoked_contexts = revoke_delegation_context_v2(
            self._db,
            provider=self._signing_provider,
            tenant_id=tenant_id,
            delegation_context_id=context.delegation_root_context_id,
            reason_code=reason_code,
            observed_at=_utc(self._now()),
        )
        root_event = self._db.scalar(
            select(DelegationLifecycleEventV2)
            .where(
                DelegationLifecycleEventV2.tenant_id == tenant_id,
                DelegationLifecycleEventV2.delegation_context_id
                == context.delegation_root_context_id,
                DelegationLifecycleEventV2.event_type == "REVOKED",
            )
            .order_by(DelegationLifecycleEventV2.sequence.desc())
            .limit(1)
        )
        authority_refs = list(root_event.affected_unconsumed_descendant_refs or []) if root_event else []
        context.status = "REVOKED"
        context.active_principal_refs = []
        context.active_consequential_action_ids = []
        self._touch(context)
        runtime = self._runtime_event(
            context=context,
            event_type="agent_collective.root_revoked",
            entity_id=f"revocation:{context.id}",
            parent_action_id=context.root_action_id,
            agent_ref=None,
            decision="BLOCK",
            metadata={"actor_ref": actor_ref, "reason_code": reason_code},
        )
        audit = DelegationRootRevocation(
            tenant_id=tenant_id,
            collective_id=context.id,
            delegation_root_context_id=context.delegation_root_context_id,
            actor_ref=actor_ref,
            reason_code=reason_code,
            affected_agent_refs=list(context.member_agent_refs or []),
            affected_action_ids=list(context.authorized_action_ids or []),
            affected_authority_refs=authority_refs,
            runtime_event_id=runtime.event_id,
            occurred_at=_utc(self._now()),
        )
        self._db.add(audit)
        self._signal(
            context=context,
            signal_type="DELEGATION_ROOT_REVOKED",
            reason_code=reason_code,
            evidence_refs=tuple(authority_refs),
            safe_context={"affected_agent_count": len(context.member_agent_refs or [])},
        )
        self._db.flush()
        affected = _unique(list(revoked_contexts) + authority_refs)
        return CollectiveDecision(
            False,
            "BLOCK",
            "delegation_root_revoked",
            ("DELEGATION_ROOT_REVOKED",),
            tuple(affected),
        )


def _collective_id_from_action(action: Mapping[str, Any]) -> str | None:
    authority = action.get("authority_context")
    if isinstance(authority, str) and authority.startswith("collective:"):
        return authority.removeprefix("collective:").strip() or None
    if isinstance(authority, Mapping) and authority.get("type") == "collective":
        value = authority.get("id") or authority.get("collective_id")
        return str(value).strip() if value else None
    return None


def require_collective_action_authority(
    db: Session,
    *,
    signing_provider: SigningKeyProvider,
    tenant_id: str,
    action: Mapping[str, Any],
    now: datetime,
) -> AgentCollectiveContext | None:
    """Require a live root and exact pre-assessment for collective-bound actions."""
    collective_id = _collective_id_from_action(action)
    if collective_id is None:
        return None
    context = db.scalar(
        select(AgentCollectiveContext)
        .where(
            AgentCollectiveContext.tenant_id == tenant_id,
            AgentCollectiveContext.id == collective_id,
        )
        .with_for_update()
    )
    if context is None:
        raise PermissionError("collective authority is not available for this tenant")
    if context.status == "REVOKED":
        raise PermissionError("collective delegation root is revoked")
    if context.status not in {"ACTIVE", "RESTRICTED"}:
        raise PermissionError("collective authority is inactive")
    action_id = action.get("action_id")
    if not isinstance(action_id, str) or action_id not in set(context.authorized_action_ids or []):
        raise PermissionError("collective action was not pre-assessed")
    require_active_delegation_ancestry(
        db,
        provider=signing_provider,
        tenant_id=tenant_id,
        delegation_context_id=context.delegation_root_context_id,
        now=_utc(now),
    )
    return context
