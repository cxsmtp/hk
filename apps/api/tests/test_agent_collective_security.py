from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-agent-collective-security")
os.environ.setdefault("CONNECTOR_SECRETS_KEY", "test-connector-secrets-key")
os.environ.setdefault("CONNECTOR_SECRETS_KDF_SALT", "test-connector-secrets-salt")


NOW = datetime(2026, 8, 30, 9, tzinfo=timezone.utc)
ROOT_SCOPE = {"resources": ["synthetic-store"], "operations": ["read", "analyze"], "max_value": "10"}


@pytest.fixture()
def collective_env(tmp_path):
    from app.db import models as _models  # noqa: F401
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import issue_delegation_context_v2
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.agent_collective_security import (
        AgentCollectiveSecurityService,
        CollectiveConstraintSet,
    )

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'collective.sqlite3'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    tenant = Tenant(name="Collective Tenant", slug="collective-tenant", is_active=True)
    other = Tenant(name="Other Tenant", slug="collective-other", is_active=True)
    db.add_all([tenant, other])
    db.flush()
    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(
        purpose="delegation_context_signing",
        tenant_id=tenant.id,
        key_id="delegation-key",
        secret=b"d" * 32,
    )
    root = register_delegated_child_v2(
        db,
        provider=provider,
        tenant_id=tenant.id,
        parent_action_id="root-objective",
        delegated_action_id="agent-a-action",
        parent_delegation_context_id=None,
        parent_scope=ROOT_SCOPE,
        child_scope=ROOT_SCOPE,
        source_principal_ref="human:operator",
        destination_principal_ref="agent:A",
        expires_at=NOW + timedelta(hours=1),
        issued_at=NOW,
    )
    db.flush()
    issue_delegation_context_v2(
        db,
        provider=provider,
        tenant_id=tenant.id,
        delegation_context_id=root.delegation_context_id,
        observed_at=NOW,
    )
    constraints = CollectiveConstraintSet(
        max_active_agents=4,
        max_delegation_depth=3,
        max_fan_out_per_agent=2,
        max_active_descendants=3,
        max_aggregate_tool_classes=2,
        max_external_destinations=1,
        max_concurrent_consequential_actions=1,
        max_attempts=3,
        max_equivalent_failures=2,
        max_execution_duration_seconds=300,
        approved_channels=("registered_a2a:a2a://approved", "file:shared://approved"),
        monitored_channels=("message_queue:mq://observe",),
        approval_required_channels=("external_message:mail://approval",),
        internet_access=False,
    )
    service = AgentCollectiveSecurityService(db, signing_provider=provider, now=lambda: NOW)
    collective = service.create_collective(
        tenant_id=tenant.id,
        delegation_root_context_id=root.delegation_context_id,
        originating_actor_ref="human:operator",
        represented_subject_ref="subject:operator",
        business_purpose_ref="purpose:synthetic-analysis",
        root_objective_ref="objective:bounded-analysis",
        constraints=constraints,
    )
    db.flush()
    try:
        yield {
            "db": db,
            "engine": engine,
            "tenant": tenant,
            "other": other,
            "provider": provider,
            "root": root,
            "collective": collective,
            "constraints": constraints,
            "service": service,
        }
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _add_child(env, *, action_id: str, agent_ref: str, parent=None, scope=None):
    from app.services.action_integrity.delegation_lifecycle import issue_delegation_context_v2
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2

    parent = parent or env["root"]
    scope = scope or ROOT_SCOPE
    child = register_delegated_child_v2(
        env["db"],
        provider=env["provider"],
        tenant_id=env["tenant"].id,
        parent_action_id=parent.delegated_action_id,
        delegated_action_id=action_id,
        parent_delegation_context_id=parent.delegation_context_id,
        parent_scope=dict(parent.signed_envelope["effective_scope"]),
        child_scope=scope,
        source_principal_ref=parent.destination_principal_ref,
        destination_principal_ref=agent_ref,
        expires_at=NOW + timedelta(minutes=45),
        issued_at=NOW,
    )
    env["db"].flush()
    issue_delegation_context_v2(
        env["db"],
        provider=env["provider"],
        tenant_id=env["tenant"].id,
        delegation_context_id=child.delegation_context_id,
        observed_at=NOW,
    )
    env["db"].flush()
    return child


def test_authority_and_aggregate_capability_cannot_amplify(collective_env) -> None:
    from app.db.models.agent_collective import CollectiveSecuritySignal

    env = collective_env
    child_b = _add_child(env, action_id="agent-b-action", agent_ref="agent:B")
    child_c = _add_child(env, action_id="agent-c-action", agent_ref="agent:C")
    assert env["service"].register_member(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        delegation_context_id=child_b.delegation_context_id,
    ).allowed
    assert env["service"].register_member(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        delegation_context_id=child_c.delegation_context_id,
    ).allowed

    allowed = env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:B",
        action_id="read-action",
        operation="read",
        resource_ref="synthetic-store",
        tool_class="database-read",
        destination_ref=None,
        consequential=False,
    )
    denied = env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:C",
        action_id="write-action",
        operation="write",
        resource_ref="synthetic-store",
        tool_class="database-write",
        destination_ref=None,
        consequential=True,
    )
    assert allowed.allowed is True
    assert denied.allowed is False
    assert denied.reason_code == "authority_amplification"
    assert env["db"].scalar(
        select(CollectiveSecuritySignal).where(
            CollectiveSecuritySignal.tenant_id == env["tenant"].id,
            CollectiveSecuritySignal.signal_type == "AUTHORITY_AMPLIFICATION",
        )
    ) is not None


def test_visible_approved_unapproved_and_unknown_channels_are_distinct(collective_env) -> None:
    from app.db.models.agent_collective import CollectiveSecuritySignal

    env = collective_env
    approved = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:A",
        reader_agent_ref="agent:B",
        channel_type="registered_a2a",
        channel_ref="a2a://approved",
        operation="SEND",
        evidence_quality="NATIVE_SEMANTIC",
    )
    unapproved = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:B",
        reader_agent_ref="agent:C",
        channel_type="file",
        channel_ref="shared://rogue",
        operation="WRITE",
        evidence_quality="OS_OBSERVED",
    )
    unknown = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref=None,
        reader_agent_ref=None,
        channel_type="unknown",
        channel_ref="unknown",
        operation="UNKNOWN",
        evidence_quality="UNKNOWN",
    )
    assert approved.decision == "ALLOW"
    assert unapproved.decision == "BLOCK"
    assert unknown.decision == "UNKNOWN"
    assert env["db"].scalar(select(CollectiveSecuritySignal).where(
        CollectiveSecuritySignal.signal_type == "UNAPPROVED_COMMUNICATION_CHANNEL"
    )) is not None
    assert env["db"].scalars(select(CollectiveSecuritySignal).where(
        CollectiveSecuritySignal.signal_type == "UNKNOWN_COLLECTIVE_BEHAVIOR"
    )).all() == []


def test_channel_monitor_approval_and_visible_unknown_are_deterministic(collective_env) -> None:
    from app.db.models.agent_collective import CollectiveSecuritySignal

    env = collective_env
    monitored = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:A",
        reader_agent_ref="agent:B",
        channel_type="message_queue",
        channel_ref="mq://observe",
        operation="SEND",
        evidence_quality="NATIVE_SEMANTIC",
    )
    approval = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:A",
        reader_agent_ref=None,
        channel_type="external_message",
        channel_ref="mail://approval",
        operation="SEND",
        evidence_quality="NATIVE_SEMANTIC",
    )
    visible_unknown = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:A",
        reader_agent_ref=None,
        channel_type="unknown",
        channel_ref="visible://unclassified",
        operation="UNKNOWN",
        evidence_quality="OS_OBSERVED",
    )
    assert monitored.decision == "MONITOR"
    assert approval.decision == "REQUIRE_APPROVAL"
    assert visible_unknown.decision == "UNKNOWN"
    assert env["db"].scalar(select(CollectiveSecuritySignal).where(
        CollectiveSecuritySignal.signal_type == "UNKNOWN_COLLECTIVE_BEHAVIOR"
    )) is not None


def test_aggregate_tool_and_consequential_concurrency_budgets_apply(collective_env) -> None:
    env = collective_env
    for index, tool_class in enumerate(("tool:one", "tool:two"), start=1):
        assert env["service"].assess_action(
            tenant_id=env["tenant"].id,
            collective_id=env["collective"].id,
            agent_ref="agent:A",
            action_id=f"aggregate-tool-{index}",
            operation="read",
            resource_ref="synthetic-store",
            tool_class=tool_class,
            destination_ref=None,
            consequential=False,
        ).allowed
    tool_denial = env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:A",
        action_id="aggregate-tool-3",
        operation="read",
        resource_ref="synthetic-store",
        tool_class="tool:three",
        destination_ref=None,
        consequential=False,
    )
    assert tool_denial.reason_code == "aggregate_tool_budget_exceeded"
    first = env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:A",
        action_id="consequential-one",
        operation="analyze",
        resource_ref="synthetic-store",
        tool_class="tool:one",
        destination_ref=None,
        consequential=True,
    )
    second = env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:A",
        action_id="consequential-two",
        operation="analyze",
        resource_ref="synthetic-store",
        tool_class="tool:one",
        destination_ref=None,
        consequential=True,
    )
    assert first.allowed is True
    assert second.reason_code == "consequential_concurrency_exceeded"


def test_shared_state_goal_adoption_blocks_before_consequential_action(collective_env) -> None:
    env = collective_env
    write = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:B",
        reader_agent_ref=None,
        channel_type="file",
        channel_ref="shared://approved",
        operation="WRITE",
        shared_resource_ref="resource:synthetic-state",
        instruction_ref="instruction:rogue-objective",
        evidence_quality="OS_OBSERVED",
    )
    read = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:B",
        reader_agent_ref="agent:C",
        channel_type="file",
        channel_ref="shared://approved",
        operation="READ",
        shared_resource_ref="resource:synthetic-state",
        instruction_ref="instruction:rogue-objective",
        evidence_quality="OS_OBSERVED",
    )
    decision = env["service"].evaluate_goal_adoption(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:C",
        action_id="external-action",
        source="shared_state",
        source_event_id=read.event_id,
        objective_ref="objective:external-send",
        materially_different=True,
        source_authorized=False,
        consequential=True,
    )
    assert write.decision == "ALLOW"
    assert read.decision == "ALLOW"
    assert decision.allowed is False
    assert decision.reason_code == "unauthorized_goal_adoption"
    assert set(decision.signal_types) == {"SHARED_STATE_GOAL_PROPAGATION", "AUTHORITY_AMPLIFICATION"}


@pytest.mark.parametrize(
    ("constraint_field", "expected_signal"),
    [
        ("max_active_agents", "AGENT_POPULATION_EXCEEDED"),
        ("max_delegation_depth", "DELEGATION_DEPTH_EXCEEDED"),
        ("max_fan_out_per_agent", "FANOUT_EXCEEDED"),
    ],
)
def test_population_depth_and_fanout_limits_emit_explicit_outcomes(
    collective_env, constraint_field: str, expected_signal: str
) -> None:
    env = collective_env
    constraints = env["constraints"].replace(**{constraint_field: 1})
    env["service"].replace_constraints(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        constraints=constraints,
    )
    if constraint_field == "max_fan_out_per_agent":
        first = _add_child(env, action_id="fanout-first-child", agent_ref="agent:first")
        assert env["service"].register_member(
            tenant_id=env["tenant"].id,
            collective_id=env["collective"].id,
            delegation_context_id=first.delegation_context_id,
        ).allowed
    child = _add_child(env, action_id=f"child-{constraint_field}", agent_ref="agent:B")
    decision = env["service"].register_member(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        delegation_context_id=child.delegation_context_id,
    )
    assert decision.allowed is False
    assert expected_signal in decision.signal_types


def test_retry_budget_cannot_be_reset_by_spawning_a_child(collective_env) -> None:
    env = collective_env
    first = env["service"].record_failure(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:B",
        failure_fingerprint="failure:synthetic",
    )
    second = env["service"].record_failure(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:B",
        failure_fingerprint="failure:synthetic",
    )
    child = _add_child(env, action_id="retry-reset-child", agent_ref="agent:retry-reset")
    spawn = env["service"].register_member(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        delegation_context_id=child.delegation_context_id,
    )
    assert first.allowed is True
    assert second.allowed is False
    assert second.reason_code == "retry_limit_exceeded"
    assert spawn.allowed is False
    assert spawn.reason_code == "collective_abandoned"


def test_root_revocation_is_tenant_scoped_preserves_history_and_blocks_descendants(collective_env) -> None:
    from app.db.models.action_integrity import DelegationContextV2
    from app.db.models.agent_collective import AgentCommunicationEvent, DelegationRootRevocation

    env = collective_env
    child = _add_child(env, action_id="revoked-child-action", agent_ref="agent:B")
    assert env["service"].register_member(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        delegation_context_id=child.delegation_context_id,
    ).allowed
    env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:A",
        reader_agent_ref="agent:B",
        channel_type="registered_a2a",
        channel_ref="a2a://approved",
        operation="SEND",
        evidence_quality="NATIVE_SEMANTIC",
    )
    result = env["service"].revoke_delegation_root(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        actor_ref="human:incident-commander",
        reason_code="synthetic_swarm_escape",
    )
    assert result.allowed is False
    assert result.reason_code == "delegation_root_revoked"
    assert {env["root"].delegation_context_id, child.delegation_context_id}.issubset(set(result.affected_refs))
    assert env["db"].scalar(select(DelegationRootRevocation)) is not None
    assert env["db"].scalar(select(AgentCommunicationEvent)) is not None
    assert all(row.state == "REVOKED" for row in env["db"].scalars(select(DelegationContextV2)).all())
    assert env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:B",
        action_id="stale-queued-action",
        operation="read",
        resource_ref="synthetic-store",
        tool_class="database-read",
        destination_ref=None,
        consequential=True,
    ).reason_code == "delegation_root_revoked"
    with pytest.raises(PermissionError, match="tenant"):
        env["service"].get_context(
            tenant_id=env["other"].id,
            collective_id=env["collective"].id,
        )


def test_execution_seam_requires_preassessed_action_and_live_root(collective_env) -> None:
    from app.services.agent_collective_security import require_collective_action_authority

    env = collective_env
    authority_context = f"collective:{env['collective'].id}"
    action = {
        "tenant_id": env["tenant"].id,
        "action_id": "seam-authorized-action",
        "authority_context": authority_context,
    }
    with pytest.raises(PermissionError, match="pre-assessed"):
        require_collective_action_authority(
            env["db"],
            signing_provider=env["provider"],
            tenant_id=env["tenant"].id,
            action=action,
            now=NOW,
        )
    assert env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:A",
        action_id=action["action_id"],
        operation="read",
        resource_ref="synthetic-store",
        tool_class="database-read",
        destination_ref=None,
        consequential=True,
    ).allowed
    assert require_collective_action_authority(
        env["db"],
        signing_provider=env["provider"],
        tenant_id=env["tenant"].id,
        action=action,
        now=NOW,
    ).id == env["collective"].id
    env["service"].revoke_delegation_root(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        actor_ref="human:incident-commander",
        reason_code="synthetic_swarm_escape",
    )
    with pytest.raises(PermissionError, match="revoked"):
        require_collective_action_authority(
            env["db"],
            signing_provider=env["provider"],
            tenant_id=env["tenant"].id,
            action=action,
            now=NOW,
        )


def test_valid_bounded_collective_materializes_phase7_parent_child_path(collective_env) -> None:
    from app.db.models.activity_lineage import LineageEdge
    from app.services.activity_lineage import materialize_activity_lineage

    env = collective_env
    child_b = _add_child(env, action_id="valid-b-action", agent_ref="agent:B")
    child_c = _add_child(env, action_id="valid-c-action", agent_ref="agent:C")
    for child in (child_b, child_c):
        assert env["service"].register_member(
            tenant_id=env["tenant"].id,
            collective_id=env["collective"].id,
            delegation_context_id=child.delegation_context_id,
        ).allowed
    sent = env["service"].record_communication(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        writer_agent_ref="agent:B",
        reader_agent_ref="agent:C",
        channel_type="registered_a2a",
        channel_ref="a2a://approved",
        operation="SEND",
        evidence_quality="NATIVE_SEMANTIC",
    )
    action = env["service"].assess_action(
        tenant_id=env["tenant"].id,
        collective_id=env["collective"].id,
        agent_ref="agent:C",
        action_id="valid-analysis-action",
        operation="analyze",
        resource_ref="synthetic-store",
        tool_class="analysis",
        destination_ref=None,
        consequential=True,
    )
    assert sent.decision == "ALLOW"
    assert action.allowed is True
    env["db"].flush()
    lineage = materialize_activity_lineage(
        env["db"],
        tenant_id=env["tenant"].id,
        runtime_event_id=sent.runtime_event_id,
        depth=6,
        limit=100,
    )
    assert lineage is not None
    assert env["db"].scalar(select(LineageEdge).where(
        LineageEdge.tenant_id == env["tenant"].id,
        LineageEdge.lineage_id == lineage.id,
        LineageEdge.edge_type == "PARENT_OF",
    )) is not None
