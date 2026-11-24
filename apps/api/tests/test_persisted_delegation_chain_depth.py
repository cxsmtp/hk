from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentDelegation, AgentIdentity, CapabilityToken
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.api.routers.runtime_control import AgentActionInterceptRequest
from app.services import delegation_chain_authority_service as authority_service
from app.services.delegation_chain_authority_service import resolve_persisted_delegation_chain_depth


@pytest.fixture()
def db(tmp_path) -> Session:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'delegation-depth.sqlite3'}")
    Base.metadata.create_all(bind=engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _tenant(db: Session, tenant_id: str) -> None:
    db.add(Tenant(id=tenant_id, name=tenant_id, slug=tenant_id))


def _agent(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    action_scope: list[str] | None = None,
    max_chain_depth: int = 16,
) -> AgentIdentity:
    row = AgentIdentity(
        id=agent_id,
        tenant_id=tenant_id,
        name=agent_id,
        max_chain_depth=max_chain_depth,
        capability_inheritance=True,
        action_scope=["*"] if action_scope is None else action_scope,
    )
    db.add(row)
    return row


def _token(
    db: Session,
    *,
    tenant_id: str,
    token_id: str,
    agent_id: str,
    expired: bool = False,
    revoked: bool = False,
    scopes: list[str] | None = None,
    chain_depth: int = 16,
    ai_system_id: str | None = "system-a",
) -> CapabilityToken:
    now = datetime.now(timezone.utc)
    row = CapabilityToken(
        id=token_id,
        tenant_id=tenant_id,
        agent_identity_id=agent_id,
        token_hash=f"hash:{token_id}",
        scopes=["*"] if scopes is None else scopes,
        expires_at=now + (timedelta(minutes=-1) if expired else timedelta(hours=1)),
        revoked_at=(now if revoked else None),
        chain_depth=chain_depth,
    )
    # Assign separately so this test helper exercises both pre- and post-migration
    # model states during the RED phase.
    row.ai_system_id = ai_system_id
    db.add(row)
    return row


def test_resolver_fails_closed_for_unbound_legacy_token(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-root")
    _token(db, tenant_id="tenant-a", token_id="token-root", agent_id="agent-root", ai_system_id=None)
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-root",
        capability_token_id="token-root",
        claimed_chain_depth=1,
        ai_system_id="system-a",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_token_system_unbound"


def test_resolver_rejects_root_token_bound_to_different_system(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-root")
    _token(db, tenant_id="tenant-a", token_id="token-root", agent_id="agent-root", ai_system_id="system-a")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-root",
        capability_token_id="token-root",
        claimed_chain_depth=1,
        ai_system_id="system-b",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_token_system_mismatch"


def test_resolver_rejects_ancestor_token_bound_to_different_system(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-root")
    _agent(db, tenant_id="tenant-a", agent_id="agent-child")
    _token(db, tenant_id="tenant-a", token_id="token-root", agent_id="agent-root", ai_system_id="system-b")
    _token(db, tenant_id="tenant-a", token_id="token-child", agent_id="agent-child", ai_system_id="system-a")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-1", parent_agent_id="agent-root", child_agent_id="agent-child", parent_token_id="token-root", child_token_id="token-child")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-child",
        capability_token_id="token-child",
        claimed_chain_depth=2,
        ai_system_id="system-a",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_parent_token_system_mismatch"


def test_resolver_normalizes_naive_injected_now_to_utc(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-root")
    _token(db, tenant_id="tenant-a", token_id="token-root", agent_id="agent-root")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-root",
        capability_token_id="token-root",
        claimed_chain_depth=1,
        ai_system_id="system-a",
        now=datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0),
    )

    assert result.allowed is True
    assert result.reason_code == "delegation_chain_root"


def _delegation(
    db: Session,
    *,
    tenant_id: str,
    edge_id: str | None,
    parent_agent_id: str,
    child_agent_id: str,
    parent_token_id: str,
    child_token_id: str,
    status: str = "active",
    ai_system_id: str | None = "system-a",
    action_scope: list[str] | None = None,
    chain_depth: int = 99,
) -> AgentDelegation:
    row = AgentDelegation(
        id=edge_id,
        tenant_id=tenant_id,
        parent_agent_identity_id=parent_agent_id,
        child_agent_identity_id=child_agent_id,
        parent_token_id=parent_token_id,
        child_token_id=child_token_id,
        ai_system_id=ai_system_id,
        action_scope=["*"] if action_scope is None else action_scope,
        chain_depth=chain_depth,
        status=status,
    )
    db.add(row)
    return row


def _authority_event(
    *,
    event_id: str,
    agent_id: str,
    token_id: str,
    edge_id: str,
    parent_action_id: str | None = None,
    event_type: str = "agent_action_intercept",
    decision: str | None = "allow",
    ai_system_id: str | None = "system-a",
    chain_id: str = "chain-a",
    metadata: dict | None = None,
) -> RuntimeEvent:
    authority_metadata = {
        "capability_token_id": token_id,
        "delegation_edge_id": edge_id,
    }
    if metadata is not None:
        authority_metadata = metadata
    return RuntimeEvent(
        event_id=event_id,
        tenant_id="tenant-a",
        source_surface="aiiam",
        event_type=event_type,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        decision=decision,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        metadata_json=authority_metadata,
    )


def test_resolver_counts_persisted_edges_not_claimed_or_stored_depth(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-root")
    _agent(db, tenant_id="tenant-a", agent_id="agent-child")
    _token(db, tenant_id="tenant-a", token_id="token-root", agent_id="agent-root")
    _token(db, tenant_id="tenant-a", token_id="token-child", agent_id="agent-child")
    _delegation(
        db,
        tenant_id="tenant-a",
        edge_id="edge-1",
        parent_agent_id="agent-root",
        child_agent_id="agent-child",
        parent_token_id="token-root",
        child_token_id="token-child",
    )
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-child",
        capability_token_id="token-child",
        claimed_chain_depth=1,
        claimed_parent_agent_id="agent-root",
        ai_system_id="system-a",
    )

    assert result.derived_depth == 2
    assert result.delegation_ids == ("edge-1",)
    assert result.allowed is False
    assert result.reason_code == "delegation_chain_depth_mismatch"


def test_resolver_accepts_root_at_depth_one(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-root")
    _token(db, tenant_id="tenant-a", token_id="token-root", agent_id="agent-root")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-root",
        capability_token_id="token-root",
        claimed_chain_depth=1,
    )

    assert result.allowed is True
    assert result.derived_depth == 1
    assert result.reason_code == "delegation_chain_root"


def test_resolver_root_compatibility_does_not_allow_parent_claim_without_ai_system(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-root")
    _token(db, tenant_id="tenant-a", token_id="token-root", agent_id="agent-root")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-root",
        capability_token_id="token-root",
        claimed_chain_depth=1,
        claimed_parent_agent_id="claimed-parent",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_ai_system_required"


def test_resolver_accepts_exact_multi_hop_delegation_and_action_sequence(db: Session) -> None:
    _tenant(db, "tenant-a")
    for agent_id in ("root", "mid", "child"):
        _agent(db, tenant_id="tenant-a", agent_id=agent_id)
    for token_id, agent_id in (("token-root", "root"), ("token-mid", "mid"), ("token-child", "child")):
        _token(db, tenant_id="tenant-a", token_id=token_id, agent_id=agent_id)
    _delegation(db, tenant_id="tenant-a", edge_id="edge-root-mid", parent_agent_id="root", child_agent_id="mid", parent_token_id="token-root", child_token_id="token-mid")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-mid-child", parent_agent_id="mid", child_agent_id="child", parent_token_id="token-mid", child_token_id="token-child")
    db.add_all(
        [
            _authority_event(event_id="action-root", agent_id="root", token_id="token-root", edge_id=None),
            _authority_event(event_id="action-mid", agent_id="mid", token_id="token-mid", edge_id="edge-root-mid", parent_action_id="action-root"),
        ]
    )
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="token-child",
        claimed_chain_depth=3,
        claimed_parent_agent_id="mid",
        parent_action_id="action-mid",
        chain_id="chain-a",
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is True
    assert result.derived_depth == 3
    assert result.parent_agent_ids == ("mid", "root")
    assert result.reason_code == "delegation_chain_verified"


def test_resolver_rejects_ambiguous_active_parent_edges(db: Session) -> None:
    _tenant(db, "tenant-a")
    for agent_id in ("parent-a", "parent-b", "child"):
        _agent(db, tenant_id="tenant-a", agent_id=agent_id)
    for token_id, agent_id in (("token-a", "parent-a"), ("token-b", "parent-b"), ("token-child", "child")):
        _token(db, tenant_id="tenant-a", token_id=token_id, agent_id=agent_id)
    _delegation(db, tenant_id="tenant-a", edge_id="edge-a", parent_agent_id="parent-a", child_agent_id="child", parent_token_id="token-a", child_token_id="token-child")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-b", parent_agent_id="parent-b", child_agent_id="child", parent_token_id="token-b", child_token_id="token-child")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="token-child",
        claimed_chain_depth=2,
        ai_system_id="system-a",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_ambiguous_parent"


@pytest.mark.parametrize(
    ("edge_status", "parent_expired", "child_revoked", "expected_reason"),
    [
        ("revoked", False, False, "delegation_chain_revoked"),
        ("active", True, False, "delegation_chain_parent_token_expired"),
        ("active", False, True, "delegation_chain_token_revoked"),
    ],
)
def test_resolver_rejects_revoked_or_expired_authority(
    db: Session,
    edge_status: str,
    parent_expired: bool,
    child_revoked: bool,
    expected_reason: str,
) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="parent")
    _agent(db, tenant_id="tenant-a", agent_id="child")
    _token(db, tenant_id="tenant-a", token_id="parent-token", agent_id="parent", expired=parent_expired)
    _token(db, tenant_id="tenant-a", token_id="child-token", agent_id="child", revoked=child_revoked)
    _delegation(db, tenant_id="tenant-a", edge_id="edge", parent_agent_id="parent", child_agent_id="child", parent_token_id="parent-token", child_token_id="child-token", status=edge_status)
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="child-token",
        claimed_chain_depth=2,
        ai_system_id="system-a",
    )

    assert result.allowed is False
    assert result.reason_code == expected_reason


def test_resolver_rejects_token_agent_mismatch(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-b")
    _token(db, tenant_id="tenant-a", token_id="token-a", agent_id="agent-a")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-b",
        capability_token_id="token-a",
        claimed_chain_depth=1,
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_token_agent_mismatch"
    assert result.derived_depth is None


def test_resolver_rejects_cycles_with_bounded_traversal(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-b")
    _token(db, tenant_id="tenant-a", token_id="token-a", agent_id="agent-a")
    _token(db, tenant_id="tenant-a", token_id="token-b", agent_id="agent-b")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-ab", parent_agent_id="agent-a", child_agent_id="agent-b", parent_token_id="token-a", child_token_id="token-b")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-ba", parent_agent_id="agent-b", child_agent_id="agent-a", parent_token_id="token-b", child_token_id="token-a")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-a",
        capability_token_id="token-a",
        claimed_chain_depth=2,
        ai_system_id="system-a",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_token_cycle_detected"


def test_resolver_parent_action_is_tenant_chain_and_parent_agent_bound(db: Session) -> None:
    _tenant(db, "tenant-a")
    _tenant(db, "tenant-b")
    _agent(db, tenant_id="tenant-a", agent_id="parent")
    _agent(db, tenant_id="tenant-a", agent_id="child")
    _token(db, tenant_id="tenant-a", token_id="parent-token", agent_id="parent")
    _token(db, tenant_id="tenant-a", token_id="child-token", agent_id="child")
    _delegation(db, tenant_id="tenant-a", edge_id="edge", parent_agent_id="parent", child_agent_id="child", parent_token_id="parent-token", child_token_id="child-token")
    db.add(
        RuntimeEvent(
            event_id="foreign-parent-action",
            tenant_id="tenant-b",
            source_surface="aiiam",
            event_type="agent_action_intercept",
            agent_id="parent",
            chain_id="chain-a",
            metadata_json={},
        )
    )
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="child-token",
        claimed_chain_depth=2,
        claimed_parent_agent_id="parent",
        parent_action_id="foreign-parent-action",
        chain_id="chain-a",
        ai_system_id="system-a",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_parent_action_not_found"


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("agent", "delegation_parent_action_agent_mismatch"),
        ("chain", "delegation_parent_action_chain_mismatch"),
        ("system", "delegation_parent_action_system_mismatch"),
        ("system_unbound", "delegation_parent_action_system_unbound"),
        ("disconnected", "delegation_parent_action_disconnected"),
        ("cycle", "delegation_parent_action_cycle_detected"),
        ("over_bound", "delegation_parent_action_over_bound"),
    ],
)
def test_resolver_reconciles_every_parent_action_hop(
    db: Session,
    mutation: str,
    expected_reason: str,
) -> None:
    _tenant(db, "tenant-a")
    for agent_id in ("root", "mid", "child", "wrong"):
        _agent(db, tenant_id="tenant-a", agent_id=agent_id)
    for token_id, agent_id in (("token-root", "root"), ("token-mid", "mid"), ("token-child", "child")):
        _token(db, tenant_id="tenant-a", token_id=token_id, agent_id=agent_id)
    _delegation(db, tenant_id="tenant-a", edge_id="edge-root-mid", parent_agent_id="root", child_agent_id="mid", parent_token_id="token-root", child_token_id="token-mid")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-mid-child", parent_agent_id="mid", child_agent_id="child", parent_token_id="token-mid", child_token_id="token-child")
    root_event = _authority_event(event_id="action-root", agent_id="root", token_id="token-root", edge_id=None)
    mid_event = _authority_event(event_id="action-mid", agent_id="mid", token_id="token-mid", edge_id="edge-root-mid", parent_action_id="action-root")
    db.add_all([root_event, mid_event])
    db.flush()
    if mutation == "agent":
        mid_event.agent_id = "wrong"
    elif mutation == "chain":
        mid_event.chain_id = "chain-other"
    elif mutation == "system":
        mid_event.ai_system_id = "system-other"
    elif mutation == "system_unbound":
        mid_event.ai_system_id = None
    elif mutation == "disconnected":
        mid_event.parent_action_id = "action-missing"
    elif mutation == "cycle":
        root_event.parent_action_id = "action-mid"
    elif mutation == "over_bound":
        extra = _authority_event(event_id="action-extra", agent_id="root", token_id="token-root", edge_id=None)
        db.add(extra)
        root_event.parent_action_id = "action-extra"
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="token-child",
        claimed_chain_depth=3,
        claimed_parent_agent_id="mid",
        parent_action_id="action-mid",
        chain_id="chain-a",
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is False
    assert result.reason_code == expected_reason


def test_resolver_requires_parent_action_for_delegated_authority(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="parent")
    _agent(db, tenant_id="tenant-a", agent_id="child")
    _token(db, tenant_id="tenant-a", token_id="parent-token", agent_id="parent")
    _token(db, tenant_id="tenant-a", token_id="child-token", agent_id="child")
    _delegation(db, tenant_id="tenant-a", edge_id="edge", parent_agent_id="parent", child_agent_id="child", parent_token_id="parent-token", child_token_id="child-token")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="child-token",
        claimed_chain_depth=2,
        claimed_parent_agent_id="parent",
        chain_id="chain-a",
        ai_system_id="system-a",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_parent_action_required"


@pytest.mark.parametrize("edge_system_id", [None, "system-other"])
def test_resolver_requires_every_edge_to_match_requested_ai_system(
    db: Session,
    edge_system_id: str | None,
) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="parent")
    _agent(db, tenant_id="tenant-a", agent_id="child")
    _token(db, tenant_id="tenant-a", token_id="parent-token", agent_id="parent")
    _token(db, tenant_id="tenant-a", token_id="child-token", agent_id="child")
    _delegation(
        db,
        tenant_id="tenant-a",
        edge_id="edge",
        parent_agent_id="parent",
        child_agent_id="child",
        parent_token_id="parent-token",
        child_token_id="child-token",
        ai_system_id=edge_system_id,
    )
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="child-token",
        claimed_chain_depth=2,
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_ai_system_mismatch"


def test_resolver_rejects_delegated_authority_without_requested_ai_system(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="parent")
    _agent(db, tenant_id="tenant-a", agent_id="child")
    _token(db, tenant_id="tenant-a", token_id="parent-token", agent_id="parent")
    _token(db, tenant_id="tenant-a", token_id="child-token", agent_id="child")
    _delegation(db, tenant_id="tenant-a", edge_id="edge", parent_agent_id="parent", child_agent_id="child", parent_token_id="parent-token", child_token_id="child-token")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="child-token",
        claimed_chain_depth=2,
        claimed_parent_agent_id="parent",
        required_action="tool.run",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_ai_system_required"


@pytest.mark.parametrize(
    ("authority_layer", "expected_reason"),
    [
        ("edge_scope", "delegation_chain_edge_action_scope_mismatch"),
        ("edge_depth", "delegation_chain_edge_depth_exceeded"),
        ("parent_token_scope", "delegation_chain_parent_token_scope_mismatch"),
        ("parent_token_depth", "delegation_chain_parent_token_depth_exceeded"),
        ("parent_agent_scope", "delegation_chain_parent_agent_scope_mismatch"),
        ("parent_agent_depth", "delegation_chain_parent_agent_depth_exceeded"),
    ],
)
def test_resolver_rejects_parent_authority_escalation(
    db: Session,
    authority_layer: str,
    expected_reason: str,
) -> None:
    _tenant(db, "tenant-a")
    parent = _agent(db, tenant_id="tenant-a", agent_id="parent")
    _agent(db, tenant_id="tenant-a", agent_id="child")
    parent_token = _token(db, tenant_id="tenant-a", token_id="parent-token", agent_id="parent")
    _token(db, tenant_id="tenant-a", token_id="child-token", agent_id="child")
    edge = _delegation(
        db,
        tenant_id="tenant-a",
        edge_id="edge",
        parent_agent_id="parent",
        child_agent_id="child",
        parent_token_id="parent-token",
        child_token_id="child-token",
    )
    if authority_layer == "edge_scope":
        edge.action_scope = ["tool.read"]
    elif authority_layer == "edge_depth":
        edge.chain_depth = 1
    elif authority_layer == "parent_token_scope":
        parent_token.scopes = ["tool.read"]
    elif authority_layer == "parent_token_depth":
        parent_token.chain_depth = 0
    elif authority_layer == "parent_agent_scope":
        parent.action_scope = ["tool.read"]
    elif authority_layer == "parent_agent_depth":
        parent.max_chain_depth = 1
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="child-token",
        claimed_chain_depth=2,
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is False
    assert result.reason_code == expected_reason


@pytest.mark.parametrize(
    ("event_type", "decision", "metadata", "expected_reason"),
    [
        ("browser_telemetry", "allow", {"capability_token_id": "parent-token", "delegation_edge_id": None}, "delegation_parent_action_event_type_invalid"),
        ("agent_action_intercept", "block", {"capability_token_id": "parent-token", "delegation_edge_id": None}, "delegation_parent_action_decision_not_allowed"),
        ("agent_action_intercept", "require_approval", {"capability_token_id": "parent-token", "delegation_edge_id": None}, "delegation_parent_action_decision_not_allowed"),
        ("agent_action_intercept", "allow", {}, "delegation_parent_action_authority_binding_missing"),
        ("agent_action_intercept", "allow", {"capability_token_id": "wrong-token", "delegation_edge_id": None}, "delegation_parent_action_token_binding_mismatch"),
        ("agent_action_intercept", "allow", {"capability_token_id": "parent-token", "delegation_edge_id": "wrong-edge"}, "delegation_parent_action_edge_binding_mismatch"),
        ("agent_action_intercept", "allow", {"capability_token_id": "parent-token", "delegation_edge_id": None}, "delegation_chain_verified"),
    ],
)
def test_resolver_requires_authoritative_parent_action_provenance(
    db: Session,
    event_type: str,
    decision: str,
    metadata: dict,
    expected_reason: str,
) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="parent")
    _agent(db, tenant_id="tenant-a", agent_id="child")
    _token(db, tenant_id="tenant-a", token_id="parent-token", agent_id="parent")
    _token(db, tenant_id="tenant-a", token_id="child-token", agent_id="child")
    _delegation(db, tenant_id="tenant-a", edge_id="edge", parent_agent_id="parent", child_agent_id="child", parent_token_id="parent-token", child_token_id="child-token")
    db.add(
        _authority_event(
            event_id="action-parent",
            agent_id="parent",
            token_id="parent-token",
            edge_id="edge",
            event_type=event_type,
            decision=decision,
            metadata=metadata,
        )
    )
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="child-token",
        claimed_chain_depth=2,
        claimed_parent_agent_id="parent",
        parent_action_id="action-parent",
        chain_id="chain-a",
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is (expected_reason == "delegation_chain_verified")
    assert result.reason_code == expected_reason


def test_resolver_rejects_rotated_token_agent_cycle(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-b")
    _token(db, tenant_id="tenant-a", token_id="token-a-old", agent_id="agent-a")
    _token(db, tenant_id="tenant-a", token_id="token-a-new", agent_id="agent-a")
    _token(db, tenant_id="tenant-a", token_id="token-b", agent_id="agent-b")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-b-a", parent_agent_id="agent-b", child_agent_id="agent-a", parent_token_id="token-b", child_token_id="token-a-new")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-a-b", parent_agent_id="agent-a", child_agent_id="agent-b", parent_token_id="token-a-old", child_token_id="token-b")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-a",
        capability_token_id="token-a-new",
        claimed_chain_depth=3,
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_agent_cycle_detected"


def test_resolver_rejects_repeated_token_cycle(db: Session) -> None:
    _tenant(db, "tenant-a")
    _agent(db, tenant_id="tenant-a", agent_id="agent-a")
    _token(db, tenant_id="tenant-a", token_id="token-a", agent_id="agent-a")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-self", parent_agent_id="agent-a", child_agent_id="agent-a", parent_token_id="token-a", child_token_id="token-a")
    db.commit()

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="agent-a",
        capability_token_id="token-a",
        claimed_chain_depth=2,
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_chain_token_cycle_detected"


def test_resolver_enforces_parent_action_hop_bound(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    _tenant(db, "tenant-a")
    for agent_id in ("root", "mid", "child"):
        _agent(db, tenant_id="tenant-a", agent_id=agent_id)
    for token_id, agent_id in (("token-root", "root"), ("token-mid", "mid"), ("token-child", "child")):
        _token(db, tenant_id="tenant-a", token_id=token_id, agent_id=agent_id)
    _delegation(db, tenant_id="tenant-a", edge_id="edge-root-mid", parent_agent_id="root", child_agent_id="mid", parent_token_id="token-root", child_token_id="token-mid")
    _delegation(db, tenant_id="tenant-a", edge_id="edge-mid-child", parent_agent_id="mid", child_agent_id="child", parent_token_id="token-mid", child_token_id="token-child")
    db.add_all(
        [
            _authority_event(event_id="action-root", agent_id="root", token_id="token-root", edge_id=None),
            _authority_event(event_id="action-mid", agent_id="mid", token_id="token-mid", edge_id="edge-root-mid", parent_action_id="action-root"),
        ]
    )
    db.commit()
    monkeypatch.setattr(authority_service, "MAX_PARENT_ACTION_HOPS", 1)

    result = resolve_persisted_delegation_chain_depth(
        db,
        tenant_id="tenant-a",
        agent_id="child",
        capability_token_id="token-child",
        claimed_chain_depth=3,
        claimed_parent_agent_id="mid",
        parent_action_id="action-mid",
        chain_id="chain-a",
        ai_system_id="system-a",
        required_action="tool.run",
    )

    assert result.allowed is False
    assert result.reason_code == "delegation_parent_action_too_deep"


def test_runtime_agent_action_request_forbids_unknown_authority_fields() -> None:
    with pytest.raises(ValidationError):
        AgentActionInterceptRequest.model_validate(
            {
                "agent_id": "agent-a",
                "capability_token": "secret",
                "action_type": "tool_execution",
                "chain_depth": 2,
                "chain_id": "chain-a",
                "parent_action_id": "action-parent",
                "parent_agent_id": "agent-parent",
                "delegation_path": ["agent-parent"],
            }
        )


def test_runtime_agent_action_request_preserves_known_authority_fields() -> None:
    request = AgentActionInterceptRequest.model_validate(
        {
            "agent_id": "agent-a",
            "capability_token": "secret",
            "action_type": "tool_execution",
            "chain_depth": 2,
            "chain_id": "chain-a",
            "parent_action_id": "action-parent",
            "parent_agent_id": "agent-parent",
        }
    )

    assert request.chain_depth == 2
    assert request.chain_id == "chain-a"
    assert request.parent_action_id == "action-parent"
    assert request.parent_agent_id == "agent-parent"
