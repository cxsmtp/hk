from __future__ import annotations

from copy import deepcopy

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.activity_audit import AIAction, AISession
from app.db.session import Base
from app.services import activity_audit_service


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _payload(*, action_id: str, discovery_asset_ref: str | None = None) -> dict[str, object]:
    metadata: dict[str, object] = {
        "canonical_ai_action_v1": {"event": "already-decided", "version": 1},
        "canonical_ai_action_hash": "h" * 64,
        "ai_action": {
            "policy": {"control_mode": "enforced"},
            "policy_snapshot": {"version": "3"},
            "decision_explanation": {"reason": "already-decided"},
            "evidence_bundle": {"refs": ["evidence:1"]},
        },
    }
    if discovery_asset_ref is not None:
        metadata["discovery_asset_ref"] = discovery_asset_ref
    return {
        "action_id": action_id,
        "timestamp": "2026-08-20T10:00:00+00:00",
        "source_surface": "browser",
        "ai_app": "Hawk Runtime",
        "ai_model": "gpt-5",
        "action_taken": "block",
        "metadata": metadata,
    }


def _action(db: Session, action_id: str) -> AIAction:
    action = db.get(AIAction, action_id)
    assert action is not None
    return action


def test_default_off_omits_discovery_context_metadata(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", False)
    payload = _payload(action_id="action-flag-off")
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    metadata["discovery_context"] = {
        "status": "available",
        "ai_asset_ref": "discovery_asset:caller-spoofed",
        "unbounded": "x" * 10000,
    }
    activity_audit_service.record_activity_event(
        db, tenant_id="tenant-a", user_id=None, payload=payload
    )

    assert "discovery_context" not in _action(db, "action-flag-off").metadata_json


def test_enabled_context_is_non_authoritative_and_preserves_decision_material(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)
    payload = _payload(action_id="action-enabled", discovery_asset_ref="not-a-discovery-asset")
    expected = deepcopy(payload["metadata"])

    activity_audit_service.record_activity_event(db, tenant_id="tenant-a", user_id=None, payload=payload)

    action = _action(db, "action-enabled")
    metadata = action.metadata_json
    assert metadata["discovery_context"]["status"] == "unknown"
    assert action.enforcement_action == "blocked"
    for key in (
        "canonical_ai_action_v1", "canonical_ai_action_hash",
    ):
        assert metadata[key] == expected[key]
    assert metadata["control_mode"] == "enforced"
    assert metadata["policy_snapshot"] == {"version": "3"}
    assert metadata["decision_explanation"] == {"reason": "already-decided"}
    assert metadata["evidence_bundle"] == {"refs": ["evidence:1"]}


def test_browser_bridge_projection_prefers_evidence_surface_and_block_decision(db: Session) -> None:
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id="user-a",
        payload={
            "action_id": "action-browser-bridge-projection",
            "timestamp": "2026-09-21T05:02:41+00:00",
            "source_surface": "endpoint_agent",
            "ai_app": "desktop-native",
            "action_type": "prompt_submit",
            "enforcement_action": "warned",
            "metadata": {
                "governance_enforcement_mode": "block",
                "authorization_kernel_v2_shadow": {"v2": {"decision": "block"}},
                "ai_action": {
                    "surface": {
                        "source_surface": "browser",
                        "surface_type": "browser",
                        "browser_type": "chrome",
                        "application": "chatgpt.com",
                        "domain": "chatgpt.com",
                    },
                    "policy": {"decision": "warn"},
                },
                "policy_snapshot": {
                    "assigned_scope": {
                        "source_surface": "browser",
                        "application": "chatgpt.com",
                    }
                },
            },
        },
    )

    action = _action(db, "action-browser-bridge-projection")
    session = db.get(AISession, action.session_id)
    assert action.ai_app == "chatgpt.com"
    # A shadow block is comparison evidence; this event reports an actual warning.
    assert action.enforcement_action == "warned"
    assert session is not None
    assert session.source_surface == "browser"
    assert session.ai_app == "chatgpt.com"


def test_browser_bridge_projection_uses_context_page_domain_when_surface_is_placeholder(db: Session) -> None:
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id="user-a",
        payload={
            "action_id": "action-browser-context-domain-projection",
            "timestamp": "2026-09-21T05:12:41+00:00",
            "source_surface": "endpoint_agent",
            "ai_app": "desktop-native",
            "action_type": "prompt_submit",
            "metadata": {
                "governance_enforcement_mode": "block",
                "ai_action": {
                    "surface": {
                        "source_surface": "browser",
                        "application": "desktop-native",
                        "domain": "desktop-native",
                    },
                },
                "context": {
                    "page_context": {
                        "domain": "chatgpt.com",
                        "url": "https://chatgpt.com/c/demo",
                    },
                    "app_context": {
                        "app_name": "ChatGPT",
                        "app_domain": "chatgpt.com",
                    },
                },
            },
        },
    )

    action = _action(db, "action-browser-context-domain-projection")
    session = db.get(AISession, action.session_id)
    assert action.ai_app == "chatgpt.com"
    assert action.enforcement_action == "blocked"
    assert session is not None
    assert session.source_surface == "browser"
    assert session.ai_app == "chatgpt.com"


def test_generic_asset_and_ai_system_identifiers_never_become_discovery_bindings(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)
    observed_assets: list[str | None] = []

    def observe_asset(_provider: object, *, asset: str | None = None, **_kwargs: object) -> dict[str, object]:
        observed_assets.append(asset)
        return {"status": "unknown", "limitations": ["asset_not_resolved"]}

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        observe_asset,
    )
    payload = _payload(action_id="action-untrusted-identifiers")
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    metadata.update({"asset_id": "generic-asset", "ai_system_id": "generic-system"})

    activity_audit_service.record_activity_event(db, tenant_id="tenant-a", user_id=None, payload=payload)

    assert observed_assets == [None]


def test_caller_nested_discovery_context_never_becomes_a_request_binding(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)
    observed_assets: list[str | None] = []

    def observe_asset(_provider: object, *, asset: str | None = None, **_kwargs: object) -> dict[str, object]:
        observed_assets.append(asset)
        return {"status": "unknown", "limitations": ["asset_not_resolved"]}

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        observe_asset,
    )
    payload = _payload(action_id="action-nested-context")
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    metadata["discovery_context"] = {
        "status": "available",
        "ai_asset_ref": "discovery_asset:caller-spoofed",
    }

    activity_audit_service.record_activity_event(db, tenant_id="tenant-a", user_id=None, payload=payload)

    assert observed_assets == [None]
    assert _action(db, "action-nested-context").metadata_json["discovery_context"] == {
        "status": "unknown", "limitations": ["asset_not_resolved"]
    }


def test_discovery_context_uses_only_valid_metadata_actor_reference_hashes(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)
    observed_actors: list[str | None] = []

    def observe_actor(_provider: object, *, actor: str | None = None, **_kwargs: object) -> dict[str, object]:
        observed_actors.append(actor)
        return {"status": "unknown", "limitations": ["asset_not_resolved"]}

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        observe_actor,
    )
    payload = _payload(action_id="action-actor-ref")
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    metadata.update({
        "actor_ref": "not-a-hash",
        "actor_reference_hash": "A" * 64,
    })

    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id="raw-user-id-must-not-reach-discovery",
        payload=payload,
    )
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id="raw-user-id-must-not-reach-discovery",
        payload=_payload(action_id="action-without-actor-ref"),
    )

    assert observed_actors == ["a" * 64, None]


def test_provider_failure_rolls_back_savepoint_and_never_prevents_persistence(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)

    def poison_transaction(*_args: object, **_kwargs: object) -> dict[str, object]:
        db.execute(text("select * from discovery_context_missing_table"))
        raise AssertionError("unreachable")

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        poison_transaction,
    )
    activity_audit_service.record_activity_event(
        db, tenant_id="tenant-a", user_id=None, payload=_payload(action_id="action-provider-error")
    )

    context = _action(db, "action-provider-error").metadata_json["discovery_context"]
    assert context == {"status": "unknown", "limitations": ["provider_error"]}
    assert _action(db, "action-provider-error").enforcement_action == "blocked"


def test_sparse_update_keeps_existing_discovery_binding_and_refreshes_only_projection(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)
    observed_assets: list[str | None] = []

    def context_for(_provider: object, *, asset: str | None = None, **_kwargs: object) -> dict[str, object]:
        observed_assets.append(asset)
        return {
            "schema_version": "discovery-context/1",
            "status": "partial",
            "ai_asset_ref": f"discovery_asset:{asset}" if asset else None,
            "limitations": ["missing_authoritative_dimensions"],
        }

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        context_for,
    )
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id=None,
        payload=_payload(action_id="action-refresh", discovery_asset_ref="asset-123"),
    )
    before = deepcopy(_action(db, "action-refresh").metadata_json)
    activity_audit_service.record_activity_event(
        db, tenant_id="tenant-a", user_id=None, payload=_payload(action_id="action-refresh")
    )

    after = _action(db, "action-refresh").metadata_json
    assert observed_assets == ["asset-123", "discovery_asset:asset-123"]
    for key in (
        "canonical_ai_action_v1", "canonical_ai_action_hash", "control_mode",
        "policy_snapshot", "decision_explanation", "evidence_bundle",
    ):
        assert after[key] == before[key]
    assert after["discovery_context"] == before["discovery_context"]


def test_repeated_action_preserves_good_bound_context_when_refresh_is_unknown_and_ignores_new_binding(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)
    observed_assets: list[str | None] = []

    def good_context(_provider: object, *, asset: str | None = None, **_kwargs: object) -> dict[str, object]:
        observed_assets.append(asset)
        return {
            "schema_version": "discovery-context/1",
            "status": "partial",
            "ai_asset_ref": f"discovery_asset:{asset}",
            "limitations": ["missing_authoritative_dimensions"],
        }

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        good_context,
    )
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id=None,
        payload=_payload(action_id="action-preserve-unknown", discovery_asset_ref="asset-original"),
    )
    expected = deepcopy(_action(db, "action-preserve-unknown").metadata_json["discovery_context"])

    def unknown_context(_provider: object, *, asset: str | None = None, **_kwargs: object) -> dict[str, object]:
        observed_assets.append(asset)
        return {"status": "unknown", "limitations": ["asset_not_resolved"]}

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        unknown_context,
    )
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id=None,
        payload=_payload(action_id="action-preserve-unknown", discovery_asset_ref="asset-replacement"),
    )

    action = _action(db, "action-preserve-unknown")
    assert observed_assets == ["asset-original", "discovery_asset:asset-original"]
    assert action.metadata_json["discovery_context"] == expected
    assert action.enforcement_action == "blocked"


def test_repeated_action_preserves_good_bound_context_when_provider_errors(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_audit_service.settings, "discovery_context_provider", True)

    def good_context(_provider: object, *, asset: str | None = None, **_kwargs: object) -> dict[str, object]:
        return {
            "schema_version": "discovery-context/1",
            "status": "available",
            "ai_asset_ref": f"discovery_asset:{asset}",
            "limitations": [],
        }

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        good_context,
    )
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id=None,
        payload=_payload(action_id="action-preserve-provider-error", discovery_asset_ref="asset-original"),
    )
    expected = deepcopy(_action(db, "action-preserve-provider-error").metadata_json["discovery_context"])

    def broken_provider(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("Discovery unavailable")

    monkeypatch.setattr(
        activity_audit_service.DiscoveryContextProvider,
        "get_context_for_ai_action",
        broken_provider,
    )
    activity_audit_service.record_activity_event(
        db,
        tenant_id="tenant-a",
        user_id=None,
        payload=_payload(action_id="action-preserve-provider-error"),
    )

    action = _action(db, "action-preserve-provider-error")
    assert action.metadata_json["discovery_context"] == expected
    assert action.enforcement_action == "blocked"
