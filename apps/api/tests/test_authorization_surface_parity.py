from __future__ import annotations

import json

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.control_engine import authorization
from app.db.models.activity_audit import AIAction
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.enforcement import EnforcementEvent
from app.db.session import Base, get_db
from app.main import app
from app.services.runtime_intelligence.runtime_event_normalizer import (
    ingest_from_ai_iam_event,
    ingest_from_browser_signal,
    ingest_from_gateway_enforcement,
    ingest_runtime_event,
)
from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload
from app.services.surface_control_plane_service import ingest_surface_event


@pytest.mark.parametrize(
    ("source_surface", "event_type", "authorization_surface"),
    (
        ("gateway", "llm_intercept", "llm_gateway"),
        ("gateway", "mcp_authorize", "mcp_gateway"),
        ("aiiam", "agent_action_intercept", "runtime_control"),
        ("internal_mcp", "mcp_tool_execute", "internal_mcp"),
    ),
)
def test_selected_surface_copies_one_trusted_precomputed_comparison_to_runtime_and_activity(
    tmp_path,
    monkeypatch,
    source_surface: str,
    event_type: str,
    authorization_surface: str,
) -> None:
    from app.services.runtime_intelligence import runtime_event_normalizer as normalizer

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / f'selected-{authorization_surface}.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    tenant_id = f"tenant-selected-{authorization_surface}"
    action_id = f"selected-action-{authorization_surface}"
    policy_snapshot_id = f"selected-policy-{authorization_surface}"
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        json.dumps({tenant_id: [authorization_surface]}),
    )
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "selected-precomputed-binding-key")
    trusted = {
        "action_id": action_id,
        "actor": {"identity_id": "user-1", "identity_type": "human", "user_id": "user-1"},
        "authority": {
            "authority_type": "authenticated_user",
            "authority_source": "server_session",
            "verified": True,
        },
        "surface": {
            "application": "approved-app",
            "asset_status": "approved",
            "environment": "prod",
        },
        "action": {
            "action_type": "prompt" if authorization_surface == "llm_gateway" else "tool_execution",
            "action_risk": "low",
            "tool_name": "accounts.read",
            "tool_version": "1",
            "tool_fingerprint_id": "fingerprint-1",
            "parameter_hash": "1" * 64,
            "target_resource": "account/42",
        },
        "policy": {"policy_snapshot_id": policy_snapshot_id, "control_ids": []},
    }
    outcome = authorization.apply_trusted_pre_action_rollout(
        tenant_id=tenant_id,
        surface=authorization_surface,
        action_id=action_id,
        chain_id=f"chain-{authorization_surface}",
        collector_id="selected-surface-test",
        trusted_pre_action_governance_check=trusted,
        legacy_decision="allow",
        legacy_reason="legacy_allow",
        legacy_control_mode="inline_allowed",
        policy_snapshot_id=policy_snapshot_id,
        settings_obj=settings,
    )
    precomputed = authorization.authorization_rollout_persistence_metadata(outcome)
    trusted["authorization_kernel_v2_precomputed"] = precomputed

    evaluation_calls = 0

    def fail_duplicate_evaluation(*args, **kwargs):
        nonlocal evaluation_calls
        evaluation_calls += 1
        raise AssertionError("selected event must not evaluate authorization twice")

    monkeypatch.setattr(normalizer, "apply_authorization_rollout", fail_duplicate_evaluation)
    try:
        with session_local() as db:
            runtime = ingest_runtime_event(
                db,
                payload=RuntimeEventIngestPayload(
                    tenant_id=tenant_id,
                    source_surface=source_surface,
                    event_type=event_type,
                    app_id="approved-app",
                    user_id="user-1",
                    policy_version_id=policy_snapshot_id,
                    correlation_id=f"correlation-{authorization_surface}",
                    context_id=f"context-{authorization_surface}",
                    chain_id=f"chain-{authorization_surface}",
                    severity="low",
                    tool_name="accounts.read",
                    metadata={
                        "decision": "allow",
                        "operational_telemetry": True,
                        "authorization_kernel_v2_shadow": {"caller": "forged"},
                        "authorization_kernel_v2_shadow_health": {
                            "schema_version": "2.0",
                            "status": "ok",
                            "error_code": None,
                        },
                    },
                ),
                trusted_pre_action_governance_check=trusted,
            )
            assert runtime is not None
            db.commit()
            activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime.event_id))
            assert activity is not None
            assert runtime.metadata_json["authorization_kernel_v2_shadow"] == precomputed[
                "authorization_kernel_v2_shadow"
            ]
            assert runtime.metadata_json["authorization_kernel_v2_shadow_health"] == precomputed[
                "authorization_kernel_v2_shadow_health"
            ]
            assert activity.metadata_json["authorization_kernel_v2_shadow"] == runtime.metadata_json[
                "authorization_kernel_v2_shadow"
            ]
            assert activity.metadata_json["authorization_kernel_v2_shadow_health"] == runtime.metadata_json[
                "authorization_kernel_v2_shadow_health"
            ]
            assert evaluation_calls == 0
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_selected_surface_rejects_invalid_trusted_precomputed_metadata_without_reevaluation(
    tmp_path, monkeypatch
) -> None:
    from app.services.runtime_intelligence import runtime_event_normalizer as normalizer

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'selected-invalid-precomputed.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    tenant_id = "tenant-selected-invalid-precomputed"
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        json.dumps({tenant_id: ["llm_gateway"]}),
    )
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)

    def fail_duplicate_evaluation(*args, **kwargs):
        raise AssertionError("selected event must not re-evaluate invalid precomputed metadata")

    monkeypatch.setattr(normalizer, "apply_authorization_rollout", fail_duplicate_evaluation)
    try:
        with session_local() as db:
            runtime = ingest_runtime_event(
                db,
                payload=RuntimeEventIngestPayload(
                    tenant_id=tenant_id,
                    source_surface="gateway",
                    event_type="llm_intercept",
                    app_id="approved-app",
                    user_id="user-1",
                    policy_version_id="policy-invalid",
                    correlation_id="selected-invalid",
                    severity="low",
                    metadata={"decision": "block", "operational_telemetry": True},
                ),
                trusted_pre_action_governance_check={
                    "action_id": "selected-invalid",
                    "policy": {"policy_snapshot_id": "policy-invalid"},
                    "authorization_kernel_v2_precomputed": {
                        "authorization_kernel_v2_shadow": {"comparison_hash": "forged"},
                        "authorization_kernel_v2_shadow_health": {
                            "schema_version": "2.0",
                            "status": "ok",
                            "error_code": None,
                        },
                    },
                },
            )
            assert runtime is not None
            db.commit()
            activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime.event_id))
            expected_health = {
                "schema_version": "2.0",
                "status": "error",
                "error_code": "precomputed_authorization_invalid",
            }
            assert runtime.metadata_json["authorization_kernel_v2_shadow_health"] == expected_health
            assert activity is not None
            assert activity.metadata_json["authorization_kernel_v2_shadow_health"] == expected_health
            assert "authorization_kernel_v2_shadow" not in runtime.metadata_json
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.mark.parametrize(
    ("source_surface", "event_type", "expected_adapter"),
    (
        ("gateway", "llm_intercept", "llm_gateway"),
        ("gateway", "mcp_authorize", "mcp_gateway"),
        ("aiiam", "agent_action_intercept", "runtime_control"),
        ("browser", "browser_prompt_submitted", "browser"),
        ("sdk", "sdk_action_intercept", "sdk"),
        ("internal_mcp", "mcp_tool_execute", "internal_mcp"),
    ),
)
def test_all_six_runtime_ingress_surfaces_persist_one_shadow_comparison_pair(
    tmp_path,
    monkeypatch,
    source_surface: str,
    event_type: str,
    expected_adapter: str,
) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / f'authorization-{expected_adapter}.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "authorization-six-surface-binding-key")
    try:
        with session_local() as db:
            runtime = ingest_runtime_event(
                db,
                payload=RuntimeEventIngestPayload(
                    tenant_id=f"tenant-{expected_adapter}",
                    source_surface=source_surface,
                    event_type=event_type,
                    app_id="approved-ai-app",
                    correlation_id=f"correlation-{expected_adapter}",
                    context_id=f"context-{expected_adapter}",
                    chain_id=f"chain-{expected_adapter}",
                    risk_tier="low",
                    policy_version_id="policy-six-surface",
                    severity="low",
                    tool_name="accounts.read",
                    metadata={
                        "decision": "allow",
                        "action_type": "tool_execution" if "mcp" in expected_adapter else "prompt",
                        "target_resource": "account/42",
                        "tool_fingerprint": "fingerprint-001",
                        "operational_telemetry": True,
                        "pre_action_governance_check": {
                            "authority": {
                                "authority_type": "delegated",
                                "authority_source": "server-session",
                                "verified": True,
                            },
                            "surface": {"asset_status": "approved"},
                        },
                    },
                ),
            )
            assert runtime is not None
            db.commit()

            activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime.event_id))
            assert activity is not None
            runtime_shadow = runtime.metadata_json["authorization_kernel_v2_shadow"]
            assert runtime_shadow == activity.metadata_json["authorization_kernel_v2_shadow"]
            assert runtime.metadata_json["authorization_kernel_v2_shadow_health"]["status"] == "ok"
            assert runtime.source_surface == source_surface
            assert runtime_shadow["action_id"] == runtime.event_id
            assert runtime_shadow["v2"]["policy_snapshot_hash"] == runtime_shadow["legacy"]["policy_snapshot_hash"]
            assert runtime_shadow["v2"]["decision"] != "allow"
            assert runtime_shadow["v2"]["control_mode"] in {
                "incomplete",
                "shadow_would_block",
                "detected_only",
                "telemetry_only",
            }
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_sdk_unified_surface_ingest_persists_shadow_without_changing_legacy_result(
    tmp_path, monkeypatch
) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'authorization-sdk-surface.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", False)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", False)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "authorization-sdk-surface-binding-key")
    try:
        with session_local() as db:
            baseline = ingest_surface_event(
                db,
                tenant_id="tenant-sdk-surface",
                actor_user_id=None,
                event={
                    "surface": "sdk",
                    "app": "approved-sdk-app",
                    "event_type": "sdk.llm.request",
                    "action_type": "prompt",
                    "decision_hint": "allow",
                    "correlation_id": "sdk-surface-baseline",
                    "session_id": "sdk-surface-baseline",
                    "gateway_routed": True,
                    "metadata": {"asset_status": "approved"},
                },
            )
            monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
            monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
            result = ingest_surface_event(
                db,
                tenant_id="tenant-sdk-surface",
                actor_user_id=None,
                event={
                    "surface": "sdk",
                    "app": "approved-sdk-app",
                    "event_type": "sdk.llm.request",
                    "action_type": "prompt",
                    "decision_hint": "allow",
                    "correlation_id": "sdk-surface-correlation",
                    "session_id": "sdk-surface-session",
                    "gateway_routed": True,
                    "metadata": {"asset_status": "approved"},
                },
            )
            db.commit()

            volatile_identity_fields = {
                "runtime_event_id",
                "audit_action_id",
                "timestamp",
                "trace_url",
                "session_id",
                "endpoint_id",
                "alert_id",
            }
            assert {
                key: value for key, value in result.items() if key not in volatile_identity_fields
            } == {
                key: value for key, value in baseline.items() if key not in volatile_identity_fields
            }
            runtime = db.get(RuntimeEvent, result["runtime_event_id"])
            assert runtime is not None
            assert runtime.source_surface == "sdk"
            baseline_runtime = db.get(RuntimeEvent, baseline["runtime_event_id"])
            assert baseline_runtime is not None
            assert "authorization_kernel_v2_shadow" not in baseline_runtime.metadata_json
            activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime.event_id))
            assert activity is not None
            assert runtime.metadata_json["authorization_kernel_v2_shadow"] == activity.metadata_json[
                "authorization_kernel_v2_shadow"
            ]
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_existing_gateway_runtime_and_browser_ingress_paths_persist_shadow_pairs(
    tmp_path, monkeypatch
) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'authorization-existing-ingress.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "authorization-existing-ingress-binding-key")
    try:
        with session_local() as db:
            rows = []
            for label, summary in (("llm", "prompt_submission"), ("mcp", "mcp_authorize")):
                rows.append(
                    ingest_from_gateway_enforcement(
                        db,
                        event=EnforcementEvent(
                            tenant_id="tenant-existing-ingress",
                            correlation_id=f"gateway-{label}-correlation",
                            ai_system_id="approved-ai-system",
                            actor_type="agent",
                            actor_id="agent-existing-ingress",
                            request_id=f"gateway-{label}-request",
                            input_prompt="redacted-ref",
                            input_context_summary=summary,
                            input_attachments_meta=[],
                            guardian_results=[],
                            final_decision="allow",
                            final_actions={
                                "_meta": {"governance_state": "approved"},
                                "_trace": {
                                    "tool_name": "accounts.read",
                                    "mcp_server_id": "bank-mcp",
                                    "redacted_input_ref": "input-hash",
                                    "pre_action_governance_check": {
                                        "authority": {
                                            "authority_type": "capability_token",
                                            "authority_source": "server-session",
                                            "verified": True,
                                        },
                                        "surface": {
                                            "application": "bank-mcp",
                                            "asset_status": "approved",
                                        },
                                        "action": {
                                            "action_type": "tool_execution",
                                            "action_risk": "low",
                                            "tool_name": "accounts.read",
                                            "tool_version": "1",
                                            "tool_fingerprint_id": "bank-mcp:accounts.read:1",
                                            "parameter_hash": "2" * 64,
                                            "target_resource": "account/42",
                                        },
                                    },
                                },
                            },
                            evidence_nodes_created=[],
                            controls_impacted=[],
                            audit_log_id=f"audit-{label}",
                        ),
                    )
                )
            rows.append(
                ingest_from_ai_iam_event(
                    db,
                    tenant_id="tenant-existing-ingress",
                    event_type="agent_action_intercept",
                    ai_system_id="approved-ai-system",
                    user_id=None,
                    agent_id="agent-existing-ingress",
                    severity="low",
                    evidence_node_ids=[],
                    correlation_id="runtime-control-correlation",
                    metadata={
                        "decision": "allow",
                        "action": "accounts.read",
                        "tool_name": "accounts.read",
                        "target_resource": "account/42",
                        "operational_telemetry": True,
                        # Caller-shaped metadata is deliberately ignored as authority.
                        "pre_action_governance_check": {
                            "authority": {"verified": False},
                        },
                    },
                    trusted_pre_action_governance_check={
                        "authority": {
                            "authority_type": "capability_token",
                            "authority_source": "server-session",
                            "verified": True,
                        },
                        "surface": {"application": "bank-mcp", "asset_status": "approved"},
                        "action": {
                            "action_type": "tool_execution",
                            "action_risk": "low",
                            "tool_name": "accounts.read",
                            "tool_version": "1",
                                "tool_fingerprint_id": "runtime:accounts.read:1",
                                "parameter_hash": "3" * 64,
                            "target_resource": "account/42",
                        },
                    },
                )
            )
            rows.append(
                ingest_from_browser_signal(
                    db,
                    tenant_id="tenant-existing-ingress",
                    payload={
                        "event_type": "browser_prompt_submitted",
                        "action_taken": "allow",
                        "action_type": "prompt",
                        "domain": "assistant.example.internal",
                        "correlation_id": "browser-existing-correlation",
                        "operational_telemetry": True,
                        "pre_action_governance_check": {
                            "authority": {"verified": False},
                            "surface": {"asset_status": "unknown"},
                        },
                    },
                    ai_system_id=None,
                    evidence_node_id=None,
                    monitoring_signal_id=None,
                    trusted_pre_action_governance_check={
                        "authority": {
                            "authority_type": "browser_session",
                            "authority_source": "server-session",
                            "verified": True,
                        },
                        "surface": {
                            "application": "Assistant",
                            "asset_status": "approved",
                        },
                        "action": {
                            "action_type": "prompt",
                            "action_risk": "low",
                            "target_resource": "assistant.example.internal",
                        },
                    },
                )
            )
            db.commit()

            assert all(row is not None for row in rows)
            adapters = []
            for row in rows:
                assert row is not None
                shadow = row.metadata_json["authorization_kernel_v2_shadow"]
                activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == row.event_id))
                if row.source_surface != "browser":
                    assert activity is not None, f"missing activity for {row.source_surface}:{row.event_type}"
                    assert shadow == activity.metadata_json["authorization_kernel_v2_shadow"]
                if row.event_type in {"mcp_authorize", "agent_action_intercept", "browser_prompt_submitted"}:
                    assert shadow["v2"]["decision"] == "allow", (row.source_surface, row.event_type)
                adapters.append(row.source_surface + ":" + row.event_type)
            assert adapters == [
                "gateway:llm_intercept",
                "gateway:mcp_authorize",
                "aiiam:agent_action_intercept",
                "browser:browser_prompt_submitted",
            ]
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_shadow_kernel_persists_same_redacted_comparison_on_runtime_and_activity(
    tmp_path, monkeypatch
) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'authorization-shadow.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(
        settings,
        "canonical_action_binding_key",
        "authorization-shadow-test-binding-key-0001",
    )
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        registration = client.post(
            "/auth/register",
            json={
                "email": "authorization-shadow@example.com",
                "password": "Password123!",
                "full_name": "Authorization Shadow",
            },
        )
        assert registration.status_code == 200, registration.text
        identity = registration.json()
        headers = {
            "Authorization": f"Bearer {identity['access_token']}",
            "X-Tenant-ID": identity["tenants"][0]["id"],
        }
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "correlation_id": "authorization-shadow-chain",
                "event_type": "browser_prompt_submitted",
                "domain": "assistant.example.internal",
                "url": "https://assistant.example.internal/chat?secret=must-not-persist",
                "action_taken": "allow",
                "action_type": "prompt",
                "browser": "chrome",
                "application": "Assistant",
                "endpoint_id": "authorization-shadow-endpoint",
                "severity": "low",
            },
        )
        assert response.status_code == 200, response.text
        runtime_event_id = response.json()["runtime_event_id"]

        with session_local() as db:
            runtime = db.get(RuntimeEvent, runtime_event_id)
            activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime_event_id))
            assert runtime is not None
            assert activity is not None
            runtime_shadow = runtime.metadata_json["authorization_kernel_v2_shadow"]
            activity_shadow = activity.metadata_json["authorization_kernel_v2_shadow"]
            assert runtime_shadow == activity_shadow
            assert runtime.decision == "allow"
            assert activity.enforcement_action == "allowed"
            encoded = json.dumps(runtime_shadow, sort_keys=True)
            assert "must-not-persist" not in encoded
            assert "secret=" not in encoded
            assert len(encoded.encode("utf-8")) <= 4_096
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.mark.parametrize(
    ("failure_target", "expected_code"),
    (
        ("adapt_existing_hawk_action", "canonical_projection_failed"),
        ("apply_authorization_rollout", "authorization_evaluation_failed"),
    ),
)
def test_shadow_failure_does_not_rollback_or_change_legacy_browser_response(
    tmp_path, monkeypatch, failure_target: str, expected_code: str
) -> None:
    from app.services.runtime_intelligence import runtime_event_normalizer as normalizer

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'authorization-shadow-failure.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", False)
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "authorization-shadow-failure-binding-key")

    def fail_shadow_projection(*args, **kwargs):
        raise RuntimeError("raw secret must-not-persist")

    monkeypatch.setattr(normalizer, failure_target, fail_shadow_projection)
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        registration = client.post(
            "/auth/register",
            json={
                "email": "authorization-shadow-failure@example.com",
                "password": "Password123!",
                "full_name": "Authorization Shadow Failure",
            },
        )
        assert registration.status_code == 200, registration.text
        identity = registration.json()
        headers = {
            "Authorization": f"Bearer {identity['access_token']}",
            "X-Tenant-ID": identity["tenants"][0]["id"],
        }
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "correlation_id": "authorization-shadow-failure-chain",
                "event_type": "browser_prompt_submitted",
                "domain": "assistant.example.internal",
                "action_taken": "allow",
                "action_type": "prompt",
                "browser": "chrome",
                "application": "Assistant",
                "endpoint_id": "authorization-shadow-failure-endpoint",
                "severity": "low",
            },
        )

        assert response.status_code == 200, response.text
        runtime_event_id = response.json()["runtime_event_id"]
        with session_local() as db:
            runtime = db.get(RuntimeEvent, runtime_event_id)
            activity = db.scalar(select(AIAction).where(AIAction.runtime_event_id == runtime_event_id))
            assert runtime is not None
            assert activity is not None
            expected_health = {
                "schema_version": "2.0",
                "status": "error",
                "error_code": expected_code,
            }
            assert runtime.metadata_json["authorization_kernel_v2_shadow_health"] == expected_health
            assert activity.metadata_json["authorization_kernel_v2_shadow_health"] == expected_health
            assert "authorization_kernel_v2_shadow" not in runtime.metadata_json
            assert "must-not-persist" not in json.dumps(expected_health)
            assert runtime.decision == "allow"
            assert activity.enforcement_action == "allowed"
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
