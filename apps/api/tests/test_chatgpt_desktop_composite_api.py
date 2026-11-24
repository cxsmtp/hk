from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.evidence import EvidenceNode
from app.db.session import Base, get_db
from app.main import app
from app.services.native_control.chatgpt_desktop_service import (
    CHATGPT_EVIDENCE_QUERY_LIMIT,
    project_chatgpt_desktop_assets,
)


PASSWORD = "Password123!"
NOW = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)


@pytest.fixture()
def composite_api_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'chatgpt-composite.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    monkeypatch.setitem(settings.__dict__, "native_control_framework", True)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, session_factory
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _register(client: TestClient, email: str) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Composite Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    tenant_id = body["tenants"][0]["id"]
    return tenant_id, {
        "Authorization": f"Bearer {body['access_token']}",
        "X-Tenant-ID": tenant_id,
    }


def _node(
    tenant_id: str,
    *,
    node_type: str,
    payload: dict[str, object],
    created_at: datetime = NOW,
) -> EvidenceNode:
    return EvidenceNode(
        tenant_id=tenant_id,
        node_type=node_type,
        signal_type="test.chatgpt.composite",
        label="ChatGPT composite test evidence",
        payload=payload,
        created_at=created_at,
        updated_at=created_at,
    )


def _observation(endpoint_id: str, *, version: str, account: str = "unknown") -> dict[str, object]:
    return {
        "endpoint_id": endpoint_id,
        "event_type": "chatgpt_desktop_observation",
        "correlation_id": f"observation-{endpoint_id}",
        "chatgpt_desktop": {
            "installed": True,
            "bundle_path": "/Applications/ChatGPT.app",
            "bundle_id": "com.openai.codex",
            "version": version,
            "build": "5551",
            "team_id": "2DC432GLL2",
            "signature_verified": True,
            "notarization_verified": True,
            "native_hook_available": False,
            "process_id": 1042,
            "parent_process_id": 1,
            "process_start_time_ns": 99,
            "process_name": "ChatGPT",
            "identity_state": "bundle_and_signature_matched",
            "mode": "unknown_desktop_mode",
            "runtime_location": "unknown",
            "account_context": account,
            "supported_signal_only": True,
        },
    }


def _healthy_floor(endpoint_id: str) -> dict[str, object]:
    controls = {
        name: {
            "status": "inline_bound" if name != "network_control" else "inline",
            "verification": "verified",
            "health": "healthy",
            "evidence_refs": [f"receipt:{endpoint_id}:{name}"],
        }
        for name in ("file_control", "process_control", "network_control", "semantic_proxy")
    }
    return {
        "endpoint_id": endpoint_id,
        "hostname": "demo-mac",
        "os_type": "macos",
        "posture": {
            "endpoint_enforcement_floor": {
                "controls": controls,
                "local_policy": {
                    "status": "active",
                    "freshness": "fresh",
                    "policy_version": "policy-7",
                    "signature_verified": True,
                    "evidence_refs": ["policy-receipt:7"],
                },
                "reason_codes": [],
                "blind_spots": ["managed_network_extension_acceptance_pending"],
            }
        },
    }


def test_projection_uses_latest_observation_and_refuses_untrusted_account_claim() -> None:
    nodes = [
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="old", account="enterprise"),
            created_at=NOW - timedelta(minutes=2),
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="26.715.31925", account="enterprise"),
            created_at=NOW - timedelta(minutes=1),
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_heartbeat",
            payload=_healthy_floor("endpoint-1"),
            created_at=NOW,
        ),
    ]

    result = project_chatgpt_desktop_assets(nodes, now=NOW)

    assert result["total"] == 1
    asset = result["items"][0]
    assert asset["installation"]["version"] == "26.715.31925"
    assert asset["account"]["context"] == "unknown"
    assert asset["account"]["authoritative"] is False
    assert asset["endpoint_floor"]["health"] == "healthy"
    assert asset["built_in_browser"]["observed"] is False
    assert asset["native_hook_available"] is False
    assert "protected" not in asset


def test_authoritative_account_mode_and_compliance_evidence_are_projected_without_becoming_inline() -> None:
    nodes = [
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="26.715.31925"),
        ),
        _node(
            "tenant-1",
            node_type="openai_workspace_context",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_account_context",
                "account_context": "business",
                "account_evidence_source": "openai_admin_api",
                "source_verified": True,
                "evidence_refs": ["openai-admin:workspace-1"],
            },
            created_at=NOW + timedelta(seconds=1),
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_mode_context",
                "mode": "built_in_browser",
                "runtime_location": "local_endpoint",
                "context_evidence_source": "approved_application_context",
            },
            created_at=NOW + timedelta(seconds=2),
        ),
        _node(
            "tenant-1",
            node_type="openai_compliance_evidence",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_compliance_event",
                "provider_action_id": "provider-1",
                "provider_event_id": "provider-1",
                "evidence_source": "openai_compliance_api",
                "source_verified": True,
                "evidence_refs": ["openai-compliance:provider-1"],
            },
            created_at=NOW + timedelta(seconds=3),
        ),
    ]

    asset = project_chatgpt_desktop_assets(nodes, now=NOW + timedelta(seconds=4))["items"][0]

    assert asset["account"]["context"] == "business"
    assert asset["account"]["authoritative"] is True
    assert asset["modes_observed"] == ["built_in_browser"]
    assert asset["runtime_location"] == "local_endpoint"
    assert asset["built_in_browser"]["observed"] is True
    compliance = next(row for row in asset["capabilities"] if row["capability"] == "compliance_visibility")
    assert compliance["verification"] == "verified"
    assert compliance["control_role"] == "evidence_only"
    assert compliance["level"] == "observe"


def test_provider_control_and_compliance_claims_require_verified_origin_and_receipt() -> None:
    nodes = [
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="26.715.31925"),
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_account_context",
                "account_context": "enterprise",
                "account_evidence_source": "openai_admin_api",
            },
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_app_context",
                "evidence_source": "openai_admin_api",
                "app_action_verification": "verified",
            },
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_compliance_event",
                "provider_action_id": "untrusted-provider-claim",
            },
        ),
    ]

    asset = project_chatgpt_desktop_assets(nodes, now=NOW)["items"][0]
    capability = {row["capability"]: row for row in asset["capabilities"]}

    assert asset["account"]["context"] == "unknown"
    assert capability["app_action"]["verification"] == "unknown"
    assert capability["compliance_visibility"]["verification"] == "unknown"
    assert asset["compliance_reconciliation"]["items"] == []


def test_malformed_supported_signal_fields_are_bounded_and_do_not_crash_projection() -> None:
    observation = _observation("endpoint-1", version="26.715.31925")
    composite = observation["chatgpt_desktop"]
    assert isinstance(composite, dict)
    composite.update(
        {
            "process_id": "not-an-integer",
            "parent_process_id": {"malformed": True},
            "process_start_time_ns": -42,
            "process_name": "x" * 10_000,
            "bundle_path": "y" * 10_000,
        }
    )

    asset = project_chatgpt_desktop_assets(
        [_node("tenant-1", node_type="endpoint_agent_evidence", payload=observation)],
        now=NOW,
    )["items"][0]

    assert asset["process"]["process_id"] == 0
    assert asset["process"]["parent_process_id"] is None
    assert asset["process"]["process_start_time_ns"] == 0
    assert len(asset["process"]["process_name"]) == 128
    assert len(asset["installation"]["bundle_path"]) == 512


def test_codex_capability_is_unknown_until_codex_mode_or_adapter_evidence_is_observed() -> None:
    nodes = [
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="26.715.31925"),
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_heartbeat",
            payload=_healthy_floor("endpoint-1"),
        ),
    ]

    asset = project_chatgpt_desktop_assets(nodes, now=NOW)["items"][0]
    codex = next(row for row in asset["capabilities"] if row["capability"] == "codex_local")

    assert codex["verification"] == "unknown"


def test_stale_floor_immediately_degrades_capability_status() -> None:
    nodes = [
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="26.715.31925"),
            created_at=NOW - timedelta(minutes=10),
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_heartbeat",
            payload=_healthy_floor("endpoint-1"),
            created_at=NOW - timedelta(minutes=10),
        ),
    ]

    asset = project_chatgpt_desktop_assets(nodes, now=NOW)["items"][0]

    assert asset["endpoint_floor"]["health"] == "stale"
    browser_network = next(
        row for row in asset["capabilities"] if row["capability"] == "built_in_browser_network"
    )
    assert browser_network["verification"] == "unverified"
    assert "endpoint_floor_heartbeat_stale" in asset["endpoint_floor"]["reason_codes"]


def test_self_protection_blind_spots_are_explicit_without_claiming_a_bypass() -> None:
    nodes = [
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="26.700.10000"),
            created_at=NOW - timedelta(minutes=2),
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload=_observation("endpoint-1", version="26.715.31925"),
            created_at=NOW - timedelta(minutes=1),
        ),
        _node(
            "tenant-1",
            node_type="openai_workspace_context",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_account_context",
                "account_context": "personal",
                "account_evidence_source": "openai_admin_api",
                "source_verified": True,
                "evidence_refs": ["openai-admin:personal-context"],
            },
        ),
        _node(
            "tenant-1",
            node_type="endpoint_agent_evidence",
            payload={
                "endpoint_id": "endpoint-1",
                "event_type": "chatgpt_mode_context",
                "mode": "built_in_browser",
                "runtime_location": "local_endpoint",
                "context_evidence_source": "approved_application_context",
            },
        ),
    ]

    asset = project_chatgpt_desktop_assets(nodes, now=NOW)["items"][0]

    assert "chatgpt_binary_version_change_observed_revalidation_required" in asset["blind_spots"]
    assert "personal_workspace_provider_controls_not_proven" in asset["blind_spots"]
    assert "built_in_browser_traffic_attribution_unverified" in asset["blind_spots"]
    assert "local_semantic_proxy_bypass_detection_unverified" in asset["blind_spots"]
    assert "ordinary_transport_and_quic_bypass_acceptance_pending" in asset["blind_spots"]
    assert all("bypass_detected" not in value for value in asset["blind_spots"])


def test_unverified_or_alternate_installation_is_an_explicit_blind_spot() -> None:
    observation = _observation("endpoint-1", version="26.715.31925")
    composite = observation["chatgpt_desktop"]
    assert isinstance(composite, dict)
    composite.update(
        {
            "bundle_id": "com.example.legacy-chatgpt",
            "signature_verified": False,
            "notarization_verified": False,
            "identity_state": "name_only_unverified",
        }
    )

    asset = project_chatgpt_desktop_assets(
        [_node("tenant-1", node_type="endpoint_agent_evidence", payload=observation)],
        now=NOW,
    )["items"][0]

    assert "alternate_or_unverified_chatgpt_installation" in asset["blind_spots"]
    assert "chatgpt_signature_or_notarization_unverified" in asset["blind_spots"]


def test_query_limit_is_explicit_and_bounded() -> None:
    assert CHATGPT_EVIDENCE_QUERY_LIMIT == 500


def test_api_is_tenant_scoped_and_control_plan_uses_server_evidence(composite_api_env) -> None:
    client, session_factory = composite_api_env
    tenant_1, headers_1 = _register(client, "chatgpt-composite-one@example.com")
    tenant_2, headers_2 = _register(client, "chatgpt-composite-two@example.com")
    with session_factory() as db:
        db.add_all(
            [
                _node(
                    tenant_1,
                    node_type="endpoint_agent_evidence",
                    payload=_observation("endpoint-one", version="26.715.31925"),
                ),
                _node(
                    tenant_1,
                    node_type="endpoint_agent_heartbeat",
                    payload=_healthy_floor("endpoint-one"),
                ),
                _node(
                    tenant_2,
                    node_type="endpoint_agent_evidence",
                    payload=_observation("endpoint-two", version="other-tenant-version"),
                ),
            ]
        )
        db.commit()

    first = client.get("/native-controls/chatgpt-desktop/assets", headers=headers_1)
    second = client.get("/native-controls/chatgpt-desktop/assets", headers=headers_2)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert [row["endpoint_id"] for row in first.json()["items"]] == ["endpoint-one"]
    assert [row["endpoint_id"] for row in second.json()["items"]] == ["endpoint-two"]
    assert "other-tenant-version" not in first.text

    plan = client.post(
        "/native-controls/chatgpt-desktop/control-plan",
        headers=headers_1,
        json={"endpoint_id": "endpoint-one", "action": "built_in_browser_upload"},
    )

    assert plan.status_code == 200, plan.text
    body = plan.json()
    assert {row["floor_id"] for row in body["requirements"]["mandatory_enforcement_floors"]} == {
        "endpoint_file_read",
        "endpoint_network",
    }
    assert body["context"]["mode"] == "built_in_browser"
    assert body["context"]["runtime_location"] == "local_endpoint"
    assert body["native_hook_available"] is False
    assert body["source"] == "server_projected_evidence"


def test_control_plan_rejects_unknown_endpoint(composite_api_env) -> None:
    client, _session_factory = composite_api_env
    _tenant_id, headers = _register(client, "chatgpt-composite-missing@example.com")

    response = client.post(
        "/native-controls/chatgpt-desktop/control-plan",
        headers=headers,
        json={"endpoint_id": "not-enrolled", "action": "chat_prompt"},
    )

    assert response.status_code == 404
