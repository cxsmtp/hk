from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.db.models.runtime_intelligence import RuntimeEvent
from app.main import app
from app.services.endpoint_identity_service import (
    build_auth_statement,
    build_enrollment_statement,
    public_key_thumbprint,
)

PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "endpoint_agent.sqlite3"
    engine = create_engine(f"sqlite+pysqlite:///{db_file}", connect_args={"check_same_thread": False})
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "session_factory": session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _owner(client: TestClient) -> dict[str, str]:
    resp = client.post("/auth/register", json={"email": "ea-owner@example.com", "password": PASSWORD, "full_name": "EA Owner"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return {
        "token": body["access_token"],
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(owner: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {owner['token']}", "X-Tenant-ID": owner["tenant_id"]}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _proof(
    key: ec.EllipticCurvePrivateKey,
    *,
    token: str,
    method: str,
    path: str,
    jti: str,
) -> str:
    numbers = key.public_key().public_numbers()
    header = {
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        },
    }
    claims = {
        "htm": method.upper(),
        "htu": f"http://testserver{path}",
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": jti,
        "ath": _b64url(hashlib.sha256(token.encode("ascii")).digest()),
    }
    signing_input = (
        f"{_b64url(json.dumps(header, sort_keys=True, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(claims, sort_keys=True, separators=(',', ':')).encode())}"
    )
    der = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{signing_input}.{_b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _enroll_endpoint(
    client: TestClient, owner: dict[str, str]
) -> tuple[ec.EllipticCurvePrivateKey, str]:
    endpoint_id = "endpoint-notetaker-test"
    issued_response = client.post(
        "/endpoint-agent/enrollment-authorizations",
        headers=_headers(owner),
        json={"endpoint_id": endpoint_id, "assigned_user_id": owner["user_id"]},
    )
    assert issued_response.status_code == 200, issued_response.text
    issued = issued_response.json()
    key = ec.generate_private_key(ec.SECP256R1())
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    timestamp = int(datetime.now(timezone.utc).timestamp())
    statement = build_enrollment_statement(
        authorization_id=issued["authorization_id"],
        tenant_id=owner["tenant_id"],
        endpoint_id=endpoint_id,
        key_provider="macos_secure_enclave",
        public_key_thumbprint=public_key_thumbprint(public_pem),
        nonce=issued["enrollment_nonce"],
        timestamp=timestamp,
    )
    enrolled = client.post(
        "/endpoint-agent/enroll",
        json={
            "authorization_id": issued["authorization_id"],
            "enrollment_code": issued["enrollment_code"],
            "enrollment_nonce": issued["enrollment_nonce"],
            "tenant_id": owner["tenant_id"],
            "endpoint_id": endpoint_id,
            "key_provider": "macos_secure_enclave",
            "public_key_pem": public_pem,
            "timestamp": timestamp,
            "signature": _b64url(key.sign(statement, ec.ECDSA(hashes.SHA256()))),
        },
    )
    assert enrolled.status_code == 200, enrolled.text
    challenge_response = client.post(
        "/endpoint-agent/auth/challenge",
        json={"tenant_id": owner["tenant_id"], "endpoint_id": endpoint_id},
    )
    assert challenge_response.status_code == 200, challenge_response.text
    challenge = challenge_response.json()
    auth_statement = build_auth_statement(
        challenge_id=challenge["challenge_id"],
        tenant_id=owner["tenant_id"],
        endpoint_id=endpoint_id,
        nonce=challenge["nonce"],
    )
    token_response = client.post(
        "/endpoint-agent/auth/token",
        json={
            "challenge_id": challenge["challenge_id"],
            "tenant_id": owner["tenant_id"],
            "endpoint_id": endpoint_id,
            "nonce": challenge["nonce"],
            "signature": _b64url(key.sign(auth_statement, ec.ECDSA(hashes.SHA256()))),
        },
    )
    assert token_response.status_code == 200, token_response.text
    return key, token_response.json()["access_token"]


def _endpoint_headers(
    key: ec.EllipticCurvePrivateKey,
    token: str,
    owner: dict[str, str],
    *,
    method: str,
    path: str,
    jti: str,
) -> dict[str, str]:
    return {
        "Authorization": f"DPoP {token}",
        "DPoP": _proof(key, token=token, method=method, path=path, jti=jti),
        "X-Tenant-ID": owner["tenant_id"],
    }


def test_endpoint_policy_includes_notetaker_and_modules(test_env):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key, token, owner, method="GET", path="/endpoint-agent/policy", jti="policy-1"
    )
    resp = client.get("/endpoint-agent/policy", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "notetaker_policy" in body
    assert body["notetaker_policy"]["banner"] is True
    assert body["modules"]["notetaker"] is True


def test_endpoint_agent_runtime_registration_preserves_transport_evidence(test_env):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    path = "/endpoint-agent/telemetry"
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path=path,
        jti="agent-os-registration-1",
    )
    runtime_profile = {
        "schema_version": "1.0",
        "agent_id": "agent-os-local",
        "agent_name": "Agent OS",
        "agent_version": "1.0.0",
        "runtime_provider": "node",
        "model_provider": "ollama",
        "model_name": "qwen3.5:9b",
        "models": ["qwen3.5:9b", "qwen2.5:14b"],
        "tools": ["web_search", "GMAIL_FETCH_EMAILS", "GMAIL_CREATE_DRAFT", "GMAIL_SEND_EMAIL"],
        "actions": ["web.read", "email.read", "email.draft.create", "email.send"],
        "privileges": ["internet", "mailbox.read", "mailbox.write"],
        "listening_ports": [4000, 5174],
        "integration_transports": [
            {
                "capability": "gmail",
                "transport": "composio",
                "destination_domain": "backend.composio.dev",
                "active": True,
                "evidence_basis": "runtime_configuration",
            },
            {
                "capability": "gmail",
                "transport": "google_direct",
                "destination_domain": "gmail.googleapis.com",
                "active": False,
                "evidence_basis": "supported_binding",
            },
        ],
        "active_integration_transport": "composio",
        "control_binding": {
            "mode": "enforce",
            "pre_action_surfaces": ["llm", "developer_agent"],
        },
        "evidence_basis": "sdk_self_registration",
        "process": {"pid": 21019, "platform": "darwin", "architecture": "arm64"},
        "client": {"name": "agent-os", "version": "1.0.0", "runtime": "node"},
    }
    response = client.post(
        path,
        headers=headers,
        json={
            "event_type": "agent_runtime_discovered",
            "domain": "agent-os.local",
            "application": "Agent OS",
            "source_surface": "endpoint-agent",
            "browser": "endpoint-agent",
            "extension_version": "1.0.0",
            "agent_id": "agent-os-local",
            "agent_name": "Agent OS",
            "runtime_provider": "node",
            "model_provider": "ollama",
            "model_name": "qwen3.5:9b",
            "detected_tools": runtime_profile["tools"],
            "detected_actions": runtime_profile["actions"],
            "detected_privileges": runtime_profile["privileges"],
            "active_integration_transport": "composio",
            "integration_transports": runtime_profile["integration_transports"],
            "control_binding": runtime_profile["control_binding"],
            "evidence_basis": "sdk_self_registration",
            "agent_runtime_profile": runtime_profile,
            "control_mode": "telemetry_only",
            "action_taken": "allow:discovery_observation",
            "reason": "endpoint_bound_agent_self_registration",
            "correlation_id": "agent-os-registration-1",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["runtime_event_id"]

    entities = client.get("/shadow-ai/entities?page_size=200", headers=_headers(owner))
    assert entities.status_code == 200, entities.text
    with test_env["session_factory"]() as db:
        runtime_rows = db.scalars(select(RuntimeEvent)).all()
        debug_runtime = [
            {
                "event_type": row.event_type,
                "source_surface": row.source_surface,
                "app_id": row.app_id,
                "metadata": dict(row.metadata_json or {}),
            }
            for row in runtime_rows
        ]
    assert entities.json()["items"], debug_runtime
    matches = [item for item in entities.json()["items"] if item["canonical_name"] == "agent-os-local"]
    assert matches, {"canonical_names": [item["canonical_name"] for item in entities.json()["items"]]}
    entity = matches[0]
    assert "endpoint" in entity["source_surfaces"]
    assert entity["metadata_json"]["agent_runtime_profile"] == runtime_profile
    assert entity["metadata_json"]["active_integration_transport"] == "composio"
    assert entity["metadata_json"]["control_binding_state"] == "monitor_only"


def test_notetaker_evaluate_warns_with_banner_and_eviction(test_env):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/notetaker/evaluate",
        jti="notetaker-evaluate-1",
    )
    payload = {
        "endpoint_id": "endpoint-1",
        "hostname": "laptop-1",
        "notetaker": "otter",
        "signal": {
            "kind": "notetaker",
            "subject": "otter",
            "attributes": {"name": "Otter.ai", "category": "local_recorder", "local_audio_capture": True, "in_meeting": False},
        },
    }
    resp = client.post("/endpoint-agent/notetaker/evaluate", headers=headers, json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Any notetaker -> banner + eviction option, per requirement.
    assert body["decision"] in {"warn", "block"}
    assert body["banner"] is True
    assert body["eviction_allowed"] is True
    assert body["evidence_node_id"]  # decision was recorded as evidence


def test_teams_notetaker_platform_action_without_graph_config_is_external_required(test_env, monkeypatch):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/notetaker/platform-action",
        jti="teams-action-unconfigured-1",
    )
    monkeypatch.delenv("HAWK_TEAMS_GRAPH_EXECUTION_ENABLED", raising=False)
    monkeypatch.delenv("HAWK_TEAMS_GRAPH_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("MICROSOFT_GRAPH_ACCESS_TOKEN", raising=False)

    resp = client.post(
        "/endpoint-agent/notetaker/platform-action",
        headers=headers,
        json={
            "endpoint_id": "endpoint-1",
            "hostname": "laptop-1",
            "platform": "teams",
            "action": "remove_meeting_participant",
            "meeting_id": "meeting-123",
            "participant_id": "participant-456",
            "notetaker_label": "Fireflies.ai",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["provider_control_path"] == "microsoft_graph"
    assert body["control_mode"] == "external_required"
    assert body["performed"] is False
    assert body["reason"] == "correlated_notetaker_detection_required"
    assert body["evidence_node_id"]
    assert body["audit_log_id"]


def test_teams_notetaker_platform_action_triggers_when_graph_adapter_succeeds(test_env, monkeypatch):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/notetaker/platform-action",
        jti="teams-action-success-1",
    )

    def fake_execute(*, action, payload, access_token=None, http_client=None):
        return {
            "provider_control_path": "microsoft_graph",
            "action": action,
            "control_mode": "external_action_triggered",
            "performed": True,
            "reason": "microsoft_graph_action_succeeded",
            "graph_operation": {
                "method": "POST",
                "path": "/teams/meeting-123/participants/participant-456/remove",
            },
            "status_code": 204,
        }

    monkeypatch.setattr(
        "app.services.endpoint_agent_service.execute_microsoft_teams_notetaker_graph_action",
        fake_execute,
    )
    detection = client.post(
        "/endpoint-agent/notetaker/calendar-signal",
        headers=_headers(owner),
        json={
            "source": "microsoft_graph_calendar",
            "platform": "teams",
            "meeting_id": "meeting-123",
            "attendees": [
                {
                    "participant_id": "participant-456",
                    "email": "bot@fireflies.ai",
                    "display_name": "Fireflies.ai",
                }
            ],
        },
    )
    assert detection.status_code == 200, detection.text
    resp = client.post(
        "/endpoint-agent/notetaker/platform-action",
        headers=headers,
        json={
            "endpoint_id": "endpoint-1",
            "hostname": "laptop-1",
            "platform": "teams",
            "action": "remove_meeting_participant",
            "meeting_id": "meeting-123",
            "participant_id": "participant-456",
            "notetaker_label": "Fireflies.ai",
            "source_detection_evidence_id": detection.json()["evidence_node_id"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reason"] != "correlated_notetaker_detection_required", body
    assert body["control_mode"] == "external_action_triggered", body
    assert body["performed"] is True
    assert body["graph_operation"]["method"] == "POST"
    assert body["evidence_node_id"]
    assert body["audit_log_id"]


def test_google_meet_notetaker_platform_action_without_google_config_is_external_required(test_env, monkeypatch):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/notetaker/platform-action",
        jti="google-action-unconfigured-1",
    )
    monkeypatch.delenv("HAWK_GOOGLE_MEET_EXECUTION_ENABLED", raising=False)
    monkeypatch.delenv("HAWK_GOOGLE_MEET_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_WORKSPACE_ACCESS_TOKEN", raising=False)

    resp = client.post(
        "/endpoint-agent/notetaker/platform-action",
        headers=headers,
        json={
            "endpoint_id": "endpoint-1",
            "hostname": "laptop-1",
            "platform": "google_meet",
            "action": "remove_calendar_notetaker_invitee",
            "meeting_id": "calendar-event-123",
            "notetaker_email": "bot@fireflies.ai",
            "notetaker_label": "Fireflies.ai",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["provider_control_path"] == "google_workspace"
    assert body["control_mode"] == "external_required"
    assert body["performed"] is False
    assert body["reason"] == "correlated_notetaker_detection_required"
    assert body["evidence_node_id"]
    assert body["audit_log_id"]


def test_google_meet_notetaker_platform_action_triggers_when_google_adapter_succeeds(test_env, monkeypatch):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/notetaker/platform-action",
        jti="google-action-success-1",
    )

    def fake_execute(*, action, payload, access_token=None, http_client=None):
        return {
            "provider_control_path": "google_workspace",
            "action": action,
            "control_mode": "external_action_triggered",
            "performed": True,
            "reason": "google_workspace_action_succeeded",
            "google_operation": {
                "method": "PATCH",
                "path": "/calendar/v3/calendars/primary/events/calendar-event-123",
            },
            "status_code": 200,
        }

    monkeypatch.setattr(
        "app.services.endpoint_agent_service.execute_google_meet_notetaker_action",
        fake_execute,
    )
    detection = client.post(
        "/endpoint-agent/notetaker/calendar-signal",
        headers=_headers(owner),
        json={
            "source": "google_calendar",
            "platform": "google_meet",
            "meeting_id": "calendar-event-123",
            "attendees": [
                {"email": "bot@fireflies.ai", "display_name": "Fireflies.ai"}
            ],
        },
    )
    assert detection.status_code == 200, detection.text
    with test_env["session_factory"]() as db:
        from app.db.models.evidence import EvidenceNode

        source = db.get(EvidenceNode, detection.json()["evidence_node_id"])
        assert source is not None
        assert source.signal_type == "endpoint.notetaker.calendar_signal"
        assert source.payload["platform"] == "google_meet"
        assert source.payload["meeting_id"] == "calendar-event-123"
        assert source.payload["detections"][0]["email"] == "[email]"
        assert len(source.payload["detections"][0]["participant_identity_hash"]) == 64

    resp = client.post(
        "/endpoint-agent/notetaker/platform-action",
        headers=headers,
        json={
            "endpoint_id": "endpoint-1",
            "hostname": "laptop-1",
            "platform": "google_meet",
            "action": "remove_calendar_notetaker_invitee",
            "meeting_id": "calendar-event-123",
            "notetaker_email": "bot@fireflies.ai",
            "notetaker_label": "Fireflies.ai",
            "source_detection_evidence_id": detection.json()["evidence_node_id"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reason"] != "correlated_notetaker_detection_required", body
    assert body["control_mode"] == "external_action_triggered", body
    assert body["performed"] is True
    assert body["graph_operation"]["method"] == "PATCH"
    assert body["provider_control_path"] == "google_workspace"
    assert body["evidence_node_id"]
    assert body["audit_log_id"]


def test_zoom_notetaker_platform_action_without_zoom_config_is_external_required(test_env, monkeypatch):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/notetaker/platform-action",
        jti="zoom-action-unconfigured-1",
    )
    monkeypatch.delenv("HAWK_ZOOM_EXECUTION_ENABLED", raising=False)
    monkeypatch.delenv("HAWK_ZOOM_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("ZOOM_ACCESS_TOKEN", raising=False)

    resp = client.post(
        "/endpoint-agent/notetaker/platform-action",
        headers=headers,
        json={
            "endpoint_id": "endpoint-1",
            "hostname": "laptop-1",
            "platform": "zoom",
            "action": "remove_meeting_participant",
            "meeting_id": "zoom-meeting-123",
            "participant_id": "participant-456",
            "notetaker_label": "Fathom",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["provider_control_path"] == "zoom"
    assert body["control_mode"] == "external_required"
    assert body["performed"] is False
    assert body["reason"] == "correlated_notetaker_detection_required"
    assert body["evidence_node_id"]
    assert body["audit_log_id"]


def test_zoom_notetaker_platform_action_triggers_when_zoom_adapter_succeeds(test_env, monkeypatch):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/notetaker/platform-action",
        jti="zoom-action-success-1",
    )

    def fake_execute(*, action, payload, access_token=None, http_client=None):
        return {
            "provider_control_path": "zoom",
            "action": action,
            "control_mode": "external_action_triggered",
            "performed": True,
            "reason": "zoom_action_succeeded",
            "zoom_operation": {
                "method": "DELETE",
                "path": "/v2/meetings/zoom-meeting-123/participants/participant-456",
            },
            "status_code": 204,
        }

    monkeypatch.setattr(
        "app.services.endpoint_agent_service.execute_zoom_notetaker_action",
        fake_execute,
    )
    detection = client.post(
        "/endpoint-agent/notetaker/calendar-signal",
        headers=_headers(owner),
        json={
            "source": "zoom_roster",
            "platform": "zoom",
            "meeting_id": "zoom-meeting-123",
            "attendees": [
                {
                    "participant_id": "participant-456",
                    "email": "bot@fathom.video",
                    "display_name": "Fathom",
                }
            ],
        },
    )
    assert detection.status_code == 200, detection.text

    resp = client.post(
        "/endpoint-agent/notetaker/platform-action",
        headers=headers,
        json={
            "endpoint_id": "endpoint-1",
            "hostname": "laptop-1",
            "platform": "zoom",
            "action": "remove_meeting_participant",
            "meeting_id": "zoom-meeting-123",
            "participant_id": "participant-456",
            "notetaker_label": "Fathom",
            "source_detection_evidence_id": detection.json()["evidence_node_id"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["control_mode"] == "external_action_triggered", body
    assert body["performed"] is True
    assert body["provider_control_path"] == "zoom"
    assert body["graph_operation"]["method"] == "DELETE"
    assert body["evidence_node_id"]
    assert body["audit_log_id"]


def test_calendar_invite_notetaker_detection_creates_external_required_finding(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/calendar-signal",
        headers=headers,
        json={
            "source": "microsoft_graph_calendar",
            "platform": "teams",
            "meeting_id": "calendar-meeting-123",
            "title": "Quarterly revenue review",
            "organizer_email": "finance.lead@example.com",
            "sensitivity_label": "confidential",
            "attendees": [
                {"email": "finance.lead@example.com", "display_name": "Finance Lead"},
                {"email": "bot@fireflies.ai", "display_name": "Fireflies.ai Notetaker"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is True
    assert body["control_mode"] == "external_required"
    assert body["detections"][0]["provider"] == "fireflies"
    assert body["detections"][0]["email"] == "bot@fireflies.ai"
    assert "AI_NOTETAKER_DETECTED" in body["finding_types"]
    assert "SENSITIVE_MEETING_WITH_AI_ENABLED" in body["finding_types"]
    assert body["evidence_node_id"]
    assert len(body["finding_ids"]) == 2


def test_calendar_invite_without_notetaker_does_not_create_finding(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/calendar-signal",
        headers=headers,
        json={
            "source": "google_calendar",
            "platform": "google_meet",
            "meeting_id": "calendar-meeting-456",
            "title": "Engineering standup",
            "organizer_email": "eng.lead@example.com",
            "attendees": [
                {"email": "eng.lead@example.com", "display_name": "Engineering Lead"},
                {"email": "developer@example.com", "display_name": "Developer"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is False
    assert body["control_mode"] == "detected_only"
    assert body["detections"] == []
    assert body["finding_ids"] == []


def test_oauth_notetaker_app_with_high_risk_scopes_creates_external_required_findings(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/oauth-signal",
        headers=headers,
        json={
            "source": "microsoft_graph_oauth",
            "provider": "microsoft",
            "app_id": "app-fireflies-123",
            "client_id": "client-fireflies-123",
            "name": "Fireflies.ai Notetaker",
            "publisher": "Fireflies.ai",
            "homepage_url": "https://fireflies.ai",
            "scopes": [
                "Calendars.ReadWrite",
                "OnlineMeetings.ReadWrite",
                "offline_access",
                "User.Read.All",
            ],
            "users": ["finance.lead@example.com", "risk.analyst@example.com"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is True
    assert body["control_mode"] == "external_required"
    assert body["notetaker_provider"] == "fireflies"
    assert "Calendars.ReadWrite" in body["high_risk_scopes"]
    assert "OnlineMeetings.ReadWrite" in body["high_risk_scopes"]
    assert "UNAPPROVED_AI_NOTETAKER" in body["finding_types"]
    assert "OAUTH_NOTETAKER_APP_OVER_SCOPED" in body["finding_types"]
    assert body["evidence_node_id"]
    assert len(body["finding_ids"]) == 2


def test_oauth_app_without_notetaker_signature_does_not_create_finding(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/oauth-signal",
        headers=headers,
        json={
            "source": "google_workspace_oauth",
            "provider": "google",
            "app_id": "internal-calendar-helper",
            "name": "Internal Calendar Helper",
            "publisher": "Example IT",
            "scopes": ["openid", "profile"],
            "users": ["eng@example.com"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is False
    assert body["control_mode"] == "detected_only"
    assert body["notetaker_provider"] is None
    assert body["high_risk_scopes"] == []
    assert body["finding_types"] == []
    assert body["finding_ids"] == []


def test_hidden_notetaker_secondary_evidence_creates_incomplete_finding(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/hidden-signal",
        headers=headers,
        json={
            "source": "local_agent",
            "endpoint_id": "ep-hidden-1",
            "hostname": "finance-macbook",
            "meeting_platform": "teams",
            "meeting_id": "teams-meeting-hidden-1",
            "active_meeting": True,
            "visible_in_roster": False,
            "local_audio_capture": True,
            "microphone_active": True,
            "processes": [
                {"name": "Fireflies Desktop Helper", "bundle_id": "ai.fireflies.helper"},
            ],
            "domains": ["fireflies.ai"],
            "audio_devices": ["Fireflies Recorder"],
            "transcription_artifact_count": 1,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is True
    assert body["hidden_suspected"] is True
    assert body["control_mode"] == "incomplete"
    assert body["notetaker_provider"] == "fireflies"
    assert "known_notetaker_process" in body["evidence_signals"]
    assert "local_audio_capture" in body["evidence_signals"]
    assert "not_visible_in_roster" in body["evidence_signals"]
    assert "HIDDEN_NOTETAKER_SUSPECTED" in body["finding_types"]
    assert "AI_NOTETAKER_DETECTED" in body["finding_types"]
    assert body["evidence_node_id"]
    assert len(body["finding_ids"]) == 2


def test_hidden_notetaker_signal_without_provider_signature_does_not_create_finding(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/hidden-signal",
        headers=headers,
        json={
            "source": "local_agent",
            "endpoint_id": "ep-hidden-2",
            "hostname": "sales-macbook",
            "meeting_platform": "google_meet",
            "meeting_id": "meet-normal-audio-1",
            "active_meeting": True,
            "visible_in_roster": True,
            "local_audio_capture": False,
            "microphone_active": True,
            "processes": [{"name": "Google Chrome"}],
            "domains": ["meet.google.com"],
            "audio_devices": ["MacBook Microphone"],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is False
    assert body["hidden_suspected"] is False
    assert body["control_mode"] == "detected_only"
    assert body["notetaker_provider"] is None
    assert body["finding_types"] == []
    assert body["finding_ids"] == []
    assert body["evidence_node_id"] is None


def test_meeting_artifact_transcription_for_sensitive_meeting_creates_external_required_findings(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/artifact-signal",
        headers=headers,
        json={
            "source": "microsoft_graph_call_records",
            "platform": "teams",
            "meeting_id": "artifact-meeting-1",
            "title": "Confidential board risk review",
            "organizer_email": "risk.lead@example.com",
            "sensitivity_label": "confidential",
            "attendance_report_present": True,
            "transcription_enabled": True,
            "recording_enabled": False,
            "transcript_artifact_count": 1,
            "external_participant_count": 2,
            "attendance_participants": [
                {"email": "risk.lead@example.com", "display_name": "Risk Lead"},
                {"email": "bot@read.ai", "display_name": "Read.ai Notes"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is True
    assert body["policy_triggered"] is True
    assert body["control_mode"] == "external_required"
    assert body["detections"][0]["provider"] == "read_ai"
    assert "transcript" in body["artifact_types"]
    assert "AI_NOTETAKER_DETECTED" in body["finding_types"]
    assert "MEETING_TRANSCRIPTION_POLICY_VIOLATION" in body["finding_types"]
    assert "SENSITIVE_MEETING_WITH_AI_ENABLED" in body["finding_types"]
    assert body["evidence_node_id"]
    assert len(body["finding_ids"]) == 3


def test_meeting_artifact_attendance_only_without_risk_stays_detected_only(test_env):
    client = test_env["client"]
    headers = _headers(_owner(client))

    resp = client.post(
        "/endpoint-agent/notetaker/artifact-signal",
        headers=headers,
        json={
            "source": "google_meet_attendance",
            "platform": "google_meet",
            "meeting_id": "artifact-meeting-2",
            "attendance_report_present": True,
            "attendance_participants": [
                {"email": "eng@example.com", "display_name": "Engineer"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["detected"] is True
    assert body["policy_triggered"] is False
    assert body["control_mode"] == "detected_only"
    assert body["detections"] == []
    assert body["finding_ids"] == []
    assert body["evidence_node_id"] is None


def test_heartbeat_and_evidence_ok(test_env):
    client = test_env["client"]
    owner = _owner(client)
    key, token = _enroll_endpoint(client, owner)
    hb_headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/heartbeat",
        jti="heartbeat-1",
    )
    hb = client.post("/endpoint-agent/heartbeat", headers=hb_headers, json={"endpoint_id": "e1", "hostname": "h1"})
    assert hb.status_code == 200, hb.text
    assert hb.json()["status"] == "ok"
    evidence_headers = _endpoint_headers(
        key,
        token,
        owner,
        method="POST",
        path="/endpoint-agent/evidence",
        jti="evidence-1",
    )
    ev = client.post("/endpoint-agent/evidence", headers=evidence_headers, json={"endpoint_id": "e1", "event_type": "notetaker_control_applied"})
    assert ev.status_code == 200, ev.text
    assert ev.json()["status"] == "ok"
