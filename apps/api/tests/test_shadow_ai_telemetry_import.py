import pytest
from sqlalchemy import func, select

from test_shadow_ai_discovery_engine import test_env, _register_owner, _headers
from app.db.models.shadow_ai import ShadowAISignal, ShadowAIUsage


def payload(**changes):
    data = {
        "format": "defender_csv", "source_instance": "customer-defender",
        "window_start": "2026-09-01T00:00:00Z", "window_end": "2026-09-02T00:00:00Z",
        "preview": True,
        "content": "Timestamp,DeviceId,ReportId,RemoteUrl,InitiatingProcessFileName,InitiatingProcessAccountUpn,InitiatingProcessCommandLine\n"
                   "2026-09-01T12:00:00Z,device-1,123,https://user:secret@api.openai.com/v1?key=secret,python.exe,alice@example.com,secret\n",
    }
    return {**data, **changes}


def test_preview_then_repeat_import_is_private_and_idempotent(test_env):
    client = test_env["client"]
    owner = _register_owner(client, email="import-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    preview = client.post("/shadow-ai/telemetry-import", headers=headers, json=payload())
    assert preview.status_code == 200, preview.text
    assert preview.json()["matched"] == 1
    assert "secret" not in preview.text and "alice@example.com" not in preview.text
    with test_env["session_factory"]() as db:
        assert db.scalar(select(func.count()).select_from(ShadowAISignal)) == 0
    first = client.post("/shadow-ai/telemetry-import", headers=headers, json=payload(preview=False))
    assert first.status_code == 200, first.text
    assert first.json()["imported"] == 1
    again = client.post("/shadow-ai/telemetry-import", headers=headers, json=payload(preview=False))
    assert again.status_code == 200, again.text
    assert again.json()["duplicates"] == 1
    assert again.json()["imported"] == 0
    entity_id = first.json()["observations"][0]["entity_id"]
    detail = client.get(f"/shadow-ai/entities/{entity_id}", headers=headers).json()
    assert detail["approved_status"] == "unknown"
    assert detail["usage_count"] == 0
    assert first.json()["observations"][0]["evidence_id"] in detail["evidence_node_ids"]
    assert detail["signals"][0]["raw_fingerprint"]["observation_state"] == "connection_observed"
    assert "secret" not in str(detail) and "alice@example.com" not in str(detail)
    with test_env["session_factory"]() as db:
        assert db.scalar(select(func.count()).select_from(ShadowAISignal)) == 1
        assert db.scalar(select(func.count()).select_from(ShadowAIUsage)) == 0


def test_import_is_tenant_scoped_and_conflicting_event_is_rejected(test_env):
    client = test_env["client"]
    owners = [_register_owner(client, email=f"tenant-import-{i}@example.com") for i in range(2)]
    ids = []
    for owner in owners:
        headers = _headers(owner["access_token"], owner["tenant_id"])
        response = client.post("/shadow-ai/telemetry-import", headers=headers, json=payload(preview=False))
        assert response.status_code == 200, response.text
        ids.append(response.json()["observations"][0]["entity_id"])
    assert ids[0] != ids[1]
    changed = payload(preview=False)
    changed["content"] = changed["content"].replace("python.exe", "node.exe")
    response = client.post("/shadow-ai/telemetry-import", headers=headers, json=changed)
    assert response.status_code == 409
    assert client.get(f"/shadow-ai/entities/{ids[0]}", headers=headers).status_code == 404


@pytest.mark.parametrize("change", [
    {"content": "Timestamp,DeviceId\nnot-a-date,device\n"},
    {"window_end": "2026-08-01T00:00:00Z"},
    {"window_start": "2026-09-01T00:00:00"},
])
def test_invalid_import_fails_without_writes(test_env, change):
    client = test_env["client"]
    owner = _register_owner(client, email="invalid-import@example.com")
    response = client.post("/shadow-ai/telemetry-import", headers=_headers(owner["access_token"], owner["tenant_id"]),
                           json=payload(preview=False, **change))
    assert response.status_code == 422
    with test_env["session_factory"]() as db:
        assert db.scalar(select(func.count()).select_from(ShadowAISignal)) == 0


def test_unmatched_and_out_of_window_rows_are_explicit(test_env):
    client = test_env["client"]
    owner = _register_owner(client, email="unmatched-import@example.com")
    data = payload()
    data["content"] += "2026-09-01T13:00:00Z,device-1,124,example.com,chrome.exe,,\n"
    data["content"] += "2026-08-01T13:00:00Z,device-1,125,api.openai.com,python.exe,,\n"
    response = client.post("/shadow-ai/telemetry-import", headers=_headers(owner["access_token"], owner["tenant_id"]), json=data)
    assert response.status_code == 200, response.text
    assert response.json()["unmatched"] == 1
    assert response.json()["outside_window"] == 1
    assert response.json()["coverage_percent"] is None


def test_swg_import_keeps_device_instances_and_approval_separate(test_env):
    from app.db.models.shadow_ai import ShadowAIEntity
    client = test_env["client"]
    owner = _register_owner(client, email="swg-import@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    data = payload(format="swg_csv", preview=False, content="timestamp,event_id,device_id,destination\n2026-09-01T12:00:00Z,e1,device-1,api.openai.com\n")
    first = client.post("/shadow-ai/telemetry-import", headers=headers, json=data)
    assert first.status_code == 200, first.text
    entity_id = first.json()["observations"][0]["entity_id"]
    with test_env["session_factory"]() as db:
        db.get(ShadowAIEntity, entity_id).approved_status = "approved"
        db.commit()
    data["content"] = data["content"].replace("device-1", "device-2")
    second = client.post("/shadow-ai/telemetry-import", headers=headers, json=data)
    assert second.status_code == 200, second.text
    new_id = second.json()["observations"][0]["entity_id"]
    assert new_id != entity_id
    assert client.get(f"/shadow-ai/entities/{new_id}", headers=headers).json()["approved_status"] == "unknown"


def test_import_rejects_viewer_and_oversized_batch(test_env):
    from app.db.models.user import UserTenantRole
    client = test_env["client"]
    owner = _register_owner(client, email="permissions-import@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    data = payload()
    header, row = data["content"].splitlines()
    data["content"] = header + "\n" + (row + "\n") * 501
    response = client.post("/shadow-ai/telemetry-import", headers=headers, json=data)
    assert response.status_code == 422
    with test_env["session_factory"]() as db:
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == owner["user_id"]))
        membership.role = "viewer"
        db.commit()
    assert client.post("/shadow-ai/telemetry-import", headers=headers, json=payload()).status_code == 403


def test_parser_never_treats_command_arguments_as_a_process_name():
    from datetime import datetime
    from app.services.shadow_ai.telemetry_import import parse_telemetry
    data = payload()
    data["content"] = data["content"].replace("python.exe", "python.exe --token sensitive-value")
    records, _ = parse_telemetry(tenant_id="tenant", **{k: data[k] for k in ("content", "format", "source_instance")},
        window_start=datetime.fromisoformat(data["window_start"]), window_end=datetime.fromisoformat(data["window_end"]))
    assert records[0]["process_name"] == "unknown"
    assert "sensitive-value" not in str(records)
