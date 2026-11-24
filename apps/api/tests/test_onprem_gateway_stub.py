from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.session import Base, get_db
from app.main import app
from app.onprem_gateway.client import OnPremGatewayClient, OnPremRetryableError
from app.onprem_gateway import main as local_gateway_module
from app.onprem_gateway.main import _gateway_from_env, app as local_gateway_app


PASSWORD = "Password123!"
TEST_SIGNING_SECRET = "test-onprem-signing-secret-32-bytes-minimum"
TEST_LOCAL_AUTH_TOKEN = "test-local-gateway-auth-token-32-bytes"


def test_local_gateway_requires_bearer_auth_for_control_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeGateway:
        @staticmethod
        def load_cached_policy() -> dict[str, str]:
            return {"policy_hash": "cached-policy-hash"}

    monkeypatch.setenv("ONPREM_LOCAL_AUTH_TOKEN", TEST_LOCAL_AUTH_TOKEN)
    monkeypatch.setattr(local_gateway_module, "_gateway_from_env", lambda: FakeGateway())

    with TestClient(local_gateway_app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/policy/cache").status_code == 401
        assert client.get(
            "/policy/cache",
            headers={"Authorization": "Bearer wrong-token"},
        ).status_code == 401

        response = client.get(
            "/policy/cache",
            headers={"Authorization": f"Bearer {TEST_LOCAL_AUTH_TOKEN}"},
        )

    assert response.status_code == 200
    assert response.json()["policy_hash"] == "cached-policy-hash"


@pytest.fixture()
def test_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "onprem_gateway.sqlite3"
    artifacts_dir = tmp_path / "artifacts"
    monkeypatch.setenv("ARTIFACT_DIR", str(artifacts_dir))
    monkeypatch.setattr(settings, "onprem_bundle_signing_secret", TEST_SIGNING_SECRET)

    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "SessionLocal": testing_session_local, "tmp_path": tmp_path}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "OnPrem Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {"access_token": payload["access_token"], "tenant_id": payload["tenants"][0]["id"]}


def _create_active_policy_pack(client: TestClient, *, headers: dict[str, str]) -> str:
    created = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "OnPrem Sync Pack", "description": "onprem", "status": "draft"},
    )
    assert created.status_code == 200, created.text
    pack_id = created.json()["pack"]["id"]
    activated = client.patch(f"/policies/packs/{pack_id}", headers=headers, json={"status": "active"})
    assert activated.status_code == 200, activated.text
    return pack_id


def _create_approved_ai_system(client: TestClient, *, headers: dict[str, str]) -> str:
    created = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "OnPrem Export AI", "description": "", "risk_tier": "HIGH"},
    )
    assert created.status_code == 200, created.text
    ai_system_id = created.json()["id"]
    approved = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "approved"})
    assert approved.status_code == 200, approved.text
    return ai_system_id


def test_onprem_gateway_sync_and_signed_bundle_ingest(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tmp_path: Path = test_env["tmp_path"]
    owner = _register_owner(client, email="onprem-gateway@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_active_policy_pack(client, headers=headers)
    ai_system_id = _create_approved_ai_system(client, headers=headers)

    def _request_fn(method: str, path: str, req_headers: dict[str, str], payload: dict | None) -> dict:
        if method == "GET":
            resp = client.get(path, headers=req_headers)
        else:
            resp = client.post(path, headers=req_headers, json=payload)
        if resp.status_code >= 400:
            raise RuntimeError(f"{method} {path} failed: {resp.status_code} {resp.text}")
        return resp.json()

    gateway = OnPremGatewayClient(
        cloud_base_url="http://cloud-control-plane",
        bearer_token=owner["access_token"],
        tenant_id=owner["tenant_id"],
        gateway_id="site-edge-01",
        signing_secret=TEST_SIGNING_SECRET,
        cache_path=tmp_path / "policy_cache.json",
        request_fn=_request_fn,
    )

    sync_payload = gateway.sync_policy()
    assert sync_payload["tenant_id"] == owner["tenant_id"]
    assert isinstance(sync_payload["active_policy_versions"], list)
    assert sync_payload["policy_hash"]
    assert gateway.load_cached_policy()["policy_hash"] == sync_payload["policy_hash"]

    bundle = gateway.build_evidence_bundle(
        events=[
            {
                "signal_type": "onprem.runtime.telemetry",
                "payload": {"ai_system_id": ai_system_id, "cpu_spike": True, "value": 0.92},
            },
            {
                "signal_type": "onprem.identity.anomaly",
                "payload": {"ai_system_id": ai_system_id, "identity": "svc-bot", "risk": "high"},
            },
        ],
        source_metadata={"site": "dc-1", "cluster": "prod-a", "ai_system_id": ai_system_id},
    )
    assert bundle["signature"]
    assert bundle["root_hash"]
    assert bundle["provenance_role"] == "source_provenance"
    assert bundle["canonical_authority"] is False
    assert len(bundle["entries"]) == 2

    ingest = gateway.upload_evidence_bundle(bundle)
    assert ingest["bundle_id"] == bundle["bundle_id"]
    assert ingest["accepted_entries"] == 2
    assert len(ingest["evidence_node_ids"]) == 3

    with session_local() as db:
        root = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.node_type == "onprem_evidence_bundle",
                EvidenceNode.signal_type == "onprem.bundle.ingested",
            )
        )
        assert root is not None
        assert root.payload["provenance_role"] == "source_provenance"
        assert root.payload["canonical_authority"] is False
        assert root.payload["source_provenance_hash"] == bundle["root_hash"]
        signals = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.node_type == "onprem_signal",
            )
        ).all()
        assert len(signals) == 2
        edges = db.scalars(
            select(EvidenceEdge).where(
                EvidenceEdge.tenant_id == owner["tenant_id"],
                EvidenceEdge.from_node_id == root.id,
                EvidenceEdge.edge_type == "contains",
            )
        ).all()
        assert len(edges) == 2

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    export_payload = exported.json()
    json_artifact_path = Path(export_payload["artifacts"]["json"])
    if not json_artifact_path.is_absolute():
        json_artifact_path = tmp_path / "artifacts" / json_artifact_path
    assert json_artifact_path.exists()

    artifact_json = json.loads(json_artifact_path.read_text(encoding="utf-8"))
    onprem_refs = artifact_json.get("onprem_evidence_references") or []
    assert onprem_refs
    assert any(row.get("node_type") == "onprem_evidence_bundle" for row in onprem_refs)
    assert any(row.get("node_type") == "onprem_signal" for row in onprem_refs)

    snapshot_response = client.post("/auditor/snapshot", headers=headers, json={"ai_system_id": ai_system_id})
    assert snapshot_response.status_code == 200, snapshot_response.text
    snapshot_payload = snapshot_response.json().get("payload") or {}
    snapshot_onprem_refs = snapshot_payload.get("onprem_evidence_references") or []
    assert snapshot_onprem_refs
    assert any(row.get("node_type") == "onprem_evidence_bundle" for row in snapshot_onprem_refs)
    assert any(row.get("node_type") == "onprem_signal" for row in snapshot_onprem_refs)


def test_onprem_bundle_ingest_rejects_invalid_signature(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="onprem-invalid-signature@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_active_policy_pack(client, headers=headers)
    bundle = {
        "bundle_id": f"bundle-{uuid4().hex[:10]}",
        "tenant_id": owner["tenant_id"],
        "gateway_id": "site-edge-invalid",
        "generated_at": "2026-03-09T00:00:00Z",
        "source_metadata": {"site": "dc-2"},
        "entries": [],
        "root_hash": "bad-root",
        "signature_algorithm": "hmac-sha256",
        "signature": "bad-signature",
    }
    response = client.post("/onprem/evidence-bundles/ingest", headers=headers, json=bundle)
    assert response.status_code == 400
    assert "mismatch" in str(response.json()["detail"]).lower()


def test_onprem_gateway_sync_uses_cached_policy_after_retry_exhaustion(tmp_path: Path) -> None:
    cache_path = tmp_path / "policy_cache.json"
    cached_payload = {
        "tenant_id": "tenant-fallback",
        "platform_mode": "enforce",
        "synced_at": "2026-03-22T00:00:00Z",
        "policy_hash": "cached-hash",
        "active_policy_versions": [],
    }
    cache_path.write_text(json.dumps(cached_payload), encoding="utf-8")
    attempts = {"count": 0}

    def _always_down(_method: str, _path: str, _headers: dict[str, str], _payload: dict | None) -> dict:
        attempts["count"] += 1
        raise OnPremRetryableError("cloud unavailable")

    gateway = OnPremGatewayClient(
        cloud_base_url="http://cloud-control-plane",
        bearer_token="token",
        tenant_id="tenant-fallback",
        gateway_id="site-edge-01",
        signing_secret=TEST_SIGNING_SECRET,
        cache_path=cache_path,
        retry_max_attempts=3,
        retry_backoff_seconds=0.0,
        request_fn=_always_down,
    )
    payload = gateway.sync_policy()
    assert attempts["count"] == 3
    assert payload["policy_hash"] == "cached-hash"
    assert payload["cache_fallback"] is True
    assert "sync_error" in payload


def test_onprem_gateway_upload_retries_then_succeeds(tmp_path: Path) -> None:
    attempts = {"count": 0}

    def _flaky_upload(method: str, path: str, _headers: dict[str, str], payload: dict | None) -> dict:
        attempts["count"] += 1
        assert method == "POST"
        assert path == "/onprem/evidence-bundles/ingest"
        if attempts["count"] < 3:
            raise OnPremRetryableError("temporary connectivity issue")
        assert isinstance(payload, dict)
        return {
            "bundle_id": payload.get("bundle_id"),
            "accepted_entries": len(payload.get("entries") or []),
            "root_evidence_node_id": "root-node",
            "evidence_node_ids": ["root-node"],
        }

    gateway = OnPremGatewayClient(
        cloud_base_url="http://cloud-control-plane",
        bearer_token="token",
        tenant_id="tenant-retry",
        gateway_id="site-edge-01",
        signing_secret=TEST_SIGNING_SECRET,
        cache_path=tmp_path / "policy_cache.json",
        retry_max_attempts=4,
        retry_backoff_seconds=0.0,
        request_fn=_flaky_upload,
    )
    bundle = gateway.build_evidence_bundle(
        events=[{"signal_type": "onprem.runtime.telemetry", "payload": {"k": "v"}}],
        source_metadata={"site": "dc-1"},
    )
    result = gateway.upload_evidence_bundle(bundle)
    assert attempts["count"] == 3
    assert result["bundle_id"] == bundle["bundle_id"]
    assert result["accepted_entries"] == 1


def test_onprem_gateway_env_requires_explicit_signing_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONPREM_BEARER_TOKEN", "token")
    monkeypatch.setenv("ONPREM_TENANT_ID", "tenant")
    monkeypatch.setenv("ONPREM_POLICY_CACHE_PATH", str(tmp_path / "policy_cache.json"))
    monkeypatch.delenv("ONPREM_SIGNING_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="ONPREM_SIGNING_SECRET"):
        _gateway_from_env()


def test_onprem_gateway_env_rejects_development_signing_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONPREM_BEARER_TOKEN", "token")
    monkeypatch.setenv("ONPREM_TENANT_ID", "tenant")
    monkeypatch.setenv("ONPREM_POLICY_CACHE_PATH", str(tmp_path / "policy_cache.json"))
    monkeypatch.setenv("ONPREM_SIGNING_SECRET", "dev-onprem-signing-secret")

    with pytest.raises(RuntimeError, match="development default"):
        _gateway_from_env()
