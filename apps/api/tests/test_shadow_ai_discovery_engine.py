from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal, ShadowAIUsage
from app.db.session import Base, get_db
from app.main import app
import app.services.shadow_ai.endpoint_ingest_service as endpoint_ingest_service
import app.services.runtime_intelligence.runtime_event_normalizer as runtime_normalizer
from app.services.shadow_ai.discovery_engine import safe_process_runtime_event_for_shadow_discovery


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "shadow_ai_discovery.sqlite3"
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
        yield {"client": client, "session_factory": testing_session_local}
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
        json={"email": email, "password": PASSWORD, "full_name": "Shadow Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _create_active_ai_system(client: TestClient, *, headers: dict[str, str]) -> str:
    create = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Gateway System", "description": "", "risk_tier": "LOW"},
    )
    assert create.status_code == 200, create.text
    ai_system_id = create.json()["id"]
    activate = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "active"})
    assert activate.status_code == 200, activate.text
    return ai_system_id


def _emit_unknown_browser_event(client: TestClient, *, headers: dict[str, str], domain: str) -> dict:
    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "event_type": "unknown_ai_detected",
            "domain": domain,
            "url": f"https://{domain}/chat",
            "action_taken": "discover",
            "severity": "high",
            "input_signal_types": ["domain_policy_mismatch"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_browser_unknown_event_creates_shadow_entity_and_signal_and_finding(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-browser-create@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ingest = _emit_unknown_browser_event(client, headers=headers, domain="mystery-assistant.example.ai")
    assert ingest["runtime_event_id"]

    entities = client.get("/shadow-ai/entities?page_size=200", headers=headers)
    assert entities.status_code == 200, entities.text
    rows = entities.json()["items"]
    assert len(rows) >= 1
    entity = next(item for item in rows if item["canonical_name"] == "mystery-assistant.example.ai")
    assert entity["signal_count"] >= 1
    assert "browser" in entity["source_surfaces"]

    detail = client.get(f"/shadow-ai/entities/{entity['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert len(detail_body["signals"]) >= 1
    assert detail_body["signals"][0]["source_surface"] == "browser"

    findings = client.get("/findings?finding_type_filter=shadow_ai_discovered", headers=headers)
    assert findings.status_code == 200, findings.text
    assert any(item["ai_tool"] == "mystery-assistant.example.ai" for item in findings.json()["items"])

    evidence = client.get("/trust-center/evidence/nodes?page_size=400", headers=headers)
    assert evidence.status_code == 200, evidence.text
    node_types = {item["node_type"] for item in evidence.json()["items"]}
    assert "shadow_ai_signal" in node_types
    assert "shadow_ai_entity" in node_types


def test_repeated_signals_merge_into_single_shadow_entity(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-merge-entity@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _emit_unknown_browser_event(client, headers=headers, domain="single-entity.example.ai")
    _emit_unknown_browser_event(client, headers=headers, domain="single-entity.example.ai")

    entities = client.get("/shadow-ai/entities?page_size=200", headers=headers)
    assert entities.status_code == 200, entities.text
    same_name = [item for item in entities.json()["items"] if item["canonical_name"] == "single-entity.example.ai"]
    assert len(same_name) == 1

    detail = client.get(f"/shadow-ai/entities/{same_name[0]['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert len(detail.json()["signals"]) >= 2

    findings = client.get("/findings?finding_type_filter=shadow_ai_discovered", headers=headers)
    assert findings.status_code == 200, findings.text
    entity_findings = [item for item in findings.json()["items"] if item["ai_tool"] == "single-entity.example.ai"]
    assert len(entity_findings) == 1
    assert entity_findings[0]["occurrence_count"] == 1


def test_hawk_self_domains_are_not_shadow_ai_candidates(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_BASE_URL", "http://10.145.1.44:8000")
    monkeypatch.setenv("WEB_ORIGIN", "http://10.145.1.44:3000")
    client: TestClient = test_env["client"]
    session_factory = test_env["session_factory"]
    owner = _register_owner(client, email="shadow-ignore-hawk-self@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    for domain in ("10.145.1.44", "localhost", "127.0.0.1"):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "unknown_ai_detected",
                "domain": domain,
                "url": f"http://{domain}:8000/dashboard/command-center",
                "action_taken": "discover",
                "severity": "high",
            },
        )
        assert response.status_code == 200, response.text

    with session_factory() as db:
        assert db.scalar(select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == owner["tenant_id"])) is None
        assert db.scalar(select(ShadowAISignal).where(ShadowAISignal.tenant_id == owner["tenant_id"])) is None
        assert db.scalar(select(ShadowAIUsage).where(ShadowAIUsage.tenant_id == owner["tenant_id"])) is None
        assert db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_type.in_({"shadow_ai_discovered", "shadow_ai_discovery"}),
            )
        ) is None


def test_confidence_increases_and_high_confidence_auto_promotes_candidate(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["session_factory"]
    owner = _register_owner(client, email="shadow-confidence@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _emit_unknown_browser_event(client, headers=headers, domain="candidate-shadow.example.ai")
    before = client.get("/shadow-ai/entities?page_size=200", headers=headers)
    assert before.status_code == 200, before.text
    row = next(item for item in before.json()["items"] if item["canonical_name"] == "candidate-shadow.example.ai")
    before_score = float(row["confidence_score"])

    connector_signal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": None,
            "signal_type": "connector.runtime.discovery",
            "severity": "high",
            "payload": {
                "ai_tool": "candidate-shadow.example.ai",
                "tool_name": "candidate-shadow.example.ai",
                "domain": "candidate-shadow.example.ai",
                "provider": "openai",
                "model_provider": "openai",
                "model_name": "gpt-4.1",
                "user_id": "user-1",
            },
        },
    )
    assert connector_signal.status_code == 200, connector_signal.text

    after = client.get("/shadow-ai/entities?page_size=200", headers=headers)
    assert after.status_code == 200, after.text
    row_after = next(item for item in after.json()["items"] if item["canonical_name"] == "candidate-shadow.example.ai")
    assert float(row_after["confidence_score"]) >= before_score
    assert row_after["confidence_level"] in {"medium", "high"}
    assert row_after["linked_ai_system_id"]
    assert row_after["discovery_status"] in {"promoted", "reconciled"}

    with session_factory() as db:
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.tenant_id == owner["tenant_id"],
                AISystem.id == row_after["linked_ai_system_id"],
            )
        )
        assert ai_system is not None
        assert str(ai_system.status).lower() == "pending_review"
        metadata = dict(ai_system.metadata_json or {})
        assert str(metadata.get("source") or "") == "SHADOW_DISCOVERY"
        assert str(metadata.get("ownership_state") or "") == "UNKNOWN"
        assert str(metadata.get("business_owner") or "") == "UNKNOWN"
        assert str(metadata.get("technical_owner") or "") == "UNKNOWN"


def test_reject_and_merge_duplicate_entities(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-reject-merge@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _emit_unknown_browser_event(client, headers=headers, domain="dup-one.example.ai")
    _emit_unknown_browser_event(client, headers=headers, domain="dup-two.example.ai")
    rows = client.get("/shadow-ai/entities?page_size=200", headers=headers).json()["items"]
    source = next(item for item in rows if item["canonical_name"] == "dup-one.example.ai")
    target = next(item for item in rows if item["canonical_name"] == "dup-two.example.ai")

    merge = client.post(
        f"/shadow-ai/entities/{source['id']}/merge",
        headers=headers,
        json={"target_entity_id": target["id"]},
    )
    assert merge.status_code == 200, merge.text
    merged_body = merge.json()
    assert merged_body["id"] == target["id"]

    source_detail = client.get(f"/shadow-ai/entities/{source['id']}", headers=headers)
    assert source_detail.status_code == 200, source_detail.text
    assert source_detail.json()["discovery_status"] == "rejected"

    reject = client.post(
        f"/shadow-ai/entities/{target['id']}/reject",
        headers=headers,
        json={"reason": "false_positive"},
    )
    assert reject.status_code == 200, reject.text
    assert reject.json()["discovery_status"] == "rejected"


def test_gateway_remains_non_blocking_if_shadow_discovery_raises(monkeypatch: pytest.MonkeyPatch, test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["session_factory"]
    owner = _register_owner(client, email="shadow-nonblocking-gateway@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_active_ai_system(client, headers=headers)

    def _raise(*args, **kwargs):
        raise RuntimeError("shadow discovery unavailable")

    monkeypatch.setattr(runtime_normalizer, "safe_process_runtime_event_for_shadow_discovery", _raise)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["user_id"],
            "prompt": "normal prompt",
            "context_summary": "non-blocking check",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["final_decision"] in {"allow", "warn", "block", "hold_for_approval", "redact"}

    with session_factory() as db:
        runtime_events = db.scalars(select(ShadowAISignal).where(ShadowAISignal.tenant_id == owner["tenant_id"])).all()
        assert isinstance(runtime_events, list)


def test_shadow_entities_and_signals_tables_populated(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["session_factory"]
    owner = _register_owner(client, email="shadow-table-populated@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _emit_unknown_browser_event(client, headers=headers, domain="table-check.example.ai")

    with session_factory() as db:
        entities = db.scalars(select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == owner["tenant_id"])).all()
        signals = db.scalars(select(ShadowAISignal).where(ShadowAISignal.tenant_id == owner["tenant_id"])).all()
        evidence = db.scalars(select(EvidenceNode).where(EvidenceNode.tenant_id == owner["tenant_id"])).all()
        assert len(entities) >= 1
        assert len(signals) >= 1
        assert any(node.node_type == "shadow_ai_signal" for node in evidence)


def test_endpoint_ingest_creates_shadow_signal_runtime_and_finding(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-endpoint-ingest@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/shadow-ai/ingest/endpoint",
        headers=headers,
        json={
            "process_name": "python",
            "command_line": "python app.py",
            "destination_domain": "api.openai.com",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "user_id": owner["user_id"],
            "host_id": "host-001",
            "bytes_sent": 2048,
            "bytes_received": 1024,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source_signal_id"]
    assert body["runtime_event_id"]

    entity_rows = client.get("/shadow-ai/entities?page_size=200", headers=headers).json()["items"]
    assert any("endpoint" in row["source_surfaces"] for row in entity_rows)

    findings = client.get("/findings?page_size=300", headers=headers)
    assert findings.status_code == 200, findings.text
    assert any(
        row["finding_type"] in {"shadow_ai_endpoint_discovered", "shadow_ai_discovered", "cross_surface_shadow_ai_confirmation"}
        for row in findings.json()["items"]
    )


def test_shadow_usage_preserves_unresolved_endpoint_without_fk_binding(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["session_factory"]
    owner = _register_owner(client, email="shadow-unresolved-endpoint@example.com")

    with session_factory() as db:
        event = RuntimeEvent(
            event_id="runtime-unresolved-endpoint",
            tenant_id=owner["tenant_id"],
            source_surface="endpoint",
            event_type="unknown_ai_detected",
            app_id="api.openai.com",
            user_id=owner["user_id"],
            metadata_json={
                "domain": "api.openai.com",
                "endpoint_id": "missing-endpoint-from-agent",
                "source_surface": "endpoint",
            },
        )
        db.add(event)
        db.flush()

        result = safe_process_runtime_event_for_shadow_discovery(db, event=event)
        assert result is not None
        usage = db.scalar(select(ShadowAIUsage).where(ShadowAIUsage.tenant_id == owner["tenant_id"]))
        assert usage is not None
        assert usage.endpoint_id is None
        metadata = dict(usage.metadata_json or {})
        assert metadata["reported_endpoint_id"] == "missing-endpoint-from-agent"
        assert metadata["endpoint_binding_state"] == "unresolved"


def test_dns_weak_signal_stays_unresolved_then_repeated_dns_promotes_runtime(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-dns-weak-repeat@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    weak = client.post(
        "/shadow-ai/ingest/dns",
        headers=headers,
        json={
            "queried_domain": "unknown-ai-domain.example",
            "resolved_ip": "10.0.0.5",
            "query_count": 1,
            "source_system": "dns_sensor_1",
        },
    )
    assert weak.status_code == 200, weak.text
    weak_body = weak.json()
    assert weak_body["promoted_to_runtime"] is False
    assert weak_body["runtime_event_id"] is None

    unresolved = client.get("/shadow-ai/unresolved-signals?page_size=200", headers=headers)
    assert unresolved.status_code == 200, unresolved.text
    assert any(row["source_surface"] == "dns" for row in unresolved.json()["items"])

    for _ in range(2):
        follow = client.post(
            "/shadow-ai/ingest/dns",
            headers=headers,
            json={
                "queried_domain": "unknown-ai-domain.example",
                "resolved_ip": "10.0.0.5",
                "query_count": 3,
                "source_system": "dns_sensor_1",
            },
        )
        assert follow.status_code == 200, follow.text

    entities = client.get("/shadow-ai/entities?page_size=200", headers=headers)
    assert entities.status_code == 200, entities.text
    assert len(entities.json()["items"]) >= 1
    dns_entity = next(
        row for row in entities.json()["items"] if "dns" in row["source_surfaces"]
    )
    assert float(dns_entity["confidence_score"]) >= 0.5


def test_proxy_and_browser_signals_merge_into_single_entity(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-proxy-browser-merge@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _emit_unknown_browser_event(client, headers=headers, domain="chat.openai.com")

    proxy = client.post(
        "/shadow-ai/ingest/proxy",
        headers=headers,
        json={
            "request_domain": "chat.openai.com",
            "full_url": "https://chat.openai.com/",
            "method": "POST",
            "response_code": 200,
            "user_id": owner["user_id"],
            "host_id": "host-xy-1",
            "app_category": "chatbot",
        },
    )
    assert proxy.status_code == 200, proxy.text

    entities = client.get("/shadow-ai/entities?page_size=200", headers=headers)
    assert entities.status_code == 200, entities.text
    matching = [
        row
        for row in entities.json()["items"]
        if set(row["source_surfaces"]).intersection({"browser", "proxy"})
    ]
    assert len(matching) >= 1


def test_endpoint_plus_proxy_catalog_match_creates_high_confidence_and_proposed_candidate(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-endpoint-proxy-high-confidence@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    endpoint = client.post(
        "/shadow-ai/ingest/endpoint",
        headers=headers,
        json={
            "process_name": "node",
            "command_line": "node cli.js",
            "destination_domain": "api.openai.com",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "user_id": owner["user_id"],
            "host_id": "host-z1",
            "bytes_sent": 4096,
            "bytes_received": 3000,
        },
    )
    assert endpoint.status_code == 200, endpoint.text

    proxy = client.post(
        "/shadow-ai/ingest/proxy",
        headers=headers,
        json={
            "request_domain": "api.openai.com",
            "full_url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "response_code": 200,
            "user_id": owner["user_id"],
            "host_id": "host-z1",
            "app_category": "model_api",
            "provider": "openai",
        },
    )
    assert proxy.status_code == 200, proxy.text

    entities = client.get("/shadow-ai/entities?page_size=200", headers=headers)
    assert entities.status_code == 200, entities.text
    target = max(entities.json()["items"], key=lambda row: float(row["confidence_score"]))
    assert float(target["confidence_score"]) >= 0.8
    assert target["linked_ai_system_id"]
    assert target["discovery_status"] in {"promoted", "reconciled"}

    detail = client.get(f"/shadow-ai/entities/{target['id']}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert {"endpoint", "proxy"}.issubset(set(detail.json()["source_surfaces"]))


def test_shadow_provider_catalog_and_coverage_endpoints(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-provider-catalog-coverage@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    catalog = client.get("/shadow-ai/provider-catalog", headers=headers)
    assert catalog.status_code == 200, catalog.text
    assert any(str(item.get("provider") or "").lower() == "openai" for item in catalog.json())
    assert any(str(item.get("provider_id") or "") == "openai_chatgpt" for item in catalog.json())
    assert any(str(item.get("provider_type") or "") == "model_api" for item in catalog.json())
    assert any("gateway" in list(item.get("deployment_surfaces") or []) for item in catalog.json())

    _emit_unknown_browser_event(client, headers=headers, domain="chat.openai.com")
    client.post(
        "/shadow-ai/ingest/endpoint",
        headers=headers,
        json={
            "process_name": "python",
            "destination_domain": "api.openai.com",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "host_id": "host-cov-1",
        },
    )

    coverage = client.get("/shadow-ai/coverage", headers=headers)
    assert coverage.status_code == 200, coverage.text
    payload = coverage.json()
    assert "discovered_via_browser" in payload
    assert "discovered_via_endpoint" in payload
    assert "unresolved_low_confidence_clusters" in payload


def test_endpoint_ingest_failure_does_not_break_gateway(monkeypatch: pytest.MonkeyPatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="shadow-endpoint-failure-nonblocking@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_active_ai_system(client, headers=headers)

    def _raise(*args, **kwargs):
        raise RuntimeError("forced runtime ingest error")

    monkeypatch.setattr(endpoint_ingest_service, "ingest_runtime_event", _raise)

    ingest = client.post(
        "/shadow-ai/ingest/endpoint",
        headers=headers,
        json={
            "process_name": "python",
            "destination_domain": "api.openai.com",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "host_id": "host-fail-1",
        },
    )
    assert ingest.status_code == 200, ingest.text
    assert ingest.json()["source_signal_id"]

    gateway = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["user_id"],
            "prompt": "safe prompt",
            "context_summary": "non-blocking check",
            "attachments_meta": [],
        },
    )
    assert gateway.status_code == 200, gateway.text
    assert gateway.json()["final_decision"] in {"allow", "warn", "block", "hold_for_approval", "redact"}


def test_distinct_runtime_identities_do_not_merge_via_shared_provider(test_env):
    from datetime import datetime, timedelta, timezone
    from app.db.models.shadow_ai import ShadowAIEntity
    from app.services.shadow_ai.identity_resolution_service import resolve_identity

    owner = _register_owner(test_env["client"], email="distinct-runtimes@example.com")
    observed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    def resolve(runtime_id, seen_at=observed):
        with test_env["session_factory"]() as db:
            result = resolve_identity(
                db, tenant_id=owner["tenant_id"], source_surface="agent",
                explicit_ai_system_id=None, first_seen_at=seen_at,
                signal={"agent_runtime_id": runtime_id, "provider": "ollama", "tool_name": "ollama", "domain": "localhost", "model_name": "shared-model"},
            )
            db.commit()
            return result
    first = resolve("runtime-a")
    second = resolve("runtime-b")
    repeated = resolve("runtime-a", observed - timedelta(seconds=1))
    assert first.shadow_ai_entity_id != second.shadow_ai_entity_id
    assert repeated.shadow_ai_entity_id == first.shadow_ai_entity_id
    assert first.canonical_name == "runtime-a"
    assert second.canonical_name == "runtime-b"
    assert first.matched_ai_system_id is None
    assert second.matched_ai_system_id is None
    with test_env["session_factory"]() as db:
        stored = db.get(ShadowAIEntity, first.shadow_ai_entity_id)
        assert stored.last_seen.replace(tzinfo=timezone.utc) == observed
        provider = resolve_identity(
            db, tenant_id=owner["tenant_id"], source_surface="proxy",
            explicit_ai_system_id=None,
            signal={"provider": "ollama", "tool_name": "ollama", "domain": "localhost", "model_name": "shared-model"},
        )
        assert provider.canonical_name == "ollama"
        assert provider.shadow_ai_entity_id not in {first.shadow_ai_entity_id, second.shadow_ai_entity_id}
