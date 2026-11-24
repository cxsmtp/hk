from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.external_risk import (
    ExternalRiskAssetMapping,
    ExternalRiskImpact,
    ExternalRiskRecord,
    ExternalRiskSyncRun,
    RiskTriggeredSimulationRecommendation,
)
from app.db.models.monitoring import Connector, MonitoringSignal
from app.db.session import Base, get_db
from app.main import app
from app.services.external_risk_intel.source_connector import ExternalFeedResult


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "external_risk_intel.sqlite3"
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
        yield {"client": client, "sessionmaker": testing_session_local}
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
        json={"email": email, "password": PASSWORD, "full_name": "External Risk Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _mock_feed_for_source(source_name: str) -> dict[str, Any]:
    if source_name == "nvd":
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-1001",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "OpenAI model endpoint authentication bypass affecting gateway integrations.",
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                    }
                                }
                            ]
                        },
                        "references": [{"url": "https://example.test/nvd/CVE-2099-1001"}],
                        "published": "2026-04-01T00:00:00Z",
                        "lastModified": "2026-04-02T00:00:00Z",
                    }
                }
            ]
        }
    if source_name == "mitre":
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-1002",
                        "containers": {
                            "cna": {
                                "descriptions": [
                                    {
                                        "lang": "en",
                                        "value": "Token scope bypass may impact model gateway provider authentication.",
                                    }
                                ],
                                "references": [{"url": "https://example.test/mitre/CVE-2099-1002"}],
                            }
                        },
                        "datePublished": "2026-04-01T00:00:00Z",
                        "dateUpdated": "2026-04-02T00:00:00Z",
                    }
                }
            ]
        }
    if source_name == "cisa_kev":
        return {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2099-1003",
                    "vendorProject": "OpenAI",
                    "product": "Gateway Connector",
                    "vulnerabilityName": "Known exploited gateway auth bypass",
                    "shortDescription": "Known exploited vulnerability with active abuse in the wild.",
                    "dateAdded": "2026-04-01",
                    "dueDate": "2026-04-10",
                }
            ]
        }
    if source_name == "github":
        return {
            "advisories": [
                {
                    "ghsa_id": "GHSA-9999-aaaa-bbbb",
                    "cve_id": "CVE-2099-1004",
                    "summary": "Connector library vulnerable to credential exfiltration.",
                    "description": "Public exploit available against vulnerable connector package.",
                    "severity": "high",
                    "cvss": {"score": 8.1},
                    "published_at": "2026-04-01T00:00:00Z",
                    "updated_at": "2026-04-02T00:00:00Z",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "pip", "name": "openai-connector-lib"},
                        }
                    ],
                    "html_url": "https://example.test/ghsa/GHSA-9999-aaaa-bbbb",
                }
            ]
        }
    if source_name == "osv":
        return {
            "vulns": [
                {
                    "id": "OSV-2099-1005",
                    "aliases": ["CVE-2099-1005"],
                    "summary": "Tool call guard dependency vulnerable.",
                    "details": "Proof-of-concept exploit enables tool abuse.",
                    "severity": [{"score": "CVSS:3.1/8.2"}],
                    "published": "2026-04-01T00:00:00Z",
                    "modified": "2026-04-02T00:00:00Z",
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "tool-guard-runtime"},
                            "ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}],
                        }
                    ],
                    "references": [{"url": "https://example.test/osv/OSV-2099-1005"}],
                }
            ]
        }
    return {"records": []}


def test_external_risk_sources_secure_config_enforced(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="external-risk-source-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    default_sources = client.get("/external-risk/sources", headers=headers)
    assert default_sources.status_code == 200, default_sources.text
    payload = default_sources.json()
    assert payload["total"] >= 5
    assert {"nvd", "mitre", "cisa_kev", "github", "osv"}.issubset({item["source"] for item in payload["items"]})

    insecure_scheme = client.post(
        "/external-risk/sources",
        headers=headers,
        json={
            "source": "nvd",
            "endpoint_url": "http://insecure.example.test/feed",
            "enabled": True,
        },
    )
    assert insecure_scheme.status_code == 422
    assert "https_required" in insecure_scheme.json()["detail"]

    sensitive_query = client.post(
        "/external-risk/sources",
        headers=headers,
        json={
            "source": "nvd",
            "endpoint_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?token=secret-value",
            "enabled": True,
        },
    )
    assert sensitive_query.status_code == 422
    assert "query_contains_sensitive_key" in sensitive_query.json()["detail"]


def test_external_risk_sync_correlates_controls_updates_crq_and_surfaces_on_dashboard(
    test_env,
    monkeypatch,
) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="external-risk-sync-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_factory() as db:
        db.add(
            AISystem(
                tenant_id=owner["tenant_id"],
                name="OpenAI Production Gateway",
                description="Primary provider route",
                risk_tier="high",
                status="active",
                metadata_json={"provider": "openai", "model": "gpt-5.4", "endpoint": "gateway.openai.example"},
            )
        )
        db.add(
            Connector(
                tenant_id=owner["tenant_id"],
                name="OpenAI Connector",
                connector_type="llm_gateway",
                provider_key="openai",
                auth_type="bearer",
                enabled=True,
                status="active",
                config={},
                metadata_json={"environment": "prod"},
            )
        )
        db.commit()

    def _mock_fetch_source_records(source, timeout_seconds: float = 20.0, fetcher=None):  # noqa: ANN001,ARG001
        payload = _mock_feed_for_source(str(source.source))
        records = []
        source_name = str(source.source)
        if source_name == "nvd":
            records = payload.get("vulnerabilities", [])
        elif source_name in {"mitre", "cisa_kev"}:
            records = payload.get("vulnerabilities", [])
        elif source_name == "github":
            records = payload.get("advisories", [])
        elif source_name == "osv":
            records = payload.get("vulns", [])
        return ExternalFeedResult(
            source=source_name,
            endpoint_url=str(source.endpoint_url),
            records=[row for row in records if isinstance(row, dict)],
            metadata={"transport": "mocked_test_feed"},
        )

    monkeypatch.setattr(
        "app.services.external_risk_intel.service.fetch_source_records",
        _mock_fetch_source_records,
    )

    sync_response = client.post("/external-risk/sync", headers=headers)
    assert sync_response.status_code == 200, sync_response.text
    sync_payload = sync_response.json()
    assert sync_payload["status"] == "completed"
    assert sync_payload["records_ingested"] >= 5
    assert sync_payload["mappings_created"] >= 1
    assert sync_payload["simulation_recommendations_created"] >= 1

    records_response = client.get("/external-risk/records", headers=headers)
    assert records_response.status_code == 200, records_response.text
    records_payload = records_response.json()
    assert records_payload["total"] >= 5

    record_id = records_payload["items"][0]["id"]
    mappings_response = client.get(f"/external-risk/mappings/{record_id}", headers=headers)
    assert mappings_response.status_code == 200, mappings_response.text
    mappings_payload = mappings_response.json()
    assert len(mappings_payload["mappings"]) >= 1
    assert any(len(item["control_ids"]) >= 1 for item in mappings_payload["mappings"])

    summary_response = client.get("/external-risk/summary", headers=headers)
    assert summary_response.status_code == 200, summary_response.text
    summary_payload = summary_response.json()
    assert summary_payload["high_or_critical_risks"] >= 1
    assert summary_payload["known_exploited_items"] >= 1
    assert summary_payload["affected_assets"] >= 1
    assert summary_payload["simulations_recommended"] >= 1
    assert summary_payload["total_ale_usd"] > 0
    assert summary_payload["total_residual_risk_usd"] >= 0
    assert summary_payload["drilldown"] == "/monitoring?focus=external-risk"

    dashboard_response = client.get("/dashboard/command-center?time_window_hours=168", headers=headers)
    assert dashboard_response.status_code == 200, dashboard_response.text
    dashboard_payload = dashboard_response.json()
    external_risk = dashboard_payload["external_risk_intelligence"]
    assert external_risk["high_or_critical_risks"] >= 1
    assert external_risk["known_exploited_items"] >= 1
    assert external_risk["simulations_recommended"] >= 1
    assert len(external_risk["source_health"]) >= 1

    with session_factory() as db:
        risk_count = db.scalar(
            select(func.count(ExternalRiskRecord.id)).where(
                ExternalRiskRecord.tenant_id == owner["tenant_id"]
            )
        )
        mapping_count = db.scalar(
            select(func.count(ExternalRiskAssetMapping.id)).where(
                ExternalRiskAssetMapping.tenant_id == owner["tenant_id"]
            )
        )
        impact_rows = db.scalars(
            select(ExternalRiskImpact).where(ExternalRiskImpact.tenant_id == owner["tenant_id"])
        ).all()
        recommendation_count = db.scalar(
            select(func.count(RiskTriggeredSimulationRecommendation.id)).where(
                RiskTriggeredSimulationRecommendation.tenant_id == owner["tenant_id"]
            )
        )
        signal_rows = db.scalars(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type == "external_risk.risk_record",
            )
        ).all()

    assert int(risk_count or 0) >= 5
    assert int(mapping_count or 0) >= 1
    assert len(impact_rows) >= 1
    assert any(float(row.annualized_loss_expectancy or 0.0) > 0 for row in impact_rows)
    assert int(recommendation_count or 0) >= 1
    assert len(signal_rows) >= 1
    assert any("related_control_ids" in (row.payload or {}) for row in signal_rows)


def test_command_center_survives_external_risk_summary_failure(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="external-risk-dashboard-fallback@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("summary exploded")

    monkeypatch.setattr("app.services.dashboard.aggregator.get_external_risk_summary", _boom)

    response = client.get("/dashboard/command-center?time_window_hours=168", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    external_risk = payload["external_risk_intelligence"]
    assert external_risk["sync_status"] == "failed"
    assert external_risk["critical_risks"] == 0
    assert str(external_risk.get("error", "")).startswith("summary_unavailable:")


def test_external_risk_summary_marks_stale_running_sync_and_uses_last_completed_run(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="external-risk-stale-run@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        completed = ExternalRiskSyncRun(
            tenant_id=owner["tenant_id"],
            status="completed",
            started_at=now - timedelta(minutes=50),
            completed_at=now - timedelta(minutes=49),
            records_ingested=17,
            trace_payload={"trigger": "test"},
        )
        stale_running = ExternalRiskSyncRun(
            tenant_id=owner["tenant_id"],
            status="running",
            started_at=now - timedelta(minutes=40),
            trace_payload={"trigger": "test"},
        )
        db.add_all([completed, stale_running])
        db.commit()

    summary_response = client.get("/external-risk/summary", headers=headers)
    assert summary_response.status_code == 200, summary_response.text
    summary_payload = summary_response.json()
    assert summary_payload["sync_status"] == "failed"
    assert summary_payload["new_risks_since_last_sync"] == 17
    assert summary_payload["last_sync_at"] is not None

    with session_factory() as db:
        latest = db.scalar(
            select(ExternalRiskSyncRun)
            .where(ExternalRiskSyncRun.tenant_id == owner["tenant_id"])
            .order_by(ExternalRiskSyncRun.started_at.desc())
            .limit(1)
        )
        assert latest is not None
        assert latest.status == "failed"
        assert latest.completed_at is not None
        assert latest.error_message == "stale_running_sync_timeout"
