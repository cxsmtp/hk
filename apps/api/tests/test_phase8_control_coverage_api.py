from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.control_coverage import (
    CoverageApplicability,
    CoverageAssurance,
    CoverageCapability,
    CoverageDeployment,
    ExecutiveCoverageFacts,
)
from app.db.models.control_coverage import ControlCoverageAssessment
from app.db.session import Base, get_db
from app.main import app
from app.services.control_coverage.executive import CoverageAssessmentInput, refresh_executive_coverage_snapshot


PASSWORD = "Password123!"
NOW = datetime(2026, 8, 25, 13, tzinfo=timezone.utc)


@pytest.fixture()
def phase8_api_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'phase8-api.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    sessions = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    Base.metadata.create_all(bind=engine)
    from app.api.routers import control_coverage

    monkeypatch.setattr(control_coverage.settings, "control_coverage_api_enabled", True)

    def override_get_db():
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, sessions
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register(client: TestClient, email: str) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Phase 8 Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    tenant_id = payload["tenants"][0]["id"]
    return tenant_id, {
        "Authorization": f"Bearer {payload['access_token']}",
        "X-Tenant-ID": tenant_id,
    }


def _seed_snapshot(sessions, *, tenant_id: str, suffix: str, assurance: CoverageAssurance):
    with sessions.begin() as db:
        snapshot = refresh_executive_coverage_snapshot(
            db,
            tenant_id=tenant_id,
            scope_type="tenant",
            scope_key="all",
            display_name="Enterprise AI estate",
            inputs=[
                CoverageAssessmentInput(
                    assessment_key=f"assessment-{suffix}",
                    asset_ref="asset:generic-runtime",
                    action_class="document_update",
                    action_path_ref="action:generic-runtime",
                    deployment_surface="runtime",
                    dimension="target_binding",
                    requirement_ref="requirement:target_binding",
                    applicability_reason="The action targets a material resource.",
                    facts=ExecutiveCoverageFacts(
                        applicability=CoverageApplicability.APPLICABLE,
                        deployment=CoverageDeployment.CONFIGURED,
                        capability=CoverageCapability.VERIFIED,
                        assurance=assurance,
                        evidence_quality="cryptographically_verified",
                        evidence_refs=("decision_receipt:phase8", "validation_run:phase8"),
                        expected_control_points=("runtime:gate",),
                        contributing_control_points=("runtime:gate",),
                        missing_contributions=(),
                        bypass_reachable=False,
                        compensating_bypass_control=False,
                        previously_validated=True,
                        unresolved_regression=assurance is CoverageAssurance.REGRESSED,
                    ),
                    control_plan_ref="control-plan:phase8",
                    validation_refs=("validation_run:phase8",),
                    lineage_refs=("lineage:phase8",),
                    criticality="high",
                )
            ],
            source_versions={"policy": "policy:v1"},
            assessed_at=NOW + (timedelta(minutes=1) if assurance is CoverageAssurance.REGRESSED else timedelta()),
        )
        return snapshot.id


def test_phase8_executive_api_summary_drilldown_evidence_comparison_and_tenant_isolation(phase8_api_env) -> None:
    client, sessions = phase8_api_env
    tenant_id, headers = _register(client, f"phase8-owner-{uuid4().hex[:6]}@example.com")
    _foreign_id, foreign_headers = _register(client, f"phase8-foreign-{uuid4().hex[:6]}@example.com")
    first_id = _seed_snapshot(sessions, tenant_id=tenant_id, suffix="stable", assurance=CoverageAssurance.CURRENT)
    second_id = _seed_snapshot(sessions, tenant_id=tenant_id, suffix="regressed", assurance=CoverageAssurance.REGRESSED)

    summary = client.get("/control-coverage/executive", headers=headers)
    assert summary.status_code == 200, summary.text
    payload = summary.json()
    assert payload["snapshot_id"] == second_id
    assert payload["state_distribution"]["regressed"] == 1
    assert payload["validated_coverage_percent"] == 0
    assert payload["top_gaps"][0]["priority"] == "P0"

    assessments = client.get(
        f"/control-coverage/executive/snapshots/{second_id}/assessments?state=regressed&surface=runtime",
        headers=headers,
    )
    assert assessments.status_code == 200, assessments.text
    assert assessments.json()["count"] == 1
    assessment_id = assessments.json()["items"][0]["assessment_id"]

    detail = client.get(f"/control-coverage/executive/assessments/{assessment_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["coverage_state"] == "regressed"
    assert detail.json()["expected_control_points"] == ["runtime:gate"]
    assert detail.json()["evidence_refs"] == ["decision_receipt:phase8", "validation_run:phase8"]

    evidence = client.get(
        f"/control-coverage/executive/snapshots/{second_id}/evidence", headers=headers
    )
    assert evidence.status_code == 200, evidence.text
    assert evidence.json()["evidence_refs"] == ["decision_receipt:phase8", "validation_run:phase8"]

    comparison = client.get(
        f"/control-coverage/executive/snapshots/{second_id}/compare?previous_snapshot_id={first_id}",
        headers=headers,
    )
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["introduced"] == 1
    assert comparison.json()["removed"] == 1

    assert client.get("/control-coverage/executive", headers=foreign_headers).status_code == 404
    assert client.get(f"/control-coverage/executive/assessments/{assessment_id}", headers=foreign_headers).status_code == 404
    assert client.get(f"/control-coverage/executive/snapshots/{second_id}/evidence", headers=foreign_headers).status_code == 404


def test_phase8_refresh_uses_authoritative_tenant_sources_and_does_not_accept_client_facts(phase8_api_env) -> None:
    client, sessions = phase8_api_env
    tenant_id, headers = _register(client, f"phase8-refresh-{uuid4().hex[:6]}@example.com")

    response = client.post(
        "/control-coverage/executive/refresh",
        headers=headers,
        json={"scope_type": "tenant", "scope_key": "all", "display_name": "Enterprise AI estate"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["tenant_id"] == tenant_id
    assert payload["assessment_count"] == 0
    assert payload["validated_coverage_percent"] is None
    assert "inputs" not in payload

    with sessions() as db:
        assert db.scalars(
            select(ControlCoverageAssessment).where(ControlCoverageAssessment.tenant_id == tenant_id)
        ).all() == []
