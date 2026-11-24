from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")


NOW = datetime(2026, 8, 28, 8, tzinfo=timezone.utc)


@pytest.fixture()
def eci_db(tmp_path):
    from app.db import models as _models  # noqa: F401
    from app.db.session import Base

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'eci.sqlite3'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield sessions
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def _tenant(db, name: str = "ECI Tenant"):
    from app.db.models.tenant import Tenant

    row = Tenant(name=name, slug=name.lower().replace(" ", "-"), is_active=True)
    db.add(row)
    db.flush()
    return row


def _mcp_observation(*, display_name: str = "Records MCP", schema_extra: dict | None = None) -> dict:
    schema = {
        "type": "object",
        "properties": {"record_id": {"type": "string"}},
        "required": ["record_id"],
    }
    if schema_extra:
        schema["properties"].update(schema_extra)
    return {
        "configured_locator": "https://example.test/mcp",
        "registry_source": "demo-registry",
        "registry_identity": "records-mcp",
        "publisher_identity": "Acme Tools",
        "observed_endpoint": "https://example.test/mcp",
        "domain": "example.test",
        "transport": "https",
        "auth_mode": "oauth",
        "server_metadata": {
            "name": "records-mcp",
            "version": "1.0.0",
            "displayName": display_name,
        },
        "protocol_version": "2025-06-18",
        "tools": [
            {
                "name": "read_record",
                "version": "1.0.0",
                "description": "Read one approved customer record",
                "inputSchema": schema,
                "annotations": {"readOnlyHint": True},
                "displayName": display_name,
            }
        ],
        "resources": [{"uri": "mcp://records/templates", "mimeType": "text/plain"}],
        "instructions": ["Use bank-approved records only"],
    }


def test_mcpjacking_material_change_invalidates_trust_and_scopes_phase6_coverage_lineage(eci_db):
    from app.db.models.activity_lineage import LineageNode
    from app.db.models.continuous_assurance import ControlAssertion, DriftSignal
    from app.db.models.control_coverage import ControlCoverageAssessment
    from app.services.external_capability_integrity import ExternalCapabilityIntegrityService

    service = ExternalCapabilityIntegrityService()
    with eci_db.begin() as db:
        tenant = _tenant(db)
        observed = service.observe_mcp_capability(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            observation=_mcp_observation(),
            observed_at=NOW,
            evidence_refs=["evidence:mcp:baseline"],
        )
        assert observed.trust_state == "UNKNOWN"
        accepted = service.accept_current_baseline(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            actor_ref="user:security-admin",
            reason="initial approved registry review",
            accepted_at=NOW + timedelta(seconds=1),
        )
        assert accepted.trust_state == "TRUSTED_CURRENT"

        changed = _mcp_observation(schema_extra={"export_url": {"type": "string"}})
        drifted = service.observe_mcp_capability(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            observation=changed,
            observed_at=NOW + timedelta(minutes=1),
            evidence_refs=["evidence:mcp:takeover"],
        )

        assert drifted.configured_locator == "https://example.test/mcp"
        assert drifted.trust_state == "STALE"
        assert drifted.material_fingerprint != accepted.material_fingerprint

        assertion = db.scalar(select(ControlAssertion).where(ControlAssertion.tenant_id == tenant.id))
        assert assertion is not None
        assert assertion.assurance_state == "STALE"
        signal = db.scalar(select(DriftSignal).where(DriftSignal.tenant_id == tenant.id))
        assert signal is not None
        assert signal.category == "tool_mcp_fingerprint"
        coverage = db.scalar(
            select(ControlCoverageAssessment)
            .where(ControlCoverageAssessment.tenant_id == tenant.id)
            .order_by(ControlCoverageAssessment.assessed_at.desc())
        )
        assert coverage is not None
        assert coverage.dimension == "external_capability_integrity"
        assert coverage.coverage_state == "covered_stale"
        lineage_node = db.scalar(select(LineageNode).where(LineageNode.tenant_id == tenant.id))
        assert lineage_node is not None
        assert lineage_node.node_type == "DRIFT_SIGNAL"

        regressed = service.complete_targeted_revalidation(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            outcome="REGRESSED",
            evidence_refs=["evidence:validation:failed"],
            completed_at=NOW + timedelta(minutes=2),
        )
        assert regressed.trust_state == "REGRESSED"


def test_non_material_metadata_change_does_not_create_false_drift(eci_db):
    from app.db.models.continuous_assurance import DriftSignal
    from app.services.external_capability_integrity import ExternalCapabilityIntegrityService

    service = ExternalCapabilityIntegrityService()
    with eci_db.begin() as db:
        tenant = _tenant(db)
        service.observe_mcp_capability(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            observation=_mcp_observation(display_name="Records MCP"),
            observed_at=NOW,
        )
        accepted = service.accept_current_baseline(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            actor_ref="user:security-admin",
            reason="approve stable capability",
            accepted_at=NOW,
        )
        display_only = service.observe_mcp_capability(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            observation=_mcp_observation(display_name="Records MCP refreshed label"),
            observed_at=NOW + timedelta(minutes=1),
        )
        assert display_only.trust_state == "TRUSTED_CURRENT"
        assert display_only.material_fingerprint == accepted.material_fingerprint
        assert db.scalar(select(DriftSignal).where(DriftSignal.tenant_id == tenant.id)) is None


def test_unknown_revoked_tenant_and_stale_observation_safety(eci_db):
    from app.services.external_capability_integrity import ExternalCapabilityIntegrityService

    service = ExternalCapabilityIntegrityService()
    with eci_db.begin() as db:
        tenant_a = _tenant(db, "Tenant A")
        tenant_b = _tenant(db, "Tenant B")
        unknown = service.observe_mcp_capability(
            db,
            tenant_id=tenant_a.id,
            capability_ref="mcp:records",
            observation=_mcp_observation(),
            observed_at=NOW,
        )
        assert unknown.trust_state == "UNKNOWN"
        with pytest.raises(PermissionError, match="tenant"):
            service.accept_current_baseline(
                db,
                tenant_id=tenant_b.id,
                capability_ref="mcp:records",
                actor_ref="user:tenant-b",
                reason="cross tenant attempt",
                accepted_at=NOW,
            )
        service.accept_current_baseline(
            db,
            tenant_id=tenant_a.id,
            capability_ref="mcp:records",
            actor_ref="user:tenant-a",
            reason="tenant a approval",
            accepted_at=NOW,
        )
        service.revoke_capability(
            db,
            tenant_id=tenant_a.id,
            capability_ref="mcp:records",
            actor_ref="user:security-admin",
            reason="incident response",
            revoked_at=NOW + timedelta(minutes=1),
        )
        stale = service.observe_mcp_capability(
            db,
            tenant_id=tenant_a.id,
            capability_ref="mcp:records",
            observation=_mcp_observation(schema_extra={"late": {"type": "string"}}),
            observed_at=NOW - timedelta(minutes=1),
        )
        assert stale.trust_state == "REVOKED"
        assert stale.material_fingerprint != ""
        revalidated = service.complete_targeted_revalidation(
            db,
            tenant_id=tenant_a.id,
            capability_ref="mcp:records",
            outcome="TRUSTED_CURRENT",
            evidence_refs=["evidence:late-pass"],
            completed_at=NOW + timedelta(minutes=2),
        )
        assert revalidated.trust_state == "REVOKED"


def test_trusted_capability_does_not_override_action_time_policy(eci_db):
    from app.services.agentic_action_integrity_service import evaluate_mcp_tool_call_integrity
    from app.services.external_capability_integrity import ExternalCapabilityIntegrityService

    service = ExternalCapabilityIntegrityService()
    with eci_db.begin() as db:
        tenant = _tenant(db)
        trusted = service.observe_mcp_capability(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            observation=_mcp_observation(),
            observed_at=NOW,
        )
        service.accept_current_baseline(
            db,
            tenant_id=tenant.id,
            capability_ref="mcp:records",
            actor_ref="user:security-admin",
            reason="trusted current for normal evaluation",
            accepted_at=NOW,
        )

        result = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=tenant.id,
            chain_id="chain:unauthorized",
            action_id="action:unauthorized",
            agent_id="agent:records",
            action="send external document",
            resource="records-server/customer-secret",
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            tool_fingerprint_id=trusted.tool_fingerprints["read_record"]["fingerprint"],
            parameters={"destination": "https://evil.example/exfil", "api_key": "synthetic"},
        )

        assert result["external_capability"]["trust_state"] == "TRUSTED_CURRENT"
        assert result["decision"] == "block"
        assert "secret_or_credential_access" in result["risk_factors"]


def test_mcp_scan_and_approval_surface_external_capability_state(eci_db):
    from app.db.models.policy import ToolFingerprint
    from app.db.models.control_coverage import ControlCoverageSnapshot
    from app.services.agentic_action_integrity_service import scan_mcp_tool
    from app.services.mcp_tool_approval_service import decide_mcp_tool_fingerprint

    db = eci_db()
    try:
        tenant = _tenant(db)
        db.commit()

        scan = scan_mcp_tool(
            db,
            tenant_id=tenant.id,
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            description="Read one approved customer record",
            schema={
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
            },
            examples=[],
            manifest={
                "configured_locator": "https://example.test/mcp",
                "registry_source": "demo-registry",
                "registry_identity": "records-mcp",
                "publisher_identity": "Acme Tools",
                "observed_endpoint": "https://example.test/mcp",
                "domain": "example.test",
                "transport": "https",
                "auth_mode": "oauth",
                "server_metadata": {"name": "records-mcp", "version": "1.0.0"},
            },
            chain_id="chain:scan",
            request_id="request:scan",
        )
        assert scan["external_capability"]["capability_ref"] == "mcp:records-server"
        assert scan["external_capability"]["trust_state"] == "UNKNOWN"

        row = db.scalar(
            select(ToolFingerprint).where(
                ToolFingerprint.tenant_id == tenant.id,
                ToolFingerprint.mcp_server_id == "records-server",
                ToolFingerprint.tool_name == "read_record",
            )
        )
        assert row is not None

        approval = decide_mcp_tool_fingerprint(
            db,
            tenant_id=tenant.id,
            actor_user_id="security-admin",
            tool_fingerprint_id=row.id,
            decision="approve",
            expected_manifest_hash=row.manifest_hash,
            reason="trusted reviewed registry capability",
        )
        assert approval["trust_status"] == "approved"
        assert approval["external_capability"]["trust_state"] == "TRUSTED_CURRENT"
        snapshot = db.scalar(
            select(ControlCoverageSnapshot).where(
                ControlCoverageSnapshot.tenant_id == tenant.id,
                ControlCoverageSnapshot.snapshot_kind == "external_capability_integrity",
            )
        )
        assert snapshot is not None
        assert len(snapshot.methodology_version) <= 32
    finally:
        db.close()


def test_approved_scanned_mcp_fingerprint_resolves_trusted_capability_at_call_time(eci_db):
    from app.db.models.policy import ToolFingerprint
    from app.services.agentic_action_integrity_service import (
        evaluate_mcp_tool_call_integrity,
        scan_mcp_tool,
    )
    from app.services.mcp_tool_approval_service import decide_mcp_tool_fingerprint

    db = eci_db()
    try:
        tenant = _tenant(db)
        db.commit()

        scan = scan_mcp_tool(
            db,
            tenant_id=tenant.id,
            mcp_server_id="github-pull-requests",
            tool_name="list_pull_requests",
            tool_version="1.8.0",
            description="List pull requests in a GitHub repository.",
            schema={
                "type": "object",
                "properties": {
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "state": {"type": "string"},
                },
                "required": ["owner", "repo"],
            },
            examples=[],
            manifest={
                "configured_locator": "mcp://github-pull-requests",
                "registry_source": "codex_config",
                "registry_identity": "github-pull-requests",
                "publisher_identity": "Hawk governed MCP proxy",
                "observed_endpoint": "mcp://github-pull-requests",
                "domain": "github.com",
                "transport": "stdio",
                "auth_mode": "hawk_endpoint_agent",
                "server_metadata": {
                    "name": "github-pull-requests",
                    "version": "1.8.0",
                },
            },
            chain_id="chain:github-pr-scan",
            request_id="request:github-pr-scan",
        )
        row = db.scalar(
            select(ToolFingerprint).where(
                ToolFingerprint.tenant_id == tenant.id,
                ToolFingerprint.id == scan["tool_fingerprint_id"],
            )
        )
        assert row is not None

        approval = decide_mcp_tool_fingerprint(
            db,
            tenant_id=tenant.id,
            actor_user_id="security-admin",
            tool_fingerprint_id=row.id,
            decision="approve",
            expected_manifest_hash=row.manifest_hash,
            reason="approved governed read-only GitHub MCP descriptor",
        )
        assert approval["external_capability"]["trust_state"] == "TRUSTED_CURRENT"

        authorization = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=tenant.id,
            chain_id="chain:github-pr-call",
            action_id="action:github-pr-call",
            agent_id="agent:codex",
            action="file_read",
            resource="github.com/github/github-mcp-server",
            mcp_server_id="github-pull-requests",
            tool_name="list_pull_requests",
            tool_version="1.8.0",
            tool_fingerprint_id=row.id,
            api_endpoint="https://github.com/github/github-mcp-server",
            parameters={"owner": "github", "repo": "github-mcp-server", "state": "open"},
        )

        assert authorization["decision"] == "allow"
        assert authorization["external_capability"]["trust_state"] == "TRUSTED_CURRENT"
        assert "external_capability_trust_unknown" not in authorization["risk_factors"]
    finally:
        db.close()


def test_mcp_scan_fails_safe_when_external_capability_projection_aborts_session(
    eci_db, monkeypatch
):
    from app.db.models.policy import ToolFingerprint
    from app.services.agentic_action_integrity_service import scan_mcp_tool
    from app.services.external_capability_integrity import ExternalCapabilityIntegrityService

    db = eci_db()
    try:
        tenant = _tenant(db)
        db.commit()

        def poison_projection(self, db, **kwargs):  # noqa: ARG001
            db.execute(
                text(
                    "INSERT INTO tenants (id, name, slug, is_active) "
                    "VALUES (:id, 'duplicate', 'duplicate', 1)"
                ),
                {"id": tenant.id},
            )

        monkeypatch.setattr(
            ExternalCapabilityIntegrityService,
            "observe_mcp_capability",
            poison_projection,
        )

        scan = scan_mcp_tool(
            db,
            tenant_id=tenant.id,
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            description="Read one approved customer record",
            schema={
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
            },
            examples=[],
            manifest={"configured_locator": "https://example.test/mcp"},
            chain_id="chain:projection-fail-safe",
            request_id="request:projection-fail-safe",
        )

        assert scan["status"] == "completed"
        assert scan["external_capability"] == {
            "trust_state": "UNKNOWN",
            "reason": "external_capability_observation_failed",
        }
        assert db.scalar(
            select(ToolFingerprint).where(
                ToolFingerprint.tenant_id == tenant.id,
                ToolFingerprint.mcp_server_id == "records-server",
                ToolFingerprint.tool_name == "read_record",
            )
        ) is not None
    finally:
        db.close()
