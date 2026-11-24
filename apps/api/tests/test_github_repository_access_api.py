from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.routers.coverage import router
from app.db.session import Base
from app.db.models.activity_audit import AIAction, AISession
from app.db.models.evidence import EvidenceNode
from app.services.github_repository_access_service import (
    derive_github_repository_ai_connections,
    get_github_repository_detail,
    list_github_ai_connections,
    list_github_developers,
    list_github_repositories,
    persist_github_inventory_unit,
)
import pytest


def _db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _record(kind: str, repository_id: str = "R_1", **metadata: object) -> dict[str, object]:
    return {
        "record_kind": kind,
        "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
        "identifiers": {"host": "github.com", "organization_id": "O_1", "organization_login": "acme", "repository_id": repository_id},
        "metadata": metadata,
    }


def test_repository_query_routes_are_registered() -> None:
    paths = {route.path for route in router.routes}
    assert {
        "/control-coverage/source-control/github-repositories/organizations",
        "/control-coverage/source-control/github-repositories/repositories",
        "/control-coverage/source-control/github-repositories/repositories/{repository_id}",
        "/control-coverage/source-control/github-repositories/repositories/{repository_id}/governance",
        "/control-coverage/source-control/github-repositories/developers",
        "/control-coverage/source-control/github-repositories/ai-connections",
    } <= paths


def test_repository_detail_and_access_paths_are_tenant_scoped() -> None:
    db = _db()
    try:
        repository = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_record("github_repository", full_name="acme/app"))
        persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record={**_record("github_repository_access", principal_type="USER", permission="WRITE", evidence_state="CONFIRMED"), "identifiers": {"repository_id": repository.id, "principal_id": "direct", "access_path": "DIRECT"}})
        persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record={**_record("github_repository_access", principal_type="TEAM", permission="READ", evidence_state="CONFIRMED"), "identifiers": {"repository_id": repository.id, "principal_id": "team", "access_path": "TEAM_INHERITED"}})
        persist_github_inventory_unit(db, tenant_id="tenant-b", connection_id=None, record=_record("github_repository", full_name="acme/app"))
        db.flush()
        assert get_github_repository_detail(db, tenant_id="tenant-a", repository_id=repository.id).id == repository.id
        assert list_github_repositories(db, tenant_id="tenant-b")["items"][0].id != repository.id
        assert sorted(row.access_path for row in list_github_developers(db, tenant_id="tenant-a")["items"]) == ["DIRECT", "TEAM_INHERITED"]
    finally:
        db.close()


def test_ai_connection_keeps_unknown_fields_unknown_and_excludes_raw_content() -> None:
    db = _db()
    try:
        repository = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_record("github_repository", full_name="acme/app"))
        persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record={**_record("github_repository_ai_connection", source_surface="MCP", relationship_state="INFERRED", confidence="INFERRED", action_count=2), "identifiers": {"repository_id": repository.id}})
        row = list_github_ai_connections(db, tenant_id="tenant-a")["items"][0]
        assert row.model is None
        assert row.agent_id is None
        assert row.relationship_state == "INFERRED"
        assert "raw_prompt" not in row.evidence_refs_json
    finally:
        db.close()


def test_query_limits_and_cursor_are_bounded() -> None:
    db = _db()
    try:
        for number in range(3):
            persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_record("github_repository", repository_id=f"R_{number}", full_name=f"acme/app-{number}"))
        db.flush()
        page = list_github_repositories(db, tenant_id="tenant-a", limit=1)
        assert len(page["items"]) == 1
        assert isinstance(page["next_cursor"], str)
    finally:
        db.close()


def test_all_repository_lists_use_stable_database_bounded_cursors_and_combined_filters() -> None:
    db = _db()
    try:
        for number in range(4):
            repository = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_record("github_repository", repository_id=f"R_{number}", full_name=f"acme/app-{number}", visibility="PRIVATE" if number % 2 else "PUBLIC"))
            persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record={"record_kind": "github_repository_access", "observed_at": datetime(2026, 9, 13, tzinfo=UTC), "identifiers": {"repository_id": repository.id, "principal_id": f"U_{number}", "access_path": "DIRECT" if number % 2 else "TEAM_INHERITED"}, "metadata": {"principal_type": "USER", "permission": "READ"}})
        db.flush()
        first = list_github_repositories(db, tenant_id="tenant-a", limit=1, filters={"visibility": "PRIVATE", "host": "github.com"})
        second = list_github_repositories(db, tenant_id="tenant-a", limit=1, cursor=str(first["next_cursor"]), filters={"visibility": "PRIVATE", "host": "github.com"})
        assert len(first["items"]) == len(second["items"]) == 1
        assert first["items"][0].id != second["items"][0].id
        with pytest.raises(ValueError, match="invalid cursor"):
            list_github_repositories(db, tenant_id="tenant-a", cursor="not-a-valid-cursor")
    finally:
        db.close()


def test_accepted_source_bound_evidence_derives_ai_repository_connection_without_promoting_confidence() -> None:
    db = _db()
    try:
        repository = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_record("github_repository", full_name="acme/app"))
        db.add(AISession(session_id="session-1", tenant_id="tenant-a", source_surface="runtime", ai_app="Codex", ai_model="gpt-5", metadata_json={"provider": "openai"}))
        db.add(EvidenceNode(id="signed-evidence-1", tenant_id="tenant-a", node_type="source_evidence_bundle", signal_type="github_repository_activity", label="accepted GitHub activity", payload={"acceptance_state": "ACCEPTED", "current": True, "relationship_state": "OBSERVED", "confidence": "OBSERVED", "source_binding": {"tenant_id": "tenant-a", "action_id": "action-1", "repository": "github.com/acme/app", "source_surface": "RUNTIME"}}))
        db.add(AIAction(action_id="action-1", tenant_id="tenant-a", session_id="session-1", action_type="tool_call", ai_app="Codex", ai_model="gpt-5", evidence_bundle_id="signed-evidence-1", metadata_json={"repository": "github.com/acme/app", "provider": "openai", "agent_id": "agent-1", "mcp_server_id": "mcp-1", "tool_name": "create_pull_request", "tool_schema_fingerprint": "schema-1", "relationship_state": "CONFIRMED"}))
        db.flush()
        derived = derive_github_repository_ai_connections(db, tenant_id="tenant-a")
        row = list_github_ai_connections(db, tenant_id="tenant-a")["items"][0]
        assert derived == 1
        assert row.provider == "openai"
        assert row.model == "gpt-5"
        assert row.client_name == "Codex"
        assert row.agent_id == "agent-1"
        assert row.mcp_server_id == "mcp-1"
        assert row.tool_name == "create_pull_request"
        assert row.relationship_state == "OBSERVED"
    finally:
        db.close()


@pytest.mark.parametrize("payload, evidence_id, tenant_id", [
    ({"acceptance_state": "REJECTED", "current": True, "source_binding": {"tenant_id": "tenant-a", "action_id": "action-1", "repository": "github.com/acme/app"}}, "rejected", "tenant-a"),
    ({"acceptance_state": "ACCEPTED", "current": False, "source_binding": {"tenant_id": "tenant-a", "action_id": "action-1", "repository": "github.com/acme/app"}}, "stale", "tenant-a"),
    ({"acceptance_state": "ACCEPTED", "current": True, "source_binding": {"tenant_id": "tenant-b", "action_id": "action-1", "repository": "github.com/acme/app"}}, "cross-tenant", "tenant-a"),
])
def test_unaccepted_stale_or_cross_tenant_evidence_cannot_derive_repository_ai_connection(payload: dict[str, object], evidence_id: str, tenant_id: str) -> None:
    db = _db()
    try:
        persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_record("github_repository", full_name="acme/app"))
        db.add(AISession(session_id="session-1", tenant_id="tenant-a", source_surface="runtime"))
        db.add(EvidenceNode(id=evidence_id, tenant_id="tenant-a", node_type="source_evidence_bundle", signal_type="github_repository_activity", label="evidence", payload=payload))
        db.add(AIAction(action_id="action-1", tenant_id=tenant_id, session_id="session-1", action_type="tool_call", evidence_bundle_id=evidence_id, metadata_json={"repository": "github.com/acme/app", "relationship_state": "CONFIRMED"}))
        db.flush()
        assert derive_github_repository_ai_connections(db, tenant_id="tenant-a") == 0
        assert list_github_ai_connections(db, tenant_id="tenant-a")["items"] == []
    finally:
        db.close()


def test_arbitrary_or_missing_evidence_bundle_cannot_derive_repository_ai_connection() -> None:
    db = _db()
    try:
        persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_record("github_repository", full_name="acme/app"))
        db.add(AISession(session_id="session-1", tenant_id="tenant-a", source_surface="runtime"))
        db.add(AIAction(action_id="action-1", tenant_id="tenant-a", session_id="session-1", action_type="tool_call", evidence_bundle_id="missing", metadata_json={"repository": "github.com/acme/app"}))
        db.flush()
        assert derive_github_repository_ai_connections(db, tenant_id="tenant-a") == 0
    finally:
        db.close()
