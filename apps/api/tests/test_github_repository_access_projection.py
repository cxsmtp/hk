from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.github_repository_access import GitHubRepositoryAccess, GitHubSourceOrganization
from app.db.session import Base
from app.services.enterprise_developer_ai_control import derive_developer_ai_setup_projection
from app.services.github_repository_access_service import persist_github_inventory_unit


def _session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _repository_record(*, repository_id: str = "R_1", full_name: str = "acme/app") -> dict[str, object]:
    return {
        "record_kind": "github_repository",
        "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
        "identifiers": {
            "host": "github.com",
            "organization_id": "O_1",
            "organization_login": "acme",
            "repository_id": repository_id,
        },
        "metadata": {"full_name": full_name, "visibility": "private"},
    }


def test_repository_identity_is_unique_per_tenant_and_host() -> None:
    db = _session()
    try:
        first = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_repository_record())
        second = persist_github_inventory_unit(
            db,
            tenant_id="tenant-a",
            connection_id=None,
            record=_repository_record(full_name="acme/app-renamed"),
        )
        db.commit()
        assert first.id == second.id
        assert second.full_name == "acme/app-renamed"
    finally:
        db.close()


def test_same_repository_identifier_in_another_tenant_is_not_the_same_identity() -> None:
    db = _session()
    try:
        first = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_repository_record())
        second = persist_github_inventory_unit(db, tenant_id="tenant-b", connection_id=None, record=_repository_record())
        assert first.id != second.id
    finally:
        db.close()


def test_access_path_preserves_direct_and_team_inherited_relations() -> None:
    db = _session()
    try:
        repository = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_repository_record())
        for access_path in ("DIRECT", "TEAM_INHERITED"):
            persist_github_inventory_unit(
                db,
                tenant_id="tenant-a",
                connection_id=None,
                record={
                    "record_kind": "github_repository_access",
                    "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
                    "identifiers": {"repository_id": repository.id, "principal_id": "github-user-1", "access_path": access_path},
                    "metadata": {"principal_type": "USER", "permission": "WRITE"},
                },
            )
        db.flush()
        rows = db.query(GitHubRepositoryAccess).order_by(GitHubRepositoryAccess.access_path).all()
        assert [row.access_path for row in rows] == ["DIRECT", "TEAM_INHERITED"]
    finally:
        db.close()


def test_unknown_evidence_never_defaults_to_confirmed() -> None:
    db = _session()
    try:
        repository = persist_github_inventory_unit(db, tenant_id="tenant-a", connection_id=None, record=_repository_record())
        assert repository.evidence_state == "UNKNOWN"
    finally:
        db.close()


def test_projection_payload_rejects_raw_content_fields() -> None:
    db = _session()
    try:
        with pytest.raises(ValueError, match="unsafe projection field"):
            persist_github_inventory_unit(
                db,
                tenant_id="tenant-a",
                connection_id=None,
                record={**_repository_record(), "metadata": {"full_name": "acme/app", "raw_prompt": "secret"}},
            )
    finally:
        db.close()


@pytest.mark.parametrize("unsafe_key", ["source_code", "patch_diff", "access_token", "apiCredential", "secret-token", "nestedPrompt"])
def test_projection_payload_recursively_rejects_normalized_sensitive_keys(unsafe_key: str) -> None:
    db = _session()
    try:
        with pytest.raises(ValueError, match="unsafe projection field"):
            persist_github_inventory_unit(
                db,
                tenant_id="tenant-a",
                connection_id=None,
                record={**_repository_record(), "metadata": {"full_name": "acme/app", "safe": [{"nested": {unsafe_key: "never-project"}}]}},
            )
    finally:
        db.close()


def test_repository_identity_includes_source_organization_and_child_records_preserve_org_metadata() -> None:
    db = _session()
    try:
        first = persist_github_inventory_unit(
            db, tenant_id="tenant-a", connection_id=None,
            record={**_repository_record(repository_id="R_same", full_name="acme-one/app"), "identifiers": {"host": "github.acme-one.test", "organization_id": "O_one", "organization_login": "acme-one", "repository_id": "R_same"}, "metadata": {"full_name": "acme-one/app", "capabilities": {"repository_inventory": "available"}, "sync_state": "COMPLETE", "limitations": ["none"]}},
        )
        second = persist_github_inventory_unit(
            db, tenant_id="tenant-a", connection_id=None,
            record={**_repository_record(repository_id="R_same", full_name="acme-two/app"), "identifiers": {"host": "github.acme-two.test", "organization_id": "O_two", "organization_login": "acme-two", "repository_id": "R_same"}, "metadata": {"full_name": "acme-two/app"}},
        )
        persist_github_inventory_unit(
            db, tenant_id="tenant-a", connection_id=None,
            record={"record_kind": "github_repository_access", "observed_at": datetime(2026, 9, 13, tzinfo=UTC), "identifiers": {"host": "github.acme-one.test", "organization_id": "O_one", "repository_id": "R_same", "principal_id": "U_1", "access_path": "DIRECT"}, "metadata": {"principal_type": "USER", "permission": "READ"}},
        )
        db.flush()
        first_org = db.query(GitHubSourceOrganization).filter_by(host="github.acme-one.test").one()
        assert first.id != second.id
        assert first_org.capabilities_json == {"repository_inventory": "available"}
        assert first_org.sync_state == "COMPLETE"
        assert first_org.limitations_json == ["none"]
    finally:
        db.close()


def test_developer_ai_setup_projection_normalizes_repo_client_decision_and_evidence() -> None:
    approved_repo = SimpleNamespace(
        id="repo-approved",
        host="github.com",
        external_repository_id="R_approved",
        node_id="NODE_approved",
        full_name="acme/approved-app",
        visibility="private",
        lifecycle_state="ACTIVE",
        default_branch="main",
        protection_json={},
        governance_state="APPROVED",
        governance_version=7,
        approved_scope_ref="policy-assignment-1",
        policy_mapping_ref="policy-version-1",
        policy_current=True,
        read_posture="ALLOW",
        evidence_state="CONFIRMED",
        first_seen_at=datetime(2026, 9, 13, tzinfo=UTC),
        last_seen_at=datetime(2026, 9, 17, tzinfo=UTC),
        last_verified_at=datetime(2026, 9, 17, tzinfo=UTC),
    )
    personal_repo = SimpleNamespace(
        id="repo-personal",
        host="github.com",
        external_repository_id="R_personal",
        node_id="NODE_personal",
        full_name="hawk-demo/personal-test",
        visibility="private",
        lifecycle_state="ACTIVE",
        default_branch="main",
        protection_json={},
        governance_state="UNAPPROVED",
        governance_version=2,
        approved_scope_ref=None,
        policy_mapping_ref=None,
        policy_current=False,
        read_posture="BLOCK",
        evidence_state="CONFIRMED",
        first_seen_at=datetime(2026, 9, 13, tzinfo=UTC),
        last_seen_at=datetime(2026, 9, 16, tzinfo=UTC),
        last_verified_at=datetime(2026, 9, 16, tzinfo=UTC),
    )
    connection = SimpleNamespace(
        id="ai-connection-1",
        repository_id="repo-approved",
        user_id="user-1",
        ai_system_id="ai-system-1",
        ai_asset_id="ai-asset-1",
        provider="anthropic",
        model="claude-sonnet-4.6",
        client_name="Claude Code",
        agent_id="agent-1",
        mcp_server_id="mcp-1",
        external_capability_id="github.pull_requests",
        tool_name="create_pull_request",
        tool_schema_fingerprint="schema-1",
        relationship_state="ACTIVE",
        confidence="CONFIRMED",
        source_surface="RUNTIME",
        evidence_refs_json=["evidence:allow-1"],
        action_count=3,
        first_seen_at=datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
        last_seen_at=datetime(2026, 9, 17, 10, 5, tzinfo=UTC),
    )

    projection = derive_developer_ai_setup_projection(
        repositories=[personal_repo, approved_repo],
        ai_connections=[connection],
        unauthorized_attempts=[
            {
                "repository": "hawk-demo/personal-test",
                "operation": "REPOSITORY_PULL_REQUEST_CREATE",
                "tool": "create_pull_request",
                "decision": "BLOCK",
                "evidence_refs": ["evidence:block-1"],
            }
        ],
    )

    assert projection["approved_repository"]["full_name"] == "acme/approved-app"
    assert projection["blocked_repository"]["full_name"] == "hawk-demo/personal-test"
    assert projection["ai_clients"][0]["ai_client"] == "Claude Code"
    assert projection["ai_clients"][0]["provider"] == "anthropic"
    assert projection["ai_clients"][0]["model"] == "claude-sonnet-4.6"
    assert projection["ai_clients"][0]["tool_call"] == "create_pull_request"
    assert projection["ai_clients"][0]["action"] == "REPOSITORY_PULL_REQUEST_CREATE"
    assert projection["ai_clients"][0]["policy_decision"] == "ALLOW_ON_APPROVED_REPOSITORY"
    assert projection["ai_clients"][0]["evidence_refs"] == ["evidence:allow-1"]
    assert projection["latest_decision"]["policy_decision"] == "BLOCK"
    assert projection["latest_decision"]["evidence_refs"] == ["evidence:block-1"]
    assert projection["test_prompts"]["allow"].endswith("Return only the result or the exact policy error.")
