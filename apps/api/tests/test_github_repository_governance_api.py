from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.github_repository_access import GitHubRepository
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackDefinition, PolicyPackInstance
from app.db.session import Base
from app.services.github_repository_access_service import (
    evaluate_github_repository_mutation,
    get_github_repository_detail_payload,
    persist_github_inventory_unit,
    update_github_repository_governance,
)
from app.services.policy_pack_platform.service import _normalize_assignment_targets


def _db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _repository(db: Session, tenant_id: str = "tenant-a") -> GitHubRepository:
    repository = persist_github_inventory_unit(
        db,
        tenant_id=tenant_id,
        connection_id=None,
        record={
            "record_kind": "github_repository",
            "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
            "identifiers": {"host": "github.com", "organization_id": "O_1", "organization_login": "acme", "repository_id": "R_1"},
            "metadata": {"full_name": "acme/app", "visibility": "PRIVATE", "lifecycle_state": "ACTIVE", "evidence_state": "CONFIRMED"},
        },
    )
    repository.operation_controls_json = {"READ": "ALLOW", "EDIT": "ALLOW", "COMMIT": "ALLOW", "PULL": "ALLOW", "PUSH": "ALLOW"}
    return repository


def _personal_repository(db: Session, tenant_id: str = "tenant-a") -> GitHubRepository:
    repository = persist_github_inventory_unit(
        db,
        tenant_id=tenant_id,
        connection_id=None,
        record={
            "record_kind": "github_repository",
            "observed_at": datetime(2026, 9, 14, tzinfo=UTC),
            "identifiers": {"host": "github.com", "organization_id": "U_1", "organization_login": "octocat", "repository_id": "R_personal"},
            "metadata": {
                "full_name": "octocat/demo-private",
                "visibility": "PRIVATE",
                "lifecycle_state": "ACTIVE",
                "evidence_state": "CONFIRMED",
                "protection": {"account_scope_kind": "PERSONAL"},
            },
        },
    )
    repository.operation_controls_json = {"READ": "ALLOW", "EDIT": "ALLOW", "COMMIT": "ALLOW", "PULL": "ALLOW", "PUSH": "ALLOW"}
    return repository


def _assignment(db: Session, repository_id: str | None, tenant_id: str = "tenant-a", *, state: str = "ENFORCED", active: bool = True) -> PolicyPackAssignment:
    pack = PolicyPack(id=f"pack-{tenant_id}", tenant_id=tenant_id, name="GitHub boundary", description="test", status="active")
    version = PolicyVersion(id=f"version-{tenant_id}", tenant_id=tenant_id, pack_id=pack.id, version="1", scope={}, enforcement_defaults={}, guardian_contracts=[], contract_json={})
    definition = PolicyPackDefinition(id=f"definition-{tenant_id}", publisher_ref=f"test-{tenant_id}", stable_pack_id="DEV-GITHUB", version="1", name="GitHub", description="test", state="PUBLISHED")
    instance = PolicyPackInstance(id=f"instance-{tenant_id}", tenant_id=tenant_id, definition_id=definition.id, source_pack_id="DEV-GITHUB", source_pack_version="1", runtime_policy_pack_id=pack.id, effective_policy_version_id=version.id, owner_ref="owner", state=state)
    raw_targets: dict[str, object] = {"application": ["github"], "deployment_surface": ["mcp_gateway"]}
    if repository_id is not None:
        raw_targets["resource"] = [repository_id]
    targets = _normalize_assignment_targets(raw_targets)
    assignment = PolicyPackAssignment(id=f"assignment-{tenant_id}", tenant_id=tenant_id, instance_id=instance.id, assignment_key="repository-boundary", targets=targets, active=active)
    db.add_all([pack, version, definition, instance, assignment])
    db.flush()
    return assignment


def test_discovery_cannot_write_repository_governance_fields() -> None:
    db = _db()
    try:
        repository = _repository(db)
        persist_github_inventory_unit(
            db, tenant_id="tenant-a", connection_id=None,
            record={
                "record_kind": "github_repository", "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
                "identifiers": {"host": "github.com", "organization_id": "O_1", "organization_login": "acme", "repository_id": "R_1"},
                "metadata": {"full_name": "acme/app", "governance_state": "APPROVED", "approved_scope_ref": "forged", "policy_mapping_ref": "forged", "policy_current": True},
            },
        )
        assert repository.governance_state == "UNKNOWN"
        assert repository.governance_version == 0
        assert repository.approved_scope_ref is None
    finally:
        db.close()


def test_current_same_tenant_assignment_approves_and_unapproval_clears_refs() -> None:
    db = _db()
    try:
        repository = _repository(db)
        assignment = _assignment(db, repository.id)
        assert assignment.targets == {
            "application": ["github"],
            "deployment_surface": ["mcp_gateway"],
            "resource": [repository.id],
            "non_overridable": False,
            "explicit_revocation": False,
        }
        assert "repository_id" not in assignment.targets
        approved = update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="APPROVED", expected_governance_version=0, assignment_id=assignment.id, actor_user_id=None)
        assert approved.governance_state == "APPROVED"
        assert approved.governance_version == 1
        assert approved.policy_current is True
        unapproved = update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="UNAPPROVED", expected_governance_version=1, assignment_id=None, actor_user_id=None)
        assert unapproved.governance_state == "UNAPPROVED"
        assert unapproved.governance_version == 2
        assert unapproved.approved_scope_ref is None and unapproved.policy_mapping_ref is None and unapproved.policy_current is False
    finally:
        db.close()


@pytest.mark.parametrize("resource_id", [None, "other-repository-id"])
def test_approval_rejects_assignment_without_the_selected_immutable_resource(resource_id: str | None) -> None:
    db = _db()
    try:
        repository = _repository(db)
        assignment = _assignment(db, resource_id)
        with pytest.raises(ValueError, match="current repository policy assignment"):
            update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="APPROVED", expected_governance_version=0, assignment_id=assignment.id, actor_user_id=None)
    finally:
        db.close()


def test_unapproval_blocks_a_repository_that_previously_allowed_reads() -> None:
    db = _db()
    try:
        repository = _repository(db)
        repository.read_posture = "ALLOW"
        assignment = _assignment(db, repository.id)
        update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="APPROVED", expected_governance_version=0, assignment_id=assignment.id, actor_user_id=None)
        assert evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/acme/app")["decision"] == "ALLOW"
        unapproved = update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="UNAPPROVED", expected_governance_version=1, assignment_id=None, actor_user_id=None)
        assert unapproved.read_posture == "BLOCK"
        assert evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/acme/app") == {"decision": "BLOCK", "reason": "repository_read_blocked", "repository_id": "R_1"}
    finally:
        db.close()


def test_read_allow_fails_closed_when_the_stored_assignment_becomes_inactive() -> None:
    db = _db()
    try:
        repository = _repository(db)
        repository.read_posture = "ALLOW"
        assignment = _assignment(db, repository.id)
        update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="APPROVED", expected_governance_version=0, assignment_id=assignment.id, actor_user_id=None)
        assignment.active = False
        db.flush()
        assert evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/acme/app") == {"decision": "BLOCK", "reason": "repository_read_not_currently_approved", "repository_id": "R_1"}
    finally:
        db.close()


@pytest.mark.parametrize("state, active", [("PAUSED", True), ("ENFORCED", False)])
def test_approval_requires_active_enforcing_assignment_for_exact_repository(state: str, active: bool) -> None:
    db = _db()
    try:
        repository = _repository(db)
        assignment = _assignment(db, repository.id, state=state, active=active)
        with pytest.raises(ValueError, match="current repository policy assignment"):
            update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="APPROVED", expected_governance_version=0, assignment_id=assignment.id, actor_user_id=None)
    finally:
        db.close()


def test_approval_rejects_a_withdrawn_policy_definition() -> None:
    db = _db()
    try:
        repository = _repository(db)
        assignment = _assignment(db, repository.id)
        definition = db.get(PolicyPackDefinition, "definition-tenant-a")
        assert definition is not None
        definition.state = "WITHDRAWN"
        db.flush()
        with pytest.raises(ValueError, match="current repository policy assignment"):
            update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="APPROVED", expected_governance_version=0, assignment_id=assignment.id, actor_user_id=None)
    finally:
        db.close()


def test_governance_update_rejects_stale_version_and_cross_tenant_assignment() -> None:
    db = _db()
    try:
        repository = _repository(db)
        assignment = _assignment(db, repository.id, tenant_id="tenant-b")
        with pytest.raises(ValueError, match="current repository policy assignment"):
            update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="APPROVED", expected_governance_version=0, assignment_id=assignment.id, actor_user_id=None)
        _assignment(db, repository.id, tenant_id="tenant-a")
        with pytest.raises(ValueError, match="governance version conflict"):
            update_github_repository_governance(db, tenant_id="tenant-a", repository_id=repository.id, decision="UNAPPROVED", expected_governance_version=1, assignment_id=None, actor_user_id=None)
    finally:
        db.close()


def test_repository_detail_payload_is_tenant_scoped_and_bounded() -> None:
    db = _db()
    try:
        repository = _repository(db)
        payload = get_github_repository_detail_payload(db, tenant_id="tenant-a", repository_id=repository.id, limit=1)
        assert payload["repository"]["id"] == repository.id
        assert payload["access_relationships"] == {"items": [], "next_cursor": None, "limit": 1}
        assert payload["ai_connections"] == {"items": [], "next_cursor": None, "limit": 1}
        with pytest.raises(ValueError, match="repository not found"):
            get_github_repository_detail_payload(db, tenant_id="tenant-b", repository_id=repository.id)
    finally:
        db.close()


@pytest.mark.parametrize(
    ("deny_posture", "expected_read_posture", "read_decision", "pull_decision"),
    [
        ("BLOCK_CHANGES", "ALLOW", "ALLOW", "ALLOW"),
        ("BLOCK_ALL", "BLOCK", "BLOCK", "BLOCK"),
    ],
)
def test_personal_repository_supports_explicit_deny_postures(
    deny_posture: str,
    expected_read_posture: str,
    read_decision: str,
    pull_decision: str,
) -> None:
    db = _db()
    try:
        repository = _personal_repository(db)
        protected = update_github_repository_governance(
            db,
            tenant_id="tenant-a",
            repository_id=repository.id,
            decision="UNAPPROVED",
            expected_governance_version=0,
            assignment_id=None,
            actor_user_id=None,
            deny_posture=deny_posture,
        )
        assert protected.governance_state == "UNAPPROVED"
        assert protected.read_posture == expected_read_posture
        payload = get_github_repository_detail_payload(db, tenant_id="tenant-a", repository_id=repository.id)
        assert payload["repository"]["account_scope_kind"] == "PERSONAL"
        assert payload["repository"]["deny_posture"] == deny_posture
        read = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/octocat/demo-private")
        pull = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PULL", resource="github.com/octocat/demo-private")
        push = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", resource="github.com/octocat/demo-private")
        pull_request = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PULL_REQUEST_CREATE", resource="github.com/octocat/demo-private")
        assert read["decision"] == read_decision
        assert pull["decision"] == pull_decision
        assert push == {"decision": "BLOCK", "reason": "repository_not_explicitly_eligible", "repository_id": "R_personal"}
        assert pull_request["decision"] == "BLOCK"
    finally:
        db.close()


def test_personal_deny_posture_is_rejected_for_organization_repository() -> None:
    db = _db()
    try:
        repository = _repository(db)
        with pytest.raises(ValueError, match="personal GitHub repository"):
            update_github_repository_governance(
                db,
                tenant_id="tenant-a",
                repository_id=repository.id,
                decision="UNAPPROVED",
                expected_governance_version=0,
                assignment_id=None,
                actor_user_id=None,
                deny_posture="BLOCK_CHANGES",
            )
    finally:
        db.close()


def test_personal_deny_posture_rejects_unknown_values_and_approval_combination() -> None:
    db = _db()
    try:
        repository = _personal_repository(db)
        with pytest.raises(ValueError, match="invalid personal repository deny posture"):
            update_github_repository_governance(
                db,
                tenant_id="tenant-a",
                repository_id=repository.id,
                decision="UNAPPROVED",
                expected_governance_version=0,
                assignment_id=None,
                actor_user_id=None,
                deny_posture="ALLOW_ALL",
            )
        with pytest.raises(ValueError, match="deny posture is only valid with UNAPPROVED"):
            update_github_repository_governance(
                db,
                tenant_id="tenant-a",
                repository_id=repository.id,
                decision="APPROVED",
                expected_governance_version=0,
                assignment_id="assignment-1",
                actor_user_id=None,
                deny_posture="BLOCK_ALL",
            )
    finally:
        db.close()
