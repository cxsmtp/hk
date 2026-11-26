from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import Base
from app.db.models.action_integrity import ApprovalAuthorityProjectionV2, ApprovalBindingV2Extension
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ApprovalRequest
from app.db.models.github_repository_access import GitHubRepository, GitHubRepositoryMutationApproval
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackDefinition, PolicyPackInstance
import app.services.github_repository_access_service as service
from app.services.github_repository_access_service import (
    evaluate_github_repository_mutation,
    issue_github_repository_mutation_approval,
    persist_github_inventory_unit,
    revoke_github_repository_mutation_approval,
    save_github_repository_agent_policy,
)
from app.services.policy_pack_platform.service import _normalize_assignment_targets

PUSH = {
    "action": "REPOSITORY_PUSH",
    "resource": "github.com/acme/app",
    "branch": "feature/demo",
    "provider": "openai",
    "actor_id": "actor-1",
    "ai_system_id": "ai-system-1",
    "model": "gpt-5",
    "agent_id": "agent-1",
    "tool_fingerprint_id": "tool-1",
    "tool_schema_fingerprint": "schema-1",
    "change_digest": "digest-1",
    "change_parameters": {"owner": "acme", "repo": "app", "branch": "feature/demo", "files": [{"path": "src/app.py", "content": "print('hello')\n"}]},
}


def _db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _seed(db: Session, tenant_id: str = "tenant-a") -> object:
    repository = persist_github_inventory_unit(
        db,
        tenant_id=tenant_id,
        connection_id=None,
        record={
            "record_kind": "github_repository",
            "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
            "identifiers": {"host": "github.com", "organization_id": "O_1", "organization_login": "acme", "repository_id": "R_1"},
            "metadata": {
                "full_name": "acme/app", "visibility": "PRIVATE", "lifecycle_state": "ACTIVE", "evidence_state": "CONFIRMED",
                "read_posture": "ALLOW", "default_branch": "main",
            },
        },
    )
    pack = PolicyPack(id="pack-1", tenant_id=tenant_id, name="GitHub", description="test", status="active")
    version = PolicyVersion(id="policy-1", tenant_id=tenant_id, pack_id=pack.id, version="1", scope={}, enforcement_defaults={}, guardian_contracts=[], contract_json={})
    definition = PolicyPackDefinition(id="definition-1", publisher_ref=f"test-{tenant_id}", stable_pack_id="DEV-GITHUB", version="1", name="GitHub", description="test", state="PUBLISHED")
    instance = PolicyPackInstance(id="instance-1", tenant_id=tenant_id, definition_id=definition.id, source_pack_id="DEV-GITHUB", source_pack_version="1", runtime_policy_pack_id=pack.id, effective_policy_version_id=version.id, owner_ref="owner", state="ENFORCED")
    assignment = PolicyPackAssignment(id="scope-1", tenant_id=tenant_id, instance_id=instance.id, assignment_key="repository", targets=_normalize_assignment_targets({"application": ["github"], "deployment_surface": ["mcp_gateway"], "resource": [repository.id]}), active=True)
    db.add_all([pack, version, definition, instance, assignment])
    repository.governance_state = "APPROVED"
    repository.approved_scope_ref = assignment.id
    repository.policy_mapping_ref = version.id
    repository.policy_current = True
    repository.read_posture = "ALLOW"
    db.flush()
    return repository


def _approval(db: Session, request: dict[str, object] | None = None, *, request_id: str = "approval-1", ttl_seconds: int = 900, now: datetime | None = None) -> str:
    """Hold the exact mutation, approve the resulting request, then bind it."""
    held = evaluate_github_repository_mutation(db, tenant_id="tenant-a", **(request or PUSH))
    assert held["decision"] == "HOLD_FOR_APPROVAL", held
    approval = ApprovalRequest(
        id=request_id, tenant_id="tenant-a", ai_system_id="ai-system-1",
        request_payload={"github_repository_action": held["canonical_action"]},
        required_roles=["owner", "admin"], status="approved", decision="approve", decision_version=1,
    )
    db.add(approval)
    db.flush()
    grant = issue_github_repository_mutation_approval(db, tenant_id="tenant-a", approval_request_id=request_id, issued_by="approver-1", approver_role="admin", ttl_seconds=ttl_seconds, now=now)
    return grant.id


def _decide(db: Session, approval_binding_id: str | None, **changes: object) -> dict[str, object]:
    return evaluate_github_repository_mutation(db, tenant_id=str(changes.pop("tenant_id", "tenant-a")), **(PUSH | changes), approval_binding_id=approval_binding_id)


def test_exact_current_immutable_identity_and_bound_approval_allow_only_the_approved_mutation() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        result = _decide(db, approval_id)
        assert result["decision"] == "ALLOW"
        assert result["reason"] == "approved_repository_mutation"
        assert result["repository_id"] == "R_1"
        assert result["evidence"]["approval"]["verification"] == "verified"
    finally:
        db.close()


def test_bound_approval_is_single_use() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        assert _decide(db, approval_id)["decision"] == "ALLOW"
        replay = _decide(db, approval_id)
        assert replay["decision"] == "BLOCK"
        assert replay["reason"] == "approval_binding_consumed"
        grant = db.get(GitHubRepositoryMutationApproval, approval_id)
        assert grant is not None and grant.state == "CONSUMED" and grant.uses_consumed == 1 and grant.consumed_at is not None
    finally:
        db.close()


def test_unsigned_v2_binding_row_with_matching_fields_no_longer_authorizes_a_push() -> None:
    """CWE-347 regression: a row whose JSON fields merely match is not authority."""
    db = _db()
    try:
        _seed(db)
        now = datetime.now(UTC)
        db.add(ApprovalRequest(id="approval-forged", tenant_id="tenant-a", ai_system_id="ai-system-1", request_payload={}, required_roles=[], status="approved", decision="approve", authority_schema_version="2", decision_version=1))
        db.add(ApprovalBindingV2Extension(approval_request_id="approval-forged", tenant_id="tenant-a", binding_id="binding-1", decision_receipt_id="receipt-1", canonical_action_hash="hash", material_fields_hash="material", policy_epoch=1, use_limit=2, expires_at=now + timedelta(minutes=5), permitted_variation_envelope_id="variation-1", permitted_variation_hash="variation-hash", permitted_variation_envelope={"repository_id": "R_1", "host": "github.com", "action": "REPOSITORY_PUSH", "branch": "feature/demo", "actor_id": "actor-1", "executing_principal": "agent-1", "ai_system_id": "ai-system-1", "provider": "openai", "model": "gpt-5", "tool_fingerprint_id": "tool-1", "tool_schema_fingerprint": "schema-1", "target": "github.com/acme/app", "change_digest": "digest-1"}, trusted_approval_rendering_hash="render", decision_idempotency_key="key", binding_hash="binding-hash", signed_envelope={"approval_binding_id": "binding-1", "tenant_id": "tenant-a", "approval_decision": "APPROVED"}, algorithm="HS256", signing_key_id="key", signature="sig"))
        db.add(ApprovalAuthorityProjectionV2(tenant_id="tenant-a", approval_request_id="approval-forged", state="APPROVED", uses_consumed=0, state_version=0, reconstruction_status="VERIFIED", history_head_sequence=1))
        db.flush()
        result = _decide(db, "binding-1")
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "approval_binding_mismatch"
    finally:
        db.close()


def test_database_edit_of_the_stored_mac_or_repository_does_not_widen_an_approval() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        grant = db.get(GitHubRepositoryMutationApproval, approval_id)
        assert grant is not None
        original_mac = grant.action_mac
        grant.action_mac = "0" * 64
        db.flush()
        assert _decide(db, approval_id)["reason"] == "approval_binding_mismatch"
        grant.action_mac = original_mac
        # Rewriting the stored request payload after issuance changes nothing:
        # the MAC is checked against the live request, not the stored copy.
        request = db.get(ApprovalRequest, "approval-1")
        assert request is not None
        request.request_payload = {"github_repository_action": {**request.request_payload["github_repository_action"], "model": "other"}}
        db.flush()
        assert _decide(db, approval_id, model="other")["reason"] == "approval_binding_mismatch"
        assert _decide(db, approval_id)["decision"] == "ALLOW"
    finally:
        db.close()


def test_repository_name_without_current_projection_does_not_permit_a_write() -> None:
    db = _db()
    try:
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", resource="github.com/acme/app", approval_binding_id="forged")
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "repository_resolution_unavailable"
    finally:
        db.close()


def test_mismatched_tenant_or_material_action_change_invalidates_approval() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        mismatch = _decide(db, approval_id, tenant_id="tenant-b")
        changed_model = _decide(db, approval_id, model="other")
        assert mismatch["decision"] == "BLOCK"
        assert changed_model["decision"] == "BLOCK"
        assert changed_model["reason"] == "approval_binding_mismatch"
    finally:
        db.close()


@pytest.mark.parametrize("mutation", [
    {"actor_id": "other"}, {"provider": "anthropic"}, {"tool_fingerprint_id": "wrong-tool"}, {"resource": "github.com/acme/other"},
    {"agent_id": "agent-2"}, {"ai_system_id": "ai-system-2"}, {"tool_schema_fingerprint": "schema-2"}, {"branch": "feature/other"},
    {"change_digest": "digest-2"},
    {"change_parameters": {"files": [{"path": "src/app.py", "content": "print('changed')\n"}]}},
    {"change_parameters": {"files": [{"path": "src/other.py", "content": "print('hello')\n"}]}},
])
def test_repository_mutation_uses_persisted_current_approval_not_forged_parameters(mutation: dict[str, object]) -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        result = _decide(db, approval_id, **mutation)
        assert result["decision"] == "BLOCK"
        assert result["reason"] in {"repository_resolution_unavailable", "approval_binding_mismatch"}
        # A refused mismatch does not spend the approval.
        assert _decide(db, approval_id)["decision"] == "ALLOW"
    finally:
        db.close()


def test_reads_remain_independent_from_mutation_approval() -> None:
    db = _db()
    try:
        _seed(db)
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/acme/app")
        assert result["decision"] == "ALLOW"
    finally:
        db.close()


def test_private_discovered_repository_without_explicit_current_governance_cannot_mutate_even_with_valid_binding() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        repository = db.scalar(select(GitHubRepository))
        assert repository is not None
        repository.governance_state = "UNKNOWN"
        repository.approved_scope_ref = None
        repository.policy_mapping_ref = None
        repository.policy_current = False
        result = _decide(db, approval_id)
        assert {key: result[key] for key in ("decision", "reason", "repository_id")} == {"decision": "BLOCK", "reason": "repository_not_explicitly_eligible", "repository_id": "R_1"}
    finally:
        db.close()


def test_expired_approval_cannot_authorize() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db, ttl_seconds=60, now=datetime.now(UTC) - timedelta(minutes=5))
        result = _decide(db, approval_id)
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "approval_binding_expired"
    finally:
        db.close()


@pytest.mark.parametrize("revocation", ["request_denied", "grant_revoked"])
def test_revoked_approval_cannot_authorize(revocation: str) -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        if revocation == "request_denied":
            request = db.get(ApprovalRequest, "approval-1")
            assert request is not None
            request.status, request.decision = "denied", "deny"
        else:
            revoke_github_repository_mutation_approval(db, tenant_id="tenant-a", approval_binding_id=approval_id, actor_user_id="approver-1")
        db.flush()
        assert _decide(db, approval_id)["decision"] == "BLOCK"
    finally:
        db.close()


def test_governance_change_after_issue_invalidates_outstanding_approvals() -> None:
    db = _db()
    try:
        repository = _seed(db)
        approval_id = _approval(db)
        save_github_repository_agent_policy(db, tenant_id="tenant-a", repository_id=repository.id, policy={"max_files_changed": 50}, expected_governance_version=repository.governance_version)
        assert _decide(db, approval_id)["reason"] == "approval_binding_mismatch"
    finally:
        db.close()


def test_paused_or_replaced_policy_mapping_immediately_invalidates_repository_governance() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        instance = db.get(PolicyPackInstance, "instance-1")
        assert instance is not None
        instance.state = "PAUSED"
        result = _decide(db, approval_id)
        assert {key: result[key] for key in ("decision", "reason", "repository_id")} == {"decision": "BLOCK", "reason": "repository_not_explicitly_eligible", "repository_id": "R_1"}
    finally:
        db.close()


def test_issue_requires_an_approved_request_an_authorized_role_and_a_binding_key(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _db()
    try:
        _seed(db)
        held = evaluate_github_repository_mutation(db, tenant_id="tenant-a", **PUSH)
        db.add(ApprovalRequest(id="approval-2", tenant_id="tenant-a", ai_system_id="ai-system-1", request_payload={"github_repository_action": held["canonical_action"]}, required_roles=["owner", "admin"], status="pending"))
        db.flush()
        with pytest.raises(ValueError, match="not approved"):
            issue_github_repository_mutation_approval(db, tenant_id="tenant-a", approval_request_id="approval-2", issued_by="u", approver_role="admin")
        request = db.get(ApprovalRequest, "approval-2")
        assert request is not None
        request.status, request.decision = "approved", "approve"
        with pytest.raises(PermissionError):
            issue_github_repository_mutation_approval(db, tenant_id="tenant-a", approval_request_id="approval-2", issued_by="u", approver_role="viewer")
        with pytest.raises(ValueError, match="not found"):
            issue_github_repository_mutation_approval(db, tenant_id="tenant-b", approval_request_id="approval-2", issued_by="u", approver_role="admin")
        monkeypatch.setattr(settings, "canonical_action_binding_key", "")
        with pytest.raises(ValueError, match="CANONICAL_ACTION_BINDING_KEY"):
            issue_github_repository_mutation_approval(db, tenant_id="tenant-a", approval_request_id="approval-2", issued_by="u", approver_role="admin")
    finally:
        db.close()


def test_rotated_or_missing_binding_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        monkeypatch.setattr(settings, "canonical_action_binding_key", "another-canonical-action-binding-key-0123456789")
        assert _decide(db, approval_id)["reason"] == "approval_binding_mismatch"
        monkeypatch.setattr(settings, "canonical_action_binding_key", "")
        assert _decide(db, approval_id)["reason"] == "approval_binding_mismatch"
    finally:
        db.close()


def test_mac_is_compared_in_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        calls: list[tuple[bytes, bytes]] = []
        original = service.hmac.compare_digest

        def spy(left: bytes, right: bytes) -> bool:
            calls.append((left, right))
            return original(left, right)

        monkeypatch.setattr(service.hmac, "compare_digest", spy)
        assert _decide(db, approval_id)["decision"] == "ALLOW"
        assert len(calls) == 1 and len(calls[0][0]) == 64
    finally:
        db.close()


def test_admin_actions_are_never_approvable() -> None:
    db = _db()
    try:
        _seed(db)
        held = evaluate_github_repository_mutation(db, tenant_id="tenant-a", **PUSH)
        canonical = {**held["canonical_action"], "action": "REPOSITORY_VISIBILITY_CHANGE"}
        db.add(ApprovalRequest(id="approval-3", tenant_id="tenant-a", ai_system_id="ai-system-1", request_payload={"github_repository_action": canonical}, required_roles=["admin"], status="approved", decision="approve"))
        db.flush()
        with pytest.raises(ValueError, match="never approvable"):
            issue_github_repository_mutation_approval(db, tenant_id="tenant-a", approval_request_id="approval-3", issued_by="u", approver_role="admin")
    finally:
        db.close()


def test_every_decision_is_recorded_as_evidence_without_content() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        allowed = _decide(db, approval_id)
        node = db.get(EvidenceNode, allowed["evidence_ref"])
        assert node is not None
        assert node.signal_type == "github_repository.agent_mutation_decision"
        assert node.payload["decision"] == "ALLOW"
        assert node.payload["approval"]["verification"] == "verified"
        assert node.payload["change"]["paths"] == ["src/app.py"]
        assert "print('hello')" not in str(node.payload)
        checks = [item["check"] for item in node.payload["checks"]]
        assert checks[:3] == ["repository_identity", "repository_state", "action_class"]
        assert "approval_binding" in checks
    finally:
        db.close()
