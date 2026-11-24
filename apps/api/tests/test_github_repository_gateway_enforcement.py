from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.session import Base
from app.db.models.action_integrity import ApprovalAuthorityProjectionV2, ApprovalBindingV2Extension
from app.db.models.policy import ApprovalRequest
from app.db.models.github_repository_access import GitHubRepository
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackDefinition, PolicyPackInstance
from app.services.github_repository_access_service import (
    evaluate_github_repository_mutation,
    persist_github_inventory_unit,
)
from app.services.policy_pack_platform.service import _normalize_assignment_targets


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
                "read_posture": "ALLOW",
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
    return repository


def _approval(db: Session, **extra: object) -> str:
    now = datetime.now(UTC)
    request = ApprovalRequest(id="approval-1", tenant_id="tenant-a", ai_system_id="ai-system-1", request_payload={}, required_roles=[], status="approved", decision="approve", authority_schema_version="2", decision_version=1)
    db.add(request)
    binding = ApprovalBindingV2Extension(approval_request_id="approval-1", tenant_id="tenant-a", binding_id="binding-1", decision_receipt_id="receipt-1", canonical_action_hash="hash", material_fields_hash="material", policy_epoch=1, use_limit=2, expires_at=now + timedelta(minutes=5), permitted_variation_envelope_id="variation-1", permitted_variation_hash="variation-hash", permitted_variation_envelope={"repository_id": "R_1", "host": "github.com", "action": "REPOSITORY_PUSH", "branch": "feature/demo", "actor_id": "actor-1", "executing_principal": "agent-1", "ai_system_id": "ai-system-1", "provider": "openai", "model": "gpt-5", "tool_fingerprint_id": "tool-1", "tool_schema_fingerprint": "schema-1", "target": "github.com/acme/app", "change_digest": "digest-1"}, trusted_approval_rendering_hash="render", decision_idempotency_key="key", binding_hash="binding-hash", signed_envelope={"approval_binding_id": "binding-1", "tenant_id": "tenant-a", "approval_decision": "APPROVED"}, algorithm="HS256", signing_key_id="key", signature="sig")
    projection = ApprovalAuthorityProjectionV2(tenant_id="tenant-a", approval_request_id="approval-1", state="APPROVED", uses_consumed=0, state_version=0, reconstruction_status="VERIFIED", history_head_sequence=1)
    db.add_all([binding, projection])
    db.flush()
    return str(extra.get("approval_binding_id") or "binding-1")


def test_exact_current_immutable_identity_and_bound_approval_allow_only_the_approved_mutation() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", resource="github.com/acme/app", branch="feature/demo", provider="openai", actor_id="actor-1", ai_system_id="ai-system-1", model="gpt-5", agent_id="agent-1", tool_fingerprint_id="tool-1", tool_schema_fingerprint="schema-1", change_digest="digest-1", approval_binding_id=approval_id)
        assert result["decision"] == "ALLOW"
        assert result["repository_id"] == "R_1"
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
        mismatch = evaluate_github_repository_mutation(db, tenant_id="tenant-b", action="REPOSITORY_PUSH", resource="github.com/acme/app", approval_binding_id=approval_id)
        changed_model = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", resource="github.com/acme/app", branch="feature/demo", provider="openai", actor_id="actor-1", ai_system_id="ai-system-1", model="other", agent_id="agent-1", tool_fingerprint_id="tool-1", tool_schema_fingerprint="schema-1", change_digest="digest-1", approval_binding_id=approval_id)
        assert mismatch["decision"] == "BLOCK"
        assert changed_model["decision"] == "BLOCK"
        assert changed_model["reason"] == "approval_binding_mismatch"
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
        repository = db.scalar(select(GitHubRepository))
        assert repository is not None
        repository.governance_state = "UNKNOWN"
        repository.approved_scope_ref = None
        repository.policy_mapping_ref = None
        repository.policy_current = False
        approval_id = _approval(db)
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", resource="github.com/acme/app", branch="feature/demo", provider="openai", actor_id="actor-1", ai_system_id="ai-system-1", model="gpt-5", agent_id="agent-1", tool_fingerprint_id="tool-1", tool_schema_fingerprint="schema-1", change_digest="digest-1", approval_binding_id=approval_id)
        assert result == {"decision": "BLOCK", "reason": "repository_not_explicitly_eligible", "repository_id": "R_1"}
    finally:
        db.close()


@pytest.mark.parametrize("mutation", [
    {"actor_id": "other"}, {"provider": "anthropic"}, {"tool_fingerprint_id": "wrong-tool"}, {"resource": "github.com/acme/other"},
])
def test_repository_mutation_uses_persisted_current_approval_not_forged_parameters(mutation: dict[str, str]) -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        kwargs = {"resource": "github.com/acme/app", "actor_id": "actor-1", "provider": "openai", "tool_fingerprint_id": "tool-1"} | mutation
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", branch="feature/demo", ai_system_id="ai-system-1", model="gpt-5", agent_id="agent-1", tool_schema_fingerprint="schema-1", change_digest="digest-1", approval_binding_id=approval_id, **kwargs)
        assert result["decision"] == "BLOCK"
        assert result["reason"] in {"repository_resolution_unavailable", "approval_binding_mismatch"}
    finally:
        db.close()


def test_expired_or_revoked_persisted_approval_cannot_authorize_private_discovered_repository() -> None:
    db = _db()
    try:
        _seed(db)
        approval_id = _approval(db)
        projection = db.get(ApprovalAuthorityProjectionV2, ("tenant-a", "approval-1"))
        assert projection is not None
        projection.state = "REVOKED"
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", resource="github.com/acme/app", branch="feature/demo", provider="openai", actor_id="actor-1", ai_system_id="ai-system-1", model="gpt-5", agent_id="agent-1", tool_fingerprint_id="tool-1", tool_schema_fingerprint="schema-1", change_digest="digest-1", approval_binding_id=approval_id)
        assert result["decision"] == "BLOCK"
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
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PUSH", resource="github.com/acme/app", branch="feature/demo", provider="openai", actor_id="actor-1", ai_system_id="ai-system-1", model="gpt-5", agent_id="agent-1", tool_fingerprint_id="tool-1", tool_schema_fingerprint="schema-1", change_digest="digest-1", approval_binding_id=approval_id)
        assert result == {"decision": "BLOCK", "reason": "repository_not_explicitly_eligible", "repository_id": "R_1"}
    finally:
        db.close()
