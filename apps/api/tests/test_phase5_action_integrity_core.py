from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


def _action(operation: str = "transfer") -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "tenant_id": "tenant-a",
        "action_id": "action-1",
        "chain_id": "chain-1",
        "correlation_id": "correlation-1",
        "parent_action_id": None,
        "actor_principal": "principal:alice",
        "executing_principal": "principal:agent",
        "represented_subjects": ["subject:customer-1"],
        "resource_scopes": ["resource:account-1"],
        "authority_context": "authority:delegated-1",
        "business_purpose": "purpose:payment",
        "environment": "production",
        "provider_runtime_context": "runtime:api",
        "action_semantics": {
            "action_class": "consequential",
            "operation": operation,
            "object_type": "payment",
            "tool_or_service_ref": "service:payments",
            "tool_fingerprint": "tool:v1",
            "safe_parameters": {"currency": "USD"},
            "represented_subject_refs": ["subject:customer-1"],
            "resource_refs": ["resource:account-1"],
            "counterparty_refs": [],
            "target_refs": ["target:recipient-1"],
            "destination_refs": ["destination:account-2"],
            "values_or_quantities": [{"value": "10", "currency": "USD"}],
            "authority_ref": "authority:delegated-1",
            "business_purpose_ref": "purpose:payment",
            "side_effect": "external_write",
            "persistence": "none",
            "environment": "production",
            "reversibility": "compensatable",
            "expected_outcome_ref": "outcome:payment-posted",
        },
        "domain_profile_ref": "profile:neutral",
        "domain_profile_hash": "a" * 64,
        "materiality_profile_ref": "phase5-p0",
        "materiality_profile_hash": "b" * 64,
        "resolver_versions": {},
        "policy_version_id": "policy:1",
        "policy_epoch": 1,
        "control_plan_id": "plan:1",
        "control_plan_digest": "c" * 64,
        "approval_requirement": "required",
        "delegation_digest": "d" * 64,
        "action_plan_binding": {
            "binding_type": "STANDALONE",
            "action_plan_id": None,
            "action_plan_digest": None,
            "action_plan_step_id": None,
            "action_plan_step_digest": None,
        },
        "unresolved_material": [],
        "evidence_refs": [],
        "created_at": "2026-08-24T00:00:00.000000Z",
    }


def test_canonical_action_v2_hash_is_deterministic_and_material_mutation_changes_it() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2, canonical_action_hash_v2

    first = _action()
    reordered = dict(reversed(list(first.items())))
    assert canonical_action_hash_v2(first) == canonical_action_hash_v2(reordered)
    assert canonical_action_hash_v2(first) != canonical_action_hash_v2(_action("refund"))
    action_with_alias = {**first, "schema_version": "2.0"}
    assert b'"schema_version":"canonical-ai-action/2.0"' in canonical_action_bytes_v2(action_with_alias)


def test_canonical_action_v2_requires_an_explicit_schema_version() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2

    action = _action()
    action.pop("schema_version")

    with pytest.raises(ValueError, match="schema version"):
        canonical_action_bytes_v2(action)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-08-24T00:00:00Z",
        "2026-08-24T00:00:00.000000+00:00",
        "2026-08-24T00:00:00.000000",
    ],
)
def test_canonical_action_v2_rejects_non_exact_utc_created_at(timestamp: str) -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2

    action = _action()
    action["created_at"] = timestamp

    with pytest.raises(ValueError, match="created_at"):
        canonical_action_bytes_v2(action)


@pytest.mark.parametrize("decimal", ["+1", "01", "1.0", "1e3", "-0"])
def test_canonical_action_v2_rejects_ambiguous_semantic_decimal_values(decimal: str) -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2

    action = _action()
    action["action_semantics"] = {
        **action["action_semantics"],
        "values_or_quantities": [{"value": decimal, "currency": "USD"}],
    }

    with pytest.raises(ValueError, match="decimal"):
        canonical_action_bytes_v2(action)


def test_canonical_v2_uses_nfc_and_jcs_utf16_key_order_golden_bytes() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_json_bytes

    assert canonical_json_bytes({"\ue000": "Cafe\u0301", "\U00010000": "\\\"/\n\u2028"}) == (
        b'{"\xf0\x90\x80\x80":"\\\\\\\"/\\n\xe2\x80\xa8","\xee\x80\x80":"Caf\xc3\xa9"}'
    )


def test_trusted_execution_action_rejects_overlong_identifiers_instead_of_truncating() -> None:
    from app.services.action_integrity.execution_authority import build_trusted_execution_action

    with pytest.raises(ValueError, match="action_id"):
        build_trusted_execution_action(
            tenant_id="tenant-a",
            action_id="a" * 65,
            chain_id="chain-1",
            actor_principal="user:alice",
            executing_principal="service:test",
            operation="write",
            tool_or_service_ref="service:test",
            tool_fingerprint="f" * 64,
            parameter_hash="p" * 64,
            target_ref="resource:test",
            policy_epoch=1,
            approval_requirement="not_required",
            policy_version_id="policy:1",
            now=NOW,
        )


def test_materiality_hash_normalizes_unordered_set_collections() -> None:
    from app.services.action_integrity.materiality import material_fields_hash

    first = _action()
    first["resource_scopes"] = ["resource:z", "resource:a"]
    first["action_semantics"] = {
        **first["action_semantics"],
        "resource_refs": ["resource:z", "resource:a"],
    }
    reordered = _action()
    reordered["resource_scopes"] = ["resource:a", "resource:z"]
    reordered["action_semantics"] = {
        **reordered["action_semantics"],
        "resource_refs": ["resource:a", "resource:z"],
    }

    assert material_fields_hash(first) == material_fields_hash(reordered)


def test_materiality_rejects_duplicate_unordered_set_elements_after_nfc() -> None:
    from app.services.action_integrity.materiality import material_fields_hash

    action = _action()
    action["represented_subjects"] = ["subject:Cafe\u0301", "subject:Caf\u00e9"]

    with pytest.raises(ValueError, match="duplicate canonical"):
        material_fields_hash(action)


@pytest.mark.parametrize("value", [-(2**53), 2**53])
def test_canonical_v2_rejects_integers_outside_the_interoperable_range(value: int) -> None:
    from app.services.action_integrity.canonical_v2 import canonical_json_bytes

    with pytest.raises(ValueError, match="integer"):
        canonical_json_bytes({"value": value})


def test_canonical_v2_rejects_over_count_collections() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_json_bytes

    with pytest.raises(ValueError, match="collection"):
        canonical_json_bytes({"items": list(range(129))})


def test_canonical_v2_rejects_over_depth_values() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_json_bytes

    value: object = "leaf"
    for _ in range(65):
        value = [value]

    with pytest.raises(ValueError, match="depth"):
        canonical_json_bytes(value)


def test_profile_selection_and_policy_epoch_fail_closed_on_tenant_or_expiry() -> None:
    from app.services.action_integrity.domain_profiles import DomainSemanticProfile, select_profile

    profile = DomainSemanticProfile(
        profile_id="neutral",
        tenant_id="tenant-a",
        version="1",
        status="reviewed",
        issued_at=NOW,
        effective_at=NOW,
        expires_at=NOW + timedelta(days=1),
        content={"subject_types": ["person"]},
    )
    selected = select_profile(profile, tenant_id="tenant-a", policy_epoch=1, now=NOW)
    assert selected.policy_epoch == 1
    with pytest.raises(ValueError):
        select_profile(profile, tenant_id="tenant-b", policy_epoch=1, now=NOW)
    with pytest.raises(ValueError):
        select_profile(profile, tenant_id="tenant-a", policy_epoch=0, now=NOW)


def test_permit_is_single_use_and_rechecks_material_before_executor() -> None:
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.models.evidence import EvidenceNode
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        session_local = sessionmaker(bind=engine)
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a", is_active=True))
            db.add_all([TenantPolicyEpoch(tenant_id="tenant-a", epoch=1), TenantActionIntegrityRollout(tenant_id="tenant-a", mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id="tenant-a")
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(db, provider=provider, tenant_id="tenant-a", action={**_action(), "approval_requirement": "not_required"}, now=NOW)
        with session_local.begin() as db:
            service = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: NOW)
            permit = service.issue(tenant_id="tenant-a", action=fixture.action, expires_at=NOW + timedelta(minutes=1), rollout_mode="AUTHORITATIVE", decision_receipt_id=fixture.decision_receipt_id)
            assert service.claim(permit.permit_id, tenant_id="tenant-a", action=fixture.action, claimed_by_ref="test") is True
            assert service.claim(permit.permit_id, tenant_id="tenant-a", action=fixture.action, claimed_by_ref="test") is False
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_material_mutation_does_not_invoke_executor() -> None:
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        session_local = sessionmaker(bind=engine)
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a", is_active=True))
            db.add_all([TenantPolicyEpoch(tenant_id="tenant-a", epoch=1), TenantActionIntegrityRollout(tenant_id="tenant-a", mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id="tenant-a")
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(db, provider=provider, tenant_id="tenant-a", action={**_action(), "approval_requirement": "not_required"}, now=NOW)
        with session_local.begin() as db:
            service = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: NOW)
            permit = service.issue(tenant_id="tenant-a", action=fixture.action, expires_at=NOW + timedelta(minutes=1), rollout_mode="AUTHORITATIVE", decision_receipt_id=fixture.decision_receipt_id)
            calls: list[str] = []
            invoked, _ = service.execute(permit.permit_id, tenant_id="tenant-a", action={**_action("refund"), "approval_requirement": "not_required"}, claimed_by_ref="test", executor=lambda: calls.append("called"))
            assert not invoked
            assert calls == []
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.mark.parametrize("mode", ["DISABLED", "OBSERVE", "SHADOW"])
def test_non_authoritative_rollout_modes_preserve_the_generic_final_callback(tmp_path, mode: str) -> None:
    from app.db.models.action_integrity import TenantActionIntegrityRollout
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import (
        build_trusted_execution_action,
        install_execution_authority,
        invoke_final_seam,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / f'rollout-{mode}.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug=f"tenant-a-{mode.lower()}", is_active=True))
            db.add(TenantActionIntegrityRollout(tenant_id="tenant-a", mode=mode, policy_epoch=1))
        provider = LocalSigningKeyProvider(development=True)
        with session_local() as db:
            action = build_trusted_execution_action(
                tenant_id="tenant-a", action_id="action-1", chain_id="chain-1", actor_principal="user:a",
                executing_principal="service:test", operation="write", tool_or_service_ref="test:tool",
                tool_fingerprint="f" * 64, parameter_hash="p" * 64, target_ref="resource:test",
                policy_epoch=1, approval_requirement="not_required", policy_version_id="policy-1", now=NOW,
            )
            assert install_execution_authority(db, tenant_id="tenant-a", action=action, seam_ref="test.seam", signing_provider=provider) is None
            calls: list[str] = []
            assert invoke_final_seam(db, seam_ref="test.seam", executor=lambda: calls.append("called") or "ok") == "ok"
            assert calls == ["called"]
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.mark.parametrize("seam_ref", [
    "llm.provider.json", "llm.provider.text", "mcp.registered_executor", "agui.actual_executor",
    "endpoint.platform_invocation", "itsm.http_post", "remediation.apply", "remediation.rollback",
])
def test_authoritative_lifecycle_installs_a_committed_permit_before_final_callback(
    tmp_path,
    seam_ref: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.db.models.action_integrity import ExecutionPermitV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import (
        install_generic_seam_authority,
        invoke_final_seam,
        build_trusted_execution_action,
    )
    from app.services.action_integrity.canonical_v2 import domain_hash
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority
    import app.services.action_integrity.execution_authority as execution_authority

    def _unexpected_pre_seam_build(**_kwargs):
        raise AssertionError("stored decisions must not trigger a second pre-seam evaluation")

    monkeypatch.setattr(
        execution_authority,
        "_persist_generic_pre_seam_decision",
        _unexpected_pre_seam_build,
    )

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'authoritative-lifecycle.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-authoritative", is_active=True))
            db.add_all([TenantPolicyEpoch(tenant_id="tenant-a", epoch=1), TenantActionIntegrityRollout(tenant_id="tenant-a", mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id="tenant-a")
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id="tenant-a",
                action=build_trusted_execution_action(
                    tenant_id="tenant-a", action_id="action-1", chain_id="chain-1", actor_principal="user:a",
                    executing_principal="service:test", operation="write", tool_or_service_ref="test:tool",
                    tool_fingerprint=domain_hash("hawk:closed-seam-fingerprint:v1", {"seam": seam_ref, "tool": "test:tool"}),
                    parameter_hash="p" * 64, target_ref="resource:test", policy_epoch=1,
                    approval_requirement="not_required", policy_version_id="phase5:persisted-rollout", now=NOW,
                ), now=NOW,
            )
        with session_local() as db:
            db.info["phase5_signing_provider"] = provider
            handle = install_generic_seam_authority(
                db, tenant_id="tenant-a", seam_ref=seam_ref, action_id="action-1", chain_id="chain-1",
                actor_principal="user:a", executing_principal="service:test", operation="write", tool_or_service_ref="test:tool",
                parameter_hash="p" * 64, target_ref="resource:test", decision_receipt_id=fixture.decision_receipt_id, now=lambda: NOW,
            )
            assert handle is not None and handle.permit_id
            calls: list[str] = []
            assert invoke_final_seam(db, seam_ref=seam_ref, executor=lambda: calls.append("called") or "ok") == "ok"
            assert calls == ["called"]
        with session_local() as db:
            permit = db.get(ExecutionPermitV2, handle.permit_id)
            assert permit is not None and permit.state == "CONSUMED"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_authoritative_generic_approval_is_bound_to_a_stored_decision_and_can_issue_a_permit(tmp_path) -> None:
    from types import SimpleNamespace

    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.ai_system import AISystem
    from app.db.models.policy import ApprovalRequest
    from app.db.models.tenant import Tenant
    from app.db.models.user import User
    from app.db.session import Base
    from app.services.action_integrity.approval_service import decide_approval_request_v2
    from app.services.action_integrity.execution_authority import ApprovalRequiredError, build_trusted_execution_action, install_generic_seam_authority
    from app.services.action_integrity.canonical_v2 import domain_hash
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'auto-profile-approval.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Auto profile", slug="auto-profile", is_active=True)
            owner = User(email="owner-auto-profile@example.test", hashed_password="x", full_name="Owner", is_active=True)
            db.add_all([tenant, owner])
            db.flush()
            system = AISystem(tenant_id=tenant.id, name="auto-profile", description="test", risk_tier="HIGH", status="active", metadata_json={})
            db.add(system)
            db.add_all([TenantPolicyEpoch(tenant_id=tenant.id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1)])
            db.flush()
            tenant_id, system_id, owner_id = tenant.id, system.id, owner.id
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        provider.add_key(purpose="approval_binding_signing", tenant_id=tenant_id, key_id="approval", secret=b"a" * 32)
        provider.add_key(purpose="permitted_variation_signing", tenant_id=tenant_id, key_id="variation", secret=b"v" * 32)

        kwargs = {
            "tenant_id": tenant_id, "seam_ref": "llm.provider.json", "action_id": "approval-action-1", "chain_id": "approval-chain-1",
            "actor_principal": "user:requester", "executing_principal": "service:llm", "operation": "generate",
            "tool_or_service_ref": "provider:llm", "parameter_hash": "p" * 64, "target_ref": "target:llm",
            "ai_system_id": system_id, "approval_requirement": "required",
        }
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=build_trusted_execution_action(
                    tenant_id=tenant_id, action_id="approval-action-1", chain_id="approval-chain-1",
                    actor_principal="user:requester", executing_principal="service:llm", operation="generate",
                    tool_or_service_ref="provider:llm",
                    tool_fingerprint=domain_hash("hawk:closed-seam-fingerprint:v1", {"seam": "llm.provider.json", "tool": "provider:llm"}),
                    parameter_hash="p" * 64, target_ref="target:llm", policy_epoch=1,
                    approval_requirement="required", policy_version_id="phase5:persisted-rollout", now=NOW,
                ),
                now=NOW,
                authoritative_decision="REQUIRE_APPROVAL",
            )
        # The generic seam discovers the unique exact stored decision from
        # server-built route material; no receipt identifier crosses a client
        # or generic-call boundary.
        kwargs.update(now=lambda: NOW)
        with session_local() as db:
            db.info["phase5_signing_provider"] = provider
            with pytest.raises(ApprovalRequiredError) as blocked:
                install_generic_seam_authority(db, **kwargs)
            request_id = blocked.value.approval_request_id
        with session_local.begin() as db:
            request = db.get(ApprovalRequest, request_id)
            assert request is not None
            assert request.status == "pending"
            payload = dict(request.request_payload)
            assert payload["profile_selection_id"]
            assert len(payload["profile_selection_hash"]) == 64
            assert payload["control_selection_id"] == fixture.control_selection_id
            assert payload["decision_receipt_id"] == fixture.decision_receipt_id
            assert request.decision_receipt_id == fixture.decision_receipt_id
            result = decide_approval_request_v2(
                db, tenant_id=tenant_id, approval_request_id=request.id,
                actor=SimpleNamespace(id=owner_id, role="owner"),
                dto=SimpleNamespace(decision="approve", expected_version=1, idempotency_key="auto-profile-approval-0001", reason="approved"),
                signing_provider=provider,
                now=NOW,
            )
            assert result.binding_id
        with session_local() as db:
            db.info["phase5_signing_provider"] = provider
            handle = install_generic_seam_authority(db, **kwargs)
            assert handle is not None
            assert handle.permit_id
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_generic_final_seam_records_provider_output_as_unverified_and_rejects_explicit_noop(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A generic callback result is not independent proof of an executed action."""
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.evidence import DecisionReceipt, EvidenceNode
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import (
        build_trusted_execution_action,
        install_generic_seam_authority,
        invoke_final_seam,
    )
    from app.services.action_integrity.canonical_v2 import domain_hash
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority
    import app.services.action_integrity.execution_authority as execution_authority

    observed: list[dict[str, object]] = []

    def capture_receipt(*_args, **kwargs):
        return type("Receipt", (), {"receipt_id": "generic-receipt", "execution_attempt_id": kwargs["execution_attempt_id"], "tenant_id": kwargs["tenant_id"], "decision_receipt_id": kwargs["decision_receipt_id"], "execution_status": kwargs["execution_status"]})(), None

    def capture_lifecycle(*_args, **kwargs):
        observed.append(kwargs)
        return None

    from app.core.config import settings

    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr("app.services.receipt_service.create_execution_receipt", capture_receipt)
    monkeypatch.setattr(
        "app.services.action_integrity.lifecycle_persistence.persist_execution_receipt_v2_and_comparison",
        capture_lifecycle,
    )

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'generic-unverified.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-generic-unverified", is_active=True))
            db.add_all([TenantPolicyEpoch(tenant_id="tenant-a", epoch=1), TenantActionIntegrityRollout(tenant_id="tenant-a", mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id="tenant-a")
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id="tenant-a",
                action=build_trusted_execution_action(
                    tenant_id="tenant-a", action_id="action-1", chain_id="chain-1", actor_principal="user:a",
                    executing_principal="service:test", operation="write", tool_or_service_ref="test:tool",
                    tool_fingerprint=domain_hash("hawk:closed-seam-fingerprint:v1", {"seam": "endpoint.platform_invocation", "tool": "test:tool"}),
                    parameter_hash="p" * 64, target_ref="resource:test", policy_epoch=1,
                    approval_requirement="not_required", policy_version_id="phase5:persisted-rollout", now=NOW,
                ), now=NOW,
            )
            decision = db.get(DecisionReceipt, fixture.decision_receipt_id)
            assert decision is not None
            canonical_evidence = db.get(EvidenceNode, decision.canonical_action_evidence_node_id)
            assert canonical_evidence is not None
            canonical_evidence.payload = {"canonical_action": fixture.action}
        with session_local() as db:
            db.info["phase5_signing_provider"] = provider
            handle = install_generic_seam_authority(
                db, tenant_id="tenant-a", seam_ref="endpoint.platform_invocation", action_id="action-1", chain_id="chain-1",
                actor_principal="user:a", executing_principal="service:test", operation="write", tool_or_service_ref="test:tool",
                parameter_hash="p" * 64, target_ref="resource:test", decision_receipt_id=fixture.decision_receipt_id, now=lambda: NOW,
            )
            assert handle is not None
            db.commit()
            assert invoke_final_seam(db, seam_ref="endpoint.platform_invocation", executor=lambda: {"performed": False}) == {"performed": False}
        assert observed
        captured = observed[-1]
        assert captured["execution_receipt"].execution_status == "unverified"
        assert captured["evidence_quality"] == "PROVIDER_REPORTED"
        assert "generic_provider_execution_unverified" in captured["executed"]["unresolved_material"]
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_delegated_child_cannot_widen_parent_authority() -> None:
    from app.services.action_integrity.complex_actions import delegated_child_is_attenuated

    parent = {"resources": ["resource:a"], "operations": ["transfer"], "max_value": "10"}
    assert delegated_child_is_attenuated(parent, {"resources": ["resource:a"], "operations": ["transfer"], "max_value": "9"})
    assert not delegated_child_is_attenuated(parent, {"resources": ["resource:a", "resource:b"], "operations": ["transfer"], "max_value": "9"})


def test_production_lifecycle_writers_persist_plan_and_reject_widened_child(tmp_path) -> None:
    from app.db.models.action_integrity import ActionPlanStepV2, ActionPlanV2, DelegationContextV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import (
        persist_action_plan_v2,
        register_delegated_child_v2,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'lifecycle-writers.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-lifecycle", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="action_plan_signing", tenant_id="tenant-a", key_id="plan", secret=b"z" * 32)
        provider.add_key(purpose="delegation_context_signing", tenant_id="tenant-a", key_id="delegation", secret=b"d" * 32)
        with session_local.begin() as db:
            plan = persist_action_plan_v2(
                db, provider=provider, tenant_id="tenant-a", parent_action_id="parent-1",
                steps=[{"step_id": "step-1", "child_action_id": "child-1", "authority_mode": "SCOPED_PARENT_PERMIT", "unbound_material_fields_hash": "a" * 64}],
                issued_at=NOW, expires_at=NOW + timedelta(minutes=1),
            )
            assert db.scalar(select(ActionPlanV2).where(ActionPlanV2.plan_id == plan.plan_id)) is plan
            assert db.scalar(select(ActionPlanStepV2).where(ActionPlanStepV2.plan_id == plan.plan_id)) is not None
            context = register_delegated_child_v2(
                db, provider=provider, tenant_id="tenant-a", parent_action_id="parent-1",
                delegated_action_id="child-1", parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["transfer"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["transfer"], "max_value": "9"},
                source_principal_ref="agent:parent", destination_principal_ref="agent:child", expires_at=NOW + timedelta(minutes=1), issued_at=NOW,
            )
            assert db.scalar(select(DelegationContextV2).where(DelegationContextV2.delegation_context_id == context.delegation_context_id)) is context
            with pytest.raises(PermissionError, match="widens"):
                register_delegated_child_v2(
                    db, provider=provider, tenant_id="tenant-a", parent_action_id="parent-1",
                    delegated_action_id="widened-child-1", parent_delegation_context_id=None,
                    parent_scope={"resources": ["resource:a"], "operations": ["transfer"], "max_value": "10"},
                    child_scope={"resources": ["resource:a", "resource:b"], "operations": ["transfer"], "max_value": "9"},
                    source_principal_ref="agent:parent", destination_principal_ref="agent:child", expires_at=NOW + timedelta(minutes=1), issued_at=NOW,
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_lifecycle_effect_and_outcome_writers_freeze_signed_observations(tmp_path) -> None:
    """Phase 5 effect/outcome facts must be independently signed durable rows."""
    from app.db.models.action_integrity import ExpectedOutcomeV2, OutcomeVerificationV2, PersistentEffectV2
    from app.db.models.evidence import EvidenceNode
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import (
        persist_expected_outcome_v2,
        persist_outcome_verification_v2,
        persist_persistent_effect_v2,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'effect-outcome-writers.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-effects", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="outcome_verification_signing", tenant_id="tenant-a", key_id="outcome", secret=b"o" * 32)
        provider.add_key(purpose="persistent_effect_signing", tenant_id="tenant-a", key_id="effect", secret=b"e" * 32)
        with session_local.begin() as db:
            expected_evidence = EvidenceNode(tenant_id="tenant-a", correlation_id="expected", node_type="test", signal_type="test", label="expected", payload={})
            effect_evidence = EvidenceNode(tenant_id="tenant-a", correlation_id="effect", node_type="test", signal_type="test", label="effect", payload={})
            outcome_evidence = EvidenceNode(tenant_id="tenant-a", correlation_id="outcome", node_type="test", signal_type="test", label="outcome", payload={})
            db.add_all([expected_evidence, effect_evidence, outcome_evidence]); db.flush()
            expected = persist_expected_outcome_v2(
                db, provider=provider, tenant_id="tenant-a", action_id="action-1",
                expected_state_hash="e" * 64, verification_deadline=NOW + timedelta(minutes=5),
                issued_at=NOW, evidence_refs=[expected_evidence.id],
            )
            effect = persist_persistent_effect_v2(
                db, provider=provider, tenant_id="tenant-a", action_id="action-1", attempt_id="attempt-1",
                execution_receipt_id=None, downstream_object_hash="d" * 64, expected_object_state_hash="e" * 64,
                state="APPLIED", expires_at=NOW + timedelta(minutes=5), issued_at=NOW,
                evidence_refs=[effect_evidence.id],
            )
            outcome = persist_outcome_verification_v2(
                db, provider=provider, tenant_id="tenant-a", action_id="action-1", attempt_id="attempt-1",
                outcome_contract_id=expected.outcome_contract_id, execution_receipt_id=None, result="MATCHED",
                verification_source_set_hash="s" * 64, evidence_quality="VERIFIED", evaluated_at=NOW,
                evidence_refs=[outcome_evidence.id],
            )
            db.flush()
            assert db.get(ExpectedOutcomeV2, expected.id) is expected
            assert db.get(PersistentEffectV2, effect.id) is effect
            assert db.get(OutcomeVerificationV2, outcome.id) is outcome
            assert expected.signed_envelope["evidence_refs"] == [expected_evidence.id]
            assert effect.signed_envelope["issued_at"] == NOW.isoformat()
            assert outcome.signed_envelope["evaluated_at"] == NOW.isoformat()
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_execution_lifecycle_persists_independently_observed_material_and_marks_drift(tmp_path) -> None:
    from types import SimpleNamespace

    from app.db.models.action_integrity import ExecutionComparisonV2, ExecutionReceiptV2Extension
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import persist_execution_receipt_v2_and_comparison
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'executed-observation.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-observed", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="execution_receipt_signing", tenant_id="tenant-a", key_id="receipt", secret=b"r" * 32)
        provider.add_key(purpose="execution_comparison_signing", tenant_id="tenant-a", key_id="comparison", secret=b"c" * 32)
        authorized = {**_action(), "approval_requirement": "not_required"}
        executed = _action("refund")
        executed["approval_requirement"] = "not_required"
        receipt = SimpleNamespace(
            receipt_id="receipt-1", tenant_id="tenant-a", execution_attempt_id="attempt-1",
            execution_status="success", decision_receipt_id=None,
        )
        with session_local.begin() as db:
            extension, comparison = persist_execution_receipt_v2_and_comparison(
                db, provider=provider, execution_receipt=receipt, authorized=authorized, executed=executed,
                permit_id="permit-1", issued_at=NOW,
            )
            db.flush()
            assert db.get(ExecutionReceiptV2Extension, extension.receipt_id) is extension
            assert db.get(ExecutionComparisonV2, comparison.id) is comparison
            assert comparison.result == "DRIFTED"
            assert extension.actual_material_fields_hash != extension.canonical_action_hash
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_six_declarative_profiles_are_present_and_non_authorizing() -> None:
    profiles = Path(__file__).resolve().parents[1] / "app/services/action_integrity/profiles"
    files = sorted(path for path in profiles.glob("*.json") if not path.name.startswith("._"))
    assert len(files) == 6
    for path in files:
        payload = json.loads(path.read_text())
        assert payload["status"] == "reviewed"
        assert "policy_decision" not in payload


def test_signing_provider_enforces_purpose_tenant_and_key_lifecycle() -> None:
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="k1", secret=b"x" * 32)
    signature = provider.sign(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="k1", payload=b"body")
    assert provider.verify(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="k1", payload=b"body", signature=signature)
    assert not provider.verify(purpose="approval_binding_signing", tenant_id="tenant-a", key_id="k1", payload=b"body", signature=signature)
    provider.set_state(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="k1", state="revoked")
    assert provider.metadata(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="k1")["state"] == "revoked"


def test_kms_adapter_selects_an_active_asymmetric_key_without_a_local_fallback() -> None:
    from app.services.action_integrity.signing import KmsHsmSigningKeyProvider, active_key_id

    class FakeHsm:
        def active_key_id(self, *, purpose: str, tenant_id: str) -> str:
            assert purpose == "decision_receipt_signing"
            assert tenant_id == "tenant-a"
            return "hsm-key"

        def metadata(self, *, purpose: str, tenant_id: str, key_id: str) -> dict[str, str]:
            return {"algorithm": "ES256", "key_id": key_id, "state": "active"}

        def sign(self, *, purpose: str, tenant_id: str, key_id: str, payload: bytes) -> str:
            return "opaque-hsm-signature"

        def verify(self, *, purpose: str, tenant_id: str, key_id: str, payload: bytes, signature: str) -> bool:
            return signature == "opaque-hsm-signature"

    provider = KmsHsmSigningKeyProvider(FakeHsm())
    assert active_key_id(provider, purpose="decision_receipt_signing", tenant_id="tenant-a") == "hsm-key"
    with pytest.raises(ValueError, match="signature"):
        provider.sign(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="hsm-key", payload=b"proof")


def test_v2_approval_binding_is_tenant_epoch_expiry_and_use_bound() -> None:
    from app.services.action_integrity.approval_binding import ApprovalBindingV2

    binding = ApprovalBindingV2("request-1", "tenant-a", "decision-1", "native-1", "a" * 64, "b" * 64, 4, NOW + timedelta(minutes=1))
    assert binding.eligible(tenant_id="tenant-a", policy_epoch=4, now=NOW)
    assert not binding.eligible(tenant_id="tenant-b", policy_epoch=4, now=NOW)
    assert not binding.eligible(tenant_id="tenant-a", policy_epoch=3, now=NOW)
    assert not binding.eligible(tenant_id="tenant-a", policy_epoch=4, now=NOW + timedelta(minutes=2))
    assert len(binding.binding_hash) == 64


def test_phase5_coverage_uses_the_existing_union_and_counts_unknown_in_denominator() -> None:
    from app.core.control_coverage import PHASE5_METHODOLOGY_VERSION, PHASE5_V2_DIMENSIONS, Phase5CoverageDimension, phase5_coverage_counts

    assert len(PHASE5_V2_DIMENSIONS) == 13
    assert PHASE5_METHODOLOGY_VERSION == "control-coverage/2.0"
    assert tuple(item.value for item in Phase5CoverageDimension) == PHASE5_V2_DIMENSIONS
    counts = phase5_coverage_counts({"subject_binding": "covered", "resource_binding": "unknown"})
    assert counts["subject_binding"]["denominator"] == 1
    assert counts["resource_binding"]["unknown"] == 1
    assert counts["resource_binding"]["denominator"] == 1
    assert counts["purpose_binding"]["denominator"] == 1


def test_signed_action_plan_binds_child_order_and_rejects_mutated_step() -> None:
    from app.services.action_integrity.complex_actions import issue_action_plan, verify_action_plan
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="action_plan_signing", tenant_id="tenant-a", key_id="plan", secret=b"z" * 32)
    plan = issue_action_plan(
        provider,
        tenant_id="tenant-a",
        parent_action_id="root-action",
        steps=[{"step_id": "step-1", "child_action_id": "child-1", "authority_mode": "SEPARATE_DECISION", "unbound_material_fields_hash": "a" * 64}],
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    assert verify_action_plan(provider, plan)
    plan["steps"][0]["child_action_id"] = "child-mutated"
    assert not verify_action_plan(provider, plan)
