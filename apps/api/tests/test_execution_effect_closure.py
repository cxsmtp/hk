from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-effect-closure")
os.environ.setdefault("CONNECTOR_SECRETS_KEY", "test-connector-secrets-key")
os.environ.setdefault("CONNECTOR_SECRETS_KDF_SALT", "test-connector-secrets-salt")


NOW = datetime(2026, 8, 30, 12, tzinfo=timezone.utc)


def _action(tenant_id: str, *, action_id: str = "effect-action-1", target: str = "target:synthetic") -> dict:
    return {
        "schema_version": "2.0",
        "tenant_id": tenant_id,
        "action_id": action_id,
        "chain_id": "effect-chain-1",
        "correlation_id": f"correlation:{action_id}",
        "parent_action_id": None,
        "actor_principal": "user:requester",
        "executing_principal": "service:effect-test",
        "represented_subjects": ["subject:synthetic"],
        "resource_scopes": ["resource:synthetic"],
        "authority_context": "authority:effect-test",
        "business_purpose": "purpose:synthetic-notification",
        "environment": "production",
        "provider_runtime_context": "runtime:synthetic-effect",
        "action_semantics": {
            "action_class": "consequential",
            "operation": "create",
            "object_type": "synthetic-notification",
            "tool_or_service_ref": "synthetic:effect-provider",
            "tool_fingerprint": "f" * 64,
            "safe_parameters": {"parameter_hash": "p" * 64},
            "represented_subject_refs": ["subject:synthetic"],
            "resource_refs": ["resource:synthetic"],
            "counterparty_refs": [],
            "target_refs": [target],
            "destination_refs": ["destination:tenant-local"],
            "values_or_quantities": [{"value": "1", "unit": "synthetic-notification"}],
            "authority_ref": "authority:effect-test",
            "business_purpose_ref": "purpose:synthetic-notification",
            "side_effect": "durable_object_create",
            "persistence": "durable",
            "environment": "production",
            "reversibility": "compensatable",
            "expected_outcome_ref": "outcome:synthetic-created",
        },
        "domain_profile_ref": "placeholder",
        "domain_profile_hash": "a" * 64,
        "materiality_profile_ref": "phase5-p0",
        "materiality_profile_hash": "e" * 64,
        "resolver_versions": {},
        "policy_version_id": "policy:effect",
        "policy_epoch": 1,
        "control_plan_id": "placeholder",
        "control_plan_digest": "b" * 64,
        "approval_requirement": "not_required",
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
        "created_at": "2026-08-30T12:00:00.000000Z",
    }


@pytest.fixture()
def effect_env(tmp_path):
    from app.db import models as _models  # noqa: F401
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.action_integrity.effect_closure import EffectClosureService
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'effect-closure.sqlite3'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    db = Session()
    tenant = Tenant(name="Effect tenant", slug="effect-tenant", is_active=True)
    other = Tenant(name="Other effect tenant", slug="other-effect-tenant", is_active=True)
    db.add_all([tenant, other])
    db.flush()
    db.add_all([
        TenantPolicyEpoch(tenant_id=tenant.id, epoch=1),
        TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1),
    ])
    provider = LocalSigningKeyProvider(development=True)
    add_stored_authority_keys(provider, tenant_id=tenant.id)
    for purpose, key_id, secret in (
        ("effect_reservation_signing", "effect-reservation", b"r" * 32),
        ("execution_receipt_signing", "execution-receipt", b"x" * 32),
        ("execution_comparison_signing", "execution-comparison", b"c" * 32),
    ):
        provider.add_key(purpose=purpose, tenant_id=tenant.id, key_id=key_id, secret=secret)
    clock = [NOW]

    def issue(action: dict, suffix: str):
        fixture = seed_stored_allow_authority(
            db,
            provider=provider,
            tenant_id=tenant.id,
            action=action,
            now=clock[0],
            decision_receipt_id=f"decision-effect-{suffix}",
        )
        permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: clock[0]).issue(
            tenant_id=tenant.id,
            action=fixture.action,
            expires_at=clock[0] + timedelta(minutes=3),
            rollout_mode="AUTHORITATIVE",
            decision_receipt_id=fixture.decision_receipt_id,
        )
        db.flush()
        return fixture.action, fixture.decision_receipt_id, permit

    action, decision_id, permit = issue(_action(tenant.id), "one")
    service = EffectClosureService(db, signing_provider=provider, now=lambda: clock[0])
    try:
        yield {
            "db": db,
            "engine": engine,
            "Session": Session,
            "tenant": tenant,
            "other": other,
            "provider": provider,
            "clock": clock,
            "action": action,
            "decision_id": decision_id,
            "permit": permit,
            "service": service,
            "issue": issue,
        }
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _reserve(env, *, action=None, permit=None, decision_id=None, **kwargs):
    action = action or env["action"]
    permit = permit or env["permit"]
    return env["service"].reserve(
        tenant_id=env["tenant"].id,
        action=action,
        permit_id=permit.permit_id,
        decision_receipt_id=decision_id or env["decision_id"],
        provider_ref="synthetic:effect-provider",
        **kwargs,
    )


def _prepare_claim(env, reservation, *, action=None, worker="worker:one"):
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority

    action = action or env["action"]
    prepared = env["service"].prepare(
        tenant_id=env["tenant"].id,
        reservation_id=reservation.id,
        candidate_action=action,
        expected_version=reservation.state_version,
    )
    assert prepared.state == "PREPARED"
    assert ExecutionPermitAuthority(
        env["db"], signing_provider=env["provider"], now=lambda: env["clock"][0]
    ).claim(
        env["permit"].permit_id,
        tenant_id=env["tenant"].id,
        action=action,
        claimed_by_ref=worker,
    )
    env["db"].commit()
    return prepared


def test_reservation_is_durable_and_tenant_scoped(effect_env) -> None:
    env = effect_env
    reservation = _reserve(env)
    env["db"].commit()
    with env["Session"]() as fresh:
        from app.services.action_integrity.effect_closure import EffectClosureService

        service = EffectClosureService(fresh, signing_provider=env["provider"], now=lambda: env["clock"][0])
        assert service.get(tenant_id=env["tenant"].id, reservation_id=reservation.id).state == "RESERVED"
        with pytest.raises(PermissionError, match="tenant"):
            service.get(tenant_id=env["other"].id, reservation_id=reservation.id)


def test_manifest_mutation_before_commit_invalidates_reservation(effect_env) -> None:
    env = effect_env
    reservation = _reserve(env)
    mutated = deepcopy(env["action"])
    mutated["action_semantics"] = dict(mutated["action_semantics"])
    mutated["action_semantics"]["target_refs"] = ["target:different"]
    with pytest.raises(PermissionError, match="manifest"):
        env["service"].prepare(
            tenant_id=env["tenant"].id,
            reservation_id=reservation.id,
            candidate_action=mutated,
            expected_version=reservation.state_version,
        )
    assert reservation.state == "RESERVED"


def test_normal_commit_produces_exactly_one_effect(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    provider = SyntheticEffectProvider(mode="normal")
    result = env["service"].execute_durably(
        tenant_id=env["tenant"].id,
        reservation_id=reservation.id,
        expected_version=prepared.state_version,
        worker_ref="worker:one",
        provider=provider,
    )
    assert result.state == "COMMITTED"
    assert provider.effect_count == 1


def test_timeout_after_possible_commit_is_ambiguous(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    provider = SyntheticEffectProvider(mode="ambiguous_committed")
    result = env["service"].execute_durably(
        tenant_id=env["tenant"].id,
        reservation_id=reservation.id,
        expected_version=prepared.state_version,
        worker_ref="worker:one",
        provider=provider,
    )
    assert result.state == "AMBIGUOUS"
    assert provider.effect_count == 1


def test_ambiguous_blocks_equivalent_successor(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    provider = SyntheticEffectProvider(mode="ambiguous_committed")
    env["service"].execute_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=prepared.state_version, worker_ref="worker:one", provider=provider,
    )
    env["db"].expire_all()
    successor_action, successor_decision, successor_permit = env["issue"](
        _action(env["tenant"].id, action_id="effect-action-successor"), "successor-ambiguous"
    )
    with pytest.raises(PermissionError, match="unresolved"):
        _reserve(
            env, action=successor_action, permit=successor_permit, decision_id=successor_decision,
            predecessor_reservation_id=reservation.id, successor_reason="retry",
        )


def test_certified_no_effect_allows_linked_successor(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    provider = SyntheticEffectProvider(mode="ambiguous_no_effect")
    ambiguous = env["service"].execute_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=prepared.state_version, worker_ref="worker:one", provider=provider,
    )
    recovered = env["service"].recover_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=ambiguous.state_version, provider=provider,
    )
    assert recovered.state == "CERTIFIED_NO_EFFECT"
    env["db"].expire_all()
    successor_action, successor_decision, successor_permit = env["issue"](
        _action(env["tenant"].id, action_id="effect-action-successor"), "successor-no-effect"
    )
    successor = _reserve(
        env, action=successor_action, permit=successor_permit, decision_id=successor_decision,
        predecessor_reservation_id=reservation.id, successor_reason="certified_no_effect_retry",
        no_effect_evidence_refs=(recovered.evidence_refs[0],),
    )
    assert successor.state == "RESERVED"
    assert successor.predecessor_reservation_id == reservation.id


def test_confirmed_effect_blocks_retry_and_duplicate_delivery(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    provider = SyntheticEffectProvider(mode="normal")
    committed = env["service"].execute_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=prepared.state_version, worker_ref="worker:one", provider=provider,
    )
    replay = env["service"].execute_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=committed.state_version, worker_ref="worker:one", provider=provider,
    )
    assert replay.state == "COMMITTED"
    assert provider.effect_count == 1
    successor_action, successor_decision, successor_permit = env["issue"](
        _action(env["tenant"].id, action_id="effect-action-retry"), "committed-retry"
    )
    with pytest.raises(PermissionError, match="committed"):
        _reserve(
            env, action=successor_action, permit=successor_permit, decision_id=successor_decision,
            predecessor_reservation_id=reservation.id, successor_reason="ordinary_retry",
        )


def test_stale_worker_and_expired_permit_cannot_commit(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation, worker="worker:current")
    provider = SyntheticEffectProvider(mode="normal")
    with pytest.raises(PermissionError, match="worker"):
        env["service"].execute_durably(
            tenant_id=env["tenant"].id, reservation_id=reservation.id,
            expected_version=prepared.state_version, worker_ref="worker:stale", provider=provider,
        )
    assert provider.effect_count == 0
    env["clock"][0] += timedelta(minutes=4)
    with pytest.raises(PermissionError, match="expired"):
        env["service"].execute_durably(
            tenant_id=env["tenant"].id, reservation_id=reservation.id,
            expected_version=prepared.state_version, worker_ref="worker:current", provider=provider,
        )
    assert provider.effect_count == 0


def test_older_recovery_cannot_overwrite_terminal_state(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    provider = SyntheticEffectProvider(mode="ambiguous_committed")
    ambiguous = env["service"].execute_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=prepared.state_version, worker_ref="worker:one", provider=provider,
    )
    committed = env["service"].recover_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=ambiguous.state_version, provider=provider,
    )
    assert committed.state == "COMMITTED"
    with pytest.raises(PermissionError, match="stale"):
        env["service"].record_recovery_result(
            tenant_id=env["tenant"].id, reservation_id=reservation.id,
            expected_version=ambiguous.state_version, outcome="CERTIFIED_NO_EFFECT",
            provider_effect_ref=None, evidence_ref="evidence:stale-no-effect",
        )


def test_cancellation_after_commit_boundary_never_claims_no_effect(effect_env) -> None:
    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    committing = env["service"].begin_committing(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=prepared.state_version, worker_ref="worker:one",
    )
    with pytest.raises(PermissionError, match="commit boundary"):
        env["service"].cancel(
            tenant_id=env["tenant"].id, reservation_id=reservation.id,
            expected_version=committing.state_version,
        )
    assert committing.state == "COMMITTING"


def test_exact_and_typed_semantic_match_modes_are_distinct(effect_env) -> None:
    from app.services.action_integrity.effect_closure import classify_effect_manifest

    env = effect_env
    exact = classify_effect_manifest(
        expected_action=env["action"], candidate_action=deepcopy(env["action"]),
        provider_ref="synthetic:effect-provider", variation_authorized=False,
    )
    varied = deepcopy(env["action"])
    varied["action_semantics"] = dict(varied["action_semantics"])
    varied["action_semantics"]["safe_parameters"] = {"parameter_hash": "q" * 64}
    mismatch = classify_effect_manifest(
        expected_action=env["action"], candidate_action=varied,
        provider_ref="synthetic:effect-provider", variation_authorized=False,
    )
    semantic = classify_effect_manifest(
        expected_action=env["action"], candidate_action=varied,
        provider_ref="synthetic:effect-provider", variation_authorized=True,
    )
    assert (exact, mismatch, semantic) == ("EXACT", "MISMATCH", "TYPED_SEMANTIC_EQUIVALENT")


def test_cross_tenant_resolution_fails(effect_env) -> None:
    env = effect_env
    reservation = _reserve(env)
    with pytest.raises(PermissionError, match="tenant"):
        env["service"].record_recovery_result(
            tenant_id=env["other"].id, reservation_id=reservation.id,
            expected_version=reservation.state_version, outcome="CERTIFIED_NO_EFFECT",
            provider_effect_ref=None, evidence_ref="evidence:wrong-tenant",
        )


def test_legitimate_distinct_second_effect_with_new_authority_is_allowed(effect_env) -> None:
    from app.services.action_integrity.effect_closure import SyntheticEffectProvider

    env = effect_env
    reservation = _reserve(env)
    prepared = _prepare_claim(env, reservation)
    provider = SyntheticEffectProvider(mode="normal")
    committed = env["service"].execute_durably(
        tenant_id=env["tenant"].id, reservation_id=reservation.id,
        expected_version=prepared.state_version, worker_ref="worker:one", provider=provider,
    )
    assert committed.state == "COMMITTED"
    distinct_action, distinct_decision, distinct_permit = env["issue"](
        _action(env["tenant"].id, action_id="effect-action-distinct", target="target:other"),
        "distinct",
    )
    distinct = _reserve(
        env, action=distinct_action, permit=distinct_permit, decision_id=distinct_decision,
        predecessor_reservation_id=reservation.id, successor_reason="intentional_distinct_effect",
    )
    assert distinct.state == "RESERVED"
    assert distinct.effect_identity_hash != reservation.effect_identity_hash
