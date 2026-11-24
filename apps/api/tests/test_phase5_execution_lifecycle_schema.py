from __future__ import annotations

import pytest


def test_phase5_execution_and_effect_histories_have_signed_append_only_schema() -> None:
    from app.db.models.action_integrity import ActionExecutionTransitionV2, ExecutionPermitAttemptV2, PersistentEffectTransitionV2, PersistentEffectV2

    attempt = ExecutionPermitAttemptV2.__table__
    assert {"state_version", "next_sequence", "terminal_execution_receipt_id", "action_plan_id", "action_plan_step_id"}.issubset(attempt.c.keys())
    execution = ActionExecutionTransitionV2.__table__
    assert {"evidence_refs", "prior_transition_id", "prior_transition_hash", "signed_envelope", "supersedes_transition_id"}.issubset(execution.c.keys())
    assert any(constraint.name == "uq_phase5_action_transition_sequence" for constraint in execution.constraints)
    effect = PersistentEffectV2.__table__
    assert {"history_head_transition_id", "history_head_transition_hash", "history_head_sequence", "reconstruction_status", "recovery_requires_remediation"}.issubset(effect.c.keys())
    transition = PersistentEffectTransitionV2.__table__
    assert {"transition_kind", "verification_source_refs", "recovery_basis", "signed_envelope", "prior_transition_id", "prior_transition_hash"}.issubset(transition.c.keys())


def test_lifecycle_transition_writers_are_tenant_bound_idempotent_and_cas(tmp_path) -> None:
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.models.action_integrity import ExecutionPermitAttemptV2, PersistentEffectV2
    from app.db.models.evidence import EvidenceNode
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import append_action_execution_transition_v2, append_persistent_effect_transition_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'cas.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        provider = LocalSigningKeyProvider(development=True)
        for purpose, secret in (("execution_transition_signing", b"x" * 32), ("persistent_effect_signing", b"y" * 32)):
            provider.add_key(purpose=purpose, tenant_id="tenant-cas", key_id=purpose, secret=secret)
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-cas", name="CAS", slug="cas", is_active=True))
            evidence = EvidenceNode(tenant_id="tenant-cas", correlation_id="attempt", node_type="test", signal_type="test", label="test", payload={})
            db.add(evidence); db.flush()
            attempt = ExecutionPermitAttemptV2(tenant_id="tenant-cas", attempt_id="attempt", action_id="action", canonical_action_hash="a" * 64, material_fields_hash="b" * 64, status="PERMIT_ISSUED")
            effect = PersistentEffectV2(tenant_id="tenant-cas", action_id="action", attempt_id="attempt", execution_receipt_id=None, downstream_object_hash="c" * 64, expected_object_state_hash="d" * 64, state="CREATED", expires_at=now + timedelta(minutes=1), algorithm="HS256", signing_key_id="persistent_effect_signing", signature="s" * 43, signed_envelope={})
            db.add_all([attempt, effect]); db.flush()
            transition = append_action_execution_transition_v2(db, provider=provider, tenant_id="tenant-cas", attempt_id="attempt", expected_state="PERMIT_ISSUED", expected_version=0, to_state="QUEUED", source="test", evidence_refs=[evidence.id], observed_at=now, received_at=now, idempotency_key="a:1")
            assert append_action_execution_transition_v2(db, provider=provider, tenant_id="tenant-cas", attempt_id="attempt", expected_state="PERMIT_ISSUED", expected_version=0, to_state="QUEUED", source="test", evidence_refs=[evidence.id], observed_at=now, received_at=now, idempotency_key="a:1").id == transition.id
            effect_transition = append_persistent_effect_transition_v2(db, provider=provider, tenant_id="tenant-cas", effect_id=effect.id, expected_state="CREATED", expected_version=0, to_state="UNKNOWN", evidence_refs=[evidence.id], evidence_quality="UNKNOWN", observed_at=now, idempotency_key="e:1")
            assert effect_transition.sequence == 1 and effect.history_head_transition_id == effect_transition.id
    finally:
        Base.metadata.drop_all(engine); engine.dispose()


def test_execution_history_requires_the_stored_decision_and_permit_bridge(tmp_path) -> None:
    """A plausible attempt history without stored authority must not reconstruct."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models.action_integrity import ExecutionPermitAttemptV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import reconstruct_action_execution_history_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'attempt-authority.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-attempt-authority", name="Attempt", slug="attempt-authority", is_active=True))
            db.add(ExecutionPermitAttemptV2(
                tenant_id="tenant-attempt-authority", attempt_id="attempt", action_id="action",
                canonical_action_hash="a" * 64, material_fields_hash="b" * 64, status="PERMIT_ISSUED",
            ))
        with sessions.begin() as db:
            with pytest.raises(PermissionError, match="stored decision and permit"):
                reconstruct_action_execution_history_v2(
                    db, provider=LocalSigningKeyProvider(development=True),
                    tenant_id="tenant-attempt-authority", attempt_id="attempt",
                )
    finally:
        Base.metadata.drop_all(engine); engine.dispose()


def test_persistent_effect_history_reconstructs_signed_evidence_bound_events(tmp_path) -> None:
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models.action_integrity import PersistentEffectV2
    from app.db.models.evidence import EvidenceNode
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import (
        append_persistent_effect_transition_v2,
        reconstruct_persistent_effect_history_v2,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'effect-reconstruct.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="persistent_effect_signing", tenant_id="tenant-effect-history", key_id="effect", secret=b"e" * 32)
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-effect-history", name="Effect", slug="effect-history", is_active=True))
            evidence = EvidenceNode(tenant_id="tenant-effect-history", correlation_id="effect", node_type="test", signal_type="test", label="test", payload={})
            db.add(evidence)
            db.flush()
            effect = PersistentEffectV2(
                tenant_id="tenant-effect-history", action_id="action", attempt_id="attempt", execution_receipt_id=None,
                downstream_object_hash="c" * 64, expected_object_state_hash="d" * 64, state="CREATED",
                expires_at=now + timedelta(minutes=1), algorithm="HS256", signing_key_id="effect", signature="s" * 43,
                signed_envelope={},
            )
            db.add(effect)
            db.flush()
            transition = append_persistent_effect_transition_v2(
                db, provider=provider, tenant_id="tenant-effect-history", effect_id=effect.id,
                expected_state="CREATED", expected_version=0, to_state="UNKNOWN", evidence_refs=[evidence.id],
                evidence_quality="UNKNOWN", observed_at=now, idempotency_key="effect:1",
            )
            assert transition.signed_envelope["verification_source_refs"] == [evidence.id]
            from app.services.action_integrity.signing import verify_signed_object
            assert verify_signed_object(
                provider,
                purpose="persistent_effect_signing",
                domain="hawk:persistent-effect-transition:v1",
                tenant_id="tenant-effect-history",
                value=dict(transition.signed_envelope),
            ), transition.signed_envelope
            assert reconstruct_persistent_effect_history_v2(
                db, provider=provider, tenant_id="tenant-effect-history", effect_id=effect.id,
            ) == ("UNKNOWN", 1)
    finally:
        Base.metadata.drop_all(engine); engine.dispose()


def test_persistent_effect_history_rejects_signed_row_projection_tamper(tmp_path) -> None:
    """Signed transition material must match every persisted replay field."""
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models.action_integrity import PersistentEffectV2
    from app.db.models.evidence import EvidenceNode
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import (
        append_persistent_effect_transition_v2,
        reconstruct_persistent_effect_history_v2,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'effect-row-tamper.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="persistent_effect_signing", tenant_id="tenant-effect-tamper", key_id="effect", secret=b"e" * 32)
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-effect-tamper", name="Effect", slug="effect-tamper", is_active=True))
            evidence = EvidenceNode(tenant_id="tenant-effect-tamper", correlation_id="effect", node_type="test", signal_type="test", label="test", payload={})
            db.add(evidence)
            db.flush()
            effect = PersistentEffectV2(
                tenant_id="tenant-effect-tamper", action_id="action", attempt_id="attempt", execution_receipt_id=None,
                downstream_object_hash="c" * 64, expected_object_state_hash="d" * 64, state="CREATED",
                expires_at=now + timedelta(minutes=1), algorithm="HS256", signing_key_id="effect", signature="s" * 43,
                signed_envelope={},
            )
            db.add(effect)
            db.flush()
            transition = append_persistent_effect_transition_v2(
                db, provider=provider, tenant_id="tenant-effect-tamper", effect_id=effect.id,
                expected_state="CREATED", expected_version=0, to_state="UNKNOWN", evidence_refs=[evidence.id],
                evidence_quality="UNKNOWN", observed_at=now, idempotency_key="effect:tamper",
            )
            transition.observed_at = now + timedelta(seconds=1)
            with pytest.raises(PermissionError, match="inconsistent"):
                reconstruct_persistent_effect_history_v2(
                    db, provider=provider, tenant_id="tenant-effect-tamper", effect_id=effect.id,
                )
    finally:
        Base.metadata.drop_all(engine); engine.dispose()
