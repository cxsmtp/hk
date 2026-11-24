from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.control_coverage import CoverageState, PHASE5_V2_DIMENSIONS, Phase5CoverageDimension
from app.db.models.action_integrity import (
    DecisionReceiptV2Extension,
    ExecutionComparisonV2,
    ExecutionPermitAttemptV2,
    ExecutionPermitTransitionV2,
    ExecutionPermitV2,
    ExecutionReceiptV2Extension,
    ExpectedOutcomeV2,
    OutcomeVerificationV2,
    TenantActionIntegrityRollout,
    TenantPolicyEpoch,
)
from app.db.models.control_coverage import ControlCoverageAssertion
from app.db.models.evidence import ExecutionReceipt
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.action_integrity.signing import LocalSigningKeyProvider
from app.services.action_integrity.canonical_v2 import canonical_action_hash_v2
from app.services.action_integrity.execution_authority import ExecutionPermitAuthority, PERMIT_DOMAIN
from app.services.action_integrity.execution_proof import (
    EXECUTION_COMPARISON_DOMAIN,
    EXECUTION_RECEIPT_DOMAIN,
)
from app.services.action_integrity.lifecycle_persistence import EXPECTED_OUTCOME_DOMAIN, OUTCOME_DOMAIN
from app.services.action_integrity.materiality import material_fields_hash
from app.services.action_integrity.signing import sign_object
from app.services.control_coverage.assertion_evaluators import PathEvidence, evaluate_phase5_all
from app.services.control_coverage.service import calculate_tenant_control_coverage


def _canonical_action(tenant_id: str) -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "tenant_id": tenant_id,
        "action_id": "coverage-v2-action",
        "chain_id": "coverage-v2-chain",
        "correlation_id": "coverage-v2-correlation",
        "parent_action_id": None,
        "actor_principal": "user:operator",
        "executing_principal": "service:coverage",
        "represented_subjects": ["subject:customer-1"],
        "resource_scopes": ["resource:account-1"],
        "authority_context": "authority:delegated-1",
        "business_purpose": "purpose:account-review",
        "environment": "production",
        "provider_runtime_context": "runtime:test",
        "action_semantics": {
            "action_class": "consequential",
            "operation": "read",
            "object_type": "account",
            "tool_or_service_ref": "service:accounts",
            "tool_fingerprint": "a" * 64,
            "safe_parameters": {"account": "account-1"},
            "represented_subject_refs": ["subject:customer-1"],
            "resource_refs": ["resource:account-1"],
            "counterparty_refs": [],
            "target_refs": ["target:account-1"],
            "destination_refs": ["destination:internal"],
            "values_or_quantities": [],
            "authority_ref": "authority:delegated-1",
            "business_purpose_ref": "purpose:account-review",
            "side_effect": "none",
            "persistence": "none",
            "environment": "production",
            "reversibility": "not_applicable",
            "expected_outcome_ref": "outcome:coverage",
        },
        "domain_profile_ref": "profile:placeholder",
        "domain_profile_hash": "a" * 64,
        "materiality_profile_ref": "phase5-p0",
        "materiality_profile_hash": "b" * 64,
        "resolver_versions": {},
        "policy_version_id": "policy:coverage",
        "policy_epoch": 1,
        "control_plan_id": "plan:placeholder",
        "control_plan_digest": "c" * 64,
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
        "created_at": "2026-08-24T00:00:00.000000Z",
    }


def _add_signed_execution_chain(
    db: Session,
    *,
    provider: LocalSigningKeyProvider,
    fixture,
    now: datetime,
    outcome_result: str = "SATISFIED",
    terminal_state: str = "EXECUTED",
) -> tuple[ExecutionReceiptV2Extension, ExecutionComparisonV2, OutcomeVerificationV2]:
    """Create the smallest real signed V2 chain for Coverage validation."""
    action = fixture.action
    tenant_id = str(action["tenant_id"])
    action_id = str(action["action_id"])
    action_hash = canonical_action_hash_v2(action)
    fields_hash = material_fields_hash(action)
    decision = db.get(DecisionReceiptV2Extension, fixture.decision_receipt_id)
    assert decision is not None
    permit_id, attempt_id, receipt_id, comparison_id, contract_id, verification_id = (
        str(uuid4()), str(uuid4()), str(uuid4()), str(uuid4()), str(uuid4()), str(uuid4())
    )
    expires_at = now + timedelta(minutes=5)
    permit_envelope = sign_object(
        provider,
        purpose="execution_permit_signing",
        domain=PERMIT_DOMAIN,
        tenant_id=tenant_id,
        key_id="permit",
        value={
            "schema_version": "1.0", "permit_id": permit_id, "tenant_id": tenant_id,
            "action_id": action_id, "attempt_id": attempt_id,
            "decision_receipt_id": fixture.decision_receipt_id,
            "canonical_action_hash": action_hash, "material_fields_hash": fields_hash,
            "policy_epoch": 1, "control_plan_digest": fixture.action["control_plan_digest"],
            "authority_binding_version": 1,
            "profile_selection_id": fixture.profile_selection_id,
            "profile_selection_hash": fixture.profile_selection_hash,
            "control_selection_id": fixture.control_selection_id,
            "control_plan_id": fixture.action["control_plan_id"],
            "authoritative_decision": "ALLOW", "authority_status": "CURRENT",
            "decision_version": 1, "issued_at": now.isoformat(), "expires_at": expires_at.isoformat(),
            "nonce": str(uuid4()), "use_limit": 1,
        },
    )
    permit = ExecutionPermitV2(
        permit_id=permit_id, tenant_id=tenant_id, action_id=action_id, attempt_id=attempt_id,
        decision_receipt_id=fixture.decision_receipt_id, canonical_action_hash=action_hash,
        material_fields_hash=fields_hash, policy_epoch=1,
        control_plan_digest=str(fixture.action["control_plan_digest"]),
        algorithm=permit_envelope["algorithm"], signing_key_id=permit_envelope["signing_key_id"],
        signature=permit_envelope["signature"], signed_envelope=permit_envelope,
        authority_binding_version=1, profile_selection_id=fixture.profile_selection_id,
        profile_selection_hash=fixture.profile_selection_hash, control_selection_id=fixture.control_selection_id,
        control_plan_id=str(fixture.action["control_plan_id"]), authoritative_decision="ALLOW",
        authority_status="CURRENT", decision_version=1, state="ISSUED", state_version=0,
        reconstruction_status="VERIFIED", expires_at=expires_at, created_at=now,
    )
    db.add(permit)
    db.add(ExecutionPermitAttemptV2(
        tenant_id=tenant_id, attempt_id=attempt_id, action_id=action_id,
        canonical_action_hash=action_hash, material_fields_hash=fields_hash, status="ISSUED",
        decision_receipt_id=fixture.decision_receipt_id, execution_permit_id=permit_id,
        state_version=0, next_sequence=1,
    ))
    db.flush()
    authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
    assert authority._claim_in_current_transaction(
        permit_id,
        tenant_id=tenant_id,
        action=action,
        claimed_by_ref="runtime:coverage-v2",
        rollout_mode="AUTHORITATIVE",
    )
    assert authority._finalize_in_current_transaction(
        permit_id,
        tenant_id=tenant_id,
        to_state="CONSUMED",
        reason_code="coverage_fixture_executed",
    )
    transitions = db.scalars(
        select(ExecutionPermitTransitionV2)
        .where(
            ExecutionPermitTransitionV2.tenant_id == tenant_id,
            ExecutionPermitTransitionV2.permit_id == permit_id,
        )
        .order_by(ExecutionPermitTransitionV2.sequence)
    ).all()
    assert [transition.to_state for transition in transitions] == ["CLAIMED", "CONSUMED"]
    receipt_envelope = sign_object(
        provider,
        purpose="execution_receipt_signing",
        domain=EXECUTION_RECEIPT_DOMAIN,
        tenant_id=tenant_id,
        key_id="execution-receipt",
        value={
            "schema_version": "2.0", "receipt_id": receipt_id, "tenant_id": tenant_id,
            "attempt_id": attempt_id, "permit_id": permit_id,
            "canonical_action_hash": action_hash, "actual_material_fields_hash": fields_hash,
            "terminal_state": terminal_state, "evidence_quality": "HAWK_RUNTIME_OBSERVED",
            "issued_at": now.isoformat(),
        },
    )
    receipt = ExecutionReceiptV2Extension(
        receipt_id=receipt_id, tenant_id=tenant_id, attempt_id=attempt_id, permit_id=permit_id,
        canonical_action_hash=action_hash, actual_material_fields_hash=fields_hash,
        terminal_state=terminal_state, evidence_quality="HAWK_RUNTIME_OBSERVED",
        algorithm=receipt_envelope["algorithm"], signing_key_id=receipt_envelope["signing_key_id"],
        signature=receipt_envelope["signature"], signed_envelope=receipt_envelope,
    )
    # The V2 receipt is an extension of the tenant-bound base receipt. SQLite
    # fixtures historically masked this FK ordering; PostgreSQL acceptance
    # requires the real base evidence row to exist first.
    db.add(
        ExecutionReceipt(
            receipt_id=receipt_id,
            tenant_id=tenant_id,
            action_id=action_id,
            decision_receipt_id=fixture.decision_receipt_id,
            execution_attempt_id=attempt_id,
            actual_chain_id=str(action["chain_id"]),
            actual_actor_hash="a" * 64,
            actual_purpose_hash="b" * 64,
            actual_tool_fingerprint=fields_hash,
            actual_parameter_hash=fields_hash,
            actual_target_resource_hash=fields_hash,
            actual_destination_hash=fields_hash,
            actual_authority_hash="c" * 64,
            actual_side_effect_class=str(action["action_semantics"]["side_effect"]),
            actual_policy_snapshot_id=str(action["policy_version_id"]),
            downstream_objects=[],
            execution_status="success" if terminal_state == "EXECUTED" else terminal_state.lower(),
            executed_at=now,
            collector_id="phase5:coverage-v2",
            signature="0" * 64,
            signing_key_id="execution-receipt",
            idempotency_key=receipt_id.replace("-", "")[:64],
        )
    )
    db.flush()
    db.add(receipt)
    comparison_envelope = sign_object(
        provider,
        purpose="execution_comparison_signing",
        domain=EXECUTION_COMPARISON_DOMAIN,
        tenant_id=tenant_id,
        key_id="comparison",
        value={
            "schema_version": "2.0", "comparison_id": comparison_id, "tenant_id": tenant_id,
            "attempt_id": attempt_id, "canonical_action_hash": action_hash,
            "material_fields_hash": fields_hash, "result": "MATCHED", "drift_fields": [],
            "unresolved_fields": [], "difference_hashes": [], "issued_at": now.isoformat(),
        },
    )
    comparison = ExecutionComparisonV2(
        id=comparison_id, tenant_id=tenant_id, attempt_id=attempt_id,
        decision_receipt_id=fixture.decision_receipt_id, execution_receipt_id=receipt_id,
        result="MATCHED", material_differences=[], unresolved_fields=[],
        algorithm=comparison_envelope["algorithm"], signing_key_id=comparison_envelope["signing_key_id"],
        signature=comparison_envelope["signature"], signed_envelope=comparison_envelope,
    )
    db.add(comparison)
    expected_envelope = sign_object(
        provider,
        purpose="outcome_verification_signing",
        domain=EXPECTED_OUTCOME_DOMAIN,
        tenant_id=tenant_id,
        key_id="outcome",
        value={
            "schema_version": "2.0", "outcome_contract_id": contract_id, "tenant_id": tenant_id,
            "action_id": action_id, "expected_state_hash": None,
            "verification_deadline": expires_at.isoformat(), "issued_at": now.isoformat(), "evidence_refs": [],
        },
    )
    db.add(ExpectedOutcomeV2(
        tenant_id=tenant_id, outcome_contract_id=contract_id, action_id=action_id,
        expected_state_hash=None, verification_deadline=expires_at,
        algorithm=expected_envelope["algorithm"], signing_key_id=expected_envelope["signing_key_id"],
        signature=expected_envelope["signature"], signed_envelope=expected_envelope,
    ))
    outcome_envelope = sign_object(
        provider,
        purpose="outcome_verification_signing",
        domain=OUTCOME_DOMAIN,
        tenant_id=tenant_id,
        key_id="outcome",
        value={
            "schema_version": "2.0", "verification_id": verification_id, "tenant_id": tenant_id,
            "action_id": action_id, "attempt_id": attempt_id, "outcome_contract_id": contract_id,
            "execution_receipt_id": receipt_id, "result": outcome_result,
            "verification_source_set_hash": "a" * 64, "evidence_quality": "INDEPENDENTLY_VERIFIED",
            "evaluated_at": now.isoformat(), "evidence_refs": [],
        },
    )
    outcome = OutcomeVerificationV2(
        id=verification_id, tenant_id=tenant_id, verification_id=verification_id,
        action_id=action_id, attempt_id=attempt_id, outcome_contract_id=contract_id,
        execution_receipt_id=receipt_id, result=outcome_result,
        verification_source_set_hash="a" * 64, evidence_quality="INDEPENDENTLY_VERIFIED",
        evaluated_at=now, algorithm=outcome_envelope["algorithm"],
        signing_key_id=outcome_envelope["signing_key_id"], signature=outcome_envelope["signature"],
        signed_envelope=outcome_envelope,
    )
    db.add(outcome)
    db.flush()
    return receipt, comparison, outcome


def test_phase5_coverage_requires_verified_binding_and_execution_evidence() -> None:
    """V2 rows are covered only by the corresponding verified authority evidence."""
    now = datetime.now(timezone.utc)
    results = evaluate_phase5_all(
        PathEvidence(
            subject_binding_verified=True,
            resource_binding_verified=True,
            purpose_binding_verified=True,
            authority_binding_verified=True,
            parameter_binding_verified=True,
            target_binding_verified=True,
            destination_binding_verified=True,
            approval_binding_verified=True,
            execution_visibility_verified=True,
            execution_verification_verified=True,
            persistence_tracking_verified=True,
            delegation_integrity_verified=True,
            outcome_verification_verified=True,
            evidence_refs=("decision_receipt:decision-1", "execution_receipt:execution-1"),
            observed_at=now,
        )
    )

    assert set(item.value for item in results) == set(PHASE5_V2_DIMENSIONS)
    assert {result.state for result in results.values()} == {CoverageState.COVERED}
    assert all(result.evidence_refs for result in results.values())


def test_phase5_coverage_keeps_missing_proof_unknown_and_surfaces_verified_failure() -> None:
    results = evaluate_phase5_all(
        PathEvidence(
            execution_verification_failed=True,
            persistence_tracking_failed=True,
            delegation_integrity_failed=True,
            outcome_verification_failed=True,
        )
    )

    assert results[Phase5CoverageDimension.SUBJECT_BINDING].state == CoverageState.UNKNOWN
    assert results[Phase5CoverageDimension.EXECUTION_VERIFICATION].state == CoverageState.NOT_COVERED
    assert results[Phase5CoverageDimension.PERSISTENCE_TRACKING].state == CoverageState.NOT_COVERED
    assert results[Phase5CoverageDimension.DELEGATION_INTEGRITY].state == CoverageState.NOT_COVERED
    assert results[Phase5CoverageDimension.OUTCOME_VERIFICATION].state == CoverageState.NOT_COVERED


def test_phase5_path_aggregation_never_allows_success_or_na_to_mask_an_applicable_failure() -> None:
    """Coverage is an all-applicable-action assertion, never a path-wide OR."""
    from app.services.control_coverage.service import (
        _Phase5ActionEvidence,
        _aggregate_phase5_action_evidence,
    )

    succeeded = _Phase5ActionEvidence(
        applicable=True,
        subject_binding_verified=True,
        outcome_verification_verified=True,
    )
    failed = _Phase5ActionEvidence(
        applicable=True,
        subject_binding_verified=True,
        outcome_verification_failed=True,
    )
    not_applicable = _Phase5ActionEvidence(
        applicable=True,
        outcome_verification_not_applicable=True,
    )

    mixed = _aggregate_phase5_action_evidence(
        action_ids={"allow", "deny", "na"},
        by_action={"allow": succeeded, "deny": failed, "na": not_applicable},
    )
    assert mixed[Phase5CoverageDimension.SUBJECT_BINDING] is CoverageState.UNKNOWN
    assert mixed[Phase5CoverageDimension.OUTCOME_VERIFICATION] is CoverageState.NOT_COVERED

    applicable_and_na = _aggregate_phase5_action_evidence(
        action_ids={"allow", "na"},
        by_action={"allow": succeeded, "na": not_applicable},
    )
    assert applicable_and_na[Phase5CoverageDimension.OUTCOME_VERIFICATION] is CoverageState.COVERED

    conflicting_attempts = _aggregate_phase5_action_evidence(
        action_ids={"same-action"},
        by_action={
            "same-action": _Phase5ActionEvidence(
                applicable=True,
                execution_verification_verified=True,
                execution_verification_failed=True,
            )
        },
    )
    assert conflicting_attempts[Phase5CoverageDimension.EXECUTION_VERIFICATION] is CoverageState.NOT_COVERED


def test_phase5_service_promotes_only_a_valid_signed_decision_extension() -> None:
    """A durable signed V2 decision, not metadata strings, controls V2 binding coverage."""
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with Session(engine) as db:
            tenant = Tenant(name="Coverage V2", slug="coverage-v2")
            db.add(tenant)
            db.flush()
            db.add_all(
                [
                    TenantPolicyEpoch(tenant_id=tenant.id, epoch=1),
                    TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1),
                ]
            )
            provider = LocalSigningKeyProvider(development=True)
            add_stored_authority_keys(provider, tenant_id=tenant.id)
            db.info["phase5_signing_provider"] = provider
            fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant.id,
                action=_canonical_action(tenant.id),
                now=now,
                decision_receipt_id="coverage-v2-decision",
            )
            db.add(
                RuntimeEvent(
                    event_id=str(fixture.action["action_id"]),
                    tenant_id=tenant.id,
                    source_surface="runtime",
                    event_type="governed_action",
                    user_id="user-1",
                    app_id="coverage-app",
                    metadata_json={"control_mode": "inline_allowed"},
                    created_at=now,
                )
            )
            db.flush()

            result = calculate_tenant_control_coverage(
                db,
                tenant_id=tenant.id,
                now=now,
                methodology_version="control-coverage/2.0",
            )
            assert len(result.paths) == 1
            states = {row.dimension: row.state for row in result.assertions}
            for dimension in (
                "subject_binding",
                "resource_binding",
                "purpose_binding",
                "authority_binding",
                "parameter_binding",
                "target_binding",
                "destination_binding",
            ):
                assert states[dimension] == "covered"
            assert states["approval_binding"] == "not_applicable"
            assert states["persistence_tracking"] == "not_applicable"
            assert states["delegation_integrity"] == "not_applicable"
            assert states["outcome_verification"] == "unknown"
            assert states["execution_visibility"] == "unknown"

            extension = db.get(DecisionReceiptV2Extension, "coverage-v2-decision")
            assert extension is not None
            extension.signature = "x" * 43
            db.flush()
            refreshed = calculate_tenant_control_coverage(
                db,
                tenant_id=tenant.id,
                now=now.replace(second=1),
                methodology_version="control-coverage/2.0",
            )
            refreshed_states = {row.dimension: row.state for row in refreshed.assertions}
            assert refreshed_states["subject_binding"] == "unknown"
            assert refreshed_states["parameter_binding"] == "unknown"
            assert refreshed_states["destination_binding"] == "unknown"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_phase5_coverage_rejects_cross_attempt_and_invalid_terminal_chain_substitution() -> None:
    """Only one exact signed decision→permit→attempt→receipt chain can promote V2."""
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority
    from app.services.control_coverage.service import _phase5_action_evidence

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with Session(engine) as db:
            tenant = Tenant(name="Coverage Chain", slug="coverage-chain")
            db.add(tenant)
            db.flush()
            db.add_all(
                [
                    TenantPolicyEpoch(tenant_id=tenant.id, epoch=1),
                    TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1),
                ]
            )
            provider = LocalSigningKeyProvider(development=True)
            add_stored_authority_keys(provider, tenant_id=tenant.id)
            for purpose, key_id, secret in (
                ("execution_receipt_signing", "execution-receipt", b"r" * 32),
                ("execution_comparison_signing", "comparison", b"c" * 32),
                ("outcome_verification_signing", "outcome", b"o" * 32),
            ):
                provider.add_key(purpose=purpose, tenant_id=tenant.id, key_id=key_id, secret=secret)
            db.info["phase5_signing_provider"] = provider
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id=tenant.id, action=_canonical_action(tenant.id),
                now=now, decision_receipt_id="coverage-chain-decision",
            )
            receipt, comparison, outcome = _add_signed_execution_chain(
                db, provider=provider, fixture=fixture, now=now
            )

            evidence = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert evidence.execution_visibility_verified is True
            assert evidence.execution_verification_verified is True
            assert evidence.outcome_verification_verified is True

            decision = db.get(DecisionReceiptV2Extension, fixture.decision_receipt_id)
            permit = db.get(ExecutionPermitV2, receipt.permit_id)
            assert decision is not None and permit is not None

            # Mutable authority columns cannot contradict their signed
            # envelopes and still promote coverage.
            decision.authoritative_decision = "BLOCK"
            db.flush()
            unsigned_decision_mutation = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert unsigned_decision_mutation.applicable is False
            decision.authoritative_decision = "ALLOW"

            permit.policy_epoch = 2
            db.flush()
            unsigned_permit_mutation = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert unsigned_permit_mutation.execution_visibility_verified is False
            permit.policy_epoch = 1

            outcome.verification_source_set_hash = "b" * 64
            db.flush()
            unsigned_outcome_mutation = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert unsigned_outcome_mutation.outcome_verification_verified is False
            outcome.verification_source_set_hash = "a" * 64

            # A validly signed receipt with different actual material is still
            # visible, but cannot be promoted as an authorization match.
            original_receipt = dict(receipt.signed_envelope)
            mismatch_value = {
                key: value
                for key, value in original_receipt.items()
                if key not in {"algorithm", "signing_key_id", "signature"}
            }
            mismatch_value["actual_material_fields_hash"] = "b" * 64
            mismatch = sign_object(
                provider,
                purpose="execution_receipt_signing",
                domain=EXECUTION_RECEIPT_DOMAIN,
                tenant_id=tenant.id,
                key_id="execution-receipt",
                value=mismatch_value,
            )
            receipt.actual_material_fields_hash = "b" * 64
            receipt.algorithm = mismatch["algorithm"]
            receipt.signing_key_id = mismatch["signing_key_id"]
            receipt.signature = mismatch["signature"]
            receipt.signed_envelope = mismatch
            db.flush()
            mismatched_material = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert mismatched_material.execution_visibility_verified is True
            assert mismatched_material.execution_verification_verified is False

            receipt.actual_material_fields_hash = original_receipt["actual_material_fields_hash"]
            receipt.algorithm = original_receipt["algorithm"]
            receipt.signing_key_id = original_receipt["signing_key_id"]
            receipt.signature = original_receipt["signature"]
            receipt.signed_envelope = original_receipt

            # A row-level receipt substitution cannot borrow a valid signed
            # comparison from another attempt or execution receipt.
            comparison.execution_receipt_id = str(uuid4())
            db.flush()
            substituted = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert substituted.execution_verification_verified is False
            assert substituted.outcome_verification_verified is True

            comparison.execution_receipt_id = receipt.receipt_id
            unknown_terminal_value = {
                key: value
                for key, value in original_receipt.items()
                if key not in {"algorithm", "signing_key_id", "signature"}
            }
            unknown_terminal_value["terminal_state"] = "UNKNOWN"
            unknown_terminal = sign_object(
                provider,
                purpose="execution_receipt_signing",
                domain=EXECUTION_RECEIPT_DOMAIN,
                tenant_id=tenant.id,
                key_id="execution-receipt",
                value=unknown_terminal_value,
            )
            receipt.terminal_state = "UNKNOWN"
            receipt.algorithm = unknown_terminal["algorithm"]
            receipt.signing_key_id = unknown_terminal["signing_key_id"]
            receipt.signature = unknown_terminal["signature"]
            receipt.signed_envelope = unknown_terminal
            db.flush()
            invalid_terminal = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert invalid_terminal.execution_visibility_verified is False
            assert invalid_terminal.execution_verification_verified is False

            receipt.terminal_state = "EXECUTED"
            receipt.algorithm = original_receipt["algorithm"]
            receipt.signing_key_id = original_receipt["signing_key_id"]
            receipt.signature = original_receipt["signature"]
            receipt.signed_envelope = original_receipt

            original_outcome = dict(outcome.signed_envelope)
            violated_value = {
                key: value
                for key, value in original_outcome.items()
                if key not in {"algorithm", "signing_key_id", "signature"}
            }
            violated_value["result"] = "VIOLATED"
            violated = sign_object(
                provider,
                purpose="outcome_verification_signing",
                domain=OUTCOME_DOMAIN,
                tenant_id=tenant.id,
                key_id="outcome",
                value=violated_value,
            )
            outcome.result = "VIOLATED"
            outcome.algorithm = violated["algorithm"]
            outcome.signing_key_id = violated["signing_key_id"]
            outcome.signature = violated["signature"]
            outcome.signed_envelope = violated
            db.flush()
            violated_outcome = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert violated_outcome.outcome_verification_verified is False
            assert violated_outcome.outcome_verification_failed is True

            # Applicability comes from the signed canonical action.  A
            # post-execution row cannot turn a required outcome into N/A.
            not_applicable_value = {
                key: value
                for key, value in original_outcome.items()
                if key not in {"algorithm", "signing_key_id", "signature"}
            }
            not_applicable_value["result"] = "NOT_APPLICABLE"
            not_applicable = sign_object(
                provider,
                purpose="outcome_verification_signing",
                domain=OUTCOME_DOMAIN,
                tenant_id=tenant.id,
                key_id="outcome",
                value=not_applicable_value,
            )
            outcome.result = "NOT_APPLICABLE"
            outcome.algorithm = not_applicable["algorithm"]
            outcome.signing_key_id = not_applicable["signing_key_id"]
            outcome.signature = not_applicable["signature"]
            outcome.signed_envelope = not_applicable
            db.flush()
            required_outcome = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert required_outcome.outcome_verification_not_applicable is False
            assert required_outcome.outcome_verification_verified is False

            # Tampering an immutable outcome signature makes the outcome
            # Unknown rather than allowing a stale SATISFIED row to cover it.
            outcome.result = "SATISFIED"
            outcome.algorithm = original_outcome["algorithm"]
            outcome.signing_key_id = original_outcome["signing_key_id"]
            outcome.signature = "x" * 43
            outcome.signed_envelope = original_outcome
            db.flush()
            invalid_signature = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert invalid_signature.outcome_verification_verified is False

            # A terminal projection without its signed transition history is
            # not execution authority, even when every mutable row says it ran.
            outcome.signature = original_outcome["signature"]
            outcome.signed_envelope = original_outcome
            for transition in db.scalars(
                select(ExecutionPermitTransitionV2).where(
                    ExecutionPermitTransitionV2.tenant_id == tenant.id,
                    ExecutionPermitTransitionV2.permit_id == permit.permit_id,
                )
            ).all():
                db.delete(transition)
            db.flush()
            synthetic_terminal = _phase5_action_evidence(
                db, tenant_id=tenant.id, action_ids={str(fixture.action["action_id"])}, now=now
            )[str(fixture.action["action_id"])]
            assert synthetic_terminal.execution_visibility_verified is False
            assert synthetic_terminal.execution_verification_verified is False
            assert synthetic_terminal.outcome_verification_verified is False
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
