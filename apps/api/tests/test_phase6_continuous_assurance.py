from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker


NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)


def _canonical_action(
    tenant_id: str,
    action_id: str,
    *,
    tool_ref: str = "tool:synthetic-document",
    target_ref: str | None = None,
    side_effect: str = "isolated_write",
) -> dict[str, object]:
    target_ref = target_ref or f"fixture:{tenant_id}:synthetic-document-primary"
    return {
        "schema_version": "2.0",
        "tenant_id": tenant_id,
        "action_id": action_id,
        "chain_id": f"chain:{action_id}",
        "correlation_id": f"correlation:{action_id}",
        "parent_action_id": None,
        "actor_principal": "user:operator",
        "executing_principal": "service:synthetic-document",
        "represented_subjects": ["subject:synthetic-user"],
        "resource_scopes": [target_ref],
        "authority_context": "authority:validation",
        "business_purpose": "purpose:control-validation",
        "environment": "validation",
        "provider_runtime_context": "runtime:synthetic",
        "action_semantics": {
            "action_class": "consequential",
            "operation": "update",
            "object_type": "synthetic_document",
            "tool_or_service_ref": tool_ref,
            "tool_fingerprint": "a" * 64,
            "safe_parameters": {"document_ref": "synthetic-1"},
            "represented_subject_refs": ["subject:synthetic-user"],
            "resource_refs": [target_ref],
            "counterparty_refs": [],
            "target_refs": [target_ref],
            "destination_refs": ["destination:internal-validation"],
            "values_or_quantities": [],
            "authority_ref": "authority:validation",
            "business_purpose_ref": "purpose:control-validation",
            "side_effect": side_effect,
            "persistence": "persistent",
            "environment": "validation",
            "reversibility": "compensatable",
            "expected_outcome_ref": "outcome:synthetic-document-updated",
        },
        "domain_profile_ref": "profile:placeholder",
        "domain_profile_hash": "a" * 64,
        "materiality_profile_ref": "phase5-p0",
        "materiality_profile_hash": "b" * 64,
        "resolver_versions": {},
        "policy_version_id": "policy:validation",
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
        "created_at": NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def _add_phase5_evidence(
    db: Session,
    *,
    provider,
    tenant_id: str,
    action_id: str,
    at: datetime,
    matched_execution: bool,
    action_template: dict[str, object] | None = None,
):
    from phase5_stored_authority_support import seed_stored_allow_authority
    from test_phase5_control_coverage_v2 import _add_signed_execution_chain
    from app.services.continuous_assurance import Phase5EvidenceReference

    template = action_template or {}
    fixture = seed_stored_allow_authority(
        db,
        provider=provider,
        tenant_id=tenant_id,
        action=_canonical_action(
            tenant_id,
            action_id,
            tool_ref=str(template.get("tool_ref") or "tool:synthetic-document"),
            target_ref=str(template.get("target_ref") or f"fixture:{tenant_id}:synthetic-document-primary"),
            side_effect=str(template.get("side_effect") or "isolated_write"),
        ),
        now=at,
        decision_receipt_id=f"decision-{action_id}",
    )
    if not matched_execution:
        db.flush()
        return Phase5EvidenceReference(
            action_id=action_id,
            decision_receipt_id=fixture.decision_receipt_id,
            execution_receipt_id=None,
            comparison_id=None,
        )
    receipt, comparison, _outcome = _add_signed_execution_chain(
        db,
        provider=provider,
        fixture=fixture,
        now=at,
    )
    return Phase5EvidenceReference(
        action_id=action_id,
        decision_receipt_id=fixture.decision_receipt_id,
        execution_receipt_id=receipt.receipt_id,
        comparison_id=comparison.id,
    )


@pytest.fixture()
def assurance_db(tmp_path):
    # Register every mapped table before creating the isolated acceptance DB.
    from app.db import models as _models  # noqa: F401
    from app.db.session import Base

    database_url = os.environ.get("PHASE6_TEST_DATABASE_URL")
    engine = create_engine(database_url or f"sqlite+pysqlite:///{tmp_path / 'phase6.sqlite3'}")
    postgres_tables: tuple[str, ...] = ()
    if database_url:
        postgres_tables = tuple(
            table
            for table in inspect(engine).get_table_names(schema="public")
            if table != "alembic_version"
        )
        required = {
            "continuous_control_assertions",
            "validation_scenarios",
            "validation_runs",
            "validation_evidence_bundles",
        }
        if not required <= set(postgres_tables):
            raise RuntimeError("Phase 6 PostgreSQL tests require an Alembic 0070 schema")
        quoted = ", ".join(engine.dialect.identifier_preparer.quote(table) for table in postgres_tables)
        with engine.begin() as connection:
            connection.exec_driver_sql(f"TRUNCATE TABLE {quoted} CASCADE")
    else:
        Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield sessions
    finally:
        if database_url:
            quoted = ", ".join(
                engine.dialect.identifier_preparer.quote(table) for table in postgres_tables
            )
            with engine.begin() as connection:
                connection.exec_driver_sql(f"TRUNCATE TABLE {quoted} CASCADE")
        else:
            Base.metadata.drop_all(engine)
        engine.dispose()


def _seed_tenant_and_provider(db: Session, *, name: str):
    from phase5_stored_authority_support import add_stored_authority_keys
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    tenant = Tenant(name=name, slug=f"{name.lower().replace(' ', '-')}-{uuid4().hex[:8]}", is_active=True)
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
    return tenant, provider


def _create_assertion_and_scenario(
    db: Session,
    *,
    service,
    tenant_id: str,
    suffix: str = "primary",
    control_profile_id: str | None = None,
):
    target = f"fixture:{tenant_id}:synthetic-document-{suffix}"
    assertion = service.create_assertion(
        db,
        tenant_id=tenant_id,
        assertion_key=f"assertion:{suffix}",
        assertion_type="execution_integrity",
        asset_ref=f"asset:{suffix}",
        action_class="synthetic_document_update",
        required_capability="post_execution_verification",
        expected_outcome="PASS_EXECUTION_MATCHED",
        required_evidence_level="HAWK_RUNTIME_OBSERVED",
        dependencies={
            f"tool_mcp_fingerprint:tool:synthetic-document-{suffix}": "a" * 64,
            f"target_mapping:{target}": "b" * 64,
        },
        control_profile_id=control_profile_id,
    )
    scenario = service.create_scenario(
        db,
        tenant_id=tenant_id,
        assertion_id=assertion.id,
        scenario_key=f"scenario:{suffix}",
        action_template={
            "fixture_ref": f"fixture:{tenant_id}:synthetic-action-{suffix}",
            "action_class": "synthetic_document_update",
            "tool_ref": f"tool:synthetic-document-{suffix}",
            "target_ref": target,
            "side_effect": "isolated_write",
        },
        expected_policy_result="ALLOW",
        expected_enforcement_result="EXECUTED",
        expected_receipt_result="MATCHED",
        safety_class="S3_ISOLATED_SIDE_EFFECT",
        safety_envelope={
            "allowed_action_classes": ["synthetic_document_update"],
            "allowed_targets": [target],
            "allowed_control_points": ["runtime:synthetic"],
            "allowed_side_effect_categories": ["isolated_write"],
            "cleanup_required": True,
        },
        mutations=[],
        expected_validation_outcome="PASS_EXECUTION_MATCHED",
        freshness_seconds=3600,
    )
    return assertion, scenario


def test_s5_and_arbitrary_executable_scenarios_never_enter_execution(assurance_db) -> None:
    from app.services.continuous_assurance import ContinuousAssuranceService

    service = ContinuousAssuranceService()
    with assurance_db.begin() as db:
        tenant, _provider = _seed_tenant_and_provider(db, name="Safety")
        assertion, _scenario = _create_assertion_and_scenario(
            db, service=service, tenant_id=tenant.id
        )
        with pytest.raises(ValueError, match="executable scenario material"):
            service.create_scenario(
                db,
                tenant_id=tenant.id,
                assertion_id=assertion.id,
                scenario_key="scenario:arbitrary-shell",
                action_template={"shell": "touch /tmp/forbidden"},
                expected_policy_result="BLOCK",
                expected_enforcement_result="BLOCKED",
                expected_receipt_result="NOT_EXECUTED",
                safety_class="S1_READ_ONLY_SYNTHETIC",
                safety_envelope={},
                mutations=[],
                expected_validation_outcome="PASS_PREVENTED",
            )
        prohibited = service.create_scenario(
            db,
            tenant_id=tenant.id,
            assertion_id=assertion.id,
            scenario_key="scenario:s5",
            action_template={
                "fixture_ref": f"fixture:{tenant.id}:prohibited",
                "action_class": "real_financial_transfer",
                "tool_ref": "tool:synthetic-document",
                "target_ref": f"fixture:{tenant.id}:prohibited",
                "side_effect": "real_financial_transfer",
            },
            expected_policy_result="BLOCK",
            expected_enforcement_result="BLOCKED",
            expected_receipt_result="NOT_EXECUTED",
            safety_class="S5_PROHIBITED",
            safety_envelope={
                "allowed_action_classes": ["real_financial_transfer"],
                "allowed_targets": [f"fixture:{tenant.id}:prohibited"],
                "allowed_control_points": ["runtime:synthetic"],
                "allowed_side_effect_categories": ["real_financial_transfer"],
                "cleanup_required": False,
            },
            mutations=[],
            expected_validation_outcome="PASS_PREVENTED",
        )
        with pytest.raises(PermissionError, match="S5"):
            service.start_validation(
                db,
                tenant_id=tenant.id,
                scenario_id=prohibited.id,
                trigger="manual",
                triggered_by_ref="user:owner",
                started_at=NOW,
            )


def test_validation_target_and_assertion_are_tenant_bound(assurance_db) -> None:
    from app.services.continuous_assurance import ContinuousAssuranceService

    service = ContinuousAssuranceService()
    with assurance_db.begin() as db:
        tenant_a, _provider_a = _seed_tenant_and_provider(db, name="Tenant A")
        tenant_b, _provider_b = _seed_tenant_and_provider(db, name="Tenant B")
        _assertion, scenario = _create_assertion_and_scenario(
            db, service=service, tenant_id=tenant_a.id
        )
        with pytest.raises(PermissionError, match="tenant"):
            service.start_validation(
                db,
                tenant_id=tenant_b.id,
                scenario_id=scenario.id,
                trigger="manual",
                triggered_by_ref="user:owner",
                started_at=NOW,
            )


@pytest.mark.parametrize(
    ("expected_enforcement", "matched_execution", "expected_outcome"),
    [
        ("PREVENTED", False, "FAIL_WRONG_CONTROL_POINT"),
        ("EXECUTED", False, "FAIL_EVIDENCE_MISSING"),
    ],
)
def test_detection_or_missing_execution_evidence_never_becomes_stronger_proof(
    assurance_db,
    expected_enforcement: str,
    matched_execution: bool,
    expected_outcome: str,
) -> None:
    from app.services.continuous_assurance import ContinuousAssuranceService

    service = ContinuousAssuranceService()
    with assurance_db.begin() as db:
        tenant, provider = _seed_tenant_and_provider(db, name=f"Truth {expected_enforcement}")
        assertion, scenario = _create_assertion_and_scenario(
            db, service=service, tenant_id=tenant.id
        )
        scenario.expected_enforcement_result = expected_enforcement
        scenario.expected_validation_outcome = (
            "PASS_PREVENTED" if expected_enforcement == "PREVENTED" else "PASS_EXECUTION_MATCHED"
        )
        run = service.start_validation(
            db,
            tenant_id=tenant.id,
            scenario_id=scenario.id,
            trigger="manual",
            triggered_by_ref="user:owner",
            started_at=NOW,
        )
        evidence = _add_phase5_evidence(
            db,
            provider=provider,
            tenant_id=tenant.id,
            action_id=f"truth-{uuid4().hex[:8]}",
            at=NOW,
            matched_execution=matched_execution,
            action_template=dict(scenario.action_template or {}),
        )
        completed = service.complete_validation(
            db,
            tenant_id=tenant.id,
            run_id=run.id,
            phase5_evidence=evidence,
            completed_at=NOW + timedelta(seconds=1),
        )
        assert completed.outcome == expected_outcome
        assert assertion.assurance_state == "UNKNOWN"


def test_complete_assurance_drift_regression_remediation_loop_is_impact_scoped(assurance_db) -> None:
    from app.db.models.native_control import ControlCapabilityProfileRecord
    from app.services.continuous_assurance import ContinuousAssuranceService
    from app.services.native_control.selection_service import _claim

    service = ContinuousAssuranceService()
    with assurance_db.begin() as db:
        tenant, provider = _seed_tenant_and_provider(db, name="Lifecycle")
        profile = ControlCapabilityProfileRecord(
            manifest_id=f"phase6:synthetic:{tenant.id}",
            manifest_version="1.0",
            matrix_version="phase6-p0",
            provider="synthetic",
            product="document_fixture",
            runtime="validation",
            integration_method="runtime_inline",
            adapter_version="1.0.0",
            verification_status="verified",
            verification_source="phase6_acceptance",
            capabilities={
                "post_execution_verification": {
                    "level": "inline_bound",
                    "verification_status": "verified",
                    "evidence_refs": ["evidence:phase5:execution-comparison"],
                }
            },
            security_properties={},
            health_requirements=[],
            degradation_modes=[],
            known_blind_spots=[],
            documentation_references=[],
            supported_action_classes=["synthetic_document_update"],
            supported_control_methods=["runtime_inline"],
            manifest_fingerprint="f" * 64,
            active=True,
        )
        db.add(profile)
        db.flush()
        assertion, scenario = _create_assertion_and_scenario(
            db,
            service=service,
            tenant_id=tenant.id,
            suffix="primary",
            control_profile_id=profile.id,
        )
        unrelated, unrelated_scenario = _create_assertion_and_scenario(
            db, service=service, tenant_id=tenant.id, suffix="unrelated"
        )

        for current_assertion, current_scenario, suffix in (
            (assertion, scenario, "initial"),
            (unrelated, unrelated_scenario, "unrelated"),
        ):
            run = service.start_validation(
                db,
                tenant_id=tenant.id,
                scenario_id=current_scenario.id,
                trigger="manual",
                triggered_by_ref="user:owner",
                started_at=NOW,
            )
            evidence = _add_phase5_evidence(
                db,
                provider=provider,
                tenant_id=tenant.id,
                action_id=f"phase6-{suffix}",
                at=NOW,
                matched_execution=True,
                action_template=dict(current_scenario.action_template or {}),
            )
            completed = service.complete_validation(
                db,
                tenant_id=tenant.id,
                run_id=run.id,
                phase5_evidence=evidence,
                completed_at=NOW + timedelta(seconds=1),
            )
            assert completed.outcome == "PASS_EXECUTION_MATCHED"
            assert current_assertion.assurance_state == "CURRENT"
        assert _claim(profile.capabilities["post_execution_verification"]).verification_status.value == "verified"

        drift = service.record_drift(
            db,
            tenant_id=tenant.id,
            category="tool_mcp_fingerprint",
            dependency_key="tool:synthetic-document-primary",
            previous_digest="a" * 64,
            current_digest="c" * 64,
            source_ref="discovery:tool-fingerprint-change",
            observed_at=NOW + timedelta(minutes=1),
        )
        assert assertion.assurance_state == "STALE"
        assert unrelated.assurance_state == "CURRENT"
        assert _claim(profile.capabilities["post_execution_verification"]).verification_status.value == "unverified"
        # A target-specific signal also stays scoped to the matching binding.
        unrelated_binding = next(
            row for row in unrelated.dependencies if row.dependency_category == "target_mapping"
        )
        target_drift = service.record_drift(
            db,
            tenant_id=tenant.id,
            category="target_mapping",
            dependency_key=f"fixture:{tenant.id}:synthetic-document-primary",
            previous_digest="b" * 64,
            current_digest="d" * 64,
            source_ref="discovery:target-change",
            observed_at=NOW + timedelta(minutes=2),
        )
        assert assertion.assurance_state == "STALE"
        assert unrelated.assurance_state == "CURRENT"
        assert target_drift.affected_assertion_ids == [assertion.id]
        assert unrelated_binding.dependency_key.endswith("synthetic-document-unrelated")

        failed_run = service.start_targeted_revalidation(
            db,
            tenant_id=tenant.id,
            assertion_id=assertion.id,
            drift_signal_id=drift.id,
            started_at=NOW + timedelta(minutes=3),
        )
        missing = _add_phase5_evidence(
            db,
            provider=provider,
            tenant_id=tenant.id,
            action_id="phase6-regressed",
            at=NOW + timedelta(minutes=3),
            matched_execution=False,
            action_template=dict(scenario.action_template or {}),
        )
        service.complete_validation(
            db,
            tenant_id=tenant.id,
            run_id=failed_run.id,
            phase5_evidence=missing,
            completed_at=NOW + timedelta(minutes=3, seconds=1),
        )
        assert assertion.assurance_state == "REGRESSED"
        assert _claim(profile.capabilities["post_execution_verification"]).verification_status.value == "broken"

        remediation = service.create_remediation(
            db,
            tenant_id=tenant.id,
            assertion_id=assertion.id,
            regression_run_id=failed_run.id,
            reason="restore verified tool binding",
            created_by_ref="user:owner",
            created_at=NOW + timedelta(minutes=3, seconds=10),
        )
        service.mark_remediation_ready(
            db,
            tenant_id=tenant.id,
            remediation_id=remediation.id,
            updated_by_ref="user:owner",
            updated_at=NOW + timedelta(minutes=3, seconds=20),
        )
        recovered_run = service.start_targeted_revalidation(
            db,
            tenant_id=tenant.id,
            assertion_id=assertion.id,
            remediation_id=remediation.id,
            started_at=NOW + timedelta(minutes=4),
        )
        recovered_evidence = _add_phase5_evidence(
            db,
            provider=provider,
            tenant_id=tenant.id,
            action_id="phase6-recovered",
            at=NOW + timedelta(minutes=4),
            matched_execution=True,
            action_template=dict(scenario.action_template or {}),
        )
        service.complete_validation(
            db,
            tenant_id=tenant.id,
            run_id=recovered_run.id,
            phase5_evidence=recovered_evidence,
            completed_at=NOW + timedelta(minutes=4, seconds=1),
        )
        assert assertion.assurance_state == "CURRENT"
        assert _claim(profile.capabilities["post_execution_verification"]).verification_status.value == "verified"
        assert remediation.state == "RESOLVED"
        assert remediation.resolved_validation_run_id == recovered_run.id
        expired = service.expire_due_assertions(
            db,
            tenant_id=tenant.id,
            evaluated_at=NOW + timedelta(hours=2),
        )
        assert set(expired) == {assertion.id, unrelated.id}
        assert assertion.assurance_state == "STALE"
        assert unrelated.assurance_state == "STALE"


def test_valid_phase5_evidence_for_different_target_cannot_validate_assertion(assurance_db) -> None:
    from app.services.continuous_assurance import ContinuousAssuranceService

    service = ContinuousAssuranceService()
    with assurance_db.begin() as db:
        tenant, provider = _seed_tenant_and_provider(db, name="Material Binding")
        assertion, scenario = _create_assertion_and_scenario(
            db, service=service, tenant_id=tenant.id
        )
        run = service.start_validation(
            db,
            tenant_id=tenant.id,
            scenario_id=scenario.id,
            trigger="manual",
            triggered_by_ref="user:owner",
            started_at=NOW,
        )
        wrong_template = dict(scenario.action_template or {})
        wrong_template["target_ref"] = f"fixture:{tenant.id}:different-document"
        evidence = _add_phase5_evidence(
            db,
            provider=provider,
            tenant_id=tenant.id,
            action_id="phase6-wrong-target",
            at=NOW,
            matched_execution=True,
            action_template=wrong_template,
        )
        completed = service.complete_validation(
            db,
            tenant_id=tenant.id,
            run_id=run.id,
            phase5_evidence=evidence,
            completed_at=NOW + timedelta(seconds=1),
        )
        assert completed.outcome == "FAIL_WRONG_CONTROL_POINT"
        assert assertion.assurance_state == "UNKNOWN"


def test_assurance_api_is_read_only_and_tenant_scoped(assurance_db) -> None:
    from app.api.routers.continuous_assurance import assertion_detail
    from app.services.continuous_assurance import ContinuousAssuranceService

    service = ContinuousAssuranceService()
    with assurance_db.begin() as db:
        tenant_a, _provider_a = _seed_tenant_and_provider(db, name="API A")
        tenant_b, _provider_b = _seed_tenant_and_provider(db, name="API B")
        assertion, _scenario = _create_assertion_and_scenario(
            db, service=service, tenant_id=tenant_a.id
        )
        response = assertion_detail(
            assertion.id,
            ctx=SimpleNamespace(tenant=tenant_a),
            db=db,
        )
        assert response["assertion_id"] == assertion.id
        assert response["assurance_state"] == "UNKNOWN"
        with pytest.raises(HTTPException) as exc:
            assertion_detail(
                assertion.id,
                ctx=SimpleNamespace(tenant=tenant_b),
                db=db,
            )
        assert exc.value.status_code == 404


@pytest.mark.parametrize(
    ("assurance_state", "expected_verification"),
    [
        ("current", "verified"),
        ("stale", "unverified"),
        ("unknown", "unverified"),
        ("regressed", "broken"),
    ],
)
def test_selector_conservatively_consumes_capability_assurance_state(
    assurance_state: str,
    expected_verification: str,
) -> None:
    from app.services.native_control.selection_service import _claim

    claim = _claim(
        {
            "level": "inline_bound",
            "verification_status": "verified",
            "assurance_state": assurance_state,
            "evidence_refs": ["evidence:phase6:assertion"],
        }
    )
    assert claim.verification_status.value == expected_verification
