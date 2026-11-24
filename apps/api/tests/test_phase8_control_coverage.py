from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.control_coverage import (
    CoverageDimension,
    CoverageApplicability,
    CoverageAssurance,
    CoverageCapability,
    CoverageDeployment,
    ExecutiveCoverageFacts,
    ExecutiveCoverageState,
    derive_executive_coverage,
)
from app.db import models as _models  # noqa: F401
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoverageAssessment,
    ControlCoverageGap,
    ControlCoveragePath,
    ControlCoverageSnapshot,
    CoverageScope,
    DeploymentSurface,
)
from app.db.models.activity_lineage import ActivityLineage
from app.db.models.continuous_assurance import ControlAssertion, DriftSignal
from app.db.models.native_control import NativeControlSelection
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.executive import (
    MAX_EXECUTIVE_ASSESSMENT_INPUTS,
    MAX_EXECUTIVE_PATH_INPUTS,
    CoverageAssessmentInput,
    _validate_executive_input_count,
    compare_coverage_snapshots,
    get_coverage_assessment_explanation,
    get_executive_coverage_summary,
    refresh_executive_coverage_snapshot,
)
from app.services.control_coverage.executive_sources import collect_executive_coverage_inputs


NOW = datetime(2026, 8, 25, 12, tzinfo=timezone.utc)


def _facts(**changes: object) -> ExecutiveCoverageFacts:
    base = ExecutiveCoverageFacts(
        applicability=CoverageApplicability.APPLICABLE,
        deployment=CoverageDeployment.CONFIGURED,
        capability=CoverageCapability.VERIFIED,
        assurance=CoverageAssurance.CURRENT,
        evidence_quality="cryptographically_verified",
        evidence_refs=("evidence:phase8-current",),
        expected_control_points=("runtime:gate",),
        contributing_control_points=("runtime:gate",),
        missing_contributions=(),
        bypass_reachable=False,
        compensating_bypass_control=False,
        previously_validated=True,
        unresolved_regression=False,
    )
    return replace(base, **changes)


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, ExecutiveCoverageState.COVERED_CURRENT),
        ({"assurance": CoverageAssurance.STALE}, ExecutiveCoverageState.COVERED_STALE),
        ({"assurance": CoverageAssurance.REGRESSED}, ExecutiveCoverageState.REGRESSED),
        ({"capability": CoverageCapability.PARTIAL}, ExecutiveCoverageState.PARTIALLY_COVERED),
        ({"missing_contributions": ("endpoint:file",)}, ExecutiveCoverageState.PARTIALLY_COVERED),
        ({"deployment": CoverageDeployment.MISSING}, ExecutiveCoverageState.GAP),
        ({"capability": CoverageCapability.UNSUPPORTED}, ExecutiveCoverageState.UNSUPPORTED),
        ({"capability": CoverageCapability.UNVERIFIED, "assurance": CoverageAssurance.UNKNOWN}, ExecutiveCoverageState.CONFIGURED_UNVALIDATED),
        ({"applicability": CoverageApplicability.UNKNOWN}, ExecutiveCoverageState.UNKNOWN),
        ({"applicability": CoverageApplicability.NOT_APPLICABLE}, ExecutiveCoverageState.NOT_APPLICABLE),
        ({"bypass_reachable": True}, ExecutiveCoverageState.PARTIALLY_COVERED),
        ({"bypass_reachable": True, "compensating_bypass_control": True}, ExecutiveCoverageState.COVERED_CURRENT),
        ({"evidence_refs": ()}, ExecutiveCoverageState.CONFIGURED_UNVALIDATED),
    ],
)
def test_phase8_derivation_keeps_orthogonal_truth_distinct(
    changes: dict[str, object], expected: ExecutiveCoverageState
) -> None:
    result = derive_executive_coverage(_facts(**changes))
    assert result.state is expected
    assert result.reason_code
    assert result.explanation


def _input(
    key: str,
    *,
    dimension: str,
    surface: str,
    facts: ExecutiveCoverageFacts,
    asset_ref: str | None = None,
    action_class: str = "document_update",
    criticality: str = "high",
) -> CoverageAssessmentInput:
    return CoverageAssessmentInput(
        assessment_key=key,
        asset_ref=asset_ref or f"asset:{key}",
        action_class=action_class,
        action_path_ref=f"action:{key}",
        deployment_surface=surface,
        dimension=dimension,
        requirement_ref=f"requirement:{dimension}",
        applicability_reason="The action path requires this control property.",
        facts=facts,
        control_plan_ref=f"control-plan:{key}",
        validation_refs=(f"validation:{key}",),
        lineage_refs=(f"lineage:{key}",),
        criticality=criticality,
        source_versions={"policy": "policy:v1", "inventory": "inventory:v1"},
    )


def _session(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'phase8.sqlite3'}")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def test_phase8_reference_estate_snapshot_comparison_and_tenant_isolation(tmp_path) -> None:
    engine, sessions = _session(tmp_path)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Phase 8", slug=f"phase8-{uuid4().hex[:8]}", is_active=True)
            foreign = Tenant(name="Foreign", slug=f"foreign-{uuid4().hex[:8]}", is_active=True)
            db.add_all([tenant, foreign])
            db.flush()
            reference = [
                _input("runtime-current", dimension="target_binding", surface="runtime", facts=_facts()),
                _input("endpoint-file", dimension="file_write_control", surface="endpoint", facts=_facts(expected_control_points=("endpoint:file",), contributing_control_points=("endpoint:file",))),
                _input("endpoint-purpose", dimension="purpose_binding", surface="endpoint", facts=_facts(capability=CoverageCapability.PARTIAL, expected_control_points=("runtime:semantic", "endpoint:file"), contributing_control_points=("endpoint:file",), missing_contributions=("runtime:semantic",))),
                _input("browser-account", dimension="ai_account_boundary", surface="browser", facts=_facts(assurance=CoverageAssurance.STALE)),
                _input("direct-api", dimension="pre_execution_prevention", surface="saas_api", facts=_facts(bypass_reachable=True, expected_control_points=("gateway:inline",), contributing_control_points=("runtime:semantic",))),
                _input("unknown-owner", dimension="executing_principal_identity", surface="runtime", facts=_facts(applicability=CoverageApplicability.UNKNOWN, deployment=CoverageDeployment.UNKNOWN, capability=CoverageCapability.UNKNOWN, assurance=CoverageAssurance.UNKNOWN, evidence_refs=(), expected_control_points=(), contributing_control_points=(), previously_validated=False), criticality="medium"),
            ]
            first = refresh_executive_coverage_snapshot(
                db,
                tenant_id=tenant.id,
                scope_type="tenant",
                scope_key="all",
                display_name="Enterprise AI estate",
                inputs=reference,
                source_versions={"inventory": "inventory:v1", "policy": "policy:v1"},
                assessed_at=NOW,
            )
            first_id = first.id
            first_summary = get_executive_coverage_summary(db, tenant_id=tenant.id, snapshot_id=first_id)
            assert first_summary is not None
            assert first_summary["state_distribution"] == {
                "covered_current": 2,
                "covered_stale": 1,
                "partially_covered": 2,
                "configured_unvalidated": 0,
                "regressed": 0,
                "gap": 0,
                "unsupported": 0,
                "unknown": 1,
                "not_applicable": 0,
            }
            assert first_summary["validated_coverage_percent"] == pytest.approx(33.33)
            assert first_summary["denominator"] == 6
            assert first_summary["unknown_population"] == 1
            assert first_summary["surface_breakdown"]["endpoint"]["covered_current"] == 1
            assert first_summary["surface_breakdown"]["endpoint"]["partially_covered"] == 1
            assert first_summary["top_gaps"][0]["priority"] in {"P0", "P1"}

            changed = [
                replace(item, facts=replace(item.facts, assurance=CoverageAssurance.REGRESSED))
                if item.assessment_key == "runtime-current"
                else item
                for item in reference
            ]
            second = refresh_executive_coverage_snapshot(
                db,
                tenant_id=tenant.id,
                scope_type="tenant",
                scope_key="all",
                display_name="Enterprise AI estate",
                inputs=changed,
                source_versions={"inventory": "inventory:v1", "policy": "policy:v1"},
                assessed_at=NOW + timedelta(hours=1),
            )
            comparison = compare_coverage_snapshots(
                db, tenant_id=tenant.id, current_snapshot_id=second.id, previous_snapshot_id=first_id
            )
            assert comparison is not None
            assert comparison["transitions"]["covered_current_to_regressed"] == 1
            assert comparison["unchanged"] == 5

            assessment = db.scalar(
                select(ControlCoverageAssessment).where(
                    ControlCoverageAssessment.tenant_id == tenant.id,
                    ControlCoverageAssessment.snapshot_id == second.id,
                    ControlCoverageAssessment.assessment_key == "runtime-current",
                )
            )
            assert assessment is not None
            explanation = get_coverage_assessment_explanation(db, tenant_id=tenant.id, assessment_id=assessment.id)
            assert explanation is not None
            assert explanation["coverage_state"] == "regressed"
            assert explanation["evidence_refs"] == ["evidence:phase8-current"]
            assert explanation["lineage_refs"] == ["lineage:runtime-current"]
            assert get_coverage_assessment_explanation(db, tenant_id=foreign.id, assessment_id=assessment.id) is None
            assert get_executive_coverage_summary(db, tenant_id=foreign.id, snapshot_id=second.id) is None

            assert db.scalar(select(ControlCoverageSnapshot).where(ControlCoverageSnapshot.id == second.id)) is not None
            assert db.scalar(select(CoverageScope).where(CoverageScope.tenant_id == tenant.id)) is not None
            assert db.scalars(select(ControlCoverageGap).where(ControlCoverageGap.snapshot_id == second.id)).all()
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_phase8_summary_does_not_load_unbounded_assessment_or_gap_collections(tmp_path) -> None:
    engine, sessions = _session(tmp_path)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Bounded Summary", slug=f"bounded-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            snapshot = refresh_executive_coverage_snapshot(
                db,
                tenant_id=tenant.id,
                scope_type="tenant",
                scope_key="all",
                display_name="Enterprise AI estate",
                inputs=[
                    _input(
                        f"bounded-{index}",
                        dimension="target_binding",
                        surface="runtime",
                        facts=_facts(),
                    )
                    for index in range(12)
                ],
                source_versions={"coverage": "control-coverage/1.0"},
                assessed_at=NOW,
            )
            tenant_id = tenant.id
            snapshot_id = snapshot.id

        class RejectUnboundedCollectionLoads:
            def __init__(self, session):
                self.session = session

            def __getattr__(self, name):
                return getattr(self.session, name)

            def scalars(self, statement, *args, **kwargs):
                sql = str(statement).lower()
                if (
                    "control_coverage_assessments" in sql
                    or "control_coverage_gaps" in sql
                ) and " limit " not in sql:
                    raise AssertionError("summary attempted an unbounded collection load")
                return self.session.scalars(statement, *args, **kwargs)

        with sessions() as db:
            summary = get_executive_coverage_summary(
                RejectUnboundedCollectionLoads(db),
                tenant_id=tenant_id,
                snapshot_id=snapshot_id,
            )
        assert summary is not None
        assert summary["assessment_count"] == 12
        assert summary["denominator"] == 12
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_phase8_snapshot_uses_bounded_bulk_writes_for_assessments_and_gaps(tmp_path) -> None:
    engine, sessions = _session(tmp_path)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Bounded Writer", slug=f"bounded-writer-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id

        class RejectPerRowCoverageAdds:
            def __init__(self, session):
                self.session = session

            def __getattr__(self, name):
                return getattr(self.session, name)

            def add(self, instance):
                if isinstance(instance, (ControlCoverageAssessment, ControlCoverageGap)):
                    raise AssertionError("snapshot retained a per-row coverage ORM object")
                return self.session.add(instance)

        with sessions.begin() as db:
            wrapped = RejectPerRowCoverageAdds(db)
            snapshot = refresh_executive_coverage_snapshot(
                wrapped,
                tenant_id=tenant_id,
                scope_type="tenant",
                scope_key="all",
                display_name="Enterprise AI estate",
                inputs=[
                    _input(
                        f"bulk-{index}",
                        dimension="target_binding",
                        surface="runtime",
                        facts=_facts(
                            capability=(
                                CoverageCapability.PARTIAL
                                if index % 2
                                else CoverageCapability.VERIFIED
                            )
                        ),
                    )
                    for index in range(25)
                ],
                source_versions={"coverage": "control-coverage/1.0"},
                assessed_at=NOW,
            )
            snapshot_id = snapshot.id

        with sessions() as db:
            assessments = db.scalars(
                select(ControlCoverageAssessment).where(
                    ControlCoverageAssessment.tenant_id == tenant_id,
                    ControlCoverageAssessment.snapshot_id == snapshot_id,
                )
            ).all()
            gaps = db.scalars(
                select(ControlCoverageGap).where(
                    ControlCoverageGap.tenant_id == tenant_id,
                    ControlCoverageGap.snapshot_id == snapshot_id,
                )
            ).all()
            summary = get_executive_coverage_summary(
                db, tenant_id=tenant_id, snapshot_id=snapshot_id
            )
        assert len(assessments) == 25
        assert len(gaps) == 12
        assert summary is not None
        assert summary["assessment_count"] == 25
        assert summary["denominator"] == 25
        assert summary["state_distribution"]["covered_current"] == 13
        assert summary["state_distribution"]["partially_covered"] == 12
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_phase8_profile_terms_remain_vertical_neutral() -> None:
    result = derive_executive_coverage(_facts())
    serialized = f"{result.reason_code} {result.explanation}".lower()
    assert not any(term in serialized for term in ("bank", "patient", "citizen", "account holder"))


def test_phase8_snapshot_limit_covers_every_dimension_from_the_bounded_path_query() -> None:
    assert MAX_EXECUTIVE_ASSESSMENT_INPUTS == MAX_EXECUTIVE_PATH_INPUTS * len(CoverageDimension)
    assert MAX_EXECUTIVE_ASSESSMENT_INPUTS >= 21_651
    _validate_executive_input_count(MAX_EXECUTIVE_ASSESSMENT_INPUTS)
    with pytest.raises(ValueError, match="bounded P0 limit"):
        _validate_executive_input_count(MAX_EXECUTIVE_ASSESSMENT_INPUTS + 1)


def test_phase8_migration_is_linear_additive_and_preserves_existing_snapshots() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "app/db/migrations/versions/0072_phase8_control_coverage.py"
    ).read_text(encoding="utf-8")
    assert 'revision = "0072_phase8_control_coverage"' in source
    assert 'down_revision = "0071_phase7_activity_lineage"' in source
    assert 'op.create_table(\n        "coverage_scopes"' in source
    assert 'op.create_table(\n        "control_coverage_assessments"' in source
    assert 'op.create_table(\n        "control_coverage_gaps"' in source
    assert 'op.drop_table("control_coverage_snapshots")' not in source


def test_phase8_consumes_phase5_phase6_phase7_and_bypass_truth_without_cross_asset_drift(tmp_path) -> None:
    engine, sessions = _session(tmp_path)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Authoritative", slug=f"authoritative-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            surface = DeploymentSurface(
                tenant_id=tenant.id,
                source_kind="native_control",
                source_id="runtime-gate",
                name="Runtime Gate",
                surface_type="native_hook",
                deployment_mode="inline",
                deployment_family="runtime",
                hosting_mode="hybrid",
                environment="production",
                status="active",
                capability_profile={},
                capability_sources=["native_control:runtime-gate"],
                control_capability="inline",
                evidence_capability="complete",
                containment_capability="direct",
                bypass_detection_capability="supported",
                health_status="healthy",
                health_reason="validated",
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
            db.add(surface)
            db.flush()
            path = ControlCoveragePath(
                tenant_id=tenant.id,
                path_key="a" * 64,
                asset_ref="asset:generic-agent",
                identity_type="agent",
                identity_ref="agent:generic",
                runtime_ref="runtime:generic",
                deployment_surface_id=surface.id,
                deployment_surface_ref="surface:runtime-gate",
                destination_type="tool",
                destination_ref="tool:generic-write",
                source_refs=["ai_action:action-generic"],
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
            db.add(path)
            db.flush()
            db.add_all(
                [
                    ControlCoverageAssertion(
                        tenant_id=tenant.id,
                        path_id=path.id,
                        dimension="target_binding",
                        state="covered",
                        reason_code="verified_target_binding",
                        explanation="Target binding was proven by signed action evidence.",
                        methodology_version="control-coverage/2.0",
                        evaluator_version="phase8-test",
                        evidence_refs=["decision_receipt:generic"],
                        observed_at=NOW,
                        evaluated_at=NOW,
                        valid_until=NOW + timedelta(hours=1),
                    ),
                    ControlCoverageAssertion(
                        tenant_id=tenant.id,
                        path_id=path.id,
                        dimension="bypass",
                        state="covered",
                        reason_code="bypass_detector_operational",
                        explanation="No reachable bypass is currently evidenced.",
                        methodology_version="control-coverage/1.0",
                        evaluator_version="phase8-test",
                        evidence_refs=["evidence:bypass-monitor"],
                        observed_at=NOW,
                        evaluated_at=NOW,
                        valid_until=NOW + timedelta(hours=1),
                    ),
                ]
            )
            current = ControlAssertion(
                tenant_id=tenant.id,
                assertion_key="target-binding:generic",
                assertion_type="parameter_integrity",
                asset_ref="asset:generic-agent",
                action_class="document_update",
                required_capability="target_binding",
                expected_outcome="PASS_CONTROLLED",
                required_evidence_level="CRYPTOGRAPHICALLY_VERIFIED",
                assurance_state="CURRENT",
                assurance_version=3,
                last_validation_run_id="validation-current",
                last_validated_at=NOW,
                fresh_until=NOW + timedelta(hours=1),
            )
            unrelated = ControlAssertion(
                tenant_id=tenant.id,
                assertion_key="target-binding:unrelated",
                assertion_type="parameter_integrity",
                asset_ref="asset:unrelated",
                action_class="document_update",
                required_capability="target_binding",
                expected_outcome="PASS_CONTROLLED",
                required_evidence_level="CRYPTOGRAPHICALLY_VERIFIED",
                assurance_state="REGRESSED",
                assurance_version=2,
                last_validation_run_id="validation-unrelated",
                last_validated_at=NOW,
                fresh_until=NOW,
            )
            db.add_all([current, unrelated])
            db.flush()
            db.add(
                DriftSignal(
                    tenant_id=tenant.id,
                    signal_hash="f" * 64,
                    category="provider_version",
                    dependency_key="provider:unrelated",
                    previous_digest="b" * 64,
                    current_digest="c" * 64,
                    source_ref="provider:unrelated",
                    affected_assertion_ids=[unrelated.id],
                    status="OPEN",
                    observed_at=NOW,
                )
            )
            db.execute(
                NativeControlSelection.__table__.insert().values(
                    selection_id="selection-generic",
                    tenant_id=tenant.id,
                    action_id="action-generic",
                    canonical_action_hash="1" * 64,
                    control_plan_id="plan:generic",
                    control_plan_digest="2" * 64,
                    control_plan_material={},
                    mandatory_enforcement_floor_requirements=[],
                    selected_mandatory_floors=[],
                    semantic_primary_control_point_id="runtime:gate",
                    secondary_context_points=[],
                    verification_points=["runtime:receipt-verifier"],
                    unsatisfied_mandatory_floors=[],
                    rejected_mandatory_floor_candidates={},
                    control_requirement_unsatisfied=False,
                    control_plan_reason_codes=[],
                    degradation_policy={},
                    failure_behavior="fail_closed",
                    plan_issued_at=NOW,
                    plan_expires_at=NOW + timedelta(minutes=5),
                    contract_hashes={},
                    secondary_observation_points=[],
                    containment_points=[],
                    rejected_candidates=[],
                    selection_reason="phase8-authoritative-source",
                    required_capabilities=["target_binding"],
                    satisfied_capabilities=["target_binding"],
                    unsatisfied_capabilities=[],
                    assurance_level=3,
                    coverage_implications={},
                    known_blind_spots=[],
                    selector_version="phase8-test",
                    matrix_version="matrix:v1",
                    policy_version="policy:v1",
                    input_digest="3" * 64,
                    selected_at=NOW,
                )
            )
            lineage = ActivityLineage(
                tenant_id=tenant.id,
                lineage_key="4" * 64,
                source_watermark="5" * 64,
                seed_action_id="action-generic",
                seed_runtime_event_id="runtime-event-generic",
                root_action_id="action-generic",
                status="COMPLETE",
                blind_spots=[],
                created_at=NOW,
            )
            db.add(lineage)
            db.flush()

            inputs, versions = collect_executive_coverage_inputs(db, tenant_id=tenant.id, assessed_at=NOW)
            target = next(item for item in inputs if item.dimension == "target_binding")
            assert target.facts.assurance is CoverageAssurance.CURRENT
            assert target.facts.capability is CoverageCapability.VERIFIED
            assert target.facts.bypass_reachable is False
            assert target.control_plan_ref == "plan:generic"
            assert target.validation_refs == ["validation_run:validation-current"] or target.validation_refs == ("validation_run:validation-current",)
            assert target.lineage_refs == (f"lineage:{lineage.id}",)
            assert versions["policy"] == "policy:v1"
            assert derive_executive_coverage(target.facts).state is ExecutiveCoverageState.COVERED_CURRENT

            current.assurance_state = "STALE"
            current.fresh_until = NOW - timedelta(seconds=1)
            inputs, _ = collect_executive_coverage_inputs(db, tenant_id=tenant.id, assessed_at=NOW)
            target = next(item for item in inputs if item.dimension == "target_binding")
            assert derive_executive_coverage(target.facts).state is ExecutiveCoverageState.COVERED_STALE

            bypass = db.scalar(
                select(ControlCoverageAssertion).where(
                    ControlCoverageAssertion.tenant_id == tenant.id,
                    ControlCoverageAssertion.path_id == path.id,
                    ControlCoverageAssertion.dimension == "bypass",
                )
            )
            assert bypass is not None
            bypass.state = "not_covered"
            bypass.reason_code = "bypass_observed"
            inputs, _ = collect_executive_coverage_inputs(db, tenant_id=tenant.id, assessed_at=NOW)
            target = next(item for item in inputs if item.dimension == "target_binding")
            assert target.facts.bypass_reachable is True
            assert derive_executive_coverage(target.facts).state is ExecutiveCoverageState.PARTIALLY_COVERED
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
