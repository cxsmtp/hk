from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def test_maturity_stage_requires_explicit_evidence_gates() -> None:
    from app.services.maturity_curve.service import MaturityEvidence, derive_maturity_stage

    unknown = derive_maturity_stage(
        MaturityEvidence(
            connected=False,
            observation_count=0,
            source_kinds=(),
            asset_identity_known=False,
            usage_baseline_ready=False,
            recommendation_ready=False,
            simulation_passed=False,
            controlled=False,
            assurance_current=False,
            blocking_gaps=("no_observation",),
        )
    )
    assert unknown.stage == "UNKNOWN"
    assert unknown.missing_gates == ("connected", "observation")

    monitoring = derive_maturity_stage(
        MaturityEvidence(
            connected=True,
            observation_count=12,
            source_kinds=("browser",),
            asset_identity_known=False,
            usage_baseline_ready=False,
            recommendation_ready=False,
            simulation_passed=False,
            controlled=False,
            assurance_current=False,
        )
    )
    assert monitoring.stage == "MONITORING"

    understanding = derive_maturity_stage(
        MaturityEvidence(
            connected=True,
            observation_count=12,
            source_kinds=("browser", "runtime"),
            asset_identity_known=True,
            usage_baseline_ready=True,
            recommendation_ready=False,
            simulation_passed=False,
            controlled=False,
            assurance_current=False,
        )
    )
    assert understanding.stage == "UNDERSTANDING"

    policy_ready = derive_maturity_stage(
        MaturityEvidence(
            connected=True,
            observation_count=12,
            source_kinds=("browser", "runtime"),
            asset_identity_known=True,
            usage_baseline_ready=True,
            recommendation_ready=True,
            simulation_passed=True,
            controlled=False,
            assurance_current=False,
        )
    )
    assert policy_ready.stage == "POLICY_READY"

    controlled = derive_maturity_stage(
        MaturityEvidence(
            connected=True,
            observation_count=12,
            source_kinds=("browser", "runtime"),
            asset_identity_known=True,
            usage_baseline_ready=True,
            recommendation_ready=True,
            simulation_passed=True,
            controlled=True,
            assurance_current=False,
        )
    )
    assert controlled.stage == "CONTROLLED"

    assured = derive_maturity_stage(
        MaturityEvidence(
            connected=True,
            observation_count=12,
            source_kinds=("browser", "runtime"),
            asset_identity_known=True,
            usage_baseline_ready=True,
            recommendation_ready=True,
            simulation_passed=True,
            controlled=True,
            assurance_current=True,
        )
    )
    assert assured.stage == "ASSURED"


def test_maturity_stage_does_not_average_away_a_blocking_gap() -> None:
    from app.services.maturity_curve.service import MaturityEvidence, derive_maturity_stage

    result = derive_maturity_stage(
        MaturityEvidence(
            connected=True,
            observation_count=80,
            source_kinds=("browser", "endpoint", "runtime", "saas_api"),
            asset_identity_known=True,
            usage_baseline_ready=True,
            recommendation_ready=True,
            simulation_passed=True,
            controlled=True,
            assurance_current=True,
            blocking_gaps=("high_risk_scope_unknown",),
        )
    )

    assert result.stage == "CONTROLLED"
    assert result.blocking_gaps == ("high_risk_scope_unknown",)


def test_maturity_records_are_tenant_scoped_and_reference_only(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.maturity_curve import (
        MaturityAssessment,
        MaturityObservationWindow,
        MaturityScope,
        TenantMaturityEntitlement,
    )
    from app.db.models.tenant import Tenant
    from app.db.session import Base

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Maturity One", slug=f"maturity-{uuid4().hex[:8]}", is_active=True)
            foreign = Tenant(name="Maturity Two", slug=f"foreign-{uuid4().hex[:8]}", is_active=True)
            db.add_all([tenant, foreign])
            db.flush()

            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="assurance", enabled=True))
            scope = MaturityScope(
                tenant_id=tenant.id,
                scope_key="enterprise:all",
                scope_type="organization",
                display_name="Enterprise AI estate",
                filters={"environment": ["production"]},
                active=True,
            )
            db.add(scope)
            db.flush()
            window = MaturityObservationWindow(
                tenant_id=tenant.id,
                scope_id=scope.id,
                window_start=datetime(2026, 9, 1, tzinfo=timezone.utc),
                window_end=datetime(2026, 9, 2, tzinfo=timezone.utc),
                input_digest="a" * 64,
                source_watermarks={"ai_actions": "watermark:1"},
                source_counts={"ai_actions": 7},
                evidence_refs=["ai_action:opaque-1"],
            )
            db.add(window)
            db.flush()
            assessment = MaturityAssessment(
                tenant_id=tenant.id,
                scope_id=scope.id,
                observation_window_id=window.id,
                stage="MONITORING",
                confidence=0.75,
                source_diversity=1,
                indicators={"observed_actions": 7},
                missing_gates=["asset_identity"],
                blocking_gaps=[],
                evidence_refs=["ai_action:opaque-1"],
                status="CURRENT",
                methodology_version="maturity-v1",
            )
            db.add(assessment)

        with sessions() as db:
            visible = db.scalars(
                select(MaturityAssessment).where(MaturityAssessment.tenant_id == tenant.id)
            ).all()
            hidden = db.scalars(
                select(MaturityAssessment).where(MaturityAssessment.tenant_id == foreign.id)
            ).all()
            assert [row.stage for row in visible] == ["MONITORING"]
            assert hidden == []
            assert "raw_prompt" not in MaturityObservationWindow.__table__.columns
            assert "action_payload" not in MaturityAssessment.__table__.columns
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_typed_policy_conditions_constrain_the_existing_runtime_evaluator(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.policy import PolicyPack, PolicyVersion
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.policy_scope_service import resolve_scoped_policy_decision

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'typed-policy.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Typed Policy", slug=f"typed-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            pack = PolicyPack(tenant_id=tenant.id, name="Typed conditions", description="", status="active")
            db.add(pack)
            db.flush()
            version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=pack.id,
                version="typed-v1",
                scope={
                    "scoped_rules": [
                        {
                            "rule_id": "general-allow",
                            "enabled": True,
                            "priority": 100,
                            "effect": {"decision": "allow"},
                        },
                        {
                            "rule_id": "runtime-write-block",
                            "enabled": True,
                            "priority": 100,
                            "subjects": {"source_surfaces": ["runtime"]},
                            "condition_tree": {
                                "all": [
                                    {"field": "provider", "operator": "equals", "value": "openai"},
                                    {"not": {"field": "operation", "operator": "equals", "value": "read"}},
                                ]
                            },
                            "effect": {"decision": "block"},
                        },
                    ]
                },
                enforcement_defaults={},
                guardian_contracts=[],
                contract_json={},
            )
            db.add(version)
            db.flush()

            write_decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=version.id,
                context={
                    "source_surface": "runtime",
                    "provider": "openai",
                    "operation": "write",
                    "action_type": "tool_call",
                },
            )
            read_decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=version.id,
                context={
                    "source_surface": "runtime",
                    "provider": "openai",
                    "operation": "read",
                    "action_type": "tool_call",
                },
            )

            assert write_decision.rule_id == "runtime-write-block"
            assert write_decision.decision == "block"
            assert read_decision.rule_id == "general-allow"
            assert read_decision.decision == "allow"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_maturity_lifecycle_records_bind_to_existing_policy_versions(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.maturity_curve import (
        MaturityExecutiveSnapshot,
        MaturityObservedUsagePattern,
        MaturityPolicyEffectivenessSnapshot,
        MaturityPolicyException,
        MaturityPolicyRecommendation,
        MaturityPolicyRollout,
        MaturityPolicySimulation,
        MaturityUsageBaseline,
    )
    from app.db.models.policy import PolicyPack, PolicyVersion
    from app.db.models.tenant import Tenant
    from app.db.session import Base

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-lifecycle.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Lifecycle", slug=f"lifecycle-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            from app.db.models.maturity_curve import MaturityAssessment, MaturityObservationWindow, MaturityScope

            scope = MaturityScope(
                tenant_id=tenant.id,
                scope_key="surface:runtime",
                scope_type="surface",
                display_name="Runtime",
                filters={"source_surface": ["runtime"]},
            )
            db.add(scope)
            db.flush()
            window = MaturityObservationWindow(
                tenant_id=tenant.id,
                scope_id=scope.id,
                window_start=datetime(2026, 9, 1, tzinfo=timezone.utc),
                window_end=datetime(2026, 9, 2, tzinfo=timezone.utc),
                input_digest="b" * 64,
                source_watermarks={"ai_actions": "1"},
                source_counts={"ai_actions": 14},
                evidence_refs=["ai_action:opaque-1"],
            )
            db.add(window)
            db.flush()
            assessment = MaturityAssessment(
                tenant_id=tenant.id,
                scope_id=scope.id,
                observation_window_id=window.id,
                stage="POLICY_READY",
                confidence=0.8,
                source_diversity=2,
                indicators={"simulation_passed": True},
                missing_gates=[],
                blocking_gaps=[],
                evidence_refs=["window:opaque-1"],
                status="CURRENT",
                methodology_version="maturity-v1",
            )
            db.add(assessment)
            db.flush()
            pack = PolicyPack(tenant_id=tenant.id, name="Recommendation pack", description="", status="draft")
            db.add(pack)
            db.flush()
            version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=pack.id,
                version="maturity-v1",
                scope={"scoped_rules": []},
                enforcement_defaults={"default_decision": "warn"},
                guardian_contracts=[],
                contract_json={},
            )
            db.add(version)
            db.flush()
            baseline = MaturityUsageBaseline(
                tenant_id=tenant.id,
                scope_id=scope.id,
                observation_window_id=window.id,
                baseline_version=1,
                baseline_digest="c" * 64,
                sample_count=14,
                source_diversity=2,
                aggregates={"allow": 12, "warn": 2},
                status="COMPLETE",
            )
            db.add(baseline)
            db.flush()
            db.add(
                MaturityObservedUsagePattern(
                    tenant_id=tenant.id,
                    scope_id=scope.id,
                    observation_window_id=window.id,
                    pattern_key="provider:openai",
                    dimension="provider",
                    value_ref="provider:openai",
                    observation_count=14,
                    confidence=0.8,
                    evidence_refs=["ai_action:opaque-1"],
                )
            )
            recommendation = MaturityPolicyRecommendation(
                tenant_id=tenant.id,
                scope_id=scope.id,
                assessment_id=assessment.id,
                recommendation_key="runtime:external-write",
                title="Review external runtime writes",
                category="data_transfer",
                status="DRAFT",
                policy_draft={"scoped_rules": []},
                evidence_refs=["baseline:opaque-1"],
                assumptions=["metadata completeness"],
                unknowns=[],
                confidence=0.82,
                estimated_impact={"affected_actions": 2},
                estimated_friction={"approval_rate": 0.1},
                recommendation_digest="d" * 64,
            )
            db.add(recommendation)
            db.flush()
            simulation = MaturityPolicySimulation(
                tenant_id=tenant.id,
                scope_id=scope.id,
                recommendation_id=recommendation.id,
                policy_version_id=version.id,
                input_digest="e" * 64,
                sample_count=14,
                outcome_counts={"allow": 11, "warn": 3},
                scope_breakdown={"runtime": {"warn": 3}},
                unknown_count=0,
                passed=True,
                evidence_refs=["window:opaque-1"],
            )
            db.add(simulation)
            db.flush()
            rollout = MaturityPolicyRollout(
                tenant_id=tenant.id,
                scope_id=scope.id,
                recommendation_id=recommendation.id,
                policy_version_id=version.id,
                state="SHADOW",
                mode="shadow",
                rollout_digest="f" * 64,
            )
            db.add(rollout)
            db.flush()
            db.add(
                MaturityPolicyException(
                    tenant_id=tenant.id,
                    rollout_id=rollout.id,
                    policy_version_id=version.id,
                    scope={"users": ["user:opaque-1"], "action_types": ["read"]},
                    reason="bounded validation exception",
                    status="APPROVED",
                    requested_by_ref="user:opaque-1",
                    approved_by_ref="user:opaque-2",
                    expires_at=datetime(2026, 9, 3, tzinfo=timezone.utc),
                )
            )
            db.add(
                MaturityPolicyEffectivenessSnapshot(
                    tenant_id=tenant.id,
                    scope_id=scope.id,
                    rollout_id=rollout.id,
                    policy_version_id=version.id,
                    observation_window_id=window.id,
                    status="CURRENT",
                    outcome_summary={"prevented": 1, "friction": 0},
                    evidence_refs=["assurance:opaque-1"],
                    input_digest="a" * 64,
                )
            )
            db.add(
                MaturityExecutiveSnapshot(
                    tenant_id=tenant.id,
                    scope_id=scope.id,
                    input_digest="9" * 64,
                    stage_distribution={"POLICY_READY": 1},
                    coverage_refs=["coverage:opaque-1"],
                    gap_summary={"unknown": 0},
                    recommendation_summary={"open": 1},
                )
            )

        with sessions() as db:
            assert db.scalar(select(MaturityPolicyRollout).where(MaturityPolicyRollout.tenant_id == tenant.id)) is not None
            assert db.scalar(select(MaturityPolicySimulation).where(MaturityPolicySimulation.tenant_id == tenant.id)) is not None
            assert "raw_prompt" not in MaturityPolicyRecommendation.__table__.columns
            assert "action_payload" not in MaturityPolicySimulation.__table__.columns
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_maturity_curve_migration_is_additive_and_linear() -> None:
    source = Path("app/db/migrations/versions/0080_maturity_curve_policy_intelligence.py").read_text(
        encoding="utf-8"
    )

    assert 'revision = "0080_maturity_curve_policy_intelligence"' in source
    assert 'down_revision = "0079_instruction_tool_provenance_integration"' in source
    for table in (
        "tenant_maturity_entitlements",
        "maturity_scopes",
        "maturity_observation_windows",
        "maturity_assessments",
        "maturity_usage_baselines",
        "maturity_policy_recommendations",
        "maturity_policy_simulations",
        "maturity_policy_rollouts",
        "maturity_policy_effectiveness_snapshots",
        "maturity_executive_snapshots",
    ):
        assert f'"{table}"' in source
    assert 'op.drop_table("policy_versions")' not in source
    assert 'op.drop_table("ai_actions")' not in source


def test_materialize_scope_derives_baseline_from_existing_action_metadata(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.activity_audit import AIAction, AISession
    from app.db.models.maturity_curve import TenantMaturityEntitlement
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.maturity_curve.executive import materialize_executive_snapshot
    from app.services.maturity_curve.service import create_maturity_scope, materialize_maturity_scope

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-materialize.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)
    try:
        Base.metadata.create_all(engine)
        with sessions.begin() as db:
            tenant = Tenant(name="Materialize", slug=f"materialize-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="assurance", enabled=True))
            for index, surface in enumerate(("browser", "runtime", "runtime", "browser", "runtime", "browser")):
                session = AISession(
                    session_id=f"session-{index}",
                    tenant_id=tenant.id,
                    source_surface=surface,
                    ai_app="Hawk Test App",
                    ai_model="gpt-test",
                    start_time=now,
                )
                db.add(session)
                db.add(
                    AIAction(
                        action_id=f"action-{index}",
                        tenant_id=tenant.id,
                        session_id=session.session_id,
                        timestamp=now,
                        action_type="tool_call" if index % 2 else "prompt",
                        ai_app="Hawk Test App",
                        ai_model="gpt-test",
                        enforcement_action="allowed",
                        metadata_json={
                            "provider": "openai",
                            "tool_name": "safe_read" if index % 2 else "safe_write",
                            "environment": "production",
                            "business_purpose": "research",
                            "policy_family": "data_handling",
                        },
                    )
                )
            db.flush()
            scope = create_maturity_scope(
                db,
                tenant_id=tenant.id,
                scope_key="organization:all",
                scope_type="organization",
                display_name="Enterprise AI estate",
                filters={},
            )
            first = materialize_maturity_scope(db, tenant_id=tenant.id, scope_id=scope.id, now=now)
            second = materialize_maturity_scope(db, tenant_id=tenant.id, scope_id=scope.id, now=now)

            assert first.observation_window.id == second.observation_window.id
            assert first.baseline.sample_count == 6
            assert first.baseline.source_diversity == 2
            assert first.assessment.stage == "UNDERSTANDING"
            assert first.assessment.indicators["observed_actions"] == 6
            assert {pattern.dimension for pattern in first.patterns} >= {"source_surface", "provider", "action_type"}
            assert all("raw_prompt" not in str(pattern.evidence_refs) for pattern in first.patterns)

            executive = materialize_executive_snapshot(db, tenant_id=tenant.id, scope_id=scope.id)
            assert executive.report["scope_count"] == 1
            assert executive.report["evidence_summary"]["observed_actions"] == 6
            assert executive.report["known_limitations"] == [
                "Only canonical AI Action and AI Session metadata were used; raw prompts and action payloads were not retained."
            ]

            policy_family_scope = create_maturity_scope(
                db,
                tenant_id=tenant.id,
                scope_key="policy_family:data_handling",
                scope_type="policy_family",
                display_name="Data handling policy family",
                filters={},
            )
            policy_family_materialization = materialize_maturity_scope(
                db,
                tenant_id=tenant.id,
                scope_id=policy_family_scope.id,
                now=now,
            )
            assert policy_family_materialization.baseline.sample_count == 6
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_maturity_entitlement_is_enforced_at_the_service_boundary(tmp_path) -> None:
    import pytest

    from app.db import models as _models  # noqa: F401
    from app.db.models.maturity_curve import (
        MaturityPolicyRecommendation,
        MaturityPolicyRollout,
        TenantMaturityEntitlement,
    )
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.maturity_curve.entitlements import MaturityEntitlementError, require_maturity_capability

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-entitlement.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            tenant = Tenant(name="Entitlement", slug=f"entitlement-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            with pytest.raises(MaturityEntitlementError, match="maturity_entitlement_missing"):
                require_maturity_capability(db, tenant_id=tenant.id, capability="recommendations")

            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="secure", enabled=True))
            db.flush()
            assert require_maturity_capability(db, tenant_id=tenant.id, capability="recommendations").package_tier == "secure"
            with pytest.raises(MaturityEntitlementError, match="maturity_capability_not_entitled"):
                require_maturity_capability(db, tenant_id=tenant.id, capability="approval_workflow")
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_maturity_uses_surface_health_and_safe_account_context_for_patterns_and_recommendations(tmp_path) -> None:
    """A recurring unsafe pattern stays unapproved and becomes a draft only.

    This is the high-value personal-account reference path.  It deliberately
    asserts metadata-only context rather than recording a document, prompt, or
    upload body.
    """

    from app.db import models as _models  # noqa: F401
    from app.db.models.activity_audit import AIAction, AISession
    from app.db.models.control_coverage import DeploymentSurface
    from app.db.models.maturity_curve import TenantMaturityEntitlement
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.maturity_curve.recommendations import generate_policy_recommendations
    from app.services.maturity_curve.service import create_maturity_scope, materialize_maturity_scope

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-personal-account.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 9, 4, 12, tzinfo=timezone.utc)
    try:
        Base.metadata.create_all(engine)
        with sessions.begin() as db:
            tenant = Tenant(name="Personal account", slug=f"personal-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="control", enabled=True))
            db.add_all(
                [
                    DeploymentSurface(
                        tenant_id=tenant.id,
                        source_kind="browser_extension",
                        source_id="browser-a",
                        name="Managed browser",
                        surface_type="browser",
                        deployment_family="browser",
                        status="connected",
                        health_status="healthy",
                        control_capability="inline",
                        evidence_capability="complete",
                        containment_capability="direct",
                        bypass_detection_capability="supported",
                    ),
                    DeploymentSurface(
                        tenant_id=tenant.id,
                        source_kind="runtime_hook",
                        source_id="runtime-a",
                        name="Runtime hook",
                        surface_type="runtime",
                        deployment_family="runtime",
                        status="connected",
                        health_status="healthy",
                        control_capability="inline",
                        evidence_capability="complete",
                        containment_capability="direct",
                        bypass_detection_capability="supported",
                    ),
                ]
            )
            for index, surface in enumerate(("browser", "runtime", "browser", "runtime", "browser", "runtime")):
                session = AISession(
                    session_id=f"personal-session-{index}",
                    tenant_id=tenant.id,
                    source_surface=surface,
                    ai_app="Personal AI workspace",
                    ai_model="model-a",
                    start_time=now,
                )
                db.add(session)
                db.add(
                    AIAction(
                        action_id=f"personal-action-{index}",
                        tenant_id=tenant.id,
                        session_id=session.session_id,
                        timestamp=now,
                        action_type="file_upload",
                        ai_app="Personal AI workspace",
                        ai_model="model-a",
                        data_classification="confidential",
                        sensitivity_score=0.9,
                        enforcement_action="allowed",
                        metadata_json={
                            "provider": "openai",
                            "account_class": "personal_free",
                            "destination_class": "external",
                            "destination": "chat.example.test",
                            "agent_id": "finance-assistant",
                            "tool_name": "upload_document",
                            "business_unit": "finance",
                            "control_health": "current",
                        },
                    )
                )
            db.flush()
            scope = create_maturity_scope(
                db,
                tenant_id=tenant.id,
                scope_key="organization:all",
                scope_type="organization",
                display_name="Enterprise AI estate",
                filters={},
            )
            materialized = materialize_maturity_scope(db, tenant_id=tenant.id, scope_id=scope.id, now=now)

            assert materialized.assessment.stage == "UNDERSTANDING"
            assert materialized.assessment.indicators["surface_health"]["healthy"] == 2
            assert materialized.baseline.aggregates["account_class_counts"] == {"personal_free": 6}
            personal_pattern = next(item for item in materialized.patterns if item.dimension == "account_class")
            assert personal_pattern.pattern_type == "COMMON"
            assert personal_pattern.approval_state == "UNAPPROVED"
            assert personal_pattern.risk_state == "HIGH"

            recommendations = generate_policy_recommendations(
                db,
                tenant_id=tenant.id,
                scope_id=scope.id,
                assessment_id=materialized.assessment.id,
                baseline_id=materialized.baseline.id,
            )
            assert len(recommendations) == 1
            recommendation = recommendations[0]
            assert recommendation.category == "personal_account_sensitive_upload"
            assert recommendation.policy_draft["scoped_rules"][0]["effect"]["decision"] == "block"
            assert any(
                condition["field"] == "account_class"
                for condition in recommendation.policy_draft["scoped_rules"][0]["condition_tree"]["all"]
            )
            assert recommendation.status == "DRAFT"
            assert recommendation.estimated_impact["unsupported_surfaces"] == []
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_granular_conditions_and_recommendation_review_are_tenant_bound(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.maturity_curve import (
        MaturityAssessment,
        MaturityObservationWindow,
        MaturityPolicyRecommendation,
        MaturityRecommendationReview,
        MaturityScope,
        TenantMaturityEntitlement,
    )
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.maturity_curve.policy_conditions import evaluate_condition_tree
    from app.services.maturity_curve.recommendations import review_policy_recommendation

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-review.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 9, 4, 12, tzinfo=timezone.utc)
    try:
        Base.metadata.create_all(engine)
        with sessions.begin() as db:
            tenant = Tenant(name="Review", slug=f"review-{uuid4().hex[:8]}", is_active=True)
            foreign = Tenant(name="Foreign review", slug=f"foreign-review-{uuid4().hex[:8]}", is_active=True)
            db.add_all([tenant, foreign])
            db.flush()
            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="control", enabled=True))
            scope = MaturityScope(tenant_id=tenant.id, scope_key="all", scope_type="organization", display_name="All", filters={})
            db.add(scope)
            db.flush()
            window = MaturityObservationWindow(
                tenant_id=tenant.id,
                scope_id=scope.id,
                window_start=now,
                window_end=now,
                input_digest="a" * 64,
                source_watermarks={},
                source_counts={},
                evidence_refs=[],
            )
            db.add(window)
            db.flush()
            assessment = MaturityAssessment(
                tenant_id=tenant.id,
                scope_id=scope.id,
                observation_window_id=window.id,
                stage="POLICY_READY",
                confidence=1.0,
                source_diversity=1,
                indicators={},
                missing_gates=[],
                blocking_gaps=[],
                evidence_refs=[],
                status="CURRENT",
                methodology_version="maturity-v1",
            )
            db.add(assessment)
            db.flush()
            recommendation = MaturityPolicyRecommendation(
                tenant_id=tenant.id,
                scope_id=scope.id,
                assessment_id=assessment.id,
                recommendation_key="reviewable",
                title="Review scoped policy",
                category="policy_friction",
                status="DRAFT",
                policy_draft={"scoped_rules": []},
                evidence_refs=[],
                assumptions=[],
                unknowns=[],
                confidence=0.8,
                estimated_impact={},
                estimated_friction={},
                recommendation_digest="b" * 64,
            )
            db.add(recommendation)
            db.flush()

            condition = evaluate_condition_tree(
                {
                    "all": [
                        {"field": "account_class", "operator": "equals", "value": "personal_free"},
                        {"field": "resource_class", "operator": "equals", "value": "file"},
                        {"field": "authority_scope", "operator": "contains", "value": "finance"},
                    ]
                },
                {
                    "account_class": "personal_free",
                    "resource_class": "file",
                    "authority_scope": ["finance", "read"],
                },
            )
            assert condition.matched is True

            reviewed = review_policy_recommendation(
                db,
                tenant_id=tenant.id,
                recommendation_id=recommendation.id,
                action="defer",
                actor_ref="user:owner",
                reason="Finance owner needs a scheduled review window.",
            )
            assert reviewed.status == "DISMISSED"
            assert reviewed.review_state == "DEFERRED"
            assert db.scalar(
                select(MaturityRecommendationReview).where(
                    MaturityRecommendationReview.tenant_id == tenant.id,
                    MaturityRecommendationReview.recommendation_id == recommendation.id,
                    MaturityRecommendationReview.action == "DEFER",
                )
            ) is not None
            assert db.scalar(
                select(MaturityRecommendationReview).where(
                    MaturityRecommendationReview.tenant_id == foreign.id,
                    MaturityRecommendationReview.recommendation_id == recommendation.id,
                )
            ) is None
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_recommendation_simulation_and_rollout_use_existing_policy_authority(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.activity_audit import AIAction, AISession
    from app.db.models.maturity_curve import TenantMaturityEntitlement
    from app.db.models.policy import PolicyPack, PolicyVersion
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.maturity_curve.recommendations import generate_policy_recommendations
    from app.services.maturity_curve.rollouts import create_policy_rollout, transition_policy_rollout
    from app.services.maturity_curve.service import create_maturity_scope, materialize_maturity_scope
    from app.services.maturity_curve.simulation import simulate_policy_recommendation
    from app.services.policy_scope_service import resolve_scoped_policy_decision

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-rollout.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)
    try:
        Base.metadata.create_all(engine)
        with sessions.begin() as db:
            tenant = Tenant(name="Rollout", slug=f"rollout-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="assurance", enabled=True))
            active_pack = PolicyPack(
                tenant_id=tenant.id,
                name="Existing governed policy",
                description="Existing policy that must remain intact during a maturity rollout.",
                status="active",
            )
            db.add(active_pack)
            db.flush()
            active_version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=active_pack.id,
                version="1.0.0",
                scope={
                    "scoped_rules": [
                        {
                            "rule_id": "existing-sensitive-upload",
                            "enabled": True,
                            "condition_tree": {
                                "all": [
                                    {"field": "action_type", "operator": "equals", "value": "file_upload"},
                                ]
                            },
                            "effect": {"decision": "block"},
                        }
                    ]
                },
                enforcement_defaults={"default_decision": "allow"},
                guardian_contracts=[],
                contract_json={"profile": "existing_policy", "scope": {}},
            )
            db.add(active_version)
            db.flush()
            for index, surface in enumerate(("browser", "runtime", "runtime", "browser", "runtime", "browser")):
                session = AISession(
                    session_id=f"rollout-session-{index}",
                    tenant_id=tenant.id,
                    source_surface=surface,
                    ai_app="Governed App",
                    ai_model="model-a",
                    start_time=now,
                )
                db.add(session)
                db.add(
                    AIAction(
                        action_id=f"rollout-action-{index}",
                        tenant_id=tenant.id,
                        session_id=session.session_id,
                        timestamp=now,
                        action_type="tool_call",
                        ai_app="Governed App",
                        ai_model="model-a",
                        sensitivity_score=0.9,
                        enforcement_action="allowed",
                        metadata_json={
                            "provider": "openai",
                            "tool_name": "external_write",
                            "environment": "production",
                        },
                    )
                )
            db.flush()
            scope = create_maturity_scope(
                db,
                tenant_id=tenant.id,
                scope_key="runtime:all",
                scope_type="surface",
                display_name="Runtime activity",
                filters={},
            )
            materialized = materialize_maturity_scope(db, tenant_id=tenant.id, scope_id=scope.id, now=now)
            recommendations = generate_policy_recommendations(
                db,
                tenant_id=tenant.id,
                scope_id=scope.id,
                assessment_id=materialized.assessment.id,
                baseline_id=materialized.baseline.id,
            )
            assert len(recommendations) == 1
            recommendation = recommendations[0]
            assert recommendation.status == "DRAFT"
            assert recommendation.policy_draft["scoped_rules"][0]["effect"]["decision"] == "require_approval"

            simulation = simulate_policy_recommendation(
                db,
                tenant_id=tenant.id,
                recommendation_id=recommendation.id,
                now=now,
            )
            assert simulation.passed is True
            assert simulation.sample_count == 6
            assert simulation.outcome_counts["require_approval"] == 6

            rollout = create_policy_rollout(
                db,
                tenant_id=tenant.id,
                recommendation_id=recommendation.id,
                actor_ref="user:operator",
            )
            rollout = transition_policy_rollout(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                target_state="REVIEW",
                actor_ref="user:operator",
                reason="review evidence",
                now=now,
            )
            rollout = transition_policy_rollout(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                target_state="APPROVED",
                actor_ref="user:admin",
                reason="approved draft",
                now=now,
            )
            assert rollout.policy_version_id is not None
            derived_version = db.get(PolicyVersion, rollout.policy_version_id)
            assert derived_version is not None
            assert derived_version.pack_id == active_pack.id
            assert {
                rule["rule_id"]
                for rule in derived_version.scope["scoped_rules"]
            } >= {"existing-sensitive-upload", recommendation.policy_draft["scoped_rules"][0]["rule_id"]}
            assert derived_version.contract_json["maturity_curve"]["source_recommendation_id"] == recommendation.id
            rollout = transition_policy_rollout(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                target_state="SHADOW",
                actor_ref="user:admin",
                reason="start shadow",
                now=now,
            )
            rollout = transition_policy_rollout(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                target_state="ENFORCE",
                actor_ref="user:admin",
                reason="begin a warning rollout",
                rollout_stage="warn",
                now=now,
            )
            assert rollout.state == "ENFORCE"
            assert rollout.mode == "enforce"
            assert rollout.rollout_stage == "warn"
            warning_phase = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context={"action_type": "tool_call", "source_surface": "runtime", "provider": "openai", "sensitivity_score": 0.9},
            )
            assert warning_phase.decision == "warn"
            rollout = transition_policy_rollout(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                target_state="ENFORCE",
                actor_ref="user:admin",
                reason="escalate after warning review",
                rollout_stage="require_approval",
                now=now,
            )
            assert rollout.rollout_stage == "require_approval"
            approval_phase = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context={"action_type": "tool_call", "source_surface": "runtime", "provider": "openai", "sensitivity_score": 0.9},
            )
            assert approval_phase.decision == "require_approval"
            rollout = transition_policy_rollout(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                target_state="ROLLED_BACK",
                actor_ref="user:admin",
                reason="restore existing authority",
                now=now,
            )
            assert rollout.state == "ROLLED_BACK"
            assert active_pack.status == "active"
            restored_existing_rule = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context={"action_type": "file_upload"},
            )
            assert restored_existing_rule.decision == "block"
            rolled_back_maturity_rule = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=None,
                context={"action_type": "tool_call", "source_surface": "runtime", "provider": "openai", "sensitivity_score": 0.9},
            )
            assert rolled_back_maturity_rule.matched is False
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_recommendation_does_not_promote_one_weak_signal(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.maturity_curve import (
        MaturityAssessment,
        MaturityObservationWindow,
        MaturityScope,
        MaturityUsageBaseline,
        TenantMaturityEntitlement,
    )
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.maturity_curve.recommendations import generate_policy_recommendations

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-weak.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)
    try:
        Base.metadata.create_all(engine)
        with sessions.begin() as db:
            tenant = Tenant(name="Weak", slug=f"weak-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="secure", enabled=True))
            scope = MaturityScope(tenant_id=tenant.id, scope_key="all", scope_type="organization", display_name="All", filters={})
            db.add(scope)
            db.flush()
            window = MaturityObservationWindow(
                tenant_id=tenant.id,
                scope_id=scope.id,
                window_start=now,
                window_end=now,
                input_digest="1" * 64,
                source_watermarks={},
                source_counts={"ai_actions": 1},
                evidence_refs=["ai_action:opaque"],
            )
            db.add(window)
            db.flush()
            assessment = MaturityAssessment(
                tenant_id=tenant.id,
                scope_id=scope.id,
                observation_window_id=window.id,
                stage="MONITORING",
                confidence=0.5,
                source_diversity=1,
                indicators={},
                missing_gates=["source_diversity"],
                blocking_gaps=[],
                evidence_refs=[],
                status="CURRENT",
                methodology_version="maturity-v1",
            )
            db.add(assessment)
            db.flush()
            baseline = MaturityUsageBaseline(
                tenant_id=tenant.id,
                scope_id=scope.id,
                observation_window_id=window.id,
                baseline_version=1,
                baseline_digest="2" * 64,
                sample_count=1,
                source_diversity=1,
                aggregates={"action_type_counts": {"tool_call": 1}},
                status="PARTIAL",
            )
            db.add(baseline)
            db.flush()
            assert generate_policy_recommendations(
                db,
                tenant_id=tenant.id,
                scope_id=scope.id,
                assessment_id=assessment.id,
                baseline_id=baseline.id,
            ) == []
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_effectiveness_detects_a_policy_execution_gap_and_exception_expires(tmp_path) -> None:
    from app.db import models as _models  # noqa: F401
    from app.db.models.activity_audit import AIAction, AISession
    from app.db.models.maturity_curve import (
        MaturityAssessment,
        MaturityObservationWindow,
        MaturityPolicyRecommendation,
        MaturityPolicyRollout,
        MaturityScope,
        TenantMaturityEntitlement,
    )
    from app.db.models.policy import PolicyPack, PolicyVersion
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.maturity_curve.effectiveness import materialize_policy_effectiveness
    from app.services.maturity_curve.exceptions import create_policy_exception, exception_is_active
    from app.services.policy_scope_service import resolve_scoped_policy_decision

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-effectiveness.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)
    try:
        Base.metadata.create_all(engine)
        with sessions.begin() as db:
            tenant = Tenant(name="Effectiveness", slug=f"effectiveness-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="assurance", enabled=True))
            session = AISession(
                session_id="effectiveness-session",
                tenant_id=tenant.id,
                source_surface="runtime",
                ai_app="Governed app",
                ai_model="model-a",
                start_time=now,
            )
            db.add(session)
            db.add(
                AIAction(
                    action_id="effectiveness-action",
                    tenant_id=tenant.id,
                    session_id=session.session_id,
                    timestamp=now,
                    action_type="tool_call",
                    ai_app="Governed app",
                    ai_model="model-a",
                    sensitivity_score=0.9,
                    enforcement_action="allowed",
                    metadata_json={"provider": "openai", "tool_name": "external_write"},
                )
            )
            scope = MaturityScope(
                tenant_id=tenant.id,
                scope_key="runtime:effectiveness",
                scope_type="surface",
                display_name="Runtime",
                filters={},
            )
            db.add(scope)
            db.flush()
            window = MaturityObservationWindow(
                tenant_id=tenant.id,
                scope_id=scope.id,
                window_start=now,
                window_end=now,
                input_digest="a" * 64,
                source_watermarks={},
                source_counts={"ai_actions": 1},
                evidence_refs=["ai_action:effectiveness-action"],
            )
            db.add(window)
            db.flush()
            assessment = MaturityAssessment(
                tenant_id=tenant.id,
                scope_id=scope.id,
                observation_window_id=window.id,
                stage="CONTROLLED",
                confidence=1.0,
                source_diversity=2,
                indicators={},
                missing_gates=[],
                blocking_gaps=[],
                evidence_refs=[],
                status="CURRENT",
                methodology_version="maturity-v1",
            )
            db.add(assessment)
            pack = PolicyPack(tenant_id=tenant.id, name="Effectiveness policy", description="", status="active")
            db.add(pack)
            db.flush()
            version = PolicyVersion(
                tenant_id=tenant.id,
                pack_id=pack.id,
                version="maturity-effectiveness-v1",
                scope={
                    "scoped_rules": [
                        {
                            "rule_id": "approval-on-sensitive-runtime-tool",
                            "enabled": True,
                            "condition_tree": {
                                "all": [
                                    {"field": "source_surface", "operator": "equals", "value": "runtime"},
                                    {"field": "action_type", "operator": "equals", "value": "tool_call"},
                                    {"field": "sensitivity_score", "operator": "gte", "value": 0.7},
                                ]
                            },
                            "effect": {"decision": "require_approval"},
                        }
                    ]
                },
                enforcement_defaults={"default_decision": "warn"},
                guardian_contracts=[],
                contract_json={"profile": "maturity_curve"},
            )
            db.add(version)
            db.flush()
            recommendation = MaturityPolicyRecommendation(
                tenant_id=tenant.id,
                scope_id=scope.id,
                assessment_id=assessment.id,
                recommendation_key="effectiveness:runtime",
                title="Runtime tool approval",
                category="consequential_usage",
                status="APPROVED",
                policy_draft=version.scope,
                evidence_refs=[],
                assumptions=[],
                unknowns=[],
                confidence=1.0,
                estimated_impact={},
                estimated_friction={},
                recommendation_digest="b" * 64,
                candidate_policy_version_id=version.id,
            )
            db.add(recommendation)
            db.flush()
            rollout = MaturityPolicyRollout(
                tenant_id=tenant.id,
                scope_id=scope.id,
                recommendation_id=recommendation.id,
                policy_version_id=version.id,
                state="ENFORCE",
                mode="enforce",
                rollout_digest="c" * 64,
            )
            db.add(rollout)
            db.flush()

            exception = create_policy_exception(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                policy_version_id=version.id,
                scope={
                    "condition_tree": {
                        "all": [
                            {"field": "actor_user_id", "operator": "equals", "value": "user:operator"},
                            {"field": "action_type", "operator": "equals", "value": "tool_call"},
                        ]
                    }
                },
                reason="bounded validation exception",
                requested_by_ref="user:operator",
                approved_by_ref="user:admin",
                expires_at=now + timedelta(hours=1),
                now=now,
            )
            assert exception_is_active(exception, now=now) is True
            assert exception_is_active(exception, now=now + timedelta(hours=1, minutes=1)) is False
            exception_decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=version.id,
                context={
                    "actor_user_id": "user:operator",
                    "source_surface": "runtime",
                    "action_type": "tool_call",
                    "sensitivity_score": 0.9,
                },
            )
            assert exception_decision.decision == "allow"
            ordinary_decision = resolve_scoped_policy_decision(
                db,
                tenant_id=tenant.id,
                policy_version_id=version.id,
                context={
                    "actor_user_id": "user:other",
                    "source_surface": "runtime",
                    "action_type": "tool_call",
                    "sensitivity_score": 0.9,
                },
            )
            assert ordinary_decision.decision == "require_approval"

            snapshot = materialize_policy_effectiveness(
                db,
                tenant_id=tenant.id,
                rollout_id=rollout.id,
                now=now,
            )
            assert snapshot.status == "REGRESSED"
            assert snapshot.outcome_summary["enforcement_mismatches"] == 1
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_maturity_curve_api_is_feature_gated_rbac_protected_and_tenant_scoped(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.routers.maturity_curve import router
    from app.core.config import settings
    from app.core.tenant import require_tenant
    from app.db import models as _models  # noqa: F401
    from app.db.models.maturity_curve import (
        MaturityPolicyRecommendation,
        MaturityPolicyRollout,
        TenantMaturityEntitlement,
    )
    from app.db.models.tenant import Tenant
    from app.db.models.user import User
    from app.db.session import Base, get_db

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'maturity-api.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        Base.metadata.create_all(engine)
        db = sessions()
        tenant = Tenant(name="Maturity API", slug=f"maturity-api-{uuid4().hex[:8]}", is_active=True)
        other = Tenant(name="Other API", slug=f"other-api-{uuid4().hex[:8]}", is_active=True)
        user = User(email=f"maturity-api-{uuid4().hex[:8]}@example.test", hashed_password="test", full_name="Owner")
        db.add_all([tenant, other, user])
        db.flush()
        db.add(TenantMaturityEntitlement(tenant_id=tenant.id, package_tier="secure", enabled=True))
        db.commit()

        current = {
            "ctx": SimpleNamespace(
                tenant=tenant,
                user=user,
                role="viewer",
            )
        }
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        app.dependency_overrides[require_tenant] = lambda: current["ctx"]
        client = TestClient(app)
        monkeypatch.setattr(settings, "maturity_curve_policy_intelligence", True)
        monkeypatch.setattr(
            settings,
            "maturity_curve_policy_intelligence_rollout",
            f'{{"{tenant.id}": true}}',
        )

        assert client.get("/maturity-curve/overview").status_code == 200
        request = {
            "scope_key": "organization:all",
            "scope_type": "organization",
            "display_name": "Enterprise AI estate",
            "filters": {},
        }
        assert client.post("/maturity-curve/scopes", json=request).status_code == 403
        current["ctx"] = SimpleNamespace(tenant=tenant, user=user, role="operator")
        created = client.post("/maturity-curve/scopes", json=request)
        assert created.status_code == 201, created.text
        scope_id = created.json()["id"]
        refreshed = client.post(f"/maturity-curve/scopes/{scope_id}/refresh", json={"window_days": 30})
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["assessment"]["stage"] == "UNKNOWN"
        executive = client.post(f"/maturity-curve/scopes/{scope_id}/executive")
        assert executive.status_code == 200, executive.text
        assert executive.json()["report"]["evidence_summary"]["observed_actions"] == 0
        overview_with_executive = client.get("/maturity-curve/overview")
        assert overview_with_executive.status_code == 200, overview_with_executive.text
        assert overview_with_executive.json()["executive"]["report"]["report_version"] == "maturity-executive-v2"

        recommendation = MaturityPolicyRecommendation(
            tenant_id=tenant.id,
            scope_id=scope_id,
            assessment_id=refreshed.json()["assessment"]["id"],
            recommendation_key="api-review",
            title="Review API wiring",
            category="policy_friction",
            status="DRAFT",
            policy_draft={"scoped_rules": []},
            evidence_refs=[],
            assumptions=[],
            unknowns=[],
            confidence=0.5,
            estimated_impact={},
            estimated_friction={},
            recommendation_digest="c" * 64,
        )
        db.add(recommendation)
        db.commit()
        reviewed = client.post(
            f"/maturity-curve/recommendations/{recommendation.id}/review",
            json={"action": "REVIEW", "reason": "Operator has started evidence review."},
        )
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["review_state"] == "IN_REVIEW"

        rollout = MaturityPolicyRollout(
            tenant_id=tenant.id,
            scope_id=scope_id,
            recommendation_id=recommendation.id,
            state="SHADOW",
            mode="shadow",
            rollout_stage="monitor",
            rollout_digest="d" * 64,
            requested_by_ref=f"user:{user.id}",
        )
        db.add(rollout)
        db.commit()
        received: dict[str, str | None] = {}

        def transition_stub(*_args, **kwargs):
            received["rollout_stage"] = kwargs.get("rollout_stage")
            rollout.state = str(kwargs["target_state"]).upper()
            rollout.rollout_stage = str(kwargs.get("rollout_stage") or "enforce")
            return rollout

        monkeypatch.setattr("app.api.routers.maturity_curve.transition_policy_rollout", transition_stub)
        current["ctx"] = SimpleNamespace(tenant=tenant, user=user, role="admin")
        transitioned = client.post(
            f"/maturity-curve/rollouts/{rollout.id}/transition",
            json={"target_state": "ENFORCE", "reason": "Begin warning phase.", "rollout_stage": "warn"},
        )
        assert transitioned.status_code == 200, transitioned.text
        assert received["rollout_stage"] == "warn"
        assert transitioned.json()["rollout_stage"] == "warn"

        current["ctx"] = SimpleNamespace(tenant=other, user=user, role="viewer")
        assert client.get(f"/maturity-curve/scopes/{scope_id}").status_code == 404
        app.dependency_overrides.clear()
        db.close()
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_maturity_curve_job_requires_global_flag_and_exact_tenant_rollout(monkeypatch) -> None:
    from app.core.config import settings
    from app.jobs.celery_app import celery_app
    from app.jobs.maturity_curve_jobs import maturity_curve_enabled_for_tenant, refresh_maturity_curve

    tenant_id = "tenant-maturity-job"
    monkeypatch.setattr(settings, "maturity_curve_policy_intelligence", False)
    monkeypatch.setattr(settings, "maturity_curve_policy_intelligence_rollout", '{"tenant-maturity-job": true}')
    assert maturity_curve_enabled_for_tenant(tenant_id) is False
    assert refresh_maturity_curve.run(tenant_id) == {"tenant_id": tenant_id, "status": "disabled", "scopes": 0}

    monkeypatch.setattr(settings, "maturity_curve_policy_intelligence", True)
    monkeypatch.setattr(settings, "maturity_curve_policy_intelligence_rollout", "{}")
    assert maturity_curve_enabled_for_tenant(tenant_id) is False

    monkeypatch.setattr(settings, "maturity_curve_policy_intelligence_rollout", '{"tenant-maturity-job": true}')
    assert maturity_curve_enabled_for_tenant(tenant_id) is True
    assert "app.jobs.maturity_curve_jobs.refresh_maturity_curve" in celery_app.tasks
