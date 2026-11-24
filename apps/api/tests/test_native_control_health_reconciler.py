from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.models.finding import Finding
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlValidation,
    NativeWorkloadCredential,
)
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.native_control.health import record_health_observation
from app.services.native_control.integrity import integration_configuration_fingerprint
from app.services.native_control.reconciler import reconcile_native_control_integration


NOW = datetime(2026, 8, 11, 10, 0, tzinfo=timezone.utc)


def _fixture(db) -> NativeControlIntegration:
    tenant = Tenant(name="Reconciler", slug="native-reconciler")
    db.add(tenant)
    db.flush()
    capabilities = {
        "tool_control": {"level": "inline", "verification_status": "verified", "evidence_refs": ["test"]}
    }
    profile = ControlCapabilityProfileRecord(
        manifest_id="meta:self_hosted:endpoint_runtime",
        manifest_version="1.0",
        matrix_version="matrix-1",
        provider="meta",
        product="self_hosted",
        integration_method="endpoint_runtime",
        adapter_version="1.0.0",
        tested_min_version="explicit-hawk-client-binding-v1",
        tested_max_version="explicit-hawk-client-binding-v1",
        current_verified_version="explicit-hawk-client-binding-v1",
        verification_status="verified",
        verification_source="test",
        verified_at=NOW,
        capabilities=capabilities,
        security_properties={"expected_latency_ms": 30},
        health_requirements=[],
        degradation_modes=["fail_closed"],
        known_blind_spots=[],
        documentation_references=["test"],
        manifest_fingerprint="a" * 64,
        active=True,
    )
    db.add(profile)
    db.flush()
    integration = NativeControlIntegration(
        tenant_id=tenant.id,
        capability_profile_id=profile.id,
        instance_key="endpoint-1",
        display_name="Endpoint 1",
        provider="meta",
        product="self_hosted",
        integration_method="endpoint_runtime",
        deployment_family="endpoint",
        environment="production",
        state="enforcing",
        mode="enforce",
        health_state="healthy",
        health_reasons=[],
        provider_version="explicit-hawk-client-binding-v1",
        adapter_version="1.0.0",
        policy_version="policy-1",
        policy_fresh_until=NOW + timedelta(hours=1),
        degradation_mode="fail_closed",
        capability_snapshot=capabilities,
        known_blind_spots=[],
        last_validated_at=NOW,
    )
    db.add(integration)
    db.flush()
    integration.configuration_fingerprint = integration_configuration_fingerprint(integration)
    integration.expected_configuration_fingerprint = integration.configuration_fingerprint
    db.add(
        NativeWorkloadCredential(
            tenant_id=tenant.id,
            integration_instance_id=integration.id,
            credential_id="credential-1",
            credential_epoch=1,
            public_key_pem="test",
            key_thumbprint="b" * 64,
            signature_algorithm="ES256",
            environment="production",
            allowed_event_types=["before_tool"],
            status="active",
            expires_at=NOW + timedelta(hours=1),
        )
    )
    db.add(
        NativeControlValidation(
            tenant_id=tenant.id,
            integration_instance_id=integration.id,
            validation_version="native-control-validation/1.0",
            credential_id="credential-1",
            credential_epoch=1,
            safe_synthetic=True,
            checks={"all": True},
            result="passed",
            reason_codes=[],
            evidence_refs=["evidence:validation"],
            validated_at=NOW,
        )
    )
    db.flush()
    return integration


def test_reconciler_downgrades_stale_callback_and_resolves_after_fresh_evidence() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        integration = _fixture(db)
        first = reconcile_native_control_integration(db, integration=integration, now=NOW)
        db.flush()
        assert first["health_state"] == "degraded"
        assert integration.state == "degraded"
        finding = db.scalar(select(Finding).where(Finding.finding_type == "PROVIDER_CONTROL_UNHEALTHY"))
        assert finding is not None and finding.status == "open"

        record_health_observation(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id="credential-1",
            credential_epoch=1,
            provider_event_id="fresh-event",
            provider_event_type="after_tool",
            callback_authenticated=True,
            evidence_flowing=True,
            latency_ms=15,
            source="signed_native_callback",
            evidence_ref="evidence:fresh",
            observed_at=NOW + timedelta(seconds=1),
        )
        second = reconcile_native_control_integration(
            db,
            integration=integration,
            now=NOW + timedelta(seconds=1),
        )
        db.flush()
        assert second["health_state"] == "healthy"
        assert integration.state == "enforcing"
        assert integration.mode == "enforce"
        assert finding.status == "resolved"
    engine.dispose()


def test_reconciler_preserves_fail_closed_enforcement_intent_during_degradation() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        integration = _fixture(db)
        result = reconcile_native_control_integration(db, integration=integration, now=NOW)
        db.flush()

        assert result["health_state"] == "degraded"
        assert integration.state == "degraded"
        assert integration.mode == "enforce"

        record_health_observation(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id="credential-1",
            credential_epoch=1,
            provider_event_id="fresh-event",
            provider_event_type="after_tool",
            callback_authenticated=True,
            evidence_flowing=True,
            latency_ms=15,
            source="signed_native_callback",
            evidence_ref="evidence:fresh",
            observed_at=NOW + timedelta(seconds=1),
        )
        recovered = reconcile_native_control_integration(
            db,
            integration=integration,
            now=NOW + timedelta(seconds=1),
        )
        db.flush()

        assert recovered["health_state"] == "healthy"
        assert integration.state == "enforcing"
        assert integration.mode == "enforce"
    engine.dispose()


def test_reconciler_canonicalizes_preexisting_legacy_finding_without_duplicate() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        integration = _fixture(db)
        legacy = Finding(
            tenant_id=integration.tenant_id,
            source_surface="connector",
            ai_tool="native_control:meta",
            application=integration.id,
            severity="high",
            finding_type="NATIVE_CONTROL_CALLBACK_UNHEALTHY",
            risk_category="native_control_integrity",
            decision="review",
            status="open",
            recommended_action="Legacy callback remediation",
            evidence_node_ids=["legacy-evidence"],
            related_event_ids=[],
            related_control_ids=["NATIVE_CONTROL_CALLBACK_UNHEALTHY"],
            evidence_status="incomplete",
            canonical_action_id=None,
            dedupe_key="legacy-callback-unhealthy",
            occurrence_count=2,
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
        db.add(legacy)
        db.flush()

        reconcile_native_control_integration(db, integration=integration, now=NOW)
        db.flush()

        open_rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.tenant_id == integration.tenant_id,
                    Finding.status.in_(["open", "reviewing"]),
                    Finding.finding_type.in_(
                        [
                            "NATIVE_CONTROL_CALLBACK_UNHEALTHY",
                            "PROVIDER_CONTROL_UNHEALTHY",
                        ]
                    ),
                )
            )
        )
        assert open_rows == [legacy]
        assert legacy.finding_type == "PROVIDER_CONTROL_UNHEALTHY"
        assert legacy.occurrence_count == 2
        assert legacy.dedupe_key != "legacy-callback-unhealthy"
        assert "legacy-evidence" in legacy.evidence_node_ids
    engine.dispose()
