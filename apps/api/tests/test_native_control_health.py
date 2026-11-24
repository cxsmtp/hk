from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.native_control import NativeControlHealthObservation, NativeControlIntegration
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.native_control.health import health_snapshot, record_health_observation


NOW = datetime(2026, 8, 11, 9, 0, tzinfo=timezone.utc)


def _integration(db) -> NativeControlIntegration:
    tenant = Tenant(name="Native Health", slug="native-health")
    db.add(tenant)
    db.flush()
    row = NativeControlIntegration(
        tenant_id=tenant.id,
        instance_key="endpoint-1",
        display_name="Endpoint 1",
        provider="meta",
        product="self_hosted",
        integration_method="endpoint_runtime",
        deployment_family="endpoint",
        environment="test",
        state="monitoring",
        mode="monitor",
        health_state="unverified",
        health_reasons=[],
        adapter_version="1.0.0",
        degradation_mode="fail_closed",
        capability_snapshot={},
        known_blind_spots=[],
    )
    db.add(row)
    db.flush()
    return row


def test_health_requires_recent_observations_and_measures_p95_latency() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        integration = _integration(db)
        for index, latency in enumerate((10, 20, 30, 40, 100)):
            record_health_observation(
                db,
                tenant_id=integration.tenant_id,
                integration_id=integration.id,
                credential_id="credential-1",
                credential_epoch=2,
                provider_event_id=f"event-{index}",
                provider_event_type="before_tool" if index == 0 else "after_tool",
                callback_authenticated=True,
                evidence_flowing=index > 0,
                latency_ms=latency,
                source="signed_native_callback",
                evidence_ref=f"evidence:{index}" if index > 0 else None,
                observed_at=NOW - timedelta(seconds=index),
            )
        db.flush()

        snapshot = health_snapshot(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id="credential-1",
            credential_epoch=2,
            now=NOW,
        )

        assert snapshot.callback_authenticated is True
        assert snapshot.evidence_flowing is True
        assert snapshot.observed_latency_ms == 100
        assert snapshot.sample_count == 5
        assert snapshot.last_observed_at == NOW
        assert snapshot.reason_codes == ()
    engine.dispose()


def test_expired_or_different_credential_observations_never_count() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with factory() as db:
        integration = _integration(db)
        record_health_observation(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id="old-credential",
            credential_epoch=1,
            provider_event_id="old-event",
            provider_event_type="after_tool",
            callback_authenticated=True,
            evidence_flowing=True,
            latency_ms=8,
            source="signed_native_callback",
            evidence_ref="evidence:old",
            observed_at=NOW - timedelta(minutes=10),
            ttl=timedelta(minutes=5),
        )
        db.flush()

        snapshot = health_snapshot(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id="credential-2",
            credential_epoch=2,
            now=NOW,
        )

        assert snapshot.callback_authenticated is False
        assert snapshot.evidence_flowing is False
        assert snapshot.observed_latency_ms is None
        assert snapshot.sample_count == 0
        assert snapshot.reason_codes == ("callback_not_observed", "evidence_not_flowing", "latency_not_measured")
        assert db.query(NativeControlHealthObservation).count() == 1
    engine.dispose()

