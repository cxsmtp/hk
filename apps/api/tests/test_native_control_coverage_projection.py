from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlValidation,
    NativeWorkloadCredential,
)
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.deployment_surfaces import (
    native_control_surface_candidates,
    reconcile_deployment_surfaces,
)
from app.services.native_control.integrity import integration_configuration_fingerprint
from app.core.config import settings


NOW = datetime(2026, 8, 11, 8, 0, tzinfo=timezone.utc)


def _setup_point(db, tenant_id: str, *, state: str, health: str, verification: str):
    profile = ControlCapabilityProfileRecord(
        manifest_id=f"openai:direct_api:gateway:{state}",
        manifest_version="1.0",
        matrix_version="matrix-1",
        provider="openai",
        product="direct_api",
        integration_method="gateway_inline",
        adapter_version="1.0.0",
        tested_min_version="1.0",
        tested_max_version="1.0",
        current_verified_version="1.0",
        verification_status=verification,
        verification_source="test",
        capabilities={
            "discovery": {"level": "observe", "verification_status": "verified"},
            "identity": {"level": "inline_bound", "verification_status": "verified"},
            "tool_control": {"level": "inline", "verification_status": "verified"},
            "post_execution_visibility": {"level": "observe", "verification_status": "verified"},
            "containment": {"level": "external", "verification_status": "verified"},
            "bypass_detection": {"level": "observe", "verification_status": "verified"},
        },
        security_properties={},
        health_requirements=[],
        degradation_modes=["fail_closed"],
        known_blind_spots=["direct_api_bypass"],
        documentation_references=["test"],
        manifest_fingerprint=(state[0] * 64),
        active=True,
    )
    db.add(profile)
    db.flush()
    point = NativeControlIntegration(
        tenant_id=tenant_id,
        capability_profile_id=profile.id,
        instance_key=state,
        display_name=f"Point {state}",
        provider="openai",
        product="direct_api",
        integration_method="gateway_inline",
        deployment_family="saas_api",
        environment="production",
        state=state,
        mode="enforce" if state == "enforcing" else "discover",
        health_state=health,
        health_reasons=[],
        provider_version="1.0",
        adapter_version="1.0.0",
        configuration_fingerprint=None,
        expected_configuration_fingerprint=None,
        policy_version="policy-1",
        policy_fresh_until=NOW + timedelta(hours=1),
        degradation_mode="fail_closed",
        capability_snapshot=profile.capabilities,
        known_blind_spots=["direct_api_bypass"],
        last_validated_at=NOW if state == "enforcing" else None,
    )
    db.add(point)
    db.flush()
    point.configuration_fingerprint = integration_configuration_fingerprint(point)
    point.expected_configuration_fingerprint = point.configuration_fingerprint
    if state == "enforcing":
        db.add(
            NativeControlValidation(
                tenant_id=tenant_id,
                integration_instance_id=point.id,
                validation_version="1.0",
                credential_id=f"credential-{point.id}",
                credential_epoch=1,
                safe_synthetic=True,
                checks={"all": True},
                result="passed",
                reason_codes=[],
                evidence_refs=["evidence:validation"],
                validated_at=NOW,
            )
        )
        db.add(
            NativeWorkloadCredential(
                tenant_id=tenant_id,
                integration_instance_id=point.id,
                credential_id=f"credential-{point.id}",
                credential_epoch=1,
                public_key_pem="test-public-key",
                key_thumbprint="k" * 64,
                signature_algorithm="ES256",
                environment="production",
                allowed_event_types=["before_tool"],
                status="active",
                expires_at=NOW + timedelta(hours=1),
            )
        )
    db.flush()
    return point


def test_native_projection_counts_only_verified_healthy_validated_control(monkeypatch) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        tenant = Tenant(name="Coverage", slug="native-coverage")
        db.add(tenant)
        db.flush()
        enforcing_point = _setup_point(
            db,
            tenant.id,
            state="enforcing",
            health="healthy",
            verification="verified",
        )
        _setup_point(db, tenant.id, state="configuring", health="unverified", verification="unverified")
        for flag in (
            "native_control_framework",
            "trusted_control_selector",
            "native_control_enforce",
            "native_control_openai",
            "authorization_kernel_v2_enabled",
            "authorization_kernel_v2_enforce",
        ):
            monkeypatch.setitem(settings.__dict__, flag, True)
        monkeypatch.setitem(
            settings.__dict__,
            "authorization_kernel_v2_enforce_rollout",
            json.dumps({tenant.id: ["llm_gateway"]}),
        )
        monkeypatch.setitem(
            settings.__dict__,
            "native_control_route_bindings_json",
            json.dumps(
                {
                    tenant.id: {
                        "llm_gateway": {
                            "integration_instance_ids": [enforcing_point.id],
                            "provider": "openai",
                            "provider_version": "1.0",
                            "adapter_version": "1.0.0",
                            "product": "direct_api",
                        }
                    }
                }
            ),
        )

        candidates = native_control_surface_candidates(db, tenant_id=tenant.id, now=NOW)
        surfaces = reconcile_deployment_surfaces(db, tenant_id=tenant.id, now=NOW, candidates=candidates)
        monkeypatch.setitem(settings.__dict__, "authorization_kernel_v2_enabled", False)
        disabled_kernel_candidates = native_control_surface_candidates(
            db, tenant_id=tenant.id, now=NOW
        )
        monkeypatch.setitem(settings.__dict__, "authorization_kernel_v2_enabled", True)
        credential = db.scalar(
            select(NativeWorkloadCredential).where(
                NativeWorkloadCredential.tenant_id == tenant.id,
                NativeWorkloadCredential.status == "active",
            )
        )
        assert credential is not None
        credential.expires_at = NOW - timedelta(seconds=1)
        db.flush()
        expired_candidates = native_control_surface_candidates(db, tenant_id=tenant.id, now=NOW)
        credential.expires_at = NOW + timedelta(hours=1)
        point = db.scalar(
            select(NativeControlIntegration).where(
                NativeControlIntegration.tenant_id == tenant.id,
                NativeControlIntegration.state == "enforcing",
            )
        )
        assert point is not None
        point.adapter_version = "unexpected-adapter"
        db.flush()
        mismatched_candidates = native_control_surface_candidates(db, tenant_id=tenant.id, now=NOW)

    protected = next(row for row in candidates if row.name == "Point enforcing")
    configured = next(row for row in candidates if row.name == "Point configuring")
    assert protected.capability_metadata["inline_authorization"] == "yes"
    assert protected.capability_metadata["evidence"] == "partial"
    assert protected.metadata["deployment_family"] == "saas_api"
    assert configured.capability_metadata["inline_authorization"] == "unknown"
    assert configured.capability_metadata["evidence"] == "unknown"
    protected_surface = next(row for row in surfaces if row.name == "Point enforcing")
    assert protected_surface.deployment_family == "saas_api"
    assert protected_surface.control_capability == "inline"
    assert protected_surface.evidence_capability == "partial"
    assert protected_surface.bypass_detection_capability == "supported"
    expired = next(row for row in expired_candidates if row.name == "Point enforcing")
    assert expired.capability_metadata["inline_authorization"] == "unknown"
    mismatched = next(row for row in mismatched_candidates if row.name == "Point enforcing")
    assert mismatched.capability_metadata["inline_authorization"] == "unknown"
    disabled_kernel = next(
        row for row in disabled_kernel_candidates if row.name == "Point enforcing"
    )
    assert disabled_kernel.capability_metadata["inline_authorization"] == "unknown"
    engine.dispose()
