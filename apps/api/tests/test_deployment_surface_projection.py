from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.models.control_coverage import DeploymentSurface
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.deployment_surfaces import (
    SurfaceCandidate,
    derive_capability_profile,
    derive_health,
    reconcile_deployment_surfaces,
)


def _candidate(**overrides: object) -> SurfaceCandidate:
    now = datetime.now(timezone.utc)
    values: dict[str, object] = {
        "source_kind": "gateway",
        "source_id": "primary",
        "name": "Primary LLM Gateway",
        "surface_type": "llm_gateway",
        "deployment_mode": "inline",
        "environment": "production",
        "enabled": True,
        "status": "active",
        "last_seen_at": now,
        "last_heartbeat_at": now,
        "capability_metadata": {
            "discovery": "full",
            "inline_authorization": "yes",
            "evidence": "full",
            "containment": "end_to_end",
            "bypass_detection": "supported",
            "identity_attribution": "supported",
            "runtime_governance": "supported",
        },
        "capability_sources": ("gateway.registration:primary",),
        "metadata": {},
    }
    values.update(overrides)
    return SurfaceCandidate(**values)  # type: ignore[arg-type]


def test_unknown_capabilities_are_not_promoted() -> None:
    assert derive_capability_profile({}) == {
        "discovery": "unknown",
        "inline_authorization": "unknown",
        "evidence_generation": "unknown",
        "containment": "unknown",
        "bypass_detection": "unknown",
        "identity_attribution": "unknown",
        "runtime_governance": "unknown",
    }


def test_monitoring_metadata_never_implies_inline() -> None:
    profile = derive_capability_profile({"monitoring_only": True, "evidence": "partial"})
    assert profile["discovery"] == "partial"
    assert profile["inline_authorization"] == "no"
    assert profile["evidence_generation"] == "partial"
    assert profile["containment"] == "none"


def test_reconciliation_derives_family_from_exact_technical_surface() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.flush()
        rows = reconcile_deployment_surfaces(
            db,
            tenant_id="tenant-a",
            now=datetime.now(timezone.utc),
            candidates=[_candidate(surface_type="llm_gateway", metadata={})],
        )
        assert rows[0].deployment_family == "runtime"
    engine.dispose()


def test_health_uses_heartbeat_and_registration() -> None:
    now = datetime.now(timezone.utc)
    assert derive_health(enabled=True, status="active", last_heartbeat_at=now, now=now).status == "healthy"
    stale = now - timedelta(minutes=10)
    assert derive_health(enabled=True, status="active", last_heartbeat_at=stale, now=now).status == "degraded"
    assert derive_health(enabled=False, status="inactive", last_heartbeat_at=None, now=now).status == "offline"
    assert derive_health(enabled=True, status="unknown", last_heartbeat_at=None, now=now).status == "unknown"


def test_conflicting_capability_sources_resolve_to_unknown() -> None:
    first = _candidate(capability_metadata={"inline_authorization": "yes"})
    second = _candidate(capability_metadata={"inline_authorization": "no"})
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.flush()
        rows = reconcile_deployment_surfaces(db, tenant_id="tenant-a", now=datetime.now(timezone.utc), candidates=[first, second])
        assert len(rows) == 1
        assert rows[0].capability_profile["inline_authorization"] == "unknown"
        assert rows[0].health_status == "healthy"
    engine.dispose()


def test_reconciliation_is_idempotent_and_tenant_scoped() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        db.add_all([
            Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"),
            Tenant(id="tenant-b", name="Tenant B", slug="tenant-b"),
        ])
        db.flush()
        reconcile_deployment_surfaces(db, tenant_id="tenant-a", now=now, candidates=[_candidate()])
        reconcile_deployment_surfaces(db, tenant_id="tenant-a", now=now, candidates=[_candidate(name="Renamed Gateway")])
        reconcile_deployment_surfaces(db, tenant_id="tenant-b", now=now, candidates=[_candidate()])
        rows = db.scalars(select(DeploymentSurface).order_by(DeploymentSurface.tenant_id)).all()
        assert [(row.tenant_id, row.name) for row in rows] == [
            ("tenant-a", "Renamed Gateway"),
            ("tenant-b", "Primary LLM Gateway"),
        ]
    engine.dispose()
