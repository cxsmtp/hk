from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routers.discovery_targets import list_targets
from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_canonical import DiscoveryTarget
from app.db.session import Base
from test_phase2_asset_resolution_service import _seed


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _ctx(tenant_id: str) -> SimpleNamespace:
    return SimpleNamespace(tenant=SimpleNamespace(id=tenant_id), user=None)


def test_target_projection_is_tenant_safe_and_never_exposes_credentials() -> None:
    db = _db()
    try:
        tenant = _seed(db, suffix="target-api")
        other = _seed(db, suffix="target-other")
        db.add_all(
            [
                DiscoveryTarget(
                    target_id="target-endpoints",
                    tenant_id=tenant["tenant_id"],
                    target_type="endpoint_group",
                    identifier="managed-laptops",
                    environment="production",
                    owner_hint="security",
                    credentials_reference="vault://must-never-leave-api",
                    permitted_methods_json=["metadata_scan"],
                    exclusions_json=["privacy-sensitive-paths"],
                    rate_limit=50,
                    active_scan_allowed=True,
                    sensitive_scope=False,
                ),
                DiscoveryTarget(
                    target_id="target-other",
                    tenant_id=other["tenant_id"],
                    target_type="repository",
                    identifier="other-repository",
                    environment="test",
                    owner_hint=None,
                    credentials_reference="vault://other",
                    permitted_methods_json=["metadata_scan"],
                    exclusions_json=[],
                    rate_limit=10,
                    active_scan_allowed=True,
                    sensitive_scope=False,
                ),
            ]
        )
        db.flush()

        response = list_targets(ctx=_ctx(tenant["tenant_id"]), db=db)
        assert response.total == 2
        assert "target-other" not in {item.target_id for item in response.items}
        payload = next(
            item.model_dump()
            for item in response.items
            if item.target_id == "target-endpoints"
        )
        assert payload["target_id"] == "target-endpoints"
        assert payload["active_scan_allowed"] is True
        assert payload["permitted_methods"] == ["metadata_scan"]
        assert "credentials_reference" not in payload
        assert "vault" not in repr(payload)
    finally:
        db.close()
        db.bind.dispose()
