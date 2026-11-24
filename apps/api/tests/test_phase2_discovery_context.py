from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.attribution_service import link_identity
from app.services.hmair.capability_inference_service import infer_capability
from app.services.hmair.discovery_context_service import get_discovery_context
from app.services.hmair.reachability_service import assert_reachability
from test_phase2_asset_resolution_service import _asset, _persist_claim, _seed


NOW = datetime(2026, 8, 15, 11, 0, tzinfo=timezone.utc)


def _forbidden_keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if key.casefold() in {"allow", "block", "decision", "authorized", "authorization"}:
                found.add(key)
            found |= _forbidden_keys(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            found |= _forbidden_keys(nested)
    return found


def test_discovery_context_contains_evidence_not_authorization() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    db = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        seed = _seed(db, suffix="context")
        asset = _asset(db, seed)
        claim = _persist_claim(db, seed, key="context-claim", asset_id=asset.asset_id)
        infer_capability(
            db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"], evidence_claim_id=claim.claim_id,
            name="inference", state="observed", confidence=0.9,
            verification_state="verified", freshness="fresh", observed_usage=True,
            declared_only=False, inferred_only=False, first_observed_at=NOW,
            last_observed_at=NOW, extractor_version="phase2-context-v1",
            idempotency_key="context-capability",
        )
        assert_reachability(
            db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id,
            target_category="model", target_reference_hash="e" * 64,
            reachability_state="observed", evidence_node_id=seed["node_id"],
            confidence=0.9, verification_state="verified", freshness="fresh",
            observed_usage=True, first_observed_at=NOW, last_observed_at=NOW,
            limitations=(), idempotency_key="context-reachability",
        )
        link_identity(
            db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id,
            identity_type="workload_identity", identity_reference_hash="f" * 64,
            access_state="active", evidence_node_id=seed["node_id"], confidence=0.9,
            verification_state="verified", usage_proven=True,
            first_observed_at=NOW, last_observed_at=NOW,
            idempotency_key="context-identity",
        )
        context = get_discovery_context(
            db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id
        )
        assert context["asset"]["asset_id"] == asset.asset_id
        assert context["capabilities"][0]["evidence_claim_id"] == claim.claim_id
        assert context["reachability"][0]["evidence_node_id"] == seed["node_id"]
        assert context["identities"][0]["usage_proven"] is True
        assert _forbidden_keys(context) == set()
    finally:
        db.close()
        engine.dispose()

