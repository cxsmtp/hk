from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.capability_inference_service import (
    PHASE2_CAPABILITY_TAXONOMY,
    infer_capability,
)
from app.services.hmair.contracts import AICapabilityType, DiscoveryCapabilityType
from app.services.hmair.attribution_service import link_identity
from app.services.hmair.ownership_service import assert_ownership
from app.services.hmair.reachability_service import assert_reachability
from test_phase2_asset_resolution_service import (
    _asset,
    _persist_claim,
    _seed,
)


NOW = datetime(2026, 8, 15, 11, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def test_capability_taxonomy_and_truth_dimensions_are_complete() -> None:
    required = {
        "inference", "embeddings", "multimodal", "image_generation", "audio",
        "code_generation", "file_read", "file_write", "database_read",
        "database_write", "vector_search", "knowledge_retrieval", "memory_read",
        "memory_write", "shell_execution", "code_execution", "process_execution",
        "browser_automation", "ci_cd_execution", "git_read", "git_write",
        "repository_access", "code_modification", "patch_application",
        "internet_access", "internal_network", "api_call", "cloud_api", "webhook",
        "email_send", "tool_execution", "MCP_client", "MCP_server", "a2a",
        "delegation", "subagent", "planning", "persistent_automation",
        "secret_access", "oauth", "managed_identity", "service_principal",
        "user_impersonation", "identity_change",
    }
    assert required <= PHASE2_CAPABILITY_TAXONOMY
    assert PHASE2_CAPABILITY_TAXONOMY == {
        item.value for item in DiscoveryCapabilityType
    }
    assert len(tuple(AICapabilityType)) == 27
    assert {item.value for item in AICapabilityType} < PHASE2_CAPABILITY_TAXONOMY


def test_capability_reachability_identity_and_owner_keep_truth_separate() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="capability")
        asset = _asset(db, seed)
        claim = _persist_claim(db, seed, key="capability-claim", asset_id=asset.asset_id)
        capability = infer_capability(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim.claim_id,
            name="shell_execution",
            state="configured",
            confidence=0.72,
            verification_state="partially_verified",
            freshness="fresh",
            observed_usage=False,
            declared_only=True,
            inferred_only=False,
            first_observed_at=NOW,
            last_observed_at=NOW,
            extractor_version="phase2-capability-v1",
            idempotency_key="capability-shell-a",
        )
        reachability = assert_reachability(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            target_category="external_api",
            target_reference_hash="c" * 64,
            reachability_state="configured",
            evidence_node_id=seed["node_id"],
            confidence=0.6,
            verification_state="partially_verified",
            freshness="fresh",
            observed_usage=False,
            first_observed_at=NOW,
            last_observed_at=NOW,
            limitations=("No request event observed",),
            idempotency_key="reachability-a",
        )
        identity = link_identity(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            identity_type="oauth_app",
            identity_reference_hash="d" * 64,
            access_state="assigned",
            evidence_node_id=seed["node_id"],
            confidence=0.8,
            verification_state="verified",
            usage_proven=False,
            first_observed_at=NOW,
            last_observed_at=NOW,
            idempotency_key="identity-a",
        )
        owner = assert_ownership(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            owner_type="unknown",
            owner_reference_hash=None,
            ownership_state="unknown",
            evidence_node_id=seed["node_id"],
            confidence=0.0,
            verification_state="unknown",
            first_observed_at=NOW,
            last_observed_at=NOW,
            idempotency_key="owner-unknown-a",
        )

        assert capability.observed_usage is False
        assert capability.declared_only is True
        assert capability.inferred_only is False
        assert reachability.reachability_state == "configured"
        assert reachability.observed_usage is False
        assert identity.access_state == "assigned"
        assert identity.usage_proven is False
        assert owner.ownership_state == "unknown"
        assert owner.owner_reference_hash is None
    finally:
        db.close()
        db.bind.dispose()
