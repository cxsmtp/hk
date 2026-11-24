from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routers.discovery_assets import (
    get_asset_capabilities,
    get_asset_evidence,
    get_asset_history,
)
from app.api.routers.discovery_ecosystems import get_compatibility_summary
from app.db.models import *  # noqa: F401,F403
from app.db.models.ai_asset import (
    DiscoveryAssetHistoryEvent,
    DiscoveryAssetHistoryMember,
    DiscoveryObservationAssetLink,
    DiscoveryResolutionDecision,
    DiscoveryResolutionDecisionObservation,
)
from app.db.models.discovery import DiscoveryApplication
from app.db.models.scan import ScanResult
from app.db.models.shadow_ai import ShadowAIEntity
from app.db.session import Base
from app.services.hmair.capability_assertion_service import (
    persist_capability_assertion,
)
from app.services.hmair.compatibility_projection import (
    build_hmair_compatibility_summary,
)
from app.services.hmair.contracts import AICapabilityAssertionCreate
from app.services.hmair.evidence_claim_service import persist_evidence_claim
from test_phase2_asset_resolution_service import (
    NOW,
    _asset,
    _claim_payload,
    _seed,
)


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


def test_compatibility_summary_is_tenant_safe_bounded_and_non_authoritative() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="h1-compat")
        asset = _asset(db, seed)
        asset.asset_type = "ai_application"
        asset.canonical_name = "ChatGPT Enterprise"
        asset.shadow_ai_status = "suspected_shadow"

        other = _seed(db, suffix="h1-other")
        other_asset = _asset(db, other)
        other_asset.asset_type = "ai_application"
        other_asset.canonical_name = "ChatGPT Enterprise"

        db.add_all(
            [
                DiscoveryApplication(
                    tenant_id=seed["tenant_id"],
                    tool_key="chatgpt_enterprise",
                    tool_name="ChatGPT Enterprise",
                    vendor="OpenAI",
                    status="monitoring",
                    first_seen_at=NOW,
                    last_seen_at=NOW,
                    metadata_json={"raw_prompt": "must never be projected"},
                ),
                DiscoveryApplication(
                    tenant_id=seed["tenant_id"],
                    tool_key="unmatched_legacy_app",
                    tool_name="Unmatched Legacy App",
                    vendor="Unknown",
                    status="discovered",
                    first_seen_at=NOW,
                    last_seen_at=NOW,
                    metadata_json={},
                ),
                DiscoveryApplication(
                    tenant_id=other["tenant_id"],
                    tool_key="chatgpt_enterprise",
                    tool_name="ChatGPT Enterprise",
                    vendor="OpenAI",
                    status="monitoring",
                    first_seen_at=NOW,
                    last_seen_at=NOW,
                    metadata_json={},
                ),
                ScanResult(
                    tenant_id=seed["tenant_id"],
                    scan_id="legacy-scan-h1",
                    scan_type="discovery",
                    scope="global",
                    start_time=NOW,
                    end_time=NOW,
                    status="completed",
                    summary_json={"raw_prompt": "must never be projected"},
                    delta_json={},
                    snapshot_json={},
                ),
                ShadowAIEntity(
                    tenant_id=seed["tenant_id"],
                    canonical_name="ChatGPT Enterprise",
                    discovery_status="discovered",
                    approved_status="unknown",
                    confidence_score=0.7,
                    first_seen=NOW,
                    last_seen=NOW,
                    metadata_json={"secret": "must never be projected"},
                ),
            ]
        )
        db.flush()

        statements: list[str] = []

        def capture_statement(
            _connection, _cursor, statement, _parameters, _context, _many
        ) -> None:
            statements.append(statement)

        event.listen(db.bind, "before_cursor_execute", capture_statement)
        try:
            summary = build_hmair_compatibility_summary(
                db, tenant_id=seed["tenant_id"], generated_at=NOW
            )
        finally:
            event.remove(db.bind, "before_cursor_execute", capture_statement)

        assert summary.tenant_id == seed["tenant_id"]
        assert summary.raw_content_included is False
        assert summary.write_behavior == "read_only_no_cross_write"
        assert summary.scans.canonical_count == 1
        assert summary.scans.legacy_count == 1
        assert summary.scans.links == ()
        assert summary.scans.unmatched_legacy_count == 1
        assert summary.scans.unmatched_canonical_count == 1
        assert summary.discovery_applications.canonical_count == 1
        assert summary.discovery_applications.legacy_count == 2
        assert len(summary.discovery_applications.links) == 1
        link = summary.discovery_applications.links[0]
        assert link.canonical_record_id == asset.asset_id
        assert link.relationship_confidence == "correlated"
        assert link.verification_state == "unverified"
        assert summary.shadow_ai.canonical_count == 1
        assert summary.shadow_ai.legacy_count == 1
        assert "raw_prompt" not in summary.model_dump_json()
        assert other_asset.asset_id not in summary.model_dump_json()
        assert any(
            "FROM discovery_applications" in statement and "LIMIT" in statement
            for statement in statements
        )
        assert any(
            "FROM discovery_ai_assets" in statement and "LIMIT" in statement
            for statement in statements
        )

        api_result = get_compatibility_summary(
            ctx=_ctx(seed["tenant_id"]), db=db
        )
        assert api_result.tenant_id == seed["tenant_id"]
    finally:
        db.close()
        db.bind.dispose()


def test_asset_evidence_capability_and_history_reads_are_complete_and_tenant_safe() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="h1-api")
        asset = _asset(db, seed)
        claim = persist_evidence_claim(
            db,
            tenant_id=seed["tenant_id"],
            payload=_claim_payload(
                seed,
                subject_observation_id=None,
                subject_asset_id=asset.asset_id,
                idempotency_key="h1-api-asset-claim",
            ),
        )
        capability = persist_capability_assertion(
            db,
            tenant_id=seed["tenant_id"],
            payload=AICapabilityAssertionCreate(
                asset_id=asset.asset_id,
                source_observation_id=seed["observation_id"],
                evidence_claim_id=claim.claim_id,
                name="filesystem_read",
                state="observed",
                confidence=0.9,
                first_observed_at=NOW,
                last_observed_at=NOW,
                extractor_version="h1-closure-1.0",
            ),
        )
        history_id = str(uuid4())
        db.add(
            DiscoveryAssetHistoryEvent(
                history_event_id=history_id,
                tenant_id=seed["tenant_id"],
                event_type="create",
                reversal_of_event_id=None,
                actor_id="system",
                actor_role="system",
                reason="H1 closure fixture",
                evidence_claim_id=claim.claim_id,
                idempotency_key="h1-api-history",
                input_digest="f" * 64,
            )
        )
        db.flush()
        db.add(
            DiscoveryAssetHistoryMember(
                history_member_id=str(uuid4()),
                tenant_id=seed["tenant_id"],
                history_event_id=history_id,
                asset_id=asset.asset_id,
                member_role="result",
                ordinal=0,
            )
        )
        db.flush()
        decision_id = str(uuid4())
        db.add(
            DiscoveryResolutionDecision(
                decision_id=decision_id,
                tenant_id=seed["tenant_id"],
                canonical_asset_id=asset.asset_id,
                history_event_id=history_id,
                operation_index=0,
                action="create",
                matched_signals_json=[],
                conflicting_signals_json=[],
                confidence=0.9,
                algorithm_version="h1-closure-1.0",
                evidence_claim_id=claim.claim_id,
                idempotency_key="a" * 64,
                input_digest="b" * 64,
            )
        )
        db.flush()
        db.add_all(
            [
                DiscoveryResolutionDecisionObservation(
                    decision_observation_id=str(uuid4()),
                    tenant_id=seed["tenant_id"],
                    decision_id=decision_id,
                    observation_id=seed["observation_id"],
                    ordinal=0,
                ),
                DiscoveryObservationAssetLink(
                    link_id=str(uuid4()),
                    tenant_id=seed["tenant_id"],
                    observation_id=seed["observation_id"],
                    asset_id=asset.asset_id,
                    decision_id=decision_id,
                    history_event_id=history_id,
                    link_kind="attach",
                    sequence_no=1,
                    predecessor_link_id=None,
                    reversal_of_link_id=None,
                ),
            ]
        )
        db.flush()

        statements: list[str] = []

        def capture_statement(
            _connection, _cursor, statement, _parameters, _context, _many
        ) -> None:
            statements.append(statement)

        event.listen(db.bind, "before_cursor_execute", capture_statement)
        try:
            evidence = get_asset_evidence(
                asset.asset_id,
                limit=50,
                cursor=None,
                ctx=_ctx(seed["tenant_id"]),
                db=db,
            )
            capabilities = get_asset_capabilities(
                asset.asset_id,
                page=1,
                page_size=50,
                ctx=_ctx(seed["tenant_id"]),
                db=db,
            )
            history = get_asset_history(
                asset.asset_id,
                page=1,
                page_size=50,
                ctx=_ctx(seed["tenant_id"]),
                db=db,
            )
        finally:
            event.remove(db.bind, "before_cursor_execute", capture_statement)
        assert evidence.total == 1
        assert evidence.items[0].observation_id == seed["observation_id"]
        assert not hasattr(evidence.items[0], "normalized_signal")

        assert capabilities.total == 1
        assert capabilities.items[0].capability_id == capability.capability_id

        assert history.total == 1
        assert history.items[0].history_event_id == history_id
        assert history.items[0].member_role == "result"
        assert sum(" LIMIT " in statement.upper() for statement in statements) >= 3

        other = _seed(db, suffix="h1-api-other")
        assert other["tenant_id"] != seed["tenant_id"]
        try:
            get_asset_history(
                asset.asset_id,
                page=1,
                page_size=50,
                ctx=_ctx(other["tenant_id"]),
                db=db,
            )
        except Exception as exc:  # FastAPI HTTPException is the public boundary.
            assert getattr(exc, "status_code", None) == 404
        else:
            raise AssertionError("cross-tenant asset history must be concealed")
    finally:
        db.close()
        db.bind.dispose()
