from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.main import app
from app.db.models.audit import AuditLog
from app.db.models.discovery_canonical import DiscoveryObservation, DiscoveryScan
from app.services.hmair.enterprise_scan_service import (
    build_scan_diagnostics,
    build_scan_result_breadth,
)
from app.services.hmair.retention_service import (
    compact_terminal_scan_summaries,
    plan_terminal_scan_summary_compaction,
)
from app.services.hmair.scale_acceptance import run_hmair_streaming_benchmark
from app.services.hmair.collector_sdk import DiscoveryTargetView
from app.services.hmair.contracts import DiscoveryScanCreate
from app.jobs.hmair_discovery_jobs import _apply_scan_scope_exclusions
from test_phase2_asset_resolution_service import _seed
from test_phase2_discovery_coverage import _covered_asset, _db


NOW = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "hmair" / "h6-enterprise-scenarios.json"
DOC_ROOT = Path(__file__).parents[3] / "docs"
OPERATIONAL_DOCS = (
    "HMAIR_ARCHITECTURE.md",
    "HMAIR_COLLECTOR_CONTRACT.md",
    "HMAIR_ACTIVE_SCAN_SAFETY.md",
    "HMAIR_FINGERPRINTING.md",
    "HMAIR_ENTITY_RESOLUTION.md",
    "HMAIR_USAGE_ATTRIBUTION.md",
    "HMAIR_SHADOW_AI.md",
    "HMAIR_PRIVACY.md",
    "HMAIR_LIMITATIONS.md",
)
ACCEPTANCE_PATH = DOC_ROOT / "evidence" / "2026-09-11-hmair-h6-acceptance.json"


def test_h6_scan_results_and_diagnostics_are_bounded_and_truthful() -> None:
    db = _db()
    try:
        seed, asset_id = _covered_asset(db, suffix="h6-breadth")
        scan = db.scalar(
            select(DiscoveryScan).where(DiscoveryScan.tenant_id == seed["tenant_id"])
        )
        assert scan is not None
        scan.coverage_summary_json = {
            "confidence": "partial",
            "freshness": "fresh",
            "unsupported": ["browser_tenant"],
            "unknown": ["mcp_environment"],
            "explicit_exclusions": ["raw_content"],
        }
        db.flush()

        breadth = build_scan_result_breadth(
            db,
            tenant_id=seed["tenant_id"],
            scan_id=scan.scan_id,
            asset_ids=(asset_id,),
        )
        diagnostics = build_scan_diagnostics(
            db,
            tenant_id=seed["tenant_id"],
            scan_id=scan.scan_id,
        )

        assert breadth.total_assets == 1
        assert breadth.active_users == 1
        assert breadth.blind_spots == (
            "excluded:raw_content",
            "unknown:mcp_environment",
            "unsupported:browser_tenant",
        )
        assert breadth.control_coverage_state == "partial"
        assert diagnostics.assignments_total == 1
        assert diagnostics.sources[0].collector_health == "healthy"
        assert diagnostics.sources[0].target_exclusions == ()
        assert diagnostics.limitations
        assert "tenant" not in diagnostics.model_dump_json().lower()
    finally:
        db.close()
        db.bind.dispose()


def test_h6_scan_contract_limits_safety_profiles_and_scope_exclusions() -> None:
    material = {
        "name": "H6 safety",
        "scan_type": "targeted",
        "scope": {"exclusions": ["source_files", "credentials"]},
        "target_ids": ["target-h6"],
        "collector_ids": ["collector-h6"],
        "safety_profile": "metadata_only",
        "dry_run": True,
    }
    payload = DiscoveryScanCreate.model_validate(material)
    assert tuple(payload.scope["exclusions"]) == ("source_files", "credentials")
    assert payload.dry_run is True
    with pytest.raises(ValidationError):
        DiscoveryScanCreate.model_validate({**material, "safety_profile": "intrusive"})
    with pytest.raises(ValidationError):
        DiscoveryScanCreate.model_validate(
            {**material, "scope": {"exclusions": "not-a-list"}}
        )

    target = DiscoveryTargetView(
        target_id="target-h6",
        target_type="endpoint_group",
        identifier="managed-endpoints",
        environment="production",
        permitted_methods=("metadata",),
        exclusions=("credentials",),
        rate_limit=10,
        active_scan_allowed=True,
        sensitive_scope=False,
    )
    narrowed = _apply_scan_scope_exclusions(
        target,
        type("Scan", (), {"scope_json": {"exclusions": ["source_files"]}})(),
    )
    assert narrowed.exclusions == ("credentials", "source_files")
    assert target.exclusions == ("credentials",)


def test_h6_openapi_exposes_bounded_diagnostics_and_retention_operations() -> None:
    paths = app.openapi()["paths"]
    assert "/discovery/scans/{scan_id}/diagnostics" in paths
    assert "/discovery/scans/retention/plan" in paths
    assert "/discovery/scans/retention/compact" in paths
    assert "get" in paths["/discovery/scans/{scan_id}/diagnostics"]
    assert "post" in paths["/discovery/scans/retention/plan"]
    assert "post" in paths["/discovery/scans/retention/compact"]


def test_h6_retention_compacts_only_terminal_scan_summaries_and_audits() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="h6-retention")
        scan = db.scalar(
            select(DiscoveryScan).where(DiscoveryScan.tenant_id == seed["tenant_id"])
        )
        assert scan is not None
        scan.status = "complete"
        scan.completed_at = NOW - timedelta(days=120)
        scan.created_at = NOW - timedelta(days=121)
        scan.warnings_json = ["safe warning"] * 20
        scan.errors_json = ["safe error"] * 20
        scan.coverage_summary_json = {
            "confidence": "partial",
            "freshness": "stale",
            "unsupported": ["browser_tenant"],
            "unknown": ["mcp_environment"],
            "private_detail": "must be compacted",
        }
        observations_before = int(
            db.scalar(
                select(func.count(DiscoveryObservation.observation_id)).where(
                    DiscoveryObservation.tenant_id == seed["tenant_id"]
                )
            )
            or 0
        )
        scan_observations_before = scan.observations_count
        db.flush()

        plan = plan_terminal_scan_summary_compaction(
            db,
            tenant_id=seed["tenant_id"],
            now=NOW,
            retention_days=90,
            batch_size=10,
        )
        assert plan.scan_ids == (scan.scan_id,)
        result = compact_terminal_scan_summaries(
            db,
            tenant_id=seed["tenant_id"],
            actor_user_id=None,
            now=NOW,
            retention_days=90,
            batch_size=10,
            plan_digest=plan.plan_digest,
        )
        db.flush()

        assert result.compacted_scan_ids == (scan.scan_id,)
        assert scan.coverage_summary_json["confidence"] == "partial"
        assert scan.coverage_summary_json["freshness"] == "stale"
        assert "private_detail" not in scan.coverage_summary_json
        assert scan.coverage_summary_json["retention_compaction"]["version"] == "v1"
        assert scan.observations_count == scan_observations_before
        assert int(
            db.scalar(
                select(func.count(DiscoveryObservation.observation_id)).where(
                    DiscoveryObservation.tenant_id == seed["tenant_id"]
                )
            )
            or 0
        ) == observations_before
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == seed["tenant_id"],
                AuditLog.action == "hmair.scan_summaries_compacted",
            )
        )
        assert audit is not None
        replay = plan_terminal_scan_summary_compaction(
            db,
            tenant_id=seed["tenant_id"],
            now=NOW,
            retention_days=90,
            batch_size=10,
        )
        assert replay.scan_ids == ()
    finally:
        db.close()
        db.bind.dispose()


def test_h6_scale_acceptance_processes_exact_cardinality_without_estate_allocation() -> None:
    result = run_hmair_streaming_benchmark(
        observation_count=1_000_000,
        asset_count=100_000,
        batch_size=10_000,
    )
    replay = run_hmair_streaming_benchmark(
        observation_count=1_000_000,
        asset_count=100_000,
        batch_size=10_000,
    )
    assert result.observation_count == 1_000_000
    assert result.asset_count == 100_000
    assert result.max_batch_items == 10_000
    assert result.observation_batches == 100
    assert result.asset_batches == 10
    assert result.digest == replay.digest
    assert result.peak_traced_bytes < 16 * 1024 * 1024


def test_h6_has_exact_twelve_metadata_only_enterprise_scenarios() -> None:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    scenarios = payload["scenarios"]
    assert len(scenarios) == 12
    assert {item["id"] for item in scenarios} == {
        "cursor-endpoint",
        "claude-code-mcp",
        "azure-foundry-agent",
        "internal-langgraph-app",
        "direct-openai-api-script",
        "microsoft-365-copilot",
        "github-copilot",
        "pgvector-rag",
        "personal-chatgpt",
        "unprotected-mcp",
        "dormant-ai-service",
        "active-ai-owner-unknown",
    }
    for item in scenarios:
        assert item["evidence_mode"] == "metadata_only"
        assert item["expected_truth"] in {
            "confirmed", "observed", "correlated", "inferred", "unknown"
        }
        assert item["confidence"] in {"high", "medium", "low", "unknown"}
        assert item["limitations"]
        assert item["forbidden_content"] == [
            "raw_prompt",
            "credential",
            "source_file",
            "database_record",
        ]
    serialized = json.dumps(payload).lower()
    assert "sk-ant-" not in serialized
    assert "api_key" not in serialized


def test_h6_all_twenty_five_acceptance_criteria_have_source_evidence() -> None:
    payload = json.loads(ACCEPTANCE_PATH.read_text(encoding="utf-8"))
    criteria = payload["criteria"]
    assert [item["id"] for item in criteria] == [
        f"HMAIR-AC-{index:02d}" for index in range(1, 26)
    ]
    assert all(item["status"] == "accepted_source_and_fixture" for item in criteria)
    assert all(item["evidence"] for item in criteria)
    # Operational documents (docs/*.md) are kept privately by the owner, not in the repository; every other
    # evidence reference (source, tests, fixtures) must exist here.
    assert all(
        (DOC_ROOT.parent / evidence_ref).exists()
        for item in criteria
        for evidence_ref in item["evidence"]
        if not (evidence_ref.startswith("docs/") and evidence_ref.endswith(".md"))
    )
    assert payload["live_customer_acceptance"] == "not_claimed"
    assert payload["production_deployment"] == "not_claimed"
    assert payload["authoritative_enterprise_denominator"] == "source_dependent"
