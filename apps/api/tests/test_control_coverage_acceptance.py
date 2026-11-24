from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import Session

from app.db.models.control_coverage import ControlCoverageAssertion
from app.db.models.evidence import DecisionReceipt
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.service import calculate_tenant_control_coverage


def _engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def test_existing_surface_matrix_never_inflates_inline_or_proof() -> None:
    engine = _engine()
    now = datetime.now(timezone.utc)
    surfaces = [
        "browser",
        "gateway",
        "mcp",
        "sdk",
        "runtime_control",
        "connector",
        "endpoint",
        "foundry",
        "copilot",
    ]
    with Session(engine) as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        for index, surface in enumerate(surfaces):
            db.add(
                RuntimeEvent(
                    event_id=f"event-{surface}",
                    tenant_id="tenant-a",
                    source_surface=surface,
                    event_type="observed_action",
                    app_id=f"app-{surface}",
                    user_id=f"user-{index}",
                    metadata_json={
                        "provider": "provider",
                        "model": "model",
                        "tool_name": f"tool.{surface}",
                        "control_mode": "telemetry_only",
                    },
                    created_at=now + timedelta(seconds=index),
                )
            )
        db.flush()

        result = calculate_tenant_control_coverage(
            db,
            tenant_id="tenant-a",
            now=now + timedelta(minutes=1),
        )

        assert len(result.paths) == len(surfaces)
        assert len(result.assertions) == len(surfaces) * 7
        assert result.summary.headline_counts.denominator == len(surfaces) * 7
        authorization = [row for row in result.assertions if row.dimension == "authorization"]
        evidence = [row for row in result.assertions if row.dimension == "evidence"]
        assert {row.state for row in authorization} == {"not_covered"}
        assert {row.reason_code for row in authorization} == {"monitor_only_surface"}
        assert {row.state for row in evidence} == {"not_covered"}
        assert {row.reason_code for row in evidence} == {"missing_execution_proof"}
    engine.dispose()


def test_invalid_receipt_signature_forces_unknown_never_covered() -> None:
    engine = _engine()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.add(
            RuntimeEvent(
                event_id="event-invalid-receipt",
                tenant_id="tenant-a",
                source_surface="gateway",
                event_type="completion",
                app_id="app-a",
                metadata_json={"control_mode": "inline_allowed", "tool_name": "tool.read"},
                created_at=now,
            )
        )
        db.add(
            DecisionReceipt(
                receipt_id="receipt-invalid",
                tenant_id="tenant-a",
                action_id="event-invalid-receipt",
                chain_id="chain-1",
                canonical_action_hash="canonical",
                actor_hash="actor",
                authority_hash="authority",
                purpose_hash="purpose",
                tool_fingerprint="tool",
                parameter_hash="parameters",
                target_resource_hash="target",
                destination_hash="destination",
                side_effect_class="read",
                approval_binding_hash="approval",
                policy_snapshot_id="policy",
                decision="allow",
                control_mode="inline_allowed",
                transformations=[],
                expires_at=now + timedelta(hours=1),
                issued_at=now,
                signature="forged-signature",
                signing_key_id="missing-key",
                collector_id="collector",
                canonical_action_evidence_node_id="missing-node",
                idempotency_key="invalid-idempotency",
            )
        )
        db.flush()

        result = calculate_tenant_control_coverage(db, tenant_id="tenant-a", now=now)

        assert len(result.assertions) == 7
        assert {row.state for row in result.assertions} == {"unknown"}
        assert {row.reason_code for row in result.assertions} == {"conflicting_evidence"}
    engine.dispose()


def test_deleted_source_keeps_path_but_invalidates_current_assertions() -> None:
    engine = _engine()
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.add(
            RuntimeEvent(
                event_id="event-deleted",
                tenant_id="tenant-a",
                source_surface="browser",
                event_type="observed_action",
                user_id="user-a",
                app_id="app-a",
                metadata_json={"control_mode": "telemetry_only", "tool_name": "tool.read"},
                created_at=now,
            )
        )
        db.flush()
        baseline = calculate_tenant_control_coverage(db, tenant_id="tenant-a", now=now)
        path_id = baseline.paths[0].id
        db.execute(delete(RuntimeEvent).where(RuntimeEvent.event_id == "event-deleted"))
        db.flush()

        recalculated = calculate_tenant_control_coverage(
            db,
            tenant_id="tenant-a",
            now=now + timedelta(minutes=1),
        )

        assert [path.id for path in recalculated.paths] == [path_id]
        assert recalculated.paths[0].lifecycle_status == "source_missing"
        states = db.scalars(
            select(ControlCoverageAssertion.state).where(ControlCoverageAssertion.path_id == path_id)
        ).all()
        assert states == ["unknown"] * 7
    engine.dispose()
