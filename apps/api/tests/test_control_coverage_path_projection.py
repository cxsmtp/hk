from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction
from app.db.models.control_coverage import ControlCoveragePath, DeploymentSurface
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.path_projection import (
    MAX_SOURCE_REFS,
    PathCandidate,
    ai_action_candidate,
    make_path_key,
    runtime_event_candidate,
    upsert_path,
)


def _candidate(**overrides: str | None) -> PathCandidate:
    values: dict[str, str | None] = {
        "asset_ref": "ai-system:system-1",
        "identity_type": "user",
        "identity_ref": "user:user-1",
        "runtime_ref": "model:gpt-4o-mini",
        "deployment_surface_id": None,
        "deployment_surface_ref": "gateway:primary",
        "destination_type": "tool",
        "destination_ref": "tool:customer.lookup",
        "source_ref": "runtime_event:event-1",
    }
    values.update(overrides)
    return PathCandidate(**values)  # type: ignore[arg-type]


def test_repeated_events_share_one_path_key() -> None:
    first = _candidate(source_ref="runtime_event:event-1")
    second = _candidate(source_ref="runtime_event:event-2")
    assert make_path_key(first) == make_path_key(second)


def test_material_component_change_creates_new_path() -> None:
    assert make_path_key(_candidate()) != make_path_key(_candidate(identity_ref="user:user-2"))


def test_unknown_component_is_explicit_and_stable() -> None:
    unresolved = _candidate(identity_type="unknown", identity_ref="unknown_identity:observation-7")
    assert "" not in unresolved.score_components()
    assert make_path_key(unresolved) == make_path_key(unresolved)


def test_blank_path_components_are_rejected() -> None:
    candidate = _candidate(runtime_ref="")
    try:
        candidate.score_components()
    except ValueError as exc:
        assert "explicit unknown" in str(exc)
    else:
        raise AssertionError("blank path component was accepted")


def test_runtime_event_adapter_prefers_verified_identifiers_and_strips_url_detail() -> None:
    event = RuntimeEvent(
        event_id="event-17",
        tenant_id="tenant-a",
        source_surface="mcp_gateway",
        event_type="tool_call",
        ai_system_id="system-17",
        user_id="user-17",
        agent_id="agent-ignored",
        metadata_json={
            "provider": "OpenAI",
            "model": "gpt-5",
            "tool_name": "crm.lookup",
            "destination_url": "https://crm.example.test/customers/17?api_key=secret",
            "prompt": "must never enter a path",
        },
    )

    candidate = runtime_event_candidate(event)

    assert candidate.asset_ref == "ai_system:system-17"
    assert (candidate.identity_type, candidate.identity_ref) == ("user", "user:user-17")
    assert candidate.runtime_ref == "model:openai/gpt-5"
    assert candidate.deployment_surface_ref == "source_surface:mcp_gateway"
    assert (candidate.destination_type, candidate.destination_ref) == ("tool", "tool:crm.lookup")
    assert "secret" not in "|".join(candidate.score_components())
    assert "prompt" not in "|".join(candidate.score_components())


def test_runtime_event_adapter_uses_explicit_unknowns_without_telemetry() -> None:
    event = RuntimeEvent(
        event_id="event-unknown",
        tenant_id="tenant-a",
        source_surface="browser",
        event_type="observed",
        metadata_json={},
    )

    candidate = runtime_event_candidate(event)

    assert candidate.asset_ref == "unknown_asset:runtime_event:event-unknown"
    assert candidate.identity_type == "unknown"
    assert candidate.identity_ref == "unknown_identity:runtime_event:event-unknown"
    assert candidate.runtime_ref == "unknown_runtime:runtime_event:event-unknown"
    assert candidate.destination_ref == "unknown_destination:runtime_event:event-unknown"


def test_secret_shaped_identifier_is_hashed_before_path_projection() -> None:
    event = RuntimeEvent(
        event_id="event-secret",
        tenant_id="tenant-a",
        source_surface="sdk",
        event_type="tool_call",
        metadata_json={"tool_name": "sk-live-super-secret-value"},
    )

    candidate = runtime_event_candidate(event)

    assert candidate.destination_ref.startswith("tool_hash:")
    assert "super-secret" not in candidate.destination_ref


def test_ai_action_adapter_uses_canonical_projection_without_raw_resource() -> None:
    action = AIAction(
        action_id="action-17",
        tenant_id="tenant-a",
        session_id="session-17",
        user_id="user-17",
        action_type="tool_call",
        ai_app="support-assistant",
        ai_model="gpt-5",
        metadata_json={
            "canonical_ai_action_v1": {
                "surface": {"provider": "azure_openai", "model": "gpt-5"},
                "action": {
                    "tool_name": "crm.update",
                    "target_resource": "customer:417?token=secret",
                },
            }
        },
    )

    candidate = ai_action_candidate(action)

    assert candidate.asset_ref == "application:support-assistant"
    assert candidate.identity_ref == "user:user-17"
    assert candidate.runtime_ref == "model:azure_openai/gpt-5"
    assert candidate.destination_ref == "tool:crm.update"
    assert "secret" not in "|".join(candidate.score_components())


def test_upsert_path_deduplicates_and_bounds_safe_source_refs() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.flush()

        first = upsert_path(db, tenant_id="tenant-a", candidate=_candidate(), observed_at=now)
        initial_first_seen = first.first_seen_at
        for index in range(MAX_SOURCE_REFS + 4):
            upsert_path(
                db,
                tenant_id="tenant-a",
                candidate=_candidate(source_ref=f"runtime_event:event-{index + 2}"),
                observed_at=now + timedelta(seconds=index + 1),
            )
        db.flush()

        rows = db.scalars(select(ControlCoveragePath)).all()
        assert len(rows) == 1
        assert rows[0].first_seen_at == initial_first_seen
        assert rows[0].last_seen_at == now + timedelta(seconds=MAX_SOURCE_REFS + 4)
        assert len(rows[0].source_refs) == MAX_SOURCE_REFS
        assert all(item.startswith("runtime_event:") for item in rows[0].source_refs)
    engine.dispose()


def test_reconciled_surface_participates_in_path_identity() -> None:
    surface = DeploymentSurface(
        id="surface-17",
        tenant_id="tenant-a",
        source_kind="gateway",
        source_id="primary",
        name="Primary Gateway",
        surface_type="llm_gateway",
    )
    event = RuntimeEvent(
        event_id="event-17",
        tenant_id="tenant-a",
        source_surface="llm_gateway",
        event_type="completion",
        metadata_json={},
    )

    candidate = runtime_event_candidate(event, deployment_surface=surface)

    assert candidate.deployment_surface_id == "surface-17"
    assert candidate.deployment_surface_ref == "gateway:primary"
