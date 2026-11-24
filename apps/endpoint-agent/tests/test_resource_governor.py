from __future__ import annotations

from hawk_endpoint_agent.evidence_queue import EvidenceQueue
from hawk_endpoint_agent.resource_governor import (
    ResourceBudget,
    ResourceGovernor,
    ResourceSample,
)
from hawk_endpoint_agent.privacy import safe_failure


def _monitor(item_id: str) -> dict:
    return {"id": item_id, "kind": "monitor_observation", "surface": "llm"}


def _receipt(item_id: str) -> dict:
    return {"id": item_id, "kind": "decision_receipt", "surface": "mcp"}


def test_monitor_events_drop_before_decision_receipts(tmp_path) -> None:
    queue = EvidenceQueue(tmp_path / "queue.json", max_items=2)
    queue.append(_monitor("old"))
    queue.append(_receipt("receipt"))
    queue.append(_monitor("new"))

    assert [item["id"] for item in queue.items()] == ["receipt", "new"]
    assert queue.dropped_monitor == 1


def test_monitor_event_is_rejected_when_queue_contains_only_receipts(tmp_path) -> None:
    queue = EvidenceQueue(tmp_path / "queue.json", max_items=2)
    queue.append(_receipt("one"))
    queue.append(_receipt("two"))

    assert queue.append(_monitor("monitor")) is False
    assert [item["id"] for item in queue.items()] == ["one", "two"]
    assert queue.dropped_monitor == 1


def test_queue_redacts_raw_content_keys(tmp_path) -> None:
    queue = EvidenceQueue(tmp_path / "queue.json", max_items=2)
    queue.append({"id": "one", "kind": "decision_receipt", "prompt": "secret", "api_key": "sk-test"})

    persisted = (tmp_path / "queue.json").read_text(encoding="utf-8")
    assert "secret" not in persisted
    assert "sk-test" not in persisted
    assert queue.items()[0]["redacted_fields"] == ["api_key", "prompt"]


def test_queue_rejects_secret_bearing_reason_text(tmp_path) -> None:
    queue = EvidenceQueue(tmp_path / "queue.json", max_items=2)

    queue.append({"id": "one", "kind": "decision_receipt", "reason": "provider returned sk-live-secret"})

    persisted = (tmp_path / "queue.json").read_text(encoding="utf-8")
    assert "sk-live-secret" not in persisted
    assert queue.items()[0]["reason"] == "redacted_reason"


def test_heartbeat_failure_sanitizer_rejects_secret_text() -> None:
    assert safe_failure("provider rejected sk-live-secret") == "redacted_reason"


def test_resource_governor_degrades_passive_work_first() -> None:
    governor = ResourceGovernor(
        ResourceBudget(
            idle_rss_mb=100,
            active_rss_mb=200,
            idle_cpu_percent=1,
            active_cpu_percent=5,
        )
    )

    state = governor.evaluate(ResourceSample(rss_mb=210, cpu_percent=6, active=True))

    assert state.health == "resource_limited"
    assert state.disabled_capabilities[0] == "passive_discovery"
    assert "inline_decisions" not in state.disabled_capabilities


def test_resource_governor_is_healthy_within_balanced_budget() -> None:
    governor = ResourceGovernor(ResourceBudget())

    state = governor.evaluate(ResourceSample(rss_mb=70, cpu_percent=0.4, active=False))

    assert state.health == "healthy"
    assert state.disabled_capabilities == []


def test_resource_governor_preserves_passive_discovery_cooldown_across_idle_samples() -> None:
    now = [100.0]
    governor = ResourceGovernor(
        ResourceBudget(),
        passive_discovery_cooldown_seconds=60.0,
        monotonic=lambda: now[0],
    )

    limited = governor.evaluate(ResourceSample(rss_mb=70, cpu_percent=68.0, active=True))
    now[0] += 5.0
    during_cooldown = governor.evaluate(ResourceSample(rss_mb=70, cpu_percent=0.1, active=False))

    assert "passive_discovery" in limited.disabled_capabilities
    assert during_cooldown.health == "resource_limited"
    assert during_cooldown.disabled_capabilities == ["passive_discovery"]
    assert during_cooldown.reasons == ["passive_discovery_cooldown"]
    assert 54.9 <= during_cooldown.cooldown_remaining_seconds <= 55.0

    now[0] += 56.0
    recovered = governor.evaluate(ResourceSample(rss_mb=70, cpu_percent=0.1, active=False))

    assert recovered.health == "healthy"
    assert recovered.disabled_capabilities == []
    assert recovered.cooldown_remaining_seconds == 0.0
